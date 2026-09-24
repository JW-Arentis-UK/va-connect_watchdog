"""Hikvision HTTP event delivery helpers.

The receiver keeps only XML/JSON metadata. Camera configuration is performed only
from the guarded Setup action and the previous slot response is returned for backup.
"""
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request
import time
import xml.etree.ElementTree as ET

from .hikvision import _base_url, _digest_opener
from .hikvision_native import decode_document, read_bounded, response_error, scalar_fields


MAX_PUSH_BODY = 512 * 1024


def metadata_documents(content_type, payload):
    """Extract bounded XML/JSON MIME parts without returning media parts."""
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type in {"application/json", "application/xml", "text/xml"}:
        return [payload]
    if not media_type.startswith("multipart/"):
        return []
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + content_type.encode("ascii", errors="ignore") + b"\r\nMIME-Version: 1.0\r\n\r\n" + payload
    )
    documents = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_type().lower() in {"application/json", "application/xml", "text/xml"}:
            body = part.get_payload(decode=True) or b""
            if len(body) <= MAX_PUSH_BODY:
                documents.append(body)
    return documents


def http_host_payload(slot, receiver_address, receiver_port, channel, *, namespace=None,
                      parameter_format="XML", include_subscription=True):
    """Build a broadly compatible, metadata-only HTTP-host subscription."""
    namespace = namespace or "http://www.isapi.org/ver20/XMLSchema"
    ET.register_namespace("", namespace)
    tag = lambda name: f"{{{namespace}}}{name}"
    root = ET.Element(tag("HttpHostNotification"), version="2.0")
    values = {
        "id": str(slot),
        "url": f"http://{receiver_address}:{int(receiver_port)}/hikvision/events",
        "protocolType": "HTTP",
        "parameterFormatType": parameter_format,
        "addressingFormatType": "ipaddress",
        "ipAddress": str(receiver_address),
        "portNo": str(int(receiver_port)),
        "httpAuthenticationMethod": "none",
    }
    for name, value in values.items():
        ET.SubElement(root, tag(name)).text = value
    if include_subscription:
        subscribe = ET.SubElement(root, tag("SubscribeEvent"))
        # Firmware families disagree on the counting event name. Subscribe to
        # metadata for the channel and let the receiver retain counting events only.
        ET.SubElement(subscribe, tag("eventMode")).text = "all"
        ET.SubElement(subscribe, tag("channels")).text = str(int(channel))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _camera_template(previous):
    """Retain the camera's namespace and preferred metadata format."""
    namespace = "http://www.isapi.org/ver20/XMLSchema"
    parameter_format = "XML"
    try:
        root = decode_document(previous)
        if isinstance(root, ET.Element) and root.tag.startswith("{"):
            namespace = root.tag[1:].split("}", 1)[0]
        values = {name.lower(): value for name, value in scalar_fields(root)}
        candidate = values.get("parameterformattype", "").upper()
        if candidate in {"XML", "JSON"}:
            parameter_format = candidate
    except (ValueError, ET.ParseError):
        pass
    return namespace, parameter_format


def configure_http_push(settings, receiver_address, receiver_port, slot=1, opener=None, backup_path=None):
    """Back up, update and verify one camera HTTP host slot."""
    base = _base_url(settings)
    client = opener or _digest_opener(base, str(settings["username"]), str(settings["password"]))
    path = f"/ISAPI/Event/notification/httpHosts/{int(slot)}"
    deadline = time.monotonic() + 12
    with client.open(Request(base + path, headers={"Accept": "application/xml"}), timeout=5) as response:
        previous = read_bounded(response, deadline)
    if backup_path is not None:
        backup = Path(backup_path)
        backup.parent.mkdir(parents=True, exist_ok=True)
        temporary = backup.with_suffix(backup.suffix + ".tmp")
        temporary.write_bytes(previous)
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(backup)
    namespace, parameter_format = _camera_template(previous)
    variants = (("channel subscription", True), ("destination only", False))
    failures = []
    applied_profile = ""
    for profile, include_subscription in variants:
        body = http_host_payload(slot, receiver_address, receiver_port, settings.get("channel", 1),
                                 namespace=namespace, parameter_format=parameter_format,
                                 include_subscription=include_subscription)
        request = Request(base + path, data=body, method="PUT", headers={"Content-Type": "application/xml"})
        try:
            with client.open(request, timeout=7) as response:
                result_body = read_bounded(response, deadline)
                status = response.getcode()
        except HTTPError as exc:
            try:
                detail = response_error(exc.read(16 * 1024))
            finally:
                status = exc.code
                exc.close()
            failures.append(detail or f"camera returned HTTP {status}")
            if status == 400 and include_subscription:
                continue
            raise RuntimeError(failures[-1]) from None
        error = response_error(result_body)
        if 200 <= status < 300 and not error:
            applied_profile = profile
            break
        failures.append(error or f"camera returned HTTP {status}")
        if not include_subscription:
            raise RuntimeError(failures[-1])
    if not applied_profile:
        raise RuntimeError(failures[-1] if failures else "camera rejected the configuration")
    return {
        "ok": True,
        "slot": int(slot),
        "url": f"http://{receiver_address}:{int(receiver_port)}/hikvision/events",
        "backup_path": str(backup_path) if backup_path is not None else "",
        "profile": applied_profile,
        "message": ("Camera HTTP event destination configured using " + applied_profile
                    + ". Waiting for the first counting message."),
    }
