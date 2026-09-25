"""Hikvision HTTP event delivery helpers.

The receiver keeps only XML/JSON metadata. Camera configuration is performed only
from the guarded Setup action and the previous slot response is returned for backup.
"""
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request
import copy
import re
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

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
        ET.SubElement(subscribe, tag("heartbeat")).text = "30"
        ET.SubElement(subscribe, tag("eventMode")).text = "list"
        event_list = ET.SubElement(subscribe, tag("EventList"))
        event = ET.SubElement(event_list, tag("Event"))
        ET.SubElement(event, tag("type")).text = "mixedTargetDetection"
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


def _replace_xml_text(document, name, value):
    tag_pattern = rf"(?:[A-Za-z_][A-Za-z0-9_.-]*:)?{re.escape(name)}"
    paired = re.compile(
        rf"(<(?P<tag>{tag_pattern})\b[^>]*>).*?(</(?P=tag)\s*>)",
        re.IGNORECASE | re.DOTALL,
    )
    replacement = xml_escape(str(value))
    document, count = paired.subn(
        lambda match: match.group(1) + replacement + match.group(3), document, count=1)
    if count:
        return document
    empty = re.compile(rf"<(?P<tag>{tag_pattern})(?P<attrs>\s[^>]*)?/\s*>", re.IGNORECASE)
    document, count = empty.subn(
        lambda match: (f"<{match.group('tag')}{match.group('attrs') or ''}>"
                       f"{replacement}</{match.group('tag')}>"),
        document,
        count=1,
    )
    if not count:
        raise ValueError(f"camera configuration omitted {name}")
    return document


def _ensure_subscription(document, channel, event_type="mixedTargetDetection"):
    """Subscribe the selected host without reserializing camera-owned XML."""
    root_match = re.search(
        r"<(?P<prefix>[A-Za-z_][A-Za-z0-9_.-]*:)?HttpHostNotification\b",
        document,
        re.IGNORECASE,
    )
    prefix = (root_match.group("prefix") or "") if root_match else ""
    subscription = re.search(
        r"<(?P<tag>(?:[A-Za-z_][A-Za-z0-9_.-]*:)?SubscribeEvent)\b[^>]*>.*?</(?P=tag)\s*>",
        document,
        re.IGNORECASE | re.DOTALL,
    )
    block = (
        f"<{prefix}SubscribeEvent>"
        f"<{prefix}heartbeat>30</{prefix}heartbeat>"
        f"<{prefix}eventMode>list</{prefix}eventMode>"
        f"<{prefix}EventList><{prefix}Event>"
        f"<{prefix}type>{xml_escape(str(event_type))}</{prefix}type>"
        f"</{prefix}Event></{prefix}EventList>"
        f"<{prefix}channels>{int(channel)}</{prefix}channels>"
        f"</{prefix}SubscribeEvent>"
    )
    if subscription:
        return document[:subscription.start()] + block + document[subscription.end():]

    closing = re.search(
        r"</(?:[A-Za-z_][A-Za-z0-9_.-]*:)?HttpHostNotification\s*>",
        document,
        re.IGNORECASE,
    )
    if not closing:
        raise ValueError("camera HTTP host document has no closing element")
    return document[:closing.start()] + block + document[closing.start():]


def _roundtrip_list_payload(previous, slot, receiver_address, receiver_port, channel=None):
    """Patch one host inside the camera's complete host list response."""
    root = decode_document(previous)
    if not isinstance(root, ET.Element) or root.tag.rsplit("}", 1)[-1] != "HttpHostNotificationList":
        raise ValueError("camera did not return an HTTP host list")
    had_bom = previous.startswith(b"\xef\xbb\xbf")
    text = previous.decode("utf-8-sig")
    host_pattern = re.compile(
        r"<(?P<tag>(?:[A-Za-z_][A-Za-z0-9_.-]*:)?HttpHostNotification)\b[^>]*>.*?</(?P=tag)\s*>",
        re.IGNORECASE | re.DOTALL,
    )
    id_pattern = re.compile(
        rf"<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?id\b[^>]*>\s*{int(slot)}\s*</(?:[A-Za-z_][A-Za-z0-9_.-]*:)?id\s*>",
        re.IGNORECASE,
    )
    selected = None
    for match in host_pattern.finditer(text):
        if id_pattern.search(match.group(0)):
            selected = match
            break
    if selected is None:
        raise ValueError(f"camera HTTP host slot {int(slot)} was not returned")
    block = selected.group(0)
    block = _replace_xml_text(block, "url", "/hikvision/events")
    block = _replace_xml_text(block, "ipAddress", receiver_address)
    block = _replace_xml_text(block, "portNo", int(receiver_port))
    if channel is not None:
        block = _ensure_subscription(block, channel)
    text = text[:selected.start()] + block + text[selected.end():]
    encoded = text.encode("utf-8")
    return (b"\xef\xbb\xbf" + encoded) if had_bom else encoded


def _roundtrip_payload(previous, slot, receiver_address, receiver_port, channel,
                       include_subscription=False):
    """Update the camera's own slot document without dropping required fields."""
    try:
        source = decode_document(previous)
    except (ValueError, ET.ParseError):
        source = None
    if not isinstance(source, ET.Element) or source.tag.rsplit("}", 1)[-1] != "HttpHostNotification":
        namespace, parameter_format = _camera_template(previous)
        return http_host_payload(slot, receiver_address, receiver_port, channel,
                                 namespace=namespace, parameter_format=parameter_format,
                                 include_subscription=include_subscription)

    # Preserve the camera's exact whitespace, namespace spelling and empty-tag
    # style. Some firmware rejects an ElementTree-equivalent serialization.
    try:
        had_bom = previous.startswith(b"\xef\xbb\xbf")
        text = previous.decode("utf-8-sig")

        text = _replace_xml_text(text, "url", "/hikvision/events")
        text = _replace_xml_text(text, "ipAddress", receiver_address)
        text = _replace_xml_text(text, "portNo", int(receiver_port))
        if include_subscription:
            text = _ensure_subscription(text, channel)
        encoded = text.encode("utf-8")
        return (b"\xef\xbb\xbf" + encoded) if had_bom else encoded
    except (UnicodeDecodeError, ValueError):
        pass

    root = copy.deepcopy(source)
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    if namespace:
        ET.register_namespace("", namespace)
    tag = lambda name: f"{{{namespace}}}{name}" if namespace else name

    def direct_child(name):
        return next((child for child in root if child.tag.rsplit("}", 1)[-1] == name), None)

    def set_value(name, value):
        child = direct_child(name)
        if child is None:
            child = ET.SubElement(root, tag(name))
        child.text = str(value)

    values = {
        "url": "/hikvision/events",
        "ipAddress": receiver_address,
        "portNo": int(receiver_port),
    }
    for name, value in values.items():
        set_value(name, value)

    existing = direct_child("SubscribeEvent")
    if existing is not None:
        root.remove(existing)
    if include_subscription:
        subscribe = ET.SubElement(root, tag("SubscribeEvent"))
        ET.SubElement(subscribe, tag("heartbeat")).text = "30"
        ET.SubElement(subscribe, tag("eventMode")).text = "list"
        event_list = ET.SubElement(subscribe, tag("EventList"))
        event = ET.SubElement(event_list, tag("Event"))
        ET.SubElement(event, tag("type")).text = "mixedTargetDetection"
        ET.SubElement(subscribe, tag("channels")).text = str(int(channel))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def configure_http_push(settings, receiver_address, receiver_port, slot=1, opener=None, backup_path=None):
    """Back up, update and verify one camera HTTP host slot."""
    base = _base_url(settings)
    client = opener or _digest_opener(base, str(settings["username"]), str(settings["password"]))
    path = "/ISAPI/Event/notification/httpHosts"
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
    channel = max(1, int(settings.get("channel") or 1))
    slot_path = f"{path}/{int(slot)}"

    def get(path_to_read):
        request = Request(base + path_to_read, headers={"Accept": "application/xml"})
        with client.open(request, timeout=5) as response:
            return read_bounded(response, deadline)

    def put(path_to_write, body):
        request = Request(base + path_to_write, data=body, method="PUT",
                          headers={"Content-Type": 'application/xml; charset="UTF-8"'})
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
            raise RuntimeError(detail or f"camera returned HTTP {status}") from None
        error = response_error(result_body)
        if not 200 <= status < 300 or error:
            raise RuntimeError(error or f"camera returned HTTP {status}")

    failures = []
    applied_profile = "selected camera host with event subscription"
    try:
        selected = get(slot_path)
        body = _roundtrip_payload(selected, slot, receiver_address, receiver_port, channel,
                                  include_subscription=True)
        put(slot_path, body)
    except (HTTPError, OSError, ValueError, ET.ParseError, RuntimeError) as exc:
        failures.append(f"selected host: {exc}")
        try:
            body = _roundtrip_list_payload(previous, slot, receiver_address, receiver_port, channel)
            put(path, body)
            applied_profile = "camera host list with event subscription"
        except (HTTPError, OSError, ValueError, ET.ParseError, RuntimeError) as fallback_exc:
            failures.append(f"host list: {fallback_exc}")
            raise RuntimeError("; ".join(failures)) from None

    try:
        verified = get(slot_path)
        fields = {name.lower(): value for name, value in scalar_fields(decode_document(verified))}
        if (fields.get("ipaddress") != str(receiver_address)
                or fields.get("portno") != str(int(receiver_port))
                or fields.get("eventmode", "").lower() != "list"
                or fields.get("type", "").lower() != "mixedtargetdetection"):
            retained = ", ".join(
                f"{name}={fields.get(key) or '-'}"
                for name, key in (
                    ("ipAddress", "ipaddress"),
                    ("portNo", "portno"),
                    ("eventMode", "eventmode"),
                    ("eventType", "type"),
                )
            )
            raise RuntimeError(f"camera read-back retained {retained}")
    except (HTTPError, OSError, ValueError, ET.ParseError) as exc:
        raise RuntimeError(f"camera configuration could not be verified: {exc}") from None
    return {
        "ok": True,
        "slot": int(slot),
        "url": f"http://{receiver_address}:{int(receiver_port)}/hikvision/events",
        "backup_path": str(backup_path) if backup_path is not None else "",
        "profile": applied_profile,
        "message": ("Camera HTTP event destination and multi-target counting subscription configured using "
                    + applied_profile + ". Waiting for the first counting message."),
    }
