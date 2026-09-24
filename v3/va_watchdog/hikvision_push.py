"""Hikvision HTTP event delivery helpers.

The receiver keeps only XML/JSON metadata. Camera configuration is performed only
from the guarded Setup action and the previous slot response is returned for backup.
"""
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.request import Request
import xml.etree.ElementTree as ET

from .hikvision import _base_url, _digest_opener
from .hikvision_native import read_bounded, response_error


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


def http_host_payload(slot, receiver_address, receiver_port, channel):
    """Build the documented HTTP-host subscription for counting metadata."""
    root = ET.Element("HttpHostNotification", xmlns="http://www.isapi.org/ver20/XMLSchema", version="2.0")
    values = {
        "id": str(slot),
        "url": f"http://{receiver_address}:{int(receiver_port)}/hikvision/events",
        "protocolType": "HTTP",
        "parameterFormatType": "JSON",
        "addressingFormatType": "ipaddress",
        "ipAddress": str(receiver_address),
        "portNo": str(int(receiver_port)),
        "httpAuthenticationMethod": "none",
        "uploadImagesDataType": "URL",
        "httpBroken": "true",
    }
    for name, value in values.items():
        ET.SubElement(root, name).text = value
    subscribe = ET.SubElement(root, "SubscribeEvent")
    ET.SubElement(subscribe, "heartbeat").text = "30"
    ET.SubElement(subscribe, "eventMode").text = "list"
    event_list = ET.SubElement(subscribe, "EventList")
    event = ET.SubElement(event_list, "Event")
    ET.SubElement(event, "type").text = "regionTargetNumberCounting"
    ET.SubElement(event, "channels").text = str(int(channel))
    ET.SubElement(event, "pictureURLType").text = "localURL"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def configure_http_push(settings, receiver_address, receiver_port, slot=1, opener=None, backup_path=None):
    """Back up, update and verify one camera HTTP host slot."""
    base = _base_url(settings)
    client = opener or _digest_opener(base, str(settings["username"]), str(settings["password"]))
    path = f"/ISAPI/Event/notification/httpHosts/{int(slot)}"
    deadline = __import__("time").monotonic() + 12
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
    body = http_host_payload(slot, receiver_address, receiver_port, settings.get("channel", 1))
    request = Request(base + path, data=body, method="PUT", headers={"Content-Type": "application/xml"})
    with client.open(request, timeout=7) as response:
        result_body = read_bounded(response, deadline)
        status = response.getcode()
    error = response_error(result_body)
    if not 200 <= status < 300 or error:
        raise RuntimeError(error or f"camera returned HTTP {status}")
    return {
        "ok": True,
        "slot": int(slot),
        "url": f"http://{receiver_address}:{int(receiver_port)}/hikvision/events",
        "backup_path": str(backup_path) if backup_path is not None else "",
        "message": "Camera HTTP event destination configured. Waiting for the first counting message.",
    }
