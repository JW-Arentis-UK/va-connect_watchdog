from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, Request, build_opener


_CAPABILITY_PROBES = (
    (
        "Entrance / exit counting",
        "/ISAPI/System/Video/inputs/channels/{channel}/counting/capabilities",
    ),
    (
        "Area occupancy counting",
        "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities",
    ),
)


def _local_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _xml_values(root: ET.Element, names: set[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for element in root.iter():
        name = _local_name(element.tag)
        if name in names and element.text and element.text.strip():
            values[name] = element.text.strip()
    return values


def _base_url(settings: dict) -> str:
    scheme = str(settings.get("scheme") or "http").lower()
    address = str(settings.get("address") or "").strip()
    port = int(settings.get("port") or (443 if scheme == "https" else 80))
    if ":" in address and not address.startswith("["):
        address = f"[{address}]"
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{address}{'' if port == default_port else f':{port}'}"


def _digest_opener(base_url: str, username: str, password: str):
    password_manager = HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, base_url, username, password)
    return build_opener(HTTPDigestAuthHandler(password_manager))


def _get_xml(opener, url: str, timeout: int) -> dict:
    request = Request(
        url,
        headers={"Accept": "application/xml, text/xml, application/json"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(512 * 1024)
            status = int(getattr(response, "status", response.getcode()))
    except HTTPError as exc:
        if exc.code == 401:
            detail = "Authentication failed"
        elif exc.code in {404, 405}:
            detail = "Not supported by this camera"
        else:
            detail = f"Camera returned HTTP {exc.code}"
        return {"ok": False, "status_code": exc.code, "detail": detail}
    except (URLError, TimeoutError, socket.timeout, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"ok": False, "status_code": None, "detail": f"Connection failed: {reason}"}

    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return {"ok": False, "status_code": status, "detail": "Camera returned an unreadable response"}
    return {
        "ok": 200 <= status < 300,
        "status_code": status,
        "detail": "Supported" if 200 <= status < 300 else f"Camera returned HTTP {status}",
        "root": root,
    }


def probe_people_counting(settings: dict, opener=None) -> dict:
    """Run read-only Hikvision ISAPI capability checks without returning credentials."""
    tested_at = datetime.now(timezone.utc).isoformat()
    base_url = _base_url(settings)
    username = str(settings.get("username") or "").strip()
    password = str(settings.get("password") or "")
    channel = int(settings.get("channel") or 1)
    timeout = int(settings.get("timeout_seconds") or 5)
    client = opener or _digest_opener(base_url, username, password)

    device_response = _get_xml(client, f"{base_url}/ISAPI/System/deviceInfo", timeout)
    device: dict[str, str] = {}
    if device_response.get("ok"):
        device = _xml_values(
            device_response["root"],
            {"deviceName", "model", "deviceType", "firmwareVersion", "firmwareReleasedDate"},
        )

    capabilities = []
    for family, endpoint_template in _CAPABILITY_PROBES:
        endpoint = endpoint_template.format(channel=channel)
        response = _get_xml(client, f"{base_url}{endpoint}", timeout)
        capabilities.append({
            "family": family,
            "supported": bool(response.get("ok")),
            "status_code": response.get("status_code"),
            "detail": response.get("detail"),
        })

    supported = [item["family"] for item in capabilities if item["supported"]]
    connected = bool(device_response.get("ok")) or any(
        item.get("status_code") not in {None, 401} for item in capabilities
    )
    authenticated = bool(device_response.get("ok")) or any(item["supported"] for item in capabilities)
    if supported:
        message = f"Camera connected; supported method: {', '.join(supported)}"
    elif not connected:
        message = str(device_response.get("detail") or "Camera could not be reached")
    elif not authenticated:
        message = "Camera reached, but authentication failed"
    else:
        message = "Camera connected, but the tested people-counting APIs are not available"

    return {
        "ok": bool(supported),
        "tested_at": tested_at,
        "connected": connected,
        "authenticated": authenticated,
        "address": str(settings.get("address") or ""),
        "channel": channel,
        "device": device,
        "capabilities": capabilities,
        "message": message,
    }
