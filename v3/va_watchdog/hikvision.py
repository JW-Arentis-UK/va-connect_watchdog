from __future__ import annotations

import json
import re
import socket
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, Request, build_opener


_CAPABILITY_PROBES = (
    (
        "Intelligent analytics capabilities",
        "/ISAPI/Intelligent/capabilities",
    ),
    (
        "Channel intelligent analytics capabilities",
        "/ISAPI/Intelligent/channels/{channel}/capabilities",
    ),
    (
        "Multi-target detection capabilities",
        "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/capabilities",
    ),
    (
        "Entrance / exit counting",
        "/ISAPI/System/Video/inputs/channels/{channel}/counting/capabilities",
    ),
    (
        "Area occupancy counting",
        "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities",
    ),
    (
        "People-flow report search",
        "/ISAPI/System/Video/inputs/channels/{channel}/counting/search/capabilities",
    ),
)

_DATA_SOURCE_PROBES = (
    ("SD card storage status", "/ISAPI/ContentMgmt/Storage", "xml"),
    ("SD card health", "/ISAPI/ContentMgmt/Storage/hdd", "xml"),
    ("Live analytics metadata stream", "/ISAPI/Streaming/channels/{channel}/metadata", "stream"),
)

_REPORT_VALUE_NAMES = {
    "enterCount", "leaveCount", "passingCount", "passCount", "peopleNumber", "inCount", "outCount",
}


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


def _request_xml(opener, url: str, timeout: int, method: str = "GET", body: bytes | None = None, extra_headers: dict[str, str] | None = None) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/xml, text/xml, application/json",
            **({"Content-Type": "application/xml; charset=utf-8"} if body else {}),
            **(extra_headers or {}),
        },
        data=body,
        method=method,
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


def _get_xml(opener, url: str, timeout: int) -> dict:
    return _request_xml(opener, url, timeout)


def _get_json(opener, url: str, timeout: int) -> dict:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
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
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "status_code": status, "detail": "Camera returned an unreadable response"}
    return {
        "ok": 200 <= status < 300 and isinstance(value, dict),
        "status_code": status,
        "detail": "Supported" if 200 <= status < 300 else f"Camera returned HTTP {status}",
        "value": value,
    }


def _probe_stream(opener, url: str, timeout: int) -> dict:
    """Check that a stream can be opened without retaining video or metadata."""
    request = Request(url, headers={"Accept": "application/xml, multipart/x-mixed-replace"}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", response.getcode()))
    except HTTPError as exc:
        if exc.code == 401:
            detail = "Authentication failed"
        elif exc.code in {403, 404, 405}:
            detail = "Not supported or not permitted by this camera"
        else:
            detail = f"Camera returned HTTP {exc.code}"
        return {"ok": False, "status_code": exc.code, "detail": detail}
    except (URLError, TimeoutError, socket.timeout, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"ok": False, "status_code": None, "detail": f"Connection failed: {reason}"}
    return {"ok": 200 <= status < 300, "status_code": status, "detail": "Available" if 200 <= status < 300 else f"Camera returned HTTP {status}"}


def _discover_web_api_routes(opener, base_url: str, timeout: int) -> list[str]:
    """Find ISAPI paths advertised by the camera UI; never retain UI content."""
    try:
        with opener.open(Request(f"{base_url}/", headers={"Accept": "text/html"}), timeout=timeout) as response:
            html = response.read(512 * 1024).decode("utf-8", errors="ignore")
    except (HTTPError, URLError, TimeoutError, socket.timeout, OSError):
        return []
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)', html, flags=re.I)
    text = html
    for source in scripts[:30]:
        if not source.startswith("/"):
            continue
        try:
            with opener.open(Request(f"{base_url}{source.split('?', 1)[0]}"), timeout=timeout) as response:
                text += "\n" + response.read(1024 * 1024).decode("utf-8", errors="ignore")
        except (HTTPError, URLError, TimeoutError, socket.timeout, OSError):
            continue
    routes = re.findall(r"/ISAPI/[A-Za-z0-9_./?={}-]+", text)
    return sorted({route for route in routes if any(word in route.lower() for word in ("count", "target", "statistic"))})[:30]


def _latest_completed_day() -> tuple[str, str]:
    today = datetime.now().astimezone().date()
    end = datetime.combine(today, datetime.min.time())
    start = end - timedelta(days=1)
    return start.strftime("%Y-%m-%dT00:00:00"), (end - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S")


def _daily_report_query(start_time: str, end_time: str) -> bytes:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<CountingStatisticsDescription version=\"2.0\" xmlns=\"http://www.isapi.org/ver20/XMLSchema\">"
        "<statisticType>peoplePassing</statisticType><reportType>daily</reportType><timeSpanList><timeSpan>"
        f"<startTime>{start_time}</startTime><endTime>{end_time}</endTime>"
        "</timeSpan></timeSpanList><MinTimeInterval>hour</MinTimeInterval>"
        "</CountingStatisticsDescription>"
    ).encode("utf-8")


def _onvif_capabilities_query() -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body>'
        '<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>'
        '</s:Body></s:Envelope>'
    ).encode("utf-8")


def _onvif_event_properties_query(username: str, password: str) -> bytes:
    return ('<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>' + xml_escape(username) + '</wsse:Username><wsse:Password>' + xml_escape(password) + '</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><tev:GetEventProperties/></s:Body></s:Envelope>').encode("utf-8")


def _report_summary(root: ET.Element) -> dict:
    rows = [element for element in root.iter() if _local_name(element.tag) in {"CountingStatistics", "countingStatistics"}]
    totals: dict[str, int] = {}
    for row in rows:
        for name, value in _xml_values(row, _REPORT_VALUE_NAMES).items():
            try:
                totals[name] = totals.get(name, 0) + int(value)
            except ValueError:
                continue
    return {"rows": len(rows), "totals": totals}


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
        detail = response.get("detail")
        if response.get("ok") and response.get("root") is not None:
            names = sorted({_local_name(element.tag) for element in response["root"].iter()})[:80]
            detail = "Supported: " + ", ".join(names)
        capabilities.append({
            "family": family,
            "supported": bool(response.get("ok")),
            "status_code": response.get("status_code"),
            "detail": detail,
        })

    multi_target_response = _get_json(
        client,
        f"{base_url}/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection?format=json",
        timeout,
    )
    multi_target = multi_target_response.get("value", {}).get("MixedTargetDetection", {}) if multi_target_response.get("ok") else {}
    multi_target_enabled = bool(multi_target.get("enabled")) if isinstance(multi_target, dict) else False
    multi_target_detail = multi_target_response.get("detail")
    if multi_target_response.get("ok"):
        multi_target_detail = "Active" if multi_target_enabled else "Configured, but currently disabled"
    capabilities.append({
        "family": "Multi-target-type detection",
        "supported": bool(multi_target_response.get("ok")),
        "status_code": multi_target_response.get("status_code"),
        "detail": multi_target_detail,
    })

    data_sources = []
    for name, endpoint_template, source_type in _DATA_SOURCE_PROBES:
        endpoint = endpoint_template.format(channel=channel)
        response = _probe_stream(client, f"{base_url}{endpoint}", timeout) if source_type == "stream" else _get_xml(client, f"{base_url}{endpoint}", timeout)
        data_sources.append({
            "name": name,
            "available": bool(response.get("ok")),
            "status_code": response.get("status_code"),
            "detail": response.get("detail"),
        })
    web_routes = _discover_web_api_routes(client, base_url, timeout)
    data_sources.append({
        "name": "Statistics API routes advertised by camera UI",
        "available": bool(web_routes),
        "status_code": 200 if web_routes else None,
        "detail": "; ".join(web_routes) if web_routes else "No readable statistics route found in the camera UI scripts",
    })
    onvif_response = _request_xml(client, f"{base_url}/onvif/device_service", timeout, method="POST", body=_onvif_capabilities_query())
    onvif_names = sorted({_local_name(element.tag) for element in onvif_response.get("root", []).iter()})[:50] if onvif_response.get("ok") else []
    onvif_addresses = []
    if onvif_response.get("ok"):
        for element in onvif_response["root"].iter():
            if _local_name(element.tag) == "XAddr" and element.text and element.text.strip():
                onvif_addresses.append(element.text.strip())
    data_sources.append({
        "name": "ONVIF analytics and event services",
        "available": bool(onvif_response.get("ok")),
        "status_code": onvif_response.get("status_code"),
        "detail": "Available: " + ", ".join(onvif_addresses[:12] or onvif_names) if onvif_names else onvif_response.get("detail"),
    })
    events_address = next((value for value in onvif_addresses if "/onvif/Events" in value), "")
    if events_address:
        events_response = _request_xml(client, events_address, timeout, method="POST", body=_onvif_event_properties_query(username, password), extra_headers={"Content-Type": "application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest\""})
        topics = sorted({_local_name(element.tag) for element in events_response.get("root", []).iter()})[:60] if events_response.get("ok") else []
        data_sources.append({"name": "ONVIF event topics", "available": bool(events_response.get("ok")), "status_code": events_response.get("status_code"), "detail": "Available: " + ", ".join(topics) if topics else events_response.get("detail")})

    report_start, report_end = _latest_completed_day()
    report_response = _request_xml(
        client,
        f"{base_url}/ISAPI/System/Video/inputs/channels/{channel}/counting/search",
        timeout,
        method="POST",
        body=_daily_report_query(report_start, report_end),
    )
    report = {
        "supported": bool(report_response.get("ok")),
        "status_code": report_response.get("status_code"),
        "detail": report_response.get("detail"),
        "start_time": report_start,
        "end_time": report_end,
        "rows": 0,
        "totals": {},
    }
    if report_response.get("ok"):
        report.update(_report_summary(report_response["root"]))
        report["detail"] = f"{report['rows']} daily record{'s' if report['rows'] != 1 else ''} returned"
    capabilities.append({
        "family": "Daily people-flow report",
        "supported": report["supported"],
        "status_code": report["status_code"],
        "detail": report["detail"],
    })

    supported = [item["family"] for item in capabilities if item["supported"]]
    connected = bool(device_response.get("ok")) or any(
        item.get("status_code") not in {None, 401} for item in capabilities
    )
    authenticated = bool(device_response.get("ok")) or any(item["supported"] for item in capabilities)
    restricted = [item["family"] for item in capabilities if item.get("status_code") == 403]
    if multi_target_enabled:
        message = "Camera connected; active application is multi-target-type detection. Its counters need event-based collection."
    elif supported:
        message = f"Camera connected; supported method: {', '.join(supported)}"
    elif not connected:
        message = str(device_response.get("detail") or "Camera could not be reached")
    elif not authenticated:
        message = "Camera reached, but authentication failed"
    elif restricted:
        message = f"Camera connected; restricted interface: {', '.join(restricted)}"
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
        "multi_target_detection": {"active": multi_target_enabled},
        "report": report,
        "data_sources": data_sources,
        "message": message,
    }
