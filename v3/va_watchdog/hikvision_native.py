"""Bounded, read-only ISAPI diagnostics and safe response reduction."""
import json
import re
import subprocess
import time
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request


MAX_RESPONSE = 256 * 1024
_diagnostic_lock = threading.Lock()


def decode_document(payload):
    payload = payload or b""
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise ValueError("DTD/entity responses are not accepted")
    if payload.lstrip().startswith((b"{", b"[")):
        return json.loads(payload)
    return ET.fromstring(payload)


def scalar_fields(document):
    if isinstance(document, ET.Element):
        for node in document.iter():
            if not len(node):
                yield node.tag.rsplit("}", 1)[-1], (node.text or "").strip()
    elif isinstance(document, dict):
        for key, value in document.items():
            if isinstance(value, (dict, list)):
                yield from scalar_fields(value)
            else:
                yield key, str(value).lower() if isinstance(value, bool) else str(value)
    elif isinstance(document, list):
        for value in document:
            yield from scalar_fields(value)


def response_error(payload):
    """Retain protocol status fields, never the whole response or request."""
    try:
        document = decode_document(payload)
    except (ValueError, ET.ParseError):
        return ""
    if isinstance(document, ET.Element):
        if document.tag.rsplit("}", 1)[-1].lower() != "responsestatus":
            return ""
    elif isinstance(document, dict):
        document = document.get("ResponseStatus", document)
    else:
        return ""
    values = {key.lower(): value for key, value in scalar_fields(document)
              if key.lower() in {"statuscode", "statusstring", "substatuscode", "errorcode"}}
    status_code = values.get("statuscode")
    status_string = values.get("statusstring", "ok").lower()
    substatus_code = values.get("substatuscode", "ok").lower()
    if not values or (status_code in {"0", "1"} and status_string == "ok" and substatus_code == "ok"):
        return ""
    if set(values) == {"errorcode"} and values["errorcode"].lower() in {"0", "0x0", "0x00000000"}:
        return ""
    return "; ".join(f"{key}={re.sub(r'[^A-Za-z0-9 _.:/-]', '', value)[:120]}"
                     for key, value in values.items())


def capability_detail(document):
    flags = [(name, value.lower()) for name, value in scalar_fields(document)
             if value.lower() in {"true", "false"}]
    if flags:
        return "; ".join(f"{name}={value}" for name, value in flags[:80])
    return "Endpoint responded; feature support not established"


def capability_supported(document):
    return any(value.lower() == "true" for _, value in scalar_fields(document))


def bounded_native_diagnostic(settings, runner=None, wait_seconds=28):
    if not _diagnostic_lock.acquire(blocking=False):
        return {"message": "A native diagnostic is still running. Wait before trying again.", "requests": []}
    result = {"message": "Diagnostic timed out. No camera settings changed. A slow request may still be closing.", "requests": []}
    def run():
        try:
            result.update((runner or native_diagnostics)(dict(settings)))
        except Exception as exc:
            result.update(message=f"Diagnostic failed ({type(exc).__name__}). No camera settings changed.")
        finally:
            _diagnostic_lock.release()
    worker = threading.Thread(target=run, name="hikvision-native-diagnostic", daemon=True)
    worker.start()
    worker.join(timeout=wait_seconds)
    return dict(result)


def read_bounded(response, deadline):
    chunks, size = [], 0
    reader = getattr(response, "read1", None)
    if reader is None:  # Simple test responses and non-streaming adapters.
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise ValueError("Response exceeds diagnostic size limit")
        return payload
    while time.monotonic() < deadline:
        chunk = reader(min(8192, MAX_RESPONSE + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_RESPONSE:
            raise ValueError("Response exceeds diagnostic size limit")
    raise TimeoutError("Diagnostic time budget expired")


def native_diagnostics(settings, opener=None, budget_seconds=25):
    from .hikvision import _base_url, _digest_opener
    base = _base_url(settings)
    client = opener or _digest_opener(base, str(settings["username"]), str(settings["password"]))
    channel = int(settings.get("channel") or 1)
    push_slot = max(1, min(12, int(settings.get("push_slot") or 1)))
    paths = [
        ("Camera identity", "/ISAPI/System/deviceInfo"),
        ("Full system capabilities", "/ISAPI/System/capabilities?type=all"),
        ("Event capabilities", f"/ISAPI/Event/channels/{channel}/capabilities"),
        ("Region target counting capabilities", f"/ISAPI/Event/channels/{channel}/RegionTargetNumberCounting/Capabilities?format=json"),
        ("HTTP upload capabilities", "/ISAPI/Event/notification/httpHosts/capabilities"),
        ("Existing HTTP upload destinations", "/ISAPI/Event/notification/httpHosts"),
        ("Selected HTTP upload slot schema", f"/ISAPI/Event/notification/httpHosts/{push_slot}"),
        ("HTTP event subscription capabilities", "/ISAPI/Event/notification/subscribeEventCap"),
        ("Active multi-target configuration", f"/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection?format=json"),
    ]
    deadline = time.monotonic() + max(1, min(30, budget_seconds))
    rows = []
    authentication_failed = False
    for name, path in paths:
        row = {"name": name, "method": "GET", "path": path, "ok": False}
        remaining = deadline - time.monotonic()
        if remaining <= 0 or authentication_failed:
            row["detail"] = "Skipped: authentication failed" if authentication_failed else "Skipped: diagnostic time budget exhausted"
            rows.append(row)
            continue
        try:
            request = Request(base + path, headers={"Accept": "application/xml, application/json"})
            with client.open(request, timeout=min(3, remaining)) as response:
                payload = read_bounded(response, deadline)
                row["status_code"] = response.getcode()
            error = response_error(payload)
            document = decode_document(payload)
            row["ok"] = 200 <= row["status_code"] < 300 and not error
            details = []
            if isinstance(document, ET.Element):
                if name in {"HTTP upload capabilities", "Selected HTTP upload slot schema",
                            "HTTP event subscription capabilities"}:
                    namespace = document.tag[1:].split("}", 1)[0] if document.tag.startswith("{") else "none"
                    fields = ",".join(child.tag.rsplit("}", 1)[-1] for child in document)
                    details.extend((f"root={document.tag.rsplit('}', 1)[-1]}",
                                    f"namespace={namespace[:120]}", f"fields={fields[:1000]}"))
                for node in document.iter():
                    name_key = node.tag.rsplit("}", 1)[-1]
                    options = node.get("opt", "")
                    if (any(word in name_key.lower() for word in ("eventtype", "count", "target", "statistic", "direction"))
                            or "regionTargetNumberCounting" in options) and re.fullmatch(r"[A-Za-z0-9_, .:-]{1,1500}", options):
                        details.append(f"{name_key}.options={options}")
                    if name in {"HTTP upload capabilities", "HTTP event subscription capabilities"}:
                        safe_attributes = []
                        for attribute in ("opt", "min", "max", "def", "req"):
                            value = node.get(attribute, "")
                            if value and re.fullmatch(r"[A-Za-z0-9_, .:/-]{1,1500}", value):
                                safe_attributes.append(f"{attribute}={value}")
                        if safe_attributes:
                            details.append(f"{name_key}[{','.join(safe_attributes)}]")
            for key, value in scalar_fields(document):
                lowered = key.lower()
                if any(word in lowered for word in ("password", "secret", "token", "username", "serial", "cookie", "authorization")):
                    continue
                if lowered in {"model", "firmwareversion", "firmwarereleaseddate"}:
                    details.append(f"{key}={value[:100]}")
                elif value.lower() in {"true", "false"}:
                    details.append(f"{key}={value.lower()}")
                elif name == "Existing HTTP upload destinations" and lowered in {"id", "ipaddress", "portno", "protocoltype"}:
                    details.append(f"{key}={value[:100]}")
                elif name == "Selected HTTP upload slot schema" and lowered in {
                        "id", "protocoltype", "parameterformattype", "addressingformattype", "portno",
                        "httpauthenticationmethod", "uploadimagesdatatype", "httpbroken", "eventmode"}:
                    if re.fullmatch(r"[A-Za-z0-9_, .:/-]{0,120}", value):
                        details.append(f"{key}={value}")
                elif any(word in lowered for word in ("eventtype", "statistic", "count", "direction", "alarmhost",
                                                       "parameterformat", "authentication", "uploadimages")) and re.fullmatch(r"[A-Za-z0-9_, .:/-]{1,120}", value):
                    details.append(f"{key}={value}")
            details.sort(key=lambda value: not any(word in value.split("=", 1)[0].lower()
                         for word in ("count", "target", "statistic", "eventtype", "http", "upload", "model", "firmware")))
            row["detail"] = error or "; ".join(details[:80]) or "Endpoint responded; no recognised capability values"
        except HTTPError as exc:
            row["status_code"] = exc.code
            authentication_failed = exc.code == 401
            try:
                detail = response_error(read_bounded(exc, deadline))
            except (OSError, ValueError):
                detail = ""
            finally:
                exc.close()
            row["detail"] = f"HTTP {exc.code}" + (f": {detail}" if detail else " (no readable protocol status)")
        except (OSError, ValueError, ET.ParseError) as exc:
            row["detail"] = f"Request failed ({type(exc).__name__})"
        password = str(settings.get("password") or "")
        if password:
            row["detail"] = row["detail"].replace(password, "[redacted]")
        rows.append(row)
    return {"tested_at": datetime.now(timezone.utc).isoformat(), "requests": rows,
            "message": "Read-only diagnostic complete. A successful endpoint does not prove count delivery. No camera settings changed."}


def capture_request_paths(camera, runner=None):
    runner = runner or subprocess.run
    if camera.get("scheme") == "https":
        return {"status": "failed", "message": "HTTPS paths are encrypted. Use the native API diagnostic instead."}
    try:
        result = runner(["tcpdump", "-i", "any", "-l", "-A", "-s", "1024", "-c", "500", "host",
                         str(camera["address"]), "and", "tcp", "port", str(int(camera.get("port") or 80))],
                        capture_output=True, text=True, timeout=60, check=False)
        output = result.stdout
        if result.returncode:
            return {"status": "failed", "message": f"Packet capture failed (exit {result.returncode}). Check tcpdump installation and capture permissions."}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
    except OSError as exc:
        return {"status": "failed", "message": f"Packet capture could not start ({type(exc).__name__})."}
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    # Keep paths only, never query values that might carry credentials/tokens.
    paths = sorted(set(re.findall(r"(?m)^(?:GET|POST)\s+(/[^\s?]*)(?:\?[^\s]*)?\s+HTTP", output or "")))[:50]
    return {"status": "complete" if paths else "empty", "paths": paths,
            "message": "No visible HTTP request. Capture only sees traffic on this gateway; use the native API diagnostic instead." if not paths else "HTTP paths captured"}
