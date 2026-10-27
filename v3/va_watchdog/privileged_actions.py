"""Short-lived helper. It accepts authenticated, enumerated actions over stdin only."""
from __future__ import annotations

import base64
import ctypes
import hmac
import io
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlsplit

from .config import load_config
from .web_security import ACTION_PATHS, MAX_ACTION_BODY, credentials
from .ui_profile import route_supported


def verify_operator(cfg, authorization):
    pair = credentials(authorization)
    if pair is None or pair[0] != cfg.get("web", {}).get("operator_account", "vsuser") or os.name != "posix":
        return False
    try:
        user, password = pair
        with open("/etc/shadow", encoding="utf-8") as shadow:
            row = next((line.rstrip().split(":") for line in shadow if line.split(":", 1)[0] == user), None)
        if not row or len(row) < 8 or not row[1] or row[1][0] in "!*":
            return False
        days = int(time.time() // 86400)
        if row[7] and int(row[7]) <= days:
            return False
        if row[2] == "0" or (row[2] and row[4] and int(row[2]) + int(row[4]) < days):
            return False
        lib = ctypes.CDLL("libcrypt.so.1")
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.crypt.restype = ctypes.c_char_p
        value = lib.crypt(password.encode(), row[1].encode())
        return bool(value and hmac.compare_digest(value, row[1].encode()))
    except (OSError, ValueError):
        return False


class _Request:
    def __init__(self, data, destination="127.0.0.1"):
        self.input, self.output = io.BytesIO(data), bytearray()
        self.destination = destination

    def makefile(self, *_args):
        return self.input

    def sendall(self, data):
        self.output.extend(data)

    def settimeout(self, _timeout):
        pass

    def getsockname(self):
        return (self.destination, 9110)


def execute(payload, cfg):
    import threading
    existing_threads = set(threading.enumerate())
    operation = payload.get("operation")
    if operation not in {"authenticate", "action", "camera_event"}:
        raise ValueError("Unsupported operation")
    camera = cfg.get("people_counting", {})
    camera_event = operation == "camera_event"
    if camera_event and (not camera.get("event_collection_enabled") or camera.get("event_transport") != "http_push"
                         or not camera.get("address") or payload.get("source") != camera.get("address")
                         or payload.get("path") != "/hikvision/events"):
        raise PermissionError("Camera event rejected")
    if not camera_event and not verify_operator(cfg, payload.get("authorization", "")):
        if operation == "authenticate":
            return b'{"ok":false}'
        raise PermissionError("Operator authentication failed")
    if operation == "authenticate":
        return b'{"ok":true}'
    target = payload.get("path", "")
    if not isinstance(target, str) or not target.startswith("/") or len(target) > 2048 or any(c in target for c in "\r\n "):
        raise ValueError("Invalid action path")
    route = urlsplit(target).path
    if not route_supported(cfg, route):
        raise ValueError("This tool does not apply to this device")
    if not camera_event and route not in ACTION_PATHS:
        raise ValueError("Unsupported action")
    body = base64.b64decode(payload.get("body", ""), validate=True)
    content_type = payload.get("content_type", "application/x-www-form-urlencoded")
    if len(body) > (512 * 1024 if camera_event else MAX_ACTION_BODY) or any(c in content_type for c in "\r\n"):
        raise ValueError("Invalid action body")
    from .web import start_web
    handler = start_web(cfg, handler_only=True)
    source = str(ipaddress.ip_address(payload.get("source", "127.0.0.1")))
    destination = str(ipaddress.ip_address(payload.get("destination", "127.0.0.1")))
    request = _Request((f"POST {target} HTTP/1.0\r\nHost: localhost\r\nContent-Type: {content_type}\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n").encode() + body, destination)
    handler(request, (source, 0), None)
    # Action-started daemon work must finish before this short-lived process exits.
    for thread in threading.enumerate():
        if thread not in existing_threads:
            thread.join(timeout=35)
    return bytes(request.output)


def main():
    try:
        raw = sys.stdin.buffer.read(800000)
        if len(raw) >= 800000 or os.geteuid() != 0:
            raise ValueError("Invalid helper request")
        payload = json.loads(raw)
        if payload.get("operation") == "action":
            import fcntl
            lock = open("/run/lock/va-watchdog-web-action.lock", "a")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        output = execute(payload, load_config())
        sys.stdout.buffer.write(output)
        return 0
    except Exception as exc:
        try:
            import syslog
            syslog.syslog(syslog.LOG_WARNING, f"va-watchdog operator helper failed: {type(exc).__name__}")
        except (ImportError, OSError):
            pass
        sys.stderr.write("Watchdog operator action rejected or failed.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
