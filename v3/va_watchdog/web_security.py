"""Operator authentication and a shared request boundary for both dashboards."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore, Lock
from urllib.parse import urlsplit

HELPER = "/usr/local/lib/va-watchdog/web-action-helper.py"
MAX_ACTION_BODY = 64 * 1024
PUBLIC_GET = {"/", "/lite", "/api/lite", "/api/status", "/api/version", "/api/healthz", "/api/livez", "/api/readyz"}
ACTION_PATHS = frozenset({
    "/network-router-save", "/api/status-shortcuts", "/analytics/anpr-save", "/analytics/crossing-save",
    "/factory-reset", "/teamviewer-password", "/web-link-add", "/web-link-update", "/web-link-delete",
    "/stage0-baseline-start", "/network-speed-test", "/journal-enable", "/update-now", "/pi-storage-expand",
    "/pi-storage-reboot", "/settings-save", "/hikvision-native-diagnostic", "/hikvision-push-configure",
    "/hikvision-test-now", "/hikvision-route-capture-start", "/api/events/purge", "/storage-purge-old",
    "/storage-purge-all", "/recording-storage-confirm", "/recording-storage-blank-confirm",
    "/recording-storage-apply", "/recording-storage-blank-apply", "/recording-storage-monitor-only",
    "/recording-storage-system-directory", "/recording-storage-guard-apply", "/recovery-install-now",
    "/neousys-watchdog-install-now", "/hardware-watchdog-prepare-now", "/watchdog-hardware-probe-now",
    "/watchdog-legacy-disable-now", "/hardware-watchdog-enable-now", "/watchdog-grace-delay",
    "/watchdog-arm-now", "/hardware-watchdog-disable-now", "/watchdog-grace-config-set",
    "/service-restart-now", "/gateway-reboot-now", "/watchdog-test-arm", "/watchdog-trip-run",
    "/watchdog-liveness-run", "/watchdog-trip-arm", "/watchdog-trip-now", "/watchdog-test-run",
    "/watchdog-timeout-set",
    "/api/update", "/api/settings", "/api/purge",
})


def helper_request(payload, timeout=15):
    result = subprocess.run(["sudo", "-n", "--", HELPER], input=json.dumps(payload).encode("utf-8"),
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("Operator action helper is unavailable; run the updated installer.")
    return result.stdout


def credentials(header):
    try:
        scheme, encoded = header.split(" ", 1)
        if scheme.lower() != "basic" or len(encoded) > 4096:
            return None
        user, password = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
        if not user or not password or "\x00" in user + password:
            return None
        return user, password
    except (ValueError, UnicodeError):
        return None


class OperatorAuth:
    def __init__(self):
        self.accepted = {}
        self.lock = Lock()

    def authenticate(self, header):
        if not credentials(header):
            return False
        digest = hashlib.sha256(header.encode()).digest()
        now = time.monotonic()
        with self.lock:
            self.accepted = {key: expiry for key, expiry in self.accepted.items() if expiry > now}
            if digest in self.accepted:
                return True
        try:
            accepted = json.loads(helper_request({"operation": "authenticate", "authorization": header})).get("ok") is True
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            accepted = False
        if accepted:
            with self.lock:
                if len(self.accepted) < 32:
                    self.accepted[digest] = now + 60
        return accepted


def same_origin(headers):
    # Host includes the forwarded port. Do not trust X-Forwarded-Host from arbitrary clients.
    host = headers.get("Host", "").lower()
    origin = headers.get("Origin")
    if origin:
        parsed = urlsplit(origin)
        return parsed.scheme in {"http", "https"} and parsed.netloc.lower() == host
    referer = headers.get("Referer")
    if referer:
        return urlsplit(referer).netloc.lower() == host
    return headers.get("X-VA-Watchdog-Action") == "1"


class ProtectedHandler(BaseHTTPRequestHandler):
    auth = None
    privileged_action = False
    dashboard_mode = "full"

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def deny(self, status, message):
        body = json.dumps({"ok": False, "message": message}).encode()
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="VA-Connect operator", charset="UTF-8"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        return False

    def allow_read(self):
        route = urlsplit(self.path).path
        try:
            local = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            local = False
        if route != "/operator-login" and (route in PUBLIC_GET or local):
            return True
        if self.auth.authenticate(self.headers.get("Authorization", "")):
            return True
        return self.deny(401, "Sign in with the configured gateway operator account.")

    def allow_action(self):
        if self.privileged_action:
            return True
        route = urlsplit(self.path).path
        camera_event = route == "/hikvision/events"
        if camera_event:
            camera = self.app_cfg.get("people_counting", {})
            if (not camera.get("event_collection_enabled") or camera.get("event_transport") != "http_push"
                    or self.client_address[0].removeprefix("::ffff:") != camera.get("address")):
                return self.deny(403, "Camera receiver is unavailable for this source")
        if not camera_event and route not in ACTION_PATHS:
            return self.deny(404, "Action not found")
        if not camera_event and not self.auth.authenticate(self.headers.get("Authorization", "")):
            return self.deny(401, "Sign in with the configured gateway operator account.")
        if not camera_event and not same_origin(self.headers):
            return self.deny(403, "Open this action from the gateway page.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.deny(400, "Invalid request size")
        maximum = 512 * 1024 if camera_event else MAX_ACTION_BODY
        if not 0 <= size <= maximum or self.headers.get("Transfer-Encoding"):
            return self.deny(413, "Request is too large")
        body = self.rfile.read(size)
        if len(body) != size:
            return self.deny(400, "Incomplete request")
        payload = {"operation": "camera_event" if camera_event else "action", "path": self.path, "mode": self.dashboard_mode,
                   "source": self.client_address[0].removeprefix("::ffff:"),
                   "destination": self.connection.getsockname()[0],
                   "authorization": self.headers.get("Authorization", ""),
                   "content_type": self.headers.get("Content-Type", "application/x-www-form-urlencoded"),
                   "body": base64.b64encode(body).decode()}
        try:
            response = helper_request(payload, timeout=240)
            if not response.startswith(b"HTTP/1."):
                raise RuntimeError("Invalid action response")
        except (OSError, RuntimeError, subprocess.SubprocessError):
            return self.deny(503, "Action could not be completed. Check the gateway service log before retrying.")
        self.connection.sendall(response)
        self.action_completed = True
        self.close_connection = True
        return False


def protect(handler, mode="full", cfg=None):
    handler.auth = OperatorAuth()
    handler.dashboard_mode = mode
    handler.app_cfg = cfg or {}
    return handler


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
