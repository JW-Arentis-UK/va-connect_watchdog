"""Run the watchdog web server with an independent systemd liveness check."""

from __future__ import annotations

import json
import time
from urllib.request import ProxyHandler, build_opener

from .config import load_config
from .systemd_notify import notify

def start_web(cfg):
    if cfg.get('web', {}).get('lightweight'):
        from .lite_server import start_web as start
    else:
        from .web import start_web as start
    return start(cfg)


def health_url(cfg):
    web = cfg["web"]
    host = web.get("host", "0.0.0.0")
    host = "127.0.0.1" if host in {"", "0.0.0.0"} else "::1" if host == "::" else host
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{int(web.get('port', 9110))}/api/healthz"


def probe_web(url, opener=None):
    client = opener or build_opener(ProxyHandler({}))
    with client.open(url, timeout=3) as response:
        if response.status != 200:
            raise RuntimeError(f"Web health probe returned HTTP {response.status}")
        payload = json.load(response)
    if not isinstance(payload, dict) or "ok" not in payload:
        raise RuntimeError("Web health probe returned an invalid response")


def main():
    cfg = load_config()
    if not cfg.get("web", {}).get("enabled", True):
        return 0
    server = start_web(cfg)
    if server is None:
        raise RuntimeError("Web server did not start")
    url = health_url(cfg)
    ready = False
    failures = 0
    try:
        while True:
            if not server.serve_thread.is_alive():
                raise RuntimeError("Web serving thread exited")
            try:
                probe_web(url)
            except Exception as exc:
                failures += 1
                if failures >= 3:
                    raise RuntimeError(f"Web server failed three local probes: {exc}") from exc
            else:
                failures = 0
                if not ready:
                    notify("READY=1\nSTATUS=VA-Connect Watchdog web responding")
                    ready = True
                notify("WATCHDOG=1\nSTATUS=VA-Connect Watchdog web responding")
            time.sleep(5)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
