from __future__ import annotations

import socket
import subprocess
from urllib.parse import urlparse

from .common import CheckResult


def check_network(cfg):
    network_cfg = cfg.get("network", {})
    targets = list(network_cfg.get("internet_hosts", [])) + list(network_cfg.get("local_targets", []))
    if not targets:
        return [CheckResult("network_module", "healthy", "Network checks not configured yet", None, False)]

    results = []
    for target in targets[:8]:
        parsed = _parse_target(str(target))
        ping = _ping(parsed["host"])
        tcp = _tcp(parsed["host"], parsed["port"]) if parsed["port"] else None
        ok = ping["ok"] if tcp is None else tcp["ok"]
        results.append(
            {
                "target": target,
                "host": parsed["host"],
                "port": parsed["port"],
                "ping_ok": ping["ok"],
                "tcp_ok": tcp["ok"] if tcp else None,
                "ok": ok,
                "detail": tcp["detail"] if tcp else ping["detail"],
            }
        )

    failed = [item for item in results if not item["ok"]]
    if failed:
        return [
            CheckResult(
                "network_module",
                "warning",
                f"{len(failed)} of {len(results)} configured network targets failed",
                {"targets": results},
                False,
            )
        ]
    return [
        CheckResult(
            "network_module",
            "healthy",
            f"{len(results)} configured network targets reachable",
            {"targets": results},
            False,
        )
    ]


def _parse_target(target: str):
    text = target.strip()
    port = None
    host = text
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname or text
        port = parsed.port
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443
    elif ":" in text and text.count(":") == 1:
        maybe_host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = int(maybe_port)
    return {"host": host, "port": port}


def _ping(host: str):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", host],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        detail = result.stdout.strip() or result.stderr.strip()
        return {"ok": result.returncode == 0, "detail": detail.splitlines()[-1] if detail else ""}
    except Exception as exc:
        return {"ok": False, "detail": str(exc)}


def _tcp(host: str, port: int):
    try:
        with socket.create_connection((host, int(port)), timeout=1.5):
            return {"ok": True, "detail": f"TCP {host}:{port} connected"}
    except Exception as exc:
        return {"ok": False, "detail": f"TCP {host}:{port} failed: {exc}"}
