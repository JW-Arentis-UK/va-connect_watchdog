"""Small, bounded internet speed test used by the web UI."""

import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen


DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=2000000"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
DEFAULT_LATENCY_URL = "https://speed.cloudflare.com/cdn-cgi/trace"


def _mbps(byte_count, elapsed):
    if not elapsed:
        return 0.0
    return round((byte_count * 8.0) / elapsed / 1_000_000.0, 2)


def run_speed_test(
    download_url=DEFAULT_DOWNLOAD_URL,
    upload_url=DEFAULT_UPLOAD_URL,
    latency_url=DEFAULT_LATENCY_URL,
    timeout_seconds=15,
    download_bytes=2_000_000,
    upload_bytes=1_000_000,
    opener=urlopen,
):
    """Run bounded latency, download, and upload checks.

    Each part is independent: a failed internet test still returns the other
    measurements and never raises into the watchdog health loop.
    """
    result = {
        "ok": False,
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "endpoint": "speed.cloudflare.com",
        "latency_ms": None,
        "download_mbps": None,
        "upload_mbps": None,
        "download_bytes": 0,
        "upload_bytes": 0,
        "duration_seconds": 0.0,
        "errors": [],
    }
    started = time.monotonic()

    try:
        request_started = time.monotonic()
        with opener(Request(latency_url, headers={"User-Agent": "VA-Connect-Watchdog"}), timeout=timeout_seconds) as response:
            response.read(256)
        result["latency_ms"] = round((time.monotonic() - request_started) * 1000, 1)
    except Exception as exc:
        result["errors"].append(f"Latency: {exc}")

    try:
        request_started = time.monotonic()
        received = 0
        with opener(Request(download_url, headers={"User-Agent": "VA-Connect-Watchdog"}), timeout=timeout_seconds) as response:
            while received < download_bytes:
                chunk = response.read(min(64 * 1024, download_bytes - received))
                if not chunk:
                    break
                received += len(chunk)
        elapsed = time.monotonic() - request_started
        result["download_bytes"] = received
        if received:
            result["download_mbps"] = _mbps(received, elapsed)
        else:
            result["errors"].append("Download: no data received")
    except Exception as exc:
        result["errors"].append(f"Download: {exc}")

    try:
        payload = b"0" * upload_bytes
        request_started = time.monotonic()
        request = Request(upload_url, data=payload, method="POST", headers={"User-Agent": "VA-Connect-Watchdog"})
        with opener(request, timeout=timeout_seconds) as response:
            response.read(256)
        elapsed = time.monotonic() - request_started
        result["upload_bytes"] = upload_bytes
        result["upload_mbps"] = _mbps(upload_bytes, elapsed)
    except Exception as exc:
        result["errors"].append(f"Upload: {exc}")

    result["duration_seconds"] = round(time.monotonic() - started, 2)
    result["ok"] = bool(result["download_mbps"] is not None or result["upload_mbps"] is not None)
    return result
