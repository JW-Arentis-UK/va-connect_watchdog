from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


def _restore(path: Path, previous: bytes | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    path.write_bytes(previous)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def request_gateway_reboot(cfg: dict[str, Any], delay_seconds: int = 8) -> dict[str, Any]:
    """Record an operator request and schedule a controlled reboot independently."""
    systemd_run = shutil.which("systemd-run")
    systemctl = shutil.which("systemctl")
    if not systemd_run or not systemctl:
        return {
            "ok": False,
            "message": "The controlled reboot tools are unavailable on this gateway.",
            "output": "systemd-run and systemctl are required.",
        }

    reason_path = Path(str(cfg.get("last_reboot_reason_path") or "/var/lib/va-watchdog/last-reboot-reason.json"))
    try:
        previous = reason_path.read_bytes() if reason_path.exists() else None
    except OSError as exc:
        return {"ok": False, "message": "Could not preserve the existing reboot record.", "output": str(exc)}

    requested_at_unix = time.time()
    request_id = secrets.token_hex(8)
    reason = {
        "state": "requested",
        "message": "Manual gateway reboot requested from the watchdog web interface.",
        "requested_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(requested_at_unix)),
        "requested_at_unix": requested_at_unix,
        "requested_by": "watchdog_web",
        "request_id": request_id,
    }
    try:
        _write_json_atomic(reason_path, reason)
    except OSError as exc:
        return {"ok": False, "message": "Could not record the requested reboot.", "output": str(exc)}

    delay_seconds = max(5, min(int(delay_seconds), 60))
    unit_name = f"va-watchdog-manual-reboot-{int(requested_at_unix)}"
    command = [
        systemd_run,
        f"--unit={unit_name}",
        "--collect",
        "--no-block",
        f"--on-active={delay_seconds}s",
        systemctl,
        "reboot",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except Exception as exc:
        _restore(reason_path, previous)
        return {"ok": False, "message": "The controlled reboot could not be scheduled.", "output": str(exc)}

    if result.returncode != 0:
        _restore(reason_path, previous)
        detail = (result.stderr or result.stdout or "systemd-run failed").strip()
        return {"ok": False, "message": "The controlled reboot could not be scheduled.", "output": detail}

    return {
        "ok": True,
        "message": f"Gateway restart requested. The PC will reboot in about {delay_seconds} seconds.",
        "delay_seconds": delay_seconds,
        "requested_at": reason["requested_at"],
        "request_id": request_id,
        "output": (result.stdout or result.stderr or "Controlled reboot scheduled.").strip(),
    }
