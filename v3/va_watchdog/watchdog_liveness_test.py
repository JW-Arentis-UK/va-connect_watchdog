from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from .watchdog_grace import startup_grace_status
from .watchdog_test import current_boot_id, trip_test_summary


def liveness_test_path(cfg: dict[str, Any]) -> Path:
    data_dir = Path(cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl").parent
    return Path(cfg.get("liveness_test_path") or data_dir / "watchdog-liveness-test.json")


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_liveness_test_state(cfg: dict[str, Any]) -> dict[str, Any]:
    return _read(liveness_test_path(cfg))


def confirmed_for_boot(state: dict[str, Any], previous_boot_id: str) -> dict[str, Any]:
    if not previous_boot_id or str(state.get("triggered_boot_id") or "") != previous_boot_id:
        return {}
    if not state.get("active") and not state.get("completed"):
        return {}
    return {
        "confirmed": True,
        "triggered_boot_id": previous_boot_id,
        "triggered_at": state.get("triggered_at", ""),
        "message": state.get("message", "Full liveness test requested"),
    }


def reconcile_liveness_test(cfg: dict[str, Any]) -> dict[str, Any]:
    path = liveness_test_path(cfg)
    state = _read(path)
    if not state.get("active"):
        return state
    boot_id = current_boot_id()
    triggered_boot = str(state.get("triggered_boot_id") or "")
    now = time.time()
    if triggered_boot and triggered_boot != boot_id:
        state.update({
            "active": False,
            "completed": True,
            "ok": True,
            "completed_at_unix": now,
            "completed_boot_id": boot_id,
            "message": "Full liveness test completed: stale heartbeat led to a new boot.",
        })
        _write(path, state)
    elif now >= float(state.get("fail_after_unix") or 0):
        state.update({
            "active": False,
            "completed": True,
            "ok": False,
            "completed_at_unix": now,
            "completed_boot_id": boot_id,
            "message": "Full liveness test failed safely: the fallback restarted the main monitor on the same boot.",
        })
        _write(path, state)
    return state


def start_liveness_test(cfg: dict[str, Any], acknowledged: bool) -> dict[str, Any]:
    if not acknowledged:
        return {"ok": False, "message": "Confirm that the gateway may reboot before starting the test."}

    boot_id = current_boot_id()
    grace = startup_grace_status(cfg, trip_test_summary(cfg))
    if grace.get("active"):
        return {"ok": False, "message": "End the startup safety delay before testing the full liveness path."}
    state = reconcile_liveness_test(cfg)
    if state.get("active") and state.get("triggered_boot_id") == boot_id:
        return {"ok": False, "message": "A full liveness test is already active on this boot."}

    data_dir = Path(cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl").parent
    proof = _read(Path(cfg.get("hardware_watchdog_proof_path") or data_dir / "hardware-watchdog-proof.json"))
    feed = _read(Path(cfg.get("hardware_watchdog_feed_state_path") or data_dir / "hardware-watchdog-feed.json"))
    if not (proof.get("proven") and proof.get("boot_id") == boot_id):
        return {"ok": False, "message": "Protection has not been proven on this boot; run the hardware trip test first."}
    try:
        feed_age = max(0.0, time.time() - float(feed.get("last_feed_unix") or 0))
    except (TypeError, ValueError):
        feed_age = 999999.0
    if feed.get("process_status") != "feeding" or feed_age > 30:
        return {"ok": False, "message": "The hardware feed is not currently fresh; the full liveness test was not started."}

    hw_cfg = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog"), dict) else {}
    stale = max(5, int(hw_cfg.get("stale_heartbeat_seconds", 15) or 15))
    timeout = max(5, int(hw_cfg.get("timeout_seconds", 30) or 30))
    fallback = max(stale + timeout + 30, int(hw_cfg.get("liveness_test_fallback_seconds", 75) or 75))
    now = time.time()
    unit = f"va-watchdog-liveness-test-{int(now)}"
    command = [
        "systemd-run",
        "--unit", unit,
        "--on-active=3s",
        "--collect",
        "/bin/bash",
        "-c",
        f"systemctl stop va-watchdog.service; sleep {fallback}; systemctl start va-watchdog.service",
    ]
    state = {
        "active": True,
        "completed": False,
        "ok": None,
        "triggered_boot_id": boot_id,
        "triggered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "triggered_at_unix": now,
        "expected_stale_seconds": stale,
        "hardware_timeout_seconds": timeout,
        "fallback_seconds": fallback,
        "fail_after_unix": now + fallback + 2,
        "systemd_unit": unit,
        "message": "Full liveness test is being scheduled.",
    }
    try:
        _write(liveness_test_path(cfg), state)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        state.update({"active": False, "completed": True, "ok": False, "message": str(exc)})
        try:
            _write(liveness_test_path(cfg), state)
        except OSError:
            pass
        return {"ok": False, "message": f"Could not schedule the full liveness test: {exc}"}
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "systemd-run failed").strip()
        state.update({"active": False, "completed": True, "ok": False, "message": message})
        _write(liveness_test_path(cfg), state)
        return {"ok": False, "message": f"Could not schedule the full liveness test: {message}"}

    state["message"] = "Full liveness test scheduled: the main monitor will stop, then stale-heartbeat enforcement should allow the Neousys watchdog to reboot the gateway."
    _write(liveness_test_path(cfg), state)
    return {**state, "ok": True}
