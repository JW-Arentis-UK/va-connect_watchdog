from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

from .watchdog_test import current_boot_id


def control_path(cfg: dict[str, Any]) -> Path:
    raw = cfg.get("hardware_watchdog_control_path")
    if raw:
        return Path(raw)
    events_path = cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl"
    return Path(events_path).with_name("hardware-watchdog-control.json")


def system_uptime_seconds() -> float:
    try:
        return max(0.0, float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]))
    except Exception:
        return max(0.0, time.monotonic())


def _read_state(cfg: dict[str, Any]) -> dict[str, Any]:
    path = control_path(cfg)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _write_state(cfg: dict[str, Any], payload: dict[str, Any]) -> Path:
    path = control_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def _seconds(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def startup_grace_status(
    cfg: dict[str, Any],
    trip_summary: dict[str, Any] | None = None,
    now: float | None = None,
    uptime_seconds: float | None = None,
) -> dict[str, Any]:
    now = time.time() if now is None else float(now)
    uptime = system_uptime_seconds() if uptime_seconds is None else max(0.0, float(uptime_seconds))
    boot_id = current_boot_id()
    hw_cfg = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog", {}), dict) else {}
    normal_seconds = _seconds(hw_cfg.get("startup_grace_seconds"), 300)
    post_trip_seconds = _seconds(hw_cfg.get("post_trip_grace_seconds"), 900)
    state = _read_state(cfg)
    same_boot = str(state.get("boot_id", "")) == boot_id

    trip = trip_summary if isinstance(trip_summary, dict) else {}
    source_trip_boot_id = str(trip.get("triggered_boot_id", "") or "")
    completed_trip = bool(trip.get("completed_previous_boot")) and bool(source_trip_boot_id)
    post_trip_boot = (
        str(state.get("post_trip_grace_boot_id", "")) == boot_id
        and bool(state.get("post_trip_source_boot_id"))
    )
    if completed_trip:
        if (
            str(state.get("post_trip_grace_boot_id", "")) == boot_id
            and str(state.get("post_trip_source_boot_id", "")) == source_trip_boot_id
        ):
            post_trip_boot = True
        elif str(state.get("last_consumed_trip_boot_id", "")) != source_trip_boot_id:
            post_trip_boot = True
            state.update({
                "post_trip_grace_boot_id": boot_id,
                "post_trip_source_boot_id": source_trip_boot_id,
                "last_consumed_trip_boot_id": source_trip_boot_id,
            })
            try:
                _write_state(cfg, state)
            except OSError:
                pass

    configured_seconds = post_trip_seconds if post_trip_boot else normal_seconds
    base_remaining = max(0.0, configured_seconds - uptime)
    arm_now = same_boot and bool(state.get("arm_now"))
    manual_until = float(state.get("manual_delay_until_unix", 0) or 0) if same_boot else 0.0
    manual_remaining = max(0.0, manual_until - now)
    remaining = 0.0 if arm_now else max(base_remaining, manual_remaining)
    active = bool(hw_cfg.get("enabled")) and remaining > 0

    if arm_now:
        reason = "armed manually"
    elif manual_remaining >= base_remaining and manual_remaining > 0:
        reason = "manual safety extension"
    elif post_trip_boot and base_remaining > 0:
        reason = "post-trip reboot safety window"
    elif base_remaining > 0:
        reason = "normal boot safety window"
    elif hw_cfg.get("enabled"):
        reason = "startup safety window complete"
    else:
        reason = "hardware feed disabled"

    remaining_seconds = int(math.ceil(remaining))
    return {
        "active": active,
        "reason": reason,
        "remaining_seconds": remaining_seconds,
        "opens_at_unix": now + remaining_seconds if active else None,
        "normal_grace_seconds": normal_seconds,
        "post_trip_grace_seconds": post_trip_seconds,
        "post_trip_boot": post_trip_boot,
        "manual_delay_until_unix": manual_until or None,
        "arm_now": arm_now,
        "system_uptime_seconds": int(uptime),
        "boot_id": boot_id,
        "control_path": str(control_path(cfg)),
    }


def delay_current_boot(cfg: dict[str, Any], delay_seconds: int = 900, extend: bool = True) -> dict[str, Any]:
    delay_seconds = min(86400, max(60, int(delay_seconds)))
    now = time.time()
    current_remaining = startup_grace_status(cfg, now=now).get("remaining_seconds", 0) if extend else 0
    delay_until = min(now + 86400, now + int(current_remaining or 0) + delay_seconds)
    state = _read_state(cfg)
    state.update({
        "boot_id": current_boot_id(),
        "arm_now": False,
        "manual_delay_until_unix": delay_until,
        "manual_delay_seconds": delay_seconds,
    })
    _write_state(cfg, state)
    return startup_grace_status(cfg)


def arm_current_boot(cfg: dict[str, Any]) -> dict[str, Any]:
    state = _read_state(cfg)
    state.update({
        "boot_id": current_boot_id(),
        "arm_now": True,
        "manual_delay_until_unix": 0,
        "manual_delay_seconds": 0,
    })
    _write_state(cfg, state)
    return startup_grace_status(cfg)
