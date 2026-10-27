"""Prevent saved observations from an earlier boot looking like live health."""
from datetime import datetime, timezone

from .watchdog_test import current_boot_id


def status_boot_id(status):
    for payload, key in ((status, "boot_id"), (status.get("heartbeat"), "boot_id"),
                         (status.get("blackbox"), "last_boot_id")):
        value = payload.get(key) if isinstance(payload, dict) else None
        if value and value != "-":
            return str(value)
    return ""


def freshness(cfg, status, now=None, max_age=None):
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    boot = current_boot_id()
    observed_boot = status_boot_id(status)
    same_boot = observed_boot == boot if boot not in {"", "-"} else None
    try:
        stamp = datetime.fromisoformat(str(status.get("time", "")).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("Status timestamp has no timezone")
        age = now - stamp.timestamp()
    except (ValueError, TypeError, OverflowError):
        age = None
    limit = max_age if max_age is not None else max(30, int(cfg.get("poll_interval_seconds", 5)) * 4)
    fresh = age is not None and -5 <= age <= limit and same_boot is not False
    return {"status_fresh": fresh, "status_current_boot": same_boot,
            "status_age_seconds": round(max(0, age), 1) if age is not None else None,
            "boot_id": observed_boot, "current_boot_id": boot}


def status_view(cfg, status):
    result = {**status, **freshness(cfg, status)}
    result["recorded_state"] = status.get("state", "unknown")
    if not result["status_fresh"]:
        result["state"] = "unknown"
        result["checks"] = [{**check, "recorded_state": check.get("state"), "state": "unknown",
                             "message": "Saved result; current health is not confirmed"}
                            for check in status.get("checks", []) if isinstance(check, dict)]
    return result
