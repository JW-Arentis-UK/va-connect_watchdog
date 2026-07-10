from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any, Tuple


def trip_test_path(cfg: dict[str, Any]) -> Path:
    raw = cfg.get("trip_test_path")
    if raw:
        return Path(raw)
    events_path = cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl"
    return Path(events_path).with_name("watchdog-trip-test.json")


def current_boot_id() -> str:
    path = Path("/proc/sys/kernel/random/boot_id")
    try:
        return path.read_text(encoding="utf-8").strip() or "-"
    except Exception:
        return "-"


def read_trip_test_state(cfg: dict[str, Any]) -> dict[str, Any]:
    path = trip_test_path(cfg)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def write_trip_test_state(cfg: dict[str, Any], payload: dict[str, Any]) -> Path:
    path = trip_test_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def arm_trip_test(cfg: dict[str, Any]) -> dict[str, Any]:
    now = time.time()
    state = read_trip_test_state(cfg)
    token = secrets.token_urlsafe(18)
    state["armed"] = {
        "token": token,
        "armed_at_unix": now,
        "expires_at_unix": now + 300,
        "armed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
    }
    state["triggered"] = False
    state["triggered_at_unix"] = None
    state["triggered_at"] = ""
    state["triggered_boot_id"] = ""
    state["last_result"] = {
        "ok": False,
        "message": "Trip test armed",
        "tested_at": "",
    }
    write_trip_test_state(cfg, state)
    return {
        "token": token,
        "armed_at": state["armed"]["armed_at"],
        "expires_at_unix": state["armed"]["expires_at_unix"],
    }


def confirm_trip_test(cfg: dict[str, Any], token: str, ack_risk: bool, confirm_phrase: str) -> dict[str, Any]:
    now = time.time()
    state = read_trip_test_state(cfg)
    armed = state.get("armed", {}) if isinstance(state.get("armed", {}), dict) else {}
    confirm_phrase = str(confirm_phrase or "").strip().upper()
    if not armed.get("token"):
        return {
            "ok": False,
            "message": "Trip test confirmation failed: arm the test first.",
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        }
    if now > float(armed.get("expires_at_unix", 0) or 0):
        return {
            "ok": False,
            "message": "Trip test confirmation expired. Arm the test again.",
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        }
    if not ack_risk:
        return {
            "ok": False,
            "message": "Trip test confirmation failed: the risk checkbox was not checked.",
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        }
    if confirm_phrase != "TRIP":
        return {
            "ok": False,
            "message": "Trip test confirmation failed: type TRIP to continue.",
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        }

    boot_id = current_boot_id()
    state["armed"] = {}
    state["triggered"] = True
    state["triggered_at_unix"] = now
    state["triggered_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    state["triggered_boot_id"] = boot_id
    result = {
        "ok": True,
        "message": "Trip test confirmed: watchdog feed paused for this boot. The gateway should reboot if the hardware watchdog is healthy.",
        "tested_at": state["triggered_at"],
        "triggered_boot_id": boot_id,
    }
    state["last_result"] = result
    write_trip_test_state(cfg, state)
    return result


def trip_test_summary(cfg: dict[str, Any]) -> dict[str, Any]:
    state = read_trip_test_state(cfg)
    armed = state.get("armed", {}) if isinstance(state.get("armed", {}), dict) else {}
    boot_id = current_boot_id()
    triggered = bool(state.get("triggered")) and str(state.get("triggered_boot_id", "")) == boot_id
    completed_previous_boot = bool(state.get("triggered")) and str(state.get("triggered_boot_id", "")) not in ("", boot_id)
    last = state.get("last_result", {}) if isinstance(state.get("last_result", {}), dict) else {}
    return {
        "armed": bool(armed),
        "armed_at": armed.get("armed_at", ""),
        "expires_at_unix": armed.get("expires_at_unix"),
        "armed_token_present": bool(armed.get("token")),
        "triggered": triggered,
        "triggered_boot_id": state.get("triggered_boot_id", ""),
        "completed_previous_boot": completed_previous_boot,
        "last_result": last,
        "last_result_message": last.get("message", ""),
        "last_result_time": last.get("tested_at", ""),
        "boot_id": boot_id,
    }


def trip_test_active(cfg: dict[str, Any]) -> Tuple[bool, dict[str, Any]]:
    summary = trip_test_summary(cfg)
    return bool(summary.get("triggered")), summary
