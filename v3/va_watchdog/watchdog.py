#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
import traceback

from .config import load_config
from .common import CheckResult, score_from_checks, worst_state
from .events import EventLog
from .health import build_startup_summary, collect_health
from .history import append_history
from .recovery import RecoveryEngine
from .retention import enforce_retention
from .systemd_notify import notify as systemd_notify
from .watchdog_device import HardwareWatchdog
from .watchdog_test import trip_test_active
from .web import start_web

def atomic_write_json(path: str, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)

def write_startup_error_log():
    payload = traceback.format_exc()
    try:
        sys.stderr.write(payload + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    try:
        Path("/tmp/va-watchdog-startup-error.log").write_text(payload + "\n", encoding="utf-8")
    except Exception:
        pass

def add_hardware_feed_check(status, cfg):
    feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
    hw_cfg = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog", {}), dict) else {}
    enabled = bool(feed.get("enabled") or hw_cfg.get("enabled"))
    opened = bool(feed.get("opened"))
    device = str(feed.get("device") or hw_cfg.get("device") or "/dev/watchdog0")
    feed_interval = int(hw_cfg.get("feed_interval_seconds", 10) or 10)
    poll_interval = int(cfg.get("poll_interval_seconds", 5) or 5)
    stale_after = max(feed_interval * 3, poll_interval * 3, 30)
    last_feed = feed.get("last_feed_unix")
    age = None
    if last_feed:
        try:
            age = max(0, time.time() - float(last_feed))
        except (TypeError, ValueError):
            age = None

    if feed.get("trip_test_active"):
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            "Deliberate watchdog trip test active; feed paused for this boot",
            feed,
            False,
        )
    elif not enabled:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"Hardware watchdog present but V3 feed is disabled for {device}",
            feed,
            False,
        )
    elif not opened:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"V3 feed enabled but {device} is not opened",
            feed,
            False,
        )
    elif age is None:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            "V3 opened the watchdog, but no feed has been recorded yet",
            feed,
            False,
        )
    elif age > stale_after:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"Last hardware watchdog feed is stale ({int(age)}s ago)",
            feed,
            False,
        )
    else:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "healthy",
            f"V3 is feeding the hardware watchdog ({int(age)}s ago)",
            feed,
            False,
        )

    checks = [CheckResult(**item) for item in status.get("checks", []) if item.get("name") != check.name]
    checks.append(check)
    status["checks"] = [item.to_dict() for item in checks]
    status["state"] = worst_state([item.state for item in checks])
    status["score"] = score_from_checks(checks)
    status["critical_failed"] = any(item.state == "critical" and item.critical for item in checks)
    status["startup_summary"] = build_startup_summary(cfg, checks)
    return status

def main():
    cfg = load_config()
    event_log = EventLog(cfg["events_path"])
    recovery = RecoveryEngine(cfg, event_log)
    last_trip_active = False

    hw = HardwareWatchdog(
        enabled=cfg["hardware_watchdog"]["enabled"],
        device=cfg["hardware_watchdog"]["device"],
        feed_interval=cfg["hardware_watchdog"]["feed_interval_seconds"],
        event_log=event_log,
        timeout_seconds=cfg["hardware_watchdog"].get("timeout_seconds", 30),
    )

    event_log.add("info", "watchdog", "VA-Connect Watchdog V3 starting")
    hw.open()

    status, checks = collect_health(cfg)
    status["hardware_watchdog_feed"] = {
        "enabled": hw.enabled,
        "device": hw.device,
        "opened": hw.opened,
        "last_feed_unix": hw.last_feed,
        "feed_count": hw.feed_count,
        "timeout_seconds": hw.get_timeout(),
        "fed_this_cycle": False
    }
    add_hardware_feed_check(status, cfg)
    status["recovery"] = recovery.summary()
    event_log.add(
        "info",
        "watchdog",
        status["startup_summary"]["headline"],
        status["startup_summary"],
    )
    atomic_write_json(cfg["status_path"], status)
    append_history(cfg, status)
    start_web(cfg)
    systemd_notify("READY=1\nSTATUS=VA-Connect Watchdog V3 running")

    while True:
        try:
            status, checks = collect_health(cfg)
            event_log.add_state_changes(checks)
            event_log.add_recording_storage_change(status.get("recording_storage"))
            recovery.process(checks)
            trip_active, trip_summary = trip_test_active(cfg)
            if trip_active and not last_trip_active:
                event_log.add(
                    "warning",
                    "watchdog_test",
                    "Deliberate watchdog trip test active; hardware feed paused for this boot",
                    trip_summary,
                )
            feed_allowed = not status["critical_failed"] and not trip_active
            fed = hw.feed_if_due(feed_allowed)
            status["hardware_watchdog_feed"] = {
                "enabled": hw.enabled,
                "device": hw.device,
                "opened": hw.opened,
                "last_feed_unix": hw.last_feed,
                "feed_count": hw.feed_count,
                "timeout_seconds": hw.get_timeout(),
                "fed_this_cycle": fed,
                "trip_test_active": trip_active,
                "trip_test": trip_summary,
            }
            add_hardware_feed_check(status, cfg)
            status["recovery"] = recovery.summary()
            atomic_write_json(cfg["status_path"], status)
            append_history(cfg, status)
            retention_result = enforce_retention(cfg)
            if retention_result.get("actions"):
                event_log.add("warning", "retention", "Watchdog data retention purge completed", retention_result)
            systemd_notify("WATCHDOG=1\nSTATUS=VA-Connect Watchdog V3 healthy loop")
            last_trip_active = trip_active
        except Exception as e:
            event_log.add("critical", "watchdog", f"Main loop error: {e}")
            systemd_notify(f"STATUS=VA-Connect Watchdog V3 loop error: {e}")
        time.sleep(int(cfg["poll_interval_seconds"]))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        write_startup_error_log()
        raise
