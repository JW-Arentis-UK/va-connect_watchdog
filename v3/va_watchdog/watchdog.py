#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
import traceback

from .blackbox import check_unexpected_boot, maybe_capture_blackbox
from .config import load_config
from .common import CheckResult, score_from_checks, worst_state
from .events import EventLog
from .health import build_startup_summary, collect_health
from .history import append_history
from .recovery import RecoveryEngine
from .retention import enforce_retention
from .systemd_notify import notify as systemd_notify
from .watchdog_grace import startup_grace_status
from .watchdog_test import trip_test_active
from .web import start_web
from .heartbeat import HeartbeatPublisher
from .reboot_evidence import create as create_reboot_evidence
from .kernel_faults import scan as scan_kernel_faults

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

    startup_grace = feed.get("startup_grace", {}) if isinstance(feed.get("startup_grace", {}), dict) else {}
    if feed.get("trip_test_active"):
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            "Deliberate watchdog trip test active; feed paused for this boot",
            feed,
            False,
        )
    elif startup_grace.get("active"):
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"Hardware watchdog startup safety window active; protection arms in {int(startup_grace.get('remaining_seconds', 0))}s",
            feed,
            False,
        )
    elif not enabled:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"Hardware watchdog present but watchdog feed is disabled for {device}",
            feed,
            False,
        )
    elif not opened:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            f"Watchdog feed enabled but {device} is not opened",
            feed,
            False,
        )
    elif age is None:
        check = CheckResult(
            "hardware_watchdog_feed_status",
            "warning",
            "The watchdog service opened the device, but no feed has been recorded yet",
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
            f"The watchdog service is feeding the hardware watchdog ({int(age)}s ago)",
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


def hardware_feed_status(cfg, startup_grace, trip_active=False, trip_summary=None, fed=False):
    feed_path = Path(cfg.get("hardware_watchdog_feed_state_path") or Path(cfg["events_path"]).parent / "hardware-watchdog-feed.json")
    feed = {}
    try:
        feed = json.loads(feed_path.read_text(encoding="utf-8")) if feed_path.exists() else {}
    except Exception:
        feed = {}
    hw_cfg = cfg.get("hardware_watchdog", {})
    last_feed_unix = feed.get("last_feed_unix")
    try:
        feed_age = round(max(0.0, time.time() - float(last_feed_unix)), 1) if last_feed_unix else None
    except (TypeError, ValueError):
        feed_age = None
    return {
        "enabled": bool(hw_cfg.get("enabled")),
        "device": feed.get("device") or hw_cfg.get("device", "/dev/watchdog0"),
        "opened": feed.get("process_status") in {"running", "feeding", "paused_stale_heartbeat", "paused_trip_test"},
        "last_feed_unix": last_feed_unix,
        "feed_age_seconds": feed_age,
        "last_feed_utc": feed.get("last_feed_utc", ""),
        "feed_count": feed.get("feed_count", 0),
        "timeout_seconds": feed.get("timeout_seconds") or hw_cfg.get("timeout_seconds", 30),
        "feed_process_status": feed.get("process_status", "unknown"),
        "feed_last_error": feed.get("last_error", ""),
        "feed_error_count": feed.get("error_count", 0),
        "stale_heartbeat_seconds": feed.get("stale_heartbeat_seconds") or hw_cfg.get("stale_heartbeat_seconds", 15),
        "fed_this_cycle": fed,
        "trip_test_active": trip_active,
        "trip_test": trip_summary or {},
        "startup_grace": startup_grace,
    }

def main():
    cfg = load_config()
    event_log = EventLog(cfg["events_path"])
    recovery = RecoveryEngine(cfg, event_log)
    last_trip_active = False
    boot_change = check_unexpected_boot(cfg, event_log)
    reboot_evidence = create_reboot_evidence(cfg, boot_change)
    if reboot_evidence and boot_change.get("changed"):
        event_log.add(
            "warning" if reboot_evidence.get("confidence") != "High" else "critical",
            "reboot_evidence",
            f"Previous reboot classified as {reboot_evidence.get('reset_mechanism', 'Unknown')}",
            reboot_evidence,
        )

    event_log.add("info", "watchdog", "VA-Connect Watchdog starting")
    trip_active, trip_summary = trip_test_active(cfg)
    startup_grace = startup_grace_status(cfg, trip_summary)
    if startup_grace.get("active"):
        event_log.add(
            "info",
            "hardware_watchdog",
            f"Hardware watchdog startup safety window active for {startup_grace.get('remaining_seconds', 0)}s",
            startup_grace,
        )

    status, checks = collect_health(cfg)
    status["hardware_watchdog_feed"] = hardware_feed_status(
        cfg,
        startup_grace,
        trip_active=trip_active,
        trip_summary=trip_summary,
    )
    add_hardware_feed_check(status, cfg)
    status["recovery"] = recovery.summary()
    status["boot_change"] = boot_change
    status["reboot_evidence"] = reboot_evidence
    event_log.add(
        "info",
        "watchdog",
        status["startup_summary"]["headline"],
        status["startup_summary"],
    )
    heartbeat = HeartbeatPublisher(cfg)
    heartbeat.mark_health_sample(0, status["hardware_watchdog_feed"].get("last_feed_utc", ""), True, status.get("time"))
    status["heartbeat"] = heartbeat.publish_once()
    atomic_write_json(cfg["status_path"], status)
    append_history(cfg, status)
    maybe_capture_blackbox(cfg, status, force=True)
    heartbeat.start()
    start_web(cfg)
    systemd_notify("READY=1\nSTATUS=VA-Connect Watchdog running")

    health_sequence = 0
    last_kernel_scan = 0.0
    while True:
        try:
            health_sequence += 1
            status, checks = collect_health(cfg)
            event_log.add_state_changes(checks)
            event_log.add_service_resource_changes(checks, cfg)
            event_log.add_recording_storage_change(status.get("recording_storage"))
            recovery.process(checks)
            trip_active, trip_summary = trip_test_active(cfg)
            startup_grace = startup_grace_status(cfg, trip_summary)
            if trip_active and not last_trip_active:
                event_log.add(
                    "warning",
                    "watchdog_test",
                    "Deliberate watchdog trip test active; hardware feed paused for this boot",
                    trip_summary,
                )
            status["hardware_watchdog_feed"] = hardware_feed_status(
                cfg,
                startup_grace,
                trip_active=trip_active,
                trip_summary=trip_summary,
                fed=False,
            )
            add_hardware_feed_check(status, cfg)
            status["recovery"] = recovery.summary()
            if time.time() - last_kernel_scan >= 30:
                status["kernel_faults"] = scan_kernel_faults(cfg, event_log)
                last_kernel_scan = time.time()
            status["blackbox"] = maybe_capture_blackbox(cfg, status)
            heartbeat.mark_health_sample(
                health_sequence,
                status["hardware_watchdog_feed"].get("last_feed_utc", ""),
                True,
                status.get("time"),
            )
            status["heartbeat"] = heartbeat.snapshot()
            atomic_write_json(cfg["status_path"], status)
            append_history(cfg, status)
            retention_result = enforce_retention(cfg)
            if retention_result.get("actions"):
                event_log.add("warning", "retention", "Watchdog data retention purge completed", retention_result)
            systemd_notify("WATCHDOG=1\nSTATUS=VA-Connect Watchdog healthy loop")
            last_trip_active = trip_active
        except Exception as e:
            event_log.add("critical", "watchdog", f"Main loop error: {e}")
            systemd_notify(f"STATUS=VA-Connect Watchdog loop error: {e}")
        time.sleep(int(cfg["poll_interval_seconds"]))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        write_startup_error_log()
        raise
