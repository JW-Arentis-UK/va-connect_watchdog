#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
import traceback

from .config import load_config
from .events import EventLog
from .health import collect_health
from .history import append_history
from .recovery import RecoveryEngine
from .retention import enforce_retention
from .systemd_notify import notify as systemd_notify
from .watchdog_device import HardwareWatchdog
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

def main():
    cfg = load_config()
    event_log = EventLog(cfg["events_path"])
    recovery = RecoveryEngine(cfg, event_log)

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
            recovery.process(checks)
            fed = hw.feed_if_due(not status["critical_failed"])
            status["hardware_watchdog_feed"] = {
                "enabled": hw.enabled,
                "device": hw.device,
                "opened": hw.opened,
                "last_feed_unix": hw.last_feed,
                "feed_count": hw.feed_count,
                "timeout_seconds": hw.get_timeout(),
                "fed_this_cycle": fed
            }
            status["recovery"] = recovery.summary()
            atomic_write_json(cfg["status_path"], status)
            append_history(cfg, status)
            retention_result = enforce_retention(cfg)
            if retention_result.get("actions"):
                event_log.add("warning", "retention", "Watchdog data retention purge completed", retention_result)
            systemd_notify("WATCHDOG=1\nSTATUS=VA-Connect Watchdog V3 healthy loop")
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
