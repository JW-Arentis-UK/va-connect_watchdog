from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "poll_interval_seconds": 5,
    "status_path": "/var/lib/va-watchdog/status.json",
    "events_path": "/var/lib/va-watchdog/events.jsonl",
    "last_reboot_reason_path": "/var/lib/va-watchdog/last-reboot-reason.json",
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 9110
    },
    "hardware_watchdog": {
        "enabled": False,
        "device": "/dev/watchdog0",
        "feed_interval_seconds": 10
    },
    "thresholds": {
        "cpu_temp_warning_c": 75,
        "cpu_temp_critical_c": 90,
        "ram_warning_percent": 85,
        "ram_critical_percent": 95,
        "root_disk_warning_percent": 80,
        "root_disk_critical_percent": 95,
        "recordings_disk_warning_percent": 85,
        "recordings_disk_critical_percent": 95
    },
    "services": [
        {"name": "esg.service", "critical": True, "restart": True},
        {"name": "bridge.service", "critical": True, "restart": True},
        {"name": "esg-config.service", "critical": False, "restart": True}
    ],
    "storage": {
        "root_path": "/",
        "recordings_path": "/home/vsuser/recordings",
        "write_test_path": "/tmp"
    },
    "recovery": {
        "enabled": False,
        "restart_failed_services": False,
        "max_restart_attempts": 3,
        "critical_grace_seconds": 60,
        "allow_reboot": False
    },
    "update": {
        "enabled": True,
        "remote": "origin",
        "branch": "",
        "state_path": "/var/lib/va-watchdog/update-state.json",
        "log_path": "/var/lib/va-watchdog/update.log"
    }
}

CONFIG_PATHS = [
    Path("/etc/va-watchdog/config.json"),
    Path("./config.json"),
]

def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out

def load_config() -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG
    for path in CONFIG_PATHS:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                cfg = deep_merge(cfg, json.load(f))
            break
    return cfg
