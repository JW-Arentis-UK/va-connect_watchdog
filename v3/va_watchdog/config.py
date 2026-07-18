from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "poll_interval_seconds": 5,
    "status_path": "/var/lib/va-watchdog/status.json",
    "events_path": "/var/lib/va-watchdog/events.jsonl",
    "history_path": "/var/lib/va-watchdog/history.jsonl",
    "last_reboot_reason_path": "/var/lib/va-watchdog/last-reboot-reason.json",
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 9110
    },
    "hardware_watchdog": {
        "enabled": False,
        "device": "/dev/watchdog0",
        "feed_interval_seconds": 10,
        "timeout_seconds": 30
    },
    "trip_test_path": "/var/lib/va-watchdog/watchdog-trip-test.json",
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
        "write_test_path": "/tmp",
        "monitored_paths": [
            {
                "name": "Root Disk",
                "path": "/",
                "warning_percent": 80,
                "critical_percent": 95,
                "always_full_expected": False
            },
            {
                "name": "Recordings Disk",
                "path": "/home/vsuser/recordings",
                "warning_percent": 85,
                "critical_percent": 95,
                "always_full_expected": False
            }
        ]
    },
    "recording_storage": {
        "enabled": True,
        "expected_label": "CCTV_STORAGE",
        "mountpoint": "/media/vsuser/Storage",
        "filesystem": "ext4",
        "fstab_options": "defaults,nofail,x-systemd.device-timeout=5",
        "recording_subdir": "recordings",
        "owner": "vsuser",
        "group": "",
        "directory_mode": "775",
        "minimum_candidate_gb": 10,
        "used_warning_percent": None,
        "used_critical_percent": None,
        "free_warning_percent": None,
        "free_warning_enabled": False,
        "temperature_warning_c": 55,
        "recording_services": []
    },
    "recovery": {
        "enabled": False,
        "restart_failed_services": False,
        "restart_noncritical_services": False,
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
    },
    "network": {
        "internet_hosts": ["1.1.1.1", "8.8.8.8"],
        "local_targets": [],
        "remote_access_services": ["teamviewerd"]
    },
    "retention": {
        "max_total_mb": 100,
        "events_retention_days": 30,
        "history_retention_days": 30,
        "history_sample_seconds": 60,
        "history_max_rows": 50000,
        "exports_retention_days": 14
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

def active_config_path() -> Path:
    for path in CONFIG_PATHS:
        if path.exists():
            return path
    return CONFIG_PATHS[0]

def load_raw_config() -> Dict[str, Any]:
    path = active_config_path()
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
            return payload if isinstance(payload, dict) else {}
    return {}

def save_raw_config(payload: Dict[str, Any]) -> Path:
    path = active_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        shutil.copy2(path, path.with_name(f"{path.name}.{stamp}.bak"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path
