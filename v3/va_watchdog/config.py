from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "identity": {
        "site_name": "",
        "asset_id": ""
    },
    "poll_interval_seconds": 5,
    "heartbeat_interval_seconds": 5,
    "collector_intervals": {
        "hardware_seconds": 5,
        "services_seconds": 15,
        "storage_seconds": 30,
        "network_seconds": 30,
        "router_seconds": 60,
        "process_seconds": 5
    },
    "status_path": "/var/lib/va-watchdog/status.json",
    "events_path": "/var/lib/va-watchdog/events.jsonl",
    "history_path": "/var/lib/va-watchdog/history.jsonl",
    "last_reboot_reason_path": "/var/lib/va-watchdog/last-reboot-reason.json",
    "heartbeat_state_path": "/var/lib/va-watchdog/heartbeat-state.json",
    "heartbeat_path": "/var/lib/va-watchdog/heartbeat.jsonl",
    "reboot_evidence_path": "/var/lib/va-watchdog/reboot-evidence.jsonl",
    "kernel_fault_state_path": "/var/lib/va-watchdog/kernel-fault-state.json",
    "hardware_watchdog_feed_state_path": "/var/lib/va-watchdog/hardware-watchdog-feed.json",
    "hardware_watchdog_previous_state_path": "/var/lib/va-watchdog/hardware-watchdog-feed-previous.json",
    "hardware_watchdog_lifecycle_path": "/var/lib/va-watchdog/hardware-watchdog-lifecycle.jsonl",
    "hardware_watchdog_proof_path": "/var/lib/va-watchdog/hardware-watchdog-proof.json",
    "hardware_watchdog_lock_path": "/var/lib/va-watchdog/hardware-watchdog.lock",
    "blackbox": {
        "enabled": True,
        "path": "/var/lib/va-watchdog/blackbox.jsonl",
        "segment_dir": "/var/lib/va-watchdog/blackbox-buffer",
        "state_path": "/var/lib/va-watchdog/blackbox-state.json",
        "interval_seconds": 2,
        "retention_seconds": 900,
        "checkpoint_seconds": 10,
        "main_service": "esg.service",
        "max_kernel_records_per_sample": 256
    },
    "incident_archive": {
        "enabled": True,
        "path": "/var/lib/va-watchdog/incidents",
        "max_incidents": 10,
        "max_total_mb": 25,
        "event_tail_rows": 1000,
        "pstore_file_max_mb": 5
    },
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 9110
    },
    "hardware_watchdog": {
        "enabled": False,
        "backend": "neousys_wdt_dio",
        "device": "/dev/wdt_dio",
        "library_path": "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
        "feed_interval_seconds": 10,
        "timeout_seconds": 30,
        "stale_heartbeat_seconds": 15,
        "health_progress_timeout_seconds": 90,
        "proof_feed_count": 3,
        "liveness_test_fallback_seconds": 75,
        "device_retry_seconds": 60,
        "magic_close": False,
        "startup_grace_seconds": 300,
        "post_trip_grace_seconds": 900,
        "lifecycle_checkpoint_seconds": 60,
        "lifecycle_max_bytes": 1048576
    },
    "hardware_watchdog_control_path": "/var/lib/va-watchdog/hardware-watchdog-control.json",
    "trip_test_path": "/var/lib/va-watchdog/watchdog-trip-test.json",
    "liveness_test_path": "/var/lib/va-watchdog/watchdog-liveness-test.json",
    "process_monitor": {
        "enabled": True,
        "cpu_warning_percent": 25,
        "cpu_critical_percent": 75,
        "memory_warning_mb": 100,
        "memory_critical_mb": 200,
        "warning_sustained_seconds": 60,
        "sustained_seconds": 300
    },
    "service_resource_limits": {
        "cpu_warning_percent": 80,
        "cpu_critical_percent": 95,
        "cpu_system_warning_percent": 60,
        "cpu_system_critical_percent": 85,
        "memory_warning_mb": 512,
        "memory_critical_mb": 1024,
        "warning_sustained_seconds": 120,
        "critical_sustained_seconds": 60,
        "recovery_sustained_seconds": 60,
        "cpu_recovery_hysteresis_percent": 5
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
        {"name": "sysops.service", "critical": True, "restart": True},
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
        "mode": "dedicated_mount",
        "directory_path": "",
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
        "expected_full": False,
        "minimum_free_mb_warning": 5000,
        "minimum_free_mb_critical": 2048,
        "warning_sustained_seconds": 120,
        "warning_recovery_margin_mb": 256,
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
    "mobile_router": {
        "enabled": False,
        "address": "",
        "port": 502,
        "unit_id": 1,
        "timeout_seconds": 2,
        "poll_interval_seconds": 60,
        "snmp_enabled": False,
        "snmp_port": 161,
        "snmp_community": ""
    },
    "people_counting": {
        "event_collection_enabled": False,
        "event_transport": "isapi",
        "push_receiver_address": "",
        "push_slot": 1,
        "address": "",
        "scheme": "http",
        "port": 80,
        "channel": 1,
        "username": "",
        "password": "",
        "forward_label": "A to B",
        "back_label": "B to A",
        "stale_after_minutes": 10,
        "anomaly_threshold_percent": 50,
        "timeout_seconds": 5,
        "counter_poll_interval_seconds": 30
    },
    "web_links": [],
    "retention": {
        "max_total_mb": 100,
        "events_retention_days": 30,
        "history_retention_days": 30,
        "history_sample_seconds": 60,
        "history_max_rows": 50000,
        "exports_retention_days": 14,
        "heartbeat_max_rows": 3600,
        "heartbeat_max_mb": 5
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

def _migrate_default_videosoft_services(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Add sysops to the original three-service V3 baseline without changing custom lists."""
    services = cfg.get("services", [])
    if not isinstance(services, list):
        return cfg
    names = {
        str(item.get("name", "")).strip()
        for item in services
        if isinstance(item, dict)
    }
    original_defaults = {"esg.service", "bridge.service", "esg-config.service"}
    if original_defaults.issubset(names) and "sysops.service" not in names:
        cfg = dict(cfg)
        cfg["services"] = [*services, {"name": "sysops.service", "critical": True, "restart": True}]
    return cfg


def _enforce_neousys_watchdog(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """This test build has one hardware backend and cannot fall back to alternatives."""
    cfg = dict(cfg)
    hardware = dict(cfg.get("hardware_watchdog", {}))
    migrating_backend = hardware.get("backend") != "neousys_wdt_dio"
    hardware.update({
        "backend": "neousys_wdt_dio",
        "device": "/dev/wdt_dio",
        "library_path": "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
        "magic_close": False,
    })
    if migrating_backend:
        hardware["enabled"] = False
    cfg["hardware_watchdog"] = hardware
    return cfg


def _enforce_recording_free_space_reserve(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Apply the field-safe reserve to older configs that stored null thresholds."""
    cfg = dict(cfg)
    recording = dict(cfg.get("recording_storage", {}))
    if recording.get("minimum_free_mb_warning") in (None, ""):
        recording["minimum_free_mb_warning"] = 5000
    if recording.get("minimum_free_mb_critical") in (None, ""):
        recording["minimum_free_mb_critical"] = 2048
    cfg["recording_storage"] = recording
    return cfg

def load_config() -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG
    for path in CONFIG_PATHS:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                cfg = deep_merge(cfg, json.load(f))
            break
    cfg = _migrate_default_videosoft_services(cfg)
    cfg = _enforce_neousys_watchdog(cfg)
    return _enforce_recording_free_space_reserve(cfg)

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
