from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


MANAGED_CONFIG = Path("/etc/systemd/journald.conf.d/va-watchdog-persistent.conf")
SAFE_SYSTEM_MAX_USE_BYTES = 512 * 1024 * 1024


def _run(command, timeout=10):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": result.returncode == 0, "stdout": result.stdout.strip(), "stderr": result.stderr.strip(), "returncode": result.returncode}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}


def _size_bytes(value: Any) -> int | None:
    text = str(value or "").strip().upper()
    if not text or text == "SYSTEM DEFAULT":
        return None
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    suffix = text[-1]
    multiplier = multipliers.get(suffix, 1)
    number = text[:-1] if suffix in multipliers else text
    try:
        return int(float(number) * multiplier)
    except (TypeError, ValueError):
        return None


def persistent_status() -> dict[str, Any]:
    journal_dir = Path("/var/log/journal")
    show = _run(["journalctl", "--disk-usage"], timeout=5)
    storage = _run(["systemctl", "show", "systemd-journald", "-p", "LoadState", "-p", "ActiveState"], timeout=5)
    config = {}
    journald_conf = Path("/etc/systemd/journald.conf")
    config_files = [journald_conf]
    config_dir = Path("/etc/systemd/journald.conf.d")
    if config_dir.is_dir():
        config_files.extend(sorted(config_dir.glob("*.conf")))
    for config_file in config_files:
        if config_file.exists():
            for line in config_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key, value = stripped.split("=", 1)
                    config[key.strip()] = value.strip()
    storage_value = config.get("Storage", "auto").lower()
    enabled = journal_dir.exists() and storage_value in {"auto", "persistent"}
    system_max_use = config.get("SystemMaxUse", "system default")
    max_use_bytes = _size_bytes(system_max_use)
    bounded = bool(max_use_bytes and max_use_bytes > 0)
    within_safe_limit = bool(bounded and max_use_bytes <= SAFE_SYSTEM_MAX_USE_BYTES)
    service_active = "ActiveState=active" in str(storage.get("stdout") or "")
    healthy = bool(enabled and service_active and within_safe_limit)
    if healthy:
        summary = f"Enabled, limited to {system_max_use}"
    elif enabled and bounded:
        summary = f"Persistent, limit {system_max_use} exceeds 512M"
    elif enabled:
        summary = "Persistent, but no safe size limit is configured"
    else:
        summary = "Disabled or unavailable"
    return {
        "enabled": enabled,
        "bounded": bounded,
        "within_safe_limit": within_safe_limit,
        "healthy": healthy,
        "summary": summary,
        "journal_directory": str(journal_dir),
        "directory_exists": journal_dir.exists(),
        "storage_setting": storage_value,
        "config_path": str(journald_conf),
        "managed_config_path": str(MANAGED_CONFIG),
        "managed_config_exists": MANAGED_CONFIG.exists(),
        "system_max_use": system_max_use,
        "system_keep_free": config.get("SystemKeepFree", "system default"),
        "max_retention": config.get("MaxRetentionSec", "system default"),
        "journald_service": storage.get("stdout") or storage.get("stderr"),
        "service_active": service_active,
        "disk_usage": show.get("stdout") or show.get("stderr"),
    }


def enable_persistent() -> dict[str, Any]:
    journal_dir = Path("/var/log/journal")
    try:
        journal_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(journal_dir, 0o2755)
        MANAGED_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        temporary = MANAGED_CONFIG.with_suffix(".conf.tmp")
        temporary.write_text(
            "[Journal]\n"
            "Storage=persistent\n"
            "SystemMaxUse=512M\n"
            "SystemKeepFree=1G\n"
            "MaxRetentionSec=30day\n",
            encoding="utf-8",
        )
        os.replace(temporary, MANAGED_CONFIG)
        flushed = _run(["journalctl", "--flush"], timeout=15)
        restarted = _run(["systemctl", "restart", "systemd-journald"], timeout=15)
        vacuumed = _run(["journalctl", "--vacuum-size=512M", "--vacuum-time=30d"], timeout=30)
        status = persistent_status()
        return {
            "ok": bool(status.get("healthy")),
            "message": "Persistent journald storage enabled and limited to 512 MB." if status.get("healthy") else "Persistent journald storage and its safe size limit could not be confirmed.",
            "status": status,
            "flush": flushed,
            "restart": restarted,
            "vacuum": vacuumed,
        }
    except Exception as exc:
        return {"ok": False, "message": str(exc), "status": persistent_status()}
