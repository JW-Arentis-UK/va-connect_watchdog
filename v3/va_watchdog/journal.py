from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


MANAGED_CONFIG = Path("/etc/systemd/journald.conf.d/va-watchdog-persistent.conf")


def _run(command, timeout=10):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": result.returncode == 0, "stdout": result.stdout.strip(), "stderr": result.stderr.strip(), "returncode": result.returncode}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}


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
    return {
        "enabled": enabled,
        "journal_directory": str(journal_dir),
        "directory_exists": journal_dir.exists(),
        "storage_setting": storage_value,
        "config_path": str(journald_conf),
        "managed_config_path": str(MANAGED_CONFIG),
        "managed_config_exists": MANAGED_CONFIG.exists(),
        "system_max_use": config.get("SystemMaxUse", "system default"),
        "system_keep_free": config.get("SystemKeepFree", "system default"),
        "max_retention": config.get("MaxRetentionSec", "system default"),
        "journald_service": storage.get("stdout") or storage.get("stderr"),
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
            "ok": bool(status.get("enabled")),
            "message": "Persistent journald storage enabled." if status.get("enabled") else "Persistent journald storage could not be confirmed.",
            "status": status,
            "flush": flushed,
            "restart": restarted,
            "vacuum": vacuumed,
        }
    except Exception as exc:
        return {"ok": False, "message": str(exc), "status": persistent_status()}
