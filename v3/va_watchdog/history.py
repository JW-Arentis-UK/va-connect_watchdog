from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def history_path(cfg: dict[str, Any]) -> Path:
    return Path(cfg.get("history_path") or Path(cfg["events_path"]).with_name("history.jsonl"))


def append_history(cfg: dict[str, Any], status: dict[str, Any]) -> None:
    path = history_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not _should_sample(cfg, path):
        return
    checks = status.get("checks", [])
    previous = _last_history_row(path)
    sample_gap_seconds = None
    if previous and previous.get("time") and status.get("time"):
        try:
            sample_gap_seconds = round(_iso_to_unix(str(status.get("time"))) - _iso_to_unix(str(previous.get("time"))), 1)
        except Exception:
            sample_gap_seconds = None
    hardware_feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
    recording_storage = status.get("recording_storage", {}) if isinstance(status.get("recording_storage", {}), dict) else {}
    payload = {
        "time": status.get("time"),
        "state": status.get("state"),
        "display_state": status.get("state") or ("critical" if status.get("critical_failed") else "healthy"),
        "score": status.get("score"),
        "critical_failed": status.get("critical_failed", False),
        "boot_id": _boot_id(),
        "uptime_seconds": _uptime_seconds(),
        "sample_gap_seconds": sample_gap_seconds,
        "temperature": _check_value(checks, "temperature"),
        "cpu_load": _check_value(checks, "cpu_load"),
        "ram": _check_value(checks, "ram"),
        "root_disk": _disk_value(checks, "root_disk"),
        "recordings_disk": _disk_value(checks, "recordings_disk"),
        "warning_checks": _check_names(checks, "warning"),
        "degraded_checks": _check_names(checks, "degraded"),
        "critical_checks": _check_names(checks, "critical"),
        "service_states": _service_states(checks),
        "service_metrics": _service_metrics(checks),
        "hardware_watchdog_present": _check_value(checks, "hardware_watchdog_present"),
        "hardware_watchdog_feed_status": _check_state(checks, "hardware_watchdog_feed_status"),
        "hardware_watchdog_feed_message": _check_message(checks, "hardware_watchdog_feed_status"),
        "hardware_watchdog_feed_enabled": hardware_feed.get("enabled"),
        "hardware_watchdog_opened": hardware_feed.get("opened"),
        "hardware_watchdog_feed_count": hardware_feed.get("feed_count"),
        "hardware_watchdog_timeout_seconds": hardware_feed.get("timeout_seconds"),
        "recording_storage_status": recording_storage.get("status"),
        "recording_storage_message": recording_storage.get("message"),
        "recording_storage_mounted": recording_storage.get("mounted"),
        "recording_storage_writable": recording_storage.get("writable"),
        "recording_storage_used_percent": recording_storage.get("used_percent"),
        "recording_storage_free_mb": recording_storage.get("free_mb"),
        "recording_storage_expected_full": recording_storage.get("expected_full"),
        "recording_storage_minimum_free_mb_warning": recording_storage.get("minimum_free_mb_warning"),
        "recording_storage_minimum_free_mb_critical": recording_storage.get("minimum_free_mb_critical"),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, separators=(",", ":")) + "\n")
    trim_history(cfg)


def read_history(cfg: dict[str, Any], limit: int = 288) -> list[dict[str, Any]]:
    path = history_path(cfg)
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def trim_history(cfg: dict[str, Any]) -> None:
    path = history_path(cfg)
    if not path.exists():
        return
    retention = cfg.get("retention", {})
    days = int(retention.get("history_retention_days", 30) or 30)
    cutoff = time.time() - max(1, days) * 86400
    kept = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            payload = json.loads(line)
            timestamp = payload.get("time", "")
            # ISO strings sort by date, but mtime fallback keeps malformed rows bounded.
            if timestamp and _iso_to_unix(timestamp) >= cutoff:
                kept.append(line)
        except Exception:
            continue
    max_rows = int(retention.get("history_max_rows", 50000) or 50000)
    kept = kept[-max_rows:]
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")


def _should_sample(cfg: dict[str, Any], path: Path) -> bool:
    sample_seconds = int(cfg.get("retention", {}).get("history_sample_seconds", 60) or 60)
    if sample_seconds <= 0 or not path.exists():
        return True
    try:
        return time.time() - path.stat().st_mtime >= sample_seconds
    except OSError:
        return True


def _check_value(checks: list[dict[str, Any]], name: str) -> Any:
    for check in checks:
        if check.get("name") == name:
            return check.get("value")
    return None


def _check_state(checks: list[dict[str, Any]], name: str) -> Any:
    for check in checks:
        if check.get("name") == name:
            return check.get("state")
    return None


def _check_message(checks: list[dict[str, Any]], name: str) -> Any:
    for check in checks:
        if check.get("name") == name:
            return check.get("message")
    return None


def _check_names(checks: list[dict[str, Any]], state: str) -> str:
    return ";".join(str(check.get("name")) for check in checks if check.get("state") == state and check.get("name"))


def _service_states(checks: list[dict[str, Any]]) -> str:
    return ";".join(
        f"{check.get('name')}={check.get('state')}"
        for check in checks
        if str(check.get("name", "")).endswith(".service")
    )


def _service_metrics(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics = []
    for check in checks:
        name = str(check.get("name", ""))
        if not name.endswith(".service"):
            continue
        value = check.get("value") if isinstance(check.get("value"), dict) else {}
        metrics.append({
            "name": name,
            "state": check.get("state"),
            "active": value.get("active"),
            "cpu_percent": value.get("cpu_percent"),
            "cpu_system_percent": value.get("cpu_system_percent"),
            "memory_mb": value.get("memory_mb"),
            "restarts": value.get("restarts"),
        })
    return metrics


def _disk_value(checks: list[dict[str, Any]], name: str) -> Any:
    value = _check_value(checks, name)
    if isinstance(value, dict):
        return value.get("used_percent")
    return None


def _iso_to_unix(value: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _uptime_seconds() -> float | None:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 1)
    except Exception:
        return None


def _last_history_row(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        lines = [line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    except Exception:
        return None
    if not lines:
        return None
    try:
        payload = json.loads(lines[-1])
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None
