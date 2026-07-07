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
    payload = {
        "time": status.get("time"),
        "state": status.get("state"),
        "display_state": "critical" if status.get("critical_failed") else "healthy",
        "score": status.get("score"),
        "critical_failed": status.get("critical_failed", False),
        "temperature": _check_value(checks, "temperature"),
        "cpu_load": _check_value(checks, "cpu_load"),
        "ram": _check_value(checks, "ram"),
        "root_disk": _disk_value(checks, "root_disk"),
        "recordings_disk": _disk_value(checks, "recordings_disk"),
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


def _disk_value(checks: list[dict[str, Any]], name: str) -> Any:
    value = _check_value(checks, name)
    if isinstance(value, dict):
        return value.get("used_percent")
    return None


def _iso_to_unix(value: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
