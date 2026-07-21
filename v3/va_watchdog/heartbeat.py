from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def heartbeat_paths(cfg: dict[str, Any]) -> tuple[Path, Path]:
    events_path = Path(cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl")
    data_dir = events_path.parent
    return (
        Path(cfg.get("heartbeat_state_path") or data_dir / "heartbeat-state.json"),
        Path(cfg.get("heartbeat_path") or data_dir / "heartbeat.jsonl"),
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def monotonic_uptime() -> float:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 3)
    except Exception:
        return round(time.monotonic(), 3)


def read_state(cfg: dict[str, Any]) -> dict[str, Any]:
    state_path, _ = heartbeat_paths(cfg)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def write_heartbeat(cfg: dict[str, Any], sequence: int, last_feed_utc: str = "", feed_allowed: bool = True) -> dict[str, Any]:
    state_path, history_path = heartbeat_paths(cfg)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "time": utc_now(),
        "monotonic_uptime": monotonic_uptime(),
        "boot_id": boot_id(),
        "health_sequence": int(sequence),
        "last_health_sample": utc_now(),
        "last_hardware_watchdog_feed": last_feed_utc or "",
        "feed_allowed": bool(feed_allowed),
    }
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
    with temporary.open("r+", encoding="utf-8") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, state_path)
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    trim_heartbeat_history(cfg)
    return record


def trim_heartbeat_history(cfg: dict[str, Any]) -> None:
    _, history_path = heartbeat_paths(cfg)
    if not history_path.exists():
        return
    retention = cfg.get("retention", {}) if isinstance(cfg.get("retention", {}), dict) else {}
    max_rows = max(100, int(retention.get("heartbeat_max_rows", 3600) or 3600))
    max_bytes = max(64 * 1024, int(retention.get("heartbeat_max_mb", 5) or 5) * 1024 * 1024)
    try:
        if history_path.stat().st_size <= max_bytes:
            return
        lines = history_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_rows:]
        temporary = history_path.with_suffix(history_path.suffix + ".tmp")
        temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        os.replace(temporary, history_path)
    except OSError:
        pass


def read_tail(cfg: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    _, history_path = heartbeat_paths(cfg)
    if not history_path.exists():
        return []
    rows = []
    try:
        for line in history_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max(1, int(limit)):]:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return rows


def heartbeat_age_seconds(state: dict[str, Any], current_uptime: float | None = None) -> float | None:
    if not isinstance(state, dict) or not state.get("monotonic_uptime"):
        return None
    try:
        now = monotonic_uptime() if current_uptime is None else float(current_uptime)
        return round(max(0.0, now - float(state["monotonic_uptime"])), 3)
    except (TypeError, ValueError):
        return None
