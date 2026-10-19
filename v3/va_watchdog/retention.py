from __future__ import annotations

import time
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .history import history_path


def data_dir(cfg: dict[str, Any]) -> Path:
    return Path(cfg["events_path"]).parent


def blackbox_segment_dir(cfg: dict[str, Any]) -> Path:
    configured = cfg.get("blackbox", {}) if isinstance(cfg.get("blackbox", {}), dict) else {}
    return Path(configured.get("segment_dir") or data_dir(cfg) / "blackbox-buffer")


def data_files(cfg: dict[str, Any]) -> list[Path]:
    base = data_dir(cfg)
    files = [
        base / "status.json",
        base / "events.jsonl",
        base / "events.jsonl.1",
        base / "update-state.json",
        base / "update.log",
        base / "last-reboot-reason.json",
        base / "watchdog-test.json",
        base / "neousys-watchdog-install.log",
        base / "neousys-watchdog-probe.log",
        base / "history.jsonl",
        base / "blackbox.jsonl",
        base / "blackbox-state.json",
        base / "heartbeat-state.json",
        base / "heartbeat.jsonl",
        base / "reboot-evidence.jsonl",
        base / "kernel-fault-state.json",
        base / "hardware-watchdog-feed.json",
        base / "hardware-watchdog-feed-previous.json",
        base / "hardware-watchdog-lifecycle.jsonl",
        base / "hikvision-people-events.jsonl",
        base / "hikvision-people-events-state.json",
    ]
    custom_history = history_path(cfg)
    if custom_history not in files:
        files.append(custom_history)
    return files


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.exists() else 0
    except OSError:
        return 0


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for item in path.rglob("*"):
        if item.is_file():
            total += file_size(item)
    return total


def retention_status(cfg: dict[str, Any]) -> dict[str, Any]:
    retention = cfg.get("retention", {})
    max_mb = int(retention.get("max_total_mb", 100) or 100)
    used_bytes = dir_size(data_dir(cfg))
    files = []
    for path in data_files(cfg):
        modified = None
        if path.exists():
            try:
                modified = path.stat().st_mtime
            except OSError:
                modified = None
        files.append(
            {
                "path": str(path),
                "size_bytes": file_size(path),
                "modified_unix": modified,
            }
        )
    return {
        "data_dir": str(data_dir(cfg)),
        "max_total_mb": max_mb,
        "used_bytes": used_bytes,
        "used_mb": round(used_bytes / 1024 / 1024, 2),
        "used_percent": round((used_bytes / max(1, max_mb * 1024 * 1024)) * 100, 1),
        "events_retention_days": retention.get("events_retention_days"),
        "history_retention_days": retention.get("history_retention_days"),
        "history_sample_seconds": retention.get("history_sample_seconds"),
        "history_max_rows": retention.get("history_max_rows"),
        "exports_retention_days": retention.get("exports_retention_days"),
        "blackbox_buffer_bytes": dir_size(blackbox_segment_dir(cfg)),
        "files": files,
    }


def disposable_files(cfg):
    # Control state and crash evidence have their own retention policies.
    base = data_dir(cfg)
    return [Path(cfg['events_path']), Path(cfg['events_path']).with_suffix('.jsonl.1'),
            history_path(cfg), base / 'update.log', base / 'neousys-watchdog-install.log',
            base / 'neousys-watchdog-probe.log', base / 'hikvision-people-events.jsonl']


def purge_data(cfg: dict[str, Any], mode: str = "old", older_than_days: int | None = None) -> dict[str, Any]:
    cutoff = None
    if older_than_days is not None:
        cutoff = time.time() - max(0, int(older_than_days)) * 86400
    removed = []
    trimmed = []
    for path in disposable_files(cfg):
        if not path.exists() or path.name == "status.json":
            continue
        if mode != "all" and cutoff is not None and path.suffix == ".jsonl":
            result = _trim_jsonl_before(path, cutoff)
            if result["removed_rows"]:
                trimmed.append(result)
            continue
        if mode == "all" or (cutoff is not None and path.stat().st_mtime < cutoff):
            try:
                size = file_size(path)
                path.unlink()
                removed.append({"path": str(path), "size_bytes": size})
            except OSError:
                pass
    return {"removed": removed, "trimmed": trimmed, "retention": retention_status(cfg)}


def enforce_retention(cfg: dict[str, Any]) -> dict[str, Any]:
    retention = cfg.get("retention", {})
    max_mb = int(retention.get("max_total_mb", 100) or 100)
    if max_mb <= 0:
        return {"ok": True, "actions": [], "retention": retention_status(cfg)}

    status = retention_status(cfg)
    max_bytes = max_mb * 1024 * 1024
    if int(status.get("used_bytes", 0) or 0) <= max_bytes:
        return {"ok": True, "actions": [], "retention": status}

    days = min(
        int(retention.get("events_retention_days", 30) or 30),
        int(retention.get("history_retention_days", 30) or 30),
    )
    result = purge_data(cfg, mode="old", older_than_days=days)
    actions = []
    if result["removed"]:
        actions.append({"action": "purge_old", "older_than_days": days, "removed": result["removed"]})

    if dir_size(data_dir(cfg)) > max_bytes:
        candidates = []
        for path in disposable_files(cfg):
            if path.exists() and path.name != "status.json":
                try:
                    candidates.append((path.stat().st_mtime, path))
                except OSError:
                    continue
        for _, path in sorted(candidates):
            if dir_size(data_dir(cfg)) <= max_bytes:
                break
            try:
                if path.suffix == ".jsonl":
                    excess = dir_size(data_dir(cfg)) - max_bytes
                    result = _trim_jsonl_bytes(path, excess)
                    if result["removed_rows"]:
                        actions.append({"action": "trim_oldest_rows", **result})
                    continue
                size = file_size(path)
                path.unlink()
                actions.append({"action": "remove_oldest", "path": str(path), "size_bytes": size})
            except OSError:
                continue

    return {"ok": True, "actions": actions, "over_budget": dir_size(data_dir(cfg)) > max_bytes, "retention": retention_status(cfg)}


def _json_timestamp(line: str) -> float | None:
    try:
        payload = json.loads(line)
        value = payload.get("time") if isinstance(payload, dict) else None
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() if value else None
    except (TypeError, ValueError):
        return None


def _write_lines_atomic(path: Path, lines: list[str]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    os.replace(temporary, path)


def _stream_trim(path, discard):
    from .events import EVENTS_LOCK
    temporary = path.with_suffix(path.suffix + '.tmp')
    removed = kept = removed_bytes = 0
    with EVENTS_LOCK:
        try:
            with path.open('rb') as source, temporary.open('wb') as target:
                for line in source:
                    if discard(line, removed_bytes):
                        removed += 1
                        removed_bytes += len(line)
                    else:
                        target.write(line)
                        kept += 1
            if removed:
                os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return {'path': str(path), 'removed_rows': removed, 'remaining_rows': kept, 'removed_bytes': removed_bytes}


def _trim_jsonl_before(path, cutoff):
    def discard(line, _):
        stamp = _json_timestamp(line.decode('utf-8', errors='replace'))
        return stamp is not None and stamp < cutoff
    return _stream_trim(path, discard)


def _trim_jsonl_bytes(path, minimum_bytes):
    return _stream_trim(path, lambda line, removed: removed < max(1, minimum_bytes))
