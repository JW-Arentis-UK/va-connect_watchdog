from __future__ import annotations

import heapq
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import recording_storage_recordings_path


def _timestamp_from_name(name: str) -> int | None:
    value = str(name).split(".", 1)[0]
    if not value.isdigit():
        return None
    timestamp = int(value)
    return timestamp if 946684800 <= timestamp <= 4102444800 else None


def _display_times(timestamp: int) -> dict[str, Any]:
    utc = datetime.fromtimestamp(timestamp, timezone.utc)
    local = datetime.fromtimestamp(timestamp).astimezone()
    return {
        "unix": timestamp,
        "utc": utc.isoformat(),
        "local": local.isoformat(),
        "display_local": local.strftime("%H:%M:%S %d/%m/%Y"),
    }


def candidate_recording_paths(cfg: dict[str, Any]) -> list[Path]:
    storage_cfg = cfg.get("storage", {}) if isinstance(cfg.get("storage", {}), dict) else {}
    configured = [
        storage_cfg.get("recordings_path"),
        recording_storage_recordings_path(cfg),
        "/home/vsuser/recordings",
    ]
    paths = []
    seen = set()
    for raw in configured:
        if not raw:
            continue
        path = Path(str(raw))
        key = str(path)
        if key not in seen:
            paths.append(path)
            seen.add(key)
    return paths


def _newest_from_path(root: Path, recent_count: int, max_buckets: int) -> dict[str, Any]:
    newest: list[int] = []
    buckets: list[tuple[int, Path]] = []
    entries_checked = 0
    try:
        root_entries = list(root.iterdir())
    except OSError as exc:
        return {"path": str(root), "error": str(exc), "timestamps": [], "entries_checked": 0}

    for entry in root_entries:
        timestamp = _timestamp_from_name(entry.name)
        if entry.is_dir() and timestamp is not None:
            buckets.append((timestamp, entry))
        elif entry.is_file() and timestamp is not None:
            heapq.heappush(newest, timestamp)
            if len(newest) > recent_count:
                heapq.heappop(newest)
        entries_checked += 1

    scanned_buckets = []
    for bucket_timestamp, bucket in sorted(buckets, reverse=True)[:max_buckets]:
        scanned_buckets.append(bucket_timestamp)
        try:
            for entry in bucket.iterdir():
                entries_checked += 1
                if not entry.is_file():
                    continue
                timestamp = _timestamp_from_name(entry.name)
                if timestamp is None:
                    continue
                heapq.heappush(newest, timestamp)
                if len(newest) > recent_count:
                    heapq.heappop(newest)
        except OSError:
            continue

    return {
        "path": str(root),
        "error": "",
        "timestamps": sorted(newest, reverse=True),
        "entries_checked": entries_checked,
        "scanned_buckets": scanned_buckets,
    }


def recording_activity(
    cfg: dict[str, Any],
    recent_count: int = 10,
    max_buckets: int = 3,
    now_unix: float | None = None,
) -> dict[str, Any]:
    recent_count = min(50, max(1, int(recent_count)))
    max_buckets = min(7, max(1, int(max_buckets)))
    results = []
    for path in candidate_recording_paths(cfg):
        if path.is_dir():
            results.append(_newest_from_path(path, recent_count, max_buckets))

    best = max(
        (item for item in results if item.get("timestamps")),
        key=lambda item: item["timestamps"][0],
        default=None,
    )
    checked_at = datetime.now(timezone.utc).isoformat()
    if best is None:
        return {
            "available": False,
            "message": "No Unix-timestamped recording files were found.",
            "recordings_path": next((item["path"] for item in results), "-"),
            "latest": None,
            "recent": [],
            "checked_at": checked_at,
            "paths_checked": [item["path"] for item in results],
        }

    latest_unix = int(best["timestamps"][0])
    now = time.time() if now_unix is None else float(now_unix)
    age_seconds = max(0.0, now - latest_unix)
    recent = [_display_times(timestamp) for timestamp in best["timestamps"]]
    buckets = best.get("scanned_buckets", [])
    return {
        "available": True,
        "message": f"Latest recording: {recent[0]['display_local']}",
        "recordings_path": best["path"],
        "latest": recent[0],
        "latest_age_seconds": round(age_seconds, 1),
        "recent": recent,
        "newest_bucket_unix": buckets[0] if buckets else None,
        "newest_bucket": _display_times(buckets[0]) if buckets else None,
        "entries_checked": best.get("entries_checked", 0),
        "checked_at": checked_at,
        "paths_checked": [item["path"] for item in results],
    }
