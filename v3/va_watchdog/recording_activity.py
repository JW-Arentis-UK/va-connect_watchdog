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


def _recordings_from_path(root: Path, recording_count: int, max_buckets: int) -> dict[str, Any]:
    newest: list[int] = []
    oldest: list[int] = []
    buckets: list[tuple[int, Path]] = []
    entries_checked = 0

    def add_timestamp(timestamp: int, include_oldest: bool, include_newest: bool) -> None:
        if include_oldest:
            heapq.heappush(oldest, -timestamp)
            if len(oldest) > recording_count:
                heapq.heappop(oldest)
        if include_newest:
            heapq.heappush(newest, timestamp)
            if len(newest) > recording_count:
                heapq.heappop(newest)

    try:
        root_entries = list(root.iterdir())
    except OSError as exc:
        return {
            "path": str(root),
            "error": str(exc),
            "oldest_timestamps": [],
            "newest_timestamps": [],
            "entries_checked": 0,
        }

    for entry in root_entries:
        timestamp = _timestamp_from_name(entry.name)
        if entry.is_dir() and timestamp is not None:
            buckets.append((timestamp, entry))
        elif entry.is_file() and timestamp is not None:
            add_timestamp(timestamp, include_oldest=True, include_newest=True)
        entries_checked += 1

    sorted_buckets = sorted(buckets)
    bucket_cache: dict[Path, list[int]] = {}

    def bucket_timestamps(bucket: Path) -> list[int]:
        nonlocal entries_checked
        if bucket in bucket_cache:
            return bucket_cache[bucket]
        timestamps = []
        try:
            for entry in bucket.iterdir():
                entries_checked += 1
                if not entry.is_file():
                    continue
                timestamp = _timestamp_from_name(entry.name)
                if timestamp is not None:
                    timestamps.append(timestamp)
        except OSError:
            pass
        bucket_cache[bucket] = timestamps
        return timestamps

    oldest_buckets = []
    for bucket_timestamp, bucket in sorted_buckets[:max_buckets]:
        oldest_buckets.append((bucket_timestamp, bucket))
        for timestamp in bucket_timestamps(bucket):
            add_timestamp(timestamp, include_oldest=True, include_newest=False)
        if len(oldest) >= recording_count:
            break

    newest_buckets = []
    for bucket_timestamp, bucket in reversed(sorted_buckets[-max_buckets:]):
        newest_buckets.append((bucket_timestamp, bucket))
        for timestamp in bucket_timestamps(bucket):
            add_timestamp(timestamp, include_oldest=False, include_newest=True)
        if len(newest) >= recording_count:
            break

    return {
        "path": str(root),
        "error": "",
        "oldest_timestamps": sorted(-timestamp for timestamp in oldest),
        "newest_timestamps": sorted(newest, reverse=True),
        "entries_checked": entries_checked,
        "oldest_buckets": [timestamp for timestamp, _ in oldest_buckets],
        "newest_buckets": [timestamp for timestamp, _ in newest_buckets],
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
            results.append(_recordings_from_path(path, recent_count, max_buckets))

    best = max(
        (item for item in results if item.get("newest_timestamps")),
        key=lambda item: item["newest_timestamps"][0],
        default=None,
    )
    checked_at = datetime.now(timezone.utc).isoformat()
    if best is None:
        return {
            "available": False,
            "message": "No Unix-timestamped recording files were found.",
            "recordings_path": next((item["path"] for item in results), "-"),
            "oldest": None,
            "oldest_recordings": [],
            "latest": None,
            "recent": [],
            "checked_at": checked_at,
            "paths_checked": [item["path"] for item in results],
        }

    oldest_source = best.get("oldest_timestamps") or list(reversed(best["newest_timestamps"]))
    oldest_unix = int(oldest_source[0])
    latest_unix = int(best["newest_timestamps"][0])
    now = time.time() if now_unix is None else float(now_unix)
    oldest_age_seconds = max(0.0, now - oldest_unix)
    latest_age_seconds = max(0.0, now - latest_unix)
    oldest_recordings = [_display_times(timestamp) for timestamp in oldest_source]
    recent = [_display_times(timestamp) for timestamp in best["newest_timestamps"]]
    oldest_buckets = best.get("oldest_buckets", [])
    newest_buckets = best.get("newest_buckets", [])
    return {
        "available": True,
        "message": f"Oldest recording: {oldest_recordings[0]['display_local']}",
        "recordings_path": best["path"],
        "oldest": oldest_recordings[0],
        "oldest_age_seconds": round(oldest_age_seconds, 1),
        "oldest_recordings": oldest_recordings,
        "latest": recent[0],
        "latest_age_seconds": round(latest_age_seconds, 1),
        "recent": recent,
        "oldest_bucket_unix": oldest_buckets[0] if oldest_buckets else None,
        "oldest_bucket": _display_times(oldest_buckets[0]) if oldest_buckets else None,
        "newest_bucket_unix": newest_buckets[0] if newest_buckets else None,
        "newest_bucket": _display_times(newest_buckets[0]) if newest_buckets else None,
        "entries_checked": best.get("entries_checked", 0),
        "checked_at": checked_at,
        "paths_checked": [item["path"] for item in results],
    }
