from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (TypeError, ValueError):
        return None


def current_boot_started_at(detected_at: Any, uptime_path: Path = Path("/proc/uptime")) -> str:
    detected = _timestamp(detected_at)
    if detected is None:
        return ""
    try:
        uptime = float(uptime_path.read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return ""
    if uptime < 0:
        return ""
    return (detected - timedelta(seconds=uptime)).isoformat()


def reset_attribution(
    boot_change: dict[str, Any],
    last_heartbeat: dict[str, Any],
    previous_feed: dict[str, Any],
    requested: bool,
    unclean: bool,
) -> dict[str, Any]:
    previous_boot = str(boot_change.get("previous_boot_id") or "")
    feed_matches = bool(previous_boot and previous_feed.get("boot_id") == previous_boot)
    feed = previous_feed if feed_matches else {}
    timeout = feed.get("timeout_seconds")
    try:
        timeout = float(timeout)
        if timeout <= 0:
            timeout = None
    except (TypeError, ValueError):
        timeout = None

    last_feed = _timestamp(feed.get("last_feed_utc"))
    boot_started = _timestamp(boot_change.get("boot_started_at"))
    feed_to_boot = (
        round((boot_started - last_feed).total_seconds(), 3)
        if last_feed and boot_started else None
    )
    compatible = bool(
        not requested and unclean and feed.get("process_status") == "feeding"
        and timeout is not None and feed_to_boot is not None
        and timeout <= feed_to_boot <= timeout + 180
    )
    return {
        "assessment": "timing compatible; unconfirmed" if compatible else "insufficient evidence",
        "hardware_reset_confirmed": False,
        "previous_feed_state_matches_boot": feed_matches,
        "last_feed_utc": feed.get("last_feed_utc") or "",
        "feed_status": feed.get("process_status") or "",
        "feed_decision": feed.get("feed_decision") or "",
        "timeout_seconds": timeout,
        "last_heartbeat_utc": last_heartbeat.get("time") or "",
        "last_blackbox_sample_utc": boot_change.get("previous_last_sample_utc") or "",
        "current_boot_started_at": boot_change.get("boot_started_at") or "",
        "current_boot_detected_at": boot_change.get("detected_at") or "",
        "last_feed_to_boot_seconds": feed_to_boot,
        "limitations": (
            "Elapsed time includes firmware and Linux startup. A matching interval does not identify "
            "which component reset the gateway; independent hardware or relay evidence is required."
        ),
    }
