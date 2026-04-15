from __future__ import annotations

from datetime import datetime, timedelta, timezone
import subprocess
from typing import Any

from ..shared.config import V2Config
from ..shared.storage import (
    latest_event,
    latest_incident,
    list_incidents,
    load_build_info,
    load_device_status,
    load_events,
    load_metrics,
    load_state,
)
from ..shared.system import collect_system_sample


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _timeline_events(config: V2Config, incident_ts: datetime | None, limit: int = 50) -> list[dict[str, Any]]:
    rows = []
    for event in load_events(config):
        event_ts = _parse_iso(str(event.get("timestamp", "")))
        if incident_ts is not None and event_ts is not None and event_ts > incident_ts:
            continue
        rows.append(
            {
                "timestamp": event.get("timestamp"),
                "level": event.get("level"),
                "message": event.get("message"),
            }
        )
    return rows[-limit:]


def _key_events(incident: dict[str, Any] | None) -> list[str]:
    if not incident:
        return []
    items: list[str] = []
    for evidence in incident.get("evidence", [])[:3]:
        message = str(evidence.get("message", "")).strip()
        if message:
            items.append(message)
    for action in incident.get("actions_taken", [])[:2]:
        action_text = str(action).strip()
        if action_text:
            items.append(action_text)
    return items[:5]


def _system_activity_24h(config: V2Config) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = []
    for sample in load_metrics(config):
        sample_ts = _parse_iso(str(sample.get("timestamp", "")))
        if sample_ts is None or sample_ts < cutoff:
            continue
        rows.append(sample)
    rows.sort(key=lambda item: item.get("timestamp", ""))
    return rows[-120:]


def _metric_before(incident_ts: datetime | None, rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if incident_ts is None:
        return rows[-1] if rows else None
    selected = None
    for row in rows:
        row_ts = _parse_iso(str(row.get("timestamp", "")))
        if row_ts is None or row_ts > incident_ts:
            continue
        selected = row
    return selected


def health_payload(config: V2Config) -> dict[str, Any]:
    state = load_state(config)
    device_status = load_device_status(config)
    incidents = list_incidents(config)
    return {
        "ok": True,
        "device_id": config.device_id,
        "build_info": load_build_info(),
        "storage": {
            "data_dir": str(config.data_dir),
            "events": len(load_events(config)),
            "incidents": len(incidents),
        },
        "state": state,
        "device_status": device_status,
        "open_incident_id": state.get("open_incident_id"),
    }


def gateways_payload(config: V2Config) -> dict[str, Any]:
    device_status = load_device_status(config)
    incidents = list_incidents(config)
    return {
        "build_info": load_build_info(),
        "gateways": [
            {
                "device_status": device_status,
                "incidents": incidents,
            }
        ]
    }


def debug_last_incident_payload(config: V2Config) -> dict[str, Any]:
    incident = latest_incident(config)
    incident_ts = _parse_iso(str(incident.get("timestamp", ""))) if incident else None
    activity = _system_activity_24h(config)
    system_state = collect_system_sample()
    pre_crash_snapshot = _metric_before(incident_ts, activity) or system_state
    pre_crash_timeline = _timeline_events(config, incident_ts)

    try:
        journal_result = subprocess.run(
            ["journalctl", "-b", "-1", "-n", "250", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
        )
        previous_boot_log = {
            "ok": journal_result.returncode == 0,
            "lines": journal_result.stdout.splitlines()[-250:] if journal_result.stdout else [],
            "detail": journal_result.stderr.strip() if journal_result.stderr else "",
        }
    except FileNotFoundError:
        previous_boot_log = {"ok": False, "lines": [], "detail": "journalctl not available"}

    return {
        "incident": incident,
        "event": latest_event(config),
        "device_status": load_device_status(config),
        "build_info": load_build_info(),
        "system_state": system_state,
        "pre_crash_snapshot": pre_crash_snapshot,
        "system_activity_24h": activity,
        "pre_crash_timeline": pre_crash_timeline,
        "event_timeline": pre_crash_timeline,
        "key_events": _key_events(incident),
        "previous_boot_log": previous_boot_log,
    }
