from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
import json
from typing import Any, Iterable

from .config import V2Config
from .normalization import (
    normalize_device_status,
    normalize_event,
    normalize_incident,
    normalize_metric_sample,
    normalize_state,
)
from .paths import build_info_path, device_status_path, events_path, incidents_path, log_file_path, logs_dir, metrics_path, state_path
from .time import parse_iso, utc_now


def ensure_layout(config: V2Config) -> None:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    logs_dir(config).mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def append_jsonl(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def trim_jsonl_by_age(path: Path, *, max_age_seconds: int) -> None:
    if not path.exists():
        return
    cutoff = utc_now().timestamp() - max(0, int(max_age_seconds))
    kept: list[str] = []
    changed = False
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return
    for line in lines:
        raw = line.strip()
        if not raw:
            changed = True
            continue
        try:
            payload = json.loads(raw)
        except Exception:
            kept.append(raw)
            continue
        if isinstance(payload, dict):
            ts = parse_iso(str(payload.get("timestamp") or payload.get("ts") or ""))
            if ts is not None and ts.timestamp() < cutoff:
                changed = True
                continue
        kept.append(json.dumps(payload, sort_keys=True))
    if changed:
        path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")


def load_state(config: V2Config) -> dict[str, Any]:
    raw = read_json(state_path(config), {})
    return normalize_state(raw, device_id=config.device_id)


def save_state(config: V2Config, state: Any) -> dict[str, Any]:
    normalized = normalize_state(state, device_id=config.device_id)
    write_json(state_path(config), normalized)
    return normalized


def load_device_status(config: V2Config) -> dict[str, Any]:
    raw = read_json(device_status_path(config), {})
    if not raw:
        return normalize_device_status(
            {
                "device_id": config.device_id,
                "overall_status": "unknown",
                "last_seen": "",
                "checks": {},
                "health": {"fault_active": False, "notes": "No checks have run yet."},
            }
        )
    return normalize_device_status(raw)


def save_device_status(config: V2Config, status: Any) -> dict[str, Any]:
    normalized = normalize_device_status(status)
    write_json(device_status_path(config), normalized)
    return normalized


def load_events(config: V2Config) -> list[dict[str, Any]]:
    return [normalize_event(item) for item in read_jsonl(events_path(config))]


def append_event(config: V2Config, event: Any) -> dict[str, Any]:
    normalized = normalize_event(event)
    append_jsonl(events_path(config), normalized)
    return normalized


def load_incidents(config: V2Config) -> list[dict[str, Any]]:
    latest: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for item in read_jsonl(incidents_path(config)):
        normalized = normalize_incident(item)
        latest[normalized["incident_id"]] = normalized
    return list(latest.values())


def list_incidents(config: V2Config) -> list[dict[str, Any]]:
    incidents = load_incidents(config)
    return sorted(incidents, key=lambda item: item.get("timestamp", ""), reverse=True)


def latest_incident(config: V2Config) -> dict[str, Any] | None:
    incidents = list_incidents(config)
    return incidents[0] if incidents else None


def save_incident(config: V2Config, incident: Any) -> dict[str, Any]:
    normalized = normalize_incident(incident)
    append_jsonl(incidents_path(config), normalized)
    return normalized


def get_incident(config: V2Config, incident_id: str) -> dict[str, Any] | None:
    for incident in reversed(list_incidents(config)):
        if incident.get("incident_id") == incident_id:
            return incident
    return None


def latest_open_incident(config: V2Config) -> dict[str, Any] | None:
    for incident in list_incidents(config):
        if incident.get("status") != "resolved":
            return incident
    return None


def latest_event(config: V2Config) -> dict[str, Any] | None:
    events = load_events(config)
    return events[-1] if events else None


def load_metrics(config: V2Config) -> list[dict[str, Any]]:
    return [normalize_metric_sample(item) for item in read_jsonl(metrics_path(config))]


def append_metric(config: V2Config, metric: Any) -> dict[str, Any]:
    normalized = normalize_metric_sample(metric)
    append_jsonl(metrics_path(config), normalized)
    trim_jsonl_by_age(metrics_path(config), max_age_seconds=30 * 60)
    return normalized


def load_build_info() -> dict[str, Any]:
    return read_json(
        build_info_path(),
        {
            "build_number": "local-dev",
            "commit_sha": "unknown",
            "built_at": "",
            "source_branch": "master",
            "source_repo": "JW-Arentis-UK/va-connect_watchdog",
        },
    )


def log_path(config: V2Config) -> Path:
    return log_file_path(config)
