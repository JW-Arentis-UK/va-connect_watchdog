from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
import re
import uuid

from .models import (
    CheckResult,
    DeviceHealth,
    DeviceStatus,
    EvidenceItem,
    EventLevel,
    EventRecord,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    OverallStatus,
    StateRecord,
)
from .time import iso_utc, load_boot_id, parse_iso, utc_now


INCIDENT_TYPES: set[str] = {
    "wan_down",
    "lan_down",
    "app_crash",
    "service_failure",
    "unexpected_reboot",
    "watchdog_reboot",
    "manual_recovery",
    "unknown",
}
INCIDENT_STATUSES: set[str] = {"open", "monitoring", "resolved"}
INCIDENT_SEVERITIES: set[str] = {"info", "warning", "critical"}
EVENT_LEVELS: set[str] = {"debug", "info", "warning", "error"}
OVERALL_STATUSES: set[str] = {"healthy", "degraded", "faulted", "unknown"}


def _clean_str(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value.strip()).strip("-").lower()
    return cleaned or "device"


def normalize_timestamp(value: Any, *, default_now: bool = True) -> str:
    parsed = parse_iso(str(value or "").strip())
    if parsed is None:
        return iso_utc(utc_now()) if default_now else ""
    return iso_utc(parsed)


def normalize_boot_id(value: Any) -> str:
    text = _clean_str(value)
    return text or load_boot_id()


def normalize_evidence_item(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    data = raw.get("data", {})
    if not isinstance(data, Mapping):
        data = {"value": data}
    model = EvidenceItem(
        source=_clean_str(raw.get("source"), "system"),
        timestamp=normalize_timestamp(raw.get("timestamp")),
        message=_clean_str(raw.get("message"), "evidence"),
        data=dict(data),
    )
    return model.model_dump()


def normalize_check_result(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    model = CheckResult(
        ok=bool(raw.get("ok", False)),
        last_checked=normalize_timestamp(raw.get("last_checked")),
        detail=_clean_str(raw.get("detail"), "no detail"),
    )
    return model.model_dump()


def normalize_health(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    last_incident_type = _clean_str(raw.get("last_incident_type"), "unknown")
    if last_incident_type not in INCIDENT_TYPES:
        last_incident_type = "unknown"
    model = DeviceHealth(
        fault_active=bool(raw.get("fault_active", False)),
        last_incident_id=_clean_str(raw.get("last_incident_id")) or None,
        last_incident_type=last_incident_type,  # type: ignore[arg-type]
        last_healthy_at=normalize_timestamp(raw.get("last_healthy_at"), default_now=False) or None,
        notes=_clean_str(raw.get("notes"), ""),
    )
    return model.model_dump()


def normalize_device_status(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    checks_raw = raw.get("checks", {})
    checks: dict[str, dict[str, Any]] = {}
    if isinstance(checks_raw, Mapping):
        for key, item in checks_raw.items():
            checks[str(key)] = normalize_check_result(item)
    health = normalize_health(raw.get("health", {}))
    overall_status = _clean_str(raw.get("overall_status"), "unknown")
    if overall_status not in OVERALL_STATUSES:
        overall_status = "unknown"
    model = DeviceStatus(
        device_id=_clean_str(raw.get("device_id"), "unknown-device"),
        overall_status=overall_status,  # type: ignore[arg-type]
        last_seen=normalize_timestamp(raw.get("last_seen")),
        checks=checks,
        health=DeviceHealth.model_validate(health),
    )
    return model.model_dump()


def normalize_event(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    level = _clean_str(raw.get("level"), "info")
    if level not in EVENT_LEVELS:
        level = "info"
    incident_id = _clean_str(raw.get("incident_id")) or None
    boot_id = _clean_str(raw.get("boot_id")) or None
    context = raw.get("context")
    if context is not None and not isinstance(context, Mapping):
        context = {"value": context}
    model = EventRecord(
        timestamp=normalize_timestamp(raw.get("timestamp")),
        component=_clean_str(raw.get("component"), "site_watchdog"),
        level=level,  # type: ignore[arg-type]
        message=_clean_str(raw.get("message"), "event"),
        incident_id=incident_id,
        boot_id=boot_id,
        context=dict(context) if isinstance(context, Mapping) else None,
    )
    return model.model_dump()


def normalize_incident(value: Any) -> dict[str, Any]:
    raw = _dict(value)
    incident_type = _clean_str(raw.get("type"), "unknown")
    if incident_type not in INCIDENT_TYPES:
        incident_type = "unknown"
    status = _clean_str(raw.get("status"), "open")
    if status not in INCIDENT_STATUSES:
        status = "open"
    severity = _clean_str(raw.get("severity"), "warning")
    if severity not in INCIDENT_SEVERITIES:
        severity = "warning"
    evidence_raw = raw.get("evidence", [])
    evidence = [normalize_evidence_item(item) for item in evidence_raw] if isinstance(evidence_raw, list) else []
    actions_raw = raw.get("actions_taken", [])
    actions = [_clean_str(item, "") for item in actions_raw] if isinstance(actions_raw, list) else []
    actions = [item for item in actions if item]
    resolved_at = _clean_str(raw.get("resolved_at")) or None
    if status == "resolved" and not resolved_at:
        resolved_at = iso_utc(utc_now())
    model = Incident(
        incident_id=_clean_str(raw.get("incident_id"), f"inc_{uuid.uuid4().hex[:12]}"),
        timestamp=normalize_timestamp(raw.get("timestamp")),
        boot_id=normalize_boot_id(raw.get("boot_id")),
        device_id=_clean_str(raw.get("device_id"), "unknown-device"),
        type=incident_type,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        cause=_clean_str(raw.get("cause"), "incident recorded"),
        evidence=evidence or [normalize_evidence_item({"source": "system", "message": "no evidence supplied"})],
        actions_taken=actions or ["Recorded by watchdog"],
        resolved_at=resolved_at,
    )
    return model.model_dump()


def normalize_state(value: Any, *, device_id: str | None = None, boot_id: str | None = None) -> dict[str, Any]:
    raw = _dict(value)
    last_status = _clean_str(raw.get("last_status"), "unknown")
    if last_status not in OVERALL_STATUSES:
        last_status = "unknown"
    model = StateRecord(
        device_id=_clean_str(raw.get("device_id"), device_id or "unknown-device"),
        boot_id=_clean_str(raw.get("boot_id"), boot_id or "") or None,
        last_check_at=normalize_timestamp(raw.get("last_check_at"), default_now=False) or None,
        last_healthy_at=normalize_timestamp(raw.get("last_healthy_at"), default_now=False) or None,
        open_incident_id=_clean_str(raw.get("open_incident_id"), "") or None,
        last_status=last_status,  # type: ignore[arg-type]
        last_error=_clean_str(raw.get("last_error"), "") or None,
    )
    return model.model_dump()


def build_incident_id(device_id: str, timestamp: str | None = None) -> str:
    stamp = timestamp or iso_utc()
    dt = parse_iso(stamp) or utc_now()
    return f"inc_{dt.strftime('%Y%m%d_%H%M%S')}_{_slugify(device_id)}_{uuid.uuid4().hex[:6]}"


def build_event(
    *,
    component: str,
    level: EventLevel,
    message: str,
    incident_id: str | None = None,
    boot_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return normalize_event(
        {
            "timestamp": iso_utc(),
            "component": component,
            "level": level,
            "message": message,
            "incident_id": incident_id,
            "boot_id": boot_id,
            "context": context,
        }
    )
