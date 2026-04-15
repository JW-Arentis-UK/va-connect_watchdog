from __future__ import annotations

from typing import Any, Dict, Literal

from pydantic import BaseModel, ConfigDict, Field


IncidentType = Literal[
    "wan_down",
    "lan_down",
    "app_crash",
    "service_failure",
    "unexpected_reboot",
    "watchdog_reboot",
    "manual_recovery",
    "unknown",
]

IncidentStatus = Literal["open", "monitoring", "resolved"]
IncidentSeverity = Literal["info", "warning", "critical"]
EventLevel = Literal["debug", "info", "warning", "error"]
OverallStatus = Literal["healthy", "degraded", "faulted", "unknown"]


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    timestamp: str
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    timestamp: str
    boot_id: str
    device_id: str
    type: IncidentType
    status: IncidentStatus
    severity: IncidentSeverity
    cause: str
    evidence: list[EvidenceItem]
    actions_taken: list[str]
    resolved_at: str | None = None


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    last_checked: str
    detail: str


class DeviceHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fault_active: bool
    last_incident_id: str | None = None
    last_incident_type: IncidentType | None = None
    last_healthy_at: str | None = None
    notes: str = ""


class DeviceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    overall_status: OverallStatus
    last_seen: str
    checks: Dict[str, CheckResult]
    health: DeviceHealth


class EventRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    component: str
    level: EventLevel
    message: str
    incident_id: str | None = None
    boot_id: str | None = None
    context: Dict[str, Any] | None = None


class StateRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    boot_id: str | None = None
    last_check_at: str | None = None
    last_healthy_at: str | None = None
    open_incident_id: str | None = None
    last_status: OverallStatus = "unknown"
    last_error: str | None = None
