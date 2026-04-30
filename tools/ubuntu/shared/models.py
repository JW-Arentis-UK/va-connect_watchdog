from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Literal


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


@dataclass(frozen=True)
class EvidenceItem:
    source: str
    timestamp: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Incident:
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


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    last_checked: str
    detail: str


@dataclass(frozen=True)
class DeviceHealth:
    fault_active: bool
    last_incident_id: str | None = None
    last_incident_type: IncidentType | None = None
    last_healthy_at: str | None = None
    notes: str = ""


@dataclass(frozen=True)
class DeviceStatus:
    device_id: str
    overall_status: OverallStatus
    last_seen: str
    checks: Dict[str, CheckResult]
    health: DeviceHealth


@dataclass(frozen=True)
class EventRecord:
    timestamp: str
    component: str
    level: EventLevel
    message: str
    event_type: str | None = None
    incident_id: str | None = None
    boot_id: str | None = None
    context: Dict[str, Any] | None = None


@dataclass(frozen=True)
class StateRecord:
    device_id: str
    boot_id: str | None = None
    last_check_at: str | None = None
    last_healthy_at: str | None = None
    last_watchdog_write_at: str | None = None
    system_time: str | None = None
    rtc_available: bool | None = None
    rtc_time: str | None = None
    rtc_read_ok: bool | None = None
    clock_drift_seconds: int | None = None
    last_rtc_sync_at: str | None = None
    last_rtc_sync_result: str | None = None
    last_rtc_sync_message: str | None = None
    open_incident_id: str | None = None
    last_status: OverallStatus = "unknown"
    last_error: str | None = None
    gateway_process_running: bool | None = None
    gateway_process_pid: int | None = None
    gateway_process_cmd: str | None = None
    gateway_process_start_time: str | None = None
    gateway_process_restarted: bool | None = None
    gateway_process_restart_count: int | None = None
    gateway_process_last_pid: int | None = None
    gateway_process_last_restart_at: str | None = None
    process_running: bool | None = None
    process_pid: int | None = None
    process_cmd: str | None = None
    process_start_time: str | None = None
    process_restarted: bool | None = None
    restart_count: int | None = None
    last_process_pid: int | None = None
    last_process_restart_time: str | None = None
    system_metrics: Dict[str, Any] = field(default_factory=dict)
