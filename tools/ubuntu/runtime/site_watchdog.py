from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Any

from ..shared.config import V2Config, load_config
from ..shared.logging import setup_logging
from ..shared.models import IncidentSeverity, IncidentType
from ..shared.normalization import (
    build_event,
    build_incident_id,
    normalize_check_result,
    normalize_device_status,
    normalize_incident,
)
from ..shared.paths import log_file_path
from ..shared.storage import (
    append_event,
    append_metric,
    load_build_info,
    get_incident,
    latest_open_incident,
    load_state,
    save_device_status,
    save_incident,
    save_state,
)
from ..shared.system import collect_system_sample
from ..shared.time import iso_utc, load_boot_id
from .process_watchdog import build_process_check


def format_log(message: str, boot_id: str, incident_id: str | None = None) -> str:
    parts = [message, f"boot_id={boot_id}"]
    if incident_id:
        parts.append(f"incident_id={incident_id}")
    return " | ".join(parts)


def ping_host(host: str, timeout_seconds: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), host],
            capture_output=True,
            text=True,
            check=False,
        )
        detail = completed.stdout.strip() or completed.stderr.strip() or f"ping exit code {completed.returncode}"
        result = normalize_check_result(
            {
                "ok": completed.returncode == 0,
                "last_checked": iso_utc(),
                "detail": detail[:240],
            }
        )
        return result
    except FileNotFoundError:
        return normalize_check_result(
            {
                "ok": False,
                "last_checked": iso_utc(),
                "detail": "ping command not available",
            }
        )


def check_wan_hosts(config: V2Config) -> dict[str, Any]:
    host_results = [ping_host(host, config.ping_timeout_seconds) for host in config.wan_hosts]
    if not host_results:
        return normalize_check_result(
            {
                "ok": True,
                "last_checked": iso_utc(),
                "detail": "no WAN hosts configured",
            }
        )
    ok = any(item["ok"] for item in host_results)
    detail = "WAN reachable via " + ", ".join(
        host for host, item in zip(config.wan_hosts, host_results, strict=False) if item["ok"]
    )
    if not ok:
        detail = "WAN unreachable for " + ", ".join(config.wan_hosts)
    return normalize_check_result(
        {
            "ok": ok,
            "last_checked": iso_utc(),
            "detail": detail,
        }
    )


def build_basic_checks(config: V2Config) -> dict[str, dict[str, Any]]:
    return {
        "app": build_process_check(config.app_match),
        "wan": check_wan_hosts(config),
        "boot": normalize_check_result(
            {
                "ok": True,
                "last_checked": iso_utc(),
                "detail": f"boot_id={load_boot_id()}",
            }
        ),
    }


def classify_failure(checks: dict[str, dict[str, Any]]) -> tuple[str, IncidentType, IncidentSeverity, str, list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []
    if not checks["app"]["ok"]:
        evidence.append(
            {
                "source": "check",
                "timestamp": checks["app"]["last_checked"],
                "message": "app process missing",
                "data": {"check": "app", "detail": checks["app"]["detail"]},
            }
        )
        if not checks["wan"]["ok"]:
            evidence.append(
                {
                    "source": "check",
                    "timestamp": checks["wan"]["last_checked"],
                    "message": "wan also failed during app failure",
                    "data": {"check": "wan", "detail": checks["wan"]["detail"]},
                }
            )
        return (
            "app process is not running",
            "app_crash",
            "critical",
            "App process failed.",
            evidence,
        )

    if not checks["wan"]["ok"]:
        evidence.append(
            {
                "source": "check",
                "timestamp": checks["wan"]["last_checked"],
                "message": "wan check failed",
                "data": {"check": "wan", "detail": checks["wan"]["detail"]},
            }
        )
        return (
            "WAN connectivity failed.",
            "wan_down",
            "warning",
            "WAN connectivity failed.",
            evidence,
        )

    return (
        "No fault detected.",
        "unknown",
        "info",
        "System is healthy.",
        evidence,
    )


def build_device_status(
    config: V2Config,
    checks: dict[str, dict[str, Any]],
    state: dict[str, Any],
    observed_at: str,
) -> dict[str, Any]:
    app_ok = bool(checks["app"]["ok"])
    wan_ok = bool(checks["wan"]["ok"])
    overall_status = "healthy"
    notes = "All basic checks passed."
    fault_active = False
    last_incident_id = state.get("open_incident_id")
    last_incident_type = None

    if not app_ok:
        overall_status = "faulted"
        notes = "App process is not running."
        fault_active = True
    elif not wan_ok:
        overall_status = "degraded"
        notes = "WAN connectivity failed."
        fault_active = True

    if last_incident_id:
        incident = get_incident(config, str(last_incident_id))
        if incident:
            last_incident_type = incident.get("type")
            fault_active = incident.get("status") != "resolved" or fault_active
            if incident.get("status") == "resolved":
                last_incident_id = None
                fault_active = False if overall_status == "healthy" else fault_active

    health = {
        "fault_active": fault_active,
        "last_incident_id": last_incident_id,
        "last_incident_type": last_incident_type,
        "last_healthy_at": state.get("last_healthy_at"),
        "notes": notes,
    }
    last_seen = observed_at if overall_status != "faulted" else str(state.get("last_healthy_at") or observed_at)
    return normalize_device_status(
        {
            "device_id": config.device_id,
            "overall_status": overall_status,
            "last_seen": last_seen,
            "checks": checks,
            "health": health,
        }
    )


def create_incident_from_checks(config: V2Config, checks: dict[str, dict[str, Any]], boot_id: str) -> dict[str, Any]:
    cause, incident_type, severity, summary, evidence = classify_failure(checks)
    incident = {
        "incident_id": build_incident_id(config.device_id),
        "timestamp": iso_utc(),
        "boot_id": boot_id,
        "device_id": config.device_id,
        "type": incident_type,
        "status": "open",
        "severity": severity,
        "cause": cause,
        "evidence": evidence
        or [
            {
                "source": "check",
                "timestamp": iso_utc(),
                "message": summary,
                "data": {},
            }
        ],
        "actions_taken": ["Incident created by site watchdog"],
        "resolved_at": None,
    }
    return normalize_incident(incident)


def resolve_incident_record(incident: dict[str, Any], boot_id: str) -> dict[str, Any]:
    actions = list(incident.get("actions_taken", []))
    actions.append("Recovered and marked resolved by site watchdog")
    return normalize_incident(
        {
            **incident,
            "boot_id": boot_id,
            "status": "resolved",
            "resolved_at": iso_utc(),
            "actions_taken": actions,
            "evidence": list(incident.get("evidence", []))
            + [
                {
                    "source": "system",
                    "timestamp": iso_utc(),
                    "message": "checks recovered",
                    "data": {"overall_status": "healthy"},
                }
            ],
        }
    )


@dataclass
class SiteWatchdog:
    config: V2Config

    def __post_init__(self) -> None:
        self.logger = setup_logging(self.config.log_level, log_file_path(self.config), component="site_watchdog")
        build_info = load_build_info()
        self.logger.info(
            format_log(
                f"initialized device_id={self.config.device_id} build={build_info.get('build_number', 'local-dev')}",
                load_boot_id(),
            )
        )

    def run_once(self) -> dict[str, Any]:
        boot_id = load_boot_id()
        self.logger.info(format_log("check cycle start", boot_id))
        state = load_state(self.config)
        system_sample = collect_system_sample()
        append_metric(self.config, system_sample)
        checks = build_basic_checks(self.config)
        observed_at = iso_utc()
        self.logger.info(
            format_log(f"app check ok={checks['app']['ok']} detail={checks['app']['detail']}", boot_id)
        )
        self.logger.info(
            format_log(f"wan check ok={checks['wan']['ok']} detail={checks['wan']['detail']}", boot_id)
        )
        status = build_device_status(self.config, checks, state, observed_at)
        open_incident = latest_open_incident(self.config)
        now = observed_at

        self.logger.info(format_log(f"status={status['overall_status']}", boot_id))

        if status["overall_status"] == "healthy":
            if open_incident:
                self.logger.info(
                    format_log("incident resolved", boot_id, str(open_incident["incident_id"]))
                )
                resolved = resolve_incident_record(open_incident, boot_id)
                resolved_message = "app recovered" if checks["app"]["ok"] else "wan recovered"
                append_event(
                    self.config,
                    build_event(
                        component="site_watchdog",
                        level="info",
                        message=resolved_message,
                        incident_id=resolved["incident_id"],
                        boot_id=boot_id,
                        context={"overall_status": "healthy"},
                    ),
                )
                save_incident(self.config, resolved)
                state["open_incident_id"] = None
                state["last_healthy_at"] = now
                state["last_error"] = None
            else:
                self.logger.info(format_log("no incident open", boot_id))
        else:
            if open_incident is None:
                incident = create_incident_from_checks(self.config, checks, boot_id)
                self.logger.warning(format_log(f"incident created type={incident['type']}", boot_id, incident["incident_id"]))
                failure_message = "app process missing" if not checks["app"]["ok"] else "wan check failed"
                append_event(
                    self.config,
                    build_event(
                        component="site_watchdog",
                        level="warning" if incident["severity"] != "critical" else "error",
                        message=failure_message,
                        incident_id=incident["incident_id"],
                        boot_id=boot_id,
                        context={
                            "overall_status": status["overall_status"],
                            "failed_checks": [name for name, item in checks.items() if not item["ok"]],
                        },
                    ),
                )
                save_incident(self.config, incident)
                state["open_incident_id"] = incident["incident_id"]
                state["last_error"] = incident["cause"]
            else:
                self.logger.warning(
                    format_log("incident still open", boot_id, str(open_incident["incident_id"]))
                )
                failure_message = "app process missing" if not checks["app"]["ok"] else "wan check failed"
                append_event(
                    self.config,
                    build_event(
                        component="site_watchdog",
                        level="warning",
                        message=failure_message,
                        incident_id=open_incident["incident_id"],
                        boot_id=boot_id,
                        context={
                            "overall_status": status["overall_status"],
                            "failed_checks": [name for name, item in checks.items() if not item["ok"]],
                        },
                    ),
                )

        status = build_device_status(self.config, checks, state, observed_at)
        state["device_id"] = self.config.device_id
        state["boot_id"] = boot_id
        state["last_check_at"] = now
        state["last_status"] = status["overall_status"]
        save_device_status(self.config, status)
        save_state(self.config, state)
        self.logger.info(format_log("check cycle complete", boot_id))
        return status

    def run_forever(self) -> None:
        self.logger.info(format_log(f"loop interval={self.config.check_interval_seconds}s", load_boot_id()))
        while True:
            start = time.monotonic()
            try:
                self.run_once()
            except Exception as exc:  # pragma: no cover - defensive runtime guard
                self.logger.exception(format_log(f"run failed: {exc}", load_boot_id()))
            elapsed = time.monotonic() - start
            sleep_for = max(1, self.config.check_interval_seconds - int(elapsed))
            time.sleep(sleep_for)


def main() -> int:
    config = load_config()
    watchdog = SiteWatchdog(config)
    watchdog.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
