from __future__ import annotations

import time

from .common import CheckResult, now_iso, worst_state, score_from_checks
from .hardware import check_hardware
from .storage import check_storage
from .services import check_services
from .network import check_network
from .process_monitor import check_watchdog_process

_COLLECTOR_CACHE = {}


def _cached_checks(name, interval, collect):
    now = time.monotonic()
    cached = _COLLECTOR_CACHE.get(name)
    if cached and now - cached[0] < max(1.0, float(interval)):
        return list(cached[1])
    try:
        checks = list(collect())
        _COLLECTOR_CACHE[name] = (now, checks)
        return checks
    except Exception as exc:
        if cached:
            return list(cached[1])
        return [CheckResult(f"{name}_collector", "unknown", f"Collector unavailable: {exc}")]


def build_startup_summary(cfg, checks):
    check_map = {check.name: check for check in checks}
    healthy = [check.name for check in checks if check.state == "healthy"]
    warnings = [check.name for check in checks if check.state == "warning"]
    degraded = [check.name for check in checks if check.state == "degraded"]
    critical = [check.name for check in checks if check.state == "critical"]

    optional_missing = []
    hardware_watchdog_cfg = cfg.get("hardware_watchdog", {})
    if not hardware_watchdog_cfg.get("enabled", False):
        optional_missing.append("hardware watchdog disabled in config")

    hw_check = check_map.get("hardware_watchdog_present")
    if hw_check is not None and hw_check.state == "warning":
        optional_missing.append(hw_check.message)

    service_states = [
        {
            "name": check.name,
            "state": check.state,
            "message": check.message,
        }
        for check in checks
        if check.name.endswith(".service")
    ]

    headline = "System ready"
    if critical:
        headline = "Startup has critical failures"
    elif warnings or degraded:
        headline = "System ready with warnings"

    details = []
    if healthy:
        details.append(f"{len(healthy)} healthy checks")
    if warnings:
        details.append(f"{len(warnings)} warning checks")
    if degraded:
        details.append(f"{len(degraded)} degraded checks")
    if critical:
        details.append(f"{len(critical)} critical checks")
    if optional_missing:
        details.append("; ".join(optional_missing))

    return {
        "headline": headline,
        "details": details,
        "healthy_checks": healthy,
        "warning_checks": warnings,
        "degraded_checks": degraded,
        "critical_checks": critical,
        "optional_missing": optional_missing,
        "service_states": service_states,
        "generated_at": now_iso(),
    }

def collect_health(cfg):
    checks = []
    intervals = cfg.get("collector_intervals", {}) if isinstance(cfg.get("collector_intervals"), dict) else {}
    checks.extend(_cached_checks("hardware", intervals.get("hardware_seconds", 5), lambda: check_hardware(cfg)))
    checks.extend(_cached_checks("storage", intervals.get("storage_seconds", 30), lambda: check_storage(cfg)))
    checks.extend(_cached_checks("services", intervals.get("services_seconds", 15), lambda: check_services(cfg)))
    checks.extend(_cached_checks("network", intervals.get("network_seconds", 30), lambda: check_network(cfg)))
    checks.extend(_cached_checks("process", intervals.get("process_seconds", 5), lambda: [check_watchdog_process(cfg)]))

    critical_failed = any(c.state == "critical" and c.critical for c in checks)
    recording_storage = next((c.value for c in checks if c.name == "recording_storage"), None)

    status = {
        "time": now_iso(),
        "state": worst_state([c.state for c in checks]),
        "score": score_from_checks(checks),
        "critical_failed": critical_failed,
        "checks": [c.to_dict() for c in checks],
        "startup_summary": build_startup_summary(cfg, checks),
    }
    if isinstance(recording_storage, dict):
        status["recording_storage"] = recording_storage
    process_check = next((c.value for c in checks if c.name == "watchdog_process"), None)
    if isinstance(process_check, dict):
        status["watchdog_process"] = process_check
    return status, checks
