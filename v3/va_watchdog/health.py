from __future__ import annotations

from .common import now_iso, worst_state, score_from_checks
from .hardware import check_hardware
from .storage import check_storage
from .services import check_services
from .network import check_network

def collect_health(cfg):
    checks = []
    checks.extend(check_hardware(cfg))
    checks.extend(check_storage(cfg))
    checks.extend(check_services(cfg))
    checks.extend(check_network(cfg))

    critical_failed = any(c.state == "critical" and c.critical for c in checks)

    return {
        "time": now_iso(),
        "state": worst_state([c.state for c in checks]),
        "score": score_from_checks(checks),
        "critical_failed": critical_failed,
        "checks": [c.to_dict() for c in checks],
    }, checks
