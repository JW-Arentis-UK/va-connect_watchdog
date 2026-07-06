from __future__ import annotations

from .common import CheckResult

def check_network(cfg):
    # Placeholder for camera/router/internet checks.
    # Keep disabled initially so the watchdog cannot reboot due to network conditions.
    return [
        CheckResult("network_module", "healthy", "Network checks not configured yet", None, False)
    ]
