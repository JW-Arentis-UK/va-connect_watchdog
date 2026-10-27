"""Compatibility import for installations using the former recovery policy."""
from .recovery import RecoveryEngine


class ConsolidatedRecovery(RecoveryEngine):
    """Old policy settings cannot re-enable network restarts or automatic reboot."""
