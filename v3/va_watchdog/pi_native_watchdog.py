"""Read-only status for the Raspberry Pi watchdog owned by systemd PID 1."""

import subprocess
from pathlib import Path


DEVICE = Path("/dev/watchdog0")
SYSFS = Path("/sys/class/watchdog/watchdog0")


def _read(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def inspect():
    present = DEVICE.exists()
    state = _read(SYSFS / "state")
    identity = _read(SYSFS / "identity")
    timeout = _read(SYSFS / "timeout")
    try:
        manager = subprocess.run(
            ["systemctl", "show", "-p", "RuntimeWatchdogUSec", "--value"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        runtime_usec = int(manager.stdout.strip()) if manager.returncode == 0 else 0
    except (OSError, ValueError, subprocess.SubprocessError):
        runtime_usec = 0
    configured = runtime_usec > 0
    active = configured and present and state == "active"
    return {
        "backend": "systemd",
        "device": str(DEVICE),
        "present": present,
        "identity": identity,
        "state": state or "unknown",
        "configured": configured,
        "active": active,
        "manager_timeout_seconds": round(runtime_usec / 1_000_000, 1),
        "device_timeout_seconds": int(timeout) if timeout.isdigit() else None,
    }
