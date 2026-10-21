"""Read-only status for the Raspberry Pi watchdog owned by systemd PID 1."""

import subprocess
import re
from pathlib import Path


DEVICE = Path("/dev/watchdog0")
SYSFS = Path("/sys/class/watchdog/watchdog0")


def _read(path):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _runtime_seconds(raw):
    """systemctl may render the manager timeout as microseconds or e.g. '15s'."""
    value = str(raw).strip()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(us|ms|s|min|h)?", value)
    if not match:
        return 0.0
    number = float(match.group(1))
    multiplier = {None: 0.000001, "us": 0.000001, "ms": 0.001,
                  "s": 1, "min": 60, "h": 3600}[match.group(2)]
    return number * multiplier


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
        runtime_seconds = _runtime_seconds(manager.stdout) if manager.returncode == 0 else 0.0
    except (OSError, subprocess.SubprocessError):
        runtime_seconds = 0.0
    configured = runtime_seconds > 0
    active = configured and present and state == "active"
    return {
        "backend": "systemd",
        "device": str(DEVICE),
        "present": present,
        "identity": identity,
        "state": state or "unknown",
        "configured": configured,
        "active": active,
        "manager_timeout_seconds": round(runtime_seconds, 1),
        "device_timeout_seconds": int(timeout) if timeout.isdigit() else None,
    }
