from __future__ import annotations

import os
import time
from pathlib import Path
from .common import CheckResult

_CPU_SAMPLE = None

def _read_temperature():
    """
    Collect all plausible thermal sensor readings and use the hottest valid one.
    Some gateway tools report the package/max sensor rather than the first zone,
    which is closer to what the site software shows on this hardware.
    """
    paths = []
    thermal_root = Path("/sys/class/thermal")
    hwmon_root = Path("/sys/class/hwmon")
    try:
        if thermal_root.exists():
            paths.extend(sorted(thermal_root.glob("thermal_zone*/temp")))
        if hwmon_root.exists():
            paths.extend(sorted(hwmon_root.glob("hwmon*/temp*_input")))
    except Exception:
        pass

    readings = []
    for path in paths:
        try:
            raw = path.read_text(encoding="utf-8").strip()
            value = float(raw)
            if value > 1000:
                value = value / 1000.0
            if -20.0 <= value <= 150.0:
                readings.append(round(value, 1))
        except Exception:
            continue

    if readings:
        return max(readings)
    return None

def _mem_percent():
    try:
        data = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, val = line.split(":", 1)
                data[key] = int(val.strip().split()[0])
        total = data["MemTotal"]
        avail = data.get("MemAvailable", data.get("MemFree", 0))
        return round(((total - avail) / total) * 100, 1)
    except Exception:
        return None

def _cpu_load_percent():
    global _CPU_SAMPLE
    try:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
        values = [int(value) for value in fields]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        now = time.monotonic()
        previous = _CPU_SAMPLE
        _CPU_SAMPLE = (total, idle, now)
        if previous is None:
            return None
        total_delta = total - previous[0]
        idle_delta = idle - previous[1]
        if total_delta <= 0:
            return None
        return round(max(0.0, min(100.0, 100.0 * (total_delta - idle_delta) / total_delta)), 1)
    except (OSError, ValueError, IndexError):
        return None
    return None

def check_hardware(cfg):
    th = cfg["thresholds"]
    checks = []

    temp = _read_temperature()
    if temp is None:
        checks.append(CheckResult("temperature", "unknown", "No temperature sensor found"))
    elif temp >= th["cpu_temp_critical_c"]:
        checks.append(CheckResult("temperature", "critical", "CPU temperature critical", temp, True))
    elif temp >= th["cpu_temp_warning_c"]:
        checks.append(CheckResult("temperature", "warning", "CPU temperature high", temp))
    else:
        checks.append(CheckResult("temperature", "healthy", "CPU temperature OK", temp))

    ram = _mem_percent()
    if ram is None:
        checks.append(CheckResult("ram", "unknown", "RAM usage unavailable"))
    elif ram >= th["ram_critical_percent"]:
        checks.append(CheckResult("ram", "critical", "RAM usage critical", ram, True))
    elif ram >= th["ram_warning_percent"]:
        checks.append(CheckResult("ram", "warning", "RAM usage high", ram))
    else:
        checks.append(CheckResult("ram", "healthy", "RAM usage OK", ram))

    cpu = _cpu_load_percent()
    if cpu is None:
        checks.append(CheckResult("cpu_load", "healthy", "CPU load sampling", None))
    else:
        checks.append(CheckResult("cpu_load", "healthy", "CPU load", cpu))

    wdt_device = cfg["hardware_watchdog"]["device"]
    checks.append(CheckResult(
        "hardware_watchdog_present",
        "healthy" if os.path.exists(wdt_device) else "critical",
        f"{wdt_device} present" if os.path.exists(wdt_device) else f"{wdt_device} not present",
        os.path.exists(wdt_device),
        False,
    ))

    return checks
