from __future__ import annotations

import os
import subprocess
from .common import CheckResult

def _read_first_temp():
    paths = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
        "/sys/class/hwmon/hwmon1/temp1_input",
    ]
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            return round(int(raw) / 1000, 1)
        except Exception:
            pass
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
    try:
        out = subprocess.check_output(["bash", "-lc", "top -bn1 | grep 'Cpu(s)'"], text=True)
        # Example: %Cpu(s):  1.0 us,  0.3 sy,  0.0 ni, 98.7 id...
        idle_part = [x for x in out.split(",") if " id" in x]
        if idle_part:
            idle = float(idle_part[0].strip().split()[0])
            return round(100 - idle, 1)
    except Exception:
        pass
    return None

def check_hardware(cfg):
    th = cfg["thresholds"]
    checks = []

    temp = _read_first_temp()
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
    checks.append(CheckResult("cpu_load", "healthy" if cpu is not None else "unknown", "CPU load", cpu))

    wdt_device = cfg["hardware_watchdog"]["device"]
    checks.append(CheckResult(
        "hardware_watchdog_present",
        "healthy" if os.path.exists(wdt_device) else "warning",
        f"{wdt_device} present" if os.path.exists(wdt_device) else f"{wdt_device} not present",
        os.path.exists(wdt_device)
    ))

    return checks
