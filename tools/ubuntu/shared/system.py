from __future__ import annotations

from pathlib import Path
import os
import shutil
from typing import Any

from .time import iso_utc


_LAST_CPU_SAMPLE: tuple[int, int] | None = None


def _disk_root() -> Path:
    anchor = Path.cwd().anchor
    return Path(anchor or "/")


def _read_cpu_times() -> tuple[int, int] | None:
    try:
        line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
        parts = [int(value) for value in line.split()[1:]]
    except Exception:
        return None
    if len(parts) < 4:
        return None
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    total = sum(parts)
    return total, idle


def _cpu_percent() -> float | None:
    global _LAST_CPU_SAMPLE
    current = _read_cpu_times()
    if current is None:
        return None
    if _LAST_CPU_SAMPLE is None:
        _LAST_CPU_SAMPLE = current
        return None
    total_delta = current[0] - _LAST_CPU_SAMPLE[0]
    idle_delta = current[1] - _LAST_CPU_SAMPLE[1]
    _LAST_CPU_SAMPLE = current
    if total_delta <= 0:
        return None
    busy = max(0.0, 1.0 - (idle_delta / total_delta))
    return round(busy * 100.0, 1)


def _memory_percent() -> float | None:
    total_kb = None
    available_kb = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                total_kb = int(line.split(":", 1)[1].strip().split()[0])
            elif line.startswith("MemAvailable:"):
                available_kb = int(line.split(":", 1)[1].strip().split()[0])
    except Exception:
        return None
    if not total_kb or available_kb is None:
        return None
    used = max(0, total_kb - available_kb)
    return round((used / total_kb) * 100.0, 1)


def _temperature_c() -> float | None:
    try:
        thermal_root = Path("/sys/class/thermal")
        if not thermal_root.exists():
            return None
    except Exception:
        return None
    values: list[float] = []
    for zone_temp in thermal_root.glob("thermal_zone*/temp"):
        try:
            value = float(zone_temp.read_text(encoding="utf-8").strip())
        except Exception:
            continue
        if value > 1000:
            value = value / 1000.0
        if -20.0 <= value <= 150.0:
            values.append(round(float(value), 1))
    if values:
        return max(values)
    return None


def collect_system_sample() -> dict[str, Any]:
    cpu = _cpu_percent()
    memory = _memory_percent()
    try:
        usage = shutil.disk_usage(_disk_root())
        disk = round((usage.used / usage.total) * 100.0, 1) if usage.total else None
    except Exception:
        disk = None
    try:
        if hasattr(os, "getloadavg"):
            load_1, load_5, load_15 = os.getloadavg()
        else:
            load_1 = load_5 = load_15 = None
    except Exception:
        load_1 = load_5 = load_15 = None
    return {
        "timestamp": iso_utc(),
        "cpu_percent": cpu,
        "memory_percent": memory,
        "disk_percent": disk,
        "temperature_c": _temperature_c(),
        "load_1": round(float(load_1), 2) if load_1 is not None else None,
        "load_5": round(float(load_5), 2) if load_5 is not None else None,
        "load_15": round(float(load_15), 2) if load_15 is not None else None,
    }
