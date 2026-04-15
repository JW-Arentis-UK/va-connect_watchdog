from __future__ import annotations

from pathlib import Path
import os
import shutil
from typing import Any

import psutil

from .time import iso_utc


def _disk_root() -> Path:
    anchor = Path.cwd().anchor
    return Path(anchor or "/")


def _temperature_c() -> float | None:
    try:
        temps = psutil.sensors_temperatures(fahrenheit=False)
    except Exception:
        return None
    for entries in temps.values():
        for entry in entries:
            value = getattr(entry, "current", None)
            if value is not None:
                try:
                    return round(float(value), 1)
                except Exception:
                    continue
    return None


def collect_system_sample() -> dict[str, Any]:
    cpu = None
    memory = None
    try:
        cpu = round(float(psutil.cpu_percent(interval=None)), 1)
    except Exception:
        cpu = None
    try:
        memory = round(float(psutil.virtual_memory().percent), 1)
    except Exception:
        memory = None
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
