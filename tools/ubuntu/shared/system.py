from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import subprocess
import shutil
import time
from typing import Any

_LAST_CPU_SAMPLE: tuple[int, int] | None = None


def _config_dict(config: Any | None) -> dict[str, Any]:
    if config is None:
        return {}
    if isinstance(config, dict):
        return dict(config)
    data: dict[str, Any] = {}
    for key in ("monitor_paths", "disk_thresholds", "data_dir", "device_id", "app_match", "watch_process"):
        if hasattr(config, key):
            data[key] = getattr(config, key)
    return data


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _watch_process_config(config: Any | None) -> dict[str, Any]:
    config_data = _config_dict(config)
    watch_process = config_data.get("watch_process") if isinstance(config_data.get("watch_process"), dict) else {}
    if not isinstance(watch_process, dict):
        watch_process = {}
    name = str(watch_process.get("name") or config_data.get("app_match") or "").strip()
    cmd_contains = str(watch_process.get("cmd_contains") or name).strip()
    enabled = bool(watch_process.get("enabled", True))
    return {
        "enabled": enabled,
        "name": name,
        "cmd_contains": cmd_contains,
    }


def _proc_boot_time_epoch() -> float | None:
    try:
        uptime_raw = Path("/proc/uptime").read_text(encoding="utf-8").split()[0]
        uptime_seconds = float(uptime_raw)
        return time.time() - uptime_seconds
    except Exception:
        return None


def _read_proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except Exception:
        return ""
    return " ".join(part.decode("utf-8", errors="ignore") for part in raw.split(b"\x00") if part).strip()


def _read_proc_comm(pid: int) -> str:
    return _safe_read_text(Path(f"/proc/{pid}/comm"))


def _read_proc_start_time(pid: int) -> str | None:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return None
    if not stat_text:
        return None
    try:
        after_comm = stat_text.rsplit(") ", 1)[1]
        fields = after_comm.split()
        if len(fields) < 20:
            return None
        start_ticks = float(fields[19])
        clk_tck = float(os.sysconf("SC_CLK_TCK"))
        boot_epoch = _proc_boot_time_epoch()
        if boot_epoch is None or clk_tck <= 0:
            return None
        start_epoch = boot_epoch + (start_ticks / clk_tck)
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(start_epoch))
    except Exception:
        return None


def _process_candidates(config: Any | None = None) -> list[dict[str, Any]]:
    process_config = _watch_process_config(config)
    if not process_config["enabled"]:
        return []
    exact_name = process_config["name"]
    cmd_contains = process_config["cmd_contains"]
    candidates: list[dict[str, Any]] = []
    try:
        proc_entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except Exception:
        return []
    for entry in proc_entries:
        pid = int(entry)
        comm = _read_proc_comm(pid)
        cmdline = _read_proc_cmdline(pid)
        match_exact = bool(exact_name) and comm == exact_name
        match_cmd = bool(cmd_contains) and cmd_contains in cmdline
        if not (match_exact or match_cmd):
            continue
        candidates.append(
            {
                "pid": pid,
                "comm": comm,
                "cmdline": cmdline,
                "match_mode": "exact" if match_exact else "command",
                "start_time": _read_proc_start_time(pid),
            }
        )
    candidates.sort(key=lambda item: (0 if item.get("match_mode") == "exact" else 1, -int(item.get("pid") or 0)))
    return candidates


def collect_process_sample(config: Any | None = None) -> dict[str, Any]:
    candidates = _process_candidates(config)
    found = candidates[0] if candidates else {}
    process_running = bool(found)
    process_pid = int(found["pid"]) if found.get("pid") is not None else None
    return {
        "process_running": process_running,
        "process_pid": process_pid,
        "process_cmd": str(found.get("cmdline") or found.get("comm") or "") if found else "",
        "process_start_time": str(found.get("start_time") or "") if found else "",
        "process_match_mode": str(found.get("match_mode") or "") if found else "",
        "process_name": str(found.get("comm") or "") if found else "",
        "process_pids": [int(item["pid"]) for item in candidates if item.get("pid") is not None],
    }


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


def _memory_info() -> tuple[int | None, int | None] | None:
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
    return total_kb, available_kb


def _memory_percent() -> float | None:
    info = _memory_info()
    if info is None:
        return None
    total_kb, available_kb = info
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


def _read_rtc_info() -> dict[str, Any]:
    rtc_root = Path("/sys/class/rtc/rtc0")
    if not rtc_root.exists():
        return {
            "available": False,
            "read_ok": False,
            "text": "Not present",
            "error": "RTC not present",
        }
    try:
        date_text = _safe_read_text(rtc_root / "date")
        time_text = _safe_read_text(rtc_root / "time")
        if date_text and time_text:
            return {
                "available": True,
                "read_ok": True,
                "text": f"{date_text} {time_text}",
                "error": "",
            }
    except Exception as exc:
        return {
            "available": True,
            "read_ok": False,
            "text": "Read error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    try:
        completed = subprocess.run(["hwclock", "--show"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {
            "available": True,
            "read_ok": False,
            "text": "Read error",
            "error": "hwclock command not found",
        }
    except Exception as exc:
        return {
            "available": True,
            "read_ok": False,
            "text": "Read error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode != 0 or not stdout:
        return {
            "available": True,
            "read_ok": False,
            "text": "Read error" if stderr else "Unavailable",
            "error": stderr or stdout or f"hwclock exit code {completed.returncode}",
        }
    return {
        "available": True,
        "read_ok": True,
        "text": stdout,
        "error": "",
    }


def _disk_usage_for_path(path: str) -> dict[str, Any]:
    target = str(path or "").strip() or "/"
    try:
        usage = shutil.disk_usage(target)
    except Exception as exc:
        return {
            "path": target,
            "available": False,
            "status": "unavailable",
            "note": f"Path unavailable: {target}",
            "error": str(exc),
            "total_bytes": None,
            "used_bytes": None,
            "free_bytes": None,
            "used_percent": None,
            "free_percent": None,
            "free_gb": None,
        }
    total = int(usage.total)
    used = int(usage.used)
    free = int(usage.free)
    used_percent = round((used / total) * 100.0, 1) if total else None
    free_percent = round((free / total) * 100.0, 1) if total else None
    return {
        "path": target,
        "available": True,
        "status": "ok",
        "note": "",
        "error": "",
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "used_percent": used_percent,
        "free_percent": free_percent,
        "free_gb": round(free / (1024 ** 3), 2) if total else None,
    }


def _coerce_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except Exception:
        return None


def _threshold_float(raw: dict[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    coerced = _coerce_float(value)
    return default if coerced is None else float(coerced)


def _assess_cpu(cpu_percent: float | None) -> str:
    if cpu_percent is None:
        return "unavailable"
    if cpu_percent > 95:
        return "critical"
    if cpu_percent > 85:
        return "warning"
    return "ok"


def _assess_memory(memory_percent: float | None) -> str:
    if memory_percent is None:
        return "unavailable"
    if memory_percent > 95:
        return "critical"
    if memory_percent > 85:
        return "warning"
    return "ok"


def _assess_load(load_1: float | None, cpu_count: int | None) -> str:
    if load_1 is None:
        return "unavailable"
    limit = float(cpu_count or 1)
    if load_1 >= limit:
        return "critical"
    if load_1 >= max(1.0, limit * 0.75):
        return "warning"
    return "ok"


def _assess_disk(disk: dict[str, Any], *, warning_free_gb: float, critical_free_gb: float, expected_high_usage: bool) -> dict[str, Any]:
    if not disk.get("available"):
        disk["status"] = "unavailable"
        return disk
    free_gb = _coerce_float(disk.get("free_gb"))
    status = "ok"
    if free_gb is not None:
        if free_gb < critical_free_gb:
            status = "critical"
        elif free_gb < warning_free_gb:
            status = "warning"
    disk["status"] = status
    if status == "ok" and expected_high_usage:
        disk["note"] = "High usage expected for managed recording storage"
    elif status == "warning":
        disk["note"] = f"Low free space: {disk.get('free_gb')}GB free"
    elif status == "critical":
        disk["note"] = f"Critically low free space: {disk.get('free_gb')}GB free"
    return disk


def _dedupe_phrases(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        cleaned = " ".join(text.split())
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(cleaned[:1].upper() + cleaned[1:] if cleaned else cleaned)
    return result


def collect_system_sample(config: Any | None = None) -> dict[str, Any]:
    config_data = _config_dict(config)
    monitor_paths = config_data.get("monitor_paths") if isinstance(config_data.get("monitor_paths"), dict) else {}
    disk_thresholds = config_data.get("disk_thresholds") if isinstance(config_data.get("disk_thresholds"), dict) else {}
    os_path = str((monitor_paths or {}).get("os_path") or "/").strip() or "/"
    recording_path_raw = str((monitor_paths or {}).get("recording_path") or "").strip()
    recording_path = recording_path_raw or None

    process_sample = collect_process_sample(config)
    cpu = _cpu_percent()
    memory_info = _memory_info()
    memory = _memory_percent()
    try:
        if hasattr(os, "getloadavg"):
            load_1, load_5, load_15 = os.getloadavg()
        else:
            load_1 = load_5 = load_15 = None
    except Exception:
        load_1 = load_5 = load_15 = None
    memory_total_bytes = int(memory_info[0] * 1024) if memory_info and memory_info[0] is not None else None
    memory_available_bytes = int(memory_info[1] * 1024) if memory_info and memory_info[1] is not None else None
    memory_used_bytes = (
        max(0, memory_total_bytes - memory_available_bytes)
        if memory_total_bytes is not None and memory_available_bytes is not None
        else None
    )
    load_1_value = round(float(load_1), 2) if load_1 is not None else None
    load_5_value = round(float(load_5), 2) if load_5 is not None else None
    load_15_value = round(float(load_15), 2) if load_15 is not None else None
    cpu_count = int(os.cpu_count() or 1)

    os_disk = _disk_usage_for_path(os_path)
    recording_storage = None
    if recording_path:
        recording_storage = _disk_usage_for_path(recording_path)

    os_warning_free_gb = _threshold_float(disk_thresholds, "os_warning_free_gb", 5.0)
    os_critical_free_gb = _threshold_float(disk_thresholds, "os_critical_free_gb", 2.0)
    recording_warning_free_gb = _threshold_float(disk_thresholds, "recording_warning_free_gb", 20.0)
    recording_critical_free_gb = _threshold_float(disk_thresholds, "recording_critical_free_gb", 5.0)
    recording_high_usage_expected = bool(disk_thresholds.get("recording_high_usage_expected", True))

    os_disk = _assess_disk(os_disk, warning_free_gb=os_warning_free_gb, critical_free_gb=os_critical_free_gb, expected_high_usage=False)
    if recording_storage is not None:
        recording_storage = _assess_disk(
            recording_storage,
            warning_free_gb=recording_warning_free_gb,
            critical_free_gb=recording_critical_free_gb,
            expected_high_usage=recording_high_usage_expected,
        )

    cpu_status = _assess_cpu(cpu)
    memory_status = _assess_memory(memory)
    load_status = _assess_load(load_1_value, cpu_count)
    temperature_c = _temperature_c()
    system_dt = datetime.now().astimezone().replace(microsecond=0)
    system_time = system_dt.isoformat()
    rtc_info = _read_rtc_info()
    clock_drift_seconds = None
    if bool(rtc_info.get("read_ok")) and str(rtc_info.get("text") or "").strip():
        rtc_text = str(rtc_info.get("text") or "").strip()
        rtc_dt = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                parsed = datetime.strptime(rtc_text, fmt)
            except Exception:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=system_dt.tzinfo or timezone.utc)
            rtc_dt = parsed.astimezone(system_dt.tzinfo or timezone.utc)
            break
        if rtc_dt is not None:
            try:
                clock_drift_seconds = abs(int((system_dt - rtc_dt).total_seconds()))
            except Exception:
                clock_drift_seconds = None

    potential_factors: list[str] = []
    if os_disk.get("status") == "critical":
        potential_factors.append(f"OS disk critically low: {os_disk.get('free_gb')}GB free")
    elif os_disk.get("status") == "unavailable":
        potential_factors.append(f"OS disk unavailable: {os_path}")
    if recording_storage is not None:
        if recording_storage.get("status") == "critical":
            potential_factors.append(f"Recording location critically low: {recording_storage.get('free_gb')}GB free")
        elif recording_storage.get("status") == "unavailable":
            potential_factors.append(f"Recording path unavailable: {recording_path}")
    if cpu_status in {"warning", "critical"} and (cpu or 0) > 90:
        potential_factors.append("High CPU load")
    if load_status in {"warning", "critical"}:
        potential_factors.append("System overloaded")
    if memory_status in {"warning", "critical"} and (memory or 0) > 90:
        potential_factors.append("Memory pressure")

    if recording_storage is not None and recording_storage.get("status") == "ok" and recording_high_usage_expected:
        note = str(recording_storage.get("note") or "").strip()
        if not note:
            recording_storage["note"] = "High usage expected for managed recording storage"

    metrics_available = any(
        value not in (None, "", [])
        for value in (
            cpu,
            memory,
            load_1_value,
            load_5_value,
            load_15_value,
            temperature_c,
            os_disk.get("available"),
            recording_storage.get("available") if isinstance(recording_storage, dict) else None,
        )
    )

    all_metrics_unavailable = not any(
        value not in (None, "", [])
        for value in (
            cpu,
            memory,
            load_1_value,
            load_5_value,
            load_15_value,
            temperature_c,
            os_disk.get("available"),
            recording_storage.get("available") if isinstance(recording_storage, dict) else None,
        )
    )

    return {
        "timestamp": system_time,
        "system_time": system_time,
        "cpu_source": "proc_stat" if cpu is not None else "",
        "cpu_percent": cpu,
        "cpu_count": cpu_count,
        "cpu_status": cpu_status,
        "memory_total_bytes": memory_total_bytes,
        "memory_available_bytes": memory_available_bytes,
        "memory_used_bytes": memory_used_bytes,
        "memory_percent": memory,
        "memory_status": memory_status,
        "load_1": load_1_value,
        "load_5": load_5_value,
        "load_15": load_15_value,
        "load_status": load_status,
        "temperature_c": temperature_c,
        "os_disk": os_disk,
        "recording_storage": recording_storage,
        "process_running": bool(process_sample.get("process_running")),
        "process_pid": process_sample.get("process_pid"),
        "process_cmd": process_sample.get("process_cmd"),
        "process_start_time": process_sample.get("process_start_time"),
        "process_match_mode": process_sample.get("process_match_mode"),
        "gateway_process_running": bool(process_sample.get("process_running")),
        "gateway_process_pid": process_sample.get("process_pid"),
        "gateway_process_cmd": process_sample.get("process_cmd"),
        "gateway_process_start_time": process_sample.get("process_start_time"),
        "gateway_process_last_pid": process_sample.get("process_pid"),
        "gateway_process_pids": process_sample.get("process_pids") or [],
        "gateway_process_restart_count": 0,
        "gateway_process_restarted": False,
        "gateway_process_last_restart_at": "",
        "monitor_paths": {
            "os_path": os_path,
            "recording_path": recording_path or "",
        },
        "disk_thresholds": {
            "os_warning_free_gb": os_warning_free_gb,
            "os_critical_free_gb": os_critical_free_gb,
            "recording_warning_free_gb": recording_warning_free_gb,
            "recording_critical_free_gb": recording_critical_free_gb,
            "recording_high_usage_expected": recording_high_usage_expected,
        },
        "potential_factors": _dedupe_phrases(potential_factors),
        "metrics_available": metrics_available,
        "all_metrics_unavailable": all_metrics_unavailable,
        "rtc_available": bool(rtc_info.get("available")),
        "rtc_read_ok": bool(rtc_info.get("read_ok")),
        "rtc_time": str(rtc_info.get("text") or ""),
        "rtc_read_error": str(rtc_info.get("error") or ""),
        "clock_drift_seconds": clock_drift_seconds,
    }
