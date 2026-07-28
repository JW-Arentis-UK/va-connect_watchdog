from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def blackbox_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    configured = cfg.get("blackbox", {}) if isinstance(cfg.get("blackbox", {}), dict) else {}
    return {
        "enabled": bool(configured.get("enabled", True)),
        "path": str(configured.get("path") or data_dir / "blackbox.jsonl"),
        "state_path": str(configured.get("state_path") or data_dir / "blackbox-state.json"),
        "sample_seconds": int(configured.get("sample_seconds", 60) or 60),
        "max_rows": int(configured.get("max_rows", 300) or 300),
        "top_process_count": int(configured.get("top_process_count", 8) or 8),
        "journal_lines": int(configured.get("journal_lines", 30) or 30),
    }


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def check_unexpected_boot(cfg: dict[str, Any], event_log=None) -> dict[str, Any]:
    bb_cfg = blackbox_cfg(cfg)
    state_path = Path(bb_cfg["state_path"])
    current = boot_id()
    previous = {}
    try:
        if state_path.exists():
            previous = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        previous = {}
    last_boot = str(previous.get("boot_id") or "")
    changed = bool(last_boot and current and last_boot != current)
    result = {
        "changed": changed,
        "previous_boot_id": last_boot,
        "current_boot_id": current,
        "previous_time": previous.get("updated_at", ""),
        "detected_at": _now_iso(),
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps({"boot_id": current, "updated_at": result["detected_at"]}, indent=2), encoding="utf-8")
    os.replace(temporary, state_path)
    if changed and event_log:
        event_log.add("warning", "blackbox", "Unexpected reboot detected", result)
    return result


def maybe_capture_blackbox(cfg: dict[str, Any], status: dict[str, Any], force: bool = False) -> dict[str, Any]:
    bb_cfg = blackbox_cfg(cfg)
    if not bb_cfg["enabled"]:
        return {"captured": False, "reason": "disabled"}
    path = Path(bb_cfg["path"])
    interval = max(10, int(bb_cfg["sample_seconds"]))
    last_time = _last_snapshot_time(path)
    now = time.time()
    if not force and last_time and now - last_time < interval:
        return {"captured": False, "reason": "interval", "age_seconds": round(now - last_time, 1)}
    snapshot = build_snapshot(cfg, status)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
    trim_blackbox(cfg)
    return {"captured": True, "path": str(path), "time": snapshot["time"]}


def read_blackbox(cfg: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    path = Path(blackbox_cfg(cfg)["path"])
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def blackbox_summary(cfg: dict[str, Any]) -> dict[str, Any]:
    bb_cfg = blackbox_cfg(cfg)
    path = Path(bb_cfg["path"])
    rows = read_blackbox(cfg, limit=bb_cfg["max_rows"])
    last = rows[-1] if rows else {}
    return {
        "enabled": bb_cfg["enabled"],
        "path": str(path),
        "sample_seconds": bb_cfg["sample_seconds"],
        "max_rows": bb_cfg["max_rows"],
        "rows": len(rows),
        "first_time": rows[0].get("time") if rows else "",
        "last_time": last.get("time", ""),
        "last_boot_id": last.get("boot_id", ""),
        "size_bytes": path.stat().st_size if path.exists() else 0,
    }


def trim_blackbox(cfg: dict[str, Any]) -> None:
    bb_cfg = blackbox_cfg(cfg)
    path = Path(bb_cfg["path"])
    if not path.exists():
        return
    max_rows = max(50, int(bb_cfg["max_rows"]))
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    compact_batch = max(50, max_rows // 10)
    if len(lines) > max_rows + compact_batch:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text("\n".join(lines[-max_rows:]) + "\n", encoding="utf-8")
        os.replace(temporary, path)


def build_snapshot(cfg: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    services = cfg.get("services", []) if isinstance(cfg.get("services", []), list) else []
    service_names = [str(item.get("name", "")).strip() for item in services if isinstance(item, dict) and item.get("name")]
    return {
        "time": _now_iso(),
        "boot_id": boot_id(),
        "uptime_seconds": _uptime_seconds(),
        "status": _status_summary(status),
        "cpu": _cpu_snapshot(),
        "memory": _memory_snapshot(),
        "pressure": _pressure_snapshot(),
        "storage": _storage_snapshot(cfg, status),
        "services": _services_snapshot(service_names),
        "top_processes": _top_processes(blackbox_cfg(cfg)["top_process_count"]),
        "network": _network_snapshot(),
        "kernel_tail": _kernel_tail(blackbox_cfg(cfg)["journal_lines"]),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(command, timeout=4) -> dict[str, Any]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": result.returncode == 0, "stdout": result.stdout.strip(), "stderr": result.stderr.strip(), "returncode": result.returncode}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}


def _last_snapshot_time(path: Path) -> float | None:
    if not path.exists():
        return None
    try:
        for line in reversed(path.read_text(encoding="utf-8", errors="ignore").splitlines()[-10:]):
            row = json.loads(line)
            text = row.get("time")
            if text:
                return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None
    return None


def _uptime_seconds() -> float | None:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 1)
    except Exception:
        return None


def _status_summary(status: dict[str, Any]) -> dict[str, Any]:
    feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
    recording = status.get("recording_storage", {}) if isinstance(status.get("recording_storage", {}), dict) else {}
    return {
        "state": status.get("state"),
        "score": status.get("score"),
        "critical_failed": bool(status.get("critical_failed", False)),
        "critical_checks": [item.get("name") for item in status.get("checks", []) if item.get("state") == "critical"],
        "warning_checks": [item.get("name") for item in status.get("checks", []) if item.get("state") == "warning"],
        "hardware_watchdog_enabled": feed.get("enabled"),
        "hardware_watchdog_opened": feed.get("opened"),
        "hardware_watchdog_feed_count": feed.get("feed_count"),
        "recording_storage_status": recording.get("status"),
        "recording_storage_free_mb": recording.get("free_mb"),
        "recording_storage_used_percent": recording.get("used_percent"),
    }


def _cpu_snapshot() -> dict[str, Any]:
    loadavg = Path("/proc/loadavg").read_text(encoding="utf-8").strip() if Path("/proc/loadavg").exists() else ""
    top = _run(["sh", "-c", "top -bn1 | grep 'Cpu(s)'"], timeout=3)
    return {"loadavg": loadavg, "top_cpu_line": top["stdout"] or top["stderr"], "cpu_count": os.cpu_count()}


def _memory_snapshot() -> dict[str, Any]:
    data = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            data[key] = int(value.strip().split()[0])
    except Exception:
        pass
    total = data.get("MemTotal")
    available = data.get("MemAvailable")
    used_percent = None
    if total and available is not None:
        used_percent = round(((total - available) / total) * 100, 1)
    return {"mem_total_mb": round(total / 1024, 1) if total else None, "mem_available_mb": round(available / 1024, 1) if available is not None else None, "used_percent": used_percent, "swap_free_mb": round(data.get("SwapFree", 0) / 1024, 1)}


def _pressure_snapshot() -> dict[str, str]:
    out = {}
    for name in ["cpu", "memory", "io"]:
        path = Path("/proc/pressure") / name
        try:
            out[name] = path.read_text(encoding="utf-8").strip()
        except Exception:
            out[name] = ""
    return out


def _storage_snapshot(cfg: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    recording = status.get("recording_storage", {}) if isinstance(status.get("recording_storage", {}), dict) else {}
    paths = {"/", recording.get("mountpoint") or cfg.get("storage", {}).get("recordings_path") or ""}
    rows = []
    for path in sorted(p for p in paths if p):
        try:
            usage = shutil.disk_usage(path)
            rows.append({"path": path, "total_gb": round(usage.total / 1024 / 1024 / 1024, 1), "free_mb": round(usage.free / 1024 / 1024, 1), "used_percent": round((usage.used / max(1, usage.total)) * 100, 1)})
        except Exception as exc:
            rows.append({"path": path, "error": str(exc)})
    return {"paths": rows, "recording_storage": recording}


def _services_snapshot(service_names: list[str]) -> list[dict[str, Any]]:
    rows = []
    for name in service_names:
        props = _run(["systemctl", "show", name, "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=NRestarts"], timeout=4)
        data = {"name": name}
        for line in props["stdout"].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value
        pid = data.get("MainPID")
        if pid and pid != "0":
            ps = _run(["ps", "-p", pid, "-o", "pid=,pcpu=,pmem=,rss=,nlwp=,etimes=,comm="], timeout=3)
            data["process"] = ps["stdout"]
        rows.append(data)
    return rows


def _top_processes(limit: int) -> list[dict[str, Any]]:
    result = _run(["ps", "-eo", "pid,ppid,pcpu,pmem,rss,nlwp,etimes,comm", "--sort=-pcpu"], timeout=4)
    rows = []
    for line in result["stdout"].splitlines()[1:max(1, limit) + 1]:
        parts = line.split(None, 7)
        if len(parts) == 8:
            rows.append({"pid": parts[0], "ppid": parts[1], "cpu_percent": parts[2], "mem_percent": parts[3], "rss_kb": parts[4], "threads": parts[5], "elapsed_seconds": parts[6], "command": parts[7]})
    return rows


def _network_snapshot() -> dict[str, Any]:
    return {
        "addresses": _run(["sh", "-c", "ip -4 -brief addr show | sed 's/[[:space:]]\\+/ /g'"], timeout=4)["stdout"],
        "route": _run(["ip", "route"], timeout=4)["stdout"],
    }


def _kernel_tail(lines: int) -> str:
    result = _run(["journalctl", "-k", "-n", str(max(5, lines)), "--no-pager"], timeout=5)
    return result["stdout"] or result["stderr"]
