from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from threading import RLock
from .common import now_iso

EVENTS_LOCK = RLock()


def _timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def read_events(path: str | Path, limit: int = 500) -> list[dict]:
    target = Path(path)
    if not target.exists():
        return []
    safe_limit = max(1, min(int(limit), 5000))
    rows = []
    with EVENTS_LOCK:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in lines:
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return list(reversed(rows[-safe_limit:]))


def purge_events(path: str | Path, before: str | None = None, purge_all: bool = False) -> dict:
    """Remove event rows atomically without touching any other watchdog data."""
    target = Path(path)
    if not target.exists():
        return {"ok": True, "removed": 0, "remaining": 0}

    cutoff = _timestamp(before) if before else None
    if not purge_all and cutoff is None:
        raise ValueError("A valid before timestamp is required")

    kept = []
    removed = 0
    with EVENTS_LOCK:
        for line in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                payload = json.loads(line)
            except (TypeError, ValueError):
                kept.append(line)
                continue
            event_time = _timestamp(payload.get("time")) if isinstance(payload, dict) else None
            should_remove = purge_all or (event_time is not None and event_time < cutoff)
            if should_remove:
                removed += 1
            else:
                kept.append(line)

        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        os.replace(temporary, target)
    return {"ok": True, "removed": removed, "remaining": len(kept)}

class EventLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_states = {}

    def add(self, level: str, source: str, message: str, data=None):
        event = {
            "time": now_iso(),
            "level": level,
            "source": source,
            "message": message,
            "data": data or {}
        }
        with EVENTS_LOCK:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

    def add_state_changes(self, checks):
        for check in checks:
            old = self.previous_states.get(check.name)
            if old is not None and old != check.state:
                self.add(check.state, check.name, f"{check.name} changed from {old} to {check.state}", check.to_dict())
            self.previous_states[check.name] = check.state

    def add_service_resource_changes(self, checks, cfg=None):
        limits = (cfg or {}).get("service_resource_limits", {})
        cpu_warning = float(limits.get("cpu_warning_percent", 80) or 80)
        cpu_critical = float(limits.get("cpu_critical_percent", 95) or 95)
        memory_warning = float(limits.get("memory_warning_mb", 512) or 512)
        memory_critical = float(limits.get("memory_critical_mb", 1024) or 1024)
        for check in checks:
            name = str(getattr(check, "name", ""))
            if not name.endswith(".service"):
                continue
            value = getattr(check, "value", {}) if isinstance(getattr(check, "value", {}), dict) else {}
            try:
                cpu = float(value.get("cpu_percent")) if value.get("cpu_percent") is not None else None
            except (TypeError, ValueError):
                cpu = None
            try:
                memory = float(value.get("memory_mb")) if value.get("memory_mb") is not None else None
            except (TypeError, ValueError):
                memory = None
            cpu_high = cpu is not None and cpu >= cpu_warning
            memory_high = memory is not None and memory >= memory_warning
            critical = (cpu is not None and cpu >= cpu_critical) or (memory is not None and memory >= memory_critical)
            state = "critical" if critical else ("warning" if cpu_high or memory_high else "healthy")
            key = f"__service_resource__{name}"
            previous = self.previous_states.get(key)
            if previous == state:
                continue
            data = {
                "service": name,
                "cpu_percent": cpu,
                "cpu_system_percent": round(cpu / max(1, os.cpu_count() or 1), 1) if cpu is not None else None,
                "memory_mb": memory,
                "cpu_warning_percent": cpu_warning,
                "cpu_critical_percent": cpu_critical,
                "memory_warning_mb": memory_warning,
                "memory_critical_mb": memory_critical,
            }
            if state != "healthy":
                resources = []
                if cpu_high:
                    resources.append(f"CPU {cpu:.1f}% per core / {data['cpu_system_percent']:.1f}% system")
                if memory_high:
                    resources.append(f"RAM {memory:.1f} MB")
                self.add(state, name, f"{name} high resource usage: {', '.join(resources)}", data)
            elif previous and previous != "healthy":
                self.add("healthy", name, f"{name} resource usage returned to normal", data)
            self.previous_states[key] = state

    def add_recording_storage_change(self, status):
        if not isinstance(status, dict):
            return
        previous = self.previous_states.get("__recording_storage_snapshot__")
        current = {
            "status": status.get("status"),
            "present": status.get("present"),
            "mounted": status.get("mounted"),
            "writable": status.get("writable"),
            "read_only": status.get("read_only"),
            "smart_status": status.get("smart_status"),
            "free_percent": status.get("free_percent"),
            "message": status.get("message"),
        }
        if previous == current:
            return

        message = None
        level = status.get("status", "warning")
        if status.get("status") == "healthy" and previous and previous.get("status") != "healthy":
            message = "Recording storage restored"
            level = "healthy"
        elif status.get("mounted") and previous and not previous.get("mounted"):
            message = "Recording storage mounted"
            level = status.get("status", "healthy")
        elif not status.get("present"):
            message = "Recording storage missing"
            level = "critical"
        elif status.get("read_only"):
            message = "Recording storage read-only"
            level = "critical"
        elif status.get("smart_status") == "FAILED":
            message = "Recording storage SMART failure"
            level = "critical"
        elif str(status.get("message") or "").lower() in {
            "recording storage low space",
            "recording storage low free space",
            "recording storage low free mb",
            "recording storage critically full",
            "recording storage below minimum free mb",
        }:
            message = status.get("message")
            level = status.get("status", "warning")

        if message:
            self.add(level, "recording_storage", message, status)
        self.previous_states["__recording_storage_snapshot__"] = current
