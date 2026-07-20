from __future__ import annotations

import json
from pathlib import Path
from .common import now_iso

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
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def add_state_changes(self, checks):
        for check in checks:
            old = self.previous_states.get(check.name)
            if old is not None and old != check.state:
                self.add(check.state, check.name, f"{check.name} changed from {old} to {check.state}", check.to_dict())
            self.previous_states[check.name] = check.state

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
            "recording storage critically full",
        }:
            message = status.get("message")
            level = status.get("status", "warning")

        if message:
            self.add(level, "recording_storage", message, status)
        self.previous_states["__recording_storage_snapshot__"] = current
