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
