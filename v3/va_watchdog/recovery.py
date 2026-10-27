"""One recovery owner: explicit, bounded service restarts only."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


class RecoveryEngine:
    def __init__(self, cfg, event_log):
        self.cfg, self.event_log = cfg, event_log
        policy = cfg.get("recovery", {}).get("consolidated_policy", {})
        self.path = Path(policy.get("state_path") or
                         Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent / "recovery/state.json")
        try:
            self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            self.boot = ""
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            self.state = saved if isinstance(saved, dict) and saved.get("boot_id") == self.boot else {}
        except (OSError, ValueError):
            self.state = {}
        self.state = {"boot_id": self.boot, "services": self.state.get("services", {})}
        self.persisted = json.dumps(self.state, sort_keys=True)
        self.last_action = {}
        self._summary("disabled", "Service recovery is disabled.")

    def summary(self):
        return dict(self.last_action)

    def _summary(self, state, message, actions=None):
        self.last_action = {"state": state, "message": message, "actions": actions or [],
                            "owner": "v3", "automatic_reboot": False, "updated_at": time.time()}
        return self.summary()

    def _save(self):
        encoded = json.dumps(self.state, sort_keys=True)
        if encoded == self.persisted:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(self.path)
        self.persisted = encoded

    def process(self, checks):
        settings = self.cfg.get("recovery", {})
        if not settings.get("enabled") or not settings.get("restart_failed_services"):
            return self._summary("disabled", "Service recovery is disabled. Automatic gateway reboot is unavailable.")
        now = time.monotonic()
        cooldown = max(30, float(settings.get("restart_cooldown_seconds", 60)))
        limit = max(0, min(10, int(settings.get("max_restart_attempts", 3))))
        configured = {s["name"]: s for s in self.cfg.get("services", []) if s.get("restart")}
        actions = []
        for check in checks:
            service = configured.get(check.name)
            if not service or not check.name.endswith(".service") or "/" in check.name:
                continue
            value = check.value if isinstance(check.value, dict) else {}
            stamp = value.get("collected_at")
            if not isinstance(stamp, (int, float)) or not 0 <= time.time() - stamp <= 90:
                continue
            state = self.state["services"].setdefault(check.name, {"attempts": 0, "last_action": None})
            if check.state == "healthy":
                state.setdefault("healthy_since", now)
                if now - state["healthy_since"] >= cooldown:
                    state.update(attempts=0, last_action=None)
                continue
            state.pop("healthy_since", None)
            eligible = check.state == "critical" and bool(service.get("critical"))
            eligible |= check.state == "degraded" and settings.get("restart_noncritical_services", False)
            if not eligible or value.get("active") not in {"failed", "inactive"}:
                continue
            if state["attempts"] >= limit or (state["last_action"] is not None and now - state["last_action"] < cooldown):
                continue
            if settings.get("consolidated_policy", {}).get("enabled"):
                try:
                    owner = subprocess.run(["systemctl", "is-active", "va-connect-site-watchdog.service"],
                                           capture_output=True, timeout=3, check=False)
                    if owner.returncode not in (3, 4):
                        return self._summary("blocked", "Legacy recovery ownership is not confirmed stopped.")
                except (OSError, subprocess.SubprocessError):
                    return self._summary("blocked", "Legacy recovery ownership could not be checked.")
            state.update(attempts=state["attempts"] + 1, last_action=now)
            self._save()
            self.event_log.add("warning", "recovery", f"Service restart requested: {check.name}",
                               {"attempt": state["attempts"], "limit": limit})
            try:
                result = subprocess.run(["systemctl", "--no-block", "restart", check.name],
                                        capture_output=True, timeout=5, check=False)
                if result.returncode:
                    raise RuntimeError("service manager rejected restart")
                actions.append(f"restart queued: {check.name}")
            except (OSError, subprocess.SubprocessError, RuntimeError):
                self.event_log.add("critical", "recovery", f"Restart failed for {check.name}")
        self._save()
        return self._summary("active" if actions else "watching", "Only configured service restarts are permitted.", actions)
