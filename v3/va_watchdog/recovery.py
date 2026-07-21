from __future__ import annotations

import json
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


def _write_json(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

class RecoveryEngine:
    def __init__(self, cfg, event_log):
        self.cfg = cfg
        self.event_log = event_log
        self.restart_attempts = defaultdict(int)
        self.restart_limit_logged = set()
        self.reboot_suppressed_logged = False
        self.critical_since = None
        self.last_action = {
            "state": "disabled",
            "message": "Recovery is disabled.",
            "actions": [],
            "critical_since": None,
            "updated_at": None,
        }

    def summary(self):
        return dict(self.last_action)

    def _set_summary(self, state: str, message: str, actions=None, details=None):
        summary = {
            "state": state,
            "message": message,
            "actions": list(actions or []),
            "critical_since": self.critical_since,
            "updated_at": time.time(),
        }
        if details is not None:
            summary["details"] = details
        self.last_action = summary
        return summary

    def process(self, checks):
        recovery = self.cfg["recovery"]
        if not recovery["enabled"]:
            return self._set_summary("disabled", "Recovery is disabled.")

        critical = [c for c in checks if c.state == "critical" and c.critical]
        if critical and self.critical_since is None:
            self.critical_since = time.time()
        if not critical:
            self.critical_since = None
            self.reboot_suppressed_logged = False

        actions = []
        if recovery.get("restart_failed_services"):
            service_names = {s["name"]: s for s in self.cfg["services"]}
            for c in checks:
                if c.name in service_names and c.state == "healthy":
                    self.restart_attempts[c.name] = 0
                    self.restart_limit_logged.discard(c.name)
                if c.name in service_names and c.state == "critical":
                    svc_cfg = service_names[c.name]
                    if svc_cfg.get("restart", False) and svc_cfg.get("critical", False):
                        if self._restart_service(c.name):
                            actions.append(f"restarted {c.name}")
                elif c.name in service_names and c.state == "degraded" and recovery.get("restart_noncritical_services"):
                    svc_cfg = service_names[c.name]
                    if svc_cfg.get("restart", False):
                        if self._restart_service(c.name):
                            actions.append(f"restarted {c.name}")

        if critical:
            grace = int(recovery.get("critical_grace_seconds", 60))
            elapsed = time.time() - float(self.critical_since or time.time())
            if recovery.get("allow_reboot") and elapsed >= grace:
                reason = {
                    "state": "critical",
                    "message": "Persistent critical failure threshold reached.",
                    "critical_since": self.critical_since,
                    "elapsed_seconds": round(elapsed, 1),
                    "critical_checks": [c.to_dict() for c in critical],
                    "actions": actions,
                }
                _write_json(self.cfg["last_reboot_reason_path"], reason)
                self.event_log.add("critical", "recovery", "Reboot requested after persistent critical failure", reason)
                subprocess.run(["systemctl", "reboot"], timeout=20, check=False)
                actions.append("requested reboot")
                return self._set_summary(
                    "reboot_requested",
                    "Persistent critical failure triggered a reboot request.",
                    actions,
                    reason,
                )
            if not recovery.get("allow_reboot") and not self.reboot_suppressed_logged:
                self.event_log.add(
                    "warning",
                    "recovery",
                    "Critical fault detected, reboot suppressed by config",
                    {
                        "critical_since": self.critical_since,
                        "grace_seconds": grace,
                        "critical_checks": [c.to_dict() for c in critical],
                    },
                )
                self.reboot_suppressed_logged = True

        if actions:
            return self._set_summary(
                "active",
                "Recovery actions were attempted.",
                actions,
                {"critical_checks": [c.to_dict() for c in critical]},
            )
        if critical:
            return self._set_summary(
                "watching",
                "Critical fault is being monitored.",
                actions,
                {"critical_checks": [c.to_dict() for c in critical]},
            )
        return self._set_summary("idle", "No recovery action needed.", actions)

    def _restart_service(self, name):
        limit = self.cfg["recovery"]["max_restart_attempts"]
        if self.restart_attempts[name] >= limit:
            if name not in self.restart_limit_logged:
                self.event_log.add("critical", "recovery", f"Restart limit reached for {name}")
                self.restart_limit_logged.add(name)
            return False
        self.restart_attempts[name] += 1
        self.event_log.add("warning", "recovery", f"Restarting {name}")
        try:
            result = subprocess.run(["systemctl", "restart", name], timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.event_log.add("critical", "recovery", f"Restart failed for {name}", {"error": str(exc)})
            return False
        if result.returncode != 0:
            self.event_log.add(
                "critical",
                "recovery",
                f"Restart failed for {name}",
                {"returncode": result.returncode},
            )
            return False
        return True
