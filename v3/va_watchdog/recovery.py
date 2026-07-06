from __future__ import annotations

import subprocess
import time
from collections import defaultdict

class RecoveryEngine:
    def __init__(self, cfg, event_log):
        self.cfg = cfg
        self.event_log = event_log
        self.restart_attempts = defaultdict(int)
        self.critical_since = None

    def process(self, checks):
        recovery = self.cfg["recovery"]
        if not recovery["enabled"]:
            return

        critical = [c for c in checks if c.state == "critical" and c.critical]
        if critical and self.critical_since is None:
            self.critical_since = time.time()
        if not critical:
            self.critical_since = None

        if recovery.get("restart_failed_services"):
            service_names = {s["name"]: s for s in self.cfg["services"]}
            for c in checks:
                if c.name in service_names and c.state in ("degraded", "critical"):
                    svc_cfg = service_names[c.name]
                    if svc_cfg.get("restart", False):
                        self._restart_service(c.name)

    def _restart_service(self, name):
        limit = self.cfg["recovery"]["max_restart_attempts"]
        if self.restart_attempts[name] >= limit:
            self.event_log.add("critical", "recovery", f"Restart limit reached for {name}")
            return
        self.restart_attempts[name] += 1
        self.event_log.add("warning", "recovery", f"Restarting {name}")
        subprocess.run(["systemctl", "restart", name], timeout=20)
