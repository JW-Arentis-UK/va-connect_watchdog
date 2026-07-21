from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from va_watchdog.events import purge_events, read_events
from va_watchdog.recovery import RecoveryEngine
from va_watchdog.retention import purge_data


class FakeEventLog:
    def __init__(self):
        self.rows = []

    def add(self, level, source, message, data=None):
        self.rows.append((level, source, message, data))


class EventTests(unittest.TestCase):
    def test_read_and_purge_events_by_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            rows = [
                {"time": "2026-07-01T10:00:00+00:00", "message": "old"},
                {"time": "2026-07-20T10:00:00+00:00", "message": "new"},
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

            result = purge_events(path, before="2026-07-10T00:00:00+00:00")

            self.assertEqual(result["removed"], 1)
            self.assertEqual([row["message"] for row in read_events(path)], ["new"])


class RetentionTests(unittest.TestCase):
    def test_old_purge_trims_jsonl_rows_instead_of_deleting_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            events = base / "events.jsonl"
            events.write_text(
                json.dumps({"time": "2020-01-01T00:00:00+00:00"}) + "\n"
                + json.dumps({"time": "2999-01-01T00:00:00+00:00"}) + "\n",
                encoding="utf-8",
            )
            cfg = {"events_path": str(events), "history_path": str(base / "history.jsonl"), "retention": {"max_total_mb": 100}}

            result = purge_data(cfg, mode="old", older_than_days=30)

            self.assertTrue(events.exists())
            self.assertEqual(result["trimmed"][0]["removed_rows"], 1)
            self.assertIn("2999-01-01", events.read_text(encoding="utf-8"))


class RecoveryTests(unittest.TestCase):
    def _engine(self):
        log = FakeEventLog()
        cfg = {
            "services": [{"name": "esg.service", "critical": True, "restart": True}],
            "recovery": {
                "enabled": True,
                "restart_failed_services": True,
                "restart_noncritical_services": False,
                "max_restart_attempts": 3,
                "critical_grace_seconds": 60,
                "allow_reboot": False,
            },
        }
        return RecoveryEngine(cfg, log), log

    @patch("va_watchdog.recovery.subprocess.run")
    def test_failed_systemctl_is_not_reported_as_restart(self, run):
        run.return_value = SimpleNamespace(returncode=1)
        engine, log = self._engine()

        summary = engine.process([SimpleNamespace(name="esg.service", state="critical", critical=True, to_dict=lambda: {})])

        self.assertNotIn("restarted esg.service", summary["actions"])
        self.assertTrue(any(row[2] == "Restart failed for esg.service" for row in log.rows))

    def test_healthy_service_resets_restart_limit(self):
        engine, _ = self._engine()
        engine.restart_attempts["esg.service"] = 3
        engine.restart_limit_logged.add("esg.service")

        engine.process([SimpleNamespace(name="esg.service", state="healthy", critical=True, to_dict=lambda: {})])

        self.assertEqual(engine.restart_attempts["esg.service"], 0)
        self.assertNotIn("esg.service", engine.restart_limit_logged)


if __name__ == "__main__":
    unittest.main()
