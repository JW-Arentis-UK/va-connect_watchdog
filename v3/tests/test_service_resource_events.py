import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from va_watchdog.events import EventLog


class ServiceResourceEventTests(unittest.TestCase):
    def test_high_resource_event_is_logged_once_and_recovery_is_logged(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = EventLog(str(path))
            cfg = {"service_resource_limits": {"cpu_warning_percent": 80, "cpu_critical_percent": 95, "memory_warning_mb": 512, "memory_critical_mb": 1024}}
            high = SimpleNamespace(name="esg.service", value={"cpu_percent": 82.0, "memory_mb": 600.0})
            normal = SimpleNamespace(name="esg.service", value={"cpu_percent": 12.0, "memory_mb": 100.0})

            log.add_service_resource_changes([high], cfg)
            log.add_service_resource_changes([high], cfg)
            log.add_service_resource_changes([normal], cfg)

            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertIn("high resource usage", rows[0]["message"])
            self.assertIn("returned to normal", rows[1]["message"])
            self.assertEqual(rows[0]["data"]["cpu_percent"], 82.0)


if __name__ == "__main__":
    unittest.main()
