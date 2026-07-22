import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from va_watchdog.events import EventLog


class ServiceResourceEventTests(unittest.TestCase):
    def test_high_resource_event_is_logged_once_and_recovery_is_logged(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = EventLog(str(path))
            cfg = {"service_resource_limits": {
                "cpu_system_warning_percent": 20,
                "cpu_system_critical_percent": 90,
                "memory_warning_mb": 512,
                "memory_critical_mb": 1024,
                "warning_sustained_seconds": 0,
                "critical_sustained_seconds": 0,
                "recovery_sustained_seconds": 0,
            }}
            high = SimpleNamespace(name="esg.service", value={"cpu_percent": 82.0, "memory_mb": 600.0})
            normal = SimpleNamespace(name="esg.service", value={"cpu_percent": 12.0, "memory_mb": 100.0})

            with patch("va_watchdog.events.os.cpu_count", return_value=4):
                log.add_service_resource_changes([high], cfg)
                log.add_service_resource_changes([high], cfg)
                log.add_service_resource_changes([normal], cfg)

            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertIn("high resource usage", rows[0]["message"])
            self.assertIn("returned to normal", rows[1]["message"])
            self.assertEqual(rows[0]["data"]["cpu_percent"], 82.0)
            self.assertEqual(rows[0]["data"]["cpu_system_percent"], 20.5)

    def test_transient_cpu_spike_does_not_create_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = EventLog(str(path))
            cfg = {"service_resource_limits": {
                "cpu_system_warning_percent": 20,
                "cpu_system_critical_percent": 90,
                "warning_sustained_seconds": 120,
            }}
            high = SimpleNamespace(name="esg.service", value={"cpu_percent": 100.0, "memory_mb": 100.0})
            normal = SimpleNamespace(name="esg.service", value={"cpu_percent": 10.0, "memory_mb": 100.0})

            with patch("va_watchdog.events.os.cpu_count", return_value=4), patch("va_watchdog.events.time.monotonic", side_effect=[0.0]):
                log.add_service_resource_changes([high], cfg)
                log.add_service_resource_changes([normal], cfg)

            self.assertFalse(path.exists())

    def test_sustained_system_cpu_creates_one_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = EventLog(str(path))
            cfg = {"service_resource_limits": {
                "cpu_system_warning_percent": 20,
                "cpu_system_critical_percent": 90,
                "warning_sustained_seconds": 120,
            }}
            high = SimpleNamespace(name="esg.service", value={"cpu_percent": 100.0, "memory_mb": 100.0})

            with patch("va_watchdog.events.os.cpu_count", return_value=4), patch("va_watchdog.events.time.monotonic", side_effect=[0.0, 121.0]):
                log.add_service_resource_changes([high], cfg)
                log.add_service_resource_changes([high], cfg)

            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["data"]["cpu_system_percent"], 25.0)


if __name__ == "__main__":
    unittest.main()
