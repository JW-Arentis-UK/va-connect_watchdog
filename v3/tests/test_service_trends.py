import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from va_watchdog.history import append_history, read_history
from va_watchdog.services import check_services


class ServiceTrendTests(unittest.TestCase):
    @patch("va_watchdog.services._runtime_stats", return_value={"cpu_percent": 12.5, "memory_mb": 42.0, "uptime_seconds": 90})
    @patch("va_watchdog.services._restart_count", return_value=2)
    @patch("va_watchdog.services._is_active", return_value="active")
    def test_service_check_includes_runtime_metrics(self, _active, _restarts, _runtime):
        checks = check_services({"services": [{"name": "esg.service", "critical": True}]})

        self.assertEqual(checks[0].value["cpu_percent"], 12.5)
        self.assertEqual(checks[0].value["memory_mb"], 42.0)
        self.assertEqual(checks[0].value["restarts"], 2)

    def test_history_keeps_compact_service_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.jsonl"
            cfg = {"history_path": str(path), "events_path": str(Path(temporary) / "events.jsonl"), "retention": {"history_sample_seconds": 60, "history_max_rows": 100}}
            status = {
                "time": datetime.now(timezone.utc).isoformat(),
                "state": "healthy",
                "score": 100,
                "checks": [{"name": "esg.service", "state": "healthy", "value": {"active": "active", "cpu_percent": 12.5, "memory_mb": 42.0, "restarts": 2}}],
            }

            append_history(cfg, status)
            rows = read_history(cfg)

            self.assertEqual(rows[0]["service_metrics"][0]["name"], "esg.service")
            self.assertEqual(rows[0]["service_metrics"][0]["cpu_percent"], 12.5)


if __name__ == "__main__":
    unittest.main()
