import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from va_watchdog.history import append_history, read_history
from va_watchdog.services import check_services


class ServiceTrendTests(unittest.TestCase):
    @patch("va_watchdog.services._service_properties", return_value=("active", 2, {"cpu_percent": 12.5, "memory_mb": 42.0, "uptime_seconds": 90}))
    def test_service_check_includes_runtime_metrics(self, _properties):
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

    def test_history_keeps_compact_mobile_router_and_network_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.jsonl"
            cfg = {"history_path": str(path), "events_path": str(Path(temporary) / "events.jsonl"), "retention": {"history_sample_seconds": 0, "history_max_rows": 100}}
            status = {
                "time": "2026-09-17T12:00:00+00:00",
                "checks": [
                    {"name": "network_module", "state": "warning", "value": {}},
                    {"name": "mobile_router", "state": "healthy", "value": {"available": True, "signal_dbm": -67, "rsrp_dbm": -91, "rsrq_db": -11, "sinr_db": 18, "uptime_seconds": 3600, "started_at": "2026-09-17T11:00:00+00:00", "registration": "Registered, home"}},
                ],
            }

            append_history(cfg, status)
            row = read_history(cfg)[0]

            self.assertEqual(row["network_module_state"], "warning")
            self.assertTrue(row["mobile_router_available"])
            self.assertEqual(row["mobile_router_signal_dbm"], -67)
            self.assertEqual(row["mobile_router_rsrp_dbm"], -91)
            self.assertEqual(row["mobile_router_rsrq_db"], -11)
            self.assertEqual(row["mobile_router_sinr_db"], 18)
            self.assertEqual(row["mobile_router_uptime_seconds"], 3600)


if __name__ == "__main__":
    unittest.main()
