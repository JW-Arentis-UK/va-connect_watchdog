import copy
import io
import json
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from va_watchdog.lite import snapshot
from va_watchdog.status_freshness import freshness, status_view
from va_watchdog.system_logs import add_syslogs
from va_watchdog.web import start_web
from va_watchdog.web_health import health_response


class BootFreshnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.cfg = {"status_path": str(self.base / "status.json"),
                    "events_path": str(self.base / "events.jsonl"),
                    "web": {"host": "127.0.0.1", "port": 0}}
        boot = patch("va_watchdog.status_freshness.current_boot_id", return_value="this-boot")
        boot.start()
        self.addCleanup(boot.stop)
        self.now = time.time()
        self.status = {"time": datetime.fromtimestamp(self.now, timezone.utc).isoformat(),
                       "boot_id": "this-boot", "state": "healthy",
                       "checks": [{"name": "system", "state": "healthy"}],
                       "recording_activity": {"available": False},
                       "hardware_watchdog_feed": {"boot_id": "this-boot", "feeding": True,
                           "proven_this_boot": True, "last_feed_unix": self.now},
                       "blackbox": {"enabled": True, "recorder_running": True,
                           "last_boot_id": "this-boot", "last_time": self.now}}

    def save(self, status=None):
        Path(self.cfg["status_path"]).write_text(json.dumps(status or self.status))

    def test_current_boot_is_ready(self):
        self.save()
        self.assertTrue(health_response(self.cfg)["ready"])
        self.assertTrue(freshness(self.cfg, self.status, self.now)["status_current_boot"])

    def test_previous_boot_cannot_be_ready_even_with_recent_timestamp(self):
        self.status["boot_id"] = "previous-boot"
        self.save()
        result = health_response(self.cfg)
        self.assertTrue(result["ok"])
        self.assertFalse(result["ready"])
        self.assertFalse(result["status_fresh"])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["recorded_state"], "healthy")

    def test_missing_boot_is_unverified_but_previous_version_heartbeat_is_supported(self):
        del self.status["boot_id"]
        del self.status["blackbox"]
        self.assertFalse(freshness(self.cfg, self.status, self.now)["status_fresh"])
        self.status["heartbeat"] = {"boot_id": "this-boot"}
        self.assertTrue(freshness(self.cfg, self.status, self.now)["status_fresh"])

    def test_unknown_platform_boot_retains_timestamp_freshness(self):
        with patch("va_watchdog.status_freshness.current_boot_id", return_value="-"):
            self.assertTrue(freshness(self.cfg, self.status, self.now)["status_fresh"])
            self.assertIsNone(freshness(self.cfg, self.status, self.now)["status_current_boot"])

    def test_future_naive_and_old_timestamps_are_not_fresh(self):
        for stamp in (datetime.fromtimestamp(self.now + 60, timezone.utc).isoformat(),
                      datetime.fromtimestamp(self.now - 120, timezone.utc).isoformat(),
                      "2026-10-27T12:00:00", "not a date"):
            self.status["time"] = stamp
            self.assertFalse(freshness(self.cfg, self.status, self.now)["status_fresh"])

    def test_status_view_is_unknown_without_mutating_saved_evidence(self):
        self.status["boot_id"] = "previous-boot"
        original = copy.deepcopy(self.status)
        result = status_view(self.cfg, self.status)
        self.assertEqual(result["checks"][0]["state"], "unknown")
        self.assertEqual(result["checks"][0]["recorded_state"], "healthy")
        self.assertEqual(self.status, original)

    def test_status_endpoint_does_not_serve_previous_boot_as_live(self):
        self.status["boot_id"] = "previous-boot"
        self.save()
        server = start_web(self.cfg)
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/api/status") as response:
                result = json.load(response)
            self.assertFalse(result["status_current_boot"])
            self.assertEqual(result["state"], "unknown")
        finally:
            server.shutdown()
            server.server_close()

    def test_dashboard_rejects_previous_boot_feed_and_blackbox(self):
        self.status["boot_id"] = "previous-boot"
        self.save()
        result = snapshot(self.cfg, now=self.now)
        self.assertTrue(result["stale"])
        self.assertFalse(result["recorder"]["ok"])
        self.assertEqual(next(c for c in result["cards"] if c["title"] == "Hardware protection")["state"], "unknown")

    def test_fresh_feed_requires_same_boot_proof_and_current_core(self):
        for change in ({"boot_id": "previous-boot"}, {"proven_this_boot": False}, {"feeding": False}):
            status = copy.deepcopy(self.status)
            status["hardware_watchdog_feed"].update(change)
            self.save(status)
            result = snapshot(self.cfg, now=self.now)
            self.assertEqual(next(c for c in result["cards"] if c["title"] == "Hardware protection")["state"], "unknown")
        self.save()
        result = snapshot(self.cfg, now=self.now)
        self.assertEqual(next(c for c in result["cards"] if c["title"] == "Hardware protection")["state"], "healthy")
        self.assertTrue(result["recorder"]["ok"])

    def test_pi_uses_current_native_systemd_watchdog_observation(self):
        self.cfg["platform"] = {"kind": "raspberry_pi"}
        self.status["hardware_watchdog_feed"] = {"backend": "systemd", "active": True}
        self.status["checks"].append({"name": "hardware_watchdog_feed_status", "state": "healthy", "message": "Native watchdog active"})
        self.save()
        result = snapshot(self.cfg, now=self.now)
        self.assertEqual(next(c for c in result["cards"] if c["title"] == "Hardware protection")["state"], "healthy")
        self.status["boot_id"] = "previous-boot"
        self.save()
        result = snapshot(self.cfg, now=self.now)
        self.assertEqual(next(c for c in result["cards"] if c["title"] == "Hardware protection")["state"], "unknown")

    def test_recorder_does_not_hide_persistence_errors_or_previous_boot_samples(self):
        for change in ({"last_error": "disk write failed"}, {"last_boot_id": "previous-boot"}):
            status = copy.deepcopy(self.status)
            status["blackbox"].update(change)
            self.save(status)
            self.assertFalse(snapshot(self.cfg, now=self.now)["recorder"]["ok"])

    def test_inaccessible_log_directory_is_recorded_instead_of_breaking_download(self):
        with zipfile.ZipFile(io.BytesIO(), "w") as archive, patch.object(Path, "is_file", side_effect=PermissionError()):
            result = add_syslogs(archive, self.cfg)
        self.assertEqual(len(result["omitted"]), 5)


if __name__ == "__main__":
    unittest.main()
