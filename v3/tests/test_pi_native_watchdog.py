import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog import pi_native_watchdog
from va_watchdog.config import _enforce_neousys_watchdog
from va_watchdog.watchdog import add_hardware_feed_check, hardware_feed_status


class PiNativeWatchdogTests(unittest.TestCase):
    def test_pi_config_never_opens_neousys_feeder(self):
        cfg = _enforce_neousys_watchdog({"platform": {"kind": "raspberry_pi"},
                                        "hardware_watchdog": {"enabled": True, "backend": "neousys_wdt_dio"}})
        self.assertFalse(cfg["hardware_watchdog"]["enabled"])
        self.assertEqual(cfg["hardware_watchdog"]["backend"], "systemd")
        self.assertEqual(cfg["hardware_watchdog"]["device"], "/dev/watchdog0")

    def test_systemd_and_device_must_both_be_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            device = root / "watchdog0"
            device.touch()
            sysfs = root / "sysfs"
            sysfs.mkdir()
            (sysfs / "identity").write_text("Broadcom BCM2835 Watchdog timer")
            (sysfs / "timeout").write_text("15")
            (sysfs / "state").write_text("inactive")
            with patch.object(pi_native_watchdog, "DEVICE", device), patch.object(pi_native_watchdog, "SYSFS", sysfs), patch.object(
                pi_native_watchdog.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "0", "")
            ) as run:
                disabled = pi_native_watchdog.inspect()
                self.assertFalse(disabled["active"])
                self.assertFalse(disabled["configured"])
                (sysfs / "state").write_text("active")
                run.return_value = subprocess.CompletedProcess([], 0, "15s", "")
                active = pi_native_watchdog.inspect()
            self.assertTrue(active["active"])
            self.assertEqual(active["manager_timeout_seconds"], 15)
            self.assertEqual(active["device_timeout_seconds"], 15)
            self.assertEqual(pi_native_watchdog._runtime_seconds("15000000"), 15)
            self.assertEqual(pi_native_watchdog._runtime_seconds("0"), 0)

    def test_pi_status_uses_systemd_instead_of_neousys_feed(self):
        cfg = {"platform": {"kind": "raspberry_pi"}, "hardware_watchdog": {"enabled": False}}
        native = {"backend": "systemd", "device": "/dev/watchdog0", "present": True,
                  "configured": True, "active": True, "device_timeout_seconds": 15}
        with patch("va_watchdog.watchdog.inspect_pi_native_watchdog", return_value=native):
            feed = hardware_feed_status(cfg, {})
        result = add_hardware_feed_check({"checks": [], "hardware_watchdog_feed": feed}, cfg)
        check = next(item for item in result["checks"] if item["name"] == "hardware_watchdog_feed_status")
        self.assertEqual(check["state"], "healthy")
        self.assertIn("systemd", check["message"])
        self.assertFalse(feed["proven_this_boot"])

        feed["active"] = False
        result = add_hardware_feed_check({"checks": [], "hardware_watchdog_feed": feed}, cfg)
        check = next(item for item in result["checks"] if item["name"] == "hardware_watchdog_feed_status")
        self.assertEqual(check["state"], "critical")


if __name__ == "__main__":
    unittest.main()
