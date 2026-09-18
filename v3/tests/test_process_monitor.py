import unittest
from unittest.mock import patch

from va_watchdog.process_monitor import ProcessMonitor


class ProcessMonitorTests(unittest.TestCase):
    def test_monitor_returns_process_metadata(self):
        result = ProcessMonitor().sample({"process_monitor": {"enabled": True}})

        self.assertEqual(result.name, "watchdog_process")
        self.assertIn("pid", result.value)
        self.assertIn("memory_mb", result.value)
        self.assertIn("disk_read_kbps", result.value)
        self.assertIn("disk_write_kbps", result.value)
        self.assertIn("data_used_mb", result.value)
        self.assertEqual(result.value["data_limit_mb"], 100)
        self.assertIn("sustained_seconds", result.value)
        self.assertIn(result.state, {"healthy", "warning", "critical"})

    def test_monitor_can_be_disabled(self):
        result = ProcessMonitor().sample({"process_monitor": {"enabled": False}})

        self.assertEqual(result.state, "healthy")
        self.assertFalse(result.value["enabled"])

    def test_short_cpu_burst_does_not_raise_overall_warning(self):
        monitor = ProcessMonitor()
        cfg = {"process_monitor": {"enabled": True, "cpu_warning_percent": 25, "warning_sustained_seconds": 60}}
        with patch("va_watchdog.process_monitor.time.monotonic", side_effect=[0, 10]), patch(
            "va_watchdog.process_monitor.os.sysconf", return_value=100, create=True
        ), patch.object(monitor, "_cpu_ticks", side_effect=[0, 300]), patch.object(
            monitor, "_io_bytes", return_value=None
        ), patch.object(monitor, "_memory_mb", return_value=20), patch.object(
            monitor, "_uptime_seconds", return_value=10
        ):
            monitor.sample(cfg)
            result = monitor.sample(cfg)

        self.assertEqual(result.value["cpu_percent"], 30.0)
        self.assertEqual(result.state, "healthy")
        self.assertEqual(result.value["warning_sustained_seconds"], 60)

    def test_sustained_cpu_usage_still_raises_warning(self):
        monitor = ProcessMonitor()
        cfg = {"process_monitor": {"enabled": True, "cpu_warning_percent": 25, "warning_sustained_seconds": 60}}
        with patch("va_watchdog.process_monitor.time.monotonic", side_effect=[0, 10, 71]), patch(
            "va_watchdog.process_monitor.os.sysconf", return_value=100, create=True
        ), patch.object(monitor, "_cpu_ticks", side_effect=[0, 300, 2130]), patch.object(
            monitor, "_io_bytes", return_value=None
        ), patch.object(monitor, "_memory_mb", return_value=20), patch.object(
            monitor, "_uptime_seconds", return_value=71
        ):
            monitor.sample(cfg)
            monitor.sample(cfg)
            result = monitor.sample(cfg)

        self.assertEqual(result.value["cpu_percent"], 30.0)
        self.assertEqual(result.state, "warning")


if __name__ == "__main__":
    unittest.main()
