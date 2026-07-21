import unittest

from va_watchdog.process_monitor import ProcessMonitor


class ProcessMonitorTests(unittest.TestCase):
    def test_monitor_returns_process_metadata(self):
        result = ProcessMonitor().sample({"process_monitor": {"enabled": True}})

        self.assertEqual(result.name, "watchdog_process")
        self.assertIn("pid", result.value)
        self.assertIn("memory_mb", result.value)
        self.assertIn("sustained_seconds", result.value)
        self.assertIn(result.state, {"healthy", "warning", "critical"})

    def test_monitor_can_be_disabled(self):
        result = ProcessMonitor().sample({"process_monitor": {"enabled": False}})

        self.assertEqual(result.state, "healthy")
        self.assertFalse(result.value["enabled"])


if __name__ == "__main__":
    unittest.main()
