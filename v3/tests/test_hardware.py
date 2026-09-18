from __future__ import annotations

import unittest
from unittest.mock import patch

from va_watchdog.hardware import check_hardware


class HardwareTests(unittest.TestCase):
    def _cfg(self):
        return {
            "thresholds": {
                "cpu_temp_critical_c": 90,
                "cpu_temp_warning_c": 75,
                "ram_critical_percent": 95,
                "ram_warning_percent": 85,
            },
            "hardware_watchdog": {"device": "/dev/wdt_dio"},
        }

    @patch("va_watchdog.hardware.os.path.exists", return_value=True)
    @patch("va_watchdog.hardware._cpu_load_percent", return_value=None)
    @patch("va_watchdog.hardware._mem_percent", return_value=20.0)
    @patch("va_watchdog.hardware._read_temperature", return_value=40.0)
    def test_cpu_warmup_sample_is_not_an_alert(self, _temp, _mem, _cpu, _exists):
        checks = {check.name: check for check in check_hardware(self._cfg())}

        self.assertEqual(checks["cpu_load"].state, "healthy")
        self.assertEqual(checks["cpu_load"].message, "CPU load sampling")
        self.assertIsNone(checks["cpu_load"].value)

    @patch("va_watchdog.hardware.os.path.exists", return_value=True)
    @patch("va_watchdog.hardware._cpu_load_percent", return_value=37.5)
    @patch("va_watchdog.hardware._mem_percent", return_value=20.0)
    @patch("va_watchdog.hardware._read_temperature", return_value=40.0)
    def test_cpu_sample_remains_a_normal_reading(self, _temp, _mem, _cpu, _exists):
        checks = {check.name: check for check in check_hardware(self._cfg())}

        self.assertEqual(checks["cpu_load"].state, "healthy")
        self.assertEqual(checks["cpu_load"].message, "CPU load")
        self.assertEqual(checks["cpu_load"].value, 37.5)


if __name__ == "__main__":
    unittest.main()
