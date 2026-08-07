import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from va_watchdog.neousys_watchdog import NeousysWatchdog
from va_watchdog.watchdog_device import HardwareWatchdog
from va_watchdog.watchdog_feed import FeedWorker


class FakeFunction:
    def __init__(self, name, calls, result=1):
        self.name = name
        self.calls = calls
        self.result = result
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        self.calls.append((self.name, args))
        return self.result


class FakeLibrary:
    def __init__(self, reset_result=1):
        self.calls = []
        self.InitWDT = FakeFunction("InitWDT", self.calls)
        self.SetWDT = FakeFunction("SetWDT", self.calls)
        self.StartWDT = FakeFunction("StartWDT", self.calls)
        self.ResetWDT = FakeFunction("ResetWDT", self.calls, reset_result)
        self.StopWDT = FakeFunction("StopWDT", self.calls)


class NeousysWatchdogTests(unittest.TestCase):
    def test_vendor_start_feed_and_orderly_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            library_path = Path(temporary) / "libwdt_dio.so"
            library_path.touch()
            library = FakeLibrary()
            with patch("va_watchdog.neousys_watchdog.ctypes.CDLL", return_value=library):
                watchdog = NeousysWatchdog(str(library_path), 30)
                watchdog.start()
                watchdog.feed()
                watchdog.stop()

        self.assertEqual(
            [name for name, _args in library.calls],
            ["InitWDT", "SetWDT", "StartWDT", "ResetWDT", "ResetWDT", "StopWDT"],
        )
        self.assertEqual(library.calls[1][1], (30, 1))
        self.assertFalse(watchdog.started)

    def test_failed_initial_reset_disarms_started_watchdog(self):
        with tempfile.TemporaryDirectory() as temporary:
            library_path = Path(temporary) / "libwdt_dio.so"
            library_path.touch()
            library = FakeLibrary(reset_result=0)
            with patch("va_watchdog.neousys_watchdog.ctypes.CDLL", return_value=library):
                watchdog = NeousysWatchdog(str(library_path), 30)
                with self.assertRaisesRegex(RuntimeError, "initial ResetWDT"):
                    watchdog.start()

        self.assertIn(("StopWDT", ()), library.calls)
        self.assertFalse(watchdog.started)

    def test_hardware_adapter_uses_vendor_backend_without_linux_device_writes(self):
        vendor = Mock()
        with patch("va_watchdog.watchdog_device.os.path.exists", return_value=True), patch(
            "va_watchdog.watchdog_device.NeousysWatchdog", return_value=vendor
        ):
            hardware = HardwareWatchdog(
                True,
                "/dev/wdt_dio",
                10,
                None,
                timeout_seconds=30,
                backend="neousys_wdt_dio",
                library_path="/private/libwdt_dio.so",
            )
            hardware.open()
            hardware.feed()
            hardware.close()

        vendor.start.assert_called_once_with()
        vendor.feed.assert_called_once_with()
        vendor.stop.assert_called_once_with()
        self.assertEqual(hardware.feed_count, 1)
        self.assertFalse(hardware.opened)

    def test_vendor_trip_without_counter_resumes_after_timeout(self):
        worker = FeedWorker({
            "events_path": "/tmp/events.jsonl",
            "hardware_watchdog": {
                "backend": "neousys_wdt_dio",
                "device": "/dev/wdt_dio",
                "timeout_seconds": 30,
            },
        })

        self.assertTrue(worker.evaluate_trip_countdown(True, current_monotonic=100, timeleft=None))
        with patch("va_watchdog.watchdog_feed.fail_trip_test") as fail:
            self.assertFalse(worker.evaluate_trip_countdown(True, current_monotonic=135, timeleft=None))

        fail.assert_called_once()
        self.assertEqual(worker.trip_countdown_status, "failed_no_reset")

    def test_feeder_state_identifies_vendor_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "feed.json"
            worker = FeedWorker({
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog_feed_state_path": str(state_path),
                "hardware_watchdog": {
                    "backend": "neousys_wdt_dio",
                    "device": "/dev/wdt_dio",
                    "timeout_seconds": 30,
                },
            })
            worker.write_state("disabled")
            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertEqual(state["backend"], "neousys_wdt_dio")
        self.assertIn("StopWDT", state["shutdown_behavior"])

    def test_installer_does_not_activate_without_explicit_flag(self):
        script = Path(__file__).parents[1] / "scripts" / "install_neousys_wdt.sh"
        text = script.read_text(encoding="utf-8")
        self.assertIn("EXPECTED_SHA256=", text)
        self.assertIn('if [[ "$ACTIVATE" != 1 ]]', text)
        self.assertIn("configuration was not changed", text)
        self.assertIn('product" != *"POC-451VTC"*', text)


if __name__ == "__main__":
    unittest.main()
