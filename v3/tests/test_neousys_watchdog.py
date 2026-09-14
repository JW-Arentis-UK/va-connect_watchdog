import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from va_watchdog.config import _enforce_neousys_watchdog, _enforce_recording_free_space_reserve
from va_watchdog.neousys_watchdog import NeousysWatchdog
from va_watchdog.watchdog_device import HardwareWatchdog
from va_watchdog.watchdog_feed import FeedWorker
from va_watchdog.watchdog import add_hardware_feed_check, hardware_feed_status


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
    def test_migrating_an_enabled_linux_backend_is_safely_disabled(self):
        config = _enforce_neousys_watchdog({
            "hardware_watchdog": {
                "enabled": True,
                "backend": "linux_watchdog",
                "device": "/dev/watchdog0",
            }
        })

        self.assertEqual(config["hardware_watchdog"]["backend"], "neousys_wdt_dio")
        self.assertEqual(config["hardware_watchdog"]["device"], "/dev/wdt_dio")
        self.assertFalse(config["hardware_watchdog"]["enabled"])

    def test_existing_neousys_activation_is_preserved(self):
        config = _enforce_neousys_watchdog({
            "hardware_watchdog": {"enabled": True, "backend": "neousys_wdt_dio"}
        })

        self.assertTrue(config["hardware_watchdog"]["enabled"])

    def test_legacy_null_recording_reserve_gets_safe_defaults(self):
        config = _enforce_recording_free_space_reserve({
            "recording_storage": {
                "minimum_free_mb_warning": None,
                "minimum_free_mb_critical": None,
            }
        })

        self.assertEqual(config["recording_storage"]["minimum_free_mb_warning"], 5000)
        self.assertEqual(config["recording_storage"]["minimum_free_mb_critical"], 2048)

    def test_explicit_zero_recording_reserve_is_preserved(self):
        config = _enforce_recording_free_space_reserve({
            "recording_storage": {
                "minimum_free_mb_warning": 0,
                "minimum_free_mb_critical": 0,
            }
        })

        self.assertEqual(config["recording_storage"]["minimum_free_mb_warning"], 0)
        self.assertEqual(config["recording_storage"]["minimum_free_mb_critical"], 0)

    def test_linux_watchdog_backend_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported hardware watchdog backend"):
            HardwareWatchdog(
                True,
                "/dev/watchdog0",
                10,
                None,
                backend="linux_watchdog",
            )

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

    def test_ordinary_health_failure_does_not_stop_feeding(self):
        vendor = Mock()
        with patch("va_watchdog.watchdog_device.os.path.exists", return_value=True), patch(
            "va_watchdog.watchdog_device.NeousysWatchdog", return_value=vendor
        ):
            hardware = HardwareWatchdog(True, "/dev/wdt_dio", 10, None)
            hardware.open()
            self.assertTrue(hardware.feed_if_due(healthy=False))

        vendor.feed.assert_called_once_with()

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

    def test_stale_feeder_process_is_not_reported_as_feeding(self):
        with tempfile.TemporaryDirectory() as temporary:
            now = time.time()
            state_path = Path(temporary) / "feed.json"
            state_path.write_text(json.dumps({
                "pid": os.getpid(),
                "process_status": "feeding",
                "last_feed_unix": now - 600,
                "updated_at": now - 600,
                "feed_count": 42,
            }), encoding="utf-8")
            cfg = {
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog_feed_state_path": str(state_path),
                "hardware_watchdog": {
                    "enabled": True,
                    "feed_interval_seconds": 10,
                    "device": "/dev/wdt_dio",
                },
            }
            with patch("va_watchdog.watchdog.Path.exists", return_value=True):
                status = hardware_feed_status(cfg, {"active": False})

        self.assertTrue(status["opened"])
        self.assertTrue(status["process_alive"])
        self.assertFalse(status["feeding"])
        self.assertGreater(status["feed_age_seconds"], 590)

    def test_recent_feeder_process_is_reported_as_feeding(self):
        with tempfile.TemporaryDirectory() as temporary:
            now = time.time()
            state_path = Path(temporary) / "feed.json"
            state_path.write_text(json.dumps({
                "pid": os.getpid(),
                "process_status": "feeding",
                "last_feed_unix": now,
                "updated_at": now,
                "feed_count": 43,
            }), encoding="utf-8")
            cfg = {
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog_feed_state_path": str(state_path),
                "hardware_watchdog": {
                    "enabled": True,
                    "feed_interval_seconds": 10,
                    "device": "/dev/wdt_dio",
                },
            }
            with patch("va_watchdog.watchdog.Path.exists", return_value=True):
                status = hardware_feed_status(cfg, {"active": False})

        self.assertTrue(status["feeding"])

    def test_missing_device_waits_in_same_feeder_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "feed.json"
            worker = FeedWorker({
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog_feed_state_path": str(state_path),
                "hardware_watchdog": {
                    "enabled": True,
                    "device_retry_seconds": 60,
                    "timeout_seconds": 30,
                },
            })

            def stop_after_retry(_seconds):
                worker.stop_requested = True

            with patch("va_watchdog.watchdog_feed.load_config", return_value={"hardware_watchdog": {"enabled": True}}), patch.object(
                worker, "_legacy_conflict", return_value=""
            ), patch.object(worker, "_wait_interruptibly", side_effect=stop_after_retry):
                opened = worker._open_when_available()

            state = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertFalse(opened)
        self.assertEqual(worker.error_count, 1)
        self.assertEqual(state["process_status"], "device_unavailable")
        self.assertEqual(state["device_retry_seconds"], 60)

    def test_feeder_requests_driver_when_device_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            worker = FeedWorker({
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog": {"timeout_seconds": 30},
            })
            completed = Mock(returncode=0, stdout="", stderr="")
            with patch("va_watchdog.watchdog_feed.os.path.exists", side_effect=[False, False, True]), patch(
                "va_watchdog.watchdog_feed.subprocess.run", return_value=completed
            ) as run, patch("va_watchdog.watchdog_feed.time.sleep"):
                loaded = worker._ensure_driver_loaded()

        self.assertTrue(loaded)
        self.assertEqual(run.call_args.args[0], ["modprobe", "wdt_dio"])

    def test_abnormal_feeder_exit_does_not_stop_hardware_timer(self):
        with tempfile.TemporaryDirectory() as temporary:
            worker = FeedWorker({
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog": {"timeout_seconds": 30},
            })
            worker.hw.close = Mock()
            worker._shutdown_hardware(abnormal_exit=True)

        worker.hw.close.assert_not_called()

    def test_consecutive_feeds_create_boot_specific_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof = Path(temporary) / "proof.json"
            worker = FeedWorker({
                "events_path": str(Path(temporary) / "events.jsonl"),
                "hardware_watchdog_proof_path": str(proof),
                "hardware_watchdog": {"timeout_seconds": 30, "proof_feed_count": 3},
            })
            worker.boot_id = "boot-a"
            worker.hw.feed_count = 3
            worker.hw.last_feed = time.time()
            worker._write_protection_proof()
            state = json.loads(proof.read_text(encoding="utf-8"))

        self.assertTrue(state["proven"])
        self.assertEqual(state["boot_id"], "boot-a")
        self.assertEqual(state["feed_count"], 3)

    def test_missing_feed_is_critical_but_does_not_request_recovery_reboot(self):
        status = {
            "checks": [],
            "hardware_watchdog_feed": {
                "enabled": True,
                "opened": False,
                "device": "/dev/wdt_dio",
            },
        }
        cfg = {
            "poll_interval_seconds": 5,
            "hardware_watchdog": {
                "enabled": True,
                "device": "/dev/wdt_dio",
                "feed_interval_seconds": 10,
            },
        }

        result = add_hardware_feed_check(status, cfg)
        check = next(item for item in result["checks"] if item["name"] == "hardware_watchdog_feed_status")

        self.assertEqual(check["state"], "critical")
        self.assertFalse(check["critical"])
        self.assertFalse(result["critical_failed"])

    def test_installer_does_not_activate_without_explicit_flag(self):
        script = Path(__file__).parents[1] / "scripts" / "install_neousys_wdt.sh"
        text = script.read_text(encoding="utf-8")
        self.assertIn("EXPECTED_SHA256=", text)
        self.assertIn('if [[ "$ACTIVATE" != 1 ]]', text)
        self.assertIn("configuration was not changed", text)
        self.assertIn('product" != *"POC-451VTC"*', text)
        self.assertIn('apt-get install -y build-essential dkms gcc-12 "linux-headers-$kernel" unzip', text)
        self.assertIn('AUTOINSTALL="yes"', text)
        self.assertIn('dkms build -m "$DKMS_NAME" -v "$VERSION" -k "$kernel"', text)
        self.assertIn('dkms install -m "$DKMS_NAME" -v "$VERSION" -k "$kernel" --force', text)
        self.assertIn('Prebuilding wdt_dio.ko for installed kernel $latest_kernel', text)
        self.assertIn("blacklist iTCO_wdt", text)
        self.assertIn("apt-get remove -y watchdog", text)
        self.assertIn("systemctl enable va-watchdog.service va-watchdog-feed.service", text)
        self.assertIn('fail "va-watchdog-feed.service is not enabled for reboot"', text)

    def test_feeder_service_uses_controlled_restart_backoff(self):
        service = Path(__file__).parents[1] / "systemd" / "va-watchdog-feed.service"
        text = service.read_text(encoding="utf-8")

        self.assertIn("Restart=on-failure", text)
        self.assertIn("ExecStartPre=-/sbin/modprobe wdt_dio", text)
        self.assertIn("RestartSec=5", text)

    def test_web_activation_uses_independent_systemd_job(self):
        web = Path(__file__).parents[1] / "va_watchdog" / "web.py"
        text = web.read_text(encoding="utf-8")

        self.assertIn('unit_name = f"va-watchdog-neousys-setup-', text)
        self.assertIn('"--collect"', text)
        self.assertIn("subprocess.run(launch_command", text)
        self.assertNotIn("Device intentionally remains closed during startup safety window", text)


if __name__ == "__main__":
    unittest.main()
