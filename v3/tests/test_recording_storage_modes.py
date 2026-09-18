from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.storage import (
    _RECORDING_WARNING_STATE,
    _stabilize_recording_storage_warning,
    recording_storage_status,
    validate_system_recording_directory,
)


class RecordingStorageModeTests(unittest.TestCase):
    def setUp(self):
        _RECORDING_WARNING_STATE.clear()

    def _cfg(self, directory: str):
        return {
            "recording_storage": {
                "enabled": True,
                "mode": "system_directory",
                "directory_path": directory,
                "filesystem": "ext4",
                "expected_label": "CCTV_STORAGE",
                "recording_services": ["esg.service"],
            },
            "thresholds": {
                "recordings_disk_warning_percent": 98,
                "recordings_disk_critical_percent": 99,
            },
        }

    @patch(
        "va_watchdog.storage._smart_info",
        return_value={"status": "PASSED", "temperature_c": 35, "device": "/dev/sda"},
    )
    @patch(
        "va_watchdog.storage.shutil.disk_usage",
        return_value=(100 * 1024**3, 20 * 1024**3, 80 * 1024**3),
    )
    @patch("va_watchdog.storage.os.path.realpath", side_effect=lambda value: value)
    @patch("va_watchdog.storage._blkid_value", return_value="")
    @patch("va_watchdog.storage._row_for_device", return_value={})
    @patch(
        "va_watchdog.storage._findmnt_for_path",
        return_value={"source": "/dev/sda2", "target": "/", "fstype": "ext4", "options": "rw,relatime"},
    )
    def test_system_directory_is_healthy_without_recording_label(
        self,
        _findmnt,
        _row,
        _blkid,
        _realpath,
        _disk_usage,
        _smart,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            status = recording_storage_status(self._cfg(temporary))

        self.assertEqual(status["status"], "healthy")
        self.assertEqual(status["mode"], "system_directory")
        self.assertEqual(status["device"], "/dev/sda2")
        self.assertEqual(status["mountpoint"], "/")
        self.assertTrue(status["label_ok"])
        self.assertEqual(status["expected_label"], "Not required (system disk)")
        self.assertEqual(status["recording_service_mount_guards"], [])
        self.assertIn("Not used", status["fstab_entry"])

    @patch(
        "va_watchdog.storage._smart_info",
        return_value={"status": "PASSED", "temperature_c": 35, "device": "/dev/sda"},
    )
    @patch(
        "va_watchdog.storage.shutil.disk_usage",
        return_value=(100 * 1024**3, 96 * 1024**3, 4 * 1024**3),
    )
    @patch("va_watchdog.storage.os.path.realpath", side_effect=lambda value: value)
    @patch("va_watchdog.storage._blkid_value", return_value="")
    @patch("va_watchdog.storage._row_for_device", return_value={})
    @patch(
        "va_watchdog.storage._findmnt_for_path",
        return_value={"source": "/dev/sda2", "target": "/", "fstype": "ext4", "options": "rw,relatime"},
    )
    def test_expected_full_storage_still_warns_below_five_gb_reserve(
        self,
        _findmnt,
        _row,
        _blkid,
        _realpath,
        _disk_usage,
        _smart,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            cfg["recording_storage"].update({
                "expected_full": True,
                "minimum_free_mb_warning": 5000,
                "minimum_free_mb_critical": 2048,
            })
            status = recording_storage_status(cfg)

        self.assertEqual(status["status"], "warning")
        self.assertEqual(status["message"], "Recording storage low free MB")

    def test_brief_low_reserve_does_not_raise_overall_warning(self):
        cfg = {
            "recording_storage": {
                "warning_sustained_seconds": 120,
                "warning_recovery_margin_mb": 256,
            }
        }
        reading = {
            "status": "warning",
            "message": "Recording storage low free MB",
            "monitored_path": "/recordings",
            "free_mb": 4900,
            "minimum_free_mb_warning": 5000,
        }

        first = _stabilize_recording_storage_warning(reading, cfg, now=100)
        second = _stabilize_recording_storage_warning(reading, cfg, now=160)
        sustained = _stabilize_recording_storage_warning(reading, cfg, now=221)

        self.assertEqual(first["status"], "healthy")
        self.assertEqual(second["status"], "healthy")
        self.assertEqual(first["raw_status"], "warning")
        self.assertEqual(sustained["status"], "warning")

    def test_critical_recording_fault_is_never_delayed(self):
        reading = {
            "status": "critical",
            "message": "Recording storage below minimum free MB",
            "monitored_path": "/recordings",
            "free_mb": 1900,
            "minimum_free_mb_warning": 5000,
        }

        result = _stabilize_recording_storage_warning(reading, {"recording_storage": {}}, now=100)

        self.assertEqual(result["status"], "critical")

    def test_active_warning_uses_recovery_margin_to_prevent_flicker(self):
        cfg = {
            "recording_storage": {
                "warning_sustained_seconds": 120,
                "warning_recovery_margin_mb": 256,
            }
        }
        low = {
            "status": "warning",
            "message": "Recording storage low free MB",
            "monitored_path": "/recordings",
            "free_mb": 4900,
            "minimum_free_mb_warning": 5000,
        }
        _stabilize_recording_storage_warning(low, cfg, now=100)
        _stabilize_recording_storage_warning(low, cfg, now=221)

        near_threshold = dict(low, status="healthy", message="Recording storage healthy", free_mb=5100)
        recovered = dict(near_threshold, free_mb=5300)

        self.assertEqual(_stabilize_recording_storage_warning(near_threshold, cfg, now=230)["status"], "warning")
        self.assertEqual(_stabilize_recording_storage_warning(recovered, cfg, now=240)["status"], "healthy")

    @patch(
        "va_watchdog.storage._findmnt_for_path",
        return_value={"source": "/dev/sda2", "target": "/", "fstype": "ext4", "options": "rw"},
    )
    def test_missing_system_directory_is_critical(self, _findmnt):
        status = recording_storage_status(self._cfg("/path/that/does/not/exist"))
        self.assertEqual(status["status"], "critical")
        self.assertEqual(status["message"], "Recording directory missing")

    @patch("va_watchdog.storage.os.path.realpath", side_effect=lambda value: value)
    def test_system_root_cannot_be_selected_as_recording_directory(self, _realpath):
        result = validate_system_recording_directory("/")
        self.assertFalse(result["ok"])
        self.assertIn("protected", result["message"])

    @patch("va_watchdog.storage._recording_writable", return_value=True)
    @patch("va_watchdog.storage._parent_disk", return_value="/dev/sda")
    @patch("va_watchdog.storage._root_parent_disk", return_value="/dev/sda")
    @patch(
        "va_watchdog.storage._findmnt_for_path",
        return_value={"source": "/dev/sda2", "target": "/", "fstype": "ext4", "options": "rw"},
    )
    @patch.object(Path, "is_dir", return_value=True)
    @patch("va_watchdog.storage.os.path.realpath", side_effect=lambda value: value)
    def test_existing_home_directory_on_root_disk_is_accepted(
        self,
        _realpath,
        _is_dir,
        _findmnt,
        _root_parent,
        _parent,
        _writable,
    ):
        result = validate_system_recording_directory("/home/vsuser/recordings")
        self.assertTrue(result["ok"])
        self.assertEqual(result["device"], "/dev/sda2")
        self.assertEqual(result["mountpoint"], "/")


if __name__ == "__main__":
    unittest.main()
