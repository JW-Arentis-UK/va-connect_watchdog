from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.storage import recording_storage_status, validate_system_recording_directory


class RecordingStorageModeTests(unittest.TestCase):
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
