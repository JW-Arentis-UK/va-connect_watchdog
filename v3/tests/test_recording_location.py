import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog import recording_location as location
from va_watchdog.recording_activity import candidate_recording_paths, recording_activity
from va_watchdog.storage import recording_storage_status


class RecordingLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        location._CACHE.clear()
        for target, value in (("STATE", self.base / "state.json"),):
            mock = patch.object(location, target, value)
            mock.start()
            self.addCleanup(mock.stop)

    def disk(self, name, uuid="test-uuid", footage=True):
        mount = self.base / name
        folder = mount / "recordings"
        folder.mkdir(parents=True)
        if footage:
            bucket = folder / "1795478400"
            bucket.mkdir()
            (bucket / "1795478500.data").touch()
        return {"target": str(mount), "source": "/dev/sdb", "fstype": "ext4", "uuid": uuid}, folder

    def test_syston_and_melton_mounts_override_empty_wrong_configuration(self):
        for name in ("Storage", "1cac11a8-caf7-4184-a750-c2046e26a1ba"):
            with self.subTest(name=name):
                location._CACHE.clear()
                row, folder = self.disk(name)
                cfg = {"storage": {"recordings_path": str(self.base / "wrong")},
                       "recording_storage": {"mode": "system_directory", "directory_path": str(self.base / "wrong")}}
                with patch.object(location, "mounted_filesystems", return_value=[row]), patch.object(location, "_remember"):
                    value = location.resolve(cfg)
                    self.assertEqual(value["state"], "detected")
                    self.assertEqual(value["path"], str(folder))
                    self.assertEqual(candidate_recording_paths(cfg), [folder])
                    history = recording_activity(cfg)
                    self.assertTrue(history["available"])
                    self.assertEqual(history["recordings_path"], str(folder))
                    with patch("va_watchdog.storage._configured_recording_storage_status", return_value={}) as monitor:
                        recording_storage_status(cfg)
                        effective = monitor.call_args.args[0]["recording_storage"]
                        self.assertEqual(effective["directory_path"], str(folder))
                        self.assertEqual(effective["directory_mountpoint"], row["target"])
                        self.assertEqual(effective["filesystem"], "ext4")
                    self.assertEqual(cfg["storage"]["recordings_path"], str(self.base / "wrong"))

    def test_empty_folders_and_timestamp_directories_are_not_evidence(self):
        row, folder = self.disk("empty", footage=False)
        (folder / "1795478400").mkdir()
        with patch.object(location, "mounted_filesystems", return_value=[row]):
            self.assertEqual(location.resolve({})["state"], "not_found")

    def test_multiple_disks_do_not_guess_without_explicit_selection(self):
        first, folder = self.disk("first", uuid="one")
        second, other = self.disk("second", uuid="two")
        with patch.object(location, "mounted_filesystems", return_value=[first, second]), patch.object(location, "_remember"):
            self.assertEqual(location.resolve({})["state"], "ambiguous")
            self.assertEqual(candidate_recording_paths({}), [])
            cfg = {"storage": {"recordings_path": str(other)}}
            self.assertEqual(location.resolve(cfg)["path"], str(other))

    def test_missing_remembered_disk_does_not_fall_back_or_write_probe(self):
        row, folder = self.disk("remembered")
        saved = {"path": str(folder), "mountpoint": row["target"], "filesystem": "ext4",
                 "uuid": row["uuid"], "source": row["source"], "subdir": "recordings"}
        with patch.object(location, "mounted_filesystems", return_value=[]), patch.object(location, "_saved", return_value=saved):
            self.assertEqual(location.resolve({})["state"], "missing")
            self.assertEqual(candidate_recording_paths({}), [])
            with patch("va_watchdog.storage._configured_recording_storage_status", return_value={}) as monitor:
                result = recording_storage_status({})
                self.assertFalse(monitor.call_args.kwargs["probe_writable"])
                self.assertFalse(result["mounted"])
                self.assertIsNone(result["total_gb"])
                self.assertEqual(result["status"], "critical")

    def test_remembered_uuid_follows_changed_mountpoint(self):
        row, folder = self.disk("new-mount")
        saved = {"path": "/old/recordings", "mountpoint": "/old", "filesystem": "ext4",
                 "uuid": row["uuid"], "source": "/dev/old", "subdir": "recordings"}
        with patch.object(location, "mounted_filesystems", return_value=[row]), patch.object(location, "_saved", return_value=saved):
            self.assertEqual(location.resolve({})["path"], str(folder))

    def test_manual_override_performs_no_mount_discovery(self):
        with patch.object(location, "mounted_filesystems") as mounts:
            self.assertEqual(location.resolve({"recording_storage": {"auto_detect": False}})["state"], "disabled")
            mounts.assert_not_called()

    def test_discovery_is_cached_and_ignores_nonrecording_files(self):
        row, folder = self.disk("metadata", footage=False)
        (folder / "1795478400.log").touch()
        with patch.object(location, "mounted_filesystems", return_value=[row]) as mounts:
            self.assertEqual(location.resolve({})["state"], "not_found")
            location.resolve({})
            self.assertEqual(mounts.call_count, 1)
        self.assertIsNone(location.evidence(folder, time.monotonic() - 1))

    def test_remembered_selection_survives_process_cache_reset(self):
        row, folder = self.disk("persistent")
        with patch.object(location.os, "geteuid", return_value=0, create=True), \
                patch.object(location, "mounted_filesystems", return_value=[row]):
            first = location.resolve({})
        self.assertTrue(location.STATE.exists())
        location._CACHE.clear()
        with patch.object(location, "mounted_filesystems", return_value=[]):
            self.assertEqual(location.resolve({})["state"], "missing")

    def test_mount_inventory_excludes_loops_and_pseudo_filesystems(self):
        import json
        from unittest.mock import Mock
        result = Mock(returncode=0, stdout=json.dumps({"filesystems": [
            {"target": "/export/anpr", "source": "/dev/loop0", "fstype": "ext4"},
            {"target": "/run", "source": "tmpfs", "fstype": "tmpfs"},
            {"target": "/media/disk", "source": "/dev/sda5", "fstype": "ext4", "uuid": "test"}]}))
        with patch.object(location.subprocess, "run", return_value=result):
            self.assertEqual([row["target"] for row in location.mounted_filesystems()], ["/media/disk"])


if __name__ == "__main__":
    unittest.main()
