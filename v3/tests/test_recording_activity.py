import tempfile
import unittest
from pathlib import Path

from va_watchdog.recording_activity import recording_activity


class RecordingActivityTests(unittest.TestCase):
    def test_decodes_latest_unix_recording_filename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "recordings"
            older = root / "1784160000"
            newest = root / "1784246400"
            older.mkdir(parents=True)
            newest.mkdir()
            (older / "1784210205.data").touch()
            (newest / "1784246500.data").touch()
            (newest / "1784246800.data").touch()
            (root / "events.db").touch()
            cfg = {
                "storage": {"recordings_path": str(root)},
                "recording_storage": {"mountpoint": str(Path(temporary) / "unused")},
            }

            result = recording_activity(cfg, now_unix=1784246860)

        self.assertTrue(result["available"])
        self.assertEqual(result["oldest"]["unix"], 1784210205)
        self.assertEqual(result["oldest_age_seconds"], 36655.0)
        self.assertEqual([item["unix"] for item in result["oldest_recordings"]], [1784210205, 1784246500, 1784246800])
        self.assertEqual(result["latest"]["unix"], 1784246800)
        self.assertEqual(result["latest_age_seconds"], 60.0)
        self.assertEqual([item["unix"] for item in result["recent"][:2]], [1784246800, 1784246500])
        self.assertEqual(result["oldest_bucket_unix"], 1784160000)
        self.assertEqual(result["newest_bucket_unix"], 1784246400)

    def test_missing_timestamp_files_is_reported_without_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "recordings"
            root.mkdir()
            (root / "events.db").touch()
            cfg = {
                "storage": {"recordings_path": str(root)},
                "recording_storage": {"mountpoint": str(Path(temporary) / "unused")},
            }

            result = recording_activity(cfg)

        self.assertFalse(result["available"])
        self.assertEqual(result["oldest_recordings"], [])
        self.assertEqual(result["recent"], [])


if __name__ == "__main__":
    unittest.main()
