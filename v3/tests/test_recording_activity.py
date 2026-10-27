import tempfile
import json
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from va_watchdog.recording_activity import recording_activity
from va_watchdog.health import collect_health
from va_watchdog.lite import snapshot


class RecordingActivityTests(unittest.TestCase):
    def test_core_publishes_recording_history_through_collector_pool(self):
        pool = Mock()
        pool.poll.side_effect = lambda name, interval, deadline, callback: callback() if name == "recording_history" else []
        value = {"available": True, "checked_at": datetime.now(timezone.utc).isoformat(), "message": "recording"}
        with patch("va_watchdog.health.recording_activity", return_value=value):
            status, checks = collect_health({}, pool)
        self.assertEqual(status["recording_activity"], value)
        self.assertEqual(checks, [])
        self.assertTrue(any(call.args[0] == "recording_history" for call in pool.poll.call_args_list))

    def test_dashboard_uses_saved_history_and_rejects_stale_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            now = time.time()
            status = {"time": datetime.fromtimestamp(now, timezone.utc).isoformat(), "checks": [],
                      "recording_activity": {"available": True, "checked_at": now,
                                             "oldest": {"display_local": "old"},
                                             "latest": {"display_local": "new"}}}
            cfg = {"status_path": str(base / "status.json"), "events_path": str(base / "events.jsonl")}
            (base / "status.json").write_text(json.dumps(status))
            with patch("va_watchdog.lite.recording_activity", side_effect=AssertionError("web must not scan footage")):
                result = snapshot(cfg, now=now)
                card = next(item for item in result["cards"] if item["title"] == "Recording history")
                self.assertEqual(card["state"], "healthy")
                result = snapshot(cfg, now=now + 91)
                card = next(item for item in result["cards"] if item["title"] == "Recording history")
                self.assertEqual(card["state"], "unknown")
                self.assertIn("stale", card["detail"])

    def test_unreadable_fallback_does_not_hide_accessible_recordings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "1784246800.data").touch()
            denied = root / "private"
            original = Path.is_dir

            def is_dir(path):
                if path == denied:
                    raise PermissionError("private home directory")
                return original(path)

            with patch("va_watchdog.recording_activity.candidate_recording_paths", return_value=[root, denied]), patch.object(Path, "is_dir", is_dir):
                result = recording_activity({})
            self.assertTrue(result["available"])
            self.assertEqual(result["latest"]["unix"], 1784246800)
            self.assertEqual(result["unreadable_paths"], [str(denied)])
            with patch("va_watchdog.recording_activity.candidate_recording_paths", return_value=[denied]), patch.object(Path, "is_dir", is_dir):
                result = recording_activity({})
            self.assertFalse(result["available"])
            self.assertIn("could not be read", result["message"])

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
