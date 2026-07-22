from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.baseline_capture import baseline_status, completed_archive, start_baseline


class BaselineCaptureTests(unittest.TestCase):
    def _cfg(self, root: Path):
        return {"events_path": str(root / "events.jsonl")}

    def test_rejects_unapproved_duration(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = start_baseline(self._cfg(Path(temporary)), 120)
        self.assertFalse(result["ok"])
        self.assertIn("15 minutes or 1 hour", result["message"])

    @patch("va_watchdog.baseline_capture.baseline_status")
    def test_prevents_concurrent_capture(self, status):
        status.return_value = {"running": True, "state": "running"}
        with tempfile.TemporaryDirectory() as temporary:
            result = start_baseline(self._cfg(Path(temporary)), 900)
        self.assertFalse(result["ok"])
        self.assertIn("already running", result["message"])

    @patch("va_watchdog.baseline_capture._unit_properties")
    def test_completed_archive_stays_inside_managed_directory(self, properties):
        properties.return_value = {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = self._cfg(root)
            output = root / "stage0-baselines"
            output.mkdir()
            started = time.time() - 1000
            (output / "state.json").write_text(
                json.dumps({"unit": "capture.service", "duration_seconds": 900, "started_unix": started}),
                encoding="utf-8",
            )
            archive = output / "va-watchdog-stage0-test.tar.gz"
            archive.write_bytes(b"archive")

            status = baseline_status(cfg)
            selected = completed_archive(cfg)

        self.assertEqual(status["state"], "complete")
        self.assertTrue(status["download_ready"])
        self.assertEqual(selected.name, archive.name)

    @patch("va_watchdog.baseline_capture._unit_properties")
    def test_missing_archive_after_deadline_is_failed(self, properties):
        properties.return_value = {"ActiveState": "inactive", "Result": "", "ExecMainStatus": ""}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "stage0-baselines"
            output.mkdir()
            (output / "state.json").write_text(
                json.dumps({"unit": "capture.service", "duration_seconds": 900, "started_unix": time.time() - 1300}),
                encoding="utf-8",
            )
            status = baseline_status(self._cfg(root))

        self.assertEqual(status["state"], "failed")
        self.assertFalse(status["download_ready"])

    @patch("va_watchdog.baseline_capture._run")
    @patch("va_watchdog.baseline_capture.shutil.which")
    @patch("va_watchdog.baseline_capture.baseline_status")
    def test_launch_uses_fixed_low_priority_systemd_unit(self, status, which, run):
        status.return_value = {"running": False, "readiness": {"ready": True}}
        which.return_value = "/usr/bin/systemd-run"
        run.return_value = {"returncode": 0, "stdout": "queued", "stderr": ""}

        with tempfile.TemporaryDirectory() as temporary:
            result = start_baseline(self._cfg(Path(temporary)), 900)

        self.assertTrue(result["ok"])
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/systemd-run")
        self.assertIn("--property=Nice=10", command)
        self.assertEqual(command[-3:], ["900", "5", str(Path(temporary) / "stage0-baselines")])


if __name__ == "__main__":
    unittest.main()
