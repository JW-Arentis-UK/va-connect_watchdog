import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from va_watchdog.reboot_evidence import classify
from va_watchdog.watchdog_liveness_test import reconcile_liveness_test, start_liveness_test


class WatchdogLivenessTests(unittest.TestCase):
    def _cfg(self, root):
        return {
            "events_path": str(root / "events.jsonl"),
            "hardware_watchdog_proof_path": str(root / "proof.json"),
            "hardware_watchdog_feed_state_path": str(root / "feed.json"),
            "liveness_test_path": str(root / "liveness.json"),
            "hardware_watchdog": {
                "stale_heartbeat_seconds": 15,
                "timeout_seconds": 30,
                "liveness_test_fallback_seconds": 75,
            },
        }

    def test_full_liveness_test_requires_current_boot_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(Path(temporary))
            with patch("va_watchdog.watchdog_liveness_test.current_boot_id", return_value="boot-a"):
                result = start_liveness_test(cfg, acknowledged=True)

        self.assertFalse(result["ok"])
        self.assertIn("not been proven", result["message"])

    def test_full_liveness_test_schedules_stop_with_safe_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = self._cfg(root)
            (root / "proof.json").write_text(json.dumps({"proven": True, "boot_id": "boot-a"}), encoding="utf-8")
            (root / "feed.json").write_text(json.dumps({"process_status": "feeding", "last_feed_unix": 1000}), encoding="utf-8")
            completed = Mock(returncode=0, stdout="queued", stderr="")
            with patch("va_watchdog.watchdog_liveness_test.current_boot_id", return_value="boot-a"), patch(
                "va_watchdog.watchdog_liveness_test.time.time", return_value=1000
            ), patch("va_watchdog.watchdog_liveness_test.subprocess.run", return_value=completed) as run:
                result = start_liveness_test(cfg, acknowledged=True)

            state = json.loads((root / "liveness.json").read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertTrue(state["active"])
        command = run.call_args.args[0]
        self.assertIn("systemd-run", command)
        self.assertIn("systemctl stop va-watchdog.service", command[-1])
        self.assertIn("systemctl start va-watchdog.service", command[-1])

    def test_new_boot_completes_liveness_test(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = self._cfg(root)
            (root / "liveness.json").write_text(json.dumps({
                "active": True,
                "triggered_boot_id": "boot-a",
                "triggered_at": "2026-01-01T00:00:00Z",
            }), encoding="utf-8")
            with patch("va_watchdog.watchdog_liveness_test.current_boot_id", return_value="boot-b"):
                state = reconcile_liveness_test(cfg)

        self.assertTrue(state["ok"])
        self.assertTrue(state["completed"])
        self.assertFalse(state["active"])

    def test_liveness_marker_classifies_reset_as_watchdog(self):
        evidence = classify(
            {"changed": True, "previous_boot_id": "boot-a", "current_boot_id": "boot-b"},
            [],
            {},
            "",
            "session - crash",
            "",
            {},
            {"active": True, "triggered_boot_id": "boot-a", "triggered_at": "now"},
        )

        self.assertEqual(evidence["reset_mechanism"], "Watchdog reset")
        self.assertEqual(evidence["confidence"], "High")
        self.assertTrue(evidence["liveness_path_test"]["confirmed"])


if __name__ == "__main__":
    unittest.main()
