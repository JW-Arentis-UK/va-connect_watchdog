import json
import tempfile
import unittest
from pathlib import Path

from va_watchdog.reboot_evidence import SHUTDOWN_RECORDED, classify, event_level, recent_restarts


class RestartHistoryTests(unittest.TestCase):
    def test_shutdown_record_does_not_identify_a_reboot_initiator(self):
        last_x = "reboot   system boot current\nshutdown system down previous\nreboot   system boot previous\n"
        result = classify({"previous_boot_id": "old"}, [], {}, "", last_x)
        self.assertEqual(result["reset_mechanism"], SHUTDOWN_RECORDED)
        self.assertEqual(event_level(result), "warning")
        fault = classify({"previous_boot_id": "old"}, [], {}, "Kernel panic - not syncing", last_x)
        self.assertEqual(fault["reset_mechanism"], "Kernel fault")

    def test_shutdown_record_without_boot_boundaries_is_inconclusive(self):
        result = classify({"previous_boot_id": "old"}, [], {}, "", "shutdown system down old event")
        self.assertEqual(result["reset_mechanism"], "Unknown")

    def test_legacy_clean_reboot_is_shown_with_unknown_cause(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reboot-evidence.jsonl"
            original = json.dumps({"current_boot_id": "boot-a", "reset_mechanism": "Clean reboot"}) + "\n"
            path.write_text(original, encoding="utf-8")
            result = recent_restarts({"events_path": str(root / "events.jsonl")})
            self.assertEqual(result[0]["restart_type"], SHUTDOWN_RECORDED)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_returns_latest_unique_boots_in_newest_first_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reboot-evidence.jsonl"
            rows = [
                {"current_boot_id": "boot-a", "created_at": 100, "reset_mechanism": "Clean reboot", "confidence": "Medium"},
                {"current_boot_id": "boot-b", "created_at": 200, "reset_mechanism": "Unknown", "confidence": "Low"},
                {
                    "current_boot_id": "boot-b",
                    "created_at": 200,
                    "reset_mechanism": "Watchdog reset",
                    "confidence": "High",
                    "deliberate_trip_test": {"confirmed": True},
                },
                {"current_boot_id": "boot-c", "created_at": 300, "reset_mechanism": "Requested reboot", "confidence": "High"},
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            cfg = {"events_path": str(root / "events.jsonl"), "reboot_evidence_path": str(path)}

            result = recent_restarts(cfg, limit=2)

            self.assertEqual([row["boot_id"] for row in result], ["boot-c", "boot-b"])
            self.assertEqual(result[1]["classification"], "Watchdog reset")
            self.assertEqual(result[1]["restart_type"], "Deliberate trip test")

    def test_distinguishes_planned_tests_from_automatic_watchdog_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reboot-evidence.jsonl"
            rows = [
                {"current_boot_id": "automatic", "created_at": 100, "reset_mechanism": "Watchdog reset"},
                {
                    "current_boot_id": "liveness",
                    "created_at": 200,
                    "reset_mechanism": "Watchdog reset",
                    "liveness_path_test": {"confirmed": True},
                },
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            cfg = {"events_path": str(root / "events.jsonl"), "reboot_evidence_path": str(path)}

            result = recent_restarts(cfg)

            self.assertEqual(result[0]["restart_type"], "Full liveness test")
            self.assertEqual(result[1]["restart_type"], "Automatic watchdog recovery")

    def test_ignores_partial_or_invalid_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reboot-evidence.jsonl"
            path.write_text(
                "not-json\n"
                + json.dumps({"current_boot_id": "boot-a", "created_at": 100, "classification": "Unknown"})
                + "\n{partial",
                encoding="utf-8",
            )
            cfg = {"events_path": str(root / "events.jsonl"), "reboot_evidence_path": str(path)}

            result = recent_restarts(cfg)

            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["boot_id"], "boot-a")


if __name__ == "__main__":
    unittest.main()
