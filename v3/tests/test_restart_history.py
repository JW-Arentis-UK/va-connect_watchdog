import json
import tempfile
import unittest
from pathlib import Path

from va_watchdog.reboot_evidence import recent_restarts


class RestartHistoryTests(unittest.TestCase):
    def test_returns_latest_unique_boots_in_newest_first_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "reboot-evidence.jsonl"
            rows = [
                {"current_boot_id": "boot-a", "created_at": 100, "reset_mechanism": "Clean reboot", "confidence": "Medium"},
                {"current_boot_id": "boot-b", "created_at": 200, "reset_mechanism": "Unknown", "confidence": "Low"},
                {"current_boot_id": "boot-b", "created_at": 200, "reset_mechanism": "Watchdog reset", "confidence": "High"},
                {"current_boot_id": "boot-c", "created_at": 300, "reset_mechanism": "Requested reboot", "confidence": "High"},
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            cfg = {"events_path": str(root / "events.jsonl"), "reboot_evidence_path": str(path)}

            result = recent_restarts(cfg, limit=2)

            self.assertEqual([row["boot_id"] for row in result], ["boot-c", "boot-b"])
            self.assertEqual(result[1]["classification"], "Watchdog reset")

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
