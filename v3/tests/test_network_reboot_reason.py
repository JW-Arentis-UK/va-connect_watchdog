import json
from pathlib import Path
import tempfile
import unittest

from va_watchdog.legacy_reboot import NETWORK_REBOOT, apply_legacy_reason
from va_watchdog.reboot_evidence import create, recent_restarts


class NetworkRebootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "legacy.jsonl"
        self.cfg = {"events_path": str(self.root / "events.jsonl"), "legacy_watchdog_events_path": str(self.log)}
        self.evidence = {
            "previous_boot_id": "old", "current_boot_id": "new",
            "created_at": 1791069187,
            "classification": "Clean reboot", "confidence": "Medium",
            "last_heartbeat": {"boot_id": "old", "time": "2026-10-03T23:12:07+00:00"},
        }
        self.rows = [
            {"event": "heartbeat", "ts": "2026-10-03T23:12:07+00:00", "checks": {"lan_ok": False, "internet_ok": False, "app_ok": True, "services_ok": True, "password": "do-not-copy"}},
            {"event": "action", "ts": "2026-10-03T23:12:08+00:00", "action": "reboot", "return_code": 0},
            {"event": "startup", "ts": "2026-10-03T23:13:06+00:00", "config": {"password": "do-not-copy"}},
        ]

    def write_log(self):
        self.log.write_text("\n".join(json.dumps(row) for row in self.rows) + "\n", encoding="utf-8")

    def test_existing_incident_is_amended_and_displayed_on_restart(self):
        self.write_log()
        latest = self.root / "last-reboot-evidence.json"
        latest.write_text(json.dumps(self.evidence), encoding="utf-8")
        result = create(self.cfg, {"changed": False})
        self.assertEqual(result["previous_reboot_reason"]["message"], NETWORK_REBOOT)
        self.assertEqual(result["probable_preceding_fault"], "loss of network access")
        self.assertEqual(result["reset_mechanism"], "Requested reboot")
        self.assertNotIn("do-not-copy", json.dumps(result))
        self.assertEqual(recent_restarts(self.cfg)[0]["restart_type"], NETWORK_REBOOT)
        create(self.cfg, {"changed": False})
        self.assertEqual(len((self.root / "reboot-evidence.jsonl").read_text().splitlines()), 1)

    def test_no_network_does_not_prove_a_reboot_request(self):
        for code in (1, None):
            with self.subTest(code=code):
                self.rows[1]["return_code"] = code
                self.write_log()
                self.assertFalse(apply_legacy_reason(self.cfg, dict(self.evidence)))

    def test_stale_wrong_boot_and_new_boot_commands_are_ignored(self):
        self.write_log()
        for heartbeat in ({"boot_id": "other", "time": "2026-10-03T23:12:07+00:00"}, {"boot_id": "old", "time": "2026-10-02T23:12:07+00:00"}):
            evidence = {**self.evidence, "last_heartbeat": heartbeat}
            self.assertFalse(apply_legacy_reason(self.cfg, evidence))
        self.rows.insert(1, {"event": "startup", "ts": "2026-10-03T23:12:07+00:00"})
        self.write_log()
        self.assertFalse(apply_legacy_reason(self.cfg, self.evidence))

    def test_other_reboot_causes_are_preserved(self):
        self.write_log()
        for extra in ({"previous_reboot_reason": {"message": "manual"}}, {"reset_mechanism": "Kernel fault"}, {"deliberate_trip_test": {"confirmed": True}}):
            self.assertFalse(apply_legacy_reason(self.cfg, {**self.evidence, **extra}))

    def test_missing_or_corrupt_log_does_not_break_startup(self):
        self.assertFalse(apply_legacy_reason(self.cfg, self.evidence))
        self.log.write_text('bad-json\nnull\n[]\n{"event":"heartbeat","ts":"bad"}\n')
        self.assertFalse(apply_legacy_reason(self.cfg, self.evidence))

    def test_app_failure_does_not_get_network_label(self):
        self.rows[0]["checks"] = {"lan_ok": True, "internet_ok": True, "app_ok": False}
        self.write_log()
        self.assertTrue(apply_legacy_reason(self.cfg, self.evidence))
        self.assertEqual(self.evidence["previous_reboot_reason"]["cause"], "unknown")


if __name__ == "__main__":
    unittest.main()
