from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from va_watchdog.reboot_evidence import classify
from va_watchdog.reset_attribution import current_boot_started_at


class ResetAttributionTests(unittest.TestCase):
    def setUp(self):
        self.change = {
            "previous_boot_id": "old",
            "current_boot_id": "new",
            "previous_last_sample_utc": "2026-10-10T07:27:15+00:00",
            "detected_at": "2026-10-10T07:28:43+00:00",
            "boot_started_at": "2026-10-10T07:28:36+00:00",
        }
        self.feed = {
            "boot_id": "old",
            "process_status": "feeding",
            "feed_decision": "main process and health loop are fresh",
            "timeout_seconds": 30,
            "last_feed_utc": "2026-10-10T07:27:15+0000",
        }
        self.heartbeats = [{"boot_id": "old", "time": "2026-10-10T07:27:15+00:00"}]

    def test_compatible_timing_does_not_claim_confirmed_watchdog_reset(self):
        last_x = "\n".join((
            "reboot   system boot  kernel Sat Oct 10 08:28 still running",
            "vsuser   :0           :0     Fri Oct  9 15:06 - crash",
            "reboot   system boot  kernel Fri Oct  9 15:05 - 08:28",
        ))
        evidence = classify(self.change, self.heartbeats, {}, "", last_x, previous_feed=self.feed)
        attribution = evidence["reset_attribution"]
        self.assertEqual(evidence["reset_mechanism"], "Unknown")
        self.assertEqual(attribution["assessment"], "timing compatible; unconfirmed")
        self.assertFalse(attribution["hardware_reset_confirmed"])
        self.assertEqual(attribution["last_feed_to_boot_seconds"], 81)
        self.assertEqual(attribution["last_blackbox_sample_utc"], "2026-10-10T07:27:15+00:00")

    def test_missing_or_wrong_boot_feed_is_not_compatible(self):
        last_x = "\n".join((
            "reboot   system boot  kernel Sat Oct 10 08:28 still running",
            "vsuser   :0           :0     Fri Oct  9 15:06 - crash",
            "reboot   system boot  kernel Fri Oct  9 15:05 - 08:28",
        ))
        for feed in ({}, {**self.feed, "boot_id": "another"}):
            with self.subTest(feed=feed):
                evidence = classify(self.change, self.heartbeats, {}, "", last_x, previous_feed=feed)
                self.assertEqual(evidence["reset_attribution"]["assessment"], "insufficient evidence")

    def test_missing_shutdown_evidence_does_not_imply_unclean_reset(self):
        evidence = classify(self.change, self.heartbeats, {}, "", "", previous_feed=self.feed)
        self.assertEqual(evidence["reset_attribution"]["assessment"], "insufficient evidence")

    def test_requested_reboot_is_not_inferred_as_watchdog(self):
        evidence = classify(self.change, self.heartbeats, {"cause": "operator"}, "", "", previous_feed=self.feed)
        self.assertEqual(evidence["reset_attribution"]["assessment"], "insufficient evidence")

    def test_boot_time_from_uptime(self):
        with tempfile.TemporaryDirectory() as directory:
            uptime = Path(directory) / "uptime"
            uptime.write_text("7.5 1.0\n", encoding="utf-8")
            self.assertEqual(current_boot_started_at("2026-10-10T07:28:43+00:00", uptime), "2026-10-10T07:28:35.500000+00:00")


if __name__ == "__main__":
    unittest.main()
