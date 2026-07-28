import unittest
import gzip
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from va_watchdog.heartbeat import HeartbeatPublisher, heartbeat_age_seconds, read_state
from va_watchdog.incident_archive import archive_previous_boot, list_archives
from va_watchdog.reboot_evidence import classify
from va_watchdog.watchdog_feed import FeedWorker


class ForensicPhase1Tests(unittest.TestCase):
    def test_heartbeat_publisher_keeps_process_liveness_separate_from_health_sequence(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            cfg = {"events_path": str(Path(temporary) / "events.jsonl")}
            publisher = HeartbeatPublisher(cfg)
            publisher.mark_health_sample(7, sampled_at="2026-01-01T00:00:00+00:00")
            first = publisher.publish_once()
            second = publisher.publish_once()

        self.assertEqual(first["health_sequence"], 7)
        self.assertEqual(second["health_sequence"], 7)
        self.assertEqual(second["last_health_sample"], "2026-01-01T00:00:00+00:00")
        self.assertGreaterEqual(second["monotonic_uptime"], first["monotonic_uptime"])

    def test_heartbeat_thread_publishes_without_new_health_sample(self):
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as temporary:
            cfg = {"events_path": str(Path(temporary) / "events.jsonl")}
            publisher = HeartbeatPublisher(cfg, interval_seconds=1)
            publisher.mark_health_sample(11, sampled_at="2026-01-01T00:00:00+00:00")
            first = publisher.publish_once()
            publisher.start()
            time.sleep(1.15)
            publisher.stop()
            state = read_state(cfg)

        self.assertEqual(state["health_sequence"], 11)
        self.assertEqual(state["last_health_sample"], "2026-01-01T00:00:00+00:00")
        self.assertGreater(state["monotonic_uptime"], first["monotonic_uptime"])

    def test_heartbeat_age_uses_monotonic_uptime(self):
        state = {"monotonic_uptime": 100.0, "time": "1970-01-01T00:00:00+00:00"}
        self.assertEqual(heartbeat_age_seconds(state, current_uptime=112.5), 12.5)
        self.assertEqual(heartbeat_age_seconds(state, current_uptime=99.0), 0.0)

    def test_partial_heartbeat_state_is_ignored(self):
        with self.subTest("malformed state"):
            with patch("va_watchdog.heartbeat.heartbeat_paths", return_value=(Path("C:/does-not-exist/heartbeat-state.json"), Path("C:/does-not-exist/heartbeat.jsonl"))):
                self.assertEqual(read_state({"events_path": "/tmp/events.jsonl"}), {})

    def test_startup_grace_feeds_before_heartbeat_is_fresh(self):
        worker = FeedWorker({
            "events_path": "/tmp/events.jsonl",
            "hardware_watchdog": {"timeout_seconds": 30, "stale_heartbeat_seconds": 15},
        })
        self.assertTrue(worker.heartbeat_allows_feed({}, {"active": True, "boot_id": "boot"}))

    def test_stale_heartbeat_stops_feeding(self):
        worker = FeedWorker({
            "events_path": "/tmp/events.jsonl",
            "hardware_watchdog": {"timeout_seconds": 30, "stale_heartbeat_seconds": 15},
        })
        heartbeat = {"monotonic_uptime": 100.0, "boot_id": "boot", "feed_allowed": True}
        grace = {"active": False, "boot_id": "boot"}
        self.assertFalse(worker.heartbeat_allows_feed(heartbeat, grace, current_uptime=116.0))

    def test_trip_test_overrides_startup_grace(self):
        worker = FeedWorker({
            "events_path": "/tmp/events.jsonl",
            "hardware_watchdog": {"timeout_seconds": 30, "stale_heartbeat_seconds": 15},
        })
        self.assertFalse(worker.heartbeat_allows_feed({}, {"active": True, "boot_id": "boot"}, trip_active=True))

    def test_reboot_classification_separates_watchdog_and_storage_fault(self):
        change = {"changed": True, "previous_boot_id": "old", "current_boot_id": "new"}
        heartbeats = [{"boot_id": "old", "monotonic_uptime": 100, "time": "2026-01-01T00:00:00+00:00"}]
        evidence = classify(change, heartbeats, {}, "kernel: I/O error on dev sdb\nwatchdog: reset", "", "")
        self.assertEqual(evidence["reset_mechanism"], "Watchdog reset")
        self.assertEqual(evidence["probable_preceding_fault"], "storage I/O")
        self.assertIn(evidence["confidence"], {"Medium", "High"})

    def test_nmi_watchdog_enabled_is_not_a_hard_lockup_or_watchdog_reset(self):
        change = {
            "changed": True,
            "previous_boot_id": "old",
            "current_boot_id": "new",
            "detected_at": "2026-07-23T19:28:48+00:00",
        }
        heartbeats = [{"boot_id": "old", "time": "2026-07-23T19:15:16+00:00"}]
        kernel = "Jul 22 14:00:35 kernel: NMI watchdog: Enabled. Permanently consumes one hw-PMU counter."

        evidence = classify(change, heartbeats, {}, kernel, "", "")

        self.assertEqual(evidence["reset_mechanism"], "Unknown")
        self.assertEqual(evidence["probable_preceding_fault"], "none identified")
        self.assertEqual(evidence["kernel_findings"], [])

    def test_old_shutdown_record_does_not_make_latest_crash_clean(self):
        change = {"changed": True, "previous_boot_id": "old", "current_boot_id": "new"}
        last_x = "\n".join(
            [
                "reboot   system boot  kernel Thu Jul 23 20:28 still running",
                "runlevel (to lvl 5)   kernel Wed Jul 22 14:01 - 20:29",
                "vsuser   :0           :0     Wed Jul 22 14:00 - crash",
                "reboot   system boot  kernel Wed Jul 22 14:00 - 20:29",
                "shutdown system down  kernel Wed Jul 22 13:59 - 14:00",
            ]
        )

        evidence = classify(change, [], {}, "", last_x, "")

        self.assertEqual(evidence["reset_mechanism"], "Unknown")
        self.assertTrue(evidence["unclean_shutdown_detected"])

    def test_previous_boot_forensics_are_archived_before_rolling_files_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            cfg = {
                "events_path": str(data_dir / "events.jsonl"),
                "status_path": str(data_dir / "status.json"),
                "history_path": str(data_dir / "history.jsonl"),
                "heartbeat_path": str(data_dir / "heartbeat.jsonl"),
                "hardware_watchdog_feed_state_path": str(data_dir / "hardware-watchdog-feed.json"),
                "blackbox": {"path": str(data_dir / "blackbox.jsonl")},
                "incident_archive": {
                    "path": str(data_dir / "incidents"),
                    "max_incidents": 3,
                    "max_total_mb": 5,
                },
            }
            (data_dir / "status.json").write_text(json.dumps({"time": "old-status"}), encoding="utf-8")
            (data_dir / "heartbeat.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"boot_id": "old", "time": "old-heartbeat"}),
                        json.dumps({"boot_id": "other", "time": "other-heartbeat"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (data_dir / "blackbox.jsonl").write_text(
                json.dumps({"boot_id": "old", "time": "old-blackbox"}) + "\n",
                encoding="utf-8",
            )
            (data_dir / "history.jsonl").write_text(
                json.dumps({"boot_id": "old", "time": "old-history"}) + "\n",
                encoding="utf-8",
            )
            (data_dir / "events.jsonl").write_text(json.dumps({"time": "old-event"}) + "\n", encoding="utf-8")
            change = {
                "changed": True,
                "previous_boot_id": "old",
                "current_boot_id": "new",
                "detected_at": "2026-07-23T19:28:48+00:00",
            }

            result = archive_previous_boot(cfg, change, {"classification": "Unknown"}, "kernel text", "last x")
            archive_dir = Path(result["path"])
            with gzip.open(archive_dir / "heartbeat.jsonl.gz", "rt", encoding="utf-8") as handle:
                heartbeat_rows = [json.loads(line) for line in handle]

            self.assertTrue(result["created"])
            self.assertEqual(len(list_archives(cfg)), 1)
            self.assertEqual(heartbeat_rows, [{"boot_id": "old", "time": "old-heartbeat"}])
            self.assertTrue((archive_dir / "blackbox.jsonl.gz").is_file())
            self.assertTrue((archive_dir / "last-status.json").is_file())

    def test_main_service_restart_does_not_change_feeder_unit(self):
        feeder_unit = Path(__file__).parents[1] / "systemd" / "va-watchdog-feed.service"
        main_unit = Path(__file__).parents[1] / "systemd" / "va-watchdog.service"
        self.assertIn("Restart=on-failure", feeder_unit.read_text(encoding="utf-8"))
        self.assertNotIn("Requires=va-watchdog-feed.service", main_unit.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
