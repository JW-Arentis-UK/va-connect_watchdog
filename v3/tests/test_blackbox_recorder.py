import gzip
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from va_watchdog.blackbox import (
    BlackBoxRecorder,
    blackbox_cfg,
    cpu_utilization,
    disk_delta,
    parse_diskstats,
    parse_loadavg,
    parse_meminfo,
    parse_pressure,
    parse_proc_stat,
    read_blackbox,
    write_boot_archive,
)
import va_watchdog.blackbox as blackbox_module
from va_watchdog.retention import purge_data


class FakeSampler:
    def __init__(self, boot_id="boot-1234"):
        self.current_boot_id = boot_id
        self.closed = False

    def sample(self, sequence, scheduled_monotonic=None):
        return {
            "v": 2,
            "time": f"2026-08-07T10:00:{sequence:02d}+00:00",
            "monotonic_uptime": float(sequence),
            "boot_id": self.current_boot_id,
            "sequence": sequence,
            "cpu": {"overall_percent": sequence},
        }

    def close(self):
        self.closed = True


class BlackBoxParserTests(unittest.TestCase):
    def test_steady_state_recorder_has_no_subprocess_collectors(self):
        source = inspect.getsource(blackbox_module)

        self.assertNotIn("import subprocess", source)
        self.assertNotIn("journalctl", source)
        self.assertNotIn("top -", source)
        self.assertNotIn("mpstat", source)
        self.assertNotIn("iostat", source)
        self.assertNotIn("smartctl", source)

    def test_cpu_and_task_counts_use_counter_deltas(self):
        before, _, _ = parse_proc_stat(
            "cpu 100 0 50 850 0 0 0 0\n"
            "cpu0 50 0 25 425 0 0 0 0\n"
            "procs_running 2\nprocs_blocked 1\n"
        )
        after, running, blocked = parse_proc_stat(
            "cpu 140 0 70 890 0 0 0 0\n"
            "cpu0 70 0 35 445 0 0 0 0\n"
            "procs_running 4\nprocs_blocked 2\n"
        )

        values = cpu_utilization(before, after)

        self.assertEqual(values["cpu"], 60.0)
        self.assertEqual(values["cpu0"], 60.0)
        self.assertEqual(running, 4)
        self.assertEqual(blocked, 2)

    def test_load_memory_and_pressure_parsers(self):
        load = parse_loadavg("1.25 0.75 0.50 3/210 1234\n")
        memory = parse_meminfo("MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 1000 kB\n")
        pressure = parse_pressure("some avg10=1.25 avg60=0.50 avg300=0.10 total=12345\n")

        self.assertEqual(load["runnable_tasks"], 3)
        self.assertEqual(load["total_tasks"], 210)
        self.assertEqual(memory["MemAvailable"], 6000000)
        self.assertEqual(pressure["some"]["avg10"], 1.25)
        self.assertEqual(pressure["some"]["total"], 12345)

    def test_disk_delta_reports_throughput_queue_and_busy_time(self):
        rows = parse_diskstats("8 0 sda 100 0 200 0 50 0 100 0 3 400 600\n")
        previous = (10.0, rows["sda"])
        current = parse_diskstats("8 0 sda 120 0 300 0 60 0 180 0 4 500 800\n")

        result = disk_delta(previous, (12.0, current["sda"]))

        self.assertEqual(result["read_bps"], 25600)
        self.assertEqual(result["write_bps"], 20480)
        self.assertEqual(result["read_iops"], 10.0)
        self.assertEqual(result["busy_percent"], 5.0)
        self.assertEqual(result["average_queue_depth"], 0.1)
        self.assertEqual(result["in_flight"], 4)


class BlackBoxRetentionTests(unittest.TestCase):
    def test_default_ring_keeps_fifteen_minutes_at_two_seconds(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            recorder = BlackBoxRecorder(cfg, sampler=FakeSampler())

            for _ in range(500):
                recorder.sample_once()

            self.assertEqual(blackbox_cfg(cfg)["max_rows"], 450)
            self.assertEqual(len(recorder.snapshot()), 450)
            self.assertEqual(recorder.snapshot()[0]["sequence"], 51)

    def test_checkpoint_is_atomic_and_partial_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            recorder = BlackBoxRecorder(cfg, sampler=FakeSampler())
            for _ in range(5):
                recorder.sample_once()

            result = recorder.flush()
            segment_dir = Path(cfg["blackbox"]["segment_dir"])
            (segment_dir / "partial.jsonl.gz.tmp").write_bytes(b"incomplete")
            rows = read_blackbox(cfg, limit=100)
            state = json.loads(Path(cfg["blackbox"]["state_path"]).read_text(encoding="utf-8"))

            self.assertEqual(result["written"], 5)
            self.assertEqual(len(list(segment_dir.glob("*.jsonl.gz"))), 1)
            self.assertEqual([row["sequence"] for row in rows], [1, 2, 3, 4, 5])
            self.assertEqual(state["last_sequence"], 5)
            self.assertEqual(state["last_sample_utc"], "2026-08-07T10:00:05+00:00")

    def test_previous_boot_segments_export_to_incident_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            recorder = BlackBoxRecorder(cfg, sampler=FakeSampler("previous-boot"))
            for _ in range(3):
                recorder.sample_once()
            recorder.flush()
            destination = Path(temporary) / "incident" / "blackbox.jsonl.gz"

            result = write_boot_archive(cfg, destination, "previous-boot")
            with gzip.open(destination, "rt", encoding="utf-8") as handle:
                rows = [json.loads(line) for line in handle]

            self.assertEqual(result["rows"], 3)
            self.assertEqual(result["last_successful_sample_utc"], "2026-08-07T10:00:03+00:00")
            self.assertEqual([row["sequence"] for row in rows], [1, 2, 3])

    def test_same_boot_service_restart_continues_sequence_and_ring(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            first = BlackBoxRecorder(cfg, sampler=FakeSampler("same-boot"))
            for _ in range(3):
                first.sample_once()
            first.flush()

            restarted = BlackBoxRecorder(cfg, sampler=FakeSampler("same-boot"))
            sample = restarted.sample_once()
            restarted.flush()

            self.assertEqual(sample["sequence"], 4)
            self.assertEqual([row["sequence"] for row in restarted.snapshot()], [1, 2, 3, 4])
            self.assertEqual([row["sequence"] for row in read_blackbox(cfg, limit=10)], [1, 2, 3, 4])

    def test_new_boot_does_not_load_previous_boot_into_live_ring(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            previous = BlackBoxRecorder(cfg, sampler=FakeSampler("old-boot"))
            previous.sample_once()
            previous.flush()

            current = BlackBoxRecorder(cfg, sampler=FakeSampler("new-boot"))

            self.assertEqual(current.sequence, 0)
            self.assertEqual(current.snapshot(), [])

    def test_purge_all_removes_atomic_blackbox_segments(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self._cfg(temporary)
            recorder = BlackBoxRecorder(cfg, sampler=FakeSampler())
            recorder.sample_once()
            recorder.flush()

            result = purge_data(cfg, mode="all")

            self.assertFalse(list(Path(cfg["blackbox"]["segment_dir"]).glob("*.jsonl.gz")))
            self.assertTrue(any(item["path"].endswith(".jsonl.gz") for item in result["removed"]))

    @staticmethod
    def _cfg(temporary):
        root = Path(temporary)
        return {
            "events_path": str(root / "events.jsonl"),
            "heartbeat_state_path": str(root / "heartbeat-state.json"),
            "blackbox": {
                "path": str(root / "blackbox.jsonl"),
                "segment_dir": str(root / "blackbox-buffer"),
                "state_path": str(root / "blackbox-state.json"),
                "interval_seconds": 2,
                "retention_seconds": 900,
                "checkpoint_seconds": 10,
            },
        }


if __name__ == "__main__":
    unittest.main()
