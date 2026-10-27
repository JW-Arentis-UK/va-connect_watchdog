import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from va_watchdog.system_logs import add_syslogs
from va_watchdog.web import start_web
from urllib.request import urlopen


class SystemLogsTests(unittest.TestCase):
    def test_budget_and_missing_rotations(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            (logs / "syslog").write_bytes(b"partial\n" + b"latest\n" * 20)
            (logs / "syslog.1").write_bytes(b"previous\n")
            (logs / "syslog.2.gz").write_bytes(b"x" * 100)
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                manifest = add_syslogs(archive, {"evidence_syslog_dir": tmp}, budget=40)
            with zipfile.ZipFile(output) as archive:
                self.assertLessEqual(sum(item.file_size for item in archive.infolist()), 40)
                self.assertTrue(archive.read("system-logs/syslog.tail").startswith(b"latest\n"))
            self.assertIn("system-logs/syslog.2.gz", manifest["omitted"])
            self.assertIn("system-logs/syslog.4.gz", manifest["missing"])

    def test_full_dashboard_preserves_compact_evidence_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "syslog").write_bytes(b"system evidence\n")
            cfg = {"web": {"host": "127.0.0.1", "port": 0, "lightweight": False},
                   "events_path": str(base / "events.jsonl"),
                   "status_path": str(base / "status.json"), "evidence_syslog_dir": tmp}
            server = start_web(cfg)
            try:
                with urlopen(f"http://127.0.0.1:{server.server_port}/api/evidence.zip") as response:
                    with zipfile.ZipFile(io.BytesIO(response.read())) as archive:
                        self.assertEqual(archive.read("system-logs/syslog"), b"system evidence\n")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
