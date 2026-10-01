from __future__ import annotations

import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest.mock import Mock, patch

from va_watchdog import web_service
from va_watchdog.config import DEFAULT_CONFIG


class WebServiceTests(unittest.TestCase):
    def test_probe_reaches_the_real_local_health_endpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            cfg["web"] = {"enabled": True, "host": "127.0.0.1", "port": 0}
            cfg["status_path"] = str(Path(temporary) / "status.json")
            cfg["events_path"] = str(Path(temporary) / "events.jsonl")
            Path(cfg["status_path"]).write_text(json.dumps({"state": "healthy"}), encoding="utf-8")
            server = web_service.start_web(cfg)
            try:
                web_service.probe_web(f"http://127.0.0.1:{server.server_port}/api/healthz")
            finally:
                server.shutdown()
                server.server_close()

    def test_health_url_uses_loopback_for_wildcard_bind(self):
        cfg = {"web": {"host": "0.0.0.0", "port": 9110}}
        self.assertEqual(web_service.health_url(cfg), "http://127.0.0.1:9110/api/healthz")

    def test_previous_boot_blackbox_is_visible_and_separate_from_live_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            cfg["web"] = {"enabled": True, "host": "127.0.0.1", "port": 0}
            cfg["events_path"] = str(root / "events.jsonl")
            cfg["status_path"] = str(root / "status.json")
            cfg["blackbox"] = {
                "enabled": True,
                "segment_dir": str(root / "blackbox-buffer"),
                "state_path": str(root / "blackbox-state.json"),
            }
            cfg["incident_archive"] = {"enabled": True, "path": str(root / "incidents")}
            archive = root / "incidents" / "20260930T110812Z-old-boot"
            archive.mkdir(parents=True)
            manifest = {
                "previous_boot_id": "old-boot",
                "current_boot_id": "new-boot",
                "detected_at": "2026-09-30T11:08:12+00:00",
                "files": [{
                    "path": "blackbox.jsonl.gz",
                    "rows": 2,
                    "first_sample_utc": "2026-09-25T17:40:07+00:00",
                    "last_successful_sample_utc": "2026-09-25T17:40:09+00:00",
                }],
            }
            (archive / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            old_rows = [
                {"boot_id": "old-boot", "time": f"2026-09-25T17:40:0{second}+00:00", "sequence": second}
                for second in (7, 9)
            ]
            with gzip.open(archive / "blackbox.jsonl.gz", "wt", encoding="utf-8") as handle:
                for row in old_rows:
                    handle.write(json.dumps(row) + "\n")
            current_dir = root / "blackbox-buffer"
            current_dir.mkdir()
            (root / "blackbox-state.json").write_text(json.dumps({"boot_id": "new-boot"}), encoding="utf-8")
            with gzip.open(current_dir / "old-boot-0000000007-0000000009.jsonl.gz", "wt", encoding="utf-8") as handle:
                for row in old_rows:
                    handle.write(json.dumps(row) + "\n")
            with gzip.open(current_dir / "new-boot-0000000001-0000000001.jsonl.gz", "wt", encoding="utf-8") as handle:
                handle.write(json.dumps({"boot_id": "new-boot", "time": "2026-09-30T12:48:22+00:00", "sequence": 1}) + "\n")
            server = web_service.start_web(cfg)
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(base + "/api/blackbox", timeout=10) as response:
                    live = json.load(response)
                with urlopen(base + "/api/blackbox/archive?name=20260930T110812Z-old-boot", timeout=10) as response:
                    saved = json.load(response)
                with urlopen(base + "/evidence", timeout=30) as response:
                    page = response.read().decode("utf-8")
                with self.assertRaises(HTTPError) as unknown:
                    urlopen(base + "/api/blackbox/archive?name=../bad", timeout=10)
            finally:
                server.shutdown()
                server.server_close()
            self.assertEqual([row["boot_id"] for row in live["snapshots"]], ["new-boot"])
            self.assertEqual(saved["snapshots"], old_rows)
            self.assertEqual(saved["archive"]["previous_boot_id"], "old-boot")
            self.assertIn("Previous-boot black-box evidence", page)
            self.assertIn("2026-09-25", page)
            self.assertIn("Download all preserved samples", page)
            self.assertEqual(unknown.exception.code, 404)

    def test_probe_accepts_live_web_even_when_core_status_is_unhealthy(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read = Mock(return_value=b'{"ok": false, "state": "critical"}')
        opener = Mock()
        opener.open.return_value = response

        web_service.probe_web("http://127.0.0.1:9110/api/healthz", opener=opener)

        opener.open.assert_called_once_with("http://127.0.0.1:9110/api/healthz", timeout=3)

    def test_probe_rejects_response_without_web_health_contract(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read = Mock(return_value=b'{"state": "healthy"}')
        opener = Mock()
        opener.open.return_value = response

        with self.assertRaisesRegex(RuntimeError, "invalid response"):
            web_service.probe_web("http://127.0.0.1:9110/api/healthz", opener=opener)

    def test_three_failed_local_probes_exit_for_systemd_restart(self):
        server = Mock()
        server.serve_thread.is_alive.return_value = True
        cfg = {"web": {"enabled": True, "host": "0.0.0.0", "port": 9110}}
        with (
            patch.object(web_service, "load_config", return_value=cfg),
            patch.object(web_service, "start_web", return_value=server),
            patch.object(web_service, "probe_web", side_effect=OSError("connection refused")) as probe,
            patch.object(web_service, "notify") as notify,
            patch.object(web_service.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "three local probes"):
                web_service.main()
        self.assertEqual(probe.call_count, 3)
        notify.assert_not_called()
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()

    def test_ready_and_watchdog_are_sent_only_after_http_response(self):
        server = Mock()
        server.serve_thread.is_alive.return_value = True
        cfg = {"web": {"enabled": True, "host": "0.0.0.0", "port": 9110}}
        with (
            patch.object(web_service, "load_config", return_value=cfg),
            patch.object(web_service, "start_web", return_value=server),
            patch.object(web_service, "probe_web") as probe,
            patch.object(web_service, "notify") as notify,
            patch.object(web_service.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            with self.assertRaises(KeyboardInterrupt):
                web_service.main()
        probe.assert_called_once_with("http://127.0.0.1:9110/api/healthz")
        self.assertEqual(notify.call_count, 2)
        self.assertIn("READY=1", notify.call_args_list[0].args[0])
        self.assertIn("WATCHDOG=1", notify.call_args_list[1].args[0])
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()

    def test_web_is_supervised_independently_of_core_and_feeder(self):
        root = Path(__file__).parents[1]
        core = (root / "va_watchdog" / "watchdog.py").read_text(encoding="utf-8")
        unit = (root / "systemd" / "va-watchdog-web.service").read_text(encoding="utf-8")
        install = (root / "scripts" / "install.sh").read_text(encoding="utf-8")
        update = (root / "scripts" / "update.sh").read_text(encoding="utf-8")
        self.assertNotIn("start_web(cfg)", core)
        self.assertIn("-m va_watchdog.web_service", unit)
        self.assertIn("WatchdogSec=30", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertNotIn("Requires=va-watchdog-feed.service", unit)
        self.assertIn("systemctl restart va-watchdog-web.service", install)
        self.assertIn("systemctl restart va-watchdog-web", update)


if __name__ == "__main__":
    unittest.main()
