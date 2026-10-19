import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from va_watchdog.config import DEFAULT_CONFIG, deep_merge
from va_watchdog.build import build_number
from va_watchdog.hardware import check_hardware
from va_watchdog.lite import page, snapshot
from va_watchdog.storage import check_storage


ROOT = Path(__file__).parents[1]


class PiProfileTests(unittest.TestCase):
    def test_release_build_number(self):
        self.assertEqual(build_number(), "20261019.2")

    def config(self):
        base = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
        profile = json.loads((ROOT / "config.pi.json").read_text(encoding="utf-8"))
        return deep_merge(deep_merge(DEFAULT_CONFIG, base), profile)

    def test_pi_profile_replaces_gateway_specific_checks(self):
        cfg = self.config()
        self.assertEqual(cfg["platform"]["kind"], "raspberry_pi")
        self.assertEqual({entry["name"] for entry in cfg["services"]},
                         {"teamviewerd.service", "lightdm.service", "ssh.service"})
        self.assertFalse(cfg["recording_storage"]["enabled"])
        self.assertFalse(cfg["hardware_watchdog"]["enabled"])
        self.assertFalse(cfg["recovery"]["allow_reboot"])
        self.assertTrue(cfg["display_monitor"]["enabled"])

    def test_disabled_gateway_hardware_and_recording_checks_do_not_alarm(self):
        cfg = self.config()
        hardware = {item.name: item for item in check_hardware(cfg)}
        self.assertEqual(hardware["hardware_watchdog_present"].state, "disabled")
        with tempfile.TemporaryDirectory() as directory:
            cfg["storage"]["root_path"] = directory
            cfg["storage"]["write_test_path"] = directory
            with patch("va_watchdog.storage.recording_storage_status", side_effect=AssertionError("unexpected recording probe")):
                storage = {item.name: item for item in check_storage(cfg)}
        self.assertNotIn("recording_storage", storage)
        self.assertNotIn("recordings_disk", storage)
        self.assertIn("root_disk", storage)

    def test_lite_homepage_uses_pi_cards_without_recording_scan(self):
        cfg = self.config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg["status_path"] = str(root / "status.json")
            cfg["events_path"] = str(root / "events.jsonl")
            cfg["identity"]["site_name"] = "Pi AIO"
            (root / "status.json").write_text(json.dumps({
                "time": "2026-10-19T12:00:00+00:00",
                "checks": [
                    {"name": name, "state": "healthy", "message": "OK"}
                    for name in ("teamviewerd.service", "lightdm.service", "ssh.service",
                                 "display_session", "network_module", "root_disk", "write_test",
                                 "temperature", "ram", "cpu_load")
                ],
            }), encoding="utf-8")
            with patch("va_watchdog.lite.recording_activity", side_effect=AssertionError("unexpected recording scan")):
                result = snapshot(cfg, now=1792411205)
        self.assertEqual([card["title"] for card in result["cards"]],
                         ["Pi services", "Network", "Storage", "System"])
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(all(card["href"] == "/#diagnostics" for card in result["cards"]))

    def test_pi_page_only_links_to_available_lite_routes(self):
        html = page(self.config()).decode("utf-8")
        self.assertIn('href="/api/evidence.zip"', html)
        self.assertIn('href="/update-confirm"', html)
        self.assertIn('href="/pi-storage"', html)
        self.assertNotIn('href="/analytics"', html)
        self.assertNotIn('href="/maintenance"', html)


if __name__ == "__main__":
    unittest.main()
