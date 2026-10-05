import json
from pathlib import Path
import tempfile
import unittest

from va_watchdog.lite import event_tail, snapshot


class LiteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cfg = {"events_path": str(self.root / "events.jsonl"), "status_path": str(self.root / "status.json"), "identity": {"site_name": "Test site"}, "legacy_watchdog_state_path": str(self.root / "legacy.json"), "legacy_watchdog_config_path": str(self.root / "legacy-config.json"), "legacy_watchdog_events_path": str(self.root / "legacy-events.jsonl")}
        names = ['esg.service', 'network_module', 'mobile_router', 'recording_storage', 'temperature', 'ram', 'cpu_load', 'root_disk', 'write_test']
        self.status = {"time": "2026-10-04T00:00:00+00:00", "checks": [{"name": n, "state": "healthy", "message": "OK"} for n in names], "recording_storage": {"free_mb": 5120, "message": "Actual CCTV disk"}}
        self.now = 1791072005
        self.write('status.json', self.status)
        self.write('hardware-watchdog-feed.json', {"last_feed_unix": self.now - 2, "process_status": "feeding"})

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding='utf-8')

    def test_live_summary_uses_actual_recording_storage(self):
        result = snapshot(self.cfg, self.now)
        self.assertEqual(result['state'], 'healthy')
        self.assertIn('Actual CCTV disk', result['cards'][2]['detail'])
        self.assertIn('5.0 GiB', result['cards'][2]['detail'])

    def test_stale_and_missing_data_never_appear_healthy(self):
        result = snapshot(self.cfg, self.now + 120)
        self.assertTrue(result['stale'])
        self.assertEqual(result['state'], 'unknown')
        (self.root / 'status.json').unlink()
        self.assertTrue(snapshot(self.cfg, self.now)['stale'])

    def test_missing_recording_check_and_old_feed_need_attention(self):
        self.status['checks'] = [c for c in self.status['checks'] if c['name'] != 'recording_storage']
        self.write('status.json', self.status)
        self.assertEqual(snapshot(self.cfg, self.now)['state'], 'warning')
        self.write('hardware-watchdog-feed.json', {"last_feed_unix": self.now - 100, "process_status": "feeding"})
        self.assertEqual(snapshot(self.cfg, self.now)['cards'][-1]['state'], 'unknown')

    def test_bounded_event_tail_ignores_malformed_data_and_secrets(self):
        path = self.root / 'events.jsonl'
        path.write_text(('x' * 200000) + '\nnull\nbad\n' + json.dumps({"time": "now", "message": "Recovered", "data": {"password": "SECRET"}}))
        result = event_tail(path)
        self.assertEqual(result[0]['message'], 'Recovered')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_preserved_reboot_reason_is_used_without_mutating_files(self):
        self.write('last-reboot-evidence.json', {"previous_reboot_reason": {"message": "Watchdog reboot — no network access", "password": "SECRET"}, "confidence": "High"})
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = snapshot(self.cfg, self.now)
        self.assertIn('no network access', result['latest_reboot']['message'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_repetitive_cell_changes_are_collapsed_without_losing_faults(self):
        rows = [{"message": "Network failed", "level": "warning", "source": "network"}] + [{"message": "Cell changed", "level": "info", "source": "router"}] * 12
        (self.root / 'events.jsonl').write_text('\n'.join(json.dumps(r) for r in rows))
        result = event_tail(self.root / 'events.jsonl')
        self.assertEqual(result[0]['count'], 12)
        self.assertEqual(result[1]['message'], 'Network failed')

    def test_legacy_recovery_and_v3_recovery_are_distinct(self):
        self.write('legacy.json', {"last_check_at": self.status['time']})
        self.write('legacy-config.json', {"reboot_enabled": True, "password": "SECRET"})
        result = snapshot(self.cfg, self.now)
        self.assertIn('can request reboots', result['recovery']['legacy'])
        self.assertIn('disabled', result['recovery']['v3'])
        self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
