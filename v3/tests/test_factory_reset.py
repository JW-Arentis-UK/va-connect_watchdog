import json
import tempfile
import unittest
from pathlib import Path

from va_watchdog.factory_reset import reset_watchdog_data


class FactoryResetTest(unittest.TestCase):
    def test_site_data_is_cleared_and_protection_settings_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            etc, state, anpr = root / 'etc', root / 'state', root / 'anpr'
            etc.mkdir(); state.mkdir(); anpr.mkdir()
            config = etc / 'config.json'
            config.write_text(json.dumps({
                'identity': {'site_name': 'Old site', 'asset_id': 'Old asset'},
                'hardware_watchdog': {'enabled': True, 'timeout_seconds': 30},
                'storage': {'recordings_path': '/recordings'},
                'people_counting': {'address': 'camera', 'password': 'secret'},
                'mobile_router': {'address': 'router', 'snmp_community': 'secret'},
                'web_links': [{'url': 'http://router'}],
                'network': {'local_targets': ['camera'], 'remote_access_services': ['teamviewerd']},
            }))
            (etc / 'config.json.old.bak').write_text('old site')
            (etc / 'anpr.json').write_text('camera credentials')
            (anpr / 'reads.sqlite3').write_text('plate reads')
            (state / 'events.jsonl').write_text('old event')
            (state / 'hardware-watchdog-control.json').write_text('protection')
            (state / 'blackbox-buffer').mkdir()
            (state / 'blackbox-buffer' / 'old.gz').write_text('evidence')
            reset_watchdog_data(config, state, etc / 'anpr.json', anpr / 'reads.sqlite3')
            updated = json.loads(config.read_text())
            self.assertEqual(updated['identity']['site_name'], '')
            self.assertEqual(updated['people_counting']['address'], '')
            self.assertEqual(updated['mobile_router']['address'], '')
            self.assertEqual(updated['web_links'], [])
            self.assertEqual(updated['network']['local_targets'], [])
            self.assertEqual(updated['network']['remote_access_services'], ['teamviewerd'])
            self.assertTrue(updated['hardware_watchdog']['enabled'])
            self.assertEqual(updated['storage']['recordings_path'], '/recordings')
            self.assertFalse((etc / 'config.json.old.bak').exists())
            self.assertFalse((etc / 'anpr.json').exists())
            self.assertFalse((anpr / 'reads.sqlite3').exists())
            self.assertFalse((state / 'events.jsonl').exists())
            self.assertEqual((state / 'hardware-watchdog-control.json').read_text(), 'protection')
            self.assertEqual(list((state / 'blackbox-buffer').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
