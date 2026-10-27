import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from va_watchdog.config import DEFAULT_CONFIG
from va_watchdog.privileged_actions import execute
from va_watchdog.ui_profile import maintenance_page, route_supported
from va_watchdog.web import start_web
from va_watchdog.web_security import ACTION_PATHS


class CleanupProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cfg = copy.deepcopy(DEFAULT_CONFIG)
        self.cfg['web'] = {'host': '127.0.0.1', 'port': 0}
        self.cfg['events_path'] = str(Path(temporary.name) / 'events.jsonl')
        self.cfg['status_path'] = str(Path(temporary.name) / 'status.json')

    def server(self, pi=False):
        self.cfg['platform'] = {'kind': 'raspberry_pi' if pi else 'gateway'}
        server = start_web(self.cfg)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def test_maintenance_keeps_requested_features_and_device_links(self):
        for pi in (False, True):
            self.cfg['platform'] = {'kind': 'raspberry_pi' if pi else 'gateway'}
            html = maintenance_page(self.cfg).decode()
            for route in ('/analytics', '/anpr', '/crossing-activity', '/teamviewer', '/links'):
                self.assertIn(f'href="{route}"', html)
            self.assertIn('href="/pi-storage"' if pi else 'href="/setup#storage"', html)
            self.assertNotIn('__STORAGE_LINK__', html)
            self.assertNotIn('Full engineering interface', html)

    def test_gateway_rejects_pi_storage_before_action_dispatch(self):
        base = self.server()
        for request in (base + '/pi-storage', Request(base + '/pi-storage-expand', data=b'')):
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=10)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()

    def test_pi_rejects_neousys_actions_and_report(self):
        base = self.server(pi=True)
        for request in (base + '/api/diagnostics/manufacturer-report.zip',
                        Request(base + '/watchdog-trip-now', data=b'')):
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=10)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()

    def test_root_helper_also_rejects_wrong_device_actions(self):
        self.cfg['platform'] = {'kind': 'raspberry_pi'}
        with patch('va_watchdog.privileged_actions.verify_operator', return_value=True):
            with self.assertRaisesRegex(ValueError, 'does not apply'):
                execute({'operation': 'action', 'path': '/neousys-watchdog-install-now'}, self.cfg)

    def test_pi_protection_is_native_and_old_watchdog_link_redirects(self):
        base = self.server(pi=True)
        with urlopen(base + '/watchdog', timeout=10) as response:
            self.assertEqual(response.url, base + '/hardware-protection')
            html = response.read().decode()
        self.assertIn('native hardware watchdog through systemd', html)
        self.assertIn('s.status_fresh', html)
        self.assertNotIn('/neousys-watchdog-', html)
        self.assertNotIn('/watchdog-trip-', html)

    def test_old_status_urls_redirect_to_one_homepage(self):
        base = self.server()
        for route in ('/advanced', '/legacy', '/overview'):
            with urlopen(base + route, timeout=10) as response:
                self.assertEqual(response.url, base + '/')
                self.assertIn(b'Latest recorded restart', response.read())

    def test_requested_feature_routes_are_not_filtered(self):
        paths = ('/anpr', '/api/anpr/export.csv', '/analytics', '/crossing-activity',
                 '/api/crossing-activity/report.pdf', '/hikvision-test-now',
                 '/hikvision-push-configure', '/hikvision-route-capture-start',
                 '/network-speed-test', '/links', '/web-link-add', '/teamviewer-password')
        for kind in ('gateway', 'raspberry_pi'):
            self.cfg['platform'] = {'kind': kind}
            for path in paths:
                self.assertTrue(route_supported(self.cfg, path), (kind, path))
        self.assertIn('/web-link-add', ACTION_PATHS)
        self.assertTrue(any('teamviewer' in path for path in ACTION_PATHS))
        self.assertTrue(any('speed-test' in path for path in ACTION_PATHS))

    def test_retained_feature_pages_are_served_on_both_profiles(self):
        for pi in (False, True):
            base = self.server(pi=pi)
            for route in ('/analytics', '/analytics/anpr-setup', '/analytics/crossing-setup',
                          '/anpr', '/crossing-activity', '/links', '/teamviewer'):
                with self.subTest(pi=pi, route=route), urlopen(base + route, timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b'<!doctype html>', response.read().lower())


if __name__ == '__main__':
    unittest.main()
