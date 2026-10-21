import io
import json
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch

from va_watchdog import health, history
from va_watchdog.common import CheckResult
from va_watchdog.events import EventLog, read_events
from va_watchdog.lite_server import evidence_zip, start_web
from va_watchdog.web_smoke import check_setup
from va_watchdog.lite import snapshot
from va_watchdog.log_tail import tail_lines
from va_watchdog.retention import enforce_retention, purge_data


class LightweightTests(unittest.TestCase):
    def test_pi_storage_shows_oldest_data_recording(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            recordings = base / 'recordings'
            bucket = recordings / '1792368000'
            bucket.mkdir(parents=True)
            (bucket / '1792428312.data').touch()
            (bucket / '1792428372.data').touch()
            (bucket / '1792000000.db').touch()
            cfg = {'platform': {'kind': 'raspberry_pi'}, 'storage': {'recordings_path': str(recordings)},
                   'web': {'host': '127.0.0.1', 'port': 0},
                   'events_path': str(base / 'events.jsonl'), 'status_path': str(base / 'status.json')}
            (base / 'status.json').write_text(json.dumps({'time': datetime.now(timezone.utc).isoformat(),
                'checks': [{'name': 'root_disk', 'state': 'healthy', 'message': 'OK'}]}))
            storage = {'available': False, 'reason': 'No space beyond root', 'root': '/dev/nvme0n1p2',
                       'disk': '/dev/nvme0n1', 'root_gib': 931.01, 'disk_gib': 931.51, 'free_gib': 0}
            with patch('va_watchdog.lite_server.inspect_pi_storage', return_value=storage):
                server = start_web(cfg)
                try:
                    url = f'http://127.0.0.1:{server.server_port}'
                    with urlopen(url + '/pi-storage') as response:
                        page = response.read().decode()
                    self.assertIn('Oldest recording', page)
                    self.assertIn('17:45:12 19/10/2026', page)
                    self.assertNotIn('1792000000', page)
                    storage_card = next(item for item in snapshot(cfg)['cards'] if item['title'] == 'Storage')
                    self.assertIn('Oldest recording:', storage_card['detail'])
                    self.assertEqual(storage_card['href'], '/pi-storage')
                finally:
                    server.shutdown()
                    server.server_close()

    def test_tail_is_bounded_and_handles_partial_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'log'
            path.write_bytes(b'x' * 100000 + b'\nfirst\nsecond\n')
            self.assertEqual(tail_lines(path, 2, 128), ['first', 'second'])
            self.assertEqual(tail_lines(path, 10, 128), ['first', 'second'])

    def test_compaction_keeps_faults_between_older_healthy_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'history.jsonl'
            stamp = int((time.time() - 3 * 86400) // 300) * 300
            rows = [{'time': datetime.fromtimestamp(stamp + n, timezone.utc).isoformat(),
                     'state': state, 'service_metrics': [{'large': 'payload'}]}
                    for n, state in [(0, 'healthy'), (30, 'healthy'), (60, 'critical'), (90, 'healthy'), (120, 'healthy')]]
            path.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            cfg = {'events_path': str(path.with_name('events.jsonl')), 'retention': {'compact_history': True}}
            history.trim_history(cfg)
            result = history.read_history(cfg)
            self.assertEqual([r['state'] for r in result], ['healthy', 'critical', 'healthy'])
            self.assertTrue(all('service_metrics' not in r for r in result))

    def test_pressure_and_purge_cannot_delete_control_or_crash_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            protected = base / 'last-reboot-reason.json'
            protected.write_bytes(b'x' * 1100000)
            events = base / 'events.jsonl'
            events.write_text('{"time":"2020-01-01T00:00:00Z"}\n')
            cfg = {'events_path': str(events), 'retention': {'max_total_mb': 1}}
            result = enforce_retention(cfg)
            self.assertTrue(result['over_budget'])
            purge_data(cfg, mode='all')
            self.assertEqual(protected.stat().st_size, 1100000)

    def test_collector_failure_does_not_reuse_old_healthy_result(self):
        with patch.dict(health._COLLECTOR_CACHE, {'example': (0, [CheckResult('old', 'healthy', 'old')])}, clear=True):
            def fail():
                raise OSError('unreachable')
            result = health._cached_checks('example', 1, fail)
            self.assertEqual(result[0].state, 'unknown')

    def test_event_rotation_and_fault_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'events.jsonl'
            path.write_bytes(b'x' * (4 * 1024 * 1024))
            log = EventLog(path, compact=True)
            log.add('warning', 'mobile_router', 'Lost WAN', {'evidence': 'keep'})
            self.assertTrue(path.with_suffix('.jsonl.1').exists())
            self.assertEqual(read_events(path)[0]['data'], {'evidence': 'keep'})

    def test_server_default_page_health_export_and_retired_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cfg = {'web': {'host': '127.0.0.1', 'port': 0}, 'events_path': str(base / 'events.jsonl'), 'status_path': str(base / 'status.json')}
            (base / 'status.json').write_text('{"state":"healthy"}')
            (base / 'config.json').write_text('{"password":"secret"}')
            (base / 'blackbox-state.json').write_text('{"boot_id":"12345678-abcd-0000-0000-000000000000","retention_seconds":900}')
            (base / 'blackbox-buffer').mkdir()
            (base / 'blackbox-buffer' / '12345678abcd-1.jsonl.gz').write_bytes(b'current')
            (base / 'blackbox-buffer' / 'ffffeeeeaaaa-1.jsonl.gz').write_bytes(b'old')
            server = start_web(cfg)
            url = f'http://127.0.0.1:{server.server_port}'
            try:
                cfg['web']['lightweight'] = True
                cfg['web']['port'] = server.server_port
                check_setup(cfg, attempts=1)
                with urlopen(url) as response:
                    page = response.read().decode()
                self.assertIn('id="diagnostics"', page)
                self.assertNotIn('Full dashboard', page)
                with urlopen(url + '/api/healthz') as response:
                    self.assertTrue(json.load(response)['ok'])
                with self.assertRaises(HTTPError) as error:
                    urlopen(Request(url + '/api/reboot', data=b'{}'))
                self.assertEqual(error.exception.code, 405)
                with urlopen(url + '/api/evidence.zip') as response:
                    bundle = zipfile.ZipFile(io.BytesIO(response.read()))
                self.assertIn('status.json', bundle.namelist())
                self.assertNotIn('config.json', bundle.namelist())
                self.assertIn('blackbox-buffer/12345678abcd-1.jsonl.gz', bundle.namelist())
                self.assertNotIn('blackbox-buffer/ffffeeeeaaaa-1.jsonl.gz', bundle.namelist())
                (base / 'reboot-evidence.jsonl').write_bytes(b'x' * 4096)
                limited = zipfile.ZipFile(io.BytesIO(evidence_zip(cfg, max_bytes=1024)))
                self.assertIn('reboot-evidence.jsonl', json.loads(limited.read('manifest.json'))['omitted'])
            finally:
                server.shutdown()
                server.server_close()

    def test_pi_navigation_reaches_storage_and_update_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cfg = {'platform': {'kind': 'raspberry_pi'}, 'web': {'host': '127.0.0.1', 'port': 0},
                   'events_path': str(base / 'events.jsonl'), 'status_path': str(base / 'status.json'),
                   'update': {'enabled': True, 'state_path': str(base / 'update-state.json')}}
            storage = {'available': True, 'reason': 'Space available', 'root': '/dev/nvme0n1p2',
                       'disk': '/dev/nvme0n1', 'root_gib': 29.23, 'disk_gib': 931.51, 'free_gib': 901.78}
            with (patch('va_watchdog.lite_server.inspect_pi_storage', return_value=storage),
                  patch('va_watchdog.lite_server.verify_account_password', return_value=True),
                  patch('va_watchdog.lite_server.expand_pi_storage', return_value={'ok': True, 'message': 'Reboot required'}) as expand,
                  patch('va_watchdog.lite_server.launch_update_job') as update):
                def queue_update(_cfg):
                    (base / 'update-state.json').write_text(json.dumps({
                        'state': 'queued', 'message': 'Update queued',
                        'updated_at': datetime.now(timezone.utc).isoformat(),
                    }))
                    return {'ok': True, 'message': 'Update queued'}
                update.side_effect = queue_update
                server = start_web(cfg)
                url = f'http://127.0.0.1:{server.server_port}'
                try:
                    cfg['web']['lightweight'] = True
                    cfg['web']['port'] = server.server_port
                    check_setup(cfg, attempts=1)
                    with urlopen(url + '/') as response:
                        homepage = response.read().decode()
                    self.assertIn('href="/update-confirm"', homepage)
                    with urlopen(url + '/pi-storage') as response:
                        storage_page = response.read().decode()
                    self.assertIn('901.78 GiB', storage_page)
                    self.assertIn('Expand root partition', storage_page)
                    with urlopen(url + '/update-confirm') as response:
                        self.assertIn('Update watchdog now', response.read().decode())
                    request = Request(url + '/pi-storage-expand', data=b'root=%2Fdev%2Fnvme0n1p2&password=test', method='POST')
                    with urlopen(request) as response:
                        self.assertIn('Reboot required', response.read().decode())
                    expand.assert_called_once_with('/dev/nvme0n1p2')
                    request = Request(url + '/update-now', data=b'', method='POST')
                    with urlopen(request) as response:
                        progress = response.read().decode()
                    self.assertIn('Update running…', progress)
                    self.assertIn('window.location.replace("/")', progress)
                    self.assertIn('Reconnecting to the watchdog', progress)
                    self.assertNotIn('>Update watchdog now</button>', progress)
                    with urlopen(request) as response:
                        self.assertIn('An update is already running', response.read().decode())
                    update.assert_called_once_with(cfg)
                    (base / 'update-state.json').write_text(json.dumps({
                        'state': 'completed', 'message': 'update completed',
                        'updated_at': '2026-10-19T14:30:00+00:00',
                    }))
                    with urlopen(url + '/update-confirm?follow=1') as response:
                        self.assertEqual(response.url, url + '/')
                    with urlopen(url + '/api/version') as response:
                        version = json.load(response)
                    self.assertEqual(version['last_update_build'], version['build_number'])
                    self.assertEqual(version['last_update_at'], '2026-10-19T14:30:00+00:00')
                finally:
                    server.shutdown()
                    server.server_close()

    def test_pi_resize_reboot_requires_pending_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cfg = {'platform': {'kind': 'raspberry_pi'}, 'web': {'host': '127.0.0.1', 'port': 0},
                   'events_path': str(base / 'events.jsonl'), 'status_path': str(base / 'status.json')}
            storage = {'available': False, 'reason': 'Reboot to finish resizing.', 'root': '/dev/nvme0n1p2',
                       'disk': '/dev/nvme0n1', 'root_gib': 931.01, 'disk_gib': 931.51,
                       'free_gib': 0, 'reboot_pending': True}
            with (patch('va_watchdog.lite_server.inspect_pi_storage', return_value=storage),
                  patch('va_watchdog.lite_server.verify_account_password', return_value=True),
                  patch('va_watchdog.lite_server.request_gateway_reboot', return_value={'ok': True, 'message': 'Reboot scheduled'}) as reboot):
                server = start_web(cfg)
                url = f'http://127.0.0.1:{server.server_port}'
                try:
                    with urlopen(url + '/pi-storage') as response:
                        self.assertIn('Reboot Pi to finish resize', response.read().decode())
                    request = Request(url + '/pi-storage-reboot', data=b'password=test', method='POST')
                    with urlopen(request) as response:
                        self.assertIn('Reboot scheduled', response.read().decode())
                    reboot.assert_called_once()
                    storage['reboot_pending'] = False
                    with urlopen(request) as response:
                        self.assertIn('No pending filesystem resize', response.read().decode())
                    reboot.assert_called_once()
                finally:
                    server.shutdown()
                    server.server_close()

    def test_evidence_includes_syslog_rotations_and_marks_large_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            logs = base / 'logs'
            logs.mkdir()
            (logs / 'syslog').write_bytes(b'older\n' + b'latest\n' * 20)
            (logs / 'syslog.1').write_bytes(b'previous boot\n')
            (logs / 'syslog.2.gz').write_bytes(b'compressed rotation')
            try:
                (logs / 'syslog.3.gz').symlink_to(logs / 'syslog.2.gz')
            except OSError:
                pass  # Windows may not permit symlinks without developer mode.
            cfg = {'events_path': str(base / 'events.jsonl'), 'evidence_syslog_dir': str(logs)}
            bundle = zipfile.ZipFile(io.BytesIO(evidence_zip(cfg, max_bytes=80)))
            manifest = json.loads(bundle.read('manifest.json'))
            self.assertIn('system-logs/syslog.tail', manifest['included'])
            self.assertTrue(bundle.read('system-logs/syslog.tail').startswith(b'latest\n'))
            self.assertIn('system-logs/syslog.2.gz', manifest['omitted'])
            full = zipfile.ZipFile(io.BytesIO(evidence_zip(cfg, max_bytes=1024)))
            self.assertIn('system-logs/syslog.1', full.namelist())
            self.assertIn('system-logs/syslog.2.gz', full.namelist())
            self.assertNotIn('system-logs/syslog.3.gz', full.namelist())
