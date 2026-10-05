"""Small read-only operator server; no commissioning or recovery actions."""
import io
import json
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import zipfile

from .lite import page, read_object, snapshot
from .log_tail import tail_lines


def evidence_zip(cfg, max_bytes=32 * 1024 * 1024):
    base = Path(cfg['events_path']).parent
    output = io.BytesIO()
    manifest = {'included': [], 'omitted': [], 'note': 'Saved evidence and system syslog; configuration and credentials excluded.'}
    names = ['status.json', 'last-reboot-reason.json', 'last-reboot-evidence.json',
             'heartbeat-state.json', 'hardware-watchdog-feed.json', 'blackbox-state.json',
             'recovery/state.json', 'reboot-evidence.jsonl', 'hardware-watchdog-lifecycle.jsonl']
    paths = [base / name for name in names]
    incidents = base / 'incidents'
    if incidents.is_dir():
        folders = sorted((p for p in incidents.iterdir() if p.is_dir() and not p.is_symlink()),
                         key=lambda p: p.stat().st_mtime, reverse=True)
        if folders:
            paths.extend(sorted(folders[0].rglob('*')))
    segments = base / 'blackbox-buffer'
    if segments.is_dir():
        recorder = read_object(base / 'blackbox-state.json')
        prefix = str(recorder.get('boot_id') or '').replace('-', '')[:12]
        if prefix:
            count = max(1, min(100, int(recorder.get('retention_seconds') or 900) // 10 + 5))
            current = (p for p in segments.glob(f'{prefix}-*.jsonl.gz') if not p.is_symlink())
            paths.extend(sorted(current, key=lambda p: p.stat().st_mtime, reverse=True)[:count])
    total = 0
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            if not path.is_file() or path.is_symlink() or base.resolve() not in path.resolve().parents:
                continue
            name = path.relative_to(base).as_posix()
            try:
                size = path.stat().st_size
                if size > max_bytes - total:
                    manifest['omitted'].append(name)
                    continue
                with path.open('rb') as source:
                    payload = source.read(max_bytes - total + 1)
            except OSError:
                manifest['omitted'].append(name)
                continue
            if len(payload) > max_bytes - total:
                manifest['omitted'].append(name)
                continue
            archive.writestr(name, payload)
            total += len(payload)
            manifest['included'].append(name)
        for name, path in [('recent-events.jsonl', cfg['events_path']), ('recent-history.jsonl', cfg.get('history_path') or base / 'history.jsonl')]:
            payload = ('\n'.join(tail_lines(path, 500, max_bytes=512 * 1024)) + '\n').encode()
            if len(payload) <= max_bytes - total:
                archive.writestr(name, payload)
                total += len(payload)
                manifest['included'].append(name)
            else:
                manifest['omitted'].append(name)
        syslog_dir = Path(cfg.get('evidence_syslog_dir', '/var/log'))
        syslog_budget = min(20 * 1024 * 1024, max_bytes - total)
        for filename in ('syslog', 'syslog.1', 'syslog.2.gz', 'syslog.3.gz', 'syslog.4.gz'):
            path = syslog_dir / filename
            if not path.is_file() or path.is_symlink():
                continue
            name = f'system-logs/{filename}'
            try:
                size = path.stat().st_size
                allowance = min(4 * 1024 * 1024, syslog_budget, max_bytes - total)
                if allowance <= 0:
                    manifest['omitted'].append(name)
                    continue
                with path.open('rb') as source:
                    if size > allowance and not filename.endswith('.gz'):
                        source.seek(size - allowance)
                        source.readline()  # Start the tail at a complete log line.
                        payload = source.read(allowance)
                        name += '.tail'
                    elif size <= allowance:
                        payload = source.read(allowance + 1)
                    else:
                        manifest['omitted'].append(name)
                        continue
            except OSError:
                manifest['omitted'].append(name)
                continue
            archive.writestr(name, payload)
            total += len(payload)
            syslog_budget -= len(payload)
            manifest['included'].append(name)
        archive.writestr('manifest.json', json.dumps(manifest, indent=2))
    return output.getvalue()


def start_web(cfg):
    web = cfg.get('web', {})
    if not web.get('enabled', True):
        return None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, payload, content_type='application/json', status=200, download=False):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            if download:
                self.send_header('Content-Disposition', 'attachment; filename="watchdog-evidence.zip"')
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path in ('/', '/lite'):
                return self.send(page(), 'text/html; charset=utf-8')
            if path == '/api/healthz':
                result = {'ok': True, 'mode': 'lightweight'}
            elif path == '/api/lite':
                result = snapshot(cfg)
            elif path == '/api/status':
                result = read_object(cfg['status_path'])
            elif path == '/api/evidence.zip':
                return self.send(evidence_zip(cfg), 'application/zip', download=True)
            elif path in ('/evidence', '/events', '/watchdog', '/setup'):
                self.send_response(302)
                self.send_header('Location', '/#diagnostics')
                self.send_header('Content-Length', '0')
                return self.end_headers()
            else:
                return self.send(b'{"error":"Not found"}', status=404)
            self.send(json.dumps(result).encode())

        def do_POST(self):
            self.send(b'{"error":"This dashboard is read-only"}', status=405)

    server = ThreadingHTTPServer((web.get('host', '0.0.0.0'), int(web.get('port', 9110))), Handler)
    server.daemon_threads = True
    server.serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server.serve_thread.start()
    return server
