"""Small operator server with guarded update and Pi storage setup."""
import io
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import zipfile

from .lite import page, read_object, snapshot
from .build import build_number
from .log_tail import tail_lines
from .pi_storage import expand as expand_pi_storage, inspect as inspect_pi_storage, verify_account_password
from .update import _git_value, launch_update_job, load_update_status


def action_page(title, body, refresh=False):
    refresh_tag = '<meta http-equiv="refresh" content="15;url=/update-confirm">' if refresh else ''
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        + refresh_tag + f'<title>{escape(title)} · Watchdog</title><style>'
        ':root{color-scheme:light}body{margin:0;background:#f3f5ef;color:#182c32;font:15px/1.55 system-ui,sans-serif}'
        'main{max-width:780px;margin:auto;padding:28px 18px}header{display:flex;justify-content:space-between;align-items:center;gap:15px;border-bottom:1px solid #d9e2dd;padding-bottom:20px}'
        'nav{display:flex;gap:18px;flex-wrap:wrap}a{color:#166859}.brand{font-weight:750;letter-spacing:.08em;text-transform:uppercase}'
        '.card{background:white;border:1px solid #d9e2dd;border-radius:12px;padding:24px;margin-top:24px}'
        'h1{margin:0 0 16px;font-size:26px}.label{font-size:12px;color:#52696d;margin-top:18px}.value{font-size:18px;font-weight:700}'
        'input{font:inherit;padding:9px;border:1px solid #bfd0c6;border-radius:7px;max-width:100%}'
        'button,.button{display:inline-block;font:inherit;font-weight:650;border:1px solid #bfd0c6;border-radius:8px;padding:9px 14px;background:white;color:#166859;text-decoration:none;cursor:pointer}'
        '.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}.healthy{color:#166859}.critical{color:#a22c35}'
        'p{margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
        '</style></head><body><main><header><div class="brand">VA-Connect Watchdog</div>'
        '<nav><a href="/">Status</a><a href="/update-confirm">Update watchdog</a></nav></header>'
        f'<section class="card"><h1>{escape(title)}</h1>{body}</section></main></body></html>'
    ).encode('utf-8')


def pi_storage_page(result=None):
    status = inspect_pi_storage()
    notice = ''
    if result:
        notice = f'<p class="{"healthy" if result.get("ok") else "critical"}">{escape(str(result.get("message", "")))}</p>'
        if result.get('detail'):
            notice += f'<pre>{escape(str(result["detail"]))}</pre>'
    action = ''
    if status['available'] and result is None:
        action = (
            '<form method="post" action="/pi-storage-expand">'
            f'<p>To confirm, type the root partition <strong>{escape(status["root"])}</strong>:</p>'
            '<input name="root" required autocomplete="off">'
            '<p>Enter the Pi account password:</p><input name="password" type="password" required autocomplete="off">'
            '<div class="actions"><button type="submit">Expand root partition</button></div></form>'
        )
    body = (
        '<p>Use this after creating the reusable image and restoring it to its final SSD. '
        'Expanding before image capture can prevent the image fitting on a smaller drive.</p>'
        f'{notice}<div class="label">Drive</div><div class="value">{escape(status["disk"] or "Unknown")} · {status["disk_gib"]} GiB</div>'
        f'<div class="label">Root partition</div><div class="value">{escape(status["root"] or "Unknown")} · {status["root_gib"]} GiB</div>'
        f'<div class="label">Space beyond root</div><div class="value">Approximately {status["free_gib"]} GiB</div>'
        f'<p>{escape(status["reason"])}</p>'
        '<p>Expansion uses Raspberry Pi OS raspi-config. Reboot to finish the resize. It does not format the drive or choose a recording location.</p>'
        f'{action}<div class="actions"><a class="button" href="/">Back to Status</a></div>'
    )
    return action_page('Pi storage', body)


def update_page(cfg, result=None):
    update_cfg = cfg.get('update', {})
    state = load_update_status(cfg)
    branch = str(update_cfg.get('branch') or _git_value(['rev-parse', '--abbrev-ref', 'HEAD']) or 'current branch')
    remote = str(update_cfg.get('remote') or 'origin')
    notice = '' if result is None else f'<p class="{"healthy" if result.get("ok") else "critical"}">{escape(str(result.get("message", "")))}</p>'
    action = '<form method="post" action="/update-now"><button type="submit">Update watchdog now</button></form>' if update_cfg.get('enabled', True) else '<p>Web updates are disabled in configuration.</p>'
    body = (
        '<p>The watchdog page will briefly disconnect while its services restart.</p>'
        f'{notice}<div class="label">Current build</div><div class="value">{escape(build_number())}</div>'
        f'<div class="label">Target</div><div class="value">{escape(remote)}/{escape(branch)}</div>'
        f'<div class="label">Last result</div><p>{escape(str(state.get("state", "idle")))}: {escape(str(state.get("message", "")))}</p>'
        f'<div class="actions">{action}<a class="button" href="/">Back to Status</a></div>'
    )
    return action_page('Update watchdog', body, refresh=bool(result and result.get('ok')))


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
                return self.send(page(cfg), 'text/html; charset=utf-8')
            if path == '/update-confirm':
                return self.send(update_page(cfg), 'text/html; charset=utf-8')
            if path == '/pi-storage' and cfg.get('platform', {}).get('kind') == 'raspberry_pi':
                return self.send(pi_storage_page(), 'text/html; charset=utf-8')
            if path == '/api/healthz':
                result = {'ok': True, 'mode': 'lightweight'}
            elif path == '/api/lite':
                result = snapshot(cfg)
            elif path == '/api/status':
                result = read_object(cfg['status_path'])
            elif path == '/api/version':
                result = {'build_number': build_number(), 'build_at': datetime.fromtimestamp(Path(__file__).stat().st_mtime, timezone.utc).isoformat()}
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
            path = urlsplit(self.path).path
            if path in ('/update-now', '/pi-storage-expand'):
                size = int(self.headers.get('Content-Length', '0'))
                if size > 4096:
                    return self.send(action_page('Invalid request', '<p>Request is too large.</p>'), 'text/html; charset=utf-8', status=400)
                form = parse_qs(self.rfile.read(size).decode('utf-8'), keep_blank_values=True)
                if path == '/update-now':
                    result = launch_update_job(cfg) if cfg.get('update', {}).get('enabled', True) else {'ok': False, 'message': 'Web updates are disabled.'}
                    return self.send(update_page(cfg, result), 'text/html; charset=utf-8')
                if cfg.get('platform', {}).get('kind') != 'raspberry_pi':
                    return self.send(b'{"error":"Not found"}', status=404)
                local_client = self.client_address[0] in {'127.0.0.1', '::1', self.connection.getsockname()[0]}
                if not local_client:
                    result = {'ok': False, 'message': "Open this page in the Pi's own browser to expand storage."}
                elif not verify_account_password(form.get('password', [''])[0]):
                    result = {'ok': False, 'message': 'Pi account password was not accepted.'}
                else:
                    result = expand_pi_storage(form.get('root', [''])[0])
                return self.send(pi_storage_page(result), 'text/html; charset=utf-8')
            self.send(b'{"error":"This dashboard is read-only"}', status=405)

    server = ThreadingHTTPServer((web.get('host', '0.0.0.0'), int(web.get('port', 9110))), Handler)
    server.daemon_threads = True
    server.serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server.serve_thread.start()
    return server
