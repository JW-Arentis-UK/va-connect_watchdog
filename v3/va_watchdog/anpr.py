"""Small, separate ANPR store. Plate data never enters watchdog health evidence."""
from __future__ import annotations

import csv
import ipaddress
import io
import json
import os
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
from urllib.parse import urlsplit


DEFAULT_CONFIG = Path('/etc/va-watchdog/anpr.json')
DEFAULT_DB = Path('/var/lib/va-watchdog-anpr/reads.sqlite3')
_collector_stop = Event()
_collector_thread = None


def load_settings(path=DEFAULT_CONFIG):
    try:
        settings = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    if not isinstance(settings, dict):
        return {}
    address = str(settings.get('address') or '').strip()
    try:
        parsed = urlsplit('http://' + address)
        if parsed.hostname != address or parsed.port is not None:
            return {}
    except ValueError:
        return {}
    return settings if address and settings.get('username') and settings.get('password') else {}


def save_settings(address, username, password, retention_days=30, path=DEFAULT_CONFIG):
    address = str(ipaddress.IPv4Address(address.strip()))
    username = username.strip()
    if not username or len(username) > 64 or any(ord(c) < 32 for c in username):
        raise ValueError('Enter a valid camera username')
    if not password or len(password) > 128:
        raise ValueError('Enter a camera password')
    retention_days = int(retention_days)
    if not 1 <= retention_days <= 365:
        raise ValueError('Retention must be between 1 and 365 days')
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'address': address, 'username': username, 'password': password,
                       'retention_days': retention_days}, handle)
            handle.write('\n')
        os.chmod(temporary, 0o600)
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def fetch_latest(settings, opener=None):
    address = settings['address']
    url = f"http://{address}/home/setup/opensdk/html/WisenetRoadAI/metadata.log"
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, settings['username'], settings['password'])
    client = opener or urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(password_manager), urllib.request.ProxyHandler({}))
    with client.open(url, timeout=5) as response:
        payload = response.read(64 * 1024 + 1)
    if len(payload) > 64 * 1024:
        raise ValueError('Camera metadata exceeds size limit')
    return parse_metadata(payload, address)


def fetch_history_page(settings, end_ms, start_ms, opener=None):
    """Read one page from the camera's Road AI search database."""
    address = settings['address']
    url = f"http://{address}/cgi-bin/stw.cgi"
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, settings['username'], settings['password'])
    client = opener or urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(password_manager), urllib.request.ProxyHandler({}))
    command = (f'SEARCH;timestampfrom:{start_ms};timestampto:{end_ms};'
               'text:;country:;maker:;model:;color:;limit:1000;')
    payload = f'<GetSDK_APP_DATA><AppName>WisenetRoadAI</AppName><Data>{command}</Data></GetSDK_APP_DATA>'.encode()
    request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'text/xml'})
    with client.open(request, timeout=20) as response:
        result = response.read(4 * 1024 * 1024 + 1)
    if len(result) > 4 * 1024 * 1024:
        raise ValueError('Camera search response exceeds size limit')
    root = ET.fromstring(result)
    reads = []
    timestamps = []
    for event in root.findall('./Data/event'):
        try:
            timestamp = int(event.findtext('TS') or '0')
        except ValueError:
            continue
        if timestamp < start_ms or timestamp > end_ms:
            continue
        timestamps.append(timestamp)
        plate = (event.findtext('LPR') or '').strip().upper()
        if not plate or len(plate) > 32 or any(ord(c) < 32 for c in plate):
            continue
        reads.append({
            'time': datetime.fromtimestamp(timestamp / 1000, timezone.utc).isoformat(),
            'camera': address, 'plate': plate,
            'country': (event.findtext('COUNTRY') or '')[:32],
            'make': (event.findtext('MAKER') or '')[:64],
            'model': '', 'colour': (event.findtext('COLOR') or '')[:64],
        })
    return reads, min(timestamps) if timestamps else None


def import_history(settings, db_path=DEFAULT_DB, days=30, max_pages=100, stop=None):
    """Page backwards through Road AI history without changing camera data."""
    start_ms = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)
    end_ms = int((datetime.now(timezone.utc) + timedelta(hours=12)).timestamp() * 1000)
    imported = 0
    for _ in range(max_pages):
        if stop is not None and stop.is_set():
            break
        reads, oldest_ms = fetch_history_page(settings, end_ms, start_ms)
        for read in reads:
            imported += save_read(read, db_path)
        if oldest_ms is None or len(reads) < 1000 or oldest_ms <= start_ms:
            break
        end_ms = oldest_ms - 1
    return imported


def parse_metadata(payload, address):
    root = ET.fromstring(payload)
    frame = next((node for node in root.iter() if node.tag.split('}')[-1] == 'Frame'), None)
    if frame is None:
        return None
    timestamp = frame.attrib.get('UtcTime', '')
    try:
        stamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        stamp = stamp.astimezone(timezone.utc)
    except ValueError:
        return None
    fields = {}
    for node in frame.iter():
        name = node.tag.split('}')[-1]
        if name in {'PlateNumber', 'CountryCode', 'Brand', 'Model', 'ColorString', 'PlateType'}:
            fields[name] = (node.text or '').strip()
    plate = fields.get('PlateNumber', '').upper()
    if not plate or len(plate) > 32 or any(ord(c) < 32 for c in plate):
        return None
    return {'time': stamp.isoformat(), 'camera': address, 'plate': plate,
            'country': fields.get('CountryCode', '')[:32], 'make': fields.get('Brand', '')[:64],
            'model': fields.get('Model', '')[:64], 'colour': fields.get('ColorString', '')[:64]}


def connect(db_path=DEFAULT_DB):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == 'posix':
        path.parent.chmod(0o700)
    conn = sqlite3.connect(path, timeout=5)
    if os.name == 'posix':
        path.chmod(0o600)
    conn.execute('CREATE TABLE IF NOT EXISTS reads (time TEXT NOT NULL, camera TEXT NOT NULL, plate TEXT NOT NULL, country TEXT, make TEXT, model TEXT, colour TEXT, PRIMARY KEY(time,camera,plate))')
    return conn


def save_read(read, db_path=DEFAULT_DB):
    with closing(connect(db_path)) as conn:
        with conn:
            cursor = conn.execute('INSERT OR IGNORE INTO reads VALUES (?,?,?,?,?,?,?)', tuple(read.get(k, '') for k in ('time','camera','plate','country','make','model','colour')))
            return cursor.rowcount > 0


def query_reads(db_path=DEFAULT_DB, plate='', start='', end='', limit=500, offset=0):
    terms, args = [], []
    if plate:
        terms.append("plate LIKE ? ESCAPE '\\'")
        args.append('%' + plate.upper().replace('%', '\\%').replace('_', '\\_') + '%')
    if start:
        terms.append('time >= ?')
        args.append(start)
    if end:
        terms.append('time < ?')
        args.append(end)
    where = ' WHERE ' + ' AND '.join(terms) if terms else ''
    with closing(connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT time,camera,plate,country,make,model,colour FROM reads' + where + ' ORDER BY time DESC LIMIT ? OFFSET ?', args + [min(max(int(limit), 1), 5000), max(int(offset), 0)]).fetchall()
        total = conn.execute('SELECT count(*) FROM reads' + where, args).fetchone()[0]
    return {'rows': [dict(row) for row in rows], 'total': total}


def csv_report(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['time','camera','plate','country','make','model','colour'])
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode('utf-8-sig')


def collect_loop(settings, db_path=DEFAULT_DB, stop=None, interval=2):
    stop = stop or Event()
    retention = min(max(int(settings.get('retention_days', 30)), 1), 365)
    try:
        import_history(settings, db_path, days=retention, stop=stop)
    except (OSError, ValueError, ET.ParseError, sqlite3.Error):
        pass
    while not stop.is_set():
        try:
            latest = fetch_latest(settings)
            if latest:
                save_read(latest, db_path)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=retention)).isoformat()
            with closing(connect(db_path)) as conn:
                with conn:
                    conn.execute('DELETE FROM reads WHERE time < ?', (cutoff,))
        except (OSError, ValueError, ET.ParseError, sqlite3.Error):
            pass
        stop.wait(interval)


def start_collector(settings, db_path=DEFAULT_DB):
    global _collector_thread
    if not settings:
        return None
    _collector_stop.clear()
    thread = Thread(target=collect_loop, args=(settings, db_path, _collector_stop), daemon=True, name='va-anpr-collector')
    thread.start()
    _collector_thread = thread
    return thread


def stop_collector():
    _collector_stop.set()
    if _collector_thread is not None:
        _collector_thread.join(timeout=25)
        if _collector_thread.is_alive():
            raise TimeoutError('ANPR collector did not stop')
