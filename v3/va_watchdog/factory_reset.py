"""Clear watchdog-owned commissioning data without changing protection policy."""
from __future__ import annotations

import json
import os
from pathlib import Path


STATE_FILES = (
    'status.json', 'events.jsonl', 'history.jsonl', 'last-reboot-reason.json',
    'heartbeat-state.json', 'heartbeat.jsonl', 'reboot-evidence.jsonl',
    'last-reboot-evidence.json', 'kernel-fault-state.json', 'blackbox.jsonl',
    'blackbox-state.json', 'watchdog-trip-test.json', 'watchdog-liveness-test.json',
    'update-state.json', 'update.log', 'hikvision-people-events.jsonl',
    'hikvision-people-events-state.json',
)
STATE_DIRS = ('blackbox-buffer', 'incidents')


def reset_config(raw):
    """Keep all watchdog policy; remove only site-specific configuration."""
    result = dict(raw)
    result['identity'] = {'site_name': '', 'asset_id': ''}
    result['people_counting'] = {
        'event_collection_enabled': False, 'address': '', 'username': '',
        'password': '', 'push_receiver_address': '',
    }
    result['mobile_router'] = {'enabled': False, 'address': '', 'snmp_community': ''}
    result['web_links'] = []
    network = dict(result.get('network') or {})
    network['local_targets'] = []
    result['network'] = network
    return result


def _remove_tree_contents(directory):
    if not directory.is_dir() or directory.is_symlink():
        return 0
    removed = 0
    for entry in directory.iterdir():
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
            removed += 1
        elif entry.is_dir():
            removed += _remove_tree_contents(entry)
            entry.rmdir()
    return removed


def reset_watchdog_data(config_path=Path('/etc/va-watchdog/config.json'),
                        state_dir=Path('/var/lib/va-watchdog'),
                        anpr_config=Path('/etc/va-watchdog/anpr.json'),
                        anpr_db=Path('/var/lib/va-watchdog-anpr/reads.sqlite3')):
    config_path, state_dir = Path(config_path), Path(state_dir)
    anpr_config, anpr_db = Path(anpr_config), Path(anpr_db)
    raw = json.loads(config_path.read_text(encoding='utf-8'))
    if not isinstance(raw, dict):
        raise ValueError('Watchdog configuration is invalid')
    updated = reset_config(raw)
    temporary = config_path.with_suffix('.json.reset-tmp')
    temporary.write_text(json.dumps(updated, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(temporary, config_path.stat().st_mode & 0o777)
    temporary.replace(config_path)
    removed = 0
    for path in state_dir.glob('config.json.*.bak'):
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed += 1
    for path in config_path.parent.glob(config_path.name + '.*.bak'):
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed += 1
    for name in STATE_FILES:
        path = state_dir / name
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed += 1
    for name in STATE_DIRS:
        removed += _remove_tree_contents(state_dir / name)
    if anpr_config.is_file() or anpr_config.is_symlink():
        anpr_config.unlink()
        removed += 1
    for suffix in ('', '-wal', '-shm'):
        path = Path(str(anpr_db) + suffix)
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed += 1
    return removed
