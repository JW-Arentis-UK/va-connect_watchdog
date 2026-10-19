"""Single recovery owner for migrated legacy application/LAN/WAN policy."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time


def read(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


class ConsolidatedRecovery:
    def __init__(self, cfg, event_log):
        self.cfg = cfg
        self.policy = cfg['recovery'].get('consolidated_policy', {})
        self.log = event_log
        self.path = Path(self.policy.get('state_path') or Path(cfg['events_path']).parent / 'recovery/state.json')
        self.boot = boot_id()
        self.state = read(self.path)
        if self.state.get('boot_id') != self.boot:
            self.state = {'boot_id': self.boot, 'failure_count': self.state.get('failure_count', 0)}
        self.started = time.time()
        self.persisted = json.dumps(self.state, sort_keys=True)
        self.last = {'state': 'starting', 'message': 'Consolidated recovery starting', 'actions': []}

    def _save(self):
        encoded = json.dumps(self.state, sort_keys=True)
        if encoded != self.persisted:
            save(self.path, self.state)
            self.persisted = encoded

    def result(self, state, message, actions=None, **details):
        self._save()
        self.last = {'state': state, 'message': message, 'actions': actions or [],
                     'owner': 'v3', 'updated_at': time.time(), **details}
        return self.last

    def _run(self, command):
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=5, check=False).returncode
        except (OSError, subprocess.TimeoutExpired):
            return 999

    def _legacy_active(self):
        # Fail closed if ownership cannot be established. A masked/inactive unit
        # returns 3/4; an execution error is not proof that it is stopped.
        code = self._run(['systemctl', 'is-active', 'va-connect-site-watchdog.service'])
        return code not in (3, 4)

    def process(self, checks):
        now = time.time()
        recovery = self.cfg['recovery']
        if not recovery.get('enabled'):
            return self.result('disabled', 'V3 software recovery is disabled.')
        if self.state.get('reboot_requested'):
            return self.result('reboot_requested', 'Reboot already requested for this boot; no duplicate command.')
        lookup = {c.name: c for c in checks}
        services = self.policy.get('services', ['esg.service', 'sysops.service', 'bridge.service'])
        required = ['network_module', 'videosoft_process', *services]
        fresh = True
        for name in required:
            c = lookup.get(name)
            value = c.value if c and isinstance(c.value, dict) else {}
            stamp = value.get('collected_at')
            if not isinstance(stamp, (int, float)) or not 0 <= now - stamp <= 90 or c.state == 'unknown' or (name in services and value.get('active') == 'unknown'):
                fresh = False
        if not fresh:
            self.state.pop('fault_since', None)
            return self.result('waiting', 'Recovery paused: required checks are missing or stale.')
        network = lookup['network_module'].value
        wan = [r for r in network.get('targets', []) if r.get('group') == 'internet']
        lan = [r for r in network.get('targets', []) if r.get('group') == 'local']
        if not wan or not lan:
            self.state.pop('fault_since', None)
            return self.result('waiting', 'Recovery requires explicit LAN and internet targets.')
        wan_ok = any(r.get('ok') is True for r in wan)
        lan_ok = all(r.get('ok') is True for r in lan)
        app_ok = lookup['videosoft_process'].state == 'healthy'
        services_ok = all(lookup[name].state == 'healthy' for name in services)
        facts = {'app_ok': app_ok, 'services_ok': services_ok, 'lan_ok': lan_ok, 'internet_ok': wan_ok}
        if all(facts.values()):
            if self.state.get('fault_since') is not None:
                self.log.add('info', 'recovery', 'Connectivity and application checks recovered', facts)
            for key in ['fault_since', 'app_attempts', 'last_action_at', 'command_retry_at']:
                self.state.pop(key, None)
            self.state['failure_count'] = 0
            return self.result('idle', 'V3 owns application and network recovery; no action needed.', checks=facts)
        since = self.state.get('fault_since')
        if since is None or since > now:
            self.state['fault_since'] = now
            self.log.add('warning', 'recovery', 'Persistent application or network fault started', facts)
        if self._legacy_active():
            return self.result('blocked', 'Legacy watchdog may still be running; V3 recovery actions blocked.')
        grace = int(self.policy.get('startup_grace_seconds', 60))
        settle = int(self.policy.get('settle_seconds', 20))
        last_action = self.state.get('last_action_at', 0)
        if now - self.started < grace or (last_action and any(lookup[name].value['collected_at'] < last_action + settle for name in required)):
            return self.result('settling', 'Waiting for fresh checks after startup or recovery.', checks=facts)
        if now < self.state.get('command_retry_at', 0):
            return self.result('waiting', 'Recovery command failed; waiting before retry.', checks=facts)
        if not app_ok and recovery.get('restart_failed_services') and self.state.get('app_attempts', 0) < int(recovery.get('max_restart_attempts', 3)):
            self.state['app_attempts'] = self.state.get('app_attempts', 0) + 1
            return self._restart(['esg.service'], now, 'Videosoft restart', facts)
        cooldown = int(self.policy.get('network_restart_cooldown_seconds', 600))
        if not wan_ok and self.policy.get('restart_network_before_reboot', True) and now - self.state.get('last_network_restart_at', 0) >= cooldown:
            self.state['last_network_restart_at'] = now
            return self._restart(['NetworkManager.service', 'systemd-networkd.service'], now, 'Network restart', facts)
        base = int(self.policy.get('base_reboot_timeout_seconds', 300))
        maximum = int(self.policy.get('max_reboot_timeout_seconds', 3600))
        count = min(10, max(0, int(self.state.get('failure_count', 0))))
        threshold = min(maximum, base * float(self.policy.get('reboot_backoff_multiplier', 2)) ** count)
        elapsed = now - self.state['fault_since']
        if elapsed < threshold or not recovery.get('allow_reboot'):
            return self.result('watching', 'Persistent fault is being monitored.', checks=facts, fault_age_seconds=round(elapsed), reboot_after_seconds=threshold)
        return self._reboot(now, facts, threshold)

    def _restart(self, units, now, label, facts):
        self.state['last_action_at'] = now
        self._save()  # Persist cooldown/attempt before issuing a command.
        self.log.add('warning', 'recovery', label + ' requested', facts)
        for unit in units:
            code = self._run(['systemctl', '--no-block', 'restart', unit])
            if code == 0:
                return self.result('settling', label + ' queued; awaiting fresh checks.', [f'restart queued: {unit}'], checks=facts)
        self.state['command_retry_at'] = now + 60
        self.log.add('warning', 'recovery', label + ' command failed', {'return_code': code})
        return self.result('action_failed', label + ' command failed.', checks=facts)

    def _reboot(self, now, facts, threshold):
        network_failure = not facts['lan_ok'] or not facts['internet_ok']
        message = 'Watchdog reboot — no network access' if network_failure else 'Watchdog reboot — application or service failure'
        reason = {'source': 'v3_consolidated_recovery', 'state': 'requested', 'boot_id': self.boot,
                  'requested_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
                  'requested_at_unix': now, 'hardware_fallback_requested': True,
                  'message': message, 'cause': 'network_access_lost' if network_failure else 'application_failure',
                  'checks': facts, 'fault_since': self.state['fault_since'], 'reboot_after_seconds': threshold}
        reason_path = Path(self.cfg['last_reboot_reason_path'])
        previous = read(reason_path)
        save(reason_path, reason)
        count = self.state.get('failure_count', 0)
        self.state.update(reboot_requested=True, failure_count=count + 1)
        self._save()
        self.log.add('warning', 'recovery', message, reason)
        code = self._run(['shutdown', '-r', 'now'])
        if code != 0:
            # Do not let an unsuccessful command attribute a later unrelated boot.
            if previous:
                save(reason_path, previous)
            else:
                reason_path.unlink(missing_ok=True)
            self.state.update(reboot_requested=False, failure_count=count, command_retry_at=now + 60)
            self.log.add('critical', 'recovery', 'Reboot command failed', {'return_code': code})
            return self.result('action_failed', 'Reboot command failed; hardware supervision remains independent.')
        return self.result('reboot_requested', message, ['requested reboot'], checks=facts)
