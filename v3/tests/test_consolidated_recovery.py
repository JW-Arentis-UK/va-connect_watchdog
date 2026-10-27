import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from va_watchdog.common import CheckResult
from va_watchdog.consolidated_recovery import ConsolidatedRecovery
from va_watchdog.recovery import RecoveryEngine


class ConsolidatedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = 1000.
        self.enterContext(patch('va_watchdog.recovery.time.time', side_effect=lambda: self.now))
        self.enterContext(patch('va_watchdog.recovery.time.monotonic', side_effect=lambda: self.now))
        self.commands = []
        self.legacy_code = 3
        self.restart_code = 0
        self.enterContext(patch('va_watchdog.recovery.subprocess.run', side_effect=self.run_command))
        self.cfg = {
            'events_path': str(self.root / 'events.jsonl'),
            'services': [{'name': name, 'critical': True, 'restart': True}
                         for name in ['esg.service', 'bridge.service', 'sysops.service']],
            'recovery': {'enabled': True, 'restart_failed_services': True,
                         'max_restart_attempts': 3, 'allow_reboot': True,
                         'consolidated_policy': {'enabled': True}}}
        self.log = Mock()
        self.engine = ConsolidatedRecovery(self.cfg, self.log)

    def run_command(self, args, **kwargs):
        self.commands.append(args)
        if args[:2] == ['systemctl', 'is-active']:
            return SimpleNamespace(returncode=self.legacy_code)
        return SimpleNamespace(returncode=self.restart_code)

    def checks(self, wan=False, lan=False, app=False, services=False):
        rows = [CheckResult('network_module', 'healthy' if wan and lan else 'critical',
                            value={'collected_at': self.now}, critical=True),
                CheckResult('videosoft_process', 'healthy' if app else 'critical',
                            value={'collected_at': self.now}, critical=True)]
        rows += [CheckResult(item['name'], 'healthy' if services else 'critical',
                             value={'collected_at': self.now, 'active': 'active' if services else 'failed'},
                             critical=True) for item in self.cfg['services']]
        return rows

    def test_network_and_application_faults_never_reboot_or_restart_network(self):
        self.cfg['recovery']['restart_failed_services'] = False
        for policy in (RecoveryEngine, ConsolidatedRecovery):
            engine = policy(self.cfg, self.log)
            for advance in (0, 60, 3600, 86400):
                self.now += advance
                self.assertFalse(engine.process(self.checks())['automatic_reboot'])
        self.assertEqual(self.commands, [])
        self.assertFalse((self.root / 'last-reboot-reason.json').exists())

    def test_restarts_are_bounded_and_persist_across_monitor_restart(self):
        for _ in range(8):
            self.engine.process(self.checks())
            self.now += 60
            self.engine = ConsolidatedRecovery(self.cfg, self.log)
        for item in self.cfg['services']:
            self.assertEqual(sum(command[-1] == item['name'] for command in self.commands), 3)

    def test_cooldown_prevents_repeated_restarts(self):
        self.engine.process(self.checks())
        self.engine.process(self.checks())
        self.assertEqual(sum('--no-block' in command for command in self.commands), 3)

    def test_healthy_service_must_stay_healthy_before_attempts_reset(self):
        self.engine.process(self.checks())
        self.now += 1
        self.engine.process(self.checks(services=True))
        self.assertEqual(self.engine.state['services']['esg.service']['attempts'], 1)
        self.now += 60
        self.engine.process(self.checks(services=True))
        self.assertEqual(self.engine.state['services']['esg.service']['attempts'], 0)

    def test_stale_unknown_and_missing_checks_cannot_restart(self):
        rows = self.checks()
        self.now += 300
        self.engine.process(rows)
        self.engine.process([])
        self.engine.process([CheckResult('esg.service', 'unknown', value={'collected_at': self.now})])
        self.assertEqual(self.commands, [])

    def test_active_but_high_resource_service_is_not_restarted(self):
        rows = self.checks()
        for row in rows:
            row.value['active'] = 'active'
        self.engine.process(rows)
        self.assertEqual(self.commands, [])

    def test_legacy_owner_conflict_blocks_service_actions(self):
        for code in (0, 999):
            self.legacy_code = code
            self.assertEqual(self.engine.process(self.checks())['state'], 'blocked')
        self.assertFalse(any('--no-block' in command for command in self.commands))

    def test_only_configured_restart_services_are_eligible(self):
        self.cfg['services'][0]['restart'] = False
        self.engine.process(self.checks())
        self.assertFalse(any(command[-1] == 'esg.service' for command in self.commands))

    def test_failed_commands_consume_attempt_without_claiming_success(self):
        self.restart_code = 1
        result = self.engine.process(self.checks())
        self.assertEqual(result['actions'], [])
        self.assertEqual(self.engine.state['services']['esg.service']['attempts'], 1)

    def test_disabled_recovery_does_nothing(self):
        self.cfg['recovery']['enabled'] = False
        self.assertEqual(self.engine.process(self.checks())['state'], 'disabled')
        self.assertEqual(self.commands, [])


class CollectorContractTests(unittest.TestCase):
    def test_network_marks_fresh_lan_and_wan_results(self):
        from va_watchdog.network import check_network
        with patch('va_watchdog.network._ping',return_value={'ok':True,'detail':'ok'}), patch('va_watchdog.network._tcp',return_value={'ok':True,'detail':'ok'}):
            result=check_network({'network':{'internet_hosts':['1.1.1.1'],'local_targets':['192.168.1.1:80']}})[0]
        self.assertEqual([x['group'] for x in result.value['targets']],['internet','local'])
        self.assertIsInstance(result.value['collected_at'],float)

    def test_missing_process_and_failed_probe_are_distinct(self):
        from va_watchdog.services import check_services
        cfg={'services':[],'recovery':{'consolidated_policy':{'enabled':True}}}
        for code,state in [(0,'healthy'),(1,'critical'),(2,'unknown')]:
            with self.subTest(code=code), patch('va_watchdog.services.subprocess.run',return_value=SimpleNamespace(returncode=code)):
                result=check_services(cfg)[0]
                self.assertEqual(result.state,state)
                self.assertIsInstance(result.value['collected_at'],float)


if __name__=='__main__':
    unittest.main()
