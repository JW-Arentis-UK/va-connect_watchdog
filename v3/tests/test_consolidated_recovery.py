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
        self.clock = patch('va_watchdog.consolidated_recovery.time.time', side_effect=lambda: self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.boot = patch('va_watchdog.consolidated_recovery.boot_id', return_value='boot-a')
        self.boot.start(); self.addCleanup(self.boot.stop)
        self.runner = patch('va_watchdog.consolidated_recovery.subprocess.run', side_effect=self.run_command)
        self.runner.start(); self.addCleanup(self.runner.stop)
        self.commands = []
        self.reboot_code = 0
        self.legacy_code = 3
        self.cfg = {'events_path': str(self.root/'events.jsonl'), 'last_reboot_reason_path': str(self.root/'reason.json'), 'recovery': {'enabled': True, 'restart_failed_services': True, 'max_restart_attempts': 3, 'allow_reboot': True, 'consolidated_policy': {'enabled': True, 'startup_grace_seconds': 0}}}
        self.log = Mock()
        self.engine = ConsolidatedRecovery(self.cfg, self.log)

    def run_command(self, args, **kwargs):
        self.commands.append(args)
        if args[:2] == ['systemctl', 'is-active']:
            return SimpleNamespace(returncode=self.legacy_code)
        if args[0] == 'shutdown':
            # Reason and backoff must be durable before the reboot syscall.
            self.assertEqual(json.loads((self.root/'reason.json').read_text())['boot_id'], 'boot-a')
            self.assertTrue(json.loads(self.engine.path.read_text())['reboot_requested'])
            return SimpleNamespace(returncode=self.reboot_code)
        return SimpleNamespace(returncode=0)

    def checks(self, wan=(True, True), lan=True, app=True, service=True):
        targets = [{'group':'internet','ok':ok} for ok in wan] + [{'group':'local','ok':lan}]
        rows = [CheckResult('network_module','healthy' if all(wan) and lan else 'warning',value={'targets':targets,'collected_at':self.now}), CheckResult('videosoft_process','healthy' if app else 'critical',value={'collected_at':self.now})]
        rows += [CheckResult(n,'healthy' if service else 'critical',value={'collected_at':self.now,'active':'active' if service else 'inactive'}) for n in ['esg.service','bridge.service','sysops.service']]
        return rows

    def test_healthy_and_partial_wan_failure_do_not_restart(self):
        self.assertEqual(self.engine.process(self.checks())['state'], 'idle')
        self.assertEqual(self.engine.process(self.checks(wan=(False,True)))['state'], 'idle')
        self.assertEqual(self.commands, [])

    def test_network_restart_then_reboot_once_with_cause(self):
        self.assertEqual(self.engine.process(self.checks(wan=(False,False),lan=False))['state'],'settling')
        self.now += 299
        self.assertEqual(self.engine.process(self.checks(wan=(False,False),lan=False))['state'],'watching')
        self.now += 1
        self.assertEqual(self.engine.process(self.checks(wan=(False,False),lan=False))['state'],'reboot_requested')
        self.engine.process(self.checks(wan=(False,False),lan=False))
        self.assertEqual(sum(c[0]=='shutdown' for c in self.commands),1)
        self.assertEqual(json.loads((self.root/'reason.json').read_text())['cause'],'network_access_lost')
        engine2=ConsolidatedRecovery(self.cfg,self.log)
        self.assertEqual(engine2.process(self.checks())['state'],'reboot_requested')

    def test_lan_only_fault_reboots_without_restarting_network(self):
        self.engine.process(self.checks(lan=False))
        self.now += 300
        self.engine.process(self.checks(lan=False))
        self.assertFalse(any('--no-block' in c for c in self.commands))
        self.assertTrue(any(c[0]=='shutdown' for c in self.commands))

    def test_failed_reboot_removes_false_attribution_and_waits(self):
        self.reboot_code=1
        self.engine.process(self.checks(lan=False)); self.now += 300
        self.assertEqual(self.engine.process(self.checks(lan=False))['state'],'action_failed')
        self.assertFalse((self.root/'reason.json').exists())
        self.assertEqual(self.engine.state['failure_count'],0)
        self.assertEqual(self.engine.process(self.checks(lan=False))['state'],'waiting')

    def test_stale_missing_and_unknown_checks_cannot_reboot(self):
        self.engine.process(self.checks(lan=False))
        old=self.checks(lan=False); self.now += 300
        self.assertEqual(self.engine.process(old)['state'],'waiting')
        self.assertEqual(self.engine.process([])['state'],'waiting')
        rows=self.checks();rows[-1].value['active']='unknown'
        self.assertEqual(self.engine.process(rows)['state'],'waiting')
        self.assertFalse(any(c[0]=='shutdown' for c in self.commands))

    def test_application_restarts_are_bounded_and_settle(self):
        self.engine.process(self.checks(app=False))
        self.assertEqual(self.engine.process(self.checks(app=False))['state'],'settling')
        for _ in range(4):
            self.now += 30
            self.engine.process(self.checks(app=False))
        self.assertEqual(sum('esg.service' in c for c in self.commands),3)
        self.engine.process(self.checks())
        self.assertNotIn('app_attempts',self.engine.state)

    def test_ownership_conflict_and_command_errors_fail_closed(self):
        for code in (0,999):
            self.legacy_code=code
            self.assertEqual(self.engine.process(self.checks(lan=False))['state'],'blocked')
        self.assertFalse(any(c[0]=='shutdown' or '--no-block' in c for c in self.commands))

    def test_disabled_recovery_does_nothing(self):
        self.cfg['recovery']['enabled']=False
        self.assertEqual(self.engine.process(self.checks(lan=False))['state'],'disabled')
        self.assertEqual(self.commands,[])

    def test_backoff_survives_boot_and_resets_when_healthy(self):
        self.engine.state['failure_count']=2;self.engine._save()
        with patch('va_watchdog.consolidated_recovery.boot_id',return_value='boot-b'):
            other=ConsolidatedRecovery(self.cfg,self.log)
        other.process(self.checks(lan=False));self.now+=300
        result=other.process(self.checks(lan=False))
        self.assertEqual(result['reboot_after_seconds'],1200)
        self.assertEqual(result['state'],'watching')
        other.process(self.checks())
        self.assertEqual(other.state['failure_count'],0)

    def test_recovery_engine_dispatches_only_to_one_policy(self):
        engine=RecoveryEngine(self.cfg,self.log)
        result=engine.process(self.checks())
        self.assertEqual(result['owner'],'v3')
        self.assertEqual(engine.summary(),result)

    def test_service_failure_escalates_without_claiming_network_failure(self):
        self.engine.process(self.checks(service=False)); self.now += 300
        self.engine.process(self.checks(service=False))
        self.assertEqual(json.loads((self.root/'reason.json').read_text())['cause'],'application_failure')

    def test_network_cooldown_survives_monitor_restart(self):
        self.engine.process(self.checks(wan=(False,False)))
        self.now += 40
        other=ConsolidatedRecovery(self.cfg,self.log)
        other.process(self.checks(wan=(False,False)))
        self.assertEqual(sum('NetworkManager.service' in c for c in self.commands),1)


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
