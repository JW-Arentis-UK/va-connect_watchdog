import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.display_setup import (
    XORG_CONFIG, configure_standard, gdm_x11_config, legacy_config, modern_cmdline,
    platform_branch, write_with_backup,
)
from va_watchdog.display_monitor import DisplayMonitor
from va_watchdog.watchdog import add_display_status


class SetupTests(unittest.TestCase):
    def test_pi_os_branch_uses_legacy_only_on_buster(self):
        model = 'Raspberry Pi 4 Model B'
        self.assertEqual(platform_branch({'ID': 'raspbian', 'VERSION_ID': '10'}, model, True), 'pi_legacy')
        self.assertEqual(platform_branch({'ID': 'debian', 'VERSION_ID': '11'}, model, True), 'pi_kms')
        self.assertEqual(platform_branch({'ID': 'debian', 'VERSION_ID': '12'}, model, True), 'pi_kms')
        self.assertEqual(platform_branch({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, model, False), 'standard')

    def test_pi_boot_edits_are_idempotent_and_preserve_other_options(self):
        original = 'console=tty1 root=/dev/mmcblk0p2 video=HDMI-A-2:800x600@60 quiet\n'
        updated = modern_cmdline(original, 'HDMI-A-2')
        self.assertIn('video=HDMI-A-2:1920x1080M@60D', updated)
        self.assertIn('root=/dev/mmcblk0p2', updated)
        self.assertEqual(modern_cmdline(updated, 'HDMI-A-2'), updated)
        legacy = legacy_config('dtoverlay=vc4-fkms-v3d\n')
        self.assertIn('hdmi_force_hotplug=1', legacy)
        self.assertIn('hdmi_mode=82', legacy)
        self.assertEqual(legacy_config(legacy), legacy)

    def test_x11_config_and_backup(self):
        self.assertIn('Driver "dummy"', XORG_CONFIG)
        self.assertIn('Modes "1920x1080"', XORG_CONFIG)
        self.assertIn('Screen 0 "DummyScreen"', XORG_CONFIG)
        self.assertEqual(gdm_x11_config('[daemon]\n#WaylandEnable=true\n').count('WaylandEnable=false'), 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cmdline.txt'
            path.write_text('original\n')
            self.assertTrue(write_with_backup(path, 'updated\n'))
            self.assertFalse(write_with_backup(path, 'updated\n'))
            self.assertEqual(len(list(Path(directory).glob('*.headless.bak'))), 1)

    def test_standard_package_branch_uses_native_package_manager(self):
        with patch('va_watchdog.display_setup.run') as run, patch('va_watchdog.display_setup.write_with_backup'):
            configure_standard('fedora', 'lightdm.service', True)
            self.assertEqual(run.call_args.args, ('dnf', 'install', '-y', 'xorg-x11-drv-dummy'))
            run.reset_mock()
            configure_standard('ubuntu', 'lightdm.service', True)
            self.assertEqual(run.call_args.args, ('apt-get', 'install', '-y', 'xserver-xorg-video-dummy'))


class EventLog:
    def __init__(self):
        self.events = []

    def add(self, *args):
        self.events.append(args)


class MonitorTests(unittest.TestCase):
    def test_restarts_only_after_repeated_failure_with_hourly_limit(self):
        cfg = {'display_monitor': {'enabled': True, 'manager': 'lightdm.service',
                                   'startup_grace_seconds': 0, 'check_interval_seconds': 10,
                                   'restart_cooldown_seconds': 60, 'max_restarts_per_hour': 1}}
        clock = [0.0]
        calls = []
        log = EventLog()

        def command(*args, **_kwargs):
            calls.append(args)
            return args[1] == 'restart'

        with patch('va_watchdog.display_monitor.time.monotonic', side_effect=lambda: clock[0]), patch('va_watchdog.display_monitor.command_ok', side_effect=command):
            monitor = DisplayMonitor(cfg, log)
            self.assertEqual(monitor.poll().state, 'warning')
            self.assertFalse(any(x[1] == 'restart' for x in calls))
            clock[0] = 10
            self.assertIn('restarted', monitor.poll().message)
            clock[0] = 80
            self.assertIn('hourly restart limit', monitor.poll().message)
        self.assertEqual(sum(x[1] == 'restart' for x in calls), 1)
        self.assertEqual(len(log.events), 1)

    def test_wayland_session_is_accepted_for_pi(self):
        cfg = {'display_monitor': {'enabled': True, 'manager': 'lightdm.service', 'expect_x11': False}}
        def command(*args, **_kwargs):
            return args[:3] == ('systemctl', 'is-active', '--quiet') or args == ('pgrep', '-x', 'labwc')
        with patch('va_watchdog.display_monitor.command_ok', side_effect=command):
            monitor = DisplayMonitor(cfg)
            check = monitor.poll()
        self.assertEqual(check.state, 'healthy')
        status = {'checks': [], 'state': 'healthy', 'score': 100}
        checks = []
        with patch.object(monitor, 'poll', return_value=check):
            add_display_status(status, checks, monitor, cfg)
        self.assertEqual(status['checks'][0]['name'], 'display_session')

    def test_missing_xorg_restarts_an_active_manager(self):
        cfg = {'display_monitor': {'enabled': True, 'manager': 'gdm3.service',
                                   'startup_grace_seconds': 0, 'check_interval_seconds': 10}}
        clock = [0.0]
        restarts = []
        def command(*args, **_kwargs):
            if args[:3] == ('systemctl', 'is-active', '--quiet'):
                return True
            if args[:2] == ('systemctl', 'restart'):
                restarts.append(args)
                return True
            return False
        with patch('va_watchdog.display_monitor.time.monotonic', side_effect=lambda: clock[0]), patch('va_watchdog.display_monitor.command_ok', side_effect=command):
            monitor = DisplayMonitor(cfg)
            self.assertIn('Graphical session', monitor.poll().message)
            clock[0] = 10
            self.assertIn('restarted', monitor.poll().message)
        self.assertEqual(restarts, [('systemctl', 'restart', 'gdm3.service')])

    def test_disabled_monitor_never_probes(self):
        with patch('va_watchdog.display_monitor.command_ok') as command:
            self.assertIsNone(DisplayMonitor({}).poll())
        command.assert_not_called()
