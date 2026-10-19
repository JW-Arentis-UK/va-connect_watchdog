import runpy
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / 'enable_pi_dummy_display.py'
functions = runpy.run_path(str(SCRIPT))


class PiDummyDisplayScriptTests(unittest.TestCase):
    def test_release_branch_recognises_pi_os_64_bit(self):
        release = functions['pi_release']
        self.assertEqual(release({'ID': 'debian', 'VERSION_ID': '12'}, 'Raspberry Pi 5 Model B', True), 12)
        with self.assertRaises(RuntimeError):
            release({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'Raspberry Pi 5 Model B', False)

    def test_legacy_and_kms_edits_are_idempotent(self):
        legacy = functions['legacy_text']
        original = 'dtoverlay=vc4-fkms-v3d\n'
        changed = legacy(original, 'HDMI-A-1')
        self.assertIn('hdmi_force_hotplug=1', changed)
        self.assertIn('hdmi_mode=82', changed)
        self.assertEqual(legacy(changed, 'HDMI-A-1'), changed)
        kms = functions['kms_text']
        changed = kms('console=tty1 rootwait video=HDMI-A-1:800x600\n', 'HDMI-A-1')
        self.assertIn('video=HDMI-A-1:1920x1080M@60D', changed)
        self.assertIn('rootwait', changed)
        self.assertEqual(kms(changed, 'HDMI-A-1'), changed)

    def test_write_creates_one_backup_and_skips_same_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / 'cmdline.txt'
            boot.write_text('old\n')
            save = functions['save_file']
            self.assertTrue(save(boot, 'new\n', root / 'backups'))
            self.assertFalse(save(boot, 'new\n', root / 'backups'))
            self.assertEqual([p.read_text() for p in (root / 'backups').iterdir()], ['old\n'])
