import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASH = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")


@unittest.skipUnless(BASH and Path(BASH).exists(), "Bash required")
class GatewaySetupTests(unittest.TestCase):
    def shell(self, script):
        return subprocess.run([BASH, "-c", 'source "$1"; ' + script,
                               "test", (ROOT / "setup_gateway.sh").as_posix()],
                              capture_output=True, text=True)

    def test_supported_platform_and_rejected_platforms(self):
        self.assertEqual(self.shell("validate_platform ubuntu 22.04 amd64").returncode, 0)
        for args in ("ubuntu 24.04 amd64", "ubuntu 22.04 arm64", "debian 12 amd64"):
            with self.subTest(args=args):
                self.assertNotEqual(self.shell("validate_platform " + args).returncode, 0)

    def test_new_install_enables_journal_and_passes_package_configuration(self):
        result = self.shell('SUDO=(); INSTALL_DIR=/opt/test; env() { printf "%s\\n" "$@"; }; '
                            'run_installer /tmp/install /tmp/sources /tmp/apt 0 --site-name "Barton Lane"')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("APT_CONFIG=/tmp/apt", lines)
        self.assertIn("VA_WATCHDOG_APT_SOURCES=/tmp/sources", lines)
        self.assertIn("--persistent-journal", lines)
        self.assertNotIn("--non-interactive", lines)
        self.assertIn("Barton Lane", lines)

    def test_existing_install_keeps_identity_and_journal_without_prompts(self):
        result = self.shell('SUDO=(); INSTALL_DIR=/opt/test; env() { printf "%s\\n" "$@"; }; '
                            'run_installer /tmp/install /tmp/sources /tmp/apt 1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--non-interactive", result.stdout)
        self.assertNotIn("--persistent-journal", result.stdout)
        self.assertNotIn("--site-name", result.stdout)

    def test_active_or_enabled_legacy_service_blocks_setup(self):
        for state in ("is-active", "is-enabled"):
            result = self.shell('systemctl() { [[ "$1" == "' + state + '" ]]; }; check_legacy_services')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("attended migration", result.stderr)
        result = self.shell('systemctl() { return 1; }; check_legacy_services')
        self.assertEqual(result.returncode, 0)

    def test_help_requires_no_root_or_packages(self):
        result = self.shell("main --help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Installs, updates or repairs V3", result.stdout)


if __name__ == "__main__":
    unittest.main()
