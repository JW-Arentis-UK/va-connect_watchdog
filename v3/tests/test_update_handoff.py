import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH = ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))


@unittest.skipUnless(BASH and Path(BASH).exists(), "Bash required")
class UpdateHandoffTests(unittest.TestCase):
    def run_update(self, failure=""):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scripts = base / "repo/v3/scripts"
            scripts.mkdir(parents=True)
            commands = base / "bin"
            commands.mkdir()
            updater = scripts / "update.sh"
            shutil.copyfile(ROOT / "v3/scripts/update.sh", updater)
            # Simulate a pull replacing BOTH the running updater and setup code.
            files = {
                "python3": '#!/bin/bash\ncat >/dev/null\n',
                "git": '''#!/bin/bash
case " $* " in
  *" rev-parse "*) echo abc1234 ;;
  *" fetch "*) echo fetch >> "$TEST_TRACE"; [[ "$TEST_FAILURE" != fetch ]] ;;
  *" pull "*)
    echo pull >> "$TEST_TRACE"
    [[ "$TEST_FAILURE" != pull ]] || exit 9
    printf 'exit 88\n' > "$VA_WATCHDOG_INSTALL_DIR/v3/scripts/update.sh"
    cp "$TEST_NEW_APPLY" "$VA_WATCHDOG_INSTALL_DIR/v3/scripts/update_apply.sh"
    ;;
esac
''',
            }
            for name, text in files.items():
                path = commands / name
                path.write_text(text, encoding="utf-8", newline="\n")
                path.chmod(0o755)
            (scripts / "update_apply.sh").write_text('echo OLD >> "$TEST_TRACE"\n')
            new_apply = base / "new_apply.sh"
            new_apply.write_text('echo "NEW:$1:$2" >> "$TEST_TRACE"\nexit "${TEST_APPLY_EXIT:-0}"\n')
            trace = base / "trace"
            env = dict(os.environ, VA_WATCHDOG_INSTALL_DIR=(base / "repo").as_posix(),
                       VA_WATCHDOG_STATE_DIR=(base / "state").as_posix(),
                       TEST_TRACE=trace.as_posix(), TEST_NEW_APPLY=new_apply.as_posix(),
                       TEST_FAILURE=failure, TEST_APPLY_EXIT="7" if failure == "apply" else "0")
            # Set PATH inside Bash so Windows path separators cannot break it.
            result = subprocess.run([BASH, "-c", 'export PATH="$(cd "$1" && pwd):$PATH"; /bin/bash "$2" upstream codex/test',
                                     "test", commands.as_posix(), updater.as_posix()],
                                    env=env, capture_output=True, text=True)
            return result, trace.read_text() if trace.exists() else ""

    def test_pull_uses_new_setup_once_even_when_running_script_is_replaced(self):
        result, trace = self.run_update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(trace.splitlines(), ["fetch", "pull", "NEW:upstream:codex/test"])

    def test_git_failures_never_run_setup(self):
        for failure in ("fetch", "pull"):
            with self.subTest(failure=failure):
                result, trace = self.run_update(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("NEW", trace)
                self.assertNotIn("OLD", trace)
                self.assertIn("update failed", result.stdout)

    def test_setup_failure_is_reported_as_failure(self):
        result, trace = self.run_update("apply")
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn("NEW", trace)
        self.assertIn("update failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
