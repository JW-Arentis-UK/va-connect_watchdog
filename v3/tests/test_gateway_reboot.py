import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.gateway_reboot import request_gateway_reboot


class GatewayRebootTests(unittest.TestCase):
    def test_records_reason_and_schedules_delayed_controlled_reboot(self):
        with tempfile.TemporaryDirectory() as temporary:
            reason_path = Path(temporary) / "last-reboot-reason.json"
            completed = subprocess.CompletedProcess([], 0, stdout="Running as unit", stderr="")

            with patch("va_watchdog.gateway_reboot.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
                "va_watchdog.gateway_reboot.subprocess.run", return_value=completed
            ) as run:
                result = request_gateway_reboot({"last_reboot_reason_path": str(reason_path)}, delay_seconds=8)

            self.assertTrue(result["ok"])
            reason = json.loads(reason_path.read_text(encoding="utf-8"))
            self.assertEqual(reason["requested_by"], "watchdog_web")
            command = run.call_args.args[0]
            self.assertIn("--on-active=8s", command)
            self.assertEqual(command[-2:], ["/usr/bin/systemctl", "reboot"])

    def test_failed_schedule_restores_previous_reboot_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            reason_path = Path(temporary) / "last-reboot-reason.json"
            previous = {"message": "previous reason"}
            reason_path.write_text(json.dumps(previous), encoding="utf-8")
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="permission denied")

            with patch("va_watchdog.gateway_reboot.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch(
                "va_watchdog.gateway_reboot.subprocess.run", return_value=failed
            ):
                result = request_gateway_reboot({"last_reboot_reason_path": str(reason_path)})

            self.assertFalse(result["ok"])
            self.assertEqual(json.loads(reason_path.read_text(encoding="utf-8")), previous)


if __name__ == "__main__":
    unittest.main()
