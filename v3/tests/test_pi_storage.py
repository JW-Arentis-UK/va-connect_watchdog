import unittest
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest.mock import patch

from va_watchdog import pi_storage
from va_watchdog.web import start_web


class PiStorageTests(unittest.TestCase):
    def test_only_final_ext4_root_partition_can_expand(self):
        answers = {
            ("findmnt", "-n", "-o", "SOURCE", "/"): "/dev/nvme0n1p2",
            ("findmnt", "-n", "-o", "FSTYPE", "/"): "ext4",
            ("lsblk", "-n", "-o", "TYPE", "/dev/nvme0n1p2"): "part",
            ("lsblk", "-n", "-o", "PKNAME", "/dev/nvme0n1p2"): "nvme0n1",
            ("lsblk", "-n", "-d", "-o", "PTTYPE", "/dev/nvme0n1"): "dos",
            ("lsblk", "-n", "-l", "-b", "-o", "START,SIZE,TYPE", "/dev/nvme0n1"): "8192 536870912 part\n1056768 31385976832 part",
            ("lsblk", "-n", "-o", "START", "/dev/nvme0n1p2"): "1056768",
            ("lsblk", "-n", "-b", "-o", "SIZE", "/dev/nvme0n1p2"): "31385976832",
            ("lsblk", "-n", "-d", "-b", "-o", "SIZE", "/dev/nvme0n1"): "1000204886016",
        }
        with patch.object(pi_storage, "_run", side_effect=lambda *args: answers[args]), patch.object(pi_storage.os.path, "realpath", side_effect=lambda value: value), patch.object(pi_storage.shutil, "which", return_value="/usr/bin/raspi-config"), patch.object(pi_storage.os, "statvfs", create=True) as stats:
            stats.return_value.f_blocks = 7659980
            stats.return_value.f_frsize = 4096
            status = pi_storage.inspect()
        self.assertTrue(status["available"])
        self.assertEqual(status["free_gib"], 901.78)

        answers[("lsblk", "-n", "-l", "-b", "-o", "START,SIZE,TYPE", "/dev/nvme0n1")] += "\n999999999 1000000 part"
        with patch.object(pi_storage, "_run", side_effect=lambda *args: answers[args]), patch.object(pi_storage.os.path, "realpath", side_effect=lambda value: value), patch.object(pi_storage.shutil, "which", return_value="/usr/bin/raspi-config"), patch.object(pi_storage.os, "statvfs", create=True) as stats:
            stats.return_value.f_blocks = 7659980
            stats.return_value.f_frsize = 4096
            self.assertFalse(pi_storage.inspect()["available"])

        answers[("lsblk", "-n", "-b", "-o", "SIZE", "/dev/nvme0n1p2")] = "999550000000"
        answers[("lsblk", "-n", "-l", "-b", "-o", "START,SIZE,TYPE", "/dev/nvme0n1")] = "8192 536870912 part\n1056768 999550000000 part"
        with patch.object(pi_storage, "_run", side_effect=lambda *args: answers[args]), patch.object(pi_storage.os.path, "realpath", side_effect=lambda value: value), patch.object(pi_storage.os.path, "exists", return_value=True), patch.object(pi_storage.os, "statvfs", create=True) as stats:
            stats.return_value.f_blocks = 7659980
            stats.return_value.f_frsize = 4096
            status = pi_storage.inspect()
        self.assertTrue(status["reboot_pending"])
        self.assertFalse(status["available"])

    def test_confirmation_must_match_current_root(self):
        with patch.object(pi_storage, "inspect", return_value={"available": True, "root": "/dev/nvme0n1p2"}), patch.object(pi_storage.subprocess, "run") as run:
            result = pi_storage.expand("/dev/sda2")
        self.assertFalse(result["ok"])
        run.assert_not_called()

    def test_pi_storage_page_and_confirmed_action_are_reachable(self):
        cfg = {"platform": {"kind": "raspberry_pi"}, "web": {"host": "127.0.0.1", "port": 0},
               "events_path": "/tmp/pi-storage-test-events.jsonl", "status_path": "/tmp/pi-storage-test-status.json"}
        storage = {"available": True, "reason": "Space available", "root": "/dev/nvme0n1p2",
                   "disk": "/dev/nvme0n1", "root_gib": 29.23, "disk_gib": 931.51, "free_gib": 901.78}
        with patch("va_watchdog.web.inspect_pi_storage", return_value=storage), patch("va_watchdog.web.verify_local_reset_password", return_value=True), patch("va_watchdog.web.expand_pi_storage", return_value={"ok": True, "message": "Reboot required"}) as expand:
            server = start_web(cfg)
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                with urlopen(base + "/pi-storage", timeout=5) as response:
                    page = response.read().decode()
                self.assertIn("901.78 GiB", page)
                self.assertIn("Expand root partition", page)
                request = Request(base + "/pi-storage-expand", data=urlencode({"root": "/dev/nvme0n1p2", "password": "test"}).encode(), method="POST")
                with urlopen(request, timeout=5) as response:
                    self.assertIn("Reboot required", response.read().decode())
                expand.assert_called_once_with("/dev/nvme0n1p2")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
