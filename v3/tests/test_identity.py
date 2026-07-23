from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.identity import configured_identity, identity_slug, identity_summary


LSBLK = {
    "blockdevices": [
        {
            "name": "sda",
            "path": "/dev/sda",
            "type": "disk",
            "model": "OS SSD",
            "serial": "OS-123",
            "size": "256G",
            "mountpoints": [None],
            "children": [
                {
                    "name": "sda3",
                    "path": "/dev/sda3",
                    "type": "part",
                    "pkname": "sda",
                    "mountpoints": ["/"],
                }
            ],
        },
        {
            "name": "sdb",
            "path": "/dev/sdb",
            "type": "disk",
            "model": "Recording SSD",
            "serial": "REC-456",
            "size": "4T",
            "mountpoints": ["/mnt/storage"],
        },
    ]
}


class IdentityTests(unittest.TestCase):
    def test_configured_identity_has_safe_unconfigured_fallback(self):
        identity = configured_identity({})
        self.assertFalse(identity["configured"])
        self.assertEqual(identity["display_name"], "Site not configured")

    def test_site_name_is_used_for_download_slug(self):
        self.assertEqual(
            identity_slug({"identity": {"site_name": "Ellingers Station / North"}}),
            "Ellingers-Station-North",
        )

    @patch("va_watchdog.identity.platform.node", return_value="POC-451VTC")
    def test_summary_matches_root_and_recording_disk_serials(self, _node):
        with tempfile.TemporaryDirectory() as temporary:
            machine_id = Path(temporary) / "machine-id"
            machine_id.write_text("machine-abc\n", encoding="ascii")
            summary = identity_summary(
                {
                    "identity": {"site_name": "Ellingers", "asset_id": "GW-017"},
                    "recording_storage": {"mountpoint": "/mnt/storage"},
                },
                runner=lambda _command: json.dumps(LSBLK),
                machine_id_path=machine_id,
            )

        self.assertEqual(summary["display_name"], "Ellingers")
        self.assertEqual(summary["hostname"], "POC-451VTC")
        self.assertEqual(summary["os_disk"]["serial"], "OS-123")
        self.assertEqual(summary["recording_disk"]["serial"], "REC-456")
        self.assertEqual(len(summary["hardware_fingerprint"]), 12)

    def test_summary_tolerates_missing_lsblk_and_machine_id(self):
        summary = identity_summary(
            {"identity": {"site_name": "Test Unit"}},
            runner=lambda _command: "",
            machine_id_path=Path("/path/that/does/not/exist"),
        )
        self.assertEqual(summary["display_name"], "Test Unit")
        self.assertEqual(summary["os_disk"]["serial"], "")
        self.assertEqual(summary["recording_disk"]["serial"], "")

    @patch("va_watchdog.identity.platform.node", return_value="POC-451VTC")
    def test_one_drive_mode_uses_os_disk_as_recording_disk(self, _node):
        summary = identity_summary(
            {
                "identity": {"site_name": "Stamford Station"},
                "recording_storage": {
                    "mode": "system_directory",
                    "directory_path": "/home/vsuser/recordings",
                },
            },
            runner=lambda _command: json.dumps(LSBLK),
            machine_id_path=Path("/path/that/does/not/exist"),
        )
        self.assertEqual(summary["os_disk"]["serial"], "OS-123")
        self.assertEqual(summary["recording_disk"]["serial"], "OS-123")


if __name__ == "__main__":
    unittest.main()
