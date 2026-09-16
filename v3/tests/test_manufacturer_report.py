from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from va_watchdog.manufacturer_report import (
    collect_manufacturer_report,
    manufacturer_report_bundle,
    render_manufacturer_report,
)


class ManufacturerReportTests(unittest.TestCase):
    def test_collects_manufacturer_firmware_driver_and_watchdog_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dmi = root / "dmi"
            sys_root = root / "sys"
            proc_root = root / "proc"
            data = root / "data"
            dmi.mkdir()
            proc_root.mkdir()
            data.mkdir()
            for name, value in {
                "sys_vendor": "Neousys Technology Inc.",
                "product_name": "POC-451VTC",
                "product_version": "Rev. ES2",
                "product_serial": "UNIT-123",
                "board_name": "POC-400 Series",
                "board_version": "Rev. ES2",
                "bios_vendor": "American Megatrends",
                "bios_version": "Build230710",
                "bios_date": "07/10/2023",
            }.items():
                (dmi / name).write_text(value + "\n", encoding="ascii")
            (proc_root / "cpuinfo").write_text(
                "processor: 0\nvendor_id: GenuineIntel\nmodel name: Intel Atom Test\nstepping: 1\nmicrocode: 0x123\n\n"
                "processor: 1\nvendor_id: GenuineIntel\nmodel name: Intel Atom Test\n",
                encoding="ascii",
            )
            (proc_root / "meminfo").write_text(
                "MemTotal: 8192000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 2048000 kB\n",
                encoding="ascii",
            )
            (proc_root / "cmdline").write_text("quiet splash", encoding="ascii")
            os_release = root / "os-release"
            os_release.write_text('PRETTY_NAME="Ubuntu 22.04.5 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n', encoding="ascii")
            (data / "hardware-watchdog-feed.json").write_text(
                json.dumps({"process_status": "feeding", "last_feed_utc": "2026-09-15T19:59:18Z", "error_count": 0}),
                encoding="utf-8",
            )
            (data / "watchdog-trip-test.json").write_text(
                json.dumps({"last_result": {"ok": True, "tested_at": "2026-09-15 13:34:12"}}),
                encoding="utf-8",
            )
            (data / "watchdog-liveness-test.json").write_text(
                json.dumps({"ok": True, "completed": True, "message": "Full liveness test completed"}),
                encoding="utf-8",
            )
            (data / "last-reboot-evidence.json").write_text(
                json.dumps({"classification": "Watchdog reset", "confidence": "High"}),
                encoding="utf-8",
            )
            (data / "reboot-evidence.jsonl").write_text(
                json.dumps({
                    "created_at": 100,
                    "previous_boot_id": "field-lock",
                    "current_boot_id": "manual-restart",
                    "classification": "Unknown",
                    "confidence": "Low",
                }) + "\n" + json.dumps({
                    "created_at": 200,
                    "previous_boot_id": "liveness-test",
                    "current_boot_id": "test-restart",
                    "classification": "Watchdog reset",
                    "confidence": "High",
                    "liveness_path_test": {"confirmed": True},
                }) + "\n",
                encoding="utf-8",
            )
            incident = data / "incidents" / "20260915T192619Z-field-lock"
            incident.mkdir(parents=True)
            (incident / "manifest.json").write_text(json.dumps({
                "detected_at": "2026-09-15T19:26:19Z",
                "previous_boot_id": "field-lock",
                "current_boot_id": "manual-restart",
                "classification": "Unknown",
            }), encoding="utf-8")
            (incident / "last-watchdog-feed.json").write_text(json.dumps({
                "process_status": "feeding",
                "last_feed_utc": "2026-09-15T18:55:52Z",
                "feed_decision": "main process and health loop are fresh",
            }), encoding="utf-8")
            module = root / "wdt_dio.ko"
            module.write_bytes(b"test module")

            def runner(command, _timeout):
                if command[:3] == ["modinfo", "-n", "wdt_dio"]:
                    stdout = str(module)
                elif command[:2] == ["journalctl", "-k"]:
                    stdout = "normal message\nigc: link is up\nwdt_dio: watchdog enabled"
                elif command[0] == "lspci":
                    stdout = "00:17.0 SATA controller: Intel Corporation [8086:4dd3]\n\tKernel driver in use: ahci"
                elif command[0] == "modinfo" and command[-1] == "wdt_dio":
                    stdout = "version: 2.4.1.0\nfilename: /lib/modules/wdt_dio.ko"
                else:
                    stdout = "collected"
                return {"command": " ".join(command), "returncode": 0, "stdout": stdout, "stderr": ""}

            cfg = {
                "events_path": str(data / "events.jsonl"),
                "hardware_watchdog": {
                    "backend": "neousys_wdt_dio",
                    "enabled": True,
                    "device": "/dev/wdt_dio",
                    "feed_interval_seconds": 10,
                    "timeout_seconds": 30,
                    "stale_heartbeat_seconds": 15,
                },
            }
            identity = {
                "display_name": "Ellingers",
                "asset_id": "GW-1",
                "hostname": "POC-451VTC",
                "hardware_fingerprint": "ABC123",
                "hardware": {"display_model": "POC-451VTC"},
                "os_disk": {"device": "/dev/sda", "model": "OS SSD", "serial": "OS-1", "size": "256G"},
                "recording_disk": {"device": "/dev/sdb", "model": "Recording SSD", "serial": "REC-1", "size": "4T"},
            }
            payload = collect_manufacturer_report(
                cfg,
                identity=identity,
                app_version={"commit": "abc1234"},
                runner=runner,
                dmi_root=dmi,
                sys_root=sys_root,
                proc_root=proc_root,
                os_release_path=os_release,
            )

        self.assertEqual(payload["hardware"]["dmi"]["reported_model"], "POC-451VTC")
        self.assertEqual(payload["hardware"]["dmi"]["bios_version"], "Build230710")
        self.assertEqual(payload["hardware"]["cpu"]["logical_processors"], 2)
        self.assertEqual(payload["software"]["operating_system"]["name"], "Ubuntu 22.04.5 LTS")
        self.assertEqual(payload["watchdog"]["configuration"]["backend"], "neousys_wdt_dio")
        self.assertTrue(payload["watchdog"]["full_liveness_test"]["ok"])
        self.assertTrue(payload["watchdog"]["recent_reboots"][0]["planned_liveness_test"])
        self.assertEqual(payload["watchdog"]["preserved_incidents"][0]["watchdog_feed"]["process_status"], "feeding")
        self.assertIn("Kernel driver in use: ahci", payload["evidence"]["pci-devices-and-drivers.txt"])
        self.assertNotIn("normal message", payload["evidence"]["current-kernel-relevant.txt"])
        self.assertIn("wdt_dio: watchdog enabled", payload["evidence"]["current-kernel-relevant.txt"])
        self.assertIn("smart-sda.txt", payload["evidence"])
        self.assertIn("smart-sdb.txt", payload["evidence"])
        self.assertTrue(payload["driver_files"]["wdt_dio_module"]["sha256"])

    def test_text_and_zip_prioritize_readable_report(self):
        payload = {
            "generated_utc": "2026-09-16T10:11:12Z",
            "privacy": "No private network data included.",
            "gateway": {
                "display_name": "Ellingers",
                "hostname": "POC-451VTC",
                "hardware": {"display_model": "POC-451VTC"},
                "os_disk": {"device": "/dev/sda", "model": "OS SSD", "serial": "OS-1", "size": "256G"},
                "recording_disk": {"device": "/dev/sdb", "model": "Recording SSD", "serial": "REC-1", "size": "4T"},
            },
            "hardware": {
                "classified_model": "POC-451VTC",
                "dmi": {"manufacturer": "Neousys", "reported_model": "POC-451VTC", "bios_version": "Build230710"},
                "cpu": {"model": "Intel Atom", "logical_processors": 4},
                "memory": {"total_mib": 8000},
                "network_interfaces": [],
            },
            "software": {"operating_system": {"name": "Ubuntu"}, "kernel": "6.8.0", "architecture": "x86_64"},
            "watchdog": {
                "configuration": {"backend": "neousys_wdt_dio", "device": "/dev/wdt_dio", "feed_interval_seconds": 10, "timeout_seconds": 30},
                "current_feed": {"process_status": "feeding", "error_count": 0},
                "last_direct_trip_test": {"ok": True},
                "full_liveness_test": {"ok": True, "completed": True, "message": "completed"},
                "latest_reboot_evidence": {"classification": "Watchdog reset", "confidence": "High"},
            },
            "evidence": {"pci-devices-and-drivers.txt": "raw PCI evidence"},
        }

        text = render_manufacturer_report(payload)
        archive_bytes, filename = manufacturer_report_bundle(payload, "Ellingers / Sizewell")

        self.assertIn("Full liveness-path test: PASS", text)
        self.assertIn("Ellingers-Sizewell", filename)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertIn("NEOUSYS-SYSTEM-REPORT.txt", archive.namelist())
            self.assertIn("NEOUSYS-SYSTEM-REPORT.json", archive.namelist())
            self.assertIn("raw/pci-devices-and-drivers.txt", archive.namelist())
            self.assertNotIn("evidence", json.loads(archive.read("NEOUSYS-SYSTEM-REPORT.json"))["watchdog"])


if __name__ == "__main__":
    unittest.main()
