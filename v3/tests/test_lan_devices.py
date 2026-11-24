import json
import copy
from va_watchdog.config import DEFAULT_CONFIG
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
import base64
from urllib.parse import urlencode

from va_watchdog import lan_devices as lan
from va_watchdog.web_security import ACTION_PATHS, PUBLIC_GET


NETWORK = {"id": "eth0|192.168.1.1|192.168.1.0/30", "interface": "eth0",
           "address": "192.168.1.1", "network": "192.168.1.0/30", "label": "eth0 - 192.168.1.0/30"}


class LanDeviceTests(unittest.TestCase):
    def test_networks_are_connected_ipv4_and_large_ranges_are_bounded(self):
        payload = [{"ifname": "eth0", "addr_info": [{"local": "192.168.3.9", "prefixlen": 16, "scope": "global"}]},
                   {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]}]
        with patch.object(lan, "_command", return_value=payload):
            result = lan.interfaces()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["network"], "192.168.3.0/24")
        self.assertTrue(result[0]["limited"])

    def test_scan_rejects_arbitrary_or_disconnected_targets_before_network_io(self):
        with patch.object(lan, "interfaces", return_value=[NETWORK]), patch.object(lan, "discovery") as discover:
            for selection in ("8.8.8.8", "eth0|192.168.1.1|0.0.0.0/0", ""):
                with self.assertRaises(ValueError):
                    lan.scan(selection)
            discover.assert_not_called()

    def test_scan_uses_only_selected_subnet_and_excludes_gateway(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(lan, "STATE", Path(tmp) / "result.json"), \
                patch.object(lan, "interfaces", return_value=[NETWORK]), patch.object(lan, "_command", return_value=[]), \
                patch.object(lan, "discovery", return_value={}), patch.object(lan, "credentials", return_value=("admin", "test-secret")), \
                patch.object(lan, "inspect_device", return_value={"ip": "192.168.1.2", "model": "test"}) as probe:
            result = lan.scan(NETWORK["id"])
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(probe.call_args.args[0], "192.168.1.2")
            self.assertEqual(result["state"], "complete")
            self.assertNotIn("test-secret", json.dumps(result))

    def test_secret_retention_change_clear_and_public_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch.object(lan, "SECRET", base / "private/credentials.json"), \
                    patch.object(lan, "SETTINGS", base / "settings.json"), patch.object(lan, "STATE", base / "scan.json"), \
                    patch.object(lan, "interfaces", return_value=[NETWORK]):
                self.assertEqual(lan.credentials(), ("admin", ""))
                lan.save_credentials("admin", "test-secret")
                lan.save_credentials("admin", "")
                self.assertEqual(lan.credentials(), ("admin", "test-secret"))
                self.assertNotIn("test-secret", json.dumps(lan.status()))
                self.assertTrue(lan.status()["settings"]["password_set"])
                with self.assertRaises(ValueError):
                    lan.save_credentials("other", "")
                lan.save_credentials("admin", "", clear=True)
                self.assertFalse(lan.status()["settings"]["password_set"])
                self.assertEqual(lan.credentials(), ("admin", ""))

    def test_hikvision_identification_reads_namespaced_model_and_serial(self):
        xml = ET.fromstring('<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"><model>DS-test</model><serialNumber>SN123</serialNumber></DeviceInfo>')
        with patch.object(lan.socket, "create_connection"), patch.object(lan, "request_xml", return_value=(xml, "")):
            row = lan.inspect_device("192.168.1.2", "eth0", {}, False, "admin", "test", time.monotonic() + 30)
        self.assertEqual(row["model"], "DS-test")
        self.assertEqual(row["serial"], "SN123")
        self.assertEqual(row["status"], "Identified")

    def test_failed_credentials_and_generic_hosts_do_not_invent_device_details(self):
        with patch.object(lan.socket, "create_connection"), \
                patch.object(lan, "request_xml", return_value=(None, "Credentials required or rejected")):
            row = lan.inspect_device("192.168.1.2", "eth0", {}, False, "admin", "test", time.monotonic() + 30)
        self.assertEqual(row["manufacturer"], "Unknown")
        self.assertEqual(row["model"], "Unavailable")
        self.assertEqual(row["status"], "Credentials required or rejected")

    def test_onvif_identification_fallback(self):
        xml = ET.fromstring('<Envelope><GetDeviceInformationResponse><Manufacturer>Example</Manufacturer><Model>Cam 2</Model><SerialNumber>456</SerialNumber></GetDeviceInformationResponse></Envelope>')
        with patch.object(lan.socket, "create_connection"), \
                patch.object(lan, "request_xml", side_effect=[(None, "Unavailable"), (xml, "")]):
            row = lan.inspect_device("192.168.1.2", "eth0", {}, True, "admin", "test", time.monotonic() + 30)
        self.assertEqual(row["manufacturer"], "Example")
        self.assertEqual(row["serial"], "456")

    def test_deadline_stops_queued_probes(self):
        with patch.object(lan.socket, "create_connection") as connect:
            self.assertIsNone(lan.inspect_device("192.168.1.2", "eth0", {}, False, "", "", 0))
            connect.assert_not_called()

    def test_soap_escapes_username_and_never_sends_plaintext_password(self):
        body = lan.onvif_body("a<&", "test-secret")
        ET.fromstring(body)
        self.assertNotIn(b"test-secret", body)
        self.assertIn(b"a&lt;&amp;", body)

    def test_no_redirect_or_proxy_and_xml_entity_rejection(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'<!DOCTYPE data [<!ENTITY x "test">]><data>&x;</data>'
        opener = Mock()
        opener.open.return_value = response
        with patch.object(lan, "build_opener", return_value=opener) as build:
            root, message = lan.request_xml("http://192.168.1.2/ISAPI/System/deviceInfo", "admin", "test")
        self.assertIsNone(root)
        self.assertEqual(message, "Invalid device response")
        self.assertTrue(any(isinstance(arg, lan.NoRedirect) for arg in build.call_args.args))
        self.assertTrue(any(isinstance(arg, lan.ProxyHandler) and not arg.proxies for arg in build.call_args.args))
        self.assertIsNone(lan.NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.com"))

    def test_actions_require_operator_authorization(self):
        self.assertIn("/lan-devices-scan", ACTION_PATHS)
        self.assertIn("/lan-devices-credentials", ACTION_PATHS)
        self.assertNotIn("/api/lan-devices", PUBLIC_GET)
        self.assertNotIn("/lan-devices", PUBLIC_GET)

    def test_privileged_dispatch_saves_credentials_and_refuses_bad_operator(self):
        from va_watchdog.privileged_actions import execute
        payload = {"operation": "action", "path": "/lan-devices-credentials",
                   "authorization": "Basic test", "body": base64.b64encode(
                       urlencode({"username": "admin", "password": "test-secret"}).encode()).decode()}
        with patch("va_watchdog.privileged_actions.verify_operator", return_value=False):
            with self.assertRaises(PermissionError):
                execute(payload, copy.deepcopy(DEFAULT_CONFIG))
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch("va_watchdog.privileged_actions.verify_operator", return_value=True), \
                    patch.object(lan, "SECRET", base / "private/credentials.json"), \
                    patch.object(lan, "SETTINGS", base / "settings.json"):
                response = execute(payload, copy.deepcopy(DEFAULT_CONFIG))
                self.assertIn(b"200 OK", response)
                self.assertNotIn(b"test-secret", response)
                self.assertEqual(lan.credentials(), ("admin", "test-secret"))

    def test_privileged_dispatch_scan_rejects_nonlocal_network(self):
        from va_watchdog.privileged_actions import execute
        payload = {"operation": "action", "path": "/lan-devices-scan", "authorization": "Basic test",
                   "body": base64.b64encode(b"network=8.8.8.8").decode()}
        with patch("va_watchdog.privileged_actions.verify_operator", return_value=True), \
                patch.object(lan, "interfaces", return_value=[NETWORK]):
            response = execute(payload, copy.deepcopy(DEFAULT_CONFIG))
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"currently connected local network", response)


if __name__ == "__main__":
    unittest.main()
