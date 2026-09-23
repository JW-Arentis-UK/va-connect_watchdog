import unittest
from urllib.error import HTTPError, URLError

from va_watchdog.hikvision import probe_people_counting


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = payload.encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.payload

    def getcode(self):
        return self.status


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.urls = []

    def open(self, request, timeout):
        self.urls.append((request.full_url, timeout, request.get_method()))
        outcome = self.outcomes[request.full_url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class HikvisionProbeTests(unittest.TestCase):
    def settings(self):
        return {
            "address": "192.168.1.72",
            "scheme": "http",
            "port": 80,
            "channel": 1,
            "username": "operator",
            "password": "not-returned",
            "timeout_seconds": 5,
        }

    def test_probe_reports_device_and_supported_counting_without_secrets(self):
        base = "http://192.168.1.72"
        opener = FakeOpener({
            f"{base}/ISAPI/System/deviceInfo": FakeResponse(
                "<DeviceInfo><deviceName>Barton</deviceName><model>iDS-Test</model>"
                "<serialNumber>secret-serial</serialNumber><firmwareVersion>V5.8.60</firmwareVersion>"
                "<firmwareReleasedDate>240807</firmwareReleasedDate></DeviceInfo>"
            ),
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": FakeResponse("<CountingCap/>"),
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": HTTPError(
                f"{base}/area", 404, "Not Found", {}, None
            ),
        })

        result = probe_people_counting(self.settings(), opener=opener)

        self.assertTrue(result["ok"])
        self.assertTrue(result["connected"])
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["device"]["model"], "iDS-Test")
        self.assertEqual(result["device"]["firmwareVersion"], "V5.8.60")
        self.assertNotIn("serialNumber", result["device"])
        self.assertNotIn("password", result)
        self.assertTrue(result["capabilities"][0]["supported"])
        self.assertFalse(result["capabilities"][1]["supported"])
        self.assertTrue(all(method == "GET" for _, _, method in opener.urls))

    def test_probe_distinguishes_authentication_failure(self):
        settings = self.settings()
        base = "http://192.168.1.72"
        unauthorized = HTTPError(base, 401, "Unauthorized", {}, None)
        opener = FakeOpener({
            f"{base}/ISAPI/System/deviceInfo": unauthorized,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": unauthorized,
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": unauthorized,
        })

        result = probe_people_counting(settings, opener=opener)

        self.assertFalse(result["ok"])
        self.assertFalse(result["authenticated"])
        self.assertIn("authentication failed", result["message"].lower())

    def test_probe_reports_unreachable_camera(self):
        settings = self.settings()
        base = "http://192.168.1.72"
        unreachable = URLError("timed out")
        opener = FakeOpener({
            f"{base}/ISAPI/System/deviceInfo": unreachable,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": unreachable,
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": unreachable,
        })

        result = probe_people_counting(settings, opener=opener)

        self.assertFalse(result["ok"])
        self.assertFalse(result["connected"])
        self.assertIn("connection failed", result["message"].lower())


if __name__ == "__main__":
    unittest.main()
