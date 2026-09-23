import unittest
from urllib.error import HTTPError, URLError

from va_watchdog.hikvision import _onvif_client_error_detail, _onvif_client_event_topics, _onvif_event_properties_query, probe_people_counting
from va_watchdog.hikvision_events import HikvisionEventCollector, notification_diagnostic, parse_notification


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
        outcome = self.outcomes.get(request.full_url, HTTPError(request.full_url, 404, "Not Found", {}, None))
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
            f"{base}/ISAPI/Intelligent/capabilities": FakeResponse("<IntelligentCap/>") ,
            f"{base}/ISAPI/Intelligent/channels/1/capabilities": FakeResponse("<ChannelIntelligentCap/>") ,
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection/capabilities": FakeResponse("<MixedTargetCap/>") ,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": FakeResponse("<CountingCap/>"),
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": HTTPError(
                f"{base}/area", 404, "Not Found", {}, None
            ),
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search/capabilities": FakeResponse(
                "<CountingSearchCap/>"
            ),
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search": FakeResponse(
                "<CountingStatisticsList><CountingStatistics><enterCount>12</enterCount>"
                "<leaveCount>7</leaveCount></CountingStatistics></CountingStatisticsList>"
            ),
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection?format=json": FakeResponse(
                '{"MixedTargetDetection":{"enabled":true}}'
            ),
            f"{base}/ISAPI/ContentMgmt/Storage": FakeResponse("<Storage><status>ok</status></Storage>"),
            f"{base}/ISAPI/ContentMgmt/Storage/hdd": FakeResponse("<HDD><status>ok</status></HDD>"),
            f"{base}/ISAPI/Streaming/channels/1/metadata": FakeResponse(""),
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
        self.assertTrue(result["capabilities"][3]["supported"])
        self.assertFalse(result["capabilities"][4]["supported"])
        self.assertTrue(result["capabilities"][5]["supported"])
        self.assertEqual(result["report"]["rows"], 1)
        self.assertEqual(result["report"]["totals"], {"enterCount": 12, "leaveCount": 7})
        self.assertTrue(result["multi_target_detection"]["active"])
        self.assertTrue(all(item["available"] for item in result["data_sources"][:3]))
        self.assertEqual([method for _, _, method in opener.urls].count("POST"), 2)
        self.assertTrue(any(url.endswith("/counting/search") and method == "POST" for url, _, method in opener.urls))

    def test_onvif_event_query_uses_password_digest_without_password_text(self):
        query = _onvif_event_properties_query(
            "operator",
            "camera-secret",
            "http://192.168.1.72/onvif/Events",
        ).decode("utf-8")

        self.assertIn("PasswordDigest", query)
        self.assertIn("<wsse:Nonce", query)
        self.assertIn("<wsu:Created>", query)
        self.assertIn("<wsa:MessageID>urn:uuid:", query)
        self.assertIn("<wsa:ReplyTo>", query)
        self.assertNotIn("camera-secret", query)

    def test_onvif_client_uses_camera_events_service_without_exposing_credentials(self):
        calls = []

        class FakeEvents:
            def GetEventProperties(self):
                calls.append("properties")

        class FakeCamera:
            def __init__(self, host, port, username, password, **options):
                calls.append((host, port, username, password, options))

            def create_events_service(self):
                return FakeEvents()

        result = _onvif_client_event_topics(
            self.settings(),
            "http://192.168.1.72/onvif/Events",
            camera_factory=FakeCamera,
            transport_factory=lambda *_args: object(),
        )

        self.assertTrue(result["available"])
        self.assertEqual(result["detail"], "Available through ONVIF WS-Security client")
        self.assertEqual(calls[0][:3], ("192.168.1.72", 80, "operator"))
        self.assertTrue(calls[0][4]["adjust_time"])
        self.assertNotIn("not-returned", str(result))

    def test_onvif_client_retries_authentication_failure_with_http_digest(self):
        calls = []

        class FakeEvents:
            def __init__(self, fails):
                self.fails = fails

            def GetEventProperties(self):
                if self.fails:
                    raise RuntimeError("authentication failed")

        class FakeCamera:
            def __init__(self, *_args, **options):
                calls.append(options)
                self.options = options

            def create_events_service(self):
                return FakeEvents(not self.options.get("encrypt") is False)

        result = _onvif_client_event_topics(
            self.settings(),
            "http://192.168.1.72/onvif/Events",
            camera_factory=FakeCamera,
            transport_factory=lambda *_args: object(),
        )

        self.assertTrue(result["available"])
        self.assertEqual(result["detail"], "Available through ONVIF HTTP-Digest client")
        self.assertEqual(len(calls), 2)
        self.assertFalse(calls[1]["encrypt"])
        self.assertTrue(calls[1]["no_cache"])
        self.assertIn("transport", calls[1])

    def test_onvif_client_error_detail_reports_safe_http_status(self):
        detail = _onvif_client_error_detail(
            "event topic read",
            RuntimeError("400 Client Error: malformed request; password=not-returned"),
        )

        self.assertEqual(detail, "ONVIF event topic read: camera returned HTTP 400")
        self.assertNotIn("not-returned", detail)

    def test_onvif_client_error_detail_handles_an_error_without_http_status(self):
        detail = _onvif_client_error_detail("event service setup", RuntimeError("unexpected response"))

        self.assertEqual(detail, "ONVIF event service setup failed (RuntimeError)")

    def test_probe_distinguishes_authentication_failure(self):
        settings = self.settings()
        base = "http://192.168.1.72"
        unauthorized = HTTPError(base, 401, "Unauthorized", {}, None)
        opener = FakeOpener({
            f"{base}/ISAPI/System/deviceInfo": unauthorized,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": unauthorized,
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": unauthorized,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search/capabilities": unauthorized,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search": unauthorized,
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection?format=json": unauthorized,
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
            f"{base}/ISAPI/Intelligent/capabilities": unreachable,
            f"{base}/ISAPI/Intelligent/channels/1/capabilities": unreachable,
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection/capabilities": unreachable,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": unreachable,
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": unreachable,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search/capabilities": unreachable,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search": unreachable,
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection?format=json": unreachable,
        })

        result = probe_people_counting(settings, opener=opener)

        self.assertFalse(result["ok"])
        self.assertFalse(result["connected"])
        self.assertIn("connection failed", result["message"].lower())

    def test_probe_identifies_restricted_report_interface(self):
        base = "http://192.168.1.72"
        denied = HTTPError(base, 403, "Forbidden", {}, None)
        opener = FakeOpener({
            f"{base}/ISAPI/System/deviceInfo": FakeResponse("<DeviceInfo><model>iDS-Test</model></DeviceInfo>"),
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/capabilities": HTTPError(base, 404, "Not Found", {}, None),
            f"{base}/ISAPI/Intelligent/channels/1/framesPeopleCounting/capabilities": denied,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search/capabilities": denied,
            f"{base}/ISAPI/System/Video/inputs/channels/1/counting/search": denied,
            f"{base}/ISAPI/Intelligent/channels/1/mixedTargetDetection?format=json": FakeResponse(
                '{"MixedTargetDetection":{"enabled":true}}'
            ),
        })

        result = probe_people_counting(self.settings(), opener=opener)

        self.assertTrue(result["ok"])
        self.assertIn("multi-target-type detection", result["message"].lower())

    def test_event_parser_keeps_only_counting_fields(self):
        event = parse_notification(
            b"<EventNotificationAlert><eventType>PeopleCounting</eventType><channelID>1</channelID>"
            b"<AtoB>2</AtoB><BtoA>1</BtoA><pictureURL>http://camera/private.jpg</pictureURL>"
            b"</EventNotificationAlert>"
        )

        self.assertEqual(event["event_type"], "PeopleCounting")
        self.assertEqual(event["counts"], {"atob": "2", "btoa": "1"})
        self.assertNotIn("pictureURL", event)
        self.assertNotIn("pictureURL", event["fields_seen"])

    def test_notification_diagnostic_does_not_keep_media_urls(self):
        diagnostic = notification_diagnostic(
            b"<EventNotificationAlert><eventType>VMD</eventType><eventState>active</eventState>"
            b"<pictureURL>http://camera/private.jpg</pictureURL></EventNotificationAlert>"
        )

        self.assertEqual(diagnostic["last_notification_type"], "VMD")
        self.assertEqual(diagnostic["last_notification_state"], "active")
        self.assertNotIn("pictureURL", diagnostic["last_notification_fields"])
        self.assertNotIn("private.jpg", str(diagnostic))

    def test_counter_value_parser_keeps_numeric_directional_totals(self):
        values = HikvisionEventCollector._counter_values({
            "humanAtoB": 12,
            "humanBtoA": 7,
            "vehicleAtoB": "4",
            "enabled": True,
        })

        self.assertEqual(values, {"human_atob": "12", "human_btoa": "7", "vehicle_atob": "4"})


if __name__ == "__main__":
    unittest.main()
