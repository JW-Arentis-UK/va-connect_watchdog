import copy
import io
import json
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import urlopen, Request

from va_watchdog.config import DEFAULT_CONFIG
from va_watchdog.hikvision import _request_xml, _get_json, probe_people_counting
from va_watchdog.hikvision_events import parse_notification, event_summary, HikvisionEventCollector, record_push_event
from va_watchdog.hikvision_push import configure_http_push, http_host_payload, metadata_documents
from va_watchdog.hikvision_native import (native_diagnostics, bounded_native_diagnostic, response_error,
                                        capture_request_paths, read_bounded, MAX_RESPONSE)
from va_watchdog.hikvision_stream import AlertParts
from va_watchdog.web import render_native_diagnostic, render_capture_state, start_web
from va_watchdog.web_smoke import check_setup
from test_hikvision import FakeOpener, FakeResponse


CAMERA = {"address": "192.168.1.72", "port": 80, "scheme": "http", "channel": 1,
          "username": "admin", "password": "test-secret", "event_collection_enabled": True}


def counting(enter=22, exit=9, stamp="2026-09-24T08:00:00+01:00", region="1", method="realTime"):
    # Field structure from Hikvision Multi-Target Counting Integration Solution,
    # pp. 19-20. Values/timestamps are test data, not a live camera capture.
    return f'''<EventNotificationAlert xmlns="urn:psialliance-org">
    <channelID>1</channelID><dateTime>{stamp}</dateTime><eventType>PeopleCounting</eventType>
    <peopleCounting><statisticalMethods>{method}</statisticalMethods>
    <enter>{enter}</enter><exit>{exit}</exit><vehicleEnter>176</vehicleEnter>
    <vehicleExit>159</vehicleExit><bicycleEnter>5</bicycleEnter><bicycleExit>3</bicycleExit>
    <pass>0</pass><regionsID>{region}</regionsID>
    <TimeRange><startTime>2026-09-24T08:00:00+01:00</startTime><endTime>2026-09-24T08:15:00+01:00</endTime></TimeRange>
    </peopleCounting></EventNotificationAlert>'''.encode()


def region_counting(forward=114, back=93, stamp="2026-09-24T08:00:00+01:00"):
    return f'''<EventNotificationAlert><channelID>1</channelID><dateTime>{stamp}</dateTime>
    <eventType>regionTargetNumberCounting</eventType><ruleID>1</ruleID><statisticalMethod>realTime</statisticalMethod>
    <CountingList><DataList><statisticalDirection>forward</statisticalDirection><humanCount>{forward}</humanCount>
    <nonMotorCount>18</nonMotorCount><vehicleCount>398</vehicleCount></DataList>
    <DataList><statisticalDirection>back</statisticalDirection><humanCount>{back}</humanCount>
    <nonMotorCount>12</nonMotorCount><vehicleCount>353</vehicleCount></DataList>
    <DataList><statisticalDirection>bothway</statisticalDirection><humanCount>{forward + back}</humanCount>
    <nonMotorCount>30</nonMotorCount><vehicleCount>751</vehicleCount></DataList></CountingList>
    </EventNotificationAlert>'''.encode()


def part(payload, kind=b"application/xml", length=True):
    headers = b"--test\r\nContent-Type: " + kind + b"\r\n"
    if length:
        headers += b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
    return headers + b"\r\n" + payload + b"\r\n"


class NativeTests(unittest.TestCase):
    def test_official_field_shape_preserves_counts_mode_rule_and_time(self):
        event = parse_notification(counting())
        self.assertEqual(event["counts"]["enter"], "22")
        self.assertEqual(event["counts"]["exit"], "9")
        self.assertEqual(event["region"], "1")
        self.assertEqual(event["method"], "realTime")
        self.assertTrue(event["schema_recognised"])
        self.assertFalse(event["counts_verified"])

    def test_json_capture_is_not_treated_as_a_crossing(self):
        event = parse_notification(b'{"eventType":"mixedTargetDetection","captureResult":[{"human":{"direction":"right","pictureURL":"secret-url"}}]}')
        self.assertEqual(event["counts"], {})
        self.assertFalse(event["schema_recognised"])
        self.assertNotIn("secret-url", json.dumps(event))

    def test_unknown_region_count_schema_exposes_only_safe_numeric_candidates(self):
        payload = region_counting().replace(b"</DataList>", b"<pictureURL>private-image</pictureURL></DataList>", 1)
        event = parse_notification(payload)
        self.assertEqual(event["counts"], {"forward": "114", "back": "93", "bothway": "207"})
        self.assertEqual(event["count_schema"], "region_forward_back")
        self.assertTrue(event["schema_recognised"])
        self.assertIn("humancount", event["fields_seen"])
        self.assertNotIn("pictureurl", event["fields_seen"])
        self.assertTrue(any(key.endswith("humancount") and value == "114 | 93 | 207"
                            for key, value in event["candidate_counters"].items()))
        self.assertEqual(event["count_records"], [
            {"direction": "forward", "human": "114", "non_motor": "18", "vehicle": "398"},
            {"direction": "back", "human": "93", "non_motor": "12", "vehicle": "353"},
            {"direction": "bothway", "human": "207", "non_motor": "30", "vehicle": "751"},
        ])
        self.assertNotIn("private-image", json.dumps(event))
        self.assertNotIn("192.168.1.72", json.dumps(event))

    def test_diagnostic_only_push_updates_state_without_growing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = {"events_path": str(Path(directory) / "events.jsonl"), "people_counting": CAMERA}
            event = parse_notification(b'''<EventNotificationAlert><eventType>regionTargetNumberCounting</eventType>
            <RegionTargetNumberCounting><humanNum>2</humanNum></RegionTargetNumberCounting></EventNotificationAlert>''')
            record_push_event(cfg, event)
            record_push_event(cfg, event)
            summary = event_summary(cfg)
            self.assertEqual(summary["notifications_received"], 2)
            self.assertIn("humannum", summary["last_notification_fields"])
            self.assertEqual(summary["today"]["events"], 0)
            self.assertFalse((Path(directory) / "hikvision-people-events.jsonl").exists())

    def test_region_count_checksum_mismatch_is_not_accepted_as_counts(self):
        event = parse_notification(region_counting().replace(b"<humanCount>207</humanCount>",
                                                              b"<humanCount>208</humanCount>"))
        self.assertEqual(event["counts"], {})
        self.assertFalse(event["schema_recognised"])

    def test_dtd_and_ambiguous_count_arrays_not_recognised(self):
        self.assertIsNone(parse_notification(b'<!DOCTYPE x [<!ENTITY x "bad">]><x/>'))
        payload = counting().replace(b"<enter>22</enter>", b"<enter>22</enter><enter>23</enter>")
        self.assertFalse(parse_notification(payload)["schema_recognised"])
        self.assertFalse(parse_notification(counting(-1))["schema_recognised"])

    def test_multipart_fragments_discard_images_and_preserve_xml_json(self):
        data = part(b"image bytes " * 10000, b"image/jpeg") + part(counting()) + part(b'{"eventType":"VMD"}', b"application/json", False) + b"--test--\r\n"
        parser = AlertParts('multipart/mixed; boundary="test"')
        messages = []
        for offset in range(0, len(data), 7):
            messages.extend(parser.feed(data[offset:offset + 7]))
            self.assertLess(len(parser.buffer), 9000)
        self.assertEqual(messages, [counting(), b'{"eventType":"VMD"}'])

    def test_multipart_oversize_metadata_is_rejected(self):
        parser = AlertParts("multipart/mixed; boundary=test")
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            parser.feed(part(b"x" * (MAX_RESPONSE + 1)))
        with self.assertRaises(ValueError):
            AlertParts("application/xml")

    def test_false_capability_and_error_status_are_not_success(self):
        root = "http://192.168.1.72"
        outcome = probe_people_counting(CAMERA, FakeOpener({root + '/ISAPI/Intelligent/channels/1/capabilities':
            FakeResponse('<Cap><isSupportPeopleCounting>false</isSupportPeopleCounting></Cap>')}))
        self.assertFalse(outcome["capabilities"][1]["supported"])
        self.assertIn("false", outcome["capabilities"][1]["detail"])
        error = '<ResponseStatus><statusCode>4</statusCode><subStatusCode>notSupport</subStatusCode></ResponseStatus>'
        response = _request_xml(FakeOpener({root: FakeResponse(error)}), root, 1)
        self.assertFalse(response["ok"])
        self.assertIn("notSupport", response["detail"])
        response = _get_json(FakeOpener({root: FakeResponse('{"statusCode":4,"subStatusCode":"badJsonContent"}')}), root, 1)
        self.assertFalse(response["ok"])
        success = b'<ResponseStatus><statusCode>0</statusCode><statusString>OK</statusString><subStatusCode>ok</subStatusCode></ResponseStatus>'
        self.assertEqual(response_error(success), "")

    def test_http_error_keeps_protocol_status(self):
        url = "http://camera.invalid"
        body = b'<ResponseStatus><statusCode>4</statusCode><subStatusCode>invalidOperation</subStatusCode></ResponseStatus>'
        response = _request_xml(FakeOpener({url: HTTPError(url,403,"Forbidden",{},io.BytesIO(body))}), url, 1)
        self.assertIn("invalidOperation", response["detail"])

    def test_native_diagnostic_only_gets_and_hides_credentials(self):
        base = "http://192.168.1.72/ISAPI/Event/notification/httpHosts"
        client = FakeOpener({
            base: FakeResponse('<HttpHosts><HttpHost><id>1</id><ipAddress>192.168.1.100</ipAddress><portNo>9110</portNo><password>test-secret</password><url>/secret-token</url></HttpHost></HttpHosts>'),
            base + '/capabilities': FakeResponse('<HttpHostNotificationCap xmlns="urn:test"><portNo min="1" max="65535"/><parameterFormatType opt="XML,JSON"/></HttpHostNotificationCap>'),
            base + '/1': FakeResponse('<HttpHostNotification xmlns="urn:test"><id>1</id><protocolType>HTTP</protocolType><parameterFormatType>XML</parameterFormatType><userName>admin</userName><password>test-secret</password><url>/secret-token</url></HttpHostNotification>'),
        })
        result = native_diagnostics(CAMERA, client)
        self.assertEqual(len(result["requests"]), 9)
        self.assertTrue(all(method == "GET" for _, _, method in client.urls))
        self.assertIn("192.168.1.100", str(result))
        self.assertNotIn("test-secret", str(result))
        self.assertNotIn("secret-token", str(result))
        self.assertTrue(any("RegionTargetNumberCounting/Capabilities?format=json" in url for url, _, _ in client.urls))
        self.assertTrue(any("subscribeEventCap" in url for url, _, _ in client.urls))
        self.assertIn("parameterFormatType[opt=XML,JSON]", str(result))
        self.assertIn("fields=id,protocolType,parameterFormatType,userName,password,url", str(result))

    def test_http_push_configuration_uses_documented_event_and_preserves_backup(self):
        class SequenceOpener:
            def __init__(self):
                self.requests = []
            def open(self, request, timeout):
                self.requests.append(request)
                if request.get_method() == "GET":
                    return FakeResponse('<HttpHostNotificationList><HttpHostNotification><id>1</id><url></url><protocolType>HTTP</protocolType><parameterFormatType>XML</parameterFormatType><addressingFormatType>ipaddress</addressingFormatType><ipAddress>0.0.0.0</ipAddress><portNo>80</portNo><userName></userName><httpAuthenticationMethod>none</httpAuthenticationMethod><httpBroken>true</httpBroken></HttpHostNotification><HttpHostNotification><id>2</id><url></url><protocolType>HTTP</protocolType><parameterFormatType>XML</parameterFormatType><addressingFormatType>ipaddress</addressingFormatType><ipAddress>0.0.0.0</ipAddress><portNo>80</portNo><userName></userName><httpAuthenticationMethod>none</httpAuthenticationMethod><httpBroken>true</httpBroken></HttpHostNotification></HttpHostNotificationList>')
                return FakeResponse('<ResponseStatus><statusCode>1</statusCode><subStatusCode>ok</subStatusCode></ResponseStatus>')
        opener = SequenceOpener()
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'host.xml'
            result = configure_http_push(CAMERA, "192.168.1.100", 9110, opener=opener, backup_path=backup)
            self.assertTrue(result["ok"])
            self.assertIn(b"0.0.0.0", backup.read_bytes())
        body = opener.requests[1].data
        self.assertIn(b"<parameterFormatType>XML</parameterFormatType>", body)
        self.assertIn(b"192.168.1.100", body)
        self.assertIn(b"<url>/hikvision/events</url>", body)
        self.assertNotIn(b"http://192.168.1.100", body)
        self.assertNotIn(b"regionTargetNumberCounting", body)
        self.assertNotIn(b"SubscribeEvent", body)
        self.assertNotIn(b"password", body)
        self.assertIn(b"<userName></userName>", body)
        self.assertNotIn(b"<userName />", body)
        self.assertIn(b"<httpBroken>true</httpBroken>", body)
        self.assertNotIn(CAMERA["password"].encode(), body)
        self.assertEqual(opener.requests[1].get_method(), "PUT")
        self.assertTrue(opener.requests[1].full_url.endswith("/ISAPI/Event/notification/httpHosts"))
        self.assertEqual(body.count(b"192.168.1.100"), 1)

        class RejectingOpener(SequenceOpener):
            def open(self, request, timeout):
                if request.get_method() == "GET":
                    return super().open(request, timeout)
                body = b'<ResponseStatus><statusCode>6</statusCode><subStatusCode>badXmlContent</subStatusCode></ResponseStatus>'
                raise HTTPError(request.full_url, 400, "Bad Request", {}, io.BytesIO(body))
        with self.assertRaisesRegex(RuntimeError, "badXmlContent"):
            configure_http_push(CAMERA, "192.168.1.100", 9110, opener=RejectingOpener())

        self.assertEqual(result["profile"], "camera host list")

    def test_push_multipart_discards_media(self):
        payload = part(b"private-image", b"image/jpeg") + part(counting()) + b"--test--\r\n"
        self.assertEqual(metadata_documents("multipart/mixed; boundary=test", payload), [counting()])
        self.assertIn(b"<eventMode>all</eventMode>", http_host_payload(1, "192.168.1.100", 9110, 1))

    def test_authentication_failure_stops_further_diagnostic_requests(self):
        url = "http://192.168.1.72/ISAPI/System/deviceInfo"
        client = FakeOpener({url: HTTPError(url,401,"Unauthorized",{},io.BytesIO(b""))})
        result = native_diagnostics(CAMERA, client)
        self.assertEqual(len(client.urls), 1)
        self.assertIn("authentication failed", result["requests"][-1]["detail"])

    def test_deadline_and_size_are_bounded(self):
        client = FakeOpener({})
        with patch("va_watchdog.hikvision_native.time.monotonic", side_effect=[0] + [40] * 9):
            result = native_diagnostics(CAMERA, client)
        self.assertEqual(client.urls, [])
        self.assertIn("budget", result["requests"][0]["detail"])
        with self.assertRaises(ValueError):
            read_bounded(FakeResponse("x" * (MAX_RESPONSE + 1)), 999999999)

    def test_slow_diagnostic_does_not_block_ui_or_start_duplicates(self):
        gate, finished = threading.Event(), threading.Event()
        def slow(_settings):
            gate.wait(2)
            finished.set()
            return {"message": "complete", "requests": []}
        result = bounded_native_diagnostic(CAMERA, slow, wait_seconds=.01)
        self.assertIn("timed out", result["message"])
        self.assertIn("still running", bounded_native_diagnostic(CAMERA, slow)["message"])
        gate.set()
        self.assertTrue(finished.wait(2))

    def test_capture_decodes_linux_timeout_and_strips_queries(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("tcpdump",60,output=b"GET /ISAPI/count?password=secret HTTP/1.1\n"))
        result = capture_request_paths(CAMERA, runner)
        self.assertEqual(result["paths"], ["/ISAPI/count"])
        self.assertNotIn("secret", str(result))

    def test_capture_failures_are_not_empty_success(self):
        result = capture_request_paths(CAMERA, Mock(return_value=Mock(returncode=1, stdout="", stderr="permission denied")))
        self.assertEqual(result["status"], "failed")
        runner = Mock()
        self.assertEqual(capture_request_paths({**CAMERA, "scheme":"https"}, runner)["status"], "failed")
        runner.assert_not_called()

    def test_corrupt_capture_state_and_html_are_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            path.write_text('{bad', encoding='utf-8')
            self.assertIn("could not be read", render_capture_state(path))
        result = {"requests":[{"name":"<script>","detail":"<script>"}]}
        self.assertNotIn("<script>", render_native_diagnostic(result))

    def test_default_worker_uses_native_not_onvif(self):
        collector = HikvisionEventCollector({"people_counting":CAMERA}, Mock())
        with patch.object(collector, '_stream', side_effect=KeyboardInterrupt) as native, patch.object(collector, '_onvif_stream') as onvif:
            with self.assertRaises(KeyboardInterrupt):
                collector._run()
        native.assert_called_once()
        onvif.assert_not_called()

    def test_native_listener_receives_counts_and_closes_response(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = {"events_path":str(Path(directory)/'events.jsonl'), 'people_counting':dict(CAMERA)}
            collector = HikvisionEventCollector(cfg, Mock())
            response = Mock(headers={'Content-Type':'multipart/mixed; boundary=test'})
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read1.side_effect = [part(counting()) + b'--test\r\n', b'']
            opener = Mock()
            opener.open.return_value = response
            with patch('va_watchdog.hikvision_events._digest_opener', return_value=opener):
                with self.assertRaisesRegex(OSError, 'closed'):
                    collector._stream(cfg['people_counting'])
            state = event_summary(cfg)
            self.assertEqual(state['notifications_received'], 1)
            self.assertEqual(state['last_reported_counts']['enter'], '22')
            self.assertEqual(state['transport'], 'ISAPI alertStream')
            response.__exit__.assert_called_once()

    def test_counting_capabilities_prioritised_over_unrelated_flags(self):
        payload = '<Cap>' + ''.join(f'<flag{i}>true</flag{i}>' for i in range(100)) + '<isSupportRegionTargetNumberCounting>false</isSupportRegionTargetNumberCounting><eventType opt="PeopleCounting,VMD">VMD</eventType></Cap>'
        client = FakeOpener({'http://192.168.1.72/ISAPI/System/capabilities?type=all':FakeResponse(payload)})
        result = native_diagnostics(CAMERA, client)
        detail = result['requests'][1]['detail']
        self.assertIn('isSupportRegionTargetNumberCounting=false', detail)
        self.assertIn('PeopleCounting,VMD', detail)


class CounterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cfg = {"events_path":str(Path(self.directory.name)/'events.jsonl'), "people_counting":CAMERA}
        self.collector = HikvisionEventCollector(self.cfg, Mock())
        self.now = datetime(2026,9,24,12,tzinfo=timezone(timedelta(hours=1)))

    def record(self, *args, **kwargs):
        event = parse_notification(counting(*args, **kwargs))
        event['camera'] = CAMERA['address']
        self.collector._record(event)
        return event

    def test_cumulative_repeats_and_restart_use_persisted_baseline(self):
        self.record(22,9)
        self.record(23,10, stamp='2026-09-24T08:01:00+01:00')
        self.record(23,10, stamp='2026-09-24T08:01:00+01:00')
        self.collector = HikvisionEventCollector(self.cfg, Mock())
        self.record(24,10, stamp='2026-09-24T08:02:00+01:00')
        summary = event_summary(self.cfg, self.now)
        self.assertEqual(summary['today']['observed_enter'], 2)
        self.assertEqual(summary['today']['observed_exit'], 1)
        self.assertEqual(summary['today']['a_to_b'], 0)
        self.assertFalse(summary['counts_verified'])

    def test_rules_resets_and_out_of_order_do_not_inflate(self):
        self.record(22,9)
        self.record(100,90, region='2')
        self.record(2,1, stamp='2026-09-24T08:02:00+01:00')
        self.record(23,10, stamp='2026-09-24T08:01:00+01:00')
        self.record(3,2, stamp='2026-09-24T08:03:00+01:00')
        summary = event_summary(self.cfg, self.now)
        self.assertEqual(summary['today']['observed_enter'], 1)
        self.assertEqual(summary['counter_resets'], 1)

    def test_interval_retransmissions_are_separate_from_realtime(self):
        self.record(22,9)
        self.record(23,10, stamp='2026-09-24T08:01:00+01:00')
        self.record(5,2, method='timeRange')
        self.record(5,2, method='timeRange')
        summary = event_summary(self.cfg, self.now)
        self.assertEqual(summary['today']['observed_enter'], 1)
        self.assertEqual(summary['today']['interval_enter'], 5)
        self.assertEqual(summary['interval_reports'], 1)

    def test_local_day_is_not_utc_string_prefix(self):
        self.record(22,9, stamp='2026-09-23T23:01:00Z')
        self.record(23,10, stamp='2026-09-23T23:02:00Z')
        self.assertEqual(event_summary(self.cfg, self.now)['today']['observed_enter'], 1)

    def test_region_forward_back_repeats_produce_safe_cumulative_deltas(self):
        record_push_event(self.cfg, parse_notification(region_counting()))
        record_push_event(self.cfg, parse_notification(region_counting(115, 93, "2026-09-24T08:01:00+01:00")))
        record_push_event(self.cfg, parse_notification(region_counting(115, 93, "2026-09-24T08:02:00+01:00")))
        summary = event_summary(self.cfg, self.now)
        self.assertEqual(summary["today"]["observed_forward"], 1)
        self.assertEqual(summary["today"]["observed_back"], 0)


class SetupSmokeTests(unittest.TestCase):
    def test_http_smoke_rejects_500_and_accepts_real_setup(self):
        bad = Mock()
        bad.open.side_effect = HTTPError('http://localhost',500,'Error',{},None)
        with self.assertRaises(RuntimeError):
            check_setup(DEFAULT_CONFIG, attempts=1, opener=bad)
        with tempfile.TemporaryDirectory() as directory:
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            for key in cfg:
                if key.endswith('_path'):
                    cfg[key] = str(Path(directory)/Path(cfg[key]).name)
            cfg['web'] = {'enabled':True,'host':'127.0.0.1','port':0}
            cfg['people_counting'] = dict(CAMERA)
            cfg['people_counting']['push_receiver_address'] = '127.0.0.1'
            cfg['people_counting']['push_slot'] = 1
            server = start_web(cfg)
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                with urlopen(base+'/setup', timeout=10) as response:
                    body = response.read().decode()
                    self.assertIn('Run native API diagnostic', body)
                    self.assertIn('Native ISAPI alert stream', body)
                    self.assertIn('Camera HTTP push', body)
                    self.assertIn('Configure camera HTTP delivery', body)
                    self.assertNotIn('test-secret', body)
                with patch('va_watchdog.web.bounded_native_diagnostic', return_value={'requests':[], 'message':'Native check finished'}) as diagnostic:
                    with urlopen(Request(base+'/hikvision-native-diagnostic', data=b''), timeout=10) as response:
                        self.assertEqual(response.status, 200)
                        self.assertIn(b'Native check finished', response.read())
                    diagnostic.assert_called_once()
                with urlopen(base + '/hikvision-push-confirm', timeout=10) as response:
                    self.assertIn(b'only received counting metadata is retained', response.read())
                with patch('va_watchdog.web.configure_http_push', return_value={
                    'ok': True, 'message': 'Configured', 'url': base + '/hikvision/events',
                    'slot': 1, 'backup_path': str(Path(directory) / 'backup.xml'),
                }) as configure:
                    request = Request(base + '/hikvision-push-configure', data=b'ack=1',
                                      headers={'Content-Type': 'application/x-www-form-urlencoded'})
                    with urlopen(request, timeout=10) as response:
                        self.assertIn(b'Configured', response.read())
                    configure.assert_called_once()
                cfg['web']['port'] = server.server_port
                check_setup(cfg, attempts=1)
            finally:
                server.shutdown()
                server.server_close()

    def test_http_push_receiver_accepts_only_configured_camera_and_reduces_event(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = copy.deepcopy(DEFAULT_CONFIG)
            for key in cfg:
                if key.endswith('_path'):
                    cfg[key] = str(Path(directory) / Path(cfg[key]).name)
            cfg['web'] = {'enabled': True, 'host': '127.0.0.1', 'port': 0}
            cfg['people_counting'] = {**CAMERA, 'address': '127.0.0.1', 'event_transport': 'http_push',
                                      'push_receiver_address': '127.0.0.1', 'push_slot': 1}
            server = start_web(cfg)
            try:
                request = Request(f'http://127.0.0.1:{server.server_port}/hikvision/events', data=counting(),
                                  headers={'Content-Type': 'application/xml'})
                with urlopen(request, timeout=10) as response:
                    self.assertEqual(json.loads(response.read())['accepted'], 1)
                summary = event_summary(cfg)
                self.assertEqual(summary['transport'], 'HTTP push')
                self.assertEqual(summary['last_reported_counts']['enter'], '22')
                history = Path(directory) / 'hikvision-people-events.jsonl'
                self.assertNotIn('private-image', history.read_text(encoding='utf-8'))
            finally:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    unittest.main()
