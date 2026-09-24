import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from va_watchdog.hikvision_events import HikvisionEventCollector, event_summary, parse_onvif_notification
from va_watchdog.onvif_pull import PullSubscription
from va_watchdog.web import render_camera_collector

CAMERA = {"address": "192.168.1.72", "username": "admin", "password": "test-secret",
          "port": 80, "scheme": "http", "event_collection_enabled": True}
NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "tev": "http://www.onvif.org/ver10/events/wsdl",
    "wsnt": "http://docs.oasis-open.org/wsn/b-2",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "cam": "urn:test-camera",
}
NOTIFICATION = '''<wsnt:NotificationMessage>
  <wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">tns1:RuleEngine/PeopleCounting/Counter</wsnt:Topic>
  <wsnt:Message><tt:Message UtcTime="2026-09-24T08:00:00Z" PropertyOperation="Initialized">
    <tt:Source><tt:SimpleItem Name="Rule" Value="line1"/></tt:Source>
    <tt:Data><tt:SimpleItem Name="AtoB" Value="93"/><tt:SimpleItem Name="BtoA" Value="3"/>
    <tt:SimpleItem Name="PictureURL" Value="http://private/image.jpg"/></tt:Data>
  </tt:Message></wsnt:Message>
</wsnt:NotificationMessage>'''


class PullWireTests(unittest.TestCase):
    """Exercise real installed WSDL serialization and SOAP response decoding."""

    def setUp(self):
        try:
            import zeep  # noqa: F401
            import onvif  # noqa: F401
        except ImportError:
            self.skipTest("Install v3/requirements.txt for ONVIF wire tests")
        self.calls = []
        self.subscription_address = "http://192.168.1.72/onvif/subscription?id=7"
        self.fail_pull = False
        self.fail_renew = False

    def post(self, address, message, headers):
        from lxml import etree
        from requests import Response
        root = etree.fromstring(message)
        operation = etree.QName(root.find("s:Body", NS)[0]).localname
        self.calls.append((operation, address, root))
        status_code = 200
        if operation == "GetSystemDateAndTime":
            body = '''<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime>
            <tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings>
            <tt:UTCDateTime><tt:Time><tt:Hour>8</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time>
            <tt:Date><tt:Year>2026</tt:Year><tt:Month>9</tt:Month><tt:Day>24</tt:Day></tt:Date></tt:UTCDateTime>
            </tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>'''
        elif operation == "GetCapabilities":
            body = '''<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Events>
            <tt:XAddr>http://192.168.1.72/onvif/Events</tt:XAddr><tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport>
            <tt:WSPullPointSupport>true</tt:WSPullPointSupport><tt:WSPausableSubscriptionManagerInterfaceSupport>false</tt:WSPausableSubscriptionManagerInterfaceSupport>
            </tt:Events></tds:Capabilities></tds:GetCapabilitiesResponse>'''
        elif operation == "CreatePullPointSubscription":
            body = f'''<tev:CreatePullPointSubscriptionResponse><tev:SubscriptionReference>
            <wsa:Address>{self.subscription_address}</wsa:Address>
            <wsa:ReferenceParameters><cam:SubscriptionId>7</cam:SubscriptionId></wsa:ReferenceParameters>
            </tev:SubscriptionReference><wsnt:CurrentTime>2026-09-24T08:00:00Z</wsnt:CurrentTime>
            <wsnt:TerminationTime>2026-09-24T08:01:00Z</wsnt:TerminationTime></tev:CreatePullPointSubscriptionResponse>'''
            lease = root.find("s:Body/tev:CreatePullPointSubscription/tev:InitialTerminationTime", NS)
            if lease is None:
                status_code = 500
                body = '''<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode>
                <s:Value>cam:InvalidArgVal</s:Value></s:Subcode></s:Code>
                <s:Reason><s:Text xml:lang="en">the parameter value is illegal</s:Text></s:Reason></s:Fault>'''
            else:
                self.assertEqual(lease.text, "PT60S")
                self.assertIsNone(root.find("s:Body/tev:CreatePullPointSubscription/tev:Filter", NS))
                self.assertIsNone(root.find("s:Body/tev:CreatePullPointSubscription/tev:SubscriptionPolicy", NS))
        elif operation == "PullMessages":
            if self.fail_pull:
                raise OSError("camera disconnected")
            body = f'''<tev:PullMessagesResponse><tev:CurrentTime>2026-09-24T08:00:01Z</tev:CurrentTime>
            <tev:TerminationTime>2026-09-24T08:01:00Z</tev:TerminationTime>{NOTIFICATION}</tev:PullMessagesResponse>'''
        elif operation == "Renew":
            if self.fail_renew:
                raise OSError("renewal rejected")
            body = '''<wsnt:RenewResponse><wsnt:TerminationTime>2026-09-24T08:02:00Z</wsnt:TerminationTime>
            </wsnt:RenewResponse>'''
        elif operation == "Unsubscribe":
            body = "<wsnt:UnsubscribeResponse/>"
        else:
            self.fail(f"Unexpected operation: {operation}")
        response = Response()
        response.status_code = status_code
        response.headers["Content-Type"] = "application/soap+xml"
        declarations = " ".join(f'xmlns:{prefix}="{uri}"' for prefix, uri in NS.items())
        response._content = f"<s:Envelope {declarations}><s:Body>{body}</s:Body></s:Envelope>".encode()
        return response

    def test_camera_fixture_rejects_previous_empty_subscription_request(self):
        from zeep.exceptions import Fault
        with patch("zeep.transports.Transport.post", side_effect=self.post):
            subscription = PullSubscription(CAMERA)
            try:
                subscription.open()
                events = subscription.client.create_service(
                    "{http://www.onvif.org/ver10/events/wsdl}EventBinding", "http://192.168.1.72/onvif/Events")
                with self.assertRaisesRegex(Fault, "the parameter value is illegal") as caught:
                    events.CreatePullPointSubscription()
                self.assertEqual(caught.exception.subcodes[0].localname, "InvalidArgVal")
            finally:
                subscription.close()

    def test_single_subscription_real_duration_parser_renewal_and_cleanup(self):
        with patch("zeep.transports.Transport.post", side_effect=self.post):
            subscription = PullSubscription(CAMERA)
            try:
                subscription.open()
                event = parse_onvif_notification(subscription.pull()[0])
                self.assertEqual(event["counts"], {"atob": "93", "btoa": "3"})
                self.assertEqual(event["property_operation"], "Initialized")
                self.assertIn("PeopleCounting", event["event_type"])
                self.assertNotIn("private/image", json.dumps(event))
                self.assertFalse(event["counts_verified"])
                subscription.renew_at = 0
                subscription.pull()
            finally:
                subscription.close()
        self.assertEqual([c[0] for c in self.calls], ["GetSystemDateAndTime", "GetCapabilities",
                         "CreatePullPointSubscription", "PullMessages", "Renew", "PullMessages", "Unsubscribe"])
        for operation, address, root in self.calls[3:]:
            self.assertEqual(address, self.subscription_address)
            reference = root.find("s:Header/cam:SubscriptionId", NS)
            self.assertEqual(reference.text, "7")
            self.assertEqual(reference.get("{" + NS["wsa"] + "}IsReferenceParameter"), "true")
            if operation == "PullMessages":
                timeout = root.find("s:Body/tev:PullMessages/tev:Timeout", NS).text
                self.assertIn(timeout, {"PT15S", "PT20S"})
            passwords = root.xpath("//*[local-name()='Password']")
            self.assertEqual(len(passwords), 1)
            self.assertTrue(passwords[0].get("Type").endswith("#PasswordDigest"))
            self.assertNotEqual(passwords[0].text, CAMERA["password"])

    def test_renewal_failure_does_not_pull_expired_subscription(self):
        with patch("zeep.transports.Transport.post", side_effect=self.post):
            subscription = PullSubscription(CAMERA)
            try:
                subscription.open()
                subscription.renew_at = 0
                self.fail_renew = True
                with self.assertRaisesRegex(OSError, "renewal rejected"):
                    subscription.pull()
                self.assertEqual(subscription.stage, "subscription renewal")
            finally:
                subscription.close()
        self.assertEqual([c[0] for c in self.calls][-2:], ["Renew", "Unsubscribe"])
        self.assertNotIn("PullMessages", [c[0] for c in self.calls])

    def test_transport_timeout_is_bounded_and_pull_failure_is_cleaned_up(self):
        with patch("zeep.transports.Transport.post", side_effect=self.post):
            subscription = PullSubscription(CAMERA)
            try:
                subscription.open()
                self.assertEqual(subscription.transport.operation_timeout, 40)
                self.assertFalse(subscription.session.trust_env)
                self.fail_pull = True
                with self.assertRaisesRegex(OSError, "camera disconnected"):
                    subscription.pull()
            finally:
                subscription.close()
        self.assertEqual(self.calls[-1][0], "Unsubscribe")

    def test_empty_poll_is_a_successful_connection_not_a_count(self):
        with patch("zeep.transports.Transport.post", side_effect=self.post), patch.dict(globals(), NOTIFICATION=""):
            subscription = PullSubscription(CAMERA)
            try:
                subscription.open()
                self.assertEqual(subscription.pull(), [])
            finally:
                subscription.close()

    def test_off_camera_subscription_is_rejected(self):
        self.subscription_address = "http://other-host/onvif/subscription"
        with patch("zeep.transports.Transport.post", side_effect=self.post):
            subscription = PullSubscription(CAMERA)
            try:
                with self.assertRaisesRegex(ValueError, "unexpected subscription host"):
                    subscription.open()
            finally:
                subscription.close()
        self.assertNotIn("PullMessages", [c[0] for c in self.calls])


class CollectorLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cfg = {"events_path": str(Path(self.directory.name) / "events.jsonl"), "people_counting": dict(CAMERA)}
        self.collector = HikvisionEventCollector(self.cfg, Mock())

    def test_configuration_change_closes_subscription(self):
        sub = Mock()
        def pull():
            self.cfg["people_counting"]["event_collection_enabled"] = False
            return []
        sub.pull.side_effect = pull
        self.collector._onvif_stream(CAMERA, lambda _: sub)
        sub.open.assert_called_once()
        sub.pull.assert_called_once()
        sub.close.assert_called_once()

    def test_failed_pull_preserves_stage_and_hides_password(self):
        sub = Mock(stage="pull messages")
        sub.pull.side_effect = OSError("rejected test-secret <SOAP>private</SOAP>")
        with self.assertRaises(OSError):
            self.collector._onvif_stream(CAMERA, lambda _: sub)
        state = event_summary(self.cfg)
        self.assertEqual(state["status"], "reconnecting")
        self.assertIn("pull messages", state["last_error"])
        self.assertNotIn("test-secret", state["last_error"])
        self.assertNotIn("private", state["last_error"])
        sub.close.assert_called_once()

    def test_open_failure_also_cleans_up(self):
        sub = Mock(stage="subscription creation")
        sub.open.side_effect = ValueError("no lease")
        with self.assertRaises(ValueError):
            self.collector._onvif_stream(CAMERA, lambda _: sub)
        sub.close.assert_called_once()
        sub.pull.assert_not_called()

    def test_soap_fault_subcode_survives_in_collector_error(self):
        error = RuntimeError("the parameter value is illegal")
        error.code = "s:Sender"
        error.subcodes = ["{urn:camera}InvalidArgVal"]
        sub = Mock(stage="subscription creation (60-second lease)")
        sub.open.side_effect = error
        with self.assertRaises(RuntimeError):
            self.collector._onvif_stream(CAMERA, lambda _: sub)
        message = event_summary(self.cfg)["last_error"]
        self.assertIn("60-second lease", message)
        self.assertIn("Sender / InvalidArgVal", message)
        self.assertIn("the parameter value is illegal", message)

    def test_unverified_repeated_totals_are_not_added_as_crossings(self):
        event = parse_onvif_notification({"Topic": {"_value_1": "PeopleCounting"},
                                          "Message": {"SimpleItem": [{"Name": "AtoB", "Value": "93"}]}})
        self.collector._record(event)
        self.collector._record(event)
        summary = event_summary(self.cfg)
        self.assertEqual(summary["today"]["a_to_b"], 0)
        self.assertEqual(summary["today"]["events"], 2)

    def test_only_one_collector_owns_state(self):
        self.collector.thread = Mock()
        self.collector.counter_thread = Mock()
        self.collector.metadata_thread = Mock()
        self.collector.start()
        self.collector.thread.start.assert_called_once()
        self.collector.counter_thread.start.assert_not_called()
        self.collector.metadata_thread.start.assert_not_called()

    def test_status_renderer_exposes_error_safely_and_does_not_claim_zero_people(self):
        html = render_camera_collector({"status": "reconnecting", "last_error": "pull messages: <error>",
                                        "counts_verified": False, "notifications_received": 0})
        self.assertIn("pull messages: &lt;error&gt;", html)
        self.assertNotIn("<error>", html)
        self.assertIn("Directional totals not verified", html)
        self.assertNotIn("A to B: 0", html)
        self.assertIn("notifications this connection: 0", html)
        self.assertIn(">Waiting<", html)
        self.assertIn(">Listening<", render_camera_collector({"status": "ONVIF listening"}))


if __name__ == "__main__":
    unittest.main()
