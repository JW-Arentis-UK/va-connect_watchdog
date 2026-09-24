"""One explicitly owned ONVIF subscription, using the packaged WSDLs."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


class PullSubscription:
    def __init__(self, settings):
        self.settings = settings
        self.stage = "client setup"
        self.session = None
        self.manager = None
        self.headers = []

    def _address(self, address):
        address = str(address)
        parsed = urlsplit(address)
        expected = str(self.settings["address"]).strip("[]").lower()
        if (parsed.scheme not in {"http", "https"} or parsed.hostname != expected
                or parsed.username or parsed.password
                or (self.settings.get("scheme") == "https" and parsed.scheme != "https")):
            raise ValueError("Camera returned an unexpected subscription host or protocol")
        return address

    def discover(self):
        from onvif import ONVIFCamera
        from onvif.client import UsernameDigestTokenDtDiff
        from requests import Session
        from requests.auth import HTTPDigestAuth
        from zeep import Client, Plugin, Settings
        from zeep.transports import Transport
        import inspect
        from .hikvision import _base_url

        # ONVIFCamera.__init__ creates an implicit subscription. Build services directly
        # to avoid leaked subscriptions and accidentally pulling from an old address.
        wsdl_dir = Path(inspect.signature(ONVIFCamera).parameters["wsdl_dir"].default)
        self.session = Session()
        self.session.trust_env = False
        self.session.auth = HTTPDigestAuth(self.settings["username"], self.settings["password"])
        transport = Transport(session=self.session, timeout=5, operation_timeout=5)
        self.transport = transport
        token = UsernameDigestTokenDtDiff(self.settings["username"], self.settings["password"], use_digest=True)
        options = Settings(strict=False, forbid_dtd=True, forbid_entities=True)
        device_client = Client(str(wsdl_dir / "devicemgmt.wsdl"), transport=transport, wsse=token, settings=options)
        device = device_client.create_service("{http://www.onvif.org/ver10/device/wsdl}DeviceBinding", _base_url(self.settings) + "/onvif/device_service")
        self.stage = "camera clock"
        clock = device.GetSystemDateAndTime().UTCDateTime
        if clock is not None:
            remote_time = datetime(clock.Date.Year, clock.Date.Month, clock.Date.Day,
                                   clock.Time.Hour, clock.Time.Minute, clock.Time.Second)
            token.dt_diff = remote_time - datetime.now(timezone.utc).replace(tzinfo=None)
        self.stage = "event discovery"
        capabilities = device.GetCapabilities(Category="All")
        self.pull_supported = getattr(capabilities.Events, "WSPullPointSupport", None) is True
        endpoint = self._address(capabilities.Events.XAddr)
        class NotificationCapture(Plugin):
            messages = None
            topics = None

            def ingress(self, envelope, http_headers, operation):
                # Zeep drops mixed text in TopicExpressionType. Preserve each XML
                # notification until the whitelist parser has reduced it.
                self.messages = list(envelope.iter("{http://docs.oasis-open.org/wsn/b-2}NotificationMessage"))
                self.topics = []
                for topic_set in envelope.iter("{http://www.onvif.org/ver10/events/wsdl}TopicSet"):
                    def visit(node, prefix=""):
                        name = node.tag.rsplit("}", 1)[-1]
                        path = f"{prefix}/{name}" if prefix else name
                        if node.get("{http://docs.oasis-open.org/wsn/t-1}topic") in {"true", "1"}:
                            self.topics.append(path[:200])
                        for child in node:
                            visit(child, path)
                    for child in topic_set:
                        visit(child)
                return envelope, http_headers

        self.capture = NotificationCapture()
        self.client = Client(str(wsdl_dir / "events.wsdl"), transport=transport, wsse=token,
                             settings=options, plugins=[self.capture])
        self.events = self.client.create_service("{http://www.onvif.org/ver10/events/wsdl}EventBinding", endpoint)

    def describe(self):
        self.discover()
        self.stage = "event topic read"
        self.events.GetEventProperties()
        topics = sorted(set(self.capture.topics or []))[:40]
        return {"available": True, "installed": True, "topics": topics, "pull_supported": self.pull_supported,
                "detail": f"Topic query succeeded; PullPoint advertised: {self.pull_supported}; topics: "
                          + (", ".join(topics) or "none decoded") + "; counting not verified"}

    def open(self):
        self.discover()
        if not self.pull_supported:
            raise ValueError("Camera does not advertise ONVIF PullPoint support")
        self.stage = "subscription creation (60-second lease)"
        # This is a requested lease, not evidence of firmware compatibility.
        # Only a successful response establishes a usable subscription.
        subscription = self.events.CreatePullPointSubscription(InitialTerminationTime="PT60S")
        address = subscription.SubscriptionReference.Address
        address = self._address(getattr(address, "_value_1", address))
        self.manager = self.client.create_service("{http://www.onvif.org/ver10/events/wsdl}SubscriptionManagerBinding", address)
        parameters = subscription.SubscriptionReference.ReferenceParameters
        for parameter in getattr(parameters, "_value_1", []) or []:
            header = deepcopy(parameter)
            header.set("{http://www.w3.org/2005/08/addressing}IsReferenceParameter", "true")
            self.headers.append(header)
        self.pullpoint = self.client.create_service("{http://www.onvif.org/ver10/events/wsdl}PullPointSubscriptionBinding", address)
        self._lease(subscription)
        self.transport.operation_timeout = 40

    def _lease(self, response):
        import time
        now = time.monotonic()
        current = response.CurrentTime
        if current is None:
            current = self.camera_time + timedelta(seconds=now - self.lease_checked_at)
        self.camera_time, self.lease_checked_at = current, now
        remaining = (response.TerminationTime - current).total_seconds()
        if remaining <= 0:
            raise ValueError("Camera returned an expired subscription")
        self.renew_at = now + remaining * 0.5
        self.poll_seconds = min(20, remaining * 0.25)

    def pull(self):
        import time
        if time.monotonic() >= self.renew_at:
            self.stage = "subscription renewal"
            response = self.manager.Renew(TerminationTime="PT60S", _soapheaders=self.headers)
            self._lease(response)
        self.stage = "pull messages"
        self.capture.messages = None
        response = self.pullpoint.PullMessages(Timeout=timedelta(seconds=self.poll_seconds), MessageLimit=32, _soapheaders=self.headers)
        messages = self.capture.messages
        self.capture.messages = None
        return messages if messages is not None else response.NotificationMessage or []

    def close(self):
        try:
            if self.manager is not None:
                self.transport.operation_timeout = 5
                self.manager.Unsubscribe(_soapheaders=self.headers)
        except Exception:
            pass
        finally:
            if self.session is not None:
                self.session.close()
