"""Read only Hikvision multi-target event collection.

The camera owns analytics and video.  This listener records a compact, safe
description of notification events so the watchdog can build its own totals.
"""
from __future__ import annotations

import json
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .hikvision import _base_url, _digest_opener
from .onvif_pull import PullSubscription
from .hikvision_native import decode_document, scalar_fields
from .hikvision_stream import AlertParts


_history_lock = threading.Lock()


_VALUE_FIELDS = {
    "eventtype", "eventstate", "channelid", "channel", "targettype", "direction",
    "entercount", "leavecount", "incount", "outcount", "passcount", "passingcount",
    "atob", "btoa", "eventdescription",
    "enter", "exit", "pass", "vehicleenter", "vehicleexit", "bicycleenter", "bicycleexit",
    "statisticalmethods", "regionsid", "ruleid", "datetime", "starttime", "endtime",
}
_COUNT_FIELDS = {"entercount", "leavecount", "incount", "outcount", "passcount", "passingcount", "atob", "btoa",
                 "enter", "exit", "pass", "vehicleenter", "vehicleexit", "bicycleenter", "bicycleexit"}
_DIAGNOSTIC_COUNT_HINTS = ("count", "number", "num", "enter", "exit", "human", "people", "person",
                           "pedestrian", "vehicle", "bicycle")
_SENSITIVE_DIAGNOSTIC_HINTS = ("password", "secret", "token", "cookie", "authorization", "username",
                               "serial", "macaddress", "ipaddress", "url", "picture", "image", "deviceid",
                               "uuid")
_COUNTER_PATHS = (
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/statistics",
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/counting",
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/counts",
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/status",
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/peopleCounting",
    "/ISAPI/Intelligent/channels/{channel}/mixedTargetDetection/lineCounting",
)


def _name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _scalar_paths(value: Any, path: tuple[str, ...] = ()):
    """Yield leaf paths for schema diagnosis without retaining a source document."""
    if isinstance(value, ET.Element):
        current = path + (_name(value.tag),)
        children = list(value)
        if children:
            for child in children:
                yield from _scalar_paths(child, current)
        else:
            yield current, (value.text or "").strip()
    elif isinstance(value, dict):
        for key, item in value.items():
            current = path + (str(key),)
            if isinstance(item, (dict, list)):
                yield from _scalar_paths(item, current)
            else:
                yield current, str(item).lower() if isinstance(item, bool) else str(item)
    elif isinstance(value, list):
        for item in value:
            yield from _scalar_paths(item, path)


def _safe_event_shape(document: Any) -> tuple[list[str], dict[str, str]]:
    """Return bounded field names and numeric candidates, excluding private metadata."""
    fields: set[str] = set()
    candidates: dict[str, list[str]] = {}
    for path, value in _scalar_paths(document):
        names = [re.sub(r"[^a-z0-9]", "", name.lower())[:80] for name in path]
        names = [name for name in names if name]
        if not names or any(hint in name for name in names for hint in _SENSITIVE_DIAGNOSTIC_HINTS):
            continue
        field = names[-1]
        fields.add(field)
        if (not re.fullmatch(r"-?\d{1,12}", value.strip())
                or not any(hint in field for hint in _DIAGNOSTIC_COUNT_HINTS)):
            continue
        label = ".".join(names[-4:])[:240]
        values = candidates.setdefault(label, [])
        if value not in values and len(values) < 3:
            values.append(value)
    reduced = {key: " | ".join(values) for key, values in sorted(candidates.items())[:30]}
    return sorted(fields)[:80], reduced


def parse_notification(payload: bytes) -> dict[str, Any] | None:
    """Return whitelisted fields only; payloads can contain private media URLs."""
    try:
        root = decode_document(payload)
    except (ValueError, ET.ParseError):
        return None
    values: dict[str, str] = {}
    duplicates = set()
    for key, text in scalar_fields(root):
        lowered = key.lower()
        if lowered in _VALUE_FIELDS and text:
            if lowered in values:
                duplicates.add(lowered)
            values[lowered] = text[:160]
    diagnostic_fields, candidate_counters = _safe_event_shape(root)
    event_type = values.get("eventtype", "")
    target_type = values.get("targettype", "")
    count_values = {key: value for key, value in values.items() if key in _COUNT_FIELDS}
    # Keep only people/count notifications; generic motion alarms are irrelevant.
    relevant = bool(count_values) or any(
        word in f"{event_type} {target_type} {values.get('eventdescription', '')}".lower()
        for word in ("people", "human", "target", "count")
    )
    if not relevant:
        return None
    return {
        "time": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type or "camera event",
        "event_state": values.get("eventstate", ""),
        "channel": values.get("channelid") or values.get("channel", ""),
        "target_type": target_type,
        "direction": values.get("direction", ""),
        "counts": count_values,
        "kind": "native_notification", "counts_verified": False,
        "source_time": values.get("datetime", ""),
        "region": values.get("regionsid") or values.get("ruleid", ""),
        "method": values.get("statisticalmethods", ""),
        "start_time": values.get("starttime", ""), "end_time": values.get("endtime", ""),
        "schema_recognised": (event_type.lower() == "peoplecounting"
                              and values.get("statisticalmethods") in {"realTime", "timeRange"}
                              and {"enter", "exit"} <= count_values.keys()
                              and bool(values.get("regionsid") or values.get("ruleid"))
                              and bool(values.get("channelid") or values.get("channel"))
                              and not duplicates.intersection(_COUNT_FIELDS)
                              and all(re.fullmatch(r"\d{1,12}", value) for value in count_values.values())),
        "fields_seen": diagnostic_fields,
        "candidate_counters": candidate_counters,
    }


def notification_diagnostic(payload: bytes) -> dict[str, Any] | None:
    """Describe an unrecognised notification without retaining its payload."""
    try:
        root = decode_document(payload)
    except (ValueError, ET.ParseError):
        return None
    values: dict[str, str] = {}
    fields: list[str] = []
    for key, text in scalar_fields(root):
        key = key.lower()
        if key in _VALUE_FIELDS:
            if key not in fields:
                fields.append(key)
            if text:
                values[key] = text[:160]
    return {
        "last_notification_at": datetime.now(timezone.utc).isoformat(),
        "last_notification_type": values.get("eventtype", "unknown"),
        "last_notification_state": values.get("eventstate", ""),
        "last_notification_fields": sorted(fields),
    }


def parse_onvif_notification(value: Any) -> dict[str, Any] | None:
    """Reduce ONVIF PullMessages data to safe count fields without retaining media metadata."""
    try:
        from zeep.helpers import serialize_object
        value = serialize_object(value)
    except Exception:
        pass
    fields: dict[str, str] = {}
    names: set[str] = set()
    topic = ""

    def keep(key: str, item: Any) -> None:
        key = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if key:
            names.add(key[:80])
        if key in _VALUE_FIELDS and isinstance(item, (str, int, float, bool)):
            fields[key] = str(item).strip()[:160]

    def visit(item: Any, prefix: str = "") -> None:
        nonlocal topic
        if hasattr(item, "tag") and hasattr(item, "iter"):
            for node in item.iter():
                if _name(node.tag) == "SimpleItem":
                    keep(node.get("Name", ""), node.get("Value", ""))
                elif _name(node.tag) == "Topic":
                    topic = (node.text or "").strip()[:200]
                elif _name(node.tag) == "Message":
                    fields["propertyoperation"] = node.get("PropertyOperation", "")[:40]
                else:
                    keep(_name(node.tag), node.text or "")
            return
        if isinstance(item, dict):
            if "Name" in item and "Value" in item:
                keep(item["Name"], item["Value"])
            for key, child in item.items():
                visit(child, prefix if key == "_value_1" else str(key))
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child, prefix)
        elif isinstance(item, (str, int, float, bool)):
            if prefix.lower() == "topic":
                topic = str(item).strip()[:200]
            else:
                keep(prefix, item)

    visit(value)
    event_type = fields.get("eventtype", "")
    target_type = fields.get("targettype", "")
    counts = {key: item for key, item in fields.items() if key in _COUNT_FIELDS}
    return {
        "time": datetime.now(timezone.utc).isoformat(), "event_type": topic or event_type or "ONVIF camera event",
        # A SimpleItem count may be a cumulative total, not a per-person event.
        # Retain it for diagnosis, but do not add it to directional totals yet.
        "kind": "onvif_notification", "counts_verified": False,
        "property_operation": fields.get("propertyoperation", ""),
        "event_state": fields.get("eventstate", ""), "channel": fields.get("channelid") or fields.get("channel", ""),
        "target_type": target_type, "direction": fields.get("direction", ""), "counts": counts,
        "fields_seen": sorted(names)[:40],
    }


def event_paths(cfg: dict[str, Any]) -> tuple[Path, Path]:
    base = Path(cfg["events_path"]).parent
    people = cfg.get("people_counting", {}) if isinstance(cfg.get("people_counting"), dict) else {}
    return (
        Path(people.get("event_history_path") or base / "hikvision-people-events.jsonl"),
        Path(people.get("event_state_path") or base / "hikvision-people-events-state.json"),
    )


def _source_datetime(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except ValueError:
        return None


def _history_lines(path):
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line
    except FileNotFoundError:
        return


def event_summary(cfg: dict[str, Any], now=None) -> dict[str, Any]:
    history, state_path = event_paths(cfg)
    state: dict[str, Any] = {}
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    now = now or datetime.now().astimezone()
    today = now.date()
    totals = {"a_to_b": 0, "b_to_a": 0, "events": 0, "observed_enter": 0, "observed_exit": 0,
              "interval_enter": 0, "interval_exit": 0}
    previous = {}
    intervals = set()
    resets = 0
    camera = cfg.get("people_counting", {})
    if history.exists():
        for line in _history_lines(history):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            receipt = _source_datetime(row.get("time"))
            if receipt and receipt.astimezone(now.tzinfo).date() == today:
                totals["events"] += 1
            if not row.get("schema_recognised") or row.get("camera") != camera.get("address"):
                continue
            if str(row.get("channel")) != str(camera.get("channel", 1)):
                continue
            stamp = _source_datetime(row.get("source_time"))
            if stamp is None:
                continue
            key = (row.get("camera"), row.get("channel"), row.get("region"))
            try:
                counts = tuple(int(row["counts"][name]) for name in ("enter", "exit"))
            except (KeyError, TypeError, ValueError):
                continue
            if min(counts) < 0:
                continue
            delta = (0, 0)
            if row.get("method") == "realTime":
                prior = previous.get(key)
                if prior and stamp < prior[0]:
                    continue
                if prior and stamp.date() == prior[0].astimezone(stamp.tzinfo).date():
                    if any(value < old for value, old in zip(counts, prior[1])):
                        resets += 1
                    else:
                        delta = tuple(value - old for value, old in zip(counts, prior[1]))
                previous[key] = (stamp, counts)
            elif row.get("method") == "timeRange":
                start, end = _source_datetime(row.get("start_time")), _source_datetime(row.get("end_time"))
                if not start or not end or end <= start:
                    continue
                identity = (key, start, end)
                if identity in intervals:
                    continue
                intervals.add(identity)
                if start.astimezone(now.tzinfo).date() == today and end.astimezone(now.tzinfo).date() == today:
                    totals["interval_enter"] += counts[0]
                    totals["interval_exit"] += counts[1]
                # Keep interval reports separate from real-time deltas to avoid double counting.
                continue
            if stamp.astimezone(now.tzinfo).date() == today:
                totals["observed_enter"] += delta[0]
                totals["observed_exit"] += delta[1]
    return {**state, "enabled": bool(camera.get("event_collection_enabled")), "today": totals,
            "counts_verified": False, "counter_resets": resets,
            "interval_reports": len(intervals)}


def record_push_event(cfg, event):
    """Persist usable counts and keep a compact state for diagnostic-only pushes."""
    history, state_path = event_paths(cfg)
    event = dict(event)
    event["camera"] = str(cfg.get("people_counting", {}).get("address") or "")
    event["transport"] = "HTTP push"
    with _history_lock:
        history.parent.mkdir(parents=True, exist_ok=True)
        if event.get("counts"):
            with history.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, separators=(",", ":")) + "\n")
        try:
            prior = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            prior = {}
        try:
            received = int(prior.get("notifications_received", 0)) + 1 if isinstance(prior, dict) else 1
        except (TypeError, ValueError):
            received = 1
        state = {
            "status": "receiving",
            "transport": "HTTP push",
            "counts_verified": False,
            "last_event_at": event.get("time"),
            "last_notification_type": event.get("event_type"),
            "last_reported_counts": event.get("counts", {}),
            "last_notification_fields": event.get("fields_seen", []),
            "last_candidate_counters": event.get("candidate_counters", {}),
            "notifications_received": received,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        temporary = state_path.with_suffix(".push.tmp")
        temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        temporary.replace(state_path)
    return event


class HikvisionEventCollector:
    def __init__(self, cfg: dict[str, Any], event_log) -> None:
        self.cfg = cfg
        self.event_log = event_log
        self.thread = threading.Thread(target=self._run, name="hikvision-events", daemon=True)
        self.counter_thread = threading.Thread(target=self._counter_loop, name="hikvision-counters", daemon=True)
        self.metadata_thread = threading.Thread(target=self._metadata_loop, name="hikvision-metadata", daemon=True)
        self._last_state_signature: tuple[tuple[str, str], ...] | None = None
        self._last_counter_signature: tuple[tuple[str, str], ...] | None = None

    def start(self) -> None:
        self.thread.start()

    def _metadata_loop(self) -> None:
        """Sample analytics metadata only; video and image payloads are never read or stored."""
        while True:
            camera = self.cfg.get("people_counting", {}) if isinstance(self.cfg.get("people_counting"), dict) else {}
            if not bool(camera.get("event_collection_enabled")) or not all(camera.get(key) for key in ("address", "username", "password")):
                time.sleep(10)
                continue
            try:
                base_url = _base_url(camera)
                opener = _digest_opener(base_url, str(camera["username"]), str(camera["password"]))
                channel = int(camera.get("channel") or 1)
                request = Request(f"{base_url}/ISAPI/Streaming/channels/{channel}/metadata", headers={"Accept": "application/xml"})
                with opener.open(request, timeout=30) as response:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        text = chunk.decode("utf-8", errors="ignore")
                        tags = sorted(set(re.findall(r"<([A-Za-z][A-Za-z0-9_:.-]*)", text)))[:40]
                        target_types = sorted(set(re.findall(r"<(?:targetType|type)>\s*([^<\s]{1,40})", text, flags=re.I)))[:12]
                        if tags or target_types:
                            self._write_state(status="metadata listening", last_metadata_at=datetime.now(timezone.utc).isoformat(), metadata_fields=tags, metadata_target_types=target_types)
            except (HTTPError, URLError, socket.timeout, OSError):
                time.sleep(10)
            except Exception:
                time.sleep(10)

    def _write_state(self, **values: Any) -> None:
        _, path = event_paths(self.cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        signature = tuple(sorted((str(key), str(value)) for key, value in values.items()))
        if signature == self._last_state_signature:
            return
        self._last_state_signature = signature
        values["updated_at"] = datetime.now(timezone.utc).isoformat()
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(values, separators=(",", ":")), encoding="utf-8")
        temporary.replace(path)

    def _record(self, event: dict[str, Any]) -> None:
        history, _ = event_paths(self.cfg)
        history.parent.mkdir(parents=True, exist_ok=True)
        with _history_lock, history.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
        message = "Camera counter notification received (unverified totals)"
        self.event_log.add("info", "people_counting", message, event)

    def _counter_loop(self) -> None:
        while True:
            camera = self.cfg.get("people_counting", {}) if isinstance(self.cfg.get("people_counting"), dict) else {}
            configured = all(camera.get(key) for key in ("address", "username", "password"))
            if bool(camera.get("event_collection_enabled")) and configured:
                try:
                    counter = self._read_counter_snapshot(camera)
                    if counter:
                        self._record(counter)
                except (HTTPError, URLError, socket.timeout, OSError):
                    pass
                except Exception:
                    pass
            time.sleep(max(30, int(camera.get("counter_poll_interval_seconds", 60) or 60)))

    @staticmethod
    def _counter_values(value: Any, prefix: str = "") -> dict[str, str]:
        found: dict[str, str] = {}
        if isinstance(value, dict):
            for key, child in value.items():
                found.update(HikvisionEventCollector._counter_values(child, f"{prefix}_{key}"))
        elif isinstance(value, list):
            for child in value:
                found.update(HikvisionEventCollector._counter_values(child, prefix))
        else:
            normalized = re.sub(r"[^a-z0-9]", "", prefix.lower())
            try:
                number = int(str(value))
            except (TypeError, ValueError):
                return found
            direction = "atob" if any(token in normalized for token in ("atob", "a2b", "enter", "incount")) else "btoa" if any(token in normalized for token in ("btoa", "b2a", "leave", "outcount")) else ""
            if direction:
                target = "human" if any(token in normalized for token in ("human", "people", "person")) else "vehicle" if any(token in normalized for token in ("vehicle", "motor")) else ""
                found[f"{target + '_' if target else ''}{direction}"] = str(number)
        return found

    def _read_counter_snapshot(self, camera: dict[str, Any]) -> dict[str, Any] | None:
        base_url = _base_url(camera)
        opener = _digest_opener(base_url, str(camera["username"]), str(camera["password"]))
        timeout = max(5, int(camera.get("timeout_seconds") or 5))
        channel = int(camera.get("channel") or 1)
        for template in _COUNTER_PATHS:
            endpoint = template.format(channel=channel)
            request = Request(f"{base_url}{endpoint}", headers={"Accept": "application/json, application/xml, text/xml"})
            try:
                with opener.open(request, timeout=timeout) as response:
                    payload = response.read(128 * 1024)
            except HTTPError as exc:
                if exc.code in {401, 403, 404, 405}:
                    continue
                raise
            try:
                values: Any = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                try:
                    root = ET.fromstring(payload)
                    values = {_name(node.tag): (node.text or "").strip() for node in root.iter() if len(node) == 0}
                except ET.ParseError:
                    continue
            counts = self._counter_values(values)
            if counts:
                signature = tuple(sorted(counts.items()))
                if signature == self._last_counter_signature:
                    return None
                self._last_counter_signature = signature
                self._write_state(status="receiving", counter_endpoint=endpoint, last_counter_at=datetime.now(timezone.utc).isoformat())
                return {
                    "time": datetime.now(timezone.utc).isoformat(),
                    "kind": "counter_snapshot",
                    "event_type": "multi-target counter snapshot",
                    "event_state": "active",
                    "channel": str(channel),
                    "target_type": "human and vehicle",
                    "direction": "",
                    "counts": counts,
                    "fields_seen": sorted(counts),
                }
        return None

    def _run(self) -> None:
        backoff = 5
        while True:
            camera = self.cfg.get("people_counting", {}) if isinstance(self.cfg.get("people_counting"), dict) else {}
            enabled = bool(camera.get("event_collection_enabled"))
            configured = all(camera.get(key) for key in ("address", "username", "password"))
            if not enabled or not configured:
                self._write_state(status="disabled" if not enabled else "needs camera details")
                time.sleep(5)
                continue
            try:
                if camera.get("event_transport", "isapi") == "http_push":
                    self._write_state(status="waiting", transport="HTTP push", counts_verified=False)
                    time.sleep(5)
                elif camera.get("event_transport", "isapi") == "onvif":
                    self._onvif_stream(camera)
                else:
                    self._stream(camera)
                backoff = 5
            except Exception as exc:
                # _onvif_stream preserves the failing stage and a redacted error.
                if camera.get("event_transport", "isapi") != "onvif":
                    self._write_state(status="reconnecting", transport="ISAPI alertStream", counts_verified=False,
                                      last_error=f"Native stream failed ({type(exc).__name__}). Run native API diagnostic.")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    def _onvif_stream(self, camera: dict[str, Any], subscription_factory=PullSubscription) -> None:
        """Read only ONVIF PullMessages collector, used when the camera advertises ONVIF Events."""
        camera = dict(camera)
        subscription = subscription_factory(camera)
        diagnostic: dict[str, Any] = {"notifications_received": 0, "counts_verified": False, "topics_seen": []}
        self._write_state(status="ONVIF connecting", **diagnostic)
        try:
            subscription.open()
            while self.cfg.get("people_counting") == camera:
                messages = subscription.pull()
                if self.cfg.get("people_counting") != camera:
                    break
                for message in messages:
                    event = parse_onvif_notification(message)
                    if event:
                        diagnostic.update(last_notification_type=event["event_type"],
                                          last_notification_fields=event["fields_seen"],
                                          last_notification_at=event["time"])
                        if event["event_type"] not in diagnostic["topics_seen"]:
                            diagnostic["topics_seen"] = (diagnostic["topics_seen"] + [event["event_type"]])[-16:]
                        diagnostic["notifications_received"] += 1
                        # Store potentially useful count notifications, not every motion heartbeat.
                        if event["counts"]:
                            diagnostic.update(last_reported_counts=event["counts"], last_counter_topic=event["event_type"])
                            self._record(event)
                diagnostic["last_poll_at"] = datetime.now(timezone.utc).isoformat()
                self._write_state(status="ONVIF listening", **diagnostic)
        except Exception as exc:
            detail = str(exc)
            # SOAP subcodes identify invalid leases, unsupported operations and
            # resource limits without exposing the response body or credentials.
            codes = [getattr(exc, "code", "")] + list(getattr(exc, "subcodes", None) or [])
            fault_codes = [str(code).rsplit("}", 1)[-1].rsplit(":", 1)[-1] for code in codes if code]
            fault_codes = [code for code in fault_codes if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", code)]
            if fault_codes:
                detail = f"[{' / '.join(fault_codes[:4])}] {detail}"
            password = str(camera.get("password") or "")
            if password:
                detail = detail.replace(password, "[redacted]")
            # Never print SOAP bodies or authentication headers from transport errors.
            detail = re.sub(r"<.*", "[response body omitted]", detail, flags=re.S)
            detail = re.sub(r"(?i)(authorization|password|nonce|usernametoken).*", "[authentication detail omitted]", detail)
            self._write_state(status="reconnecting", last_error=f"{subscription.stage}: {type(exc).__name__}: {detail[:240]}", **diagnostic)
            raise
        finally:
            subscription.close()

    def _stream(self, camera: dict[str, Any]) -> None:
        camera = dict(camera)
        base_url = _base_url(camera)
        opener = _digest_opener(base_url, str(camera["username"]), str(camera["password"]))
        request = Request(f"{base_url}/ISAPI/Event/notification/alertStream", headers={"Accept": "multipart/x-mixed-replace, application/xml"})
        timeout = max(15, int(camera.get("timeout_seconds") or 5) * 6)
        diagnostic = {"transport": "ISAPI alertStream", "counts_verified": False, "notifications_received": 0}
        self._write_state(status="connecting", **diagnostic)
        with opener.open(request, timeout=timeout) as response:
            parser = AlertParts(response.headers.get("Content-Type", ""))
            self._write_state(status="listening", **diagnostic)
            while self.cfg.get("people_counting") == camera:
                chunk = response.read1(8192)
                if not chunk:
                    raise OSError("camera closed the event stream")
                if self.cfg.get("people_counting") != camera:
                    break
                for notification in parser.feed(chunk):
                    diagnostic["notifications_received"] += 1
                    event = parse_notification(notification)
                    if event and event["counts"]:
                        event["camera"] = camera["address"]
                        self._record(event)
                        diagnostic["last_reported_counts"] = event["counts"]
                    diagnostic.update(notification_diagnostic(notification) or {})
                    self._write_state(status="receiving" if event and event["counts"] else "listening", **diagnostic)
