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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .hikvision import _base_url, _digest_opener
from .onvif_pull import PullSubscription
from .hikvision_native import decode_document, response_error, scalar_fields
from .hikvision_stream import AlertParts


_history_lock = threading.Lock()


_VALUE_FIELDS = {
    "eventtype", "eventstate", "channelid", "channel", "targettype", "direction",
    "entercount", "leavecount", "incount", "outcount", "passcount", "passingcount",
    "atob", "btoa", "eventdescription",
    "enter", "exit", "pass", "vehicleenter", "vehicleexit", "bicycleenter", "bicycleexit",
    "statisticalmethod", "statisticalmethods", "regionsid", "ruleid", "datetime", "starttime", "endtime",
}
_COUNT_FIELDS = {"entercount", "leavecount", "incount", "outcount", "passcount", "passingcount", "atob", "btoa",
                 "enter", "exit", "pass", "vehicleenter", "vehicleexit", "bicycleenter", "bicycleexit"}
_DIAGNOSTIC_COUNT_HINTS = ("count", "number", "num", "enter", "exit", "human", "people", "person",
                           "pedestrian", "vehicle", "bicycle")
_SENSITIVE_DIAGNOSTIC_HINTS = ("password", "secret", "token", "cookie", "authorization", "username",
                               "serial", "macaddress", "ipaddress", "url", "picture", "image", "deviceid",
                               "uuid")
_COUNTER_REPORT_PATH = "/ISAPI/Event/channels/{channel}/SearchRegionTargetNumberCounting?format=json"
_COUNTER_DIRECTIONS = ("forward", "back", "bothway")


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


def _safe_count_records(document: Any) -> list[dict[str, str]]:
    """Keep count rows associated with their direction, never the surrounding payload."""
    records: list[dict[str, str]] = []
    count_names = {"humancount": "human", "nonmotorcount": "non_motor", "vehiclecount": "vehicle"}

    def add(values: dict[str, str]) -> None:
        direction = values.get("statisticaldirection", "")
        if not direction or not any(name in values for name in count_names):
            return
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,40}", direction):
            return
        record = {"direction": direction}
        method = values.get("statisticalmethod", "")
        if method and re.fullmatch(r"[A-Za-z0-9_.:-]{1,40}", method):
            record["method"] = method
        for source, target in count_names.items():
            value = values.get(source, "")
            if re.fullmatch(r"\d{1,12}", value):
                record[target] = value
        if len(record) > 1 and record not in records and len(records) < 12:
            records.append(record)

    def visit(value: Any) -> None:
        if isinstance(value, ET.Element):
            direct = {_name(child.tag).lower(): (child.text or "").strip()
                      for child in value if not len(child)}
            add(direct)
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            direct = {str(key).lower(): str(item) for key, item in value.items()
                      if not isinstance(item, (dict, list))}
            add(direct)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)
    return records


def _validated_region_counts(records: list[dict[str, str]]) -> dict[str, str]:
    """Validate forward, back and both-way region totals before using human counts."""
    by_direction: dict[str, dict[str, str]] = {}
    for record in records:
        direction = record.get("direction", "").lower()
        if direction in by_direction or direction not in {"forward", "back", "bothway"}:
            continue
        by_direction[direction] = record
    if set(by_direction) != {"forward", "back", "bothway"}:
        return {}
    for category in ("human", "non_motor", "vehicle"):
        present = [category in by_direction[direction] for direction in ("forward", "back", "bothway")]
        if any(present) and (not all(present) or
                             int(by_direction["forward"][category]) + int(by_direction["back"][category])
                             != int(by_direction["bothway"][category])):
            return {}
    if not all("human" in by_direction[direction] for direction in ("forward", "back", "bothway")):
        return {}
    return {direction: by_direction[direction]["human"] for direction in ("forward", "back", "bothway")}


def _report_category_counts(document: Any) -> dict[str, str]:
    """Extract one unambiguous count per requested target category."""
    found: dict[str, set[str]] = {"human": set(), "non_motor": set(), "vehicle": set()}
    direct_names = {
        "humancount": "human",
        "humannum": "human",
        "human": "human",
        "peoplecount": "human",
        "personcount": "human",
        "nonmotorcount": "non_motor",
        "nonmotornum": "non_motor",
        "nonmotor": "non_motor",
        "nonmotorvehiclecount": "non_motor",
        "vehiclecount": "vehicle",
        "vehiclenum": "vehicle",
        "vehicle": "vehicle",
    }
    objective_names = {
        "human": "human", "people": "human", "person": "human",
        "nonmotor": "non_motor", "nonmotorvehicle": "non_motor",
        "vehicle": "vehicle",
    }

    def normalized(name: Any) -> str:
        return re.sub(r"[^a-z0-9]", "", str(name).lower())

    def number(value: Any) -> str | None:
        text = str(value).strip()
        return text if re.fullmatch(r"\d{1,12}", text) else None

    def visit(value: Any) -> None:
        if isinstance(value, ET.Element):
            direct = {_name(child.tag): (child.text or "").strip()
                      for child in value if not len(child)}
            inspect(direct)
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            inspect({str(key): item for key, item in value.items()
                     if not isinstance(item, (dict, list))})
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    def inspect(values: dict[str, Any]) -> None:
        reduced = {normalized(key): item for key, item in values.items()}
        for key, category in direct_names.items():
            candidate = number(reduced.get(key, ""))
            if candidate is not None:
                found[category].add(candidate)
        objective = next((reduced.get(key) for key in (
            "statisticalobjective", "objective", "targettype", "targetclass"
        ) if reduced.get(key) is not None), None)
        category = objective_names.get(normalized(objective)) if objective is not None else None
        if category:
            candidate = next((number(reduced.get(key, "")) for key in (
                "count", "targetcount", "targetnumber", "statisticalcount",
                "number", "num", "value"
            ) if number(reduced.get(key, "")) is not None), None)
            if candidate is not None:
                found[category].add(candidate)

    visit(document)
    return {category: next(iter(values)) for category, values in found.items() if len(values) == 1}


def _region_category_counts(row: dict[str, Any]) -> dict[str, tuple[int, int]]:
    """Return validated forward/back pairs for every category retained in a region event."""
    records = row.get("count_records") if isinstance(row.get("count_records"), list) else []
    by_direction = {
        str(record.get("direction") or "").lower(): record
        for record in records if isinstance(record, dict)
    }
    if not {"forward", "back", "bothway"} <= set(by_direction):
        return {}
    categories = {}
    for category in ("human", "non_motor", "vehicle"):
        try:
            forward = int(by_direction["forward"][category])
            back = int(by_direction["back"][category])
            bothway = int(by_direction["bothway"][category])
        except (KeyError, TypeError, ValueError):
            continue
        if min(forward, back, bothway) >= 0 and forward + back == bothway:
            categories[category] = (forward, back)
    return categories


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
    count_records = _safe_count_records(root)
    event_type = values.get("eventtype", "")
    target_type = values.get("targettype", "")
    count_values = {key: value for key, value in values.items() if key in _COUNT_FIELDS}
    region_counts = _validated_region_counts(count_records)
    region_event = event_type.lower() in {"regiontargetnumbercounting", "mixedtargetdetection"}
    if region_event and region_counts:
        count_values = region_counts
    method = values.get("statisticalmethod") or values.get("statisticalmethods", "")
    traditional_schema = (event_type.lower() == "peoplecounting"
                          and method.lower() in {"realtime", "timerange"}
                          and {"enter", "exit"} <= count_values.keys()
                          and bool(values.get("regionsid") or values.get("ruleid"))
                          and bool(values.get("channelid") or values.get("channel"))
                          and not duplicates.intersection(_COUNT_FIELDS)
                          and all(re.fullmatch(r"\d{1,12}", value) for value in count_values.values()))
    region_schema = (region_event
                     and bool(region_counts)
                     and method.lower() == "realtime"
                     and bool(values.get("ruleid"))
                     and bool(values.get("channelid") or values.get("channel"))
                     and bool(values.get("datetime")))
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
        "method": method,
        "start_time": values.get("starttime", ""), "end_time": values.get("endtime", ""),
        "schema_recognised": traditional_schema or region_schema,
        "count_schema": "region_forward_back" if region_schema else "people_enter_exit" if traditional_schema else "",
        "fields_seen": diagnostic_fields,
        "candidate_counters": candidate_counters,
        "count_records": count_records,
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
              "observed_forward": 0, "observed_back": 0,
              "interval_enter": 0, "interval_exit": 0}
    previous = {}
    intervals = set()
    resets = 0
    observations = []
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
            count_names = (("forward", "back") if row.get("count_schema") == "region_forward_back"
                           else ("enter", "exit"))
            try:
                counts = tuple(int(row["counts"][name]) for name in count_names)
            except (KeyError, TypeError, ValueError):
                continue
            if min(counts) < 0:
                continue
            category_counts = _region_category_counts(row)
            if not category_counts and row.get("count_schema") == "region_forward_back":
                category_counts = {"human": counts}
            observations.append((stamp, key, row.get("count_schema"), category_counts))
            delta = (0, 0)
            method = str(row.get("method") or "").lower()
            if method == "realtime":
                prior = previous.get(key)
                if prior and stamp < prior[0]:
                    continue
                if prior and stamp.date() == prior[0].astimezone(stamp.tzinfo).date():
                    if any(value < old for value, old in zip(counts, prior[1])):
                        resets += 1
                    else:
                        delta = tuple(value - old for value, old in zip(counts, prior[1]))
                previous[key] = (stamp, counts)
            elif method == "timerange":
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
                if row.get("count_schema") == "region_forward_back":
                    totals["observed_forward"] += delta[0]
                    totals["observed_back"] += delta[1]
                else:
                    totals["observed_enter"] += delta[0]
                    totals["observed_exit"] += delta[1]
    daily_rollups = _daily_count_history(observations, now, 40)
    daily_history = daily_rollups[-7:]
    last_event = _source_datetime(state.get("last_event_at"))
    stale_after_minutes = max(1, int(camera.get("stale_after_minutes", 10) or 10))
    message_age_seconds = max(0, int((now - last_event.astimezone(now.tzinfo)).total_seconds())) if last_event else None
    stale = bool(camera.get("event_collection_enabled")) and (
        message_age_seconds is None or message_age_seconds > stale_after_minutes * 60
    )
    return {**state, "enabled": bool(camera.get("event_collection_enabled")), "today": totals,
            "counts_verified": False, "counter_resets": resets,
            "unexpected_resets_today": daily_history[-1]["unexpected_resets"] if daily_history else 0,
            "scheduled_resets": sum(row["scheduled_resets"] for row in daily_history),
            "daily_history": daily_history, "stale": stale,
            "hourly_history": _hourly_count_history(observations, now, 24),
            "period_totals": _period_totals(daily_rollups, now),
            "activity_anomalies": _activity_anomalies(
                daily_rollups, int(camera.get("anomaly_threshold_percent", 50) or 50)
            ),
            "anomaly_threshold_percent": int(camera.get("anomaly_threshold_percent", 50) or 50),
            "stale_after_minutes": stale_after_minutes, "message_age_seconds": message_age_seconds,
            "interval_reports": len(intervals)}


def _daily_count_history(observations, now, days):
    """Build camera-day totals, treating a date-boundary drop as the expected midnight reset."""
    days = max(1, int(days))
    first_day = now.date() - timedelta(days=days - 1)
    rows = {
        first_day + timedelta(days=offset): {
            "date": (first_day + timedelta(days=offset)).isoformat(),
            "forward": None, "back": None, "bothway": None, "samples": 0,
            "non_motor_forward": None, "non_motor_back": None, "non_motor_bothway": None,
            "vehicle_forward": None, "vehicle_back": None, "vehicle_bothway": None,
            "scheduled_resets": 0, "unexpected_resets": 0,
            "complete": (first_day + timedelta(days=offset)) < now.date(),
        }
        for offset in range(days)
    }
    per_key = {}
    for stamp, key, schema, categories in sorted(observations, key=lambda item: item[0]):
        if schema != "region_forward_back" or "human" not in categories:
            continue
        local_day = stamp.astimezone(now.tzinfo).date()
        prior = per_key.get(key)
        if prior and stamp < prior[0]:
            continue
        if local_day in rows:
            row = rows[local_day]
            row["samples"] += 1
            if prior and local_day == prior[1]:
                dropped = False
                for category, counts in categories.items():
                    prior_counts = prior[2].get(category)
                    if prior_counts is None:
                        continue
                    prefix = "" if category == "human" else f"{category}_"
                    for index, name in enumerate(("forward", "back")):
                        delta = counts[index] if counts[index] < prior_counts[index] else counts[index] - prior_counts[index]
                        dropped = dropped or counts[index] < prior_counts[index]
                        field = f"{prefix}{name}"
                        row[field] = int(row[field] or 0) + delta
                if dropped:
                    row["unexpected_resets"] += 1
            else:
                for category, counts in categories.items():
                    prefix = "" if category == "human" else f"{category}_"
                    row[f"{prefix}forward"] = int(row[f"{prefix}forward"] or 0) + counts[0]
                    row[f"{prefix}back"] = int(row[f"{prefix}back"] or 0) + counts[1]
                prior_categories = prior[2] if prior else {}
                if (prior and local_day != prior[1]
                        and any(value < old for category, counts in categories.items()
                                for old, value in zip(prior_categories.get(category, counts), counts))):
                    row["scheduled_resets"] += 1
            for category in ("human", "non_motor", "vehicle"):
                prefix = "" if category == "human" else f"{category}_"
                forward, back = row.get(f"{prefix}forward"), row.get(f"{prefix}back")
                row[f"{prefix}bothway"] = (int(forward) + int(back)) if forward is not None and back is not None else None
        per_key[key] = (stamp, local_day, categories)
    return list(rows.values())


def _hourly_count_history(observations, now, hours):
    """Return observed counter changes by hour; the first-ever baseline is not counted."""
    hours = max(1, int(hours))
    end = now.replace(minute=0, second=0, microsecond=0)
    first = end - timedelta(hours=hours - 1)
    rows = {
        first + timedelta(hours=offset): {
            "start": (first + timedelta(hours=offset)).isoformat(),
            "human": 0, "non_motor": 0, "vehicle": 0, "samples": 0,
        }
        for offset in range(hours)
    }
    per_key = {}
    for stamp, key, schema, categories in sorted(observations, key=lambda item: item[0]):
        if schema != "region_forward_back" or "human" not in categories:
            continue
        local_stamp = stamp.astimezone(now.tzinfo)
        bucket = local_stamp.replace(minute=0, second=0, microsecond=0)
        prior = per_key.get(key)
        if prior and stamp < prior[0]:
            continue
        if bucket in rows and prior:
            rows[bucket]["samples"] += 1
            same_day = local_stamp.date() == prior[1]
            for category, counts in categories.items():
                prior_counts = prior[2].get(category)
                if prior_counts is None:
                    continue
                change = 0
                for old, value in zip(prior_counts, counts):
                    change += value if (not same_day or value < old) else value - old
                rows[bucket][category] += change
        per_key[key] = (stamp, local_stamp.date(), categories)
    return list(rows.values())


def _period_totals(daily_rows, now):
    dated = [(datetime.fromisoformat(row["date"]).date(), row) for row in daily_rows]
    periods = {
        "today": [row for day, row in dated if day == now.date()],
        "last_7_days": [row for day, row in dated if now.date() - timedelta(days=6) <= day <= now.date()],
        "this_month": [row for day, row in dated if day.year == now.year and day.month == now.month],
    }
    result = {}
    for name, rows in periods.items():
        result[name] = {
            category: sum(int(row.get(key) or 0) for row in rows)
            for category, key in (("human", "bothway"), ("non_motor", "non_motor_bothway"),
                                  ("vehicle", "vehicle_bothway"))
        }
        result[name]["days_with_data"] = sum(1 for row in rows if row.get("bothway") is not None)
    return result


def _activity_anomalies(daily_rows, threshold_percent=50):
    complete = [row for row in daily_rows if row.get("complete") and row.get("bothway") is not None]
    if len(complete) < 4:
        return []
    latest = complete[-1]
    baseline = complete[-8:-1]
    anomalies = []
    for label, key in (("Human", "bothway"), ("Non-motor Vehicle", "non_motor_bothway"),
                       ("Vehicle", "vehicle_bothway")):
        values = [int(row[key]) for row in baseline if row.get(key) is not None]
        if len(values) < 3:
            continue
        average = sum(values) / len(values)
        latest_value = int(latest.get(key) or 0)
        if average <= 0:
            continue
        change_percent = round(((latest_value - average) / average) * 100)
        if abs(change_percent) >= threshold_percent:
            anomalies.append({
                "category": label, "date": latest["date"], "value": latest_value,
                "baseline_average": round(average, 1), "change_percent": change_percent,
            })
    return anomalies


def daily_count_history(cfg: dict[str, Any], now=None, days=7) -> list[dict[str, Any]]:
    """Return A-to-B/B-to-A daily totals for operator history and export."""
    history, _ = event_paths(cfg)
    camera = cfg.get("people_counting", {})
    now = now or datetime.now().astimezone()
    observations = []
    for line in _history_lines(history):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (not isinstance(row, dict) or not row.get("schema_recognised")
                or row.get("camera") != camera.get("address")
                or str(row.get("channel")) != str(camera.get("channel", 1))):
            continue
        stamp = _source_datetime(row.get("source_time"))
        if stamp is None:
            continue
        key = (row.get("camera"), row.get("channel"), row.get("region"))
        names = (("forward", "back") if row.get("count_schema") == "region_forward_back" else ("enter", "exit"))
        try:
            counts = tuple(int(row["counts"][name]) for name in names)
        except (KeyError, TypeError, ValueError):
            continue
        if min(counts) >= 0:
            categories = _region_category_counts(row)
            if not categories and row.get("count_schema") == "region_forward_back":
                categories = {"human": counts}
            observations.append((stamp, key, row.get("count_schema"), categories))
    return _daily_count_history(observations, now, days)


def record_push_event(cfg, event):
    """Persist usable counts and keep a compact state for diagnostic-only pushes."""
    history, state_path = event_paths(cfg)
    event = dict(event)
    event["camera"] = str(cfg.get("people_counting", {}).get("address") or "")
    event["transport"] = "HTTP push"
    with _history_lock:
        history.parent.mkdir(parents=True, exist_ok=True)
        try:
            prior = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            prior = {}
        if not isinstance(prior, dict):
            prior = {}
        current_source = _source_datetime(event.get("source_time"))
        prior_source = _source_datetime(prior.get("last_source_time"))
        source_day_changed = bool(
            current_source and prior_source
            and current_source.astimezone().date() != prior_source.astimezone().date()
        )
        counter_changed = (
            event.get("counts") != prior.get("last_reported_counts")
            or event.get("count_records") != prior.get("last_count_records")
            or source_day_changed
        )
        if event.get("counts") and counter_changed:
            with history.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, separators=(",", ":")) + "\n")
        try:
            received = int(prior.get("notifications_received", 0)) + 1
        except (TypeError, ValueError):
            received = 1
        state = {
            "status": "receiving",
            "transport": "HTTP push",
            "counts_verified": False,
            "last_event_at": event.get("time"),
            "last_source_time": event.get("source_time"),
            "last_notification_type": event.get("event_type"),
            "last_reported_counts": event.get("counts", {}),
            "last_notification_fields": event.get("fields_seen", []),
            "last_candidate_counters": event.get("candidate_counters", {}),
            "last_count_records": event.get("count_records", []),
            "notifications_received": received,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        for key, value in prior.items():
            if key.startswith("last_http_") or key == "http_posts_received":
                state[key] = value
        temporary = state_path.with_suffix(".push.tmp")
        temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        temporary.replace(state_path)
    return event


def record_http_delivery(cfg, *, content_type, body_size, documents, accepted, ignored, unrecognised,
                         message_type="", fields=None, candidate_counters=None):
    """Record a payload-free delivery outcome so transport and parsing faults are distinguishable."""
    _, state_path = event_paths(cfg)
    with _history_lock:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        try:
            received = int(state.get("http_posts_received", 0)) + 1
        except (TypeError, ValueError):
            received = 1
        state.update({
            "last_http_post_at": datetime.now(timezone.utc).isoformat(),
            "last_http_content_type": str(content_type or "unknown").split(";", 1)[0][:80],
            "last_http_body_size": max(0, int(body_size)),
            "last_http_documents": max(0, int(documents)),
            "last_http_accepted": max(0, int(accepted)),
            "last_http_ignored": max(0, int(ignored)),
            "last_http_unrecognised": max(0, int(unrecognised)),
            "last_http_message_type": str(message_type or "")[:160],
            "last_http_fields": list(fields or [])[:80],
            "last_http_candidate_counters": dict(list((candidate_counters or {}).items())[:30]),
            "http_posts_received": received,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        temporary = state_path.with_suffix(".http.tmp")
        temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        temporary.replace(state_path)


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
        self.counter_thread.start()

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
        with _history_lock:
            try:
                prior = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            except (OSError, json.JSONDecodeError):
                prior = {}
            if not isinstance(prior, dict):
                prior = {}
            prior.update(values)
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(prior, separators=(",", ":")), encoding="utf-8")
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
            report_polling = camera.get("event_transport", "isapi") == "http_push"
            if bool(camera.get("event_collection_enabled")) and configured and report_polling:
                try:
                    counter = self._read_counter_snapshot(camera)
                    if counter:
                        self._record(counter)
                except HTTPError as exc:
                    self._write_state(counter_poll_status=f"camera returned HTTP {exc.code}")
                except RuntimeError as exc:
                    self._write_state(counter_poll_status=f"camera rejected report: {str(exc)[:180]}")
                except (URLError, socket.timeout, OSError) as exc:
                    self._write_state(counter_poll_status=f"connection failed ({type(exc).__name__})")
                except Exception as exc:
                    self._write_state(counter_poll_status=f"report failed ({type(exc).__name__})")
            time.sleep(max(15, int(camera.get("counter_poll_interval_seconds", 30) or 30)))

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
        rule_id = max(1, int(camera.get("rule_id") or 1))
        endpoint = _COUNTER_REPORT_PATH.format(channel=channel)
        observed = datetime.now().astimezone()
        source_time = observed.isoformat(timespec="seconds")
        records = []
        for direction in _COUNTER_DIRECTIONS:
            condition = {
                "ReportCond": {
                    "reportType": "monthly",
                    "ruleID": rule_id,
                    "statisticalDirection": direction,
                    "statisticalObjectives": ["human", "nonMotor", "vehicle"],
                    "statisticalTime": observed.strftime("%Y-%m-%dT00:00:00"),
                }
            }
            body = json.dumps(condition, separators=(",", ":")).encode("utf-8")
            request = Request(
                f"{base_url}{endpoint}", data=body, method="POST",
                headers={"Accept": "application/json, application/xml, text/xml",
                         "Content-Type": "application/json; charset=UTF-8"},
            )
            try:
                with opener.open(request, timeout=timeout) as response:
                    payload = response.read(128 * 1024)
            except HTTPError as exc:
                try:
                    detail = response_error(exc.read(16 * 1024))
                    status = exc.code
                finally:
                    exc.close()
                raise RuntimeError(detail or f"HTTP {status}") from None
            try:
                values: Any = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                try:
                    values = ET.fromstring(payload)
                except ET.ParseError:
                    self._write_state(counter_poll_status="camera returned an unreadable report")
                    return None
            counts = _report_category_counts(values)
            if "human" not in counts:
                fields, candidates = _safe_event_shape(values)
                self._write_state(
                    counter_poll_status=f"unrecognised {direction} report",
                    counter_report_fields=fields,
                    counter_report_candidates=candidates,
                )
                return None
            records.append({"direction": direction, "method": "realTime", **counts})
        human_counts = _validated_region_counts(records)
        if not human_counts:
            self._write_state(counter_poll_status="report checksum did not validate")
            return None
        received_at = datetime.now(timezone.utc).isoformat()
        event = {
            "time": received_at,
            "kind": "counter_snapshot",
            "event_type": "regionTargetNumberCounting",
            "event_state": "active",
            "channel": str(channel),
            "target_type": "human, nonMotor and vehicle",
            "direction": "",
            "counts": human_counts,
            "camera": str(camera["address"]),
            "transport": "ISAPI report polling",
            "counts_verified": False,
            "source_time": source_time,
            "region": str(rule_id),
            "method": "realTime",
            "schema_recognised": True,
            "count_schema": "region_forward_back",
            "fields_seen": sorted({name for record in records for name in record}),
            "candidate_counters": {},
            "count_records": records,
        }
        self._write_state(
            status="receiving", transport="HTTP push + ISAPI report polling",
            counter_endpoint=endpoint, counter_poll_status="ok", last_counter_at=received_at,
            counter_report_fields=[], counter_report_candidates={},
            last_event_at=received_at, last_source_time=source_time,
            last_notification_type=event["event_type"], last_reported_counts=human_counts,
            last_notification_fields=event["fields_seen"], last_count_records=records,
        )
        signature = tuple(
            sorted((f"{record['direction']}_{category}", value)
                   for record in records for category, value in record.items()
                   if category in {"human", "non_motor", "vehicle"})
        )
        if signature == self._last_counter_signature:
            return None
        self._last_counter_signature = signature
        return event

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
