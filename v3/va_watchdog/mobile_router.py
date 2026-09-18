from __future__ import annotations

import re
import socket
import struct
import time
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from .common import CheckResult, now_iso


_SNAPSHOT_LOCK = Lock()
_LATEST_SNAPSHOT: dict[str, Any] = {}
_PREVIOUS_UPTIME: dict[str, int] = {}
_PREVIOUS_CELL: dict[str, str] = {}
_PREVIOUS_CONNECTION_UPTIME: dict[str, int] = {}

_RADIO_OIDS = {
    "cell_id": "1.3.6.1.4.1.48690.2.2.1.18.1",
    "sinr_db": "1.3.6.1.4.1.48690.2.2.1.19.1",
    "rsrp_dbm": "1.3.6.1.4.1.48690.2.2.1.20.1",
    "rsrq_db": "1.3.6.1.4.1.48690.2.2.1.21.1",
    "connection_uptime_seconds": "1.3.6.1.4.1.48690.2.3.0",
}


def signal_quality(signal_dbm: Any) -> dict[str, str]:
    """Return a simple operator-facing RSSI quality without affecting watchdog safety."""
    try:
        value = int(signal_dbm)
    except (TypeError, ValueError):
        return {"label": "Unknown", "state": "unknown"}
    if value >= -80:
        return {"label": "Strong", "state": "healthy"}
    if value >= -100:
        return {"label": "Fair", "state": "warning"}
    return {"label": "Low", "state": "critical"}


def radio_quality(name: str, value: Any) -> dict[str, str]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return {"label": "Unknown", "state": "unknown"}
    if name == "rsrp_dbm":
        if number >= -90:
            return {"label": "Good", "state": "healthy"}
        return {"label": "Fair", "state": "warning"} if number >= -105 else {"label": "Low", "state": "critical"}
    if name == "rsrq_db":
        if number >= -10:
            return {"label": "Good", "state": "healthy"}
        return {"label": "Fair", "state": "warning"} if number >= -15 else {"label": "Low", "state": "critical"}
    if name == "sinr_db":
        if number >= 10:
            return {"label": "Good", "state": "healthy"}
        return {"label": "Fair", "state": "warning"} if number >= 0 else {"label": "Low", "state": "critical"}
    return {"label": "Unknown", "state": "unknown"}


def radio_metric_score(name: str, value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    limits = {
        "signal_dbm": (-110.0, -65.0),
        "rsrp_dbm": (-120.0, -80.0),
        "rsrq_db": (-20.0, -5.0),
        "sinr_db": (-5.0, 25.0),
    }
    if name not in limits:
        return None
    low, high = limits[name]
    return round(max(0.0, min(100.0, (number - low) / (high - low) * 100.0)), 1)


def radio_score(values: dict[str, Any]) -> dict[str, Any]:
    metrics = []
    labels = {"signal_dbm": "RSSI", "rsrp_dbm": "RSRP", "rsrq_db": "RSRQ", "sinr_db": "SINR"}
    preferred = ("rsrp_dbm", "rsrq_db", "sinr_db")
    selected = preferred if any(values.get(name) is not None for name in preferred) else ("signal_dbm",)
    for name in selected:
        score = radio_metric_score(name, values.get(name))
        if score is not None:
            metrics.append((score, name))
    if not metrics:
        return {"score": None, "label": "Unknown", "state": "unknown", "limiting": "No radio readings"}
    score, limiting = min(metrics)
    if score >= 80:
        label, state = "Good", "healthy"
    elif score >= 50:
        label, state = "Fair", "warning"
    else:
        label, state = "Poor", "critical"
    return {"score": round(score), "label": label, "state": state, "limiting": labels[limiting]}


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _ber_length(len(value)) + value


def _ber_integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    encoded = value.to_bytes(length, "big", signed=True)
    while len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
        encoded = encoded[1:]
    return _ber_tlv(0x02, encoded)


def _ber_oid(value: str) -> bytes:
    parts = [int(part) for part in value.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("SNMP OID is incomplete")
    encoded = bytearray((parts[0] * 40 + parts[1],))
    for part in parts[2:]:
        chunks = [part & 0x7F]
        part >>= 7
        while part:
            chunks.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(chunks))
    return _ber_tlv(0x06, bytes(encoded))


def _read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("SNMP response is truncated")
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if not count or offset + count > len(data):
            raise ValueError("SNMP response has an invalid length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("SNMP response value is truncated")
    return tag, data[offset:end], end


def _snmp_value(tag: int, value: bytes) -> float | None:
    if tag == 0x02:
        return float(int.from_bytes(value, "big", signed=True))
    if tag in (0x41, 0x42, 0x43, 0x46):
        return float(int.from_bytes(value, "big", signed=False))
    if tag == 0x04:
        match = re.search(rb"[-+]?\d+(?:\.\d+)?", value)
        return float(match.group(0)) if match else None
    return None


def read_radio_signal(address: str, community: str, port: int = 161, timeout: float = 2.0) -> dict[str, float]:
    request_id = int(time.monotonic() * 1000) & 0x7FFFFFFF
    varbinds = b"".join(_ber_tlv(0x30, _ber_oid(oid) + _ber_tlv(0x05, b"")) for oid in _RADIO_OIDS.values())
    pdu = _ber_integer(request_id) + _ber_integer(0) + _ber_integer(0) + _ber_tlv(0x30, varbinds)
    packet = _ber_tlv(0x30, _ber_integer(1) + _ber_tlv(0x04, community.encode("utf-8")) + _ber_tlv(0xA0, pdu))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(timeout)
        connection.sendto(packet, (address, port))
        response, _ = connection.recvfrom(8192)

    tag, message, _ = _read_tlv(response)
    if tag != 0x30:
        raise ValueError("Router returned a malformed SNMP message")
    _, _, offset = _read_tlv(message, 0)
    _, _, offset = _read_tlv(message, offset)
    pdu_tag, response_pdu, _ = _read_tlv(message, offset)
    if pdu_tag != 0xA2:
        raise ValueError("Router did not return an SNMP response")
    _, _, pdu_offset = _read_tlv(response_pdu, 0)
    _, error_value, pdu_offset = _read_tlv(response_pdu, pdu_offset)
    if int.from_bytes(error_value, "big", signed=True):
        raise ValueError("Router returned an SNMP error")
    _, _, pdu_offset = _read_tlv(response_pdu, pdu_offset)
    list_tag, varbind_list, _ = _read_tlv(response_pdu, pdu_offset)
    if list_tag != 0x30:
        raise ValueError("Router returned malformed SNMP variables")

    results: dict[str, float] = {}
    offset = 0
    for name in _RADIO_OIDS:
        bind_tag, bind, offset = _read_tlv(varbind_list, offset)
        if bind_tag != 0x30:
            continue
        _, _, bind_offset = _read_tlv(bind, 0)
        value_tag, value, _ = _read_tlv(bind, bind_offset)
        parsed = _snmp_value(value_tag, value)
        if parsed is not None:
            results[name] = parsed
    if not results:
        raise ValueError("Router returned no radio quality values")
    return results


def latest_snapshot() -> dict[str, Any]:
    with _SNAPSHOT_LOCK:
        return dict(_LATEST_SNAPSHOT)


def blackbox_snapshot() -> dict[str, Any]:
    snapshot = latest_snapshot()
    keep = (
        "available",
        "address",
        "collected_at",
        "uptime_seconds",
        "started_at",
        "signal_dbm",
        "rsrp_dbm",
        "rsrq_db",
        "sinr_db",
        "radio_score",
        "radio_score_label",
        "radio_score_limiting",
        "cell_id",
        "cell_changed",
        "connection_uptime_seconds",
        "mobile_reconnected",
        "temperature_c",
        "active_sim",
        "registration",
        "network_type",
        "restart_detected",
        "error",
    )
    return {key: snapshot[key] for key in keep if key in snapshot}


def _publish(snapshot: dict[str, Any]) -> None:
    with _SNAPSHOT_LOCK:
        _LATEST_SNAPSHOT.clear()
        _LATEST_SNAPSHOT.update(snapshot)


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = connection.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("Router closed the Modbus connection")
        payload.extend(chunk)
    return bytes(payload)


def _read_registers(connection: socket.socket, transaction: int, unit_id: int, address: int, count: int) -> list[int]:
    request = struct.pack(">HHHBBHH", transaction, 0, 6, unit_id, 3, address, count)
    connection.sendall(request)
    header = _receive_exact(connection, 7)
    response_transaction, protocol, length, response_unit = struct.unpack(">HHHB", header)
    if response_transaction != transaction or protocol != 0 or response_unit != unit_id:
        raise ValueError("Router returned an unexpected Modbus response")
    body = _receive_exact(connection, length - 1)
    if not body:
        raise ValueError("Router returned an empty Modbus response")
    function = body[0]
    if function & 0x80:
        code = body[1] if len(body) > 1 else -1
        raise ValueError(f"Router rejected the Modbus request (code {code})")
    if function != 3 or len(body) < 2 or body[1] != count * 2:
        raise ValueError("Router returned malformed Modbus register data")
    data = body[2:]
    return list(struct.unpack(f">{count}H", data))


def _uint32(registers: list[int], offset: int) -> int:
    return (registers[offset] << 16) | registers[offset + 1]


def _int32(registers: list[int], offset: int) -> int:
    return struct.unpack(">i", struct.pack(">HH", registers[offset], registers[offset + 1]))[0]


def _text(registers: list[int], offset: int, count: int = 16) -> str:
    raw = struct.pack(f">{count}H", *registers[offset:offset + count])
    return raw.rstrip(b"\x00\xff").decode("utf-8", errors="replace").strip()


def read_router(address: str, port: int = 502, unit_id: int = 1, timeout: float = 2.0) -> dict[str, Any]:
    with socket.create_connection((address, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        first = _read_registers(connection, 1, unit_id, 1, 86)
        second = _read_registers(connection, 2, unit_id, 87, 48)

    collected_at = now_iso()
    uptime_seconds = _uint32(first, 0)
    started_at = (datetime.fromisoformat(collected_at) - timedelta(seconds=uptime_seconds)).isoformat()
    return {
        "address": address,
        "port": port,
        "collected_at": collected_at,
        "uptime_seconds": uptime_seconds,
        "started_at": started_at,
        "signal_dbm": _int32(first, 2),
        "temperature_c": round(_int32(first, 4) / 10.0, 1),
        "hostname": _text(first, 6),
        "operator": _text(first, 22),
        "serial": _text(first, 38),
        "lan_mac": _text(first, 54),
        "device_name": _text(first, 70),
        "active_sim": _text(second, 0),
        "registration": _text(second, 16),
        "network_type": _text(second, 32),
        "available": True,
    }


def check_mobile_router(cfg: dict[str, Any]) -> list[CheckResult]:
    settings = cfg.get("mobile_router", {}) if isinstance(cfg.get("mobile_router", {}), dict) else {}
    if not settings.get("enabled", False):
        _publish({})
        return []

    address = str(settings.get("address") or "").strip()
    if not address:
        snapshot = {"available": False, "address": "", "error": "Router address is not configured", "collected_at": now_iso()}
        _publish(snapshot)
        return [CheckResult("mobile_router", "warning", "Mobile router address is not configured", snapshot, False)]

    try:
        snapshot = read_router(
            address,
            int(settings.get("port", 502) or 502),
            int(settings.get("unit_id", 1) or 1),
            float(settings.get("timeout_seconds", 2) or 2),
        )
        snmp_error = ""
        if settings.get("snmp_enabled", False):
            community = str(settings.get("snmp_community") or "").strip()
            if community:
                try:
                    snapshot.update(read_radio_signal(
                        address,
                        community,
                        int(settings.get("snmp_port", 161) or 161),
                        float(settings.get("timeout_seconds", 2) or 2),
                    ))
                except Exception as exc:
                    snmp_error = str(exc)
                    snapshot["radio_metrics_error"] = snmp_error
            else:
                snmp_error = "SNMP community is not configured"
                snapshot["radio_metrics_error"] = snmp_error
        uptime = int(snapshot.get("uptime_seconds") or 0)
        previous = _PREVIOUS_UPTIME.get(address)
        restarted = previous is not None and uptime + 30 < previous
        _PREVIOUS_UPTIME[address] = uptime
        snapshot["restart_detected"] = restarted
        cell_id = str(snapshot.get("cell_id") or "").strip()
        previous_cell = _PREVIOUS_CELL.get(address)
        snapshot["cell_changed"] = bool(cell_id and previous_cell and cell_id != previous_cell)
        if cell_id:
            _PREVIOUS_CELL[address] = cell_id
        connection_uptime_raw = snapshot.get("connection_uptime_seconds")
        connection_uptime = int(connection_uptime_raw) if connection_uptime_raw is not None else None
        previous_connection_uptime = _PREVIOUS_CONNECTION_UPTIME.get(address)
        snapshot["mobile_reconnected"] = bool(
            connection_uptime is not None
            and previous_connection_uptime is not None
            and connection_uptime + 30 < previous_connection_uptime
        )
        if connection_uptime is not None:
            _PREVIOUS_CONNECTION_UPTIME[address] = connection_uptime
        network = str(snapshot.get("network_type") or "Mobile connected")
        signal = snapshot.get("signal_dbm")
        quality = signal_quality(signal)
        snapshot["signal_quality"] = quality["label"]
        snapshot["signal_state"] = quality["state"]
        low_radio = []
        for metric, label in (("rsrp_dbm", "RSRP"), ("rsrq_db", "RSRQ"), ("sinr_db", "SINR")):
            metric_quality = radio_quality(metric, snapshot.get(metric))
            snapshot[f"{metric}_quality"] = metric_quality["label"]
            if metric_quality["state"] == "critical":
                low_radio.append(f"{label} {snapshot.get(metric):g}")
        score = radio_score(snapshot)
        snapshot["radio_score"] = score["score"]
        snapshot["radio_score_label"] = score["label"]
        snapshot["radio_score_state"] = score["state"]
        snapshot["radio_score_limiting"] = score["limiting"]
        _publish(snapshot)
        detail = f"{network}; signal {signal} dBm ({quality['label'].lower()})" if signal is not None else network
        if restarted:
            return [CheckResult("mobile_router", "warning", "Mobile router restart detected", snapshot, False)]
        if snmp_error:
            return [CheckResult("mobile_router", "warning", "Router reachable; detailed radio metrics unavailable", snapshot, False)]
        if low_radio:
            return [CheckResult("mobile_router", "warning", f"Router connected; low radio quality: {', '.join(low_radio)}", snapshot, False)]
        has_detailed_radio = any(snapshot.get(metric) is not None for metric in ("rsrp_dbm", "rsrq_db", "sinr_db"))
        if has_detailed_radio and score["state"] == "critical":
            limiting_key = {"RSRP": "rsrp_dbm", "RSRQ": "rsrq_db", "SINR": "sinr_db"}.get(score["limiting"])
            limiting_value = snapshot.get(limiting_key) if limiting_key else None
            limiting_unit = "dBm" if score["limiting"] == "RSRP" else "dB"
            limiting_detail = f" {limiting_value:g} {limiting_unit}" if isinstance(limiting_value, (int, float)) else ""
            return [CheckResult(
                "mobile_router",
                "warning",
                f"Router connected; poor radio quality, limited by {score['limiting']}{limiting_detail}",
                snapshot,
                False,
            )]
        if quality["state"] == "critical":
            return [CheckResult("mobile_router", "warning", f"Router connected; low mobile signal {signal} dBm", snapshot, False)]
        return [CheckResult("mobile_router", "healthy", detail, snapshot, False)]
    except Exception as exc:
        snapshot = {
            "available": False,
            "address": address,
            "port": int(settings.get("port", 502) or 502),
            "error": str(exc),
            "collected_at": now_iso(),
        }
        _publish(snapshot)
        return [CheckResult("mobile_router", "warning", f"Mobile router unavailable at {address}", snapshot, False)]
