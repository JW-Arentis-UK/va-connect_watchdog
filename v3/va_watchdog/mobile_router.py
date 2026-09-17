from __future__ import annotations

import socket
import struct
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from .common import CheckResult, now_iso


_SNAPSHOT_LOCK = Lock()
_LATEST_SNAPSHOT: dict[str, Any] = {}
_PREVIOUS_UPTIME: dict[str, int] = {}


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
        uptime = int(snapshot.get("uptime_seconds") or 0)
        previous = _PREVIOUS_UPTIME.get(address)
        restarted = previous is not None and uptime + 30 < previous
        _PREVIOUS_UPTIME[address] = uptime
        snapshot["restart_detected"] = restarted
        _publish(snapshot)
        network = str(snapshot.get("network_type") or "Mobile connected")
        signal = snapshot.get("signal_dbm")
        detail = f"{network}; signal {signal} dBm" if signal is not None else network
        if restarted:
            return [CheckResult("mobile_router", "warning", "Mobile router restart detected", snapshot, False)]
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
