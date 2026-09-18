import struct
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog import mobile_router
from va_watchdog.common import CheckResult
from va_watchdog.events import EventLog


def _set_int32(registers, offset, value):
    registers[offset:offset + 2] = struct.unpack(">HH", struct.pack(">i", value))


def _set_uint32(registers, offset, value):
    registers[offset:offset + 2] = struct.unpack(">HH", struct.pack(">I", value))


def _set_text(registers, offset, value):
    raw = value.encode("utf-8")[:32].ljust(32, b"\x00")
    registers[offset:offset + 16] = struct.unpack(">16H", raw)


class FakeModbusConnection:
    def __init__(self):
        self.pending = bytearray()
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        return None

    def sendall(self, request):
        transaction, protocol, length, unit_id, function, address, count = struct.unpack(">HHHBBHH", request)
        self.requests.append((address, count))
        self.assert_request(protocol, length, function)
        registers = [0] * count
        if address == 1:
            _set_uint32(registers, 0, 86400)
            _set_int32(registers, 2, -95)
            _set_int32(registers, 4, 463)
            _set_text(registers, 6, "RUTX50-Ellingers")
            _set_text(registers, 22, "Tesco Mobile")
            _set_text(registers, 38, "6003151436")
            _set_text(registers, 54, "20:97:27:43:46:80")
            _set_text(registers, 70, "RUTX50")
        else:
            _set_text(registers, 0, "SIM 1")
            _set_text(registers, 16, "Registered (home)")
            _set_text(registers, 32, "5G-NSA")
        data = struct.pack(f">{count}H", *registers)
        body = bytes((3, len(data))) + data
        header = struct.pack(">HHHB", transaction, 0, len(body) + 1, unit_id)
        self.pending.extend(header + body)

    @staticmethod
    def assert_request(protocol, length, function):
        if (protocol, length, function) != (0, 6, 3):
            raise AssertionError("unexpected Modbus request")

    def recv(self, length):
        chunk = bytes(self.pending[:length])
        del self.pending[:length]
        return chunk


class FakeSnmpSocket:
    def __init__(self, response):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        return None

    def sendto(self, payload, _target):
        self.sent = payload

    def recvfrom(self, _length):
        return self.response, ("192.168.1.1", 161)


def _snmp_response(values):
    varbinds = b""
    for oid, value in zip(mobile_router._RADIO_OIDS.values(), values):
        varbinds += mobile_router._ber_tlv(0x30, mobile_router._ber_oid(oid) + mobile_router._ber_integer(value))
    pdu = mobile_router._ber_integer(1) + mobile_router._ber_integer(0) + mobile_router._ber_integer(0) + mobile_router._ber_tlv(0x30, varbinds)
    return mobile_router._ber_tlv(0x30, mobile_router._ber_integer(1) + mobile_router._ber_tlv(0x04, b"private-read") + mobile_router._ber_tlv(0xA2, pdu))


class MobileRouterTests(unittest.TestCase):
    def setUp(self):
        mobile_router._PREVIOUS_UPTIME.clear()
        mobile_router._PREVIOUS_CELL.clear()
        mobile_router._PREVIOUS_CONNECTION_UPTIME.clear()
        mobile_router._publish({})

    def test_reads_teltonika_monitoring_registers(self):
        connection = FakeModbusConnection()
        with patch("va_watchdog.mobile_router.socket.create_connection", return_value=connection):
            result = mobile_router.read_router("192.168.1.1")

        self.assertEqual(connection.requests, [(1, 86), (87, 48)])
        self.assertEqual(result["uptime_seconds"], 86400)
        self.assertTrue(result["started_at"])
        self.assertEqual(result["signal_dbm"], -95)
        self.assertEqual(result["temperature_c"], 46.3)
        self.assertEqual(result["hostname"], "RUTX50-Ellingers")
        self.assertEqual(result["operator"], "Tesco Mobile")
        self.assertEqual(result["active_sim"], "SIM 1")
        self.assertEqual(result["registration"], "Registered (home)")
        self.assertEqual(result["network_type"], "5G-NSA")

    def test_reads_detailed_radio_metrics_in_one_snmp_request(self):
        connection = FakeSnmpSocket(_snmp_response([12345, 18, -91, -11, 3600]))
        with patch("va_watchdog.mobile_router.socket.socket", return_value=connection):
            result = mobile_router.read_radio_signal("192.168.1.1", "private-read")

        self.assertEqual(result, {
            "cell_id": 12345.0,
            "sinr_db": 18.0,
            "rsrp_dbm": -91.0,
            "rsrq_db": -11.0,
            "connection_uptime_seconds": 3600.0,
        })
        self.assertTrue(connection.sent)

    def test_disabled_router_adds_no_health_warning(self):
        self.assertEqual(mobile_router.check_mobile_router({"mobile_router": {"enabled": False}}), [])

    def test_blackbox_snapshot_omits_static_router_identity(self):
        mobile_router._publish({
            "available": True,
            "signal_dbm": -95,
            "uptime_seconds": 100,
            "serial": "secret-serial",
            "lan_mac": "00:11:22:33:44:55",
        })

        snapshot = mobile_router.blackbox_snapshot()

        self.assertEqual(snapshot["signal_dbm"], -95)
        self.assertNotIn("serial", snapshot)
        self.assertNotIn("lan_mac", snapshot)

    def test_unavailable_router_is_noncritical_warning(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1"}}
        with patch("va_watchdog.mobile_router.read_router", side_effect=TimeoutError("timed out")):
            check = mobile_router.check_mobile_router(cfg)[0]

        self.assertEqual(check.state, "warning")
        self.assertFalse(check.critical)
        self.assertFalse(check.value["available"])

    def test_signal_quality_uses_clear_operator_bands(self):
        self.assertEqual(mobile_router.signal_quality(-67), {"label": "Strong", "state": "healthy"})
        self.assertEqual(mobile_router.signal_quality(-90), {"label": "Fair", "state": "warning"})
        self.assertEqual(mobile_router.signal_quality(-105), {"label": "Low", "state": "critical"})
        self.assertEqual(mobile_router.radio_quality("rsrp_dbm", -110)["state"], "critical")
        self.assertEqual(mobile_router.radio_quality("rsrq_db", -12)["state"], "warning")
        self.assertEqual(mobile_router.radio_quality("sinr_db", 18)["state"], "healthy")

    def test_overall_radio_score_uses_the_weakest_detailed_metric(self):
        score = mobile_router.radio_score({"signal_dbm": -65, "rsrp_dbm": -88, "rsrq_db": -16, "sinr_db": 18})

        self.assertEqual(score["label"], "Poor")
        self.assertEqual(score["state"], "critical")
        self.assertEqual(score["limiting"], "RSRQ")

    def test_overall_radio_score_falls_back_to_rssi(self):
        score = mobile_router.radio_score({"signal_dbm": -70})

        self.assertEqual(score["label"], "Good")
        self.assertEqual(score["limiting"], "RSSI")

    def test_low_signal_is_advisory_while_router_is_connected(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1"}}
        sample = {"available": True, "uptime_seconds": 5000, "network_type": "LTE", "signal_dbm": -105}
        with patch("va_watchdog.mobile_router.read_router", return_value=sample):
            check = mobile_router.check_mobile_router(cfg)[0]

        self.assertEqual(check.state, "healthy")
        self.assertFalse(check.critical)
        self.assertEqual(check.value["signal_quality"], "Low")
        self.assertIn("advisory", check.message)

    def test_low_detailed_radio_metric_is_advisory_while_connected(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1", "snmp_enabled": True, "snmp_community": "private-read"}}
        sample = {"available": True, "uptime_seconds": 5000, "network_type": "LTE", "signal_dbm": -75}
        with patch("va_watchdog.mobile_router.read_router", return_value=sample), patch(
            "va_watchdog.mobile_router.read_radio_signal",
            return_value={"rsrp_dbm": -110.0, "rsrq_db": -12.0, "sinr_db": 8.0},
        ):
            check = mobile_router.check_mobile_router(cfg)[0]

        self.assertEqual(check.state, "healthy")
        self.assertFalse(check.critical)
        self.assertIn("RSRP", check.message)

    def test_poor_composite_radio_score_is_advisory_while_connected(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1", "snmp_enabled": True, "snmp_community": "private-read"}}
        sample = {"available": True, "uptime_seconds": 5000, "network_type": "LTE", "signal_dbm": -75}
        with patch("va_watchdog.mobile_router.read_router", return_value=sample), patch(
            "va_watchdog.mobile_router.read_radio_signal",
            return_value={"rsrp_dbm": -95.0, "rsrq_db": -14.0, "sinr_db": 8.0},
        ):
            check = mobile_router.check_mobile_router(cfg)[0]

        self.assertEqual(check.state, "healthy")
        self.assertFalse(check.critical)
        self.assertIn("limited by RSRQ", check.message)
        self.assertIn("Router connected", check.message)
        self.assertIn("-14", check.message)

    def test_uptime_reset_reports_router_restart_for_one_sample(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1"}}
        samples = [
            {"available": True, "uptime_seconds": 5000, "network_type": "5G", "signal_dbm": -95},
            {"available": True, "uptime_seconds": 20, "network_type": "5G", "signal_dbm": -95},
        ]
        with patch("va_watchdog.mobile_router.read_router", side_effect=samples):
            first = mobile_router.check_mobile_router(cfg)[0]
            second = mobile_router.check_mobile_router(cfg)[0]

        self.assertEqual(first.state, "healthy")
        self.assertEqual(second.state, "warning")
        self.assertTrue(second.value["restart_detected"])
        self.assertIn("restart detected", second.message.lower())

    def test_cell_change_and_mobile_reconnect_are_recorded(self):
        cfg = {"mobile_router": {"enabled": True, "address": "192.168.1.1", "snmp_enabled": True, "snmp_community": "private-read"}}
        router_samples = [
            {"available": True, "uptime_seconds": 5000, "network_type": "5G", "signal_dbm": -75},
            {"available": True, "uptime_seconds": 5060, "network_type": "5G", "signal_dbm": -75},
        ]
        radio_samples = [
            {"cell_id": 101, "connection_uptime_seconds": 4000, "rsrp_dbm": -88, "rsrq_db": -9, "sinr_db": 18},
            {"cell_id": 202, "connection_uptime_seconds": 10, "rsrp_dbm": -88, "rsrq_db": -9, "sinr_db": 18},
        ]
        with patch("va_watchdog.mobile_router.read_router", side_effect=router_samples), patch(
            "va_watchdog.mobile_router.read_radio_signal", side_effect=radio_samples
        ):
            first = mobile_router.check_mobile_router(cfg)[0]
            second = mobile_router.check_mobile_router(cfg)[0]

        self.assertFalse(first.value["cell_changed"])
        self.assertFalse(first.value["mobile_reconnected"])
        self.assertTrue(second.value["cell_changed"])
        self.assertTrue(second.value["mobile_reconnected"])
        self.assertEqual(second.state, "warning")
        self.assertIn("connection restarted", second.message.lower())

    def test_router_restart_is_logged_immediately_and_only_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            event_log = EventLog(str(path))
            check = CheckResult(
                "mobile_router",
                "warning",
                "Mobile router restart detected",
                {
                    "restart_detected": True,
                    "address": "192.168.1.1",
                    "collected_at": "2026-09-17T17:00:00+00:00",
                    "uptime_seconds": 20,
                },
                False,
            )

            event_log.add_state_changes([check])
            event_log.add_state_changes([check])
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["message"], "Mobile router restart detected")


if __name__ == "__main__":
    unittest.main()
