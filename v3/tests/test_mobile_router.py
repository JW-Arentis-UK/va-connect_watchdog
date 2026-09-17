import struct
import unittest
from unittest.mock import patch

from va_watchdog import mobile_router


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


class MobileRouterTests(unittest.TestCase):
    def setUp(self):
        mobile_router._PREVIOUS_UPTIME.clear()
        mobile_router._publish({})

    def test_reads_teltonika_monitoring_registers(self):
        connection = FakeModbusConnection()
        with patch("va_watchdog.mobile_router.socket.create_connection", return_value=connection):
            result = mobile_router.read_router("192.168.1.1")

        self.assertEqual(connection.requests, [(1, 86), (87, 48)])
        self.assertEqual(result["uptime_seconds"], 86400)
        self.assertEqual(result["signal_dbm"], -95)
        self.assertEqual(result["temperature_c"], 46.3)
        self.assertEqual(result["hostname"], "RUTX50-Ellingers")
        self.assertEqual(result["operator"], "Tesco Mobile")
        self.assertEqual(result["active_sim"], "SIM 1")
        self.assertEqual(result["registration"], "Registered (home)")
        self.assertEqual(result["network_type"], "5G-NSA")

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


if __name__ == "__main__":
    unittest.main()
