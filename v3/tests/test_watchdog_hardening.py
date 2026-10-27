import base64
import copy
import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from va_watchdog.blackbox import BlackBoxRecorder
from va_watchdog.collectors import CollectorPool
from va_watchdog.common import CheckResult
from va_watchdog.config import DEFAULT_CONFIG, load_config
from va_watchdog.privileged_actions import execute
from va_watchdog.web import start_web
from va_watchdog.web_health import health_response
from va_watchdog.web_security import credentials, same_origin
from va_watchdog.watchdog import hardware_feed_status
from va_watchdog.watchdog_test import current_boot_id


class CollectorIsolationTests(unittest.TestCase):
    def test_hung_collector_is_bounded_and_does_not_block_other_checks(self):
        entered, release, finished = Event(), Event(), Event()
        clock = [100.0]
        calls = []
        pool = CollectorPool(clock=lambda: clock[0])

        def blocked():
            calls.append(1)
            entered.set()
            release.wait(3)
            finished.set()
            return [CheckResult("disk", "healthy")]

        try:
            before = time.monotonic()
            pool.poll("disk", 30, 10, blocked)
            self.assertLess(time.monotonic() - before, .2)
            self.assertTrue(entered.wait(1))
            clock[0] += 11
            result = pool.poll("disk", 30, 10, blocked)
            self.assertEqual(result[0].state, "unknown")
            self.assertIn("deadline", result[0].message)
            other = Event()
            pool.poll("network", 30, 10, lambda: (other.set(), [CheckResult("network", "healthy")])[1])
            self.assertTrue(other.wait(1))
            for _ in range(20):
                pool.poll("disk", 30, 10, blocked)
            self.assertEqual(len(calls), 1)
        finally:
            release.set()
            self.assertTrue(finished.wait(1))

    def test_failed_check_does_not_keep_old_healthy_result(self):
        pool = CollectorPool()
        done = Event()
        def failed():
            done.set()
            raise OSError("disk unavailable")
        pool.poll("disk", 30, 10, failed)
        self.assertTrue(done.wait(1))
        pool.workers["disk"].thread.join(1)
        result = pool.poll("disk", 30, 10, failed)
        self.assertEqual(result[0].state, "unknown")


class HardenedWebTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cfg = copy.deepcopy(DEFAULT_CONFIG)
        self.cfg["web"] = {"host": "127.0.0.1", "port": 0}
        self.cfg["events_path"] = str(self.root / "events.jsonl")
        self.cfg["status_path"] = str(self.root / "status.json")
        self.server = start_web(self.cfg)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def test_anonymous_local_post_cannot_reboot(self):
        with patch("va_watchdog.web.request_gateway_reboot") as reboot:
            with self.assertRaises(HTTPError) as denied:
                urlopen(Request(self.base + "/gateway-reboot-now", data=b"ack=1"))
            self.assertEqual(denied.exception.code, 401)
            reboot.assert_not_called()

    def test_authenticated_cross_site_post_cannot_reach_helper(self):
        with patch("va_watchdog.web_security.OperatorAuth.authenticate", return_value=True), patch("va_watchdog.web_security.helper_request") as helper:
            request = Request(self.base + "/gateway-reboot-now", data=b"ack=1", headers={"Origin": "http://untrusted.example"})
            with self.assertRaises(HTTPError) as denied:
                urlopen(request)
            self.assertEqual(denied.exception.code, 403)
            helper.assert_not_called()

    def test_valid_operator_action_reaches_only_allowlisted_helper(self):
        def dispatch(payload, **kwargs):
            return execute(payload, self.cfg)
        with patch("va_watchdog.web_security.OperatorAuth.authenticate", return_value=True), patch("va_watchdog.web_security.helper_request", side_effect=dispatch), patch("va_watchdog.privileged_actions.verify_operator", return_value=True), patch("va_watchdog.web.request_gateway_reboot", return_value={"ok": True, "message": "Restart scheduled"}) as reboot:
            request = Request(self.base + "/gateway-reboot-now", data=b"ack=1", headers={"Origin": self.base})
            with urlopen(request, timeout=10) as response:
                self.assertIn(b"Restart scheduled", response.read())
            reboot.assert_called_once()

    def test_helper_rejects_unlisted_action_and_header_injection(self):
        with patch("va_watchdog.privileged_actions.verify_operator", return_value=True):
            with self.assertRaises(ValueError):
                execute({"operation": "action", "path": "/shell"}, self.cfg)
            with self.assertRaises(ValueError):
                execute({"operation": "action", "path": "/gateway-reboot-now", "content_type": "text/plain\r\nInjected: yes"}, self.cfg)

    def test_helper_rejects_forged_camera_delivery(self):
        with self.assertRaises(PermissionError):
            execute({"operation": "camera_event", "path": "/gateway-reboot-now", "source": "127.0.0.1"}, self.cfg)

    def test_helper_preserves_local_only_pi_storage_policy(self):
        self.cfg["platform"] = {"kind": "raspberry_pi"}
        with patch("va_watchdog.privileged_actions.verify_operator", return_value=True), patch("va_watchdog.web.expand_pi_storage") as expand:
            response = execute({"operation": "action", "path": "/pi-storage-expand",
                                "source": "198.51.100.2", "destination": "127.0.0.1"}, self.cfg)
            self.assertIn(b"own browser", response)
            expand.assert_not_called()

    def test_compatible_purge_api_keeps_query_parameters_in_helper(self):
        with patch("va_watchdog.privileged_actions.verify_operator", return_value=True), patch("va_watchdog.web.retention_purge_data", return_value={"ok": True}) as purge:
            execute({"operation": "action", "path": "/api/purge?mode=all&older_than_days=7"}, self.cfg)
        purge.assert_called_once_with(self.cfg, mode="all", older_than_days=7)

    def test_liveness_survives_missing_core_but_readiness_fails(self):
        with urlopen(self.base + "/api/livez") as response:
            self.assertTrue(json.load(response)["ok"])
        with self.assertRaises(HTTPError) as unready:
            urlopen(self.base + "/api/readyz")
        self.assertEqual(unready.exception.code, 503)

    def test_readiness_requires_fresh_healthy_status(self):
        path = Path(self.cfg["status_path"])
        now = datetime.now(timezone.utc)
        for stamp, state, expected in [(now, "healthy", True), (now, "critical", False), (now - timedelta(minutes=5), "healthy", False)]:
            path.write_text(json.dumps({"time": stamp.isoformat(), "state": state, "boot_id": current_boot_id()}), encoding="utf-8")
            self.assertEqual(health_response(self.cfg)["ready"], expected)

    def test_storage_page_uses_saved_core_result_without_web_write_probe(self):
        Path(self.cfg["status_path"]).write_text(json.dumps({
            "time": datetime.now(timezone.utc).isoformat(), "state": "healthy",
            "recording_storage": {"status": "healthy", "message": "Storage ready", "mountpoint": "/recordings"}}))
        with patch("va_watchdog.web.recording_storage_status", side_effect=AssertionError("Web must not probe writes")) as probe, patch("va_watchdog.web.recording_storage_candidates", return_value=[]):
            with urlopen(self.base + "/recording-storage-configure") as response:
                self.assertEqual(response.status, 200)
            probe.assert_not_called()

    def test_legacy_saved_reboot_permission_is_overridden(self):
        config = self.root / "config.json"
        config.write_text('{"recovery":{"allow_reboot":true,"critical_grace_seconds":60,"consolidated_policy":{"enabled":true,"restart_network_before_reboot":true}}}', encoding="utf-8")
        with patch("va_watchdog.config.CONFIG_PATHS", [config]):
            recovery = load_config()["recovery"]
        self.assertFalse(recovery["allow_reboot"])
        self.assertNotIn("critical_grace_seconds", recovery)
        self.assertNotIn("restart_network_before_reboot", recovery["consolidated_policy"])
        self.assertTrue(recovery["consolidated_policy"]["enabled"])


class CredentialAndEvidenceTests(unittest.TestCase):
    def test_access_setup_migrates_legacy_reboot_flags_and_keeps_backup(self):
        script = Path(__file__).parents[1] / "scripts/setup_web_access.sh"
        source = script.read_text(encoding="utf-8")
        block = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(json.dumps({"identity": {"site_name": "Keep this"}, "recovery": {
                "allow_reboot": True, "critical_grace_seconds": 60,
                "consolidated_policy": {"restart_network_before_reboot": True}}}))
            with patch("sys.argv", [str(script), str(config)]):
                exec(compile(block, str(script), "exec"), {})
            migrated = json.loads(config.read_text())
            self.assertFalse(migrated["recovery"]["allow_reboot"])
            self.assertNotIn("critical_grace_seconds", migrated["recovery"])
            self.assertNotIn("restart_network_before_reboot", migrated["recovery"]["consolidated_policy"])
            self.assertEqual(migrated["identity"]["site_name"], "Keep this")
            backup = next(Path(temporary).glob("*.bak"))
            self.assertTrue(json.loads(backup.read_text())["recovery"]["allow_reboot"])

    @unittest.skipUnless(os.name == "posix", "Linux password verification")
    def test_linux_password_verifier_works_without_removed_crypt_and_spwd_modules(self):
        import ctypes
        from unittest.mock import mock_open
        from va_watchdog.privileged_actions import verify_operator
        lib = ctypes.CDLL("libcrypt.so.1")
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.crypt.restype = ctypes.c_char_p
        encoded = lib.crypt(b"operator-test", b"$6$test-salt$").decode()
        authorization = "Basic " + base64.b64encode(b"vsuser:operator-test").decode()
        with patch("builtins.open", mock_open(read_data=f"vsuser:{encoded}:20000:0:99999:7:::\n")):
            self.assertTrue(verify_operator({}, authorization))
            self.assertFalse(verify_operator({}, "Basic " + base64.b64encode(b"vsuser:wrong").decode()))

    def test_previous_boot_feed_proof_is_not_current_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = time.time()
            (root / "feed.json").write_text(json.dumps({"boot_id": "old", "pid": os.getpid(), "process_status": "feeding", "last_feed_unix": now, "updated_at": now}))
            (root / "proof.json").write_text('{"boot_id":"old","proven":true}')
            cfg = {"events_path": str(root / "events.jsonl"), "hardware_watchdog_feed_state_path": str(root / "feed.json"), "hardware_watchdog_proof_path": str(root / "proof.json")}
            with patch("va_watchdog.watchdog.Path.exists", return_value=True):
                status = hardware_feed_status(cfg, {"boot_id": "new"})
            self.assertFalse(status["feeding"])
            self.assertFalse(status["proven_this_boot"])

    def test_basic_credentials_are_strict_and_never_accept_empty_password(self):
        self.assertIsNone(credentials("Basic !!!"))
        self.assertIsNone(credentials("Basic " + base64.b64encode(b"vsuser:").decode()))
        self.assertEqual(credentials("Basic " + base64.b64encode(b"vsuser:test").decode()), ("vsuser", "test"))

    def test_origin_uses_actual_forwarded_host_and_port(self):
        self.assertTrue(same_origin({"Host": "router:8088", "Origin": "http://router:8088"}))
        self.assertFalse(same_origin({"Host": "router:8088", "Origin": "http://router:8089"}))
        self.assertFalse(same_origin({"Host": "router:8088"}))

    def test_blackbox_pending_queue_is_bounded_when_disk_writes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            sampler = Mock(current_boot_id="boot-a")
            sampler.sample.side_effect = lambda sequence, *_args: {"boot_id": "boot-a", "sequence": sequence}
            cfg = {"events_path": str(Path(temporary) / "events.jsonl"), "blackbox": {"retention_seconds": 60, "interval_seconds": 2}}
            recorder = BlackBoxRecorder(cfg, sampler=sampler)
            with patch("va_watchdog.blackbox._write_segment", side_effect=OSError("disk full")):
                for _ in range(100):
                    recorder.sample_once()
                    recorder.flush()
            self.assertEqual(len(recorder.pending), recorder.settings["max_rows"])
            self.assertGreater(recorder.dropped_pending_samples, 0)
            self.assertEqual(recorder.pending[-1]["sequence"], 100)
