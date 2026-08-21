from __future__ import annotations

try:
    import fcntl
except ImportError:  # Windows development/test hosts do not expose Linux file locks.
    fcntl = None
import os
import signal
import subprocess
import time
from pathlib import Path

from .config import load_config
from .heartbeat import heartbeat_age_seconds, read_state
from .watchdog_device import HardwareWatchdog
from .watchdog_grace import startup_grace_status
from .watchdog_test import fail_trip_test, trip_test_active
from .watchdog_feed_evidence import (
    append_lifecycle,
    atomic_write_json,
    current_boot_id,
    preserve_previous_boot_state,
)


class FeedWorker:
    def __init__(self, cfg):
        self.cfg = cfg
        hw_cfg = cfg.get("hardware_watchdog", {})
        self.enabled = bool(hw_cfg.get("enabled", False))
        self.backend = "neousys_wdt_dio"
        self.device = "/dev/wdt_dio"
        self.library_path = str(
            hw_cfg.get("library_path")
            or "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so"
        )
        self.interval = max(1, int(hw_cfg.get("feed_interval_seconds", 10) or 10))
        self.timeout = max(5, int(hw_cfg.get("timeout_seconds", 30) or 30))
        configured_stale = float(hw_cfg.get("stale_heartbeat_seconds", 15) or 15)
        self.stale_seconds = max(5.0, min(configured_stale, float(self.timeout) - 2.0))
        self.state_path = Path(cfg.get("hardware_watchdog_feed_state_path") or Path(cfg["events_path"]).parent / "hardware-watchdog-feed.json")
        self.lock_path = Path(cfg.get("hardware_watchdog_lock_path") or Path(cfg["events_path"]).parent / "hardware-watchdog.lock")
        self.stop_requested = False
        self.lock_handle = None
        self.hw = HardwareWatchdog(
            True,
            self.device,
            self.interval,
            None,
            timeout_seconds=self.timeout,
            backend=self.backend,
            library_path=self.library_path,
        )
        self.last_error = ""
        self.error_count = 0
        self.magic_close = bool(hw_cfg.get("magic_close", False))
        self.nowayout = self._read_nowayout()
        configured_verify = float(hw_cfg.get("trip_countdown_verify_seconds", 8) or 8)
        self.trip_verify_seconds = max(3.0, min(configured_verify, float(self.timeout) - 5.0))
        self.trip_started_monotonic = None
        self.trip_initial_timeleft = None
        self.trip_current_timeleft = None
        self.trip_countdown_status = "inactive"
        self.trip_countdown_confirmed = False
        self.boot_id = current_boot_id()
        self.last_lifecycle_status = ""
        self.last_lifecycle_checkpoint = 0.0
        self.lifecycle_checkpoint_seconds = max(10, int(hw_cfg.get("lifecycle_checkpoint_seconds", 60) or 60))
        self.received_signal = ""
        heartbeat_boot = str(read_state(cfg).get("boot_id") or "")
        self.preservation_result = preserve_previous_boot_state(
            cfg,
            self.boot_id,
            fallback_boot_id=heartbeat_boot,
        )

    def heartbeat_allows_feed(self, heartbeat, grace, trip_active=False, current_uptime=None):
        if trip_active:
            return False
        if grace.get("active"):
            return True
        age = heartbeat_age_seconds(heartbeat, current_uptime=current_uptime)
        return bool(
            age is not None
            and age <= self.stale_seconds
            and heartbeat.get("boot_id") == grace.get("boot_id")
            and heartbeat.get("feed_allowed", True)
        )

    def stop(self, *_args):
        if _args:
            try:
                self.received_signal = signal.Signals(int(_args[0])).name
            except (TypeError, ValueError):
                self.received_signal = str(_args[0])
        self.stop_requested = True

    def write_state(self, status):
        last_feed_unix = self.hw.last_feed
        last_feed_utc = ""
        if last_feed_unix is not None:
            last_feed_utc = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(last_feed_unix))
        payload = {
            "boot_id": self.boot_id,
            "pid": os.getpid(),
            "process_status": status,
            "backend": self.backend,
            "device": self.device,
            "interval_seconds": self.interval,
            "timeout_seconds": self.hw.get_timeout(),
            "stale_heartbeat_seconds": self.stale_seconds,
            "magic_close_requested": self.magic_close,
            "shutdown_behavior": self._shutdown_behavior(),
            "nowayout": self.nowayout,
            "last_feed_utc": last_feed_utc,
            "last_feed_unix": last_feed_unix,
            "feed_count": self.hw.feed_count,
            "last_error": self.last_error,
            "error_count": self.error_count,
            "trip_countdown": {
                "status": self.trip_countdown_status,
                "verify_seconds": self.trip_verify_seconds,
                "initial_timeleft": self.trip_initial_timeleft,
                "current_timeleft": self.trip_current_timeleft,
                "confirmed": self.trip_countdown_confirmed,
            },
            "updated_at": time.time(),
        }
        try:
            atomic_write_json(self.state_path, payload)
        except OSError:
            # State reporting must never interrupt hardware feeding.
            pass
        self._record_lifecycle(status, payload)

    def _record_lifecycle(self, status, payload, force=False):
        now = time.monotonic()
        checkpoint_due = now - self.last_lifecycle_checkpoint >= self.lifecycle_checkpoint_seconds
        if not force and status == self.last_lifecycle_status and not checkpoint_due:
            return
        event = "feed_checkpoint" if status == "feeding" and status == self.last_lifecycle_status else f"state_{status}"
        append_lifecycle(
            self.cfg,
            self.boot_id,
            event,
            {
                "status": status,
                "backend": self.backend,
                "device": self.device,
                "feed_count": payload.get("feed_count", 0),
                "last_feed_utc": payload.get("last_feed_utc", ""),
                "last_error": payload.get("last_error", ""),
                "error_count": payload.get("error_count", 0),
            },
        )
        self.last_lifecycle_status = status
        self.last_lifecycle_checkpoint = now

    def log_lifecycle(self, event, details=None):
        append_lifecycle(self.cfg, self.boot_id, event, details or {})

    def _read_timeleft(self):
        return None

    def evaluate_trip_countdown(self, trip_active, current_monotonic=None, timeleft=None):
        if not trip_active:
            self.trip_started_monotonic = None
            self.trip_initial_timeleft = None
            self.trip_current_timeleft = None
            self.trip_countdown_status = "inactive"
            self.trip_countdown_confirmed = False
            return False

        now = time.monotonic() if current_monotonic is None else float(current_monotonic)
        current = self._read_timeleft() if timeleft is None else timeleft
        self.trip_current_timeleft = current

        if self.trip_started_monotonic is None:
            self.trip_started_monotonic = now
            self.trip_initial_timeleft = current
            self.trip_countdown_status = "verifying" if current is not None else "unavailable"
            return True

        if (
            current is not None
            and self.trip_initial_timeleft is not None
            and current < self.trip_initial_timeleft
        ):
            self.trip_countdown_confirmed = True
            self.trip_countdown_status = "countdown_confirmed"

        elapsed = max(0.0, now - self.trip_started_monotonic)
        if current is None or self.trip_initial_timeleft is None:
            self.trip_countdown_status = "unavailable"
            if elapsed >= float(self.timeout) + 5.0:
                message = (
                    "Trip test failed safely: this watchdog does not expose a countdown and "
                    "the gateway did not reboot within the configured timeout; feeding resumed."
                )
                fail_trip_test(
                    self.cfg,
                    message,
                    {
                        "backend": self.backend,
                        "device": self.device,
                        "elapsed_seconds": round(elapsed, 1),
                    },
                )
                self.last_error = message
                self.error_count += 1
                self.trip_countdown_status = "failed_no_reset"
                return False
            return True

        if not self.trip_countdown_confirmed and elapsed >= self.trip_verify_seconds:
            message = (
                "Trip test failed safely: the hardware watchdog counter did not decrease; "
                "feeding resumed and the gateway was not expected to reboot."
            )
            fail_trip_test(
                self.cfg,
                message,
                {
                    "device": self.device,
                    "initial_timeleft": self.trip_initial_timeleft,
                    "current_timeleft": current,
                    "verification_seconds": round(elapsed, 1),
                },
            )
            self.last_error = message
            self.error_count += 1
            self.trip_countdown_status = "failed_static_counter"
            return False

        if self.trip_countdown_confirmed and elapsed >= float(self.timeout) + 5.0:
            message = (
                "Trip test failed safely: the counter decreased but the gateway did not reboot "
                "within the watchdog timeout; feeding resumed."
            )
            fail_trip_test(
                self.cfg,
                message,
                {
                    "device": self.device,
                    "initial_timeleft": self.trip_initial_timeleft,
                    "current_timeleft": current,
                    "elapsed_seconds": round(elapsed, 1),
                },
            )
            self.last_error = message
            self.error_count += 1
            self.trip_countdown_status = "failed_no_reset"
            return False

        self.trip_countdown_status = "countdown_confirmed" if self.trip_countdown_confirmed else "verifying"
        return True

    def acquire_lock(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_handle = self.lock_path.open("a+")
        if fcntl is None:
            return
        try:
            fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError(f"another watchdog feeder owns {self.device}: {exc}") from exc

    def _read_nowayout(self):
        return None

    def _shutdown_behavior(self):
        return "StopWDT on orderly service stop; feeder crash leaves hardware timer active"

    def _legacy_conflict(self):
        for unit in ("watchdog.service", "wd_keepalive.service"):
            try:
                result = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=3, check=False)
                if result.stdout.strip() == "active":
                    return unit
            except Exception:
                continue
        return ""

    def run(self):
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.acquire_lock()
        self.log_lifecycle("feeder_started", {
            "backend": self.backend,
            "device": self.device,
            "enabled": self.enabled,
            "previous_state": self.preservation_result,
        })
        if not self.enabled:
            self.write_state("disabled")
            if self.lock_handle:
                if fcntl is not None:
                    fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_UN)
                self.lock_handle.close()
            return 0
        conflict = self._legacy_conflict()
        if conflict:
            self.last_error = f"legacy watchdog service is active: {conflict}"
            self.error_count += 1
            self.write_state("legacy_conflict")
            if self.lock_handle:
                if fcntl is not None:
                    fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_UN)
                self.lock_handle.close()
            return 1
        self.write_state("starting")
        try:
            self.hw.open()
            if not self.hw.opened:
                self.write_state("device_unavailable")
                return 1
            self.write_state("running")
            self.log_lifecycle("hardware_opened", {"timeout_seconds": self.hw.get_timeout()})
            while not self.stop_requested:
                if not bool(load_config().get("hardware_watchdog", {}).get("enabled", False)):
                    self.log_lifecycle("feed_disabled_by_config")
                    self.stop_requested = True
                    break
                trip_active, trip_summary = trip_test_active(self.cfg)
                effective_trip_active = self.evaluate_trip_countdown(trip_active)
                grace = startup_grace_status(self.cfg, trip_summary)
                heartbeat = read_state(self.cfg)
                age = heartbeat_age_seconds(heartbeat)
                # Startup grace protects boot: feed while the application starts.
                # After grace, only a fresh main-loop heartbeat permits feeding.
                allowed = self.heartbeat_allows_feed(heartbeat, grace, trip_active=effective_trip_active)
                if allowed and (self.hw.last_feed is None or time.time() - self.hw.last_feed >= self.interval):
                    try:
                        self.hw.feed()
                        self.last_error = ""
                        self.write_state("feeding")
                    except Exception as exc:
                        self.last_error = str(exc)
                        self.error_count += 1
                        self.write_state("feed_error")
                elif not allowed:
                    self.write_state("paused_stale_heartbeat" if not effective_trip_active else "paused_trip_test")
                time.sleep(min(1, self.interval))
        except Exception as exc:
            self.last_error = str(exc)
            self.error_count += 1
            self.log_lifecycle("feeder_exception", {"error": str(exc), "feed_count": self.hw.feed_count})
            raise
        finally:
            if self.received_signal:
                self.log_lifecycle("signal_received", {"signal": self.received_signal})
            self.write_state("stopping")
            try:
                self.log_lifecycle("stop_wdt_requested", {"opened": self.hw.opened, "feed_count": self.hw.feed_count})
                self.hw.close(magic_close=bool(self.cfg.get("hardware_watchdog", {}).get("magic_close", False)))
                self.log_lifecycle("stop_wdt_completed", {"opened": self.hw.opened})
            except Exception as exc:
                self.last_error = f"orderly watchdog stop failed: {exc}"
                self.error_count += 1
                self.write_state("stop_error")
                self.log_lifecycle("stop_wdt_error", {"error": str(exc)})
            finally:
                if self.lock_handle:
                    if fcntl is not None:
                        fcntl.flock(self.lock_handle.fileno(), fcntl.LOCK_UN)
                    self.lock_handle.close()
        return 0


def main():
    while True:
        cfg = load_config()
        if not bool(cfg.get("hardware_watchdog", {}).get("enabled", False)):
            FeedWorker(cfg).write_state("disabled")
            time.sleep(5)
            continue
        return FeedWorker(cfg).run()


if __name__ == "__main__":
    raise SystemExit(main())
