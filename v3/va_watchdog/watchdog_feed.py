from __future__ import annotations

try:
    import fcntl
except ImportError:  # Windows development/test hosts do not expose Linux file locks.
    fcntl = None
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from .config import load_config
from .heartbeat import heartbeat_age_seconds, read_state
from .watchdog_device import HardwareWatchdog
from .watchdog_grace import startup_grace_status
from .watchdog_test import trip_test_active


class FeedWorker:
    def __init__(self, cfg):
        self.cfg = cfg
        hw_cfg = cfg.get("hardware_watchdog", {})
        self.enabled = bool(hw_cfg.get("enabled", False))
        self.device = str(hw_cfg.get("device") or "/dev/watchdog0")
        self.interval = max(1, int(hw_cfg.get("feed_interval_seconds", 10) or 10))
        self.timeout = max(5, int(hw_cfg.get("timeout_seconds", 30) or 30))
        configured_stale = float(hw_cfg.get("stale_heartbeat_seconds", 15) or 15)
        self.stale_seconds = max(5.0, min(configured_stale, float(self.timeout) - 2.0))
        self.state_path = Path(cfg.get("hardware_watchdog_feed_state_path") or Path(cfg["events_path"]).parent / "hardware-watchdog-feed.json")
        self.lock_path = Path(cfg.get("hardware_watchdog_lock_path") or Path(cfg["events_path"]).parent / "hardware-watchdog.lock")
        self.stop_requested = False
        self.lock_handle = None
        self.hw = HardwareWatchdog(True, self.device, self.interval, None, timeout_seconds=self.timeout)
        self.last_error = ""
        self.error_count = 0
        self.magic_close = bool(hw_cfg.get("magic_close", False))
        self.nowayout = self._read_nowayout()

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
        self.stop_requested = True

    def write_state(self, status, last_feed=None):
        payload = {
            "pid": os.getpid(),
            "process_status": status,
            "device": self.device,
            "interval_seconds": self.interval,
            "timeout_seconds": self.hw.get_timeout(),
            "stale_heartbeat_seconds": self.stale_seconds,
            "magic_close_requested": self.magic_close,
            "shutdown_behavior": "write V before close" if self.magic_close else "driver close semantics; nowayout may keep timer armed",
            "nowayout": self.nowayout,
            "last_feed_utc": last_feed or "",
            "last_feed_unix": time.time() if last_feed else None,
            "feed_count": self.hw.feed_count,
            "last_error": self.last_error,
            "error_count": self.error_count,
            "updated_at": time.time(),
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.state_path)

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
        for path in ("/sys/module/iTCO_wdt/parameters/nowayout", "/sys/module/watchdog_core/parameters/nowayout"):
            try:
                value = Path(path).read_text(encoding="utf-8").strip().lower()
                if value:
                    return value in {"1", "y", "yes", "true"}
            except OSError:
                continue
        return None

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
            last_feed = ""
            self.write_state("running", last_feed)
            while not self.stop_requested:
                if not bool(load_config().get("hardware_watchdog", {}).get("enabled", False)):
                    self.stop_requested = True
                    break
                trip_active, trip_summary = trip_test_active(self.cfg)
                grace = startup_grace_status(self.cfg, trip_summary)
                heartbeat = read_state(self.cfg)
                age = heartbeat_age_seconds(heartbeat)
                # Startup grace protects boot: feed while the application starts.
                # After grace, only a fresh main-loop heartbeat permits feeding.
                allowed = self.heartbeat_allows_feed(heartbeat, grace, trip_active=trip_active)
                if allowed and (self.hw.last_feed is None or time.time() - self.hw.last_feed >= self.interval):
                    try:
                        self.hw.handle.write(b"\0")
                        self.hw.last_feed = time.time()
                        self.hw.feed_count += 1
                        last_feed = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(self.hw.last_feed))
                        self.last_error = ""
                        self.write_state("feeding", last_feed)
                    except Exception as exc:
                        self.last_error = str(exc)
                        self.error_count += 1
                        self.write_state("feed_error", last_feed)
                elif not allowed:
                    self.write_state("paused_stale_heartbeat" if not trip_active else "paused_trip_test", last_feed)
                time.sleep(min(1, self.interval))
        finally:
            self.write_state("stopping", last_feed if 'last_feed' in locals() else "")
            self.hw.close(magic_close=bool(self.cfg.get("hardware_watchdog", {}).get("magic_close", False)))
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
