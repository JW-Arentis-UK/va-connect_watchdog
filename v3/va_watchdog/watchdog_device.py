from __future__ import annotations

import os
import time

from .neousys_watchdog import NeousysWatchdog


class HardwareWatchdog:
    """Neousys-only hardware watchdog used by the independent feeder."""

    def __init__(
        self,
        enabled: bool,
        device: str,
        feed_interval: int,
        event_log,
        timeout_seconds: int = 30,
        backend: str = "neousys_wdt_dio",
        library_path: str = "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
    ):
        if backend != "neousys_wdt_dio":
            raise ValueError(f"unsupported hardware watchdog backend: {backend}")
        self.enabled = enabled
        self.device = device
        self.feed_interval = feed_interval
        self.timeout_seconds = int(timeout_seconds or 30)
        self.event_log = event_log
        self.backend = "neousys_wdt_dio"
        self.library_path = str(library_path)
        self.vendor = None
        self.last_feed = None
        self.feed_count = 0
        self.opened = False

    def _event(self, level, message, data=None):
        if self.event_log is not None:
            self.event_log.add(level, "hardware_watchdog", message, data)

    def close(self, magic_close: bool = False):
        del magic_close
        if self.vendor is None:
            return
        try:
            self.vendor.stop()
        finally:
            self.vendor = None
            self.opened = False

    def open(self):
        if not self.enabled:
            return
        if not os.path.exists(self.device):
            self._event("warning", f"{self.device} not found")
            return
        try:
            self.vendor = NeousysWatchdog(self.library_path, self.timeout_seconds)
            self.vendor.start()
            self.opened = True
            self._event("info", f"Started Neousys watchdog through {self.device}")
        except Exception as exc:
            if self.vendor is not None:
                try:
                    self.vendor.stop()
                except Exception:
                    pass
            self.vendor = None
            self.opened = False
            self._event("critical", f"Failed to start Neousys watchdog: {exc}")

    def get_timeout(self):
        return self.timeout_seconds

    def feed_if_due(self, healthy: bool):
        # Ordinary health faults remain diagnostic; feeder liveness controls resets.
        del healthy
        if not self.enabled or not self.opened:
            return False
        now = time.time()
        if self.last_feed is None or now - self.last_feed >= self.feed_interval:
            try:
                self.feed()
                return True
            except Exception as exc:
                self._event("critical", f"Feed failed: {exc}")
        return False

    def feed(self):
        if not self.enabled or not self.opened:
            raise RuntimeError("hardware watchdog is not open")
        self.vendor.feed()
        self.last_feed = time.time()
        self.feed_count += 1
