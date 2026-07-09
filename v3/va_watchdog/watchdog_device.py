from __future__ import annotations

import os
import subprocess
import time
import array
import fcntl

class HardwareWatchdog:
    WDIOC_SETTIMEOUT = 0xC0045706
    WDIOC_GETTIMEOUT = 0x80045707

    def __init__(self, enabled: bool, device: str, feed_interval: int, event_log, timeout_seconds: int = 30):
        self.enabled = enabled
        self.device = device
        self.feed_interval = feed_interval
        self.timeout_seconds = int(timeout_seconds or 30)
        self.event_log = event_log
        self.handle = None
        self.last_feed = None
        self.feed_count = 0
        self.opened = False

    def open(self):
        if not self.enabled:
            return
        if not os.path.exists(self.device):
            self._try_load_itco()
        if not os.path.exists(self.device):
            self.event_log.add("warning", "hardware_watchdog", f"{self.device} not found")
            return
        try:
            self.handle = open(self.device, "wb", buffering=0)
            self._apply_timeout()
            self.opened = True
            self.event_log.add("info", "hardware_watchdog", f"Opened {self.device}")
        except Exception as e:
            self.event_log.add("critical", "hardware_watchdog", f"Failed to open {self.device}: {e}")

    def _apply_timeout(self):
        if self.handle is None or self.timeout_seconds <= 0:
            return
        try:
            timeout = array.array("i", [int(self.timeout_seconds)])
            fcntl.ioctl(self.handle.fileno(), self.WDIOC_SETTIMEOUT, timeout, True)
            self.timeout_seconds = int(timeout[0])
            self.event_log.add("info", "hardware_watchdog", f"Set hardware watchdog timeout to {self.timeout_seconds}s")
        except Exception as exc:
            self.event_log.add("warning", "hardware_watchdog", f"Could not set watchdog timeout: {exc}")

    def get_timeout(self):
        if self.handle is None:
            return self.timeout_seconds
        try:
            timeout = array.array("i", [0])
            fcntl.ioctl(self.handle.fileno(), self.WDIOC_GETTIMEOUT, timeout, True)
            return int(timeout[0])
        except Exception:
            return self.timeout_seconds

    def _try_load_itco(self):
        try:
            result = subprocess.run(
                ["modprobe", "iTCO_wdt"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                self.event_log.add("info", "hardware_watchdog", "Loaded iTCO_wdt because watchdog device was missing")
            else:
                detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
                self.event_log.add("warning", "hardware_watchdog", f"Could not load iTCO_wdt: {detail}")
        except Exception as e:
            self.event_log.add("warning", "hardware_watchdog", f"Could not load iTCO_wdt: {e}")

    def feed_if_due(self, healthy: bool):
        if not self.enabled or self.handle is None:
            return False
        if not healthy:
            self.event_log.add("critical", "hardware_watchdog", "Not feeding hardware watchdog because critical health failed")
            return False
        now = time.time()
        if self.last_feed is None or now - self.last_feed >= self.feed_interval:
            try:
                self.handle.write(b"\0")
                self.last_feed = now
                self.feed_count += 1
                return True
            except Exception as e:
                self.event_log.add("critical", "hardware_watchdog", f"Feed failed: {e}")
        return False
