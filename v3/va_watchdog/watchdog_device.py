from __future__ import annotations

import os
import time

class HardwareWatchdog:
    def __init__(self, enabled: bool, device: str, feed_interval: int, event_log):
        self.enabled = enabled
        self.device = device
        self.feed_interval = feed_interval
        self.event_log = event_log
        self.handle = None
        self.last_feed = None
        self.feed_count = 0
        self.opened = False

    def open(self):
        if not self.enabled:
            return
        if not os.path.exists(self.device):
            self.event_log.add("warning", "hardware_watchdog", f"{self.device} not found")
            return
        try:
            self.handle = open(self.device, "wb", buffering=0)
            self.opened = True
            self.event_log.add("info", "hardware_watchdog", f"Opened {self.device}")
        except Exception as e:
            self.event_log.add("critical", "hardware_watchdog", f"Failed to open {self.device}: {e}")

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
