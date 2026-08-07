from __future__ import annotations

import os
import subprocess
import time
import array

from .neousys_watchdog import NeousysWatchdog

try:
    import fcntl
except ImportError:  # Windows development/test hosts do not expose Linux ioctl support.
    fcntl = None


class HardwareWatchdog:
    WDIOC_SETTIMEOUT = 0xC0045706
    WDIOC_GETTIMEOUT = 0x80045707

    def __init__(
        self,
        enabled: bool,
        device: str,
        feed_interval: int,
        event_log,
        timeout_seconds: int = 30,
        backend: str = "linux",
        library_path: str = "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
    ):
        self.enabled = enabled
        self.device = device
        self.feed_interval = feed_interval
        self.timeout_seconds = int(timeout_seconds or 30)
        self.event_log = event_log
        self.backend = str(backend or "linux")
        self.library_path = str(library_path)
        self.handle = None
        self.vendor = None
        self.last_feed = None
        self.feed_count = 0
        self.opened = False

    def _event(self, level, message, data=None):
        if self.event_log is not None:
            self.event_log.add(level, "hardware_watchdog", message, data)

    def close(self, magic_close: bool = False):
        if self.backend == "neousys_wdt_dio":
            if self.vendor is None:
                return
            try:
                self.vendor.stop()
            finally:
                self.vendor = None
                self.opened = False
            return
        if self.handle is None:
            return
        try:
            if magic_close:
                self.handle.write(b"V")
        except Exception:
            pass
        try:
            self.handle.close()
        finally:
            self.handle = None
            self.opened = False

    def open(self):
        if not self.enabled:
            return
        if self.backend == "neousys_wdt_dio":
            self._open_neousys()
            return
        if not os.path.exists(self.device):
            self._try_load_itco()
        if not os.path.exists(self.device):
            self._event("warning", f"{self.device} not found")
            return
        try:
            self.handle = open(self.device, "wb", buffering=0)
            self._apply_timeout()
            self.opened = True
            self._event("info", f"Opened {self.device}")
        except Exception as e:
            self._event("critical", f"Failed to open {self.device}: {e}")

    def _open_neousys(self):
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

    def _apply_timeout(self):
        if self.handle is None or self.timeout_seconds <= 0:
            return
        try:
            timeout = array.array("i", [int(self.timeout_seconds)])
            if fcntl is None:
                return
            fcntl.ioctl(self.handle.fileno(), self.WDIOC_SETTIMEOUT, timeout, True)
            self.timeout_seconds = int(timeout[0])
            self._event("info", f"Set hardware watchdog timeout to {self.timeout_seconds}s")
        except Exception as exc:
            self._event("warning", f"Could not set watchdog timeout: {exc}")

    def get_timeout(self):
        if self.backend == "neousys_wdt_dio":
            return self.timeout_seconds
        if self.handle is None:
            return self.timeout_seconds
        try:
            timeout = array.array("i", [0])
            if fcntl is None:
                return self.timeout_seconds
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
                self._event("info", "Loaded iTCO_wdt because watchdog device was missing")
            else:
                detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
                self._event("warning", f"Could not load iTCO_wdt: {detail}")
        except Exception as e:
            self._event("warning", f"Could not load iTCO_wdt: {e}")

    def feed_if_due(self, healthy: bool):
        if not self.enabled or not self.opened:
            return False
        if not healthy:
            self._event("critical", "Not feeding hardware watchdog because critical health failed")
            return False
        now = time.time()
        if self.last_feed is None or now - self.last_feed >= self.feed_interval:
            try:
                self.feed()
                return True
            except Exception as e:
                self._event("critical", f"Feed failed: {e}")
        return False

    def feed(self):
        if not self.enabled or not self.opened:
            raise RuntimeError("hardware watchdog is not open")
        if self.backend == "neousys_wdt_dio":
            self.vendor.feed()
        else:
            self.handle.write(b"\0")
        self.last_feed = time.time()
        self.feed_count += 1
