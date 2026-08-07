from __future__ import annotations

import ctypes
from pathlib import Path


class NeousysWatchdog:
    """Small adapter around the vendor WDT_DIO userspace API."""

    def __init__(self, library_path: str, timeout_seconds: int):
        self.library_path = str(library_path)
        self.timeout_seconds = int(timeout_seconds)
        self.library = None
        self.started = False

    def _load(self):
        path = Path(self.library_path)
        if not path.is_file():
            raise RuntimeError(f"Neousys watchdog library not found: {path}")

        library = ctypes.CDLL(str(path), use_errno=True)
        for name in ("InitWDT", "StopWDT", "StartWDT", "ResetWDT"):
            function = getattr(library, name)
            function.argtypes = []
            function.restype = ctypes.c_int
        library.SetWDT.argtypes = [ctypes.c_ushort, ctypes.c_ubyte]
        library.SetWDT.restype = ctypes.c_int
        self.library = library

    def start(self):
        if self.library is None:
            self._load()
        if not self.library.InitWDT():
            raise RuntimeError("Neousys InitWDT failed")
        # The vendor sample uses unit=1 for seconds.
        if not self.library.SetWDT(self.timeout_seconds, 1):
            raise RuntimeError(f"Neousys SetWDT({self.timeout_seconds}s) failed")
        if not self.library.StartWDT():
            raise RuntimeError("Neousys StartWDT failed")
        self.started = True
        try:
            if not self.library.ResetWDT():
                raise RuntimeError("Neousys initial ResetWDT failed")
        except Exception:
            self.stop()
            raise

    def feed(self):
        if not self.started or self.library is None:
            raise RuntimeError("Neousys watchdog has not been started")
        if not self.library.ResetWDT():
            raise RuntimeError("Neousys ResetWDT failed")

    def stop(self):
        if not self.started or self.library is None:
            return
        try:
            if not self.library.StopWDT():
                raise RuntimeError("Neousys StopWDT failed")
        finally:
            self.started = False
