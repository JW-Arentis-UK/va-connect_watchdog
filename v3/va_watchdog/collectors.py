"""Bounded daemon workers keep slow device checks outside supervisor liveness."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock, Thread

from .common import CheckResult


@dataclass
class _Worker:
    thread: Thread | None = None
    started: float = 0
    completed: float = 0
    result: list = field(default_factory=list)
    error: str = ""


class CollectorPool:
    """At most one worker per collector; a hung check cannot spawn replacements."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.workers = {}
        self.lock = Lock()

    def poll(self, name, interval, deadline, collect):
        now = self.clock()
        with self.lock:
            worker = self.workers.setdefault(name, _Worker())
            running = bool(worker.thread and worker.thread.is_alive())
            if not running and (not worker.thread or now - worker.completed >= interval):
                worker.started = now
                worker.thread = Thread(target=self._collect, args=(worker, collect),
                                       name=f"va-check-{name}", daemon=True)
                worker.thread.start()
                running = True
            age = now - worker.started
            if running and age >= deadline:
                return [CheckResult(f"{name}_collector", "unknown", "Check exceeded its deadline",
                                    {"age_seconds": round(age, 1), "deadline_seconds": deadline})]
            if worker.error:
                return [CheckResult(f"{name}_collector", "unknown", worker.error)]
            if worker.completed and now - worker.completed <= interval + deadline:
                return list(worker.result)
            return [CheckResult(f"{name}_collector", "unknown", "Waiting for current check")]

    def _collect(self, worker, collect):
        try:
            result, error = list(collect()), ""
        except Exception as exc:
            result, error = [], f"Collector unavailable: {type(exc).__name__}"
        with self.lock:
            worker.result, worker.error = result, error
            worker.completed = self.clock()
