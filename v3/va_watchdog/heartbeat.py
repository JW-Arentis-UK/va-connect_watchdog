from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any


def heartbeat_paths(cfg: dict[str, Any]) -> tuple[Path, Path]:
    events_path = Path(cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl")
    data_dir = events_path.parent
    return (
        Path(cfg.get("heartbeat_state_path") or data_dir / "heartbeat-state.json"),
        Path(cfg.get("heartbeat_path") or data_dir / "heartbeat.jsonl"),
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def monotonic_uptime() -> float:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 3)
    except Exception:
        return round(time.monotonic(), 3)


def read_state(cfg: dict[str, Any]) -> dict[str, Any]:
    state_path, _ = heartbeat_paths(cfg)
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def write_heartbeat(
    cfg: dict[str, Any],
    sequence: int,
    last_feed_utc: str = "",
    feed_allowed: bool = True,
    last_health_sample: str | None = None,
    last_health_sample_uptime: float | None = None,
) -> dict[str, Any]:
    state_path, history_path = heartbeat_paths(cfg)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    now = utc_now()
    record = {
        "time": now,
        "monotonic_uptime": monotonic_uptime(),
        "boot_id": boot_id(),
        "health_sequence": int(sequence),
        "last_health_sample": last_health_sample or now,
        "last_health_sample_monotonic_uptime": last_health_sample_uptime,
        "last_hardware_watchdog_feed": last_feed_utc or "",
        "feed_allowed": bool(feed_allowed),
    }
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
    with temporary.open("r+", encoding="utf-8") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, state_path)
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    trim_heartbeat_history(cfg)
    return record


class HeartbeatPublisher:
    """Publish process liveness independently from slow health collectors."""

    def __init__(self, cfg: dict[str, Any], interval_seconds: float | None = None):
        self.cfg = cfg
        configured = interval_seconds if interval_seconds is not None else cfg.get("heartbeat_interval_seconds", 5)
        self.interval_seconds = max(1.0, float(configured or 5))
        self._lock = Lock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._sequence = 0
        self._last_health_sample = utc_now()
        self._last_health_sample_uptime = monotonic_uptime()
        self._last_feed_utc = ""
        self._feed_allowed = True
        self._last_record: dict[str, Any] = {}
        self._last_error = ""

    def mark_health_sample(
        self,
        sequence: int,
        last_feed_utc: str = "",
        feed_allowed: bool = True,
        sampled_at: str | None = None,
    ) -> None:
        with self._lock:
            self._sequence = int(sequence)
            self._last_health_sample = sampled_at or utc_now()
            self._last_health_sample_uptime = monotonic_uptime()
            self._last_feed_utc = last_feed_utc or ""
            self._feed_allowed = bool(feed_allowed)

    def publish_once(self) -> dict[str, Any]:
        with self._lock:
            sequence = self._sequence
            last_health_sample = self._last_health_sample
            last_health_sample_uptime = self._last_health_sample_uptime
            last_feed_utc = self._last_feed_utc
            feed_allowed = self._feed_allowed
        try:
            record = write_heartbeat(
                self.cfg,
                sequence,
                last_feed_utc,
                feed_allowed,
                last_health_sample=last_health_sample,
                last_health_sample_uptime=last_health_sample_uptime,
            )
            with self._lock:
                self._last_record = dict(record)
                self._last_error = ""
            return record
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
            return {}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            record = dict(self._last_record)
            error = self._last_error
        if error:
            record["publisher_error"] = error
        record["publisher_running"] = bool(self._thread and self._thread.is_alive())
        return record

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="va-watchdog-heartbeat", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(0.0, timeout))

    def _run(self) -> None:
        next_deadline = time.monotonic() + self.interval_seconds
        while not self._stop.is_set():
            if self._stop.wait(max(0.0, next_deadline - time.monotonic())):
                break
            self.publish_once()
            next_deadline += self.interval_seconds
            if next_deadline <= time.monotonic():
                next_deadline = time.monotonic() + self.interval_seconds


def trim_heartbeat_history(cfg: dict[str, Any]) -> None:
    _, history_path = heartbeat_paths(cfg)
    if not history_path.exists():
        return
    retention = cfg.get("retention", {}) if isinstance(cfg.get("retention", {}), dict) else {}
    max_rows = max(100, int(retention.get("heartbeat_max_rows", 3600) or 3600))
    max_bytes = max(64 * 1024, int(retention.get("heartbeat_max_mb", 5) or 5) * 1024 * 1024)
    try:
        if history_path.stat().st_size <= max_bytes:
            return
        lines = history_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_rows:]
        temporary = history_path.with_suffix(history_path.suffix + ".tmp")
        temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        os.replace(temporary, history_path)
    except OSError:
        pass


def read_tail(cfg: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    _, history_path = heartbeat_paths(cfg)
    if not history_path.exists():
        return []
    rows = []
    try:
        for line in history_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max(1, int(limit)):]:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return rows


def heartbeat_age_seconds(state: dict[str, Any], current_uptime: float | None = None) -> float | None:
    if not isinstance(state, dict) or not state.get("monotonic_uptime"):
        return None
    try:
        now = monotonic_uptime() if current_uptime is None else float(current_uptime)
        return round(max(0.0, now - float(state["monotonic_uptime"])), 3)
    except (TypeError, ValueError):
        return None
