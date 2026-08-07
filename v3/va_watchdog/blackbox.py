from __future__ import annotations

import gzip
import json
import math
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any


_ACTIVE_RECORDER: "BlackBoxRecorder | None" = None


def blackbox_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    configured = cfg.get("blackbox", {}) if isinstance(cfg.get("blackbox", {}), dict) else {}
    interval = max(1.0, float(configured.get("interval_seconds", 2) or 2))
    retention = max(60, int(configured.get("retention_seconds", 900) or 900))
    checkpoint = max(interval, float(configured.get("checkpoint_seconds", 10) or 10))
    return {
        "enabled": bool(configured.get("enabled", True)),
        "path": str(configured.get("path") or data_dir / "blackbox.jsonl"),
        "segment_dir": str(configured.get("segment_dir") or data_dir / "blackbox-buffer"),
        "state_path": str(configured.get("state_path") or data_dir / "blackbox-state.json"),
        "interval_seconds": interval,
        "sample_seconds": interval,
        "retention_seconds": retention,
        "checkpoint_seconds": checkpoint,
        "max_rows": max(30, int(math.ceil(retention / interval))),
        "main_service": str(configured.get("main_service") or "esg.service"),
        "max_kernel_records_per_sample": max(10, int(configured.get("max_kernel_records_per_sample", 256) or 256)),
    }


def boot_id(proc_root: Path | str = "/proc") -> str:
    try:
        return (Path(proc_root) / "sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def check_unexpected_boot(cfg: dict[str, Any], event_log=None) -> dict[str, Any]:
    settings = blackbox_cfg(cfg)
    state_path = Path(settings["state_path"])
    current = boot_id()
    previous = _read_json(state_path)
    last_boot = str(previous.get("boot_id") or "")
    changed = bool(last_boot and current and last_boot != current)
    result = {
        "changed": changed,
        "previous_boot_id": last_boot,
        "current_boot_id": current,
        "previous_time": previous.get("updated_at", ""),
        "previous_last_sample_utc": previous.get("last_sample_utc", ""),
        "previous_last_sequence": previous.get("last_sequence"),
        "detected_at": _now_iso(),
    }
    next_state = {**previous, "boot_id": current, "updated_at": result["detected_at"]}
    if changed:
        next_state = {"schema_version": 2, "boot_id": current, "updated_at": result["detected_at"]}
    _atomic_write_json(state_path, next_state)
    if changed and event_log:
        event_log.add("warning", "blackbox", "Unexpected reboot detected", result)
    return result


class KernelMessageReader:
    """Count new kernel warning/error records through a persistent kmsg cursor."""

    def __init__(self, path: Path | str = "/dev/kmsg", maximum: int = 256):
        self.path = Path(path)
        self.maximum = max(10, int(maximum))
        self.fd: int | None = None
        self.available = False
        self.error = ""
        self.last_sequence: int | None = None
        self.dropped_records = 0
        try:
            self.fd = os.open(str(self.path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
            try:
                os.lseek(self.fd, 0, os.SEEK_END)
            except OSError:
                pass
            self.available = True
        except OSError as exc:
            self.error = str(exc)

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def sample(self) -> dict[str, Any]:
        result = {"available": self.available, "warnings": 0, "errors": 0, "records": 0, "dropped": 0}
        if self.fd is None:
            if self.error:
                result["error"] = self.error
            return result
        for _ in range(self.maximum):
            try:
                raw = os.read(self.fd, 8192)
            except BlockingIOError:
                break
            except OSError as exc:
                self.error = str(exc)
                result["error"] = self.error
                break
            if not raw:
                break
            result["records"] += 1
            header = raw.split(b";", 1)[0].decode("ascii", errors="ignore").split(",")
            try:
                priority = int(header[0]) & 7
                sequence = int(header[1])
            except (IndexError, ValueError):
                continue
            if self.last_sequence is not None and sequence > self.last_sequence + 1:
                lost = sequence - self.last_sequence - 1
                self.dropped_records += lost
                result["dropped"] += lost
            self.last_sequence = sequence
            if priority <= 3:
                result["errors"] += 1
            elif priority == 4:
                result["warnings"] += 1
        if result["records"] >= self.maximum:
            result["backlog"] = True
        return result


class ProcSampler:
    def __init__(
        self,
        cfg: dict[str, Any],
        proc_root: Path | str = "/proc",
        sys_root: Path | str = "/sys",
        kmsg_path: Path | str = "/dev/kmsg",
    ):
        self.cfg = cfg
        self.settings = blackbox_cfg(cfg)
        self.proc_root = Path(proc_root)
        self.sys_root = Path(sys_root)
        self.current_boot_id = boot_id(self.proc_root)
        self.clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        self.page_size = int(os.sysconf("SC_PAGE_SIZE"))
        self.cpu_count = max(1, os.cpu_count() or 1)
        self.previous_cpu: dict[str, tuple[int, ...]] = {}
        self.previous_disks: dict[str, tuple[float, dict[str, int]]] = {}
        self.previous_process: tuple[int, int, float] | None = None
        self.main_pid: int | None = None
        self.sensor_paths: list[Path] = []
        self.edac_paths: list[tuple[str, Path]] = []
        self.frequency_paths: dict[int, Path] = {}
        self.disk_roles: dict[str, list[str]] = {}
        self.recording_path = self._recording_path()
        self.last_discovery = 0.0
        self.kernel = KernelMessageReader(kmsg_path, self.settings["max_kernel_records_per_sample"])
        self._discover_static_paths()

    def close(self) -> None:
        self.kernel.close()

    def sample(self, sequence: int, scheduled_monotonic: float | None = None) -> dict[str, Any]:
        started = time.monotonic()
        uptime = self._uptime()
        errors: list[str] = []

        def collect(name, callback, default):
            try:
                return callback()
            except Exception as exc:
                errors.append(f"{name}:{type(exc).__name__}")
                return default

        if started - self.last_discovery >= 60 or not self.disk_roles:
            collect("discovery", self._discover_dynamic_paths, None)
            self.last_discovery = started

        sample = {
            "v": 2,
            "time": _now_iso(),
            "monotonic_uptime": round(uptime, 3) if uptime is not None else None,
            "boot_id": self.current_boot_id,
            "sequence": int(sequence),
            "cpu": collect("cpu", self._cpu, {}),
            "memory": collect("memory", self._memory, {}),
            "pressure": collect("pressure", self._pressure, {}),
            "disks": collect("disks", lambda: self._disks(started), []),
            "recording_free": collect("recording_free", self._recording_free, {}),
            "temperature": collect("temperature", self._temperature, {}),
            "edac": collect("edac", self._edac, {}),
            "kernel": collect("kernel", self.kernel.sample, {"available": False}),
            "videosoft": collect("videosoft", lambda: self._videosoft(started), {}),
            "heartbeat": collect("heartbeat", lambda: self._heartbeat(uptime), {}),
        }
        finished = time.monotonic()
        sample["sample_duration_ms"] = round((finished - started) * 1000, 2)
        if scheduled_monotonic is not None:
            sample["schedule_lag_ms"] = round(max(0.0, started - scheduled_monotonic) * 1000, 2)
        if errors:
            sample["collector_errors"] = errors
        return sample

    def _uptime(self) -> float | None:
        try:
            return float((self.proc_root / "uptime").read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            return None

    def _cpu(self) -> dict[str, Any]:
        cpu_rows, running, blocked = parse_proc_stat((self.proc_root / "stat").read_text(encoding="utf-8"))
        utilization = cpu_utilization(self.previous_cpu, cpu_rows)
        self.previous_cpu = cpu_rows
        load = parse_loadavg((self.proc_root / "loadavg").read_text(encoding="utf-8"))
        cores = []
        for name in sorted((item for item in utilization if item != "cpu"), key=lambda value: int(value[3:])):
            index = int(name[3:])
            cores.append({"core": index, "utilization_percent": utilization[name], "frequency_mhz": self._frequency(index)})
        return {
            "overall_percent": utilization.get("cpu"),
            "cores": cores,
            "load_1": load.get("load_1"),
            "load_5": load.get("load_5"),
            "load_15": load.get("load_15"),
            "runnable_tasks": load.get("runnable_tasks", running),
            "total_tasks": load.get("total_tasks"),
            "blocked_tasks": blocked,
        }

    def _frequency(self, index: int) -> float | None:
        path = self.frequency_paths.get(index)
        if not path:
            return None
        try:
            value = float(path.read_text(encoding="utf-8").strip())
            return round(value / 1000.0, 1)
        except (OSError, ValueError):
            return None

    def _memory(self) -> dict[str, Any]:
        values = parse_meminfo((self.proc_root / "meminfo").read_text(encoding="utf-8"))
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0))
        swap_total = values.get("SwapTotal", 0)
        swap_free = values.get("SwapFree", 0)
        return {
            "total_mb": _kb_to_mb(total),
            "available_mb": _kb_to_mb(available),
            "used_percent": round((total - available) / total * 100, 1) if total else None,
            "swap_total_mb": _kb_to_mb(swap_total),
            "swap_used_mb": _kb_to_mb(max(0, swap_total - swap_free)),
            "dirty_mb": _kb_to_mb(values.get("Dirty", 0)),
            "writeback_mb": _kb_to_mb(values.get("Writeback", 0)),
        }

    def _pressure(self) -> dict[str, Any]:
        result = {}
        for resource in ("cpu", "memory", "io"):
            path = self.proc_root / "pressure" / resource
            try:
                result[resource] = parse_pressure(path.read_text(encoding="utf-8"))
            except OSError:
                result[resource] = {"available": False}
        return result

    def _disks(self, now: float) -> list[dict[str, Any]]:
        rows = parse_diskstats((self.proc_root / "diskstats").read_text(encoding="utf-8"))
        result = []
        for device, roles in sorted(self.disk_roles.items()):
            current = rows.get(device)
            if not current:
                result.append({"device": device, "roles": roles, "available": False})
                continue
            previous = self.previous_disks.get(device)
            metrics = disk_delta(previous, (now, current))
            self.previous_disks[device] = (now, current)
            result.append({"device": device, "roles": roles, "available": True, **metrics})
        return result

    def _recording_free(self) -> dict[str, Any]:
        path = Path(self.recording_path)
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        available = stat.f_bavail * stat.f_frsize
        return {
            "path": str(path),
            "free_gb": round(available / 1024**3, 2),
            "used_percent": round((total - available) / total * 100, 1) if total else None,
        }

    def _temperature(self) -> dict[str, Any]:
        readings = []
        for path in self.sensor_paths:
            try:
                value = float(path.read_text(encoding="utf-8").strip())
                if abs(value) > 1000:
                    value /= 1000.0
                if -20 <= value <= 150:
                    readings.append((round(value, 1), path.name))
            except (OSError, ValueError):
                continue
        if not readings:
            return {"available": False}
        hottest = max(readings, key=lambda item: item[0])
        return {"available": True, "max_c": hottest[0], "sensor": hottest[1], "sensor_count": len(readings)}

    def _edac(self) -> dict[str, Any]:
        if not self.edac_paths:
            return {"available": False, "ce_count": None, "ue_count": None, "dimms": {}}
        ce_total = 0
        ue_total = 0
        dimms: dict[str, dict[str, int]] = {}
        for label, path in self.edac_paths:
            try:
                value = int(path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                continue
            if label == "ce_count":
                ce_total += value
            elif label == "ue_count":
                ue_total += value
            else:
                dimm, counter = label.split(":", 1)
                dimms.setdefault(dimm, {})[counter] = value
        return {"available": True, "ce_count": ce_total, "ue_count": ue_total, "dimms": dimms}

    def _videosoft(self, now: float) -> dict[str, Any]:
        if self.main_pid is None or not (self.proc_root / str(self.main_pid) / "stat").exists():
            self.main_pid = self._find_service_pid()
            self.previous_process = None
        if not self.main_pid:
            return {"service": self.settings["main_service"], "available": False}
        text = (self.proc_root / str(self.main_pid) / "stat").read_text(encoding="utf-8")
        command, fields = parse_process_stat(text)
        ticks = int(fields[11]) + int(fields[12])
        cpu_percent = None
        if self.previous_process and self.previous_process[0] == self.main_pid:
            elapsed = max(0.001, now - self.previous_process[2])
            cpu_percent = max(0.0, (ticks - self.previous_process[1]) / self.clock_ticks / elapsed * 100)
        self.previous_process = (self.main_pid, ticks, now)
        rss_mb = int(fields[21]) * self.page_size / 1024**2
        return {
            "service": self.settings["main_service"],
            "available": True,
            "pid": self.main_pid,
            "command": command,
            "state": fields[0],
            "parent_pid": int(fields[1]),
            "threads": int(fields[17]),
            "cpu_percent_one_core": round(cpu_percent, 1) if cpu_percent is not None else None,
            "cpu_percent_system": round(cpu_percent / self.cpu_count, 1) if cpu_percent is not None else None,
            "memory_mb": round(rss_mb, 1),
        }

    def _heartbeat(self, uptime: float | None) -> dict[str, Any]:
        path = Path(self.cfg.get("heartbeat_state_path") or Path(self.cfg["events_path"]).parent / "heartbeat-state.json")
        state = _read_json(path)
        age = None
        try:
            if uptime is not None and state.get("boot_id") == self.current_boot_id:
                age = round(max(0.0, uptime - float(state.get("monotonic_uptime"))), 3)
        except (TypeError, ValueError):
            age = None
        return {
            "available": bool(state),
            "age_seconds": age,
            "health_sequence": state.get("health_sequence"),
            "last_health_sample": state.get("last_health_sample"),
            "last_hardware_watchdog_feed": state.get("last_hardware_watchdog_feed"),
            "feed_allowed": state.get("feed_allowed"),
        }

    def _recording_path(self) -> str:
        recording = self.cfg.get("recording_storage", {}) if isinstance(self.cfg.get("recording_storage", {}), dict) else {}
        storage = self.cfg.get("storage", {}) if isinstance(self.cfg.get("storage", {}), dict) else {}
        return str(
            recording.get("monitored_path")
            or recording.get("mountpoint")
            or storage.get("recordings_path")
            or "/home/vsuser/recordings"
        )

    def _discover_static_paths(self) -> None:
        for index in range(self.cpu_count):
            base = self.sys_root / "devices/system/cpu" / f"cpu{index}" / "cpufreq"
            for name in ("scaling_cur_freq", "cpuinfo_cur_freq"):
                path = base / name
                if path.exists():
                    self.frequency_paths[index] = path
                    break
        self.sensor_paths = sorted((self.sys_root / "class/thermal").glob("thermal_zone*/temp"))
        self.sensor_paths.extend(sorted((self.sys_root / "class/hwmon").glob("hwmon*/temp*_input")))
        edac_root = self.sys_root / "devices/system/edac/mc"
        for controller in sorted(edac_root.glob("mc*")):
            for counter in ("ce_count", "ue_count"):
                path = controller / counter
                if path.exists():
                    self.edac_paths.append((counter, path))
            for dimm in sorted(controller.glob("dimm*")):
                for filename, label in (("dimm_ce_count", "ce_count"), ("dimm_ue_count", "ue_count")):
                    path = dimm / filename
                    if path.exists():
                        self.edac_paths.append((f"{controller.name}/{dimm.name}:{label}", path))

    def _discover_dynamic_paths(self) -> None:
        roles: dict[str, list[str]] = {}
        for role, path in (("root", "/"), ("recording", self.recording_path)):
            device = resolve_block_device(self.proc_root, self.sys_root, path)
            if device:
                roles.setdefault(device, []).append(role)
        self.disk_roles = roles
        if self.main_pid is None:
            self.main_pid = self._find_service_pid()

    def _find_service_pid(self) -> int | None:
        service = self.settings["main_service"]
        candidates = [
            self.sys_root / "fs/cgroup/system.slice" / service / "cgroup.procs",
            self.sys_root / "fs/cgroup/systemd/system.slice" / service / "cgroup.procs",
        ]
        candidates.extend(self.sys_root.glob(f"fs/cgroup/*/system.slice/{service}/cgroup.procs"))
        pids = set()
        for path in candidates:
            try:
                pids.update(int(value) for value in path.read_text(encoding="utf-8").split() if value.isdigit())
            except OSError:
                continue
        oldest: tuple[int, int] | None = None
        for pid in pids:
            try:
                _, fields = parse_process_stat((self.proc_root / str(pid) / "stat").read_text(encoding="utf-8"))
                start_ticks = int(fields[19])
                if oldest is None or start_ticks < oldest[0]:
                    oldest = (start_ticks, pid)
            except (OSError, ValueError, IndexError):
                continue
        return oldest[1] if oldest else None


class BlackBoxRecorder:
    def __init__(self, cfg: dict[str, Any], sampler: ProcSampler | None = None):
        self.cfg = cfg
        self.settings = blackbox_cfg(cfg)
        self.sampler = sampler or (ProcSampler(cfg) if self.settings["enabled"] else None)
        self.ring: deque[dict[str, Any]] = deque(maxlen=self.settings["max_rows"])
        self.pending: list[dict[str, Any]] = []
        self._lock = Lock()
        self._stop = Event()
        self._thread: Thread | None = None
        existing = []
        if self.sampler:
            existing = [
                row for row in _read_segment_rows(cfg)
                if str(row.get("boot_id") or "") == self.sampler.current_boot_id
            ][-self.settings["max_rows"]:]
            self.ring.extend(existing)
        self.sequence = max((int(row.get("sequence") or 0) for row in existing), default=0)
        self.last_error = ""
        self.missed_deadlines = 0

    def start(self) -> None:
        global _ACTIVE_RECORDER
        if not self.settings["enabled"] or (self._thread and self._thread.is_alive()):
            return
        _ACTIVE_RECORDER = self
        self._stop.clear()
        self._thread = Thread(target=self._run, name="va-watchdog-blackbox", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        global _ACTIVE_RECORDER
        self._stop.set()
        if self._thread:
            self._thread.join(max(0.0, timeout))
        self.flush()
        if self.sampler:
            self.sampler.close()
        if _ACTIVE_RECORDER is self:
            _ACTIVE_RECORDER = None

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.ring)

    def sample_once(self, scheduled_monotonic: float | None = None) -> dict[str, Any]:
        if not self.sampler:
            raise RuntimeError("black-box recorder is disabled")
        self.sequence += 1
        sample = self.sampler.sample(self.sequence, scheduled_monotonic)
        with self._lock:
            self.ring.append(sample)
            self.pending.append(sample)
        return sample

    def flush(self) -> dict[str, Any]:
        with self._lock:
            rows = self.pending
            self.pending = []
        if not rows:
            return {"written": 0}
        if not self.sampler:
            return {"written": 0, "error": "black-box recorder is disabled"}
        try:
            result = _write_segment(self.cfg, rows)
            _rotate_segments(self.cfg, self.sampler.current_boot_id)
            last = rows[-1]
            _atomic_write_json(Path(self.settings["state_path"]), {
                "schema_version": 2,
                "boot_id": self.sampler.current_boot_id,
                "updated_at": _now_iso(),
                "last_sample_utc": last.get("time"),
                "last_sample_monotonic_uptime": last.get("monotonic_uptime"),
                "last_sequence": last.get("sequence"),
                "recorder_running": bool(self._thread and self._thread.is_alive()),
                "sample_seconds": self.settings["interval_seconds"],
                "retention_seconds": self.settings["retention_seconds"],
                "checkpoint_seconds": self.settings["checkpoint_seconds"],
                "missed_deadlines": self.missed_deadlines,
                "last_error": "",
            })
            self.last_error = ""
            return result
        except Exception as exc:
            self.last_error = str(exc)
            with self._lock:
                self.pending = rows + self.pending
            return {"written": 0, "error": self.last_error}

    def _run(self) -> None:
        interval = self.settings["interval_seconds"]
        checkpoint = self.settings["checkpoint_seconds"]
        next_sample = time.monotonic()
        next_checkpoint = next_sample + checkpoint
        while not self._stop.is_set():
            now = time.monotonic()
            if now < next_sample:
                self._stop.wait(next_sample - now)
                continue
            try:
                self.sample_once(next_sample)
            except Exception as exc:
                self.last_error = str(exc)
            next_sample += interval
            after = time.monotonic()
            if after >= next_checkpoint:
                self.flush()
                while next_checkpoint <= after:
                    next_checkpoint += checkpoint
            if next_sample <= after:
                skipped = int((after - next_sample) // interval) + 1
                self.missed_deadlines += skipped
                next_sample += skipped * interval
        self.flush()


def start_recorder(cfg: dict[str, Any]) -> BlackBoxRecorder:
    recorder = BlackBoxRecorder(cfg)
    recorder.start()
    return recorder


def maybe_capture_blackbox(cfg: dict[str, Any], status: dict[str, Any] | None = None, force: bool = False) -> dict[str, Any]:
    """Compatibility entry point; the active recorder owns normal sampling."""
    if _ACTIVE_RECORDER:
        if force:
            sample = _ACTIVE_RECORDER.sample_once()
            return {"captured": True, "time": sample.get("time"), "buffered": True}
        return {"captured": False, "reason": "independent_recorder_active"}
    settings = blackbox_cfg(cfg)
    if not settings["enabled"]:
        return {"captured": False, "reason": "disabled"}
    sampler = ProcSampler(cfg)
    try:
        sample = sampler.sample(1)
        result = _write_segment(cfg, [sample])
        return {"captured": True, "time": sample.get("time"), **result}
    finally:
        sampler.close()


def read_blackbox(cfg: dict[str, Any], limit: int = 100, boot_id_filter: str | None = None) -> list[dict[str, Any]]:
    rows = _read_segment_rows(cfg)
    legacy = Path(blackbox_cfg(cfg)["path"])
    if legacy.exists():
        rows.extend(_read_jsonl(legacy))
    if _ACTIVE_RECORDER:
        rows.extend(_ACTIVE_RECORDER.snapshot())
    unique = {}
    for row in rows:
        if boot_id_filter and str(row.get("boot_id") or "") != boot_id_filter:
            continue
        key = (str(row.get("boot_id") or ""), row.get("sequence"), str(row.get("time") or ""))
        unique[key] = row
    ordered = sorted(unique.values(), key=lambda row: (str(row.get("time") or ""), int(row.get("sequence") or 0)))
    return ordered[-max(1, int(limit)):] if limit is not None else ordered


def blackbox_summary(cfg: dict[str, Any]) -> dict[str, Any]:
    settings = blackbox_cfg(cfg)
    rows = _ACTIVE_RECORDER.snapshot() if _ACTIVE_RECORDER else read_blackbox(cfg, limit=settings["max_rows"])
    last = rows[-1] if rows else {}
    segment_dir = Path(settings["segment_dir"])
    state = _read_json(Path(settings["state_path"]))
    return {
        "enabled": settings["enabled"],
        "path": str(segment_dir),
        "sample_seconds": settings["interval_seconds"],
        "retention_seconds": settings["retention_seconds"],
        "checkpoint_seconds": settings["checkpoint_seconds"],
        "max_rows": settings["max_rows"],
        "rows": len(rows),
        "first_time": rows[0].get("time") if rows else "",
        "last_time": last.get("time", ""),
        "last_boot_id": last.get("boot_id", ""),
        "last_sequence": last.get("sequence"),
        "recorder_running": bool(_ACTIVE_RECORDER and _ACTIVE_RECORDER._thread and _ACTIVE_RECORDER._thread.is_alive()),
        "last_error": (_ACTIVE_RECORDER.last_error if _ACTIVE_RECORDER else "") or state.get("last_error", ""),
        "missed_deadlines": _ACTIVE_RECORDER.missed_deadlines if _ACTIVE_RECORDER else state.get("missed_deadlines", 0),
        "size_bytes": _directory_size(segment_dir),
    }


def write_boot_archive(cfg: dict[str, Any], destination: Path, previous_boot_id: str) -> dict[str, Any]:
    rows = read_blackbox(cfg, limit=None, boot_id_filter=previous_boot_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(destination, "wt", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, separators=(",", ":")) + "\n")
    return {
        "path": destination.name,
        "source": blackbox_cfg(cfg)["segment_dir"],
        "rows": len(rows),
        "size_bytes": destination.stat().st_size,
        "first_sample_utc": rows[0].get("time") if rows else "",
        "last_successful_sample_utc": rows[-1].get("time") if rows else "",
        "last_sequence": rows[-1].get("sequence") if rows else None,
    }


def trim_blackbox(cfg: dict[str, Any]) -> None:
    """Retain compatibility with legacy blackbox.jsonl installations."""
    settings = blackbox_cfg(cfg)
    path = Path(settings["path"])
    if path.exists():
        configured = cfg.get("blackbox", {}) if isinstance(cfg.get("blackbox", {}), dict) else {}
        max_rows = max(50, int(configured.get("max_rows", settings["max_rows"]) or settings["max_rows"]))
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        compact_batch = max(50, max_rows // 10)
        if len(lines) > max_rows + compact_batch:
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_text("\n".join(lines[-max_rows:]) + "\n", encoding="utf-8")
            os.replace(temporary, path)
    _rotate_segments(cfg, boot_id())


def parse_proc_stat(text: str) -> tuple[dict[str, tuple[int, ...]], int | None, int | None]:
    cpus = {}
    running = None
    blocked = None
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "cpu" or (fields[0].startswith("cpu") and fields[0][3:].isdigit()):
            try:
                cpus[fields[0]] = tuple(int(value) for value in fields[1:])
            except ValueError:
                continue
        elif fields[0] == "procs_running" and len(fields) > 1:
            running = int(fields[1])
        elif fields[0] == "procs_blocked" and len(fields) > 1:
            blocked = int(fields[1])
    return cpus, running, blocked


def cpu_utilization(previous: dict[str, tuple[int, ...]], current: dict[str, tuple[int, ...]]) -> dict[str, float | None]:
    result = {}
    for name, values in current.items():
        old = previous.get(name)
        if not old:
            result[name] = None
            continue
        total_delta = sum(values) - sum(old)
        idle_delta = sum(values[3:5]) - sum(old[3:5]) if len(values) >= 5 and len(old) >= 5 else values[3] - old[3]
        result[name] = round(max(0.0, min(100.0, (total_delta - idle_delta) / total_delta * 100)), 1) if total_delta > 0 else None
    return result


def parse_loadavg(text: str) -> dict[str, Any]:
    fields = text.split()
    running, total = (fields[3].split("/", 1) + [None])[:2] if len(fields) > 3 else (None, None)
    return {
        "load_1": float(fields[0]) if len(fields) > 0 else None,
        "load_5": float(fields[1]) if len(fields) > 1 else None,
        "load_15": float(fields[2]) if len(fields) > 2 else None,
        "runnable_tasks": int(running) if running is not None else None,
        "total_tasks": int(total) if total is not None else None,
    }


def parse_meminfo(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        try:
            result[key] = int(value.strip().split()[0])
        except (ValueError, IndexError):
            continue
    return result


def parse_pressure(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"available": True}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        values = {}
        for item in fields[1:]:
            key, _, value = item.partition("=")
            try:
                values[key] = int(value) if key == "total" else float(value)
            except ValueError:
                continue
        result[fields[0]] = values
    return result


def parse_diskstats(text: str) -> dict[str, dict[str, int]]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        try:
            result[fields[2]] = {
                "read_ios": int(fields[3]),
                "read_sectors": int(fields[5]),
                "write_ios": int(fields[7]),
                "write_sectors": int(fields[9]),
                "in_flight": int(fields[11]),
                "io_ms": int(fields[12]),
                "weighted_io_ms": int(fields[13]),
            }
        except ValueError:
            continue
    return result


def disk_delta(previous: tuple[float, dict[str, int]] | None, current: tuple[float, dict[str, int]]) -> dict[str, Any]:
    now, values = current
    if not previous:
        return {"read_bps": None, "write_bps": None, "read_iops": None, "write_iops": None, "busy_percent": None, "average_queue_depth": None, "in_flight": values["in_flight"]}
    old_time, old = previous
    elapsed = max(0.001, now - old_time)
    elapsed_ms = elapsed * 1000
    delta = lambda key: max(0, values[key] - old.get(key, 0))
    return {
        "read_bps": round(delta("read_sectors") * 512 / elapsed),
        "write_bps": round(delta("write_sectors") * 512 / elapsed),
        "read_iops": round(delta("read_ios") / elapsed, 2),
        "write_iops": round(delta("write_ios") / elapsed, 2),
        "busy_percent": round(min(100.0, delta("io_ms") / elapsed_ms * 100), 1),
        "average_queue_depth": round(delta("weighted_io_ms") / elapsed_ms, 2),
        "in_flight": values["in_flight"],
    }


def parse_process_stat(text: str) -> tuple[str, list[str]]:
    opening = text.find("(")
    closing = text.rfind(")")
    if opening < 0 or closing <= opening:
        raise ValueError("invalid process stat")
    return text[opening + 1:closing], text[closing + 2:].split()


def resolve_block_device(proc_root: Path, sys_root: Path, target_path: str) -> str | None:
    try:
        resolved = Path(target_path).resolve()
    except OSError:
        resolved = Path(target_path)
    best: tuple[int, str] | None = None
    try:
        lines = (proc_root / "self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        before, separator, _ = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        if len(fields) < 5:
            continue
        mountpoint = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mountpoint)
        except ValueError:
            continue
        if best is None or len(str(mountpoint)) > best[0]:
            best = (len(str(mountpoint)), fields[2])
    if not best:
        return None
    link = sys_root / "dev/block" / best[1]
    try:
        block_path = link.resolve()
    except OSError:
        return None
    if (block_path / "partition").exists():
        return block_path.parent.name
    return block_path.name


def _write_segment(cfg: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"written": 0}
    settings = blackbox_cfg(cfg)
    directory = Path(settings["segment_dir"])
    directory.mkdir(parents=True, exist_ok=True)
    boot_prefix = str(rows[-1].get("boot_id") or "unknown").replace("-", "")[:12]
    first_sequence = int(rows[0].get("sequence") or 0)
    last_sequence = int(rows[-1].get("sequence") or first_sequence)
    target = directory / f"{boot_prefix}-{first_sequence:010d}-{last_sequence:010d}.jsonl.gz"
    temporary = target.with_suffix(target.suffix + f".tmp-{os.getpid()}")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=5) as output:
            for row in rows:
                output.write((json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8"))
        raw.flush()
        os.fsync(raw.fileno())
    os.replace(temporary, target)
    return {"written": len(rows), "path": str(target), "size_bytes": target.stat().st_size}


def _read_segment_rows(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    directory = Path(blackbox_cfg(cfg)["segment_dir"])
    rows = []
    if not directory.is_dir():
        return rows
    for path in sorted(directory.glob("*.jsonl.gz")):
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        except (OSError, json.JSONDecodeError, EOFError):
            continue
    return rows


def _rotate_segments(cfg: dict[str, Any], current_boot_id: str) -> None:
    settings = blackbox_cfg(cfg)
    directory = Path(settings["segment_dir"])
    if not directory.is_dir():
        return
    current_prefix = current_boot_id.replace("-", "")[:12]
    maximum_current = int(math.ceil(settings["retention_seconds"] / settings["checkpoint_seconds"])) + 2
    by_boot: dict[str, list[Path]] = {}
    for path in directory.glob("*.jsonl.gz"):
        by_boot.setdefault(path.name.split("-", 1)[0], []).append(path)
    for path in sorted(by_boot.get(current_prefix, []))[:-maximum_current]:
        _safe_unlink(path)
    other = sorted(
        ((max((item.stat().st_mtime for item in paths), default=0), prefix, paths) for prefix, paths in by_boot.items() if prefix != current_prefix),
        reverse=True,
    )
    for _, _, paths in other[1:]:
        for path in paths:
            _safe_unlink(path)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError):
        pass
    return rows


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
    with temporary.open("r+", encoding="utf-8") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _directory_size(path: Path) -> int:
    if not path.is_dir():
        return 0
    total = 0
    for item in path.glob("*.jsonl.gz"):
        try:
            total += item.stat().st_size
        except OSError:
            pass
    return total


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _kb_to_mb(value: int | float) -> float:
    return round(float(value) / 1024, 1)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
