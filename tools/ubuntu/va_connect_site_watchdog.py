#!/usr/bin/env python3

import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DEFAULT_CONFIG_PATH = "/opt/va-connect-watchdog/site-watchdog.json"
DEFAULT_MANUAL_DIR = "/var/lib/va-connect-site-watchdog"
DEFAULT_INCIDENTS_PATH = "/var/log/va-connect-site-watchdog/incidents.jsonl"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_iso(value: str) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.fromisoformat(raw)
        except Exception:
            return None


def local_export_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc).astimezone()
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def tail_jsonl(path: Path, limit: int):
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    items = []
    for line in lines:
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def run_command(command: List[str], timeout: int = 10) -> Tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode, output.strip()
    except Exception as exc:
        return 999, f"{type(exc).__name__}: {exc}"


def run_shell(command: str, timeout: int = 15) -> Tuple[int, str]:
    return run_command(["bash", "-lc", command], timeout=timeout)


def ping_host(host: str, timeout_seconds: int) -> Dict[str, object]:
    code, output = run_command(
        ["ping", "-c", "1", "-W", str(timeout_seconds), host],
        timeout=timeout_seconds + 3,
    )
    return {"host": host, "ok": code == 0, "detail": output[-400:]}


def tcp_check(host: str, port: int, timeout_seconds: int) -> Dict[str, object]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            latency_ms = int((time.monotonic() - start) * 1000)
            return {
                "host": host,
                "port": port,
                "ok": True,
                "detail": f"connected in {latency_ms}ms",
            }
    except OSError as exc:
        return {"host": host, "port": port, "ok": False, "detail": str(exc)}


def process_running(match_text: str) -> bool:
    code, _ = run_command(["pgrep", "-f", "--", match_text], timeout=5)
    return code == 0


def service_status(service_name: str) -> Dict[str, object]:
    code, output = run_command(["systemctl", "is-active", service_name], timeout=10)
    detail = output.strip() or ("active" if code == 0 else "unknown")
    return {"service": service_name, "ok": code == 0 and detail == "active", "detail": detail}


def run_action(command: str) -> Tuple[int, str]:
    return run_shell(command, timeout=120)


def summarize_checks(pings: List[Dict[str, object]], ports: List[Dict[str, object]]) -> Dict[str, bool]:
    internet_ok = any(item["ok"] for item in pings) if pings else True
    lan_ok = all(item["ok"] for item in ports) if ports else True
    return {"internet_ok": internet_ok, "lan_ok": lan_ok}


def backoff_seconds(base: int, multiplier: float, maximum: int, failures: int) -> int:
    delay = float(base)
    for _ in range(max(failures, 0)):
        delay = min(delay * multiplier, maximum)
    return int(delay)


def read_cpu_times() -> Tuple[int, int]:
    line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
    parts = [int(value) for value in line.split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    total = sum(parts)
    return total, idle


def read_meminfo_values() -> Dict[str, int]:
    values = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, value = line.split(":", 1)
        values[key] = int(value.strip().split()[0])
    return values


def read_mem_percent() -> float:
    values = read_meminfo_values()
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if total <= 0:
        return 0.0
    return round(((total - available) / total) * 100.0, 2)


def read_mem_available_mb() -> int:
    values = read_meminfo_values()
    return max(0, values.get("MemAvailable", values.get("MemFree", 0)) // 1024)


def read_mem_cached_mb() -> int:
    values = read_meminfo_values()
    return max(0, values.get("Cached", 0) // 1024)


def read_disk_percent(path_text: str) -> Optional[float]:
    path = Path(path_text)
    if not path.exists():
        return None
    stats = os.statvfs(path)
    total = stats.f_blocks * stats.f_frsize
    available = stats.f_bavail * stats.f_frsize
    if total <= 0:
        return None
    used = total - available
    return round((used / total) * 100.0, 2)


def read_temperature_summary() -> Dict[str, object]:
    thermal_root = Path("/sys/class/thermal")
    sensors: List[Dict[str, object]] = []
    if thermal_root.exists():
        for zone_temp in thermal_root.glob("thermal_zone*/temp"):
            try:
                raw = zone_temp.read_text(encoding="utf-8").strip()
                value = float(raw)
            except Exception:
                continue
            if value > 1000:
                value = value / 1000.0
            if -20.0 <= value <= 150.0:
                zone_dir = zone_temp.parent
                zone_name = zone_dir.name
                sensor_name = zone_name
                try:
                    sensor_type = (zone_dir / "type").read_text(encoding="utf-8").strip()
                    if sensor_type:
                        sensor_name = f"{zone_name}:{sensor_type}"
                except Exception:
                    pass
                sensors.append(
                    {
                        "name": sensor_name[:80],
                        "value_c": round(value, 1),
                    }
                )
    sensors.sort(key=lambda item: float(item.get("value_c", 0.0)), reverse=True)
    return {
        "temperature_c": sensors[0]["value_c"] if sensors else None,
        "temperature_sensor_count": len(sensors),
        "temperature_sensors": sensors[:8],
    }


def command_available(name: str) -> bool:
    code, _ = run_command(["bash", "-lc", f"command -v {shlex.quote(name)}"], timeout=5)
    return code == 0


def hardware_warning_lines(limit: int = 20) -> List[str]:
    patterns = (
        "edac|mce|machine check|hardware error|i/o error|ext4-fs warning|buffer i/o error|"
        "ata[0-9].*failed|failed command|resetting link|link is down|nvme.*error|watchdog"
    )
    code, output = run_shell(
        f"journalctl -k -n 400 --no-pager | grep -Ei {shlex.quote(patterns)} | tail -n {int(limit)} || true",
        timeout=20,
    )
    if code not in (0, 1, 999):
        return [f"journal scan failed: {output[:240]}"]
    return [line.strip()[:240] for line in output.splitlines() if line.strip()][:limit]


def smart_summary(device: str) -> Dict[str, object]:
    if not command_available("smartctl"):
        return {"device": device, "available": False, "summary": "smartctl not installed"}
    code, output = run_command(["smartctl", "-H", "-A", device], timeout=25)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    interesting = [
        line for line in lines
        if any(
            term in line.lower()
            for term in ("overall-health", "result", "reallocated", "pending", "uncorrect", "crc", "media_wearout")
        )
    ][:8]
    summary = "; ".join(interesting) if interesting else (lines[0] if lines else "no SMART output")
    return {"device": device, "available": True, "ok": code == 0, "summary": summary[:400]}


def collect_hardware_health() -> Dict[str, object]:
    pstore_entries: List[str] = []
    pstore_path = Path("/sys/fs/pstore")
    if pstore_path.exists():
        try:
            pstore_entries = sorted(item.name for item in pstore_path.iterdir())
        except Exception:
            pstore_entries = []

    warnings = hardware_warning_lines(limit=20)
    smart = [smart_summary("/dev/sda"), smart_summary("/dev/sdb")]
    warning_signature = json.dumps(
        {
            "warnings": warnings,
            "smart": [{k: item.get(k) for k in ("device", "available", "ok", "summary")} for item in smart],
            "pstore": pstore_entries,
        },
        sort_keys=True,
    )
    return {
        "checked_at": iso_now(),
        "warnings": warnings,
        "smart": smart,
        "pstore_entries": pstore_entries,
        "warning_count": len(warnings),
        "warning_signature": warning_signature,
    }


def capture_snapshot(snapshot_dir: Path, reason: str, app_match: str, max_journal_lines: int) -> Path:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    target_dir = snapshot_dir / f"{timestamp}_{reason}"
    target_dir.mkdir(parents=True, exist_ok=True)

    commands = {
        "date.txt": "date -Is",
        "uptime.txt": "uptime",
        "loadavg.txt": "cat /proc/loadavg",
        "ip_addr.txt": "ip addr",
        "ip_route.txt": "ip route",
        "resolvectl.txt": "resolvectl status || systemd-resolve --status",
        "free.txt": "free -m",
        "df.txt": "df -h",
        "findmnt.txt": "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS,USED,AVAIL",
        "failed_services.txt": "systemctl --failed --no-pager",
        "service_status.txt": "systemctl status esg.service bridge.service sysops.service teamviewerd.service NetworkManager.service --no-pager || true",
        "top.txt": "top -b -n 1 | head -n 40",
        "vmstat.txt": "vmstat 1 5",
        "dmesg_tail.txt": "dmesg | tail -n 80",
        "journal_kernel.txt": f"journalctl -k -n {max_journal_lines} --no-pager",
        "processes.txt": "ps -eo pid,ppid,stat,%cpu,%mem,etime,args --sort=-%cpu | head -n 40",
        "app_processes.txt": f"pgrep -af -- {shlex.quote(app_match)} || true",
        "journal_system.txt": f"journalctl -n {max_journal_lines} --no-pager",
        "journal_network.txt": f"journalctl -u NetworkManager -n {max_journal_lines} --no-pager || journalctl -u systemd-networkd -n {max_journal_lines} --no-pager || true",
        "journal_teamviewer.txt": f"journalctl -u teamviewerd -n {max_journal_lines} --no-pager || true",
        "journal_esg.txt": f"journalctl -u esg.service -n {max_journal_lines} --no-pager || true",
        "journal_bridge.txt": f"journalctl -u bridge.service -n {max_journal_lines} --no-pager || true",
        "journal_sysops.txt": f"journalctl -u sysops.service -n {max_journal_lines} --no-pager || true",
        "journal_kernel_hardware_warnings.txt": "journalctl -k -n 400 --no-pager | grep -Ei 'edac|mce|machine check|hardware error|i/o error|ext4-fs warning|buffer i/o error|ata[0-9].*failed|failed command|resetting link|link is down|nvme.*error|watchdog' || true",
        "pstore_listing.txt": "ls -la /sys/fs/pstore 2>/dev/null || true",
        "smart_sda.txt": "smartctl -a /dev/sda 2>/dev/null || echo 'smartctl not installed or /dev/sda unavailable'",
        "smart_sdb.txt": "smartctl -a /dev/sdb 2>/dev/null || echo 'smartctl not installed or /dev/sdb unavailable'",
        "recording_mount.txt": "df -h /mnt/storage /mnt/storage/recordings 2>/dev/null || true",
        "recording_tree.txt": "ls -lah /mnt/storage 2>/dev/null && ls -lah /mnt/storage/recordings 2>/dev/null | tail -n 50 || true",
    }

    for filename, command in commands.items():
        _, output = run_shell(command, timeout=20)
        (target_dir / filename).write_text(output + "\n", encoding="utf-8")

    return target_dir


def read_boot_id() -> str:
    path = Path("/proc/sys/kernel/random/boot_id")
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def capture_previous_boot_snapshot(snapshot_dir: Path, max_journal_lines: int) -> Optional[Path]:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    target_dir = snapshot_dir / f"{timestamp}_previous-boot-review"
    target_dir.mkdir(parents=True, exist_ok=True)

    commands = {
        "journal_previous_boot.txt": f"journalctl -b -1 -n {max_journal_lines} --no-pager || true",
        "journal_kernel_previous_boot.txt": f"journalctl -k -b -1 -n {max_journal_lines} --no-pager || true",
        "journal_kernel_previous_boot_hardware_warnings.txt": "journalctl -k -b -1 --no-pager | grep -Ei 'edac|mce|machine check|hardware error|i/o error|ext4-fs warning|buffer i/o error|ata[0-9].*failed|failed command|resetting link|link is down|nvme.*error|watchdog' || true",
        "last_reboots.txt": "last -x -n 20 || true",
        "uptime_since.txt": "uptime -s || true",
        "boot_list.txt": "journalctl --list-boots || true",
        "pstore_listing.txt": "ls -la /sys/fs/pstore 2>/dev/null || true",
        "smart_sda.txt": "smartctl -a /dev/sda 2>/dev/null || echo 'smartctl not installed or /dev/sda unavailable'",
        "smart_sdb.txt": "smartctl -a /dev/sdb 2>/dev/null || echo 'smartctl not installed or /dev/sdb unavailable'",
    }

    wrote_any = False
    for filename, command in commands.items():
        _, output = run_shell(command, timeout=25)
        (target_dir / filename).write_text(output + "\n", encoding="utf-8")
        if output.strip():
            wrote_any = True

    return target_dir if wrote_any else None


class SiteWatchdog:
    def __init__(self, config: Dict[str, object]):
        self.config = config
        self.stop_requested = False
        self.state_path = Path(str(config["state_file"]))
        self.log_path = Path(str(config["json_log"]))
        self.metrics_path = Path(str(config.get("metrics_file", "/var/log/va-connect-site-watchdog/metrics.jsonl")))
        self.snapshot_dir = Path(str(config["snapshot_dir"]))
        self.incidents_path = Path(str(config.get("incidents_file", DEFAULT_INCIDENTS_PATH)))
        self.manual_dir = Path(str(config.get("manual_dir", DEFAULT_MANUAL_DIR)))
        self.prev_cpu_total, self.prev_cpu_idle = read_cpu_times()
        self.state = read_json(
            self.state_path,
            {
                "failure_count": 0,
                "fault_active": False,
                "fault_started_at": None,
                "last_reboot_attempt_at": None,
                "last_network_restart_at": None,
                "last_fault_signature": None,
                "last_snapshot_at": None,
                "last_checks": None,
                "last_metrics": None,
                "last_check_at": None,
                "last_healthy_at": None,
                "last_wan_ok_at": None,
                "last_lan_ok_at": None,
                "last_app_ok_at": None,
                "last_services_ok_at": None,
                "monitoring_state": "starting",
                "hostname": socket.gethostname(),
                "boot_id": read_boot_id(),
                "last_startup_at": None,
                "reboot_commands_sent_count": 0,
                "reboot_detections_count": 0,
                "unexpected_reboot_count": 0,
                "last_reboot_reason": None,
                "hardware_health": None,
                "last_hardware_check_at": None,
                "last_hardware_signature": None,
            },
        )

    def request_stop(self, *_args):
        self.stop_requested = True

    def log_event(self, event_type: str, **fields) -> None:
        payload = {"ts": iso_now(), "event": event_type}
        payload.update(fields)
        append_jsonl(self.log_path, payload)

    def collect_metrics(self) -> Dict[str, object]:
        total, idle = read_cpu_times()
        delta_total = max(1, total - self.prev_cpu_total)
        delta_idle = max(0, idle - self.prev_cpu_idle)
        cpu_percent = round(((delta_total - delta_idle) / delta_total) * 100.0, 2)
        self.prev_cpu_total = total
        self.prev_cpu_idle = idle

        load_1, load_5, load_15 = os.getloadavg()
        thermal = read_temperature_summary()
        metrics = {
            "ts": iso_now(),
            "cpu_percent": cpu_percent,
            "mem_percent": read_mem_percent(),
            "mem_available_mb": read_mem_available_mb(),
            "mem_cached_mb": read_mem_cached_mb(),
            "root_disk_percent": read_disk_percent("/"),
            "recording_disk_percent": read_disk_percent("/mnt/storage"),
            "temperature_c": thermal["temperature_c"],
            "temperature_sensor_count": thermal["temperature_sensor_count"],
            "temperature_sensors": thermal["temperature_sensors"],
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
        }
        append_jsonl(self.metrics_path, metrics)
        self.state["last_metrics"] = metrics

        # Keep the metrics file bounded without extra dependencies.
        recent = tail_jsonl(self.metrics_path, 6000)
        if len(recent) >= 5800:
            self.metrics_path.write_text(
                "\n".join(json.dumps(item, sort_keys=True) for item in recent[-5000:]) + "\n",
                encoding="utf-8",
            )
        return metrics

    def record_reboot_incident(
        self,
        previous_boot_id: str,
        current_boot_id: str,
        last_check_at: str,
        reboot_detected_at: str,
        reboot_was_requested: bool,
        snapshot_path: Optional[Path],
    ) -> None:
        anchor_dt = parse_iso(last_check_at) or parse_iso(str(self.state.get("last_healthy_at") or "")) or parse_iso(reboot_detected_at)
        reboot_dt = parse_iso(reboot_detected_at) or utc_now()
        if anchor_dt is None:
            anchor_dt = reboot_dt - timedelta(minutes=5)
        window_since = local_export_time(anchor_dt - timedelta(minutes=5))
        window_until = local_export_time(reboot_dt + timedelta(minutes=5))
        incident_id = f"{reboot_dt.astimezone().strftime('%Y%m%d_%H%M%S')}_{current_boot_id[:8]}"
        last_checks = dict(self.state.get("last_checks") or {})
        incident = {
            "incident_id": incident_id,
            "ts": reboot_detected_at,
            "incident_time": last_check_at or str(self.state.get("last_healthy_at") or reboot_detected_at),
            "last_known_healthy_at": str(self.state.get("last_healthy_at") or ""),
            "reboot_detected_at": reboot_detected_at,
            "window_since": window_since,
            "window_until": window_until,
            "previous_boot_id": previous_boot_id,
            "current_boot_id": current_boot_id,
            "watchdog_requested_reboot": reboot_was_requested,
            "classification": "watchdog_reboot" if reboot_was_requested else "manual_relay_recovery_suspected",
            "title": "Watchdog reboot" if reboot_was_requested else "Unexpected reboot",
            "reporting_text": (
                "Watchdog requested a reboot after the unit stayed non-functional."
                if reboot_was_requested
                else "Unit became non-functional and required an unplanned hard reboot or repower to recover."
            ),
            "suspected_reason": (
                "Watchdog itself requested the reboot."
                if reboot_was_requested
                else "Watchdog did not request reboot. Manual reboot, GSM relay, power-cycle, or crash recovery is more likely."
            ),
            "last_wan_ok_at": str(self.state.get("last_wan_ok_at") or ""),
            "last_lan_ok_at": str(self.state.get("last_lan_ok_at") or ""),
            "last_app_ok_at": str(self.state.get("last_app_ok_at") or ""),
            "last_services_ok_at": str(self.state.get("last_services_ok_at") or ""),
            "last_successful_watchdog_check_at": last_check_at,
            "last_sampled_pc_stats": dict(self.state.get("last_metrics") or {}),
            "last_checks": last_checks,
            "snapshot_path": str(snapshot_path) if snapshot_path is not None else "",
            "export_generated_at": "",
            "export_archive_path": "",
            "export_folder_path": "",
            "export_log_path": "",
        }
        append_jsonl(self.incidents_path, incident)
        self.log_event("incident_recorded", incident_id=incident_id, classification=incident["classification"], title=incident["title"])

    def inspect_boot_transition(self) -> None:
        current_boot_id = read_boot_id()
        previous_boot_id = str(self.state.get("boot_id") or "")
        last_check_at = str(self.state.get("last_check_at") or "")
        self.state["last_startup_at"] = iso_now()

        if previous_boot_id and current_boot_id and previous_boot_id != current_boot_id:
            self.state["reboot_detections_count"] = int(self.state.get("reboot_detections_count", 0)) + 1
            last_reboot_attempt_at = float(self.state.get("last_reboot_attempt_at") or 0)
            reboot_was_requested = last_reboot_attempt_at > 0 and (time.time() - last_reboot_attempt_at) < 1800
            event = {
                "previous_boot_id": previous_boot_id,
                "current_boot_id": current_boot_id,
                "last_check_at": last_check_at,
            }
            snapshot_path = capture_previous_boot_snapshot(
                self.snapshot_dir,
                max_journal_lines=int(self.config["journal_lines"]),
            )
            if reboot_was_requested:
                self.state["last_reboot_reason"] = "watchdog reboot observed"
                self.log_event("watchdog_reboot_observed", **event)
            else:
                self.state["unexpected_reboot_count"] = int(self.state.get("unexpected_reboot_count", 0)) + 1
                self.state["last_reboot_reason"] = "unexpected reboot detected after boot"
                self.log_event("unexpected_reboot_detected", **event)
            if snapshot_path is not None:
                self.log_event("snapshot", reason="previous-boot-review", path=str(snapshot_path))
            self.record_reboot_incident(
                previous_boot_id=previous_boot_id,
                current_boot_id=current_boot_id,
                last_check_at=last_check_at,
                reboot_detected_at=str(self.state.get("last_startup_at") or iso_now()),
                reboot_was_requested=reboot_was_requested,
                snapshot_path=snapshot_path,
            )

        self.state["boot_id"] = current_boot_id
        self.refresh_hardware_health(force=True)
        write_json(self.state_path, self.state)

    def refresh_hardware_health(self, force: bool = False) -> None:
        now_epoch = time.time()
        last_check_at = float(self.state.get("last_hardware_check_at") or 0)
        if not force and (now_epoch - last_check_at) < 3600:
            return
        hardware = collect_hardware_health()
        self.state["hardware_health"] = hardware
        self.state["last_hardware_check_at"] = now_epoch
        new_signature = str(hardware.get("warning_signature") or "")
        if new_signature and new_signature != str(self.state.get("last_hardware_signature") or ""):
            self.log_event(
                "hardware_warning_update",
                warning_count=int(hardware.get("warning_count", 0)),
                warnings=hardware.get("warnings", []),
                smart=hardware.get("smart", []),
                pstore_entries=hardware.get("pstore_entries", []),
            )
        self.state["last_hardware_signature"] = new_signature

    def pop_manual_marker(self, name: str) -> bool:
        path = self.manual_dir / name
        if path.exists():
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            return True
        return False

    def maybe_snapshot(self, reason: str, signature: str) -> Optional[str]:
        cooldown = int(self.config["snapshot_cooldown_seconds"])
        last_snapshot_at = self.state.get("last_snapshot_at")
        now = time.time()
        if last_snapshot_at and now - float(last_snapshot_at) < cooldown:
            return None
        snapshot_path = capture_snapshot(
            self.snapshot_dir,
            reason=reason,
            app_match=str(self.config["app_match"]),
            max_journal_lines=int(self.config["journal_lines"]),
        )
        self.state["last_snapshot_at"] = now
        self.state["last_fault_signature"] = signature
        self.log_event("snapshot", reason=reason, signature=signature, path=str(snapshot_path))
        return str(snapshot_path)

    def start_app(self) -> bool:
        if not bool(self.config.get("app_restart_enabled", True)):
            self.log_event("action_skipped", action="start_app", reason="app restart disabled")
            return False
        command = str(self.config.get("app_start_command", "")).strip()
        if not command:
            self.log_event("action_skipped", action="start_app", reason="app_start_command empty")
            return False
        code, output = run_action(command)
        self.log_event("action", action="start_app", return_code=code, detail=output[-600:])
        return code == 0

    def restart_network(self) -> bool:
        command = str(self.config.get("network_restart_command", "")).strip()
        if not command:
            self.log_event("action_skipped", action="restart_network", reason="network_restart_command empty")
            return False
        code, output = run_action(command)
        self.state["last_network_restart_at"] = time.time()
        self.log_event("action", action="restart_network", return_code=code, detail=output[-600:])
        return code == 0

    def reboot_host(self) -> bool:
        if not bool(self.config.get("reboot_enabled", True)):
            self.log_event("action_skipped", action="reboot", reason="reboot disabled")
            return False
        command = str(self.config.get("reboot_command", "shutdown -r now")).strip()
        code, output = run_action(command)
        self.state["last_reboot_attempt_at"] = time.time()
        self.state["reboot_commands_sent_count"] = int(self.state.get("reboot_commands_sent_count", 0)) + 1
        self.state["last_reboot_reason"] = "watchdog issued reboot command"
        self.log_event("action", action="reboot", return_code=code, detail=output[-600:])
        return code == 0

    def perform_checks(self) -> Dict[str, object]:
        pings = [ping_host(host, int(self.config["ping_timeout_seconds"])) for host in self.config["internet_hosts"]]
        ports = [
            tcp_check(item["host"], int(item["port"]), int(self.config["tcp_timeout_seconds"]))
            for item in self.config["tcp_targets"]
        ]
        services = [
            service_status(service_name)
            for service_name in self.config.get("systemd_services", [])
        ]
        app_ok = process_running(str(self.config["app_match"]))
        summary = summarize_checks(pings, ports)
        services_ok = all(item["ok"] for item in services) if services else True
        result = {
            "pings": pings,
            "ports": ports,
            "services": services,
            "app_ok": app_ok,
            "services_ok": services_ok,
            **summary,
        }
        result["healthy"] = bool(result["internet_ok"] and result["lan_ok"] and result["app_ok"] and result["services_ok"])
        return result

    def run_once(self) -> None:
        if self.pop_manual_marker("manual-snapshot"):
            self.maybe_snapshot("manual", "manual")

        if self.pop_manual_marker("manual-restart-network"):
            self.restart_network()

        run_only_checks = self.pop_manual_marker("manual-run-checks")
        if not bool(self.config.get("monitoring_enabled", True)):
            if run_only_checks:
                checks = self.perform_checks()
                self.state["last_checks"] = checks
                self.state["last_check_at"] = iso_now()
            self.collect_metrics()
            self.state["monitoring_state"] = "disabled"
            self.state["fault_active"] = False
            self.state["fault_started_at"] = None
            self.state["last_fault_signature"] = None
            write_json(self.state_path, self.state)
            if run_only_checks:
                self.log_event("manual_check", checks=self.state.get("last_checks"))
            else:
                self.log_event("heartbeat", status="disabled")
            return

        checks = self.perform_checks()
        self.collect_metrics()
        self.refresh_hardware_health()
        self.state["monitoring_state"] = "active"
        self.state["last_checks"] = checks
        self.state["last_check_at"] = iso_now()
        if checks["internet_ok"]:
            self.state["last_wan_ok_at"] = self.state["last_check_at"]
        if checks["lan_ok"]:
            self.state["last_lan_ok_at"] = self.state["last_check_at"]
        if checks["app_ok"]:
            self.state["last_app_ok_at"] = self.state["last_check_at"]
        if checks["services_ok"]:
            self.state["last_services_ok_at"] = self.state["last_check_at"]
        if run_only_checks:
            write_json(self.state_path, self.state)
            self.log_event("manual_check", checks=checks)
            return

        signature = json.dumps(
            {
                "internet_ok": checks["internet_ok"],
                "lan_ok": checks["lan_ok"],
                "app_ok": checks["app_ok"],
                "services_ok": checks["services_ok"],
                "bad_pings": [item["host"] for item in checks["pings"] if not item["ok"]],
                "bad_ports": [f'{item["host"]}:{item["port"]}' for item in checks["ports"] if not item["ok"]],
                "bad_services": [item["service"] for item in checks["services"] if not item["ok"]],
            },
            sort_keys=True,
        )

        if checks["healthy"]:
            if self.state.get("fault_active"):
                started = self.state.get("fault_started_at")
                duration = None
                if started:
                    duration = int(time.time() - float(started))
                self.log_event("recovered", duration_seconds=duration, checks=checks)
            self.state["fault_active"] = False
            self.state["fault_started_at"] = None
            self.state["failure_count"] = 0
            self.state["last_fault_signature"] = None
            self.state["last_healthy_at"] = iso_now()
            write_json(self.state_path, self.state)
            self.log_event("heartbeat", status="healthy", checks=checks)
            return

        now_epoch = time.time()
        if not self.state.get("fault_active"):
            self.state["fault_active"] = True
            self.state["fault_started_at"] = now_epoch
            self.log_event("fault_started", checks=checks)

        if signature != self.state.get("last_fault_signature"):
            self.maybe_snapshot("fault-change", signature)

        fault_age = int(now_epoch - float(self.state["fault_started_at"]))
        reboot_after = backoff_seconds(
            int(self.config["base_reboot_timeout_seconds"]),
            float(self.config["reboot_backoff_multiplier"]),
            int(self.config["max_reboot_timeout_seconds"]),
            int(self.state.get("failure_count", 0)),
        )

        event = {
            "status": "fault",
            "fault_age_seconds": fault_age,
            "reboot_after_seconds": reboot_after,
            "checks": checks,
        }
        self.log_event("heartbeat", **event)

        if not checks["app_ok"]:
            self.start_app()
            time.sleep(int(self.config["post_action_settle_seconds"]))
            checks_after_start = self.perform_checks()
            self.log_event("post_action_check", action="start_app", checks=checks_after_start)
            if checks_after_start["healthy"]:
                self.state["fault_active"] = False
                self.state["fault_started_at"] = None
                self.state["failure_count"] = 0
                self.state["last_fault_signature"] = None
                self.state["last_healthy_at"] = iso_now()
                write_json(self.state_path, self.state)
                return

        if not checks["internet_ok"] and bool(self.config["restart_network_before_reboot"]):
            last_restart = float(self.state.get("last_network_restart_at") or 0)
            if now_epoch - last_restart >= int(self.config["network_restart_cooldown_seconds"]):
                self.restart_network()
                time.sleep(int(self.config["post_action_settle_seconds"]))
                checks_after_network = self.perform_checks()
                self.log_event("post_action_check", action="restart_network", checks=checks_after_network)
                if checks_after_network["healthy"]:
                    self.state["fault_active"] = False
                    self.state["fault_started_at"] = None
                    self.state["failure_count"] = 0
                    self.state["last_fault_signature"] = None
                    self.state["last_healthy_at"] = iso_now()
                    write_json(self.state_path, self.state)
                    return

        if fault_age >= reboot_after:
            self.maybe_snapshot("pre-reboot", signature)
            self.state["failure_count"] = int(self.state.get("failure_count", 0)) + 1
            write_json(self.state_path, self.state)
            self.reboot_host()
            return

        write_json(self.state_path, self.state)

    def run_forever(self) -> int:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        self.log_event("startup", config=self.config)
        self.inspect_boot_transition()

        while not self.stop_requested:
            started_at = time.time()
            try:
                self.config = load_config()
                self.run_once()
            except Exception as exc:
                self.log_event("error", detail=f"{type(exc).__name__}: {exc}")
            sleep_for = max(1, int(self.config["check_interval_seconds"]) - int(time.time() - started_at))
            time.sleep(sleep_for)

        self.log_event("shutdown")
        return 0


def load_config() -> Dict[str, object]:
    config_path = Path(os.environ.get("SITE_WATCHDOG_CONFIG", DEFAULT_CONFIG_PATH))
    config = read_json(config_path, {})

    defaults = {
        "check_interval_seconds": 30,
        "ping_timeout_seconds": 3,
        "tcp_timeout_seconds": 3,
        "internet_hosts": ["1.1.1.1", "8.8.8.8"],
        "tcp_targets": [],
        "systemd_services": [],
        "app_match": "va-connect",
        "app_start_command": "",
        "monitoring_enabled": True,
        "app_restart_enabled": True,
        "restart_network_before_reboot": True,
        "reboot_enabled": True,
        "network_restart_command": "systemctl restart NetworkManager || systemctl restart systemd-networkd",
        "network_restart_cooldown_seconds": 600,
        "base_reboot_timeout_seconds": 300,
        "max_reboot_timeout_seconds": 3600,
        "reboot_backoff_multiplier": 2.0,
        "post_action_settle_seconds": 20,
        "reboot_command": "shutdown -r now",
        "json_log": "/var/log/va-connect-site-watchdog/events.jsonl",
        "metrics_file": "/var/log/va-connect-site-watchdog/metrics.jsonl",
        "state_file": "/var/lib/va-connect-site-watchdog/state.json",
        "manual_dir": "/var/lib/va-connect-site-watchdog",
        "snapshot_dir": "/var/log/va-connect-site-watchdog/snapshots",
        "snapshot_cooldown_seconds": 900,
        "journal_lines": 120,
    }

    merged = {**defaults, **config}
    if not isinstance(merged["internet_hosts"], list):
        raise ValueError("internet_hosts must be a JSON array")
    if not isinstance(merged["tcp_targets"], list):
        raise ValueError("tcp_targets must be a JSON array")
    return merged


def main() -> int:
    config = load_config()
    watchdog = SiteWatchdog(config)
    return watchdog.run_forever()


if __name__ == "__main__":
    sys.exit(main())
