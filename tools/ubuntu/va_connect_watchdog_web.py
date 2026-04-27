#!/usr/bin/env python3

import html
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from mimetypes import guess_type
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPBasicAuthHandler, HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, build_opener, Request
import xml.etree.ElementTree as ET


CONFIG_PATH = Path(os.environ.get("SITE_WATCHDOG_CONFIG", "/opt/va-connect-watchdog/site-watchdog.json"))
STATE_PATH = Path("/var/lib/va-connect-site-watchdog/state.json")
EVENTS_PATH = Path("/var/log/va-connect-site-watchdog/events.jsonl")
METRICS_PATH = Path("/var/log/va-connect-site-watchdog/metrics.jsonl")
INCIDENTS_PATH = Path("/var/log/va-connect-site-watchdog/incidents.jsonl")
BUILD_INFO_PATH = Path("/opt/va-connect-watchdog/build-info.json")
UPDATE_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-update-status.json")
UPDATE_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-update.log")
EXPORT_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-export-status.json")
EXPORT_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-export.log")
INCIDENT_EXPORTS_PATH = Path("/var/lib/va-connect-site-watchdog/incident-export-status.json")
MEMTEST_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-memtest-status.json")
MEMTEST_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-memtest.log")
SPEEDTEST_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-speedtest-status.json")
SPEEDTEST_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-speedtest.log")
SPEEDTEST_HISTORY_PATH = Path("/var/log/va-connect-site-watchdog/speedtests.jsonl")
HIK_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-hik-status.json")
TOOLS_INSTALL_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-tools-install-status.json")
TOOLS_INSTALL_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-tools-install.log")
SNAPSHOT_DIR = Path("/var/log/va-connect-site-watchdog/snapshots")


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


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "+00:00"


def slugify_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip()).strip("-").lower()
    return cleaned or "watchdog"


def export_time_token(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "unknown"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            parsed = datetime.strptime(raw, fmt)
            return parsed.strftime("%Y%m%d-%H%M%S")
        except ValueError:
            continue
    return slugify_label(raw)


def export_download_names(export_status: Dict[str, Any]) -> Dict[str, str]:
    site_label = slugify_label(str(export_status.get("site_label") or socket.gethostname()))
    since_token = export_time_token(str(export_status.get("since", "")))
    until_token = export_time_token(str(export_status.get("until", "")))
    base = f"{site_label}_{since_token}_to_{until_token}"
    return {
        "base": base,
        "archive": f"{base}_incident-pack.tar.gz",
        "readme": f"{base}_incident-pack-readme.txt",
        "log": f"{base}_incident-pack.log",
    }


def incident_export_names(incident: Dict[str, Any]) -> Dict[str, str]:
    site_label = slugify_label(str(incident.get("site_label") or socket.gethostname()))
    incident_at = export_time_token(
        str(
            incident.get("incident_time")
            or incident.get("reboot_detected_at")
            or incident.get("window_until", "")
        )
    )
    classification = slugify_label(str(incident.get("classification") or "incident"))
    base = f"{site_label}_{incident_at}_{classification}"
    return {
        "base": base,
        "archive": f"{base}_incident-pack.tar.gz",
        "readme": f"{base}_incident-pack-readme.txt",
        "log": f"{base}_incident-pack.log",
    }


def redacted_config(config: Dict[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for key, value in (config or {}).items():
        key_lower = str(key).lower()
        if any(token in key_lower for token in ("password", "secret", "token")):
            redacted[key] = "<redacted>" if value not in (None, "", False) else ""
        else:
            redacted[key] = value
    return redacted


def audit_download_name(status: Dict[str, Any]) -> str:
    site_label = slugify_label(str(status.get("hostname") or socket.gethostname()))
    build_label = slugify_label(str((status.get("build_info") or {}).get("git_commit") or "unknown"))
    stamp = export_time_token(now_iso())
    return f"{site_label}_{stamp}_{build_label}_audit-report.json"


def audit_report_payload(status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    current = status or status_payload()
    hardware = current.get("hardware_identity") or {}
    metrics = (current.get("state") or {}).get("last_metrics") or {}
    required_tools = current.get("required_tools") or {}
    system_profile = current.get("system_profile") or {}
    teamviewer = current.get("teamviewer") or {}
    return {
        "generated_at": now_iso(),
        "hostname": current.get("hostname"),
        "display_name": current.get("display_name"),
        "build_info": current.get("build_info") or {},
        "hardware_identity": hardware,
        "state_summary": {
            "monitoring_state": str((current.get("state") or {}).get("monitoring_state", "unknown")),
            "last_check_at": str((current.get("state") or {}).get("last_check_at", "")),
            "last_healthy_at": str((current.get("state") or {}).get("last_healthy_at", "")),
        },
        "required_tools": required_tools,
        "system_profile": system_profile,
        "teamviewer": teamviewer,
        "paths": current.get("paths") or {},
        "config_redacted": redacted_config(current.get("config") or {}),
        "latest_metrics": metrics,
        "audit_summary": {
            "site_label": current.get("hostname"),
            "model": hardware.get("model", "unknown"),
            "serial": hardware.get("serial", "unknown"),
            "bios": " ".join(str(part) for part in [hardware.get("bios_vendor"), hardware.get("bios_version")] if part),
            "root_disk_percent": metrics.get("root_disk_percent", "unknown"),
            "recording_disk_percent": metrics.get("recording_disk_percent", "unknown"),
            "temperature_c": metrics.get("temperature_c", "unknown"),
            "required_tools_missing": required_tools.get("missing_important", []),
            "teamviewer_summary": teamviewer.get("summary", "unknown"),
            "kernel_release": system_profile.get("kernel_release", "unknown"),
            "default_interface": system_profile.get("default_interface", "unknown"),
        },
    }


def read_incident_export_statuses() -> Dict[str, Dict[str, Any]]:
    raw = read_json(INCIDENT_EXPORTS_PATH, {})
    return raw if isinstance(raw, dict) else {}


def write_incident_export_statuses(payload: Dict[str, Dict[str, Any]]) -> None:
    write_json(INCIDENT_EXPORTS_PATH, payload)


def latest_log_block(path: Path, start_prefix: str, max_lines: int = 10) -> List[str]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    start_index = 0
    for index, line in enumerate(lines):
        if line.startswith(start_prefix):
            start_index = index
    block = [line.rstrip() for line in lines[start_index:] if line.strip()]
    return block[-max_lines:]


def export_log_excerpt(export_status: Dict[str, Any], max_lines: int = 10) -> List[str]:
    if not EXPORT_LOG_PATH.exists():
        return []
    try:
        lines = EXPORT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    request_id = str(export_status.get("request_id", "")).strip()
    start_index = 0
    if request_id:
        marker = f"===== Web export started request_id={request_id} "
        for index, line in enumerate(lines):
            if line.startswith(marker):
                start_index = index
    else:
        for index, line in enumerate(lines):
            if line.startswith("===== Web export started "):
                start_index = index
    block = [line.rstrip() for line in lines[start_index:] if line.strip()]
    return block[-max_lines:]


def export_search_roots(export_status: Dict[str, Any]) -> List[Path]:
    roots: List[Path] = []
    folder = str(export_status.get("folder", "")).strip()
    archive = str(export_status.get("archive", "")).strip()
    if archive:
        roots.append(Path(archive).parent)
    if folder:
        roots.append(Path(folder).parent)
    roots.extend([Path("/root/Desktop"), Path("/home/vsuser/Desktop")])
    home_root = Path("/home")
    if home_root.exists():
        try:
            for child in home_root.iterdir():
                roots.append(child / "Desktop")
        except Exception:
            pass
    unique: List[Path] = []
    seen = set()
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def parse_iso(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def load_config() -> Dict[str, Any]:
    config = read_json(CONFIG_PATH, {})
    defaults = {
        "gateway_name": "",
        "monitoring_enabled": True,
        "app_restart_enabled": True,
        "restart_network_before_reboot": False,
        "reboot_enabled": False,
        "web_bind": "0.0.0.0",
        "web_port": 80,
        "web_token": "",
        "base_reboot_timeout_seconds": 300,
        "max_reboot_timeout_seconds": 3600,
        "internet_hosts": [],
        "tcp_targets": [],
        "systemd_services": [],
        "teamviewer_id_command": "teamviewer info",
        "teamviewer_password_reset_command": "teamviewer passwd {password}",
        "teamviewer_start_command": "systemctl start teamviewerd",
        "teamviewer_restart_command": "systemctl restart teamviewerd",
        "hik_enabled": False,
        "hik_scheme": "http",
        "hik_host": "",
        "hik_username": "",
        "hik_password": "",
        "hik_channel": 1,
        "hik_people_count_result_path": "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/result",
        "hik_people_count_capabilities_path": "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities",
    }
    merged = {**defaults, **config}
    merged["web_port"] = int(merged["web_port"])
    return merged


def command_exists(name: str) -> bool:
    return subprocess.run(["bash", "-lc", f"command -v {shlex.quote(name)}"], capture_output=True, text=True).returncode == 0


def run_shell(command: str, timeout: int = 15) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part).strip()
        return {"ok": result.returncode == 0, "return_code": result.returncode, "output": output}
    except subprocess.TimeoutExpired:
        return {"ok": False, "return_code": 124, "output": f"Timed out after {timeout}s."}
    except Exception as exc:
        return {"ok": False, "return_code": 1, "output": f"{type(exc).__name__}: {exc}"}


def system_profile_payload() -> Dict[str, Any]:
    os_release: Dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            os_release[key.strip()] = value.strip().strip('"')
    except Exception:
        os_release = {}

    default_iface = ""
    route_result = run_shell("ip route show default", timeout=10)
    if route_result["output"]:
        match = re.search(r"\bdev\s+(\S+)", route_result["output"])
        if match:
            default_iface = match.group(1)

    kernel_release = run_shell("uname -r", timeout=10)["output"]
    kernel_full = run_shell("uname -a", timeout=10)["output"]

    iface_driver: Dict[str, str] = {}
    eee_output = ""
    if default_iface and command_exists("ethtool"):
        driver_result = run_shell(f"ethtool -i {shlex.quote(default_iface)}", timeout=10)
        for line in driver_result["output"].splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            iface_driver[key.strip().lower().replace("-", "_")] = value.strip()
        eee_output = run_shell(f"ethtool --show-eee {shlex.quote(default_iface)}", timeout=10)["output"]

    nic_lspci = ""
    if iface_driver.get("bus_info") and command_exists("lspci"):
        nic_lspci = run_shell(f"lspci -s {shlex.quote(iface_driver['bus_info'])} -nn", timeout=10)["output"]
    elif command_exists("lspci"):
        nic_lspci = run_shell("lspci -nnk | grep -A3 -i 'Ethernet controller' | head -n 12", timeout=10)["output"]

    drives: List[Dict[str, Any]] = []
    if command_exists("lsblk"):
        lsblk_result = run_shell("lsblk -J -o NAME,KNAME,MODEL,SIZE,TYPE,FSTYPE,MOUNTPOINT,ROTA,TRAN,SERIAL,VENDOR", timeout=15)
        if lsblk_result["output"]:
            try:
                lsblk_payload = json.loads(lsblk_result["output"])
                for item in lsblk_payload.get("blockdevices", []) or []:
                    if str(item.get("type", "")).lower() != "disk":
                        continue
                    drives.append(
                        {
                            "name": item.get("name", ""),
                            "kname": item.get("kname", ""),
                            "model": item.get("model", ""),
                            "size": item.get("size", ""),
                            "transport": item.get("tran", ""),
                            "vendor": item.get("vendor", ""),
                            "serial": item.get("serial", ""),
                            "rotational": item.get("rota", ""),
                            "children": item.get("children", []),
                        }
                    )
            except Exception:
                drives = []

    igc_hint = ""
    nic_text = " ".join(
        part for part in [nic_lspci, iface_driver.get("driver", ""), iface_driver.get("bus_info", "")]
        if part
    ).lower()
    if "igc" in nic_text or "i225" in nic_text:
        igc_hint = (
            "Intel I225 / igc detected. Treat PCIe ASPM, EEE, and link-state instability as live suspects, "
            "but do not change mitigations until the audit evidence is reviewed."
        )

    return {
        "os_name": os_release.get("PRETTY_NAME", os_release.get("NAME", "unknown")),
        "kernel_release": kernel_release or "unknown",
        "kernel_full": kernel_full or "unknown",
        "default_interface": default_iface or "unknown",
        "driver": iface_driver.get("driver", ""),
        "driver_version": iface_driver.get("version", ""),
        "firmware_version": iface_driver.get("firmware_version", ""),
        "bus_info": iface_driver.get("bus_info", ""),
        "supports_statistics": iface_driver.get("supports_statistics", ""),
        "supports_test": iface_driver.get("supports_test", ""),
        "supports_eeprom_access": iface_driver.get("supports_eeprom_access", ""),
        "supports_register_dump": iface_driver.get("supports_register_dump", ""),
        "supports_priv_flags": iface_driver.get("supports_priv_flags", ""),
        "eee": eee_output or "EEE details not available.",
        "nic_lspci": nic_lspci or "NIC PCI information not available.",
        "drives": drives,
        "igc_hint": igc_hint,
    }


def mem_available_mb() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                kb = int(line.split(":", 1)[1].strip().split()[0])
                return max(0, kb // 1024)
    except Exception:
        return 0
    return 0


def memtest_recommendation() -> Dict[str, Any]:
    available_mb = mem_available_mb()
    recommended_mb = max(256, int(available_mb * 0.5)) if available_mb else 1024
    recommended_mb = min(recommended_mb, 4096)
    return {
        "installed": command_exists("memtester"),
        "available_mb": available_mb,
        "recommended_mb": recommended_mb,
        "recommended_label": f"{recommended_mb}M",
        "recommended_loops": 2,
    }


def read_first_line(path_text: str) -> str:
    path = Path(path_text)
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return ""


def hardware_identity() -> Dict[str, str]:
    sys_vendor = read_first_line("/sys/class/dmi/id/sys_vendor")
    product_name = read_first_line("/sys/class/dmi/id/product_name")
    product_serial = read_first_line("/sys/class/dmi/id/product_serial")
    board_serial = read_first_line("/sys/class/dmi/id/board_serial")
    chassis_serial = read_first_line("/sys/class/dmi/id/chassis_serial")
    board_name = read_first_line("/sys/class/dmi/id/board_name")
    bios_vendor = read_first_line("/sys/class/dmi/id/bios_vendor")
    bios_version = read_first_line("/sys/class/dmi/id/bios_version")
    bios_date = read_first_line("/sys/class/dmi/id/bios_date")

    serial = product_serial or board_serial or chassis_serial or "unknown"
    model = product_name or "unknown"
    return {
        "vendor": sys_vendor or "unknown",
        "model": model,
        "serial": serial,
        "board_name": board_name or "unknown",
        "board_serial": board_serial or "unknown",
        "chassis_serial": chassis_serial or "unknown",
        "bios_vendor": bios_vendor or "unknown",
        "bios_version": bios_version or "unknown",
        "bios_date": bios_date or "unknown",
    }


def effective_reboot_counts(state: Dict[str, Any]) -> Dict[str, int]:
    raw_watchdog = int(state.get("reboot_commands_sent_count", 0) or 0)
    raw_detected = int(state.get("reboot_detections_count", 0) or 0)
    raw_unexpected = int(state.get("unexpected_reboot_count", 0) or 0)
    ack_watchdog = int(state.get("ack_reboot_commands_sent_count", 0) or 0)
    ack_detected = int(state.get("ack_reboot_detections_count", 0) or 0)
    ack_unexpected = int(state.get("ack_unexpected_reboot_count", 0) or 0)
    return {
        "watchdog": max(0, raw_watchdog - ack_watchdog),
        "detected": max(0, raw_detected - ack_detected),
        "unexpected": max(0, raw_unexpected - ack_unexpected),
    }


def sanitize_patch(data: Dict[str, Any]) -> Dict[str, Any]:
    patch: Dict[str, Any] = {}

    bool_keys = [
        "monitoring_enabled",
        "app_restart_enabled",
        "restart_network_before_reboot",
        "reboot_enabled",
        "hik_enabled",
    ]
    int_keys = [
        "base_reboot_timeout_seconds",
        "max_reboot_timeout_seconds",
        "check_interval_seconds",
        "network_restart_cooldown_seconds",
        "post_action_settle_seconds",
        "web_port",
    ]
    float_keys = ["reboot_backoff_multiplier"]
    str_keys = [
        "gateway_name",
        "app_match",
        "app_start_command",
        "web_bind",
        "web_token",
        "network_restart_command",
        "teamviewer_id_command",
        "teamviewer_password_reset_command",
        "teamviewer_start_command",
        "teamviewer_restart_command",
        "hik_scheme",
        "hik_host",
        "hik_username",
        "hik_password",
        "hik_people_count_result_path",
        "hik_people_count_capabilities_path",
    ]

    for key in bool_keys:
        if key in data:
            patch[key] = bool(data[key])
    for key in int_keys:
        if key in data:
            patch[key] = int(data[key])
    for key in float_keys:
        if key in data:
            patch[key] = float(data[key])
    for key in str_keys:
        if key in data:
            patch[key] = str(data[key]).strip()
    if "internet_hosts" in data:
        patch["internet_hosts"] = [str(item).strip() for item in data["internet_hosts"] if str(item).strip()]
    if "systemd_services" in data:
        patch["systemd_services"] = [str(item).strip() for item in data["systemd_services"] if str(item).strip()]
    if "tcp_targets" in data:
        targets = []
        for item in data["tcp_targets"]:
            host = str(item.get("host", "")).strip()
            port = int(item.get("port", 0))
            if host and 1 <= port <= 65535:
                targets.append({"host": host, "port": port})
        patch["tcp_targets"] = targets
    if "hik_channel" in data:
        patch["hik_channel"] = max(1, int(data["hik_channel"]))
    return patch


def recent_events(limit: int = 30) -> List[Dict[str, Any]]:
    if not EVENTS_PATH.exists():
        return []
    events = []
    for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(events))


def all_events() -> List[Dict[str, Any]]:
    if not EVENTS_PATH.exists():
        return []
    events: List[Dict[str, Any]] = []
    for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def all_incidents() -> List[Dict[str, Any]]:
    if not INCIDENTS_PATH.exists():
        return []
    incidents: List[Dict[str, Any]] = []
    for line in INCIDENTS_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            incidents.append(item)
    incidents.sort(key=lambda item: str(item.get("reboot_detected_at") or item.get("ts") or ""), reverse=True)
    return incidents


def recent_metrics(hours: int = 24) -> List[Dict[str, Any]]:
    if not METRICS_PATH.exists():
        return []
    cutoff = time.time() - (hours * 3600)
    points: List[Dict[str, Any]] = []
    for line in METRICS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = parse_iso(str(item.get("ts", "")))
        if ts is None:
            continue
        epoch = ts.timestamp()
        if epoch >= cutoff:
            points.append(item)
    max_points = 3000 if hours <= 24 else 8000
    real_points = points[-max_points:]
    if not real_points:
        return []

    epochs: List[float] = []
    for item in real_points:
        ts = parse_iso(str(item.get("ts", "")))
        if ts is None:
            continue
        epochs.append(ts.timestamp())
    diffs = sorted(
        diff for diff in (
            epochs[index] - epochs[index - 1]
            for index in range(1, len(epochs))
        )
        if diff > 0
    )
    expected_step = int(diffs[len(diffs) // 2]) if diffs else 30
    expected_step = max(30, min(expected_step, 15 * 60))
    gap_threshold = max(expected_step * 3, 180)
    start_epoch = cutoff
    end_epoch = time.time()

    def iso_from_epoch(epoch: float) -> str:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()

    enriched: List[Dict[str, Any]] = []
    first_epoch = epochs[0] if epochs else None
    if first_epoch and first_epoch - start_epoch > gap_threshold:
        enriched.append({"ts": iso_from_epoch(start_epoch), "gap": True})

    for index, item in enumerate(real_points):
        enriched.append(item)
        if index >= len(real_points) - 1:
            continue
        current_ts = parse_iso(str(item.get("ts", "")))
        next_ts = parse_iso(str(real_points[index + 1].get("ts", "")))
        if current_ts is None or next_ts is None:
            continue
        current_epoch = current_ts.timestamp()
        next_epoch = next_ts.timestamp()
        if (next_epoch - current_epoch) > gap_threshold:
            enriched.append({"ts": iso_from_epoch(current_epoch + expected_step), "gap": True})
            enriched.append({"ts": iso_from_epoch(next_epoch - expected_step), "gap": True})

    last_epoch = epochs[-1] if epochs else None
    if last_epoch and end_epoch - last_epoch > gap_threshold:
        enriched.append({"ts": iso_from_epoch(end_epoch), "gap": True})
    return enriched


def recent_speedtests(limit: int = 10) -> List[Dict[str, Any]]:
    if not SPEEDTEST_HISTORY_PATH.exists():
        return []
    items = []
    for line in SPEEDTEST_HISTORY_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(items))


def recent_metric_events(hours: int = 24) -> List[Dict[str, Any]]:
    if not EVENTS_PATH.exists():
        return []
    cutoff = time.time() - (hours * 3600)
    marker_events = {
        "unexpected_reboot_detected": {"label": "Unexpected reboot", "kind": "detected"},
        "watchdog_reboot_observed": {"label": "Watchdog reboot observed", "kind": "detected"},
        "reboot_counts_acknowledged": {"label": "Reboot counts acknowledged", "kind": "note"},
    }
    markers: List[Dict[str, Any]] = []
    for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_type = str(item.get("event", ""))
        ts = str(item.get("ts", ""))
        event_dt = parse_iso(ts)
        if event_dt is None:
            continue
        epoch = event_dt.timestamp()
        if epoch < cutoff:
            continue
        if event_type == "action" and str(item.get("action", "")) == "reboot":
            markers.append(
                {
                    "ts": ts,
                    "label": "Watchdog reboot command",
                    "kind": "command",
                    "detail": str(item.get("detail", ""))[:120],
                }
            )
            continue
        if event_type in marker_events:
            meta = marker_events[event_type]
            markers.append(
                {
                    "ts": ts,
                    "label": meta["label"],
                    "kind": meta["kind"],
                    "detail": str(item.get("last_reboot_reason", "") or item.get("detail", ""))[:120],
                }
            )
    return markers[-200:]


def service_status_payload(service_name: str) -> Dict[str, Any]:
    installed = False
    active = False
    enabled = False
    detail = "systemctl not available."
    if command_exists("systemctl"):
        installed_result = run_shell(f"systemctl status {shlex.quote(service_name)} >/dev/null 2>&1", timeout=5)
        active_result = run_shell(f"systemctl is-active {shlex.quote(service_name)}", timeout=5)
        enabled_result = run_shell(f"systemctl is-enabled {shlex.quote(service_name)}", timeout=5)
        installed = installed_result["return_code"] in {0, 3, 4}
        active = active_result["output"].splitlines()[0].strip().lower() == "active" if active_result["output"] else False
        enabled = enabled_result["output"].splitlines()[0].strip().lower() == "enabled" if enabled_result["output"] else False
        detail = []
        detail.append("installed" if installed else "not installed")
        detail.append("active" if active else "not active")
        detail.append("enabled" if enabled else "not enabled")
        detail = ", ".join(detail)
    return {
        "service": service_name,
        "installed": installed,
        "active": active,
        "enabled": enabled,
        "ok": installed and active,
        "detail": detail,
    }


def required_tools_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    smartmontools_pkg = run_shell("dpkg-query -W -f='${Status}' smartmontools", timeout=10)
    edac_utils_pkg = run_shell("dpkg-query -W -f='${Status}' edac-utils", timeout=10)
    site_service = service_status_payload("va-connect-site-watchdog.service")
    web_service = service_status_payload("va-connect-watchdog-web.service")
    tools = [
        {
            "id": "smartmontools_pkg",
            "label": "smartmontools package",
            "why": "Needed for SMART disk evidence when the PC hangs or storage looks suspicious.",
            "ok": smartmontools_pkg["ok"] and "installed" in smartmontools_pkg["output"].lower(),
            "detail": smartmontools_pkg["output"] or "Package not installed.",
            "required": True,
        },
        {
            "id": "smartctl_cli",
            "label": "smartctl CLI",
            "why": "Lets the watchdog collect disk health and self-test clues from the encoder drives.",
            "ok": command_exists("smartctl"),
            "detail": "smartctl available in PATH." if command_exists("smartctl") else "smartctl command not found.",
            "required": False,
        },
        {
            "id": "edac_utils_pkg",
            "label": "edac-utils package",
            "why": "Needed to surface memory-controller and correctable RAM error evidence after hard freezes.",
            "ok": edac_utils_pkg["ok"] and "installed" in edac_utils_pkg["output"].lower(),
            "detail": edac_utils_pkg["output"] or "Package not installed.",
            "required": True,
        },
        {
            "id": "edac_util_cli",
            "label": "edac-util CLI",
            "why": "Lets the page check for EDAC memory error counters without shell access.",
            "ok": command_exists("edac-util"),
            "detail": "edac-util available in PATH." if command_exists("edac-util") else "edac-util command not found.",
            "required": False,
        },
        {
            "id": "teamviewer_cli",
            "label": "TeamViewer CLI",
            "why": "Needed for password reset and quick remote-recovery actions from the web page.",
            "ok": command_exists("teamviewer"),
            "detail": "teamviewer command available." if command_exists("teamviewer") else "teamviewer command not found.",
            "required": False,
        },
        {
            "id": "site_watchdog_service",
            "label": "Site watchdog service",
            "why": "This is the background monitor that collects checks, metrics, and reboot evidence.",
            "ok": site_service["ok"],
            "detail": site_service["detail"],
            "required": False,
        },
        {
            "id": "web_watchdog_service",
            "label": "Watchdog web service",
            "why": "This is the operator page itself. If it is not active, remote diagnosis becomes harder.",
            "ok": web_service["ok"],
            "detail": web_service["detail"],
            "required": False,
        },
    ]
    missing_required = [item["label"] for item in tools if item.get("required") and not item.get("ok")]
    missing_important = [item["label"] for item in tools if not item.get("ok")]
    install_status = read_json(TOOLS_INSTALL_STATUS_PATH, {"state": "idle"})
    return {
        "items": tools,
        "missing_required": missing_required,
        "missing_important": missing_important,
        "healthy": not missing_required,
        "install_status": install_status,
    }


def latest_previous_boot_snapshot() -> Optional[Path]:
    if not SNAPSHOT_DIR.exists():
        return None
    candidates = sorted(
        (path for path in SNAPSHOT_DIR.iterdir() if path.is_dir() and path.name.endswith("_previous-boot-review")),
        key=lambda item: item.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def snapshot_shows_manual_reboot(snapshot_path_text: str) -> bool:
    snapshot_path = Path(str(snapshot_path_text or "").strip())
    if not snapshot_path.exists() or not snapshot_path.is_dir():
        return False
    journal_path = snapshot_path / "journal_previous_boot.txt"
    if not journal_path.exists():
        return False
    journal_text = journal_path.read_text(encoding="utf-8", errors="ignore").lower()
    manual_markers = (
        "command=/usr/sbin/reboot",
        "command=/sbin/reboot",
        "command=/usr/bin/systemctl reboot",
        "command=/bin/systemctl reboot",
        "command=/usr/sbin/shutdown -r",
        "command=/sbin/shutdown -r",
        "system is rebooting",
        "starting reboot",
        "reached target reboot",
    )
    return any(marker in journal_text for marker in manual_markers)


def extract_notable_lines(path: Path, limit: int = 8) -> List[str]:
    if not path.exists():
        return []
    high_keywords = (
        "error",
        "failed",
        "failure",
        "timed out",
        "timeout",
        "segfault",
        "panic",
        "watchdog",
        "hung",
        "i/o error",
        "reset",
        "oom",
        "out of memory",
        "memory error",
        "nvrm",
        "gpu",
        "call trace",
        "blocked for more than",
        "stack trace",
    )
    medium_keywords = (
        "teamviewer",
        "bridge",
        "esg",
        "sysops",
        "network",
        "link is down",
        "dhcp",
        "carrier",
        "nvme",
        "sda",
        "ext4-fs warning",
        "xfs",
    )
    ignore_terms = (
        "mounted filesystem",
        "unmounting filesystem",
        "apparmor=",
        "audit:",
        "quota mode: none",
    )
    notable: List[str] = []
    seen = set()
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if any(term in lowered for term in ignore_terms):
            continue
        if any(keyword in lowered for keyword in high_keywords) or any(keyword in lowered for keyword in medium_keywords):
            if line not in seen:
                seen.add(line)
                notable.append(line[:240])
        if len(notable) >= limit:
            break
    return notable


def extract_all_notable_lines(path: Path, limit: int = 40) -> List[str]:
    if not path.exists():
        return []
    all_lines = extract_notable_lines(path, limit=limit)
    return all_lines[:limit]


def extract_tail_lines(path: Path, limit: int = 20) -> List[str]:
    if not path.exists():
        return []
    lines: List[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if line:
            lines.append(line[:240])
    return lines[-limit:]


def latest_incident() -> Optional[Dict[str, Any]]:
    incidents = all_incidents()
    return incidents[0] if incidents else None


def parse_journal_timestamp(line: str, reference: datetime) -> Optional[datetime]:
    match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+", str(line or ""))
    if not match:
        return None
    try:
        parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
    except ValueError:
        return None
    local_reference = reference.astimezone()
    candidate = parsed.replace(year=local_reference.year, tzinfo=local_reference.tzinfo)
    if candidate > (local_reference + timedelta(days=2)):
        candidate = candidate.replace(year=candidate.year - 1)
    return candidate


def last_lines_before_big_gap(lines: List[str], reference: datetime, visible_limit: int = 10, gap_seconds: int = 300) -> List[str]:
    stamped: List[Dict[str, Any]] = []
    for line in lines:
        ts = parse_journal_timestamp(line, reference)
        stamped.append({"line": line, "ts": ts})
    gap_index: Optional[int] = None
    for index in range(1, len(stamped)):
        prev_ts = stamped[index - 1]["ts"]
        curr_ts = stamped[index]["ts"]
        if prev_ts is None or curr_ts is None:
            continue
        if (curr_ts - prev_ts).total_seconds() >= gap_seconds:
            gap_index = index
    if gap_index is None:
        return lines[-visible_limit:]
    return [str(item["line"]) for item in stamped[max(0, gap_index - visible_limit):gap_index]]


def previous_boot_lines_near(anchor_time: Optional[datetime], kernel: bool = False, limit: int = 20) -> Dict[str, Any]:
    if anchor_time is None:
        return {"lines": [], "mode": "none"}
    local_anchor = anchor_time.astimezone()
    cutoff = local_anchor.strftime("%Y-%m-%d %H:%M:%S")
    since = (local_anchor - timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S")
    until = (local_anchor + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    kernel_flag = "-k " if kernel else ""

    before_result = run_shell(
        f"journalctl {kernel_flag}-b -1 --until {shlex.quote(cutoff)} -n {int(limit)} --no-pager || true",
        timeout=20,
    )
    before_lines = [line.strip()[:240] for line in str(before_result.get("output", "")).splitlines() if line.strip()]
    if before_lines:
        gap_lines = last_lines_before_big_gap(before_lines, local_anchor, visible_limit=min(10, limit), gap_seconds=300)
        if gap_lines and gap_lines != before_lines[-min(10, limit):]:
            return {"lines": gap_lines, "mode": "gap"}
        return {"lines": before_lines[-limit:], "mode": "before"}

    window_result = run_shell(
        f"journalctl {kernel_flag}-b -1 --since {shlex.quote(since)} --until {shlex.quote(until)} -n {int(limit)} --no-pager || true",
        timeout=20,
    )
    window_lines = [line.strip()[:240] for line in str(window_result.get("output", "")).splitlines() if line.strip()]
    if window_lines:
        return {"lines": window_lines[-limit:], "mode": "window"}

    tail_result = run_shell(
        f"journalctl {kernel_flag}-b -1 -n {int(limit)} --no-pager || true",
        timeout=20,
    )
    tail_lines = [line.strip()[:240] for line in str(tail_result.get("output", "")).splitlines() if line.strip()]
    return {"lines": tail_lines[-limit:], "mode": "tail" if tail_lines else "none"}


def service_lines_near(anchor_time: Optional[datetime], limit: int = 10) -> Dict[str, Any]:
    if anchor_time is None:
        return {"lines": [], "mode": "none"}
    local_anchor = anchor_time.astimezone()
    cutoff = local_anchor.strftime("%Y-%m-%d %H:%M:%S")
    since = (local_anchor - timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S")
    units = (
        "-u esg.service -u bridge.service -u sysops.service "
        "-u NetworkManager.service -u systemd-networkd.service -u systemd-resolved.service "
        "-u ModemManager.service"
    )
    result = run_shell(
        "journalctl "
        "-b -1 "
        f"{units} "
        f"--since {shlex.quote(since)} --until {shlex.quote(cutoff)} "
        f"-n {int(limit)} --no-pager || true",
        timeout=20,
    )
    lines = [line.strip()[:240] for line in str(result.get("output", "")).splitlines() if line.strip()]
    if lines:
        return {"lines": lines[-limit:], "mode": "service"}

    tail_result = run_shell(
        "journalctl "
        "-b -1 "
        f"{units} "
        f"-n {int(limit)} --no-pager || true",
        timeout=20,
    )
    tail_lines = [line.strip()[:240] for line in str(tail_result.get("output", "")).splitlines() if line.strip()]
    return {"lines": tail_lines[-limit:], "mode": "service-tail" if tail_lines else "none"}


def watchdog_event_lines_near(anchor_time: Optional[datetime], limit: int = 10) -> List[str]:
    if anchor_time is None or not EVENTS_PATH.exists():
        return []
    window_start = anchor_time - timedelta(minutes=60)
    lines: List[str] = []
    for item in all_events():
        ts = parse_iso(str(item.get("ts", "")))
        if ts is None or ts > anchor_time or ts < window_start:
            continue
        title = str(item.get("event", "event")).replace("_", " ")
        detail = str(item.get("detail") or item.get("reason") or item.get("status") or "").strip()
        line = f"{ts.astimezone().strftime('%d/%m/%Y, %H:%M:%S')} | {title}"
        if detail:
            line += f" | {detail}"
        lines.append(line[:240])
    return lines[-limit:]


def summarize_crash_findings(system_lines: List[str], kernel_lines: List[str]) -> List[str]:
    findings: List[str] = []
    combined = [*kernel_lines, *system_lines]
    lowered = " \n".join(line.lower() for line in combined)

    if "memory error" in lowered or "edac" in lowered:
        findings.append("Memory-related kernel messages were seen before the reboot. This is worth treating as a possible hardware or platform-stability clue.")
    if "oom" in lowered or "out of memory" in lowered:
        findings.append("The previous boot shows signs of memory exhaustion, which could explain a hang or forced restart.")
    if "i/o error" in lowered or "nvme" in lowered or "sda" in lowered:
        findings.append("Storage-related messages appeared in the previous boot logs. Check whether the OS disk or recording disk showed instability.")
    if "network" in lowered or "link is down" in lowered or "dhcp" in lowered:
        findings.append("Network-related messages appeared before reboot. Compare these with any loss of remote access or RUT reachability.")
    if "bridge" in lowered or "esg" in lowered or "sysops" in lowered:
        findings.append("Videosoft service names appeared in the previous-boot logs. Compare their timing with the fault window.")

    if not findings and (system_lines or kernel_lines):
        findings.append("A previous-boot snapshot exists, but nothing strongly suspicious ranked above normal noise. Review the highlighted lines and full snapshot files if the fault repeats.")
    if not findings:
        findings.append("No previous-boot findings yet. The next detected reboot should populate this section.")
    return findings[:4]


def hardware_review_payload(state: Dict[str, Any]) -> Dict[str, Any]:
    hardware = state.get("hardware_health") or {}
    warnings = [str(line) for line in hardware.get("warnings", []) if str(line).strip()]
    smart = hardware.get("smart", []) if isinstance(hardware.get("smart", []), list) else []
    pstore_entries = [str(item) for item in hardware.get("pstore_entries", []) if str(item).strip()]
    findings: List[str] = []
    combined = " \n".join(warnings).lower()

    if "edac" in combined or "memory error" in combined or "machine check" in combined:
        findings.append("Memory-controller or EDAC warnings are present. Treat RAM or platform stability as a live suspect.")
    if any(not bool(item.get("available", True)) for item in smart):
        findings.append("SMART data is not available yet for one or more disks. Install smartmontools to rule storage in or out properly.")
    failing_smart = [str(item.get("device")) for item in smart if item.get("available") and item.get("ok") is False]
    if failing_smart:
        findings.append("SMART returned a non-zero result for " + ", ".join(failing_smart) + ". Check disk health next.")
    if pstore_entries:
        findings.append("Persistent crash-store files exist in /sys/fs/pstore. These may contain kernel panic or reset clues.")
    if not findings and warnings:
        findings.append("Hardware-related warnings exist, but nothing clearly ranks above the rest yet. Compare them across repeated incidents.")
    if not findings:
        findings.append("No current hardware-warning summary is available yet.")

    return {
        "checked_at": str(hardware.get("checked_at", "")),
        "warnings": warnings,
        "smart": smart,
        "pstore_entries": pstore_entries,
        "findings": findings[:4],
    }


def parse_teamviewer_info(output: str) -> Dict[str, str]:
    parsed = {"id": "", "version": "", "status": "", "device": ""}
    for raw_line in output.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw_line).replace("\u25cf", " ").strip()
        if not line:
            continue
        lower = line.lower()
        if not parsed["id"]:
            match = re.search(r"\b(?:id|teamviewer id)\b[^0-9]*([0-9][0-9 ]{5,})", line, re.IGNORECASE)
            if match:
                parsed["id"] = re.sub(r"\s+", "", match.group(1))
            else:
                loose_match = re.search(r"\b([0-9]{7,12})\b", line)
                if loose_match:
                    parsed["id"] = loose_match.group(1)
        if not parsed["version"] and "version" in lower:
            parsed["version"] = line.split(":", 1)[1].strip() if ":" in line else line
        if not parsed["status"] and any(term in lower for term in ("status", "state", "ready", "disabled", "daemon")):
            parsed["status"] = line.split(":", 1)[1].strip() if ":" in line else line
        if not parsed["device"] and "device" in lower:
            parsed["device"] = line.split(":", 1)[1].strip() if ":" in line else line
    return parsed


def teamviewer_status_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    installed = command_exists("teamviewer")
    daemon_running = False
    gui_running = False
    id_permission_issue = False

    daemon_check = run_shell("pgrep -fa teamviewerd", timeout=5)
    if daemon_check["ok"] and daemon_check["output"]:
        daemon_running = True
    gui_check = run_shell("pgrep -fa TeamViewer", timeout=5)
    if gui_check["ok"] and gui_check["output"]:
        gui_running = True
    daemon_state = "running" if daemon_running else "stopped"
    if command_exists("systemctl"):
        daemon_state_result = run_shell("systemctl is-active teamviewerd.service || systemctl is-active teamviewer.service", timeout=5)
        cleaned_state = daemon_state_result["output"].splitlines()[0].strip().lower() if daemon_state_result["output"] else ""
        if cleaned_state in {"active", "inactive", "failed", "activating", "deactivating"}:
            daemon_state = cleaned_state

    info_output = ""
    parsed_info: Dict[str, str] = {"id": "", "version": "", "status": "", "device": ""}
    command = str(config.get("teamviewer_id_command", "")).strip()
    if installed and command:
        info_result = run_shell(command, timeout=15)
        info_output = info_result["output"]
        parsed_info = parse_teamviewer_info(info_output)
        id_permission_issue = "permission denied" in info_output.lower() and "global.conf" in info_output.lower()
        if not daemon_running and ("daemon" in info_output.lower() or "ready" in info_output.lower()):
            daemon_running = True
    if not parsed_info.get("version") and installed:
        version_result = run_shell("teamviewer --version", timeout=10)
        parsed_version = parse_teamviewer_info(version_result["output"])
        parsed_info["version"] = parsed_version.get("version", "") or version_result["output"].splitlines()[0].strip()
    if not parsed_info.get("version") and command_exists("dpkg-query"):
        dpkg_result = run_shell("dpkg-query -W -f='${Version}' teamviewer", timeout=10)
        if dpkg_result["ok"] and dpkg_result["output"]:
            parsed_info["version"] = dpkg_result["output"].splitlines()[0].strip()

    status_text = "Daemon running" if daemon_running else "Daemon stopped"
    if daemon_state == "active":
        status_text = "Daemon active"
    elif daemon_state == "failed":
        status_text = "Daemon failed"
    elif daemon_state not in {"running", "stopped"}:
        status_text = f"Daemon {daemon_state}"
    if gui_running:
        status_text += ", GUI running"
    elif installed:
        status_text += ", GUI not running"
    if id_permission_issue:
        status_text += ", ID needs elevated read access"

    summary_parts = []
    if not installed:
        summary_parts.append("TeamViewer CLI not found")
    elif daemon_running:
        summary_parts.append("daemon running")
    else:
        summary_parts.append("daemon not running")
    if gui_running:
        summary_parts.append("GUI running")
    if id_permission_issue:
        summary_parts.append("ID blocked by permissions")
    if parsed_info.get("id"):
        summary_parts.append(f"ID {parsed_info['id']}")

    return {
        "installed": installed,
        "daemon_running": daemon_running,
        "gui_running": gui_running,
        "id": parsed_info.get("id", "") or ("Permission denied" if id_permission_issue else ""),
        "version": parsed_info.get("version", ""),
        "status_text": status_text,
        "device": parsed_info.get("device", ""),
        "summary": ", ".join(summary_parts) if summary_parts else "No TeamViewer information available.",
        "raw_output": info_output[:1000],
        "id_permission_issue": id_permission_issue,
        "reset_supported": installed and bool(str(config.get("teamviewer_password_reset_command", "")).strip()),
    }


def reset_teamviewer_password(config: Dict[str, Any], requested_password: str = "") -> Dict[str, Any]:
    command_template = str(config.get("teamviewer_password_reset_command", "")).strip()
    if not command_exists("teamviewer"):
        return {"ok": False, "message": "TeamViewer CLI is not installed on this unit."}
    if not command_template:
        return {"ok": False, "message": "No TeamViewer password reset command is configured."}

    password = requested_password.strip()
    if password:
        if len(password) < 6:
            return {"ok": False, "message": "Choose a TeamViewer password with at least 6 characters."}
    else:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        password = "".join(secrets.choice(alphabet) for _ in range(10))
    command = command_template.replace("{password}", shlex.quote(password))
    result = run_shell(command, timeout=20)
    if not result["ok"]:
        return {
            "ok": False,
            "message": "TeamViewer password reset failed.",
            "detail": result["output"][:500],
        }
    return {
        "ok": True,
        "message": f"TeamViewer password reset to: {password}",
        "password": password,
        "detail": result["output"][:500],
    }


def run_teamviewer_command(config: Dict[str, Any], action: str) -> Dict[str, Any]:
    key = "teamviewer_start_command" if action == "start" else "teamviewer_restart_command"
    command = str(config.get(key, "")).strip()
    if not command:
        return {"ok": False, "message": f"No TeamViewer {action} command is configured."}
    result = run_shell(command, timeout=20)
    if not result["ok"]:
        return {"ok": False, "message": f"TeamViewer {action} failed.", "detail": result["output"][:500]}
    return {"ok": True, "message": f"TeamViewer {action} command sent.", "detail": result["output"][:500]}


def clue_counter_payload(hardware_review: Dict[str, Any], crash_review: Dict[str, Any]) -> List[Dict[str, Any]]:
    lines = [
        str(line).lower()
        for line in [
            *(hardware_review.get("warnings", []) or []),
            *(crash_review.get("system_lines_all", []) or []),
            *(crash_review.get("kernel_lines_all", []) or []),
        ]
    ]
    categories = [
        ("igc / NIC", ("igc", "link is down", "carrier", "pcie link", "detached", "enp3s0")),
        ("EDAC / memory", ("edac", "memory error", "machine check", "ibecc", "mce")),
        ("Storage", ("nvme", "i/o error", "buffer i/o", "ext4", "xfs", "ata")),
        ("App / service", ("teamviewer", "bridge", "esg", "sysops", "segfault", "oom", "killed process")),
    ]
    counters: List[Dict[str, Any]] = []
    for label, terms in categories:
        matches = [line for line in lines if any(term in line for term in terms)]
        counters.append({"label": label, "count": len(matches), "state": "hot" if matches else "clear"})
    return counters


def linux_stability_payload(state: Dict[str, Any], hardware_review: Dict[str, Any], crash_review: Dict[str, Any]) -> Dict[str, Any]:
    previous_boot_lines = [
        str(line)
        for line in [
            *(crash_review.get("kernel_lines_all", []) or []),
            *(crash_review.get("system_lines_all", []) or []),
        ]
    ]
    current_warning_lines = [str(line) for line in hardware_review.get("warnings", [])]

    def count_matches(lines: List[str], terms: tuple[str, ...]) -> int:
        return sum(1 for line in lines if any(term in line.lower() for term in terms))

    link_terms = ("link is down", "link up", "link down", "carrier", "nic link is down", "enp3s0")
    igc_terms = ("igc", "igc_rd32", "reset adapter", "resetting", "watchdog")
    pcie_terms = ("pcie link", "device now detached", "detached", "aer:", "aspm")
    memory_terms = ("edac", "memory error", "machine check", "ibecc", "mce")

    previous_counts = {
        "link_flaps": count_matches(previous_boot_lines, link_terms),
        "igc_errors": count_matches(previous_boot_lines, igc_terms),
        "pcie_events": count_matches(previous_boot_lines, pcie_terms),
        "memory_events": count_matches(previous_boot_lines, memory_terms),
    }
    current_counts = {
        "link_flaps": count_matches(current_warning_lines, link_terms),
        "igc_errors": count_matches(current_warning_lines, igc_terms),
        "pcie_events": count_matches(current_warning_lines, pcie_terms),
        "memory_events": count_matches(current_warning_lines, memory_terms),
    }

    strongest_previous_line = ""
    strongest_current_line = ""
    priority_terms = (
        "device now detached",
        "pcie link",
        "igc",
        "link is down",
        "watchdog",
        "edac",
        "memory error",
        "machine check",
    )
    for line in previous_boot_lines:
        lowered = line.lower()
        if any(term in lowered for term in priority_terms):
            strongest_previous_line = line[:240]
            break
    for line in current_warning_lines:
        lowered = line.lower()
        if any(term in lowered for term in priority_terms):
            strongest_current_line = line[:240]
            break

    interpretation = []
    if previous_counts["link_flaps"] or previous_counts["igc_errors"] or previous_counts["pcie_events"]:
        interpretation.append("Previous-boot logs contain NIC or PCIe clues, so the network path may have been involved before the restart.")
    elif current_counts["link_flaps"] or current_counts["igc_errors"] or current_counts["pcie_events"]:
        interpretation.append("NIC or PCIe clues are present in current warnings only, which can fit a post-repower or after-boot observation rather than the original freeze.")
    else:
        interpretation.append("No strong NIC or PCIe clue is standing out yet from the lines collected so far.")

    if previous_counts["memory_events"]:
        interpretation.append("Previous-boot logs contain EDAC or memory-controller clues, which keeps RAM or platform stability in scope.")
    elif current_counts["memory_events"]:
        interpretation.append("Memory-controller clues are present in current warnings, but they are not yet tied to the freeze window.")
    else:
        interpretation.append("No EDAC or memory-controller clue is standing out yet from the collected lines.")

    alert_rules = [
        {"label": "Link flap rule", "threshold": ">5 link changes / 30s", "meaning": "Flag likely NIC instability"},
        {"label": "igc rule", "threshold": "Repeated igc/reset lines", "meaning": "Flag driver or link instability"},
        {"label": "PCIe rule", "threshold": "Any detach / PCIe-link-lost line", "meaning": "Treat as high-priority hardware or driver clue"},
        {"label": "Memory rule", "threshold": "Any EDAC/MCE/IBECC line", "meaning": "Treat RAM or platform stability as a live suspect"},
    ]

    return {
        "previous_boot_counts": previous_counts,
        "current_warning_counts": current_counts,
        "strongest_previous_line": strongest_previous_line,
        "strongest_current_line": strongest_current_line,
        "interpretation": interpretation[:4],
        "alert_rules": alert_rules,
    }


def fault_reporting_payload(
    state: Dict[str, Any],
    checks: Dict[str, Any],
    reboot_counts: Dict[str, int],
    hardware_review: Dict[str, Any],
    crash_review: Dict[str, Any],
    suspect_scores: List[Dict[str, Any]],
    teamviewer: Dict[str, Any],
) -> Dict[str, Any]:
    warning_text = " \n".join(str(line).lower() for line in hardware_review.get("warnings", []))
    crash_text = " \n".join(
        str(line).lower()
        for line in [*(crash_review.get("system_lines_all", []) or []), *(crash_review.get("kernel_lines_all", []) or [])]
    )
    combined_text = warning_text + " \n" + crash_text

    impact = "System currently healthy."
    if state.get("fault_active"):
        impact = summarize_fault_checks(checks)
    elif reboot_counts.get("unexpected"):
        impact = "The unit is up now, but it became non-functional and required an unplanned reboot or repower to recover."

    primary = suspect_scores[0] if suspect_scores else {"label": "No clear suspect yet", "score": 0, "reasons": []}
    short_status = "Healthy now"
    if state.get("fault_active"):
        short_status = "Fault active now"
    elif reboot_counts.get("unexpected"):
        short_status = "Recovered after unplanned reboot or repower"
    plain_summary = f"{short_status}. Top suspect: {primary.get('label', 'unknown')}."
    if primary.get("score", 0) <= 0:
        plain_summary = f"{short_status}. No suspect category has strong evidence yet."

    stability_clues = []
    if any(term in combined_text for term in ("igc", "link is down", "carrier", "pcie link", "detached")):
        stability_clues.append("Linux network-driver clues were seen. Intel I225 / igc link stability is worth checking.")
    if any(term in combined_text for term in ("edac", "memory error", "machine check", "ibecc", "mce")):
        stability_clues.append("Linux memory-controller clues were seen. RAM, EDAC, or platform stability remains a live suspect.")
    if any(term in combined_text for term in ("out of memory", "oom", "killed process")):
        stability_clues.append("The logs include memory-pressure signs. This may be application or system memory exhaustion.")
    if any(term in combined_text for term in ("nvme", "i/o error", "ext4", "xfs", "buffer i/o")):
        stability_clues.append("Linux storage clues were seen. Disk or filesystem health should be checked.")
    if not stability_clues:
        stability_clues.append("No strong Linux kernel/platform clue is standing out above the rest yet.")

    quick_actions: List[str] = []
    if state.get("fault_active"):
        quick_actions.append("Check Latest checks to confirm whether the fault is app, service, LAN/TCP, or WAN.")
    if reboot_counts.get("unexpected"):
        quick_actions.append("Review Crash review and the latest previous-boot snapshot for the minutes before restart.")
    if any(term in combined_text for term in ("igc", "link is down", "carrier", "pcie link")):
        quick_actions.append("Compare the freeze time with NIC or link messages. Repeated igc or link events raise the network path suspicion.")
    if any(term in combined_text for term in ("edac", "memory error", "machine check", "ibecc", "mce")):
        quick_actions.append("Check whether EDAC or memory errors are repeating across incidents before changing hardware.")
    if checks.get("app_ok") is False:
        quick_actions.append("The app is currently missing. Confirm the launch command and whether the process stays up after restart.")
    if teamviewer.get("installed") and not teamviewer.get("daemon_running"):
        quick_actions.append("TeamViewer daemon is not running, so remote access may be unavailable even if the box is up.")
    if not quick_actions:
        quick_actions.append("Watch the timeline and chart for the next fault transition, then compare it with the previous-boot review.")

    return {
        "headline": short_status,
        "summary": plain_summary,
        "impact": impact,
        "top_suspect": primary,
        "stability_clues": stability_clues[:4],
        "quick_actions": quick_actions[:5],
    }


def xml_leaf_values(raw_xml: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        root = ET.fromstring(raw_xml)
    except Exception:
        return values
    for node in root.iter():
        if list(node):
            continue
        tag = str(node.tag).split("}", 1)[-1]
        text = (node.text or "").strip()
        if text and tag not in values:
            values[tag] = text
    return values


def hik_request(config: Dict[str, Any], path_template: str, timeout: int = 8) -> Dict[str, Any]:
    scheme = str(config.get("hik_scheme", "http")).strip() or "http"
    host = str(config.get("hik_host", "")).strip()
    username = str(config.get("hik_username", "")).strip()
    password = str(config.get("hik_password", "")).strip()
    channel = int(config.get("hik_channel", 1) or 1)
    if not host:
        return {"ok": False, "message": "Hik host is empty.", "status": 0, "body": ""}
    raw_path = str(path_template or "").strip()
    try:
        path = raw_path.format(channel=channel)
    except Exception as exc:
        return {
            "ok": False,
            "message": f"Invalid Hik path template '{raw_path}': {type(exc).__name__}: {exc}",
            "status": 0,
            "body": "",
            "path": raw_path,
            "url": "",
        }
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{scheme}://{host}{path}"
    password_mgr = HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, password)
    opener = build_opener(HTTPDigestAuthHandler(password_mgr), HTTPBasicAuthHandler(password_mgr))
    request = Request(url, headers={"User-Agent": "VA-Connect-Watchdog-HikProbe"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return {"ok": True, "message": "ok", "status": getattr(response, "status", 200), "body": body, "path": path, "url": url}
    except HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {"ok": False, "message": f"HTTPError: {exc}", "status": int(getattr(exc, "code", 0) or 0), "body": body, "path": path, "url": url}
    except URLError as exc:
        return {"ok": False, "message": f"URLError: {exc}", "status": 0, "body": "", "path": path, "url": url}
    except Exception as exc:
        return {"ok": False, "message": f"{type(exc).__name__}: {exc}", "status": 0, "body": "", "path": path, "url": url}


def parse_hik_people_count(raw_xml: str) -> Dict[str, Any]:
    values = xml_leaf_values(raw_xml)
    parsed: Dict[str, Any] = {}
    if not raw_xml.strip():
        return parsed
    candidate_tags = [
        ("peopleEntering", "entering"),
        ("peopleExiting", "exiting"),
        ("enterNum", "entering"),
        ("outNum", "exiting"),
        ("entered", "entered"),
        ("exited", "exited"),
        ("in", "entering"),
        ("out", "exiting"),
        ("currentPeopleNumber", "current"),
        ("peopleNum", "current"),
        ("numOfPeople", "current"),
        ("total", "total"),
        ("totalCount", "total"),
        ("peopleCounting", "current"),
        ("realTimeCount", "current"),
    ]
    lower_values = {str(k).lower(): v for k, v in values.items()}
    for tag, output_key in candidate_tags:
        value = values.get(tag)
        if value is None:
            value = lower_values.get(tag.lower())
        if value is None:
            continue
        parsed[output_key] = value
    if not parsed:
        for tag, value in values.items():
            tag_l = str(tag).lower()
            if not re.search(r"(people|person|count|enter|exit|in|out|num|total)", tag_l):
                continue
            if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", str(value).strip()):
                parsed[tag] = value
    return parsed


def hik_path_candidates(path_template: str, fallback_paths: List[str]) -> List[str]:
    ordered: List[str] = []
    seeds = [str(path_template or "").strip()] + list(fallback_paths)
    swap_words = [
        ("framesPeopleCounting", "peopleCounting"),
        ("peopleCounting", "framesPeopleCounting"),
        ("peopleCounting", "personCounting"),
        ("personCounting", "peopleCounting"),
    ]
    for seed in seeds:
        if not seed:
            continue
        if not seed.startswith("/"):
            seed = f"/{seed}"
        if seed not in ordered:
            ordered.append(seed)
        for old, new in swap_words:
            if old not in seed:
                continue
            variant = seed.replace(old, new)
            if variant not in ordered:
                ordered.append(variant)
    return ordered


def hik_attempt_probe(config: Dict[str, Any], path_candidates: List[str]) -> Dict[str, Any]:
    attempts: List[Dict[str, Any]] = []
    chosen: Optional[Dict[str, Any]] = None
    for path in path_candidates:
        response = hik_request(config, path)
        attempt = {
            "path": str(response.get("path", path)),
            "url": str(response.get("url", "")),
            "ok": bool(response.get("ok")),
            "status": int(response.get("status", 0) or 0),
            "message": str(response.get("message", "")),
        }
        attempts.append(attempt)
        if chosen is None:
            chosen = response
        if response.get("ok"):
            chosen = response
            break
    return {"attempts": attempts, "response": chosen or {"ok": False, "message": "No path candidates.", "status": 0, "body": ""}}


def hik_probe_payload(config: Dict[str, Any]) -> Dict[str, Any]:
    prior_status = read_json(HIK_STATUS_PATH, {})
    probe_sequence = int(prior_status.get("probe_sequence", 0) or 0) + 1
    if not bool(config.get("hik_enabled")):
        payload = {"enabled": False, "message": "Hik probe disabled.", "state": "idle", "checked_at": now_iso(), "probe_sequence": probe_sequence}
        write_json(HIK_STATUS_PATH, payload)
        return payload
    host = str(config.get("hik_host", "")).strip()
    if not host:
        payload = {"enabled": True, "message": "Hik host not configured.", "state": "idle", "checked_at": now_iso(), "probe_sequence": probe_sequence}
        write_json(HIK_STATUS_PATH, payload)
        return payload

    started_at = now_iso()
    running_payload = {
        "enabled": True,
        "state": "running",
        "message": "Running Hik people-count probe...",
        "checked_at": started_at,
        "host": host,
        "probe_sequence": probe_sequence,
    }
    write_json(HIK_STATUS_PATH, running_payload)

    device_info = hik_request(config, "/ISAPI/System/deviceInfo")
    device_values = xml_leaf_values(str(device_info.get("body", "")))

    capabilities_probe = hik_attempt_probe(
        config,
        hik_path_candidates(
            str(config.get("hik_people_count_capabilities_path", "")),
            [
                "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities",
                "/ISAPI/Intelligent/channels/{channel}/peopleCounting/capabilities",
                "/ISAPI/Intelligent/channels/{channel}/personCounting/capabilities",
                "/ISAPI/Intelligent/channels/{channel}/Shield/peopleCounting/capabilities",
                "/ISAPI/System/Video/inputs/channels/{channel}/counting/capabilities",
            ],
        ),
    )
    result_probe = hik_attempt_probe(
        config,
        hik_path_candidates(
            str(config.get("hik_people_count_result_path", "")),
            [
                "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/result",
                "/ISAPI/Intelligent/channels/{channel}/peopleCounting/result",
                "/ISAPI/Intelligent/channels/{channel}/personCounting/result",
                "/ISAPI/Intelligent/channels/{channel}/Shield/peopleCounting",
                "/ISAPI/System/Video/inputs/channels/{channel}/counting",
            ],
        ),
    )
    capabilities = capabilities_probe.get("response", {})
    result = result_probe.get("response", {})
    parsed = parse_hik_people_count(result.get("body", ""))
    result_values = xml_leaf_values(str(result.get("body", "")))

    state = "ok" if result.get("ok") else "failed"
    if result.get("ok") and parsed:
        message = f"Hik people-count probe completed ({len(parsed)} value(s) parsed)."
    elif result.get("ok") and "Shield/peopleCounting" in str(result.get("path", "")) and str(result_values.get("enabled", "")).lower() == "false":
        message = "Hik Shield endpoint is reachable, but people counting is disabled in camera settings (enabled=false)."
    elif result.get("ok"):
        message = "Hik endpoint reachable but no count values were parsed."
    elif device_info.get("ok") and int(result.get("status", 0) or 0) in {401, 403}:
        message = "Camera is reachable but people-count endpoint is denied (401/403). Feature may be unsupported or blocked by permissions."
    elif not device_info.get("ok"):
        message = f"Hik camera auth/connectivity check failed: {device_info.get('message', 'unknown error')}"
    else:
        message = f"Hik probe failed: {result.get('message', 'unknown error')}"
    payload = {
        "enabled": True,
        "state": state,
        "message": message,
        "checked_at": now_iso(),
        "started_at": started_at,
        "host": host,
        "probe_sequence": probe_sequence,
        "capabilities_ok": bool(capabilities.get("ok")),
        "result_ok": bool(result.get("ok")),
        "capabilities_status": int(capabilities.get("status", 0) or 0),
        "result_status": int(result.get("status", 0) or 0),
        "device_info_ok": bool(device_info.get("ok")),
        "device_info_status": int(device_info.get("status", 0) or 0),
        "device_info_message": str(device_info.get("message", "")),
        "device_model": str(device_values.get("model", "")),
        "device_name": str(device_values.get("deviceName", "")),
        "firmware_version": str(device_values.get("firmwareVersion", "")),
        "capabilities_path_used": str(capabilities.get("path", "")),
        "result_path_used": str(result.get("path", "")),
        "capabilities_attempts": capabilities_probe.get("attempts", []),
        "result_attempts": result_probe.get("attempts", []),
        "parsed_counts": parsed,
        "capabilities_excerpt": str(capabilities.get("body", ""))[:800],
        "result_excerpt": str(result.get("body", ""))[:800],
    }
    write_json(HIK_STATUS_PATH, payload)
    return payload


def hik_console_text(hik_status: Dict[str, Any]) -> str:
    if not isinstance(hik_status, dict):
        return "No Hik probe output yet."
    lines: List[str] = []
    checked_at = str(hik_status.get("checked_at", "")).strip() or "unknown"
    lines.append(f"[{checked_at}] state={str(hik_status.get('state', 'idle'))}")
    lines.append(f"message: {str(hik_status.get('message', 'No Hik probe run yet.'))}")
    lines.append(
        "deviceInfo: "
        f"ok={'true' if hik_status.get('device_info_ok') else 'false'} "
        f"status={int(hik_status.get('device_info_status', 0) or 0)} "
        f"model={str(hik_status.get('device_model', 'unknown') or 'unknown')}"
    )
    for attempt in hik_status.get("capabilities_attempts", []) or []:
        lines.append(
            f"capabilities: {'OK' if attempt.get('ok') else 'FAIL'} "
            f"[{int(attempt.get('status', 0) or 0)}] {str(attempt.get('path', ''))}"
        )
    for attempt in hik_status.get("result_attempts", []) or []:
        lines.append(
            f"result: {'OK' if attempt.get('ok') else 'FAIL'} "
            f"[{int(attempt.get('status', 0) or 0)}] {str(attempt.get('path', ''))}"
        )
    return "\n".join(lines) if lines else "No Hik probe output yet."


def suspect_scores_payload(state: Dict[str, Any], crash_review: Dict[str, Any], hardware_review: Dict[str, Any]) -> List[Dict[str, Any]]:
    checks = state.get("last_checks") or {}
    suspects = {
        "Memory / platform": {"score": 0, "reasons": []},
        "Storage / recording disk": {"score": 0, "reasons": []},
        "Network / RUT path": {"score": 0, "reasons": []},
        "Videosoft app / service": {"score": 0, "reasons": []},
    }

    warning_text = " \n".join(str(line).lower() for line in hardware_review.get("warnings", []))
    crash_text = " \n".join(str(line).lower() for line in [*(crash_review.get("system_lines_all", []) or []), *(crash_review.get("kernel_lines_all", []) or [])])

    if any(term in warning_text for term in ("edac", "memory error", "machine check")):
        suspects["Memory / platform"]["score"] += 4
        suspects["Memory / platform"]["reasons"].append("EDAC or memory-controller warnings were detected.")
    if any(term in crash_text for term in ("edac", "memory error", "machine check")):
        suspects["Memory / platform"]["score"] += 2
        suspects["Memory / platform"]["reasons"].append("Previous-boot review also contains memory-related lines.")

    last_metrics = state.get("last_metrics") or {}
    recording_disk = last_metrics.get("recording_disk_percent")
    if isinstance(recording_disk, (int, float)) and recording_disk >= 99.0:
        suspects["Storage / recording disk"]["reasons"].append(f"Recording disk is full at {recording_disk:.2f}%, but that alone may not explain a gateway lockup.")
    if any(term in warning_text for term in ("i/o error", "ext4", "ata", "nvme", "resetting link", "buffer i/o error")):
        suspects["Storage / recording disk"]["score"] += 4
        suspects["Storage / recording disk"]["reasons"].append("Kernel warnings include storage or filesystem terms.")
    failing_smart = [item for item in hardware_review.get("smart", []) if item.get("available") and item.get("ok") is False]
    if failing_smart:
        suspects["Storage / recording disk"]["score"] += 4
        suspects["Storage / recording disk"]["reasons"].append("SMART returned a non-zero result for at least one disk.")

    if checks.get("internet_ok") is False:
        suspects["Network / RUT path"]["score"] += 4
        suspects["Network / RUT path"]["reasons"].append("Current checks show WAN reachability issues.")
    if checks.get("lan_ok") is False:
        suspects["Network / RUT path"]["score"] += 3
        suspects["Network / RUT path"]["reasons"].append("Current checks show LAN/TCP target failures.")
    if any(term in warning_text for term in ("link is down", "dhcp", "carrier")):
        suspects["Network / RUT path"]["score"] += 2
        suspects["Network / RUT path"]["reasons"].append("Kernel warnings include network-link terms.")

    if checks.get("app_ok") is False or checks.get("services_ok") is False:
        suspects["Videosoft app / service"]["score"] += 4
        suspects["Videosoft app / service"]["reasons"].append("Current checks show the app or a monitored service failing.")
    if any(term in crash_text for term in ("esg", "bridge", "sysops", "segfault", "oom", "killed")):
        suspects["Videosoft app / service"]["score"] += 2
        suspects["Videosoft app / service"]["reasons"].append("Previous-boot review includes app or service-related clues.")

    if state.get("unexpected_reboot_count", 0):
        suspects["Memory / platform"]["score"] += 1

    ranked = []
    for label, data in suspects.items():
        ranked.append(
            {
                "label": label,
                "score": int(data["score"]),
                "reasons": data["reasons"][:3] or ["No specific evidence pushing this cause higher yet."],
            }
        )
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked


def summarize_event(event: Dict[str, Any]) -> Dict[str, str]:
    event_type = str(event.get("event", "event"))
    ts = str(event.get("ts", ""))
    severity = "info"
    title = event_type.replace("_", " ").title()
    detail = ""

    if event_type == "unexpected_reboot_detected":
        severity = "warn"
        title = "Unexpected reboot detected"
        detail = f"Boot changed after last check at {event.get('last_check_at', 'unknown')}."
    elif event_type == "watchdog_reboot_observed":
        title = "Watchdog reboot observed"
        detail = "A reboot followed a watchdog-issued reboot command."
    elif event_type == "fault_started":
        severity = "danger"
        checks = event.get("checks", {})
        detail = summarize_fault_checks(checks)
        title = "Fault started"
    elif event_type == "recovered":
        title = "Recovered"
        duration = event.get("duration_seconds")
        detail = f"System returned healthy after {duration}s." if duration is not None else "System returned healthy."
    elif event_type == "snapshot":
        title = "Snapshot captured"
        detail = f"{event.get('reason', 'snapshot')} at {event.get('path', '')}"
    elif event_type == "action":
        action = str(event.get("action", "action"))
        rc = event.get("return_code", "")
        title = f"Action: {action}"
        detail = f"Return code {rc}. {str(event.get('detail', ''))[:120]}"
        severity = "warn" if str(rc) not in {"0", ""} else "info"
    elif event_type == "post_action_check":
        title = f"Post-action check: {event.get('action', 'action')}"
        detail = summarize_fault_checks(event.get("checks", {}))
    elif event_type == "heartbeat":
        if event.get("status") == "fault":
            severity = "warn"
            title = "Fault heartbeat"
            detail = f"Fault age {event.get('fault_age_seconds', '?')}s, reboot after {event.get('reboot_after_seconds', '?')}s."
        else:
            title = "Healthy heartbeat"
            detail = "All monitored checks healthy."
    elif event_type == "manual_check":
        title = "Manual check"
        detail = summarize_fault_checks(event.get("checks", {}))
    elif event_type == "hardware_warning_update":
        severity = "warn"
        title = "Hardware warning update"
        warning_count = int(event.get("warning_count", 0))
        detail = f"{warning_count} hardware warning line(s) currently surfaced."
    elif event_type == "reboot_counts_acknowledged":
        title = "Reboot counts acknowledged"
        detail = "Known manual or remote-triggered reboot counts were cleared from the active view."
    elif event_type == "startup":
        title = "Watchdog startup"
        detail = "Site watchdog process started."
    elif event_type == "error":
        severity = "danger"
        title = "Watchdog error"
        detail = str(event.get("detail", ""))

    return {"ts": ts, "title": title, "detail": detail, "severity": severity}


def summarize_fault_checks(checks: Any) -> str:
    if not isinstance(checks, dict) or not checks:
        return "No check details recorded."
    if checks.get("healthy") is True:
        return "All monitored checks healthy."
    if checks.get("app_ok") is False:
        return "App process missing."
    bad_services = [item.get("service") for item in checks.get("services", []) if not item.get("ok")]
    if bad_services:
        return "Service issue: " + ", ".join(str(item) for item in bad_services)
    bad_ports = [f"{item.get('host')}:{item.get('port')}" for item in checks.get("ports", []) if not item.get("ok")]
    if bad_ports:
        return "LAN target issue: " + ", ".join(bad_ports)
    bad_pings = [item.get("host") for item in checks.get("pings", []) if not item.get("ok")]
    if bad_pings:
        return "WAN issue: " + ", ".join(str(item) for item in bad_pings)
    return "A fault was recorded, but no simple summary matched."


def build_incident_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    interesting = []
    for event in events:
        event_type = str(event.get("event", ""))
        if event_type in {"heartbeat"} and event.get("status") != "fault":
            continue
        if event_type == "heartbeat" and event.get("status") == "fault":
            if interesting and interesting[-1].get("title") == "Fault heartbeat":
                continue
        interesting.append(summarize_event(event))
        if len(interesting) >= 12:
            break
    return interesting


def metric_at_or_before(ts_value: str) -> Dict[str, Any]:
    target = parse_iso(ts_value)
    if target is None or not METRICS_PATH.exists():
        return {}
    latest: Dict[str, Any] = {}
    for line in METRICS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = parse_iso(str(item.get("ts", "")))
        if ts is None or ts > target:
            continue
        latest = item
    return latest


def export_dt_string(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc).astimezone()
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def quick_export_window(events: List[Dict[str, Any]], state: Dict[str, Any]) -> Dict[str, Any]:
    startup_at = parse_iso(str(state.get("last_startup_at", "")))
    reboot_event = None
    for event in reversed(events):
        if str(event.get("event", "")) in {"unexpected_reboot_detected", "watchdog_reboot_observed"}:
            reboot_event = event
            break

    reboot_anchor = startup_at
    if reboot_anchor is None and reboot_event is not None:
        reboot_anchor = parse_iso(str(reboot_event.get("ts", "")))
    if reboot_anchor is None:
        return {
            "available": False,
            "message": "No reboot/startup point is available yet for a quick incident export.",
            "since": "",
            "until": "",
            "pre_event_at": "",
            "reboot_at": "",
            "pre_event_title": "",
        }

    last_pre_event = None
    for event in reversed(events):
        event_dt = parse_iso(str(event.get("ts", "")))
        if event_dt is None or event_dt >= reboot_anchor:
            continue
        last_pre_event = event
        break

    pre_event_dt = parse_iso(str((last_pre_event or {}).get("ts", ""))) if last_pre_event else None
    if pre_event_dt is None:
        pre_event_dt = reboot_anchor - timedelta(minutes=5)

    since_dt = pre_event_dt - timedelta(minutes=5)
    until_dt = reboot_anchor + timedelta(minutes=5)
    summary = summarize_event(last_pre_event or {"event": "unknown", "ts": export_dt_string(pre_event_dt)})
    if last_pre_event is None:
        summary = {
            "title": "No pre-reboot event found",
            "detail": "Falling back to five minutes before the startup point.",
        }

    return {
        "available": True,
        "since": export_dt_string(since_dt),
        "until": export_dt_string(until_dt),
        "pre_event_at": export_dt_string(pre_event_dt),
        "reboot_at": export_dt_string(reboot_anchor),
        "pre_event_title": str(summary.get("title", "Last event")),
        "message": f"Captures 5 minutes before {summary.get('title', 'the last event')} and 5 minutes after the reboot/startup point.",
    }


def reboot_leadup_payload(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    reboot_event = None
    for event in events:
        if str(event.get("event", "")) in {"unexpected_reboot_detected", "watchdog_reboot_observed"}:
            reboot_event = event
            break
    if reboot_event is None:
        return {
            "available": False,
            "title": "No reboot lead-up yet",
            "detail": "When a reboot is detected, this section will show the last events and last sampled PC stats before it.",
            "events": [],
            "last_metrics": {},
            "reference_at": "",
        }

    reference_at = str(reboot_event.get("last_check_at") or reboot_event.get("ts") or "")
    reference_dt = parse_iso(reference_at)
    leadup_events: List[Dict[str, str]] = []
    if reference_dt is not None:
        for event in reversed(events):
            ts = parse_iso(str(event.get("ts", "")))
            if ts is None or ts > reference_dt:
                continue
            if (reference_dt - ts).total_seconds() > 30 * 60:
                break
            leadup_events.append(summarize_event(event))
            if len(leadup_events) >= 8:
                break
        leadup_events.reverse()

    metrics = metric_at_or_before(reference_at)
    detail = "Showing the last sampled PC stats and recent events before the reboot-detection point."
    if not metrics:
        detail = "A reboot was detected, but no metric sample was found before the detection point."
    return {
        "available": True,
        "title": "Lead-up to latest reboot",
        "detail": detail,
        "events": leadup_events,
        "last_metrics": metrics,
        "reference_at": reference_at,
    }


def incidents_payload(limit: int = 12) -> List[Dict[str, Any]]:
    statuses = read_incident_export_statuses()
    changed = False
    rows: List[Dict[str, Any]] = []
    for incident in all_incidents()[:limit]:
        incident_id = str(incident.get("incident_id", "")).strip()
        if not incident_id:
            continue
        export_status = normalize_incident_export_status(statuses.get(incident_id, {"state": "idle"}))
        if export_status != statuses.get(incident_id, {"state": "idle"}):
            statuses[incident_id] = export_status
            changed = True
        watchdog_requested = bool(incident.get("watchdog_requested_reboot"))
        classification = str(incident.get("classification", "") or ("watchdog_reboot" if watchdog_requested else "manual_relay_recovery_suspected"))
        snapshot_path = str(incident.get("snapshot_path", "") or "")
        if classification == "manual_relay_recovery_suspected" and snapshot_shows_manual_reboot(snapshot_path):
            classification = "manual_shell_reboot"
            if not incident.get("suspected_reason"):
                incident["suspected_reason"] = "Previous-boot journal shows a shell or system reboot request rather than a watchdog-triggered reboot."
            if not incident.get("reporting_text"):
                incident["reporting_text"] = "A manual reboot command was issued outside the watchdog and the unit restarted cleanly."
        if watchdog_requested or classification == "watchdog_reboot":
            kind_label = "Watchdog reboot"
        elif classification == "manual_shell_reboot":
            kind_label = "Manual reboot detected"
        elif classification == "manual_relay_recovery_suspected":
            kind_label = "Manual/relay recovery suspected"
        else:
            kind_label = "Unexpected reboot"
        checks = dict(incident.get("last_checks") or {})
        rows.append(
            {
                "incident_id": incident_id,
                "incident_time": str(incident.get("incident_time", "")),
                "last_known_healthy_at": str(incident.get("last_known_healthy_at", "")),
                "reboot_detected_at": str(incident.get("reboot_detected_at") or incident.get("ts", "")),
                "suspected_reason": str(incident.get("suspected_reason", "")),
                "reporting_text": str(incident.get("reporting_text", "")),
                "watchdog_requested_reboot": watchdog_requested,
                "kind_label": kind_label,
                "classification": classification,
                "window_since": str(incident.get("window_since", "")),
                "window_until": str(incident.get("window_until", "")),
                "previous_boot_id": str(incident.get("previous_boot_id", "")),
                "current_boot_id": str(incident.get("current_boot_id", "")),
                "snapshot_path": snapshot_path,
                "last_sampled_pc_stats": dict(incident.get("last_sampled_pc_stats") or {}),
                "last_successful_watchdog_check_at": str(incident.get("last_successful_watchdog_check_at", "")),
                "last_wan_ok_at": str(incident.get("last_wan_ok_at", "")),
                "last_lan_ok_at": str(incident.get("last_lan_ok_at", "")),
                "last_app_ok_at": str(incident.get("last_app_ok_at", "")),
                "last_services_ok_at": str(incident.get("last_services_ok_at", "")),
                "last_checks": checks,
                "export_status": export_status,
                "export_console_lines": incident_export_log_excerpt(export_status, 6),
            }
        )
    if changed:
        write_incident_export_statuses(statuses)
    return rows


def crash_review_payload() -> Dict[str, Any]:
    snapshot = latest_previous_boot_snapshot()
    if snapshot is None:
        return {
            "available": False,
            "title": "No previous-boot review yet",
            "detail": "A previous-boot review snapshot will appear here after the next detected reboot.",
            "snapshot_path": "",
            "system_lines": [],
            "system_tail_lines": [],
            "kernel_lines": [],
            "kernel_tail_lines": [],
        }

    system_lines = extract_notable_lines(snapshot / "journal_previous_boot.txt")
    kernel_lines = extract_notable_lines(snapshot / "journal_kernel_previous_boot.txt")
    system_lines_all = extract_all_notable_lines(snapshot / "journal_previous_boot.txt", limit=40)
    kernel_lines_all = extract_all_notable_lines(snapshot / "journal_kernel_previous_boot.txt", limit=40)
    incident = latest_incident() or {}
    anchor_time = parse_iso(
        str(
            incident.get("last_known_healthy_at")
            or incident.get("incident_time")
            or incident.get("window_since")
            or incident.get("reboot_detected_at")
            or ""
        )
    )
    system_near = previous_boot_lines_near(anchor_time, kernel=False, limit=20)
    kernel_near = previous_boot_lines_near(anchor_time, kernel=True, limit=20)
    service_near = service_lines_near(anchor_time, limit=10)
    watchdog_event_lines = watchdog_event_lines_near(anchor_time, limit=10)
    system_tail_lines = list(system_near.get("lines") or [])
    if not system_tail_lines and service_near.get("lines"):
        system_tail_lines = list(service_near.get("lines") or [])
        system_near["mode"] = "service"
    if not system_tail_lines:
        system_tail_lines = extract_tail_lines(snapshot / "journal_previous_boot.txt", limit=20)
    kernel_tail_lines = list(kernel_near.get("lines") or []) or extract_tail_lines(snapshot / "journal_kernel_previous_boot.txt", limit=20)
    detail = "Review the highlighted lines below first."
    if anchor_time is not None:
        detail = f"Review the highlighted lines below first. Pre-crash logs are anchored to {anchor_time.astimezone().strftime('%d/%m/%Y, %H:%M:%S')}."
        if system_near.get("mode") == "gap" or kernel_near.get("mode") == "gap":
            detail += " A large journal gap was detected, so the pre-crash panes show the last 10 lines before logging went quiet."
        elif system_near.get("mode") == "service":
            detail += " No Linux journal lines were found near that point, so the pre-crash system pane is showing previous-boot app/service and network journal lines instead."
        elif service_near.get("mode") == "service-tail":
            detail += " No service or network lines were found close to the incident, so the service pane is showing the latest previous-boot service/network lines instead."
        elif system_near.get("mode") == "window" or kernel_near.get("mode") == "window":
            detail += " No journal lines existed strictly before that point, so the nearest lines within a 10-minute window are shown instead."
        elif system_near.get("mode") == "tail" or kernel_near.get("mode") == "tail":
            detail += " No nearby journal lines were found, so the latest previous-boot lines are shown instead."
    if not system_lines and not kernel_lines:
        detail = "No obvious error lines were extracted automatically. Open the snapshot files for the full previous-boot logs."

    return {
        "available": True,
        "title": "Latest previous-boot review",
        "detail": detail,
        "snapshot_path": str(snapshot),
        "findings": summarize_crash_findings(system_lines, kernel_lines),
        "system_lines": system_lines,
        "system_lines_all": system_lines_all,
        "system_tail_lines": system_tail_lines,
        "service_tail_lines": list(service_near.get("lines") or []),
        "watchdog_event_lines": watchdog_event_lines,
        "kernel_lines": kernel_lines,
        "kernel_lines_all": kernel_lines_all,
        "kernel_tail_lines": kernel_tail_lines,
    }


def normalize_update_status(update_status: Dict[str, Any], build_info: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(update_status or {})
    if status.get("state") != "running":
        return status

    if status.get("mode") == "check":
        started_at = parse_iso(str(status.get("started_at", "")))
        now = datetime.utcnow().astimezone()
        if started_at and (now - started_at).total_seconds() > 120:
            status["state"] = "failed"
            status["finished_at"] = status.get("finished_at") or now_iso()
            status["message"] = "Update check ran too long. Check web-update.log."
            write_json(UPDATE_STATUS_PATH, status)
        return status

    started_at = parse_iso(str(status.get("started_at", "")))
    deployed_at = parse_iso(str(build_info.get("deployed_at", "")))
    now = datetime.utcnow().astimezone()
    current_build = str(build_info.get("git_commit", "unknown") or "unknown")
    from_build = str(status.get("from_build", "") or "")
    to_build = str(status.get("to_build", "") or "")

    if started_at and deployed_at and deployed_at >= started_at:
        status["state"] = "ok"
        status["finished_at"] = status.get("finished_at") or build_info.get("deployed_at", "")
        status["to_build"] = status.get("to_build") or build_info.get("git_commit", "unknown")
        status["message"] = "Update appears to have completed after the web service restarted."
        write_json(UPDATE_STATUS_PATH, status)
        return status

    # If the unit is already on the target/current build, do not leave the UI stuck in "running".
    if started_at and (now - started_at).total_seconds() > 20:
        if current_build != "unknown" and current_build in {from_build, to_build}:
            status["state"] = "ok"
            status["finished_at"] = status.get("finished_at") or now_iso()
            status["to_build"] = to_build or current_build
            status["message"] = "Already on the current build."
            write_json(UPDATE_STATUS_PATH, status)
            return status

    if started_at and (now - started_at).total_seconds() > 300:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Web update stayed in running state too long. Check web-update.log."
        write_json(UPDATE_STATUS_PATH, status)
        return status

    return status


def launch_update_check() -> Dict[str, Any]:
    current = read_json(UPDATE_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Update task already running."}

    build_info = read_json(BUILD_INFO_PATH, {})
    payload = {
        "state": "running",
        "mode": "check",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Checking GitHub for updates.",
        "log_path": str(UPDATE_LOG_PATH),
        "from_build": str(build_info.get("git_commit", "unknown")),
        "to_build": "",
        "update_available": False,
    }
    write_json(UPDATE_STATUS_PATH, payload)
    UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-update-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-update.log')\n"
        "build_info_path = Path('/opt/va-connect-watchdog/build-info.json')\n"
        "repo_hint = ''\n"
        "if build_info_path.exists():\n"
        "    try:\n"
        "        repo_hint = str(json.loads(build_info_path.read_text(encoding='utf-8')).get('source_repo_dir', '') or '')\n"
        "    except Exception:\n"
        "        repo_hint = ''\n"
        "repo_dir_file = Path('/opt/va-connect-watchdog/repo-dir.txt')\n"
        "repo_dir = repo_hint.strip() or (repo_dir_file.read_text(encoding='utf-8').strip() if repo_dir_file.exists() else '/home/vsuser/Desktop/va-connect-watchdog')\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web update check started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    fetch = subprocess.run(['git', '-C', repo_dir, 'fetch', 'origin'], stdout=log, stderr=subprocess.STDOUT, text=True)\n"
        "    local = subprocess.run(['git', '-C', repo_dir, 'rev-parse', 'HEAD'], capture_output=True, text=True)\n"
        "    remote = subprocess.run(['git', '-C', repo_dir, 'rev-parse', 'origin/master'], capture_output=True, text=True)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = 0 if fetch.returncode == 0 and local.returncode == 0 and remote.returncode == 0 else 1\n"
        "payload['from_build'] = local.stdout.strip() or payload.get('from_build', 'unknown')\n"
        "payload['to_build'] = remote.stdout.strip() or payload.get('to_build', 'unknown')\n"
        "payload['update_available'] = bool(payload['to_build'] and payload['from_build'] and payload['to_build'] != payload['from_build'])\n"
        "payload['state'] = 'ok' if payload['return_code'] == 0 else 'failed'\n"
        "payload['message'] = ('Update available.' if payload['update_available'] else 'Already up to date.') if payload['state'] == 'ok' else 'Update check failed. Check web-update.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Update check started.", "status": payload}


def normalize_export_status(export_status: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(export_status or {})
    if status.get("state") != "running":
        return status

    request_id = str(status.get("request_id", "")).strip()
    started_at = parse_iso(str(status.get("started_at", "")))
    now = datetime.utcnow().astimezone()
    lines: List[str] = []
    try:
        lines = EXPORT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        lines = []

    if request_id and lines:
        marker = f"===== Web export started request_id={request_id} "
        finish_marker = f"===== Web export finished request_id={request_id} "
        section_start = None
        finished_line = ""
        for index, line in enumerate(lines):
            if line.startswith(marker):
                section_start = index + 1
            if line.startswith(finish_marker):
                finished_line = line
        if section_start is not None:
            for line in lines[section_start:]:
                if line.startswith("===== Web export started request_id="):
                    break
                if line.startswith("  Folder: "):
                    status["folder"] = line.split(": ", 1)[1]
                if line.startswith("  Archive: "):
                    status["archive"] = line.split(": ", 1)[1]
            if finished_line:
                status["finished_at"] = status.get("finished_at") or now_iso()
                status["return_code"] = 0 if "return_code=0" in finished_line else int(status.get("return_code", 1) or 1)
                status["state"] = "ok" if int(status.get("return_code", 1) or 1) == 0 and status.get("archive") else "failed"
                status["message"] = "Incident export ready." if status["state"] == "ok" else "Incident export failed. Check web-export.log."
                write_json(EXPORT_STATUS_PATH, status)
                return status

    if started_at and (now - started_at).total_seconds() > 30 * 60:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Incident export ran too long or got stuck. Check web-export.log."
        write_json(EXPORT_STATUS_PATH, status)
    return status


def launch_export(since_time: str, until_time: str) -> Dict[str, Any]:
    current = read_json(EXPORT_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Export already running."}
    if not since_time.strip() or not until_time.strip():
        return {"ok": False, "message": "Provide both since and until times."}

    site_label = socket.gethostname()
    request_id = secrets.token_hex(8)
    download_names = export_download_names(
        {
            "site_label": site_label,
            "since": since_time,
            "until": until_time,
        }
    )
    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Incident export requested from web UI.",
        "request_id": request_id,
        "since": since_time,
        "until": until_time,
        "site_label": site_label,
        "export_label": download_names["base"],
        "folder": "",
        "archive": "",
        "log_path": str(EXPORT_LOG_PATH),
        "download_archive_name": download_names["archive"],
        "download_readme_name": download_names["readme"],
        "download_log_name": download_names["log"],
    }
    write_json(EXPORT_STATUS_PATH, payload)
    EXPORT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-export-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-export.log')\n"
        "request_id = " + repr(request_id) + "\n"
        "cmd = ['bash', '/opt/va-connect-watchdog/export_watchdog_incident.sh', '--since', " + repr(since_time) + ", '--until', " + repr(until_time) + "]\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web export started request_id={request_id} {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)\n"
        "    log.write((f'===== Web export finished request_id={request_id} return_code={result.returncode} {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['folder'] = ''\n"
        "payload['archive'] = ''\n"
        "try:\n"
        "    lines = log_path.read_text(encoding='utf-8', errors='ignore').splitlines()\n"
        "except Exception:\n"
        "    lines = []\n"
        "section_start = 0\n"
        "marker = f'===== Web export started request_id={request_id} '\n"
        "for index, line in enumerate(lines):\n"
        "    if line.startswith(marker):\n"
        "        section_start = index + 1\n"
        "for line in lines[section_start:]:\n"
        "    if line.startswith('  Folder: '):\n"
        "        payload['folder'] = line.split(': ', 1)[1]\n"
        "    if line.startswith('  Archive: '):\n"
        "        payload['archive'] = line.split(': ', 1)[1]\n"
        "payload['message'] = 'Incident export ready.' if result.returncode == 0 else 'Incident export failed. Check web-export.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Export started.", "status": payload}


def launch_quick_export() -> Dict[str, Any]:
    state = read_json(STATE_PATH, {})
    window = quick_export_window(all_events(), state)
    if not window.get("available"):
        return {"ok": False, "message": window.get("message", "Quick export window is not available yet.")}
    result = launch_export(str(window.get("since", "")).strip(), str(window.get("until", "")).strip())
    if result.get("ok") and isinstance(result.get("status"), dict):
        result["status"]["quick_window"] = window
        result["message"] = (
            f"Quick incident export started from {window.get('since', 'unknown')} "
            f"to {window.get('until', 'unknown')}."
        )
    return result


def normalize_incident_export_status(status: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(status or {})
    if payload.get("state") != "running":
        return payload
    started_at = parse_iso(str(payload.get("started_at", "")))
    log_path = Path(str(payload.get("log_path", "")).strip()) if payload.get("log_path") else None
    if log_path and log_path.exists():
        try:
            lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            lines = []
        finish_marker = f"===== Incident export finished request_id={payload.get('request_id', '')} "
        for line in lines:
            if line.startswith("  Folder: "):
                payload["folder"] = line.split(": ", 1)[1]
            if line.startswith("  Archive: "):
                payload["archive"] = line.split(": ", 1)[1]
            if line.startswith(finish_marker):
                payload["finished_at"] = payload.get("finished_at") or now_iso()
                payload["return_code"] = 0 if "return_code=0" in line else int(payload.get("return_code", 1) or 1)
                payload["state"] = "ok" if int(payload.get("return_code", 1) or 1) == 0 and payload.get("archive") else "failed"
                payload["message"] = (
                    "Incident pack ready."
                    if payload["state"] == "ok"
                    else "Incident pack failed. Check the incident export log."
                )
                return payload
    if started_at and (datetime.utcnow().astimezone() - started_at).total_seconds() > 30 * 60:
        payload["state"] = "failed"
        payload["finished_at"] = payload.get("finished_at") or now_iso()
        payload["message"] = "Incident pack ran too long or got stuck. Check the incident export log."
    return payload


def incident_export_log_excerpt(status: Dict[str, Any], max_lines: int = 8) -> List[str]:
    log_path = Path(str(status.get("log_path", "")).strip()) if status.get("log_path") else None
    if not log_path or not log_path.exists():
        return []
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    return [line.rstrip() for line in lines if line.strip()][-max_lines:]


def incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    for incident in all_incidents():
        if str(incident.get("incident_id", "")) == incident_id:
            return incident
    return None


def launch_incident_export(incident_id: str) -> Dict[str, Any]:
    incident = incident_by_id(incident_id)
    if incident is None:
        return {"ok": False, "message": "Incident not found."}
    statuses = read_incident_export_statuses()
    current = normalize_incident_export_status(statuses.get(incident_id, {}))
    if current.get("state") == "running":
        return {"ok": False, "message": "This incident pack is already running."}

    request_id = secrets.token_hex(8)
    log_path = Path(f"/var/log/va-connect-site-watchdog/incident-export-{slugify_label(incident_id)}.log")
    names = incident_export_names(incident)
    payload = {
        "incident_id": incident_id,
        "request_id": request_id,
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Generating incident pack for this reboot event.",
        "since": str(incident.get("window_since", "")).strip(),
        "until": str(incident.get("window_until", "")).strip(),
        "log_path": str(log_path),
        "folder": "",
        "archive": "",
        "download_archive_name": names["archive"],
        "download_readme_name": names["readme"],
        "download_log_name": names["log"],
    }
    statuses[incident_id] = payload
    write_incident_export_statuses(statuses)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        f"status_path = Path({repr(str(INCIDENT_EXPORTS_PATH))})\n"
        f"log_path = Path({repr(str(log_path))})\n"
        f"incident_id = {repr(incident_id)}\n"
        f"request_id = {repr(request_id)}\n"
        f"since_time = {repr(payload['since'])}\n"
        f"until_time = {repr(payload['until'])}\n"
        "cmd = ['bash', '/opt/va-connect-watchdog/export_watchdog_incident.sh', '--since', since_time, '--until', until_time]\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Incident export started request_id={request_id} {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)\n"
        "    log.write((f'===== Incident export finished request_id={request_id} return_code={result.returncode} {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "payloads = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload = payloads.get(incident_id, {})\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['folder'] = ''\n"
        "payload['archive'] = ''\n"
        "try:\n"
        "    lines = log_path.read_text(encoding='utf-8', errors='ignore').splitlines()\n"
        "except Exception:\n"
        "    lines = []\n"
        "for line in lines:\n"
        "    if line.startswith('  Folder: '):\n"
        "        payload['folder'] = line.split(': ', 1)[1]\n"
        "    if line.startswith('  Archive: '):\n"
        "        payload['archive'] = line.split(': ', 1)[1]\n"
        "payload['message'] = 'Incident pack ready.' if result.returncode == 0 else 'Incident pack failed. Check the incident export log.'\n"
        "payloads[incident_id] = payload\n"
        "status_path.write_text(json.dumps(payloads, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Incident pack generation started.", "status": payload}


def safe_incident_export_file(incident_id: str, kind: str) -> Optional[Path]:
    statuses = read_incident_export_statuses()
    status = normalize_incident_export_status(statuses.get(incident_id, {}))
    if status != statuses.get(incident_id, {}):
        statuses[incident_id] = status
        write_incident_export_statuses(statuses)
    candidate = ""
    folder = str(status.get("folder", "")).strip()
    archive = str(status.get("archive", "")).strip()
    if kind == "archive":
        candidate = archive or (str(Path(folder).with_suffix(".tar.gz")) if folder else "")
    elif kind == "folder_readme":
        candidate = str(Path(folder) / "README.txt") if folder else ""
    elif kind == "log":
        candidate = str(status.get("log_path", "")).strip()
    if candidate:
        path = Path(candidate)
        if path.exists() and path.is_file():
            return path
    return None


def safe_export_file(kind: str) -> Optional[Path]:
    export_status = normalize_export_status(read_json(EXPORT_STATUS_PATH, {}))
    candidate = ""
    folder = str(export_status.get("folder", "")).strip()
    archive = str(export_status.get("archive", "")).strip()
    if kind == "archive":
        candidate = archive
        if not candidate and folder:
            candidate = str(Path(folder).with_suffix(".tar.gz"))
    elif kind == "log":
        candidate = str(export_status.get("log_path", "")).strip()
    elif kind == "folder_readme":
        if folder:
            candidate = str(Path(folder) / "README.txt")
    if candidate:
        path = Path(candidate)
        if path.exists() and path.is_file():
            return path

    if kind == "archive":
        for root in export_search_roots(export_status):
            if not root.exists():
                continue
            matches = sorted(root.glob("watchdog_incident_export_*.tar.gz"), key=lambda item: item.stat().st_mtime, reverse=True)
            if matches:
                return matches[0]

    if kind == "folder_readme":
        for root in export_search_roots(export_status):
            if not root.exists():
                continue
            matches = sorted(root.glob("watchdog_incident_export_*/README.txt"), key=lambda item: item.stat().st_mtime, reverse=True)
            if matches:
                return matches[0]

    return None


def safe_memtest_file(kind: str) -> Optional[Path]:
    memtest_status = read_json(MEMTEST_STATUS_PATH, {})
    candidate = ""
    if kind == "log":
        candidate = str(memtest_status.get("log_path", "")).strip()
    if not candidate:
        return None
    path = Path(candidate)
    if not path.exists() or not path.is_file():
        return None
    return path


def safe_speedtest_file(kind: str) -> Optional[Path]:
    speedtest_status = read_json(SPEEDTEST_STATUS_PATH, {})
    candidate = ""
    if kind == "log":
        candidate = str(speedtest_status.get("log_path", "")).strip()
    if not candidate:
        return None
    path = Path(candidate)
    if not path.exists() or not path.is_file():
        return None
    return path


def safe_tools_install_file(kind: str) -> Optional[Path]:
    install_status = read_json(TOOLS_INSTALL_STATUS_PATH, {})
    candidate = ""
    if kind == "log":
        candidate = str(install_status.get("log_path", "")).strip()
    if not candidate:
        return None
    path = Path(candidate)
    if not path.exists() or not path.is_file():
        return None
    return path


def normalize_memtest_status(memtest_status: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(memtest_status or {})
    if status.get("state") != "running":
        return status

    started_at = parse_iso(str(status.get("started_at", "")))
    now = datetime.utcnow().astimezone()
    if started_at and (now - started_at).total_seconds() > 6 * 3600:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Memtester ran too long or got stuck. Check web-memtest.log."
        write_json(MEMTEST_STATUS_PATH, status)
    return status


def normalize_speedtest_status(speedtest_status: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(speedtest_status or {})
    if status.get("state") != "running":
        return status

    started_at = parse_iso(str(status.get("started_at", "")))
    now = datetime.utcnow().astimezone()
    if started_at and (now - started_at).total_seconds() > 10 * 60:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Speed test ran too long or got stuck. Check web-speedtest.log."
        write_json(SPEEDTEST_STATUS_PATH, status)
    return status


def normalize_tools_install_status(install_status: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(install_status or {})
    if status.get("state") != "running":
        return status

    started_at = parse_iso(str(status.get("started_at", "")))
    now = datetime.utcnow().astimezone()
    if started_at and (now - started_at).total_seconds() > 30 * 60:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Tool install ran too long or got stuck. Check web-tools-install.log."
        write_json(TOOLS_INSTALL_STATUS_PATH, status)
    return status


def launch_memtest(size_mb: int, loops: int) -> Dict[str, Any]:
    current = read_json(MEMTEST_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Memory test already running."}

    recommendation = memtest_recommendation()
    available_mb = int(recommendation.get("available_mb", 0))
    if not recommendation.get("installed"):
        return {"ok": False, "message": "memtester is not installed on the gateway."}
    if size_mb <= 0 or loops <= 0:
        return {"ok": False, "message": "Provide a positive memory-test size and loop count."}
    if available_mb and size_mb >= available_mb:
        return {"ok": False, "message": f"Requested size is too high for current free RAM ({available_mb} MB available)."}

    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Memory test requested from web UI.",
        "size_mb": int(size_mb),
        "loops": int(loops),
        "log_path": str(MEMTEST_LOG_PATH),
    }
    write_json(MEMTEST_STATUS_PATH, payload)
    MEMTEST_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-memtest-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-memtest.log')\n"
        f"cmd = ['memtester', '{int(size_mb)}M', '{int(loops)}']\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web memtest started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['message'] = 'Memory test completed successfully.' if result.returncode == 0 else 'Memory test failed. Check web-memtest.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Memory test started.", "status": payload}


def launch_speedtest() -> Dict[str, Any]:
    current = read_json(SPEEDTEST_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Speed test already running."}

    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Speed test requested from web UI.",
        "log_path": str(SPEEDTEST_LOG_PATH),
        "download_mbps": None,
        "upload_mbps": None,
        "cpu_percent": None,
        "memory_percent": None,
        "provider": "Cloudflare simple test",
    }
    write_json(SPEEDTEST_STATUS_PATH, payload)
    SPEEDTEST_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, time, urllib.request, urllib.error\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-speedtest-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-speedtest.log')\n"
        "DOWN_URL = 'https://speed.cloudflare.com/__down?bytes=50000000'\n"
        "UP_URL = 'https://speed.cloudflare.com/__up'\n"
        "HEADERS = {'User-Agent': 'Mozilla/5.0 VA-Connect-Watchdog-SpeedTest'}\n"
        "def read_mem_percent():\n"
        "    values = {}\n"
        "    for line in Path('/proc/meminfo').read_text(encoding='utf-8').splitlines():\n"
        "        key, value = line.split(':', 1)\n"
        "        values[key] = int(value.strip().split()[0])\n"
        "    total = values.get('MemTotal', 0)\n"
        "    available = values.get('MemAvailable', values.get('MemFree', 0))\n"
        "    return round(((total - available) / total) * 100.0, 2) if total else 0.0\n"
        "def read_cpu_percent(interval=1.0):\n"
        "    def sample():\n"
        "        parts = [int(v) for v in Path('/proc/stat').read_text(encoding='utf-8').splitlines()[0].split()[1:]]\n"
        "        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)\n"
        "        total = sum(parts)\n"
        "        return total, idle\n"
        "    total1, idle1 = sample()\n"
        "    time.sleep(interval)\n"
        "    total2, idle2 = sample()\n"
        "    total_delta = max(1, total2 - total1)\n"
        "    idle_delta = max(0, idle2 - idle1)\n"
        "    return round((1 - (idle_delta / total_delta)) * 100.0, 2)\n"
        "def run_download():\n"
        "    start = time.time()\n"
        "    downloaded = 0\n"
        "    request = urllib.request.Request(DOWN_URL, headers=HEADERS)\n"
        "    with urllib.request.urlopen(request, timeout=30) as response:\n"
        "        while True:\n"
        "            chunk = response.read(65536)\n"
        "            if not chunk:\n"
        "                break\n"
        "            downloaded += len(chunk)\n"
        "    elapsed = max(0.001, time.time() - start)\n"
        "    return round((downloaded * 8 / 1_000_000) / elapsed, 2)\n"
        "def run_upload():\n"
        "    payload = b'x' * 5_000_000\n"
        "    upload_headers = dict(HEADERS)\n"
        "    upload_headers['Content-Type'] = 'application/octet-stream'\n"
        "    request = urllib.request.Request(UP_URL, data=payload, method='POST', headers=upload_headers)\n"
        "    start = time.time()\n"
        "    with urllib.request.urlopen(request, timeout=30) as response:\n"
        "        response.read()\n"
        "    elapsed = max(0.001, time.time() - start)\n"
        "    return round((len(payload) * 8 / 1_000_000) / elapsed, 2)\n"
        "result = {\n"
        "    'state': 'failed',\n"
        "    'finished_at': datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00',\n"
        "    'message': 'Speed test failed. Check web-speedtest.log.',\n"
        "}\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web speed test started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    try:\n"
        "        download = run_download()\n"
        "        upload = run_upload()\n"
        "        cpu = read_cpu_percent()\n"
        "        memory = read_mem_percent()\n"
        "        log.write((f'Download Mbps: {download}\\nUpload Mbps: {upload}\\nCPU percent: {cpu}\\nMemory percent: {memory}\\n').encode())\n"
        "        result.update({\n"
        "            'state': 'ok',\n"
        "            'message': 'Speed test completed successfully.',\n"
        "            'download_mbps': download,\n"
        "            'upload_mbps': upload,\n"
        "            'cpu_percent': cpu,\n"
        "            'memory_percent': memory,\n"
        "        })\n"
        "    except Exception as exc:\n"
        "        log.write((f'ERROR: {type(exc).__name__}: {exc}\\n').encode())\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload.update(result)\n"
        "payload['return_code'] = 0 if result.get('state') == 'ok' else 1\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "history_path = Path('/var/log/va-connect-site-watchdog/speedtests.jsonl')\n"
        "history_path.parent.mkdir(parents=True, exist_ok=True)\n"
        "with history_path.open('a', encoding='utf-8') as history:\n"
        "    history.write(json.dumps({\n"
        "        'ts': result.get('finished_at', datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'),\n"
        "        'state': result.get('state', 'failed'),\n"
        "        'download_mbps': result.get('download_mbps'),\n"
        "        'upload_mbps': result.get('upload_mbps'),\n"
        "        'cpu_percent': result.get('cpu_percent'),\n"
        "        'memory_percent': result.get('memory_percent'),\n"
        "    }, sort_keys=True) + '\\n')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Speed test started.", "status": payload}


def launch_required_tools_install() -> Dict[str, Any]:
    current = read_json(TOOLS_INSTALL_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Tool install already running."}

    tools_status = required_tools_payload(load_config())
    packages = []
    if "smartmontools package" in tools_status.get("missing_required", []):
        packages.append("smartmontools")
    if "edac-utils package" in tools_status.get("missing_required", []):
        packages.append("edac-utils")
    if not packages:
        return {"ok": False, "message": "All required tools are already installed."}

    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Installing missing required tools from web UI.",
        "log_path": str(TOOLS_INSTALL_LOG_PATH),
        "packages": packages,
    }
    write_json(TOOLS_INSTALL_STATUS_PATH, payload)
    TOOLS_INSTALL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-tools-install-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-tools-install.log')\n"
        f"packages = {packages!r}\n"
        "cmd = ['bash', '-lc', 'export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y ' + ' '.join(packages)]\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web tool install started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    log.write((('Packages: ' + ', '.join(packages) + '\\n').encode()))\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['message'] = 'Required tools installed successfully.' if result.returncode == 0 else 'Tool install failed. Check web-tools-install.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Tool install started.", "status": payload}


def status_payload() -> Dict[str, Any]:
    state = read_json(STATE_PATH, {})
    config = load_config()
    gateway_name = str(config.get("gateway_name", "") or "").strip()
    display_name = gateway_name or "Enter gateway name"
    checks = state.get("last_checks") or {}
    reboot_counts = effective_reboot_counts(state)
    diagnosis = "Healthy"
    diagnosis_detail = "All monitored checks are passing."

    if reboot_counts["unexpected"]:
        diagnosis = "Unexpected reboot seen"
        diagnosis_detail = str(state.get("last_reboot_reason") or "A reboot was detected after startup.")
    if state.get("fault_active"):
        diagnosis = "Active fault"
        if not checks.get("app_ok", True):
            diagnosis_detail = "App process is missing."
        elif not checks.get("services_ok", True):
            bad = [item.get("service") for item in checks.get("services", []) if not item.get("ok")]
            diagnosis_detail = "Service issue: " + ", ".join(bad) if bad else "A monitored service is not active."
        elif not checks.get("lan_ok", True):
            bad = [f"{item.get('host')}:{item.get('port')}" for item in checks.get("ports", []) if not item.get("ok")]
            diagnosis_detail = "LAN target issue: " + ", ".join(bad) if bad else "A monitored TCP target failed."
        elif not checks.get("internet_ok", True):
            bad = [item.get("host") for item in checks.get("pings", []) if not item.get("ok")]
            diagnosis_detail = "WAN issue: " + ", ".join(bad) if bad else "A monitored internet host failed."

    next_steps: List[str] = []
    if state.get("fault_active"):
        next_steps.append("Check Latest checks first to see whether the app, a service, WAN, or the RUT target is currently failing.")
    elif reboot_counts["unexpected"]:
        next_steps.append("Review Recent events for the exact time the unexpected reboot was detected.")
        next_steps.append("Open the latest previous-boot snapshot to inspect journal and kernel messages from before the restart.")
    else:
        next_steps.append("Watch Recent events for the next change in state or reboot detection.")

    hardware_payload = hardware_review_payload(state)
    crash_payload = crash_review_payload()
    suspects_payload = suspect_scores_payload(state, crash_payload, hardware_payload)
    required_tools = required_tools_payload(config)
    required_tools["install_status"] = normalize_tools_install_status(required_tools.get("install_status", {"state": "idle"}))
    if hardware_payload.get("warnings"):
        next_steps.append("Review Hardware warnings for EDAC, storage, or persistent-crash clues that may explain a hard freeze.")
    if required_tools.get("missing_required"):
        next_steps.insert(0, "Install the missing required tools on the Overview page so SMART and EDAC evidence can be collected remotely.")
    next_steps.append("Use PC stats to look for CPU, memory, or disk changes building before a reboot or hang.")
    next_steps.append("If it freezes overnight again, compare the last event time with the next boot's previous-boot snapshot.")

    events = recent_events()
    events_all = all_events()
    summarized_events = []
    for event in events:
        enriched = dict(event)
        enriched["summary"] = summarize_event(event)
        summarized_events.append(enriched)
    build_info = read_json(BUILD_INFO_PATH, {})
    update_status = normalize_update_status(read_json(UPDATE_STATUS_PATH, {"state": "idle"}), build_info)
    export_status = normalize_export_status(read_json(EXPORT_STATUS_PATH, {"state": "idle"}))
    memtest_info = memtest_recommendation()
    memtest_status = normalize_memtest_status(read_json(MEMTEST_STATUS_PATH, {"state": "idle"}))
    speedtest_status = normalize_speedtest_status(read_json(SPEEDTEST_STATUS_PATH, {"state": "idle"}))
    speedtest_history = recent_speedtests()
    reboot_leadup = reboot_leadup_payload(events)
    quick_export = quick_export_window(events_all, state)
    try:
        incidents = incidents_payload()
    except Exception:
        incidents = []
    hik_status = read_json(HIK_STATUS_PATH, {"state": "idle", "enabled": bool(config.get("hik_enabled"))})
    hw_identity = hardware_identity()
    system_profile = system_profile_payload()
    teamviewer = teamviewer_status_payload(config)
    clue_counters = clue_counter_payload(hardware_payload, crash_payload)
    linux_stability = linux_stability_payload(state, hardware_payload, crash_payload)
    fault_reporting = fault_reporting_payload(
        state,
        checks,
        reboot_counts,
        hardware_payload,
        crash_payload,
        suspects_payload,
        teamviewer,
    )
    return {
        "hostname": socket.gethostname(),
        "display_name": display_name,
        "hardware_identity": hw_identity,
        "system_profile": system_profile,
        "config": config,
        "state": state,
        "build_info": build_info,
        "update_status": update_status,
        "export_status": export_status,
        "quick_export": quick_export,
        "incidents": incidents,
        "update_console_lines": latest_log_block(UPDATE_LOG_PATH, "===== Web update started ", 10),
        "export_console_lines": export_log_excerpt(export_status, 10),
        "memtest_status": memtest_status,
        "memtest_info": memtest_info,
        "speedtest_status": speedtest_status,
        "speedtest_history": speedtest_history,
        "reboot_leadup": reboot_leadup,
        "hik_status": hik_status,
        "required_tools": required_tools,
        "reboot_counts": reboot_counts,
        "diagnosis": {"title": diagnosis, "detail": diagnosis_detail},
        "teamviewer": teamviewer,
        "clue_counters": clue_counters,
        "linux_stability": linux_stability,
        "fault_reporting": fault_reporting,
        "next_steps": next_steps,
        "hardware_review": hardware_payload,
        "crash_review": crash_payload,
        "suspect_scores": suspects_payload,
        "recent_events": summarized_events,
        "timeline": build_incident_timeline(events),
        "paths": {
            "config": str(CONFIG_PATH),
            "state": str(STATE_PATH),
            "events": str(EVENTS_PATH),
            "metrics": str(METRICS_PATH),
            "incidents": str(INCIDENTS_PATH),
            "build_info": str(BUILD_INFO_PATH),
            "update_status": str(UPDATE_STATUS_PATH),
            "update_log": str(UPDATE_LOG_PATH),
            "export_status": str(EXPORT_STATUS_PATH),
            "export_log": str(EXPORT_LOG_PATH),
            "incident_export_status": str(INCIDENT_EXPORTS_PATH),
            "memtest_status": str(MEMTEST_STATUS_PATH),
            "memtest_log": str(MEMTEST_LOG_PATH),
            "speedtest_status": str(SPEEDTEST_STATUS_PATH),
            "speedtest_log": str(SPEEDTEST_LOG_PATH),
            "hik_status": str(HIK_STATUS_PATH),
            "tools_install_status": str(TOOLS_INSTALL_STATUS_PATH),
            "tools_install_log": str(TOOLS_INSTALL_LOG_PATH),
        },
    }


def base_status_payload() -> Dict[str, Any]:
    try:
        state = read_json(STATE_PATH, {})
    except Exception:
        state = {}
    try:
        config = load_config()
    except Exception:
        config = {}
    try:
        build_info = read_json(BUILD_INFO_PATH, {})
    except Exception:
        build_info = {}
    try:
        events = recent_events()
    except Exception:
        events = []
    try:
        web_service = service_status_payload("va-connect-watchdog-web.service")
    except Exception:
        web_service = {
            "service": "va-connect-watchdog-web.service",
            "installed": False,
            "active": False,
            "enabled": False,
            "ok": False,
            "detail": "service status unavailable",
        }
    device_id = str((config or {}).get("device_id") or socket.gethostname()).strip()
    if not device_id:
        device_id = socket.gethostname()
    return {
        "device_id": device_id,
        "display_name": str((config or {}).get("gateway_name") or device_id),
        "build": str((build_info or {}).get("git_commit", "unknown")),
        "fault_active": bool((state or {}).get("fault_active")),
        "last_check_at": str((state or {}).get("last_check_at", "")),
        "last_healthy_at": str((state or {}).get("last_healthy_at", "")),
        "monitoring_state": str((state or {}).get("monitoring_state", "unknown")),
        "diagnosis": {
            "title": "Web base ready" if web_service.get("ok") else "Web base starting",
            "detail": "The legacy web UI is up and serving a minimal summary." if web_service.get("ok") else "The legacy web UI is not fully healthy yet.",
        },
        "web_service": web_service,
        "recent_events": [
            {
                "ts": str(item.get("ts", "")),
                "summary": str(item.get("summary", "")),
                "kind": str(item.get("kind", "")),
            }
            for item in events[:10]
        ],
    }


def render_base_page() -> str:
    status = base_status_payload()
    web_service = status.get("web_service") or {}
    status_class = "ok" if web_service.get("ok") else "bad"
    status_text = "running" if web_service.get("ok") else "not ready"
    recent_events = status.get("recent_events") or []
    events_html = "".join(
        f"<li><span class=\"muted\">{html.escape(str(item.get('ts', '')))}</span> {html.escape(str(item.get('summary', '')))}</li>"
        for item in recent_events
    ) or '<li class="muted">No recent events yet.</li>'
    diagnosis = html.escape(str((status.get("diagnosis") or {}).get("detail") or ""))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VA-Connect Gateway</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #0f1419; color: #e8eef5; }}
    .wrap {{ max-width: 900px; margin: 0 auto; padding: 24px; }}
    .card {{ background: #17212b; border: 1px solid #2a3947; border-radius: 12px; padding: 18px; margin-top: 16px; }}
    .title {{ font-size: 28px; font-weight: 700; }}
    .muted {{ color: #9fb0bf; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 12px; }}
    .item {{ background: #0f1720; border: 1px solid #2a3947; border-radius: 10px; padding: 12px; }}
    .label {{ color: #9fb0bf; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    .value {{ margin-top: 6px; font-size: 18px; font-weight: 600; }}
    .ok {{ color: #5ee06d; }}
    .bad {{ color: #ff6b6b; }}
    ul {{ margin: 10px 0 0; padding-left: 18px; }}
    li {{ margin: 0 0 6px; }}
    a {{ color: #7cc7ff; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">VA-Connect Gateway</div>
    <div class="muted">Minimal web base on port 8787</div>
    <div class="card">
      <div class="grid">
        <div class="item"><div class="label">Device</div><div class="value">{html.escape(str(status.get("device_id") or "unknown"))}</div></div>
        <div class="item"><div class="label">Status</div><div class="value {status_class}">{status_text}</div></div>
        <div class="item"><div class="label">Last check</div><div class="value">{html.escape(str(status.get("last_check_at") or "-"))}</div></div>
        <div class="item"><div class="label">Last healthy</div><div class="value">{html.escape(str(status.get("last_healthy_at") or "-"))}</div></div>
      </div>
      <div style="margin-top:12px;">{diagnosis}</div>
    </div>
    <div class="card">
      <div class="label">API</div>
      <div><a href="/api/base-status">/api/base-status</a></div>
    </div>
    <div class="card">
      <div class="label">Recent events</div>
      <ul>{events_html}</ul>
    </div>
  </div>
</body>
</html>"""


def launch_update() -> Dict[str, Any]:
    current = read_json(UPDATE_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Update already running."}

    build_info = read_json(BUILD_INFO_PATH, {})
    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Git update requested from web UI.",
        "log_path": str(UPDATE_LOG_PATH),
        "from_build": str(build_info.get("git_commit", "unknown")),
        "to_build": "",
    }
    write_json(UPDATE_STATUS_PATH, payload)
    UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-update-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-update.log')\n"
        "cmd = ['bash', '/usr/local/bin/watchdog-update']\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web update started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "build_info_path = Path('/opt/va-connect-watchdog/build-info.json')\n"
        "build_info = json.loads(build_info_path.read_text(encoding='utf-8')) if build_info_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['to_build'] = str(build_info.get('git_commit', 'unknown'))\n"
        "payload['message'] = 'Update completed successfully.' if result.returncode == 0 else 'Update failed. Check web-update.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Update started.", "status": payload}


def authorized(path: str, headers) -> bool:
    token = str(load_config().get("web_token", "")).strip()
    if not token:
        return True
    parsed = urlparse(path)
    query_token = parse_qs(parsed.query).get("token", [""])[0]
    header_token = headers.get("X-Watchdog-Token", "")
    return query_token == token or header_token == token


def render_page(status: Dict[str, Any]) -> str:
    cfg = status["config"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VA-Connect Encoder Watchdog</title>
  <style>
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      font-size: 14px;
      line-height: 1.35;
      background:
        radial-gradient(circle at top left, rgba(54, 89, 122, 0.28), transparent 28%),
        radial-gradient(circle at top right, rgba(120, 87, 31, 0.22), transparent 24%),
        linear-gradient(180deg, #0d151c 0%, #111c24 55%, #0b1319 100%);
      color: #e7eef5;
    }}
    .wrap {{ max-width: 1540px; margin: 0 auto; padding: 10px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }}
    .overview-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-top: 10px; }}
    .current-stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }}
    .compact-grid {{
      display: grid;
      grid-template-columns: minmax(340px, 1.1fr) minmax(280px, 0.9fr);
      gap: 14px;
      margin-top: 14px;
    }}
    .summary-list {{
      margin: 8px 0 0;
      padding-left: 18px;
    }}
    .summary-list li {{
      margin: 0 0 6px;
      color: #d5e1ea;
    }}
    .mini-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .operator-note {{
      margin-top: 10px;
      color: #a8bfce;
      font-size: 0.86rem;
    }}
    .counter-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }}
    .counter-chip {{
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(13, 22, 30, 0.8);
    }}
    .counter-chip.hot {{
      border-color: rgba(171, 123, 42, 0.38);
      background: rgba(76, 49, 17, 0.35);
    }}
    .counter-chip .count {{
      font-size: 1.1rem;
      font-weight: 800;
      color: #f0f6fb;
    }}
    .stability-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 10px;
    }}
    .stability-box {{
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 12px;
      padding: 10px;
      background: rgba(13, 22, 30, 0.8);
    }}
    .panel {{
      background: rgba(18, 29, 39, 0.9);
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 16px;
      padding: 10px 11px;
      box-shadow: 0 14px 34px rgba(0, 0, 0, 0.28);
      backdrop-filter: blur(10px);
    }}
    h1 {{ margin: 0 0 6px; font-size: 1.2rem; }}
    h2 {{ margin: 0 0 10px; font-size: 0.95rem; }}
    p {{ margin: 0 0 10px; }}
    .sub {{ color: #8ea5b9; margin-bottom: 12px; font-size: 0.88rem; }}
    .navline {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      margin-bottom: 8px;
      position: sticky;
      top: 0;
      z-index: 60;
      padding: 8px 8px 6px;
      border: 1px solid rgba(122, 150, 176, 0.2);
      border-radius: 12px;
      background: rgba(11, 18, 24, 0.96);
      backdrop-filter: blur(10px);
    }}
    .tabs {{
      display: flex;
      flex-wrap: nowrap;
      align-items: flex-start;
      gap: 6px;
      flex: 1 1 420px;
      min-width: 0;
      overflow-x: auto;
      padding-bottom: 1px;
    }}
    .tab-btn {{
      border: 1px solid rgba(133, 159, 180, 0.3);
      border-bottom-color: rgba(83, 111, 133, 0.6);
      border-radius: 10px 10px 0 0;
      padding: 8px 14px 7px;
      background: rgba(24, 37, 48, 0.95);
      color: #d9e5ef;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
      flex: 0 0 auto;
      margin-top: 0;
      margin-right: 0;
      margin-bottom: -1px;
    }}
    .tab-btn.active {{
      background: rgba(58, 108, 152, 0.98);
      color: #fff;
      border-color: #5d8bb3;
      border-bottom-color: rgba(11, 18, 24, 0.96);
    }}
    .tab-panel {{
      display: none;
    }}
    .tab-panel.active {{
      display: block;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      background: rgba(53, 122, 88, 0.2);
      color: #9be0b1;
      border: 1px solid rgba(97, 168, 123, 0.2);
    }}
    .danger {{ background: rgba(153, 57, 57, 0.22); color: #ffb3b3; border-color: rgba(182, 78, 78, 0.26); }}
    .warn {{ background: rgba(157, 108, 26, 0.22); color: #ffd28a; border-color: rgba(171, 123, 42, 0.28); }}
    label {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 7px 0;
      border-bottom: 1px solid rgba(130, 153, 173, 0.14);
    }}
    label:last-child {{ border-bottom: 0; }}
    button {{
      border: 0;
      border-radius: 12px;
      padding: 8px 11px;
      background: #366a97;
      color: white;
      font-weight: 700;
      cursor: pointer;
      margin-right: 8px;
      margin-top: 8px;
    }}
    button.secondary {{ background: #486458; }}
    button.warnbtn {{ background: #8a6521; }}
    button.status-running {{ background: #8a6521; }}
    button.status-failed {{ background: #7a3434; }}
    button.status-ready {{ background: #486458; }}
    button:disabled {{ opacity: 0.92; cursor: wait; }}
    .targets, .events {{ display: grid; gap: 8px; }}
    .targets {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .item {{
      border: 1px solid rgba(130, 153, 173, 0.15);
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(22, 35, 46, 0.86);
      font-size: 0.83rem;
    }}
    .incident-list {{
      display: grid;
      gap: 6px;
      margin-top: 6px;
    }}
    .incident-list-scroll {{
      max-height: 360px;
      overflow-y: auto;
      padding-right: 4px;
    }}
    .incident-row {{
      border: 1px solid rgba(130, 153, 173, 0.15);
      border-radius: 12px;
      padding: 7px 9px;
      background: rgba(20, 33, 44, 0.88);
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: start;
    }}
    .incident-main {{
      min-width: 0;
    }}
    .incident-head {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 6px;
      align-items: center;
      margin-bottom: 4px;
    }}
    .incident-title {{
      font-weight: 700;
      font-size: 0.88rem;
    }}
    .incident-summary {{
      color: #d8e4ee;
      font-size: 0.84rem;
      margin-bottom: 6px;
    }}
    .incident-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 4px 8px;
      font-size: 0.74rem;
      color: #a9bdce;
    }}
    .incident-meta-chip {{
      border-radius: 10px;
      padding: 4px 7px;
      background: rgba(16, 26, 35, 0.78);
      border: 1px solid rgba(130, 153, 173, 0.12);
    }}
    .incident-meta-chip strong {{
      display: inline-block;
      margin-left: 3px;
    }}
    .incident-meta-incident strong {{ color: #ffd666; }}
    .incident-meta-healthy strong {{ color: #9be0b1; }}
    .incident-meta-detected strong {{ color: #8ec7ff; }}
    .incident-meta-watchdog strong {{ color: #ffcf9b; }}
    .incident-meta-window strong {{ color: #dbe7f4; }}
    .incident-reason {{
      margin-top: 4px;
      font-size: 0.74rem;
      color: #b9cada;
    }}
    .incident-actions {{
      display: flex;
      flex-direction: column;
      gap: 4px;
      align-items: center;
      min-width: 170px;
    }}
    .incident-actions .link-btn {{
      margin-top: 0;
      width: 100%;
      text-align: center;
      box-sizing: border-box;
    }}
    .incident-actions button {{
      width: 100%;
      margin: 0;
      padding: 7px 10px;
      font-size: 0.82rem;
    }}
    .incident-more {{
      margin-top: 8px;
      grid-column: 1 / -1;
    }}
    .incident-more summary {{
      cursor: pointer;
      color: #8ea5b9;
      font-size: 0.8rem;
    }}
    .incident-console {{
      margin-top: 8px;
      max-height: 92px;
      overflow: auto;
      white-space: pre-wrap;
      font-family: Consolas, monospace;
      font-size: 0.72rem;
      line-height: 1.35;
      background: rgba(8, 14, 19, 0.82);
      border: 1px solid rgba(130, 153, 173, 0.12);
      border-radius: 10px;
      padding: 8px;
      color: #b6c7d6;
    }}
    .incident-note-line {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 6px;
      font-size: 0.74rem;
      color: #a9bdce;
    }}
    .audit-grid {{
      display: grid;
      gap: 14px;
      grid-template-columns: 1.25fr 1fr;
    }}
    .audit-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 8px;
    }}
    .audit-list li {{
      border: 1px solid rgba(130, 153, 173, 0.12);
      border-radius: 10px;
      padding: 8px 10px;
      background: rgba(18, 29, 39, 0.76);
      color: #cfe0ee;
    }}
    .audit-paths {{
      max-height: 280px;
      overflow: auto;
    }}
    .audit-paths code {{
      display: block;
      margin-top: 3px;
      font-size: 0.76rem;
      color: #9fb8cf;
      word-break: break-all;
    }}
    .stat-card {{
      border: 1px solid rgba(130, 153, 173, 0.15);
      border-radius: 14px;
      padding: 10px;
      background: rgba(20, 33, 44, 0.88);
    }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(240px, 1.1fr) minmax(180px, 0.9fr);
      gap: 8px;
      margin-top: 8px;
    }}
    .hero-main {{
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 18px;
      padding: 11px 12px;
      background: linear-gradient(135deg, rgba(53, 93, 128, 0.34), rgba(47, 78, 62, 0.22));
    }}
    .hero-title {{ font-size: 1.08rem; font-weight: 800; margin: 2px 0 6px; }}
    .hero-detail {{ font-size: 0.85rem; color: #b8c9d8; }}
    .status-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }}
    .stat-label {{ color: #8da4b8; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-value {{ font-size: 1.18rem; font-weight: 700; margin-top: 3px; }}
    .current-stats-grid .stat-card {{
      padding: 8px 9px;
      border-radius: 12px;
    }}
    .current-stats-grid .stat-label {{
      font-size: 0.64rem;
    }}
    .current-stats-grid .stat-value {{
      font-size: 0.9rem;
      line-height: 1.15;
    }}
    .formgrid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 10px;
      margin-top: 10px;
    }}
    .field {{
      display: grid;
      gap: 6px;
    }}
    .field label {{
      border: 0;
      padding: 0;
      display: block;
      font-weight: 600;
    }}
    input[type="text"], input[type="number"], textarea {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid rgba(129, 154, 175, 0.18);
      border-radius: 10px;
      padding: 8px 10px;
      font: inherit;
      background: rgba(9, 18, 25, 0.88);
      color: #e7eef5;
    }}
    textarea {{ min-height: 84px; resize: vertical; }}
    .hint {{ color: #8ea5b9; font-size: 0.78rem; }}
    code {{ font-family: Consolas, monospace; font-size: 0.78rem; word-break: break-word; }}
    canvas {{
      width: 100%;
      height: 220px;
      border: 1px solid rgba(129, 154, 175, 0.18);
      border-radius: 14px;
      background: rgba(10, 18, 25, 0.92);
    }}
    .chart-hover {{
      min-height: 18px;
      color: #b2c3d1;
      font-size: 0.8rem;
      margin: 0 0 6px;
    }}
    .chart-event-legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      margin: 10px 0 8px;
      color: #90a6b8;
      font-size: 0.76rem;
    }}
    .chart-event-item {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }}
    .chart-event-dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      display: inline-block;
    }}
    .chart-event-dot.temp {{ background: #ff9f6e; }}
    .chart-event-dot.command {{ background: #b06d10; }}
    .chart-event-dot.detected {{ background: #b34747; }}
    .chart-event-dot.note {{ background: #607064; }}
    .chart-toolbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 6px;
      flex-wrap: wrap;
    }}
    .chart-toolbar-main {{
      display: grid;
      gap: 4px;
    }}
    .chart-toolbar-meta {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .range-toggle {{
      display: inline-flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .range-btn {{
      border: 1px solid rgba(129, 154, 175, 0.18);
      background: rgba(17, 28, 37, 0.95);
      color: #dce7ef;
      border-radius: 999px;
      padding: 5px 11px;
      font-size: 0.76rem;
      cursor: pointer;
    }}
    .range-btn.active {{
      background: #3c6f9c;
      border-color: #4d7fad;
      color: #fff;
    }}
    .next-steps {{
      margin: 8px 0 0;
      padding-left: 18px;
      display: grid;
      gap: 8px;
      font-size: 0.88rem;
    }}
    .events .item code {{
      white-space: pre-wrap;
    }}
    .update-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-top: 8px;
    }}
    .review-list {{
      margin: 8px 0 0;
      padding-left: 18px;
      display: grid;
      gap: 6px;
      font-size: 0.85rem;
    }}
    .review-scroll {{
      margin-top: 10px;
      max-height: 180px;
      overflow: auto;
      border: 1px solid rgba(129, 154, 175, 0.18);
      border-radius: 10px;
      background: rgba(18, 29, 39, 0.9);
      padding: 8px 10px;
    }}
    .review-scroll.compact {{
      max-height: 15rem;
    }}
    .crash-review-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 16px;
      align-items: start;
    }}
    .crash-review-column {{
      display: grid;
      gap: 14px;
    }}
    .crash-review-box {{
      border: 1px solid rgba(129, 154, 175, 0.18);
      border-radius: 14px;
      background: rgba(28, 41, 53, 0.62);
      padding: 12px 14px;
    }}
    .crash-review-box strong {{
      display: block;
    }}
    .crash-review-box .hint {{
      margin-top: 6px;
      margin-bottom: 0;
    }}
    @media (max-width: 980px) {{
      .crash-review-grid {{
        grid-template-columns: 1fr;
      }}
    }}
    .timeline {{
      display: grid;
      gap: 8px;
      max-height: 300px;
      overflow: auto;
    }}
    .timeline-card {{
      border: 1px solid rgba(129, 154, 175, 0.14);
      border-left: 4px solid #5c7b66;
      border-radius: 12px;
      padding: 8px 9px;
      background: rgba(20, 33, 44, 0.88);
    }}
    .timeline-card.warn {{ border-left-color: #b47b1f; }}
    .timeline-card.danger {{ border-left-color: #a23d3d; }}
    .timeline-time {{ color: #8ea5b9; font-size: 0.71rem; margin-bottom: 2px; }}
    .timeline-title {{ font-weight: 700; margin-bottom: 3px; }}
    .analysis-grid {{
      display: grid;
      grid-template-columns: minmax(320px, 0.95fr) minmax(420px, 1.35fr);
      gap: 10px;
      align-items: start;
    }}
    .status-grid {{
      display: grid;
      grid-template-columns: minmax(320px, 1fr) minmax(320px, 1fr);
      gap: 10px;
      margin-top: 10px;
    }}
    .overview-top-grid {{
      display: grid;
      grid-template-columns: minmax(340px, 1.1fr) minmax(280px, 0.9fr);
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .overview-main-grid {{
      display: grid;
      grid-template-columns: minmax(340px, 0.95fr) minmax(520px, 1.35fr);
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .overview-bottom-grid {{
      display: grid;
      grid-template-columns: minmax(340px, 0.95fr) minmax(360px, 1.05fr);
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .ops-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(260px, 1fr));
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .bottom-grid {{
      display: grid;
      grid-template-columns: minmax(420px, 1.2fr) minmax(320px, 0.8fr);
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .sidebar-stack {{
      display: grid;
      gap: 14px;
    }}
    .timeline-panel {{
      min-height: 160px;
    }}
    .checks-panel {{
      min-height: 220px;
    }}
    .controls-panel {{
      min-height: 240px;
    }}
    .summary-panel {{
      min-height: 120px;
    }}
    .timeline-empty {{
      color: #8ea5b9;
      font-size: 0.84rem;
      padding: 12px 4px;
    }}
    .compact-metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
      gap: 6px;
      margin-top: 6px;
    }}
    .metric-chip {{
      border: 1px solid rgba(129, 154, 175, 0.14);
      border-radius: 12px;
      padding: 7px 8px;
      background: rgba(20, 33, 44, 0.78);
    }}
    .metric-chip strong {{
      display: block;
      margin-top: 2px;
      font-size: 0.92rem;
      color: #eff6fb;
    }}
    .summary-lines {{
      display: grid;
      gap: 4px;
      margin-top: 6px;
      font-size: 0.81rem;
      color: #d7e2eb;
    }}
    .checks-compact {{
      display: grid;
      gap: 8px;
    }}
    .check-group {{
      border: 1px solid rgba(129, 154, 175, 0.15);
      border-radius: 12px;
      padding: 6px 8px;
      background: rgba(20, 33, 44, 0.84);
    }}
    .check-group summary {{
      cursor: pointer;
      color: #dbe7f0;
      font-weight: 700;
      font-size: 0.83rem;
      list-style: none;
    }}
    .check-group summary::-webkit-details-marker {{
      display: none;
    }}
    .check-list {{
      display: grid;
      gap: 6px;
      margin-top: 6px;
    }}
    .hardware-grid {{
      display: grid;
      grid-template-columns: minmax(280px, 0.95fr) minmax(380px, 1.05fr);
      gap: 10px;
      margin-top: 10px;
      align-items: start;
    }}
    .smart-table {{
      display: grid;
      gap: 8px;
    }}
    .tool-grid {{
      display: grid;
      gap: 8px;
      margin-top: 8px;
    }}
    .tool-card {{
      border: 1px solid rgba(129, 154, 175, 0.15);
      border-radius: 12px;
      padding: 7px 9px;
      background: rgba(20, 33, 44, 0.88);
    }}
    .tool-head {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
    }}
    .tool-title {{
      font-weight: 700;
    }}
    .tool-status.ok {{
      color: #98f5a7;
    }}
    .tool-status.bad {{
      color: #ff9f9f;
    }}
    .tool-why {{
      margin-top: 5px;
      color: #c9d7e2;
      font-size: 0.82rem;
    }}
    .tool-detail {{
      margin-top: 5px;
      color: #8ea5b9;
      font-size: 0.78rem;
      word-break: break-word;
    }}
    .tool-summary {{
      margin-top: 8px;
      color: #c9d7e2;
      font-size: 0.8rem;
    }}
    .tool-expand {{
      margin-top: 8px;
      border-top: 1px solid rgba(129, 154, 175, 0.12);
      padding-top: 6px;
    }}
    .tool-expand summary {{
      color: #8ea5b9;
      font-size: 0.8rem;
      cursor: pointer;
      user-select: none;
    }}
    .console-box {{
      margin-top: 8px;
      padding: 8px 10px;
      border-radius: 12px;
      border: 1px solid rgba(129, 154, 175, 0.14);
      background: rgba(8, 14, 19, 0.92);
      color: #a8c1d6;
      font: 0.73rem/1.35 Consolas, monospace;
      max-height: 120px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .suspect-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }}
    .suspect-card {{
      border: 1px solid rgba(129, 154, 175, 0.15);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(20, 33, 44, 0.88);
    }}
    .suspect-score {{
      font-size: 1.15rem;
      font-weight: 800;
      margin: 4px 0 8px;
    }}
    .mini-form {{
      display: grid;
      grid-template-columns: repeat(2, minmax(160px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }}
    .link-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }}
    .help-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 10px;
      margin-top: 10px;
    }}
    .help-card {{
      border: 1px solid rgba(129, 154, 175, 0.15);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(20, 33, 44, 0.88);
    }}
    .help-card h3 {{
      margin: 0 0 8px;
      font-size: 0.92rem;
    }}
    .help-card p {{
      margin: 0 0 8px;
      color: #c9d7e2;
      font-size: 0.84rem;
    }}
    .link-btn {{
      display: inline-block;
      text-decoration: none;
      border-radius: 10px;
      padding: 7px 10px;
      background: rgba(17, 28, 37, 0.95);
      border: 1px solid rgba(129, 154, 175, 0.18);
      color: #dce7ef;
      font-size: 0.82rem;
      font-weight: 600;
    }}
    .topbar {{
      margin-bottom: 8px;
    }}
    .topbar-main {{
      min-width: 0;
    }}
    .topbar-actions {{
      border: 1px solid rgba(129, 154, 175, 0.16);
      border-radius: 14px;
      padding: 5px 7px;
      background: rgba(14, 23, 31, 0.92);
      flex: 0 1 560px;
      min-width: 280px;
      margin-left: auto;
    }}
    .topbar-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      justify-content: flex-end;
    }}
    .topbar-actions .button-row {{
      margin-top: 0;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      justify-content: flex-end;
      width: 100%;
    }}
    .topbar-actions .button-row #updateMessage {{
      flex: 0 1 210px;
      min-width: 140px;
      font-size: 0.8rem;
      text-align: right;
    }}
    .topbar-actions .hint {{
      margin: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1 1 140px;
      min-width: 0;
      text-align: right;
      font-size: 0.68rem;
    }}
    .topbar-actions .console-box {{
      flex: 1 1 100%;
      margin-top: 0;
      max-height: 84px;
      font-size: 0.7rem;
    }}
    .topbar-actions button {{
      margin-top: 0;
      margin-right: 0;
      padding: 7px 10px;
      font-size: 0.8rem;
    }}
    .topbar-actions button.status-running {{
      background: #8a6521;
      box-shadow: 0 0 0 1px rgba(255, 210, 138, 0.15) inset;
    }}
    .topbar-actions button.status-ready {{
      background: #3f6954;
    }}
    .topbar-actions button.status-failed {{
      background: #7a3434;
    }}
    .update-progress {{
      display: none;
      flex: 1 1 100%;
      height: 8px;
      border-radius: 999px;
      background: rgba(44, 62, 77, 0.7);
      border: 1px solid rgba(129, 154, 175, 0.22);
      overflow: hidden;
    }}
    .update-progress-bar {{
      width: 35%;
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, #5a879f 0%, #7fc9ae 50%, #5a879f 100%);
      background-size: 200% 100%;
      animation: update-progress-slide 1.2s linear infinite;
    }}
    @keyframes update-progress-slide {{
      0% {{ transform: translateX(-10%); background-position: 0% 50%; }}
      100% {{ transform: translateX(190%); background-position: 100% 50%; }}
    }}
    .inline-fields {{
      display: grid;
      grid-template-columns: repeat(2, minmax(120px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }}
    details summary {{
      cursor: pointer;
      color: #8ea5b9;
      font-size: 0.8rem;
      margin-top: 6px;
    }}
    @media (max-width: 1100px) {{
      .hero,
      .analysis-grid,
      .status-grid,
      .ops-grid,
      .bottom-grid,
      .compact-grid,
      .hardware-grid,
      .audit-grid {{
        grid-template-columns: 1fr;
      }}
      .navline {{
        flex-direction: column;
        align-items: stretch;
      }}
      .topbar-actions {{
        min-width: 0;
      }}
    }}
    @media (max-width: 900px) {{
      .navline {{
        display: block;
      }}
      .tabs {{
        width: 100%;
        margin-bottom: 8px;
      }}
      .topbar-actions {{
        width: 100%;
        margin-left: 0;
      }}
      .topbar-strip,
      .topbar-actions .button-row {{
        justify-content: flex-start;
      }}
      .topbar-actions .button-row #updateMessage,
      .topbar-actions .hint {{
        text-align: left;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="topbar-main">
        <h1>VA-Connect Encoder Watchdog</h1>
        <div class="sub">Control page for <strong id="topDisplayName">{html.escape(str(status.get("display_name", "Enter gateway name")))}</strong> | Hardware ID <strong>{html.escape(str(status["hardware_identity"].get("serial", "unknown")))}</strong> | Build <strong id="topBuildCommit">{html.escape(str(status["build_info"].get("git_commit", "unknown")))}</strong></div>
      </div>
    </div>
    <div class="navline">
      <div class="tabs">
        <button type="button" class="tab-btn active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
        <button type="button" class="tab-btn" data-tab="investigation" onclick="switchTab('investigation')">Investigation</button>
        <button type="button" class="tab-btn" data-tab="audit" onclick="switchTab('audit')">Audit</button>
        <button type="button" class="tab-btn" data-tab="remote" onclick="switchTab('remote')">TeamViewer</button>
        <button type="button" class="tab-btn" data-tab="dev" onclick="switchTab('dev')">Dev</button>
        <button type="button" class="tab-btn" data-tab="help" onclick="switchTab('help')">Help</button>
        <button type="button" class="tab-btn" data-tab="config" onclick="switchTab('config')">Config</button>
      </div>
      <section class="topbar-actions">
        <div class="topbar-strip">
          <div class="button-row">
            <button class="secondary" id="updateNowButton" onclick="runAction('update_watchdog')">Update now</button>
            <button class="secondary" onclick="hardRefreshPage()">Hard refresh page</button>
            <span id="updateMessage">{html.escape(str(status["update_status"].get("message", "No web update run yet.")))}</span>
          </div>
          <p class="hint" id="updateMeta">{html.escape(str(status["update_status"].get("from_build", "unknown")))} to {html.escape(str(status["update_status"].get("to_build", "unknown")))} | {html.escape(str(status["update_status"].get("finished_at", "not finished yet")))}</p>
          <div class="update-progress" id="updateProgress"><div class="update-progress-bar"></div></div>
          <div class="console-box" id="updateConsole" style="display:none;">{html.escape(chr(10).join(status.get("update_console_lines", []) or ["No update progress yet."]))}</div>
        </div>
      </section>
    </div>
    <section class="tab-panel active" data-tab-panel="overview">
    <div class="hero">
      <section class="hero-main">
        <div class="stat-label">Current diagnosis</div>
        <div class="hero-title">{html.escape(status["diagnosis"]["title"])}</div>
        <div class="hero-detail">{html.escape(status["diagnosis"]["detail"])}</div>
        <div class="status-strip">
          <span class="badge {'danger' if status['state'].get('fault_active') else ''}">{'Fault active' if status['state'].get('fault_active') else 'Healthy now'}</span>
          <span class="badge {'warn' if status['reboot_counts'].get('unexpected', 0) else ''}">Unexpected reboots: {int(status["reboot_counts"].get("unexpected", 0))}</span>
          <span class="badge">Detected reboots: {int(status["reboot_counts"].get("detected", 0))}</span>
          <span class="badge">Watchdog commands: {int(status["reboot_counts"].get("watchdog", 0))}</span>
        </div>
      </section>
      <section class="panel">
        <div class="stat-label">What to look at next</div>
        <ol class="next-steps" id="nextSteps">
          {"".join(f"<li>{html.escape(step)}</li>" for step in status.get("next_steps", []))}
        </ol>
      </section>
    </div>
    <div class="overview-top-grid">
      <section class="panel summary-panel" id="systemOverviewPanel">
        <h2>System overview</h2>
        <div class="mini-meta">
          <span class="badge {'danger' if status['state'].get('fault_active') else ''}">{'Fault active' if status['state'].get('fault_active') else 'Healthy / idle'}</span>
          <span class="badge">Build {html.escape(str(status["build_info"].get("git_commit", "unknown")))}</span>
        </div>
        <div class="summary-lines">
          <div>Monitoring state: <strong>{html.escape(str(status["state"].get("monitoring_state", "unknown")))}</strong></div>
          <div>Last check: <strong>{html.escape(str(status["state"].get("last_check_at", "never")))}</strong></div>
          <div>Last healthy: <strong>{html.escape(str(status["state"].get("last_healthy_at", "unknown")))}</strong></div>
          <div>Unexpected reboots: <strong>{int(status["reboot_counts"].get("unexpected", 0))}</strong></div>
          <div>Detected reboots: <strong>{int(status["reboot_counts"].get("detected", 0))}</strong></div>
          <div>Last reboot reason: <strong>{html.escape(str(status["state"].get("last_reboot_reason", "none")))}</strong></div>
          <div>Hardware: <strong>{html.escape(str(status["hardware_identity"].get("model", "unknown")))}</strong></div>
          <div>Hardware ID: <strong>{html.escape(str(status["hardware_identity"].get("serial", "unknown")))}</strong></div>
        </div>
      </section>
      <section class="panel summary-panel" id="remoteSummaryPanel">
        <h2>Remote status</h2>
        <div class="mini-meta">
          <span class="badge" id="teamviewerInstalledBadgeMain">{'Installed' if status.get("teamviewer", {}).get("installed") else 'Not installed'}</span>
          <span class="badge {'danger' if not status.get('teamviewer', {}).get('daemon_running') else ''}" id="teamviewerDaemonBadgeMain">{'Daemon running' if status.get("teamviewer", {}).get("daemon_running") else 'Daemon stopped'}</span>
          <span class="badge {'warn' if not status.get('teamviewer', {}).get('gui_running') else ''}" id="teamviewerGuiBadgeMain">{'GUI running' if status.get("teamviewer", {}).get("gui_running") else 'GUI not running'}</span>
        </div>
        <p id="teamviewerSummaryMain">{html.escape(str(status.get("teamviewer", {}).get("summary", "No TeamViewer information available.")))}</p>
        <p class="hint" id="remoteSpeedtestSummary">No web speed test run yet.</p>
      </section>
    </div>
    <section class="panel" style="margin-top:10px;" id="statusOverviewPanel">
      <h2>Status</h2>
      <div class="overview-grid"></div>
    </section>

    <section class="panel" style="margin-top:10px;" id="incidentsPanel">
      <h2>Last unplanned repower</h2>
      <p class="hint">Overview shows the latest outage only. Open Investigation for the full incident history.</p>
      <div class="incident-list" id="incidentsList">
        <div class="timeline-empty">Loading incident history...</div>
      </div>
    </section>

    <div class="compact-grid">
      <section class="panel" id="faultSummaryPanel">
        <h2>Fault summary</h2>
        <div class="mini-meta">
          <span class="badge" id="faultHeadline">{html.escape(str(status.get("fault_reporting", {}).get("headline", "Healthy now")))}</span>
        </div>
        <p><strong id="faultSummaryText">{html.escape(str(status.get("fault_reporting", {}).get("summary", "No summary yet.")))}</strong></p>
        <p id="faultImpactText">{html.escape(str(status.get("fault_reporting", {}).get("impact", "")))}</p>
        <div class="mini-meta">
          <span class="badge" id="faultTopSuspectBadge">{html.escape(str((status.get("fault_reporting", {}).get("top_suspect", {}) or {}).get("label", "No top suspect")))}</span>
          <span class="badge" id="faultTopSuspectScore">Score {int((status.get("fault_reporting", {}).get("top_suspect", {}) or {}).get("score", 0) or 0)}</span>
        </div>
        <div class="counter-strip" id="clueCounterStrip">
          {"".join(f"<div class='counter-chip {'hot' if int(item.get('count', 0) or 0) else ''}'><div class='stat-label'>{html.escape(str(item.get('label', 'Clue')))}</div><div class='count'>{int(item.get('count', 0) or 0)}</div></div>" for item in status.get("clue_counters", []))}
        </div>
        <ul class="summary-list" id="faultQuickActions">
          {"".join(f"<li>{html.escape(item)}</li>" for item in status.get("fault_reporting", {}).get("quick_actions", []))}
        </ul>
      </section>
      <section class="panel" id="linuxCluesPanel">
        <h2>Linux stability clues</h2>
        <p class="hint">This is the simple operator view of the kernel and hardware evidence already collected.</p>
        <ul class="summary-list" id="linuxStabilityClues">
          {"".join(f"<li>{html.escape(item)}</li>" for item in status.get("fault_reporting", {}).get("stability_clues", []))}
        </ul>
      </section>
    </div>

    <section class="panel" style="margin-top:14px;">
      <h2>Required tools</h2>
      <p class="hint">These tools make SMART, EDAC, TeamViewer recovery, and watchdog evidence collection work without shell access.</p>
      <div class="mini-meta">
        <span class="badge {'danger' if status.get('required_tools', {}).get('missing_required') else ''}" id="requiredToolsHeadline">{'Missing required tools' if status.get('required_tools', {}).get('missing_required') else 'Required tools ready'}</span>
        <span class="badge" id="requiredToolsMissingCount">{len(status.get("required_tools", {}).get("missing_important", []))} missing or inactive</span>
      </div>
      <p class="tool-summary" id="requiredToolsSummary">{'Missing: ' + ', '.join(str(item) for item in status.get("required_tools", {}).get("missing_important", [])) if status.get("required_tools", {}).get("missing_important") else 'All key support tools and services look available.'}</p>
      <div class="mini-meta" style="margin-top:10px;" id="toolsInstallRow">
        <button class="secondary" id="installToolsButton" onclick="installRequiredTools()">Install missing tools</button>
        <span class="badge {'warn' if status.get('required_tools', {}).get('install_status', {}).get('state') == 'running' else ('danger' if status.get('required_tools', {}).get('install_status', {}).get('state') == 'failed' else '')}" id="toolsInstallState">{html.escape(str(status.get("required_tools", {}).get("install_status", {}).get("state", "idle")).title())}</span>
        <span id="toolsInstallMessage">{html.escape(str(status.get("required_tools", {}).get("install_status", {}).get("message", "No tool install run yet.")))}</span>
      </div>
      <p class="hint" id="toolsInstallMeta">{html.escape(", ".join(status.get("required_tools", {}).get("install_status", {}).get("packages", []) or []))} {html.escape(str(status.get("required_tools", {}).get("install_status", {}).get("finished_at", "")))}</p>
      <div class="link-row" id="toolsInstallLinks">
        <a class="link-btn" id="toolsInstallLogLink" href="/download/tools-install-log">Download tool install log</a>
      </div>
      <details class="tool-expand">
        <summary>Show tool details</summary>
        <div class="tool-grid" id="requiredToolsGrid">
          {"".join(
            f"<div class='tool-card'><div class='tool-head'><span class='tool-title'>{html.escape(str(item.get('label', 'Tool')))}</span><span class='tool-status {'ok' if item.get('ok') else 'bad'}'>{'Tick Ready' if item.get('ok') else 'Cross Missing'}</span></div><div class='tool-why'>{html.escape(str(item.get('why', '')))}</div><div class='tool-detail'>{html.escape(str(item.get('detail', '')))}</div></div>"
            for item in status.get("required_tools", {}).get("items", [])
          )}
        </div>
      </details>
    </section>

    <div class="analysis-grid" style="margin-top:16px;">
      <section class="panel" style="grid-column: 1 / -1;" id="currentStatsPanel">
        <div class="chart-toolbar">
        <h2>Current PC Stats Live</h2>
          <span class="hint" id="currentStatsAt">Latest sample unknown</span>
        </div>
        <div class="current-stats-grid" id="currentStatsGrid">
          <section class="stat-card"><div class="stat-label">CPU</div><div class="stat-value">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("cpu_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">MemAvailable</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_available_mb", "unknown")))} MB</div></section>
          <section class="stat-card"><div class="stat-label">Cached</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_cached_mb", "unknown")))} MB</div></section>
          <section class="stat-card"><div class="stat-label">Root disk</div><div class="stat-value">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("root_disk_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">Recording disk</div><div class="stat-value">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("recording_disk_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">Temperature</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("temperature_c", "unknown")))} C</div></section>
          <section class="stat-card"><div class="stat-label">Load</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("load_1", "unknown")))}</div></section>
        </div>
      </section>
      <section class="panel timeline-panel">
        <h2>Incident timeline</h2>
        <div class="timeline" id="timeline">
          {"".join(f'<div class="timeline-card {html.escape(item.get("severity", ""))}"><div class="timeline-time">{html.escape(item.get("ts", ""))}</div><div class="timeline-title">{html.escape(item.get("title", ""))}</div><div>{html.escape(item.get("detail", ""))}</div></div>' for item in status.get("timeline", []))}
        </div>
      </section>
      <section class="panel" id="leadupPanel">
        <h2>Lead-up to latest reboot</h2>
        <p class="hint" id="rebootLeadupDetail">{html.escape(str(status.get("reboot_leadup", {}).get("detail", "No reboot lead-up yet.")))}</p>
        <p class="hint" id="rebootLeadupAt">{html.escape(str(status.get("reboot_leadup", {}).get("reference_at", "")))}</p>
        <div class="current-stats-grid" id="rebootLeadupStats">
          <section class="stat-card"><div class="stat-label">CPU</div><div class="stat-value">{html.escape(str((status.get("reboot_leadup", {}).get("last_metrics", {}) or {}).get("cpu_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">{html.escape(str((status.get("reboot_leadup", {}).get("last_metrics", {}) or {}).get("mem_percent", "unknown")))}%</div></section>
          <section class="stat-card"><div class="stat-label">MemAvailable</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("reboot_leadup", {}).get("last_metrics", {}) or {}).get("mem_available_mb", "unknown")))} MB</div></section>
          <section class="stat-card"><div class="stat-label">Temp</div><div class="stat-value" style="font-size:1rem;">{html.escape(str((status.get("reboot_leadup", {}).get("last_metrics", {}) or {}).get("temperature_c", "unknown")))} C</div></section>
        </div>
        <div class="timeline" id="rebootLeadupTimeline" style="margin-top:10px; max-height:220px;">
          {"".join(f'<div class="timeline-card {html.escape(item.get("severity", ""))}"><div class="timeline-time">{html.escape(item.get("ts", ""))}</div><div class="timeline-title">{html.escape(item.get("title", ""))}</div><div>{html.escape(item.get("detail", ""))}</div></div>' for item in status.get("reboot_leadup", {}).get("events", []))}
        </div>
      </section>
      <section class="panel" id="chartPanel">
        <div class="chart-toolbar">
          <div class="chart-toolbar-main">
            <h2 id="metricsTitle">PC Stats - Last 24 Hours</h2>
            <div class="hint" id="metricsTempSummary">Temperature summary unavailable</div>
          </div>
          <div class="chart-toolbar-meta">
            <span class="hint" id="metricsSampleAt">Latest sample unknown</span>
            <div class="range-toggle">
            <button type="button" class="range-btn" id="range1hBtn" onclick="setMetricRange(1)">1 hour</button>
            <button type="button" class="range-btn active" id="range24hBtn" onclick="setMetricRange(24)">24 hours</button>
            <button type="button" class="range-btn" id="range168hBtn" onclick="setMetricRange(168)">7 days</button>
            </div>
          </div>
        </div>
        <div class="chart-hover" id="metricsHover">Move across the graph to inspect time and values.</div>
        <canvas id="metricsChart" width="1000" height="280"></canvas>
        <div class="chart-event-legend">
          <span class="chart-event-item" id="legendTemp"><span class="chart-event-dot temp"></span>Temperature</span>
          <span class="chart-event-item" id="legendGap"><span class="chart-event-dot note"></span>No samples / watchdog offline</span>
          <span class="chart-event-item" id="legendCommand"><span class="chart-event-dot command"></span>Watchdog reboot command (0)</span>
          <span class="chart-event-item" id="legendDetected"><span class="chart-event-dot detected"></span>Detected or unexpected reboot (0)</span>
          <span class="chart-event-item" id="legendNote"><span class="chart-event-dot note"></span>Reboot counts acknowledged (0)</span>
        </div>
        <p class="hint">CPU, memory, root disk, recording disk, and temperature are plotted together. Gaps stay blank when the watchdog was not sampling. Hover also shows MemAvailable and temperature when available.</p>
      </section>
    </div>

    <div class="ops-grid" id="overviewOpsGrid">
      <section class="panel controls-panel" id="speedtestPanel">
        <h2>Speed test</h2>
        <button class="secondary" onclick="runSpeedtest()">Run speed test</button>
        <div class="update-row">
          <span class="badge {'warn' if status['speedtest_status'].get('state') == 'running' else ('danger' if status['speedtest_status'].get('state') == 'failed' else '')}" id="speedtestState">{html.escape(str(status["speedtest_status"].get("state", "idle")).title())}</span>
          <span id="speedtestMessage">{html.escape(str(status["speedtest_status"].get("message", "No web speed test run yet.")))}</span>
        </div>
        <p class="hint" id="speedtestMeta">
          Download {html.escape(str(status["speedtest_status"].get("download_mbps", "unknown")))} Mbps |
          Upload {html.escape(str(status["speedtest_status"].get("upload_mbps", "unknown")))} Mbps |
          {html.escape(str(status["speedtest_status"].get("finished_at", "not finished yet")))}
        </p>
        <div class="link-row">
          <a class="link-btn" id="speedtestLogLink" href="/download/speedtest-log">Download speed test log</a>
        </div>
        <div class="review-scroll" style="margin-top:10px;">
          <ul class="review-list" id="speedtestHistory">
            {"".join(f"<li>{html.escape(str(item.get('ts', 'unknown')))} | {html.escape(str(item.get('state', 'unknown')))} | Down {html.escape(str(item.get('download_mbps', 'n/a')))} Mbps | Up {html.escape(str(item.get('upload_mbps', 'n/a')))} Mbps</li>" for item in status.get("speedtest_history", []))}
          </ul>
        </div>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="investigation">
    <div class="grid" style="margin-top:16px;">
      <div class="compact-grid" id="investigationIntroPanels" style="grid-column: 1 / -1;"></div>
      <div class="bottom-grid" id="investigationActionPanels" style="grid-column: 1 / -1;"></div>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Detected crashes</h2>
        <p class="hint">Newest first. The latest three incidents stay visible before the list scrolls. Use the buttons on the right to generate or download that specific incident pack.</p>
        <div class="incident-list incident-list-scroll" id="incidentsInvestigationList">
          <div class="timeline-empty">Loading incident history...</div>
        </div>
      </section>
      <section class="panel controls-panel" id="controlsPanel" style="grid-column: 1 / -1;">
        <h2>Controls</h2>
        <label>Monitoring enabled <input type="checkbox" id="monitoring_enabled" {'checked' if cfg['monitoring_enabled'] else ''}></label>
        <label>App auto-restart <input type="checkbox" id="app_restart_enabled" {'checked' if cfg['app_restart_enabled'] else ''}></label>
        <label>Network restart before reboot <input type="checkbox" id="restart_network_before_reboot" {'checked' if cfg['restart_network_before_reboot'] else ''}></label>
        <label>Reboot allowed <input type="checkbox" id="reboot_enabled" {'checked' if cfg['reboot_enabled'] else ''}></label>
        <button onclick="saveSettings()">Save settings</button>
        <button class="secondary" onclick="runAction('ack_reboots')">Acknowledge reboot counts</button>
        <button class="secondary" onclick="runAction('run_checks')">Run checks now</button>
        <button class="secondary" onclick="runAction('snapshot')">Capture snapshot</button>
        <button class="warnbtn" onclick="runAction('restart_network')">Restart network</button>
        <button class="secondary" id="quickExportButton" onclick="quickExportIncident()">Quick incident export</button>
        <p class="hint" id="quickExportMeta">{html.escape(str(status.get("quick_export", {}).get("message", "Quick export will appear when a reboot/startup point is available.")))}</p>
        <p class="hint" id="exportMeta">{html.escape(str(status["export_status"].get("message", "No incident export run yet.")))}</p>
        <div class="console-box" id="exportConsole">{html.escape(chr(10).join(status.get("export_console_lines", []) or ["No export progress yet."]))}</div>
        <div class="link-row">
          <a class="link-btn" id="exportArchiveLink" href="/download/export-archive">Download export archive</a>
          <a class="link-btn" id="exportReadmeLink" href="/download/export-readme">Download export README</a>
          <a class="link-btn" id="exportLogLink" href="/download/export-log">Download export log</a>
        </div>
      </section>
      <section class="panel checks-panel" id="latestChecksPanel" style="grid-column: 1 / -1;">
        <h2>Latest checks</h2>
        <div class="targets" id="targets"></div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Likely causes</h2>
        <p class="hint">Higher scores mean the current evidence points more strongly in that direction. This is only a guide, not proof.</p>
        <div class="suspect-grid" id="suspectScores">
          {"".join(f"<div class='suspect-card'><div class='stat-label'>{html.escape(item['label'])}</div><div class='suspect-score'>{int(item['score'])}</div><ul class='review-list'>{''.join(f'<li>{html.escape(reason)}</li>' for reason in item.get('reasons', []))}</ul></div>" for item in status.get("suspect_scores", []))}
        </div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Hardware warnings</h2>
        <p><strong>Last checked:</strong> <span id="hardwareCheckedAt">{html.escape(str(status["hardware_review"].get("checked_at", "unknown")))}</span></p>
        <div class="hardware-grid">
          <section class="item">
            <strong>Hardware and BIOS</strong>
            <ul class="review-list" id="hardwareIdentitySummary">
              <li><strong>Vendor:</strong> {html.escape(str(status["hardware_identity"].get("vendor", "unknown")))}</li>
              <li><strong>Model:</strong> {html.escape(str(status["hardware_identity"].get("model", "unknown")))}</li>
              <li><strong>Serial:</strong> {html.escape(str(status["hardware_identity"].get("serial", "unknown")))}</li>
              <li><strong>Board:</strong> {html.escape(str(status["hardware_identity"].get("board_name", "unknown")))}</li>
              <li><strong>BIOS:</strong> {html.escape(str(status["hardware_identity"].get("bios_vendor", "unknown")))} {html.escape(str(status["hardware_identity"].get("bios_version", "unknown")))}</li>
              <li><strong>BIOS date:</strong> {html.escape(str(status["hardware_identity"].get("bios_date", "unknown")))}</li>
            </ul>
          </section>
          <section class="item">
            <strong>Current memory and temperature</strong>
            <ul class="review-list" id="memoryThermalSummary">
              <li><strong>Memory used:</strong> {html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_percent", "unknown")))}%</li>
              <li><strong>MemAvailable:</strong> {html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_available_mb", "unknown")))} MB</li>
              <li><strong>Cached:</strong> {html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("mem_cached_mb", "unknown")))} MB</li>
              <li><strong>Temperature:</strong> {html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("temperature_c", "unknown")))} C</li>
            </ul>
          </section>
        </div>
        <ul class="review-list" id="hardwareFindings">
          {"".join(f"<li>{html.escape(line)}</li>" for line in status["hardware_review"].get("findings", []))}
        </ul>
        <div class="hardware-grid">
          <section class="item">
            <strong>Detected warning lines</strong>
            <ul class="review-list" id="hardwareWarnings">
              {"".join(f"<li>{html.escape(line)}</li>" for line in status["hardware_review"].get("warnings", []))}
            </ul>
          </section>
          <section class="item">
            <strong>Disk and crash-store overview</strong>
            <div class="smart-table" id="hardwareSmart">
              {"".join(f"<div><strong>{html.escape(str(item.get('device', 'disk')))}</strong><br><code>{html.escape(str(item.get('summary', '')))}</code></div>" for item in status["hardware_review"].get("smart", []))}
            </div>
            <p style="margin-top:10px;"><strong>pstore entries</strong></p>
            <ul class="review-list" id="hardwarePstore">
              {"".join(f"<li>{html.escape(line)}</li>" for line in status["hardware_review"].get("pstore_entries", []))}
            </ul>
            <p style="margin-top:10px;"><strong>Online memory test</strong></p>
            <p class="hint" id="memtestHint">
              memtester {'is installed' if status["memtest_info"].get("installed") else 'is not installed'}.
              Free RAM: {int(status["memtest_info"].get("available_mb", 0))} MB.
              Suggested test: {html.escape(str(status["memtest_info"].get("recommended_label", "1024M")))} x {int(status["memtest_info"].get("recommended_loops", 2))}.
            </p>
            <div class="inline-fields">
              <div class="field">
                <label for="memtest_size_mb">Mem test MB</label>
                <input id="memtest_size_mb" type="number" min="128" value="{int(status['memtest_info'].get('recommended_mb', 1024))}">
              </div>
              <div class="field">
                <label for="memtest_loops">Loops</label>
                <input id="memtest_loops" type="number" min="1" value="{int(status['memtest_info'].get('recommended_loops', 2))}">
              </div>
            </div>
            <button class="secondary" onclick="runMemtest()">Run online mem test</button>
            <div class="update-row">
              <span class="badge {'warn' if status['memtest_status'].get('state') == 'running' else ('danger' if status['memtest_status'].get('state') == 'failed' else '')}" id="memtestState">{html.escape(str(status["memtest_status"].get("state", "idle")).title())}</span>
              <span id="memtestMessage">{html.escape(str(status["memtest_status"].get("message", "No web memory test run yet.")))}</span>
            </div>
            <p class="hint" id="memtestMeta">{html.escape(str(status["memtest_status"].get("finished_at", "not finished yet")))}</p>
            <div class="link-row">
              <a class="link-btn" id="memtestLogLink" href="/download/memtest-log">Download memtest log</a>
            </div>
          </section>
        </div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Crash review</h2>
        <p><strong id="crashReviewTitle">{html.escape(status["crash_review"]["title"])}</strong></p>
        <p id="crashReviewDetail">{html.escape(status["crash_review"]["detail"])}</p>
        <p><code id="crashReviewPath">{html.escape(status["crash_review"]["snapshot_path"])}</code></p>
        <ul class="review-list" id="crashReviewFindings">
          {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("findings", []))}
        </ul>
        <div class="crash-review-grid">
          <div class="crash-review-column">
            <section class="crash-review-box">
              <strong>Pre-crash system log</strong>
              <p class="hint">Last 20 lines before the incident time. Scroll for the full tail.</p>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewSystemAll">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("system_tail_lines", []))}
                </ul>
              </div>
            </section>
            <section class="crash-review-box">
              <strong>Pre-crash kernel log</strong>
              <p class="hint">Last 20 kernel lines before the incident time. Scroll for the full tail.</p>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewKernelAll">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("kernel_tail_lines", []))}
                </ul>
              </div>
            </section>
            <section class="crash-review-box">
              <strong>Pre-crash service/network log</strong>
              <p class="hint">Recent `esg`, `bridge`, `sysops`, and network-service journal lines before the incident time.</p>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewServiceAll">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("service_tail_lines", []))}
                </ul>
              </div>
            </section>
            <section class="crash-review-box">
              <strong>Watchdog/events before incident</strong>
              <p class="hint">Recent watchdog event log entries leading into the incident.</p>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewEventsAll">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("watchdog_event_lines", []))}
                </ul>
              </div>
            </section>
          </div>
          <div class="crash-review-column">
            <section class="crash-review-box">
              <strong>Previous boot system log highlights</strong>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewSystem">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("system_lines", []))}
                </ul>
              </div>
            </section>
            <section class="crash-review-box">
              <strong>Previous boot kernel log highlights</strong>
              <div class="review-scroll compact">
                <ul class="review-list" id="crashReviewKernel">
                  {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("kernel_lines", []))}
                </ul>
              </div>
            </section>
          </div>
        </div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Linux stability</h2>
        <p class="hint">Focused view for NIC flaps, igc resets, PCIe detach clues, and EDAC or memory-controller messages.</p>
        <div class="stability-grid">
          <section class="stability-box">
            <strong>Previous boot</strong>
            <ul class="review-list" id="linuxPreviousCounts">
              <li>Link flaps: {int((status.get("linux_stability", {}).get("previous_boot_counts", {}) or {}).get("link_flaps", 0) or 0)}</li>
              <li>igc/reset clues: {int((status.get("linux_stability", {}).get("previous_boot_counts", {}) or {}).get("igc_errors", 0) or 0)}</li>
              <li>PCIe clues: {int((status.get("linux_stability", {}).get("previous_boot_counts", {}) or {}).get("pcie_events", 0) or 0)}</li>
              <li>EDAC/memory clues: {int((status.get("linux_stability", {}).get("previous_boot_counts", {}) or {}).get("memory_events", 0) or 0)}</li>
            </ul>
            <p><strong>Most suspicious previous-boot line</strong></p>
            <p id="linuxPreviousLine"><code>{html.escape(str(status.get("linux_stability", {}).get("strongest_previous_line", "No highlighted previous-boot line yet.")))}</code></p>
          </section>
          <section class="stability-box">
            <strong>Current warnings</strong>
            <ul class="review-list" id="linuxCurrentCounts">
              <li>Link flaps: {int((status.get("linux_stability", {}).get("current_warning_counts", {}) or {}).get("link_flaps", 0) or 0)}</li>
              <li>igc/reset clues: {int((status.get("linux_stability", {}).get("current_warning_counts", {}) or {}).get("igc_errors", 0) or 0)}</li>
              <li>PCIe clues: {int((status.get("linux_stability", {}).get("current_warning_counts", {}) or {}).get("pcie_events", 0) or 0)}</li>
              <li>EDAC/memory clues: {int((status.get("linux_stability", {}).get("current_warning_counts", {}) or {}).get("memory_events", 0) or 0)}</li>
            </ul>
            <p><strong>Most suspicious current-warning line</strong></p>
            <p id="linuxCurrentLine"><code>{html.escape(str(status.get("linux_stability", {}).get("strongest_current_line", "No highlighted current-warning line yet.")))}</code></p>
          </section>
        </div>
        <div class="grid" style="margin-top:10px;">
          <section class="item">
            <strong>How to read this</strong>
            <ul class="review-list" id="linuxInterpretation">
              {"".join(f"<li>{html.escape(line)}</li>" for line in status.get("linux_stability", {}).get("interpretation", []))}
            </ul>
          </section>
          <section class="item">
            <strong>Alert rules</strong>
            <ul class="review-list" id="linuxAlertRules">
              {"".join(f"<li><strong>{html.escape(str(item.get('label', 'Rule')))}:</strong> {html.escape(str(item.get('threshold', '')))} - {html.escape(str(item.get('meaning', '')))}</li>" for item in status.get("linux_stability", {}).get("alert_rules", []))}
            </ul>
          </section>
        </div>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="audit">
    <div class="audit-grid" style="margin-top:16px;">
      <section class="panel" style="grid-column: 1 / -1;">
        <div class="chart-toolbar">
          <div class="chart-toolbar-main">
            <h2>PC audit and fault-finding export</h2>
            <div class="hint">Hardware identity, build, storage, thermal, watchdog evidence, and useful logs in one operator export.</div>
          </div>
          <div class="chart-toolbar-meta">
            <a class="link-btn" id="auditDownloadLink" href="/download/audit-report">Download audit export</a>
          </div>
        </div>
        <div class="mini-meta" style="margin-top:8px;">
          <span class="badge" id="auditBuildBadge">Build {html.escape(str(status["build_info"].get("git_commit", "unknown")))}</span>
          <span class="badge" id="auditToolsBadge">{len(status.get("required_tools", {}).get("missing_important", []))} tools missing</span>
          <span class="badge" id="auditDiskBadge">Root disk {html.escape(str((status.get("state", {}).get("last_metrics") or {}).get("root_disk_percent", "unknown")))}%</span>
        </div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Audit summary</h2>
        <p><strong>Last checked:</strong> <span id="auditCheckedAt">{html.escape(str(status["hardware_review"].get("checked_at", "unknown")))}</span></p>
        <div class="hardware-grid">
          <section class="item">
            <strong>Hardware and BIOS</strong>
            <ul class="review-list" id="auditHardwareIdentity">
              <li>Loading hardware identity...</li>
            </ul>
          </section>
          <section class="item">
            <strong>Current memory and temperature</strong>
            <ul class="review-list" id="auditMemoryThermal">
              <li>Loading memory and thermal summary...</li>
            </ul>
          </section>
        </div>
        <ul class="review-list" id="auditFindings">
          <li>Loading audit findings...</li>
        </ul>
        <div class="hardware-grid">
          <section class="item">
            <strong>Detected warning lines</strong>
            <ul class="review-list" id="auditWarnings">
              <li>Loading warning lines...</li>
            </ul>
          </section>
          <section class="item">
            <strong>Disk and crash-store overview</strong>
            <div class="smart-table" id="auditSmart">
              <div><strong>Storage</strong><br><code>Loading SMART summary...</code></div>
            </div>
            <p style="margin-top:10px;"><strong>pstore entries</strong></p>
            <ul class="review-list" id="auditPstore">
              <li>Loading pstore entries...</li>
            </ul>
          </section>
        </div>
        <div class="hardware-grid" style="margin-top:10px;">
          <section class="item">
            <strong>Kernel and NIC details</strong>
            <ul class="review-list" id="auditKernelNic">
              <li>Loading kernel and NIC details...</li>
            </ul>
          </section>
          <section class="item">
            <strong>Drive inventory</strong>
            <ul class="review-list" id="auditDriveInventory">
              <li>Loading drive inventory...</li>
            </ul>
          </section>
        </div>
      </section>
      <section class="panel">
        <h2>Operational highlights</h2>
        <ul class="audit-list" id="auditHighlights">
          <li>Generating operational highlights...</li>
        </ul>
      </section>
      <section class="panel">
        <h2>Important paths</h2>
        <div class="audit-paths">
          <ul class="audit-list" id="auditPathsList">
            <li>Generating path summary...</li>
          </ul>
        </div>
      </section>
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Audit notes</h2>
        <ul class="summary-list" id="auditNotes">
          <li>Latest sample and watchdog evidence will appear here after page load.</li>
        </ul>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="remote">
    <div class="grid" style="margin-top:16px;" id="remotePanels">
      <section class="panel" id="teamviewerPanel">
        <h2>TeamViewer</h2>
        <div class="mini-meta">
          <span class="badge" id="teamviewerInstalledBadge">{'Installed' if status.get("teamviewer", {}).get("installed") else 'Not installed'}</span>
          <span class="badge {'danger' if not status.get('teamviewer', {}).get('daemon_running') else ''}" id="teamviewerDaemonBadge">{'Daemon running' if status.get("teamviewer", {}).get("daemon_running") else 'Daemon stopped'}</span>
          <span class="badge {'warn' if not status.get('teamviewer', {}).get('gui_running') else ''}" id="teamviewerGuiBadge">{'GUI running' if status.get("teamviewer", {}).get("gui_running") else 'GUI not running'}</span>
        </div>
        <p id="teamviewerSummary">{html.escape(str(status.get("teamviewer", {}).get("summary", "No TeamViewer information available.")))}</p>
        <p><strong>ID:</strong> <span id="teamviewerId">{html.escape(str(status.get("teamviewer", {}).get("id", "unknown")))}</span></p>
        <p><strong>Version:</strong> <span id="teamviewerVersion">{html.escape(str(status.get("teamviewer", {}).get("version", "unknown")))}</span></p>
        <p><strong>Status:</strong> <span id="teamviewerStatus">{html.escape(str(status.get("teamviewer", {}).get("status_text", "unknown")))}</span></p>
        <div class="field">
          <label for="teamviewerManualPassword">TeamViewer password</label>
          <input id="teamviewerManualPassword" type="text" placeholder="Enter password or leave blank to generate">
        </div>
        <div class="mini-meta">
          <button class="secondary" id="teamviewerSetButton" onclick="setTeamviewerPassword()">Set password</button>
          <button class="secondary" id="teamviewerStartButton" onclick="runAction('start_teamviewer')">Start TeamViewer</button>
          <button class="secondary" id="teamviewerRestartButton" onclick="runAction('restart_teamviewer')">Restart TeamViewer</button>
          <button class="secondary" id="teamviewerResetButton" onclick="runAction('reset_teamviewer_password')">Reset TeamViewer password</button>
        </div>
        <p class="operator-note" id="teamviewerResetResult">Password reset generates a new one-time password on the unit and shows it here.</p>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="dev">
    <div class="bottom-grid">
      <section class="panel">
        <h2>Dev</h2>
        <p class="hint">Use this tab to test new integrations before they graduate into the operator view.</p>
        <div class="formgrid">
          <div class="field">
            <label>Hik enabled</label>
            <input id="hik_enabled" type="checkbox" {'checked' if cfg.get('hik_enabled') else ''}>
          </div>
          <div class="field">
            <label for="hik_scheme">Hik scheme</label>
            <input id="hik_scheme" type="text" value="{html.escape(str(cfg.get("hik_scheme", "http")))}">
          </div>
          <div class="field">
            <label for="hik_host">Hik host</label>
            <input id="hik_host" type="text" value="{html.escape(str(cfg.get("hik_host", "")))}">
          </div>
          <div class="field">
            <label for="hik_username">Hik username</label>
            <input id="hik_username" type="text" value="{html.escape(str(cfg.get("hik_username", "")))}">
          </div>
          <div class="field">
            <label for="hik_password">Hik password</label>
            <input id="hik_password" type="text" value="{html.escape(str(cfg.get("hik_password", "")))}">
          </div>
          <div class="field">
            <label for="hik_channel">Hik channel</label>
            <input id="hik_channel" type="number" min="1" value="{int(cfg.get("hik_channel", 1))}">
          </div>
          <div class="field">
            <label for="hik_people_count_result_path">Result path</label>
            <input id="hik_people_count_result_path" type="text" value="{html.escape(str(cfg.get("hik_people_count_result_path", "/ISAPI/Intelligent/channels/{{channel}}/framesPeopleCounting/result")))}">
          </div>
          <div class="field">
            <label for="hik_people_count_capabilities_path">Capabilities path</label>
            <input id="hik_people_count_capabilities_path" type="text" value="{html.escape(str(cfg.get("hik_people_count_capabilities_path", "/ISAPI/Intelligent/channels/{{channel}}/framesPeopleCounting/capabilities")))}">
          </div>
        </div>
        <button class="secondary" onclick="saveHikConfig()">Save Hik settings</button>
        <button class="secondary" id="hikProbeButton" onclick="runHikProbe()">Probe Hik people count</button>
        <a class="link-btn" href="/run-hik-probe" style="margin-left:6px;">Probe fallback</a>
        <div class="console-box" id="hikProbeConsole">{html.escape(hik_console_text(status.get("hik_status", {})))}</div>
        <p style="margin-top:12px;"><strong>Saved Hik settings</strong></p>
        <ul class="review-list" id="hikSavedSettings">
          <li>Enabled: {html.escape(str(bool(cfg.get("hik_enabled"))))}</li>
          <li>Scheme: {html.escape(str(cfg.get("hik_scheme", "http")))}</li>
          <li>Host: {html.escape(str(cfg.get("hik_host", "")))}</li>
          <li>Username: {html.escape(str(cfg.get("hik_username", "")))}</li>
          <li>Password: {'set' if str(cfg.get('hik_password', '')).strip() else 'empty'}</li>
          <li>Channel: {int(cfg.get("hik_channel", 1) or 1)}</li>
          <li>Result path: {html.escape(str(cfg.get("hik_people_count_result_path", "")))}</li>
          <li>Capabilities path: {html.escape(str(cfg.get("hik_people_count_capabilities_path", "")))}</li>
        </ul>
        <div class="update-row">
          <span class="badge {'warn' if status.get('hik_status', {}).get('state') == 'idle' else ('danger' if status.get('hik_status', {}).get('state') == 'failed' else '')}" id="hikState">{html.escape(str(status.get("hik_status", {}).get("state", "idle")).title())}</span>
          <span id="hikMessage">{html.escape(str(status.get("hik_status", {}).get("message", "No Hik probe run yet.")))}</span>
        </div>
        <p class="hint" id="hikMeta">{html.escape(str(status.get("hik_status", {}).get("checked_at", "")))}</p>
        <ul class="review-list" id="hikCounts">
          {"".join(f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>" for key, value in (status.get('hik_status', {}).get('parsed_counts', {}) or {}).items())}
        </ul>
      </section>
      <section class="panel">
        <h2>Hik Raw</h2>
        <p><strong>Probe console</strong></p>
        <div class="console-box" id="hikProbeConsoleRaw" style="min-height:96px;">{html.escape(hik_console_text(status.get("hik_status", {})))}</div>
        <p><strong>Capabilities</strong></p>
        <div class="review-scroll"><code id="hikCapabilitiesRaw">{html.escape(str(status.get("hik_status", {}).get("capabilities_excerpt", "")))}</code></div>
        <p style="margin-top:10px;"><strong>Result</strong></p>
        <div class="review-scroll"><code id="hikResultRaw">{html.escape(str(status.get("hik_status", {}).get("result_excerpt", "")))}</code></div>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="help">
    <div class="grid" style="margin-top:10px;">
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>Help</h2>
        <p class="hint">This page is meant to help remote fault finding on the VA-Connect encoder. The short descriptions below explain what each section means and how to use it.</p>
        <div class="help-grid">
          <section class="help-card">
            <h3>Overview</h3>
            <p><strong>Current diagnosis</strong> is the watchdog's best plain-English summary of what looks wrong right now.</p>
            <p><strong>Current state</strong> shows whether the watchdog currently thinks the box is healthy or in fault.</p>
            <p><strong>Unexpected reboots</strong> means the PC restarted without a recent watchdog reboot command, which can point to manual reboot, power issue, or hard crash.</p>
            <p><strong>Fault summary</strong> and <strong>Linux stability clues</strong> condense the logs into the simplest operator wording the watchdog can currently justify.</p>
          </section>
          <section class="help-card">
            <h3>Current PC Stats</h3>
            <p>This row shows the most recent metric sample taken by the site watchdog.</p>
            <p><strong>CPU</strong> and <strong>Memory</strong> are percentages. <strong>MemAvailable</strong> is free RAM available to Linux. <strong>Cached</strong> is RAM being used for cache and can usually be reclaimed.</p>
            <p><strong>Temp max</strong> is the hottest thermal sensor currently exposed by Ubuntu. <strong>Load</strong> is the 1-minute load average.</p>
          </section>
          <section class="help-card">
            <h3>Incident Timeline</h3>
            <p>This is the short event history for the latest watchdog activity.</p>
            <p>Use it to see the sequence of startup, fault start, recovery, snapshots, reboot actions, and reboot detections.</p>
          </section>
          <section class="help-card">
            <h3>PC Stats Chart</h3>
            <p>This chart trends the last 24 hours or 7 days of watchdog metrics.</p>
            <p>CPU, memory, root disk, recording disk, and temperature are plotted together. Hover the graph to inspect a point in time.</p>
            <p>The reboot markers show when the watchdog asked for a reboot or when a reboot was later detected. Numbers in brackets show how many of each marker are visible in the current chart range.</p>
          </section>
          <section class="help-card">
            <h3>TeamViewer</h3>
            <p>This panel shows whether TeamViewer is installed, whether the daemon is up, and the detected TeamViewer ID.</p>
            <p><strong>Reset TeamViewer password</strong> asks the local TeamViewer CLI to generate a new password and shows it immediately so you can reconnect.</p>
            <p><strong>Start</strong> and <strong>Restart TeamViewer</strong> send daemon control commands for remote recovery when TeamViewer itself is the problem.</p>
          </section>
          <section class="help-card">
            <h3>Latest Checks</h3>
            <p><strong>App process</strong> is whether the watched VA-Connect process is running.</p>
            <p><strong>WAN</strong> checks prove internet reachability. <strong>TCP</strong> checks prove local devices such as the RUT or RTSP endpoint are reachable. <strong>Service</strong> checks prove selected systemd services are active.</p>
          </section>
          <section class="help-card">
            <h3>Controls</h3>
            <p><strong>Monitoring enabled</strong> turns automatic watchdog behaviour on or off.</p>
            <p><strong>App auto-restart</strong> allows the watchdog to start the app if it disappears.</p>
            <p><strong>Network restart before reboot</strong> tries the configured network restart command before a reboot. <strong>Reboot allowed</strong> controls whether the watchdog is allowed to reboot the PC.</p>
            <p><strong>Speed test</strong> runs a simple Cloudflare download/upload check from the codec and records Mbps along with CPU and memory usage at the time.</p>
          </section>
          <section class="help-card">
            <h3>Investigation</h3>
            <p><strong>Likely causes</strong> is a scoring guide based on the current evidence. It helps point you at memory/platform, storage, network, or app/service problems first.</p>
            <p><strong>Hardware warnings</strong> surfaces kernel, SMART, and persistent-crash clues. <strong>Crash review</strong> summarizes the latest previous-boot review if the box restarted.</p>
            <p><strong>Linux stability</strong> separates previous-boot clues from current-warning clues so you can judge whether NIC or memory messages were likely before the freeze or only after repower.</p>
          </section>
          <section class="help-card">
            <h3>Config</h3>
            <p><strong>App match</strong> is the process text the watchdog looks for. <strong>App start command</strong> is what it runs if that process disappears.</p>
            <p><strong>Internet hosts</strong> are public endpoints used to prove WAN access. <strong>TCP targets</strong> are local devices you want the watchdog to reach on host:port.</p>
            <p><strong>Base reboot timeout</strong> is the first wait before reboot. <strong>Max reboot timeout</strong> is the cap after backoff increases the reboot delay.</p>
          </section>
          <section class="help-card">
            <h3>Logs And Files</h3>
            <p>The watchdog writes events to <code>/var/log/va-connect-site-watchdog/events.jsonl</code> and metrics to <code>/var/log/va-connect-site-watchdog/metrics.jsonl</code>.</p>
            <p>Snapshots go under <code>/var/log/va-connect-site-watchdog/snapshots</code>. Current state lives in <code>/var/lib/va-connect-site-watchdog/state.json</code>.</p>
          </section>
        </div>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="config">
    <div class="bottom-grid">
      <section class="panel">
        <h2>Config</h2>
        <div class="formgrid">
          <div class="field">
            <label for="gateway_name">Gateway / crossing name</label>
<input id="gateway_name" type="text" placeholder="Enter gateway name" autocomplete="off" autocapitalize="off" spellcheck="false" value="{html.escape(str(cfg.get("gateway_name", "")))}">
          </div>
          <div class="field">
            <label for="app_match">App match</label>
            <input id="app_match" type="text" value="{html.escape(str(cfg.get("app_match", "")))}">
          </div>
          <div class="field">
            <label for="app_start_command">App start command</label>
            <input id="app_start_command" type="text" value="{html.escape(str(cfg.get("app_start_command", "")))}">
          </div>
          <div class="field">
            <label for="base_reboot_timeout_seconds">Base reboot timeout (s)</label>
            <input id="base_reboot_timeout_seconds" type="number" min="60" value="{int(cfg.get("base_reboot_timeout_seconds", 300))}">
          </div>
          <div class="field">
            <label for="max_reboot_timeout_seconds">Max reboot timeout (s)</label>
            <input id="max_reboot_timeout_seconds" type="number" min="60" value="{int(cfg.get("max_reboot_timeout_seconds", 3600))}">
          </div>
          <div class="field">
            <label for="reboot_backoff_multiplier">Backoff multiplier</label>
            <input id="reboot_backoff_multiplier" type="number" min="1" step="0.1" value="{html.escape(str(cfg.get("reboot_backoff_multiplier", 2.0)))}">
          </div>
          <div class="field">
            <label for="check_interval_seconds">Check interval (s)</label>
            <input id="check_interval_seconds" type="number" min="5" value="{int(cfg.get("check_interval_seconds", 30))}">
          </div>
          <div class="field">
            <label for="network_restart_cooldown_seconds">Network restart cooldown (s)</label>
            <input id="network_restart_cooldown_seconds" type="number" min="30" value="{int(cfg.get("network_restart_cooldown_seconds", 600))}">
          </div>
          <div class="field">
            <label for="post_action_settle_seconds">Post-action settle (s)</label>
            <input id="post_action_settle_seconds" type="number" min="5" value="{int(cfg.get("post_action_settle_seconds", 20))}">
          </div>
          <div class="field">
            <label for="web_bind">Web bind</label>
            <input id="web_bind" type="text" value="{html.escape(str(cfg.get("web_bind", "0.0.0.0")))}">
          </div>
          <div class="field">
            <label for="web_port">Web port</label>
            <input id="web_port" type="number" min="1" max="65535" value="{int(cfg.get("web_port", 80))}">
          </div>
          <div class="field">
            <label for="web_token">Web token</label>
            <input id="web_token" type="text" value="{html.escape(str(cfg.get("web_token", "")))}">
          </div>
          <div class="field">
            <label for="network_restart_command">Network restart command</label>
            <input id="network_restart_command" type="text" value="{html.escape(str(cfg.get("network_restart_command", "")))}">
          </div>
          <div class="field">
            <label for="teamviewer_id_command">TeamViewer info command</label>
            <input id="teamviewer_id_command" type="text" value="{html.escape(str(cfg.get("teamviewer_id_command", "teamviewer info")))}">
          </div>
          <div class="field">
            <label for="teamviewer_password_reset_command">TeamViewer password reset command</label>
            <input id="teamviewer_password_reset_command" type="text" value="{html.escape(str(cfg.get("teamviewer_password_reset_command", "teamviewer passwd {{password}}")))}">
          </div>
          <div class="field">
            <label for="teamviewer_start_command">TeamViewer start command</label>
            <input id="teamviewer_start_command" type="text" value="{html.escape(str(cfg.get("teamviewer_start_command", "systemctl start teamviewerd")))}">
          </div>
          <div class="field">
            <label for="teamviewer_restart_command">TeamViewer restart command</label>
            <input id="teamviewer_restart_command" type="text" value="{html.escape(str(cfg.get("teamviewer_restart_command", "systemctl restart teamviewerd")))}">
          </div>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="internet_hosts">Internet hosts, one per line</label>
          <textarea id="internet_hosts">{html.escape(chr(10).join(str(item) for item in cfg.get("internet_hosts", [])))}</textarea>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="systemd_services">Systemd services, one per line</label>
          <textarea id="systemd_services">{html.escape(chr(10).join(str(item) for item in cfg.get("systemd_services", [])))}</textarea>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="tcp_targets">TCP targets, one per line as host:port</label>
          <textarea id="tcp_targets">{html.escape(chr(10).join(f"{item.get('host','')}:{item.get('port','')}" for item in cfg.get("tcp_targets", [])))}</textarea>
        </div>
        <button onclick="saveConfig()">Save full config</button>
        <p class="hint">Use one internet host per line. Use one TCP target per line in the form <code>192.168.1.132:554</code>.</p>
      </section>
      <div class="sidebar-stack">
        <section class="panel" style="max-height: 560px; overflow: auto;">
          <h2>Recent events</h2>
          <div class="events" id="events"></div>
        </section>
        <section class="panel">
          <h2>Watchdog files</h2>
          <p><code>{html.escape(status["paths"]["state"])}</code></p>
          <p><code>{html.escape(status["paths"]["events"])}</code></p>
          <p><code>{html.escape(status["paths"].get("metrics", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("build_info", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("update_status", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("update_log", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("export_status", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("export_log", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("memtest_status", ""))}</code></p>
          <p><code>{html.escape(status["paths"].get("memtest_log", ""))}</code></p>
          <p><code>{html.escape(str(status["build_info"].get("source_repo_dir", "unknown")))}</code></p>
        </section>
      </div>
    </div>
    </section>
  </div>
  <script>
    (function () {{
      function authQuery() {{
        return window.location.search || '';
      }}

      function postJson(path, payload, callback) {{
        var xhr = new XMLHttpRequest();
        xhr.open('POST', path + authQuery(), true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {{
          if (xhr.readyState !== 4) {{
            return;
          }}
          var body = {{}};
          try {{
            body = JSON.parse(xhr.responseText || '{{}}');
          }} catch (err) {{
            body = {{}};
          }}
          callback(xhr.status, body);
        }};
        xhr.send(JSON.stringify(payload || {{}}));
      }}

      function reloadSoon() {{
        window.setTimeout(function () {{
          var url = new URL(window.location.href);
          var activeBtn = document.querySelector('.tab-btn.active');
          var activeTab = activeBtn ? activeBtn.getAttribute('data-tab') : '';
          if (activeTab) {{
            url.searchParams.set('tab', activeTab);
          }}
          window.location.replace(url.toString());
        }}, 900);
      }}

      window.switchTab = function (name) {{
        var buttons = document.getElementsByClassName('tab-btn');
        var panels = document.getElementsByClassName('tab-panel');
        var i;
        for (i = 0; i < buttons.length; i += 1) {{
          buttons[i].classList[buttons[i].getAttribute('data-tab') === name ? 'add' : 'remove']('active');
        }}
        for (i = 0; i < panels.length; i += 1) {{
          panels[i].classList[panels[i].getAttribute('data-tab-panel') === name ? 'add' : 'remove']('active');
        }}
        try {{
          var url = new URL(window.location.href);
          url.searchParams.set('tab', name);
          window.history.replaceState(null, '', url.toString());
        }} catch (_err) {{
          // ignore URL rewrite issues in limited browsers
        }}
      }};

      window.hardRefreshPage = function () {{
        try {{
          var url = new URL(window.location.href);
          url.searchParams.set('_refresh', String(Date.now()));
          var activeBtn = document.querySelector('.tab-btn.active');
          var activeTab = activeBtn ? activeBtn.getAttribute('data-tab') : '';
          if (activeTab) {{
            url.searchParams.set('tab', activeTab);
          }}
          window.location.replace(url.toString());
        }} catch (_err) {{
          var joiner = window.location.search ? '&' : '?';
          window.location.href = window.location.pathname + (window.location.search || '') + joiner + '_refresh=' + new Date().getTime();
        }}
      }};

      window.runAction = function (action, extraPayload) {{
        var payload = {{ action: action }};
        var key;
        extraPayload = extraPayload || {{}};
        if (action === 'update_watchdog') {{
          try {{
            window.sessionStorage.setItem('watchdogAutoHardRefreshPending', '1');
          }} catch (_storageErr) {{
            // ignore storage failures
          }}
          var updateNowButton = document.getElementById('updateNowButton');
          var updateMessage = document.getElementById('updateMessage');
          var updateProgress = document.getElementById('updateProgress');
          if (updateNowButton) {{
            updateNowButton.textContent = 'Updating...';
            updateNowButton.className = 'secondary status-running';
            updateNowButton.disabled = true;
          }}
          if (updateMessage) {{
            updateMessage.textContent = 'Starting update...';
          }}
          if (updateProgress) {{
            updateProgress.style.display = 'block';
          }}
        }}
        for (key in extraPayload) {{
          if (Object.prototype.hasOwnProperty.call(extraPayload, key)) {{
            payload[key] = extraPayload[key];
          }}
        }}
        postJson('/api/action', payload, function (status, body) {{
          if (status >= 200 && status < 300) {{
            if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {{
              var result = document.getElementById('teamviewerResetResult');
              if (result) {{
                result.textContent = body.password ? ('New password: ' + body.password) : (body.message || 'Action complete.');
              }}
            }}
            reloadSoon();
            return;
          }}
          alert((body && body.message) || 'Action failed.');
        }});
      }};

      window.setTeamviewerPassword = function () {{
        var input = document.getElementById('teamviewerManualPassword');
        window.runAction('reset_teamviewer_password', {{ password: input ? input.value : '' }});
      }};

      window.quickExportIncident = function () {{
        postJson('/api/action', {{ action: 'quick_export' }}, function (status, body) {{
          if (status >= 200 && status < 300) {{
            var meta = document.getElementById('quickExportMeta');
            if (meta && body && body.message) {{
              meta.textContent = body.message;
            }}
            reloadSoon();
            return;
          }}
          alert((body && body.message) || 'Quick export failed.');
        }});
      }};

      window.runIncidentExport = function (incidentId) {{
        postJson('/api/action', {{ action: 'incident_export', incident_id: incidentId }}, function (status, body) {{
          if (status >= 200 && status < 300) {{
            reloadSoon();
            return;
          }}
          alert((body && body.message) || 'Incident export failed.');
        }});
      }};

      window.runSpeedtest = function () {{
        postJson('/api/speedtest', {{}}, function (status, body) {{
          if (status >= 200 && status < 300) {{
            reloadSoon();
            return;
          }}
          alert((body && body.message) || 'Speed test failed to start.');
        }});
      }};

      window.runMemtest = function () {{
        var size = document.getElementById('memtest_size_mb');
        var loops = document.getElementById('memtest_loops');
        postJson('/api/memtest', {{
          size_mb: size && size.value ? Number(size.value) : 1024,
          loops: loops && loops.value ? Number(loops.value) : 2
        }}, function (status, body) {{
          if (status >= 200 && status < 300) {{
            reloadSoon();
            return;
          }}
          alert((body && body.message) || 'Memory test failed to start.');
        }});
      }};

      window.installRequiredTools = function () {{
        window.runAction('install_required_tools');
      }};

      window.saveSettings = function () {{
        postJson('/api/config', {{
          monitoring_enabled: !!(document.getElementById('monitoring_enabled') || {{}}).checked,
          app_restart_enabled: !!(document.getElementById('app_restart_enabled') || {{}}).checked,
          restart_network_before_reboot: !!(document.getElementById('restart_network_before_reboot') || {{}}).checked,
          reboot_enabled: !!(document.getElementById('reboot_enabled') || {{}}).checked
        }}, function () {{
          reloadSoon();
        }});
      }};

      function fetchJson(path, callback) {{
        var xhr = new XMLHttpRequest();
        var query = authQuery();
        var url = path;
        if (query) {{
          url += (path.indexOf('?') >= 0 ? '&' : '?') + query.substring(1);
        }}
        xhr.open('GET', url, true);
        xhr.onreadystatechange = function () {{
          if (xhr.readyState !== 4) {{
            return;
          }}
          var body = {{}};
          try {{
            body = JSON.parse(xhr.responseText || '{{}}');
          }} catch (err) {{
            body = {{}};
          }}
          callback(xhr.status, body);
        }};
        xhr.send();
      }}

      function drawLegacyMetrics(points) {{
        var canvas = document.getElementById('metricsChart');
        if (!canvas || !canvas.getContext) {{
          return;
        }}
        var ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#0f1820';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        var pad = 40;
        var chartWidth = canvas.width - pad * 2;
        var chartHeight = canvas.height - pad * 2;
        ctx.strokeStyle = '#29404f';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 4; i += 1) {{
          var y = pad + (chartHeight / 4) * i;
          ctx.beginPath();
          ctx.moveTo(pad, y);
          ctx.lineTo(pad + chartWidth, y);
          ctx.stroke();
        }}
        if (!points || !points.length) {{
          ctx.fillStyle = '#8ea5b9';
          ctx.font = '16px Segoe UI';
          ctx.fillText('No metrics collected yet.', pad, canvas.height / 2);
          return;
        }}
        var epochs = [];
        for (var j = 0; j < points.length; j += 1) {{
          var epoch = Date.parse((points[j] || {{}}).ts || '');
          if (!isNaN(epoch)) {{
            epochs.push(epoch);
          }}
        }}
        if (!epochs.length) {{
          ctx.fillStyle = '#8ea5b9';
          ctx.font = '16px Segoe UI';
          ctx.fillText('No timestamped metrics available.', pad, canvas.height / 2);
          return;
        }}
        var firstEpoch = epochs[0];
        var lastEpoch = epochs[epochs.length - 1];
        var spanEpoch = Math.max(1, lastEpoch - firstEpoch);
        ctx.strokeStyle = '#67a8db';
        ctx.lineWidth = 2;
        var started = false;
        for (var k = 0; k < points.length; k += 1) {{
          var point = points[k] || {{}};
          if (point.gap) {{
            if (started) {{
              ctx.stroke();
              started = false;
            }}
            continue;
          }}
          var pointEpoch = Date.parse(point.ts || '');
          var value = Number(point.cpu_percent || 0);
          if (isNaN(pointEpoch) || isNaN(value)) {{
            continue;
          }}
          var x = pad + (((pointEpoch - firstEpoch) / spanEpoch) * chartWidth);
          var yPoint = pad + chartHeight - ((Math.max(0, Math.min(100, value)) / 100) * chartHeight);
          if (!started) {{
            ctx.beginPath();
            ctx.moveTo(x, yPoint);
            started = true;
          }} else {{
            ctx.lineTo(x, yPoint);
          }}
        }}
        if (started) {{
          ctx.stroke();
        }}
      }}

      window.setMetricRange = function (hours) {{
        var h = Number(hours) || 24;
        var b1 = document.getElementById('range1hBtn');
        var b24 = document.getElementById('range24hBtn');
        var b168 = document.getElementById('range168hBtn');
        if (b1) b1.classList[h === 1 ? 'add' : 'remove']('active');
        if (b24) b24.classList[h === 24 ? 'add' : 'remove']('active');
        if (b168) b168.classList[h === 168 ? 'add' : 'remove']('active');
        var title = document.getElementById('metricsTitle');
        if (title) {{
          title.textContent = h === 1 ? 'PC Stats - Last Hour' : (h === 168 ? 'PC Stats - Last 7 Days' : 'PC Stats - Last 24 Hours');
        }}
        var sep = authQuery() ? '&' : '?';
        fetchJson('/api/metrics' + sep + 'hours=' + h, function (_status, body) {{
          var points = (body && body.points) ? body.points : [];
          drawLegacyMetrics(points);
          var sample = document.getElementById('metricsSampleAt');
          if (sample) {{
            var latest = points.length ? ((points[points.length - 1] || {{}}).ts || '') : '';
            sample.textContent = latest ? ('Latest sample ' + latest) : 'Latest sample unknown';
          }}
        }});
      }};

      if (document.getElementById('metricsChart')) {{
        window.setMetricRange(24);
      }}
      try {{
        var initialTab = new URLSearchParams(window.location.search || '').get('tab');
        if (initialTab) {{
          window.switchTab(initialTab);
        }}
      }} catch (_err) {{
        // ignore tab parse issues
      }}
    }})();
  </script>
  <script>
    const initialStatus = null;
    const authQuery = window.location.search || '';
    let latestMetrics = [];
    let latestMetricEvents = [];
    let metricsRangeHours = 24;

    function switchTab(name) {{
      document.querySelectorAll('.tab-btn').forEach((btn) => {{
        btn.classList.toggle('active', btn.dataset.tab === name);
      }});
      document.querySelectorAll('.tab-panel').forEach((panel) => {{
        panel.classList.toggle('active', panel.dataset.tabPanel === name);
      }});
      try {{
        const url = new URL(window.location.href);
        url.searchParams.set('tab', name);
        window.history.replaceState(null, '', url.toString());
      }} catch (_err) {{
        // ignore URL rewrite issues
      }}
    }}

    function hardRefreshPage() {{
      try {{
        const url = new URL(window.location.href);
        url.searchParams.set('_refresh', String(Date.now()));
        const activeBtn = document.querySelector('.tab-btn.active');
        const activeTab = activeBtn ? activeBtn.dataset.tab : '';
        if (activeTab) {{
          url.searchParams.set('tab', activeTab);
        }}
        window.location.replace(url.toString());
      }} catch (_err) {{
        window.location.reload();
      }}
    }}

    function buildAuthedUrl(path, extraParams = {{}}) {{
      const map = {{}};
      const rawSearch = (window.location.search || '').replace(/^\\?/, '');
      if (rawSearch) {{
        rawSearch.split('&').forEach((pair) => {{
          if (!pair) {{
            return;
          }}
          const eqIndex = pair.indexOf('=');
          const rawKey = eqIndex >= 0 ? pair.slice(0, eqIndex) : pair;
          const rawValue = eqIndex >= 0 ? pair.slice(eqIndex + 1) : '';
          const key = decodeURIComponent(rawKey || '');
          const value = decodeURIComponent(rawValue || '');
          if (key && key !== '_refresh') {{
            map[key] = value;
          }}
        }});
      }}
      const params = extraParams || {{}};
      for (const key in params) {{
        if (Object.prototype.hasOwnProperty.call(params, key)) {{
          const value = params[key];
          if (value !== undefined && value !== null && value !== '') {{
            map[key] = String(value);
          }}
        }}
      }}
      const query = Object.keys(map)
        .map((key) => `${{encodeURIComponent(key)}}=${{encodeURIComponent(map[key])}}`)
        .join('&');
      return query ? `${{path}}?${{query}}` : path;
    }}

    function pinCurrentTabInUrl() {{
      try {{
        const activeBtn = document.querySelector('.tab-btn.active');
        const activeTab = activeBtn ? activeBtn.dataset.tab : '';
        if (!activeTab) {{
          return;
        }}
        const url = new URL(window.location.href);
        url.searchParams.set('tab', activeTab);
        window.history.replaceState(null, '', url.toString());
      }} catch (_err) {{
        // ignore URL rewrite issues
      }}
    }}

    function badge(ok) {{
      return ok ? 'badge' : 'badge danger';
    }}

    function fallback(value, alt) {{
      return value === undefined || value === null ? alt : value;
    }}

    function safeDomId(value) {{
      return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '_');
    }}

    function findIncidentExportStatus(statusPayload, incidentId) {{
      const incidents = Array.isArray(statusPayload && statusPayload.incidents) ? statusPayload.incidents : [];
      const target = String(incidentId || '');
      for (const item of incidents) {{
        if (String((item && item.incident_id) || '') === target) {{
          return (item && item.export_status) || {{}};
        }}
      }}
      return {{}};
    }}

    function metricRangeLabel(hours) {{
      if (hours === 1) {{
        return 'PC Stats - Last Hour';
      }}
      if (hours === 168) {{
        return 'PC Stats - Last 7 Days';
      }}
      return 'PC Stats - Last 24 Hours';
    }}

    function formatLocalTimestamp(ts) {{
      if (!ts) {{
        return 'unknown';
      }}
      const date = new Date(ts);
      if (Number.isNaN(date.getTime())) {{
        return ts;
      }}
      return date.toLocaleString([], {{
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }});
    }}

    function formatLocalDateTimeInput(ts) {{
      if (!ts) {{
        return '';
      }}
      const date = new Date(ts);
      if (Number.isNaN(date.getTime())) {{
        return '';
      }}
      const pad = (value) => String(value).padStart(2, '0');
      return `${{date.getFullYear()}}-${{pad(date.getMonth() + 1)}}-${{pad(date.getDate())}}T${{pad(date.getHours())}}:${{pad(date.getMinutes())}}`;
    }}

    function coerceDateTimeInputValue(ts) {{
      if (!ts) {{
        return '';
      }}
      if (/^\\d{{4}}-\\d{{2}}-\\d{{2}} \\d{{2}}:\\d{{2}}(:\\d{{2}})?$/.test(ts)) {{
        return ts.slice(0, 16).replace(' ', 'T');
      }}
      return formatLocalDateTimeInput(ts);
    }}

    function isEditingAny(ids) {{
      const active = document.activeElement;
      return !!active && ids.includes(active.id);
    }}

    function movePanel(panelId, targetId) {{
      const panel = document.getElementById(panelId);
      const target = document.getElementById(targetId);
      if (panel && target && panel.parentElement !== target) {{
        target.appendChild(panel);
      }}
    }}

    function organizeLayout() {{
      movePanel('faultSummaryPanel', 'investigationIntroPanels');
      movePanel('linuxCluesPanel', 'investigationIntroPanels');
      movePanel('leadupPanel', 'investigationActionPanels');
    }}

    function render(status) {{
      organizeLayout();
      const topBuildCommit = document.getElementById('topBuildCommit');
      if (topBuildCommit) {{
        topBuildCommit.textContent = (status.build_info && status.build_info.git_commit) || 'unknown';
      }}
      const topDisplayName = document.getElementById('topDisplayName');
      if (topDisplayName) {{
        topDisplayName.textContent = status.display_name || 'Enter gateway name';
      }}
      document.getElementById('monitoring_enabled').checked = !!status.config.monitoring_enabled;
      document.getElementById('app_restart_enabled').checked = !!status.config.app_restart_enabled;
      document.getElementById('restart_network_before_reboot').checked = !!status.config.restart_network_before_reboot;
      document.getElementById('reboot_enabled').checked = !!status.config.reboot_enabled;
      document.getElementById('gateway_name').value = status.config.gateway_name || '';
      document.getElementById('app_match').value = status.config.app_match || '';
      document.getElementById('app_start_command').value = status.config.app_start_command || '';
      document.getElementById('base_reboot_timeout_seconds').value = status.config.base_reboot_timeout_seconds || 300;
      document.getElementById('max_reboot_timeout_seconds').value = status.config.max_reboot_timeout_seconds || 3600;
      document.getElementById('reboot_backoff_multiplier').value = status.config.reboot_backoff_multiplier || 2.0;
      document.getElementById('check_interval_seconds').value = status.config.check_interval_seconds || 30;
      document.getElementById('network_restart_cooldown_seconds').value = status.config.network_restart_cooldown_seconds || 600;
      document.getElementById('post_action_settle_seconds').value = status.config.post_action_settle_seconds || 20;
      document.getElementById('web_bind').value = status.config.web_bind || '0.0.0.0';
      document.getElementById('web_port').value = status.config.web_port || 80;
      document.getElementById('web_token').value = status.config.web_token || '';
      document.getElementById('network_restart_command').value = status.config.network_restart_command || '';
      document.getElementById('teamviewer_id_command').value = status.config.teamviewer_id_command || 'teamviewer info';
      document.getElementById('teamviewer_password_reset_command').value = status.config.teamviewer_password_reset_command || 'teamviewer passwd {{password}}';
      document.getElementById('teamviewer_start_command').value = status.config.teamviewer_start_command || 'systemctl start teamviewerd';
      document.getElementById('teamviewer_restart_command').value = status.config.teamviewer_restart_command || 'systemctl restart teamviewerd';
      const hikFieldIds = ['hik_enabled', 'hik_scheme', 'hik_host', 'hik_username', 'hik_password', 'hik_channel', 'hik_people_count_result_path', 'hik_people_count_capabilities_path'];
      if (!isEditingAny(hikFieldIds)) {{
        document.getElementById('hik_enabled').checked = !!status.config.hik_enabled;
        document.getElementById('hik_scheme').value = status.config.hik_scheme || 'http';
        document.getElementById('hik_host').value = status.config.hik_host || '';
        document.getElementById('hik_username').value = status.config.hik_username || '';
        document.getElementById('hik_password').value = status.config.hik_password || '';
        document.getElementById('hik_channel').value = status.config.hik_channel || 1;
        document.getElementById('hik_people_count_result_path').value = status.config.hik_people_count_result_path || '/ISAPI/Intelligent/channels/{{channel}}/framesPeopleCounting/result';
        document.getElementById('hik_people_count_capabilities_path').value = status.config.hik_people_count_capabilities_path || '/ISAPI/Intelligent/channels/{{channel}}/framesPeopleCounting/capabilities';
      }}
      document.getElementById('internet_hosts').value = (status.config.internet_hosts || []).join('\\n');
      document.getElementById('systemd_services').value = (status.config.systemd_services || []).join('\\n');
      document.getElementById('tcp_targets').value = (status.config.tcp_targets || []).map((item) => `${{item.host}}:${{item.port}}`).join('\\n');
      const checks = status.state.last_checks || {{ pings: [], ports: [], app_ok: null }};
      const pingCount = checks.pings || [];
      const serviceCount = checks.services || [];
      const tcpCount = checks.ports || [];
      const pingOk = pingCount.filter((item) => item.ok).length;
      const serviceOk = serviceCount.filter((item) => item.ok).length;
      const tcpOk = tcpCount.filter((item) => item.ok).length;
      const detailBlock = (items, formatter) => items.length
        ? `<div class="check-list">${{items.map(formatter).join('')}}</div>`
        : `<div class="timeline-empty">No checks configured in this section.</div>`;
      document.getElementById('targets').innerHTML = `
        <div class="item"><strong>App process</strong><br><span class="${{badge(!!checks.app_ok)}}">${{checks.app_ok ? 'Running' : 'Missing'}}</span></div>
        <details class="check-group" ${{pingOk !== pingCount.length ? 'open' : ''}}>
          <summary>WAN pings: ${{pingOk}}/${{pingCount.length}} reachable</summary>
          ${{detailBlock(pingCount, (item) => `<div class="item"><strong>${{item.host}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`)}}
        </details>
        <details class="check-group" ${{serviceOk !== serviceCount.length ? 'open' : ''}}>
          <summary>Services: ${{serviceOk}}/${{serviceCount.length}} active</summary>
          ${{detailBlock(serviceCount, (item) => `<div class="item"><strong>${{item.service}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Active' : 'Not active'}}</span><br><code>${{item.detail || ''}}</code></div>`)}}
        </details>
        <details class="check-group" ${{tcpOk !== tcpCount.length ? 'open' : ''}}>
          <summary>TCP targets: ${{tcpOk}}/${{tcpCount.length}} reachable</summary>
          ${{detailBlock(tcpCount, (item) => `<div class="item"><strong>${{item.host}}:${{item.port}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`)}}
        </details>
      `;

      document.getElementById('events').innerHTML = (status.recent_events || []).map((event) => {{
        const summary = event.summary || {{ title: (event.event || 'event'), detail: '', severity: 'info', ts: event.ts || '' }};
        const raw = JSON.stringify(event, null, 2);
        return `<div class="item"><strong>${{summary.title}}</strong><br><span class="hint">${{formatLocalTimestamp(summary.ts || '')}}</span><br>${{summary.detail || ''}}<details><summary>Raw event</summary><code>${{raw}}</code></details></div>`;
      }}).join('');
      document.getElementById('nextSteps').innerHTML = (status.next_steps || []).map((step) => `<li>${{step}}</li>`).join('');
      document.getElementById('timeline').innerHTML = (status.timeline || []).map((item) => (
        `<div class="timeline-card ${{item.severity || ''}}"><div class="timeline-time">${{formatLocalTimestamp(item.ts || '')}}</div><div class="timeline-title">${{item.title || ''}}</div><div>${{item.detail || ''}}</div></div>`
      )).join('') || '<div class="timeline-empty">No incident timeline entries yet.</div>';
      const crashReview = status.crash_review || {{}};
      document.getElementById('crashReviewTitle').textContent = crashReview.title || 'Crash review unavailable';
      document.getElementById('crashReviewDetail').textContent = crashReview.detail || '';
      document.getElementById('crashReviewPath').textContent = crashReview.snapshot_path || '';
      const hardwareReview = status.hardware_review || {{}};
      document.getElementById('suspectScores').innerHTML = (status.suspect_scores || []).map((item) => (
        `<div class="suspect-card"><div class="stat-label">${{item.label || 'Cause'}}</div><div class="suspect-score">${{item.score || 0}}</div><ul class="review-list">${{(item.reasons || []).map((reason) => `<li>${{reason}}</li>`).join('')}}</ul></div>`
      )).join('');
      document.getElementById('hardwareCheckedAt').textContent = formatLocalTimestamp(hardwareReview.checked_at || '');
      document.getElementById('hardwareFindings').innerHTML = (hardwareReview.findings || []).length
        ? (hardwareReview.findings || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No hardware findings yet.</li>';
      document.getElementById('hardwareWarnings').innerHTML = (hardwareReview.warnings || []).length
        ? (hardwareReview.warnings || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No hardware-warning lines surfaced yet.</li>';
      document.getElementById('hardwareSmart').innerHTML = (hardwareReview.smart || []).length
        ? (hardwareReview.smart || []).map((item) => `<div><strong>${{item.device || 'disk'}}</strong><br><code>${{item.summary || ''}}</code></div>`).join('')
        : '<div><code>No SMART summary yet.</code></div>';
      document.getElementById('hardwarePstore').innerHTML = (hardwareReview.pstore_entries || []).length
        ? (hardwareReview.pstore_entries || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No pstore entries present.</li>';
      const hardwareIdentity = status.hardware_identity || {{}};
      document.getElementById('hardwareIdentitySummary').innerHTML = `
        <li><strong>Vendor:</strong> ${{hardwareIdentity.vendor || 'unknown'}}</li>
        <li><strong>Model:</strong> ${{hardwareIdentity.model || 'unknown'}}</li>
        <li><strong>Serial:</strong> ${{hardwareIdentity.serial || 'unknown'}}</li>
        <li><strong>Board:</strong> ${{hardwareIdentity.board_name || 'unknown'}}</li>
        <li><strong>BIOS:</strong> ${{(hardwareIdentity.bios_vendor || 'unknown')}} ${{(hardwareIdentity.bios_version || 'unknown')}}</li>
        <li><strong>BIOS date:</strong> ${{hardwareIdentity.bios_date || 'unknown'}}</li>
      `;
      const currentMetrics = status.state.last_metrics || {{}};
      const formatMetricNumber = (value, digits = 1) => {{
        if (value === null || value === undefined || Number.isNaN(Number(value))) {{
          return 'unknown';
        }}
        return Number(value).toFixed(digits);
      }};
      const sensorSummary = (currentMetrics.temperature_sensors || [])
        .slice(0, 3)
        .map((item) => `${{item.name || 'sensor'}} ${{fallback(item.value_c, 'unknown')}} C`)
        .join(' | ');
      document.getElementById('currentStatsAt').textContent = currentMetrics.ts ? `Latest sample ${{formatLocalTimestamp(currentMetrics.ts)}}` : 'Latest sample unknown';
      document.getElementById('currentStatsGrid').innerHTML = `
        <div class="metric-chip"><div class="stat-label">CPU</div><strong>${{formatMetricNumber(currentMetrics.cpu_percent)}}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Memory</div><strong>${{formatMetricNumber(currentMetrics.mem_percent)}}%</strong></div>
        <div class="metric-chip"><div class="stat-label">MemAvailable</div><strong>${{fallback(currentMetrics.mem_available_mb, 'unknown')}} MB</strong></div>
        <div class="metric-chip"><div class="stat-label">Cached</div><strong>${{fallback(currentMetrics.mem_cached_mb, 'unknown')}} MB</strong></div>
        <div class="metric-chip"><div class="stat-label">Root disk</div><strong>${{formatMetricNumber(currentMetrics.root_disk_percent)}}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Recording disk</div><strong>${{formatMetricNumber(currentMetrics.recording_disk_percent)}}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Temp max</div><strong>${{fallback(currentMetrics.temperature_c, 'unknown')}} C</strong></div>
        <div class="metric-chip"><div class="stat-label">Load</div><strong>${{formatMetricNumber(currentMetrics.load_1, 2)}}</strong></div>
      `;
      document.getElementById('metricsSampleAt').textContent = currentMetrics.ts ? `Latest sample ${{formatLocalTimestamp(currentMetrics.ts)}}` : 'Latest sample unknown';
      document.getElementById('metricsTempSummary').textContent = sensorSummary
        ? `Temperature: ${{sensorSummary}}`
        : `Temperature: ${{fallback(currentMetrics.temperature_c, 'unknown')}} C`;
      document.getElementById('memoryThermalSummary').innerHTML = `
        <li><strong>Memory used:</strong> ${{Number(currentMetrics.mem_percent || 0).toFixed(1)}}%</li>
        <li><strong>MemAvailable:</strong> ${{fallback(currentMetrics.mem_available_mb, 'unknown')}} MB</li>
        <li><strong>Cached:</strong> ${{fallback(currentMetrics.mem_cached_mb, 'unknown')}} MB</li>
        <li><strong>Temperature max:</strong> ${{fallback(currentMetrics.temperature_c, 'unknown')}} C</li>
        <li><strong>Thermal zones:</strong> ${{fallback(currentMetrics.temperature_sensor_count, 0)}}</li>
        <li><strong>Top sensors:</strong> ${{sensorSummary || 'unknown'}}</li>
      `;
      const teamviewer = status.teamviewer || {{}};
      const speedtestStatus = status.speedtest_status || {{}};
      const teamviewerInstalledBadgeMain = document.getElementById('teamviewerInstalledBadgeMain');
      const teamviewerDaemonBadgeMain = document.getElementById('teamviewerDaemonBadgeMain');
      const teamviewerGuiBadgeMain = document.getElementById('teamviewerGuiBadgeMain');
      const teamviewerInstalledBadge = document.getElementById('teamviewerInstalledBadge');
      const teamviewerDaemonBadge = document.getElementById('teamviewerDaemonBadge');
      const teamviewerGuiBadge = document.getElementById('teamviewerGuiBadge');
      teamviewerInstalledBadgeMain.className = `badge ${{teamviewer.installed ? '' : 'danger'}}`;
      teamviewerInstalledBadgeMain.textContent = teamviewer.installed ? 'Installed' : 'Not installed';
      teamviewerDaemonBadgeMain.className = `badge ${{teamviewer.daemon_running ? '' : 'danger'}}`;
      teamviewerDaemonBadgeMain.textContent = teamviewer.daemon_running ? 'Daemon running' : 'Daemon stopped';
      teamviewerGuiBadgeMain.className = `badge ${{teamviewer.gui_running ? '' : 'warn'}}`;
      teamviewerGuiBadgeMain.textContent = teamviewer.gui_running ? 'GUI running' : 'GUI not running';
      document.getElementById('teamviewerSummaryMain').textContent = teamviewer.summary || 'No TeamViewer information available.';
      teamviewerInstalledBadge.className = `badge ${{teamviewer.installed ? '' : 'danger'}}`;
      teamviewerInstalledBadge.textContent = teamviewer.installed ? 'Installed' : 'Not installed';
      teamviewerDaemonBadge.className = `badge ${{teamviewer.daemon_running ? '' : 'danger'}}`;
      teamviewerDaemonBadge.textContent = teamviewer.daemon_running ? 'Daemon running' : 'Daemon stopped';
      teamviewerGuiBadge.className = `badge ${{teamviewer.gui_running ? '' : 'warn'}}`;
      teamviewerGuiBadge.textContent = teamviewer.gui_running ? 'GUI running' : 'GUI not running';
      document.getElementById('teamviewerSummary').textContent = teamviewer.summary || 'No TeamViewer information available.';
      document.getElementById('teamviewerId').textContent = teamviewer.id || (teamviewer.id_permission_issue ? 'Permission denied' : 'unknown');
      document.getElementById('teamviewerVersion').textContent = teamviewer.version || 'unknown';
      document.getElementById('teamviewerStatus').textContent = teamviewer.status_text || 'unknown';
      document.getElementById('remoteSpeedtestSummary').textContent = speedtestStatus.finished_at
        ? `Last speed test: Down ${{fallback(speedtestStatus.download_mbps, 'n/a')}} Mbps | Up ${{fallback(speedtestStatus.upload_mbps, 'n/a')}} Mbps | ${{formatLocalTimestamp(speedtestStatus.finished_at)}}`
        : 'No web speed test run yet.';
      document.getElementById('teamviewerResetButton').disabled = !teamviewer.reset_supported;
      if (!teamviewer.reset_supported) {{
        document.getElementById('teamviewerResetResult').textContent = 'Password reset is unavailable because the TeamViewer CLI or reset command is not configured on this unit.';
      }}
      const faultReporting = status.fault_reporting || {{}};
      const topSuspect = faultReporting.top_suspect || {{}};
      const clueCounters = status.clue_counters || [];
      document.getElementById('faultHeadline').textContent = faultReporting.headline || 'Healthy now';
      document.getElementById('faultSummaryText').textContent = faultReporting.summary || 'No summary yet.';
      document.getElementById('faultImpactText').textContent = faultReporting.impact || '';
      document.getElementById('faultTopSuspectBadge').textContent = topSuspect.label || 'No top suspect';
      document.getElementById('faultTopSuspectScore').textContent = `Score ${{topSuspect.score || 0}}`;
      document.getElementById('clueCounterStrip').innerHTML = clueCounters.map((item) => `<div class="counter-chip ${{item.count ? 'hot' : ''}}"><div class="stat-label">${{item.label || 'Clue'}}</div><div class="count">${{item.count || 0}}</div></div>`).join('') || '<div class="counter-chip"><div class="stat-label">Clues</div><div class="count">0</div></div>';
      document.getElementById('faultQuickActions').innerHTML = (faultReporting.quick_actions || []).map((item) => `<li>${{item}}</li>`).join('') || '<li>No quick actions suggested yet.</li>';
      document.getElementById('linuxStabilityClues').innerHTML = (faultReporting.stability_clues || []).map((item) => `<li>${{item}}</li>`).join('') || '<li>No Linux stability clues collected yet.</li>';
      const linuxStability = status.linux_stability || {{}};
      const previousCounts = linuxStability.previous_boot_counts || {{}};
      const currentCounts = linuxStability.current_warning_counts || {{}};
      document.getElementById('linuxPreviousCounts').innerHTML = `
        <li>Link flaps: ${{previousCounts.link_flaps || 0}}</li>
        <li>igc/reset clues: ${{previousCounts.igc_errors || 0}}</li>
        <li>PCIe clues: ${{previousCounts.pcie_events || 0}}</li>
        <li>EDAC/memory clues: ${{previousCounts.memory_events || 0}}</li>
      `;
      document.getElementById('linuxCurrentCounts').innerHTML = `
        <li>Link flaps: ${{currentCounts.link_flaps || 0}}</li>
        <li>igc/reset clues: ${{currentCounts.igc_errors || 0}}</li>
        <li>PCIe clues: ${{currentCounts.pcie_events || 0}}</li>
        <li>EDAC/memory clues: ${{currentCounts.memory_events || 0}}</li>
      `;
      document.getElementById('linuxPreviousLine').innerHTML = `<code>${{linuxStability.strongest_previous_line || 'No highlighted previous-boot line yet.'}}</code>`;
      document.getElementById('linuxCurrentLine').innerHTML = `<code>${{linuxStability.strongest_current_line || 'No highlighted current-warning line yet.'}}</code>`;
      document.getElementById('linuxInterpretation').innerHTML = (linuxStability.interpretation || []).map((item) => `<li>${{item}}</li>`).join('') || '<li>No Linux stability interpretation available yet.</li>';
      document.getElementById('linuxAlertRules').innerHTML = (linuxStability.alert_rules || []).map((item) => `<li><strong>${{item.label || 'Rule'}}:</strong> ${{item.threshold || ''}} - ${{item.meaning || ''}}</li>`).join('') || '<li>No alert rules configured.</li>';
      const memtestInfo = status.memtest_info || {{}};
      document.getElementById('memtestHint').textContent = `memtester ${{memtestInfo.installed ? 'is installed' : 'is not installed'}}. Free RAM: ${{memtestInfo.available_mb || 0}} MB. Suggested test: ${{memtestInfo.recommended_label || '1024M'}} x ${{memtestInfo.recommended_loops || 2}}.`;
      document.getElementById('memtest_size_mb').value = memtestInfo.recommended_mb || 1024;
      document.getElementById('memtest_loops').value = memtestInfo.recommended_loops || 2;
      const memtestStatus = status.memtest_status || {{}};
      const memtestBadge = document.getElementById('memtestState');
      memtestBadge.className = `badge ${{memtestStatus.state === 'running' ? 'warn' : (memtestStatus.state === 'failed' ? 'danger' : '')}}`;
      memtestBadge.textContent = (memtestStatus.state || 'idle').toUpperCase();
      document.getElementById('memtestMessage').textContent = memtestStatus.message || 'No web memory test run yet.';
      document.getElementById('memtestMeta').textContent = memtestStatus.finished_at ? formatLocalTimestamp(memtestStatus.finished_at) : 'not finished yet';
      document.getElementById('memtestLogLink').style.display = memtestStatus.log_path ? 'inline-block' : 'none';
      const speedtestBadge = document.getElementById('speedtestState');
      speedtestBadge.className = `badge ${{speedtestStatus.state === 'running' ? 'warn' : (speedtestStatus.state === 'failed' ? 'danger' : '')}}`;
      speedtestBadge.textContent = (speedtestStatus.state || 'idle').toUpperCase();
      document.getElementById('speedtestMessage').textContent = speedtestStatus.message || 'No web speed test run yet.';
      const speedtestMetaParts = [];
      if (speedtestStatus.download_mbps !== null && speedtestStatus.download_mbps !== undefined) {{
        speedtestMetaParts.push(`Download ${{speedtestStatus.download_mbps}} Mbps`);
      }}
      if (speedtestStatus.upload_mbps !== null && speedtestStatus.upload_mbps !== undefined) {{
        speedtestMetaParts.push(`Upload ${{speedtestStatus.upload_mbps}} Mbps`);
      }}
      if (speedtestStatus.cpu_percent !== null && speedtestStatus.cpu_percent !== undefined) {{
        speedtestMetaParts.push(`CPU ${{speedtestStatus.cpu_percent}}%`);
      }}
      if (speedtestStatus.memory_percent !== null && speedtestStatus.memory_percent !== undefined) {{
        speedtestMetaParts.push(`Memory ${{speedtestStatus.memory_percent}}%`);
      }}
      if (speedtestStatus.finished_at) {{
        speedtestMetaParts.push(formatLocalTimestamp(speedtestStatus.finished_at));
      }}
      document.getElementById('speedtestMeta').textContent = speedtestMetaParts.join(' | ') || 'not finished yet';
      document.getElementById('speedtestLogLink').style.display = speedtestStatus.log_path ? 'inline-block' : 'none';
      document.getElementById('speedtestHistory').innerHTML = (status.speedtest_history || []).map((item) => `<li>${{formatLocalTimestamp(item.ts || '')}} | ${{item.state || 'unknown'}} | Down ${{fallback(item.download_mbps, 'n/a')}} Mbps | Up ${{fallback(item.upload_mbps, 'n/a')}} Mbps</li>`).join('') || '<li>No speed test history yet.</li>';
      const hikStatus = status.hik_status || {{}};
      const hikBadge = document.getElementById('hikState');
      hikBadge.className = `badge ${{hikStatus.state === 'failed' ? 'danger' : (hikStatus.state === 'idle' ? 'warn' : '')}}`;
      hikBadge.textContent = (hikStatus.state || 'idle').toUpperCase();
      document.getElementById('hikMessage').textContent = hikStatus.message || 'No Hik probe run yet.';
      const hikMetaParts = [];
      if (hikStatus.checked_at) {{
        hikMetaParts.push(`Probe #${{hikStatus.probe_sequence || '?'}}`);
        hikMetaParts.push(formatLocalTimestamp(hikStatus.checked_at));
      }}
      if (hikStatus.device_model) {{
        hikMetaParts.push(`Model: ${{hikStatus.device_model}}`);
      }}
      if (hikStatus.result_path_used) {{
        hikMetaParts.push(`Result path: ${{hikStatus.result_path_used}}`);
      }}
      const hikFailedAttempts = (hikStatus.result_attempts || []).filter((item) => !item.ok);
      if (hikFailedAttempts.length) {{
        hikMetaParts.push(`${{hikFailedAttempts.length}} failed path attempt(s)`);
      }}
      document.getElementById('hikMeta').textContent = hikMetaParts.join(' | ');
      const hikCounts = hikStatus.parsed_counts || {{}};
      const hikCountLines = [];
      for (const key in hikCounts) {{
        if (Object.prototype.hasOwnProperty.call(hikCounts, key)) {{
          hikCountLines.push(`<li><strong>${{key}}</strong>: ${{hikCounts[key]}}</li>`);
        }}
      }}
      if ((hikStatus.result_attempts || []).length) {{
        hikCountLines.push(`<li><strong>Endpoint attempts</strong>:</li>`);
        for (const attempt of (hikStatus.result_attempts || [])) {{
          hikCountLines.push(`<li>${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}</li>`);
        }}
      }}
      if (!hikStatus.device_info_ok) {{
        hikCountLines.push(`<li><strong>Device info check failed</strong>: ${{hikStatus.device_info_message || 'unknown error'}}</li>`);
      }}
      document.getElementById('hikCounts').innerHTML = hikCountLines.join('') || '<li>No people-count values parsed yet.</li>';
      const hikConsole = document.getElementById('hikProbeConsole');
      if (hikConsole) {{
        const consoleLines = [];
        consoleLines.push(`[${{hikStatus.checked_at || 'unknown'}}] state=${{hikStatus.state || 'idle'}}`);
        consoleLines.push(`message: ${{hikStatus.message || 'No Hik probe run yet.'}}`);
        consoleLines.push(`deviceInfo: ok=${{hikStatus.device_info_ok ? 'true' : 'false'}} status=${{hikStatus.device_info_status || 0}} model=${{hikStatus.device_model || 'unknown'}}`);
        for (const attempt of (hikStatus.capabilities_attempts || [])) {{
          consoleLines.push(`capabilities: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
        }}
        for (const attempt of (hikStatus.result_attempts || [])) {{
          consoleLines.push(`result: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
        }}
        hikConsole.textContent = consoleLines.join('\\n');
      }}
      const hikConsoleRaw = document.getElementById('hikProbeConsoleRaw');
      if (hikConsoleRaw) {{
        const consoleLines = [];
        consoleLines.push(`[${{hikStatus.checked_at || 'unknown'}}] state=${{hikStatus.state || 'idle'}}`);
        consoleLines.push(`message: ${{hikStatus.message || 'No Hik probe run yet.'}}`);
        consoleLines.push(`deviceInfo: ok=${{hikStatus.device_info_ok ? 'true' : 'false'}} status=${{hikStatus.device_info_status || 0}} model=${{hikStatus.device_model || 'unknown'}}`);
        for (const attempt of (hikStatus.capabilities_attempts || [])) {{
          consoleLines.push(`capabilities: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
        }}
        for (const attempt of (hikStatus.result_attempts || [])) {{
          consoleLines.push(`result: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
        }}
        hikConsoleRaw.textContent = consoleLines.join('\\n');
      }}
      document.getElementById('hikCapabilitiesRaw').textContent = hikStatus.capabilities_excerpt || '';
      document.getElementById('hikResultRaw').textContent = hikStatus.result_excerpt || '';
      document.getElementById('hikSavedSettings').innerHTML = `
        <li>Enabled: ${{status.config.hik_enabled ? 'true' : 'false'}}</li>
        <li>Scheme: ${{status.config.hik_scheme || 'http'}}</li>
        <li>Host: ${{status.config.hik_host || ''}}</li>
        <li>Username: ${{status.config.hik_username || ''}}</li>
        <li>Password: ${{(status.config.hik_password || '').trim() ? 'set' : 'empty'}}</li>
        <li>Channel: ${{status.config.hik_channel || 1}}</li>
        <li>Result path: ${{status.config.hik_people_count_result_path || ''}}</li>
        <li>Capabilities path: ${{status.config.hik_people_count_capabilities_path || ''}}</li>
      `;
      const rebootLeadup = status.reboot_leadup || {{}};
      const rebootLeadupMetrics = rebootLeadup.last_metrics || {{}};
      document.getElementById('rebootLeadupDetail').textContent = rebootLeadup.detail || 'No reboot lead-up yet.';
      document.getElementById('rebootLeadupAt').textContent = rebootLeadup.reference_at ? `Reference point ${{formatLocalTimestamp(rebootLeadup.reference_at)}}` : '';
      document.getElementById('rebootLeadupStats').innerHTML = `
        <section class="stat-card"><div class="stat-label">CPU</div><div class="stat-value">${{fallback(rebootLeadupMetrics.cpu_percent, 'unknown')}}%</div></section>
        <section class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">${{fallback(rebootLeadupMetrics.mem_percent, 'unknown')}}%</div></section>
        <section class="stat-card"><div class="stat-label">MemAvailable</div><div class="stat-value" style="font-size:1rem;">${{fallback(rebootLeadupMetrics.mem_available_mb, 'unknown')}} MB</div></section>
        <section class="stat-card"><div class="stat-label">Temp</div><div class="stat-value" style="font-size:1rem;">${{fallback(rebootLeadupMetrics.temperature_c, 'unknown')}} C</div></section>
      `;
      document.getElementById('rebootLeadupTimeline').innerHTML = (rebootLeadup.events || []).map((item) => `<div class="timeline-card ${{item.severity || ''}}"><div class="timeline-time">${{formatLocalTimestamp(item.ts || '')}}</div><div class="timeline-title">${{item.title || ''}}</div><div>${{item.detail || ''}}</div></div>`).join('') || '<div class="timeline-empty">No lead-up events captured yet.</div>';
      document.getElementById('crashReviewFindings').innerHTML = (crashReview.findings || []).length
        ? (crashReview.findings || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No crash-review findings yet.</li>';
      document.getElementById('crashReviewSystem').innerHTML = (crashReview.system_lines || []).length
        ? (crashReview.system_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No notable system-log lines extracted yet.</li>';
      document.getElementById('crashReviewSystemAll').innerHTML = (crashReview.system_tail_lines || []).length
        ? (crashReview.system_tail_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No final system-log lines available before reboot.</li>';
      document.getElementById('crashReviewKernel').innerHTML = (crashReview.kernel_lines || []).length
        ? (crashReview.kernel_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No notable kernel-log lines extracted yet.</li>';
      document.getElementById('crashReviewKernelAll').innerHTML = (crashReview.kernel_tail_lines || []).length
        ? (crashReview.kernel_tail_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No final kernel-log lines available before reboot.</li>';
      document.getElementById('crashReviewServiceAll').innerHTML = (crashReview.service_tail_lines || []).length
        ? (crashReview.service_tail_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No recent service journal lines found before the incident.</li>';
      document.getElementById('crashReviewEventsAll').innerHTML = (crashReview.watchdog_event_lines || []).length
        ? (crashReview.watchdog_event_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No watchdog/event entries found before the incident.</li>';
      const updateState = status.update_status || {{}};
      const updateNowButton = document.getElementById('updateNowButton');
      const updateProgress = document.getElementById('updateProgress');
      const targetBuild = updateState.to_build || updateState.from_build || 'unknown';
      const updateMessageEl = document.getElementById('updateMessage');
      let autoHardRefreshPending = false;
      try {{
        autoHardRefreshPending = window.sessionStorage.getItem('watchdogAutoHardRefreshPending') === '1';
      }} catch (_storageErr) {{
        autoHardRefreshPending = false;
      }}
      if (updateState.state === 'running') {{
        if (updateMessageEl) {{
          updateMessageEl.textContent = `Updating to ${{targetBuild}}...`;
        }}
      }} else if (updateState.state === 'ok') {{
        if (updateMessageEl) {{
          updateMessageEl.textContent = `Completed: ${{targetBuild}}`;
        }}
      }} else if (updateState.state === 'failed') {{
        if (updateMessageEl) {{
          updateMessageEl.textContent = `Failed: ${{targetBuild}}`;
        }}
      }} else {{
        if (updateMessageEl) {{
          updateMessageEl.textContent = `Current build: ${{targetBuild}}`;
        }}
      }}
      const updateMetaParts = [];
      if (updateState.state === 'running' && updateState.started_at) {{
        updateMetaParts.push(`Started ${{formatLocalTimestamp(updateState.started_at)}}`);
      }}
      if (updateState.state !== 'running' && updateState.finished_at) {{
        updateMetaParts.push(`Finished ${{formatLocalTimestamp(updateState.finished_at)}}`);
      }}
      const updateMetaEl = document.getElementById('updateMeta');
      if (updateMetaEl) {{
        updateMetaEl.textContent = updateMetaParts.join(' | ');
      }}
      const updateConsole = document.getElementById('updateConsole');
      const updateConsoleLines = status.update_console_lines || [];
      if (updateConsole) {{
        if (updateState.state === 'failed') {{
          updateConsole.style.display = 'block';
          updateConsole.textContent = updateConsoleLines.length ? updateConsoleLines.slice(-10).join('\\n') : 'Update failed with no log lines.';
        }} else {{
          updateConsole.style.display = 'none';
          updateConsole.textContent = '';
        }}
      }}
      if (updateProgress) {{
        updateProgress.style.display = updateState.state === 'running' ? 'block' : 'none';
      }}
      if (updateNowButton) {{
        updateNowButton.style.display = 'inline-block';
        if (updateState.state === 'running') {{
          updateNowButton.textContent = 'Updating...';
          updateNowButton.className = 'secondary status-running';
          updateNowButton.disabled = true;
        }} else if (updateState.state === 'ok') {{
          updateNowButton.textContent = 'Updated';
          updateNowButton.className = 'secondary status-ready';
          updateNowButton.disabled = false;
        }} else if (updateState.state === 'failed') {{
          updateNowButton.textContent = 'Retry update';
          updateNowButton.className = 'secondary status-failed';
          updateNowButton.disabled = false;
        }} else {{
          updateNowButton.textContent = 'Update now';
          updateNowButton.className = 'secondary';
          updateNowButton.disabled = false;
        }}
      }}
      if (updateState.state === 'running') {{
        try {{
          window.sessionStorage.setItem('watchdogAutoHardRefreshPending', '1');
        }} catch (_storageErr) {{
          // ignore storage failures
        }}
      }} else if (updateState.state === 'ok' && autoHardRefreshPending) {{
        try {{
          window.sessionStorage.removeItem('watchdogAutoHardRefreshPending');
        }} catch (_storageErr) {{
          // ignore storage failures
        }}
        window.setTimeout(function () {{
          hardRefreshPage();
        }}, 700);
      }} else if (updateState.state === 'failed') {{
        try {{
          window.sessionStorage.removeItem('watchdogAutoHardRefreshPending');
        }} catch (_storageErr) {{
          // ignore storage failures
        }}
      }}
      const requiredTools = status.required_tools || {{}};
      const missingImportant = requiredTools.missing_important || [];
      const missingRequired = requiredTools.missing_required || [];
      const requiredHeadline = document.getElementById('requiredToolsHeadline');
      requiredHeadline.className = `badge ${{missingRequired.length ? 'danger' : ''}}`;
      requiredHeadline.textContent = missingRequired.length ? 'Missing tools' : 'Tools ready';
      const requiredMissingCount = document.getElementById('requiredToolsMissingCount');
      requiredMissingCount.textContent = `${{missingImportant.length}} missing`;
      requiredMissingCount.style.display = missingImportant.length ? 'inline-block' : 'none';
      document.getElementById('requiredToolsSummary').textContent = missingImportant.length
        ? `Missing: ${{missingImportant.join(', ')}}`
        : 'SMART, EDAC, TeamViewer CLI, and watchdog services look available.';
      document.getElementById('requiredToolsGrid').innerHTML = (requiredTools.items || []).map((item) => `
        <div class="tool-card">
          <div class="tool-head">
            <span class="tool-title">${{item.label || 'Tool'}}</span>
            <span class="tool-status ${{item.ok ? 'ok' : 'bad'}}">${{item.ok ? 'Tick Ready' : 'Cross Missing'}}</span>
          </div>
          <div class="tool-why">${{item.why || ''}}</div>
          <div class="tool-detail">${{item.detail || ''}}</div>
        </div>
      `).join('') || '<div class="timeline-empty">No tool status available yet.</div>';
      const toolsInstallState = requiredTools.install_status || {{}};
      const toolsInstallRow = document.getElementById('toolsInstallRow');
      const toolsInstallLinks = document.getElementById('toolsInstallLinks');
      const installToolsButton = document.getElementById('installToolsButton');
      const toolsBadge = document.getElementById('toolsInstallState');
      toolsBadge.className = `badge ${{toolsInstallState.state === 'running' ? 'warn' : (toolsInstallState.state === 'failed' ? 'danger' : '')}}`;
      toolsBadge.textContent = (toolsInstallState.state || 'idle').toUpperCase();
      document.getElementById('toolsInstallMessage').textContent = toolsInstallState.message || '';
      const toolsMetaParts = [];
      if ((toolsInstallState.packages || []).length) {{
        toolsMetaParts.push((toolsInstallState.packages || []).join(', '));
      }}
      if (toolsInstallState.finished_at) {{
        toolsMetaParts.push(formatLocalTimestamp(toolsInstallState.finished_at));
      }}
      const showInstallRow = missingImportant.length > 0 || toolsInstallState.state === 'running' || toolsInstallState.state === 'failed';
      toolsInstallRow.style.display = showInstallRow ? 'flex' : 'none';
      installToolsButton.style.display = missingImportant.length > 0 ? 'inline-block' : 'none';
      installToolsButton.disabled = toolsInstallState.state === 'running';
      document.getElementById('toolsInstallMeta').textContent = toolsMetaParts.join(' | ');
      document.getElementById('toolsInstallMeta').style.display = toolsMetaParts.length && showInstallRow ? 'block' : 'none';
      toolsInstallLinks.style.display = toolsInstallState.log_path && showInstallRow ? 'flex' : 'none';
      document.getElementById('toolsInstallLogLink').style.display = toolsInstallState.log_path && showInstallRow ? 'inline-block' : 'none';
      const exportState = status.export_status || {{}};
      const quickExport = status.quick_export || {{}};
      const quickExportButton = document.getElementById('quickExportButton');
      const exportDownloadName = exportState.download_archive_name || 'incident pack';
      const exportMetaParts = [];
      if (exportState.message) {{
        exportMetaParts.push(exportState.message);
      }}
      if (exportState.export_label) {{
        exportMetaParts.push(exportState.export_label);
      }}
      if (exportState.folder) {{
        exportMetaParts.push(exportState.folder);
      }}
      if (exportState.since || exportState.until) {{
        exportMetaParts.push(`${{exportState.since || 'unknown'}} to ${{exportState.until || 'unknown'}}`);
      }}
      if (exportState.finished_at) {{
        exportMetaParts.push(formatLocalTimestamp(exportState.finished_at));
      }}
      document.getElementById('exportMeta').textContent = exportMetaParts.join(' | ') || 'No incident export run yet.';
      document.getElementById('quickExportMeta').textContent = quickExport.message || 'Quick export will appear when a reboot/startup point is available.';
      if (quickExportButton) {{
        quickExportButton.style.display = quickExport.available ? 'inline-block' : 'none';
        quickExportButton.disabled = exportState.state === 'running';
        quickExportButton.textContent = exportState.state === 'running' ? `Quick export running: ${{exportDownloadName}}` : 'Quick incident export';
      }}
      document.getElementById('exportConsole').textContent = (status.export_console_lines || []).length
        ? (status.export_console_lines || []).join('\\n')
        : 'No export progress yet.';
      const exportToken = exportState.request_id || exportState.finished_at || exportState.export_label || '';
      const exportArchiveLink = document.getElementById('exportArchiveLink');
      const exportReadmeLink = document.getElementById('exportReadmeLink');
      const exportLogLink = document.getElementById('exportLogLink');
      exportArchiveLink.href = buildAuthedUrl('/download/export-archive', {{ export: exportToken }});
      exportReadmeLink.href = buildAuthedUrl('/download/export-readme', {{ export: exportToken }});
      exportLogLink.href = buildAuthedUrl('/download/export-log', {{ export: exportToken }});
      exportArchiveLink.style.display = exportState.archive ? 'inline-block' : 'none';
      exportReadmeLink.style.display = exportState.folder ? 'inline-block' : 'none';
      exportLogLink.style.display = exportState.log_path ? 'inline-block' : 'none';
      const renderIncidentRows = function (incidentItems) {{
        if (!incidentItems.length) {{
          return '<div class="timeline-empty">No reboot incidents recorded yet.</div>';
        }}
        return incidentItems.map((item) => {{
          const incidentExport = item && item.export_status ? item.export_status : {{}};
          const incidentToken = String((item && item.incident_id) || '');
          const incidentDomId = safeDomId(incidentToken);
          const archiveHref = buildAuthedUrl('/download/incident-archive', {{ id: incidentToken, export: incidentExport.request_id || incidentExport.finished_at || '' }});
          const logHref = buildAuthedUrl('/download/incident-log', {{ id: incidentToken, export: incidentExport.request_id || incidentExport.finished_at || '' }});
          const badgeClass = item && item.watchdog_requested_reboot ? '' : 'warn';
          const classificationLabel = String((item && item.classification) || 'incident').replace(/_/g, ' ');
          const exportButtonLabel = incidentExport.state === 'running'
            ? 'Generating incident pack...'
            : (incidentExport.archive ? 'Download incident pack' : 'Generate + download pack');
          const exportConsole = (item && Array.isArray(item.export_console_lines) && item.export_console_lines.length)
            ? item.export_console_lines.join('\\n')
            : 'No incident pack run yet.';
          const reason = String((item && item.suspected_reason) || 'unknown');
          const kind = String((item && item.kind_label) || 'Incident');
          const reportingText = String((item && item.reporting_text) || 'No incident wording available.');
          const windowLabel = `${{formatLocalTimestamp((item && item.window_since) || '')}} to ${{formatLocalTimestamp((item && item.window_until) || '')}}`;
          return `
            <div class="incident-row">
              <div class="incident-main">
                <div class="incident-head">
                  <div class="incident-title">${{kind}}</div>
                  <span class="badge ${{badgeClass}}">${{classificationLabel}}</span>
                </div>
                <div class="incident-meta">
                  <div class="incident-meta-chip incident-meta-incident">Incident<strong>${{formatLocalTimestamp((item && item.incident_time) || '')}}</strong></div>
                  <div class="incident-meta-chip incident-meta-healthy">Last healthy<strong>${{formatLocalTimestamp((item && item.last_known_healthy_at) || '')}}</strong></div>
                  <div class="incident-meta-chip incident-meta-detected">Detected<strong>${{formatLocalTimestamp((item && item.reboot_detected_at) || '')}}</strong></div>
                  <div class="incident-meta-chip incident-meta-watchdog">Watchdog reboot<strong>${{item && item.watchdog_requested_reboot ? 'Yes' : 'No'}}</strong></div>
                  <div class="incident-meta-chip incident-meta-window">Window<strong>${{windowLabel}}</strong></div>
                </div>
                <div class="incident-reason"><strong>Reason:</strong> ${{reason}}</div>
                <div class="incident-note-line">
                  <span class="badge ${{badgeClass}}">${{classificationLabel}}</span>
                  <span>${{reportingText}}</span>
                </div>
              </div>
              <div class="incident-actions">
                <button id="incidentExportButton_${{incidentDomId}}" data-incident-id="${{incidentToken}}" class="secondary ${{incidentExport.state === 'running' ? 'status-running' : (incidentExport.state === 'failed' ? 'status-failed' : '')}}" onclick="runIncidentExport(this.dataset.incidentId)" ${{incidentExport.state === 'running' ? 'disabled' : ''}}>${{exportButtonLabel}}</button>
                <a id="incidentArchiveLink_${{incidentDomId}}" class="link-btn" href="${{archiveHref}}" style="display:${{incidentExport.archive ? 'inline-block' : 'none'}}">Download pack</a>
                <a id="incidentLogLink_${{incidentDomId}}" class="link-btn" href="${{logHref}}" style="display:${{incidentExport.log_path ? 'inline-block' : 'none'}}">Download log</a>
                <div id="incidentExportHint_${{incidentDomId}}" class="hint">${{incidentExport.state === 'running' ? 'Generating incident pack...' : (incidentExport.archive ? 'Incident pack ready to download.' : 'Press generate to create a pack.')}}</div>
              </div>
              <details class="incident-more">
                <summary>Show incident notes and export log</summary>
                <div class="incident-console">${{exportConsole}}</div>
              </details>
            </div>
          `;
        }}).join('');
      }};
      let overviewIncidentRowsHtml = '<div class="timeline-empty">No reboot incidents recorded yet.</div>';
      let investigationIncidentRowsHtml = '<div class="timeline-empty">No reboot incidents recorded yet.</div>';
      try {{
        const incidentItems = Array.isArray(status.incidents) ? status.incidents : [];
        overviewIncidentRowsHtml = renderIncidentRows(incidentItems.slice(0, 1));
        investigationIncidentRowsHtml = renderIncidentRows(incidentItems);
      }} catch (incidentRenderError) {{
        const incidentErrorHtml = `<div class="timeline-empty">Failed to render incidents: ${{incidentRenderError && incidentRenderError.message ? incidentRenderError.message : 'unknown error'}}</div>`;
        overviewIncidentRowsHtml = incidentErrorHtml;
        investigationIncidentRowsHtml = incidentErrorHtml;
      }}
      const incidentsList = document.getElementById('incidentsList');
      if (incidentsList) {{
        incidentsList.innerHTML = overviewIncidentRowsHtml;
      }}
      const incidentsInvestigationList = document.getElementById('incidentsInvestigationList');
      if (incidentsInvestigationList) {{
        incidentsInvestigationList.innerHTML = investigationIncidentRowsHtml;
      }}

      const auditDownloadLink = document.getElementById('auditDownloadLink');
      if (auditDownloadLink) {{
        auditDownloadLink.href = buildAuthedUrl('/download/audit-report', {{}});
      }}
      try {{
        const auditMetrics = (status.state && status.state.last_metrics) || {{}};
        const hardwareIdentity = status.hardware_identity || {{}};
        const buildInfo = status.build_info || {{}};
        const teamviewer = status.teamviewer || {{}};
        const hardwareReview = status.hardware_review || {{}};
        const systemProfile = status.system_profile || {{}};
        const missingImportantTools = ((status.required_tools || {{}}).missing_important) || [];
        const auditCheckedAt = document.getElementById('auditCheckedAt');
        if (auditCheckedAt) {{
          auditCheckedAt.textContent = formatLocalTimestamp(hardwareReview.checked_at || '') || 'unknown';
        }}
        const auditBuildBadge = document.getElementById('auditBuildBadge');
        if (auditBuildBadge) {{
          auditBuildBadge.textContent = `Build ${{buildInfo.git_commit || 'unknown'}}`;
        }}
        const auditToolsBadge = document.getElementById('auditToolsBadge');
        if (auditToolsBadge) {{
          auditToolsBadge.className = `badge ${{missingImportantTools.length ? 'warn' : ''}}`;
          auditToolsBadge.textContent = missingImportantTools.length ? `${{missingImportantTools.length}} tools missing` : 'Tools ready';
        }}
        const auditDiskBadge = document.getElementById('auditDiskBadge');
        if (auditDiskBadge) {{
          const rootDiskRisk = Number(auditMetrics.root_disk_percent || 0);
          auditDiskBadge.className = `badge ${{rootDiskRisk >= 95 ? 'danger' : ''}}`;
          auditDiskBadge.textContent = `Root disk ${{fallback(auditMetrics.root_disk_percent, 'unknown')}}%`;
        }}
        const auditHardwareIdentity = document.getElementById('auditHardwareIdentity');
        if (auditHardwareIdentity) {{
          auditHardwareIdentity.innerHTML = [
            `<li><strong>Vendor:</strong> ${{hardwareIdentity.vendor || 'unknown'}}</li>`,
            `<li><strong>Model:</strong> ${{hardwareIdentity.model || 'unknown'}}</li>`,
            `<li><strong>Serial:</strong> ${{hardwareIdentity.serial || 'unknown'}}</li>`,
            `<li><strong>Board:</strong> ${{hardwareIdentity.board_name || 'unknown'}}</li>`,
            `<li><strong>BIOS:</strong> ${{[hardwareIdentity.bios_vendor, hardwareIdentity.bios_version].filter(Boolean).join(' ') || 'unknown'}}</li>`,
            `<li><strong>BIOS date:</strong> ${{hardwareIdentity.bios_date || 'unknown'}}</li>`,
            `<li><strong>Build:</strong> ${{buildInfo.git_commit || 'unknown'}}</li>`,
            `<li><strong>Deployed:</strong> ${{formatLocalTimestamp(buildInfo.deployed_at || '') || 'unknown'}}</li>`
          ].join('');
        }}
        const auditMemoryThermal = document.getElementById('auditMemoryThermal');
        if (auditMemoryThermal) {{
          const thermalSummary = hardwareReview.thermal || {{}};
          const topSensors = Array.isArray(thermalSummary.top_sensors) ? thermalSummary.top_sensors : [];
          auditMemoryThermal.innerHTML = [
            `<li><strong>Memory used:</strong> ${{fallback(auditMetrics.mem_percent, 'unknown')}}%</li>`,
            `<li><strong>MemAvailable:</strong> ${{fallback(auditMetrics.mem_available_mb, 'unknown')}} MB</li>`,
            `<li><strong>Cached:</strong> ${{fallback(auditMetrics.mem_cached_mb, 'unknown')}} MB</li>`,
            `<li><strong>Temperature:</strong> ${{fallback(auditMetrics.temperature_c, 'unknown')}} C</li>`,
            `<li><strong>Temperature max:</strong> ${{fallback(thermalSummary.max_c, 'unknown')}} C</li>`,
            `<li><strong>Thermal zones:</strong> ${{fallback(thermalSummary.zone_count, topSensors.length || 0)}}</li>`,
            `<li><strong>Top sensors:</strong> ${{topSensors.length ? topSensors.join(' | ') : 'No thermal sensors reported'}}</li>`
          ].join('');
        }}
        const auditFindings = document.getElementById('auditFindings');
        if (auditFindings) {{
          const findingLines = [];
          if (missingImportantTools.length) {{
            findingLines.push(`Important tools missing: ${{missingImportantTools.join(', ')}}`);
          }}
          if (teamviewer.summary) {{
            findingLines.push(`TeamViewer: ${{teamviewer.summary}}`);
          }}
          if (systemProfile.igc_hint) {{
            findingLines.push(systemProfile.igc_hint);
          }}
          auditFindings.innerHTML = (findingLines.length ? findingLines : ['No extra audit notes recorded.']).map(function (line) {{ return `<li>${{line}}</li>`; }}).join('');
        }}
        const auditWarnings = document.getElementById('auditWarnings');
        if (auditWarnings) {{
          auditWarnings.innerHTML = (hardwareReview.warnings || []).length
            ? (hardwareReview.warnings || []).map(function (line) {{ return `<li>${{line}}</li>`; }}).join('')
            : '<li>No warning lines captured.</li>';
        }}
        const auditSmart = document.getElementById('auditSmart');
        if (auditSmart) {{
          auditSmart.innerHTML = (hardwareReview.smart || []).length
            ? (hardwareReview.smart || []).map(function (item) {{ return `<div><strong>${{item.device || 'disk'}}</strong><br><code>${{item.summary || ''}}</code></div>`; }}).join('')
            : '<div><strong>Storage</strong><br><code>No SMART summary captured.</code></div>';
        }}
        const auditPstore = document.getElementById('auditPstore');
        if (auditPstore) {{
          auditPstore.innerHTML = (hardwareReview.pstore_entries || []).length
            ? (hardwareReview.pstore_entries || []).map(function (line) {{ return `<li>${{line}}</li>`; }}).join('')
            : '<li>No pstore entries present.</li>';
        }}
        const auditKernelNic = document.getElementById('auditKernelNic');
        if (auditKernelNic) {{
          const nicDetails = [
            `<li><strong>OS:</strong> ${{systemProfile.os_name || 'unknown'}}</li>`,
            `<li><strong>Kernel release:</strong> ${{systemProfile.kernel_release || 'unknown'}}</li>`,
            `<li><strong>Kernel full:</strong> ${{systemProfile.kernel_full || 'unknown'}}</li>`,
            `<li><strong>Default interface:</strong> ${{systemProfile.default_interface || 'unknown'}}</li>`,
            `<li><strong>Driver:</strong> ${{systemProfile.driver || 'unknown'}}</li>`,
            `<li><strong>Driver version:</strong> ${{systemProfile.driver_version || 'unknown'}}</li>`,
            `<li><strong>Firmware:</strong> ${{systemProfile.firmware_version || 'unknown'}}</li>`,
            `<li><strong>Bus info:</strong> ${{systemProfile.bus_info || 'unknown'}}</li>`,
            `<li><strong>PCI:</strong> ${{systemProfile.nic_lspci || 'NIC PCI information not available.'}}</li>`,
            `<li><strong>EEE:</strong> ${{systemProfile.eee || 'EEE details not available.'}}</li>`
          ];
          if (systemProfile.igc_hint) {{
            nicDetails.push(`<li><strong>Intel I225 / igc note:</strong> ${{systemProfile.igc_hint}}</li>`);
          }}
          auditKernelNic.innerHTML = nicDetails.join('');
        }}
        const auditDriveInventory = document.getElementById('auditDriveInventory');
        if (auditDriveInventory) {{
          const drives = Array.isArray(systemProfile.drives) ? systemProfile.drives : [];
          auditDriveInventory.innerHTML = drives.length
            ? drives.map(function (drive) {{
                const children = Array.isArray(drive.children) ? drive.children : [];
                const mountSummary = children.map(function (child) {{
                  return `${{child.name || 'part'}}:${{child.mountpoint || 'unmounted'}}`;
                }}).join(' | ');
                let line = `<strong>${{drive.kname || drive.name || 'disk'}}</strong> | ${{drive.model || 'unknown model'}} | ${{drive.size || 'unknown size'}} | ${{drive.transport || 'unknown transport'}}`;
                if (mountSummary) {{
                  line += ` | ${{mountSummary}}`;
                }}
                return `<li>${{line}}</li>`;
              }}).join('')
            : '<li>No drive inventory available.</li>';
        }}
        const auditHighlights = document.getElementById('auditHighlights');
        if (auditHighlights) {{
          const rootDiskRisk = Number(auditMetrics.root_disk_percent || 0);
          const missingTools = ((status.required_tools || {{}}).missing_important) || [];
          const highlightLines = [
            `Kernel / NIC: ${{systemProfile.kernel_release || 'unknown'}} on ${{systemProfile.default_interface || 'unknown'}} using ${{systemProfile.driver || 'unknown'}}`,
            `Root disk pressure: ${{isNaN(rootDiskRisk) ? 'unknown' : `${{rootDiskRisk}}% used`}}${{rootDiskRisk >= 95 ? ' - live risk' : ''}}`,
            `Required tools: ${{missingTools.length ? `missing ${{missingTools.join(', ')}}` : 'all key tools ready'}}`,
            `TeamViewer: ${{teamviewer.summary || 'unknown'}}`,
            `Latest metrics sample: ${{formatLocalTimestamp((auditMetrics || {{}}).ts || '')}}`,
          ];
          if (systemProfile.igc_hint) {{
            highlightLines.push(systemProfile.igc_hint);
          }}
          auditHighlights.innerHTML = highlightLines.map(function (line) {{ return `<li>${{line}}</li>`; }}).join('');
        }}
        const auditPathsList = document.getElementById('auditPathsList');
        if (auditPathsList) {{
          const importantPaths = status.paths || {{}};
          const pathEntries = [
            ['Config', importantPaths.config],
            ['State', importantPaths.state],
            ['Metrics', importantPaths.metrics],
            ['Build info', importantPaths.build_info],
            ['Tools install status', importantPaths.tools_install_status],
            ['Speed test status', importantPaths.speedtest_status],
          ].filter(function (entry) {{ return entry[1]; }});
          auditPathsList.innerHTML = pathEntries.map(function (entry) {{
            return `<li><strong>${{entry[0]}}</strong><code>${{entry[1]}}</code></li>`;
          }}).join('');
        }}
        const auditNotes = document.getElementById('auditNotes');
        if (auditNotes) {{
          const notes = [];
          notes.push(`Monitoring state: ${{(status.state || {{}}).monitoring_state || 'unknown'}}`);
          notes.push(`Last check: ${{formatLocalTimestamp((status.state || {{}}).last_check_at || '')}}`);
          notes.push(`Last healthy: ${{formatLocalTimestamp((status.state || {{}}).last_healthy_at || '')}}`);
          notes.push(`Current build: ${{buildInfo.git_commit || 'unknown'}}`);
          auditNotes.innerHTML = notes.map(function (line) {{ return `<li>${{line}}</li>`; }}).join('');
        }}
      }} catch (auditRenderError) {{
        const auditError = auditRenderError && auditRenderError.message ? auditRenderError.message : 'Audit render failed';
        ['auditHardwareIdentity', 'auditMemoryThermal', 'auditFindings', 'auditWarnings', 'auditPstore', 'auditKernelNic', 'auditDriveInventory', 'auditHighlights', 'auditPathsList', 'auditNotes'].forEach(function (id) {{
          const el = document.getElementById(id);
          if (el) {{
            el.innerHTML = `<li>Audit render failed: ${{auditError}}</li>`;
          }}
        }});
      }}

      const overviewGrid = document.querySelector('.overview-grid');
      if (overviewGrid) {{
        overviewGrid.innerHTML = `
          <section class="stat-card"><div class="stat-label">Current state</div><div class="stat-value">${{status.state.fault_active ? 'Fault' : 'Healthy'}}</div></section>
          <section class="stat-card"><div class="stat-label">Watchdog reboot commands</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.watchdog) || 0}}</div></section>
          <section class="stat-card"><div class="stat-label">Detected reboots</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.detected) || 0}}</div></section>
          <section class="stat-card"><div class="stat-label">Unexpected reboots</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.unexpected) || 0}}</div></section>
          <section class="stat-card"><div class="stat-label">Last reboot reason</div><div class="stat-value" style="font-size:1rem;">${{status.state.last_reboot_reason || 'none'}}</div></section>
          <section class="stat-card"><div class="stat-label">Last startup</div><div class="stat-value" style="font-size:1rem;">${{formatLocalTimestamp(status.state.last_startup_at || '')}}</div></section>
          <section class="stat-card"><div class="stat-label">Hardware ID</div><div class="stat-value" style="font-size:1rem;">${{(status.hardware_identity && status.hardware_identity.serial) || 'unknown'}}</div></section>
          <section class="stat-card"><div class="stat-label">Build</div><div class="stat-value" style="font-size:1rem;">${{(status.build_info && status.build_info.git_commit) || 'unknown'}}</div></section>
        `;
      }}

      const heroMain = document.querySelector('.hero-main');
      heroMain.innerHTML = `
        <div class="stat-label">Current diagnosis</div>
        <div class="hero-title">${{status.diagnosis.title}}</div>
        <div class="hero-detail">${{status.diagnosis.detail}}</div>
        <div class="status-strip">
          <span class="badge ${{status.state.fault_active ? 'danger' : ''}}">${{status.state.fault_active ? 'Fault active' : 'Healthy now'}}</span>
          <span class="badge ${{status.reboot_counts && status.reboot_counts.unexpected ? 'warn' : ''}}">Unexpected reboots: ${{(status.reboot_counts && status.reboot_counts.unexpected) || 0}}</span>
          <span class="badge">Detected reboots: ${{(status.reboot_counts && status.reboot_counts.detected) || 0}}</span>
          <span class="badge">Watchdog commands: ${{(status.reboot_counts && status.reboot_counts.watchdog) || 0}}</span>
        </div>
      `;
    }}

    function drawMetrics(points, hoverIndex = null) {{
      const canvas = document.getElementById('metricsChart');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#0f1820';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const pad = 40;
      const chartWidth = canvas.width - pad * 2;
      const chartHeight = canvas.height - pad * 2;

      ctx.strokeStyle = '#29404f';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i += 1) {{
        const y = pad + (chartHeight / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(pad + chartWidth, y);
        ctx.stroke();
      }}

      ctx.fillStyle = '#8ea5b9';
      ctx.font = '12px Segoe UI';
      for (let i = 0; i <= 4; i += 1) {{
        const value = 100 - (25 * i);
        const y = pad + (chartHeight / 4) * i + 4;
        ctx.fillText(`${{value}}%`, 6, y);
      }}

      if (!points.length) {{
        ctx.fillStyle = '#8ea5b9';
        ctx.font = '16px Segoe UI';
        ctx.fillText('No metrics collected yet.', pad, canvas.height / 2);
        return;
      }}

      const series = [
        {{ key: 'cpu_percent', color: '#67a8db', label: 'CPU' }},
        {{ key: 'mem_percent', color: '#e07b7b', label: 'Memory' }},
        {{ key: 'root_disk_percent', color: '#7ab08a', label: 'Root disk' }},
        {{ key: 'recording_disk_percent', color: '#d4a34a', label: 'Recording disk' }},
        {{ key: 'temperature_c', color: '#ff9f6e', label: 'Temp C' }}
      ];

      const epochs = points.map((point) => Date.parse(point.ts || '')).filter((epoch) => Number.isFinite(epoch));
      const firstEpoch = epochs.length ? epochs[0] : Date.now();
      const lastEpoch = epochs.length ? epochs[epochs.length - 1] : (firstEpoch + 1);
      const spanEpoch = Math.max(1, lastEpoch - firstEpoch);
      const xForEpoch = (epoch) => pad + (((epoch - firstEpoch) / spanEpoch) * chartWidth);
      const yFor = (value) => pad + chartHeight - ((Math.max(0, Math.min(100, Number(value || 0))) / 100) * chartHeight);

      series.forEach((line, idx) => {{
        ctx.strokeStyle = line.color;
        ctx.lineWidth = 2;
        let started = false;
        points.forEach((point) => {{
          const pointEpoch = Date.parse(point.ts || '');
          const value = point[line.key];
          if (!Number.isFinite(pointEpoch) || point.gap || value === null || value === undefined || Number.isNaN(Number(value))) {{
            if (started) {{
              ctx.stroke();
              started = false;
            }}
            return;
          }}
          const x = xForEpoch(pointEpoch);
          const y = yFor(value);
          if (!started) {{
            ctx.beginPath();
            ctx.moveTo(x, y);
            started = true;
          }} else {{
            ctx.lineTo(x, y);
          }}
        }});
        if (started) {{
          ctx.stroke();
        }}
        ctx.fillStyle = line.color;
        ctx.fillRect(pad + idx * 140, 10, 12, 12);
        ctx.fillStyle = '#d8e6f1';
        ctx.fillText(line.label, pad + idx * 140 + 18, 20);
      }});

      latestMetricEvents.forEach((event, index) => {{
        const eventEpoch = Date.parse(event.ts || '');
        if (!Number.isFinite(eventEpoch)) {{
          return;
        }}
        const x = xForEpoch(eventEpoch);
        if (x < pad || x > pad + chartWidth) {{
          return;
        }}
        const markerColor = event.kind === 'command' ? '#d4a34a' : (event.kind === 'detected' ? '#e07b7b' : '#8ea5b9');
        ctx.strokeStyle = markerColor;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, pad);
        ctx.lineTo(x, pad + chartHeight);
        ctx.stroke();
        ctx.fillStyle = markerColor;
        ctx.beginPath();
        ctx.arc(x, pad + 8 + (index % 3) * 8, 3, 0, Math.PI * 2);
        ctx.fill();
      }});

      if (hoverIndex !== null && points[hoverIndex]) {{
        const hoverEpoch = Date.parse(points[hoverIndex].ts || '');
        if (Number.isFinite(hoverEpoch)) {{
          const x = xForEpoch(hoverEpoch);
          ctx.strokeStyle = '#8ea5b9';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(x, pad);
          ctx.lineTo(x, pad + chartHeight);
          ctx.stroke();
        }}
      }}
    }}

    function updateEventLegend() {{
      const counts = latestMetricEvents.reduce((acc, item) => {{
        const kind = item.kind || 'other';
        acc[kind] = (acc[kind] || 0) + 1;
        return acc;
      }}, {{}});
      document.getElementById('legendTemp').innerHTML = '<span class="chart-event-dot temp"></span>Temperature';
      document.getElementById('legendGap').innerHTML = '<span class="chart-event-dot note"></span>No samples / watchdog offline';
      document.getElementById('legendCommand').innerHTML = '<span class="chart-event-dot command"></span>Watchdog reboot command (' + (counts.command || 0) + ')';
      document.getElementById('legendDetected').innerHTML = '<span class="chart-event-dot detected"></span>Detected or unexpected reboot (' + (counts.detected || 0) + ')';
      document.getElementById('legendNote').innerHTML = '<span class="chart-event-dot note"></span>Reboot counts acknowledged (' + (counts.note || 0) + ')';
    }}

    async function fetchStatus() {{
      try {{
        const response = await fetch('/api/status' + authQuery, {{ cache: 'no-store' }});
        if (!response.ok) {{
          throw new Error(`status http ${{response.status}}`);
        }}
        safeRender(await response.json());
      }} catch (error) {{
        const message = error && error.message ? error.message : String(error || 'status fetch failed');
        const incidentsList = document.getElementById('incidentsList');
        if (incidentsList) {{
          incidentsList.innerHTML = `<div class="timeline-empty">Status refresh failed: ${{message}}</div>`;
        }}
        const incidentsInvestigationList = document.getElementById('incidentsInvestigationList');
        if (incidentsInvestigationList) {{
          incidentsInvestigationList.innerHTML = `<div class="timeline-empty">Status refresh failed: ${{message}}</div>`;
        }}
      }}
    }}

    function setMetricRange(hours) {{
      metricsRangeHours = hours;
      document.getElementById('range1hBtn').classList.toggle('active', hours === 1);
      document.getElementById('range24hBtn').classList.toggle('active', hours === 24);
      document.getElementById('range168hBtn').classList.toggle('active', hours === 168);
      document.getElementById('metricsTitle').textContent = metricRangeLabel(hours);
      fetchMetrics();
    }}

    async function fetchMetrics() {{
      try {{
        const separator = authQuery ? '&' : '?';
        const response = await fetch(`/api/metrics${{authQuery}}${{separator}}hours=${{metricsRangeHours}}`, {{ cache: 'no-store' }});
        if (!response.ok) {{
          throw new Error(`metrics http ${{response.status}}`);
        }}
        const payload = await response.json();
        latestMetrics = payload.points || [];
        latestMetricEvents = payload.events || [];
        updateEventLegend();
        drawMetrics(latestMetrics);
      }} catch (error) {{
        latestMetrics = [];
        latestMetricEvents = [];
        updateEventLegend();
        drawMetrics([]);
        const hover = document.getElementById('metricsHover');
        if (hover) {{
          const message = error && error.message ? error.message : String(error || 'metrics fetch failed');
          hover.textContent = `PC stats refresh failed: ${{message}}`;
        }}
      }}
    }}

    async function saveSettings() {{
      await fetch('/api/config' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          monitoring_enabled: document.getElementById('monitoring_enabled').checked,
          app_restart_enabled: document.getElementById('app_restart_enabled').checked,
          restart_network_before_reboot: document.getElementById('restart_network_before_reboot').checked,
          reboot_enabled: document.getElementById('reboot_enabled').checked
        }})
      }});
      await fetchStatus();
    }}

    function parseLines(id) {{
      return document.getElementById(id).value
        .split('\\n')
        .map((line) => line.trim())
        .filter(Boolean);
    }}

    function parseTcpTargets() {{
      return parseLines('tcp_targets')
        .map((line) => {{
          const lastColon = line.lastIndexOf(':');
          if (lastColon <= 0 || lastColon === line.length - 1) {{
            throw new Error(`Invalid TCP target: ${{line}}`);
          }}
          const host = line.slice(0, lastColon).trim();
          const port = Number(line.slice(lastColon + 1).trim());
          if (!host || !Number.isFinite(port) || port < 1 || port > 65535) {{
            throw new Error(`Invalid TCP target: ${{line}}`);
          }}
          return {{ host, port }};
        }});
    }}

    async function saveConfig() {{
      const payload = {{
        monitoring_enabled: document.getElementById('monitoring_enabled').checked,
        app_restart_enabled: document.getElementById('app_restart_enabled').checked,
        restart_network_before_reboot: document.getElementById('restart_network_before_reboot').checked,
        reboot_enabled: document.getElementById('reboot_enabled').checked,
        gateway_name: document.getElementById('gateway_name').value.trim(),
        app_match: document.getElementById('app_match').value.trim(),
        app_start_command: document.getElementById('app_start_command').value.trim(),
        base_reboot_timeout_seconds: Number(document.getElementById('base_reboot_timeout_seconds').value || 300),
        max_reboot_timeout_seconds: Number(document.getElementById('max_reboot_timeout_seconds').value || 3600),
        reboot_backoff_multiplier: Number(document.getElementById('reboot_backoff_multiplier').value || 2.0),
        check_interval_seconds: Number(document.getElementById('check_interval_seconds').value || 30),
        network_restart_cooldown_seconds: Number(document.getElementById('network_restart_cooldown_seconds').value || 600),
        post_action_settle_seconds: Number(document.getElementById('post_action_settle_seconds').value || 20),
        web_bind: document.getElementById('web_bind').value.trim(),
        web_port: Number(document.getElementById('web_port').value || 80),
        web_token: document.getElementById('web_token').value.trim(),
        network_restart_command: document.getElementById('network_restart_command').value.trim(),
        teamviewer_id_command: document.getElementById('teamviewer_id_command').value.trim(),
        teamviewer_password_reset_command: document.getElementById('teamviewer_password_reset_command').value.trim(),
        teamviewer_start_command: document.getElementById('teamviewer_start_command').value.trim(),
        teamviewer_restart_command: document.getElementById('teamviewer_restart_command').value.trim(),
        hik_enabled: document.getElementById('hik_enabled').checked,
        hik_scheme: document.getElementById('hik_scheme').value.trim(),
        hik_host: document.getElementById('hik_host').value.trim(),
        hik_username: document.getElementById('hik_username').value.trim(),
        hik_password: document.getElementById('hik_password').value.trim(),
        hik_channel: Number(document.getElementById('hik_channel').value || 1),
        hik_people_count_result_path: document.getElementById('hik_people_count_result_path').value.trim(),
        hik_people_count_capabilities_path: document.getElementById('hik_people_count_capabilities_path').value.trim(),
        internet_hosts: parseLines('internet_hosts'),
        systemd_services: parseLines('systemd_services'),
        tcp_targets: parseTcpTargets()
      }};
      await fetch('/api/config' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      await fetchStatus();
    }}

    async function saveHikConfig() {{
      await fetch('/api/config' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          hik_enabled: document.getElementById('hik_enabled').checked,
          hik_scheme: document.getElementById('hik_scheme').value.trim(),
          hik_host: document.getElementById('hik_host').value.trim(),
          hik_username: document.getElementById('hik_username').value.trim(),
          hik_password: document.getElementById('hik_password').value.trim(),
          hik_channel: Number(document.getElementById('hik_channel').value || 1),
          hik_people_count_result_path: document.getElementById('hik_people_count_result_path').value.trim(),
          hik_people_count_capabilities_path: document.getElementById('hik_people_count_capabilities_path').value.trim()
        }})
      }});
      await fetchStatus();
    }}

    async function runHikProbe() {{
      const hikMessage = document.getElementById('hikMessage');
      const hikState = document.getElementById('hikState');
      const hikMeta = document.getElementById('hikMeta');
      const hikProbeConsole = document.getElementById('hikProbeConsole');
      const hikProbeConsoleRaw = document.getElementById('hikProbeConsoleRaw');
      if (hikMessage) {{
        hikMessage.textContent = 'Running Hik probe...';
      }}
      if (hikState) {{
        hikState.className = 'badge warn';
        hikState.textContent = 'RUNNING';
      }}
      if (hikMeta) {{
        hikMeta.textContent = `Probe requested ${{formatLocalTimestamp(new Date().toISOString())}}`;
      }}
      if (hikProbeConsole) {{
        hikProbeConsole.textContent = `[${{new Date().toISOString()}}] Starting Hik probe...\\nWaiting for response...`;
      }}
      if (hikProbeConsoleRaw) {{
        hikProbeConsoleRaw.textContent = `[${{new Date().toISOString()}}] Starting Hik probe...\\nWaiting for response...`;
      }}
      try {{
        const response = await fetch('/api/action' + authQuery, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ action: 'hik_probe' }})
        }});
        const payload = await response.json().catch(() => ({{ message: 'Hik probe failed.' }}));
        if (hikProbeConsole && payload && typeof payload === 'object') {{
          const lines = [];
          lines.push(`[${{payload.checked_at || new Date().toISOString()}}] state=${{payload.state || 'unknown'}}`);
          lines.push(`message: ${{payload.message || 'none'}}`);
          lines.push(`deviceInfo: ok=${{payload.device_info_ok ? 'true' : 'false'}} status=${{payload.device_info_status || 0}} model=${{payload.device_model || 'unknown'}}`);
          for (const attempt of (payload.capabilities_attempts || [])) {{
            lines.push(`capabilities: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
          }}
          for (const attempt of (payload.result_attempts || [])) {{
            lines.push(`result: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
          }}
          hikProbeConsole.textContent = lines.join('\\n');
        }}
        if (hikProbeConsoleRaw && payload && typeof payload === 'object') {{
          const lines = [];
          lines.push(`[${{payload.checked_at || new Date().toISOString()}}] state=${{payload.state || 'unknown'}}`);
          lines.push(`message: ${{payload.message || 'none'}}`);
          lines.push(`deviceInfo: ok=${{payload.device_info_ok ? 'true' : 'false'}} status=${{payload.device_info_status || 0}} model=${{payload.device_model || 'unknown'}}`);
          for (const attempt of (payload.capabilities_attempts || [])) {{
            lines.push(`capabilities: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
          }}
          for (const attempt of (payload.result_attempts || [])) {{
            lines.push(`result: ${{attempt.ok ? 'OK' : 'FAIL'}} [${{attempt.status || 0}}] ${{attempt.path || ''}}`);
          }}
          hikProbeConsoleRaw.textContent = lines.join('\\n');
        }}
        if (payload && typeof payload === 'object') {{
          if (payload.state) {{
            if (hikState) {{
              hikState.textContent = String(payload.state).toUpperCase();
              hikState.className = `badge ${{payload.state === 'failed' ? 'danger' : (payload.state === 'running' || payload.state === 'idle' ? 'warn' : '')}}`;
            }}
          }}
          if (payload.message) {{
            if (hikMessage) {{
              hikMessage.textContent = payload.message;
            }}
          }}
          if (payload.checked_at) {{
            if (hikMeta) {{
              hikMeta.textContent = `Probe #${{payload.probe_sequence || '?'}} | Last checked ${{formatLocalTimestamp(payload.checked_at)}}`;
            }}
          }}
        }}
        if (!response.ok) {{
          if (hikMessage) {{
            hikMessage.textContent = payload.message || 'Hik probe failed.';
          }}
        }}
      }} catch (_error) {{
        if (hikMessage) {{
          hikMessage.textContent = 'Hik probe request failed before completion.';
        }}
        if (hikProbeConsole) {{
          hikProbeConsole.textContent = `[${{new Date().toISOString()}}] Probe request failed before completion.`;
        }}
        if (hikProbeConsoleRaw) {{
          hikProbeConsoleRaw.textContent = `[${{new Date().toISOString()}}] Probe request failed before completion.`;
        }}
      }}
      await fetchStatus();
    }}

    async function runAction(action, extraPayload = {{}}) {{
      pinCurrentTabInUrl();
      if (action === 'update_watchdog') {{
        try {{
          window.sessionStorage.setItem('watchdogAutoHardRefreshPending', '1');
        }} catch (_storageErr) {{
          // ignore storage failures
        }}
        const updateNowButton = document.getElementById('updateNowButton');
        const updateMessage = document.getElementById('updateMessage');
        const updateMeta = document.getElementById('updateMeta');
        const updateProgress = document.getElementById('updateProgress');
        if (updateNowButton) {{
          updateNowButton.textContent = 'Updating...';
          updateNowButton.className = 'secondary status-running';
          updateNowButton.disabled = true;
        }}
        if (updateMessage) {{
          updateMessage.textContent = 'Starting update...';
        }}
        if (updateMeta) {{
          updateMeta.textContent = '';
        }}
        if (updateProgress) {{
          updateProgress.style.display = 'block';
        }}
      }}
      const requestPayload = Object.assign({{ action: action }}, extraPayload || {{}});
      const response = await fetch('/api/action' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(requestPayload)
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Action failed.' }}));
        if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {{
          document.getElementById('teamviewerResetResult').textContent = payload.detail ? `${{payload.message}} (${{payload.detail}})` : (payload.message || 'Action failed.');
        }}
        alert(payload.message || 'Action failed.');
        return;
      }}
      const payload = await response.json().catch(() => ({{ ok: true }}));
      if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {{
        const detail = payload.password ? `New password: ${{payload.password}}` : (payload.message || 'TeamViewer action complete.');
        document.getElementById('teamviewerResetResult').textContent = detail;
      }}
      if (action === 'update_watchdog' && payload && payload.status) {{
        const updateNowButton = document.getElementById('updateNowButton');
        const updateMessage = document.getElementById('updateMessage');
        const updateMeta = document.getElementById('updateMeta');
        const updateProgress = document.getElementById('updateProgress');
        const startedAt = payload.status.started_at ? formatLocalTimestamp(payload.status.started_at) : '';
        const targetBuild = payload.status.to_build || payload.status.from_build || 'unknown';
        if (updateNowButton) {{
          updateNowButton.textContent = payload.status.state === 'running' ? 'Updating...' : 'Update now';
          updateNowButton.className = payload.status.state === 'running' ? 'secondary status-running' : 'secondary';
          updateNowButton.disabled = payload.status.state === 'running';
        }}
        if (updateMessage) {{
          updateMessage.textContent = payload.status.state === 'running' ? `Updating to ${{targetBuild}}...` : (payload.message || 'Update requested.');
        }}
        if (updateMeta) {{
          updateMeta.textContent = startedAt ? `Started ${{startedAt}}` : '';
        }}
        if (updateProgress) {{
          updateProgress.style.display = payload.status.state === 'running' ? 'block' : 'none';
        }}
      }}
      await fetchStatus();
    }}

    async function setTeamviewerPassword() {{
      const password = document.getElementById('teamviewerManualPassword').value.trim();
      await runAction('reset_teamviewer_password', {{ password }});
    }}

    async function quickExportIncident() {{
      pinCurrentTabInUrl();
      const response = await fetch('/api/action' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ action: 'quick_export' }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Quick export failed.' }}));
        alert(payload.message || 'Quick export failed.');
        return;
      }}
      const payload = await response.json().catch(() => ({{ ok: true }}));
      if (payload && payload.message) {{
        document.getElementById('quickExportMeta').textContent = payload.message;
      }}
      await fetchStatus();
    }}

    async function runIncidentExport(incidentId) {{
      pinCurrentTabInUrl();
      const incidentDomId = safeDomId(incidentId);
      const button = document.getElementById(`incidentExportButton_${{incidentDomId}}`);
      const hint = document.getElementById(`incidentExportHint_${{incidentDomId}}`);
      const archiveLinkBefore = document.getElementById(`incidentArchiveLink_${{incidentDomId}}`);
      if (archiveLinkBefore && archiveLinkBefore.style.display !== 'none' && archiveLinkBefore.href) {{
        archiveLinkBefore.click();
        return;
      }}
      if (button) {{
        button.textContent = 'Starting...';
        button.className = 'secondary status-running';
        button.disabled = true;
      }}
      if (hint) {{
        hint.textContent = 'Starting incident pack generation...';
      }}
      const response = await fetch('/api/action' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ action: 'incident_export', incident_id: incidentId }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Incident export failed.' }}));
        if (button) {{
          button.textContent = 'Generate incident pack';
          button.className = 'secondary status-failed';
          button.disabled = false;
        }}
        if (hint) {{
          hint.textContent = payload.message || 'Incident export failed.';
        }}
        alert(payload.message || 'Incident export failed.');
        return;
      }}
      let ready = false;
      let archiveHref = '';
      let finalMessage = '';
      const startedAt = Date.now();
      for (let index = 0; index < 60; index += 1) {{
        try {{
          const statusResponse = await fetch('/api/status' + authQuery, {{ cache: 'no-store' }});
          const statusPayload = await statusResponse.json();
          safeRender(statusPayload);
          const exportStatus = findIncidentExportStatus(statusPayload, incidentId);
          if (exportStatus && exportStatus.archive) {{
            ready = true;
            archiveHref = buildAuthedUrl('/download/incident-archive', {{
              id: String(incidentId || ''),
              export: exportStatus.request_id || exportStatus.finished_at || ''
            }});
            break;
          }}
          if (exportStatus && exportStatus.state === 'failed') {{
            finalMessage = exportStatus.message || 'Incident pack failed.';
            break;
          }}
        }} catch (_pollError) {{
          // keep polling and show progress text
        }}
        if (hint) {{
          const elapsed = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
          hint.textContent = `Generating incident pack... ${{elapsed}}s`;
        }}
        if (button) {{
          button.textContent = 'Generating...';
        }}
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }}
      if (button) {{
        if (ready) {{
          button.textContent = 'Download pack';
          button.className = 'secondary status-ready';
        }} else if (finalMessage) {{
          button.textContent = 'Generate failed';
          button.className = 'secondary status-failed';
        }} else {{
          button.textContent = 'Refresh incident pack';
          button.className = 'secondary';
        }}
        button.disabled = false;
      }}
      if (hint) {{
        hint.textContent = ready
          ? 'Incident pack ready. Use the button or download link.'
          : (finalMessage || 'Still generating. Press refresh incident pack if it takes longer.');
      }}
      if (ready) {{
        const archiveLink = document.getElementById(`incidentArchiveLink_${{incidentDomId}}`);
        if (archiveLink) {{
          archiveLink.href = archiveHref;
          archiveLink.style.display = 'inline-block';
        }}
        if (button) {{
          button.onclick = function () {{ window.location.href = archiveHref; }};
        }}
      }}
    }}

    async function runMemtest() {{
      const response = await fetch('/api/memtest' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          size_mb: Number(document.getElementById('memtest_size_mb').value || 1024),
          loops: Number(document.getElementById('memtest_loops').value || 2)
        }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Memory test failed to start.' }}));
        alert(payload.message || 'Memory test failed to start.');
        return;
      }}
      await fetchStatus();
    }}

    async function runSpeedtest() {{
      const response = await fetch('/api/speedtest' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{}})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Speed test failed to start.' }}));
        alert(payload.message || 'Speed test failed to start.');
        return;
      }}
      await fetchStatus();
    }}

    async function installRequiredTools() {{
      await runAction('install_required_tools');
    }}

    function attachChartHover() {{
      const canvas = document.getElementById('metricsChart');
      const hover = document.getElementById('metricsHover');
      if (!canvas || !hover) {{
        return;
      }}

      canvas.addEventListener('mousemove', (event) => {{
        if (!latestMetrics.length) {{
          return;
        }}
        const rect = canvas.getBoundingClientRect();
        const ratioX = canvas.width / rect.width;
        const x = (event.clientX - rect.left) * ratioX;
        const pad = 40;
        const chartWidth = canvas.width - pad * 2;
        const clamped = Math.max(pad, Math.min(pad + chartWidth, x));
        const firstEpoch = Date.parse((latestMetrics[0] || {{}}).ts || '');
        const lastEpoch = Date.parse((latestMetrics[latestMetrics.length - 1] || {{}}).ts || '');
        const spanEpoch = Math.max(1, lastEpoch - firstEpoch);
        const targetEpoch = firstEpoch + (((clamped - pad) / chartWidth) * spanEpoch);
        let idx = 0;
        let bestDistance = Number.POSITIVE_INFINITY;
        latestMetrics.forEach((item, index) => {{
          const epoch = Date.parse(item.ts || '');
          if (!Number.isFinite(epoch)) {{
            return;
          }}
          const distance = Math.abs(epoch - targetEpoch);
          if (distance < bestDistance) {{
            bestDistance = distance;
            idx = index;
          }}
        }});
        const point = latestMetrics[idx];
        if (!point) {{
          return;
        }}
        const pointEpoch = Date.parse(point.ts || '');
        const nearbyWindowMs = metricsRangeHours > 24 ? 30 * 60 * 1000 : 5 * 60 * 1000;
        if (point.gap) {{
          hover.textContent = `${{formatLocalTimestamp(point.ts || '')}} | No watchdog sample in this period.`;
          drawMetrics(latestMetrics, idx);
          return;
        }}
        const nearbyEvents = latestMetricEvents
          .filter((item) => {{
            const eventEpoch = Date.parse(item.ts || '');
            return Number.isFinite(eventEpoch) && Number.isFinite(pointEpoch) && Math.abs(eventEpoch - pointEpoch) <= nearbyWindowMs;
          }})
          .map((item) => item.label);
        const eventText = nearbyEvents.length ? ` | Events: ${{nearbyEvents.join(', ')}}` : '';
        const memAvailText = point.mem_available_mb !== undefined && point.mem_available_mb !== null ? ` | MemAvailable ${{point.mem_available_mb}} MB` : '';
        const tempText = point.temperature_c !== undefined && point.temperature_c !== null ? ` | Temp ${{Number(point.temperature_c).toFixed(1)}} C` : '';
        hover.textContent = `${{formatLocalTimestamp(point.ts || '')}} | CPU ${{Number(point.cpu_percent || 0).toFixed(1)}}% | Memory ${{Number(point.mem_percent || 0).toFixed(1)}}%${{memAvailText}} | Root ${{Number(point.root_disk_percent || 0).toFixed(1)}}% | Recording ${{Number(point.recording_disk_percent || 0).toFixed(1)}}%${{tempText}}${{eventText}}`;
        drawMetrics(latestMetrics, idx);
      }});

      canvas.addEventListener('mouseleave', () => {{
        hover.textContent = 'Move across the graph to inspect time and values.';
        drawMetrics(latestMetrics);
      }});
    }}

    function safeRender(status) {{
      try {{
        render(status);
      }} catch (renderError) {{
        const message = renderError && renderError.message ? renderError.message : String(renderError || 'unknown render error');
        const incidentsList = document.getElementById('incidentsList');
        if (incidentsList) {{
          incidentsList.innerHTML = `<div class="timeline-empty">Render error: ${{message}}</div>`;
        }}
        const incidentsInvestigationList = document.getElementById('incidentsInvestigationList');
        if (incidentsInvestigationList) {{
          incidentsInvestigationList.innerHTML = `<div class="timeline-empty">Render error: ${{message}}</div>`;
        }}
        const metricsHover = document.getElementById('metricsHover');
        if (metricsHover) {{
          metricsHover.textContent = `Render error: ${{message}}`;
        }}
        if (window && window.console && window.console.error) {{
          window.console.error('watchdog render failed', renderError);
        }}
      }}
    }}

    if (initialStatus) {{
      safeRender(initialStatus);
    }}
    try {{
      const initialTab = new URLSearchParams(window.location.search || '').get('tab');
      if (initialTab) {{
        switchTab(initialTab);
      }}
    }} catch (_err) {{
      // ignore tab parse issues
    }}
    const hikProbeButton = document.getElementById('hikProbeButton');
    if (hikProbeButton) {{
      hikProbeButton.addEventListener('click', function(event) {{
        event.preventDefault();
        runHikProbe();
      }});
    }}
    fetchStatus();
    fetchMetrics();
    attachChartHover();
    setInterval(fetchStatus, 15000);
    setInterval(fetchMetrics, 60000);
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not authorized(self.path, self.headers):
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self._send_json(status_payload())
            return
        if parsed.path == "/run-hik-probe":
            hik_probe_payload(load_config())
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/?tab=dev")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            return
        if parsed.path == "/api/metrics":
            hours_raw = parse_qs(parsed.query).get("hours", ["24"])[0]
            try:
                hours = int(hours_raw)
            except ValueError:
                hours = 24
            hours = 168 if hours >= 168 else (24 if hours >= 24 else 1)
            self._send_json({"points": recent_metrics(hours), "events": recent_metric_events(hours)})
            return
        if parsed.path == "/download/export-archive":
            export_status = read_json(EXPORT_STATUS_PATH, {})
            self._send_file(safe_export_file("archive"), download_name=export_download_names(export_status)["archive"])
            return
        if parsed.path == "/download/export-readme":
            export_status = read_json(EXPORT_STATUS_PATH, {})
            self._send_file(safe_export_file("folder_readme"), download_name=export_download_names(export_status)["readme"])
            return
        if parsed.path == "/download/export-log":
            export_status = read_json(EXPORT_STATUS_PATH, {})
            self._send_file(safe_export_file("log"), download_name=export_download_names(export_status)["log"])
            return
        if parsed.path == "/download/incident-archive":
            incident_id = parse_qs(parsed.query).get("id", [""])[0]
            incident = incident_by_id(incident_id) or {"incident_id": incident_id}
            self._send_file(safe_incident_export_file(incident_id, "archive"), download_name=incident_export_names(incident)["archive"])
            return
        if parsed.path == "/download/incident-log":
            incident_id = parse_qs(parsed.query).get("id", [""])[0]
            incident = incident_by_id(incident_id) or {"incident_id": incident_id}
            self._send_file(safe_incident_export_file(incident_id, "log"), download_name=incident_export_names(incident)["log"])
            return
        if parsed.path == "/download/audit-report":
            payload = audit_report_payload()
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{audit_download_name(payload)}"')
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/download/memtest-log":
            self._send_file(safe_memtest_file("log"), download_name="watchdog-memtest.log")
            return
        if parsed.path == "/download/speedtest-log":
            self._send_file(safe_speedtest_file("log"), download_name="watchdog-speedtest.log")
            return
        if parsed.path == "/download/tools-install-log":
            self._send_file(safe_tools_install_file("log"), download_name="watchdog-tools-install.log")
            return
        if parsed.path in {"/api/base-status", "/status.json"}:
            self._send_json(base_status_payload())
            return
        if parsed.path in {"/", "/index.html"}:
            body = render_base_page().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _send_file(self, path: Optional[Path], download_name: str) -> None:
        if path is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        content_type = guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not authorized(self.path, self.headers):
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/config":
            config = load_config()
            data = self._read_json()
            config.update(sanitize_patch(data))
            write_json(CONFIG_PATH, config)
            self._send_json({"ok": True, "config": config})
            return

        if parsed.path == "/api/export":
            data = self._read_json()
            result = launch_export(str(data.get("since", "")).strip(), str(data.get("until", "")).strip())
            self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
            return

        if parsed.path == "/api/memtest":
            data = self._read_json()
            result = launch_memtest(int(data.get("size_mb", 0) or 0), int(data.get("loops", 0) or 0))
            self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
            return

        if parsed.path == "/api/speedtest":
            result = launch_speedtest()
            self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
            return

        if parsed.path == "/api/action":
            data = self._read_json()
            action = str(data.get("action", "")).strip()
            action_map = {
                "run_checks": Path("/var/lib/va-connect-site-watchdog/manual-run-checks"),
                "snapshot": Path("/var/lib/va-connect-site-watchdog/manual-snapshot"),
                "restart_network": Path("/var/lib/va-connect-site-watchdog/manual-restart-network"),
            }
            if action == "update_watchdog":
                result = launch_update()
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT)
                return
            if action == "check_updates":
                result = launch_update_check()
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT)
                return
            if action == "ack_reboots":
                state = read_json(STATE_PATH, {})
                state["ack_reboot_commands_sent_count"] = int(state.get("reboot_commands_sent_count", 0) or 0)
                state["ack_reboot_detections_count"] = int(state.get("reboot_detections_count", 0) or 0)
                state["ack_unexpected_reboot_count"] = int(state.get("unexpected_reboot_count", 0) or 0)
                write_json(STATE_PATH, state)
                append_path = EVENTS_PATH
                append_path.parent.mkdir(parents=True, exist_ok=True)
                with append_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"ts": now_iso(), "event": "reboot_counts_acknowledged"}, sort_keys=True) + "\n")
                self._send_json({"ok": True, "action": action, "message": "Reboot counts acknowledged."})
                return
            if action == "reset_teamviewer_password":
                result = reset_teamviewer_password(load_config(), str(data.get("password", "")))
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                return
            if action == "start_teamviewer":
                result = run_teamviewer_command(load_config(), "start")
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                return
            if action == "restart_teamviewer":
                result = run_teamviewer_command(load_config(), "restart")
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                return
            if action == "hik_probe":
                try:
                    result = hik_probe_payload(load_config())
                    self._send_json(result, HTTPStatus.OK if result.get("state") != "failed" else HTTPStatus.BAD_REQUEST)
                except Exception as exc:
                    payload = {
                        "enabled": True,
                        "state": "failed",
                        "message": f"Hik probe crashed: {type(exc).__name__}: {exc}",
                        "checked_at": now_iso(),
                    }
                    write_json(HIK_STATUS_PATH, payload)
                    self._send_json(payload, HTTPStatus.BAD_REQUEST)
                return
            if action == "install_required_tools":
                result = launch_required_tools_install()
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT)
                return
            if action == "quick_export":
                result = launch_quick_export()
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                return
            if action == "incident_export":
                result = launch_incident_export(str(data.get("incident_id", "")).strip())
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                return
            marker = action_map.get(action)
            if not marker:
                self._send_json({"ok": False, "message": f"Unknown action: {action}"}, HTTPStatus.BAD_REQUEST)
                return
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
            self._send_json({"ok": True, "action": action})
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, _format: str, *_args) -> None:
        return


def main() -> int:
    config = load_config()
    server = ThreadingHTTPServer((str(config["web_bind"]), int(config["web_port"])), Handler)
    print(f"VA-Connect watchdog web UI listening on {config['web_bind']}:{config['web_port']}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
