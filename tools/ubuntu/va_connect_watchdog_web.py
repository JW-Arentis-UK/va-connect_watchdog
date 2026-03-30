#!/usr/bin/env python3

import html
import json
import os
import shlex
import socket
import subprocess
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from mimetypes import guess_type
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


CONFIG_PATH = Path(os.environ.get("SITE_WATCHDOG_CONFIG", "/opt/va-connect-watchdog/site-watchdog.json"))
STATE_PATH = Path("/var/lib/va-connect-site-watchdog/state.json")
EVENTS_PATH = Path("/var/log/va-connect-site-watchdog/events.jsonl")
METRICS_PATH = Path("/var/log/va-connect-site-watchdog/metrics.jsonl")
BUILD_INFO_PATH = Path("/opt/va-connect-watchdog/build-info.json")
UPDATE_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-update-status.json")
UPDATE_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-update.log")
EXPORT_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-export-status.json")
EXPORT_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-export.log")
MEMTEST_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-memtest-status.json")
MEMTEST_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-memtest.log")
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


def parse_iso(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def load_config() -> Dict[str, Any]:
    config = read_json(CONFIG_PATH, {})
    defaults = {
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
    }
    merged = {**defaults, **config}
    merged["web_port"] = int(merged["web_port"])
    return merged


def command_exists(name: str) -> bool:
    return subprocess.run(["bash", "-lc", f"command -v {shlex.quote(name)}"], capture_output=True, text=True).returncode == 0


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
        "app_match",
        "app_start_command",
        "web_bind",
        "web_token",
        "network_restart_command",
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
        ts = item.get("ts", "")
        try:
            epoch = datetime.fromisoformat(ts).timestamp()
        except Exception:
            continue
        if epoch >= cutoff:
            points.append(item)
    max_points = 3000 if hours <= 24 else 8000
    return points[-max_points:]


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
        try:
            epoch = datetime.fromisoformat(ts).timestamp()
        except Exception:
            continue
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


def latest_previous_boot_snapshot() -> Optional[Path]:
    if not SNAPSHOT_DIR.exists():
        return None
    candidates = sorted(
        (path for path in SNAPSHOT_DIR.iterdir() if path.is_dir() and path.name.endswith("_previous-boot-review")),
        key=lambda item: item.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


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


def crash_review_payload() -> Dict[str, Any]:
    snapshot = latest_previous_boot_snapshot()
    if snapshot is None:
        return {
            "available": False,
            "title": "No previous-boot review yet",
            "detail": "A previous-boot review snapshot will appear here after the next detected reboot.",
            "snapshot_path": "",
            "system_lines": [],
            "kernel_lines": [],
        }

    system_lines = extract_notable_lines(snapshot / "journal_previous_boot.txt")
    kernel_lines = extract_notable_lines(snapshot / "journal_kernel_previous_boot.txt")
    system_lines_all = extract_all_notable_lines(snapshot / "journal_previous_boot.txt", limit=40)
    kernel_lines_all = extract_all_notable_lines(snapshot / "journal_kernel_previous_boot.txt", limit=40)
    detail = "Review the highlighted lines below first."
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
        "kernel_lines": kernel_lines,
        "kernel_lines_all": kernel_lines_all,
    }


def normalize_update_status(update_status: Dict[str, Any], build_info: Dict[str, Any]) -> Dict[str, Any]:
    status = dict(update_status or {})
    if status.get("state") != "running":
        return status

    started_at = parse_iso(str(status.get("started_at", "")))
    deployed_at = parse_iso(str(build_info.get("deployed_at", "")))
    now = datetime.utcnow().astimezone()

    if started_at and deployed_at and deployed_at >= started_at:
        status["state"] = "ok"
        status["finished_at"] = status.get("finished_at") or build_info.get("deployed_at", "")
        status["to_build"] = status.get("to_build") or build_info.get("git_commit", "unknown")
        status["message"] = "Update appears to have completed after the web service restarted."
        write_json(UPDATE_STATUS_PATH, status)
        return status

    if started_at and (now - started_at).total_seconds() > 300:
        status["state"] = "failed"
        status["finished_at"] = status.get("finished_at") or now_iso()
        status["message"] = "Web update stayed in running state too long. Check web-update.log."
        write_json(UPDATE_STATUS_PATH, status)
        return status

    return status


def launch_export(since_time: str, until_time: str) -> Dict[str, Any]:
    current = read_json(EXPORT_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Export already running."}
    if not since_time.strip() or not until_time.strip():
        return {"ok": False, "message": "Provide both since and until times."}

    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Incident export requested from web UI.",
        "since": since_time,
        "until": until_time,
        "folder": "",
        "archive": "",
        "log_path": str(EXPORT_LOG_PATH),
    }
    write_json(EXPORT_STATUS_PATH, payload)
    EXPORT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    since_q = shlex.quote(since_time)
    until_q = shlex.quote(until_time)
    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-export-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-export.log')\n"
        "cmd = ['bash', '/opt/va-connect-watchdog/export_watchdog_incident.sh', '--since', " + repr(since_time) + ", '--until', " + repr(until_time) + "]\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web export started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "try:\n"
        "    lines = log_path.read_text(encoding='utf-8', errors='ignore').splitlines()\n"
        "except Exception:\n"
        "    lines = []\n"
        "    \n"
        "for line in reversed(lines):\n"
        "    if line.startswith('  Folder: '):\n"
        "        payload['folder'] = line.split(': ', 1)[1]\n"
        "    if line.startswith('  Archive: '):\n"
        "        payload['archive'] = line.split(': ', 1)[1]\n"
        "payload['message'] = 'Incident export created.' if result.returncode == 0 else 'Incident export failed. Check web-export.log.'\n"
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


def safe_export_file(kind: str) -> Optional[Path]:
    export_status = read_json(EXPORT_STATUS_PATH, {})
    candidate = ""
    if kind == "archive":
        candidate = str(export_status.get("archive", "")).strip()
    elif kind == "log":
        candidate = str(export_status.get("log_path", "")).strip()
    elif kind == "folder_readme":
        folder = str(export_status.get("folder", "")).strip()
        if folder:
            candidate = str(Path(folder) / "README.txt")
    if not candidate:
        return None
    path = Path(candidate)
    if not path.exists() or not path.is_file():
        return None
    return path


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


def status_payload() -> Dict[str, Any]:
    state = read_json(STATE_PATH, {})
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
    if hardware_payload.get("warnings"):
        next_steps.append("Review Hardware warnings for EDAC, storage, or persistent-crash clues that may explain a hard freeze.")
    next_steps.append("Use PC stats to look for CPU, memory, or disk changes building before a reboot or hang.")
    next_steps.append("If it freezes overnight again, compare the last event time with the next boot's previous-boot snapshot.")

    events = recent_events()
    summarized_events = []
    for event in events:
        enriched = dict(event)
        enriched["summary"] = summarize_event(event)
        summarized_events.append(enriched)
    build_info = read_json(BUILD_INFO_PATH, {})
    update_status = normalize_update_status(read_json(UPDATE_STATUS_PATH, {"state": "idle"}), build_info)
    memtest_info = memtest_recommendation()
    memtest_status = normalize_memtest_status(read_json(MEMTEST_STATUS_PATH, {"state": "idle"}))
    hw_identity = hardware_identity()
    return {
        "hostname": socket.gethostname(),
        "hardware_identity": hw_identity,
        "config": load_config(),
        "state": state,
        "build_info": build_info,
        "update_status": update_status,
        "export_status": read_json(EXPORT_STATUS_PATH, {"state": "idle"}),
        "memtest_status": memtest_status,
        "memtest_info": memtest_info,
        "reboot_counts": reboot_counts,
        "diagnosis": {"title": diagnosis, "detail": diagnosis_detail},
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
            "build_info": str(BUILD_INFO_PATH),
            "update_status": str(UPDATE_STATUS_PATH),
            "update_log": str(UPDATE_LOG_PATH),
            "export_status": str(EXPORT_STATUS_PATH),
            "export_log": str(EXPORT_LOG_PATH),
            "memtest_status": str(MEMTEST_STATUS_PATH),
            "memtest_log": str(MEMTEST_LOG_PATH),
        },
    }


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
    .wrap {{ max-width: 1540px; margin: 0 auto; padding: 12px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .overview-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-top: 10px; }}
    .current-stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }}
    .panel {{
      background: rgba(18, 29, 39, 0.9);
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 16px;
      padding: 12px;
      box-shadow: 0 14px 34px rgba(0, 0, 0, 0.28);
      backdrop-filter: blur(10px);
    }}
    h1 {{ margin: 0 0 6px; font-size: 1.2rem; }}
    h2 {{ margin: 0 0 10px; font-size: 0.95rem; }}
    p {{ margin: 0 0 10px; }}
    .sub {{ color: #8ea5b9; margin-bottom: 12px; font-size: 0.88rem; }}
    .tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }}
    .tab-btn {{
      border: 1px solid rgba(133, 159, 180, 0.24);
      border-radius: 999px;
      padding: 7px 13px;
      background: rgba(19, 32, 43, 0.9);
      color: #d9e5ef;
      font-weight: 700;
      cursor: pointer;
    }}
    .tab-btn.active {{
      background: #3a6c98;
      color: #fff;
      border-color: #4b7ca8;
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
    .targets, .events {{ display: grid; gap: 8px; }}
    .targets {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .item {{
      border: 1px solid rgba(130, 153, 173, 0.15);
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(22, 35, 46, 0.86);
      font-size: 0.83rem;
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
      gap: 10px;
      margin-top: 10px;
    }}
    .hero-main {{
      border: 1px solid rgba(122, 150, 176, 0.18);
      border-radius: 18px;
      padding: 14px;
      background: linear-gradient(135deg, rgba(53, 93, 128, 0.34), rgba(47, 78, 62, 0.22));
    }}
    .hero-title {{ font-size: 1.18rem; font-weight: 800; margin: 3px 0 8px; }}
    .hero-detail {{ font-size: 0.9rem; color: #b8c9d8; }}
    .status-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
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
    .chart-event-dot.command {{ background: #b06d10; }}
    .chart-event-dot.detected {{ background: #b34747; }}
    .chart-event-dot.note {{ background: #607064; }}
    .chart-toolbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 6px;
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
      grid-template-columns: minmax(320px, 0.85fr) minmax(420px, 1.4fr);
      gap: 10px;
      align-items: start;
    }}
    .status-grid {{
      display: grid;
      grid-template-columns: minmax(320px, 1fr) minmax(320px, 1fr);
      gap: 10px;
      margin-top: 10px;
    }}
    .ops-grid {{
      display: grid;
      grid-template-columns: minmax(360px, 1fr) minmax(480px, 1fr);
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
      min-height: 250px;
    }}
    .checks-panel {{
      min-height: 320px;
    }}
    .controls-panel {{
      min-height: 240px;
    }}
    .summary-panel {{
      min-height: 150px;
    }}
    .timeline-empty {{
      color: #8ea5b9;
      font-size: 0.84rem;
      padding: 12px 4px;
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
      .hardware-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>VA-Connect Encoder Watchdog</h1>
    <div class="sub">Control page for <strong>{html.escape(status["hostname"])}</strong> | Hardware ID <strong>{html.escape(str(status["hardware_identity"].get("serial", "unknown")))}</strong></div>
    <div class="tabs">
      <button type="button" class="tab-btn active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
      <button type="button" class="tab-btn" data-tab="investigation" onclick="switchTab('investigation')">Investigation</button>
      <button type="button" class="tab-btn" data-tab="config" onclick="switchTab('config')">Config</button>
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
    <div class="overview-grid">
      <section class="stat-card">
        <div class="stat-label">Current state</div>
        <div class="stat-value">{'Healthy' if not status['state'].get('fault_active') else 'Fault'}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Watchdog reboot commands</div>
        <div class="stat-value">{int(status["reboot_counts"].get("watchdog", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Detected reboots</div>
        <div class="stat-value">{int(status["reboot_counts"].get("detected", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Unexpected reboots</div>
        <div class="stat-value">{int(status["reboot_counts"].get("unexpected", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Last reboot reason</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["state"].get("last_reboot_reason", "none")))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Last startup</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["state"].get("last_startup_at", "unknown")))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Hardware ID</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["hardware_identity"].get("serial", "unknown")))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Build</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["build_info"].get("git_commit", "unknown")))}</div>
      </section>
    </div>
    <div class="status-grid">
      <section class="panel summary-panel">
        <div class="badge {'danger' if status['state'].get('fault_active') else ''}">{'Fault Active' if status['state'].get('fault_active') else 'Healthy / Idle'}</div>
        <p>Monitoring state: <strong>{html.escape(str(status["state"].get("monitoring_state", "unknown")))}</strong></p>
        <p>Last check: <strong>{html.escape(str(status["state"].get("last_check_at", "never")))}</strong></p>
        <p>Last healthy: <strong>{html.escape(str(status["state"].get("last_healthy_at", "unknown")))}</strong></p>
        <p>Failure count: <strong>{html.escape(str(status["state"].get("failure_count", 0)))}</strong></p>
      </section>
      <section class="panel summary-panel">
        <div class="badge">{html.escape(str(cfg["web_bind"]))}:{cfg["web_port"]}</div>
        <p>Base reboot timer: <strong>{cfg["base_reboot_timeout_seconds"]}s</strong></p>
        <p>Max reboot timer: <strong>{cfg["max_reboot_timeout_seconds"]}s</strong></p>
        <p>Hardware model: <strong>{html.escape(str(status["hardware_identity"].get("model", "unknown")))}</strong></p>
        <p>Deployed: <strong>{html.escape(str(status["build_info"].get("deployed_at", "unknown")))}</strong></p>
        <p>Config path: <code>{html.escape(status["paths"]["config"])}</code></p>
      </section>
    </div>

    <div class="analysis-grid" style="margin-top:16px;">
      <section class="panel" style="grid-column: 1 / -1;">
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
      <section class="panel">
        <div class="chart-toolbar">
          <h2 id="metricsTitle">PC Stats - Last 24 Hours</h2>
          <div class="range-toggle">
            <button type="button" class="range-btn active" id="range24hBtn" onclick="setMetricRange(24)">24 hours</button>
            <button type="button" class="range-btn" id="range168hBtn" onclick="setMetricRange(168)">7 days</button>
          </div>
        </div>
        <div class="chart-hover" id="metricsHover">Move across the graph to inspect time and values.</div>
        <canvas id="metricsChart" width="1000" height="280"></canvas>
        <div class="chart-event-legend">
          <span class="chart-event-item"><span class="chart-event-dot command"></span>Watchdog reboot command</span>
          <span class="chart-event-item"><span class="chart-event-dot detected"></span>Detected or unexpected reboot</span>
          <span class="chart-event-item"><span class="chart-event-dot note"></span>Reboot counts acknowledged</span>
        </div>
        <p class="hint">CPU, memory, root disk, and recording disk usage are plotted as percentages. Hover also shows MemAvailable and temperature when available.</p>
      </section>
    </div>

    <div class="ops-grid">
      <section class="panel controls-panel">
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
        <button class="secondary" onclick="runAction('update_watchdog')">Update from GitHub</button>
        <div class="update-row">
          <span class="badge {'warn' if status['update_status'].get('state') == 'running' else ('danger' if status['update_status'].get('state') == 'failed' else '')}" id="updateState">{html.escape(str(status["update_status"].get("state", "idle")).title())}</span>
          <span id="updateMessage">{html.escape(str(status["update_status"].get("message", "No web update run yet.")))}</span>
        </div>
        <p class="hint" id="updateMeta">{html.escape(str(status["update_status"].get("from_build", "unknown")))} to {html.escape(str(status["update_status"].get("to_build", "unknown")))} | {html.escape(str(status["update_status"].get("finished_at", "not finished yet")))}</p>
        <div class="mini-form">
          <div class="field">
            <label for="export_since">Export since</label>
            <input id="export_since" type="datetime-local">
          </div>
          <div class="field">
            <label for="export_until">Export until</label>
            <input id="export_until" type="datetime-local">
          </div>
        </div>
        <button class="secondary" onclick="exportIncident()">Export incident pack</button>
        <div class="update-row">
          <span class="badge {'warn' if status['export_status'].get('state') == 'running' else ('danger' if status['export_status'].get('state') == 'failed' else '')}" id="exportState">{html.escape(str(status["export_status"].get("state", "idle")).title())}</span>
          <span id="exportMessage">{html.escape(str(status["export_status"].get("message", "No incident export run yet.")))}</span>
        </div>
        <p class="hint" id="exportMeta">{html.escape(str(status["export_status"].get("folder", "")))} {html.escape(str(status["export_status"].get("archive", "")))}</p>
        <div class="link-row">
          <a class="link-btn" id="exportArchiveLink" href="/download/export-archive">Download export archive</a>
          <a class="link-btn" id="exportReadmeLink" href="/download/export-readme">Download export README</a>
          <a class="link-btn" id="exportLogLink" href="/download/export-log">Download export log</a>
        </div>
      </section>
      <section class="panel checks-panel">
        <h2>Latest checks</h2>
        <div class="targets" id="targets"></div>
      </section>
    </div>
    </section>

    <section class="tab-panel" data-tab-panel="investigation">
    <div class="grid" style="margin-top:16px;">
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
        <div class="grid">
          <section class="item">
            <strong>Previous boot system log highlights</strong>
            <ul class="review-list" id="crashReviewSystem">
              {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("system_lines", []))}
            </ul>
            <div class="review-scroll">
              <ul class="review-list" id="crashReviewSystemAll">
                {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("system_lines_all", []))}
              </ul>
            </div>
          </section>
          <section class="item">
            <strong>Previous boot kernel log highlights</strong>
            <ul class="review-list" id="crashReviewKernel">
              {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("kernel_lines", []))}
            </ul>
            <div class="review-scroll">
              <ul class="review-list" id="crashReviewKernelAll">
                {"".join(f"<li>{html.escape(line)}</li>" for line in status["crash_review"].get("kernel_lines_all", []))}
              </ul>
            </div>
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
    const initialStatus = {json.dumps(status)};
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
    }}

    function badge(ok) {{
      return ok ? 'badge' : 'badge danger';
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

    function render(status) {{
      document.getElementById('monitoring_enabled').checked = !!status.config.monitoring_enabled;
      document.getElementById('app_restart_enabled').checked = !!status.config.app_restart_enabled;
      document.getElementById('restart_network_before_reboot').checked = !!status.config.restart_network_before_reboot;
      document.getElementById('reboot_enabled').checked = !!status.config.reboot_enabled;
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
      if (!document.getElementById('export_since').value) {{
        const startup = status.state.last_startup_at || '';
        if (startup) {{
          const startupDate = new Date(startup);
          const sinceDate = new Date(startupDate.getTime() - (30 * 60000));
          document.getElementById('export_since').value = formatLocalDateTimeInput(sinceDate.toISOString());
          document.getElementById('export_until').value = formatLocalDateTimeInput(startupDate.toISOString());
        }}
      }}
      document.getElementById('internet_hosts').value = (status.config.internet_hosts || []).join('\\n');
      document.getElementById('systemd_services').value = (status.config.systemd_services || []).join('\\n');
      document.getElementById('tcp_targets').value = (status.config.tcp_targets || []).map((item) => `${{item.host}}:${{item.port}}`).join('\\n');
      const checks = status.state.last_checks || {{ pings: [], ports: [], app_ok: null }};
      document.getElementById('targets').innerHTML = [
        `<div class="item"><strong>App process</strong><br><span class="${{badge(!!checks.app_ok)}}">${{checks.app_ok ? 'Running' : 'Missing'}}</span></div>`,
        ...(checks.pings || []).map((item) => `<div class="item"><strong>WAN: ${{item.host}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`),
        ...(checks.services || []).map((item) => `<div class="item"><strong>Service: ${{item.service}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Active' : 'Not active'}}</span><br><code>${{item.detail || ''}}</code></div>`),
        ...(checks.ports || []).map((item) => `<div class="item"><strong>TCP: ${{item.host}}:${{item.port}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`)
      ].join('');

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
      document.getElementById('currentStatsAt').textContent = currentMetrics.ts ? `Latest sample ${{formatLocalTimestamp(currentMetrics.ts)}}` : 'Latest sample unknown';
      document.getElementById('currentStatsGrid').innerHTML = `
        <section class="stat-card"><div class="stat-label">CPU</div><div class="stat-value">${{formatMetricNumber(currentMetrics.cpu_percent)}}%</div></section>
        <section class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">${{formatMetricNumber(currentMetrics.mem_percent)}}%</div></section>
        <section class="stat-card"><div class="stat-label">MemAvailable</div><div class="stat-value" style="font-size:1rem;">${{currentMetrics.mem_available_mb ?? 'unknown'}} MB</div></section>
        <section class="stat-card"><div class="stat-label">Cached</div><div class="stat-value" style="font-size:1rem;">${{currentMetrics.mem_cached_mb ?? 'unknown'}} MB</div></section>
        <section class="stat-card"><div class="stat-label">Root disk</div><div class="stat-value">${{formatMetricNumber(currentMetrics.root_disk_percent)}}%</div></section>
        <section class="stat-card"><div class="stat-label">Recording disk</div><div class="stat-value">${{formatMetricNumber(currentMetrics.recording_disk_percent)}}%</div></section>
        <section class="stat-card"><div class="stat-label">Temperature</div><div class="stat-value" style="font-size:1rem;">${{currentMetrics.temperature_c ?? 'unknown'}} C</div></section>
        <section class="stat-card"><div class="stat-label">Load</div><div class="stat-value" style="font-size:1rem;">${{formatMetricNumber(currentMetrics.load_1, 2)}}</div></section>
      `;
      document.getElementById('memoryThermalSummary').innerHTML = `
        <li><strong>Memory used:</strong> ${{Number(currentMetrics.mem_percent || 0).toFixed(1)}}%</li>
        <li><strong>MemAvailable:</strong> ${{currentMetrics.mem_available_mb ?? 'unknown'}} MB</li>
        <li><strong>Cached:</strong> ${{currentMetrics.mem_cached_mb ?? 'unknown'}} MB</li>
        <li><strong>Temperature:</strong> ${{currentMetrics.temperature_c ?? 'unknown'}} C</li>
      `;
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
      document.getElementById('crashReviewFindings').innerHTML = (crashReview.findings || []).length
        ? (crashReview.findings || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No crash-review findings yet.</li>';
      document.getElementById('crashReviewSystem').innerHTML = (crashReview.system_lines || []).length
        ? (crashReview.system_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No notable system-log lines extracted yet.</li>';
      document.getElementById('crashReviewSystemAll').innerHTML = (crashReview.system_lines_all || []).length
        ? (crashReview.system_lines_all || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No extra system-log lines extracted yet.</li>';
      document.getElementById('crashReviewKernel').innerHTML = (crashReview.kernel_lines || []).length
        ? (crashReview.kernel_lines || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No notable kernel-log lines extracted yet.</li>';
      document.getElementById('crashReviewKernelAll').innerHTML = (crashReview.kernel_lines_all || []).length
        ? (crashReview.kernel_lines_all || []).map((line) => `<li>${{line}}</li>`).join('')
        : '<li>No extra kernel-log lines extracted yet.</li>';
      const updateState = status.update_status || {{}};
      const updateBadge = document.getElementById('updateState');
      updateBadge.className = `badge ${{updateState.state === 'running' ? 'warn' : (updateState.state === 'failed' ? 'danger' : '')}}`;
      updateBadge.textContent = (updateState.state || 'idle').toUpperCase();
      document.getElementById('updateMessage').textContent = updateState.message || 'No web update run yet.';
      document.getElementById('updateMeta').textContent = `${{updateState.from_build || 'unknown'}} to ${{updateState.to_build || 'unknown'}} | ${{updateState.finished_at ? formatLocalTimestamp(updateState.finished_at) : 'not finished yet'}}`;
      const exportState = status.export_status || {{}};
      const exportBadge = document.getElementById('exportState');
      exportBadge.className = `badge ${{exportState.state === 'running' ? 'warn' : (exportState.state === 'failed' ? 'danger' : '')}}`;
      exportBadge.textContent = (exportState.state || 'idle').toUpperCase();
      document.getElementById('exportMessage').textContent = exportState.message || 'No incident export run yet.';
      const exportMetaParts = [];
      if (exportState.folder) {{
        exportMetaParts.push(exportState.folder);
      }}
      if (exportState.archive) {{
        exportMetaParts.push(exportState.archive);
      }}
      if (exportState.finished_at) {{
        exportMetaParts.push(formatLocalTimestamp(exportState.finished_at));
      }}
      document.getElementById('exportMeta').textContent = exportMetaParts.join(' | ') || 'not finished yet';
      document.getElementById('exportArchiveLink').style.display = exportState.archive ? 'inline-block' : 'none';
      document.getElementById('exportReadmeLink').style.display = exportState.folder ? 'inline-block' : 'none';
      document.getElementById('exportLogLink').style.display = exportState.log_path ? 'inline-block' : 'none';

      document.querySelector('.overview-grid').innerHTML = `
        <section class="stat-card"><div class="stat-label">Current state</div><div class="stat-value">${{status.state.fault_active ? 'Fault' : 'Healthy'}}</div></section>
        <section class="stat-card"><div class="stat-label">Watchdog reboot commands</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.watchdog) || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Detected reboots</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.detected) || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Unexpected reboots</div><div class="stat-value">${{(status.reboot_counts && status.reboot_counts.unexpected) || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Last reboot reason</div><div class="stat-value" style="font-size:1rem;">${{status.state.last_reboot_reason || 'none'}}</div></section>
        <section class="stat-card"><div class="stat-label">Last startup</div><div class="stat-value" style="font-size:1rem;">${{formatLocalTimestamp(status.state.last_startup_at || '')}}</div></section>
        <section class="stat-card"><div class="stat-label">Hardware ID</div><div class="stat-value" style="font-size:1rem;">${{(status.hardware_identity && status.hardware_identity.serial) || 'unknown'}}</div></section>
        <section class="stat-card"><div class="stat-label">Build</div><div class="stat-value" style="font-size:1rem;">${{(status.build_info && status.build_info.git_commit) || 'unknown'}}</div></section>
      `;

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
        {{ key: 'recording_disk_percent', color: '#d4a34a', label: 'Recording disk' }}
      ];

      const maxIndex = Math.max(1, points.length - 1);
      const xFor = (index) => pad + (chartWidth * index / maxIndex);
      const yFor = (value) => pad + chartHeight - ((Math.max(0, Math.min(100, Number(value || 0))) / 100) * chartHeight);
      const firstEpoch = Date.parse(points[0].ts || '');
      const lastEpoch = Date.parse(points[points.length - 1].ts || '');
      const spanEpoch = Math.max(1, lastEpoch - firstEpoch);

      series.forEach((line, idx) => {{
        ctx.strokeStyle = line.color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        let started = false;
        points.forEach((point, index) => {{
          const value = point[line.key];
          if (value === null || value === undefined || Number.isNaN(Number(value))) {{
            return;
          }}
          const x = xFor(index);
          const y = yFor(value);
          if (!started) {{
            ctx.moveTo(x, y);
            started = true;
          }} else {{
            ctx.lineTo(x, y);
          }}
        }});
        ctx.stroke();
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
        const x = pad + (((eventEpoch - firstEpoch) / spanEpoch) * chartWidth);
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
        const x = xFor(hoverIndex);
        ctx.strokeStyle = '#8ea5b9';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, pad);
        ctx.lineTo(x, pad + chartHeight);
        ctx.stroke();
      }}
    }}

    async function fetchStatus() {{
      const response = await fetch('/api/status' + authQuery);
      render(await response.json());
    }}

    function setMetricRange(hours) {{
      metricsRangeHours = hours;
      document.getElementById('range24hBtn').classList.toggle('active', hours === 24);
      document.getElementById('range168hBtn').classList.toggle('active', hours === 168);
      document.getElementById('metricsTitle').textContent = hours === 168 ? 'PC Stats - Last 7 Days' : 'PC Stats - Last 24 Hours';
      fetchMetrics();
    }}

    async function fetchMetrics() {{
      const separator = authQuery ? '&' : '?';
      const response = await fetch(`/api/metrics${{authQuery}}${{separator}}hours=${{metricsRangeHours}}`);
      const payload = await response.json();
      latestMetrics = payload.points || [];
      latestMetricEvents = payload.events || [];
      drawMetrics(latestMetrics);
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

    async function runAction(action) {{
      const response = await fetch('/api/action' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ action }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Action failed.' }}));
        alert(payload.message || 'Action failed.');
        return;
      }}
      await fetchStatus();
    }}

    async function exportIncident() {{
      const since = document.getElementById('export_since').value;
      const until = document.getElementById('export_until').value;
      const response = await fetch('/api/export' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          since: since ? since.replace('T', ' ') : '',
          until: until ? until.replace('T', ' ') : ''
        }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Export failed.' }}));
        alert(payload.message || 'Export failed.');
        return;
      }}
      await fetchStatus();
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
        const idx = Math.round(((clamped - pad) / chartWidth) * Math.max(1, latestMetrics.length - 1));
        const point = latestMetrics[idx];
        if (!point) {{
          return;
        }}
        const pointEpoch = Date.parse(point.ts || '');
        const nearbyWindowMs = metricsRangeHours > 24 ? 30 * 60 * 1000 : 5 * 60 * 1000;
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

    render(initialStatus);
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
        if parsed.path == "/api/metrics":
            hours_raw = parse_qs(parsed.query).get("hours", ["24"])[0]
            try:
                hours = int(hours_raw)
            except ValueError:
                hours = 24
            hours = 168 if hours >= 168 else 24
            self._send_json({"points": recent_metrics(hours), "events": recent_metric_events(hours)})
            return
        if parsed.path == "/download/export-archive":
            self._send_file(safe_export_file("archive"), download_name="watchdog-incident-export.tar.gz")
            return
        if parsed.path == "/download/export-readme":
            self._send_file(safe_export_file("folder_readme"), download_name="watchdog-incident-export-readme.txt")
            return
        if parsed.path == "/download/export-log":
            self._send_file(safe_export_file("log"), download_name="watchdog-incident-export.log")
            return
        if parsed.path == "/download/memtest-log":
            self._send_file(safe_memtest_file("log"), download_name="watchdog-memtest.log")
            return
        if parsed.path in {"/", "/index.html"}:
            body = render_page(status_payload()).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
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
