from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .heartbeat import heartbeat_paths, read_tail
from .incident_archive import archive_previous_boot
from .watchdog_test import read_trip_test_state


def _run(command, timeout=10):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout or result.stderr
    except Exception:
        return ""


def _write(path: Path, payload: dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _faults(kernel_text: str) -> list[dict[str, str]]:
    patterns = {
        "oom": r"\boom-killer\b|\bout of memory\b|\bkilled process\b.*\bout of memory\b",
        "hung_task": r"\bhung task\b|\bblocked for more than \d+ seconds\b",
        "soft_lockup": r"\bsoft lockup\b",
        "hard_lockup": r"\bhard lockup\b|\bwatchdog:\s+bug:.*lockup\b",
        "kernel_panic": r"\bkernel panic\b|\bpanic - not syncing\b",
        "storage_io": r"\bi/o error\b|\bblk_update_request\b|\bbuffer i/o error\b|\bext[234]-fs error\b|\bxfs .* error\b",
        "device_reset": r"\bata\d+.*(?:hard resetting|reset failed)\b|\breset (?:high|full|super)-speed usb device\b|\bnetdev watchdog\b|\btransmit queue.*timed out\b|\bfirmware.*reset\b",
        "watchdog_reset": r"\bwatchdog\b.*\b(?:reset|reboot|bootstatus|triggered|bite)\b|\bitco.*\bbootstatus\b",
    }
    result = []
    for line in kernel_text.splitlines():
        for category, pattern in patterns.items():
            if re.search(pattern, line.lower()):
                result.append({"category": category, "message": line[-1000:]})
                break
    return result[-100:]


def _reset_reason() -> str:
    candidates = [
        Path("/sys/devices/platform/watchdog/watchdog0/bootstatus"),
        Path("/sys/class/watchdog/watchdog0/bootstatus"),
        Path("/sys/firmware/efi/efivars/ResetReason"),
    ]
    for path in candidates:
        try:
            if path.exists():
                value = path.read_text(encoding="utf-8", errors="ignore").strip()
                if value:
                    return value
        except OSError:
            continue
    return ""


def _confirmed_trip(trip_state: dict[str, Any], previous_boot: str) -> dict[str, Any]:
    last_result = trip_state.get("last_result", {}) if isinstance(trip_state.get("last_result", {}), dict) else {}
    triggered_boot = str(trip_state.get("triggered_boot_id") or "")
    result_boot = str(last_result.get("triggered_boot_id") or triggered_boot)
    confirmed = bool(
        previous_boot
        and trip_state.get("triggered")
        and triggered_boot == previous_boot
        and result_boot == previous_boot
        and last_result.get("ok") is True
    )
    if not confirmed:
        return {}
    return {
        "confirmed": True,
        "triggered_boot_id": triggered_boot,
        "triggered_at": trip_state.get("triggered_at", ""),
        "message": last_result.get("message", ""),
    }


def _apply_confirmed_trip(evidence: dict[str, Any], trip_state: dict[str, Any]) -> bool:
    trip = _confirmed_trip(trip_state, str(evidence.get("previous_boot_id") or ""))
    if not trip or evidence.get("deliberate_trip_test", {}).get("confirmed"):
        return False
    evidence["reset_mechanism"] = "Watchdog reset"
    evidence["classification"] = "Watchdog reset"
    evidence["confidence"] = "High"
    evidence["deliberate_trip_test"] = trip
    evidence_used = [
        item for item in evidence.get("evidence_used", [])
        if "classification remains Unknown" not in str(item)
    ]
    evidence_used.append("A confirmed deliberate watchdog trip was recorded for the previous boot ID.")
    evidence["evidence_used"] = evidence_used
    return True


def classify(boot_change: dict[str, Any], heartbeats: list[dict[str, Any]], previous_reboot_reason: dict[str, Any], kernel_text: str, last_x: str, reset_reason: str = "", trip_state: dict[str, Any] | None = None) -> dict[str, Any]:
    previous_boot = str(boot_change.get("previous_boot_id") or "")
    previous_rows = [row for row in heartbeats if str(row.get("boot_id")) == previous_boot]
    last_heartbeat = previous_rows[-1] if previous_rows else (heartbeats[-1] if heartbeats else {})
    faults = _faults(kernel_text)
    requested = bool(previous_reboot_reason)
    deliberate_trip = _confirmed_trip(trip_state or {}, previous_boot)
    watchdog_evidence = bool(deliberate_trip) or bool(reset_reason and "watchdog" in reset_reason.lower()) or any(item["category"] == "watchdog_reset" for item in faults)
    kernel_fault = any(item["category"] in {"oom", "hung_task", "soft_lockup", "hard_lockup", "kernel_panic"} for item in faults)
    storage_fault = any(item["category"] == "storage_io" for item in faults)
    recent_session = _previous_session_lines(last_x)
    clean = any("shutdown system down" in line.lower() for line in recent_session) and not any("crash" in line.lower() for line in recent_session)
    if requested:
        mechanism = "Requested reboot"
        confidence = "High"
    elif watchdog_evidence:
        mechanism = "Watchdog reset"
        confidence = "High" if reset_reason or deliberate_trip else "Medium"
    elif clean:
        mechanism = "Clean reboot"
        confidence = "Medium"
    elif kernel_fault:
        mechanism = "Kernel fault"
        confidence = "Medium"
    else:
        mechanism = "Unknown"
        confidence = "Low"
    gap = None
    if last_heartbeat.get("time") and boot_change.get("detected_at"):
        try:
            before = datetime.fromisoformat(str(last_heartbeat["time"]).replace("Z", "+00:00")).timestamp()
            after = datetime.fromisoformat(str(boot_change["detected_at"]).replace("Z", "+00:00")).timestamp()
            gap = round(max(0.0, after - before), 3)
        except (TypeError, ValueError, KeyError):
            gap = None
    evidence_used = []
    if requested:
        evidence_used.append("A watchdog-requested reboot reason was preserved before shutdown.")
    if reset_reason:
        evidence_used.append(f"Platform reset reason: {reset_reason}")
    if deliberate_trip:
        evidence_used.append("A confirmed deliberate watchdog trip was recorded for the previous boot ID.")
    if watchdog_evidence:
        evidence_used.append("The platform or previous-boot kernel log explicitly reported a watchdog reset.")
    if clean:
        evidence_used.append("The immediately preceding last -x session contains a clean shutdown record.")
    if kernel_fault:
        evidence_used.append("The previous-boot kernel log contains an explicit kernel fault signature.")
    if storage_fault:
        evidence_used.append("The previous-boot kernel log contains a storage I/O fault signature.")
    if not evidence_used:
        evidence_used.append("No direct reset-cause evidence was found; classification remains Unknown.")
    return {
        "reset_mechanism": mechanism,
        "probable_preceding_fault": "storage I/O" if storage_fault else ("kernel fault" if kernel_fault else "none identified"),
        "classification": mechanism,
        "confidence": confidence,
        "previous_boot_id": previous_boot,
        "current_boot_id": boot_change.get("current_boot_id", ""),
        "last_heartbeat": last_heartbeat,
        "heartbeat_gap_seconds": gap,
        "previous_reboot_reason": previous_reboot_reason,
        "kernel_findings": faults,
        "evidence_used": evidence_used,
        "previous_session_last_x": recent_session,
        "unclean_shutdown_detected": any("crash" in line.lower() for line in recent_session),
        "last_x": last_x[-5000:],
        "reset_reason": reset_reason,
        "deliberate_trip_test": deliberate_trip,
        "created_at": time.time(),
    }


def _previous_session_lines(last_x: str) -> list[str]:
    lines = [line for line in last_x.splitlines() if line.strip()]
    reboot_indexes = [index for index, line in enumerate(lines) if "reboot   system boot" in line.lower()]
    if len(reboot_indexes) >= 2:
        return lines[reboot_indexes[0] + 1:reboot_indexes[1]]
    return lines[:12]


def create(cfg: dict[str, Any], boot_change: dict[str, Any], feed_state: dict[str, Any] | None = None) -> dict[str, Any]:
    path = Path(cfg.get("reboot_evidence_path") or Path(cfg["events_path"]).parent / "reboot-evidence.jsonl")
    trip_state = read_trip_test_state(cfg)
    if not boot_change.get("changed"):
        latest = path.with_name("last-reboot-evidence.json")
        try:
            value = json.loads(latest.read_text(encoding="utf-8")) if latest.exists() else {}
            if not isinstance(value, dict):
                return {}
            if _apply_confirmed_trip(value, trip_state):
                _write(latest, value)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(value, separators=(",", ":")) + "\n")
                archive_path = value.get("incident_archive", {}).get("path") if isinstance(value.get("incident_archive", {}), dict) else ""
                if archive_path:
                    _write(Path(str(archive_path)) / "reboot-evidence.json", value)
            return value
        except Exception:
            return {}
    _, heartbeat_history = heartbeat_paths(cfg)
    heartbeats = read_tail(cfg, 1000)
    reason_path = Path(cfg.get("last_reboot_reason_path") or path.parent / "last-reboot-reason.json")
    try:
        reason = json.loads(reason_path.read_text(encoding="utf-8")) if reason_path.exists() else {}
    except Exception:
        reason = {}
    kernel = _run(["journalctl", "-b", "-1", "-k", "--no-pager"], timeout=15)
    last_x = _run(["last", "-x"], timeout=10)
    evidence = classify(boot_change, heartbeats, reason if isinstance(reason, dict) else {}, kernel, last_x, str((feed_state or {}).get("reset_reason") or _reset_reason()), trip_state)
    try:
        archive = archive_previous_boot(cfg, boot_change, evidence, kernel, last_x)
    except Exception as exc:
        archive = {"created": False, "reason": f"archive failed without blocking startup: {exc}"}
    evidence["incident_archive"] = archive
    if archive.get("path"):
        _write(Path(str(archive["path"])) / "reboot-evidence.json", evidence)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(evidence, separators=(",", ":")) + "\n")
        handle.flush()
    latest = path.with_name("last-reboot-evidence.json")
    _write(latest, evidence)
    return evidence
