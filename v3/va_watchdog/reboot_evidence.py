from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .heartbeat import heartbeat_paths, read_tail


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
        "oom": r"oom-killer|out of memory",
        "hung_task": r"hung task|blocked for more than",
        "soft_lockup": r"soft lockup",
        "hard_lockup": r"hard lockup|nmi watchdog",
        "kernel_panic": r"kernel panic|not syncing",
        "storage_io": r"i/o error|blk_update_request|buffer i/o error|ext[234]-fs error|xfs .* error",
        "device_reset": r"sata.*reset|usb .*reset|link is down|firmware.*reset",
        "watchdog": r"watchdog|itco",
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


def classify(boot_change: dict[str, Any], heartbeats: list[dict[str, Any]], previous_reboot_reason: dict[str, Any], kernel_text: str, last_x: str, reset_reason: str = "") -> dict[str, Any]:
    previous_boot = str(boot_change.get("previous_boot_id") or "")
    previous_rows = [row for row in heartbeats if str(row.get("boot_id")) == previous_boot]
    last_heartbeat = previous_rows[-1] if previous_rows else (heartbeats[-1] if heartbeats else {})
    faults = _faults(kernel_text)
    requested = bool(previous_reboot_reason)
    watchdog_evidence = bool(reset_reason and "watchdog" in reset_reason.lower()) or any(item["category"] == "watchdog" for item in faults)
    kernel_fault = any(item["category"] in {"oom", "hung_task", "soft_lockup", "hard_lockup", "kernel_panic"} for item in faults)
    storage_fault = any(item["category"] == "storage_io" for item in faults)
    clean = bool(re.search(r"shutdown|reboot|systemd-shutdown", last_x.lower())) and not faults and not requested
    if requested:
        mechanism = "Requested reboot"
        confidence = "High"
    elif watchdog_evidence:
        mechanism = "Watchdog reset"
        confidence = "High" if reset_reason else "Medium"
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
        "last_x": last_x[-5000:],
        "reset_reason": reset_reason,
        "created_at": time.time(),
    }


def create(cfg: dict[str, Any], boot_change: dict[str, Any], feed_state: dict[str, Any] | None = None) -> dict[str, Any]:
    path = Path(cfg.get("reboot_evidence_path") or Path(cfg["events_path"]).parent / "reboot-evidence.jsonl")
    if not boot_change.get("changed"):
        latest = path.with_name("last-reboot-evidence.json")
        try:
            value = json.loads(latest.read_text(encoding="utf-8")) if latest.exists() else {}
            return value if isinstance(value, dict) else {}
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
    evidence = classify(boot_change, heartbeats, reason if isinstance(reason, dict) else {}, kernel, last_x, str((feed_state or {}).get("reset_reason") or _reset_reason()))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(evidence, separators=(",", ":")) + "\n")
        handle.flush()
    latest = path.with_name("last-reboot-evidence.json")
    _write(latest, evidence)
    return evidence
