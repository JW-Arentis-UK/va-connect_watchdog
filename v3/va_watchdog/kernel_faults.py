from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any


PATTERNS = {
    "oom": r"\boom-killer\b|\bout of memory\b|\bkilled process\b.*\bout of memory\b",
    "hung_task": r"\bhung task\b|\bblocked for more than \d+ seconds\b",
    "soft_lockup": r"\bsoft lockup\b",
    "hard_lockup": r"\bhard lockup\b|\bwatchdog:\s+bug:.*lockup\b",
    "kernel_panic": r"\bkernel panic\b|\bpanic - not syncing\b",
    "filesystem_error": r"\bext[234]-fs error\b|\bxfs .* error\b",
    "block_io": r"\bblk_update_request\b|\bbuffer i/o error\b|\bend_request\b|\bcritical medium error\b",
    "sata_reset": r"\bata[0-9].*(?:hard resetting|reset failed)\b|\bsata.*reset failed\b",
    "usb_reset": r"\breset (?:high|full|super)-speed usb device\b|\busb .*reset device\b",
    "nic_reset": r"\bnetdev watchdog\b|\btransmit queue.*timed out\b|\b(?:igc|e1000e?|r8169).*(?:adapter reset|resetting)\b|\bfirmware.*reset\b",
    "watchdog_reset": r"\bwatchdog\b.*\b(?:reset|reboot|bootstatus|triggered|bite)\b|\bitco.*\bbootstatus\b",
}


def _run(command, timeout=5):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout or result.stderr
    except Exception:
        return ""


def _read_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _write_state(path: Path, value: dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def scan(cfg: dict[str, Any], event_log=None) -> dict[str, Any]:
    state_path = Path(cfg.get("kernel_fault_state_path") or Path(cfg["events_path"]).parent / "kernel-fault-state.json")
    state = _read_state(state_path)
    cursor = state.get("cursor")
    command = ["journalctl", "-k", "--no-pager", "--show-cursor"]
    if cursor:
        command.insert(2, "--after-cursor")
        command.insert(3, str(cursor))
    else:
        command.insert(2, "-n")
        command.insert(3, "200")
    text = _run(command, timeout=5)
    lines = [line for line in text.splitlines() if line and not line.startswith("-- cursor:")]
    findings = []
    for line in lines:
        lower = line.lower()
        for category, pattern in PATTERNS.items():
            if re.search(pattern, lower):
                findings.append({"category": category, "message": line[-1000:]})
                break
    seen = state.get("seen", {}) if isinstance(state.get("seen", {}), dict) else {}
    new_findings = []
    for finding in findings:
        normalized = re.sub(r"^\w{3}\s+\d+\s+\d+:\d+:\d+\s+", "", finding["message"])
        normalized = re.sub(r"\[[0-9]+\.[0-9]+\]", "", normalized)
        key = f"{finding['category']}:{normalized.strip()}"
        if key in seen:
            seen[key] = int(seen[key]) + 1
            continue
        seen[key] = 1
        new_findings.append(finding)
        if event_log:
            event_log.add("critical" if finding["category"] in {"oom", "kernel_panic", "hard_lockup", "filesystem_error", "block_io"} else "warning", "kernel_fault", finding["category"], finding)
    next_cursor = cursor
    for line in text.splitlines():
        if line.startswith("-- cursor:"):
            next_cursor = line.removeprefix("-- cursor:").strip().removesuffix(" --")
    state = {"cursor": next_cursor or "", "seen": dict(list(seen.items())[-500:]), "updated_at": time.time(), "last_findings": new_findings}
    _write_state(state_path, state)
    return {"cursor": next_cursor or "", "findings": new_findings, "updated_at": state["updated_at"]}
