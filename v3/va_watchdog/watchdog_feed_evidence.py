from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def current_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def evidence_paths(cfg: dict[str, Any]) -> tuple[Path, Path, Path]:
    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    state = Path(cfg.get("hardware_watchdog_feed_state_path") or data_dir / "hardware-watchdog-feed.json")
    previous = Path(cfg.get("hardware_watchdog_previous_state_path") or data_dir / "hardware-watchdog-feed-previous.json")
    lifecycle = Path(cfg.get("hardware_watchdog_lifecycle_path") or data_dir / "hardware-watchdog-lifecycle.jsonl")
    return state, previous, lifecycle


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def preserve_previous_boot_state(cfg: dict[str, Any], boot_id: str, fallback_boot_id: str = "") -> dict[str, Any]:
    state_path, previous_path, _ = evidence_paths(cfg)
    state = read_json(state_path)
    if not state:
        return {"preserved": False, "reason": "no existing feeder state"}

    state_boot = str(state.get("boot_id") or fallback_boot_id or "")
    if not state_boot:
        return {"preserved": False, "reason": "existing feeder state has no boot ID"}
    if state_boot == boot_id:
        return {"preserved": False, "reason": "existing feeder state belongs to current boot"}

    preserved = {
        **state,
        "boot_id": state_boot,
        "preserved_at": _utc_now(),
        "preserved_before_boot_id": boot_id,
    }
    try:
        atomic_write_json(previous_path, preserved)
    except OSError as exc:
        return {"preserved": False, "reason": f"could not preserve feeder state: {exc}"}
    return {"preserved": True, "path": str(previous_path), "boot_id": state_boot}


def append_lifecycle(
    cfg: dict[str, Any],
    boot_id: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _, _, path = evidence_paths(cfg)
    configured = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog"), dict) else {}
    max_bytes = max(64 * 1024, int(configured.get("lifecycle_max_bytes", 1024 * 1024) or 1024 * 1024))
    payload = {
        "time": _utc_now(),
        "monotonic_uptime": _monotonic_uptime(),
        "boot_id": boot_id,
        "pid": os.getpid(),
        "event": event,
        "details": details or {},
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _trim_if_needed(path, max_bytes)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        return {**payload, "write_error": str(exc)}
    return payload


def feeder_state_for_boot(cfg: dict[str, Any], boot_id: str) -> tuple[dict[str, Any], Path | None]:
    state_path, previous_path, _ = evidence_paths(cfg)
    for path in (previous_path, state_path):
        state = read_json(path)
        if state and str(state.get("boot_id") or "") == boot_id:
            return state, path
    return {}, None


def _trim_if_needed(path: Path, max_bytes: int) -> None:
    try:
        if not path.exists() or path.stat().st_size < max_bytes:
            return
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return
    keep_bytes = int(max_bytes * 0.7)
    kept: list[str] = []
    used = 0
    for line in reversed(lines):
        size = len(line.encode("utf-8")) + 1
        if kept and used + size > keep_bytes:
            break
        kept.append(line)
        used += size
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(reversed(kept)) + ("\n" if kept else ""), encoding="utf-8")
    os.replace(temporary, path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _monotonic_uptime() -> float | None:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 3)
    except (OSError, ValueError, IndexError):
        try:
            return round(time.monotonic(), 3)
        except Exception:
            return None
