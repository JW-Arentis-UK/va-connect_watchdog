from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


ALLOWED_DURATIONS = {900: "15 minutes", 3600: "1 hour"}
MINIMUM_FREE_MB = 100
MAX_ARCHIVES = 3
MAX_AGE_DAYS = 7
_START_LOCK = Lock()


def baseline_paths(cfg: dict[str, Any]) -> tuple[Path, Path]:
    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    output_dir = data_dir / "stage0-baselines"
    return output_dir, output_dir / "state.json"


def baseline_readiness(cfg: dict[str, Any]) -> dict[str, Any]:
    output_dir, _ = baseline_paths(cfg)
    script = _script_path()
    writable = _ensure_writable(output_dir)
    try:
        free_mb = round(shutil.disk_usage(output_dir).free / 1024 / 1024, 1) if writable else None
    except OSError:
        free_mb = None
    main_state = _unit_properties("va-watchdog.service").get("ActiveState", "unknown")
    feed_state = _unit_properties("va-watchdog-feed.service").get("ActiveState", "unknown")
    checks = [
        {"name": "Capture script", "ok": script.is_file(), "detail": str(script)},
        {"name": "systemd-run", "ok": bool(shutil.which("systemd-run")), "detail": shutil.which("systemd-run") or "not found"},
        {"name": "Output directory", "ok": writable, "detail": str(output_dir)},
        {"name": "Free space", "ok": free_mb is not None and free_mb >= MINIMUM_FREE_MB, "detail": f"{free_mb} MB" if free_mb is not None else "unavailable"},
        {"name": "Main watchdog", "ok": main_state == "active", "detail": main_state},
        {"name": "Hardware feeder", "ok": feed_state == "active", "detail": feed_state, "advisory": True},
        {"name": "Persistent journal directory", "ok": Path("/var/log/journal").is_dir(), "detail": "present" if Path("/var/log/journal").is_dir() else "not present", "advisory": True},
    ]
    blocking = [item for item in checks if not item.get("advisory") and not item["ok"]]
    return {"ready": not blocking, "checks": checks, "output_dir": str(output_dir), "free_mb": free_mb}


def baseline_status(cfg: dict[str, Any]) -> dict[str, Any]:
    output_dir, state_path = baseline_paths(cfg)
    state = _read_json(state_path)
    readiness = baseline_readiness(cfg)
    latest = _latest_archive(output_dir, float(state.get("started_unix", 0) or 0))
    if not state:
        return {
            "state": "idle",
            "message": "No Stage 0 baseline capture has been started.",
            "running": False,
            "download_ready": bool(latest),
            "archive": _archive_info(latest),
            "readiness": readiness,
        }

    unit = str(state.get("unit") or "")
    properties = _unit_properties(unit) if unit else {}
    active_state = properties.get("ActiveState", "unknown")
    result = properties.get("Result", "")
    exit_status = properties.get("ExecMainStatus", "")
    now = time.time()
    started = float(state.get("started_unix", 0) or 0)
    duration = int(state.get("duration_seconds", 0) or 0)
    elapsed = max(0, int(now - started)) if started else 0

    if active_state in {"active", "activating", "reloading"}:
        current_state = "running"
        message = f"Baseline capture is running ({elapsed}s elapsed of {duration}s)."
    elif latest and (result in {"", "success"} or exit_status in {"", "0"}):
        current_state = "complete"
        message = "Baseline capture completed and is ready to download."
    elif result and result != "success":
        current_state = "failed"
        message = f"Baseline capture failed: {result} (exit {exit_status or 'unknown'})."
    elif duration and elapsed > duration + 300:
        current_state = "failed"
        message = "Baseline capture did not produce an archive within the expected time."
    else:
        current_state = "queued"
        message = "Baseline capture is queued or waiting for systemd status."

    return {
        **state,
        "state": current_state,
        "message": message,
        "running": current_state in {"queued", "running"},
        "elapsed_seconds": elapsed,
        "active_state": active_state,
        "result": result,
        "exit_status": exit_status,
        "download_ready": current_state == "complete" and bool(latest),
        "archive": _archive_info(latest),
        "readiness": readiness,
    }


def start_baseline(cfg: dict[str, Any], duration_seconds: int) -> dict[str, Any]:
    try:
        duration = int(duration_seconds)
    except (TypeError, ValueError):
        return {"ok": False, "message": "Invalid baseline duration."}
    if duration not in ALLOWED_DURATIONS:
        return {"ok": False, "message": "Baseline duration must be 15 minutes or 1 hour."}

    with _START_LOCK:
        current = baseline_status(cfg)
        if current.get("running"):
            return {"ok": False, "message": "A baseline capture is already running.", "status": current}
        readiness = current.get("readiness") or baseline_readiness(cfg)
        if not readiness.get("ready"):
            return {"ok": False, "message": "Baseline readiness checks failed.", "status": current}

        output_dir, state_path = baseline_paths(cfg)
        _cleanup_archives(output_dir)
        script = _script_path()
        systemd_run = shutil.which("systemd-run")
        if not systemd_run:
            return {"ok": False, "message": "systemd-run is not available."}

        started_unix = time.time()
        started_utc = datetime.now(timezone.utc).isoformat()
        unit = f"va-watchdog-baseline-{int(started_unix)}"
        command = [
            systemd_run,
            f"--unit={unit}",
            "--collect",
            "--no-block",
            "--property=Nice=10",
            "--property=CPUAccounting=yes",
            "--property=MemoryAccounting=yes",
            "/bin/bash",
            str(script),
            str(duration),
            "5",
            str(output_dir),
        ]
        result = _run(command, timeout=15)
        if result["returncode"] != 0:
            return {"ok": False, "message": result["stderr"] or result["stdout"] or "Could not start baseline capture."}

        state = {
            "schema_version": 1,
            "state": "queued",
            "unit": unit,
            "duration_seconds": duration,
            "duration_label": ALLOWED_DURATIONS[duration],
            "interval_seconds": 5,
            "started_unix": started_unix,
            "started_utc": started_utc,
            "output_dir": str(output_dir),
            "command": [str(item) for item in command],
        }
        _write_json_atomic(state_path, state)
        return {"ok": True, "message": f"{ALLOWED_DURATIONS[duration]} baseline capture started.", "status": baseline_status(cfg)}


def completed_archive(cfg: dict[str, Any]) -> Path | None:
    status = baseline_status(cfg)
    if not status.get("download_ready"):
        return None
    archive = status.get("archive") if isinstance(status.get("archive"), dict) else {}
    path = Path(str(archive.get("path") or ""))
    output_dir, _ = baseline_paths(cfg)
    try:
        resolved = path.resolve()
        resolved.relative_to(output_dir.resolve())
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() and resolved.name.endswith(".tar.gz") else None


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "stage0_baseline.sh"


def _ensure_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write-test"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        return True
    except OSError:
        return False


def _run(command: list[str], timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)}


def _unit_properties(unit: str) -> dict[str, str]:
    if not unit:
        return {}
    result = _run(
        ["systemctl", "show", unit, "--property=ActiveState", "--property=SubState", "--property=Result", "--property=ExecMainStatus"],
        timeout=4,
    )
    properties: dict[str, str] = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    return properties


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _latest_archive(output_dir: Path, started_unix: float = 0) -> Path | None:
    try:
        candidates = [
            path
            for path in output_dir.glob("va-watchdog-stage0-*.tar.gz")
            if path.is_file() and path.stat().st_mtime >= max(0, started_unix - 2)
        ]
        return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None
    except OSError:
        return None


def _archive_info(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        stat = path.stat()
        return {"name": path.name, "path": str(path), "size_bytes": stat.st_size, "modified_unix": stat.st_mtime}
    except OSError:
        return None


def _cleanup_archives(output_dir: Path) -> None:
    cutoff = time.time() - MAX_AGE_DAYS * 86400
    try:
        archives = sorted(
            (path for path in output_dir.glob("va-watchdog-stage0-*.tar.gz") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return
    for index, path in enumerate(archives):
        try:
            if index >= MAX_ARCHIVES - 1 or path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            continue
    try:
        directories = sorted(
            (path for path in output_dir.glob("va-watchdog-stage0-*") if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return
    for index, path in enumerate(directories):
        try:
            if index >= MAX_ARCHIVES - 1 or path.stat().st_mtime < cutoff:
                shutil.rmtree(path)
        except OSError:
            continue
