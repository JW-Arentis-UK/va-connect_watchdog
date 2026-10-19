from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _checkout_root() -> Path:
    return _repo_root().parent


def update_script_path() -> Path:
    return _repo_root() / "scripts" / "update.sh"


def update_state_path(cfg: dict[str, Any]) -> Path:
    return Path(cfg.get("update", {}).get("state_path") or Path(cfg["events_path"]).with_name("update-state.json"))


def update_log_path(cfg: dict[str, Any]) -> Path:
    return Path(cfg.get("update", {}).get("log_path") or Path(cfg["events_path"]).with_name("update.log"))


def load_update_status(cfg: dict[str, Any]) -> dict[str, Any]:
    path = update_state_path(cfg)
    if not path.exists():
        return {
            "state": "idle",
            "message": "No update has been started yet.",
            "branch": "",
            "commit": "",
            "updated_at": "",
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {
        "state": "unknown",
        "message": "Update status is unreadable.",
        "branch": "",
        "commit": "",
        "updated_at": "",
    }


def last_completed(status: dict[str, Any], current_build: str) -> dict[str, str]:
    """Return the latest successful update, including pre-metadata deployments."""
    when = str(status.get("last_completed_at") or "")
    build = str(status.get("last_completed_build") or "")
    if not when and status.get("state") == "completed":
        when = str(status.get("updated_at") or "")
        build = current_build
    return {"at": when, "build": build or (current_build if when else "")}


def update_in_progress(status: dict[str, Any], max_age_seconds: int = 900) -> bool:
    if status.get("state") not in {"queued", "running"}:
        return False
    try:
        stamp = datetime.fromisoformat(str(status.get("updated_at") or "").replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - stamp.astimezone(timezone.utc)).total_seconds()
        return -30 <= age < max_age_seconds
    except (ValueError, TypeError):
        return False


def launch_update_job(cfg: dict[str, Any]) -> dict[str, Any]:
    script = update_script_path()
    if not script.exists():
        return {
            "ok": False,
            "message": f"Update script not found at {script}",
        }

    update_cfg = cfg.get("update", {})
    remote = str(update_cfg.get("remote", "origin")).strip() or "origin"
    branch = str(update_cfg.get("branch", "")).strip()
    before_commit = _git_value(["rev-parse", "--short", "HEAD"])

    cmd = ["/bin/bash", str(script)]
    if branch:
        cmd.extend([remote, branch])
    elif remote:
        cmd.append(remote)

    log_path = update_log_path(cfg)
    state_path = update_state_path(cfg)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)
    unit_name = f"va-watchdog-update-{int(time.time())}"
    systemd_run = shutil.which("systemd-run")
    active_branch = branch or _git_value(["rev-parse", "--abbrev-ref", "HEAD"])
    _write_state(state_path, "queued", f"Waiting for {unit_name} to start", active_branch, before_commit)

    def _launch_direct() -> dict[str, Any]:
        try:
            with log_path.open("ab") as log_handle:
                subprocess.Popen(
                    cmd,
                    cwd=str(_checkout_root()),
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            return {
                "ok": True,
                "message": "Update started in background process.",
                "command": cmd,
                "log_path": str(log_path),
                "before_commit": before_commit,
                "branch": active_branch,
                "mode": "direct",
            }
        except Exception as exc:
            _write_state(state_path, "failed", f"Update could not be launched: {exc}", branch, before_commit)
            return {
                "ok": False,
                "message": f"Update could not be started: {exc}",
                "command": cmd,
                "log_path": str(log_path),
                "before_commit": before_commit,
                "branch": active_branch,
            }

    if not systemd_run:
        return _launch_direct()

    launch_cmd = [
        systemd_run,
        f"--unit={unit_name}",
        "--collect",
        "--no-block",
        f"--setenv=VA_WATCHDOG_STATE_FILE={state_path}",
        f"--setenv=VA_WATCHDOG_LOG_FILE={log_path}",
        *cmd,
    ]
    try:
        result = subprocess.run(
            launch_cmd,
            cwd=str(_checkout_root()),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return _launch_direct()
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemd-run failed").strip()
        direct = _launch_direct()
        if direct.get("ok"):
            direct["message"] = f"Update started without systemd-run after fallback: {detail}"
            direct["command"] = cmd
            return direct
        _write_state(state_path, "failed", detail, branch, before_commit)
        return {
            "ok": False,
            "message": f"Update could not be started: {detail}",
            "command": launch_cmd,
            "log_path": str(log_path),
            "before_commit": before_commit,
            "branch": branch or _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        }
    return {
        "ok": True,
        "message": f"Update started in background unit {unit_name}.",
        "command": launch_cmd,
        "log_path": str(log_path),
        "before_commit": before_commit,
        "branch": active_branch,
        "unit": unit_name,
    }


def _git_value(arguments: list[str]) -> str:
    try:
        checkout = _checkout_root()
        command = ["git", "-c", f"safe.directory={checkout}", "-C", str(checkout), *arguments]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip()
    except Exception:
        return ""


def _write_state(path: Path, state: str, message: str, branch: str, commit: str) -> None:
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(previous, dict):
            previous = {}
    except (OSError, ValueError):
        previous = {}
    last_at = previous.get("last_completed_at") or (previous.get("updated_at") if previous.get("state") == "completed" else "")
    last_build = previous.get("last_completed_build")
    if last_at and not last_build:
        from .build import build_number
        last_build = build_number()
    payload = {
        "state": state,
        "message": message,
        "branch": branch,
        "commit": commit,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "last_completed_at": last_at or "",
        "last_completed_build": last_build or "",
        "last_completed_commit": previous.get("last_completed_commit") or (previous.get("commit") if previous.get("state") == "completed" else ""),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
