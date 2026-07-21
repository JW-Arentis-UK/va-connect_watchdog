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
    if not systemd_run:
        return {
            "ok": False,
            "message": "Update could not start because systemd-run is unavailable.",
            "command": cmd,
            "log_path": str(log_path),
            "before_commit": before_commit,
            "branch": branch or _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        }

    launch_cmd = [
        systemd_run,
        f"--unit={unit_name}",
        "--collect",
        "--no-block",
        f"--setenv=VA_WATCHDOG_STATE_FILE={state_path}",
        f"--setenv=VA_WATCHDOG_LOG_FILE={log_path}",
        *cmd,
    ]
    active_branch = branch or _git_value(["rev-parse", "--abbrev-ref", "HEAD"])
    _write_state(state_path, "queued", f"Waiting for {unit_name} to start", active_branch, before_commit)
    try:
        result = subprocess.run(
            launch_cmd,
            cwd=str(_checkout_root()),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        _write_state(state_path, "failed", f"Update could not be launched: {exc}", branch, before_commit)
        return {
            "ok": False,
            "message": f"Update could not be started: {exc}",
            "command": launch_cmd,
            "log_path": str(log_path),
            "before_commit": before_commit,
            "branch": branch or _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        }
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemd-run failed").strip()
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
    payload = {
        "state": state,
        "message": message,
        "branch": branch,
        "commit": commit,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
