from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


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

    cmd = ["/bin/bash", str(script)]
    if branch:
        cmd.extend([remote, branch])
    elif remote:
        cmd.append(remote)

    log_path = update_log_path(cfg)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("a", encoding="utf-8")
    subprocess.Popen(
        cmd,
        cwd=str(_repo_root()),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return {
        "ok": True,
        "message": "Update started in the background.",
        "command": cmd,
        "log_path": str(log_path),
    }
