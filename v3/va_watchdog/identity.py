from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Callable


DEFAULT_IDENTITY = {
    "site_name": "",
    "asset_id": "",
}


def configured_identity(cfg: dict[str, Any]) -> dict[str, Any]:
    value = cfg.get("identity", {})
    identity = value if isinstance(value, dict) else {}
    site_name = str(identity.get("site_name") or "").strip()
    asset_id = str(identity.get("asset_id") or "").strip()
    return {
        "site_name": site_name,
        "asset_id": asset_id,
        "configured": bool(site_name),
        "display_name": site_name or "Site not configured",
    }


def identity_slug(cfg: dict[str, Any]) -> str:
    identity = configured_identity(cfg)
    source = identity["site_name"] or identity["asset_id"] or platform.node() or "gateway"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", source.strip()).strip("-._")
    return (slug or "gateway")[:48]


def identity_summary(
    cfg: dict[str, Any],
    runner: Callable[[list[str]], str] | None = None,
    machine_id_path: Path = Path("/etc/machine-id"),
) -> dict[str, Any]:
    configured = configured_identity(cfg)
    run = runner or _run
    devices = _block_devices(run)
    os_disk = _disk_for_mount(devices, "/") or _first_disk(devices)
    recording_cfg = cfg.get("recording_storage", {})
    recording_mountpoint = (
        str(recording_cfg.get("mountpoint") or "")
        if isinstance(recording_cfg, dict)
        else ""
    )
    recording_disk = _disk_for_mount(devices, recording_mountpoint) if recording_mountpoint else None
    machine_id = _read_text(machine_id_path)
    fingerprint_source = "|".join(
        part
        for part in [
            machine_id,
            str((os_disk or {}).get("serial") or ""),
            str((recording_disk or {}).get("serial") or ""),
        ]
        if part
    )
    fingerprint = (
        hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:12].upper()
        if fingerprint_source
        else ""
    )
    return {
        **configured,
        "hostname": platform.node(),
        "hardware_fingerprint": fingerprint,
        "machine_id_hash": hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:12].upper() if machine_id else "",
        "os_disk": _public_disk(os_disk),
        "recording_disk": _public_disk(recording_disk),
    }


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _block_devices(runner: Callable[[list[str]], str]) -> list[dict[str, Any]]:
    raw = runner(
        [
            "lsblk",
            "--json",
            "-o",
            "NAME,PATH,TYPE,PKNAME,MOUNTPOINTS,MODEL,SERIAL,SIZE",
        ]
    )
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return []
    roots = payload.get("blockdevices", []) if isinstance(payload, dict) else []
    flattened: list[dict[str, Any]] = []

    def visit(item: Any, parent: dict[str, Any] | None = None) -> None:
        if not isinstance(item, dict):
            return
        current = dict(item)
        current["_parent"] = parent
        flattened.append(current)
        for child in item.get("children", []) or []:
            visit(child, current)

    for root in roots if isinstance(roots, list) else []:
        visit(root)
    return flattened


def _mountpoints(item: dict[str, Any]) -> list[str]:
    value = item.get("mountpoints")
    if isinstance(value, list):
        return [str(item) for item in value if item]
    mountpoint = item.get("mountpoint")
    return [str(mountpoint)] if mountpoint else []


def _disk_for_mount(devices: list[dict[str, Any]], mountpoint: str) -> dict[str, Any] | None:
    if not mountpoint:
        return None
    for item in devices:
        if mountpoint not in _mountpoints(item):
            continue
        current = item
        while isinstance(current.get("_parent"), dict):
            current = current["_parent"]
        return current if current.get("type") == "disk" else item
    return None


def _first_disk(devices: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((item for item in devices if item.get("type") == "disk"), None)


def _public_disk(item: dict[str, Any] | None) -> dict[str, str]:
    if not item:
        return {"device": "", "model": "", "serial": "", "size": ""}
    return {
        "device": str(item.get("path") or (f"/dev/{item.get('name')}" if item.get("name") else "")),
        "model": str(item.get("model") or "").strip(),
        "serial": str(item.get("serial") or "").strip(),
        "size": str(item.get("size") or "").strip(),
    }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
