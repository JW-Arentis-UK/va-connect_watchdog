from __future__ import annotations

import gzip
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def archive_config(cfg: dict[str, Any]) -> dict[str, Any]:
    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    configured = cfg.get("incident_archive", {}) if isinstance(cfg.get("incident_archive"), dict) else {}
    return {
        "enabled": bool(configured.get("enabled", True)),
        "path": Path(configured.get("path") or data_dir / "incidents"),
        "max_incidents": max(1, int(configured.get("max_incidents", 10) or 10)),
        "max_total_mb": max(5, int(configured.get("max_total_mb", 25) or 25)),
        "event_tail_rows": max(100, int(configured.get("event_tail_rows", 1000) or 1000)),
        "pstore_file_max_mb": max(1, int(configured.get("pstore_file_max_mb", 5) or 5)),
    }


def archive_previous_boot(
    cfg: dict[str, Any],
    boot_change: dict[str, Any],
    evidence: dict[str, Any],
    kernel_text: str,
    last_x: str,
) -> dict[str, Any]:
    settings = archive_config(cfg)
    previous_boot = str(boot_change.get("previous_boot_id") or "")
    if not settings["enabled"] or not boot_change.get("changed") or not previous_boot:
        return {"created": False, "reason": "disabled or no previous boot"}

    root = settings["path"]
    root.mkdir(parents=True, exist_ok=True)
    existing = _existing_archive(root, previous_boot)
    if existing:
        return {"created": False, "reason": "already archived", "path": str(existing)}

    detected = str(boot_change.get("detected_at") or _now_iso())
    stamp = _safe_stamp(detected)
    target = root / f"{stamp}-{previous_boot[:12]}"
    temporary = root / f".{target.name}.tmp-{os.getpid()}"
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True)

    data_dir = Path(cfg.get("events_path", "/var/lib/va-watchdog/events.jsonl")).parent
    files: list[dict[str, Any]] = []
    files.append(_write_json(temporary / "reboot-evidence.json", evidence))
    files.append(_write_text(temporary / "previous-boot-kernel.log", kernel_text))
    files.append(_write_text(temporary / "last-x.log", last_x))

    status_path = Path(cfg.get("status_path") or data_dir / "status.json")
    files.append(_copy_file(status_path, temporary / "last-status.json"))
    feed_path = Path(cfg.get("hardware_watchdog_feed_state_path") or data_dir / "hardware-watchdog-feed.json")
    files.append(_copy_file(feed_path, temporary / "last-watchdog-feed.json"))

    heartbeat_path = Path(cfg.get("heartbeat_path") or data_dir / "heartbeat.jsonl")
    files.append(_filter_jsonl(heartbeat_path, temporary / "heartbeat.jsonl.gz", previous_boot))
    blackbox_cfg = cfg.get("blackbox", {}) if isinstance(cfg.get("blackbox"), dict) else {}
    blackbox_path = Path(blackbox_cfg.get("path") or data_dir / "blackbox.jsonl")
    files.append(_filter_jsonl(blackbox_path, temporary / "blackbox.jsonl.gz", previous_boot))
    history_path = Path(cfg.get("history_path") or data_dir / "history.jsonl")
    files.append(_filter_jsonl(history_path, temporary / "history.jsonl.gz", previous_boot))
    events_path = Path(cfg.get("events_path") or data_dir / "events.jsonl")
    files.append(_tail_jsonl(events_path, temporary / "events-tail.jsonl.gz", settings["event_tail_rows"]))
    files.extend(_copy_pstore(temporary / "pstore", settings["pstore_file_max_mb"]))

    manifest = {
        "schema_version": 1,
        "created_at": _now_iso(),
        "previous_boot_id": previous_boot,
        "current_boot_id": str(boot_change.get("current_boot_id") or ""),
        "detected_at": detected,
        "classification": evidence.get("classification", "Unknown"),
        "reset_mechanism": evidence.get("reset_mechanism", "Unknown"),
        "probable_preceding_fault": evidence.get("probable_preceding_fault", "none identified"),
        "files": [item for item in files if item],
    }
    _write_json(temporary / "manifest.json", manifest)
    temporary.replace(target)
    retention = enforce_archive_retention(cfg)
    return {
        "created": True,
        "path": str(target),
        "previous_boot_id": previous_boot,
        "files": len(manifest["files"]),
        "retention": retention,
    }


def list_archives(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    root = archive_config(cfg)["path"]
    if not root.exists():
        return []
    result = []
    for directory in sorted((item for item in root.iterdir() if item.is_dir() and not item.name.startswith(".")), reverse=True):
        manifest = _read_json(directory / "manifest.json")
        result.append(
            {
                "name": directory.name,
                "path": str(directory),
                "size_bytes": _directory_size(directory),
                "manifest": manifest,
            }
        )
    return result


def enforce_archive_retention(cfg: dict[str, Any]) -> dict[str, Any]:
    settings = archive_config(cfg)
    root = settings["path"]
    archives = list_archives(cfg)
    max_bytes = settings["max_total_mb"] * 1024 * 1024
    removed = []
    while archives and (
        len(archives) > settings["max_incidents"]
        or (len(archives) > 1 and sum(item["size_bytes"] for item in archives) > max_bytes)
    ):
        oldest = archives.pop()
        path = Path(oldest["path"])
        try:
            shutil.rmtree(path)
            removed.append({"path": str(path), "size_bytes": oldest["size_bytes"]})
        except OSError:
            break
    return {
        "path": str(root),
        "max_incidents": settings["max_incidents"],
        "max_total_mb": settings["max_total_mb"],
        "retained": len(archives),
        "used_bytes": sum(item["size_bytes"] for item in archives),
        "removed": removed,
    }


def _existing_archive(root: Path, previous_boot: str) -> Path | None:
    for directory in root.iterdir():
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        manifest = _read_json(directory / "manifest.json")
        if str(manifest.get("previous_boot_id") or "") == previous_boot:
            return directory
    return None


def _filter_jsonl(source: Path, destination: Path, boot_id: str) -> dict[str, Any]:
    rows = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(destination, "wt", encoding="utf-8") as output:
        if source.exists():
            with source.open("r", encoding="utf-8", errors="ignore") as input_file:
                for line in input_file:
                    line = line.rstrip("\r\n")
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(payload, dict) and str(payload.get("boot_id") or "") == boot_id:
                        output.write(json.dumps(payload, separators=(",", ":")) + "\n")
                        rows += 1
    return {"path": destination.name, "source": str(source), "rows": rows, "size_bytes": destination.stat().st_size}


def _tail_jsonl(source: Path, destination: Path, limit: int) -> dict[str, Any]:
    lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:] if source.exists() else []
    with gzip.open(destination, "wt", encoding="utf-8") as output:
        for line in lines:
            output.write(line + "\n")
    return {"path": destination.name, "source": str(source), "rows": len(lines), "size_bytes": destination.stat().st_size}


def _copy_pstore(destination: Path, max_file_mb: int) -> list[dict[str, Any]]:
    copied = []
    maximum = max_file_mb * 1024 * 1024
    sources = (("live", Path("/sys/fs/pstore")), ("archived", Path("/var/lib/systemd/pstore")))
    for source_name, source in sources:
        if not source.is_dir():
            continue
        for item in sorted(source.iterdir()):
            if not item.is_file():
                continue
            try:
                data = item.read_bytes()[:maximum]
                target = destination / source_name / item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                copied.append({"path": str(Path("pstore") / source_name / item.name), "source": str(item), "size_bytes": len(data)})
            except OSError:
                continue
    if not copied:
        copied.append({"path": "pstore", "sources": [str(item[1]) for item in sources], "files": 0})
    return copied


def _copy_file(source: Path, destination: Path) -> dict[str, Any]:
    if not source.is_file():
        return {"path": destination.name, "source": str(source), "available": False}
    shutil.copy2(source, destination)
    return {"path": destination.name, "source": str(source), "size_bytes": destination.stat().st_size}


def _write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {"path": path.name, "size_bytes": path.stat().st_size}


def _write_text(path: Path, text: str) -> dict[str, Any]:
    path.write_text(text, encoding="utf-8")
    return {"path": path.name, "size_bytes": path.stat().st_size}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _directory_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError:
                continue
    return total


def _safe_stamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
