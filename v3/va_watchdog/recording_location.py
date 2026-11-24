"""Read-only recording discovery shared by history and storage monitoring."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

STATE = Path("/var/lib/va-watchdog/recording-location.json")
_LOCK = threading.Lock()
_CACHE = {}
FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "exfat", "vfat", "ntfs", "ntfs3", "fuseblk"}


def mounted_filesystems():
    try:
        result = subprocess.run(["findmnt", "-J", "-l", "-o", "TARGET,SOURCE,FSTYPE,UUID"],
                                capture_output=True, text=True, timeout=3, check=False)
        if result.returncode:
            return []
        rows = json.loads(result.stdout).get("filesystems", [])
        return [row for row in rows if str(row.get("source", "")).startswith("/dev/")
                and not str(row.get("source", "")).startswith("/dev/loop")
                and row.get("fstype") in FILESYSTEMS and row.get("target")][:64]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def configured_paths(cfg):
    rec = cfg.get("recording_storage", {})
    path = rec.get("directory_path") if rec.get("mode") == "system_directory" else str(
        Path(rec.get("mountpoint") or "/media/vsuser/Storage") / str(rec.get("recording_subdir", "recordings")).strip("/"))
    return list(dict.fromkeys(str(value) for value in (cfg.get("storage", {}).get("recordings_path"), path,
                                                    "/recordings", "/home/vsuser/recordings") if value))


def _timestamp(name):
    stem = name.split(".", 1)[0]
    if stem.isdigit() and 946684800 <= int(stem) <= 4102444800:
        return int(stem)
    return None


def evidence(path, deadline):
    """At most two levels, bounded entries/time; no symlinks or metadata-only matches."""
    newest = None
    buckets = []
    try:
        with os.scandir(path) as entries:
            for index, entry in enumerate(entries):
                if index >= 10000 or time.monotonic() >= deadline:
                    break
                stamp = _timestamp(entry.name)
                if stamp is None or entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False) and entry.name.endswith((".data", ".mp4", ".mkv")):
                    newest = max(newest or 0, stamp)
                elif entry.is_dir(follow_symlinks=False):
                    buckets.append((stamp, entry.path))
        for _, bucket in sorted(buckets, reverse=True)[:4]:
            with os.scandir(bucket) as entries:
                for index, entry in enumerate(entries):
                    if index >= 2048 or time.monotonic() >= deadline:
                        break
                    stamp = _timestamp(entry.name)
                    if stamp is not None and entry.name.endswith((".data", ".mp4", ".mkv")) and entry.is_file(follow_symlinks=False):
                        newest = max(newest or 0, stamp)
    except OSError:
        pass
    return newest


def _mount_for(path, mounts):
    matches = []
    for row in mounts:
        try:
            Path(path).relative_to(row["target"])
            matches.append(row)
        except ValueError:
            pass
    return max(matches, key=lambda row: len(row["target"]), default=None)


def _saved(key):
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
        return value.get("location") if value.get("key") == key else None
    except (OSError, ValueError, AttributeError):
        return None


def _remember(key, location):
    # Only the core/root collector persists decisions. Web reads never need write access.
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        temporary = STATE.with_suffix(".tmp")
        temporary.write_text(json.dumps({"key": key, "location": location}), encoding="utf-8")
        os.chmod(temporary, 0o644)
        os.replace(temporary, STATE)
    except OSError:
        pass


def _resolve(cfg, mounts, key):
    saved = _saved(key)
    if saved:
        identity = saved.get("uuid") or saved.get("source")
        current = next((row for row in mounts if (row.get("uuid") or row.get("source")) == identity), None)
        if current is None:
            return dict(saved, state="missing", message="Previously detected recording disk is missing; no fallback selected")
        path = str(Path(current["target"]) / saved["subdir"])
        return dict(saved, path=path, mountpoint=current["target"], filesystem=current["fstype"],
                    state="detected", message="Automatically detected recording location")
    if not mounts:
        return {"state": "not_found", "message": "No recording disks discovered; using configured location"}
    configured = configured_paths(cfg)
    candidates = []
    for row in mounts:
        if row["target"] != "/":
            candidates.extend([str(Path(row["target"]) / "recordings"), row["target"]])
    candidates.extend(configured)
    found = []
    deadline = time.monotonic() + 3
    for raw in dict.fromkeys(candidates):
        path = Path(raw)
        if not path.is_absolute():
            continue
        # Resolve aliases to the underlying mount rather than incorrectly identifying root.
        try:
            path = path.resolve()
        except (OSError, RuntimeError):
            continue
        mount = _mount_for(path, mounts)
        if mount is None:
            continue
        if mount["target"] == "/" and any(item["mountpoint"] != "/" for item in found):
            continue
        newest = evidence(path, deadline)
        if newest is not None:
            value = {"path": str(path), "mountpoint": mount["target"], "source": mount["source"],
                     "uuid": mount.get("uuid") or "", "filesystem": mount["fstype"],
                     "subdir": str(path.relative_to(mount["target"])), "newest": newest}
            if not any(item["path"] == value["path"] for item in found):
                found.append(value)
    if time.monotonic() >= deadline:
        return {"state": "ambiguous", "message": "Recording discovery reached its time limit; no automatic location selected",
                "candidates": [item["path"] for item in found]}
    external = [item for item in found if item["mountpoint"] != "/"]
    choices = external or found
    if len(choices) > 1:
        explicit = [item for item in choices if item["path"] in configured[:2]]
        if len(explicit) == 1:
            choices = explicit
    if len(choices) == 1:
        result = dict(choices[0], state="detected", message="Automatically detected recording location")
        _remember(key, result)
        return result
    if choices:
        return {"state": "ambiguous", "message": "Multiple recording locations found; select the intended location in storage settings",
                "candidates": [item["path"] for item in choices]}
    return {"state": "not_found", "message": "No recording files found on mounted disks; using configured location"}


def resolve(cfg):
    if not cfg.get("recording_storage", {}).get("auto_detect", True):
        return {"state": "disabled", "message": "Using manually configured recording location"}
    key = hashlib.sha256(json.dumps(configured_paths(cfg)).encode()).hexdigest()
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and time.monotonic() - cached[0] < 30:
            return dict(cached[1])
        mounts = mounted_filesystems()
        result = _resolve(cfg, mounts, key)
        _CACHE.clear()
        _CACHE[key] = (time.monotonic(), result)
        return dict(result)
