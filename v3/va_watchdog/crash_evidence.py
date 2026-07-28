from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def pstore_status() -> dict[str, Any]:
    path = Path("/sys/fs/pstore")
    archived_path = Path("/var/lib/systemd/pstore")
    files = _files(path)
    archived_files = _files(archived_path)
    mounted = False
    try:
        mounted = any(
            len(parts := line.split()) >= 3 and parts[1] == str(path) and parts[2] == "pstore"
            for line in Path("/proc/mounts").read_text(encoding="utf-8", errors="ignore").splitlines()
        )
    except OSError:
        pass
    kernel_support = _kernel_setting("CONFIG_PSTORE")
    backend_settings = {
        name: _kernel_setting(name)
        for name in ("CONFIG_PSTORE_RAM", "CONFIG_EFI_VARS_PSTORE", "CONFIG_PSTORE_PMSG")
    }
    return {
        "available": path.is_dir(),
        "mounted": mounted,
        "path": str(path),
        "archived_path": str(archived_path),
        "kernel_support": kernel_support,
        "backend_settings": backend_settings,
        "files": files,
        "archived_files": archived_files,
        "has_crash_records": bool(files or archived_files),
        "message": (
            f"{len(files) + len(archived_files)} preserved crash record(s)"
            if files or archived_files
            else "pstore is available but contains no crash records"
            if path.is_dir()
            else "pstore is not exposed by this kernel/platform"
        ),
    }


def _files(path: Path) -> list[dict[str, Any]]:
    files = []
    if not path.is_dir():
        return files
    try:
        for item in sorted(path.iterdir()):
            if item.is_file():
                files.append({"name": item.name, "size_bytes": item.stat().st_size})
    except OSError:
        return []
    return files


def _kernel_setting(name: str) -> str:
    release = ""
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    config = Path("/boot") / f"config-{release}"
    try:
        match = re.search(rf"^{re.escape(name)}=(.+)$", config.read_text(encoding="utf-8", errors="ignore"), re.MULTILINE)
        return match.group(1).strip() if match else "not set"
    except OSError:
        return "unknown"
