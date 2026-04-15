from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    current = value or utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_boot_id() -> str:
    override = str(os.environ.get("VA_CONNECT_V2_BOOT_ID", "")).strip()
    if override:
        return override

    boot_id_path = Path("/proc/sys/kernel/random/boot_id")
    if boot_id_path.exists():
        try:
            value = boot_id_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass

    return "unknown"
