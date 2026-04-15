from __future__ import annotations

from pathlib import Path
import os


def default_data_dir() -> Path:
    override = str(os.environ.get("VA_CONNECT_V2_DATA_DIR", "")).strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / ".v2-data"


def data_dir(config: object | None = None) -> Path:
    if config is not None and hasattr(config, "data_dir"):
        return Path(getattr(config, "data_dir"))
    return default_data_dir()


def logs_dir(config: object | None = None) -> Path:
    return data_dir(config) / "logs"


def config_path(config: object | None = None) -> Path:
    return data_dir(config) / "config.json"


def events_path(config: object | None = None) -> Path:
    return data_dir(config) / "events.jsonl"


def incidents_path(config: object | None = None) -> Path:
    return data_dir(config) / "incidents.jsonl"


def state_path(config: object | None = None) -> Path:
    return data_dir(config) / "state.json"


def device_status_path(config: object | None = None) -> Path:
    return data_dir(config) / "device_status.json"


def metrics_path(config: object | None = None) -> Path:
    return data_dir(config) / "metrics.jsonl"


def log_file_path(config: object | None = None) -> Path:
    return logs_dir(config) / "v2.log"
