from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import socket
from typing import Any

from .paths import default_data_dir, repo_root


@dataclass(frozen=True)
class V2Config:
    device_id: str
    data_dir: Path
    app_match: str
    wan_hosts: tuple[str, ...]
    check_interval_seconds: int
    ping_timeout_seconds: int
    web_host: str
    web_port: int
    log_level: str


def _load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_config() -> V2Config:
    env_config = str(os.environ.get("VA_CONNECT_V2_CONFIG", "")).strip()
    candidate_paths = []
    if env_config:
        candidate_paths.append(Path(env_config))
    candidate_paths.append(repo_root() / "site-watchdog.json")
    candidate_paths.append(repo_root() / "config.json")
    candidate_paths.append(default_data_dir() / "config.json")

    raw: dict[str, Any] = {}
    for candidate in candidate_paths:
        raw = _load_config_file(candidate)
        if raw:
            break

    device_id = str(os.environ.get("VA_CONNECT_V2_DEVICE_ID", raw.get("device_id", socket.gethostname()))).strip() or socket.gethostname()
    data_dir = Path(str(os.environ.get("VA_CONNECT_V2_DATA_DIR", raw.get("data_dir", default_data_dir()))))
    app_match = str(os.environ.get("VA_CONNECT_V2_APP_MATCH", raw.get("app_match", "va-connect"))).strip() or "va-connect"
    wan_hosts_raw = str(os.environ.get("VA_CONNECT_V2_WAN_HOSTS", raw.get("wan_hosts", "1.1.1.1"))).strip()
    wan_hosts = tuple(host.strip() for host in wan_hosts_raw.split(",") if host.strip()) or ("1.1.1.1",)
    check_interval_seconds = int(os.environ.get("VA_CONNECT_V2_CHECK_INTERVAL_SECONDS", raw.get("check_interval_seconds", 30)))
    ping_timeout_seconds = int(os.environ.get("VA_CONNECT_V2_PING_TIMEOUT_SECONDS", raw.get("ping_timeout_seconds", 3)))
    web_host = str(os.environ.get("VA_CONNECT_V2_WEB_HOST", raw.get("web_host", "127.0.0.1"))).strip() or "127.0.0.1"
    web_port = int(os.environ.get("VA_CONNECT_V2_WEB_PORT", raw.get("web_port", 8787)))
    log_level = str(os.environ.get("VA_CONNECT_V2_LOG_LEVEL", raw.get("log_level", "INFO"))).strip().upper() or "INFO"

    return V2Config(
        device_id=device_id,
        data_dir=data_dir,
        app_match=app_match,
        wan_hosts=wan_hosts,
        check_interval_seconds=check_interval_seconds,
        ping_timeout_seconds=ping_timeout_seconds,
        web_host=web_host,
        web_port=web_port,
        log_level=log_level,
    )
