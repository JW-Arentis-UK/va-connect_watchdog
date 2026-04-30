from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..shared.config import V2Config, load_config
from ..shared.logging import setup_logging
from ..shared.models import CheckResult
from ..shared.normalization import normalize_check_result
from ..shared.paths import log_file_path
from ..shared.time import iso_utc
from ..shared.system import collect_process_sample


def build_process_check(config: V2Config | dict[str, Any] | str) -> dict[str, Any]:
    process_sample = collect_process_sample(config)
    ok = bool(process_sample.get("process_running"))
    match = ""
    if isinstance(config, str):
        match = config
    elif isinstance(config, dict):
        match = str((config.get("watch_process") or {}).get("name") or config.get("app_match") or "")
    else:
        watch_process = getattr(config, "watch_process", {}) if hasattr(config, "watch_process") else {}
        if isinstance(watch_process, dict):
            match = str(watch_process.get("name") or getattr(config, "app_match", "") or "")
    result = CheckResult(
        ok=ok,
        last_checked=iso_utc(),
        detail=(
            f"process found for match '{match}'"
            if ok
            else f"process missing for match '{match}'"
        ),
    )
    normalized = normalize_check_result(asdict(result))
    normalized["process_pid"] = process_sample.get("process_pid")
    normalized["process_cmd"] = process_sample.get("process_cmd")
    normalized["process_start_time"] = process_sample.get("process_start_time")
    normalized["process_match_mode"] = process_sample.get("process_match_mode")
    return normalized


def run_once(config: V2Config) -> dict[str, Any]:
    from ..shared.time import load_boot_id

    logger = setup_logging(config.log_level, log_file_path(config), component="process_watchdog")
    boot_id = load_boot_id()
    logger.info(f"check start | boot_id={boot_id} | match={config.app_match}")
    check = build_process_check(config)
    logger.info(f"check result ok={check['ok']} | boot_id={boot_id}")
    return check


def main() -> int:
    config = load_config()
    check = run_once(config)
    return 0 if check["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
