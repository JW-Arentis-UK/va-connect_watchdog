from __future__ import annotations

import subprocess
from typing import Any

from ..shared.config import V2Config, load_config
from ..shared.logging import setup_logging
from ..shared.models import CheckResult
from ..shared.normalization import normalize_check_result
from ..shared.paths import log_file_path
from ..shared.time import iso_utc


def process_is_running(match: str) -> bool:
    try:
        completed = subprocess.run(
            ["pgrep", "-f", match],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode == 0
    except FileNotFoundError:
        return False


def build_process_check(match: str) -> dict[str, Any]:
    ok = process_is_running(match)
    result = CheckResult(
        ok=ok,
        last_checked=iso_utc(),
        detail=f"process {'found' if ok else 'missing'} for match '{match}'",
    )
    return normalize_check_result(result.model_dump())


def run_once(config: V2Config) -> dict[str, Any]:
    from ..shared.time import load_boot_id

    logger = setup_logging(config.log_level, log_file_path(config), component="process_watchdog")
    boot_id = load_boot_id()
    logger.info(f"check start | boot_id={boot_id} | match={config.app_match}")
    check = build_process_check(config.app_match)
    logger.info(f"check result ok={check['ok']} | boot_id={boot_id}")
    return check


def main() -> int:
    config = load_config()
    check = run_once(config)
    return 0 if check["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
