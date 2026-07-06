from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from .common import CheckResult

def _disk_usage_percent(path):
    total, used, free = shutil.disk_usage(path)
    return {
        "path": path,
        "used_percent": round((used / total) * 100, 1),
        "free_gb": round(free / 1024 / 1024 / 1024, 1),
        "total_gb": round(total / 1024 / 1024 / 1024, 1),
    }

def _writable(path):
    p = Path(path)
    test_file = p / ".va_watchdog_write_test"
    try:
        p.mkdir(parents=True, exist_ok=True)
        test_file.write_text(str(time.time()), encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def _usage_check(name, path, warn, crit, critical):
    if not os.path.exists(path):
        return CheckResult(name, "warning", f"{path} not found", None, False)
    try:
        usage = _disk_usage_percent(path)
        used = usage["used_percent"]
        if used >= crit:
            return CheckResult(name, "critical", f"{path} disk critical", usage, critical)
        if used >= warn:
            return CheckResult(name, "warning", f"{path} disk warning", usage)
        return CheckResult(name, "healthy", f"{path} disk OK", usage)
    except Exception as e:
        return CheckResult(name, "unknown", str(e), None, critical)

def check_storage(cfg):
    th = cfg["thresholds"]
    st = cfg["storage"]
    checks = [
        _usage_check("root_disk", st["root_path"], th["root_disk_warning_percent"], th["root_disk_critical_percent"], True),
        _usage_check("recordings_disk", st["recordings_path"], th["recordings_disk_warning_percent"], th["recordings_disk_critical_percent"], False),
    ]
    writable = _writable(st["write_test_path"])
    checks.append(CheckResult(
        "write_test",
        "healthy" if writable else "critical",
        "Storage write test OK" if writable else "Storage write test failed",
        writable,
        True
    ))
    return checks
