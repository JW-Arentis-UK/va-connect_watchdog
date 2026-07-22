#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "v3" / "va_watchdog"
SYSTEMD = ROOT / "v3" / "systemd"


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())


def build_report() -> dict:
    modules = sorted(PACKAGE.glob("*.py"))
    units = sorted(SYSTEMD.glob("*.service"))
    module_rows = [{"name": path.name, "lines": line_count(path)} for path in modules]
    web_lines = next((row["lines"] for row in module_rows if row["name"] == "web.py"), 0)
    return {
        "production_python_modules": len(modules),
        "production_python_lines": sum(row["lines"] for row in module_rows),
        "web_lines": web_lines,
        "systemd_service_units": len(units),
        "modules": sorted(module_rows, key=lambda row: row["lines"], reverse=True),
        "services": [path.name for path in units],
        "targets": {
            "production_python_modules_min": 16,
            "production_python_modules_max": 20,
            "production_python_lines_min": 4500,
            "production_python_lines_max": 6000,
            "web_lines_min": 1200,
            "web_lines_max": 1800,
            "systemd_service_units": 3,
        },
    }


def violations(report: dict) -> list[str]:
    targets = report["targets"]
    checks = [
        (targets["production_python_modules_min"] <= report["production_python_modules"] <= targets["production_python_modules_max"], "production module count outside target"),
        (targets["production_python_lines_min"] <= report["production_python_lines"] <= targets["production_python_lines_max"], "production Python lines outside target"),
        (targets["web_lines_min"] <= report["web_lines"] <= targets["web_lines_max"], "Web lines outside target"),
        (report["systemd_service_units"] == targets["systemd_service_units"], "systemd service count outside target"),
    ]
    return [message for passed, message in checks if not passed]


def main() -> int:
    parser = argparse.ArgumentParser(description="Report VA-Connect Watchdog architecture size budgets.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--enforce", action="store_true", help="Return failure when final target budgets are not met.")
    args = parser.parse_args()

    report = build_report()
    issues = violations(report)
    report["violations"] = issues

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("VA-Connect Watchdog architecture report")
        print(f"Production modules: {report['production_python_modules']} (target 16-20)")
        print(f"Production Python lines: {report['production_python_lines']} (target 4500-6000)")
        print(f"Web lines: {report['web_lines']} (target 1200-1800)")
        print(f"Systemd service units: {report['systemd_service_units']} (target 3)")
        print("Largest modules:")
        for row in report["modules"][:10]:
            print(f"  {row['name']}: {row['lines']}")
        if issues:
            print("Current target differences:")
            for issue in issues:
                print(f"  - {issue}")
            if not args.enforce:
                print("Informational during migration; use --enforce only at final conformance.")

    return 1 if args.enforce and issues else 0


if __name__ == "__main__":
    raise SystemExit(main())

