#!/usr/bin/env python3
"""Enable a 1920x1080 virtual HDMI output on Raspberry Pi OS.

Copy this one file to the Pi, then run: sudo python3 enable_pi_dummy_display.py
The script does not reboot or restart an active desktop session.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

MANAGERS = ("lightdm.service", "gdm3.service", "gdm.service", "sddm.service")
BACKUP_DIR = Path("/var/backups/va-watchdog/headless-display")
WATCHDOG_CONFIG = Path("/etc/va-watchdog/config.json")
WATCHDOG_DISPLAY_MODULE = Path("/opt/va-connect-watchdog-v3/v3/va_watchdog/display_monitor.py")


def os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def pi_release(values: dict[str, str], model: str, marker: bool) -> int:
    if "raspberry pi" not in model.lower() or not (marker or values.get("ID") == "raspbian"):
        raise RuntimeError("This script only supports Raspberry Pi OS on Raspberry Pi hardware")
    try:
        return int(values["VERSION_ID"].split(".")[0])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("Could not determine Raspberry Pi OS version") from exc


def legacy_text(original: str, output: str) -> str:
    port = "" if output == "HDMI-A-1" else ":1"
    start, end = "# BEGIN VA-CONNECT HEADLESS HDMI", "# END VA-CONNECT HEADLESS HDMI"
    if start in original:
        if end not in original:
            raise RuntimeError("The existing managed HDMI block is incomplete")
        original = re.sub(re.escape(start) + r".*?" + re.escape(end) + r"\n?", "", original, flags=re.S)
    block = (f"{start}\n[all]\nhdmi_force_hotplug{port}=1\n"
             f"hdmi_group{port}=2\nhdmi_mode{port}=82\n{end}\n")
    return original.rstrip() + "\n\n" + block


def kms_text(original: str, output: str) -> str:
    parts = original.strip().split()
    setting = f"video={output}:1920x1080M@60D"
    matches = [index for index, value in enumerate(parts) if value.startswith(f"video={output}:")]
    if matches:
        parts[matches[0]] = setting
        for index in reversed(matches[1:]):
            del parts[index]
    else:
        parts.append(setting)
    return " ".join(parts) + "\n"


def installed_manager() -> str | None:
    for name in MANAGERS:
        try:
            result = subprocess.run(["systemctl", "show", "-p", "LoadState", "--value", name],
                                    check=False, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            return name
    return None


def save_file(path: Path, contents: str, backup_dir: Path = BACKUP_DIR) -> bool:
    before = path.read_text(encoding="utf-8")
    if before == contents:
        return False
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = backup_dir / f"{path.name}.{stamp}.bak"
    shutil.copyfile(path, backup)
    os.chmod(backup, 0o600)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".headless-", delete=False) as handle:
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Updated {path}; backup: {backup}")
    return True


def update_watchdog(manager: str, expect_x11: bool, config: Path = WATCHDOG_CONFIG) -> None:
    if not config.exists():
        print("V3 watchdog configuration not found; HDMI output is configured, but watchdog display monitoring was not enabled.")
        return
    if not WATCHDOG_DISPLAY_MODULE.exists():
        print("This watchdog installation lacks display_monitor.py; update the watchdog before enabling display monitoring.")
        return
    data = json.loads(config.read_text(encoding="utf-8"))
    data.setdefault("display_monitor", {}).update({
        "enabled": True, "manager": manager, "expect_x11": expect_x11,
        "check_interval_seconds": 30, "startup_grace_seconds": 90,
        "restart_cooldown_seconds": 300, "max_restarts_per_hour": 3,
    })
    save_file(config, json.dumps(data, indent=2) + "\n")
    subprocess.run(["systemctl", "try-restart", "va-watchdog.service"], check=True, timeout=30)
    print("Enabled V3 display monitoring.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", choices=("HDMI-A-1", "HDMI-A-2"), default="HDMI-A-1",
                        help="HDMI port to force (default: first port)")
    parser.add_argument("--dry-run", action="store_true", help="Show the change without writing files")
    args = parser.parse_args()
    if not args.dry_run and os.geteuid() != 0:
        parser.error("Run with sudo to write boot settings")

    model_path = Path("/proc/device-tree/model")
    model = model_path.read_text(encoding="utf-8", errors="replace") if model_path.exists() else ""
    release = pi_release(os_release(), model, Path("/etc/rpi-issue").exists())
    manager = installed_manager()
    if manager is None:
        raise RuntimeError("Install a desktop and a display manager (usually lightdm) before enabling a remote desktop")

    if release <= 10:
        target = next((path for path in (Path("/boot/config.txt"), Path("/boot/firmware/config.txt")) if path.exists()), None)
        method = "legacy HDMI hotplug"
        transform = legacy_text
    else:
        target = next((path for path in (Path("/boot/firmware/cmdline.txt"), Path("/boot/cmdline.txt")) if path.exists()), None)
        method = "KMS forced HDMI output"
        transform = kms_text
    if target is None:
        raise RuntimeError("Could not find the Raspberry Pi boot configuration file")
    contents = transform(target.read_text(encoding="utf-8"), args.output)
    print(f"Raspberry Pi OS {release}: {method}, {args.output}, 1920x1080; manager: {manager}")
    print(f"Boot file: {target}")
    if args.dry_run:
        print("Proposed boot configuration:\n" + contents)
        return 0

    save_file(target, contents)
    subprocess.run(["systemctl", "enable", manager], check=True, timeout=30)
    subprocess.run(["systemctl", "set-default", "graphical.target"], check=True, timeout=30)
    update_watchdog(manager, expect_x11=release <= 11)
    print("Done. Reboot the Pi to activate the virtual output: sudo reboot")
    if release >= 12:
        print("Raspberry Pi OS Bookworm uses Wayland by default; TeamViewer may also require an X11 desktop session.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"Headless display setup failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
