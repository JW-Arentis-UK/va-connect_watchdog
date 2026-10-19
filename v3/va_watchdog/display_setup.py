"""Opt-in headless desktop setup for Xorg hosts and Raspberry Pi OS."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .display_monitor import MANAGERS

XORG_CONFIG = '''# Managed by VA-Connect headless display setup.
Section "Device"
    Identifier "DummyDevice"
    Driver "dummy"
    VideoRam 256000
EndSection
Section "Monitor"
    Identifier "DummyMonitor"
    HorizSync 30.0-80.0
    VertRefresh 50.0-75.0
    Modeline "1920x1080" 148.50 1920 2008 2052 2200 1080 1084 1089 1125 +HSync +VSync
EndSection
Section "Screen"
    Identifier "DummyScreen"
    Device "DummyDevice"
    Monitor "DummyMonitor"
    DefaultDepth 24
    SubSection "Display"
        Depth 24
        Modes "1920x1080"
    EndSubSection
EndSection
Section "ServerLayout"
    Identifier "DummyLayout"
    Screen 0 "DummyScreen"
EndSection
'''
LEGACY_BLOCK = '''# BEGIN VA-CONNECT HEADLESS DISPLAY
[all]
hdmi_force_hotplug=1
hdmi_group=2
hdmi_mode=82
# END VA-CONNECT HEADLESS DISPLAY
'''


def parse_os_release(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value.strip().strip('"')
    return result


def platform_branch(os_release: dict[str, str], model: str, pi_marker: bool) -> str:
    distro = os_release.get("ID", "").lower()
    pi_os = "raspberry pi" in model.lower() and (pi_marker or distro == "raspbian")
    if pi_os:
        try:
            return "pi_legacy" if int(os_release["VERSION_ID"].split(".")[0]) <= 10 else "pi_kms"
        except ValueError as exc:
            raise ValueError("Cannot determine Raspberry Pi OS release") from exc
    if distro in {"ubuntu", "debian", "fedora"}:
        return "standard"
    raise ValueError(f"Unsupported distribution: {distro or 'unknown'}")


def modern_cmdline(original: str, output: str = "HDMI-A-1") -> str:
    if output not in {"HDMI-A-1", "HDMI-A-2"}:
        raise ValueError("HDMI output must be HDMI-A-1 or HDMI-A-2")
    token = f"video={output}:1920x1080M@60D"
    parts = original.strip().split()
    matches = [i for i, part in enumerate(parts) if part.startswith(f"video={output}:")]
    if matches:
        parts[matches[0]] = token
        for index in reversed(matches[1:]):
            del parts[index]
    else:
        parts.append(token)
    return " ".join(parts) + "\n"


def legacy_config(original: str) -> str:
    start = "# BEGIN VA-CONNECT HEADLESS DISPLAY"
    end = "# END VA-CONNECT HEADLESS DISPLAY"
    if start in original:
        if end not in original:
            raise ValueError("Unclosed managed block in config.txt")
        original = re.sub(re.escape(start) + r".*?" + re.escape(end) + r"\n?", "", original, flags=re.S)
    return original.rstrip() + "\n\n" + LEGACY_BLOCK


def gdm_x11_config(original: str) -> str:
    section = re.search(r"(?m)^\[daemon\]\s*$", original)
    if not section:
        return original.rstrip() + "\n\n[daemon]\nWaylandEnable=false\n"
    tail = original[section.end():]
    next_section = re.search(r"(?m)^\[.+\]\s*$", tail)
    end = section.end() + next_section.start() if next_section else len(original)
    chunk = original[section.end():end]
    setting = re.search(r"(?m)^\s*#?\s*WaylandEnable\s*=.*$", chunk)
    if setting:
        chunk = chunk[:setting.start()] + "WaylandEnable=false" + chunk[setting.end():]
    else:
        chunk = "\nWaylandEnable=false" + chunk
    return original[:section.end()] + chunk + original[end:]


def find_manager(preferred: str = "") -> str:
    names = [preferred] if preferred else MANAGERS
    if preferred and preferred not in MANAGERS:
        raise ValueError("Unsupported display manager")
    for name in names:
        result = subprocess.run(["systemctl", "show", "-p", "LoadState", "--value", name],
                                capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            return name
    raise RuntimeError("No supported display manager is installed; install a desktop and gdm3, lightdm or sddm first")


def run(*args: str) -> None:
    subprocess.run(args, check=True, timeout=300)


def write_with_backup(path: Path, content: str) -> bool:
    before = path.read_text(encoding="utf-8") if path.exists() else None
    if before == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    if before is not None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(path, path.with_name(path.name + f".{stamp}.headless.bak"))
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".headless-", delete=False) as temp:
        temp.write(content)
        temp.flush()
        os.fsync(temp.fileno())
        temporary = Path(temp.name)
    try:
        try:
            os.chmod(temporary, path.stat().st_mode & 0o777 if path.exists() else 0o644)
        except OSError:
            if not str(path).startswith("/boot/"):
                raise
        if path.exists() and hasattr(os, "chown"):
            old = path.stat()
            try:
                os.chown(temporary, old.st_uid, old.st_gid)
            except OSError:
                if not str(path).startswith("/boot/"):
                    raise
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def configure_standard(distro: str, manager: str, apply: bool) -> list[str]:
    package = "xorg-x11-drv-dummy" if distro == "fedora" else "xserver-xorg-video-dummy"
    commands = [f"Install {package}", "Write /etc/X11/xorg.conf.d/99-dummy.conf at 1920x1080"]
    if manager in {"gdm.service", "gdm3.service"}:
        commands.append("Set WaylandEnable=false for GDM")
    if apply:
        if package.startswith("xorg-x11"):
            run("dnf", "install", "-y", package)
        else:
            run("apt-get", "update")
            run("apt-get", "install", "-y", package)
        write_with_backup(Path("/etc/X11/xorg.conf.d/99-dummy.conf"), XORG_CONFIG)
        if manager in {"gdm.service", "gdm3.service"}:
            gdm = Path("/etc/gdm3/custom.conf") if manager == "gdm3.service" else Path("/etc/gdm/custom.conf")
            write_with_backup(gdm, gdm_x11_config(gdm.read_text() if gdm.exists() else ""))
    return commands


def configure_pi(branch: str, output: str, apply: bool) -> list[str]:
    if branch == "pi_legacy":
        target = Path("/boot/config.txt")
        if not target.exists():
            target = Path("/boot/firmware/config.txt")
        description = f"Set hdmi_force_hotplug=1 and 1920x1080 mode in {target}"
        if apply:
            if not target.exists():
                raise FileNotFoundError(target)
            write_with_backup(target, legacy_config(target.read_text()))
    else:
        target = Path("/boot/firmware/cmdline.txt")
        if not target.exists():
            target = Path("/boot/cmdline.txt")
        description = f"Force {output} to 1920x1080 on the kernel command line in {target}"
        if apply:
            if not target.exists():
                raise FileNotFoundError(target)
            write_with_backup(target, modern_cmdline(target.read_text(), output))
    return [description]


def enable_monitor(config_path: Path, manager: str, branch: str) -> None:
    if not config_path.exists():
        raise FileNotFoundError(f"Watchdog config missing: {config_path}")
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    cfg.setdefault("display_monitor", {}).update({"enabled": True, "manager": manager, "expect_x11": branch != "pi_kms"})
    write_with_backup(config_path, json.dumps(cfg, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Install and write configuration; otherwise only preview")
    parser.add_argument("--manager", choices=MANAGERS, default="", help="Existing display manager")
    parser.add_argument("--output", choices=("HDMI-A-1", "HDMI-A-2"), default="HDMI-A-1")
    parser.add_argument("--config", type=Path, default=Path("/etc/va-watchdog/config.json"))
    args = parser.parse_args()
    if args.apply and os.geteuid() != 0:
        parser.error("--apply requires root")
    os_release = parse_os_release(Path("/etc/os-release").read_text())
    model_file = Path("/proc/device-tree/model")
    model = model_file.read_text(errors="ignore") if model_file.exists() else ""
    branch = platform_branch(os_release, model, Path("/etc/rpi-issue").exists())
    manager = find_manager(args.manager)
    if not args.config.exists():
        raise FileNotFoundError(f"Watchdog config missing: {args.config}")
    if branch == "standard":
        steps = configure_standard(os_release["ID"].lower(), manager, args.apply)
    else:
        steps = configure_pi(branch, args.output, args.apply)
    steps += [f"Enable {manager} and graphical.target", "Enable optional watchdog display monitoring"]
    for step in steps:
        print(step)
    if args.apply:
        run("systemctl", "enable", manager)
        run("systemctl", "set-default", "graphical.target")
        enable_monitor(args.config, manager, branch)
        if subprocess.run(["systemctl", "is-active", "--quiet", manager], check=False).returncode != 0:
            run("systemctl", "start", manager)
        run("systemctl", "try-restart", "va-watchdog.service")
        print("Configured. Reboot or restart the display manager to load the virtual output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
