"""Guarded Raspberry Pi root expansion after an image is restored."""

import os
import shutil
import subprocess


def _run(*args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True).stdout.strip()


def inspect():
    result = {"available": False, "reason": "", "root": "", "disk": "", "root_gib": 0, "disk_gib": 0, "free_gib": 0}
    try:
        root = os.path.realpath(_run("findmnt", "-n", "-o", "SOURCE", "/"))
        fstype = _run("findmnt", "-n", "-o", "FSTYPE", "/")
        result["root"] = root
        if not root.startswith("/dev/") or fstype != "ext4":
            result["reason"] = "Only an ext4 root partition on a physical Pi drive is supported."
            return result
        if _run("lsblk", "-n", "-o", "TYPE", root) != "part":
            result["reason"] = "Root is not a direct disk partition."
            return result
        parent = _run("lsblk", "-n", "-o", "PKNAME", root)
        number = _run("lsblk", "-n", "-o", "PARTN", root)
        if not parent or number != "2":
            result["reason"] = "The root partition must be partition 2 on a physical drive."
            return result
        disk = "/dev/" + parent
        result["disk"] = disk
        if _run("lsblk", "-n", "-d", "-o", "PTTYPE", disk) != "dos":
            result["reason"] = "Automatic expansion supports the standard Raspberry Pi OS DOS partition layout only."
            return result
        partitions = _run("lsblk", "-n", "-l", "-b", "-o", "START,SIZE,TYPE", disk).splitlines()
        entries = []
        for line in partitions:
            columns = line.split()
            if len(columns) == 3 and columns[2] == "part":
                entries.append((int(columns[0]), int(columns[1])))
        root_start = int(_run("lsblk", "-n", "-o", "START", root))
        root_bytes = int(_run("lsblk", "-n", "-b", "-o", "SIZE", root))
        disk_bytes = int(_run("blockdev", "--getsize64", disk))
        sector_bytes = int(_run("blockdev", "--getss", disk))
        free_bytes = max(0, disk_bytes - root_start * sector_bytes - root_bytes)
        result.update(root_gib=round(root_bytes / 2**30, 2), disk_gib=round(disk_bytes / 2**30, 2), free_gib=round(free_bytes / 2**30, 2))
        if not entries or root_start != max(start for start, _ in entries):
            result["reason"] = "Root is not the final partition; automatic expansion is disabled."
        elif free_bytes < 1024**3:
            result["reason"] = "There is less than 1 GiB to add to the root partition."
        elif not shutil.which("raspi-config"):
            result["reason"] = "raspi-config is not installed."
        else:
            result["available"] = True
            result["reason"] = "The root partition can be expanded into the unused space."
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result["reason"] = f"Storage layout could not be checked: {type(exc).__name__}."
    return result


def expand(expected_root):
    status = inspect()
    if not status["available"] or expected_root != status["root"]:
        return {"ok": False, "message": status["reason"] if not status["available"] else "Root partition confirmation did not match."}
    try:
        completed = subprocess.run(
            ["raspi-config", "nonint", "do_expand_rootfs"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "message": f"Expansion could not be started: {type(exc).__name__}."}
    if completed.returncode:
        return {"ok": False, "message": "raspi-config reported an error; check the system journal before retrying.", "detail": (completed.stderr or completed.stdout)[-1500:]}
    return {"ok": True, "message": "Partition expansion requested. Reboot the Pi to complete the filesystem resize, then check the capacity here."}
