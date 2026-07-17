from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .common import CheckResult

DEFAULT_RECORDING_STORAGE = {
    "enabled": True,
    "expected_label": "CCTV_STORAGE",
    "mountpoint": "/media/vsuser/Storage",
    "filesystem": "ext4",
    "fstab_options": "defaults,nofail,x-systemd.device-timeout=5",
    "free_warning_percent": 10,
    "temperature_warning_c": 55,
    "recording_services": [],
}

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

def _run(command, timeout=8):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except FileNotFoundError as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}

def recording_storage_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    configured = cfg.get("recording_storage", {}) if isinstance(cfg.get("recording_storage", {}), dict) else {}
    merged = dict(DEFAULT_RECORDING_STORAGE)
    merged.update(configured)
    if merged.get("mountpoint") == "/media/ususer/Storage" and Path("/home/vsuser").exists():
        merged["mountpoint"] = "/media/vsuser/Storage"
    return merged

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _lsblk_rows():
    result = _run([
        "lsblk",
        "-J",
        "-b",
        "-o",
        "NAME,PATH,TYPE,PKNAME,MOUNTPOINT,FSTYPE,LABEL,MODEL,SERIAL,SIZE,RM,ROTA",
    ])
    if not result["ok"]:
        return []
    try:
        payload = json.loads(result["stdout"])
    except Exception:
        return []
    rows = []

    def walk(items, parent=None):
        for item in items or []:
            row = dict(item)
            if parent:
                row.setdefault("parent_path", parent.get("path"))
                row.setdefault("parent_name", parent.get("name"))
                row.setdefault("model", parent.get("model") or row.get("model"))
                row.setdefault("serial", parent.get("serial") or row.get("serial"))
            rows.append(row)
            walk(row.get("children", []), row)

    walk(payload.get("blockdevices", []))
    return rows

def _row_for_device(device):
    real_device = os.path.realpath(str(device or ""))
    for row in _lsblk_rows():
        path = row.get("path")
        if path and os.path.realpath(str(path)) == real_device:
            return row
    return {}

def _device_by_label(label):
    by_label = Path("/dev/disk/by-label") / str(label)
    if by_label.exists():
        try:
            return os.path.realpath(str(by_label))
        except OSError:
            return str(by_label)
    for row in _lsblk_rows():
        if str(row.get("label") or "") == str(label):
            return row.get("path")
    return None

def _findmnt(mountpoint):
    result = _run(["findmnt", "-J", "--mountpoint", str(mountpoint), "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"], timeout=5)
    if not result["ok"]:
        return {}
    try:
        payload = json.loads(result["stdout"])
    except Exception:
        return {}
    filesystems = payload.get("filesystems", [])
    if not filesystems:
        return {}
    return filesystems[0]

def _blkid_value(device, key):
    if not device:
        return ""
    result = _run(["blkid", "-o", "value", "-s", key, str(device)], timeout=5)
    return result["stdout"].strip() if result["ok"] else ""

def _parent_disk(device):
    if not device:
        return None
    result = _run(["lsblk", "-no", "PKNAME", str(device)], timeout=5)
    parent = result["stdout"].splitlines()[0].strip() if result["stdout"] else ""
    if parent:
        return f"/dev/{parent}"
    row = _row_for_device(device)
    if row.get("type") == "disk":
        return row.get("path")
    parent_name = row.get("pkname") or row.get("parent_name")
    return f"/dev/{parent_name}" if parent_name else None

def _smart_info(device):
    disk = _parent_disk(device) or device
    result = _run(["smartctl", "-H", "-A", "-j", str(disk)], timeout=15)
    if result["returncode"] is None or "No such file" in result["stderr"]:
        return {"status": "unavailable", "temperature_c": None, "device": disk, "message": "smartctl unavailable"}
    raw = result["stdout"] or result["stderr"]
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        payload = {}
    smart_status = "unavailable"
    passed = payload.get("smart_status", {}).get("passed")
    if passed is True:
        smart_status = "PASSED"
    elif passed is False:
        smart_status = "FAILED"
    elif result["ok"]:
        smart_status = "PASSED"
    elif raw:
        smart_status = "unavailable"
    temperature = payload.get("temperature", {}).get("current")
    if temperature is None:
        for table_name in ["ata_smart_attributes", "nvme_smart_health_information_log"]:
            table = payload.get(table_name, {})
            rows = table.get("table", []) if isinstance(table, dict) else []
            for item in rows:
                name = str(item.get("name", "")).lower()
                if "temperature" in name:
                    temperature = item.get("raw", {}).get("value") or item.get("value")
                    break
            if temperature is not None:
                break
    try:
        temperature = int(float(temperature)) if temperature is not None else None
    except (TypeError, ValueError):
        temperature = None
    return {
        "status": smart_status,
        "temperature_c": temperature,
        "device": disk,
        "message": result["stderr"] or result["stdout"] or "",
    }

def _recording_writable(mountpoint):
    p = Path(mountpoint)
    test_file = p / ".va_watchdog_recording_storage_write_test"
    try:
        test_file.write_text(str(time.time()), encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def recording_storage_status(cfg: dict[str, Any]) -> dict[str, Any]:
    rec_cfg = recording_storage_cfg(cfg)
    expected_label = str(rec_cfg.get("expected_label") or "CCTV_STORAGE")
    mountpoint = str(rec_cfg.get("mountpoint") or "/media/vsuser/Storage")
    expected_fs = str(rec_cfg.get("filesystem") or "ext4")
    checked_at = _now_iso()
    mounted_info = _findmnt(mountpoint)
    mounted = bool(mounted_info)
    label_device = _device_by_label(expected_label)
    device = mounted_info.get("source") or label_device
    if str(device or "").startswith("LABEL="):
        device = _device_by_label(str(device).split("=", 1)[1]) or device
    elif device and not str(device).startswith("/dev/") and label_device:
        device = label_device
    if device and device.startswith("/dev/"):
        try:
            device = os.path.realpath(device)
        except OSError:
            pass
    row = _row_for_device(device) if device else {}
    present = bool(device and Path(device).exists())
    filesystem = mounted_info.get("fstype") or row.get("fstype") or _blkid_value(device, "TYPE")
    label = row.get("label") or _blkid_value(device, "LABEL")
    label_ok = label == expected_label
    options = str(mounted_info.get("options", ""))
    option_set = {item.strip() for item in options.split(",") if item.strip()}
    read_only = mounted and "ro" in option_set
    writable = bool(mounted and not read_only and _recording_writable(mountpoint))
    total_gb = free_gb = used_percent = free_percent = None
    if mounted:
        try:
            total, used, free = shutil.disk_usage(mountpoint)
            total_gb = round(total / 1024 / 1024 / 1024, 1)
            free_gb = round(free / 1024 / 1024 / 1024, 1)
            used_percent = round((used / max(1, total)) * 100, 1)
            free_percent = round((free / max(1, total)) * 100, 1)
        except Exception:
            pass
    smart = _smart_info(device) if present else {"status": "unavailable", "temperature_c": None, "device": None, "message": "Drive not present"}
    smart_status = smart.get("status") or "unavailable"
    temperature_c = smart.get("temperature_c")
    free_warning_percent = float(rec_cfg.get("free_warning_percent", 10) or 10)
    temp_warning = int(rec_cfg.get("temperature_warning_c", 55) or 55)

    status = "healthy"
    message = "Recording storage healthy"
    if not present:
        status = "critical"
        message = "Recording storage missing"
    elif not mounted:
        status = "critical"
        message = "Recording storage not mounted"
    elif filesystem != expected_fs:
        status = "critical"
        message = f"Recording storage filesystem is {filesystem or 'unknown'}, expected {expected_fs}"
    elif not label_ok:
        status = "critical"
        message = f"Recording storage label is {label or 'missing'}, expected {expected_label}"
    elif read_only:
        status = "critical"
        message = "Recording storage read-only"
    elif not writable:
        status = "critical"
        message = "Recording storage not writable"
    elif smart_status == "FAILED":
        status = "critical"
        message = "Recording storage SMART failure"
    elif free_percent is not None and free_percent < free_warning_percent:
        status = "warning"
        message = "Recording storage low space"
    elif smart_status == "unavailable":
        status = "warning"
        message = "Recording storage SMART unavailable"
    elif temperature_c is not None and temperature_c >= temp_warning:
        status = "warning"
        message = "Recording storage temperature high"

    return {
        "device": device or "-",
        "mountpoint": mountpoint,
        "label": label or "-",
        "expected_label": expected_label,
        "label_ok": label_ok,
        "filesystem": filesystem or "-",
        "expected_filesystem": expected_fs,
        "present": present,
        "mounted": mounted,
        "writable": writable,
        "read_only": read_only,
        "total_gb": total_gb,
        "free_gb": free_gb,
        "used_percent": used_percent,
        "free_percent": free_percent,
        "smart_status": smart_status,
        "smart_device": smart.get("device"),
        "temperature_c": temperature_c,
        "status": status,
        "message": message,
        "checked_at": checked_at,
        "last_successful_check": checked_at if status in ("healthy", "warning") else "",
        "fstab_entry": f"LABEL={expected_label} {mountpoint} {expected_fs} {rec_cfg.get('fstab_options')} 0 2",
        "recording_service_mount_guards": recording_service_mount_guards(cfg),
    }

def recording_service_mount_guards(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    rec_cfg = recording_storage_cfg(cfg)
    mountpoint = str(rec_cfg.get("mountpoint") or "/media/vsuser/Storage")
    guards = []
    for service in rec_cfg.get("recording_services", []) or []:
        service = str(service).strip()
        if not service:
            continue
        dropin = Path("/etc/systemd/system") / f"{service}.d" / "recording-storage.conf"
        content = ""
        if dropin.exists():
            try:
                content = dropin.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
        guards.append({
            "service": service,
            "dropin": str(dropin),
            "configured": f"RequiresMountsFor={mountpoint}" in content,
            "mountpoint": mountpoint,
        })
    return guards

def apply_recording_service_mount_guards(cfg: dict[str, Any], ack: bool) -> dict[str, Any]:
    if not ack:
        return {"ok": False, "message": "Confirmation checkbox was not ticked.", "output": ""}
    rec_cfg = recording_storage_cfg(cfg)
    services = [str(item).strip() for item in rec_cfg.get("recording_services", []) or [] if str(item).strip()]
    mountpoint = str(rec_cfg.get("mountpoint") or "/media/vsuser/Storage")
    if not services:
        return {
            "ok": False,
            "message": "No recording services are configured. Add service names to recording_storage.recording_services first.",
            "output": "",
        }
    output = []
    for service in services:
        dropin_dir = Path("/etc/systemd/system") / f"{service}.d"
        dropin_dir.mkdir(parents=True, exist_ok=True)
        dropin = dropin_dir / "recording-storage.conf"
        dropin.write_text(
            "[Unit]\n"
            f"RequiresMountsFor={mountpoint}\n",
            encoding="utf-8",
        )
        output.append(f"Wrote {dropin}")
    daemon = _run(["systemctl", "daemon-reload"], timeout=20)
    output.append(f"systemctl daemon-reload: {daemon['stdout'] or daemon['stderr'] or daemon['returncode']}")
    return {
        "ok": bool(daemon["ok"]),
        "message": "Recording service mount guard applied." if daemon["ok"] else "Mount guard files were written but daemon-reload failed.",
        "output": "\n".join(output),
        "guards": recording_service_mount_guards(cfg),
    }

def _root_parent_disk():
    root = _run(["findmnt", "-n", "-o", "SOURCE", "/"], timeout=5)
    source = root["stdout"].splitlines()[0].strip() if root["stdout"] else ""
    if not source:
        return ""
    try:
        source = os.path.realpath(source)
    except OSError:
        pass
    parent = _parent_disk(source)
    return os.path.realpath(parent) if parent else source

def _partitions_for_disk(disk):
    disk_real = os.path.realpath(str(disk or ""))
    parts = []
    for row in _lsblk_rows():
        if row.get("type") != "part":
            continue
        parent = _parent_disk(row.get("path")) or row.get("parent_path")
        if parent and os.path.realpath(str(parent)) == disk_real:
            parts.append(row.get("path"))
    return [p for p in parts if p]

def recording_storage_candidates(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    root_parent = _root_parent_disk()
    protected_mounts = {"/", "/boot", "/boot/efi"}
    candidates = []
    for row in _lsblk_rows():
        path = row.get("path")
        if not path:
            continue
        mountpoint = row.get("mountpoint") or ""
        parent = _parent_disk(path) or row.get("parent_path") or path
        try:
            parent_real = os.path.realpath(str(parent))
        except OSError:
            parent_real = str(parent)
        reasons = []
        blank_prepare_reasons = []
        if row.get("type") != "part":
            reasons.append("select a partition, not a whole disk")
        if mountpoint in protected_mounts:
            reasons.append(f"protected mount {mountpoint}")
        if root_parent and parent_real == root_parent:
            reasons.append("parent disk contains the active root filesystem")
        if row.get("type") == "part" and row.get("fstype") != "ext4":
            reasons.append(f"filesystem is {row.get('fstype') or 'missing'}, expected ext4")
        if row.get("type") != "disk":
            blank_prepare_reasons.append("only whole disks can be prepared as blank recording storage")
        if root_parent and parent_real == root_parent:
            blank_prepare_reasons.append("disk contains the active root filesystem")
        if mountpoint:
            blank_prepare_reasons.append(f"disk is mounted at {mountpoint}")
        if row.get("fstype"):
            blank_prepare_reasons.append(f"disk already has filesystem {row.get('fstype')}")
        children = row.get("children") or []
        if children:
            blank_prepare_reasons.append("disk already has partitions")
        candidates.append({
            "device": path,
            "parent_disk": parent,
            "type": row.get("type") or "",
            "model": row.get("model") or "",
            "serial": row.get("serial") or "",
            "size_bytes": row.get("size"),
            "size_gb": round(float(row.get("size") or 0) / 1024 / 1024 / 1024, 1),
            "filesystem": row.get("fstype") or "",
            "label": row.get("label") or "",
            "mountpoint": mountpoint,
            "allowed": not reasons,
            "blocked_reason": "; ".join(reasons),
            "blank_prepare_allowed": not blank_prepare_reasons,
            "blank_prepare_reason": "; ".join(blank_prepare_reasons),
        })
    return candidates

def _fstab_backup_path(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return path.with_name(f"{path.name}.va-watchdog-recording-storage.{stamp}.bak")

def _update_fstab(path: Path, entry: str, mountpoint: str, expected_label: str) -> tuple[Path | None, str]:
    backup = None
    original = ""
    if path.exists():
        original = path.read_text(encoding="utf-8")
        backup = _fstab_backup_path(path)
        shutil.copy2(path, backup)
    lines = original.splitlines()
    output = []
    replaced = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue
        parts = stripped.split()
        if len(parts) >= 2 and (parts[0] == f"LABEL={expected_label}" or parts[1] == mountpoint):
            if not replaced:
                output.append(entry)
                replaced = True
            continue
        output.append(line)
    if not replaced:
        output.append(entry)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    tmp.replace(path)
    return backup, original

def _restore_fstab(path: Path, backup: Path | None, original: str):
    if backup and backup.exists():
        shutil.copy2(backup, path)
    elif original:
        path.write_text(original, encoding="utf-8")
    elif path.exists():
        path.unlink()

def configure_recording_storage(cfg: dict[str, Any], device: str, confirm_label: str, ack: bool) -> dict[str, Any]:
    rec_cfg = recording_storage_cfg(cfg)
    expected_label = str(rec_cfg["expected_label"])
    mountpoint = str(rec_cfg["mountpoint"])
    expected_fs = str(rec_cfg["filesystem"])
    fstab_options = str(rec_cfg["fstab_options"])
    device = os.path.realpath(str(device or ""))
    if not ack or str(confirm_label or "").strip() != expected_label:
        return {"ok": False, "message": f"Confirmation failed. Type {expected_label} and tick the confirmation box.", "output": ""}
    candidates = recording_storage_candidates(cfg)
    selected = next((item for item in candidates if os.path.realpath(str(item.get("device"))) == device), None)
    if not selected:
        return {"ok": False, "message": f"Selected device was not detected: {device}", "output": ""}
    if not selected.get("allowed"):
        return {"ok": False, "message": "Selected device is protected or unsuitable.", "output": selected.get("blocked_reason", "")}
    if selected.get("filesystem") != expected_fs:
        return {"ok": False, "message": f"Selected device must already be {expected_fs}. The watchdog will not format disks.", "output": ""}

    output = []
    current_label = selected.get("label") or _blkid_value(device, "LABEL")
    previous_label = current_label
    label_changed = False
    if current_label != expected_label:
        relabel = _run(["e2label", device, expected_label], timeout=20)
        output.append(f"e2label: {relabel['stdout'] or relabel['stderr'] or relabel['returncode']}")
        if not relabel["ok"]:
            return {"ok": False, "message": "Could not set ext4 label.", "output": "\n".join(output)}
        label_changed = True

    fstab_path = Path("/etc/fstab")
    entry = f"LABEL={expected_label} {mountpoint} {expected_fs} {fstab_options} 0 2"
    backup = None
    original = ""
    try:
        Path(mountpoint).mkdir(parents=True, exist_ok=True)
        backup, original = _update_fstab(fstab_path, entry, mountpoint, expected_label)
        output.append(f"Backed up /etc/fstab to {backup}" if backup else "Created /etc/fstab entry")
        mount = _run(["mount", "-a"], timeout=30)
        output.append(f"mount -a: {mount['stdout'] or mount['stderr'] or mount['returncode']}")
    except Exception as exc:
        if label_changed:
            restored_label = _run(["e2label", device, previous_label], timeout=20)
            output.append(f"Restored previous label: {restored_label['stdout'] or restored_label['stderr'] or restored_label['returncode']}")
        return {"ok": False, "message": f"Recording storage configuration failed: {exc}", "output": "\n".join(output)}

    status = recording_storage_status(cfg)
    if not (status.get("mounted") and status.get("writable") and status.get("label") == expected_label and status.get("filesystem") == expected_fs):
        _restore_fstab(fstab_path, backup, original)
        remount = _run(["mount", "-a"], timeout=30)
        output.append("Validation failed; restored previous /etc/fstab.")
        output.append(f"mount -a after restore: {remount['stdout'] or remount['stderr'] or remount['returncode']}")
        if label_changed:
            restored_label = _run(["e2label", device, previous_label], timeout=20)
            output.append(f"Restored previous label: {restored_label['stdout'] or restored_label['stderr'] or restored_label['returncode']}")
        return {
            "ok": False,
            "message": "Recording storage validation failed. Previous /etc/fstab was restored.",
            "output": "\n".join(output),
            "status": status,
            "backup": str(backup) if backup else "",
        }

    return {
        "ok": True,
        "message": "Recording storage configured and writable.",
        "output": "\n".join(output),
        "status": status,
        "backup": str(backup) if backup else "",
        "fstab_entry": entry,
    }

def prepare_blank_recording_disk(cfg: dict[str, Any], disk: str, confirm_device: str, confirm_label: str, ack: bool) -> dict[str, Any]:
    rec_cfg = recording_storage_cfg(cfg)
    expected_label = str(rec_cfg["expected_label"])
    mountpoint = str(rec_cfg["mountpoint"])
    expected_fs = str(rec_cfg["filesystem"])
    fstab_options = str(rec_cfg["fstab_options"])
    disk = os.path.realpath(str(disk or ""))
    confirm_device = os.path.realpath(str(confirm_device or ""))
    if not ack or confirm_device != disk or str(confirm_label or "").strip() != expected_label:
        return {
            "ok": False,
            "message": f"Confirmation failed. Tick the box, type {expected_label}, and type the selected disk path exactly.",
            "output": "",
        }
    if expected_fs != "ext4":
        return {"ok": False, "message": "Blank disk preparation currently only supports ext4.", "output": ""}

    candidates = recording_storage_candidates(cfg)
    selected = next((item for item in candidates if os.path.realpath(str(item.get("device"))) == disk), None)
    if not selected:
        return {"ok": False, "message": f"Selected disk was not detected: {disk}", "output": ""}
    if not selected.get("blank_prepare_allowed"):
        return {"ok": False, "message": "Selected disk is protected or not blank.", "output": selected.get("blank_prepare_reason", "")}

    fstab_path = Path("/etc/fstab")
    entry = f"LABEL={expected_label} {mountpoint} {expected_fs} {fstab_options} 0 2"
    backup = None
    original = ""
    output = [
        f"Preparing blank recording disk {disk}.",
        "This creates one ext4 partition labelled CCTV_STORAGE and writes the labelled fstab entry.",
    ]
    try:
        wipe = _run(["wipefs", "-a", disk], timeout=30)
        output.append(f"wipefs: {wipe['stdout'] or wipe['stderr'] or wipe['returncode']}")
        if not wipe["ok"]:
            return {"ok": False, "message": "Could not clear existing disk signatures.", "output": "\n".join(output)}
        part = _run(["parted", "-s", disk, "mklabel", "gpt", "mkpart", "primary", "ext4", "0%", "100%"], timeout=60)
        output.append(f"parted: {part['stdout'] or part['stderr'] or part['returncode']}")
        if not part["ok"]:
            return {"ok": False, "message": "Could not create recording partition.", "output": "\n".join(output)}
        _run(["partprobe", disk], timeout=20)
        time.sleep(2)
        parts = _partitions_for_disk(disk)
        if not parts:
            time.sleep(3)
            parts = _partitions_for_disk(disk)
        if not parts:
            return {"ok": False, "message": "Partition was created but not detected yet. Reboot or run partprobe, then try existing partition setup.", "output": "\n".join(output)}
        partition = parts[0]
        mkfs = _run(["mkfs.ext4", "-F", "-L", expected_label, partition], timeout=180)
        output.append(f"mkfs.ext4: {mkfs['stdout'] or mkfs['stderr'] or mkfs['returncode']}")
        if not mkfs["ok"]:
            return {"ok": False, "message": "Could not create ext4 recording filesystem.", "output": "\n".join(output)}
        Path(mountpoint).mkdir(parents=True, exist_ok=True)
        backup, original = _update_fstab(fstab_path, entry, mountpoint, expected_label)
        output.append(f"Backed up /etc/fstab to {backup}" if backup else "Created /etc/fstab entry")
        mount = _run(["mount", "-a"], timeout=30)
        output.append(f"mount -a: {mount['stdout'] or mount['stderr'] or mount['returncode']}")
        status = recording_storage_status(cfg)
        if not (status.get("mounted") and status.get("writable") and status.get("label") == expected_label and status.get("filesystem") == expected_fs):
            _restore_fstab(fstab_path, backup, original)
            remount = _run(["mount", "-a"], timeout=30)
            output.append("Validation failed; restored previous /etc/fstab.")
            output.append(f"mount -a after restore: {remount['stdout'] or remount['stderr'] or remount['returncode']}")
            return {
                "ok": False,
                "message": "Recording disk was prepared, but mount validation failed. Previous /etc/fstab was restored.",
                "output": "\n".join(output),
                "status": status,
                "backup": str(backup) if backup else "",
                "fstab_entry": entry,
            }
        return {
            "ok": True,
            "message": "Blank recording disk prepared, mounted, and verified writable.",
            "output": "\n".join(output),
            "status": status,
            "backup": str(backup) if backup else "",
            "fstab_entry": entry,
        }
    except Exception as exc:
        if backup is not None or original:
            _restore_fstab(fstab_path, backup, original)
        return {"ok": False, "message": f"Blank recording disk preparation failed: {exc}", "output": "\n".join(output)}

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
    recording = recording_storage_status(cfg)
    checks = [
        _usage_check("root_disk", st["root_path"], th["root_disk_warning_percent"], th["root_disk_critical_percent"], True),
        _usage_check("recordings_disk", st["recordings_path"], th["recordings_disk_warning_percent"], th["recordings_disk_critical_percent"], False),
        CheckResult("recording_storage", recording["status"], recording["message"], recording, False),
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
