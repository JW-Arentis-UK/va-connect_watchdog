from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shlex
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Callable


CommandResult = dict[str, Any]
Runner = Callable[[list[str], int], CommandResult]

DMI_FIELDS = {
    "manufacturer": "sys_vendor",
    "reported_model": "product_name",
    "product_version": "product_version",
    "product_serial": "product_serial",
    "product_uuid": "product_uuid",
    "board_vendor": "board_vendor",
    "board_name": "board_name",
    "board_version": "board_version",
    "board_serial": "board_serial",
    "chassis_vendor": "chassis_vendor",
    "chassis_type": "chassis_type",
    "chassis_version": "chassis_version",
    "chassis_serial": "chassis_serial",
    "bios_vendor": "bios_vendor",
    "bios_version": "bios_version",
    "bios_date": "bios_date",
    "bios_release": "bios_release",
}

KERNEL_EVIDENCE_TERMS = (
    "watchdog",
    "wdt_dio",
    "ata",
    "sata",
    "ahci",
    "igc",
    "pcie",
    "edac",
    "mce",
    "hardware error",
    "thermal",
    "reset",
    "hang",
    "lockup",
)


def _run(command: list[str], timeout: int = 10) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": shlex.join(command),
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "command": shlex.join(command),
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _parse_key_values(text: str, separator: str = "=") -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, found, value = line.partition(separator)
        if not found:
            continue
        values[key.strip()] = value.strip().strip('"')
    return values


def _cpu_summary(cpuinfo: str) -> dict[str, Any]:
    blocks = [block for block in cpuinfo.split("\n\n") if block.strip()]
    first = _parse_key_values(blocks[0], ":") if blocks else {}
    return {
        "model": first.get("model name", ""),
        "vendor": first.get("vendor_id", ""),
        "family": first.get("cpu family", ""),
        "model_number": first.get("model", ""),
        "stepping": first.get("stepping", ""),
        "microcode": first.get("microcode", ""),
        "logical_processors": len(blocks),
    }


def _memory_summary(meminfo: str) -> dict[str, Any]:
    values = _parse_key_values(meminfo, ":")

    def mib(name: str) -> float | None:
        match = re.search(r"(\d+)", values.get(name, ""))
        return round(int(match.group(1)) / 1024, 1) if match else None

    return {
        "total_mib": mib("MemTotal"),
        "available_mib": mib("MemAvailable"),
        "swap_total_mib": mib("SwapTotal"),
    }


def _network_summary(sys_root: Path) -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    net_root = sys_root / "class" / "net"
    try:
        candidates = sorted(net_root.iterdir(), key=lambda item: item.name)
    except OSError:
        return interfaces
    for interface in candidates:
        if interface.name == "lo":
            continue
        try:
            driver = (interface / "device" / "driver").resolve().name
        except OSError:
            driver = ""
        counters = {
            name: _read_text(interface / "statistics" / name)
            for name in (
                "rx_packets",
                "rx_errors",
                "rx_dropped",
                "rx_missed_errors",
                "tx_packets",
                "tx_errors",
                "tx_dropped",
                "collisions",
            )
        }
        interfaces.append({
            "name": interface.name,
            "driver": driver,
            "operstate": _read_text(interface / "operstate"),
            "speed_mbps": _read_text(interface / "speed"),
            "duplex": _read_text(interface / "duplex"),
            "statistics": counters,
        })
    return interfaces


def _power_summary(sys_root: Path, proc_root: Path) -> dict[str, Any]:
    scsi_policies: dict[str, str] = {}
    for path in sorted((sys_root / "class" / "scsi_host").glob("host*/link_power_management_policy")):
        scsi_policies[path.parent.name] = _read_text(path)
    return {
        "boot_id": _read_text(proc_root / "sys" / "kernel" / "random" / "boot_id"),
        "uptime": _read_text(proc_root / "uptime"),
        "kernel_taint": _read_text(proc_root / "sys" / "kernel" / "tainted"),
        "kernel_command_line": _read_text(proc_root / "cmdline"),
        "pcie_aspm_policy": _read_text(sys_root / "module" / "pcie_aspm" / "parameters" / "policy"),
        "intel_idle_max_cstate": _read_text(sys_root / "module" / "intel_idle" / "parameters" / "max_cstate"),
        "processor_max_cstate": _read_text(sys_root / "module" / "processor" / "parameters" / "max_cstate"),
        "cpu_scaling_driver": _read_text(sys_root / "devices" / "system" / "cpu" / "cpu0" / "cpufreq" / "scaling_driver"),
        "cpu_scaling_governor": _read_text(sys_root / "devices" / "system" / "cpu" / "cpu0" / "cpufreq" / "scaling_governor"),
        "sata_link_power_management": scsi_policies,
    }


def _watchdog_summary(cfg: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    raw = cfg.get("hardware_watchdog", {})
    hardware = raw if isinstance(raw, dict) else {}
    feed = _read_json(Path(cfg.get("hardware_watchdog_feed_state_path") or data_dir / "hardware-watchdog-feed.json"))
    proof = _read_json(Path(cfg.get("hardware_watchdog_proof_path") or data_dir / "hardware-watchdog-proof.json"))
    trip = _read_json(Path(cfg.get("trip_test_path") or data_dir / "watchdog-trip-test.json"))
    liveness = _read_json(Path(cfg.get("liveness_test_path") or data_dir / "watchdog-liveness-test.json"))
    reboot = _read_json(Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl").with_name("last-reboot-evidence.json"))
    return {
        "configuration": {
            "backend": hardware.get("backend"),
            "enabled": hardware.get("enabled"),
            "device": hardware.get("device"),
            "feed_interval_seconds": hardware.get("feed_interval_seconds"),
            "timeout_seconds": hardware.get("timeout_seconds"),
            "stale_heartbeat_seconds": hardware.get("stale_heartbeat_seconds"),
            "health_progress_timeout_seconds": hardware.get("health_progress_timeout_seconds"),
        },
        "current_feed": {
            key: feed.get(key)
            for key in (
                "boot_id",
                "pid",
                "process_status",
                "backend",
                "device",
                "last_feed_utc",
                "feed_count",
                "feed_decision",
                "last_error",
                "error_count",
            )
        },
        "current_boot_proof": proof,
        "last_direct_trip_test": trip.get("last_result", {}),
        "full_liveness_test": liveness,
        "latest_reboot_evidence": {
            key: reboot.get(key)
            for key in (
                "reset_mechanism",
                "probable_preceding_fault",
                "classification",
                "confidence",
                "previous_boot_id",
                "current_boot_id",
                "evidence_used",
                "liveness_path_test",
                "deliberate_trip_test",
            )
        },
    }


def _recent_reboot_summaries(cfg: dict[str, Any], data_dir: Path, limit: int = 15) -> list[dict[str, Any]]:
    path = Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(row, dict):
            continue
        boot_id = str(row.get("current_boot_id") or "")
        if boot_id and boot_id in seen:
            continue
        if boot_id:
            seen.add(boot_id)
        summaries.append({
            "created_at": row.get("created_at"),
            "previous_boot_id": row.get("previous_boot_id"),
            "current_boot_id": row.get("current_boot_id"),
            "classification": row.get("classification") or row.get("reset_mechanism") or "Unknown",
            "confidence": row.get("confidence"),
            "probable_preceding_fault": row.get("probable_preceding_fault"),
            "planned_direct_trip_test": bool((row.get("deliberate_trip_test") or {}).get("confirmed")) if isinstance(row.get("deliberate_trip_test"), dict) else False,
            "planned_liveness_test": bool((row.get("liveness_path_test") or {}).get("confirmed")) if isinstance(row.get("liveness_path_test"), dict) else False,
        })
        if len(summaries) >= limit:
            break
    return summaries


def _incident_summaries(cfg: dict[str, Any], data_dir: Path, limit: int = 10) -> list[dict[str, Any]]:
    configured = cfg.get("incident_archive", {}) if isinstance(cfg.get("incident_archive"), dict) else {}
    root = Path(configured.get("path") or data_dir / "incidents")
    try:
        directories = sorted(
            (item for item in root.iterdir() if item.is_dir() and not item.name.startswith(".")),
            reverse=True,
        )[:limit]
    except OSError:
        return []
    incidents: list[dict[str, Any]] = []
    for directory in directories:
        manifest = _read_json(directory / "manifest.json")
        evidence = _read_json(directory / "reboot-evidence.json")
        feed = _read_json(directory / "last-watchdog-feed.json")
        incidents.append({
            "archive": directory.name,
            "detected_at": manifest.get("detected_at") or manifest.get("created_at"),
            "previous_boot_id": manifest.get("previous_boot_id"),
            "current_boot_id": manifest.get("current_boot_id"),
            "classification": manifest.get("classification") or evidence.get("classification") or "Unknown",
            "reset_mechanism": manifest.get("reset_mechanism") or evidence.get("reset_mechanism") or "Unknown",
            "confidence": evidence.get("confidence"),
            "probable_preceding_fault": manifest.get("probable_preceding_fault") or evidence.get("probable_preceding_fault"),
            "watchdog_feed": {
                key: feed.get(key)
                for key in (
                    "process_status",
                    "backend",
                    "device",
                    "last_feed_utc",
                    "feed_count",
                    "feed_decision",
                    "last_error",
                    "error_count",
                )
            },
            "planned_direct_trip_test": bool((evidence.get("deliberate_trip_test") or {}).get("confirmed")) if isinstance(evidence.get("deliberate_trip_test"), dict) else False,
            "planned_liveness_test": bool((evidence.get("liveness_path_test") or {}).get("confirmed")) if isinstance(evidence.get("liveness_path_test"), dict) else False,
        })
    return incidents


def _hash_file(path: Path) -> dict[str, Any]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"path": str(path), "sha256": digest.hexdigest(), "size_bytes": path.stat().st_size}
    except OSError as exc:
        return {"path": str(path), "sha256": "", "error": str(exc)}


def _evidence_text(result: CommandResult) -> str:
    return (
        f"Command: {result.get('command', '')}\n"
        f"Exit status: {result.get('returncode')}\n\n"
        f"STDOUT\n{result.get('stdout', '')}\n\n"
        f"STDERR\n{result.get('stderr', '')}\n"
    )


def _filter_kernel_result(result: CommandResult) -> CommandResult:
    lines = [
        line for line in str(result.get("stdout") or "").splitlines()
        if any(term in line.casefold() for term in KERNEL_EVIDENCE_TERMS)
    ]
    return {**result, "stdout": "\n".join(lines[-1000:])}


def collect_manufacturer_report(
    cfg: dict[str, Any],
    *,
    identity: dict[str, Any] | None = None,
    app_version: dict[str, Any] | None = None,
    runner: Runner | None = None,
    dmi_root: Path = Path("/sys/class/dmi/id"),
    sys_root: Path = Path("/sys"),
    proc_root: Path = Path("/proc"),
    os_release_path: Path = Path("/etc/os-release"),
) -> dict[str, Any]:
    run = runner or _run
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data_dir = Path(cfg.get("events_path") or "/var/lib/va-watchdog/events.jsonl").parent
    dmi = {name: _read_text(dmi_root / filename) for name, filename in DMI_FIELDS.items()}
    os_release = _parse_key_values(_read_text(os_release_path))
    cpuinfo = _read_text(proc_root / "cpuinfo")
    meminfo = _read_text(proc_root / "meminfo")
    report_identity = identity if isinstance(identity, dict) else {}
    network_interfaces = _network_summary(sys_root)
    supplied_version = app_version if isinstance(app_version, dict) else {}
    public_version = {
        key: supplied_version.get(key)
        for key in ("name", "branch", "commit", "commit_id", "build_at")
        if supplied_version.get(key) not in (None, "")
    }

    commands: dict[str, tuple[list[str], int]] = {
        "uname.txt": (["uname", "-a"], 5),
        "lscpu.txt": (["lscpu"], 8),
        "block-devices.txt": (["lsblk", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL,REV,TRAN"], 8),
        "pci-devices-and-drivers.txt": (["lspci", "-nnk"], 10),
        "usb-devices.txt": (["lsusb"], 8),
        "loaded-kernel-modules.txt": (["lsmod"], 8),
        "wdt-dio-module.txt": (["modinfo", "wdt_dio"], 8),
        "igc-module.txt": (["modinfo", "igc"], 8),
        "ahci-module.txt": (["modinfo", "ahci"], 8),
        "dkms-status.txt": (["dkms", "status"], 8),
        "watchdog-services.txt": (["systemctl", "show", "va-watchdog", "va-watchdog-feed", "-p", "Id", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState", "-p", "ExecMainStartTimestamp", "-p", "NRestarts"], 10),
        "installed-packages.txt": (["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n", "linux-image-*", "linux-firmware", "dkms", "smartmontools", "python3", "gcc", "libc6"], 10),
        "compiler-version.txt": (["gcc", "--version"], 5),
        "python-version.txt": (["python3", "--version"], 5),
        "dmi-bios.txt": (["dmidecode", "--type", "bios"], 10),
        "dmi-system.txt": (["dmidecode", "--type", "system"], 10),
        "dmi-baseboard.txt": (["dmidecode", "--type", "baseboard"], 10),
        "current-kernel-relevant.txt": (["journalctl", "-k", "-b", "--no-pager", "-n", "2000", "-o", "short-iso"], 15),
        "previous-kernel-relevant.txt": (["journalctl", "-k", "-b", "-1", "--no-pager", "-n", "2000", "-o", "short-iso"], 15),
    }
    evidence: dict[str, str] = {}
    for name, (command, timeout) in commands.items():
        result = run(command, timeout)
        if name.endswith("kernel-relevant.txt"):
            result = _filter_kernel_result(result)
        evidence[name] = _evidence_text(result)

    for interface in network_interfaces:
        name = str(interface.get("name") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
            continue
        evidence[f"network-{name}-driver.txt"] = _evidence_text(run(["ethtool", "-i", name], 8))
        evidence[f"network-{name}-statistics.txt"] = _evidence_text(run(["ethtool", "-S", name], 10))

    evidence["interrupts.txt"] = (
        "Snapshot of /proc/interrupts\n\n" + _read_text(proc_root / "interrupts") + "\n"
    )
    module_parameters: dict[str, str] = {}
    for path in sorted((sys_root / "module" / "wdt_dio" / "parameters").glob("*")):
        if path.is_file():
            module_parameters[path.name] = _read_text(path)

    disk_devices: list[str] = []
    for role in ("os_disk", "recording_disk"):
        item = report_identity.get(role, {}) if isinstance(report_identity.get(role, {}), dict) else {}
        device = str(item.get("device") or "")
        if re.fullmatch(r"/dev/[A-Za-z0-9._+-]+", device) and device not in disk_devices:
            disk_devices.append(device)
    for device in disk_devices:
        safe_name = Path(device).name
        evidence[f"smart-{safe_name}.txt"] = _evidence_text(run(["smartctl", "-x", device], 20))

    library = Path("/usr/local/lib/va-watchdog/vendor/libwdt_dio.so")
    module_filename = run(["modinfo", "-n", "wdt_dio"], 8)
    module_path = Path(str(module_filename.get("stdout") or ""))
    files = {
        "wdt_dio_library": _hash_file(library),
        "wdt_dio_module": _hash_file(module_path) if module_path.is_absolute() else {"path": str(module_path), "sha256": ""},
    }

    return {
        "schema_version": 1,
        "generated_utc": generated,
        "purpose": "Neousys engineering report for intermittent POC-451VTC lockup and WDT_DIO recovery investigation",
        "privacy": "The collector does not intentionally gather CCTV recordings, configured IP addresses/routes, credentials, or complete application journals.",
        "gateway": report_identity,
        "hardware": {
            "dmi": dmi,
            "classified_model": (report_identity.get("hardware") or {}).get("display_model") if isinstance(report_identity.get("hardware"), dict) else "",
            "cpu": _cpu_summary(cpuinfo),
            "memory": _memory_summary(meminfo),
            "network_interfaces": network_interfaces,
            "power_and_bus_settings": _power_summary(sys_root, proc_root),
        },
        "software": {
            "operating_system": {
                "name": os_release.get("PRETTY_NAME", ""),
                "id": os_release.get("ID", ""),
                "version_id": os_release.get("VERSION_ID", ""),
            },
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "watchdog_build": public_version,
        },
        "watchdog": {
            **_watchdog_summary(cfg, data_dir),
            "module_parameters": module_parameters,
            "recent_reboots": _recent_reboot_summaries(cfg, data_dir),
            "preserved_incidents": _incident_summaries(cfg, data_dir),
        },
        "driver_files": files,
        "evidence": evidence,
    }


def render_manufacturer_report(payload: dict[str, Any]) -> str:
    gateway = payload.get("gateway", {}) if isinstance(payload.get("gateway"), dict) else {}
    hardware = payload.get("hardware", {}) if isinstance(payload.get("hardware"), dict) else {}
    dmi = hardware.get("dmi", {}) if isinstance(hardware.get("dmi"), dict) else {}
    cpu = hardware.get("cpu", {}) if isinstance(hardware.get("cpu"), dict) else {}
    memory = hardware.get("memory", {}) if isinstance(hardware.get("memory"), dict) else {}
    software = payload.get("software", {}) if isinstance(payload.get("software"), dict) else {}
    os_info = software.get("operating_system", {}) if isinstance(software.get("operating_system"), dict) else {}
    watchdog = payload.get("watchdog", {}) if isinstance(payload.get("watchdog"), dict) else {}
    config = watchdog.get("configuration", {}) if isinstance(watchdog.get("configuration"), dict) else {}
    feed = watchdog.get("current_feed", {}) if isinstance(watchdog.get("current_feed"), dict) else {}
    direct = watchdog.get("last_direct_trip_test", {}) if isinstance(watchdog.get("last_direct_trip_test"), dict) else {}
    liveness = watchdog.get("full_liveness_test", {}) if isinstance(watchdog.get("full_liveness_test"), dict) else {}
    reboot = watchdog.get("latest_reboot_evidence", {}) if isinstance(watchdog.get("latest_reboot_evidence"), dict) else {}
    recent_reboots = watchdog.get("recent_reboots", []) if isinstance(watchdog.get("recent_reboots"), list) else []
    incidents = watchdog.get("preserved_incidents", []) if isinstance(watchdog.get("preserved_incidents"), list) else []
    network = hardware.get("network_interfaces", []) if isinstance(hardware.get("network_interfaces"), list) else []
    disks = [gateway.get("os_disk", {}), gateway.get("recording_disk", {})]

    lines = [
        "NEOUSYS ENGINEERING SYSTEM REPORT",
        "=================================",
        f"Generated UTC: {payload.get('generated_utc', '-')}",
        f"Site: {gateway.get('display_name') or '-'}",
        f"Asset ID: {gateway.get('asset_id') or '-'}",
        f"Hostname: {gateway.get('hostname') or '-'}",
        f"Hardware fingerprint: {gateway.get('hardware_fingerprint') or '-'}",
        "",
        "UNIT AND FIRMWARE",
        f"Manufacturer: {dmi.get('manufacturer') or '-'}",
        f"Model reported by BIOS: {dmi.get('reported_model') or '-'}",
        f"Reviewed model: {hardware.get('classified_model') or '-'}",
        f"Product version: {dmi.get('product_version') or '-'}",
        f"Product serial: {dmi.get('product_serial') or '-'}",
        f"Board: {dmi.get('board_vendor') or '-'} {dmi.get('board_name') or '-'} {dmi.get('board_version') or ''}".rstrip(),
        f"Board serial: {dmi.get('board_serial') or '-'}",
        f"BIOS: {dmi.get('bios_vendor') or '-'} {dmi.get('bios_version') or '-'}",
        f"BIOS date: {dmi.get('bios_date') or '-'}",
        "",
        "OPERATING SYSTEM",
        f"OS: {os_info.get('name') or '-'}",
        f"Kernel: {software.get('kernel') or '-'}",
        f"Architecture: {software.get('architecture') or '-'}",
        f"CPU: {cpu.get('model') or '-'}",
        f"CPU stepping / microcode: {cpu.get('stepping') or '-'} / {cpu.get('microcode') or '-'}",
        f"Logical processors: {cpu.get('logical_processors') if cpu.get('logical_processors') is not None else '-'}",
        f"Memory: {memory.get('total_mib') if memory.get('total_mib') is not None else '-'} MiB",
        "",
        "STORAGE",
    ]
    seen_disks: set[str] = set()
    for disk in disks:
        if not isinstance(disk, dict):
            continue
        device = str(disk.get("device") or "")
        if not device or device in seen_disks:
            continue
        seen_disks.add(device)
        lines.append(f"{device}: {disk.get('model') or '-'} / serial {disk.get('serial') or '-'} / {disk.get('size') or '-'}")
    if not seen_disks:
        lines.append("No disk identity was available.")

    lines.extend(["", "NETWORK DRIVERS"])
    for interface in network:
        if isinstance(interface, dict):
            stats = interface.get("statistics", {}) if isinstance(interface.get("statistics"), dict) else {}
            lines.append(
                f"{interface.get('name') or '-'}: driver {interface.get('driver') or '-'}, "
                f"{interface.get('speed_mbps') or '-'} Mb/s {interface.get('duplex') or '-'}, "
                f"RX errors/drops {stats.get('rx_errors') or '0'}/{stats.get('rx_dropped') or '0'}, "
                f"TX errors/drops {stats.get('tx_errors') or '0'}/{stats.get('tx_dropped') or '0'}"
            )
    if not network:
        lines.append("No network interface details were available.")

    lines.extend([
        "",
        "NEOUSYS WATCHDOG",
        f"Backend / device: {config.get('backend') or '-'} / {config.get('device') or '-'}",
        f"Feed interval / timeout: {config.get('feed_interval_seconds') or '-'}s / {config.get('timeout_seconds') or '-'}s",
        f"Current state: {feed.get('process_status') or '-'}; last feed {feed.get('last_feed_utc') or '-'}; errors {feed.get('error_count') or 0}",
        f"Direct trip test: {'PASS' if direct.get('ok') else 'not confirmed'} - {direct.get('tested_at') or '-'}",
        f"Full liveness-path test: {'PASS' if liveness.get('ok') and liveness.get('completed') else 'not confirmed'} - {liveness.get('message') or '-'}",
        f"Latest reboot classification: {reboot.get('classification') or '-'} ({reboot.get('confidence') or '-'})",
        "",
        "RECENT RESTARTS AND PRESERVED INCIDENTS",
    ])
    if recent_reboots:
        for item in recent_reboots[:10]:
            if not isinstance(item, dict):
                continue
            planned = "planned liveness test" if item.get("planned_liveness_test") else "planned direct trip test" if item.get("planned_direct_trip_test") else "not marked as a planned test"
            lines.append(
                f"Reboot {item.get('created_at') or '-'}: {item.get('classification') or 'Unknown'} "
                f"({item.get('confidence') or '-'}; {planned})"
            )
    else:
        lines.append("No reboot timeline was available.")
    if incidents:
        for item in incidents[:10]:
            if not isinstance(item, dict):
                continue
            feed_item = item.get("watchdog_feed", {}) if isinstance(item.get("watchdog_feed"), dict) else {}
            lines.append(
                f"Incident {item.get('detected_at') or item.get('archive') or '-'}: "
                f"{item.get('classification') or 'Unknown'}; last feed {feed_item.get('last_feed_utc') or '-'}; "
                f"feeder state {feed_item.get('process_status') or '-'}; decision {feed_item.get('feed_decision') or '-'}"
            )
    else:
        lines.append("No preserved incident summaries were available.")

    lines.extend([
        "",
        "ATTACHED RAW EVIDENCE",
        "The raw/ directory contains DMI, PCI driver bindings, kernel modules, DKMS status, SMART data,",
        "power settings, service state, and filtered current/previous kernel messages.",
        "",
        str(payload.get("privacy") or ""),
    ])
    return "\n".join(lines).rstrip() + "\n"


def manufacturer_report_bundle(payload: dict[str, Any], slug: str) -> tuple[bytes, str]:
    buffer = io.BytesIO()
    generated = re.sub(r"[^0-9]", "", str(payload.get("generated_utc") or ""))[:14] or time.strftime("%Y%m%d%H%M%S")
    safe_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", slug).strip("-._") or "gateway"
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("NEOUSYS-SYSTEM-REPORT.txt", render_manufacturer_report(payload))
        archive.writestr("NEOUSYS-SYSTEM-REPORT.json", json.dumps({key: value for key, value in payload.items() if key != "evidence"}, indent=2))
        evidence = payload.get("evidence", {}) if isinstance(payload.get("evidence"), dict) else {}
        for name, content in evidence.items():
            archive.writestr(f"raw/{name}", str(content))
        archive.writestr(
            "README.txt",
            "Open NEOUSYS-SYSTEM-REPORT.txt first. The raw directory contains the supporting command output.\n"
            "This archive does not intentionally collect CCTV recordings, configured IP addresses/routes, credentials, or complete application journals.\n",
        )
    return buffer.getvalue(), f"va-watchdog-neousys-report-{safe_slug}-{generated}.zip"
