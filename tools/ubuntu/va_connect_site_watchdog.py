#!/usr/bin/env python3

import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DEFAULT_CONFIG_PATH = "/opt/va-connect-watchdog/site-watchdog.json"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def run_command(command: List[str], timeout: int = 10) -> Tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode, output.strip()
    except Exception as exc:
        return 999, f"{type(exc).__name__}: {exc}"


def run_shell(command: str, timeout: int = 15) -> Tuple[int, str]:
    return run_command(["bash", "-lc", command], timeout=timeout)


def ping_host(host: str, timeout_seconds: int) -> Dict[str, object]:
    code, output = run_command(
        ["ping", "-c", "1", "-W", str(timeout_seconds), host],
        timeout=timeout_seconds + 3,
    )
    return {"host": host, "ok": code == 0, "detail": output[-400:]}


def tcp_check(host: str, port: int, timeout_seconds: int) -> Dict[str, object]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            latency_ms = int((time.monotonic() - start) * 1000)
            return {
                "host": host,
                "port": port,
                "ok": True,
                "detail": f"connected in {latency_ms}ms",
            }
    except OSError as exc:
        return {"host": host, "port": port, "ok": False, "detail": str(exc)}


def process_running(match_text: str) -> bool:
    code, _ = run_command(["pgrep", "-f", "--", match_text], timeout=5)
    return code == 0


def run_action(command: str) -> Tuple[int, str]:
    return run_shell(command, timeout=120)


def summarize_checks(pings: List[Dict[str, object]], ports: List[Dict[str, object]]) -> Dict[str, bool]:
    internet_ok = any(item["ok"] for item in pings) if pings else True
    lan_ok = all(item["ok"] for item in ports) if ports else True
    return {"internet_ok": internet_ok, "lan_ok": lan_ok}


def backoff_seconds(base: int, multiplier: float, maximum: int, failures: int) -> int:
    delay = float(base)
    for _ in range(max(failures, 0)):
        delay = min(delay * multiplier, maximum)
    return int(delay)


def capture_snapshot(snapshot_dir: Path, reason: str, app_match: str, max_journal_lines: int) -> Path:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    target_dir = snapshot_dir / f"{timestamp}_{reason}"
    target_dir.mkdir(parents=True, exist_ok=True)

    commands = {
        "date.txt": "date -Is",
        "uptime.txt": "uptime",
        "ip_addr.txt": "ip addr",
        "ip_route.txt": "ip route",
        "resolvectl.txt": "resolvectl status || systemd-resolve --status",
        "free.txt": "free -m",
        "df.txt": "df -h",
        "top.txt": "top -b -n 1 | head -n 40",
        "dmesg_tail.txt": "dmesg | tail -n 80",
        "processes.txt": "ps -eo pid,ppid,stat,%cpu,%mem,etime,args --sort=-%cpu | head -n 40",
        "app_processes.txt": f"pgrep -af -- {shlex.quote(app_match)} || true",
        "journal_system.txt": f"journalctl -n {max_journal_lines} --no-pager",
        "journal_network.txt": f"journalctl -u NetworkManager -n {max_journal_lines} --no-pager || journalctl -u systemd-networkd -n {max_journal_lines} --no-pager || true",
        "journal_teamviewer.txt": f"journalctl -u teamviewerd -n {max_journal_lines} --no-pager || true",
    }

    for filename, command in commands.items():
        _, output = run_shell(command, timeout=20)
        (target_dir / filename).write_text(output + "\n", encoding="utf-8")

    return target_dir


class SiteWatchdog:
    def __init__(self, config: Dict[str, object]):
        self.config = config
        self.stop_requested = False
        self.state_path = Path(str(config["state_file"]))
        self.log_path = Path(str(config["json_log"]))
        self.snapshot_dir = Path(str(config["snapshot_dir"]))
        self.state = read_json(
            self.state_path,
            {
                "failure_count": 0,
                "fault_active": False,
                "fault_started_at": None,
                "last_reboot_attempt_at": None,
                "last_network_restart_at": None,
                "last_fault_signature": None,
                "last_snapshot_at": None,
            },
        )

    def request_stop(self, *_args):
        self.stop_requested = True

    def log_event(self, event_type: str, **fields) -> None:
        payload = {"ts": iso_now(), "event": event_type}
        payload.update(fields)
        append_jsonl(self.log_path, payload)

    def maybe_snapshot(self, reason: str, signature: str) -> Optional[str]:
        cooldown = int(self.config["snapshot_cooldown_seconds"])
        last_snapshot_at = self.state.get("last_snapshot_at")
        now = time.time()
        if last_snapshot_at and now - float(last_snapshot_at) < cooldown:
            return None
        snapshot_path = capture_snapshot(
            self.snapshot_dir,
            reason=reason,
            app_match=str(self.config["app_match"]),
            max_journal_lines=int(self.config["journal_lines"]),
        )
        self.state["last_snapshot_at"] = now
        self.state["last_fault_signature"] = signature
        self.log_event("snapshot", reason=reason, signature=signature, path=str(snapshot_path))
        return str(snapshot_path)

    def start_app(self) -> bool:
        command = str(self.config.get("app_start_command", "")).strip()
        if not command:
            self.log_event("action_skipped", action="start_app", reason="app_start_command empty")
            return False
        code, output = run_action(command)
        self.log_event("action", action="start_app", return_code=code, detail=output[-600:])
        return code == 0

    def restart_network(self) -> bool:
        command = str(self.config.get("network_restart_command", "")).strip()
        if not command:
            self.log_event("action_skipped", action="restart_network", reason="network_restart_command empty")
            return False
        code, output = run_action(command)
        self.state["last_network_restart_at"] = time.time()
        self.log_event("action", action="restart_network", return_code=code, detail=output[-600:])
        return code == 0

    def reboot_host(self) -> bool:
        command = str(self.config.get("reboot_command", "shutdown -r now")).strip()
        code, output = run_action(command)
        self.state["last_reboot_attempt_at"] = time.time()
        self.log_event("action", action="reboot", return_code=code, detail=output[-600:])
        return code == 0

    def perform_checks(self) -> Dict[str, object]:
        pings = [ping_host(host, int(self.config["ping_timeout_seconds"])) for host in self.config["internet_hosts"]]
        ports = [
            tcp_check(item["host"], int(item["port"]), int(self.config["tcp_timeout_seconds"]))
            for item in self.config["tcp_targets"]
        ]
        app_ok = process_running(str(self.config["app_match"]))
        summary = summarize_checks(pings, ports)
        result = {
            "pings": pings,
            "ports": ports,
            "app_ok": app_ok,
            **summary,
        }
        result["healthy"] = bool(result["internet_ok"] and result["lan_ok"] and result["app_ok"])
        return result

    def run_once(self) -> None:
        checks = self.perform_checks()
        signature = json.dumps(
            {
                "internet_ok": checks["internet_ok"],
                "lan_ok": checks["lan_ok"],
                "app_ok": checks["app_ok"],
                "bad_pings": [item["host"] for item in checks["pings"] if not item["ok"]],
                "bad_ports": [f'{item["host"]}:{item["port"]}' for item in checks["ports"] if not item["ok"]],
            },
            sort_keys=True,
        )

        if checks["healthy"]:
            if self.state.get("fault_active"):
                started = self.state.get("fault_started_at")
                duration = None
                if started:
                    duration = int(time.time() - float(started))
                self.log_event("recovered", duration_seconds=duration, checks=checks)
            self.state["fault_active"] = False
            self.state["fault_started_at"] = None
            self.state["failure_count"] = 0
            self.state["last_fault_signature"] = None
            write_json(self.state_path, self.state)
            self.log_event("heartbeat", status="healthy", checks=checks)
            return

        now_epoch = time.time()
        if not self.state.get("fault_active"):
            self.state["fault_active"] = True
            self.state["fault_started_at"] = now_epoch
            self.log_event("fault_started", checks=checks)

        if signature != self.state.get("last_fault_signature"):
            self.maybe_snapshot("fault-change", signature)

        fault_age = int(now_epoch - float(self.state["fault_started_at"]))
        reboot_after = backoff_seconds(
            int(self.config["base_reboot_timeout_seconds"]),
            float(self.config["reboot_backoff_multiplier"]),
            int(self.config["max_reboot_timeout_seconds"]),
            int(self.state.get("failure_count", 0)),
        )

        event = {
            "status": "fault",
            "fault_age_seconds": fault_age,
            "reboot_after_seconds": reboot_after,
            "checks": checks,
        }
        self.log_event("heartbeat", **event)

        if not checks["app_ok"]:
            self.start_app()
            time.sleep(int(self.config["post_action_settle_seconds"]))
            checks_after_start = self.perform_checks()
            self.log_event("post_action_check", action="start_app", checks=checks_after_start)
            if checks_after_start["healthy"]:
                self.state["fault_active"] = False
                self.state["fault_started_at"] = None
                self.state["failure_count"] = 0
                self.state["last_fault_signature"] = None
                write_json(self.state_path, self.state)
                return

        if not checks["internet_ok"] and bool(self.config["restart_network_before_reboot"]):
            last_restart = float(self.state.get("last_network_restart_at") or 0)
            if now_epoch - last_restart >= int(self.config["network_restart_cooldown_seconds"]):
                self.restart_network()
                time.sleep(int(self.config["post_action_settle_seconds"]))
                checks_after_network = self.perform_checks()
                self.log_event("post_action_check", action="restart_network", checks=checks_after_network)
                if checks_after_network["healthy"]:
                    self.state["fault_active"] = False
                    self.state["fault_started_at"] = None
                    self.state["failure_count"] = 0
                    self.state["last_fault_signature"] = None
                    write_json(self.state_path, self.state)
                    return

        if fault_age >= reboot_after:
            self.maybe_snapshot("pre-reboot", signature)
            self.state["failure_count"] = int(self.state.get("failure_count", 0)) + 1
            write_json(self.state_path, self.state)
            self.reboot_host()
            return

        write_json(self.state_path, self.state)

    def run_forever(self) -> int:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        self.log_event("startup", config=self.config)

        while not self.stop_requested:
            started_at = time.time()
            try:
                self.run_once()
            except Exception as exc:
                self.log_event("error", detail=f"{type(exc).__name__}: {exc}")
            sleep_for = max(1, int(self.config["check_interval_seconds"]) - int(time.time() - started_at))
            time.sleep(sleep_for)

        self.log_event("shutdown")
        return 0


def load_config() -> Dict[str, object]:
    config_path = Path(os.environ.get("SITE_WATCHDOG_CONFIG", DEFAULT_CONFIG_PATH))
    config = read_json(config_path, {})

    defaults = {
        "check_interval_seconds": 30,
        "ping_timeout_seconds": 3,
        "tcp_timeout_seconds": 3,
        "internet_hosts": ["1.1.1.1", "8.8.8.8"],
        "tcp_targets": [],
        "app_match": "va-connect",
        "app_start_command": "",
        "restart_network_before_reboot": True,
        "network_restart_command": "systemctl restart NetworkManager || systemctl restart systemd-networkd",
        "network_restart_cooldown_seconds": 600,
        "base_reboot_timeout_seconds": 300,
        "max_reboot_timeout_seconds": 3600,
        "reboot_backoff_multiplier": 2.0,
        "post_action_settle_seconds": 20,
        "reboot_command": "shutdown -r now",
        "json_log": "/var/log/va-connect-site-watchdog/events.jsonl",
        "state_file": "/var/lib/va-connect-site-watchdog/state.json",
        "snapshot_dir": "/var/log/va-connect-site-watchdog/snapshots",
        "snapshot_cooldown_seconds": 900,
        "journal_lines": 120,
    }

    merged = {**defaults, **config}
    if not isinstance(merged["internet_hosts"], list):
        raise ValueError("internet_hosts must be a JSON array")
    if not isinstance(merged["tcp_targets"], list):
        raise ValueError("tcp_targets must be a JSON array")
    return merged


def main() -> int:
    config = load_config()
    watchdog = SiteWatchdog(config)
    return watchdog.run_forever()


if __name__ == "__main__":
    sys.exit(main())
