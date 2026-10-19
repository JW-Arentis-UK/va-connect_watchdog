"""Read reboot attribution from the older site watchdog without importing its settings."""
from datetime import datetime
from pathlib import Path
import json


NETWORK_REBOOT = "Watchdog reboot — no network access"


def _timestamp(value):
    try:
        if isinstance(value, (float, int)):
            return float(value)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def legacy_reboot_reason(cfg, evidence):
    """Require a successful reboot command near the previous boot's final heartbeat.

    A failed ping alone is never evidence that networking caused a reboot.
    Read a bounded tail and whitelist fields: legacy startup events contain secrets.
    """
    heartbeat = evidence.get("last_heartbeat") or {}
    if heartbeat.get("boot_id") != evidence.get("previous_boot_id"):
        return {}
    last_alive = _timestamp(heartbeat.get("time"))
    detected = _timestamp(evidence.get("created_at"))
    if last_alive is None or detected is None or not 0 <= detected - last_alive <= 600:
        return {}
    path = Path(cfg.get("legacy_watchdog_events_path") or "/var/log/va-connect-site-watchdog/events.jsonl")
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            offset = max(0, handle.tell() - 16 * 1024 * 1024)
            handle.seek(offset)
            if offset:
                handle.readline()
            lines = handle.read().splitlines()
    except OSError:
        return {}
    checks = {}
    checks_at = None
    reason = {}
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(row, dict):
            continue
        when = _timestamp(row.get("ts"))
        if when is None or not last_alive - 120 <= when <= min(last_alive + 120, detected):
            continue
        if row.get("event") == "startup":
            break  # Never borrow a command or checks from the new boot.
        if row.get("event") == "heartbeat" and isinstance(row.get("checks"), dict):
            checks = {key: row["checks"].get(key) for key in ("lan_ok", "internet_ok", "app_ok", "services_ok")}
            checks_at = when
        if row.get("event") == "action" and row.get("action") == "reboot" and row.get("return_code") == 0:
            network = checks_at is not None and 0 <= when - checks_at <= 120 and (checks.get("lan_ok") is False or checks.get("internet_ok") is False)
            reason = {
                "source": "legacy_site_watchdog",
                "requested_at": row["ts"],
                "boot_id": evidence["previous_boot_id"],
                "message": NETWORK_REBOOT if network else "Reboot requested by the older watchdog",
                "cause": "network_access_lost" if network else "unknown",
                "checks": checks if checks_at is not None and 0 <= when - checks_at <= 120 else {},
                "evidence_path": str(path),
            }
    return reason


def apply_legacy_reason(cfg, evidence):
    if evidence.get("previous_reboot_reason") or evidence.get("deliberate_trip_test") or evidence.get("liveness_path_test"):
        return False
    if (evidence.get("reset_mechanism") or evidence.get("classification")) not in {"Clean reboot", "Shutdown recorded (cause unknown)", "Unknown"}:
        return False
    reason = legacy_reboot_reason(cfg, evidence)
    if not reason:
        return False
    evidence.update(reset_mechanism="Requested reboot", classification="Requested reboot", confidence="High", previous_reboot_reason=reason)
    if reason["cause"] == "network_access_lost":
        evidence["probable_preceding_fault"] = "loss of network access"
    evidence["evidence_used"] = [item for item in evidence.get("evidence_used", []) if "initiator and reset cause are unknown" not in item and "classification remains Unknown" not in item]
    evidence["evidence_used"].append("The older watchdog logged a successful reboot command immediately before this boot; the recorded checks identify the preceding failure.")
    return True
