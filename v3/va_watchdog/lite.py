"""Read-only operator view. Uses saved evidence; never runs collectors or actions."""
from datetime import datetime
import json
from pathlib import Path
import time


def read_object(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def age(value, now):
    try:
        stamp = float(value) if isinstance(value, (int, float)) else datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        return max(0, now - stamp) if stamp <= now + 5 else None
    except (ValueError, TypeError, OverflowError):
        return None


def event_tail(path, limit=6):
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, 2)
            start = max(0, handle.tell() - 128 * 1024)
            handle.seek(start)
            if start:
                handle.readline()
            lines = handle.read(128 * 1024).splitlines()
    except OSError:
        return []
    rows = []
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(row, dict) or row.get("source") == "retention":
            continue
        if row.get("level") == "info" and row.get("source") in ("watchdog", "mobile_router"):
            continue
        if rows and all(rows[-1].get(key) == row.get(key) for key in ("level", "source", "message")):
            rows[-1]["count"] += 1
            continue
        if len(rows) >= limit:
            break
        rows.append({**{key: row.get(key) for key in ("time", "level", "source", "message")}, "count": 1})
    return rows


def snapshot(cfg, now=None):
    now = time.time() if now is None else now
    data = Path(cfg["events_path"]).parent
    status = read_object(cfg["status_path"])
    feed = read_object(cfg.get("hardware_watchdog_feed_state_path") or data / "hardware-watchdog-feed.json")
    evidence_path = Path(cfg.get("reboot_evidence_path") or data / "reboot-evidence.jsonl").with_name("last-reboot-evidence.json")
    evidence = read_object(evidence_path)
    legacy = read_object(cfg.get("legacy_watchdog_state_path") or "/var/lib/va-connect-site-watchdog/state.json")
    legacy_config = read_object(cfg.get("legacy_watchdog_config_path") or "/opt/va-connect-watchdog/site-watchdog.json")
    checks = {c["name"]: c for c in status.get("checks", []) if isinstance(c, dict) and c.get("name")}
    sample_age = age(status.get("time"), now)
    stale = sample_age is None or sample_age > max(60, cfg.get("poll_interval_seconds", 5) * 6)

    def card(title, names, detail=None):
        found = [checks[name] for name in names if name in checks]
        rank = {"healthy": 0, "disabled": 1, "unknown": 2, "warning": 3, "degraded": 4, "critical": 5}
        worst = max(found, key=lambda c: rank.get(c.get("state"), 2), default={})
        state = "unknown" if stale or not found else worst.get("state", "unknown")
        return {"title": title, "state": state, "detail": "Waiting for fresh monitoring data" if stale else detail or worst.get("message") or "Not measured"}

    services = [name for name in checks if name.endswith(".service")]
    running = sum(checks[name].get("state") == "healthy" for name in services)
    storage = status.get("recording_storage") or {}
    storage_note = storage.get("message") or "Dedicated recording storage is not measured"
    if isinstance(storage.get("free_mb"), (int, float)):
        storage_note += f" · {storage['free_mb'] / 1024:.1f} GiB free"
    cards = [
        card("Videosoft services", services + ["videosoft_process"], f"{running} of {len(services)} monitored services running"),
        card("Network & router", ["network_module", "mobile_router"]),
        card("Recording storage", ["recording_storage"], storage_note),
        card("System", ["temperature", "ram", "cpu_load", "root_disk", "write_test"]),
    ]
    if cards[-1]["state"] == "healthy":
        metrics = []
        for name, label, unit in [("temperature", "CPU", "°C"), ("ram", "RAM", "%"), ("cpu_load", "Load", "%")]:
            value = checks.get(name, {}).get("value")
            if isinstance(value, (float, int)):
                metrics.append(f"{label} {value:g}{unit}")
        if metrics:
            cards[-1]["detail"] = " · ".join(metrics)
    feed_age = age(feed.get("last_feed_unix"), now)
    feed_fresh = feed_age is not None and feed_age < cfg.get("hardware_watchdog", {}).get("timeout_seconds", 30)
    feeding = feed.get("process_status") == "feeding" and feed_fresh
    cards.append({"title": "Hardware protection", "state": "healthy" if feeding else "unknown", "detail": f"Feeding · last feed {int(feed_age)}s ago" if feeding else "Fresh hardware feeding is not confirmed"})
    alerts = [{"name": c.get("name"), "state": c.get("state"), "message": c.get("message")} for c in checks.values() if c.get("state") not in ("healthy", "disabled")]
    healthy = not stale and bool(checks) and not alerts and all(c["state"] == "healthy" for c in cards)
    reason = evidence.get("previous_reboot_reason") or {}
    legacy_age = age(legacy.get("last_check_at"), now)
    legacy_fresh = legacy_age is not None and legacy_age < 120
    recovery = cfg.get("recovery") or {}
    consolidated = recovery.get('consolidated_policy', {}).get('enabled', False)
    recovery_live = status.get('recovery') or {}
    blackbox = status.get("blackbox") or {}
    box_age = age(blackbox.get("last_time"), now)
    recorder_ok = blackbox.get("enabled") and blackbox.get("recorder_running") and box_age is not None and box_age < 30
    capture = [
        {"id": "incident", "name": "Reboot & incident evidence", "current": "Boot IDs, command reason, previous journal, crash signatures", "proposal": "Keep", "why": "Distinguishes a requested reboot, watchdog reset and an unexplained restart."},
        {"id": "blackbox", "name": "Before-crash recorder", "current": f"{blackbox.get('sample_seconds', '?')}s samples; {int(blackbox.get('retention_seconds', 0) / 60)} minute rolling buffer", "proposal": "Keep", "why": "CPU, memory pressure, disk I/O, kernel counters and application progress before a freeze."},
        {"id": "health", "name": "Services, storage & connectivity", "current": "Service state, actual recording disk, router and internet reachability", "proposal": "Keep", "why": "Explains application failures and network-triggered recovery."},
        {"id": "liveness", "name": "Monitor heartbeat & hardware feed", "current": "Separate health progress, process heartbeat and hardware feeder", "proposal": "Keep", "why": "A responsive web page does not prove the monitor is working."},
        {"id": "history", "name": "Long-term metric history", "current": f"One sample per {cfg.get('retention', {}).get('history_sample_seconds', 60)}s", "proposal": "Reduce", "why": "Keep compact trends; avoid repeating full service and router payloads."},
        {"id": "legacy", "name": "Older watchdog & duplicate logs", "current": "Separate monitor, recovery policy, event log and website", "proposal": "Retire after migration", "why": "Move required recovery and LAN checks to one owner before removing it."},
        {"id": "router", "name": "Detailed mobile radio history", "current": "LTE quality, signal, cell and interface information", "proposal": "Details only", "why": "Keep connectivity and outage evidence visible; radio engineering detail can stay collapsed."},
        {"id": "extras", "name": "People counts, inventory & test tools", "current": "Crossing activity, hardware inventory, speed and commissioning tests", "proposal": "Separate", "why": "Useful for other jobs; not needed on the crash-monitoring homepage."},
    ]
    if consolidated:
        capture[5].update(name="Legacy evidence archive", current="Recovery migrated to V3; existing legacy logs retained", proposal="Details only", why="Keep historical incident evidence. The retired monitor no longer creates duplicate logs.")
    files = []
    for label, path in [("V3 history", Path(cfg.get("history_path") or data / "history.jsonl")), ("V3 events", Path(cfg["events_path"])), ("Older watchdog events", Path(cfg.get("legacy_watchdog_events_path") or "/var/log/va-connect-site-watchdog/events.jsonl"))]:
        try:
            files.append({"name": label, "mib": round(path.stat().st_size / 1048576, 1)})
        except OSError:
            pass
    return {
        "site": (cfg.get("identity") or {}).get("site_name") or "Gateway",
        "time": status.get("time"), "sample_age": sample_age, "stale": stale,
        "headline": "Monitoring data is stale" if stale else "All current checks are healthy" if healthy else "Attention needed",
        "state": "unknown" if stale else "healthy" if healthy else "warning",
        "cards": cards, "alerts": alerts[:8],
        "latest_reboot": {"message": reason.get("message") or evidence.get("reset_mechanism") or evidence.get("classification") or "No reboot evidence available", "time": reason.get("requested_at") or evidence.get("created_at"), "confidence": evidence.get("confidence") or "Unknown", "fault": evidence.get("probable_preceding_fault") or "Not established"},
        "recorder": {"ok": bool(recorder_ok), "message": "Before-crash recorder is current" if recorder_ok else "Before-crash recording is not confirmed"},
        "recovery": {"legacy": ("V3 owns application and network recovery" if recovery_live.get('owner') == 'v3' and not stale and recovery_live.get('state') != 'blocked' else "Consolidated recovery configured; live ownership needs checking") if consolidated else ("Older watchdog can request reboots" if legacy_fresh and legacy_config.get("reboot_enabled") is True else "Older watchdog detected; status or reboot permission needs checking" if legacy else "Older watchdog not observed"), "v3": str(recovery_live.get('message') or 'V3 software recovery enabled') if recovery.get("enabled") else "V3 software recovery disabled", "note": "Hardware protection is separate from software recovery."},
        "events": event_tail(cfg["events_path"]), "capture": [] if cfg.get("web", {}).get("lightweight") else capture, "log_sizes": files,
        "diagnostics": [{k: c.get(k) for k in ("name", "state", "message")} for c in checks.values()],
    }


def page():
    return Path(__file__).with_name("lite.html").read_bytes()
