#!/usr/bin/env python3

import html
import json
import os
import socket
import subprocess
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse


CONFIG_PATH = Path(os.environ.get("SITE_WATCHDOG_CONFIG", "/opt/va-connect-watchdog/site-watchdog.json"))
STATE_PATH = Path("/var/lib/va-connect-site-watchdog/state.json")
EVENTS_PATH = Path("/var/log/va-connect-site-watchdog/events.jsonl")
METRICS_PATH = Path("/var/log/va-connect-site-watchdog/metrics.jsonl")
BUILD_INFO_PATH = Path("/opt/va-connect-watchdog/build-info.json")
UPDATE_STATUS_PATH = Path("/var/lib/va-connect-site-watchdog/web-update-status.json")
UPDATE_LOG_PATH = Path("/var/log/va-connect-site-watchdog/web-update.log")


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


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "+00:00"


def load_config() -> Dict[str, Any]:
    config = read_json(CONFIG_PATH, {})
    defaults = {
        "monitoring_enabled": True,
        "app_restart_enabled": True,
        "restart_network_before_reboot": True,
        "reboot_enabled": True,
        "web_bind": "0.0.0.0",
        "web_port": 8787,
        "web_token": "",
        "base_reboot_timeout_seconds": 300,
        "max_reboot_timeout_seconds": 3600,
        "internet_hosts": [],
        "tcp_targets": [],
        "systemd_services": [],
    }
    merged = {**defaults, **config}
    merged["web_port"] = int(merged["web_port"])
    return merged


def sanitize_patch(data: Dict[str, Any]) -> Dict[str, Any]:
    patch: Dict[str, Any] = {}

    bool_keys = [
        "monitoring_enabled",
        "app_restart_enabled",
        "restart_network_before_reboot",
        "reboot_enabled",
    ]
    int_keys = [
        "base_reboot_timeout_seconds",
        "max_reboot_timeout_seconds",
        "check_interval_seconds",
        "network_restart_cooldown_seconds",
        "post_action_settle_seconds",
        "web_port",
    ]
    float_keys = ["reboot_backoff_multiplier"]
    str_keys = [
        "app_match",
        "app_start_command",
        "web_bind",
        "web_token",
        "network_restart_command",
    ]

    for key in bool_keys:
        if key in data:
            patch[key] = bool(data[key])
    for key in int_keys:
        if key in data:
            patch[key] = int(data[key])
    for key in float_keys:
        if key in data:
            patch[key] = float(data[key])
    for key in str_keys:
        if key in data:
            patch[key] = str(data[key]).strip()
    if "internet_hosts" in data:
        patch["internet_hosts"] = [str(item).strip() for item in data["internet_hosts"] if str(item).strip()]
    if "systemd_services" in data:
        patch["systemd_services"] = [str(item).strip() for item in data["systemd_services"] if str(item).strip()]
    if "tcp_targets" in data:
        targets = []
        for item in data["tcp_targets"]:
            host = str(item.get("host", "")).strip()
            port = int(item.get("port", 0))
            if host and 1 <= port <= 65535:
                targets.append({"host": host, "port": port})
        patch["tcp_targets"] = targets
    return patch


def recent_events(limit: int = 20) -> List[Dict[str, Any]]:
    if not EVENTS_PATH.exists():
        return []
    events = []
    for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(events))


def recent_metrics(hours: int = 24) -> List[Dict[str, Any]]:
    if not METRICS_PATH.exists():
        return []
    cutoff = time.time() - (hours * 3600)
    points: List[Dict[str, Any]] = []
    for line in METRICS_PATH.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = item.get("ts", "")
        try:
            epoch = datetime.fromisoformat(ts).timestamp()
        except Exception:
            continue
        if epoch >= cutoff:
            points.append(item)
    return points[-3000:]


def status_payload() -> Dict[str, Any]:
    state = read_json(STATE_PATH, {})
    checks = state.get("last_checks") or {}
    diagnosis = "Healthy"
    diagnosis_detail = "All monitored checks are passing."

    if state.get("unexpected_reboot_count", 0):
        diagnosis = "Unexpected reboot seen"
        diagnosis_detail = str(state.get("last_reboot_reason") or "A reboot was detected after startup.")
    if state.get("fault_active"):
        diagnosis = "Active fault"
        if not checks.get("app_ok", True):
            diagnosis_detail = "App process is missing."
        elif not checks.get("services_ok", True):
            bad = [item.get("service") for item in checks.get("services", []) if not item.get("ok")]
            diagnosis_detail = "Service issue: " + ", ".join(bad) if bad else "A monitored service is not active."
        elif not checks.get("lan_ok", True):
            bad = [f"{item.get('host')}:{item.get('port')}" for item in checks.get("ports", []) if not item.get("ok")]
            diagnosis_detail = "LAN target issue: " + ", ".join(bad) if bad else "A monitored TCP target failed."
        elif not checks.get("internet_ok", True):
            bad = [item.get("host") for item in checks.get("pings", []) if not item.get("ok")]
            diagnosis_detail = "WAN issue: " + ", ".join(bad) if bad else "A monitored internet host failed."

    next_steps: List[str] = []
    if state.get("fault_active"):
        next_steps.append("Check Latest checks first to see whether the app, a service, WAN, or the RUT target is currently failing.")
    elif state.get("unexpected_reboot_count", 0):
        next_steps.append("Review Recent events for the exact time the unexpected reboot was detected.")
        next_steps.append("Open the latest previous-boot snapshot to inspect journal and kernel messages from before the restart.")
    else:
        next_steps.append("Watch Recent events for the next change in state or reboot detection.")

    next_steps.append("Use PC stats to look for CPU, memory, or disk changes building before a reboot or hang.")
    next_steps.append("If it freezes overnight again, compare the last event time with the next boot's previous-boot snapshot.")

    return {
        "hostname": socket.gethostname(),
        "config": load_config(),
        "state": state,
        "build_info": read_json(BUILD_INFO_PATH, {}),
        "update_status": read_json(UPDATE_STATUS_PATH, {"state": "idle"}),
        "diagnosis": {"title": diagnosis, "detail": diagnosis_detail},
        "next_steps": next_steps,
        "recent_events": recent_events(),
        "paths": {
            "config": str(CONFIG_PATH),
            "state": str(STATE_PATH),
            "events": str(EVENTS_PATH),
            "metrics": str(METRICS_PATH),
            "build_info": str(BUILD_INFO_PATH),
            "update_status": str(UPDATE_STATUS_PATH),
            "update_log": str(UPDATE_LOG_PATH),
        },
    }


def launch_update() -> Dict[str, Any]:
    current = read_json(UPDATE_STATUS_PATH, {})
    if current.get("state") == "running":
        return {"ok": False, "message": "Update already running."}

    payload = {
        "state": "running",
        "started_at": now_iso(),
        "finished_at": "",
        "message": "Git update requested from web UI.",
        "log_path": str(UPDATE_LOG_PATH),
    }
    write_json(UPDATE_STATUS_PATH, payload)
    UPDATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    command = (
        "python3 - <<'PY'\n"
        "import json, subprocess\n"
        "from datetime import datetime\n"
        "from pathlib import Path\n"
        "status_path = Path('/var/lib/va-connect-site-watchdog/web-update-status.json')\n"
        "log_path = Path('/var/log/va-connect-site-watchdog/web-update.log')\n"
        "cmd = ['bash', '/usr/local/bin/watchdog-update']\n"
        "with log_path.open('ab') as log:\n"
        "    log.write((f'\\n===== Web update started {datetime.utcnow().replace(microsecond=0).isoformat()}+00:00 =====\\n').encode())\n"
        "    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)\n"
        "payload = json.loads(status_path.read_text(encoding='utf-8')) if status_path.exists() else {}\n"
        "payload['state'] = 'ok' if result.returncode == 0 else 'failed'\n"
        "payload['finished_at'] = datetime.utcnow().replace(microsecond=0).isoformat() + '+00:00'\n"
        "payload['return_code'] = result.returncode\n"
        "payload['message'] = 'Update completed successfully.' if result.returncode == 0 else 'Update failed. Check web-update.log.'\n"
        "status_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\\n', encoding='utf-8')\n"
        "PY"
    )
    subprocess.Popen(
        ["nohup", "bash", "-lc", command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {"ok": True, "message": "Update started.", "status": payload}


def authorized(path: str, headers) -> bool:
    token = str(load_config().get("web_token", "")).strip()
    if not token:
        return True
    parsed = urlparse(path)
    query_token = parse_qs(parsed.query).get("token", [""])[0]
    header_token = headers.get("X-Watchdog-Token", "")
    return query_token == token or header_token == token


def render_page(status: Dict[str, Any]) -> str:
    cfg = status["config"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VA-Connect Encoder Watchdog</title>
  <style>
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      font-size: 14px;
      line-height: 1.35;
      background: linear-gradient(180deg, #eff5ef 0%, #e5efe7 100%);
      color: #17301f;
    }}
    .wrap {{ max-width: 1600px; margin: 0 auto; padding: 18px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .overview-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 14px; }}
    .panel {{
      background: rgba(255,255,255,0.82);
      border: 1px solid #ccd9cf;
      border-radius: 18px;
      padding: 14px;
      box-shadow: 0 10px 28px rgba(24, 48, 31, 0.08);
    }}
    h1 {{ margin: 0 0 6px; font-size: 1.2rem; }}
    h2 {{ margin: 0 0 10px; font-size: 0.95rem; }}
    p {{ margin: 0 0 10px; }}
    .sub {{ color: #607064; margin-bottom: 14px; font-size: 0.9rem; }}
    .badge {{
      display: inline-block;
      padding: 5px 9px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      background: #e0f0e4;
      color: #246241;
    }}
    .danger {{ background: #f6e1e1; color: #a23d3d; }}
    .warn {{ background: #f4ead7; color: #9a6708; }}
    label {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid #dbe4dc;
    }}
    label:last-child {{ border-bottom: 0; }}
    button {{
      border: 0;
      border-radius: 12px;
      padding: 9px 12px;
      background: #285f83;
      color: white;
      font-weight: 700;
      cursor: pointer;
      margin-right: 8px;
      margin-top: 8px;
    }}
    button.secondary {{ background: #4c6d55; }}
    button.warnbtn {{ background: #956615; }}
    .targets, .events {{ display: grid; gap: 10px; }}
    .targets {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .item {{
      border: 1px solid #dbe4dc;
      border-radius: 14px;
      padding: 8px 10px;
      background: rgba(255,255,255,0.66);
      font-size: 0.83rem;
    }}
    .stat-card {{
      border: 1px solid #dbe4dc;
      border-radius: 16px;
      padding: 12px;
      background: rgba(255,255,255,0.78);
    }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(240px, 1.1fr) minmax(180px, 0.9fr);
      gap: 14px;
      margin-top: 14px;
    }}
    .hero-main {{
      border: 1px solid #ccd9cf;
      border-radius: 18px;
      padding: 14px;
      background: linear-gradient(135deg, rgba(40,95,131,0.1), rgba(76,109,85,0.08));
    }}
    .hero-title {{ font-size: 1.18rem; font-weight: 800; margin: 3px 0 8px; }}
    .hero-detail {{ font-size: 0.9rem; color: #415448; }}
    .status-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .stat-label {{ color: #607064; font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.03em; }}
    .stat-value {{ font-size: 1.25rem; font-weight: 700; margin-top: 4px; }}
    .formgrid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 10px;
      margin-top: 10px;
    }}
    .field {{
      display: grid;
      gap: 6px;
    }}
    .field label {{
      border: 0;
      padding: 0;
      display: block;
      font-weight: 600;
    }}
    input[type="text"], input[type="number"], textarea {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #c7d6ca;
      border-radius: 10px;
      padding: 8px 10px;
      font: inherit;
      background: #fff;
      color: #17301f;
    }}
    textarea {{ min-height: 84px; resize: vertical; }}
    .hint {{ color: #607064; font-size: 0.8rem; }}
    code {{ font-family: Consolas, monospace; font-size: 0.78rem; word-break: break-word; }}
    canvas {{
      width: 100%;
      height: 240px;
      border: 1px solid #dbe4dc;
      border-radius: 14px;
      background: rgba(255,255,255,0.72);
    }}
    .next-steps {{
      margin: 8px 0 0;
      padding-left: 18px;
      display: grid;
      gap: 8px;
      font-size: 0.88rem;
    }}
    .events .item code {{
      white-space: pre-wrap;
    }}
    .update-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-top: 10px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>VA-Connect Encoder Watchdog</h1>
    <div class="sub">Control page for <strong>{html.escape(status["hostname"])}</strong></div>
    <div class="hero">
      <section class="hero-main">
        <div class="stat-label">Current diagnosis</div>
        <div class="hero-title">{html.escape(status["diagnosis"]["title"])}</div>
        <div class="hero-detail">{html.escape(status["diagnosis"]["detail"])}</div>
        <div class="status-strip">
          <span class="badge {'danger' if status['state'].get('fault_active') else ''}">{'Fault active' if status['state'].get('fault_active') else 'Healthy now'}</span>
          <span class="badge {'warn' if status['state'].get('unexpected_reboot_count', 0) else ''}">Unexpected reboots: {int(status["state"].get("unexpected_reboot_count", 0))}</span>
          <span class="badge">Detected reboots: {int(status["state"].get("reboot_detections_count", 0))}</span>
          <span class="badge">Watchdog commands: {int(status["state"].get("reboot_commands_sent_count", 0))}</span>
        </div>
      </section>
      <section class="panel">
        <div class="stat-label">What to look at next</div>
        <ol class="next-steps" id="nextSteps">
          {"".join(f"<li>{html.escape(step)}</li>" for step in status.get("next_steps", []))}
        </ol>
      </section>
    </div>
    <div class="overview-grid">
      <section class="stat-card">
        <div class="stat-label">Current state</div>
        <div class="stat-value">{'Healthy' if not status['state'].get('fault_active') else 'Fault'}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Watchdog reboot commands</div>
        <div class="stat-value">{int(status["state"].get("reboot_commands_sent_count", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Detected reboots</div>
        <div class="stat-value">{int(status["state"].get("reboot_detections_count", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Unexpected reboots</div>
        <div class="stat-value">{int(status["state"].get("unexpected_reboot_count", 0))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Last reboot reason</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["state"].get("last_reboot_reason", "none")))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Last startup</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["state"].get("last_startup_at", "unknown")))}</div>
      </section>
      <section class="stat-card">
        <div class="stat-label">Build</div>
        <div class="stat-value" style="font-size:1rem;">{html.escape(str(status["build_info"].get("git_commit", "unknown")))}</div>
      </section>
    </div>
    <div class="grid">
      <section class="panel">
        <div class="badge {'danger' if status['state'].get('fault_active') else ''}">{'Fault Active' if status['state'].get('fault_active') else 'Healthy / Idle'}</div>
        <p>Monitoring state: <strong>{html.escape(str(status["state"].get("monitoring_state", "unknown")))}</strong></p>
        <p>Last check: <strong>{html.escape(str(status["state"].get("last_check_at", "never")))}</strong></p>
        <p>Last healthy: <strong>{html.escape(str(status["state"].get("last_healthy_at", "unknown")))}</strong></p>
        <p>Failure count: <strong>{html.escape(str(status["state"].get("failure_count", 0)))}</strong></p>
      </section>
      <section class="panel">
        <div class="badge">{html.escape(str(cfg["web_bind"]))}:{cfg["web_port"]}</div>
        <p>Base reboot timer: <strong>{cfg["base_reboot_timeout_seconds"]}s</strong></p>
        <p>Max reboot timer: <strong>{cfg["max_reboot_timeout_seconds"]}s</strong></p>
        <p>Deployed: <strong>{html.escape(str(status["build_info"].get("deployed_at", "unknown")))}</strong></p>
        <p>Config path: <code>{html.escape(status["paths"]["config"])}</code></p>
      </section>
    </div>

    <div class="grid" style="margin-top:16px;">
      <section class="panel">
        <h2>Controls</h2>
        <label>Monitoring enabled <input type="checkbox" id="monitoring_enabled" {'checked' if cfg['monitoring_enabled'] else ''}></label>
        <label>App auto-restart <input type="checkbox" id="app_restart_enabled" {'checked' if cfg['app_restart_enabled'] else ''}></label>
        <label>Network restart before reboot <input type="checkbox" id="restart_network_before_reboot" {'checked' if cfg['restart_network_before_reboot'] else ''}></label>
        <label>Reboot allowed <input type="checkbox" id="reboot_enabled" {'checked' if cfg['reboot_enabled'] else ''}></label>
        <button onclick="saveSettings()">Save settings</button>
        <button class="secondary" onclick="runAction('run_checks')">Run checks now</button>
        <button class="secondary" onclick="runAction('snapshot')">Capture snapshot</button>
        <button class="warnbtn" onclick="runAction('restart_network')">Restart network</button>
        <button class="secondary" onclick="runAction('update_watchdog')">Update from GitHub</button>
        <div class="update-row">
          <span class="badge {'warn' if status['update_status'].get('state') == 'running' else ('danger' if status['update_status'].get('state') == 'failed' else '')}" id="updateState">{html.escape(str(status["update_status"].get("state", "idle")).title())}</span>
          <span id="updateMessage">{html.escape(str(status["update_status"].get("message", "No web update run yet.")))}</span>
        </div>
      </section>
      <section class="panel">
        <h2>Latest checks</h2>
        <div class="targets" id="targets"></div>
      </section>
    </div>

    <div class="grid" style="margin-top:16px;">
      <section class="panel" style="grid-column: 1 / -1;">
        <h2>PC Stats - Last 24 Hours</h2>
        <canvas id="metricsChart" width="1000" height="280"></canvas>
        <p class="hint">CPU, memory, root disk, and recording disk usage are plotted as percentages.</p>
      </section>
    </div>

    <div class="grid" style="margin-top:16px; align-items:start;">
      <section class="panel" style="grid-column: span 2;">
        <h2>Config</h2>
        <div class="formgrid">
          <div class="field">
            <label for="app_match">App match</label>
            <input id="app_match" type="text" value="{html.escape(str(cfg.get("app_match", "")))}">
          </div>
          <div class="field">
            <label for="app_start_command">App start command</label>
            <input id="app_start_command" type="text" value="{html.escape(str(cfg.get("app_start_command", "")))}">
          </div>
          <div class="field">
            <label for="base_reboot_timeout_seconds">Base reboot timeout (s)</label>
            <input id="base_reboot_timeout_seconds" type="number" min="60" value="{int(cfg.get("base_reboot_timeout_seconds", 300))}">
          </div>
          <div class="field">
            <label for="max_reboot_timeout_seconds">Max reboot timeout (s)</label>
            <input id="max_reboot_timeout_seconds" type="number" min="60" value="{int(cfg.get("max_reboot_timeout_seconds", 3600))}">
          </div>
          <div class="field">
            <label for="reboot_backoff_multiplier">Backoff multiplier</label>
            <input id="reboot_backoff_multiplier" type="number" min="1" step="0.1" value="{html.escape(str(cfg.get("reboot_backoff_multiplier", 2.0)))}">
          </div>
          <div class="field">
            <label for="check_interval_seconds">Check interval (s)</label>
            <input id="check_interval_seconds" type="number" min="5" value="{int(cfg.get("check_interval_seconds", 30))}">
          </div>
          <div class="field">
            <label for="network_restart_cooldown_seconds">Network restart cooldown (s)</label>
            <input id="network_restart_cooldown_seconds" type="number" min="30" value="{int(cfg.get("network_restart_cooldown_seconds", 600))}">
          </div>
          <div class="field">
            <label for="post_action_settle_seconds">Post-action settle (s)</label>
            <input id="post_action_settle_seconds" type="number" min="5" value="{int(cfg.get("post_action_settle_seconds", 20))}">
          </div>
          <div class="field">
            <label for="web_bind">Web bind</label>
            <input id="web_bind" type="text" value="{html.escape(str(cfg.get("web_bind", "0.0.0.0")))}">
          </div>
          <div class="field">
            <label for="web_port">Web port</label>
            <input id="web_port" type="number" min="1" max="65535" value="{int(cfg.get("web_port", 8787))}">
          </div>
          <div class="field">
            <label for="web_token">Web token</label>
            <input id="web_token" type="text" value="{html.escape(str(cfg.get("web_token", "")))}">
          </div>
          <div class="field">
            <label for="network_restart_command">Network restart command</label>
            <input id="network_restart_command" type="text" value="{html.escape(str(cfg.get("network_restart_command", "")))}">
          </div>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="internet_hosts">Internet hosts, one per line</label>
          <textarea id="internet_hosts">{html.escape(chr(10).join(str(item) for item in cfg.get("internet_hosts", [])))}</textarea>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="systemd_services">Systemd services, one per line</label>
          <textarea id="systemd_services">{html.escape(chr(10).join(str(item) for item in cfg.get("systemd_services", [])))}</textarea>
        </div>
        <div class="field" style="margin-top:12px;">
          <label for="tcp_targets">TCP targets, one per line as host:port</label>
          <textarea id="tcp_targets">{html.escape(chr(10).join(f"{item.get('host','')}:{item.get('port','')}" for item in cfg.get("tcp_targets", [])))}</textarea>
        </div>
        <button onclick="saveConfig()">Save full config</button>
        <p class="hint">Use one internet host per line. Use one TCP target per line in the form <code>192.168.1.132:554</code>.</p>
      </section>
      <section class="panel" style="max-height: 760px; overflow: auto;">
        <h2>Recent events</h2>
        <div class="events" id="events"></div>
      </section>
      <section class="panel">
        <h2>Watchdog files</h2>
        <p><code>{html.escape(status["paths"]["state"])}</code></p>
        <p><code>{html.escape(status["paths"]["events"])}</code></p>
        <p><code>{html.escape(status["paths"].get("metrics", ""))}</code></p>
        <p><code>{html.escape(status["paths"].get("build_info", ""))}</code></p>
        <p><code>{html.escape(status["paths"].get("update_status", ""))}</code></p>
        <p><code>{html.escape(status["paths"].get("update_log", ""))}</code></p>
      </section>
    </div>
  </div>
  <script>
    const initialStatus = {json.dumps(status)};
    const authQuery = window.location.search || '';
    let latestMetrics = [];

    function badge(ok) {{
      return ok ? 'badge' : 'badge danger';
    }}

    function render(status) {{
      document.getElementById('monitoring_enabled').checked = !!status.config.monitoring_enabled;
      document.getElementById('app_restart_enabled').checked = !!status.config.app_restart_enabled;
      document.getElementById('restart_network_before_reboot').checked = !!status.config.restart_network_before_reboot;
      document.getElementById('reboot_enabled').checked = !!status.config.reboot_enabled;
      document.getElementById('app_match').value = status.config.app_match || '';
      document.getElementById('app_start_command').value = status.config.app_start_command || '';
      document.getElementById('base_reboot_timeout_seconds').value = status.config.base_reboot_timeout_seconds || 300;
      document.getElementById('max_reboot_timeout_seconds').value = status.config.max_reboot_timeout_seconds || 3600;
      document.getElementById('reboot_backoff_multiplier').value = status.config.reboot_backoff_multiplier || 2.0;
      document.getElementById('check_interval_seconds').value = status.config.check_interval_seconds || 30;
      document.getElementById('network_restart_cooldown_seconds').value = status.config.network_restart_cooldown_seconds || 600;
      document.getElementById('post_action_settle_seconds').value = status.config.post_action_settle_seconds || 20;
      document.getElementById('web_bind').value = status.config.web_bind || '0.0.0.0';
      document.getElementById('web_port').value = status.config.web_port || 8787;
      document.getElementById('web_token').value = status.config.web_token || '';
      document.getElementById('network_restart_command').value = status.config.network_restart_command || '';
      document.getElementById('internet_hosts').value = (status.config.internet_hosts || []).join('\\n');
      document.getElementById('systemd_services').value = (status.config.systemd_services || []).join('\\n');
      document.getElementById('tcp_targets').value = (status.config.tcp_targets || []).map((item) => `${{item.host}}:${{item.port}}`).join('\\n');
      const checks = status.state.last_checks || {{ pings: [], ports: [], app_ok: null }};
      document.getElementById('targets').innerHTML = [
        `<div class="item"><strong>App process</strong><br><span class="${{badge(!!checks.app_ok)}}">${{checks.app_ok ? 'Running' : 'Missing'}}</span></div>`,
        ...(checks.pings || []).map((item) => `<div class="item"><strong>WAN: ${{item.host}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`),
        ...(checks.services || []).map((item) => `<div class="item"><strong>Service: ${{item.service}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Active' : 'Not active'}}</span><br><code>${{item.detail || ''}}</code></div>`),
        ...(checks.ports || []).map((item) => `<div class="item"><strong>TCP: ${{item.host}}:${{item.port}}</strong><br><span class="${{badge(!!item.ok)}}">${{item.ok ? 'Reachable' : 'Failed'}}</span><br><code>${{item.detail || ''}}</code></div>`)
      ].join('');

      document.getElementById('events').innerHTML = (status.recent_events || []).map((event) => (
        `<div class="item"><strong>${{event.event}}</strong><br><code>${{JSON.stringify(event)}}</code></div>`
      )).join('');
      document.getElementById('nextSteps').innerHTML = (status.next_steps || []).map((step) => `<li>${{step}}</li>`).join('');
      const updateState = status.update_status || {{}};
      const updateBadge = document.getElementById('updateState');
      updateBadge.className = `badge ${{updateState.state === 'running' ? 'warn' : (updateState.state === 'failed' ? 'danger' : '')}}`;
      updateBadge.textContent = (updateState.state || 'idle').toUpperCase();
      document.getElementById('updateMessage').textContent = updateState.message || 'No web update run yet.';

      document.querySelector('.overview-grid').innerHTML = `
        <section class="stat-card"><div class="stat-label">Current state</div><div class="stat-value">${{status.state.fault_active ? 'Fault' : 'Healthy'}}</div></section>
        <section class="stat-card"><div class="stat-label">Watchdog reboot commands</div><div class="stat-value">${{status.state.reboot_commands_sent_count || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Detected reboots</div><div class="stat-value">${{status.state.reboot_detections_count || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Unexpected reboots</div><div class="stat-value">${{status.state.unexpected_reboot_count || 0}}</div></section>
        <section class="stat-card"><div class="stat-label">Last reboot reason</div><div class="stat-value" style="font-size:1rem;">${{status.state.last_reboot_reason || 'none'}}</div></section>
        <section class="stat-card"><div class="stat-label">Last startup</div><div class="stat-value" style="font-size:1rem;">${{status.state.last_startup_at || 'unknown'}}</div></section>
        <section class="stat-card"><div class="stat-label">Build</div><div class="stat-value" style="font-size:1rem;">${{(status.build_info && status.build_info.git_commit) || 'unknown'}}</div></section>
      `;

      const heroMain = document.querySelector('.hero-main');
      heroMain.innerHTML = `
        <div class="stat-label">Current diagnosis</div>
        <div class="hero-title">${{status.diagnosis.title}}</div>
        <div class="hero-detail">${{status.diagnosis.detail}}</div>
        <div class="status-strip">
          <span class="badge ${{status.state.fault_active ? 'danger' : ''}}">${{status.state.fault_active ? 'Fault active' : 'Healthy now'}}</span>
          <span class="badge ${{status.state.unexpected_reboot_count ? 'warn' : ''}}">Unexpected reboots: ${{status.state.unexpected_reboot_count || 0}}</span>
          <span class="badge">Detected reboots: ${{status.state.reboot_detections_count || 0}}</span>
          <span class="badge">Watchdog commands: ${{status.state.reboot_commands_sent_count || 0}}</span>
        </div>
      `;
    }}

    function drawMetrics(points) {{
      const canvas = document.getElementById('metricsChart');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const pad = 40;
      const chartWidth = canvas.width - pad * 2;
      const chartHeight = canvas.height - pad * 2;

      ctx.strokeStyle = '#d0ddd3';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i += 1) {{
        const y = pad + (chartHeight / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(pad + chartWidth, y);
        ctx.stroke();
      }}

      ctx.fillStyle = '#607064';
      ctx.font = '12px Segoe UI';
      for (let i = 0; i <= 4; i += 1) {{
        const value = 100 - (25 * i);
        const y = pad + (chartHeight / 4) * i + 4;
        ctx.fillText(`${{value}}%`, 6, y);
      }}

      if (!points.length) {{
        ctx.fillStyle = '#607064';
        ctx.font = '16px Segoe UI';
        ctx.fillText('No metrics collected yet.', pad, canvas.height / 2);
        return;
      }}

      const series = [
        {{ key: 'cpu_percent', color: '#285f83', label: 'CPU' }},
        {{ key: 'mem_percent', color: '#ad3d3d', label: 'Memory' }},
        {{ key: 'root_disk_percent', color: '#4c6d55', label: 'Root disk' }},
        {{ key: 'recording_disk_percent', color: '#956615', label: 'Recording disk' }}
      ];

      const maxIndex = Math.max(1, points.length - 1);
      const xFor = (index) => pad + (chartWidth * index / maxIndex);
      const yFor = (value) => pad + chartHeight - ((Math.max(0, Math.min(100, Number(value || 0))) / 100) * chartHeight);

      series.forEach((line, idx) => {{
        ctx.strokeStyle = line.color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        let started = false;
        points.forEach((point, index) => {{
          const value = point[line.key];
          if (value === null || value === undefined || Number.isNaN(Number(value))) {{
            return;
          }}
          const x = xFor(index);
          const y = yFor(value);
          if (!started) {{
            ctx.moveTo(x, y);
            started = true;
          }} else {{
            ctx.lineTo(x, y);
          }}
        }});
        ctx.stroke();
        ctx.fillStyle = line.color;
        ctx.fillRect(pad + idx * 140, 10, 12, 12);
        ctx.fillStyle = '#17301f';
        ctx.fillText(line.label, pad + idx * 140 + 18, 20);
      }});
    }}

    async function fetchStatus() {{
      const response = await fetch('/api/status' + authQuery);
      render(await response.json());
    }}

    async function fetchMetrics() {{
      const response = await fetch('/api/metrics' + authQuery);
      const payload = await response.json();
      latestMetrics = payload.points || [];
      drawMetrics(latestMetrics);
    }}

    async function saveSettings() {{
      await fetch('/api/config' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          monitoring_enabled: document.getElementById('monitoring_enabled').checked,
          app_restart_enabled: document.getElementById('app_restart_enabled').checked,
          restart_network_before_reboot: document.getElementById('restart_network_before_reboot').checked,
          reboot_enabled: document.getElementById('reboot_enabled').checked
        }})
      }});
      await fetchStatus();
    }}

    function parseLines(id) {{
      return document.getElementById(id).value
        .split('\\n')
        .map((line) => line.trim())
        .filter(Boolean);
    }}

    function parseTcpTargets() {{
      return parseLines('tcp_targets')
        .map((line) => {{
          const lastColon = line.lastIndexOf(':');
          if (lastColon <= 0 || lastColon === line.length - 1) {{
            throw new Error(`Invalid TCP target: ${{line}}`);
          }}
          const host = line.slice(0, lastColon).trim();
          const port = Number(line.slice(lastColon + 1).trim());
          if (!host || !Number.isFinite(port) || port < 1 || port > 65535) {{
            throw new Error(`Invalid TCP target: ${{line}}`);
          }}
          return {{ host, port }};
        }});
    }}

    async function saveConfig() {{
      const payload = {{
        monitoring_enabled: document.getElementById('monitoring_enabled').checked,
        app_restart_enabled: document.getElementById('app_restart_enabled').checked,
        restart_network_before_reboot: document.getElementById('restart_network_before_reboot').checked,
        reboot_enabled: document.getElementById('reboot_enabled').checked,
        app_match: document.getElementById('app_match').value.trim(),
        app_start_command: document.getElementById('app_start_command').value.trim(),
        base_reboot_timeout_seconds: Number(document.getElementById('base_reboot_timeout_seconds').value || 300),
        max_reboot_timeout_seconds: Number(document.getElementById('max_reboot_timeout_seconds').value || 3600),
        reboot_backoff_multiplier: Number(document.getElementById('reboot_backoff_multiplier').value || 2.0),
        check_interval_seconds: Number(document.getElementById('check_interval_seconds').value || 30),
        network_restart_cooldown_seconds: Number(document.getElementById('network_restart_cooldown_seconds').value || 600),
        post_action_settle_seconds: Number(document.getElementById('post_action_settle_seconds').value || 20),
        web_bind: document.getElementById('web_bind').value.trim(),
        web_port: Number(document.getElementById('web_port').value || 8787),
        web_token: document.getElementById('web_token').value.trim(),
        network_restart_command: document.getElementById('network_restart_command').value.trim(),
        internet_hosts: parseLines('internet_hosts'),
        systemd_services: parseLines('systemd_services'),
        tcp_targets: parseTcpTargets()
      }};
      await fetch('/api/config' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      await fetchStatus();
    }}

    async function runAction(action) {{
      const response = await fetch('/api/action' + authQuery, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ action }})
      }});
      if (!response.ok) {{
        const payload = await response.json().catch(() => ({{ message: 'Action failed.' }}));
        alert(payload.message || 'Action failed.');
        return;
      }}
      await fetchStatus();
    }}

    render(initialStatus);
    fetchMetrics();
    setInterval(fetchStatus, 15000);
    setInterval(fetchMetrics, 60000);
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not authorized(self.path, self.headers):
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self._send_json(status_payload())
            return
        if parsed.path == "/api/metrics":
            self._send_json({"points": recent_metrics()})
            return
        if parsed.path in {"/", "/index.html"}:
            body = render_page(status_payload()).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not authorized(self.path, self.headers):
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/config":
            config = load_config()
            data = self._read_json()
            config.update(sanitize_patch(data))
            write_json(CONFIG_PATH, config)
            self._send_json({"ok": True, "config": config})
            return

        if parsed.path == "/api/action":
            data = self._read_json()
            action = str(data.get("action", "")).strip()
            action_map = {
                "run_checks": Path("/var/lib/va-connect-site-watchdog/manual-run-checks"),
                "snapshot": Path("/var/lib/va-connect-site-watchdog/manual-snapshot"),
                "restart_network": Path("/var/lib/va-connect-site-watchdog/manual-restart-network"),
            }
            if action == "update_watchdog":
                result = launch_update()
                self._send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT)
                return
            marker = action_map.get(action)
            if not marker:
                self._send_json({"ok": False, "message": f"Unknown action: {action}"}, HTTPStatus.BAD_REQUEST)
                return
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
            self._send_json({"ok": True, "action": action})
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, _format: str, *_args) -> None:
        return


def main() -> int:
    config = load_config()
    server = ThreadingHTTPServer((str(config["web_bind"]), int(config["web_port"])), Handler)
    print(f"VA-Connect watchdog web UI listening on {config['web_bind']}:{config['web_port']}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
