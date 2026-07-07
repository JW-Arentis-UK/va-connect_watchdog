from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from .update import launch_update_job, load_update_status

HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VA-Connect Watchdog V3</title>
<style>
:root {
  --bg: #080b0f;
  --panel: #11161d;
  --panel-2: #151b23;
  --line: #28313d;
  --text: #edf2f7;
  --muted: #9aa6b2;
  --green: #36d15f;
  --amber: #ffbf3c;
  --orange: #ff8a34;
  --red: #ff4f64;
  --blue: #3b82f6;
  --scale: .75;
}
* { box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: var(--bg); color: var(--text); margin:0; font-size:calc(14px * var(--scale)); }
.shell { display:grid; grid-template-columns: calc(220px * var(--scale)) 1fr; min-height:100vh; }
.sidebar { border-right:1px solid var(--line); background:#05080c; padding:calc(18px * var(--scale)) calc(14px * var(--scale)); display:flex; flex-direction:column; gap:calc(18px * var(--scale)); }
.brand { font-size:calc(18px * var(--scale)); font-weight:700; line-height:1.25; }
.nav { display:grid; gap:calc(6px * var(--scale)); }
.nav button { width:100%; text-align:left; background:transparent; color:var(--muted); border:1px solid transparent; border-radius:6px; padding:calc(10px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-size:inherit; }
.nav button.active { color:var(--text); background:#0f2d59; border-color:#235a9e; }
.side-status { margin-top:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:calc(12px * var(--scale)); color:var(--muted); }
.main { min-width:0; }
.topbar { height:calc(58px * var(--scale)); border-bottom:1px solid var(--line); display:flex; align-items:center; justify-content:space-between; padding:0 calc(18px * var(--scale)); color:var(--muted); }
.content { padding:calc(18px * var(--scale)); max-width:calc(1360px * var(--scale)); margin:0 auto; }
.grid { display:grid; gap:calc(12px * var(--scale)); }
.top-grid { grid-template-columns: minmax(0, 1.6fr) minmax(300px, 0.9fr); }
.metric-grid { grid-template-columns: repeat(6, minmax(calc(130px * var(--scale)), 1fr)); }
.lower-grid { grid-template-columns: minmax(0, 1.1fr) minmax(330px, 0.9fr); }
.bottom-grid { grid-template-columns: minmax(300px, 0.8fr) minmax(0, 1.2fr); }
.card, .tile { background:linear-gradient(145deg, var(--panel), var(--panel-2)); border:1px solid var(--line); border-radius:8px; padding:calc(14px * var(--scale)); min-width:0; }
.card h2, .card h3, .tile h3 { margin:0 0 calc(10px * var(--scale)); font-size:calc(16px * var(--scale)); }
.summary-card { display:grid; grid-template-columns: calc(130px * var(--scale)) 1fr 1fr; gap:calc(18px * var(--scale)); align-items:center; }
.score { font-size:calc(38px * var(--scale)); font-weight:800; margin:calc(6px * var(--scale)) 0; }
.status-word { font-size:calc(22px * var(--scale)); font-weight:800; }
.healthy { color:var(--green); }
.warning { color:var(--amber); }
.degraded { color:var(--orange); }
.critical { color:var(--red); }
.unknown, .disabled, .idle { color:var(--muted); }
.pill { display:inline-block; border-radius:999px; padding:calc(4px * var(--scale)) calc(8px * var(--scale)); background:#0d2b17; color:var(--green); font-size:calc(12px * var(--scale)); font-weight:700; }
.label { color:var(--muted); font-size:calc(12px * var(--scale)); margin-top:calc(8px * var(--scale)); }
.value { font-weight:700; overflow-wrap:anywhere; }
.tile-value { font-size:calc(24px * var(--scale)); font-weight:800; margin:calc(8px * var(--scale)) 0 calc(4px * var(--scale)); }
.tile-detail { color:var(--green); font-size:calc(13px * var(--scale)); overflow-wrap:anywhere; }
table { width:100%; border-collapse:collapse; }
th, td { padding:calc(9px * var(--scale)) calc(6px * var(--scale)); border-top:1px solid var(--line); text-align:left; white-space:nowrap; }
th { color:var(--muted); font-weight:600; font-size:calc(12px * var(--scale)); }
.events { display:grid; gap:calc(8px * var(--scale)); }
.event { display:grid; grid-template-columns: calc(82px * var(--scale)) 1fr; gap:calc(8px * var(--scale)); border-top:1px solid var(--line); padding-top:calc(8px * var(--scale)); }
.event-time { color:var(--muted); font-size:calc(12px * var(--scale)); }
.donut { width:calc(140px * var(--scale)); height:calc(140px * var(--scale)); border-radius:50%; display:grid; place-items:center; margin:calc(4px * var(--scale)) auto; background:conic-gradient(var(--green) calc(var(--score) * 1%), #26313d 0); }
.donut span { width:calc(86px * var(--scale)); height:calc(86px * var(--scale)); display:grid; place-items:center; border-radius:50%; background:var(--panel); font-size:calc(26px * var(--scale)); font-weight:800; }
.breakdown-row { display:flex; justify-content:space-between; gap:calc(12px * var(--scale)); margin:calc(8px * var(--scale)) 0; color:var(--muted); }
.history-box { height:calc(160px * var(--scale)); border:1px solid var(--line); border-radius:6px; background:linear-gradient(180deg, rgba(54,209,95,.18), rgba(54,209,95,.04)); display:flex; align-items:center; justify-content:center; color:var(--muted); }
pre { white-space:pre-wrap; overflow:auto; max-height:calc(540px * var(--scale)); background:#05080c; border:1px solid var(--line); border-radius:6px; padding:calc(12px * var(--scale)); }
.button-row { display:flex; gap:calc(8px * var(--scale)); flex-wrap:wrap; align-items:center; margin:calc(10px * var(--scale)) 0; }
button.action { background:var(--blue); color:#fff; border:0; border-radius:6px; padding:calc(9px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-weight:700; font-size:inherit; }
button.action:disabled { opacity:.5; cursor:not-allowed; }
.page { display:none; }
.page.active { display:block; }
@media (max-width: 1100px) {
  .shell { grid-template-columns: calc(180px * var(--scale)) 1fr; }
  .metric-grid { grid-template-columns: repeat(3, minmax(calc(130px * var(--scale)), 1fr)); }
  .top-grid, .lower-grid, .bottom-grid { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar { position:static; }
  .metric-grid { grid-template-columns: repeat(2, minmax(calc(130px * var(--scale)), 1fr)); }
  .summary-card { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand">VA-Connect<br>Watchdog V3</div>
    <nav class="nav" id="nav"></nav>
    <div class="side-status">
      <div>Watchdog</div>
      <div id="side-state" class="value">Loading</div>
      <div class="label">Version</div>
      <div class="value">V3</div>
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div id="page-title">Overview</div>
      <div id="last-update">Last update: -</div>
    </header>
    <section class="content" id="app">Loading...</section>
  </main>
</div>
<script>
const PAGES = ['Overview','Hardware','Services','Storage','Network','Recovery','Events','History','Settings','Updates','Diagnostics'];
let currentPage = 'Overview';
let lastStatus = null;
let lastUpdateStatus = null;
let lastEvents = [];
let lastConfigSummary = {};

function escapeHtml(value){
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function findCheck(status, name){
  return (status.checks || []).find(c => c.name === name) || {};
}

function statusClass(state){
  const value = String(state || 'unknown').toLowerCase();
  return ['healthy','warning','degraded','critical'].includes(value) ? value : 'unknown';
}

function displayState(status){
  const critical = !!status.critical_failed;
  const degraded = (status.checks || []).some(c => c.state === 'degraded');
  const warnings = (status.checks || []).some(c => c.state === 'warning' || c.state === 'unknown');
  if (critical) return 'critical';
  if (degraded) return 'degraded';
  if (warnings) return 'healthy';
  return 'healthy';
}

function displayWord(status){
  return displayState(status).toUpperCase();
}

function fmtPercent(value){
  if (value === null || value === undefined || value === '') return '-';
  return `${value} %`;
}

function fmtValue(value, suffix=''){
  if (value === null || value === undefined || value === '') return '-';
  return `${value}${suffix}`;
}

function fmtTime(value){
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString();
}

function buildNav(){
  const nav = document.getElementById('nav');
  nav.innerHTML = PAGES.map(page => `<button class="${page === currentPage ? 'active' : ''}" onclick="showPage('${page}')">${escapeHtml(page)}</button>`).join('');
}

function showPage(page){
  currentPage = page;
  buildNav();
  render();
}

function groupChecks(checks){
  const groups = {
    hardware: [],
    services: [],
    storage: [],
    recovery: [],
    system: [],
  };
  for (const check of checks || []) {
    const name = String(check.name || '');
    if (name === 'temperature' || name === 'ram' || name === 'cpu_load' || name === 'hardware_watchdog_present') {
      groups.hardware.push(check);
    } else if (name.endsWith('.service')) {
      groups.services.push(check);
    } else if (name === 'root_disk' || name === 'recordings_disk' || name === 'write_test') {
      groups.storage.push(check);
    } else if (name === 'network_module') {
      groups.system.push(check);
    } else {
      groups.system.push(check);
    }
  }
  return groups;
}

function tile(title, check, value, detail){
  const state = statusClass(check.state);
  return `<div class="tile"><h3>${escapeHtml(title)}</h3><div class="tile-value ${state}">${escapeHtml(value)}</div><div class="tile-detail">${escapeHtml(detail || check.message || '')}</div></div>`;
}

function serviceRows(status){
  const services = (status.checks || []).filter(c => String(c.name || '').endsWith('.service'));
  return services.map(c => {
    const value = c.value || {};
    return `<tr><td>${escapeHtml(c.name)}</td><td><span class="pill">${escapeHtml((value.active || c.state || '-').toUpperCase())}</span></td><td>-</td><td>-</td><td>${escapeHtml(value.restarts ?? '-')}</td><td>-</td></tr>`;
  }).join('');
}

function renderEvents(events, limit=8){
  const rows = (events || []).slice(0, limit);
  if (!rows.length) return '<div class="event"><div class="event-time">-</div><div>No events yet</div></div>';
  return rows.map(event => `<div class="event"><div class="event-time">${escapeHtml(fmtTime(event.time))}</div><div><span class="${statusClass(event.level)}">${escapeHtml((event.level || 'info').toUpperCase())}</span> ${escapeHtml(event.message || '')}</div></div>`).join('');
}

function renderGatewaySummary(status){
  const state = displayState(status);
  const recovery = status.recovery || {};
  return `<div class="card summary-card"><div><div class="status-word ${state}">${displayWord(status)}</div><div class="score">${escapeHtml(status.score ?? '-')}%</div><span class="pill">${status.critical_failed ? 'Critical issue' : 'No critical issues'}</span></div><div><div class="label">Gateway Name</div><div class="value">POC-451VTC</div><div class="label">Branch</div><div class="value">${escapeHtml(lastUpdateStatus?.branch || 'codex/v3-gateway-ready')}</div><div class="label">Last Status</div><div class="value">${escapeHtml(status.time || '-')}</div></div><div><div class="label">Recovery Status</div><div class="value ${escapeHtml(recovery.state || 'unknown')}">${escapeHtml((recovery.state || 'unknown').toUpperCase())}</div><div class="label">Watchdog Feed</div><div class="value">${status.hardware_watchdog_feed?.enabled ? 'Enabled' : 'Disabled'}</div></div></div>`;
}

function renderBreakdown(status){
  const grouped = groupChecks(status.checks || []);
  const score = Number(status.score || 0);
  const sectionScore = checks => checks.length ? Math.max(0, 100 - checks.filter(c => c.state !== 'healthy').length * 5) : null;
  const rows = [
    ['Hardware', sectionScore(grouped.hardware)],
    ['Services', sectionScore(grouped.services)],
    ['Storage', sectionScore(grouped.storage)],
    ['Network', sectionScore(grouped.system)],
    ['Recovery', status.recovery ? (status.recovery.state === 'disabled' ? null : 100) : null],
  ];
  return `<div class="card"><h2>Health Breakdown</h2><div class="donut" style="--score:${score}"><span>${escapeHtml(score)}%</span></div>${rows.map(([name, value]) => `<div class="breakdown-row"><span>${escapeHtml(name)}</span><strong>${value === null ? 'N/A' : `${value}%`}</strong></div>`).join('')}</div>`;
}

function renderMetricTiles(status){
  const temp = findCheck(status, 'temperature');
  const cpu = findCheck(status, 'cpu_load');
  const ram = findCheck(status, 'ram');
  const root = findCheck(status, 'root_disk');
  const rec = findCheck(status, 'recordings_disk');
  const wdt = findCheck(status, 'hardware_watchdog_present');
  const wdtFeed = status.hardware_watchdog_feed || {};
  const wdtConfig = lastConfigSummary.hardware_watchdog || {};
  const wdtDetails = [
    wdtFeed.enabled ? 'Enabled' : 'Disabled',
    wdtConfig.timeout_seconds ? `${wdtConfig.timeout_seconds}s timeout` : 'Timeout unknown',
    wdtFeed.enabled && wdtFeed.last_feed_unix ? `Last feed ${wdtFeed.last_feed_unix}` : '',
  ].filter(Boolean).join(' | ');
  return `<div class="grid metric-grid">${tile('CPU Temp', temp, fmtValue(temp.value, ' C'), temp.message)}${tile('CPU Load', cpu, fmtPercent(cpu.value), cpu.message)}${tile('RAM', ram, fmtPercent(ram.value), ram.message)}${tile('Root Disk', root, fmtPercent(root.value?.used_percent), `${root.value?.free_gb ?? '-'} GB free`)}${tile('Recordings Disk', rec, fmtPercent(rec.value?.used_percent), `${rec.value?.free_gb ?? '-'} GB free`)}${tile('Hardware WDT', wdt, wdt.value ? 'Present' : 'Not present', wdtDetails)}</div>`;
}

function renderServices(status){
  return `<div class="card"><h2>Services</h2><table><thead><tr><th>Service</th><th>Status</th><th>CPU</th><th>Memory</th><th>Restarts</th><th>Uptime</th></tr></thead><tbody>${serviceRows(status)}</tbody></table></div>`;
}

function renderSystemInfo(status){
  return `<div class="card"><h2>System Information</h2><div class="label">Status Time</div><div class="value">${escapeHtml(status.time || '-')}</div><div class="label">Critical Failed</div><div class="value">${escapeHtml(status.critical_failed)}</div><div class="label">Checks</div><div class="value">${escapeHtml((status.checks || []).length)}</div></div>`;
}

function renderOverview(status, events){
  return `<div class="grid top-grid">${renderGatewaySummary(status)}${renderBreakdown(status)}</div>${renderMetricTiles(status)}<div class="grid lower-grid">${renderServices(status)}<div class="card"><h2>Recent Events</h2><div class="events">${renderEvents(events, 8)}</div></div></div><div class="grid bottom-grid">${renderSystemInfo(status)}<div class="card"><h2>Health History</h2><div class="history-box">Health history placeholder</div></div></div>`;
}

function renderSimplePage(title, content){
  return `<div class="card"><h2>${escapeHtml(title)}</h2>${content}</div>`;
}

function renderPage(status, updateStatus, events){
  const grouped = groupChecks(status.checks || []);
  if (currentPage === 'Overview') return renderOverview(status, events);
  if (currentPage === 'Hardware') return `<div class="grid metric-grid">${grouped.hardware.map(c => tile(c.name, c, c.value === true ? 'Present' : fmtValue(c.value), c.message)).join('')}</div>`;
  if (currentPage === 'Services') return renderServices(status);
  if (currentPage === 'Storage') return `<div class="grid metric-grid">${grouped.storage.map(c => tile(c.name, c, c.value?.used_percent !== undefined ? fmtPercent(c.value.used_percent) : fmtValue(c.value), c.message)).join('')}</div>`;
  if (currentPage === 'Network') return renderSimplePage('Network', grouped.system.map(c => `<p><strong>${escapeHtml(c.name)}</strong>: ${escapeHtml(c.message)}</p>`).join(''));
  if (currentPage === 'Recovery') return renderSimplePage('Recovery', `<p class="${escapeHtml(status.recovery?.state || 'unknown')}">${escapeHtml((status.recovery?.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(status.recovery?.message || 'No recovery state available.')}</p>`);
  if (currentPage === 'Events') return renderSimplePage('Events', `<div class="events">${renderEvents(events, 20)}</div>`);
  if (currentPage === 'History') return renderSimplePage('History', '<div class="history-box">Health history placeholder</div>');
  if (currentPage === 'Settings') return renderSimplePage('Settings', '<p>Settings view placeholder.</p>');
  if (currentPage === 'Updates') return renderSimplePage('Updates', `<p class="${statusClass(updateStatus.state)}">${escapeHtml((updateStatus.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(updateStatus.message || '')}</p><div class="button-row"><button class="action" id="update-button" onclick="triggerUpdate()">Update watchdog now</button></div><p id="update-feedback"></p>`);
  if (currentPage === 'Diagnostics') return renderSimplePage('Diagnostics', `<h3>Raw status</h3><pre>${escapeHtml(JSON.stringify(status, null, 2))}</pre><h3>Update status</h3><pre>${escapeHtml(JSON.stringify(updateStatus, null, 2))}</pre>`);
  return renderOverview(status, events);
}

async function load(){
  const [statusResponse, updateResponse, eventsResponse, configResponse] = await Promise.all([
    fetch('/api/status'),
    fetch('/api/update-status'),
    fetch('/api/events'),
    fetch('/api/config-summary'),
  ]);
  lastStatus = await statusResponse.json();
  lastUpdateStatus = await updateResponse.json();
  lastEvents = await eventsResponse.json();
  lastConfigSummary = await configResponse.json();
  render();
}

function render(){
  if (!lastStatus) return;
  document.getElementById('page-title').textContent = currentPage;
  document.getElementById('last-update').textContent = `Last update: ${fmtTime(lastStatus.time)}`;
  document.getElementById('side-state').textContent = displayWord(lastStatus);
  document.getElementById('side-state').className = `value ${displayState(lastStatus)}`;
  document.getElementById('app').innerHTML = renderPage(lastStatus, lastUpdateStatus || {}, lastEvents || []);
}

async function triggerUpdate(){
  const button = document.getElementById('update-button');
  const feedback = document.getElementById('update-feedback');
  if (!button || !feedback) return;
  if (!confirm('Start a watchdog update now? The service will restart when the update finishes.')) {
    return;
  }
  button.disabled = true;
  feedback.textContent = 'Starting update...';
  try {
    const response = await fetch('/api/update', { method: 'POST' });
    const payload = await response.json();
    feedback.textContent = payload.message || 'Update request sent.';
  } catch (error) {
    feedback.textContent = `Update failed: ${error}`;
  } finally {
    button.disabled = false;
    setTimeout(load, 3000);
  }
}
buildNav();
load();
setInterval(load, 5000);
</script>
</body>
</html>
"""

def start_web(cfg):
    web_cfg = cfg["web"]
    if not web_cfg.get("enabled", True):
        return None

    status_path = Path(cfg["status_path"])
    events_path = Path(cfg["events_path"])

    def recent_events(limit=10):
        if not events_path.exists():
            return []
        events = []
        for line in events_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]:
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                events.append(payload)
        return list(reversed(events))[:limit]

    def config_summary():
        hardware = cfg.get("hardware_watchdog", {})
        return {
            "hardware_watchdog": {
                "enabled": bool(hardware.get("enabled", False)),
                "device": str(hardware.get("device", "")),
                "timeout_seconds": hardware.get("feed_interval_seconds"),
            }
        }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send_json(self, payload, status=200):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(HTML.encode("utf-8"))
                return
            if self.path == "/api/status":
                try:
                    body = status_path.read_text(encoding="utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body.encode("utf-8"))))
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                except Exception as e:
                    self._send_json({"error": str(e)}, status=503)
                return
            if self.path == "/api/update-status":
                self._send_json(load_update_status(cfg))
                return
            if self.path == "/api/events":
                self._send_json(recent_events())
                return
            if self.path == "/api/config-summary":
                self._send_json(config_summary())
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path == "/api/update":
                result = launch_update_job(cfg)
                status = 200 if result.get("ok") else 500
                self._send_json(result, status=status)
                return
            self._send_json({"error": "not found"}, status=404)

    server = ThreadingHTTPServer((web_cfg["host"], int(web_cfg["port"])), Handler)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
