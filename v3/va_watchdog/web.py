from __future__ import annotations

import json
import platform
import subprocess
import time
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
.topbar-right { display:flex; gap:10px; align-items:center; }
select { background:#05080c; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:5px 8px; font-size:inherit; }
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
button.ghost { background:transparent; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:calc(7px * var(--scale)) calc(10px * var(--scale)); cursor:pointer; font-size:inherit; }
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
      <div class="topbar-right">
        <label>Refresh <select id="refresh-select" onchange="setRefreshInterval(this.value)"><option value="5000">5s</option><option value="15000">15s</option><option value="30000">30s</option><option value="60000">60s</option><option value="0">Manual</option></select></label>
        <button class="ghost" onclick="load()">Refresh now</button>
        <div id="last-update">Last update: -</div>
      </div>
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
let lastSystemInfo = {};
let lastNetworkInfo = {};
let lastSettings = {};
let lastRetention = {};
let refreshTimer = null;

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

function setRefreshInterval(value){
  localStorage.setItem('va_watchdog_refresh_ms', String(value));
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  const ms = Number(value);
  if (ms > 0) {
    refreshTimer = setInterval(load, ms);
  }
}

function initRefresh(){
  const saved = localStorage.getItem('va_watchdog_refresh_ms') || '5000';
  const select = document.getElementById('refresh-select');
  select.value = saved;
  setRefreshInterval(saved);
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
  const rtc = lastSystemInfo.rtc || {};
  return `<div class="card"><h2>System Information</h2><div class="label">Hostname</div><div class="value">${escapeHtml(lastSystemInfo.hostname || '-')}</div><div class="label">OS</div><div class="value">${escapeHtml(lastSystemInfo.os || '-')}</div><div class="label">Kernel</div><div class="value">${escapeHtml(lastSystemInfo.kernel || '-')}</div><div class="label">Uptime</div><div class="value">${escapeHtml(lastSystemInfo.uptime_seconds ? `${Math.round(lastSystemInfo.uptime_seconds)}s` : '-')}</div><div class="label">BIOS/RTC Clock</div><div class="value ${rtc.rtc0_present ? 'healthy' : 'warning'}">${rtc.rtc0_present ? 'RTC present' : 'RTC not confirmed'}</div></div>`;
}

function renderOverview(status, events){
  return `<div class="grid top-grid">${renderGatewaySummary(status)}${renderBreakdown(status)}</div>${renderMetricTiles(status)}<div class="grid lower-grid">${renderServices(status)}<div class="card"><h2>Recent Events</h2><div class="events">${renderEvents(events, 8)}</div></div></div><div class="grid bottom-grid">${renderSystemInfo(status)}<div class="card"><h2>Health History</h2><div class="history-box">Health history placeholder</div></div></div>`;
}

function renderSimplePage(title, content){
  return `<div class="card"><h2>${escapeHtml(title)}</h2>${content}</div>`;
}

function placeholderList(items){
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

function renderSettingsPage(){
  return renderSimplePage('Settings', `<p>Editable config will live here. Current settings summary:</p><pre>${escapeHtml(JSON.stringify(lastSettings, null, 2))}</pre>${placeholderList(['Poll interval editor','Storage warning and critical limits','Network targets','Recovery policy','Update branch and remote','Retention and max watchdog storage budget'])}`);
}

function renderRetentionPage(){
  return `<div class="card"><h2>Watchdog Data Storage</h2><p>Used ${escapeHtml(lastRetention.used_mb ?? '-')} MB of ${escapeHtml(lastRetention.max_total_mb ?? '-')} MB (${escapeHtml(lastRetention.used_percent ?? '-')}%).</p><div class="button-row"><button class="action" onclick="purgeOldData()">Purge old data</button><button class="ghost" onclick="purgeAllData()">Purge all non-status data</button></div><pre>${escapeHtml(JSON.stringify(lastRetention, null, 2))}</pre></div>`;
}

function renderNetworkPage(){
  return renderSimplePage('Network', `<div class="label">IP Addresses</div><div class="value">${escapeHtml(lastNetworkInfo.ip_addresses || '-')}</div><div class="label">Default Route</div><div class="value">${escapeHtml(lastNetworkInfo.default_route || '-')}</div><div class="label">Remote Access</div><div class="value">${escapeHtml((lastNetworkInfo.remote_access_services || []).join(', ') || 'TeamViewer placeholder')}</div>${placeholderList(['Gateway ping','Internet ping','DNS health','Local target checks','Forwarder reachability'])}`);
}

function renderUpdatesPage(updateStatus){
  return renderSimplePage('Updates', `<p class="${statusClass(updateStatus.state)}">${escapeHtml((updateStatus.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(updateStatus.message || '')}</p><div class="label">Branch</div><div class="value">${escapeHtml(updateStatus.branch || '-')}</div><div class="label">Commit</div><div class="value">${escapeHtml(updateStatus.commit || '-')}</div><div class="label">Updated</div><div class="value">${escapeHtml(updateStatus.updated_at || '-')}</div><div class="button-row"><button class="action" id="update-button" onclick="triggerUpdate()">Update watchdog now</button></div><p id="update-feedback"></p>${placeholderList(['Check for updates without applying','Show local and remote commit comparison','Show update log tail','Rollback placeholder'])}`);
}

function renderDiagnosticsPage(status, updateStatus){
  return renderSimplePage('Diagnostics', `<p>Advanced troubleshooting and support bundle tools. Raw JSON is intentionally kept here.</p>${placeholderList(['systemd status','journal tail','hardware probes','network command output','support bundle export'])}<h3>Raw status</h3><pre>${escapeHtml(JSON.stringify(status, null, 2))}</pre><h3>Update status</h3><pre>${escapeHtml(JSON.stringify(updateStatus, null, 2))}</pre>`);
}

function renderPage(status, updateStatus, events){
  const grouped = groupChecks(status.checks || []);
  if (currentPage === 'Overview') return renderOverview(status, events);
  if (currentPage === 'Hardware') return `<div class="grid metric-grid">${grouped.hardware.map(c => tile(c.name, c, c.value === true ? 'Present' : fmtValue(c.value), c.message)).join('')}</div>${renderSimplePage('Hardware roadmap', placeholderList(['More temperature sensors','CPU model and cores','RAM detail','Watchdog device discovery','USB/controller/device inventory']))}`;
  if (currentPage === 'Services') return renderServices(status);
  if (currentPage === 'Storage') return `<div class="grid metric-grid">${grouped.storage.map(c => tile(c.name, c, c.value?.used_percent !== undefined ? fmtPercent(c.value.used_percent) : fmtValue(c.value), c.message)).join('')}</div>${renderRetentionPage()}`;
  if (currentPage === 'Network') return renderNetworkPage();
  if (currentPage === 'Recovery') return renderSimplePage('Recovery', `<p class="${escapeHtml(status.recovery?.state || 'unknown')}">${escapeHtml((status.recovery?.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(status.recovery?.message || 'No recovery state available.')}</p>${placeholderList(['Enable/disable recovery','Restart service policy','Reboot grace period','Install/configure hardware watchdog','Last reboot reason'])}`);
  if (currentPage === 'Events') return renderSimplePage('Events', `<div class="button-row"><button class="action" onclick="exportEvents()">Export events JSON</button></div><div class="events">${renderEvents(events, 20)}</div>${placeholderList(['Severity filters','Search','CSV export','Clear/purge events'])}`);
  if (currentPage === 'History') return renderSimplePage('History', '<div class="history-box">Health history placeholder</div>' + placeholderList(['Health score trend','CPU temp/load trend','RAM trend','Disk trend','Service failure timeline']));
  if (currentPage === 'Settings') return renderSettingsPage();
  if (currentPage === 'Updates') return renderUpdatesPage(updateStatus);
  if (currentPage === 'Diagnostics') return renderDiagnosticsPage(status, updateStatus);
  return renderOverview(status, events);
}

async function load(){
  const [statusResponse, updateResponse, eventsResponse, configResponse, systemResponse, networkResponse, settingsResponse, retentionResponse] = await Promise.all([
    fetch('/api/status'),
    fetch('/api/update-status'),
    fetch('/api/events'),
    fetch('/api/config-summary'),
    fetch('/api/system-info'),
    fetch('/api/network-info'),
    fetch('/api/settings-summary'),
    fetch('/api/retention'),
  ]);
  lastStatus = await statusResponse.json();
  lastUpdateStatus = await updateResponse.json();
  lastEvents = await eventsResponse.json();
  lastConfigSummary = await configResponse.json();
  lastSystemInfo = await systemResponse.json();
  lastNetworkInfo = await networkResponse.json();
  lastSettings = await settingsResponse.json();
  lastRetention = await retentionResponse.json();
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

async function exportEvents(){
  const response = await fetch('/api/events/export');
  const payload = await response.json();
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'va-watchdog-events.json';
  link.click();
  URL.revokeObjectURL(url);
}

async function purgeOldData(){
  if (!confirm('Purge watchdog data older than the configured retention window?')) return;
  const days = lastRetention.events_retention_days || 30;
  await fetch(`/api/purge?mode=old&older_than_days=${encodeURIComponent(days)}`, { method: 'POST' });
  await load();
}

async function purgeAllData(){
  if (!confirm('Purge all non-status watchdog data? This removes events and update logs.')) return;
  await fetch('/api/purge?mode=all', { method: 'POST' });
  await load();
}
buildNav();
initRefresh();
load();
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
    data_dir = events_path.parent

    def _run(command, timeout=5):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            return {
                "ok": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }
        except Exception as exc:
            return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": None}

    def _file_size(path):
        try:
            return path.stat().st_size if path.exists() else 0
        except OSError:
            return 0

    def _data_files():
        names = [
            "status.json",
            "events.jsonl",
            "update-state.json",
            "update.log",
            "last-reboot-reason.json",
            "history.jsonl",
        ]
        return [data_dir / name for name in names]

    def _dir_size(path):
        total = 0
        if not path.exists():
            return 0
        for item in path.rglob("*"):
            if item.is_file():
                total += _file_size(item)
        return total

    def retention_status():
        retention = cfg.get("retention", {})
        max_mb = int(retention.get("max_total_mb", 100) or 100)
        used_bytes = _dir_size(data_dir)
        files = [
            {
                "path": str(path),
                "size_bytes": _file_size(path),
                "modified_unix": path.stat().st_mtime if path.exists() else None,
            }
            for path in _data_files()
        ]
        return {
            "data_dir": str(data_dir),
            "max_total_mb": max_mb,
            "used_mb": round(used_bytes / 1024 / 1024, 2),
            "used_percent": round((used_bytes / max(1, max_mb * 1024 * 1024)) * 100, 1),
            "events_retention_days": retention.get("events_retention_days"),
            "history_retention_days": retention.get("history_retention_days"),
            "exports_retention_days": retention.get("exports_retention_days"),
            "files": files,
        }

    def purge_data(mode="old", older_than_days=None):
        cutoff = None
        if older_than_days is not None:
            cutoff = time.time() - max(0, int(older_than_days)) * 86400
        removed = []
        for path in _data_files():
            if not path.exists() or path.name == "status.json":
                continue
            if mode == "all" or (cutoff is not None and path.stat().st_mtime < cutoff):
                try:
                    path.unlink()
                    removed.append(str(path))
                except OSError:
                    pass
        return {"removed": removed, "retention": retention_status()}

    def rtc_status():
        timedate = _run(["timedatectl"])
        hwclock = _run(["hwclock", "--show"])
        rtc_path = Path("/sys/class/rtc/rtc0")
        return {
            "timedatectl_available": timedate["ok"],
            "timedatectl": timedate["stdout"] or timedate["stderr"],
            "hwclock_available": hwclock["ok"],
            "hwclock": hwclock["stdout"] or hwclock["stderr"],
            "rtc0_present": rtc_path.exists(),
        }

    def system_info():
        uptime_seconds = None
        try:
            uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
        except Exception:
            pass
        return {
            "hostname": platform.node(),
            "os": platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "uptime_seconds": uptime_seconds,
            "timezone": time.tzname,
            "rtc": rtc_status(),
        }

    def network_info():
        return {
            "ip_addresses": _run(["hostname", "-I"])["stdout"],
            "default_route": _run(["ip", "route", "show", "default"])["stdout"],
            "dns": Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore") if Path("/etc/resolv.conf").exists() else "",
            "configured_internet_hosts": cfg.get("network", {}).get("internet_hosts", []),
            "configured_local_targets": cfg.get("network", {}).get("local_targets", []),
            "remote_access_services": cfg.get("network", {}).get("remote_access_services", []),
            "listening_port": cfg.get("web", {}).get("port", 9110),
        }

    def settings_summary():
        return {
            "poll_interval_seconds": cfg.get("poll_interval_seconds"),
            "web": cfg.get("web", {}),
            "hardware_watchdog": cfg.get("hardware_watchdog", {}),
            "storage": cfg.get("storage", {}),
            "thresholds": cfg.get("thresholds", {}),
            "services": cfg.get("services", []),
            "network": cfg.get("network", {}),
            "recovery": cfg.get("recovery", {}),
            "retention": cfg.get("retention", {}),
            "update": cfg.get("update", {}),
        }

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
            if self.path == "/api/system-info":
                self._send_json(system_info())
                return
            if self.path == "/api/network-info":
                self._send_json(network_info())
                return
            if self.path == "/api/settings-summary":
                self._send_json(settings_summary())
                return
            if self.path == "/api/retention":
                self._send_json(retention_status())
                return
            if self.path == "/api/events/export":
                self._send_json({"events": recent_events(limit=200)})
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path == "/api/update":
                result = launch_update_job(cfg)
                status = 200 if result.get("ok") else 500
                self._send_json(result, status=status)
                return
            if self.path.startswith("/api/purge"):
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                mode = "old"
                older_than_days = None
                for part in query.split("&"):
                    if not part:
                        continue
                    key, _, value = part.partition("=")
                    if key == "mode":
                        mode = value
                    elif key == "older_than_days":
                        try:
                            older_than_days = int(value)
                        except ValueError:
                            older_than_days = None
                self._send_json(purge_data(mode=mode, older_than_days=older_than_days))
                return
            self._send_json({"error": "not found"}, status=404)

    server = ThreadingHTTPServer((web_cfg["host"], int(web_cfg["port"])), Handler)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
