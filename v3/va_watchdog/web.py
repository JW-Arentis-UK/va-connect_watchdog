from __future__ import annotations

import json
import platform
import subprocess
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from .config import active_config_path, deep_merge, load_raw_config, save_raw_config
from .history import history_path, read_history
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
  --sidebar: #05080c;
  --panel: #11161d;
  --panel-2: #151b23;
  --input: #05080c;
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
body[data-theme="light"] {
  --bg: #eef3f8;
  --sidebar: #dde7f1;
  --panel: #ffffff;
  --panel-2: #edf4fb;
  --input: #ffffff;
  --line: #c9d5e2;
  --text: #182230;
  --muted: #526173;
  --green: #168a3a;
  --amber: #a86700;
  --orange: #b45309;
  --red: #c6283a;
  --blue: #1d64d8;
}
body[data-theme="steel"] {
  --bg: #10151a;
  --sidebar: #161d24;
  --panel: #1e2730;
  --panel-2: #25313b;
  --input: #141b22;
  --line: #3b4855;
  --text: #f4f7f9;
  --muted: #b4c0cb;
  --blue: #38a3ff;
}
body[data-theme="sand"] {
  --bg: #f2eadc;
  --sidebar: #e0d2bb;
  --panel: #fff9ef;
  --panel-2: #f2e5cf;
  --input: #fffaf0;
  --line: #cbbda4;
  --text: #261f17;
  --muted: #6d604f;
  --green: #2f7d32;
  --amber: #9a6400;
  --orange: #a34800;
  --red: #b52222;
  --blue: #1769aa;
}
* { box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: var(--bg); color: var(--text); margin:0; font-size:calc(14px * var(--scale)); }
.shell { display:grid; grid-template-columns: calc(220px * var(--scale)) 1fr; min-height:100vh; }
.sidebar { border-right:1px solid var(--line); background:var(--sidebar); padding:calc(18px * var(--scale)) calc(14px * var(--scale)); display:flex; flex-direction:column; gap:calc(18px * var(--scale)); }
.brand { font-size:calc(18px * var(--scale)); font-weight:700; line-height:1.25; }
.nav { display:grid; gap:calc(6px * var(--scale)); }
.nav button { width:100%; text-align:left; background:transparent; color:var(--muted); border:1px solid transparent; border-radius:6px; padding:calc(10px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-size:inherit; }
.nav button.active { color:var(--text); background:#0f2d59; border-color:#235a9e; }
.side-status { margin-top:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:calc(12px * var(--scale)); color:var(--muted); }
.main { min-width:0; }
.topbar { height:calc(58px * var(--scale)); border-bottom:1px solid var(--line); display:flex; align-items:center; justify-content:space-between; padding:0 calc(18px * var(--scale)); color:var(--muted); }
.topbar-right { display:flex; gap:10px; align-items:center; }
select, input, textarea { background:var(--input); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:5px 8px; font-size:inherit; max-width:100%; }
textarea { width:100%; min-height:calc(70px * var(--scale)); resize:vertical; }
label { display:block; margin:calc(6px * var(--scale)) 0; }
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
pre { white-space:pre-wrap; overflow:auto; max-height:calc(540px * var(--scale)); background:var(--input); border:1px solid var(--line); border-radius:6px; padding:calc(12px * var(--scale)); }
.detail-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:calc(10px * var(--scale)); }
.mini-card { border:1px solid var(--line); border-radius:6px; padding:calc(10px * var(--scale)); background:rgba(255,255,255,.03); min-width:0; }
.muted { color:var(--muted); }
.toolbar { display:flex; flex-wrap:wrap; gap:calc(8px * var(--scale)); align-items:center; margin-bottom:calc(10px * var(--scale)); }
.chart { width:100%; height:calc(180px * var(--scale)); border:1px solid var(--line); border-radius:6px; background:rgba(54,209,95,.08); }
.chart text { fill:var(--muted); font-size:10px; }
.chart polyline { fill:none; stroke:var(--green); stroke-width:2; }
.chart .grid-line { stroke:var(--line); stroke-width:1; }
.button-row { display:flex; gap:calc(8px * var(--scale)); flex-wrap:wrap; align-items:center; margin:calc(10px * var(--scale)) 0; }
button.action { background:var(--blue); color:#fff; border:0; border-radius:6px; padding:calc(9px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-weight:700; font-size:inherit; }
button.ghost { background:transparent; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:calc(7px * var(--scale)) calc(10px * var(--scale)); cursor:pointer; font-size:inherit; }
form.inline { display:inline-block; margin:0; }
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
        <label>Theme <select id="theme-select" onchange="setTheme(this.value)"><option value="dark">Dark</option><option value="light">Light</option><option value="steel">Steel</option><option value="sand">Sand</option></select></label>
        <span class="advanced-only"><label>Refresh <select id="refresh-select" onchange="setRefreshInterval(this.value)"><option value="5000">5s</option><option value="15000">15s</option><option value="30000">30s</option><option value="60000">60s</option><option value="0">Manual</option></select></label></span>
        <button class="ghost advanced-only" onclick="load()">Refresh now</button>
        <button class="ghost" onclick="reloadPage()">Reload page</button>
        <div id="last-update">Last update: -</div>
      </div>
    </header>
    <section class="content" id="app">
      __BASIC_DASHBOARD__
    </section>
  </main>
</div>
<script>
(function(){
  var refreshTimer = null;
  function esc(value){
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function request(path, done){
    var xhr = new XMLHttpRequest();
    xhr.open('GET', path, true);
    xhr.onreadystatechange = function(){
      if (xhr.readyState === 4) {
        if (xhr.status >= 200 && xhr.status < 300) {
          try { done(null, JSON.parse(xhr.responseText)); }
          catch (e) { done(e); }
        } else {
          done(new Error('HTTP ' + xhr.status));
        }
      }
    };
    xhr.send();
  }
  function renderBasic(status){
    var app = document.getElementById('app');
    var lastUpdate = document.getElementById('last-update');
    var sideState = document.getElementById('side-state');
    var state = status.critical_failed ? 'critical' : 'healthy';
    var checks = status.checks || [];
    var rows = '';
    for (var i = 0; i < checks.length; i++) {
      rows += '<tr><td>' + esc(checks[i].name) + '</td><td class="' + esc(checks[i].state) + '">' + esc(String(checks[i].state || '').toUpperCase()) + '</td><td>' + esc(checks[i].message || '') + '</td></tr>';
    }
    app.innerHTML = '<div class="card"><h2>Compatibility Dashboard</h2><p>This browser is using the simpler view. The watchdog service is still running.</p><div class="status-word ' + state + '">' + (status.critical_failed ? 'CRITICAL' : 'HEALTHY') + '</div><div class="score">' + esc(status.score) + '%</div><div class="label">Last status</div><div class="value">' + esc(status.time || '-') + '</div></div><div class="card"><h2>Checks</h2><table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    if (lastUpdate) lastUpdate.textContent = 'Last update: ' + (status.time || '-');
    if (sideState) {
      sideState.textContent = status.critical_failed ? 'CRITICAL' : 'HEALTHY';
      sideState.className = 'value ' + state;
    }
  }
  function hideAdvancedControls(){
    var items = document.getElementsByClassName('advanced-only');
    for (var i = 0; i < items.length; i++) {
      items[i].style.display = 'none';
    }
  }
  window.vaWatchdogCompatibilityLoad = function(){
    request('/api/status', function(error, status){
      if (error) {
        document.getElementById('app').innerHTML = '<div class="card"><h2>Dashboard Load Error</h2><p>Could not read /api/status: ' + esc(error.message || error) + '</p></div>';
        return;
      }
      renderBasic(status);
    });
  };
  window.load = window.vaWatchdogCompatibilityLoad;
  window.reloadPage = function(){
    window.location.reload();
  };
  window.setRefreshInterval = function(value){
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
    var ms = Number(value);
    if (ms > 0) {
      refreshTimer = setInterval(window.vaWatchdogCompatibilityLoad, ms);
    }
  };
  window.setTheme = function(value){
    document.body.setAttribute('data-theme', value === 'dark' ? '' : value);
  };
  hideAdvancedControls();
  window.vaWatchdogCompatibilityLoad();
}());
</script>
<script type="module">
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
let lastHardwareInfo = {};
let lastServiceInfo = {};
let lastStorageInfo = {};
let lastHistory = [];
let lastUpdateLog = {};
let lastDiagnostics = {};
let lastVersion = {};
let refreshTimer = null;
let eventLevelFilter = 'all';
let eventSearch = '';

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

function showAdvancedControls(){
  const items = document.getElementsByClassName('advanced-only');
  for (const item of items) {
    item.style.display = '';
  }
}

function setTheme(value){
  localStorage.setItem('va_watchdog_theme', value);
  document.body.dataset.theme = value === 'dark' ? '' : value;
}

function reloadPage(){
  window.location.reload();
}

function initTheme(){
  const saved = localStorage.getItem('va_watchdog_theme') || 'dark';
  const select = document.getElementById('theme-select');
  select.value = saved;
  setTheme(saved);
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
    const live = (lastServiceInfo.services || []).find(item => item.name === c.name) || {};
    return `<tr><td>${escapeHtml(c.name)}</td><td><span class="pill">${escapeHtml((value.active || c.state || '-').toUpperCase())}</span></td><td>${escapeHtml(live.cpu_percent ?? '-')}</td><td>${escapeHtml(live.memory_mb !== undefined ? `${live.memory_mb} MB` : '-')}</td><td>${escapeHtml(value.restarts ?? live.restarts ?? '-')}</td><td>${escapeHtml(live.uptime || '-')}</td></tr>`;
  }).join('');
}

function renderEvents(events, limit=8){
  const rows = (events || []).slice(0, limit);
  if (!rows.length) return '<div class="event"><div class="event-time">-</div><div>No events yet</div></div>';
  return rows.map(event => `<div class="event"><div class="event-time">${escapeHtml(fmtTime(event.time))}</div><div><span class="${statusClass(event.level)}">${escapeHtml((event.level || 'info').toUpperCase())}</span> ${escapeHtml(event.message || '')}</div></div>`).join('');
}

function filteredEvents(limit=50){
  return (lastEvents || []).filter(event => {
    const levelOk = eventLevelFilter === 'all' || String(event.level || '').toLowerCase() === eventLevelFilter;
    const text = `${event.source || ''} ${event.message || ''}`.toLowerCase();
    return levelOk && (!eventSearch || text.includes(eventSearch));
  }).slice(0, limit);
}

function setEventLevel(value){
  eventLevelFilter = value;
  render();
}

function setEventSearch(value){
  eventSearch = String(value || '').toLowerCase();
  render();
}

function renderHistoryChart(rows, key='score'){
  const points = (rows || []).filter(row => row[key] !== null && row[key] !== undefined).slice(-120);
  if (!points.length) return '<div class="history-box">No history captured yet</div>';
  const width = 640;
  const height = 180;
  const pad = 24;
  const values = points.map(row => Number(row[key]));
  const min = Math.min(0, Math.min(...values));
  const max = Math.max(100, Math.max(...values));
  const span = Math.max(1, max - min);
  const coords = values.map((value, index) => {
    const x = pad + (index / Math.max(1, values.length - 1)) * (width - pad * 2);
    const y = height - pad - ((value - min) / span) * (height - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return `<svg class="chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none"><line class="grid-line" x1="${pad}" y1="${pad}" x2="${width - pad}" y2="${pad}"></line><line class="grid-line" x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}"></line><text x="4" y="${pad + 4}">${escapeHtml(max)}</text><text x="4" y="${height - pad}">${escapeHtml(min)}</text><polyline points="${coords}"></polyline></svg>`;
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
  return `<div class="card"><h2>System Information</h2><div class="detail-grid"><div><div class="label">Hostname</div><div class="value">${escapeHtml(lastSystemInfo.hostname || '-')}</div><div class="label">OS</div><div class="value">${escapeHtml(lastSystemInfo.os || '-')}</div><div class="label">Kernel</div><div class="value">${escapeHtml(lastSystemInfo.kernel || '-')}</div><div class="label">Architecture</div><div class="value">${escapeHtml(lastSystemInfo.architecture || '-')}</div><div class="label">Build</div><div class="value">${escapeHtml(lastVersion.branch || '-')} / ${escapeHtml(lastVersion.commit || '-')}</div></div><div><div class="label">Uptime</div><div class="value">${escapeHtml(lastSystemInfo.uptime_seconds ? `${Math.round(lastSystemInfo.uptime_seconds)}s` : '-')}</div><div class="label">Python</div><div class="value">${escapeHtml(lastSystemInfo.python || '-')}</div><div class="label">Timezone</div><div class="value">${escapeHtml((lastSystemInfo.timezone || []).join(' / ') || '-')}</div><div class="label">BIOS/RTC Clock</div><div class="value ${rtc.rtc0_present ? 'healthy' : 'warning'}">${rtc.rtc0_present ? 'RTC present' : 'RTC not confirmed'}</div><div class="label">Config</div><div class="value">${escapeHtml(lastVersion.config_path || '-')}</div></div></div><div class="label">Clock detail</div><pre>${escapeHtml(rtc.hwclock || rtc.timedatectl || 'Clock command output not available')}</pre></div>`;
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
  const t = lastSettings.thresholds || {};
  const r = lastSettings.retention || {};
  const n = lastSettings.network || {};
  const u = lastSettings.update || {};
  const h = lastSettings.hardware_watchdog || {};
  const rec = lastSettings.recovery || {};
  return renderSimplePage('Settings', `<p>Edit common watchdog settings. A backup is made before saving to disk.</p><div class="detail-grid"><div class="mini-card"><h3>Polling and History</h3><label class="label">Poll interval seconds</label><input id="set-poll" type="number" min="2" max="300" value="${escapeHtml(lastSettings.poll_interval_seconds ?? 5)}"><label class="label">History sample seconds</label><input id="set-history-sample" type="number" min="10" max="3600" value="${escapeHtml(r.history_sample_seconds ?? 60)}"><label class="label">History retention days</label><input id="set-history-days" type="number" min="1" max="365" value="${escapeHtml(r.history_retention_days ?? 30)}"><label class="label">Max watchdog storage MB</label><input id="set-max-mb" type="number" min="10" max="4096" value="${escapeHtml(r.max_total_mb ?? 100)}"></div><div class="mini-card"><h3>Storage Thresholds</h3><label class="label">Root warn %</label><input id="set-root-warn" type="number" min="1" max="100" value="${escapeHtml(t.root_disk_warning_percent ?? 80)}"><label class="label">Root critical %</label><input id="set-root-critical" type="number" min="1" max="100" value="${escapeHtml(t.root_disk_critical_percent ?? 95)}"><label class="label">Recordings warn %</label><input id="set-rec-warn" type="number" min="1" max="100" value="${escapeHtml(t.recordings_disk_warning_percent ?? 85)}"><label class="label">Recordings critical %</label><input id="set-rec-critical" type="number" min="1" max="100" value="${escapeHtml(t.recordings_disk_critical_percent ?? 95)}"></div><div class="mini-card"><h3>Network</h3><label class="label">Internet hosts, one per line</label><textarea id="set-internet-hosts">${escapeHtml((n.internet_hosts || []).join('\\n'))}</textarea><label class="label">Local targets, one per line</label><textarea id="set-local-targets">${escapeHtml((n.local_targets || []).join('\\n'))}</textarea><label class="label">Remote access services, one per line</label><textarea id="set-remote-services">${escapeHtml((n.remote_access_services || []).join('\\n'))}</textarea></div><div class="mini-card"><h3>Updates and Recovery</h3><label class="label">Update remote</label><input id="set-update-remote" value="${escapeHtml(u.remote || 'origin')}"><label class="label">Update branch</label><input id="set-update-branch" value="${escapeHtml(u.branch || '')}" placeholder="blank = current branch"><label><input id="set-hw-enabled" type="checkbox" ${h.enabled ? 'checked' : ''}> Enable hardware watchdog feed</label><label><input id="set-recovery-enabled" type="checkbox" ${rec.enabled ? 'checked' : ''}> Enable recovery engine</label><label><input id="set-restart-services" type="checkbox" ${rec.restart_failed_services ? 'checked' : ''}> Restart failed critical services</label><label><input id="set-allow-reboot" type="checkbox" ${rec.allow_reboot ? 'checked' : ''}> Allow reboot on persistent critical failure</label></div></div><div class="button-row"><button class="action" onclick="saveSettings()">Save settings</button><button class="ghost" onclick="load()">Reload from service</button></div><p id="settings-feedback"></p><h3>Current config summary</h3><pre>${escapeHtml(JSON.stringify(lastSettings, null, 2))}</pre>${placeholderList(['Service list editor','Install/reconfigure watchdog from Recovery page','Full raw config editor with validation'])}`);
}

function renderRetentionPage(){
  return `<div class="card"><h2>Watchdog Data Storage</h2><p>Used ${escapeHtml(lastRetention.used_mb ?? '-')} MB of ${escapeHtml(lastRetention.max_total_mb ?? '-')} MB (${escapeHtml(lastRetention.used_percent ?? '-')}%).</p><div class="button-row"><button class="action" onclick="purgeOldData()">Purge old data</button><button class="ghost" onclick="purgeAllData()">Purge all non-status data</button></div><pre>${escapeHtml(JSON.stringify(lastRetention, null, 2))}</pre></div>`;
}

function renderNetworkPage(){
  const pings = (lastNetworkInfo.pings || []).map(item => `<tr><td>${escapeHtml(item.target)}</td><td class="${item.ok ? 'healthy' : 'warning'}">${item.ok ? 'OK' : 'Failed'}</td><td>${escapeHtml(item.detail || '-')}</td></tr>`).join('');
  const remote = (lastNetworkInfo.remote_access || []).map(item => `<tr><td>${escapeHtml(item.service)}</td><td class="${item.active ? 'healthy' : 'warning'}">${escapeHtml(item.state || '-')}</td><td>${escapeHtml(item.note || '')}</td></tr>`).join('');
  return `<div class="grid lower-grid"><div class="card"><h2>Network</h2><div class="label">IP Addresses</div><div class="value">${escapeHtml(lastNetworkInfo.ip_addresses || '-')}</div><div class="label">Default Route</div><div class="value">${escapeHtml(lastNetworkInfo.default_route || '-')}</div><div class="label">DNS</div><pre>${escapeHtml(lastNetworkInfo.dns || '-')}</pre></div><div class="card"><h2>Connectivity</h2><table><thead><tr><th>Target</th><th>Status</th><th>Detail</th></tr></thead><tbody>${pings || '<tr><td colspan="3">No network targets configured</td></tr>'}</tbody></table><h3>Remote Access</h3><table><thead><tr><th>Service</th><th>Status</th><th>Note</th></tr></thead><tbody>${remote || '<tr><td>TeamViewer</td><td class="muted">Placeholder</td><td>Add/check service name when confirmed</td></tr>'}</tbody></table>${placeholderList(['Forwarder reachability','Gateway software web forwarding status','Local recorder/camera targets'])}</div></div>`;
}

function renderUpdatesPage(updateStatus){
  return renderSimplePage('Updates', `<p class="${statusClass(updateStatus.state)}">${escapeHtml((updateStatus.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(updateStatus.message || '')}</p><div class="detail-grid"><div><div class="label">Branch</div><div class="value">${escapeHtml(updateStatus.branch || '-')}</div><div class="label">Commit</div><div class="value">${escapeHtml(updateStatus.commit || '-')}</div><div class="label">Updated</div><div class="value">${escapeHtml(updateStatus.updated_at || '-')}</div></div><div><div class="label">Log file</div><div class="value">${escapeHtml(lastUpdateLog.path || '-')}</div><div class="label">Last log update</div><div class="value">${escapeHtml(lastUpdateLog.modified_unix ? new Date(lastUpdateLog.modified_unix * 1000).toLocaleString() : '-')}</div></div></div><div class="button-row"><button class="action" id="update-button" onclick="triggerUpdate()">Update watchdog now</button><button class="ghost" onclick="load()">Refresh update status</button></div><p id="update-feedback"></p><h3>Update Log Tail</h3><pre>${escapeHtml(lastUpdateLog.tail || 'No update log yet')}</pre>${placeholderList(['Check for updates without applying','Show local and remote commit comparison','Rollback placeholder'])}`);
}

function renderDiagnosticsPage(status, updateStatus){
  return renderSimplePage('Diagnostics', `<p>Advanced troubleshooting and support bundle tools. Raw JSON is intentionally kept here.</p><div class="detail-grid"><div><h3>Watchdog Service</h3><pre>${escapeHtml(lastDiagnostics.service_status || 'Not available')}</pre></div><div><h3>Journal Tail</h3><pre>${escapeHtml(lastDiagnostics.journal_tail || 'Not available')}</pre></div></div>${placeholderList(['Hardware probes detail','Network command output bundle','Support bundle export file'])}<h3>Raw status</h3><pre>${escapeHtml(JSON.stringify(status, null, 2))}</pre><h3>Update status</h3><pre>${escapeHtml(JSON.stringify(updateStatus, null, 2))}</pre>`);
}

function renderHardwarePage(grouped){
  const cpu = lastHardwareInfo.cpu || {};
  const memory = lastHardwareInfo.memory || {};
  const block = lastHardwareInfo.block_devices || [];
  return `<div class="grid metric-grid">${grouped.hardware.map(c => tile(c.name, c, c.value === true ? 'Present' : fmtValue(c.value), c.message)).join('')}</div><div class="grid lower-grid"><div class="card"><h2>CPU and Memory</h2><div class="label">CPU</div><div class="value">${escapeHtml(cpu.model || '-')}</div><div class="label">Cores</div><div class="value">${escapeHtml(cpu.cores || '-')}</div><div class="label">RAM Total</div><div class="value">${escapeHtml(memory.total_mb !== undefined ? `${memory.total_mb} MB` : '-')}</div><div class="label">RAM Available</div><div class="value">${escapeHtml(memory.available_mb !== undefined ? `${memory.available_mb} MB` : '-')}</div></div><div class="card"><h2>Detected Block Devices</h2><pre>${escapeHtml(block.join('\\n') || 'No block device detail available')}</pre>${placeholderList(['USB/controller/device inventory','More temperature sensors','Watchdog device discovery detail'])}</div></div>`;
}

function renderStoragePage(grouped){
  const rows = (lastStorageInfo.volumes || []).map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.path)}</td><td>${escapeHtml(item.used_percent)}%</td><td>${escapeHtml(item.free_gb)} GB</td><td>${escapeHtml(item.warning_percent)}%</td><td>${escapeHtml(item.critical_percent)}%</td><td>${item.always_full_expected ? 'Yes' : 'No'}</td></tr>`).join('');
  return `<div class="grid metric-grid">${grouped.storage.map(c => tile(c.name, c, c.value?.used_percent !== undefined ? fmtPercent(c.value.used_percent) : fmtValue(c.value), c.message)).join('')}</div><div class="card"><h2>Configured Storage Limits</h2><table><thead><tr><th>Name</th><th>Path</th><th>Used</th><th>Free</th><th>Warn</th><th>Critical</th><th>Full expected</th></tr></thead><tbody>${rows || '<tr><td colspan="7">No monitored paths configured</td></tr>'}</tbody></table>${placeholderList(['Editable warning/critical limits','Separate recordings drive detection','One-drive full-expected mode'])}</div>${renderRetentionPage()}`;
}

function renderEventsPage(){
  const events = filteredEvents(50);
  return renderSimplePage('Events', `<div class="toolbar"><label>Level <select id="event-level-filter" onchange="setEventLevel(this.value)"><option value="all" ${eventLevelFilter === 'all' ? 'selected' : ''}>All</option><option value="critical" ${eventLevelFilter === 'critical' ? 'selected' : ''}>Critical</option><option value="degraded" ${eventLevelFilter === 'degraded' ? 'selected' : ''}>Degraded</option><option value="warning" ${eventLevelFilter === 'warning' ? 'selected' : ''}>Warning</option><option value="info" ${eventLevelFilter === 'info' ? 'selected' : ''}>Info</option><option value="healthy" ${eventLevelFilter === 'healthy' ? 'selected' : ''}>Healthy</option></select></label><label>Search <input id="event-search" value="${escapeHtml(eventSearch)}" oninput="setEventSearch(this.value)" placeholder="service, storage, watchdog"></label><button class="action" onclick="exportEvents()">Export JSON</button><button class="ghost" onclick="exportEventsCsv()">Export CSV</button></div><div class="events">${renderEvents(events, 50)}</div>${placeholderList(['Date range filter','Clear/purge events with confirmation'])}`);
}

function renderHistoryPage(){
  const latest = (lastHistory || []).slice(-1)[0] || {};
  return renderSimplePage('History', `<div class="detail-grid"><div><h3>Health Score</h3>${renderHistoryChart(lastHistory, 'score')}</div><div><h3>Recent Snapshot</h3><div class="label">Samples</div><div class="value">${escapeHtml((lastHistory || []).length)}</div><div class="label">Latest score</div><div class="value">${escapeHtml(latest.score ?? '-')}%</div><div class="label">Latest RAM</div><div class="value">${escapeHtml(latest.ram ?? '-')}%</div><div class="label">Latest CPU temp</div><div class="value">${escapeHtml(latest.temperature ?? '-')}</div><div class="label">Latest root disk</div><div class="value">${escapeHtml(latest.root_disk ?? '-')}%</div></div></div>${placeholderList(['Selectable time ranges','CPU temp/load trend','RAM trend','Disk trend','Service failure timeline'])}`);
}

function renderPage(status, updateStatus, events){
  const grouped = groupChecks(status.checks || []);
  if (currentPage === 'Overview') return renderOverview(status, events);
  if (currentPage === 'Hardware') return renderHardwarePage(grouped);
  if (currentPage === 'Services') return renderServices(status);
  if (currentPage === 'Storage') return renderStoragePage(grouped);
  if (currentPage === 'Network') return renderNetworkPage();
  if (currentPage === 'Recovery') return renderSimplePage('Recovery', `<p class="${escapeHtml(status.recovery?.state || 'unknown')}">${escapeHtml((status.recovery?.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(status.recovery?.message || 'No recovery state available.')}</p>${placeholderList(['Enable/disable recovery','Restart service policy','Reboot grace period','Install/configure hardware watchdog','Last reboot reason'])}`);
  if (currentPage === 'Events') return renderEventsPage();
  if (currentPage === 'History') return renderHistoryPage();
  if (currentPage === 'Settings') return renderSettingsPage();
  if (currentPage === 'Updates') return renderUpdatesPage(updateStatus);
  if (currentPage === 'Diagnostics') return renderDiagnosticsPage(status, updateStatus);
  return renderOverview(status, events);
}

async function load(){
  lastStatus = await fetchJson('/api/status', lastStatus || {});
  render();

  const core = await Promise.allSettled([
    fetchJson('/api/update-status', lastUpdateStatus || {}),
    fetchJson('/api/events', lastEvents || []),
    fetchJson('/api/config-summary', lastConfigSummary || {}),
    fetchJson('/api/system-info', lastSystemInfo || {}),
    fetchJson('/api/settings-summary', lastSettings || {}),
    fetchJson('/api/retention', lastRetention || {}),
    fetchJson('/api/version', lastVersion || {}),
  ]);
  if (core[0].status === 'fulfilled') lastUpdateStatus = core[0].value;
  if (core[1].status === 'fulfilled') lastEvents = core[1].value;
  if (core[2].status === 'fulfilled') lastConfigSummary = core[2].value;
  if (core[3].status === 'fulfilled') lastSystemInfo = core[3].value;
  if (core[4].status === 'fulfilled') lastSettings = core[4].value;
  if (core[5].status === 'fulfilled') lastRetention = core[5].value;
  if (core[6].status === 'fulfilled') lastVersion = core[6].value;

  const pageFetches = [];
  if (currentPage === 'Overview' || currentPage === 'Services') {
    pageFetches.push(fetchJson('/api/services-info', lastServiceInfo || {}).then(value => { lastServiceInfo = value; }));
  }
  if (currentPage === 'Hardware') {
    pageFetches.push(fetchJson('/api/hardware-info', lastHardwareInfo || {}).then(value => { lastHardwareInfo = value; }));
  }
  if (currentPage === 'Storage') {
    pageFetches.push(fetchJson('/api/storage-info', lastStorageInfo || {}).then(value => { lastStorageInfo = value; }));
  }
  if (currentPage === 'Network') {
    pageFetches.push(fetchJson('/api/network-info', lastNetworkInfo || {}).then(value => { lastNetworkInfo = value; }));
  }
  if (currentPage === 'History') {
    pageFetches.push(fetchJson('/api/history', lastHistory || []).then(value => { lastHistory = value; }));
  }
  if (currentPage === 'Updates') {
    pageFetches.push(fetchJson('/api/update-log', lastUpdateLog || {}).then(value => { lastUpdateLog = value; }));
  }
  if (currentPage === 'Diagnostics') {
    pageFetches.push(fetchJson('/api/diagnostics', lastDiagnostics || {}).then(value => { lastDiagnostics = value; }));
  }
  await Promise.allSettled(pageFetches);
  render();
}

async function fetchJson(path, fallback){
  try {
    const response = await fetchWithTimeout(path, 4500);
    if (!response.ok) return fallback;
    return response.json();
  } catch (error) {
    return fallback;
  }
}

function fetchWithTimeout(path, timeoutMs){
  if (typeof AbortController === 'undefined') {
    return fetch(path);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(path, { signal: controller.signal }).finally(() => clearTimeout(timer));
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

async function exportEventsCsv(){
  const response = await fetch('/api/events/export.csv');
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'va-watchdog-events.csv';
  link.click();
  URL.revokeObjectURL(url);
}

function linesFromTextarea(id){
  return String(document.getElementById(id)?.value || '')
    .split(/\r?\n/)
    .map(item => item.trim())
    .filter(Boolean);
}

function numberValue(id){
  return Number(document.getElementById(id)?.value);
}

async function saveSettings(){
  const feedback = document.getElementById('settings-feedback');
  const allowReboot = !!document.getElementById('set-allow-reboot')?.checked;
  if (allowReboot && !confirm('Allowing automatic reboot can restart the gateway if critical checks remain failed. Continue?')) {
    return;
  }
  const payload = {
    poll_interval_seconds: numberValue('set-poll'),
    thresholds: {
      root_disk_warning_percent: numberValue('set-root-warn'),
      root_disk_critical_percent: numberValue('set-root-critical'),
      recordings_disk_warning_percent: numberValue('set-rec-warn'),
      recordings_disk_critical_percent: numberValue('set-rec-critical'),
    },
    retention: {
      max_total_mb: numberValue('set-max-mb'),
      history_sample_seconds: numberValue('set-history-sample'),
      history_retention_days: numberValue('set-history-days'),
    },
    network: {
      internet_hosts: linesFromTextarea('set-internet-hosts'),
      local_targets: linesFromTextarea('set-local-targets'),
      remote_access_services: linesFromTextarea('set-remote-services'),
    },
    update: {
      remote: String(document.getElementById('set-update-remote')?.value || 'origin').trim(),
      branch: String(document.getElementById('set-update-branch')?.value || '').trim(),
    },
    hardware_watchdog: {
      enabled: !!document.getElementById('set-hw-enabled')?.checked,
    },
    recovery: {
      enabled: !!document.getElementById('set-recovery-enabled')?.checked,
      restart_failed_services: !!document.getElementById('set-restart-services')?.checked,
      allow_reboot: allowReboot,
    },
  };
  feedback.textContent = 'Saving settings...';
  try {
    const response = await fetch('/api/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      feedback.textContent = result.error || 'Settings save failed.';
      return;
    }
    feedback.textContent = `Saved to ${result.path}. Backup created if a config already existed.`;
    await load();
  } catch (error) {
    feedback.textContent = `Settings save failed: ${error}`;
  }
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
window.setRefreshInterval = setRefreshInterval;
window.setTheme = setTheme;
window.reloadPage = reloadPage;
window.showPage = showPage;
window.load = load;
window.triggerUpdate = triggerUpdate;
window.exportEvents = exportEvents;
window.exportEventsCsv = exportEventsCsv;
window.setEventLevel = setEventLevel;
window.setEventSearch = setEventSearch;
window.saveSettings = saveSettings;
window.purgeOldData = purgeOldData;
window.purgeAllData = purgeAllData;
buildNav();
showAdvancedControls();
initTheme();
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

    def _quick_run(command, cwd=None, timeout=3):
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result.stdout.strip() or result.stderr.strip()
        except Exception as exc:
            return str(exc)

    def repo_root():
        return Path(__file__).resolve().parents[1]

    def version_info():
        root = repo_root()
        commit = _quick_run(["git", "rev-parse", "--short", "HEAD"], cwd=root)
        branch = _quick_run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
        remote = _quick_run(["git", "config", "--get", "remote.origin.url"], cwd=root)
        return {
            "name": "VA-Connect Watchdog V3",
            "branch": branch,
            "commit": commit,
            "remote": remote,
            "repo_root": str(root),
            "config_path": str(active_config_path()),
            "data_dir": str(data_dir),
        }

    def status_snapshot():
        try:
            payload = json.loads(status_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception as exc:
            return {
                "time": "",
                "score": "-",
                "critical_failed": True,
                "checks": [],
                "error": str(exc),
            }

    def basic_dashboard_html():
        status = status_snapshot()
        version = version_info()
        critical = bool(status.get("critical_failed", False))
        state = "critical" if critical else "healthy"
        word = "CRITICAL" if critical else "HEALTHY"
        checks = [check for check in status.get("checks", []) or [] if isinstance(check, dict)]
        check_map = {str(check.get("name", "")): check for check in checks}

        def check_value(name, default="-"):
            return check_map.get(name, {}).get("value", default)

        def check_message(name, default=""):
            return check_map.get(name, {}).get("message", default)

        def check_state(name, default="unknown"):
            return str(check_map.get(name, {}).get("state", default))

        def disk_used(name):
            value = check_value(name, {})
            if isinstance(value, dict):
                return f"{escape(str(value.get('used_percent', '-')))}%"
            return "-"

        def disk_free(name):
            value = check_value(name, {})
            if isinstance(value, dict):
                return f"{escape(str(value.get('free_gb', '-')))} GB free"
            return escape(str(check_message(name, "")))

        def tile(title, value, detail, tile_state="healthy"):
            return (
                "<div class=\"tile\">"
                f"<h3>{escape(str(title))}</h3>"
                f"<div class=\"tile-value {escape(str(tile_state))}\">{escape(str(value))}</div>"
                f"<div class=\"tile-detail\">{escape(str(detail))}</div>"
                "</div>"
            )

        def service_rows():
            rows = []
            for check in checks:
                name = str(check.get("name", ""))
                if not name.endswith(".service"):
                    continue
                value = check.get("value", {})
                restarts = value.get("restarts", "-") if isinstance(value, dict) else "-"
                active = value.get("active", check.get("state", "-")) if isinstance(value, dict) else check.get("state", "-")
                rows.append(
                    "<tr>"
                    f"<td>{escape(name)}</td>"
                    f"<td class=\"{escape(str(check.get('state', 'unknown')))}\">{escape(str(active).upper())}</td>"
                    "<td>-</td><td>-</td>"
                    f"<td>{escape(str(restarts))}</td>"
                    "<td>-</td>"
                    "</tr>"
                )
            if not rows:
                rows.append("<tr><td colspan=\"6\">No configured services found.</td></tr>")
            return "".join(rows)

        def event_rows(limit=8):
            events = recent_events(limit=limit)
            rows = []
            for event in events:
                rows.append(
                    "<div class=\"event\">"
                    f"<div class=\"event-time\">{escape(str(event.get('time', '-')))}</div>"
                    f"<div><span class=\"{escape(str(event.get('level', 'info')))}\">{escape(str(event.get('level', 'info')).upper())}</span> {escape(str(event.get('message', '')))}</div>"
                    "</div>"
                )
            if not rows:
                rows.append("<div class=\"event\"><div class=\"event-time\">-</div><div>No events yet</div></div>")
            return "".join(rows)

        rows = []
        for check in checks:
            if not isinstance(check, dict):
                continue
            row_state = str(check.get("state", "unknown"))
            rows.append(
                "<tr>"
                f"<td>{escape(str(check.get('name', '-')))}</td>"
                f"<td class=\"{escape(row_state)}\">{escape(row_state.upper())}</td>"
                f"<td>{escape(str(check.get('message', '')))}</td>"
                "</tr>"
            )
        if not rows:
            rows.append("<tr><td colspan=\"3\">No checks available yet.</td></tr>")
        error_html = ""
        if status.get("error"):
            error_html = f"<p class=\"critical\">{escape(str(status.get('error')))}</p>"
        issue_pill = "<span class=\"pill\">No critical issues</span>"
        if critical:
            issue_pill = "<span class=\"pill critical\">Critical issue</span>"
        return (
            "<div class=\"grid top-grid\">"
            "<div class=\"card summary-card\">"
            "<div>"
            f"<div class=\"status-word {state}\">{word}</div>"
            f"<div class=\"score\">{escape(str(status.get('score', '-')))}%</div>"
            f"{issue_pill}"
            "</div>"
            "<div>"
            "<div class=\"label\">Gateway</div><div class=\"value\">POC-451VTC</div>"
            f"<div class=\"label\">Last status</div><div class=\"value\">{escape(str(status.get('time', '-')))}</div>"
            f"<div class=\"label\">Build</div><div class=\"value\">{escape(str(version.get('branch', '-')))} / {escape(str(version.get('commit', '-')))}</div>"
            "</div>"
            "<div>"
            f"<div class=\"label\">Config</div><div class=\"value\">{escape(str(version.get('config_path', '-')))}</div>"
            f"<div class=\"label\">Data</div><div class=\"value\">{escape(str(version.get('data_dir', '-')))}</div>"
            "<button class=\"action\" onclick=\"window.location.reload()\">Refresh dashboard</button>"
            "</div>"
            f"{error_html}"
            "</div>"
            "<div class=\"card\"><h2>Health Breakdown</h2>"
            f"<div class=\"donut\" style=\"--score:{escape(str(status.get('score', 0)))}\"><span>{escape(str(status.get('score', '-')))}%</span></div>"
            "<div class=\"breakdown-row\"><span>Critical failed</span><strong>" + escape(str(critical).lower()) + "</strong></div>"
            "<div class=\"breakdown-row\"><span>Total checks</span><strong>" + escape(str(len(checks))) + "</strong></div>"
            "<div class=\"breakdown-row\"><span>Mode</span><strong>Compatibility</strong></div>"
            "</div></div>"
            "<div class=\"grid metric-grid\">"
            + tile("CPU Temp", check_value("temperature", "-"), check_message("temperature", ""), check_state("temperature", "healthy"))
            + tile("CPU Load", f"{escape(str(check_value('cpu_load', '-')))}%", check_message("cpu_load", ""), check_state("cpu_load", "healthy"))
            + tile("RAM", f"{escape(str(check_value('ram', '-')))}%", check_message("ram", ""), check_state("ram", "healthy"))
            + tile("Root Disk", disk_used("root_disk"), disk_free("root_disk"), check_state("root_disk", "healthy"))
            + tile("Recordings Disk", disk_used("recordings_disk"), disk_free("recordings_disk"), check_state("recordings_disk", "healthy"))
            + tile("Hardware WDT", "Present" if check_value("hardware_watchdog_present", False) else "Not present", check_message("hardware_watchdog_present", ""), check_state("hardware_watchdog_present", "warning"))
            + "</div>"
            "<div class=\"grid lower-grid\">"
            "<div class=\"card\"><h2>Services</h2><table><thead><tr><th>Service</th><th>Status</th><th>CPU</th><th>Memory</th><th>Restarts</th><th>Uptime</th></tr></thead>"
            f"<tbody>{service_rows()}</tbody></table></div>"
            f"<div class=\"card\"><h2>Recent Events</h2><div class=\"events\">{event_rows()}</div></div>"
            "</div>"
            "<div class=\"grid bottom-grid\">"
            "<div class=\"card\"><h2>System Information</h2>"
            f"<div class=\"label\">Repository</div><div class=\"value\">{escape(str(version.get('repo_root', '-')))}</div>"
            f"<div class=\"label\">Remote</div><div class=\"value\">{escape(str(version.get('remote', '-')))}</div>"
            "<div class=\"label\">Dashboard</div><div class=\"value\">Server-rendered compatibility appliance view</div>"
            "</div>"
            "<div class=\"card\"><h2>Next Sections</h2>"
            "<ul><li>Hardware details placeholder</li><li>Storage settings placeholder</li><li>Network details placeholder</li><li>Recovery controls placeholder</li><li>History graph placeholder</li></ul>"
            "</div></div>"
            "<div class=\"card\"><h2>All Checks</h2><table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )

    def html_page():
        return HTML.replace("__BASIC_DASHBOARD__", basic_dashboard_html())

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
        files = [data_dir / name for name in names]
        custom_history = history_path(cfg)
        if custom_history not in files:
            files.append(custom_history)
        return files

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
            "history_sample_seconds": retention.get("history_sample_seconds"),
            "history_max_rows": retention.get("history_max_rows"),
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
        network_cfg = cfg.get("network", {})
        targets = list(network_cfg.get("internet_hosts", [])) + list(network_cfg.get("local_targets", []))
        pings = []
        for target in targets[:8]:
            result = _run(["ping", "-c", "1", "-W", "1", str(target)], timeout=3)
            detail = ""
            for line in result["stdout"].splitlines():
                if "time=" in line or "packet loss" in line:
                    detail = line.strip()
                    break
            pings.append({"target": target, "ok": result["ok"], "detail": detail or result["stderr"]})
        remote_access = []
        for service in network_cfg.get("remote_access_services", []):
            state = _run(["systemctl", "is-active", str(service)], timeout=3)
            remote_access.append({
                "service": service,
                "active": state["stdout"] == "active",
                "state": state["stdout"] or state["stderr"] or "unknown",
                "note": "TeamViewer/remote support service placeholder" if "teamviewer" in str(service).lower() else "",
            })
        return {
            "ip_addresses": _run(["hostname", "-I"])["stdout"],
            "default_route": _run(["ip", "route", "show", "default"])["stdout"],
            "dns": Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore") if Path("/etc/resolv.conf").exists() else "",
            "configured_internet_hosts": network_cfg.get("internet_hosts", []),
            "configured_local_targets": network_cfg.get("local_targets", []),
            "remote_access_services": network_cfg.get("remote_access_services", []),
            "remote_access": remote_access,
            "pings": pings,
            "listening_port": cfg.get("web", {}).get("port", 9110),
        }

    def _kv_output(command):
        result = _run(command)
        out = {}
        for line in result["stdout"].splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                out[key.strip()] = value.strip()
        return out

    def hardware_info():
        cpu = _kv_output(["lscpu"])
        memory = {}
        free = _run(["free", "-m"])
        for line in free["stdout"].splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 7:
                    memory = {
                        "total_mb": int(parts[1]),
                        "used_mb": int(parts[2]),
                        "free_mb": int(parts[3]),
                        "available_mb": int(parts[6]),
                    }
        block_devices = _run(["lsblk", "-o", "NAME,MODEL,SIZE,TYPE,MOUNTPOINT", "-n"])["stdout"].splitlines()
        watchdog_devices = sorted(str(path) for path in Path("/dev").glob("watchdog*"))
        return {
            "cpu": {
                "model": cpu.get("Model name", ""),
                "cores": cpu.get("CPU(s)", ""),
                "vendor": cpu.get("Vendor ID", ""),
                "architecture": cpu.get("Architecture", ""),
            },
            "memory": memory,
            "block_devices": block_devices,
            "watchdog_devices": watchdog_devices,
        }

    def _df_path(path, label="", warning=0, critical=0, full_expected=False):
        result = _run(["df", "-P", "-B1", str(path)])
        lines = result["stdout"].splitlines()
        if len(lines) < 2:
            return {
                "name": label or str(path),
                "path": str(path),
                "error": result["stderr"] or result["stdout"] or "df unavailable",
                "warning_percent": warning,
                "critical_percent": critical,
                "always_full_expected": full_expected,
            }
        parts = lines[-1].split()
        total = int(parts[1])
        used = int(parts[2])
        available = int(parts[3])
        used_percent = round((used / max(1, total)) * 100, 1)
        return {
            "name": label or str(path),
            "path": str(path),
            "filesystem": parts[0],
            "mountpoint": parts[-1],
            "used_percent": used_percent,
            "free_gb": round(available / 1024 / 1024 / 1024, 1),
            "total_gb": round(total / 1024 / 1024 / 1024, 1),
            "warning_percent": warning,
            "critical_percent": critical,
            "always_full_expected": full_expected,
        }

    def storage_info():
        storage_cfg = cfg.get("storage", {})
        thresholds = cfg.get("thresholds", {})
        monitored = storage_cfg.get("monitored_paths") or [
            {
                "name": "Root Disk",
                "path": storage_cfg.get("root_path", "/"),
                "warning_percent": thresholds.get("root_disk_warning_percent", 80),
                "critical_percent": thresholds.get("root_disk_critical_percent", 95),
                "always_full_expected": False,
            },
            {
                "name": "Recordings Disk",
                "path": storage_cfg.get("recordings_path", "/home/vsuser/recordings"),
                "warning_percent": thresholds.get("recordings_disk_warning_percent", 85),
                "critical_percent": thresholds.get("recordings_disk_critical_percent", 95),
                "always_full_expected": False,
            },
        ]
        volumes = []
        seen = set()
        for item in monitored:
            path = item.get("path", "/")
            key = (item.get("name", path), path)
            if key in seen:
                continue
            seen.add(key)
            volumes.append(_df_path(
                path,
                label=item.get("name", path),
                warning=item.get("warning_percent", 0),
                critical=item.get("critical_percent", 0),
                full_expected=bool(item.get("always_full_expected", False)),
            ))
        return {
            "volumes": volumes,
            "write_test_path": storage_cfg.get("write_test_path"),
            "retention": retention_status(),
        }

    def _format_duration(seconds):
        if seconds is None:
            return ""
        seconds = max(0, int(seconds))
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, _ = divmod(remainder, 60)
        if days:
            return f"{days}d {hours}h"
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    def service_info():
        services = []
        for item in cfg.get("services", []):
            name = item.get("name", "")
            props = _run([
                "systemctl",
                "show",
                name,
                "--property=ActiveState",
                "--property=NRestarts",
                "--property=MainPID",
                "--property=ExecMainStartTimestampMonotonic",
                "--value",
            ])
            values = props["stdout"].splitlines()
            active = values[0] if len(values) > 0 else ""
            restarts = values[1] if len(values) > 1 else ""
            pid = values[2] if len(values) > 2 else "0"
            start_mono = values[3] if len(values) > 3 else ""
            ps = _run(["ps", "-p", pid, "-o", "%cpu=,rss=,etimes="]) if pid and pid != "0" else {"stdout": ""}
            cpu_percent = "-"
            memory_mb = None
            uptime = ""
            parts = ps["stdout"].split()
            if len(parts) >= 3:
                cpu_percent = parts[0]
                memory_mb = round(int(parts[1]) / 1024, 1)
                uptime = _format_duration(int(parts[2]))
            services.append({
                "name": name,
                "active": active,
                "restarts": restarts,
                "main_pid": pid,
                "cpu_percent": cpu_percent,
                "memory_mb": memory_mb,
                "uptime": uptime,
                "critical": bool(item.get("critical", False)),
                "restart": bool(item.get("restart", False)),
                "start_monotonic": start_mono,
            })
        return {"services": services}

    def settings_summary():
        return {
            "config_path": str(active_config_path()),
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

    def _int_range(payload, name, minimum, maximum):
        try:
            value = int(payload[name])
        except Exception as exc:
            raise ValueError(f"{name} must be a number") from exc
        if value < minimum or value > maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
        return value

    def _string_list(value, name):
        if not isinstance(value, list):
            raise ValueError(f"{name} must be a list")
        cleaned = []
        for item in value:
            text = str(item).strip()
            if text:
                cleaned.append(text)
        return cleaned[:50]

    def apply_settings(payload):
        if not isinstance(payload, dict):
            raise ValueError("settings payload must be an object")
        thresholds = payload.get("thresholds", {})
        retention = payload.get("retention", {})
        network = payload.get("network", {})
        update = payload.get("update", {})
        hardware = payload.get("hardware_watchdog", {})
        recovery = payload.get("recovery", {})

        updates = {
            "poll_interval_seconds": _int_range(payload, "poll_interval_seconds", 2, 300),
            "thresholds": {
                "root_disk_warning_percent": _int_range(thresholds, "root_disk_warning_percent", 1, 100),
                "root_disk_critical_percent": _int_range(thresholds, "root_disk_critical_percent", 1, 100),
                "recordings_disk_warning_percent": _int_range(thresholds, "recordings_disk_warning_percent", 1, 100),
                "recordings_disk_critical_percent": _int_range(thresholds, "recordings_disk_critical_percent", 1, 100),
            },
            "retention": {
                "max_total_mb": _int_range(retention, "max_total_mb", 10, 4096),
                "history_sample_seconds": _int_range(retention, "history_sample_seconds", 10, 3600),
                "history_retention_days": _int_range(retention, "history_retention_days", 1, 365),
            },
            "network": {
                "internet_hosts": _string_list(network.get("internet_hosts", []), "internet_hosts"),
                "local_targets": _string_list(network.get("local_targets", []), "local_targets"),
                "remote_access_services": _string_list(network.get("remote_access_services", []), "remote_access_services"),
            },
            "update": {
                "remote": str(update.get("remote", "origin")).strip() or "origin",
                "branch": str(update.get("branch", "")).strip(),
            },
            "hardware_watchdog": {
                "enabled": bool(hardware.get("enabled", False)),
            },
            "recovery": {
                "enabled": bool(recovery.get("enabled", False)),
                "restart_failed_services": bool(recovery.get("restart_failed_services", False)),
                "allow_reboot": bool(recovery.get("allow_reboot", False)),
            },
        }
        if updates["thresholds"]["root_disk_warning_percent"] >= updates["thresholds"]["root_disk_critical_percent"]:
            raise ValueError("root disk warning must be lower than critical")
        if updates["thresholds"]["recordings_disk_warning_percent"] >= updates["thresholds"]["recordings_disk_critical_percent"]:
            raise ValueError("recordings disk warning must be lower than critical")

        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        return {
            "ok": True,
            "path": str(saved_path),
            "settings": settings_summary(),
            "restart_required": False,
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

    def events_csv(limit=200):
        rows = recent_events(limit=limit)
        lines = ["time,level,source,message"]
        for event in rows:
            values = [
                event.get("time", ""),
                event.get("level", ""),
                event.get("source", ""),
                event.get("message", ""),
            ]
            lines.append(",".join(_csv_cell(value) for value in values))
        return "\n".join(lines) + "\n"

    def _csv_cell(value):
        text = str(value).replace('"', '""')
        if any(ch in text for ch in [",", '"', "\n", "\r"]):
            return f'"{text}"'
        return text

    def tail_file(path, lines=80):
        target = Path(path)
        if not target.exists():
            return {"path": str(target), "tail": "", "modified_unix": None}
        content = target.read_text(encoding="utf-8", errors="ignore").splitlines()[-lines:]
        return {
            "path": str(target),
            "tail": "\n".join(content),
            "modified_unix": target.stat().st_mtime,
            "size_bytes": target.stat().st_size,
        }

    def diagnostics_summary():
        service_status = _run(["systemctl", "status", "va-watchdog", "--no-pager"], timeout=5)
        journal = _run(["journalctl", "-u", "va-watchdog", "-n", "80", "--no-pager"], timeout=5)
        return {
            "service_status": service_status["stdout"] or service_status["stderr"],
            "journal_tail": journal["stdout"] or journal["stderr"],
            "generated_at_unix": time.time(),
        }

    def config_summary():
        hardware = cfg.get("hardware_watchdog", {})
        return {
            "hardware_watchdog": {
                "enabled": bool(hardware.get("enabled", False)),
                "device": str(hardware.get("device", "")),
                "timeout_seconds": hardware.get("feed_interval_seconds"),
            }
        }

    def healthz():
        status = status_snapshot()
        return {
            "ok": "error" not in status,
            "state": status.get("state"),
            "score": status.get("score"),
            "critical_failed": bool(status.get("critical_failed", False)),
            "status_time": status.get("time"),
            "version": version_info(),
        }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send_no_cache_headers(self):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")

        def _send_json(self, payload, status=200):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._send_no_cache_headers()
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, body, content_type="text/plain", status=200):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self._send_no_cache_headers()
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            route_path = self.path.split("?", 1)[0]
            if route_path == "/" or route_path.startswith("/index") or route_path.startswith("/basic"):
                body = html_page().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/api/status":
                try:
                    body = status_path.read_text(encoding="utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body.encode("utf-8"))))
                    self._send_no_cache_headers()
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                except Exception as e:
                    self._send_json({"error": str(e)}, status=503)
                return
            if route_path == "/api/update-status":
                self._send_json(load_update_status(cfg))
                return
            if route_path == "/api/events":
                self._send_json(recent_events())
                return
            if route_path == "/api/config-summary":
                self._send_json(config_summary())
                return
            if route_path == "/api/version":
                self._send_json(version_info())
                return
            if route_path == "/api/healthz":
                self._send_json(healthz())
                return
            if route_path == "/api/system-info":
                self._send_json(system_info())
                return
            if route_path == "/api/network-info":
                self._send_json(network_info())
                return
            if route_path == "/api/settings-summary":
                self._send_json(settings_summary())
                return
            if route_path == "/api/retention":
                self._send_json(retention_status())
                return
            if route_path == "/api/events/export":
                self._send_json({"events": recent_events(limit=200)})
                return
            if route_path == "/api/events/export.csv":
                self._send_text(events_csv(limit=200), content_type="text/csv")
                return
            if route_path == "/api/history":
                self._send_json(read_history(cfg, limit=288))
                return
            if route_path == "/api/update-log":
                self._send_json(tail_file(cfg.get("update", {}).get("log_path") or data_dir / "update.log"))
                return
            if route_path == "/api/diagnostics":
                self._send_json(diagnostics_summary())
                return
            if route_path == "/api/hardware-info":
                self._send_json(hardware_info())
                return
            if route_path == "/api/services-info":
                self._send_json(service_info())
                return
            if route_path == "/api/storage-info":
                self._send_json(storage_info())
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path == "/api/update":
                result = launch_update_job(cfg)
                status = 200 if result.get("ok") else 500
                self._send_json(result, status=status)
                return
            if self.path == "/api/settings":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
                    payload = json.loads(raw_body)
                    self._send_json(apply_settings(payload))
                except Exception as exc:
                    self._send_json({"ok": False, "error": str(exc)}, status=400)
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
