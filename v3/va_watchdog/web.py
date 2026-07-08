from __future__ import annotations

import json
import platform
import secrets
import socket
import subprocess
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, quote, unquote

from .config import active_config_path, deep_merge, load_raw_config, save_raw_config
from .history import history_path, read_history
from .retention import purge_data as retention_purge_data
from .retention import retention_status as retention_status_for_cfg
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
.nav button, .nav a { width:100%; text-align:left; background:transparent; color:var(--muted); border:1px solid transparent; border-radius:6px; padding:calc(10px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-size:inherit; text-decoration:none; display:block; }
.nav button.active, .nav a.active { color:var(--text); background:#0f2d59; border-color:#235a9e; }
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
.build-badge { display:inline-block; font-size:calc(18px * var(--scale)); font-weight:800; border:1px solid var(--line); border-radius:8px; padding:calc(8px * var(--scale)) calc(10px * var(--scale)); margin:calc(6px * var(--scale)) 0; background:rgba(59,130,246,.16); color:var(--text); }
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
.event-card { border:1px solid var(--line); border-radius:6px; padding:calc(10px * var(--scale)); background:rgba(255,255,255,.025); }
.event-card .event-head { display:flex; justify-content:space-between; gap:calc(10px * var(--scale)); align-items:center; margin-bottom:calc(6px * var(--scale)); }
.event-source { color:var(--muted); font-size:calc(12px * var(--scale)); }
.event-message { font-weight:700; }
.event-data { margin-top:calc(6px * var(--scale)); max-height:calc(130px * var(--scale)); }
.count-grid { display:grid; grid-template-columns: repeat(5, minmax(calc(90px * var(--scale)), 1fr)); gap:calc(8px * var(--scale)); margin-bottom:calc(10px * var(--scale)); }
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
button.ghost, a.ghost { background:transparent; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:calc(7px * var(--scale)) calc(10px * var(--scale)); cursor:pointer; font-size:inherit; text-decoration:none; display:inline-block; }
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
    <nav class="nav" id="nav">__SERVER_NAV__</nav>
    <div class="side-status">
      <div>Watchdog</div>
      <div id="side-state" class="value">Loading</div>
      <div class="label">Version</div>
      <div class="value">V3</div>
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div id="page-title">__PAGE_TITLE__</div>
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
    var lastUpdate = document.getElementById('last-update');
    var sideState = document.getElementById('side-state');
    var state = status.critical_failed ? 'critical' : 'healthy';
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

    server_pages = [
        ("Overview", "/"),
        ("Hardware", "/hardware"),
        ("Services", "/services"),
        ("Storage", "/storage"),
        ("Network", "/network"),
        ("Recovery", "/recovery"),
        ("Events", "/events"),
        ("History", "/history"),
        ("Settings", "/settings"),
        ("Updates", "/updates"),
        ("Diagnostics", "/diagnostics"),
    ]

    def page_name_for_path(route_path):
        if route_path in ("", "/"):
            return "Overview"
        cleaned = route_path.strip("/").lower()
        for name, path in server_pages:
            if cleaned == path.strip("/").lower():
                return name
        return "Overview"

    def server_nav_html(current_page):
        links = []
        for name, path in server_pages:
            active = "active" if name == current_page else ""
            links.append(f"<a class=\"{active}\" href=\"{escape(path)}\">{escape(name)}</a>")
        return "".join(links)

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

    def basic_dashboard_html(page="Overview"):
        status = status_snapshot()
        version = version_info()
        update_status = load_update_status(cfg)
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

        def metric_tiles():
            return (
                "<div class=\"grid metric-grid\">"
                + tile("CPU Temp", check_value("temperature", "-"), check_message("temperature", ""), check_state("temperature", "healthy"))
                + tile("CPU Load", f"{escape(str(check_value('cpu_load', '-')))}%", check_message("cpu_load", ""), check_state("cpu_load", "healthy"))
                + tile("RAM", f"{escape(str(check_value('ram', '-')))}%", check_message("ram", ""), check_state("ram", "healthy"))
                + tile("Root Disk", disk_used("root_disk"), disk_free("root_disk"), check_state("root_disk", "healthy"))
                + tile("Recordings Disk", disk_used("recordings_disk"), disk_free("recordings_disk"), check_state("recordings_disk", "healthy"))
                + tile("Hardware WDT", "Present" if check_value("hardware_watchdog_present", False) else "Not present", check_message("hardware_watchdog_present", ""), check_state("hardware_watchdog_present", "warning"))
                + "</div>"
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

        def all_checks_table(title="All Checks", selected=None):
            table_rows = []
            for check in checks:
                name = str(check.get("name", ""))
                if selected and name not in selected and not any(name.endswith(suffix) for suffix in selected):
                    continue
                row_state = str(check.get("state", "unknown"))
                table_rows.append(
                    "<tr>"
                    f"<td>{escape(name or '-')}</td>"
                    f"<td class=\"{escape(row_state)}\">{escape(row_state.upper())}</td>"
                    f"<td>{escape(str(check.get('message', '')))}</td>"
                    "</tr>"
                )
            if not table_rows:
                table_rows.append("<tr><td colspan=\"3\">No matching checks available.</td></tr>")
            return (
                f"<div class=\"card\"><h2>{escape(title)}</h2>"
                "<table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead>"
                f"<tbody>{''.join(table_rows)}</tbody></table></div>"
            )

        def event_rows(limit=8):
            events = recent_events(limit=limit)
            rows = []
            for event in events:
                rows.append(
                    "<div class=\"event-card\">"
                    "<div class=\"event-head\">"
                    f"<span class=\"{escape(str(event.get('level', 'info')))}\">{escape(str(event.get('level', 'info')).upper())}</span>"
                    f"<span class=\"event-time\">{escape(str(event.get('time', '-')))}</span>"
                    "</div>"
                    f"<div class=\"event-message\">{escape(str(event.get('message', '')))}</div>"
                    f"<div class=\"event-source\">Source: {escape(str(event.get('source', '-')))}</div>"
                    "</div>"
                )
            if not rows:
                rows.append("<div class=\"event\"><div class=\"event-time\">-</div><div>No events yet</div></div>")
            return "".join(rows)

        def events_page(limit=50):
            events = recent_events(limit=limit)
            counts = {}
            for event in events:
                level = str(event.get("level", "info")).lower()
                counts[level] = counts.get(level, 0) + 1
            count_cards = []
            for level in ["critical", "warning", "degraded", "info", "healthy"]:
                count_cards.append(
                    "<div class=\"mini-card\">"
                    f"<div class=\"label\">{escape(level.upper())}</div>"
                    f"<div class=\"tile-value {escape(level)}\">{escape(str(counts.get(level, 0)))}</div>"
                    "</div>"
                )
            event_cards = []
            for event in events:
                data_html = ""
                data = event.get("data")
                if data:
                    data_html = f"<pre class=\"event-data\">{escape(json.dumps(data, indent=2))}</pre>"
                event_cards.append(
                    "<div class=\"event-card\">"
                    "<div class=\"event-head\">"
                    f"<span class=\"{escape(str(event.get('level', 'info')))}\">{escape(str(event.get('level', 'info')).upper())}</span>"
                    f"<span class=\"event-time\">{escape(str(event.get('time', '-')))}</span>"
                    "</div>"
                    f"<div class=\"event-message\">{escape(str(event.get('message', '')))}</div>"
                    f"<div class=\"event-source\">Source: {escape(str(event.get('source', '-')))}</div>"
                    f"{data_html}"
                    "</div>"
                )
            if not event_cards:
                event_cards.append("<div class=\"event-card\">No events yet.</div>")
            return (
                "<div class=\"card\"><h2>Events</h2>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/api/events/export\">Export JSON</a><a class=\"ghost\" href=\"/api/events/export.csv\">Export CSV</a></div>"
                f"<div class=\"count-grid\">{''.join(count_cards)}</div>"
                f"<div class=\"events\">{''.join(event_cards)}</div>"
                "</div>"
            )

        def services_card():
            live = service_info().get("services", [])
            rows = []
            for svc in live:
                name = str(svc.get("name", ""))
                active = str(svc.get("active", "unknown"))
                rows.append(
                    "<tr>"
                    f"<td>{escape(name)}</td>"
                    f"<td class=\"{'healthy' if active == 'active' else 'critical' if svc.get('critical') else 'warning'}\">{escape(active.upper())}</td>"
                    f"<td>{escape(str(svc.get('sub_state', '-')))}</td>"
                    f"<td>{escape(str(svc.get('unit_file_state', '-')))}</td>"
                    f"<td>{escape(str(svc.get('cpu_percent', '-')))}</td>"
                    f"<td>{escape(str(svc.get('memory_mb', '-')))} MB</td>"
                    f"<td>{escape(str(svc.get('restarts', '-')))}</td>"
                    f"<td>{escape(str(svc.get('uptime', '-')))}</td>"
                    f"<td>{'Yes' if svc.get('critical') else 'No'}</td>"
                    f"<td><a class=\"ghost\" href=\"/service/{quote(name)}\">Details</a> <a class=\"ghost\" href=\"/service-restart-confirm/{quote(name)}\">Restart</a></td>"
                    "</tr>"
                )
            if not rows:
                rows.append("<tr><td colspan=\"10\">No configured services found.</td></tr>")
            return (
                "<div class=\"card\"><h2>Services</h2>"
                "<p class=\"muted\">Configured services monitored by the watchdog. Restart actions are manual and require confirmation.</p>"
                "<table><thead><tr><th>Service</th><th>Active</th><th>Substate</th><th>Enabled</th><th>CPU</th><th>Memory</th><th>Restarts</th><th>Uptime</th><th>Critical</th><th>Actions</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table></div>"
            )

        def updates_card():
            return (
                "<div class=\"card\"><h2>Updates</h2>"
                "<p class=\"healthy\">Web update enabled</p>"
                f"<div class=\"label\">State</div><div class=\"value {escape(str(update_status.get('state', 'unknown')))}\">{escape(str(update_status.get('state', 'unknown')).upper())}</div>"
                f"<div class=\"label\">Message</div><div class=\"value\">{escape(str(update_status.get('message', '-')))}</div>"
                f"<div class=\"label\">Branch</div><div class=\"value\">{escape(str(update_status.get('branch', '-')))}</div>"
                f"<div class=\"label\">Commit</div><div class=\"value\">{escape(str(update_status.get('commit', '-')))}</div>"
                f"<div class=\"label\">Updated</div><div class=\"value\">{escape(str(update_status.get('updated_at', '-')))}</div>"
                "<form class=\"inline\" method=\"post\" action=\"/update-now\"><button class=\"action\" type=\"submit\">Update watchdog now</button></form>"
                "<p class=\"muted\">The watchdog service may restart after an update. This page returns automatically after the update request.</p>"
                "</div>"
            )

        def settings_card():
            thresholds = cfg.get("thresholds", {})
            retention = cfg.get("retention", {})
            network = cfg.get("network", {})
            update = cfg.get("update", {})
            recovery = cfg.get("recovery", {})
            return (
                "<div class=\"card\"><h2>Settings</h2>"
                f"<div class=\"label\">Config path</div><div class=\"value\">{escape(str(active_config_path()))}</div>"
                "<p class=\"muted\">Saving creates a config backup and applies safe settings immediately.</p>"
                "<form method=\"post\" action=\"/settings-save\">"
                "<div class=\"detail-grid\">"
                "<div class=\"mini-card\"><h3>Polling and Retention</h3>"
                f"<label class=\"label\">Poll interval seconds</label><input name=\"poll_interval_seconds\" type=\"number\" min=\"2\" max=\"300\" value=\"{escape(str(cfg.get('poll_interval_seconds', 5)))}\">"
                f"<label class=\"label\">History sample seconds</label><input name=\"history_sample_seconds\" type=\"number\" min=\"10\" max=\"3600\" value=\"{escape(str(retention.get('history_sample_seconds', 60)))}\">"
                f"<label class=\"label\">History retention days</label><input name=\"history_retention_days\" type=\"number\" min=\"1\" max=\"365\" value=\"{escape(str(retention.get('history_retention_days', 30)))}\">"
                f"<label class=\"label\">Max watchdog storage MB</label><input name=\"max_total_mb\" type=\"number\" min=\"10\" max=\"4096\" value=\"{escape(str(retention.get('max_total_mb', 100)))}\">"
                "</div>"
                "<div class=\"mini-card\"><h3>Storage Thresholds</h3>"
                f"<label class=\"label\">Root warn %</label><input name=\"root_disk_warning_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('root_disk_warning_percent', 80)))}\">"
                f"<label class=\"label\">Root critical %</label><input name=\"root_disk_critical_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('root_disk_critical_percent', 95)))}\">"
                f"<label class=\"label\">Recordings warn %</label><input name=\"recordings_disk_warning_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('recordings_disk_warning_percent', 85)))}\">"
                f"<label class=\"label\">Recordings critical %</label><input name=\"recordings_disk_critical_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('recordings_disk_critical_percent', 95)))}\">"
                "</div>"
                "<div class=\"mini-card\"><h3>Network</h3>"
                f"<label class=\"label\">Internet hosts, one per line</label><textarea name=\"internet_hosts\">{escape(chr(10).join(network.get('internet_hosts', [])))}</textarea>"
                f"<label class=\"label\">Local targets, one per line</label><textarea name=\"local_targets\">{escape(chr(10).join(network.get('local_targets', [])))}</textarea>"
                f"<label class=\"label\">Remote access services, one per line</label><textarea name=\"remote_access_services\">{escape(chr(10).join(network.get('remote_access_services', [])))}</textarea>"
                "</div>"
                "<div class=\"mini-card\"><h3>Updates and Recovery</h3>"
                f"<label class=\"label\">Update remote</label><input name=\"update_remote\" value=\"{escape(str(update.get('remote', 'origin')))}\">"
                f"<label class=\"label\">Update branch</label><input name=\"update_branch\" value=\"{escape(str(update.get('branch', '')))}\" placeholder=\"blank = current branch\">"
                f"<label><input name=\"recovery_enabled\" type=\"checkbox\" {'checked' if recovery.get('enabled') else ''}> Enable recovery engine</label>"
                f"<label><input name=\"restart_failed_services\" type=\"checkbox\" {'checked' if recovery.get('restart_failed_services') else ''}> Restart failed critical services</label>"
                f"<label><input name=\"allow_reboot\" type=\"checkbox\" {'checked' if recovery.get('allow_reboot') else ''}> Allow reboot on persistent critical failure</label>"
                "</div></div>"
                "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Save settings</button><a class=\"ghost\" href=\"/settings\">Cancel</a></div>"
                "</form>"
                "</div>"
            )

        def hardware_page():
            info = hardware_info()
            cpu = info.get("cpu", {})
            memory = info.get("memory", {})
            block_devices = info.get("block_devices", [])
            watchdog_devices = info.get("watchdog_devices", [])
            watchdog = info.get("watchdog", {})
            modules = watchdog.get("modules", {})
            wdctl = watchdog.get("wdctl", {})
            wdt = watchdog_test_summary()
            systemd_wdt = systemd_watchdog_info()
            return (
                metric_tiles()
                + "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>CPU and Memory</h2>"
                f"<div class=\"label\">CPU model</div><div class=\"value\">{escape(str(cpu.get('model', '-')))}</div>"
                f"<div class=\"label\">CPU cores</div><div class=\"value\">{escape(str(cpu.get('cores', '-')))}</div>"
                f"<div class=\"label\">Architecture</div><div class=\"value\">{escape(str(cpu.get('architecture', '-')))}</div>"
                f"<div class=\"label\">RAM total</div><div class=\"value\">{escape(str(memory.get('total_mb', '-')))} MB</div>"
                f"<div class=\"label\">RAM available</div><div class=\"value\">{escape(str(memory.get('available_mb', '-')))} MB</div>"
                "</div>"
                "<div class=\"card\"><h2>Detected Devices</h2>"
                f"<div class=\"label\">Watchdog devices</div><div class=\"value\">{escape(', '.join(watchdog_devices) if watchdog_devices else 'None detected')}</div>"
                f"<div class=\"label\">Block devices</div><pre>{escape(chr(10).join(block_devices) if block_devices else 'No block device details available')}</pre>"
                "</div></div>"
                "<div class=\"card\"><h2>Intel TCO Watchdog</h2>"
                f"<div class=\"label\">Expected driver</div><div class=\"value\">iTCO_wdt with iTCO_vendor_support</div>"
                f"<div class=\"label\">iTCO_wdt loaded</div><div class=\"value {'healthy' if modules.get('iTCO_wdt') else 'warning'}\">{escape('Yes' if modules.get('iTCO_wdt') else 'No')}</div>"
                f"<div class=\"label\">iTCO_vendor_support loaded</div><div class=\"value {'healthy' if modules.get('iTCO_vendor_support') else 'warning'}\">{escape('Yes' if modules.get('iTCO_vendor_support') else 'No')}</div>"
                f"<div class=\"label\">intel_pmc_bxt loaded</div><div class=\"value {'healthy' if modules.get('intel_pmc_bxt') else 'warning'}\">{escape('Yes' if modules.get('intel_pmc_bxt') else 'No')}</div>"
                f"<div class=\"label\">wdctl identity</div><div class=\"value {escape(str(wdctl.get('state', 'unknown')))}\">{escape(str(wdctl.get('identity', '-')))}</div>"
                f"<div class=\"label\">wdctl timeout</div><div class=\"value\">{escape(str(wdctl.get('timeout', '-')))}</div>"
                f"<div class=\"label\">wdctl raw output</div><pre>{escape(str(wdctl.get('raw', 'wdctl not available or watchdog not present')))}</pre>"
                f"<div class=\"label\">Last setup log</div><pre>{escape(str(watchdog.get('setup_log', 'No setup log yet')))}</pre>"
                f"<div class=\"label\">Last full probe</div><pre>{escape(str(watchdog.get('probe_log', 'No hardware probe log yet')))}</pre>"
                "<p class=\"muted\">For POC-451VTC, the expected hardware watchdog is Intel TCO. Use the button below to load and persist the driver. Feeding stays disabled until you explicitly enable it in Settings/config.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/itco-watchdog-install-confirm\">Install/load Intel TCO watchdog</a><a class=\"ghost\" href=\"/watchdog-hardware-probe-confirm\">Run full watchdog probe</a></div>"
                "<pre>cd /opt/va-connect-watchdog-v3\nsudo ./v3/scripts/setup_itco_watchdog.sh</pre>"
                "</div>"
                "<div class=\"card\"><h2>Watchdog Protection Layers</h2>"
                f"<div class=\"label\">Hardware reboot watchdog</div><div class=\"value {escape(str(wdt.get('device_state', 'unknown')))}\">{escape(str(wdt.get('device_message', '-')).upper())}</div>"
                "<p class=\"muted\">This layer can reboot the gateway if the whole system stops responding, but only when the OS exposes a watchdog device such as /dev/watchdog0.</p>"
                f"<div class=\"label\">Systemd service watchdog</div><div class=\"value {escape(str(systemd_wdt.get('state', 'unknown')))}\">{escape(str(systemd_wdt.get('message', '-')))}</div>"
                f"<div class=\"label\">WatchdogSec</div><div class=\"value\">{escape(str(systemd_wdt.get('watchdog_sec', '-')))}</div>"
                f"<div class=\"label\">Service manager status</div><div class=\"value\">{escape(str(systemd_wdt.get('status_text', '-')))}</div>"
                "<p class=\"muted\">This layer restarts va-watchdog if the Python process hangs. It does not reboot the gateway, but it is the correct fallback when hardware watchdog is not present.</p>"
                "</div>"
                "<div class=\"card\"><h2>Hardware Watchdog Test</h2>"
                f"<div class=\"label\">Device</div><div class=\"value {escape(str(wdt.get('device_state', 'unknown')))}\">{escape(str(wdt.get('device', '-')))} - {escape(str(wdt.get('device_message', '-')))}</div>"
                f"<div class=\"label\">Driver identity</div><div class=\"value\">{escape(str(wdt.get('driver_identity', '-')))}</div>"
                f"<div class=\"label\">Timeout</div><div class=\"value\">{escape(str(wdt.get('driver_timeout', '-')))}</div>"
                f"<div class=\"label\">Configured feed</div><div class=\"value {'healthy' if wdt.get('feed_enabled') else 'warning'}\">{escape('Enabled' if wdt.get('feed_enabled') else 'Disabled')}</div>"
                f"<div class=\"label\">Opened by VA-Connect</div><div class=\"value {'healthy' if wdt.get('opened') else 'warning'}\">{escape('Yes' if wdt.get('opened') else 'No')}</div>"
                f"<div class=\"label\">Feed count</div><div class=\"value\">{escape(str(wdt.get('feed_count', 0)))}</div>"
                f"<div class=\"label\">Last feed</div><div class=\"value {escape(str(wdt.get('feed_state', 'unknown')))}\">{escape(str(wdt.get('last_feed_message', '-')))}</div>"
                f"<div class=\"label\">Last safe test</div><div class=\"value\">{escape(str(wdt.get('last_test_message', 'No test recorded yet')))}</div>"
                "<p class=\"muted\">Double-knock test: first click arms the test, second click confirms it. This safe test does not stop feeding the watchdog or intentionally reboot the gateway.</p>"
                "<form class=\"inline\" method=\"post\" action=\"/watchdog-test-arm\"><button class=\"action\" type=\"submit\">Arm safe watchdog test</button></form>"
                "<p class=\"muted\">A full trip test would deliberately stop feeding the hardware watchdog and may reboot the gateway. That is not enabled here yet.</p>"
                "</div>"
            )

        def storage_page():
            info = storage_info()
            volume_rows = []
            for volume in info.get("volumes", []):
                volume_rows.append(
                    "<tr>"
                    f"<td>{escape(str(volume.get('name', '-')))}</td>"
                    f"<td>{escape(str(volume.get('path', '-')))}</td>"
                    f"<td>{escape(str(volume.get('used_percent', '-')))}%</td>"
                    f"<td>{escape(str(volume.get('free_gb', '-')))} GB</td>"
                    f"<td>{escape(str(volume.get('warning_percent', '-')))}%</td>"
                    f"<td>{escape(str(volume.get('critical_percent', '-')))}%</td>"
                    f"<td>{'Yes' if volume.get('always_full_expected') else 'No'}</td>"
                    "</tr>"
                )
            if not volume_rows:
                volume_rows.append("<tr><td colspan=\"7\">No configured storage volumes.</td></tr>")
            retention = info.get("retention", {})
            file_rows = []
            for item in retention.get("files", []):
                file_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('path', '-')))}</td>"
                    f"<td>{escape(human_size(item.get('size_bytes', 0)))}</td>"
                    f"<td>{escape(unix_time(item.get('modified_unix')))}</td>"
                    "</tr>"
                )
            if not file_rows:
                file_rows.append("<tr><td colspan=\"3\">No watchdog data files found.</td></tr>")
            default_days = retention.get("events_retention_days") or 30
            return (
                metric_tiles()
                + "<div class=\"card\"><h2>Configured Storage Limits</h2>"
                "<table><thead><tr><th>Name</th><th>Path</th><th>Used</th><th>Free</th><th>Warn</th><th>Critical</th><th>Full expected</th></tr></thead>"
                f"<tbody>{''.join(volume_rows)}</tbody></table></div>"
                "<div class=\"card\"><h2>Watchdog Data Storage</h2>"
                f"<div class=\"label\">Data directory</div><div class=\"value\">{escape(str(retention.get('data_dir', '-')))}</div>"
                f"<div class=\"label\">Used</div><div class=\"value\">{escape(str(retention.get('used_mb', '-')))} MB / {escape(str(retention.get('max_total_mb', '-')))} MB</div>"
                f"<div class=\"label\">Events retention</div><div class=\"value\">{escape(str(retention.get('events_retention_days', '-')))} days</div>"
                f"<div class=\"label\">History retention</div><div class=\"value\">{escape(str(retention.get('history_retention_days', '-')))} days</div>"
                f"<div class=\"label\">Auto-purge rule</div><div class=\"value\">Self-purge old watchdog data when usage exceeds {escape(str(retention.get('max_total_mb', '-')))} MB.</div>"
                "<div class=\"button-row\">"
                "<form class=\"inline\" method=\"post\" action=\"/storage-purge-old\">"
                f"<label class=\"label\">Older than days</label><input name=\"older_than_days\" type=\"number\" min=\"0\" max=\"3650\" value=\"{escape(str(default_days))}\"> "
                "<button class=\"action\" type=\"submit\">Purge old data</button>"
                "</form>"
                "<a class=\"ghost\" href=\"/storage-purge-confirm\">Purge all non-status data</a>"
                "<a class=\"ghost\" href=\"/settings\">Edit retention settings</a>"
                "</div>"
                "<p class=\"muted\">Purge never removes the live status file, so /api/status remains available.</p>"
                "</div>"
                "<div class=\"card\"><h2>Watchdog Data Files</h2>"
                "<table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead>"
                f"<tbody>{''.join(file_rows)}</tbody></table>"
                "</div>"
            )

        def network_page():
            info = network_info()
            local_web = info.get("local_web", {})
            interfaces = []
            for item in info.get("interfaces", []):
                interfaces.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('name', '-')))}</td>"
                    f"<td class=\"{'healthy' if str(item.get('state', '')).upper() in ('UP', 'UNKNOWN') else 'warning'}\">{escape(str(item.get('state', '-')))}</td>"
                    f"<td>{escape(str(item.get('addresses', '-')))}</td>"
                    "</tr>"
                )
            if not interfaces:
                interfaces.append("<tr><td colspan=\"3\">No interface details available.</td></tr>")
            ping_rows = []
            for item in info.get("pings", []):
                ping_state = "OK" if item.get("ping_ok") else "FAILED"
                tcp_state = "N/A" if item.get("tcp_ok") is None else ("OK" if item.get("tcp_ok") else "FAILED")
                row_ok = item.get("ok")
                ping_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('target', '-')))}</td>"
                    f"<td>{escape(str(item.get('host', '-')))}</td>"
                    f"<td>{escape(str(item.get('port') or '-'))}</td>"
                    f"<td class=\"{'healthy' if item.get('ping_ok') else 'warning'}\">{ping_state}</td>"
                    f"<td class=\"{'healthy' if item.get('tcp_ok') else ('muted' if item.get('tcp_ok') is None else 'warning')}\">{tcp_state}</td>"
                    f"<td class=\"{'healthy' if row_ok else 'warning'}\">{'OK' if row_ok else 'CHECK'}</td>"
                    f"<td>{escape(str(item.get('tcp_detail') or item.get('detail') or '-'))}</td>"
                    "</tr>"
                )
            if not ping_rows:
                ping_rows.append("<tr><td colspan=\"7\">No network targets configured yet. Add internet hosts/local targets in Settings.</td></tr>")
            remote_rows = []
            for item in info.get("remote_access", []):
                remote_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('service', '-')))}</td>"
                    f"<td class=\"{'healthy' if item.get('active') else 'warning'}\">{escape(str(item.get('state', '-')).upper())}</td>"
                    f"<td>{escape(str(item.get('enabled', '-')).upper())}</td>"
                    f"<td>{escape(str(item.get('detail') or item.get('note') or ''))}</td>"
                    "</tr>"
                )
            if not remote_rows:
                remote_rows.append("<tr><td colspan=\"4\">No remote access services configured. TeamViewer placeholder remains in Settings as teamviewerd.</td></tr>")
            urls = "".join(f"<li>{escape(str(url))}</li>" for url in info.get("support_urls", []))
            return (
                "<div class=\"grid metric-grid\">"
                f"<div class=\"tile\"><h3>Hostname</h3><div class=\"tile-value\">{escape(str(info.get('hostname', '-')))}</div><div class=\"tile-detail\">Gateway identity</div></div>"
                f"<div class=\"tile\"><h3>IP Addresses</h3><div class=\"tile-value\">{escape(str(info.get('ip_addresses', '-') or '-'))}</div><div class=\"tile-detail\">hostname -I</div></div>"
                f"<div class=\"tile\"><h3>Web Port</h3><div class=\"tile-value {'healthy' if local_web.get('ok') else 'warning'}\">{escape(str(info.get('listening_port', '-')))}</div><div class=\"tile-detail\">{escape(str(local_web.get('detail', '-')))}</div></div>"
                f"<div class=\"tile\"><h3>Internet Targets</h3><div class=\"tile-value\">{escape(str(len(info.get('configured_internet_hosts', []))))}</div><div class=\"tile-detail\">Configured checks</div></div>"
                f"<div class=\"tile\"><h3>Local Targets</h3><div class=\"tile-value\">{escape(str(len(info.get('configured_local_targets', []))))}</div><div class=\"tile-detail\">Camera/router/software checks</div></div>"
                f"<div class=\"tile\"><h3>Remote Access</h3><div class=\"tile-value\">{escape(str(len(info.get('remote_access', []))))}</div><div class=\"tile-detail\">TeamViewer/support services</div></div>"
                "</div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Interfaces</h2>"
                "<table><thead><tr><th>Name</th><th>State</th><th>Addresses</th></tr></thead>"
                f"<tbody>{''.join(interfaces)}</tbody></table>"
                f"<div class=\"label\">Default route</div><pre>{escape(str(info.get('default_route', '-')))}</pre>"
                "</div>"
                "<div class=\"card\"><h2>Support URLs</h2>"
                f"<ul>{urls}</ul>"
                "<p class=\"muted\">Use the gateway IP URL remotely. Some forwarders only accept the port at the end, so keep the format as http://IP:9110/.</p>"
                f"<div class=\"label\">DNS</div><pre>{escape(str(info.get('dns', '-')))}</pre>"
                "</div></div>"
                "<div class=\"card\"><h2>Connectivity Checks</h2>"
                "<table><thead><tr><th>Target</th><th>Host</th><th>Port</th><th>Ping</th><th>TCP</th><th>Overall</th><th>Detail</th></tr></thead>"
                f"<tbody>{''.join(ping_rows)}</tbody></table></div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Remote Access Services</h2>"
                "<table><thead><tr><th>Service</th><th>Status</th><th>Enabled</th><th>Detail</th></tr></thead>"
                f"<tbody>{''.join(remote_rows)}</tbody></table>"
                "<p class=\"muted\">TeamViewer or other support tooling can be tracked here by adding the systemd service name in Settings.</p>"
                "</div>"
                "<div class=\"card\"><h2>Routes and Neighbours</h2>"
                f"<div class=\"label\">Route table</div><pre>{escape(str(info.get('route_table', '-')))}</pre>"
                f"<div class=\"label\">LAN neighbours</div><pre>{escape(str(info.get('neighbours', '-')))}</pre>"
                "</div></div>"
                "<div class=\"card\"><h2>Listening TCP Sockets</h2>"
                f"<pre>{escape(str(info.get('listening_sockets', 'ss output not available')))}</pre>"
                "</div>"
                + all_checks_table("Network Checks", {"network_module"})
            )

        def recovery_page():
            recovery = status.get("recovery", {}) if isinstance(status.get("recovery", {}), dict) else {}
            cfg_recovery = cfg.get("recovery", {})
            install = install_status()
            reboot = last_reboot_reason()
            service_rows = []
            for item in cfg.get("services", []):
                service_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('name', '-')))}</td>"
                    f"<td>{'Yes' if item.get('critical') else 'No'}</td>"
                    f"<td>{'Yes' if item.get('restart') else 'No'}</td>"
                    "</tr>"
                )
            if not service_rows:
                service_rows.append("<tr><td colspan=\"3\">No monitored services configured.</td></tr>")
            return (
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Recovery Status</h2>"
                f"<div class=\"label\">Current state</div><div class=\"value {escape(str(recovery.get('state', 'unknown')))}\">{escape(str(recovery.get('state', 'unknown')).upper())}</div>"
                f"<div class=\"label\">Message</div><div class=\"value\">{escape(str(recovery.get('message', '-')))}</div>"
                f"<div class=\"label\">Updated</div><div class=\"value\">{escape(str(recovery.get('updated_at', '-')))}</div>"
                f"<div class=\"label\">Last reboot reason</div><pre>{escape(json.dumps(reboot, indent=2) if reboot else 'No watchdog reboot reason recorded.')}</pre>"
                "</div>"
                "<div class=\"card\"><h2>Recovery Configuration</h2>"
                f"<div class=\"label\">Enabled</div><div class=\"value\">{escape(str(cfg_recovery.get('enabled', False)))}</div>"
                f"<div class=\"label\">Restart failed services</div><div class=\"value\">{escape(str(cfg_recovery.get('restart_failed_services', False)))}</div>"
                f"<div class=\"label\">Restart non-critical services</div><div class=\"value\">{escape(str(cfg_recovery.get('restart_noncritical_services', False)))}</div>"
                f"<div class=\"label\">Allow reboot</div><div class=\"value\">{escape(str(cfg_recovery.get('allow_reboot', False)))}</div>"
                f"<div class=\"label\">Critical grace seconds</div><div class=\"value\">{escape(str(cfg_recovery.get('critical_grace_seconds', '-')))}</div>"
                "<a class=\"ghost\" href=\"/settings\">Edit recovery settings</a>"
                "</div></div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Install and Service</h2>"
                f"<div class=\"label\">Service unit</div><div class=\"value {escape(str(install.get('unit_state', 'unknown')))}\">{escape(str(install.get('unit_path', '-')))}</div>"
                f"<div class=\"label\">Service active</div><div class=\"value {escape(str(install.get('active', 'unknown')))}\">{escape(str(install.get('active', '-')).upper())}</div>"
                f"<div class=\"label\">Service enabled</div><div class=\"value\">{escape(str(install.get('enabled', '-')).upper())}</div>"
                f"<div class=\"label\">Install path</div><div class=\"value\">{escape(str(install.get('install_path', '-')))}</div>"
                f"<div class=\"label\">Config path</div><div class=\"value\">{escape(str(active_config_path()))}</div>"
                f"<div class=\"label\">Data directory</div><div class=\"value\">{escape(str(data_dir))}</div>"
                f"<div class=\"label\">Install log</div><div class=\"value\">{escape(str(install.get('log_path', '-')))}</div>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/recovery-install-confirm\">Reinstall/reconfigure watchdog service</a><a class=\"ghost\" href=\"/diagnostics\">Open diagnostics</a></div>"
                "<p class=\"muted\">Reinstall copies the systemd unit, reloads systemd, enables the service, and restarts va-watchdog. It does not remove config or data.</p>"
                "</div>"
                "<div class=\"card\"><h2>Recovery Policy Matrix</h2>"
                "<table><thead><tr><th>Service</th><th>Critical</th><th>Restart allowed</th></tr></thead>"
                f"<tbody>{''.join(service_rows)}</tbody></table>"
                "<p class=\"muted\">Service restart controls are deliberately kept in Settings/Recovery policy first; manual per-service restart buttons can be added once the field rules are confirmed.</p>"
                "</div></div>"
            )

        def history_page():
            samples = read_history(cfg, limit=288)
            summary = history_summary(samples)
            retention = cfg.get("retention", {})
            latest = samples[-1] if samples else {}
            state_rows = []
            for state, count in summary.get("state_counts", {}).items():
                state_rows.append(
                    "<tr>"
                    f"<td class=\"{escape(str(state))}\">{escape(str(state).upper())}</td>"
                    f"<td>{escape(str(count))}</td>"
                    "</tr>"
                )
            if not state_rows:
                state_rows.append("<tr><td colspan=\"2\">No states recorded.</td></tr>")
            rows = []
            for item in samples[-48:]:
                rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('time', '-')))}</td>"
                    f"<td class=\"{escape(str(item.get('state', 'unknown')))}\">{escape(str(item.get('state', 'unknown')).upper())}</td>"
                    f"<td>{escape(str(item.get('score', '-')))}%</td>"
                    f"<td>{escape(str(item.get('temperature', '-')))}</td>"
                    f"<td>{escape(str(item.get('cpu_load', '-')))}%</td>"
                    f"<td>{escape(str(item.get('ram', '-')))}%</td>"
                    f"<td>{escape(str(item.get('root_disk', '-')))}%</td>"
                    f"<td>{escape(str(item.get('recordings_disk', '-')))}%</td>"
                    "</tr>"
                )
            if not rows:
                rows.append("<tr><td colspan=\"8\">No history samples have been captured yet.</td></tr>")
            return (
                "<div class=\"grid metric-grid\">"
                f"<div class=\"tile\"><h3>Samples</h3><div class=\"tile-value\">{escape(str(summary.get('samples', 0)))}</div><div class=\"tile-detail\">Stored history rows</div></div>"
                f"<div class=\"tile\"><h3>Latest Score</h3><div class=\"tile-value {'healthy' if not latest.get('critical_failed') else 'critical'}\">{escape(str(latest.get('score', '-')))}%</div><div class=\"tile-detail\">{escape(str(latest.get('time', '-')))}</div></div>"
                f"<div class=\"tile\"><h3>Average Score</h3><div class=\"tile-value\">{escape(str(summary.get('avg_score', '-')))}%</div><div class=\"tile-detail\">Recent retained window</div></div>"
                f"<div class=\"tile\"><h3>Lowest Score</h3><div class=\"tile-value {'warning' if summary.get('min_score') not in ('-', None) and float(summary.get('min_score')) < 95 else 'healthy'}\">{escape(str(summary.get('min_score', '-')))}%</div><div class=\"tile-detail\">Worst recorded score</div></div>"
                f"<div class=\"tile\"><h3>Critical Samples</h3><div class=\"tile-value {'critical' if summary.get('critical_count', 0) else 'healthy'}\">{escape(str(summary.get('critical_count', 0)))}</div><div class=\"tile-detail\">critical_failed true</div></div>"
                f"<div class=\"tile\"><h3>Retention</h3><div class=\"tile-value\">{escape(str(retention.get('history_retention_days', '-')))}d</div><div class=\"tile-detail\">sample every {escape(str(retention.get('history_sample_seconds', '-')))}s</div></div>"
                "</div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Health Score Trend</h2>"
                f"{history_chart(samples, 'score', 0, 100, '%')}"
                "</div>"
                "<div class=\"card\"><h2>CPU/RAM Trend</h2>"
                f"{multi_history_chart(samples, [('cpu_load', 'CPU load'), ('ram', 'RAM')], 0, 100, '%')}"
                "</div></div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Temperature Trend</h2>"
                f"{history_chart(samples, 'temperature', 0, 100, 'C')}"
                "</div>"
                "<div class=\"card\"><h2>Disk Usage Trend</h2>"
                f"{multi_history_chart(samples, [('root_disk', 'Root'), ('recordings_disk', 'Recordings')], 0, 100, '%')}"
                "</div></div>"
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>State Counts</h2>"
                "<table><thead><tr><th>State</th><th>Samples</th></tr></thead>"
                f"<tbody>{''.join(state_rows)}</tbody></table>"
                "</div>"
                "<div class=\"card\"><h2>History Storage</h2>"
                f"<div class=\"label\">History file</div><div class=\"value\">{escape(str(history_path(cfg)))}</div>"
                f"<div class=\"label\">Max rows</div><div class=\"value\">{escape(str(retention.get('history_max_rows', '-')))}</div>"
                f"<div class=\"label\">Time range</div><div class=\"value\">{escape(str(summary.get('first_time', '-')))} to {escape(str(summary.get('last_time', '-')))}</div>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/api/history\">Export JSON</a><a class=\"ghost\" href=\"/api/history/export.csv\">Export CSV</a></div>"
                "</div></div>"
                "<div class=\"card\"><h2>Recent Samples</h2>"
                "<table><thead><tr><th>Time</th><th>State</th><th>Score</th><th>Temp</th><th>CPU</th><th>RAM</th><th>Root Disk</th><th>Recordings Disk</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table></div>"
            )

        def diagnostics_page():
            service_status = _run(["systemctl", "is-active", "va-watchdog"], timeout=3)
            service_enabled = _run(["systemctl", "is-enabled", "va-watchdog"], timeout=3)
            return (
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Diagnostics</h2>"
                f"<div class=\"label\">Service active</div><div class=\"value {escape(str(service_status.get('stdout', 'unknown')))}\">{escape(str(service_status.get('stdout') or service_status.get('stderr') or 'unknown'))}</div>"
                f"<div class=\"label\">Service enabled</div><div class=\"value\">{escape(str(service_enabled.get('stdout') or service_enabled.get('stderr') or 'unknown'))}</div>"
                f"<div class=\"label\">Status path</div><div class=\"value\">{escape(str(status_path))}</div>"
                f"<div class=\"label\">Events path</div><div class=\"value\">{escape(str(events_path))}</div>"
                "</div>"
                "<div class=\"card\"><h2>Useful Commands</h2>"
                "<pre>systemctl status va-watchdog\njournalctl -u va-watchdog -n 80 --no-pager\nwget -qO- http://127.0.0.1:9110/api/healthz\nwget -qO- http://127.0.0.1:9110/api/version</pre>"
                "</div></div>"
                + all_checks_table("Diagnostics Checks")
            )

        error_html = ""
        if status.get("error"):
            error_html = f"<p class=\"critical\">{escape(str(status.get('error')))}</p>"
        issue_pill = "<span class=\"pill\">No critical issues</span>"
        if critical:
            issue_pill = "<span class=\"pill critical\">Critical issue</span>"
        overview_html = (
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
            "<div class=\"label\">Current version</div>"
            f"<div class=\"build-badge\">{escape(str(version.get('commit', '-')))}</div>"
            f"<div class=\"value\">{escape(str(version.get('branch', '-')))}</div>"
            "</div>"
            "<div>"
            f"<div class=\"label\">Config</div><div class=\"value\">{escape(str(version.get('config_path', '-')))}</div>"
            f"<div class=\"label\">Data</div><div class=\"value\">{escape(str(version.get('data_dir', '-')))}</div>"
            "<button class=\"action\" onclick=\"window.location.reload()\">Refresh dashboard</button>"
            "<form class=\"inline\" method=\"post\" action=\"/update-now\"><button class=\"ghost\" type=\"submit\">Update watchdog</button></form>"
            "</div>"
            f"{error_html}"
            "</div>"
            "<div class=\"card\"><h2>Health Breakdown</h2>"
            f"<div class=\"donut\" style=\"--score:{escape(str(status.get('score', 0)))}\"><span>{escape(str(status.get('score', '-')))}%</span></div>"
            "<div class=\"breakdown-row\"><span>Critical failed</span><strong>" + escape(str(critical).lower()) + "</strong></div>"
            "<div class=\"breakdown-row\"><span>Total checks</span><strong>" + escape(str(len(checks))) + "</strong></div>"
            "<div class=\"breakdown-row\"><span>Mode</span><strong>Compatibility</strong></div>"
            "</div></div>"
            + metric_tiles()
            + "<div class=\"grid lower-grid\">"
            + services_card()
            + f"<div class=\"card\"><h2>Recent Events</h2><div class=\"events\">{event_rows()}</div></div>"
            "</div>"
            "<div class=\"grid bottom-grid\">"
            "<div class=\"card\"><h2>System Information</h2>"
            f"<div class=\"label\">Repository</div><div class=\"value\">{escape(str(version.get('repo_root', '-')))}</div>"
            f"<div class=\"label\">Remote</div><div class=\"value\">{escape(str(version.get('remote', '-')))}</div>"
            "<div class=\"label\">Dashboard</div><div class=\"value\">Server-rendered compatibility appliance view</div>"
            "</div>"
            + updates_card()
            + "</div>"
            + "<div class=\"card\"><h2>Next Sections</h2>"
            "<ul><li>Hardware deep probes</li><li>Settings service/path editor</li><li>Diagnostics support bundle</li></ul>"
            "</div>"
            + "<div class=\"card\"><h2>Health History</h2>"
            + history_chart(read_history(cfg, limit=60), "score", 0, 100, "%")
            + "<a class=\"ghost\" href=\"/history\">Open History</a>"
            + "</div>"
            + all_checks_table()
        )

        if page == "Overview":
            return overview_html
        if page == "Hardware":
            return hardware_page()
        if page == "Services":
            return services_card()
        if page == "Storage":
            return storage_page()
        if page == "Network":
            return network_page()
        if page == "Recovery":
            return recovery_page()
        if page == "Events":
            return events_page(limit=50)
        if page == "History":
            return history_page()
        if page == "Settings":
            return settings_card()
        if page == "Updates":
            return updates_card()
        if page == "Diagnostics":
            return diagnostics_page() + "<div class=\"card\"><h2>Raw Status</h2><pre>" + escape(json.dumps(status, indent=2)) + "</pre></div>"
        return overview_html

    def html_page(route_path="/"):
        page = page_name_for_path(route_path)
        return (
            HTML.replace("__BASIC_DASHBOARD__", basic_dashboard_html(page))
            .replace("__SERVER_NAV__", server_nav_html(page))
            .replace("__PAGE_TITLE__", page)
        )

    def update_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        current_version = version_info()
        before_commit = result.get("before_commit") or current_version.get("commit", "-")
        target_branch = result.get("branch") or current_version.get("branch", "-")
        body = (
                "<meta http-equiv=\"refresh\" content=\"20;url=/\">"
                "<div class=\"card\">"
                "<h2>Watchdog Update</h2>"
                "<p class=\"muted\">This page will return to the dashboard automatically in 20 seconds.</p>"
                f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Update request sent.')))}</p>"
                f"<div class=\"label\">Version before update</div><div class=\"build-badge\">{escape(str(before_commit))}</div>"
                f"<div class=\"label\">Target branch</div><div class=\"value\">{escape(str(target_branch))}</div>"
                f"<div class=\"label\">Current served version</div><div class=\"value\">{escape(str(current_version.get('branch', '-')))} / {escape(str(current_version.get('commit', '-')))}</div>"
                f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
                f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
                "<p class=\"muted\">If the update succeeds, the watchdog service will restart. Wait 10-20 seconds, then reload the dashboard.</p>"
                "<form class=\"inline\" method=\"get\" action=\"/\"><button class=\"action\" type=\"submit\">Back to dashboard</button></form>"
                "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Updates"))
            .replace("__PAGE_TITLE__", "Updates")
        )

    def settings_saved_html(result):
        ok = bool(result.get("ok"))
        status_class = "healthy" if ok else "critical"
        message = f"Settings saved to {result.get('path', '-')}" if ok else result.get("error", "Settings save failed")
        body = (
            "<meta http-equiv=\"refresh\" content=\"8;url=/settings\">"
            "<div class=\"card\">"
            "<h2>Settings</h2>"
            f"<p class=\"{status_class}\">{escape(str(message))}</p>"
            "<p class=\"muted\">This page will return to Settings automatically in 8 seconds.</p>"
            "<a class=\"ghost\" href=\"/settings\">Back to Settings</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Settings"))
            .replace("__PAGE_TITLE__", "Settings")
        )

    def storage_purge_confirm_html():
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Storage Purge</h2>"
            "<p class=\"warning\">This will remove all non-status watchdog data files.</p>"
            "<p class=\"muted\">It removes events, history, update state/logs, and reboot reason files. It does not remove status.json, config files, or recordings.</p>"
            "<form class=\"inline\" method=\"post\" action=\"/storage-purge-all\"><button class=\"action\" type=\"submit\">Confirm purge all non-status data</button></form> "
            "<a class=\"ghost\" href=\"/storage\">Cancel</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Storage"))
            .replace("__PAGE_TITLE__", "Storage")
        )

    def storage_purge_result_html(result, mode):
        removed = result.get("removed", [])
        rows = []
        for item in removed:
            if isinstance(item, dict):
                rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('path', '-')))}</td>"
                    f"<td>{escape(human_size(item.get('size_bytes', 0)))}</td>"
                    "</tr>"
                )
            else:
                rows.append(f"<tr><td>{escape(str(item))}</td><td>-</td></tr>")
        if not rows:
            rows.append("<tr><td colspan=\"2\">No files matched the purge rule.</td></tr>")
        retention = result.get("retention", {})
        body = (
            "<meta http-equiv=\"refresh\" content=\"8;url=/storage\">"
            "<div class=\"card\">"
            f"<h2>Storage Purge {'Complete' if mode != 'all' else 'Complete'}</h2>"
            "<p class=\"healthy\">Purge command finished.</p>"
            f"<div class=\"label\">Used after purge</div><div class=\"value\">{escape(str(retention.get('used_mb', '-')))} MB / {escape(str(retention.get('max_total_mb', '-')))} MB</div>"
            "<table><thead><tr><th>Removed file</th><th>Size</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "<p class=\"muted\">This page will return to Storage automatically in 8 seconds.</p>"
            "<a class=\"ghost\" href=\"/storage\">Back to Storage</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Storage"))
            .replace("__PAGE_TITLE__", "Storage")
        )

    def recovery_install_confirm_html():
        install = install_status()
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Watchdog Reinstall</h2>"
            "<p class=\"warning\">This will reconfigure the VA-Connect Watchdog service and restart va-watchdog.</p>"
            "<p class=\"muted\">It runs v3/scripts/install.sh from the current repository. Existing config and watchdog data are kept.</p>"
            f"<div class=\"label\">Install path</div><div class=\"value\">{escape(str(install.get('install_path', '-')))}</div>"
            f"<div class=\"label\">Unit path</div><div class=\"value\">{escape(str(install.get('unit_path', '-')))}</div>"
            f"<div class=\"label\">Log path</div><div class=\"value\">{escape(str(install.get('log_path', '-')))}</div>"
            "<form class=\"inline\" method=\"post\" action=\"/recovery-install-now\"><button class=\"action\" type=\"submit\">Confirm reinstall/reconfigure</button></form> "
            "<a class=\"ghost\" href=\"/recovery\">Cancel</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Recovery"))
            .replace("__PAGE_TITLE__", "Recovery")
        )

    def recovery_install_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/recovery\">"
            "<div class=\"card\">"
            "<h2>Watchdog Reinstall</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Install request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Recovery automatically in 20 seconds. The watchdog service may restart during this time.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/recovery\">Back to Recovery</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Recovery"))
            .replace("__PAGE_TITLE__", "Recovery")
        )

    def itco_install_confirm_html():
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Intel TCO Watchdog Setup</h2>"
            "<p class=\"warning\">This will load the Intel TCO watchdog kernel driver and persist it across reboot.</p>"
            "<p class=\"muted\">It runs v3/scripts/setup_itco_watchdog.sh. It does not enable VA-Connect hardware feeding and does not intentionally reboot the gateway.</p>"
            "<div class=\"label\">Expected driver</div><div class=\"value\">iTCO_wdt</div>"
            "<div class=\"label\">Expected device after success</div><div class=\"value\">/dev/watchdog0</div>"
            "<div class=\"label\">Expected identity</div><div class=\"value\">iTCO_wdt [version 6]</div>"
            "<form class=\"inline\" method=\"post\" action=\"/itco-watchdog-install-now\"><button class=\"action\" type=\"submit\">Confirm install/load Intel TCO</button></form> "
            "<a class=\"ghost\" href=\"/hardware\">Cancel</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def itco_install_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Intel TCO Watchdog Setup</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Setup request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Hardware automatically in 20 seconds. Reload Hardware after that to see module/device status.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/hardware\">Back to Hardware</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def watchdog_probe_confirm_html():
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Full Watchdog Hardware Probe</h2>"
            "<p class=\"warning\">This will run the full Intel TCO/watchdog diagnostic command set on the gateway.</p>"
            "<p class=\"muted\">It includes sudo modprobe iTCO_wdt, wdctl /dev/watchdog0, dmesg checks, systemd checks, and module/autoload checks. It does not enable VA-Connect hardware feeding.</p>"
            "<form class=\"inline\" method=\"post\" action=\"/watchdog-hardware-probe-now\"><button class=\"action\" type=\"submit\">Run full watchdog probe</button></form> "
            "<a class=\"ghost\" href=\"/hardware\">Cancel</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def watchdog_probe_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Watchdog Hardware Probe</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Probe request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Hardware automatically in 20 seconds. Reload Hardware to see the full probe log.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/hardware\">Back to Hardware</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def service_detail_html(name):
        detail = service_detail(name)
        if not detail.get("ok"):
            body = (
                "<div class=\"card\">"
                "<h2>Service Detail</h2>"
                f"<p class=\"critical\">{escape(str(detail.get('error', 'Service not found')))}</p>"
                "<a class=\"ghost\" href=\"/services\">Back to Services</a>"
                "</div>"
            )
        else:
            svc = detail.get("service", {})
            body = (
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Service Detail</h2>"
                f"<div class=\"label\">Name</div><div class=\"value\">{escape(str(svc.get('name', '-')))}</div>"
                f"<div class=\"label\">Description</div><div class=\"value\">{escape(str(svc.get('description', '-')))}</div>"
                f"<div class=\"label\">Active</div><div class=\"value {'healthy' if svc.get('active') == 'active' else 'critical' if svc.get('critical') else 'warning'}\">{escape(str(svc.get('active', '-')).upper())}</div>"
                f"<div class=\"label\">Substate</div><div class=\"value\">{escape(str(svc.get('sub_state', '-')))}</div>"
                f"<div class=\"label\">Enabled</div><div class=\"value\">{escape(str(svc.get('unit_file_state', '-')))}</div>"
                f"<div class=\"label\">Main PID</div><div class=\"value\">{escape(str(svc.get('main_pid', '-')))}</div>"
                f"<div class=\"label\">Uptime</div><div class=\"value\">{escape(str(svc.get('uptime', '-')))}</div>"
                f"<div class=\"label\">Critical</div><div class=\"value\">{'Yes' if svc.get('critical') else 'No'}</div>"
                f"<div class=\"label\">Restart allowed by policy</div><div class=\"value\">{'Yes' if svc.get('restart') else 'No'}</div>"
                "<div class=\"button-row\">"
                f"<a class=\"ghost\" href=\"/service-restart-confirm/{quote(str(svc.get('name', '')))}\">Restart service</a>"
                "<a class=\"ghost\" href=\"/services\">Back to Services</a>"
                "</div>"
                "</div>"
                "<div class=\"card\"><h2>Systemd Properties</h2>"
                f"<pre>{escape(json.dumps(svc.get('properties', {}), indent=2))}</pre>"
                "</div></div>"
                "<div class=\"card\"><h2>systemctl status</h2>"
                f"<pre>{escape(str(detail.get('status', '')))}</pre>"
                "</div>"
                "<div class=\"card\"><h2>Recent Journal</h2>"
                f"<pre>{escape(str(detail.get('journal', '')))}</pre>"
                "</div>"
            )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Services"))
            .replace("__PAGE_TITLE__", "Services")
        )

    def service_restart_confirm_html(name):
        detail = service_detail(name)
        if not detail.get("ok"):
            body = (
                "<div class=\"card\">"
                "<h2>Restart Service</h2>"
                f"<p class=\"critical\">{escape(str(detail.get('error', 'Service not found')))}</p>"
                "<a class=\"ghost\" href=\"/services\">Back to Services</a>"
                "</div>"
            )
        else:
            svc = detail.get("service", {})
            body = (
                "<div class=\"card\">"
                "<h2>Confirm Service Restart</h2>"
                f"<p class=\"warning\">Restart {escape(str(svc.get('name', '-')))}?</p>"
                "<p class=\"muted\">This runs systemctl restart for a configured watchdog service only. It may briefly interrupt gateway operation.</p>"
                f"<div class=\"label\">Current state</div><div class=\"value\">{escape(str(svc.get('active', '-')))} / {escape(str(svc.get('sub_state', '-')))}</div>"
                f"<div class=\"label\">Policy critical</div><div class=\"value\">{'Yes' if svc.get('critical') else 'No'}</div>"
                "<form class=\"inline\" method=\"post\" action=\"/service-restart-now\">"
                f"<input type=\"hidden\" name=\"service\" value=\"{escape(str(svc.get('name', '')))}\">"
                "<button class=\"action\" type=\"submit\">Confirm restart</button>"
                "</form> "
                "<a class=\"ghost\" href=\"/services\">Cancel</a>"
                "</div>"
            )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Services"))
            .replace("__PAGE_TITLE__", "Services")
        )

    def service_restart_result_html(result):
        ok = bool(result.get("ok"))
        body = (
            "<meta http-equiv=\"refresh\" content=\"8;url=/services\">"
            "<div class=\"card\">"
            "<h2>Service Restart</h2>"
            f"<p class=\"{'healthy' if ok else 'critical'}\">{escape(str(result.get('message', 'Restart finished.')))}</p>"
            f"<div class=\"label\">Service</div><div class=\"value\">{escape(str(result.get('service', '-')))}</div>"
            f"<div class=\"label\">Return code</div><div class=\"value\">{escape(str(result.get('returncode', '-')))}</div>"
            f"<div class=\"label\">Output</div><pre>{escape(str(result.get('output', '')))}</pre>"
            "<p class=\"muted\">This page will return to Services automatically in 8 seconds.</p>"
            "<a class=\"ghost\" href=\"/services\">Back to Services</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Services"))
            .replace("__PAGE_TITLE__", "Services")
        )

    def watchdog_test_armed_html(result):
        body = (
            "<meta http-equiv=\"refresh\" content=\"45;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Safe Watchdog Test Armed</h2>"
            "<p class=\"warning\">Second knock required.</p>"
            "<p class=\"muted\">This test is armed for 45 seconds. Confirming will verify watchdog config, device presence, and recent feed state. It will not intentionally reboot the gateway.</p>"
            f"<div class=\"label\">Armed at</div><div class=\"value\">{escape(str(result.get('armed_at', '-')))}</div>"
            "<form class=\"inline\" method=\"post\" action=\"/watchdog-test-run\">"
            f"<input type=\"hidden\" name=\"token\" value=\"{escape(str(result.get('token', '')))}\">"
            "<button class=\"action\" type=\"submit\">Second knock: run safe test</button>"
            "</form> "
            "<a class=\"ghost\" href=\"/hardware\">Cancel</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def watchdog_test_result_html(result):
        ok = bool(result.get("ok"))
        checks = result.get("checks", [])
        rows = []
        for check in checks:
            state = str(check.get("state", "unknown"))
            rows.append(
                "<tr>"
                f"<td>{escape(str(check.get('name', '-')))}</td>"
                f"<td class=\"{escape(state)}\">{escape(state.upper())}</td>"
                f"<td>{escape(str(check.get('message', '-')))}</td>"
                "</tr>"
            )
        if not rows:
            rows.append("<tr><td colspan=\"3\">No checks were run.</td></tr>")
        body = (
            "<meta http-equiv=\"refresh\" content=\"12;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Safe Watchdog Test Result</h2>"
            f"<p class=\"{'healthy' if ok else 'warning'}\">{escape(str(result.get('message', 'Test complete')))}</p>"
            f"<div class=\"label\">Test time</div><div class=\"value\">{escape(str(result.get('tested_at', '-')))}</div>"
            "<table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "<p class=\"muted\">This page will return to Hardware automatically in 12 seconds.</p>"
            "<a class=\"ghost\" href=\"/hardware\">Back to Hardware</a>"
            "</div>"
        )
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html("Hardware"))
            .replace("__PAGE_TITLE__", "Hardware")
        )

    def settings_payload_from_form(form):
        def first(name, default=""):
            return form.get(name, [default])[0]

        def lines(name):
            return [line.strip() for line in first(name).splitlines() if line.strip()]

        return {
            "poll_interval_seconds": first("poll_interval_seconds", "5"),
            "thresholds": {
                "root_disk_warning_percent": first("root_disk_warning_percent", "80"),
                "root_disk_critical_percent": first("root_disk_critical_percent", "95"),
                "recordings_disk_warning_percent": first("recordings_disk_warning_percent", "85"),
                "recordings_disk_critical_percent": first("recordings_disk_critical_percent", "95"),
            },
            "retention": {
                "max_total_mb": first("max_total_mb", "100"),
                "history_sample_seconds": first("history_sample_seconds", "60"),
                "history_retention_days": first("history_retention_days", "30"),
            },
            "network": {
                "internet_hosts": lines("internet_hosts"),
                "local_targets": lines("local_targets"),
                "remote_access_services": lines("remote_access_services"),
            },
            "update": {
                "remote": first("update_remote", "origin"),
                "branch": first("update_branch", ""),
            },
            "hardware_watchdog": {
                "enabled": bool(cfg.get("hardware_watchdog", {}).get("enabled", False)),
            },
            "recovery": {
                "enabled": "recovery_enabled" in form,
                "restart_failed_services": "restart_failed_services" in form,
                "allow_reboot": "allow_reboot" in form,
            },
        }

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
        return retention_status_for_cfg(cfg)

    def purge_data(mode="old", older_than_days=None):
        return retention_purge_data(cfg, mode=mode, older_than_days=older_than_days)

    def human_size(size_bytes):
        try:
            size = float(size_bytes or 0)
        except (TypeError, ValueError):
            size = 0
        units = ["B", "KB", "MB", "GB"]
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024

    def unix_time(value):
        if not value:
            return "-"
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
        except (TypeError, ValueError, OSError):
            return "-"

    def watchdog_test_path():
        return data_dir / "watchdog-test.json"

    def write_watchdog_test_state(payload):
        path = watchdog_test_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def read_watchdog_test_state():
        path = watchdog_test_path()
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def append_web_event(level, source, message, data=None):
        event = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "level": level,
            "source": source,
            "message": message,
            "data": data or {},
        }
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def watchdog_test_summary():
        status = status_snapshot()
        hw_cfg = cfg.get("hardware_watchdog", {})
        feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
        device = str(hw_cfg.get("device", "/dev/watchdog0"))
        device_exists = Path(device).exists()
        driver = watchdog_driver_info(sorted(str(path) for path in Path("/dev").glob("watchdog*")))
        wdctl = driver.get("wdctl", {})
        last_feed = feed.get("last_feed_unix")
        feed_interval = int(hw_cfg.get("feed_interval_seconds", 10) or 10)
        stale_after = max(feed_interval * 3, int(cfg.get("poll_interval_seconds", 5) or 5) * 3, 30)
        age = None
        if last_feed:
            try:
                age = max(0, time.time() - float(last_feed))
            except (TypeError, ValueError):
                age = None
        feed_enabled = bool(feed.get("enabled") or hw_cfg.get("enabled"))
        if not feed_enabled:
            feed_state = "warning"
            last_feed_message = "Feed disabled in config/status"
        elif age is None:
            feed_state = "warning"
            last_feed_message = "No feed timestamp recorded yet"
        elif age <= stale_after:
            feed_state = "healthy"
            last_feed_message = f"Last feed {round(age, 1)}s ago"
        else:
            feed_state = "warning"
            last_feed_message = f"Last feed stale: {round(age, 1)}s ago"

        state = read_watchdog_test_state()
        last = state.get("last_result", {})
        last_test_message = ""
        if last:
            last_test_message = f"{last.get('tested_at', '-')} - {last.get('message', '-')}"
        return {
            "device": device,
            "device_state": "healthy" if device_exists else "warning",
            "device_message": "present" if device_exists else "not present",
            "driver_identity": wdctl.get("identity", "-"),
            "driver_timeout": wdctl.get("timeout", "-"),
            "feed_enabled": feed_enabled,
            "opened": bool(feed.get("opened")),
            "feed_count": feed.get("feed_count", 0),
            "feed_state": feed_state,
            "last_feed_message": last_feed_message,
            "last_test_message": last_test_message,
        }

    def systemd_watchdog_info():
        props = _run([
            "systemctl",
            "show",
            "va-watchdog",
            "-p",
            "WatchdogUSec",
            "-p",
            "WatchdogTimestamp",
            "-p",
            "StatusText",
            "-p",
            "Type",
        ], timeout=3)
        values = {}
        for line in props["stdout"].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        usec = int(values.get("WatchdogUSec", "0") or 0)
        watchdog_sec = round(usec / 1000000, 1) if usec else 0
        if watchdog_sec:
            state = "healthy"
            message = "Enabled"
        else:
            state = "warning"
            message = "Not enabled in installed systemd unit yet"
        return {
            "state": state,
            "message": message,
            "watchdog_sec": f"{watchdog_sec}s" if watchdog_sec else "0s",
            "timestamp": values.get("WatchdogTimestamp", ""),
            "status_text": values.get("StatusText", ""),
            "type": values.get("Type", ""),
            "raw": values,
        }

    def arm_watchdog_test():
        now = time.time()
        token = secrets.token_urlsafe(18)
        state = read_watchdog_test_state()
        state["armed"] = {
            "token": token,
            "armed_at_unix": now,
            "expires_at_unix": now + 45,
            "armed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        }
        write_watchdog_test_state(state)
        append_web_event("info", "watchdog_test", "Safe watchdog test armed", {"expires_at_unix": now + 45})
        return {"token": token, "armed_at": state["armed"]["armed_at"], "expires_at_unix": now + 45}

    def run_watchdog_test(token):
        now = time.time()
        state = read_watchdog_test_state()
        armed = state.get("armed", {}) if isinstance(state.get("armed", {}), dict) else {}
        if not token or token != armed.get("token"):
            return {"ok": False, "message": "Second knock failed: test token did not match.", "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "checks": []}
        if now > float(armed.get("expires_at_unix", 0) or 0):
            return {"ok": False, "message": "Second knock expired. Arm the test again.", "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "checks": []}

        status = status_snapshot()
        hw_cfg = cfg.get("hardware_watchdog", {})
        feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
        device = str(hw_cfg.get("device", "/dev/watchdog0"))
        feed_interval = int(hw_cfg.get("feed_interval_seconds", 10) or 10)
        stale_after = max(feed_interval * 3, int(cfg.get("poll_interval_seconds", 5) or 5) * 3, 30)
        checks = []

        device_exists = Path(device).exists()
        checks.append({
            "name": "device_present",
            "state": "healthy" if device_exists else "warning",
            "message": f"{device} present" if device_exists else f"{device} not present",
        })

        feed_enabled = bool(feed.get("enabled") or hw_cfg.get("enabled"))
        checks.append({
            "name": "feed_enabled",
            "state": "healthy" if feed_enabled else "warning",
            "message": "Hardware watchdog feed enabled" if feed_enabled else "Hardware watchdog feed disabled",
        })

        last_feed = feed.get("last_feed_unix")
        age = None
        if last_feed:
            try:
                age = max(0, now - float(last_feed))
            except (TypeError, ValueError):
                age = None
        if not feed_enabled:
            feed_state = "warning"
            feed_message = "Feed disabled; no live feed expected"
        elif age is None:
            feed_state = "warning"
            feed_message = "No feed timestamp recorded"
        elif age <= stale_after:
            feed_state = "healthy"
            feed_message = f"Feed is recent: {round(age, 1)}s old"
        else:
            feed_state = "warning"
            feed_message = f"Feed is stale: {round(age, 1)}s old"
        checks.append({"name": "feed_freshness", "state": feed_state, "message": feed_message})

        critical_failed = bool(status.get("critical_failed", False))
        checks.append({
            "name": "health_allows_feed",
            "state": "healthy" if not critical_failed else "warning",
            "message": "No critical checks blocking feed" if not critical_failed else "Critical health is currently blocking feed",
        })

        systemd_wdt = systemd_watchdog_info()
        checks.append({
            "name": "systemd_watchdog_fallback",
            "state": systemd_wdt.get("state", "unknown"),
            "message": f"{systemd_wdt.get('message', '-')}; WatchdogSec {systemd_wdt.get('watchdog_sec', '-')}",
        })

        hardware_ok = device_exists and feed_enabled and any(check.get("name") == "feed_freshness" and check.get("state") == "healthy" for check in checks)
        fallback_ok = systemd_wdt.get("state") == "healthy"
        ok = (hardware_ok or fallback_ok) and not critical_failed
        result = {
            "ok": ok,
            "message": "Safe watchdog test passed" if ok else "Safe watchdog test completed with warnings",
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "checks": checks,
            "hardware_ok": hardware_ok,
            "systemd_fallback_ok": fallback_ok,
        }
        state["last_result"] = result
        state.pop("armed", None)
        write_watchdog_test_state(state)
        append_web_event("healthy" if ok else "warning", "watchdog_test", result["message"], result)
        return result

    def numeric_values(rows, key):
        values = []
        for row in rows:
            try:
                value = row.get(key)
                if value is None or value == "":
                    continue
                values.append(float(value))
            except (TypeError, ValueError):
                continue
        return values

    def history_summary(rows):
        scores = numeric_values(rows, "score")
        state_counts = {}
        critical_count = 0
        for row in rows:
            state = str(row.get("display_state") or row.get("state") or "unknown")
            state_counts[state] = state_counts.get(state, 0) + 1
            if row.get("critical_failed"):
                critical_count += 1
        return {
            "samples": len(rows),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else "-",
            "min_score": round(min(scores), 1) if scores else "-",
            "max_score": round(max(scores), 1) if scores else "-",
            "critical_count": critical_count,
            "state_counts": state_counts,
            "first_time": rows[0].get("time") if rows else "-",
            "last_time": rows[-1].get("time") if rows else "-",
        }

    def history_chart(rows, key, min_value=0, max_value=100, suffix=""):
        return multi_history_chart(rows, [(key, key)], min_value, max_value, suffix)

    def multi_history_chart(rows, series, min_value=0, max_value=100, suffix=""):
        width = 640
        height = 190
        pad_left = 42
        pad_right = 14
        pad_top = 18
        pad_bottom = 32
        plot_w = width - pad_left - pad_right
        plot_h = height - pad_top - pad_bottom
        clean_rows = rows[-160:]
        if not clean_rows:
            return "<div class=\"history-box\">No history captured yet</div>"

        span = max(1, float(max_value) - float(min_value))
        colors = ["var(--green)", "var(--blue)", "var(--amber)", "var(--orange)"]
        paths = []
        legend = []
        for index, (key, label) in enumerate(series):
            points = []
            usable = []
            for row_index, row in enumerate(clean_rows):
                try:
                    value = row.get(key)
                    if value is None or value == "":
                        continue
                    usable.append((row_index, float(value)))
                except (TypeError, ValueError):
                    continue
            if not usable:
                continue
            for row_index, value in usable:
                x = pad_left + (row_index / max(1, len(clean_rows) - 1)) * plot_w
                clamped = min(float(max_value), max(float(min_value), value))
                y = pad_top + (1 - ((clamped - float(min_value)) / span)) * plot_h
                points.append(f"{x:.1f},{y:.1f}")
            color = colors[index % len(colors)]
            paths.append(f"<polyline points=\"{' '.join(points)}\" style=\"stroke:{color}\"></polyline>")
            latest = usable[-1][1]
            legend.append(f"<span style=\"color:{color}\">{escape(str(label))}: {escape(str(round(latest, 1)))}{escape(suffix)}</span>")
        if not paths:
            return "<div class=\"history-box\">No numeric history for this metric yet</div>"

        first_label = str(clean_rows[0].get("time", ""))[:16].replace("T", " ")
        last_label = str(clean_rows[-1].get("time", ""))[:16].replace("T", " ")
        return (
            "<div class=\"toolbar\">"
            + " ".join(legend)
            + "</div>"
            f"<svg class=\"chart\" viewBox=\"0 0 {width} {height}\" preserveAspectRatio=\"none\">"
            f"<line class=\"grid-line\" x1=\"{pad_left}\" y1=\"{pad_top}\" x2=\"{width - pad_right}\" y2=\"{pad_top}\"></line>"
            f"<line class=\"grid-line\" x1=\"{pad_left}\" y1=\"{pad_top + plot_h / 2}\" x2=\"{width - pad_right}\" y2=\"{pad_top + plot_h / 2}\"></line>"
            f"<line class=\"grid-line\" x1=\"{pad_left}\" y1=\"{pad_top + plot_h}\" x2=\"{width - pad_right}\" y2=\"{pad_top + plot_h}\"></line>"
            f"<text x=\"4\" y=\"{pad_top + 4}\">{escape(str(max_value))}{escape(suffix)}</text>"
            f"<text x=\"4\" y=\"{pad_top + plot_h + 4}\">{escape(str(min_value))}{escape(suffix)}</text>"
            f"<text x=\"{pad_left}\" y=\"{height - 8}\">{escape(first_label)}</text>"
            f"<text x=\"{width - 190}\" y=\"{height - 8}\">{escape(last_label)}</text>"
            + "".join(paths)
            + "</svg>"
        )

    def install_status():
        root = repo_root()
        unit_path = Path("/etc/systemd/system/va-watchdog.service")
        active = _run(["systemctl", "is-active", "va-watchdog"], timeout=3)
        enabled = _run(["systemctl", "is-enabled", "va-watchdog"], timeout=3)
        log_path = Path(cfg.get("update", {}).get("log_path") or data_dir / "update.log").with_name("install.log")
        return {
            "install_path": str(root.parent),
            "repo_root": str(root),
            "install_script": str(root / "scripts" / "install.sh"),
            "unit_path": str(unit_path),
            "unit_state": "healthy" if unit_path.exists() else "warning",
            "active": active["stdout"] or active["stderr"] or "unknown",
            "enabled": enabled["stdout"] or enabled["stderr"] or "unknown",
            "log_path": str(log_path),
            "last_log": tail_file(log_path).get("tail", ""),
        }

    def last_reboot_reason():
        path = Path(cfg.get("last_reboot_reason_path") or data_dir / "last-reboot-reason.json")
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {"value": payload}
        except Exception as exc:
            return {"error": str(exc), "path": str(path)}

    def launch_recovery_install():
        install = install_status()
        script = Path(install["install_script"])
        log_path = Path(install["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Install script not found: {script}", "log_path": str(log_path)}
        command = f"sleep 2; cd {repo_root()!s}; /bin/bash scripts/install.sh >> {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {"ok": False, "message": f"Could not start install: {exc}", "command": command, "log_path": str(log_path)}
        return {
            "ok": True,
            "message": "Watchdog reinstall/reconfigure started in the background.",
            "command": command,
            "log_path": str(log_path),
        }

    def itco_setup_status():
        log_path = data_dir / "itco-watchdog-setup.log"
        return {
            "script": str(repo_root() / "scripts" / "setup_itco_watchdog.sh"),
            "log_path": str(log_path),
            "last_log": tail_file(log_path, lines=80).get("tail", ""),
        }

    def watchdog_probe_status():
        log_path = data_dir / "watchdog-hardware-probe.log"
        return {
            "script": str(repo_root() / "scripts" / "probe_watchdog_hardware.sh"),
            "log_path": str(log_path),
            "last_log": tail_file(log_path, lines=200).get("tail", ""),
        }

    def launch_itco_setup():
        status = itco_setup_status()
        script = Path(status["script"])
        log_path = Path(status["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Intel TCO setup script not found: {script}", "log_path": str(log_path)}
        command = f"cd {repo_root()!s}; /bin/bash scripts/setup_itco_watchdog.sh >> {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {"ok": False, "message": f"Could not start Intel TCO setup: {exc}", "command": command, "log_path": str(log_path)}
        append_web_event("info", "hardware_watchdog", "Intel TCO watchdog setup started", {"log_path": str(log_path)})
        return {
            "ok": True,
            "message": "Intel TCO watchdog setup started in the background.",
            "command": command,
            "log_path": str(log_path),
        }

    def launch_watchdog_probe():
        status = watchdog_probe_status()
        script = Path(status["script"])
        log_path = Path(status["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Watchdog probe script not found: {script}", "log_path": str(log_path)}
        command = f"cd {repo_root()!s}; /bin/bash scripts/probe_watchdog_hardware.sh > {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {"ok": False, "message": f"Could not start watchdog probe: {exc}", "command": command, "log_path": str(log_path)}
        append_web_event("info", "hardware_watchdog", "Full watchdog hardware probe started", {"log_path": str(log_path)})
        return {
            "ok": True,
            "message": "Full watchdog hardware probe started in the background.",
            "command": command,
            "log_path": str(log_path),
        }

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
            parsed = parse_network_target(str(target))
            result = _run(["ping", "-c", "1", "-W", "1", parsed["host"]], timeout=3)
            detail = ""
            for line in result["stdout"].splitlines():
                if "time=" in line or "packet loss" in line:
                    detail = line.strip()
                    break
            tcp = tcp_check(parsed["host"], parsed["port"]) if parsed["port"] else None
            pings.append({
                "target": target,
                "host": parsed["host"],
                "port": parsed["port"],
                "ping_ok": result["ok"],
                "tcp_ok": tcp.get("ok") if tcp else None,
                "ok": result["ok"] if tcp is None else bool(tcp.get("ok")),
                "detail": detail or result["stderr"] or result["stdout"],
                "tcp_detail": tcp.get("detail") if tcp else "",
            })
        remote_access = []
        for service in network_cfg.get("remote_access_services", []):
            state = _run(["systemctl", "is-active", str(service)], timeout=3)
            enabled = _run(["systemctl", "is-enabled", str(service)], timeout=3)
            status = _run(["systemctl", "show", str(service), "-p", "SubState", "-p", "ActiveEnterTimestamp", "--value"], timeout=3)
            remote_access.append({
                "service": service,
                "active": state["stdout"] == "active",
                "state": state["stdout"] or state["stderr"] or "unknown",
                "enabled": enabled["stdout"] or enabled["stderr"] or "unknown",
                "detail": status["stdout"] or status["stderr"],
                "note": "TeamViewer/remote support service placeholder" if "teamviewer" in str(service).lower() else "",
            })
        web_port = int(cfg.get("web", {}).get("port", 9110))
        local_web = tcp_check("127.0.0.1", web_port)
        route_table = _run(["ip", "route", "show"])["stdout"]
        interfaces = interface_info()
        dns_text = resolv_conf()
        return {
            "ip_addresses": _run(["hostname", "-I"])["stdout"],
            "hostname": platform.node(),
            "default_route": _run(["ip", "route", "show", "default"])["stdout"],
            "route_table": route_table,
            "interfaces": interfaces,
            "neighbours": _run(["ip", "neigh", "show"])["stdout"],
            "dns": dns_text,
            "configured_internet_hosts": network_cfg.get("internet_hosts", []),
            "configured_local_targets": network_cfg.get("local_targets", []),
            "remote_access_services": network_cfg.get("remote_access_services", []),
            "remote_access": remote_access,
            "pings": pings,
            "listening_port": web_port,
            "local_web": local_web,
            "listening_sockets": _run(["ss", "-ltnp"], timeout=3)["stdout"],
            "support_urls": [
                f"http://127.0.0.1:{web_port}/",
                f"http://<gateway-ip>:{web_port}/",
            ],
        }

    def resolv_conf():
        path = Path("/etc/resolv.conf")
        if path.exists():
            return path.read_text(encoding="utf-8", errors="ignore")
        return _run(["resolvectl", "dns"], timeout=3)["stdout"]

    def parse_network_target(target):
        text = target.strip()
        port = None
        host = text
        if "://" in text:
            from urllib.parse import urlparse

            parsed = urlparse(text)
            host = parsed.hostname or text
            port = parsed.port
            if port is None and parsed.scheme == "http":
                port = 80
            elif port is None and parsed.scheme == "https":
                port = 443
        elif ":" in text and text.count(":") == 1:
            maybe_host, maybe_port = text.rsplit(":", 1)
            if maybe_port.isdigit():
                host = maybe_host
                port = int(maybe_port)
        return {"host": host, "port": port}

    def tcp_check(host, port, timeout=1.5):
        try:
            with socket.create_connection((str(host), int(port)), timeout=timeout):
                return {"ok": True, "detail": f"TCP {host}:{port} connected"}
        except Exception as exc:
            return {"ok": False, "detail": f"TCP {host}:{port} failed: {exc}"}

    def interface_info():
        brief = _run(["ip", "-brief", "addr"], timeout=3)["stdout"]
        rows = []
        for line in brief.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                rows.append({
                    "name": parts[0],
                    "state": parts[1],
                    "addresses": " ".join(parts[2:]) if len(parts) > 2 else "",
                })
        if rows:
            return rows
        return [{"name": "-", "state": "unknown", "addresses": brief or "Interface details unavailable"}]

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
            "watchdog": watchdog_driver_info(watchdog_devices),
        }

    def watchdog_driver_info(watchdog_devices):
        modules = {
            "iTCO_wdt": False,
            "iTCO_vendor_support": False,
            "intel_pmc_bxt": False,
        }
        proc_modules = Path("/proc/modules")
        if proc_modules.exists():
            text = proc_modules.read_text(encoding="utf-8", errors="ignore")
            for name in modules:
                modules[name] = any(line.startswith(name + " ") for line in text.splitlines())
        device = "/dev/watchdog0" if "/dev/watchdog0" in watchdog_devices else (watchdog_devices[0] if watchdog_devices else "/dev/watchdog0")
        wdctl = {
            "device": device,
            "state": "warning",
            "identity": "-",
            "timeout": "-",
            "raw": "",
        }
        if Path(device).exists():
            result = _run(["wdctl", device], timeout=4)
            raw = result["stdout"] or result["stderr"]
            wdctl["raw"] = raw
            if result["ok"]:
                wdctl["state"] = "healthy"
            for line in raw.splitlines():
                if "Identity:" in line:
                    wdctl["identity"] = line.split("Identity:", 1)[1].strip()
                elif "Timeout:" in line:
                    wdctl["timeout"] = line.split("Timeout:", 1)[1].strip()
        return {
            "expected_driver": "iTCO_wdt",
            "expected_identity": "iTCO_wdt [version 6]",
            "device": device,
            "modules": modules,
            "wdctl": wdctl,
            "setup_log": itco_setup_status().get("last_log", ""),
            "probe_log": watchdog_probe_status().get("last_log", ""),
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

    def configured_service(name):
        for item in cfg.get("services", []):
            if item.get("name") == name:
                return item
        return None

    def systemctl_show(name, properties=None):
        command = ["systemctl", "show", name]
        if properties:
            for prop in properties:
                command.append(f"--property={prop}")
        result = _run(command, timeout=5)
        values = {}
        for line in result["stdout"].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        return values

    def service_snapshot(item):
        name = item.get("name", "")
        props = systemctl_show(name, [
            "Description",
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "NRestarts",
            "MainPID",
            "ActiveEnterTimestamp",
            "ExecMainStartTimestamp",
            "ExecMainStatus",
            "Result",
            "FragmentPath",
        ])
        active = props.get("ActiveState", "unknown")
        pid = props.get("MainPID", "0")
        ps = _run(["ps", "-p", pid, "-o", "%cpu=,rss=,etimes="]) if pid and pid != "0" else {"stdout": ""}
        cpu_percent = "-"
        memory_mb = "-"
        uptime = "-"
        parts = ps["stdout"].split()
        if len(parts) >= 3:
            cpu_percent = parts[0]
            memory_mb = round(int(parts[1]) / 1024, 1)
            uptime = _format_duration(int(parts[2]))
        return {
            "name": name,
            "description": props.get("Description", ""),
            "load_state": props.get("LoadState", ""),
            "active": active,
            "sub_state": props.get("SubState", ""),
            "unit_file_state": props.get("UnitFileState", ""),
            "restarts": props.get("NRestarts", ""),
            "main_pid": pid,
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "uptime": uptime,
            "active_since": props.get("ActiveEnterTimestamp", ""),
            "exec_started": props.get("ExecMainStartTimestamp", ""),
            "exec_status": props.get("ExecMainStatus", ""),
            "result": props.get("Result", ""),
            "fragment_path": props.get("FragmentPath", ""),
            "critical": bool(item.get("critical", False)),
            "restart": bool(item.get("restart", False)),
            "properties": props,
        }

    def service_info():
        services = []
        for item in cfg.get("services", []):
            services.append(service_snapshot(item))
        return {"services": services}

    def service_detail(name):
        item = configured_service(name)
        if not item:
            return {"ok": False, "error": f"{name} is not in watchdog service config"}
        status = _run(["systemctl", "status", name, "--no-pager", "-l"], timeout=5)
        journal = _run(["journalctl", "-u", name, "-n", "80", "--no-pager"], timeout=5)
        return {
            "ok": True,
            "service": service_snapshot(item),
            "status": status["stdout"] or status["stderr"],
            "journal": journal["stdout"] or journal["stderr"],
        }

    def restart_configured_service(name):
        item = configured_service(name)
        if not item:
            return {"ok": False, "service": name, "message": f"{name} is not configured for watchdog monitoring", "returncode": None, "output": ""}
        result = _run(["systemctl", "restart", name], timeout=20)
        output = "\n".join(part for part in [result.get("stdout", ""), result.get("stderr", "")] if part)
        return {
            "ok": bool(result.get("ok")),
            "service": name,
            "message": f"{name} restarted successfully" if result.get("ok") else f"{name} restart failed",
            "returncode": result.get("returncode"),
            "output": output,
        }

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

    def history_csv(limit=1000):
        rows = read_history(cfg, limit=limit)
        columns = [
            "time",
            "state",
            "display_state",
            "score",
            "critical_failed",
            "temperature",
            "cpu_load",
            "ram",
            "root_disk",
            "recordings_disk",
        ]
        lines = [",".join(columns)]
        for row in rows:
            lines.append(",".join(_csv_cell(row.get(column, "")) for column in columns))
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
        install = install_status()
        return {
            "service_status": service_status["stdout"] or service_status["stderr"],
            "journal_tail": journal["stdout"] or journal["stderr"],
            "install_status": install,
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
            server_paths = {path for _, path in server_pages}
            if route_path in server_paths or route_path.startswith("/index") or route_path.startswith("/basic"):
                body = html_page(route_path).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/storage-purge-confirm":
                body = storage_purge_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recovery-install-confirm":
                body = recovery_install_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/itco-watchdog-install-confirm":
                body = itco_install_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-hardware-probe-confirm":
                body = watchdog_probe_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path.startswith("/service-restart-confirm/"):
                name = unquote(route_path.rsplit("/", 1)[-1])
                body = service_restart_confirm_html(name).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path.startswith("/service/"):
                name = unquote(route_path.rsplit("/", 1)[-1])
                body = service_detail_html(name).encode("utf-8")
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
            if route_path == "/api/history/export.csv":
                self._send_text(history_csv(limit=1000), content_type="text/csv")
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
            if route_path == "/api/install-status":
                self._send_json(install_status())
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            route_path = self.path.split("?", 1)[0]
            if route_path == "/update-now":
                result = launch_update_job(cfg)
                body = update_started_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/settings-save":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    result = apply_settings(settings_payload_from_form(form))
                except Exception as exc:
                    result = {"ok": False, "error": str(exc)}
                body = settings_saved_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/storage-purge-old":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    older_than_days = int(form.get("older_than_days", ["30"])[0] or 30)
                    result = purge_data(mode="old", older_than_days=older_than_days)
                except Exception as exc:
                    result = {"removed": [], "retention": retention_status(), "error": str(exc)}
                body = storage_purge_result_html(result, "old").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/storage-purge-all":
                result = purge_data(mode="all")
                body = storage_purge_result_html(result, "all").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recovery-install-now":
                result = launch_recovery_install()
                body = recovery_install_started_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/itco-watchdog-install-now":
                result = launch_itco_setup()
                body = itco_install_started_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-hardware-probe-now":
                result = launch_watchdog_probe()
                body = watchdog_probe_started_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/service-restart-now":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    name = form.get("service", [""])[0]
                    result = restart_configured_service(name)
                except Exception as exc:
                    result = {"ok": False, "service": "", "message": str(exc), "returncode": None, "output": ""}
                body = service_restart_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-test-arm":
                result = arm_watchdog_test()
                body = watchdog_test_armed_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-test-run":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    token = form.get("token", [""])[0]
                    result = run_watchdog_test(token)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "tested_at": "", "checks": []}
                body = watchdog_test_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
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
