from __future__ import annotations

import json
import os
import platform
import secrets
import socket
import subprocess
import re
import time
import io
import zipfile
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread, local
from urllib.parse import parse_qs, quote, unquote, urlencode

from .blackbox import blackbox_summary, read_blackbox
from .config import active_config_path, deep_merge, load_raw_config, save_raw_config
from .history import history_path, read_history
from .events import purge_events, read_events
from .retention import purge_data as retention_purge_data
from .retention import retention_status as retention_status_for_cfg
from .storage import apply_recording_service_mount_guards, configure_recording_storage, prepare_blank_recording_disk, recording_storage_candidates, recording_storage_status, validate_system_recording_directory
from .services import _runtime_stats
from .watchdog_grace import arm_current_boot, delay_current_boot, startup_grace_status
from .watchdog_test import arm_trip_test, confirm_trip_test, read_trip_test_state, trigger_trip_test, trip_test_summary
from .update import launch_update_job, load_update_status
from .speedtest import run_speed_test
from .heartbeat import heartbeat_paths, read_state, read_tail, heartbeat_age_seconds
from .journal import persistent_status, enable_persistent
from .crash_evidence import pstore_status
from .incident_archive import archive_config, list_archives
from .baseline_capture import baseline_paths, baseline_status, completed_archive, start_baseline
from .identity import configured_identity, identity_slug, identity_summary
from .recording_activity import recording_activity

VISIBLE_PAGE_GROUPS = (
    ("Operations", (("Overview", "/"), ("Events", "/events"))),
    ("System", (("Hardware", "/hardware"), ("Network", "/network"), ("Services", "/services"))),
    ("Administration", (("Settings", "/settings"),)),
)

LEGACY_PAGE_REDIRECTS = {
    "/storage": "/hardware#storage",
    "/watchdog": "/services#watchdog",
    "/history": "/events?view=history",
    "/diagnostics": "/events?view=evidence",
    "/recovery": "/settings#recovery",
    "/updates": "/settings#software-update",
}

HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__SITE_NAME__ - VA-Connect Watchdog</title>
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
body { font-family:"Trebuchet MS", "DejaVu Sans", sans-serif; background:var(--bg); color:var(--text); margin:0; font-size:calc(14px * var(--scale)); }
.shell { display:grid; grid-template-columns: calc(220px * var(--scale)) 1fr; min-height:100vh; }
.sidebar { border-right:1px solid var(--line); background:var(--sidebar); padding:calc(18px * var(--scale)) calc(14px * var(--scale)); display:flex; flex-direction:column; gap:calc(18px * var(--scale)); }
.brand { font-size:calc(18px * var(--scale)); font-weight:800; line-height:1.25; letter-spacing:-.02em; }
.brand small { display:block; margin-top:calc(5px * var(--scale)); color:var(--muted); font-size:calc(10px * var(--scale)); font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
.nav { display:grid; gap:calc(6px * var(--scale)); }
.nav button, .nav a { width:100%; text-align:left; background:transparent; color:var(--muted); border:1px solid transparent; border-radius:6px; padding:calc(10px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-size:inherit; text-decoration:none; display:block; }
.nav button.active, .nav a.active { color:#fff; background:var(--blue); border-color:var(--blue); font-weight:700; }
.mode-switcher { display:grid; grid-template-columns:1fr; gap:calc(4px * var(--scale)); margin-bottom:calc(12px * var(--scale)); padding:calc(4px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel); }
.nav .mode-tab { padding:calc(7px * var(--scale)) calc(8px * var(--scale)); text-align:left; font-size:calc(10px * var(--scale)); font-weight:800; text-transform:uppercase; letter-spacing:.04em; }
.nav .mode-tab.active { background:var(--blue); border-color:var(--blue); color:#fff; }
.nav-section { padding:calc(4px * var(--scale)) calc(10px * var(--scale)); color:var(--muted); font-size:calc(10px * var(--scale)); font-weight:800; letter-spacing:.12em; text-transform:uppercase; }
.nav-section:not(:first-child) { margin-top:calc(12px * var(--scale)); }
.moved-section { margin-top:calc(18px * var(--scale)); scroll-margin-top:calc(72px * var(--scale)); }
.moved-section-heading { margin:0 0 calc(10px * var(--scale)); padding:0 calc(2px * var(--scale)); }
.moved-section-heading h2 { margin:0 0 calc(3px * var(--scale)); }
.moved-section-heading p { margin:0; color:var(--muted); }
.side-status { margin-top:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:calc(12px * var(--scale)); color:var(--muted); }
.main { min-width:0; }
.topbar { height:calc(58px * var(--scale)); border-bottom:1px solid var(--line); display:flex; align-items:center; justify-content:space-between; padding:0 calc(18px * var(--scale)); color:var(--muted); }
.topbar-right { display:flex; gap:10px; align-items:center; }
select, input, textarea { background:var(--input); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:5px 8px; font-size:inherit; max-width:100%; }
textarea { width:100%; min-height:calc(70px * var(--scale)); resize:vertical; }
label { display:block; margin:calc(6px * var(--scale)) 0; }
.content { padding:calc(18px * var(--scale)); max-width:calc(1360px * var(--scale)); margin:0 auto; }
.page-intro { display:flex; align-items:center; justify-content:space-between; gap:calc(14px * var(--scale)); margin-bottom:calc(14px * var(--scale)); padding:0 calc(2px * var(--scale)); }
.page-intro h1 { margin:calc(2px * var(--scale)) 0; font-size:calc(24px * var(--scale)); letter-spacing:-.03em; }
.page-kicker { color:var(--blue); font-size:calc(11px * var(--scale)); font-weight:800; letter-spacing:.12em; text-transform:uppercase; }
.page-question { color:var(--muted); font-size:calc(13px * var(--scale)); }
.help-popover { position:relative; flex:0 0 auto; }
.help-popover summary { display:grid; place-items:center; width:calc(32px * var(--scale)); height:calc(32px * var(--scale)); border:1px solid var(--line); border-radius:999px; color:var(--blue); background:var(--panel); cursor:pointer; font-weight:900; list-style:none; }
.help-popover summary::-webkit-details-marker { display:none; }
.help-popover p { position:absolute; z-index:5; right:0; width:calc(300px * var(--scale)); margin:calc(8px * var(--scale)) 0 0; padding:calc(12px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel); color:var(--text); box-shadow:0 10px 30px rgba(0,0,0,.2); }
.grid { display:grid; gap:calc(12px * var(--scale)); }
.top-grid { grid-template-columns: minmax(0, 1.6fr) minmax(300px, 0.9fr); }
.metric-grid { grid-template-columns: repeat(6, minmax(calc(130px * var(--scale)), 1fr)); }
.lower-grid { grid-template-columns: minmax(0, 1.1fr) minmax(330px, 0.9fr); }
.operations-grid { grid-template-columns:repeat(2, minmax(0,1fr)); }
.bottom-grid { grid-template-columns: minmax(300px, 0.8fr) minmax(0, 1.2fr); }
.card, .tile { background:linear-gradient(145deg, var(--panel), var(--panel-2)); border:1px solid var(--line); border-radius:8px; padding:calc(14px * var(--scale)); min-width:0; }
.card h2, .card h3, .tile h3 { margin:0 0 calc(10px * var(--scale)); font-size:calc(16px * var(--scale)); }
.summary-card { display:grid; grid-template-columns:minmax(calc(145px * var(--scale)), .8fr) minmax(calc(210px * var(--scale)), 1.25fr) minmax(calc(170px * var(--scale)), 1fr); gap:calc(10px * var(--scale)); align-items:stretch; }
.summary-panel { padding:calc(14px * var(--scale)); border:1px solid var(--line); border-radius:7px; background:rgba(255,255,255,.025); }
.summary-status { display:flex; flex-direction:column; justify-content:center; background:linear-gradient(145deg, rgba(59,130,246,.11), rgba(255,255,255,.025)); }
.summary-panel-title { color:var(--muted); font-size:calc(11px * var(--scale)); font-weight:800; letter-spacing:.1em; text-transform:uppercase; margin-bottom:calc(8px * var(--scale)); }
.summary-primary { font-size:calc(19px * var(--scale)); font-weight:800; line-height:1.2; overflow-wrap:anywhere; }
.summary-pairs { display:grid; grid-template-columns:1fr 1fr; gap:calc(8px * var(--scale)) calc(14px * var(--scale)); }
.summary-pairs .label { margin-top:0; }
.operational-list { display:grid; gap:0; }
.operational-row { display:grid; grid-template-columns:minmax(calc(135px * var(--scale)), .75fr) minmax(calc(240px * var(--scale)), 2fr) auto auto; gap:calc(12px * var(--scale)); align-items:center; padding:calc(11px * var(--scale)) calc(4px * var(--scale)); border-top:1px solid var(--line); }
.operational-row:first-child { border-top:0; }
.operational-area { font-weight:800; }
.operational-detail { color:var(--muted); overflow-wrap:anywhere; }
.operational-state { min-width:calc(105px * var(--scale)); font-weight:800; text-align:right; }
.operational-link { white-space:nowrap; }
.build-badge { display:inline-block; font-size:calc(18px * var(--scale)); font-weight:800; border:1px solid var(--line); border-radius:8px; padding:calc(8px * var(--scale)) calc(10px * var(--scale)); margin:calc(6px * var(--scale)) 0; background:rgba(59,130,246,.16); color:var(--text); }
.status-word { font-size:calc(22px * var(--scale)); font-weight:800; }
.healthy { color:var(--green); }
.warning { color:var(--amber); }
.degraded { color:var(--orange); }
.critical { color:var(--red); }
.waiting { color:var(--blue); }
.unknown, .disabled, .idle { color:var(--muted); }
.pill { display:inline-block; border-radius:999px; padding:calc(4px * var(--scale)) calc(8px * var(--scale)); background:#0d2b17; color:var(--green); font-size:calc(12px * var(--scale)); font-weight:700; }
.pill.warning { background:rgba(255,191,60,.14); color:var(--amber); }
.pill.critical { background:rgba(255,79,100,.14); color:var(--red); }
.label { color:var(--muted); font-size:calc(12px * var(--scale)); margin-top:calc(8px * var(--scale)); }
.value { font-weight:700; overflow-wrap:anywhere; }
.tile-value { font-size:calc(24px * var(--scale)); font-weight:800; margin:calc(8px * var(--scale)) 0 calc(4px * var(--scale)); }
.tile-detail { color:var(--green); font-size:calc(13px * var(--scale)); overflow-wrap:anywhere; }
.overview-page .tile { min-height:calc(116px * var(--scale)); }
.overview-page .tile h3 { font-size:calc(17px * var(--scale)); }
.overview-page .tile-value { font-size:calc(28px * var(--scale)); line-height:1.08; }
.recording-tile { border-color:rgba(59,130,246,.55); background:linear-gradient(145deg, rgba(59,130,246,.14), var(--panel-2)); }
.recording-tile .tile-value { color:var(--blue); font-size:calc(27px * var(--scale)); }
.recording-tile .tile-detail { color:var(--muted); }
table { width:100%; border-collapse:collapse; }
th, td { padding:calc(9px * var(--scale)) calc(6px * var(--scale)); border-top:1px solid var(--line); text-align:left; white-space:nowrap; }
th { color:var(--muted); font-weight:600; font-size:calc(12px * var(--scale)); }
tr.selectable-row { cursor:pointer; }
tr.selectable-row:hover { outline:2px solid var(--blue); outline-offset:-2px; }
tr.selectable-row.selected { background:rgba(59,130,246,.18); }
input[type="radio"] { width:18px; height:18px; }
.events { display:grid; gap:calc(8px * var(--scale)); }
.event { display:grid; grid-template-columns: calc(82px * var(--scale)) 1fr; gap:calc(8px * var(--scale)); border-top:1px solid var(--line); padding-top:calc(8px * var(--scale)); }
.event-time { color:var(--muted); font-size:calc(12px * var(--scale)); }
.event-card { border:1px solid var(--line); border-radius:6px; padding:calc(8px * var(--scale)); background:rgba(255,255,255,.025); }
.event-card .event-head { display:flex; justify-content:space-between; gap:calc(10px * var(--scale)); align-items:center; margin-bottom:calc(6px * var(--scale)); }
.event-card summary { cursor:pointer; list-style:none; }
.event-card summary::-webkit-details-marker { display:none; }
.event-summary { display:grid; grid-template-columns:calc(76px * var(--scale)) minmax(0, 1fr) auto; gap:calc(10px * var(--scale)); align-items:center; }
.event-summary .event-message { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.event-card[open] .event-summary .event-message { white-space:normal; }
.event-detail { margin-top:calc(8px * var(--scale)); padding-top:calc(8px * var(--scale)); border-top:1px solid var(--line); }
.event-source { color:var(--muted); font-size:calc(12px * var(--scale)); }
.event-message { font-weight:700; }
.event-data { margin-top:calc(6px * var(--scale)); max-height:calc(130px * var(--scale)); }
.count-grid { display:grid; grid-template-columns: repeat(5, minmax(calc(90px * var(--scale)), 1fr)); gap:calc(8px * var(--scale)); margin-bottom:calc(10px * var(--scale)); }
.history-box { height:calc(160px * var(--scale)); border:1px solid var(--line); border-radius:6px; background:linear-gradient(180deg, rgba(54,209,95,.18), rgba(54,209,95,.04)); display:flex; align-items:center; justify-content:center; color:var(--muted); }
.trend-bars { display:flex; align-items:flex-end; gap:2px; height:34px; min-width:150px; padding:4px 0; }
.trend-bar { flex:1; min-width:2px; background:var(--blue); border-radius:2px 2px 0 0; opacity:.8; }
.top-watchdog { display:flex; align-items:center; gap:calc(8px * var(--scale)); border:1px solid var(--line); border-radius:8px; padding:calc(5px * var(--scale)) calc(8px * var(--scale)); background:var(--panel); white-space:nowrap; }
pre { white-space:pre-wrap; overflow:auto; max-height:calc(540px * var(--scale)); background:var(--input); border:1px solid var(--line); border-radius:6px; padding:calc(12px * var(--scale)); }
.detail-grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:calc(10px * var(--scale)); }
.mini-card { border:1px solid var(--line); border-radius:6px; padding:calc(10px * var(--scale)); background:rgba(255,255,255,.03); min-width:0; }
.status-strip { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:calc(10px * var(--scale)); margin:calc(10px * var(--scale)) 0; }
.status-box { border:1px solid var(--line); border-radius:8px; padding:calc(12px * var(--scale)); background:rgba(255,255,255,.035); min-width:0; }
.status-box .big { font-size:calc(22px * var(--scale)); font-weight:800; margin:calc(4px * var(--scale)) 0; overflow-wrap:anywhere; }
.action-panel { border-left:calc(5px * var(--scale)) solid var(--amber); }
.action-panel.healthy { border-left-color:var(--green); }
.action-panel.critical { border-left-color:var(--red); }
.setup-steps { display:grid; gap:calc(8px * var(--scale)); counter-reset:step; }
.setup-step { display:grid; grid-template-columns:calc(28px * var(--scale)) 1fr auto; gap:calc(10px * var(--scale)); align-items:center; border:1px solid var(--line); border-radius:8px; padding:calc(10px * var(--scale)); background:rgba(255,255,255,.025); }
.setup-step:before { counter-increment:step; content:counter(step); width:calc(24px * var(--scale)); height:calc(24px * var(--scale)); display:grid; place-items:center; border-radius:999px; background:var(--input); color:var(--muted); font-weight:800; }
.setup-step.healthy:before { background:rgba(54,209,95,.16); color:var(--green); }
.setup-step.warning:before { background:rgba(255,191,60,.16); color:var(--amber); }
.setup-step.critical:before { background:rgba(255,79,100,.16); color:var(--red); }
.step-title { font-weight:800; }
.step-detail { color:var(--muted); font-size:calc(12px * var(--scale)); overflow-wrap:anywhere; }
.compact-table td, .compact-table th { white-space:normal; }
.muted { color:var(--muted); }
.toolbar { display:flex; flex-wrap:wrap; gap:calc(8px * var(--scale)); align-items:center; margin-bottom:calc(10px * var(--scale)); }
.page-tabs { display:flex; gap:calc(6px * var(--scale)); margin-bottom:calc(12px * var(--scale)); padding:calc(5px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel); }
.page-tabs a { flex:1; padding:calc(10px * var(--scale)); border-radius:6px; color:var(--muted); text-align:center; text-decoration:none; font-weight:800; }
.page-tabs a.active { background:var(--blue); color:#fff; }
.event-table { table-layout:fixed; }
.event-table th:nth-child(1), .event-table td:nth-child(1) { width:calc(132px * var(--scale)); }
.event-table th:nth-child(2), .event-table td:nth-child(2) { width:calc(82px * var(--scale)); }
.event-table th:nth-child(3), .event-table td:nth-child(3) { width:calc(125px * var(--scale)); }
.event-table th:nth-child(5), .event-table td:nth-child(5) { width:calc(92px * var(--scale)); }
.event-table th:nth-child(6), .event-table td:nth-child(6) { width:calc(78px * var(--scale)); }
.event-table td { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.event-table .event-message-cell { font-weight:700; }
.event-evidence { position:relative; overflow:visible; }
.event-evidence summary { color:var(--blue); cursor:pointer; font-weight:700; list-style:none; }
.event-evidence summary::-webkit-details-marker { display:none; }
.event-evidence[open] .event-evidence-body { position:absolute; z-index:4; right:0; width:min(calc(600px * var(--scale)), 75vw); padding:calc(12px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel); box-shadow:0 12px 30px rgba(0,0,0,.28); }
.event-evidence-body pre { max-height:calc(260px * var(--scale)); }
.chart { width:100%; height:calc(180px * var(--scale)); border:1px solid var(--line); border-radius:6px; background:rgba(54,209,95,.08); }
.chart text { fill:var(--muted); font-size:10px; }
.chart polyline { fill:none; stroke:var(--green); stroke-width:2; }
.chart .grid-line { stroke:var(--line); stroke-width:1; }
.button-row { display:flex; gap:calc(8px * var(--scale)); flex-wrap:wrap; align-items:center; margin:calc(10px * var(--scale)) 0; }
.quick-actions { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:calc(8px * var(--scale)); }
.quick-actions a { min-height:calc(54px * var(--scale)); display:flex; flex-direction:column; justify-content:center; }
.quick-actions a span { display:block; margin-top:calc(3px * var(--scale)); color:var(--muted); font-size:calc(11px * var(--scale)); font-weight:400; }
.issue-list { display:grid; gap:calc(7px * var(--scale)); }
.issue-row { display:grid; grid-template-columns:auto 1fr; gap:calc(9px * var(--scale)); align-items:start; padding:calc(9px * var(--scale)); border:1px solid var(--line); border-radius:7px; background:rgba(255,255,255,.025); }
.issue-row .pill { min-width:calc(68px * var(--scale)); text-align:center; }
.advanced-disclosure { margin-top:calc(12px * var(--scale)); border-top:1px solid var(--line); padding-top:calc(10px * var(--scale)); }
.advanced-disclosure summary { color:var(--blue); cursor:pointer; font-weight:700; }
.section-disclosure { margin-top:calc(12px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel); overflow:hidden; }
.section-disclosure > summary { display:flex; align-items:center; justify-content:space-between; gap:calc(10px * var(--scale)); padding:calc(12px * var(--scale)) calc(14px * var(--scale)); color:var(--text); cursor:pointer; font-weight:800; list-style:none; }
.section-disclosure > summary::-webkit-details-marker { display:none; }
.section-disclosure > summary:after { content:'Show'; color:var(--blue); font-size:calc(11px * var(--scale)); font-weight:700; }
.section-disclosure[open] > summary:after { content:'Hide'; }
.section-disclosure[open] > summary { border-bottom:1px solid var(--line); }
.section-body { padding:calc(14px * var(--scale)); }
.summary-strip { display:grid; grid-template-columns:repeat(auto-fit, minmax(calc(145px * var(--scale)),1fr)); gap:calc(10px * var(--scale)); margin-bottom:calc(12px * var(--scale)); }
.summary-stat { min-width:0; padding:calc(12px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:linear-gradient(145deg, var(--panel), var(--panel-2)); }
.summary-stat .stat-value { margin-top:calc(5px * var(--scale)); font-size:calc(21px * var(--scale)); font-weight:800; overflow-wrap:anywhere; }
.summary-stat .stat-detail { margin-top:calc(3px * var(--scale)); color:var(--muted); font-size:calc(11px * var(--scale)); overflow-wrap:anywhere; }
.tool-grid { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:calc(9px * var(--scale)); }
.tool-card { display:flex; flex-direction:column; justify-content:space-between; min-height:calc(86px * var(--scale)); padding:calc(12px * var(--scale)); border:1px solid var(--line); border-radius:8px; background:var(--panel-2); color:var(--text); text-decoration:none; }
.tool-card strong { font-size:calc(14px * var(--scale)); }
.tool-card span { margin-top:calc(5px * var(--scale)); color:var(--muted); font-size:calc(11px * var(--scale)); }
.tool-card:not(.disabled):hover { border-color:var(--blue); }
.tool-card.primary { background:var(--blue); color:#fff; border-color:var(--blue); }
.tool-card.primary span { color:rgba(255,255,255,.78); }
.tool-card.danger { border-color:var(--red); }
.tool-card.disabled { opacity:.58; cursor:not-allowed; }
.section-lead { display:flex; align-items:flex-start; justify-content:space-between; gap:calc(12px * var(--scale)); margin-bottom:calc(10px * var(--scale)); }
.section-lead h2 { margin-bottom:calc(4px * var(--scale)); }
.section-lead p { margin:0; }
.status-dot { display:inline-block; width:calc(8px * var(--scale)); height:calc(8px * var(--scale)); margin-right:calc(5px * var(--scale)); border-radius:999px; background:currentColor; }
.settings-sections { display:grid; gap:calc(9px * var(--scale)); }
.settings-sections .section-disclosure { margin-top:0; }
.settings-grid { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:calc(12px * var(--scale)); }
.option-row { display:flex; align-items:flex-start; gap:calc(8px * var(--scale)); margin:calc(10px * var(--scale)) 0; padding:calc(10px * var(--scale)); border:1px solid var(--line); border-radius:7px; background:var(--panel-2); }
.option-row input { width:auto; margin-top:calc(2px * var(--scale)); }
.table-scroll { overflow-x:auto; }
button.action, a.action { background:var(--blue); color:#fff; border:0; border-radius:6px; padding:calc(9px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-weight:700; font-size:inherit; text-decoration:none; display:inline-block; }
button.danger, a.danger { background:var(--red); color:#fff; border:0; border-radius:6px; padding:calc(9px * var(--scale)) calc(12px * var(--scale)); cursor:pointer; font-weight:700; font-size:inherit; text-decoration:none; display:inline-block; }
button.ghost, a.ghost { background:transparent; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:calc(7px * var(--scale)) calc(10px * var(--scale)); cursor:pointer; font-size:inherit; text-decoration:none; display:inline-block; }
form.inline { display:inline-block; margin:0; }
button.action:disabled { opacity:.5; cursor:not-allowed; }
.page { display:none; }
.page.active { display:block; }
@media (max-width: 1100px) {
  .shell { grid-template-columns: calc(180px * var(--scale)) 1fr; }
  .metric-grid { grid-template-columns: repeat(3, minmax(calc(130px * var(--scale)), 1fr)); }
  .status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .top-grid, .lower-grid, .bottom-grid { grid-template-columns: 1fr; }
  .tool-grid { grid-template-columns:repeat(2, minmax(0,1fr)); }
}
@media (max-width: 760px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar { position:static; }
  .topbar { height:auto; min-height:calc(58px * var(--scale)); align-items:flex-start; flex-direction:column; gap:calc(8px * var(--scale)); padding-top:calc(10px * var(--scale)); padding-bottom:calc(10px * var(--scale)); }
  .topbar-right { width:100%; flex-wrap:wrap; gap:calc(7px * var(--scale)); }
  #last-update { flex:1 1 100%; overflow-wrap:anywhere; }
  .metric-grid { grid-template-columns: repeat(2, minmax(calc(130px * var(--scale)), 1fr)); }
  .status-strip { grid-template-columns: 1fr; }
  .summary-card { grid-template-columns: 1fr; }
  .summary-pairs { grid-template-columns:1fr 1fr; }
  .operations-grid { grid-template-columns:1fr; }
  .page-intro { align-items:flex-start; }
  .quick-actions { grid-template-columns:1fr; }
  .summary-strip, .tool-grid, .settings-grid { grid-template-columns:1fr; }
  .event-summary { grid-template-columns:auto 1fr; }
  .event-summary .event-time { grid-column:2; }
  .page-tabs { display:grid; grid-template-columns:1fr; }
  .operational-row { grid-template-columns:1fr auto; }
  .operational-detail { grid-column:1 / -1; grid-row:2; }
  .operational-state { min-width:0; }
  .operational-link { grid-column:1 / -1; }
}
</style>
</head>
<body data-theme="__BODY_THEME__">
<div class="shell">
  <aside class="sidebar">
    <div class="brand">VA-Connect Watchdog<small>__SITE_NAME__</small></div>
    <nav class="nav" id="nav">__SERVER_NAV__</nav>
  </aside>
  <main class="main">
    <header class="topbar">
      <div id="page-title">__SITE_NAME__ / __PAGE_MODE__ / __PAGE_TITLE__</div>
      <div class="topbar-right">
        <div class="top-watchdog"><span>Watchdog</span><strong id="side-state" class="value">Loading</strong><span class="label">Build</span><strong>__BUILD_ID__</strong></div>
        <label>Theme <select id="theme-select" onchange="setTheme(this.value)"><option value="light">Light</option><option value="dark">Dark</option><option value="steel">Steel</option><option value="sand">Sand</option></select></label>
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
    var checks = status.checks || [];
    var hasIssue = false;
    for (var i = 0; i < checks.length; i++) {
      if (checks[i].state === 'critical' || checks[i].state === 'warning' || checks[i].state === 'unknown') {
        hasIssue = true;
        break;
      }
    }
    var state = status.critical_failed ? 'critical' : (hasIssue ? 'warning' : 'healthy');
    if (lastUpdate) lastUpdate.textContent = 'Last update: ' + (status.time || '-');
    if (sideState) {
      sideState.textContent = state.toUpperCase();
      sideState.className = 'value ' + state;
    }
  }
  function hideAdvancedControls(){
    var items = document.getElementsByClassName('advanced-only');
    for (var i = 0; i < items.length; i++) {
      items[i].style.display = 'none';
    }
  }
  function restoreDisclosureState(){
    var details = document.querySelectorAll('details.section-disclosure');
    for (var i = 0; i < details.length; i++) {
      var summary = details[i].querySelector('summary');
      if (!summary) continue;
      var key = 'va_watchdog_disclosure_' + location.pathname + '_' + summary.textContent.trim();
      try {
        var saved = localStorage.getItem(key);
        if (saved === 'open') details[i].open = true;
        if (saved === 'closed') details[i].open = false;
      } catch (e) {}
      details[i].addEventListener('toggle', function(){
        var item = this.querySelector('summary');
        if (!item) return;
        try {
          localStorage.setItem('va_watchdog_disclosure_' + location.pathname + '_' + item.textContent.trim(), this.open ? 'open' : 'closed');
        } catch (e) {}
      });
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
    try {
      localStorage.setItem('va_watchdog_theme', value);
    } catch (e) {}
    document.cookie = 'va_watchdog_theme=' + encodeURIComponent(value) + '; path=/; max-age=31536000; samesite=lax';
    document.body.setAttribute('data-theme', value);
  };
  var initialTheme = document.body.getAttribute('data-theme') || 'light';
  var themeSelect = document.getElementById('theme-select');
  if (themeSelect) themeSelect.value = initialTheme;
  hideAdvancedControls();
  restoreDisclosureState();
  window.vaWatchdogCompatibilityLoad();
}());
</script>
<script type="module">
const PAGE_MODES = {
  Operations: ['Overview', 'Events'],
  System: ['Hardware', 'Network', 'Services'],
  Administration: ['Settings'],
};
const PATH_PAGES = {
  '/': 'Overview', '/events': 'Events', '/hardware': 'Hardware', '/network': 'Network',
  '/services': 'Services', '/settings': 'Settings',
};
const PAGES = Object.keys(PAGE_MODES).reduce((pages, mode) => pages.concat(PAGE_MODES[mode]), []);
let currentPage = PATH_PAGES[window.location.pathname] || '__PAGE_TITLE__';
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
let lastRecordingActivity = {};
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
  const nonFeedCritical = (status.checks || []).some(c => c.state === 'critical');
  const degraded = (status.checks || []).some(c => c.state === 'degraded');
  const warnings = (status.checks || []).some(c => c.state === 'warning' || c.state === 'unknown');
  if (critical) return 'critical';
  if (nonFeedCritical) return 'warning';
  if (degraded) return 'degraded';
  if (warnings) return 'warning';
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
  const pad = part => String(part).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function buildNav(){
  const nav = document.getElementById('nav');
  nav.innerHTML = Object.keys(PAGE_MODES).map(mode => {
    const pageLinks = PAGE_MODES[mode].map(page => `<a class="${page === currentPage ? 'active' : ''}" href="${pathForPage(page)}">${escapeHtml(page)}</a>`).join('');
    return `<div class="nav-section">${escapeHtml(mode)}</div>${pageLinks}`;
  }).join('');
}

function modeForPage(page){
  return Object.keys(PAGE_MODES).find(mode => PAGE_MODES[mode].includes(page)) || 'Operations';
}

function pathForPage(page){
  return Object.keys(PATH_PAGES).find(path => PATH_PAGES[path] === page) || '/';
}

function setRefreshInterval(value){
  localStorage.setItem('va_watchdog_refresh_ms', String(value));
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (currentPage === 'Events') return;
  const ms = Number(value);
  if (ms > 0) {
    refreshTimer = setInterval(load, ms);
  }
}

function initRefresh(){
  let saved = localStorage.getItem('va_watchdog_refresh_ms');
  if (!saved || saved === '5000') {
    saved = '30000';
    localStorage.setItem('va_watchdog_refresh_ms', saved);
  }
  const select = document.getElementById('refresh-select');
  if (currentPage === 'Events') {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
    select.value = '0';
    select.disabled = true;
    select.title = 'Automatic refresh is paused while reviewing events';
    return;
  }
  select.disabled = false;
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
    document.cookie = 'va_watchdog_theme=' + encodeURIComponent(value) + '; path=/; max-age=31536000; samesite=lax';
    document.body.dataset.theme = value;
  }

function reloadPage(){
  window.location.reload();
}

function initTheme(){
  const cookieMatch = document.cookie.match(/(?:^|; )va_watchdog_theme=([^;]+)/);
  const saved = (cookieMatch ? decodeURIComponent(cookieMatch[1]) : '') || localStorage.getItem('va_watchdog_theme') || 'light';
  const select = document.getElementById('theme-select');
  select.value = saved;
  setTheme(saved);
}

async function showPage(page){
  currentPage = page;
  const title = document.getElementById('page-title');
  if (title) title.textContent = `${modeForPage(page)} / ${page}`;
  buildNav();
  await load();
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
    if (name === 'temperature' || name === 'ram' || name === 'cpu_load' || name === 'hardware_watchdog_present' || name === 'hardware_watchdog_feed_status') {
      groups.hardware.push(check);
    } else if (name.endsWith('.service')) {
      groups.services.push(check);
    } else if (name === 'root_disk' || name === 'recordings_disk' || name === 'recording_storage' || name === 'write_test') {
      groups.storage.push(check);
    } else if (name === 'network_module') {
      groups.system.push(check);
    } else {
      groups.system.push(check);
    }
  }
  return groups;
}

function tile(title, check, value, detail, extraClass = ''){
  const state = statusClass(check.state);
  return `<div class="tile ${escapeHtml(extraClass)}"><h3>${escapeHtml(title)}</h3><div class="tile-value ${state}">${escapeHtml(value)}</div><div class="tile-detail">${escapeHtml(detail || check.message || '')}</div></div>`;
}

function serviceRows(status){
  const checks = (status.checks || []).filter(c => String(c.name || '').endsWith('.service'));
  const liveServices = lastServiceInfo.services || [];
  const names = [...new Set([...checks.map(c => c.name), ...liveServices.map(item => item.name)])];
  return names.map(name => {
    const check = checks.find(c => c.name === name) || {};
    const value = check.value || {};
    const live = liveServices.find(item => item.name === name) || {};
    const active = value.active || live.active || check.state || '-';
    const state = String(active).toLowerCase() === 'active' ? 'healthy' : 'warning';
    return `<tr><td>${escapeHtml(name)}</td><td><span class="pill ${state}">${escapeHtml(String(active).toUpperCase())}</span></td><td>${escapeHtml(live.cpu_percent ?? '-')}</td><td>${escapeHtml(live.memory_mb !== undefined && live.memory_mb !== '-' ? `${live.memory_mb} MB` : '-')}</td><td>${escapeHtml(value.restarts ?? live.restarts ?? '-')}</td><td>${escapeHtml(live.uptime || '-')}</td></tr>`;
  }).join('');
}

function renderEvents(events, limit=8){
  const rows = (events || []).slice(0, limit);
  if (!rows.length) return '<div class="event"><div class="event-time">-</div><div>No events yet</div></div>';
  return rows.map(event => `<details class="event-card"><summary class="event-summary"><span class="${statusClass(event.level)}">${escapeHtml((event.level || 'info').toUpperCase())}</span><span class="event-message">${escapeHtml(event.message || '')}</span><span class="event-time">${escapeHtml(fmtTime(event.time))}</span></summary><div class="event-detail"><div class="event-source">Source: ${escapeHtml(event.source || '-')}</div>${event.data ? `<pre class="event-data">${escapeHtml(JSON.stringify(event.data, null, 2))}</pre>` : '<p class="muted">No additional event data.</p>'}</div></details>`).join('');
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
  const wdt = findCheck(status, 'hardware_watchdog_present');
  const hasNonFeedCritical = (status.checks || []).some(c => c.state === 'critical');
  const warningCount = (status.checks || []).filter(c =>
    (c.state === 'warning' || c.state === 'unknown')
    && !(c.name === 'hardware_watchdog_feed_status' && !wdt.value)
  ).length;
  const pill = status.critical_failed ? 'Critical issue blocking feed' : (hasNonFeedCritical ? 'Attention needed, feed safe' : (warningCount ? `${warningCount} active warning${warningCount === 1 ? '' : 's'}` : 'No active alerts'));
  const identity = lastSystemInfo.identity || lastVersion.identity || {};
  const gatewayName = identity.display_name || identity.site_name || lastSystemInfo.hostname || 'Site not configured';
  const buildTime = lastVersion.build_at ? fmtTime(lastVersion.build_at) : '-';
  return `<div class="card summary-card"><div class="summary-panel summary-status"><div class="summary-panel-title">Overall state</div><div class="status-word ${state}">${displayWord(status)}</div><span class="pill ${state}">${escapeHtml(pill)}</span></div><div class="summary-panel"><div class="summary-panel-title">Gateway identity</div><div class="summary-primary">${escapeHtml(gatewayName)}</div><div class="summary-pairs"><div><div class="label">Asset ID</div><div class="value">${escapeHtml(identity.asset_id || '-')}</div></div><div><div class="label">Hostname</div><div class="value">${escapeHtml(identity.hostname || lastSystemInfo.hostname || '-')}</div></div></div></div><div class="summary-panel"><div class="summary-panel-title">Running software</div><div class="label">Build</div><div class="build-badge">${escapeHtml(lastVersion.commit || '-')}</div><div class="label">Build time and date</div><div class="value">${escapeHtml(buildTime)}</div><div class="muted">${escapeHtml(lastVersion.branch || lastUpdateStatus?.branch || '-')}</div><div class="label">Last update</div><div class="value">${escapeHtml(fmtTime(status.time))}</div></div></div>`;
}

function pageHelp(page){
  const help = {
    Overview: ['Is this gateway ready to operate?', 'Shows gateway identity, operational readiness, live metrics, recording availability, and current alerts.'],
    Hardware: ['Is the hardware healthy?', 'Read-only sensor, CPU, memory, disk, and device discovery details.'],
    Watchdog: ['Will the gateway recover itself?', 'Configure, verify, and test the hardware and process watchdog protection layers.'],
    Services: ['Are the Videosoft services running?', 'Shows each monitored service and provides confirmed manual restart controls.'],
    Storage: ['Will recordings continue?', 'Shows recording storage, mount health, capacity, permissions, retention, and setup tools.'],
    Network: ['Can the gateway communicate?', 'Shows interfaces, routes, targets, sockets, and remote-access service status.'],
    Recovery: ['How can this gateway be recovered?', 'Contains service repair, reinstall, reboot policy, and emergency support actions.'],
    Events: ['What changed recently?', 'Review concise event summaries, expand technical detail, or export the event log.'],
    History: ['Has gateway health changed over time?', 'Shows retained health trends and previous state samples.'],
    Settings: ['What should the watchdog monitor?', 'Configure monitoring, display, storage, network, update, and recovery behavior.'],
    Updates: ['Which build is running?', 'Starts a controlled update and shows the branch, commit, result, and log.'],
    Diagnostics: ['What evidence is available?', 'Technical toolbox, raw status, black-box snapshots, and downloadable support bundle.'],
  };
  const content = help[page] || ['What does this page show?', 'Page help unavailable.'];
  return `<div class="page-intro"><div><div class="page-kicker">${escapeHtml(modeForPage(page))}</div><h1>${escapeHtml(page)}</h1><div class="page-question">${escapeHtml(content[0])}</div></div><details class="help-popover"><summary title="Page help">?</summary><p>${escapeHtml(content[1])}</p></details></div>`;
}

function renderWatchdogPage(status){
  const watchdog = lastHardwareInfo.watchdog || {};
  const process = status.watchdog_process || {};
  const hwCfg = lastSettings.hardware_watchdog || {};
  const feed = status.hardware_watchdog_feed || {};
  const backend = 'neousys_wdt_dio';
  const vendorBackend = true;
  const timeout = Number(hwCfg.timeout_seconds || 30);
  const systemd = watchdog.systemd_watchdog || {};
  const safeTest = watchdog.safe_test || {};
  const tripTest = watchdog.trip_test || {};
  const tripCountdown = feed.trip_countdown || {};
  const wdctl = watchdog.wdctl || {};
  const modules = watchdog.modules || {};
  const legacy = watchdog.legacy_daemon || {};
  const units = legacy.units || [];
  const legacyClean = units.length ? units.every(unit => unit.active !== 'active' && !['enabled', 'static'].includes(unit.enabled)) : legacy.active !== 'active' && !['enabled', 'static'].includes(legacy.enabled);
  const lastFeed = feed.last_feed_unix ? `${Math.round((Date.now() / 1000) - Number(feed.last_feed_unix))}s ago` : 'No feed timestamp';
  const feedRecent = !!feed.last_feed_unix && ((Date.now() / 1000) - Number(feed.last_feed_unix)) <= Math.max(Number(hwCfg.feed_interval_seconds || 10) * 3, 30);
  const driverLoaded = !!modules.wdt_dio;
  const expectedIdentity = 'Neousys WDT_DIO';
  const identityReady = String(wdctl.identity || '').includes(expectedIdentity) || (vendorBackend && feed.opened);
  const selectedDevice = feed.device || hwCfg.device || '/dev/wdt_dio';
  const setupChecks = [
    ['Neousys WDT_DIO driver', driverLoaded ? 'healthy' : 'warning', driverLoaded ? 'Loaded' : 'Not loaded yet'],
    ['Watchdog device', feed.opened || wdctl.state === 'healthy' ? 'healthy' : 'warning', `${selectedDevice} / ${wdctl.identity || 'not ready'}`],
    ['Driver identity', identityReady ? 'healthy' : 'warning', wdctl.identity || `No ${expectedIdentity} identity reported yet`],
    ['Legacy daemon', legacyClean ? 'healthy' : 'critical', legacyClean ? 'Removed/disabled' : 'Another watchdog daemon may still own the device'],
    ['Watchdog config', hwCfg.enabled ? 'healthy' : 'warning', `backend=${backend}, enabled=${!!hwCfg.enabled}, device=${selectedDevice}`],
    ['Device owner', feed.opened ? 'healthy' : 'warning', feed.opened ? 'The watchdog service has opened the device' : (watchdog.owners?.summary || 'The watchdog service has not opened the device')],
    ['Live feed', feedRecent ? 'healthy' : 'warning', lastFeed],
    ['Process watchdog', systemd.state || 'warning', `${systemd.message || '-'}; ${systemd.watchdog_sec || '-'}`],
  ];
  const ready = setupChecks.slice(0, 7).every(row => row[1] === 'healthy');
  const checkRows = setupChecks.map(row => `<tr><td>${escapeHtml(row[0])}</td><td class="${escapeHtml(row[1])}">${escapeHtml(row[1].toUpperCase())}</td><td>${escapeHtml(row[2])}</td></tr>`).join('');
  const checkCards = setupChecks.map(row => `<div class="setup-step ${escapeHtml(row[1])}"><div><div class="step-title">${escapeHtml(row[0])}</div><div class="step-detail">${escapeHtml(row[2])}</div></div><strong class="${escapeHtml(row[1])}">${escapeHtml(row[1].toUpperCase())}</strong></div>`).join('');
  const configRows = [
    ['Backend', 'Neousys WDT_DIO'],
    ['Hardware feed', hwCfg.enabled ? 'Enabled' : 'Disabled'],
    ['Device', selectedDevice],
    ['Opened device', feed.opened ? 'Yes' : 'No'],
    ['Feed interval', `${hwCfg.feed_interval_seconds || 10} seconds`],
    ['Configured timeout', `${timeout} seconds`],
    ['Driver timeout', wdctl.timeout || '-'],
    ['Trip countdown check', tripCountdown.status || 'inactive'],
    ['Device owner', watchdog.owners?.summary || '-'],
    ['Legacy package', legacy.package_status || '-'],
    ['Watchdog CPU', process.cpu_percent == null ? '-' : `${Number(process.cpu_percent).toFixed(1)}%`],
    ['Watchdog memory', process.memory_mb == null ? '-' : `${Number(process.memory_mb).toFixed(1)} MB`],
    ['Watchdog PID', process.pid ?? '-'],
    ['Resource monitor', process.message || 'Unavailable'],
    ['CPU thresholds', `${process.cpu_warning_percent ?? '-'}% warning / ${process.cpu_critical_percent ?? '-'}% critical`],
    ['Memory thresholds', `${process.memory_warning_mb ?? '-'} MB warning / ${process.memory_critical_mb ?? '-'} MB critical`],
    ['Systemd memory limit', systemd.memory_max || 'Not reported'],
    ['Systemd task limit', systemd.tasks_max || 'Not reported'],
    ['Systemd restarts', systemd.restarts || '0'],
  ].map(row => `<tr><td>${escapeHtml(row[0])}</td><td>${escapeHtml(row[1])}</td></tr>`).join('');
  const legacyRows = units.length ? units.map(unit => `<tr><td>${escapeHtml(unit.unit || '-')}</td><td class="${unit.active === 'active' ? 'critical' : 'healthy'}">${escapeHtml(unit.active || '-')}</td><td class="${['enabled', 'static'].includes(unit.enabled) ? 'warning' : 'healthy'}">${escapeHtml(unit.enabled || '-')}</td></tr>`).join('') : '<tr><td colspan="3">No legacy watchdog units found.</td></tr>';
  const tripAction = ready ? '<a class="action" href="/watchdog-trip-confirm">Open trip test</a>' : '<button class="action" disabled>Open trip test</button>';
  const legacyProblem = !legacyClean;
  const pageState = ready ? 'healthy' : (legacyProblem ? 'critical' : 'warning');
  const pageTitle = ready ? 'Hardware watchdog ready' : (legacyProblem ? 'Existing watchdog conflict found' : 'Watchdog needs setup');
  const pageMessage = ready ? `The independent feeder owns ${selectedDevice} using the Neousys WDT_DIO API. The deliberate trip test is available.` : (legacyProblem ? 'A legacy watchdog service may own the device. Clean legacy watchdogs, then complete setup.' : 'The Neousys driver, device, or feed is not ready. Run Neousys setup.');
  const primaryAction = ready ? `<a class="action" href="/watchdog-trip-confirm">${tripTest.armed ? 'Continue armed trip confirmation' : 'Start deliberate trip test'}</a>` : (legacyProblem ? '<a class="danger" href="/watchdog-legacy-disable-confirm">Clean legacy watchdogs</a>' : '<a class="action" href="/hardware-watchdog-prepare-confirm">Run Neousys setup</a>');
  const feedState = feed.enabled && feed.opened ? 'healthy' : 'warning';
  const setupLink = '<a class="ghost" href="/hardware-watchdog-prepare-confirm">Run Neousys setup/cleanup</a>';
  return `${pageHelp('Watchdog')}<div class="card action-panel ${pageState}"><h2>${escapeHtml(pageTitle)}</h2><p class="${pageState}">${escapeHtml(pageMessage)}</p><div class="button-row">${primaryAction}${setupLink}<a class="ghost" href="/watchdog-hardware-probe-confirm">Run probe</a></div></div><div class="status-strip"><div class="status-box"><div class="label">Driver</div><div class="big ${driverLoaded ? 'healthy' : 'warning'}">${driverLoaded ? 'Loaded' : 'Needs setup'}</div><div class="step-detail">Neousys WDT_DIO</div></div><div class="status-box"><div class="label">Device</div><div class="big ${feed.opened || wdctl.state === 'healthy' ? 'healthy' : 'warning'}">${escapeHtml(selectedDevice)}</div><div class="step-detail">${escapeHtml(wdctl.identity || 'No identity yet')}</div></div><div class="status-box"><div class="label">Hardware feed</div><div class="big ${feedState}">${feed.enabled && feed.opened ? 'Feeding' : 'Not feeding'}</div><div class="step-detail">${escapeHtml(lastFeed)}</div></div><div class="status-box"><div class="label">Legacy watchdogs</div><div class="big ${legacyProblem ? 'critical' : 'healthy'}">${legacyProblem ? 'Conflict' : 'Clear'}</div><div class="step-detail">${escapeHtml(legacyProblem ? 'Cleanup needed' : 'Removed/disabled')}</div></div></div><div class="grid lower-grid"><div class="card"><h2>Setup Checklist</h2><p class="muted">Work from top to bottom. Green means that layer is ready; amber/red shows the part to fix next.</p><div class="setup-steps">${checkCards}</div></div><div class="card"><h2>Existing Watchdogs and Cleanup</h2><p class="${legacyProblem ? 'critical' : 'healthy'}">${legacyProblem ? 'Another watchdog may still be installed or enabled.' : 'No conflicting legacy watchdog services detected.'}</p><table class="compact-table"><thead><tr><th>Unit</th><th>Active</th><th>Enabled</th></tr></thead><tbody>${legacyRows}</tbody></table><p class="muted">This service should be the only process feeding the hardware watchdog.</p><div class="button-row"><a class="ghost" href="/watchdog-legacy-disable-confirm">Clean legacy watchdogs only</a><a class="ghost" href="/hardware">Hardware details</a></div></div></div><div class="grid lower-grid"><div class="card"><h2>Current Watchdog Configuration</h2><table class="compact-table"><tbody>${configRows}</tbody></table></div><div class="card"><h2>What the Layers Mean</h2><ul><li><strong>Hardware watchdog</strong> reboots the whole gateway if its selected backend stops receiving feeds.</li><li><strong>Hardware feed</strong> is the independent feeder controlling the selected device.</li><li><strong>Process watchdog</strong> is systemd restarting va-watchdog if the Python process hangs.</li><li><strong>Legacy watchdogs</strong> are old daemons/packages that should not also control the hardware.</li></ul></div></div><div class="grid lower-grid"><div class="card"><h2>Safe Watchdog Test</h2><p class="muted">Double knock: arm the test, then confirm it before it expires. This does not intentionally reboot the gateway.</p><div class="button-row"><form class="inline" method="post" action="/watchdog-test-arm"><button class="action" type="submit">Arm safe test</button></form></div><div class="label">Feed enabled</div><div class="value">${feed.enabled ? 'Enabled' : 'Disabled'}</div><div class="label">Last feed</div><div class="value">${escapeHtml(lastFeed)}</div></div><div class="card"><h2>Deliberate Watchdog Trip Test</h2><p class="warning">This stops hardware feeding and may reboot the gateway.</p><p class="muted">Open the test, tick the acknowledgement box, then run it.</p><div class="button-row">${tripAction}</div>${ready ? '' : '<p class="warning">Trip test is blocked until setup is complete and the service has a recent hardware feed.</p>'}<div class="label">State</div><div class="value">${escapeHtml(tripTest.triggered ? 'Triggered this boot' : (tripTest.completed_previous_boot ? 'Completed on previous boot' : 'Ready'))}</div><div class="label">Countdown verification</div><div class="value">${escapeHtml(tripCountdown.status || 'inactive')}${tripCountdown.current_timeleft == null ? '' : `; ${escapeHtml(tripCountdown.current_timeleft)}s remaining`}</div><div class="label">Last result</div><div class="value">${escapeHtml(tripTest.last_result_message || 'No trip test recorded yet')}</div></div><div class="card"><h2>Extend Timeout</h2><p class="muted">Change the watchdog timeout and restart the service to give the gateway more time before reboot.</p><form method="post" action="/watchdog-timeout-set"><label class="label">Timeout seconds</label><select name="timeout_seconds"><option value="30" ${timeout === 30 ? 'selected' : ''}>30</option><option value="60" ${timeout === 60 ? 'selected' : ''}>60</option><option value="120" ${timeout === 120 ? 'selected' : ''}>120</option><option value="180" ${timeout === 180 ? 'selected' : ''}>180</option><option value="300" ${timeout === 300 ? 'selected' : ''}>300</option></select><div class="button-row"><button class="action" type="submit">Apply timeout</button></div></form><p class="muted">Use a longer timeout while diagnosing reboot loops. Put it back to 30s once stable.</p></div></div><div class="card"><h2>Advanced Tools</h2><p class="muted">Use these only when the guided setup cannot complete.</p><div class="button-row"><a class="ghost" href="/watchdog-legacy-disable-confirm">Clean legacy only</a><a class="ghost" href="/hardware">Hardware details</a><a class="ghost" href="/events#evidence">Diagnostics</a></div></div>`;
}

function renderOperationalStatus(status){
  const checks = status.checks || [];
  const worstState = items => {
    const rank = {healthy: 0, degraded: 1, warning: 2, unknown: 2, critical: 3};
    return (items || []).reduce((worst, item) => (rank[item.state] ?? 2) > (rank[worst] ?? 2) ? item.state : worst, 'healthy');
  };
  const operatorState = (state, configured=true) => {
    if (!configured) return ['Not configured', 'unknown'];
    if (state === 'critical') return ['Failed', 'critical'];
    if (state === 'healthy') return ['Correct', 'healthy'];
    return ['Warning', 'warning'];
  };
  const row = (area, detail, state, href, configured=true) => {
    const [label, cssState] = operatorState(state, configured);
    return `<div class="operational-row"><div class="operational-area">${escapeHtml(area)}</div><div class="operational-detail">${escapeHtml(detail)}</div><div class="operational-state ${cssState}">${escapeHtml(label)}</div><a class="ghost operational-link" href="${escapeHtml(href)}">Details</a></div>`;
  };
  const systemChecks = ['temperature', 'cpu_load', 'ram', 'root_disk', 'write_test'].map(name => findCheck(status, name)).filter(check => check.name);
  const systemState = worstState(systemChecks);
  const systemIssue = systemChecks.find(check => check.state !== 'healthy');
  const services = checks.filter(check => String(check.name || '').endsWith('.service'));
  const healthyServices = services.filter(check => check.state === 'healthy').length;
  const serviceIssue = services.find(check => check.state !== 'healthy');
  const recording = status.recording_storage || {};
  const recordingCheck = findCheck(status, 'recording_storage');
  const recordingConfigured = Boolean(recording.mode || recording.mountpoint || recordingCheck.name);
  const network = findCheck(status, 'network_module');
  const networkConfigured = Boolean(network.name) && !String(network.message || '').toLowerCase().includes('not configured');
  const feed = status.hardware_watchdog_feed || {};
  const watchdogPresent = Boolean(findCheck(status, 'hardware_watchdog_present').value);
  const watchdogConfigured = Boolean(feed.enabled);
  const watchdogState = watchdogPresent && feed.enabled && feed.opened ? 'healthy' : 'warning';
  const watchdogDetail = watchdogPresent ? (feed.enabled && feed.opened ? `Feeding ${feed.device || '/dev/wdt_dio'}` : 'Device detected but hardware recovery is not active') : 'No verified Neousys hardware watchdog device';
  return `<div class="card"><h2>Operational Status</h2><p class="muted">This list shows what is ready and where attention is needed. Open Details for the relevant setup or evidence.</p><div class="operational-list">${row('System', systemIssue?.message || 'Operating system, CPU, memory and root storage checks are normal.', systemState, '/hardware', systemChecks.length > 0)}${row('Services', serviceIssue?.message || `${healthyServices}/${services.length} monitored services running`, worstState(services), '/services', services.length > 0)}${row('Recording storage', recording.message || recordingCheck.message || 'Recording storage has not been configured.', recording.status || recordingCheck.state || 'unknown', '/hardware#storage', recordingConfigured)}${row('Network', network.message || 'Network checks have not been configured.', network.state || 'unknown', '/network', networkConfigured)}${row('Hardware watchdog', watchdogDetail, watchdogState, '/services#watchdog', watchdogConfigured)}</div></div>`;
}

function renderMetricTiles(status){
  const temp = findCheck(status, 'temperature');
  const cpu = findCheck(status, 'cpu_load');
  const ram = findCheck(status, 'ram');
  const root = findCheck(status, 'root_disk');
  const recStorage = status.recording_storage || {};
  const recStorageCheck = {
    state: recStorage.status || findCheck(status, 'recording_storage').state || 'unknown',
    message: recStorage.message || findCheck(status, 'recording_storage').message || 'Recording storage status unavailable',
  };
  const oldestRecordingFound = Boolean(lastRecordingActivity.oldest?.display_local);
  const oldestRecordingValue = lastRecordingActivity.oldest?.display_local || (recStorage.mounted ? 'No recording found' : 'Storage unavailable');
  const oldestRecordingDetail = oldestRecordingFound ? 'Oldest available Videosoft recording' : (recStorage.message || 'No timestamped recording found');
  const oldestRecordingCheck = {state: oldestRecordingFound ? 'healthy' : (recStorage.mounted ? 'warning' : 'critical')};
  const dedicatedStorage = recStorage.mode !== 'system_directory';
  const rootUsed = `${root.value?.used_percent ?? '-'}%`;
  const storageUsed = `${recStorage.used_percent ?? '-'}%`;
  const diskValue = dedicatedStorage ? `Root ${rootUsed}` : `Root / Storage ${rootUsed}`;
  const diskDetail = dedicatedStorage ? (recStorage.mounted ? `Storage ${storageUsed}` : 'Storage unavailable') : `${root.value?.free_gb ?? '-'} GB free`;
  const diskState = root.state !== 'healthy' ? root.state : (dedicatedStorage ? recStorageCheck.state : root.state);
  const wdt = findCheck(status, 'hardware_watchdog_present');
  const wdtFeedCheck = findCheck(status, 'hardware_watchdog_feed_status');
  const wdtFeed = status.hardware_watchdog_feed || {};
  const wdtConfig = lastConfigSummary.hardware_watchdog || {};
  const startupGrace = wdtFeed.startup_grace || {};
  const graceRemaining = Math.max(0, Number(startupGrace.remaining_seconds || 0));
  const graceCountdown = `${Math.floor(graceRemaining / 60)}:${String(graceRemaining % 60).padStart(2, '0')}`;
  const wdtState = startupGrace.active ? 'waiting' : (wdtFeedCheck.state || wdt.state || 'unknown');
  const wdtValue = startupGrace.active ? `Waiting ${graceCountdown}` : (wdtFeed.enabled && wdtFeed.opened ? 'Feeding' : (wdt.value ? 'Not feeding' : 'Not present'));
  const wdtDetails = startupGrace.active
    ? `Safety window: ${graceCountdown} remaining`
    : (wdtFeed.enabled && wdtFeed.opened
      ? `${wdtConfig.timeout_seconds || '-'}s timeout`
      : (wdt.value ? 'Device detected; feed inactive' : 'No verified hardware watchdog'));
  return `<div class="grid metric-grid">${tile('CPU Temp', temp, fmtValue(temp.value, ' C'), temp.message)}${tile('CPU Load', cpu, fmtPercent(cpu.value), cpu.message)}${tile('RAM', ram, fmtPercent(ram.value), ram.message)}${tile('Disk Usage', {state: diskState}, diskValue, diskDetail)}${tile('Oldest Recording', oldestRecordingCheck, oldestRecordingValue, oldestRecordingDetail, 'recording-tile')}${tile('Hardware Recovery', {state: wdtState, message: wdtDetails}, wdtValue, wdtDetails)}</div>`;
}

function renderServices(status){
  const names = [...new Set([...(status.checks || []).filter(c => String(c.name || '').endsWith('.service')).map(c => c.name), ...(lastServiceInfo.services || []).map(item => item.name)])];
  const trend = (name, key, color) => {
    const values = (lastHistory || []).flatMap(row => row.service_metrics || []).filter(item => item.name === name).map(item => Number(item[key])).filter(value => Number.isFinite(value)).slice(-30);
    if (!values.length) return '<span class="muted">No history yet</span>';
    const max = Math.max(1, ...values);
    return `<div class="trend-bars" title="Last ${values.length} retained samples">${values.map(value => `<span class="trend-bar" style="height:${Math.max(4, Math.round((value / max) * 30))}px;background:${color}" title="${value}"></span>`).join('')}</div>`;
  };
  const trendRows = names.map(name => `<tr><td>${escapeHtml(name)}</td><td>${trend(name, 'cpu_percent', 'var(--blue)')}</td><td>${trend(name, 'memory_mb', 'var(--green)')}</td></tr>`).join('');
  const serviceEvents = (lastEvents || []).filter(event => names.some(name => `${event.source || ''} ${event.message || ''}`.includes(name))).slice(0, 5);
  return `<div class="card"><h2>Services</h2><p class="muted">CPU is the service process reading and may differ from whole-system CPU, especially on a multi-core gateway.</p><table><thead><tr><th>Service</th><th>Status</th><th>CPU</th><th>Memory</th><th>Restarts</th><th>Uptime</th></tr></thead><tbody>${serviceRows(status)}</tbody></table></div><div class="grid lower-grid"><div class="card"><h2>Service Trends</h2><p class="muted">Retained samples, normally one per history interval. Blue is CPU; green is memory. Taller bars mean higher usage.</p><table><thead><tr><th>Service</th><th>CPU trend</th><th>Memory trend</th></tr></thead><tbody>${trendRows || '<tr><td colspan="3">No service history captured yet.</td></tr>'}</tbody></table></div><div class="card"><h2>Recent Service Faults</h2>${serviceEvents.length ? renderEvents(serviceEvents, 5) : '<p class="healthy">No recent service-specific events.</p>'}<a class="ghost" href="/events">Open full event history</a></div></div>`;
}

function renderOperationalAlerts(status){
  const hardwarePresent = Boolean(findCheck(status, 'hardware_watchdog_present').value);
  const issues = (status.checks || []).filter(check => check.state !== 'healthy' && !(check.name === 'hardware_watchdog_feed_status' && !hardwarePresent)).slice(0, 6);
  const alertName = name => name === 'hardware_watchdog_present' ? 'Hardware recovery unavailable' : String(name || 'Unknown check').replaceAll('_', ' ');
  const rows = issues.length ? issues.map(check => `<div class="issue-row"><span class="pill ${statusClass(check.state)}">${escapeHtml(String(check.state || 'unknown').toUpperCase())}</span><div><div class="value">${escapeHtml(alertName(check.name))}</div><div class="muted">${escapeHtml(check.message || 'No detail')}</div></div></div>`).join('') : '<div class="issue-row"><span class="pill">CLEAR</span><div><div class="value">No active alerts</div><div class="muted">All current checks are healthy.</div></div></div>';
  return `<div class="card"><h2>Active Alerts</h2><div class="issue-list">${rows}</div><div class="button-row"><a class="ghost" href="/events">Open event history</a></div></div>`;
}

function renderSystemInfo(status){
  const rtc = lastSystemInfo.rtc || {};
  return `<div class="card"><h2>System Information</h2><div class="detail-grid"><div><div class="label">Hostname</div><div class="value">${escapeHtml(lastSystemInfo.hostname || '-')}</div><div class="label">OS</div><div class="value">${escapeHtml(lastSystemInfo.os || '-')}</div><div class="label">Kernel</div><div class="value">${escapeHtml(lastSystemInfo.kernel || '-')}</div><div class="label">Architecture</div><div class="value">${escapeHtml(lastSystemInfo.architecture || '-')}</div><div class="label">Build</div><div class="value">${escapeHtml(lastVersion.branch || '-')} / ${escapeHtml(lastVersion.commit || '-')}</div></div><div><div class="label">Uptime</div><div class="value">${escapeHtml(lastSystemInfo.uptime_seconds ? `${Math.round(lastSystemInfo.uptime_seconds)}s` : '-')}</div><div class="label">Python</div><div class="value">${escapeHtml(lastSystemInfo.python || '-')}</div><div class="label">Timezone</div><div class="value">${escapeHtml((lastSystemInfo.timezone || []).join(' / ') || '-')}</div><div class="label">BIOS/RTC Clock</div><div class="value ${rtc.rtc0_present ? 'healthy' : 'warning'}">${rtc.rtc0_present ? 'RTC present' : 'RTC not confirmed'}</div><div class="label">Config</div><div class="value">${escapeHtml(lastVersion.config_path || '-')}</div></div></div><div class="label">Clock detail</div><pre>${escapeHtml(rtc.hwclock || rtc.timedatectl || 'Clock command output not available')}</pre></div>`;
}

function renderOverview(status, events){
  return `${pageHelp('Overview')}<div class="overview-page">${renderGatewaySummary(status)}${renderOperationalStatus(status)}${renderMetricTiles(status)}${renderOperationalAlerts(status)}</div>`;
}

function renderSimplePage(title, content){
  return `<div class="card"><h2>${escapeHtml(title)}</h2>${content}</div>`;
}

function placeholderList(items){
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

function renderIdentitySettingsCard(){
  const identity = lastSettings.identity || {};
  return `<div class="card"><h2>Gateway Identity</h2><div class="detail-grid"><div><label class="label">Site name</label><input id="set-site-name" maxlength="80" value="${escapeHtml(identity.site_name || '')}" placeholder="e.g. Ellingers"><p class="muted">Shown throughout the watchdog and included in downloaded evidence.</p><label class="label">Asset ID (optional)</label><input id="set-asset-id" maxlength="64" value="${escapeHtml(identity.asset_id || '')}" placeholder="e.g. GW-017"></div><div><div class="label">Hostname</div><div class="value">${escapeHtml(identity.hostname || '-')}</div><div class="label">Hardware fingerprint</div><div class="value">${escapeHtml(identity.hardware_fingerprint || '-')}</div><div class="label">OS disk serial</div><div class="value">${escapeHtml(identity.os_disk?.serial || '-')}</div><div class="label">Recording disk serial</div><div class="value">${escapeHtml(identity.recording_disk?.serial || '-')}</div></div></div><p class="warning">Confirm these serials before changing a remote gateway. Cloned units may share the same hostname.</p></div>`;
}

function renderSettingsPage(){
  const t = lastSettings.thresholds || {};
  const r = lastSettings.retention || {};
  const n = lastSettings.network || {};
  const u = lastSettings.update || {};
  const h = lastSettings.hardware_watchdog || {};
  const rec = lastSettings.recovery || {};
  const rs = lastSettings.recording_storage || {};
  return renderSimplePage('Settings', `<p>Edit common watchdog settings. A backup is made before saving to disk.</p><div class="detail-grid"><div class="mini-card"><h3>Polling and History</h3><label class="label">Poll interval seconds</label><input id="set-poll" type="number" min="2" max="300" value="${escapeHtml(lastSettings.poll_interval_seconds ?? 5)}"><label class="label">History sample seconds</label><input id="set-history-sample" type="number" min="10" max="3600" value="${escapeHtml(r.history_sample_seconds ?? 60)}"><label class="label">History retention days</label><input id="set-history-days" type="number" min="1" max="365" value="${escapeHtml(r.history_retention_days ?? 30)}"><label class="label">Max watchdog storage MB</label><input id="set-max-mb" type="number" min="10" max="4096" value="${escapeHtml(r.max_total_mb ?? 100)}"></div><div class="mini-card"><h3>Storage Thresholds</h3><label class="label">Root warn %</label><input id="set-root-warn" type="number" min="1" max="100" value="${escapeHtml(t.root_disk_warning_percent ?? 80)}"><label class="label">Root critical %</label><input id="set-root-critical" type="number" min="1" max="100" value="${escapeHtml(t.root_disk_critical_percent ?? 95)}"><label class="label">Recordings warn %</label><input id="set-rec-warn" type="number" min="1" max="100" value="${escapeHtml(t.recordings_disk_warning_percent ?? 85)}"><label class="label">Recordings critical %</label><input id="set-rec-critical" type="number" min="1" max="100" value="${escapeHtml(t.recordings_disk_critical_percent ?? 95)}"><label><input id="set-rs-expected-full" type="checkbox" ${rs.expected_full ? 'checked' : ''}> Recording storage is Videosoft managed / expected full</label><label class="label">Recording storage warn below free MB</label><input id="set-rs-min-free-warning" type="number" min="0" max="1048576" value="${escapeHtml(rs.minimum_free_mb_warning ?? '')}" placeholder="blank = disabled"><label class="label">Recording storage critical below free MB</label><input id="set-rs-min-free-critical" type="number" min="0" max="1048576" value="${escapeHtml(rs.minimum_free_mb_critical ?? '')}" placeholder="blank = disabled"><p class="muted">Use expected-full mode when Videosoft manages retention and high used percentage is normal.</p></div><div class="mini-card"><h3>Network</h3><label class="label">Internet hosts, one per line</label><textarea id="set-internet-hosts">${escapeHtml((n.internet_hosts || []).join('\\n'))}</textarea><label class="label">Local targets, one per line</label><textarea id="set-local-targets">${escapeHtml((n.local_targets || []).join('\\n'))}</textarea><label class="label">Remote access services, one per line</label><textarea id="set-remote-services">${escapeHtml((n.remote_access_services || []).join('\\n'))}</textarea></div><div class="mini-card"><h3>Updates and Recovery</h3><label class="label">Update remote</label><input id="set-update-remote" value="${escapeHtml(u.remote || 'origin')}"><label class="label">Update branch</label><input id="set-update-branch" value="${escapeHtml(u.branch || '')}" placeholder="blank = current branch"><label><input id="set-hw-enabled" type="checkbox" ${h.enabled ? 'checked' : ''}> Enable hardware watchdog feed</label><label><input id="set-recovery-enabled" type="checkbox" ${rec.enabled ? 'checked' : ''}> Enable recovery engine</label><label><input id="set-restart-services" type="checkbox" ${rec.restart_failed_services ? 'checked' : ''}> Restart failed critical services</label><label><input id="set-allow-reboot" type="checkbox" ${rec.allow_reboot ? 'checked' : ''}> Allow reboot on persistent critical failure</label></div></div><div class="button-row"><button class="action" onclick="saveSettings()">Save settings</button><button class="ghost" onclick="load()">Reload from service</button></div><p id="settings-feedback"></p><h3>Current config summary</h3><pre>${escapeHtml(JSON.stringify(lastSettings, null, 2))}</pre>${placeholderList(['Service list editor','Install/reconfigure watchdog from Recovery page','Full raw config editor with validation'])}`);
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
  const rec = lastStatus.recording_storage || {};
  const recStatus = rec.status || 'unknown';
  const recRows = [
    ['Status', recStatus.toUpperCase()],
    ['Mode', rec.mode === 'system_directory' ? 'One drive / OS filesystem' : 'Dedicated recording storage'],
    ['Device', rec.device || '-'],
    ['Mountpoint', rec.mountpoint || '-'],
    ['Recordings folder', rec.recordings_path || '-'],
    ['Owner', `${rec.owner || '-'}:${rec.group || '-'}`],
    ['Label', `${rec.label || '-'} / expected ${rec.expected_label || '-'}`],
    ['Filesystem', `${rec.filesystem || '-'} / expected ${rec.expected_filesystem || '-'}`],
    ['Capacity', rec.total_gb !== null && rec.total_gb !== undefined ? `${rec.total_gb} GB` : '-'],
    ['Free space', rec.free_gb !== null && rec.free_gb !== undefined ? `${rec.free_gb} GB` : '-'],
    ['Used %', rec.used_percent !== null && rec.used_percent !== undefined ? `${rec.used_percent}%` : '-'],
    ['Used warn / critical', `${rec.used_warning_percent ?? '-'}% / ${rec.used_critical_percent ?? '-'}%`],
    ['Expected full mode', rec.expected_full ? 'Enabled' : 'Disabled'],
    ['Minimum free MB warn / critical', `${rec.minimum_free_mb_warning ?? '-'} / ${rec.minimum_free_mb_critical ?? '-'}`],
    ['Legacy free warning', rec.free_warning_enabled ? `${rec.free_warning_percent ?? '-'}% free` : 'Disabled'],
    ['Writable', rec.writable ? 'Yes' : 'No'],
    ['SMART', rec.smart_status || '-'],
    ['Temperature', rec.temperature_c !== null && rec.temperature_c !== undefined ? `${rec.temperature_c} C` : '-'],
    ['Last successful check', rec.last_successful_check || rec.checked_at || '-'],
  ].map(row => `<tr><td>${escapeHtml(row[0])}</td><td>${escapeHtml(row[1])}</td></tr>`).join('');
  const guards = rec.recording_service_mount_guards || [];
  const guardRows = guards.length ? guards.map(item => `<tr><td>${escapeHtml(item.service || '-')}</td><td>${escapeHtml(item.mountpoint || '-')}</td><td class="${item.configured ? 'healthy' : 'warning'}">${item.configured ? 'Configured' : 'Not configured'}</td></tr>`).join('') : '<tr><td colspan="3">No recording services configured. Add service names to recording_storage.recording_services when known.</td></tr>';
  const recordingPanel = `<div class="card"><h2>Recording Storage</h2><p class="${escapeHtml(recStatus)}">${escapeHtml(rec.message || 'Recording storage status unavailable')}</p><table><tbody>${recRows}</tbody></table><h3>Recording Service Mount Guard</h3><table><thead><tr><th>Service</th><th>Requires mount</th><th>Status</th></tr></thead><tbody>${guardRows}</tbody></table><div class="button-row"><a class="action" href="/recording-storage-configure">Configure recording storage</a><a class="ghost" href="/api/status">Raw status</a></div><form class="inline" method="post" action="/recording-storage-guard-apply"><label><input type="checkbox" name="ack" value="1"> Apply RequiresMountsFor to configured recording services</label> <button class="ghost" type="submit">Apply service guard</button></form></div>`;
  return `<div class="grid metric-grid">${grouped.storage.map(c => tile(c.name, c, c.value?.used_percent !== undefined ? fmtPercent(c.value.used_percent) : fmtValue(c.value), c.message)).join('')}</div>${recordingPanel}<div class="card"><h2>Configured Storage Limits</h2><table><thead><tr><th>Name</th><th>Path</th><th>Used</th><th>Free</th><th>Warn</th><th>Critical</th><th>Full expected</th></tr></thead><tbody>${rows || '<tr><td colspan="7">No monitored paths configured</td></tr>'}</tbody></table></div>${renderRetentionPage()}`;
}

function renderHistoryPage(){
  const latest = (lastHistory || []).slice(-1)[0] || {};
  const serviceNames = [...new Set((lastHistory || []).flatMap(row => (row.service_metrics || []).map(item => item.name)))];
  const serviceTrend = (name, key, color) => {
    const values = (lastHistory || []).flatMap(row => row.service_metrics || []).filter(item => item.name === name).map(item => Number(item[key])).filter(value => Number.isFinite(value)).slice(-30);
    if (!values.length) return '<span class="muted">No samples yet</span>';
    const max = Math.max(1, ...values);
    return `<div class="trend-bars" title="Last ${values.length} retained samples">${values.map(value => `<span class="trend-bar" style="height:${Math.max(4, Math.round((value / max) * 30))}px;background:${color}" title="${value}"></span>`).join('')}</div>`;
  };
  const serviceRows = serviceNames.map(name => `<tr><td>${escapeHtml(name)}</td><td>${serviceTrend(name, 'cpu_percent', 'var(--blue)')}</td><td>${serviceTrend(name, 'memory_mb', 'var(--green)')}</td></tr>`).join('');
  const serviceHistory = `<div class="card"><h3>Service History</h3><p class="muted">CPU and memory samples retained with the normal history interval. New samples appear after the watchdog has completed a history interval.</p><table><thead><tr><th>Service</th><th>CPU trend</th><th>Memory trend</th></tr></thead><tbody>${serviceRows || '<tr><td colspan="3">No service history has been captured yet.</td></tr>'}</tbody></table></div>`;
  return renderSimplePage('History', `<div class="detail-grid"><div><h3>Health Score</h3>${renderHistoryChart(lastHistory, 'score')}</div><div><h3>Recent Snapshot</h3><div class="label">Samples</div><div class="value">${escapeHtml((lastHistory || []).length)}</div><div class="label">Latest score</div><div class="value">${escapeHtml(latest.score ?? '-')}%</div><div class="label">Latest RAM</div><div class="value">${escapeHtml(latest.ram ?? '-')}%</div><div class="label">Latest CPU temp</div><div class="value">${escapeHtml(latest.temperature ?? '-')}</div><div class="label">Latest root disk</div><div class="value">${escapeHtml(latest.root_disk ?? '-')}%</div></div></div>${serviceHistory}${placeholderList(['Selectable time ranges','CPU temp/load trend','RAM trend','Disk trend','Service failure timeline'])}`);
}

function renderPage(status, updateStatus, events){
  const grouped = groupChecks(status.checks || []);
  if (currentPage === 'Overview') return renderOverview(status, events);
  if (currentPage === 'Hardware') return `${pageHelp('Hardware')}${renderHardwarePage(grouped)}`;
  if (currentPage === 'Watchdog') return renderWatchdogPage(status);
  if (currentPage === 'Services') return `${pageHelp('Services')}${renderServices(status)}`;
  if (currentPage === 'Storage') return `${pageHelp('Storage')}${renderStoragePage(grouped)}`;
  if (currentPage === 'Network') return `${pageHelp('Network')}${renderNetworkPage()}`;
  if (currentPage === 'Recovery') return `${pageHelp('Recovery')}${renderSimplePage('Recovery', `<p class="${escapeHtml(status.recovery?.state || 'unknown')}">${escapeHtml((status.recovery?.state || 'unknown').toUpperCase())}</p><p>${escapeHtml(status.recovery?.message || 'No recovery state available.')}</p>${placeholderList(['Enable/disable recovery','Restart service policy','Reboot grace period','Install/configure hardware watchdog','Last reboot reason'])}`)}`;
  if (currentPage === 'History') return `${pageHelp('History')}${renderHistoryPage()}`;
  if (currentPage === 'Settings') return `${pageHelp('Settings')}${renderIdentitySettingsCard()}${renderSettingsPage()}`;
  if (currentPage === 'Updates') return `${pageHelp('Updates')}${renderUpdatesPage(updateStatus)}`;
  if (currentPage === 'Diagnostics') return `${pageHelp('Diagnostics')}${renderDiagnosticsPage(status, updateStatus)}`;
  return renderOverview(status, events);
}

async function load(){
  lastStatus = await fetchJson('/api/status', lastStatus || {});
  render();

  const core = await Promise.allSettled([
    fetchJson('/api/update-status', lastUpdateStatus || {}),
    fetchJson(currentPage === 'Events' ? '/api/events?limit=5000' : '/api/events?limit=10', lastEvents || []),
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
  if (core[6].status === 'fulfilled') {
    lastVersion = core[6].value;
  }

  const pageFetches = [];
  if (currentPage === 'Overview' || currentPage === 'Services') {
    pageFetches.push(fetchJson('/api/services-info', lastServiceInfo || {}).then(value => { lastServiceInfo = value; }));
    pageFetches.push(fetchJson('/api/history', lastHistory || []).then(value => { lastHistory = value; }));
  }
  if (currentPage === 'Overview' || currentPage === 'Storage') {
    pageFetches.push(fetchJson('/api/recording-activity', lastRecordingActivity || {}).then(value => { lastRecordingActivity = value; }));
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
  document.getElementById('page-title').textContent = `${modeForPage(currentPage)} / ${currentPage}`;
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

function linesFromTextarea(id){
  return String(document.getElementById(id)?.value || '')
    .split(/\\r?\\n/)
    .map(item => item.trim())
    .filter(Boolean);
}

function numberValue(id){
  return Number(document.getElementById(id)?.value);
}

function nullableNumberValue(id){
  const raw = String(document.getElementById(id)?.value ?? '').trim();
  return raw === '' ? null : Number(raw);
}

async function saveSettings(){
  const feedback = document.getElementById('settings-feedback');
  const allowReboot = !!document.getElementById('set-allow-reboot')?.checked;
  if (allowReboot && !confirm('Allowing automatic reboot can restart the gateway if critical checks remain failed. Continue?')) {
    return;
  }
  const payload = {
    identity: {
      site_name: String(document.getElementById('set-site-name')?.value || '').trim(),
      asset_id: String(document.getElementById('set-asset-id')?.value || '').trim(),
    },
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
    recording_storage: {
      expected_full: !!document.getElementById('set-rs-expected-full')?.checked,
      minimum_free_mb_warning: nullableNumberValue('set-rs-min-free-warning'),
      minimum_free_mb_critical: nullableNumberValue('set-rs-min-free-critical'),
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
    window.location.reload();
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
window.saveSettings = saveSettings;
window.purgeOldData = purgeOldData;
window.purgeAllData = purgeAllData;
const LIVE_RENDERED_PAGES = ['Overview'];
initTheme();
if (LIVE_RENDERED_PAGES.includes(currentPage)) {
  buildNav();
  showAdvancedControls();
  initRefresh();
  load();
}
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
        build_at = _quick_run(["git", "show", "-s", "--format=%cI", "HEAD"], cwd=root)
        branch = _quick_run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
        remote = _quick_run(["git", "config", "--get", "remote.origin.url"], cwd=root)
        return {
            "name": "VA-Connect Watchdog",
            "branch": branch,
            "commit": commit,
            "commit_id": commit,
            "build_at": build_at,
            "remote": remote,
            "repo_root": str(root),
            "config_path": str(active_config_path()),
            "data_dir": str(data_dir),
            "identity": configured_identity(cfg),
        }

    page_modes = VISIBLE_PAGE_GROUPS
    server_pages = [item for _, pages in page_modes for item in pages]
    legacy_page_names = {
        "Storage": "Hardware",
        "Watchdog": "Services",
        "History": "Events",
        "Diagnostics": "Events",
        "Recovery": "Settings",
        "Updates": "Settings",
    }

    request_context = local()

    def current_theme_name():
        theme = getattr(request_context, "theme", "light") or "light"
        return theme if theme in {"dark", "light", "steel", "sand"} else "light"

    def mode_for_page(page):
        page = legacy_page_names.get(page, page)
        for mode, pages in page_modes:
            if any(name == page for name, _ in pages):
                return mode
        return "Operations"

    def page_shell(body, page):
        page = legacy_page_names.get(page, page)
        theme = current_theme_name()
        build = version_info().get("commit") or "-"
        site_name = configured_identity(cfg)["display_name"]
        return (
            HTML.replace("__BASIC_DASHBOARD__", body)
            .replace("__SERVER_NAV__", server_nav_html(page))
            .replace("__PAGE_TITLE__", page)
            .replace("__PAGE_MODE__", mode_for_page(page))
            .replace("__BUILD_ID__", escape(str(build)))
            .replace("__SITE_NAME__", escape(str(site_name)))
            .replace("__BODY_THEME__", theme)
        )

    def page_help_html(page):
        help_map = {
            "Overview": ("Is this gateway ready to operate?", "Shows live health, current alerts, the four Videosoft services, and the actions used most often."),
            "Hardware": ("Is the hardware and recording storage healthy?", "Shows sensors, CPU, memory, devices, recording storage health, capacity, permissions, and setup tools."),
            "Services": ("Are the gateway services and watchdog protection running?", "Shows monitored services, confirmed restart controls, and hardware watchdog setup and testing."),
            "Network": ("Can the gateway communicate?", "Shows interfaces, routes, targets, sockets, and remote-access service status."),
            "Events": ("What changed and what evidence is available?", "Review events, retained history, black-box evidence, diagnostics, and exports."),
            "Settings": ("How is this gateway configured and recovered?", "Configure monitoring, updates, recovery, identity, storage, network, and watchdog behaviour."),
        }
        question, detail = help_map.get(page, ("What does this page show?", "Page help unavailable."))
        return (
            "<div class=\"page-intro\"><div>"
            f"<div class=\"page-kicker\">{escape(mode_for_page(page))}</div>"
            f"<h1>{escape(page)}</h1><div class=\"page-question\">{escape(question)}</div>"
            "</div><details class=\"help-popover\"><summary title=\"Page help\">?</summary>"
            f"<p>{escape(detail)}</p></details></div>"
        )

    def page_name_for_path(route_path):
        if route_path in ("", "/"):
            return "Overview"
        cleaned = route_path.strip("/").lower()
        for name, path in server_pages:
            if cleaned == path.strip("/").lower():
                return name
        return "Overview"

    def server_nav_html(current_page):
        current_page = legacy_page_names.get(current_page, current_page)
        links = []
        for mode, pages in page_modes:
            links.append(f"<div class=\"nav-section\">{escape(mode)}</div>")
            for name, path in pages:
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

    def local_time(value):
        if not value:
            return "-"
        text = str(value)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.astimezone().strftime("%H:%M:%S %Y-%m-%d")
        except Exception:
            return text

    def basic_dashboard_html(page="Overview"):
        status = status_snapshot()
        version = version_info()
        update_status = load_update_status(cfg)
        overview_recording_activity = recording_activity(cfg) if page == "Overview" else {}
        critical = bool(status.get("critical_failed", False))
        checks = [check for check in status.get("checks", []) or [] if isinstance(check, dict)]
        check_map = {str(check.get("name", "")): check for check in checks}
        has_any_critical = any(check.get("state") == "critical" for check in checks)
        has_degraded = any(check.get("state") == "degraded" for check in checks)
        has_warning = any(check.get("state") in ("warning", "unknown") for check in checks)
        if critical:
            state = "critical"
        elif has_any_critical or has_warning:
            state = "warning"
        elif has_degraded:
            state = "degraded"
        else:
            state = "healthy"
        word = state.upper()

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

        def tile(title, value, detail, tile_state="healthy", tile_class=""):
            return (
                f"<div class=\"tile {escape(str(tile_class))}\">"
                f"<h3>{escape(str(title))}</h3>"
                f"<div class=\"tile-value {escape(str(tile_state))}\">{escape(str(value))}</div>"
                f"<div class=\"tile-detail\">{escape(str(detail))}</div>"
                "</div>"
            )

        def summary_strip(items):
            cards = []
            for label, value, detail, item_state in items:
                cards.append(
                    "<div class=\"summary-stat\">"
                    f"<div class=\"label\">{escape(str(label))}</div>"
                    f"<div class=\"stat-value {escape(str(item_state or ''))}\">{escape(str(value))}</div>"
                    f"<div class=\"stat-detail\">{escape(str(detail or ''))}</div>"
                    "</div>"
                )
            return f"<div class=\"summary-strip\">{''.join(cards)}</div>"

        def disclosure(title, body, opened=False):
            open_attr = " open" if opened else ""
            return (
                f"<details class=\"section-disclosure\"{open_attr}>"
                f"<summary>{escape(str(title))}</summary>"
                f"<div class=\"section-body\">{body}</div></details>"
            )

        def tool_grid(items):
            cards = []
            for title, detail, href, style in items:
                classes = f"tool-card {style or ''}".strip()
                if href:
                    cards.append(
                        f"<a class=\"{escape(classes)}\" href=\"{escape(str(href))}\">"
                        f"<strong>{escape(str(title))}</strong><span>{escape(str(detail))}</span></a>"
                    )
                else:
                    cards.append(
                        f"<div class=\"{escape(classes)} disabled\">"
                        f"<strong>{escape(str(title))}</strong><span>{escape(str(detail))}</span></div>"
                    )
            return f"<div class=\"tool-grid\">{''.join(cards)}</div>"

        def metric_tiles():
            rec_storage = status.get("recording_storage", {}) if isinstance(status.get("recording_storage", {}), dict) else {}
            watchdog_feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
            startup_grace = watchdog_feed.get("startup_grace", {}) if isinstance(watchdog_feed.get("startup_grace", {}), dict) else {}
            if startup_grace.get("active"):
                watchdog_seconds = int(startup_grace.get("remaining_seconds", 0) or 0)
                watchdog_minutes, watchdog_remainder = divmod(watchdog_seconds, 60)
                watchdog_value = f"Waiting {watchdog_minutes}:{watchdog_remainder:02d}"
                watchdog_state = "waiting"
            elif watchdog_feed.get("enabled") and watchdog_feed.get("opened"):
                watchdog_value = "Feeding"
                watchdog_state = "healthy"
            else:
                watchdog_value = "Not feeding" if check_value("hardware_watchdog_present", False) else "Not present"
                watchdog_state = check_state("hardware_watchdog_feed_status", check_state("hardware_watchdog_present", "warning"))
            rec_storage_state = str(rec_storage.get("status") or check_state("recording_storage", "unknown"))
            oldest_recording = (
                overview_recording_activity.get("oldest", {})
                if isinstance(overview_recording_activity.get("oldest", {}), dict)
                else {}
            )
            if oldest_recording.get("display_local"):
                oldest_recording_value = str(oldest_recording.get("display_local"))
                oldest_recording_detail = "Oldest available Videosoft recording"
            elif rec_storage.get("mounted"):
                oldest_recording_value = "No recording found"
                oldest_recording_detail = "No timestamped recording found"
            else:
                oldest_recording_value = "Storage unavailable"
                oldest_recording_detail = str(rec_storage.get("message") or "Recording storage is not mounted")
            oldest_recording_state = "healthy" if oldest_recording.get("display_local") else ("warning" if rec_storage.get("mounted") else "critical")
            dedicated_storage = rec_storage.get("mode") != "system_directory"
            root_used = disk_used("root_disk")
            disk_value = f"Root {root_used}" if dedicated_storage else f"Root / Storage {root_used}"
            disk_detail = (
                (f"Storage {escape(str(rec_storage.get('used_percent', '-')))}%" if rec_storage.get("mounted") else "Storage unavailable")
                if dedicated_storage
                else disk_free("root_disk")
            )
            disk_state = check_state("root_disk", "healthy")
            if disk_state == "healthy" and dedicated_storage:
                disk_state = rec_storage_state
            return (
                "<div class=\"grid metric-grid\">"
                + tile("CPU Temp", check_value("temperature", "-"), check_message("temperature", ""), check_state("temperature", "healthy"))
                + tile("CPU Load", f"{escape(str(check_value('cpu_load', '-')))}%", check_message("cpu_load", ""), check_state("cpu_load", "healthy"))
                + tile("RAM", f"{escape(str(check_value('ram', '-')))}%", check_message("ram", ""), check_state("ram", "healthy"))
                + tile("Disk Usage", disk_value, disk_detail, disk_state)
                + tile("Oldest Recording", oldest_recording_value, oldest_recording_detail, oldest_recording_state, "recording-tile")
                + tile(
                    "Hardware Recovery",
                    watchdog_value,
                    (
                        f"Safety window: {watchdog_minutes}:{watchdog_remainder:02d} remaining"
                        if startup_grace.get("active")
                        else (
                            f"{cfg.get('hardware_watchdog', {}).get('timeout_seconds', '-')}s timeout"
                            if watchdog_feed.get("enabled") and watchdog_feed.get("opened")
                            else ("Device detected; feed inactive" if check_value("hardware_watchdog_present", False) else "No verified hardware watchdog")
                        )
                    ),
                    watchdog_state,
                )
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
                    "<details class=\"event-card\">"
                    "<summary>"
                    "<div class=\"event-head\">"
                    f"<span class=\"{escape(str(event.get('level', 'info')))}\">{escape(str(event.get('level', 'info')).upper())}</span>"
                    f"<span class=\"event-time\">{escape(local_time(event.get('time')))}</span>"
                    "</div>"
                    f"<div class=\"event-message\">{escape(str(event.get('message', '')))}</div>"
                    "</summary>"
                    f"<div class=\"event-source\">Source: {escape(str(event.get('source', '-')))}</div>"
                    "</details>"
                )
            if not rows:
                rows.append("<div class=\"event\"><div class=\"event-time\">-</div><div>No events yet</div></div>")
            return "".join(rows)

        def events_page():
            query = getattr(request_context, "query", {}) or {}
            filtered, filters = filtered_events(query, limit=5000)
            try:
                display_limit = max(50, min(int(query.get("show", ["50"])[0]), 500))
            except (TypeError, ValueError):
                display_limit = 50
            visible = filtered[:display_limit]

            def event_result(event):
                level = str(event.get("level", "info")).lower()
                data = event.get("data") if isinstance(event.get("data"), dict) else {}
                message = str(event.get("message", "")).lower()
                if data.get("ok") is False or level == "critical":
                    return "Failed", "critical"
                if data.get("ok") is True:
                    return "Success", "healthy"
                if level in {"warning", "degraded"}:
                    return "Attention", "warning"
                if level == "healthy" or "changed to healthy" in message or "restored" in message:
                    return "Recovered", "healthy"
                return "Recorded", "muted"

            rows = []
            for event in visible:
                level = str(event.get("level", "info")).lower()
                result, result_state = event_result(event)
                data = event.get("data") if isinstance(event.get("data"), dict) else {}
                evidence = escape(json.dumps(data, indent=2)) if data else "No additional technical evidence was recorded for this event."
                rows.append(
                    "<tr>"
                    f"<td title=\"{escape(str(event.get('time', '-')))}\">{escape(local_time(event.get('time')))}</td>"
                    f"<td><span class=\"pill {escape(level)}\">{escape(level.upper())}</span></td>"
                    f"<td title=\"{escape(str(event.get('source', '-')))}\">{escape(str(event.get('source', '-')))}</td>"
                    f"<td class=\"event-message-cell\" title=\"{escape(str(event.get('message', '')))}\">{escape(str(event.get('message', '')))}</td>"
                    f"<td class=\"{result_state}\">{result}</td>"
                    "<td><details class=\"event-evidence\"><summary>View</summary>"
                    f"<div class=\"event-evidence-body\"><div class=\"label\">Recorded time</div><div class=\"value\">{escape(str(event.get('time', '-')))}</div><div class=\"label\">Technical evidence</div><pre>{evidence}</pre></div>"
                    "</details></td></tr>"
                )
            if not rows:
                rows.append("<tr><td colspan=\"6\">No events match the selected filters.</td></tr>")

            critical_count = sum(1 for event in filtered if str(event.get("level", "")).lower() == "critical")
            warning_count = sum(1 for event in filtered if str(event.get("level", "")).lower() in {"warning", "degraded"})
            info_count = sum(1 for event in filtered if str(event.get("level", "")).lower() in {"info", "healthy"})
            query_values = {key: value for key, value in filters.items() if value}
            export_query = urlencode(query_values)
            export_suffix = f"?{export_query}" if export_query else ""
            more_values = dict(query_values)
            more_values["view"] = "events"
            more_values["show"] = str(min(display_limit + 50, 500))
            more_link = ""
            if len(visible) < len(filtered) and display_limit < 500:
                more_link = f"<a class=\"ghost\" href=\"/events?{escape(urlencode(more_values))}\">Load 50 more</a>"
            selected_level = filters.get("level", "all")
            options = [
                ("all", "All events"),
                ("attention", "Critical and warnings"),
                ("critical", "Critical"),
                ("warning", "Warning"),
                ("degraded", "Degraded"),
                ("info", "Information"),
                ("healthy", "Recovery/healthy"),
            ]
            level_options = "".join(
                f"<option value=\"{value}\" {'selected' if selected_level == value else ''}>{label}</option>"
                for value, label in options
            )
            return (
                summary_strip([
                    ("Critical", critical_count, "Matching events", "critical" if critical_count else "healthy"),
                    ("Warnings", warning_count, "Warning and degraded", "warning" if warning_count else "healthy"),
                    ("Information", info_count, "Information and recovery", "healthy"),
                ])
                + "<div class=\"card\"><div class=\"section-lead\"><div><h2>Event Log</h2><p class=\"muted\">Manual refresh prevents an event closing while you review its evidence.</p></div>"
                f"<div class=\"muted\">Loaded {escape(datetime.now().astimezone().strftime('%H:%M:%S %Y-%m-%d'))}</div></div>"
                "<form method=\"get\" action=\"/events\"><input type=\"hidden\" name=\"view\" value=\"events\">"
                "<div class=\"toolbar\">"
                f"<label>Level <select name=\"level\">{level_options}</select></label>"
                f"<label>Search <input name=\"search\" value=\"{escape(filters.get('search', ''))}\" placeholder=\"message or evidence\"></label>"
                f"<label>Source <input name=\"source\" value=\"{escape(filters.get('source', ''))}\" placeholder=\"service, storage, watchdog\"></label>"
                f"<label>From <input type=\"datetime-local\" name=\"from\" value=\"{escape(filters.get('from', ''))}\"></label>"
                f"<label>To <input type=\"datetime-local\" name=\"to\" value=\"{escape(filters.get('to', ''))}\"></label>"
                "<button class=\"action\" type=\"submit\">Apply / refresh</button><a class=\"ghost\" href=\"/events?view=events\">Clear filters</a>"
                "</div></form>"
                f"<p class=\"muted\">Showing {len(visible)} of {len(filtered)} matching events. Newest events appear first; times use the gateway's local timezone.</p>"
                "<div class=\"table-scroll\"><table class=\"event-table compact-table\"><thead><tr><th>Time / date</th><th>Level</th><th>Source</th><th>Event</th><th>Result</th><th>Evidence</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table></div>"
                f"<div class=\"button-row\">{more_link}<a class=\"action\" href=\"/api/events/export.csv{escape(export_suffix)}\" download=\"va-watchdog-events.csv\">Export CSV</a><a class=\"ghost\" href=\"/api/events/export{escape(export_suffix)}\" download=\"va-watchdog-events.json\">Export JSON</a></div>"
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
                    f"<td>{escape(str(svc.get('cpu_percent', '-')))}% / {escape(str(svc.get('cpu_system_percent', '-')))}% system</td>"
                    f"<td>{escape(str(svc.get('memory_mb', '-')))} MB</td>"
                    f"<td>{escape(str(svc.get('restarts', '-')))}</td>"
                    f"<td>{escape(str(svc.get('uptime', '-')))}</td>"
                    f"<td>{'Yes' if svc.get('critical') else 'No'}</td>"
                    f"<td><a class=\"ghost\" href=\"/service/{quote(name)}\">Details</a> <a class=\"ghost\" href=\"/service-restart-confirm/{quote(name)}\">Restart</a></td>"
                    "</tr>"
                )
            if not rows:
                rows.append("<tr><td colspan=\"10\">No configured services found.</td></tr>")
            videosoft = [svc for svc in live if svc.get("name") != "va-watchdog"]
            active_count = sum(1 for svc in videosoft if str(svc.get("active", "")) == "active")
            watchdog_service = next((svc for svc in live if svc.get("name") == "va-watchdog"), {})
            critical_failures = sum(1 for svc in live if svc.get("critical") and str(svc.get("active", "")) != "active")
            restart_count = sum(int(svc.get("restarts") or 0) for svc in live)
            return (
                summary_strip([
                    ("Videosoft services", f"{active_count}/{len(videosoft)}", "Running now", "healthy" if videosoft and active_count == len(videosoft) else "warning"),
                    ("Watchdog service", str(watchdog_service.get("active", "unknown")).upper(), "Process monitor", "healthy" if watchdog_service.get("active") == "active" else "critical"),
                    ("Critical failures", critical_failures, "Require attention", "critical" if critical_failures else "healthy"),
                    ("Service restarts", restart_count, "Since service start", "warning" if restart_count else "healthy"),
                    ("Monitoring", "ACTIVE", "Four configured units", "healthy"),
                ])
                + "<div class=\"card\"><h2>Videosoft Services</h2>"
                "<p class=\"muted\">CPU shows per-core usage followed by its whole-system equivalent. For example, 93% per core on a 4-core gateway is about 23% of total CPU capacity.</p>"
                "<div class=\"table-scroll\"><table><thead><tr><th>Service</th><th>Active</th><th>Substate</th><th>Enabled</th><th>CPU / system</th><th>Memory</th><th>Restarts</th><th>Uptime</th><th>Critical</th><th>Actions</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table></div></div>"
            )

        def operational_alerts_card():
            hardware_present = bool(check_value("hardware_watchdog_present", False))
            issues = [
                check
                for check in checks
                if str(check.get("state", "unknown")) != "healthy"
                and not (str(check.get("name", "")) == "hardware_watchdog_feed_status" and not hardware_present)
            ][:6]
            rows = []
            for check in issues:
                item_state = str(check.get("state", "unknown"))
                check_name = str(check.get("name", "Unknown check"))
                display_name = "Hardware recovery unavailable" if check_name == "hardware_watchdog_present" else check_name.replace("_", " ")
                rows.append(
                    "<div class=\"issue-row\">"
                    f"<span class=\"pill {escape(item_state)}\">{escape(item_state.upper())}</span>"
                    "<div>"
                    f"<div class=\"value\">{escape(display_name)}</div>"
                    f"<div class=\"muted\">{escape(str(check.get('message', 'No detail')))}</div>"
                    "</div></div>"
                )
            if not rows:
                rows.append(
                    "<div class=\"issue-row\"><span class=\"pill\">CLEAR</span>"
                    "<div><div class=\"value\">No active alerts</div>"
                    "<div class=\"muted\">All current checks are healthy.</div></div></div>"
                )
            return (
                "<div class=\"card\"><h2>Active Alerts</h2>"
                f"<div class=\"issue-list\">{''.join(rows)}</div>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/events\">Open event history</a></div></div>"
            )

        def updates_card():
            current = version_info()
            update_cfg = cfg.get("update", {}) if isinstance(cfg.get("update", {}), dict) else {}
            log = tail_file(update_cfg.get("log_path") or data_dir / "update.log")
            update_state = str(update_status.get("state", "unknown"))
            log_detail = (
                f"<div class=\"label\">Log file</div><div class=\"value\">{escape(str(log.get('path', '-')))}</div>"
                f"<div class=\"label\">Last log change</div><div class=\"value\">{escape(unix_time(log.get('modified_unix')))}</div>"
                f"<pre>{escape(str(log.get('tail') or 'No update log yet.'))}</pre>"
            )
            return (
                summary_strip([
                    ("Current build", current.get("commit", "-"), current.get("branch", "-"), "healthy"),
                    ("Update state", update_state.upper(), update_status.get("message", "-"), "healthy" if update_state in {"idle", "complete", "completed", "success"} else "warning"),
                    ("Target", update_cfg.get("branch") or current.get("branch", "-"), f"Remote {update_cfg.get('remote', 'origin')}", "healthy"),
                    ("Last update", local_time(update_status.get("updated_at")), update_status.get("commit", "-"), "healthy"),
                ])
                + "<div class=\"card\"><h2>Controlled Update</h2>"
                "<p class=\"section-lead\">Updates pull the configured Git branch and restart this watchdog service. Videosoft services are not deliberately restarted by this action.</p>"
                f"<p class=\"{escape(update_state)}\">{escape(str(update_status.get('message', 'No update has been started.')))}</p>"
                "<a class=\"action\" href=\"/update-confirm\">Update watchdog now</a>"
                "<p class=\"muted\">After starting, the result page returns to Operations automatically. Reopen Updates to confirm the new build and log result.</p>"
                "</div>"
                + disclosure("Update log", log_detail)
                + tool_grid([
                    ("Check-only comparison", "Planned: compare local and remote builds without applying an update.", "", ""),
                    ("Rollback", "Planned: return to a previously validated build after explicit confirmation.", "", ""),
                ])
            )

        def settings_card():
            gateway_identity = identity_summary(cfg)
            thresholds = cfg.get("thresholds", {})
            retention = cfg.get("retention", {})
            network = cfg.get("network", {})
            update = cfg.get("update", {})
            recovery = cfg.get("recovery", {})
            rec_storage = cfg.get("recording_storage", {}) if isinstance(cfg.get("recording_storage", {}), dict) else {}
            hw_cfg = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog", {}), dict) else {}
            current = version_info()
            update_state = str(update_status.get("state", "idle"))
            update_target = update.get("branch") or current.get("branch", "-")
            software_update = (
                summary_strip([
                    ("Running build", current.get("commit", "-"), current.get("branch", "-"), "healthy"),
                    ("Update target", update_target, f"Remote {update.get('remote', 'origin')}", "healthy"),
                    ("Last update", update_state.upper(), local_time(update_status.get("updated_at")), "healthy" if update_state in {"idle", "complete", "completed", "success"} else "warning"),
                ])
                + "<div class=\"card\"><h2>Software Update</h2>"
                "<p>Update VA-Connect Watchdog from the configured Git branch and restart only the watchdog service.</p>"
                "<p class=\"warning\">Check the target branch above before continuing. Save any branch change below before starting the update.</p>"
                "<div class=\"button-row\"><a class=\"action\" href=\"/update-confirm\">Update watchdog</a>"
                "<a class=\"ghost\" href=\"/settings#software-update\">View update details and log</a></div></div>"
            )
            general_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Health check interval</label><input name=\"poll_interval_seconds\" type=\"number\" min=\"2\" max=\"300\" value=\"{escape(str(cfg.get('poll_interval_seconds', 5)))}\"><p class=\"muted\">Seconds between live gateway checks.</p></div>"
                f"<div><label class=\"label\">History sample interval</label><input name=\"history_sample_seconds\" type=\"number\" min=\"10\" max=\"3600\" value=\"{escape(str(retention.get('history_sample_seconds', 60)))}\"><p class=\"muted\">How often a trend sample is stored.</p></div>"
                f"<div><label class=\"label\">History retention</label><input name=\"history_retention_days\" type=\"number\" min=\"1\" max=\"365\" value=\"{escape(str(retention.get('history_retention_days', 30)))}\"><p class=\"muted\">Days of historical samples to retain.</p></div>"
                f"<div><label class=\"label\">Maximum watchdog data</label><input name=\"max_total_mb\" type=\"number\" min=\"10\" max=\"4096\" value=\"{escape(str(retention.get('max_total_mb', 100)))}\"><p class=\"muted\">Self-purge starts when this limit is reached.</p></div>"
                "</div>"
            )
            identity_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Site name</label><input name=\"site_name\" maxlength=\"80\" value=\"{escape(str(gateway_identity.get('site_name', '')))}\" placeholder=\"e.g. Ellingers\"><p class=\"muted\">Shown throughout the watchdog and included in downloaded evidence.</p></div>"
                f"<div><label class=\"label\">Asset ID (optional)</label><input name=\"asset_id\" maxlength=\"64\" value=\"{escape(str(gateway_identity.get('asset_id', '')))}\" placeholder=\"e.g. GW-017\"><p class=\"muted\">Use the number printed on the physical gateway when available.</p></div>"
                "</div>"
                "<div class=\"table-scroll\"><table class=\"compact-table\"><tbody>"
                f"<tr><th>Hostname</th><td>{escape(str(gateway_identity.get('hostname') or '-'))}</td></tr>"
                f"<tr><th>Hardware fingerprint</th><td>{escape(str(gateway_identity.get('hardware_fingerprint') or '-'))}</td></tr>"
                f"<tr><th>OS disk</th><td>{escape(str(gateway_identity.get('os_disk', {}).get('model') or '-'))} / serial {escape(str(gateway_identity.get('os_disk', {}).get('serial') or '-'))}</td></tr>"
                f"<tr><th>Recording disk</th><td>{escape(str(gateway_identity.get('recording_disk', {}).get('model') or '-'))} / serial {escape(str(gateway_identity.get('recording_disk', {}).get('serial') or '-'))}</td></tr>"
                "</tbody></table></div>"
                "<p class=\"warning\">Confirm these serials before changing a remote gateway. Cloned units may share the same hostname.</p>"
            )
            storage_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Root warning used %</label><input name=\"root_disk_warning_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('root_disk_warning_percent', 80)))}\"></div>"
                f"<div><label class=\"label\">Root critical used %</label><input name=\"root_disk_critical_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('root_disk_critical_percent', 95)))}\"></div>"
                f"<div><label class=\"label\">Legacy recordings warning used %</label><input name=\"recordings_disk_warning_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('recordings_disk_warning_percent', 85)))}\"></div>"
                f"<div><label class=\"label\">Legacy recordings critical used %</label><input name=\"recordings_disk_critical_percent\" type=\"number\" min=\"1\" max=\"100\" value=\"{escape(str(thresholds.get('recordings_disk_critical_percent', 95)))}\"></div>"
                "</div>"
                f"<label class=\"option-row\"><input name=\"recording_storage_expected_full\" type=\"checkbox\" {'checked' if rec_storage.get('expected_full') else ''}> <span><strong>Videosoft-managed recording storage</strong><br><span class=\"muted\">High used percentage is normal; alert using minimum free space instead.</span></span></label>"
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Recording warning below free MB</label><input name=\"recording_storage_minimum_free_mb_warning\" type=\"number\" min=\"0\" max=\"1048576\" value=\"{escape(str(rec_storage.get('minimum_free_mb_warning') or ''))}\" placeholder=\"blank = disabled\"></div>"
                f"<div><label class=\"label\">Recording critical below free MB</label><input name=\"recording_storage_minimum_free_mb_critical\" type=\"number\" min=\"0\" max=\"1048576\" value=\"{escape(str(rec_storage.get('minimum_free_mb_critical') or ''))}\" placeholder=\"blank = disabled\"></div>"
                "</div>"
            )
            network_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Internet hosts, one per line</label><textarea name=\"internet_hosts\">{escape(chr(10).join(network.get('internet_hosts', [])))}</textarea><p class=\"muted\">Public hosts used to check internet reachability.</p></div>"
                f"<div><label class=\"label\">Local targets, one per line</label><textarea name=\"local_targets\">{escape(chr(10).join(network.get('local_targets', [])))}</textarea><p class=\"muted\">Router, camera, or local service targets.</p></div>"
                f"<div><label class=\"label\">Remote access services, one per line</label><textarea name=\"remote_access_services\">{escape(chr(10).join(network.get('remote_access_services', [])))}</textarea><p class=\"muted\">Systemd units such as TeamViewer support.</p></div>"
                "</div>"
            )
            recovery_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Update remote</label><input name=\"update_remote\" value=\"{escape(str(update.get('remote', 'origin')))}\"></div>"
                f"<div><label class=\"label\">Update branch</label><input name=\"update_branch\" value=\"{escape(str(update.get('branch', '')))}\" placeholder=\"blank = current branch\"></div>"
                "</div>"
                f"<label class=\"option-row\"><input name=\"recovery_enabled\" type=\"checkbox\" {'checked' if recovery.get('enabled') else ''}> Enable recovery engine</label>"
                f"<label class=\"option-row\"><input name=\"restart_failed_services\" type=\"checkbox\" {'checked' if recovery.get('restart_failed_services') else ''}> Restart failed critical services</label>"
                f"<label class=\"option-row\"><input name=\"allow_reboot\" type=\"checkbox\" {'checked' if recovery.get('allow_reboot') else ''}> Allow gateway reboot after a persistent critical failure</label>"
                "<p class=\"warning\">Automatic reboot should remain disabled until recovery rules have been tested on the gateway.</p>"
            )
            normal_grace = int(hw_cfg.get("startup_grace_seconds", 300) or 0)
            post_trip_grace = int(hw_cfg.get("post_trip_grace_seconds", 900) or 0)
            normal_grace_options = "".join(
                f"<option value=\"{value}\" {'selected' if normal_grace == value else ''}>{label}</option>"
                for value, label in [(60, "1 minute"), (300, "5 minutes"), (600, "10 minutes"), (900, "15 minutes")]
            )
            post_trip_grace_options = "".join(
                f"<option value=\"{value}\" {'selected' if post_trip_grace == value else ''}>{label}</option>"
                for value, label in [(300, "5 minutes"), (900, "15 minutes"), (1800, "30 minutes"), (3600, "60 minutes")]
            )
            watchdog_settings = (
                "<div class=\"settings-grid\">"
                f"<div><label class=\"label\">Normal reboot safety window</label><select name=\"watchdog_startup_grace_seconds\">{normal_grace_options}</select><p class=\"muted\">How long after boot before VA-Connect opens the hardware watchdog.</p></div>"
                f"<div><label class=\"label\">After deliberate trip reboot</label><select name=\"watchdog_post_trip_grace_seconds\">{post_trip_grace_options}</select><p class=\"muted\">Extended window after a deliberate watchdog test to prevent a reboot loop.</p></div>"
                "</div><p>The hardware timeout remains separate and starts only after the safety window ends.</p>"
            )
            journal_state = persistent_status()
            journal_settings = (
                f"<p class=\"{'healthy' if journal_state.get('enabled') else 'warning'}\"><strong>{'Enabled' if journal_state.get('enabled') else 'Disabled or unavailable'}</strong></p>"
                "<p>Persistent journald storage preserves kernel and service evidence across a reboot. Enabling it is an explicit confirmed action and does not overwrite unrelated journald settings.</p>"
                "<div class=\"button-row\"><a class=\"action\" href=\"/journal-enable-confirm\">Enable or apply safe logging limits</a></div>"
            )
            advanced_settings = (
                "<div class=\"label\">Active config file</div>"
                f"<div class=\"value\">{escape(str(active_config_path()))}</div>"
                "<p class=\"muted\">The theme is saved by this browser and is changed from the page header.</p>"
            )
            return (
                software_update
                + "<div class=\"card\"><h2>Gateway Settings</h2>"
                "<p class=\"section-lead\">Settings are grouped by purpose. Saving creates a backup before the new configuration is applied.</p>"
                "<form method=\"post\" action=\"/settings-save\">"
                + disclosure("Gateway identity", identity_settings, opened=True)
                + disclosure("General and monitoring", general_settings, opened=True)
                + disclosure("Watchdog startup safety", watchdog_settings, opened=True)
                + "<div id=\"persistent-journal\">" + disclosure("Persistent evidence logging", journal_settings) + "</div>"
                + disclosure("Storage alerts", storage_settings, opened=True)
                + disclosure("Network and remote access", network_settings)
                + disclosure("Recovery and updates", recovery_settings)
                + disclosure("Advanced configuration", advanced_settings)
                + "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Save settings</button><a class=\"ghost\" href=\"/settings\">Cancel</a></div>"
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
            legacy = watchdog.get("legacy_daemon", {})
            wdt = watchdog_test_summary()
            systemd_wdt = systemd_watchdog_info()
            wizard = hardware_watchdog_wizard_state(watchdog, systemd_wdt)
            prereq_rows = []
            for item in wizard.get("checks", []):
                prereq_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('name', '-')))}</td>"
                    f"<td class=\"{escape(str(item.get('state', 'unknown')))}\">{escape(str(item.get('state', 'unknown')).upper())}</td>"
                    f"<td>{escape(str(item.get('message', '-')))}</td>"
                    "</tr>"
                )
            hardware_state = "healthy" if watchdog_devices else "warning"
            device_detail = (
                "<div class=\"card\"><h2>Detected Devices</h2>"
                f"<div class=\"label\">Watchdog devices</div><div class=\"value\">{escape(', '.join(watchdog_devices) if watchdog_devices else 'None detected')}</div>"
                f"<div class=\"label\">Block devices</div><pre>{escape(chr(10).join(block_devices) if block_devices else 'No block device details available')}</pre>"
                "</div>"
            )
            watchdog_detail = (
                "<div class=\"card\"><h2>Neousys Watchdog Discovery</h2>"
                "<p class=\"muted\">These values identify whether the test driver and vendor API are ready. Setup and testing are managed on the dedicated Watchdog page.</p>"
                "<div class=\"settings-grid\">"
                f"<div><div class=\"label\">Expected driver</div><div class=\"value\">Neousys wdt_dio</div></div>"
                f"<div><div class=\"label\">wdt_dio loaded</div><div class=\"value {'healthy' if modules.get('wdt_dio') else 'warning'}\">{escape('Yes' if modules.get('wdt_dio') else 'No')}</div></div>"
                f"<div><div class=\"label\">Device</div><div class=\"value {'healthy' if '/dev/wdt_dio' in watchdog_devices else 'warning'}\">/dev/wdt_dio</div></div>"
                f"<div><div class=\"label\">Backend</div><div class=\"value\">Neousys WDT_DIO API</div></div>"
                f"<div><div class=\"label\">Driver identity</div><div class=\"value {escape(str(wdctl.get('state', 'unknown')))}\">{escape(str(wdctl.get('identity', '-')))}</div></div>"
                f"<div><div class=\"label\">Driver timeout</div><div class=\"value\">{escape(str(wdctl.get('timeout', '-')))}</div></div>"
                f"<div><div class=\"label\">Legacy watchdog service</div><div class=\"value {'warning' if legacy.get('active') == 'active' else 'healthy'}\">{escape(str(legacy.get('active', '-')).upper())} / {escape(str(legacy.get('enabled', '-')).upper())}</div></div>"
                "</div>"
                "<div class=\"button-row\"><a class=\"action\" href=\"/services#watchdog\">Open Watchdog setup</a><a class=\"ghost\" href=\"/watchdog-hardware-probe-confirm\">Run full probe</a></div>"
                f"{disclosure('Raw watchdog status', '<pre>' + escape(str(wdctl.get('raw', 'Neousys device not present'))) + '</pre>')}"
                f"{disclosure('Setup and probe logs', '<h3>One-click prepare</h3><pre>' + escape(str(watchdog.get('prepare_log', 'No prepare log yet'))) + '</pre><h3>Setup</h3><pre>' + escape(str(watchdog.get('setup_log', 'No setup log yet'))) + '</pre><h3>Full probe</h3><pre>' + escape(str(watchdog.get('probe_log', 'No hardware probe log yet'))) + '</pre>')}"
                "</div>"
            )
            return (
                summary_strip([
                    ("Hardware", "DETECTED", "Gateway sensors available", "healthy"),
                    ("CPU temperature", f"{check_value('temperature', '-')} C", "Current reading", check_state("temperature")),
                    ("CPU load", f"{check_value('cpu_load', '-')}%", f"{cpu.get('cores', '-')} logical cores", check_state("cpu_load")),
                    ("Memory", f"{check_value('ram', '-')}%", f"{memory.get('available_mb', '-')} MB available", check_state("ram")),
                    ("Watchdog device", "Present" if watchdog_devices else "Not present", ", ".join(watchdog_devices) if watchdog_devices else "Run discovery", hardware_state),
                ])
                + "<div class=\"card\"><h2>CPU and Memory</h2>"
                "<p class=\"section-lead\">The live hardware readings used by the health engine.</p>"
                "<div class=\"settings-grid\">"
                f"<div class=\"label\">CPU model</div><div class=\"value\">{escape(str(cpu.get('model', '-')))}</div>"
                f"<div class=\"label\">CPU cores</div><div class=\"value\">{escape(str(cpu.get('cores', '-')))}</div>"
                f"<div class=\"label\">Architecture</div><div class=\"value\">{escape(str(cpu.get('architecture', '-')))}</div>"
                f"<div class=\"label\">RAM total</div><div class=\"value\">{escape(str(memory.get('total_mb', '-')))} MB</div>"
                f"<div class=\"label\">RAM available</div><div class=\"value\">{escape(str(memory.get('available_mb', '-')))} MB</div>"
                "</div></div>"
                + disclosure("Detected devices", device_detail)
                + disclosure("Hardware watchdog discovery", watchdog_detail)
            )

        def watchdog_page():
            info = hardware_info()
            watchdog = info.get("watchdog", {})
            hw_cfg = cfg.get("hardware_watchdog", {})
            trip_test = watchdog.get("trip_test", trip_test_summary(cfg))
            systemd_wdt = watchdog.get("systemd_watchdog", systemd_watchdog_info())
            setup = watchdog_setup_rows(watchdog, systemd_wdt)
            setup_config = setup.get("config", {})
            legacy = watchdog.get("legacy_daemon", {})
            wdctl = watchdog.get("wdctl", {})
            timeout = int(hw_cfg.get("timeout_seconds", 30) or 30)
            checks = setup.get("checks", [])
            by_name = {str(row.get("name", "")): row for row in checks}
            driver = by_name.get("Neousys WDT_DIO driver", {})
            device = by_name.get("Watchdog device", {})
            legacy_check = by_name.get("Legacy daemon", {})
            config_check = by_name.get("Watchdog config", {})
            owner_check = by_name.get("Device owner", {})
            feed_check = by_name.get("Live feed", {})
            process_check = by_name.get("Process watchdog", {})
            trip_ready = bool(setup.get("trip_ready"))
            legacy_units = legacy.get("units", [])
            legacy_problem = str(legacy_check.get("state", "")) == "critical"
            feed_enabled = bool(setup_config.get("enabled"))
            feed_opened = bool(setup_config.get("opened"))
            feed_count = setup_config.get("feed_count", 0)
            startup_grace = setup.get("startup_grace", {}) if isinstance(setup.get("startup_grace", {}), dict) else {}
            grace_active = bool(startup_grace.get("active"))
            remaining_seconds = int(startup_grace.get("remaining_seconds", 0) or 0)
            remaining_minutes, remaining_remainder = divmod(remaining_seconds, 60)
            grace_countdown = f"{remaining_minutes:02d}:{remaining_remainder:02d}"
            if grace_active:
                page_state = "waiting"
                page_title = "Startup safety window active"
                page_message = f"Hardware protection will arm in {grace_countdown}. Remote access remains available while /dev/wdt_dio stays closed."
                primary_action = (
                    "<form class=\"inline\" method=\"post\" action=\"/watchdog-grace-delay\"><input type=\"hidden\" name=\"delay_seconds\" value=\"900\"><button class=\"action\" type=\"submit\">Delay another 15 minutes</button></form> "
                    "<a class=\"ghost\" href=\"/watchdog-arm-now-confirm\">Arm now</a> "
                    "<a class=\"danger\" href=\"/hardware-watchdog-disable-confirm\">Disable hardware feed</a>"
                )
            elif setup.get("ready"):
                page_state = "healthy"
                if trip_test.get("armed"):
                    page_title = "Trip test armed; final confirmation required"
                    page_message = "Hardware feeding continues until you tick the risk box, type TRIP, and submit the final trigger."
                    primary_action = "<a class=\"action\" href=\"/watchdog-trip-confirm\">Continue armed trip confirmation</a>"
                else:
                    page_title = "Hardware watchdog ready"
                    page_message = "The feeder owns /dev/wdt_dio and is feeding it. The deliberate trip test is available."
                    primary_action = "<a class=\"action\" href=\"/watchdog-trip-confirm\">Start deliberate trip test</a>"
            elif legacy_problem:
                page_state = "critical"
                page_title = "Existing watchdog conflict found"
                page_message = "A legacy watchdog service may own the device. Clean legacy watchdogs, then run one-click setup."
                primary_action = "<a class=\"danger\" href=\"/watchdog-legacy-disable-confirm\">Clean legacy watchdogs</a>"
            elif str(driver.get("state", "")) != "healthy" or str(device.get("state", "")) != "healthy":
                page_state = "warning"
                page_title = "Hardware watchdog not fully prepared"
                page_message = "Install the Neousys driver and let the independent feeder configure hardware protection in one step."
                primary_action = "<a class=\"action\" href=\"/hardware-watchdog-prepare-confirm\">Run one-click setup</a>"
            elif not feed_enabled or not feed_opened:
                page_state = "warning"
                page_title = "Hardware feed is not enabled yet"
                page_message = "The hardware exists, but feed is not enabled or the service has not opened the device."
                primary_action = "<a class=\"action\" href=\"/hardware-watchdog-prepare-confirm\">Enable hardware feed</a>"
            else:
                page_state = "warning"
                page_title = "Watchdog needs attention"
                page_message = str(setup.get("message", "Check the setup steps below."))
                primary_action = "<a class=\"action\" href=\"/hardware-watchdog-prepare-confirm\">Run one-click setup</a>"
            timeout_options = "".join(
                f"<option value=\"{value}\" {'selected' if timeout == value else ''}>{value}</option>"
                for value in [30, 60, 120, 180, 300]
            )
            step_rows = []
            for row in checks:
                state = str(row.get("state", "unknown"))
                step_rows.append(
                    f"<div class=\"setup-step {escape(state)}\">"
                    "<div>"
                    f"<div class=\"step-title\">{escape(str(row.get('name', '-')))}</div>"
                    f"<div class=\"step-detail\">{escape(str(row.get('message', '-')))}</div>"
                    "</div>"
                    f"<strong class=\"{escape(state)}\">{escape(state.upper())}</strong>"
                    "</div>"
                )
            config_rows = [
                ("Config file", setup_config.get("path", "-")),
                ("Hardware feed", "Enabled" if setup_config.get("enabled") else "Disabled"),
                ("Device", setup_config.get("device", "-")),
                ("Opened device", "Yes" if setup_config.get("opened") else "No"),
                ("Feed interval", f"{setup_config.get('feed_interval_seconds', '-')} seconds"),
                ("Configured timeout", f"{setup_config.get('timeout_seconds', '-')} seconds"),
                ("Driver identity", wdctl.get("identity", "-")),
                ("Driver timeout", wdctl.get("timeout", "-")),
                ("Device owner", watchdog.get("owners", {}).get("summary", "-")),
                ("Legacy package", legacy.get("package_status", "-")),
                ("Last feed", setup_config.get("last_feed", "-")),
                ("Feed count", setup_config.get("feed_count", 0)),
                ("Normal boot safety window", f"{setup_config.get('startup_grace_seconds', 300)} seconds"),
                ("Post-trip safety window", f"{setup_config.get('post_trip_grace_seconds', 900)} seconds"),
            ]
            config_html = "".join(
                "<tr>"
                f"<td>{escape(str(label))}</td>"
                f"<td>{escape(str(value))}</td>"
                "</tr>"
                for label, value in config_rows
            )
            legacy_rows = "".join(
                "<tr>"
                f"<td>{escape(str(unit.get('unit', '-')))}</td>"
                f"<td class=\"{'critical' if unit.get('active') == 'active' else 'healthy'}\">{escape(str(unit.get('active', '-')))}</td>"
                f"<td class=\"{'warning' if unit.get('enabled') in {'enabled', 'static'} else 'healthy'}\">{escape(str(unit.get('enabled', '-')))}</td>"
                "</tr>"
                for unit in legacy_units
            )
            if not legacy_rows:
                legacy_rows = "<tr><td colspan=\"3\">No legacy watchdog units found.</td></tr>"
            trip_action = (
                "<a class=\"action\" href=\"/watchdog-trip-confirm\">Open trip test</a>"
                if trip_ready
                else "<button class=\"action\" disabled>Open trip test</button>"
            )
            trip_warning = "" if trip_ready else "<p class=\"warning\">Trip test is blocked until setup is complete and the service has a recent hardware feed.</p>"
            legacy_detail = (
                f"<p class=\"{escape(str(legacy_check.get('state', 'unknown')))}\">{escape(str(legacy_check.get('message', '-')))}</p>"
                "<div class=\"table-scroll\"><table class=\"compact-table\"><thead><tr><th>Unit</th><th>Active</th><th>Enabled</th></tr></thead>"
                f"<tbody>{legacy_rows}</tbody></table></div>"
                "<p class=\"muted\">A legacy watchdog service must not compete with the Neousys backend. VA-Connect should be the only hardware feeder.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/watchdog-legacy-disable-confirm\">Clean legacy watchdogs</a><a class=\"ghost\" href=\"/hardware\">Hardware details</a></div>"
            )
            config_detail = (
                "<div class=\"table-scroll\"><table class=\"compact-table\"><tbody>"
                f"{config_html}"
                "</tbody></table></div>"
            )
            layers_detail = (
                "<ul>"
                "<li><strong>Hardware watchdog:</strong> reboots the gateway if VA-Connect stops resetting the Neousys timer.</li>"
                "<li><strong>Hardware feed:</strong> VA-Connect opening and regularly feeding the hardware device.</li>"
                "<li><strong>Process watchdog:</strong> systemd restarting VA-Connect if its Python process hangs.</li>"
                "<li><strong>Legacy watchdog:</strong> an older daemon that must not compete for the same device.</li>"
                "</ul>"
            )
            normal_grace = int(setup_config.get("startup_grace_seconds", 300) or 0)
            post_trip_grace = int(setup_config.get("post_trip_grace_seconds", 900) or 0)
            normal_grace_options = "".join(
                f"<option value=\"{value}\" {'selected' if normal_grace == value else ''}>{label}</option>"
                for value, label in [(60, "1 minute"), (300, "5 minutes"), (600, "10 minutes"), (900, "15 minutes")]
            )
            post_trip_grace_options = "".join(
                f"<option value=\"{value}\" {'selected' if post_trip_grace == value else ''}>{label}</option>"
                for value, label in [(300, "5 minutes"), (900, "15 minutes"), (1800, "30 minutes"), (3600, "60 minutes")]
            )
            grace_state = "WAITING" if grace_active else ("PROTECTION ACTIVE" if feed_opened else "INACTIVE")
            grace_state_class = "waiting" if grace_active else ("healthy" if feed_opened else "warning")
            grace_display = grace_countdown if grace_active else "No delay active"
            grace_explanation = (
                "During this window the hardware device is not opened, so you can reconnect remotely and disable protection without causing another watchdog reboot."
                if grace_active
                else (
                    "The startup delay has finished and the independent feeder owns the Neousys watchdog device."
                    if feed_opened
                    else "Hardware protection is inactive. Complete setup to install the driver and enable the independent feeder."
                )
            )
            grace_controls = (
                "<div class=\"card\"><h2>Startup Safety Window</h2>"
                f"<div class=\"status-word {grace_state_class}\">{grace_state}</div>"
                f"<div class=\"score\" id=\"watchdog-grace-countdown\" data-seconds=\"{remaining_seconds}\">{grace_display}</div>"
                f"<p>{escape(str(startup_grace.get('reason', 'Startup safety state unavailable.')))}</p>"
                f"<p class=\"muted\">{escape(grace_explanation)}</p>"
                "<div class=\"button-row\">"
                "<form class=\"inline\" method=\"post\" action=\"/watchdog-grace-delay\"><input type=\"hidden\" name=\"delay_seconds\" value=\"900\"><button class=\"action\" type=\"submit\" " + ("" if grace_active else "disabled") + ">Delay another 15 minutes</button></form>"
                + ("<a class=\"ghost\" href=\"/watchdog-arm-now-confirm\">End delay and arm now</a>" if grace_active else "")
                + "<a class=\"danger\" href=\"/hardware-watchdog-disable-confirm\">Disable hardware feed</a>"
                "</div><form method=\"post\" action=\"/watchdog-grace-config-set\"><div class=\"settings-grid\">"
                f"<div><label class=\"label\">Normal reboot delay</label><select name=\"startup_grace_seconds\">{normal_grace_options}</select></div>"
                f"<div><label class=\"label\">After deliberate trip reboot</label><select name=\"post_trip_grace_seconds\">{post_trip_grace_options}</select></div>"
                "</div><div class=\"button-row\"><button class=\"ghost\" type=\"submit\">Save safety windows</button></div></form>"
                + ("<script>(function(){var e=document.getElementById('watchdog-grace-countdown');if(!e)return;var s=Number(e.getAttribute('data-seconds')||0);setInterval(function(){if(s<=0)return;s-=1;e.textContent=Math.floor(s/60)+':' + String(s%60).padStart(2,'0');},1000);}());</script>" if grace_active else "")
                + "</div>"
            )
            return (
                summary_strip([
                    ("Overall readiness", "WAITING" if grace_active else ("READY" if setup.get("ready") else "SETUP NEEDED"), page_message, page_state),
                    ("Neousys WDT_DIO", "Loaded" if driver.get("state") == "healthy" else "Needs setup", driver.get("message", "-"), driver.get("state", "unknown")),
                    ("Watchdog device", setup_config.get("device", "/dev/wdt_dio"), wdctl.get("identity") or device.get("message") or "-", device.get("state", "unknown")),
                    ("Live feed", f"Starts in {grace_countdown}" if grace_active else ("Feeding" if feed_enabled and feed_opened else "Not feeding"), f"Feed count {feed_count}", "waiting" if grace_active else ("healthy" if feed_enabled and feed_opened else "warning")),
                    ("Legacy watchdogs", "Clear" if not legacy_problem else "Conflict", legacy_check.get("message", "-"), legacy_check.get("state", "unknown")),
                ])
                + f"<div class=\"card action-panel {escape(page_state)}\"><h2>{escape(page_title)}</h2>"
                f"<p class=\"{escape(page_state)}\">{escape(page_message)}</p>"
                "<div class=\"button-row\">"
                f"{primary_action}"
                "<a class=\"ghost\" href=\"/watchdog-hardware-probe-confirm\">Run probe</a>"
                "</div>"
                "</div>"
                + grace_controls
                + "<div class=\"card\"><h2>Setup Checklist</h2>"
                "<p class=\"section-lead\">Work from top to bottom. The first amber or red item identifies what to fix next.</p>"
                f"<div class=\"setup-steps\">{''.join(step_rows)}</div>"
                "</div>"
                + disclosure("Existing watchdogs and cleanup", legacy_detail, opened=legacy_problem)
                + disclosure("Current configuration", config_detail)
                + disclosure("What the protection layers mean", layers_detail)
                +
                "<div class=\"grid lower-grid\">"
                "<div class=\"card\"><h2>Safe Watchdog Test</h2>"
                "<p class=\"muted\">Double knock: arm the test, then confirm it before it expires. This does not intentionally reboot the gateway.</p>"
                "<div class=\"button-row\"><form class=\"inline\" method=\"post\" action=\"/watchdog-test-arm\"><button class=\"action\" type=\"submit\">Arm safe test</button></form></div>"
                f"<div class=\"label\">Feed enabled</div><div class=\"value\">{'Enabled' if watchdog.get('safe_test', {}).get('feed_enabled') else 'Disabled'}</div>"
                f"<div class=\"label\">Last feed</div><div class=\"value\">{escape(str(watchdog.get('safe_test', {}).get('last_feed_message', 'Not recorded')))}</div>"
                "</div>"
                "<div class=\"card\"><h2>Deliberate Watchdog Trip Test</h2>"
                "<p class=\"warning\">This test intentionally stops hardware feeding for the current boot and may reboot the gateway if the watchdog is healthy.</p>"
                "<p class=\"muted\">Open the test, tick the acknowledgement box, then run it.</p>"
                f"<div class=\"button-row\">{trip_action}</div>"
                f"{trip_warning}"
                f"<div class=\"label\">State</div><div class=\"value\">{escape('Triggered: feeding paused' if trip_test.get('triggered') else ('Completed on previous boot' if trip_test.get('completed_previous_boot') else ('Armed: feeding continues until final confirmation' if trip_test.get('armed') else 'Not armed')))}</div>"
                f"<div class=\"label\">Last result</div><div class=\"value\">{escape(str(trip_test.get('last_result_message', 'No trip test recorded yet')))}</div>"
                f"<div class=\"label\">Armed at</div><div class=\"value\">{escape(str(trip_test.get('armed_at', '-')))}</div>"
                "</div>"
                "<div class=\"card\"><h2>Extend Timeout</h2>"
                "<p class=\"muted\">Change the watchdog timeout and restart the service to give the gateway more time before reboot.</p>"
                "<form method=\"post\" action=\"/watchdog-timeout-set\">"
                f"<label class=\"label\">Timeout seconds</label><select name=\"timeout_seconds\">{timeout_options}</select>"
                "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Apply timeout</button></div>"
                "</form>"
                "<p class=\"muted\">Use a longer timeout while diagnosing reboot loops or slow startup. Put it back to 30s once stable.</p>"
                "</div>"
                "</div>"
                "<div class=\"card\"><h2>Advanced Tools</h2>"
                "<p class=\"muted\">Use these only when the guided setup cannot complete. Diagnostics are intentionally separated from the normal operator path.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/watchdog-legacy-disable-confirm\">Clean legacy only</a><a class=\"ghost\" href=\"/hardware-watchdog-enable-confirm\">Enable feed only</a><a class=\"ghost\" href=\"/hardware\">Hardware details</a><a class=\"ghost\" href=\"/events?view=evidence\">Diagnostics</a></div>"
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
            recording = status_snapshot().get("recording_storage") or recording_storage_status(cfg)
            activity = recording_activity(cfg)
            oldest_activity = activity.get("oldest") if isinstance(activity.get("oldest"), dict) else {}
            rec_rows = [
                ("Status", str(recording.get("status", "unknown")).upper()),
                ("Mode", "One drive / OS filesystem" if recording.get("mode") == "system_directory" else "Dedicated recording storage"),
                ("Device", recording.get("device", "-")),
                ("Mountpoint", recording.get("mountpoint", "-")),
                ("Recordings folder", recording.get("recordings_path", "-")),
                ("Owner", f"{recording.get('owner', '-') or '-'}:{recording.get('group', '-') or '-'}"),
                ("Label", f"{recording.get('label', '-')} / expected {recording.get('expected_label', '-')}"),
                ("Filesystem", f"{recording.get('filesystem', '-')} / expected {recording.get('expected_filesystem', '-')}"),
                ("Capacity", f"{recording.get('total_gb', '-')} GB"),
                ("Free space", f"{recording.get('free_gb', '-')} GB"),
                ("Used %", f"{recording.get('used_percent', '-')}%"),
                ("Used warn / critical", f"{recording.get('used_warning_percent', '-')}% / {recording.get('used_critical_percent', '-')}%"),
                ("Expected full mode", "Enabled" if recording.get("expected_full") else "Disabled"),
                ("Minimum free MB warn / critical", f"{recording.get('minimum_free_mb_warning', '-')} / {recording.get('minimum_free_mb_critical', '-')}"),
                ("Legacy free warning", f"{recording.get('free_warning_percent', '-')}% free" if recording.get("free_warning_enabled") else "Disabled"),
                ("Writable", "Yes" if recording.get("writable") else "No"),
                ("SMART", recording.get("smart_status", "-")),
                ("Temperature", f"{recording.get('temperature_c', '-')} C"),
                ("Last successful check", recording.get("last_successful_check") or recording.get("checked_at", "-")),
            ]
            rec_html = "".join(
                "<tr>"
                f"<td>{escape(str(label))}</td>"
                f"<td>{escape(str(value))}</td>"
                "</tr>"
                for label, value in rec_rows
            )
            guard_rows = "".join(
                "<tr>"
                f"<td>{escape(str(item.get('service', '-')))}</td>"
                f"<td>{escape(str(item.get('mountpoint', '-')))}</td>"
                f"<td class=\"{'healthy' if item.get('configured') else 'warning'}\">{escape('Configured' if item.get('configured') else 'Not configured')}</td>"
                "</tr>"
                for item in recording.get("recording_service_mount_guards", [])
            )
            if not guard_rows:
                guard_rows = "<tr><td colspan=\"3\">No recording services configured. Add service names to recording_storage.recording_services when known.</td></tr>"
            rec_state = str(recording.get("status", "unknown"))
            limits_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>Name</th><th>Path</th><th>Used</th><th>Free</th><th>Warn</th><th>Critical</th><th>Full expected</th></tr></thead>"
                f"<tbody>{''.join(volume_rows)}</tbody></table></div>"
            )
            retention_detail = (
                f"<div class=\"label\">Data directory</div><div class=\"value\">{escape(str(retention.get('data_dir', '-')))}</div>"
                f"<div class=\"label\">Used</div><div class=\"value\">{escape(str(retention.get('used_mb', '-')))} MB / {escape(str(retention.get('max_total_mb', '-')))} MB</div>"
                f"<div class=\"label\">Events retention</div><div class=\"value\">{escape(str(retention.get('events_retention_days', '-')))} days</div>"
                f"<div class=\"label\">History retention</div><div class=\"value\">{escape(str(retention.get('history_retention_days', '-')))} days</div>"
                "<p class=\"muted\">Old watchdog data is self-purged when the configured limit is reached. Recordings are never purged by this control.</p>"
                "<div class=\"button-row\">"
                "<form class=\"inline\" method=\"post\" action=\"/storage-purge-old\">"
                f"<label class=\"label\">Older than days</label><input name=\"older_than_days\" type=\"number\" min=\"0\" max=\"3650\" value=\"{escape(str(default_days))}\"> "
                "<button class=\"action\" type=\"submit\">Purge old watchdog data</button>"
                "</form>"
                "<a class=\"ghost\" href=\"/storage-purge-confirm\">Purge all non-status data</a>"
                "<a class=\"ghost\" href=\"/settings\">Edit retention</a>"
                "</div>"
            )
            files_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead>"
                f"<tbody>{''.join(file_rows)}</tbody></table></div>"
            )
            return (
                summary_strip([
                    ("Recording storage", rec_state.upper(), recording.get("message", "Status unavailable"), rec_state),
                    ("Mounted", "Yes" if recording.get("mounted") else "No", recording.get("mountpoint", "-"), "healthy" if recording.get("mounted") else "critical"),
                    ("Writable", "Yes" if recording.get("writable") else "No", recording.get("recordings_path", "-"), "healthy" if recording.get("writable") else "critical"),
                    ("Free space", f"{recording.get('free_gb', '-')} GB", f"{recording.get('used_percent', '-')}% used", rec_state),
                    ("Oldest recording", oldest_activity.get("display_local", "Not found"), "Oldest footage currently available", "healthy" if activity.get("available") else "warning"),
                    ("SMART", recording.get("smart_status", "-"), f"{recording.get('temperature_c', '-')} C", "warning" if str(recording.get("smart_status", "")).lower() == "unavailable" else rec_state),
                ])
                + "<div class=\"card\"><h2>Recording Storage</h2>"
                f"<p class=\"{escape(rec_state)}\">{escape(str(recording.get('message', 'Recording storage status unavailable')))}</p>"
                "<div class=\"table-scroll\"><table><tbody>"
                f"{rec_html}"
                "</tbody></table></div>"
                "<h3>Recording Service Mount Guard</h3>"
                "<div class=\"table-scroll\"><table><thead><tr><th>Service</th><th>Requires mount</th><th>Status</th></tr></thead>"
                f"<tbody>{guard_rows}</tbody></table></div>"
                "<div class=\"button-row\"><a class=\"action\" href=\"/recording-storage-configure\">Configure recording storage</a><a class=\"ghost\" href=\"/api/status\">Raw status</a></div>"
                "<form class=\"inline\" method=\"post\" action=\"/recording-storage-guard-apply\"><label><input type=\"checkbox\" name=\"ack\" value=\"1\"> Apply RequiresMountsFor to configured recording services</label> <button class=\"ghost\" type=\"submit\">Apply service guard</button></form>"
                "</div>"
                + disclosure("Configured storage limits", limits_detail)
                + disclosure("Watchdog data retention and purge", retention_detail)
                + disclosure("Watchdog data files", files_detail)
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
            ping_items = info.get("pings", [])
            ping_ok = sum(1 for item in ping_items if item.get("ok"))
            remote_items = info.get("remote_access", [])
            remote_ok = sum(1 for item in remote_items if item.get("active"))
            interface_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>Name</th><th>State</th><th>Addresses</th></tr></thead>"
                f"<tbody>{''.join(interfaces)}</tbody></table></div>"
                f"<div class=\"label\">Default route</div><pre>{escape(str(info.get('default_route', '-')))}</pre>"
            )
            support_detail = (
                f"<ul>{urls}</ul>"
                "<p class=\"muted\">Use the gateway IP remotely in the form http://IP:9110/. This keeps the port at the end for forwarding software.</p>"
                f"<div class=\"label\">DNS</div><pre>{escape(str(info.get('dns', '-')))}</pre>"
            )
            route_detail = (
                f"<div class=\"label\">Route table</div><pre>{escape(str(info.get('route_table', '-')))}</pre>"
                f"<div class=\"label\">LAN neighbours</div><pre>{escape(str(info.get('neighbours', '-')))}</pre>"
                f"<div class=\"label\">Listening TCP sockets</div><pre>{escape(str(info.get('listening_sockets', 'ss output not available')))}</pre>"
            )
            speed_test_card = (
                "<div class=\"card\"><h2>Internet Speed Test</h2>"
                "<p class=\"section-lead\">Runs a short manual test for latency, download and upload speed. "
                "It does not run during normal health checks and does not change the gateway health score.</p>"
                "<form class=\"inline\" method=\"post\" action=\"/network-speed-test\">"
                "<button class=\"action\" type=\"submit\">Run speed test</button></form></div>"
            )
            return (
                summary_strip([
                    ("Gateway", info.get("hostname", "-"), info.get("ip_addresses", "-") or "-", "healthy"),
                    ("Dashboard", f"Port {info.get('listening_port', '-')}", local_web.get("detail", "-"), "healthy" if local_web.get("ok") else "warning"),
                    ("Connectivity", f"{ping_ok}/{len(ping_items)}", "Configured targets reachable", "healthy" if ping_items and ping_ok == len(ping_items) else "warning"),
                    ("Remote access", f"{remote_ok}/{len(remote_items)}", "Support services active", "healthy" if remote_items and remote_ok == len(remote_items) else "warning"),
                ])
                +
                "<div class=\"card\"><h2>Connectivity Checks</h2>"
                "<p class=\"section-lead\">Configured internet, local device, and TCP checks. Add or change targets in Settings.</p>"
                "<div class=\"table-scroll\"><table><thead><tr><th>Target</th><th>Host</th><th>Port</th><th>Ping</th><th>TCP</th><th>Overall</th><th>Detail</th></tr></thead>"
                f"<tbody>{''.join(ping_rows)}</tbody></table></div></div>"
                "<div class=\"card\"><h2>Remote Access Services</h2>"
                "<div class=\"table-scroll\"><table><thead><tr><th>Service</th><th>Status</th><th>Enabled</th><th>Detail</th></tr></thead>"
                f"<tbody>{''.join(remote_rows)}</tbody></table></div>"
                "<p class=\"muted\">TeamViewer or other support tooling can be tracked here by adding the systemd service name in Settings.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/settings\">Edit network targets</a></div></div>"
                + speed_test_card
                + disclosure("Interfaces and default route", interface_detail)
                + disclosure("Support URLs and DNS", support_detail)
                + disclosure("Routes, neighbours, and listening sockets", route_detail)
                + disclosure("Health-engine network check", all_checks_table("Network Check", {"network_module"}))
            )

        def speed_test_result_html(result):
            status = "HEALTHY" if result.get("ok") else "WARNING"
            status_class = "healthy" if result.get("ok") else "warning"
            errors = result.get("errors") or []
            error_html = "" if not errors else "<div class=\"notice warning\"><strong>Some measurements failed:</strong><ul>" + "".join(
                f"<li>{escape(str(error))}</li>" for error in errors
            ) + "</ul></div>"
            body = (
                "<div class=\"card\"><h2>Internet Speed Test</h2>"
                f"<p class=\"{status_class}\"><strong>{status}</strong></p>"
                "<div class=\"table-scroll\"><table><tbody>"
                f"<tr><th>Latency</th><td>{escape(str(result.get('latency_ms') if result.get('latency_ms') is not None else '-'))} ms</td></tr>"
                f"<tr><th>Download</th><td>{escape(str(result.get('download_mbps') if result.get('download_mbps') is not None else '-'))} Mbps</td></tr>"
                f"<tr><th>Upload</th><td>{escape(str(result.get('upload_mbps') if result.get('upload_mbps') is not None else '-'))} Mbps</td></tr>"
                f"<tr><th>Test duration</th><td>{escape(str(result.get('duration_seconds', '-')))} seconds</td></tr>"
                f"<tr><th>Test time</th><td>{escape(str(result.get('tested_at', '-')))}</td></tr>"
                "</tbody></table></div>"
                f"{error_html}<p class=\"muted\">The test used a small, bounded transfer through speed.cloudflare.com.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/network\">Back to Network</a></div></div>"
            )
            return page_shell(body, "Network")

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
            configured_services = [item for item in cfg.get("services", []) if isinstance(item, dict) and item.get("name")]
            active_services = sum(
                1 for item in configured_services
                if str(check_map.get(str(item.get("name")), {}).get("state", "unknown")) == "healthy"
            )
            recovery_tools = [
                (f"Restart {item.get('name')}", "Open a confirmation page before restarting this Videosoft service.", f"/service-restart-confirm/{quote(str(item.get('name')))}", "")
                for item in configured_services
            ]
            recovery_tools.extend([
                ("Reinstall watchdog service", "Repair the VA-Connect systemd installation without deleting configuration or data.", "/recovery-install-confirm", "primary"),
                ("Update VA-Connect", "Open controlled build update and result details.", "/updates", ""),
                ("Download support bundle", "Collect status, journals, history, storage, network, and reboot evidence.", "/api/diagnostics/support-bundle.zip", ""),
                ("Hardware watchdog controls", "Open setup, timeout, and deliberate test controls.", "/watchdog", ""),
                ("Restart gateway", "Planned emergency action. Not enabled until field policy is agreed.", "", "danger"),
            ])
            recovery_detail = (
                f"<div class=\"label\">Current state</div><div class=\"value {escape(str(recovery.get('state', 'unknown')))}\">{escape(str(recovery.get('state', 'unknown')).upper())}</div>"
                f"<div class=\"label\">Message</div><div class=\"value\">{escape(str(recovery.get('message', '-')))}</div>"
                f"<div class=\"label\">Updated</div><div class=\"value\">{escape(local_time(recovery.get('updated_at')))}</div>"
                f"<div class=\"label\">Last reboot reason</div><pre>{escape(json.dumps(reboot, indent=2) if reboot else 'No watchdog reboot reason recorded.')}</pre>"
            )
            install_detail = (
                f"<div class=\"label\">Service unit</div><div class=\"value {escape(str(install.get('unit_state', 'unknown')))}\">{escape(str(install.get('unit_path', '-')))}</div>"
                f"<div class=\"label\">Service active</div><div class=\"value {escape(str(install.get('active', 'unknown')))}\">{escape(str(install.get('active', '-')).upper())}</div>"
                f"<div class=\"label\">Service enabled</div><div class=\"value\">{escape(str(install.get('enabled', '-')).upper())}</div>"
                f"<div class=\"label\">Install path</div><div class=\"value\">{escape(str(install.get('install_path', '-')))}</div>"
                f"<div class=\"label\">Config path</div><div class=\"value\">{escape(str(active_config_path()))}</div>"
                f"<div class=\"label\">Data directory</div><div class=\"value\">{escape(str(data_dir))}</div>"
                f"<div class=\"label\">Install log</div><div class=\"value\">{escape(str(install.get('log_path', '-')))}</div>"
            )
            policy_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>Service</th><th>Critical</th><th>Restart allowed</th></tr></thead>"
                f"<tbody>{''.join(service_rows)}</tbody></table></div>"
                f"<p class=\"muted\">Recovery engine enabled: {escape(str(cfg_recovery.get('enabled', False)))}. Restart failed services: {escape(str(cfg_recovery.get('restart_failed_services', False)))}. Allow reboot: {escape(str(cfg_recovery.get('allow_reboot', False)))}.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/settings\">Edit recovery policy</a></div>"
            )
            return (
                summary_strip([
                    ("Recovery engine", "Enabled" if cfg_recovery.get("enabled") else "Disabled", recovery.get("message", "-"), "healthy" if cfg_recovery.get("enabled") else "warning"),
                    ("Videosoft services", f"{active_services}/{len(configured_services)}", "Running now", "healthy" if configured_services and active_services == len(configured_services) else "critical"),
                    ("Watchdog service", str(install.get("active", "unknown")).upper(), str(install.get("enabled", "-")).upper(), "healthy" if install.get("active") == "active" else "critical"),
                    ("Automatic reboot", "Allowed" if cfg_recovery.get("allow_reboot") else "Blocked", f"Grace {cfg_recovery.get('critical_grace_seconds', '-')}s", "warning" if cfg_recovery.get("allow_reboot") else "healthy"),
                ])
                + "<div class=\"card\"><h2>Recovery Toolbox</h2>"
                "<p class=\"section-lead\">Every live action opens a confirmation or download. Disabled cards identify planned controls that are not safe to expose yet.</p>"
                + tool_grid(recovery_tools)
                + "</div>"
                + disclosure("Current recovery status and reboot evidence", recovery_detail, opened=bool(reboot))
                + disclosure("Watchdog installation details", install_detail)
                + disclosure("Recovery policy matrix", policy_detail)
            )

        def history_page():
            samples = read_history(cfg, limit=288)
            summary = history_summary(samples)
            retention = cfg.get("retention", {})
            warning_count = sum(1 for item in samples if str(item.get("state", "")).lower() in {"warning", "degraded"})
            critical_count = sum(1 for item in samples if str(item.get("state", "")).lower() == "critical" or item.get("critical_failed"))
            last_abnormal = next((item for item in reversed(samples) if str(item.get("state", "healthy")).lower() != "healthy"), None)

            state_rows = [
                f"<tr><td class=\"{escape(str(item_state))}\">{escape(str(item_state).upper())}</td><td>{escape(str(count))}</td></tr>"
                for item_state, count in summary.get("state_counts", {}).items()
            ] or ["<tr><td colspan=\"2\">No states recorded.</td></tr>"]

            sample_rows = []
            for item in samples[-48:]:
                sample_rows.append(
                    "<tr>"
                    f"<td>{escape(local_time(item.get('time')))}</td>"
                    f"<td class=\"{escape(str(item.get('state', 'unknown')))}\">{escape(str(item.get('state', 'unknown')).upper())}</td>"
                    f"<td>{escape(str(item.get('temperature', '-')))}</td>"
                    f"<td>{escape(str(item.get('cpu_load', '-')))}%</td>"
                    f"<td>{escape(str(item.get('ram', '-')))}%</td>"
                    f"<td>{escape(str(item.get('root_disk', '-')))}%</td>"
                    f"<td>{escape(str(item.get('recordings_disk', '-')))}%</td>"
                    "</tr>"
                )
            if not sample_rows:
                sample_rows.append("<tr><td colspan=\"7\">No history samples have been captured yet.</td></tr>")

            abnormal_rows = []
            abnormal_samples = [item for item in samples if str(item.get("state", "healthy")).lower() != "healthy"][-20:]
            for item in reversed(abnormal_samples):
                conditions = item.get("critical_checks") or item.get("warning_checks") or item.get("degraded_checks") or []
                detail = ", ".join(str(value) for value in conditions) or "State outside healthy"
                abnormal_rows.append(
                    f"<tr><td>{escape(local_time(item.get('time')))}</td>"
                    f"<td class=\"{escape(str(item.get('state', 'unknown')))}\">{escape(str(item.get('state', 'unknown')).upper())}</td>"
                    f"<td>{escape(detail)}</td></tr>"
                )
            if not abnormal_rows:
                abnormal_rows.append("<tr><td colspan=\"3\">No abnormal samples in the retained window.</td></tr>")

            extra_charts = (
                "<div class=\"grid lower-grid\"><div><h3>Temperature Trend</h3>"
                f"{history_chart(samples, 'temperature', 0, 100, 'C')}"
                "</div><div><h3>Disk Usage Trend</h3>"
                f"{multi_history_chart(samples, [('root_disk', 'Root'), ('recordings_disk', 'Recordings')], 0, 100, '%')}"
                "</div></div>"
            )
            service_names = sorted({
                str(metric.get("name"))
                for sample in samples
                for metric in (sample.get("service_metrics") or [])
                if isinstance(metric, dict) and metric.get("name")
            })
            service_trend_rows = [
                f"<tr><td>{escape(name)}</td><td>{service_combined_history_chart(samples, name)}</td></tr>"
                for name in service_names
            ] or ['<tr><td colspan="2">No service history samples have been captured yet.</td></tr>']
            service_history_detail = (
                '<div class="table-scroll"><table><thead><tr><th>Service</th><th>CPU and RAM trend</th></tr></thead>'
                f"<tbody>{''.join(service_trend_rows)}</tbody></table></div>"
            )
            abnormal_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>Time</th><th>State</th><th>Recorded condition</th></tr></thead>"
                f"<tbody>{''.join(abnormal_rows)}</tbody></table></div>"
            )
            export_detail = (
                "<div class=\"grid lower-grid\"><div><h3>State Counts</h3><table><thead><tr><th>State</th><th>Samples</th></tr></thead>"
                f"<tbody>{''.join(state_rows)}</tbody></table></div><div><h3>History Export</h3>"
                f"<div class=\"label\">Time range</div><div class=\"value\">{escape(local_time(summary.get('first_time')))} to {escape(local_time(summary.get('last_time')))}</div>"
                "<div class=\"button-row\"><a class=\"action\" href=\"/api/history/export.csv\" download=\"va-watchdog-history.csv\">Export CSV</a><a class=\"ghost\" href=\"/api/history\" download=\"va-watchdog-history.json\">Export JSON</a></div></div></div>"
            )
            samples_detail = (
                "<div class=\"table-scroll\"><table><thead><tr><th>Time</th><th>State</th><th>Temp</th><th>CPU</th><th>RAM</th><th>Root Disk</th><th>Recordings Disk</th></tr></thead>"
                f"<tbody>{''.join(sample_rows)}</tbody></table></div>"
            )
            return (
                summary_strip([
                    ("Samples", summary.get("samples", 0), "Retained window", "healthy"),
                    ("History period", f"{retention.get('history_retention_days', '-')} days", "Configured retention", "healthy"),
                    ("Warnings", warning_count, "Warning/degraded samples", "warning" if warning_count else "healthy"),
                    ("Critical", critical_count, "Critical samples", "critical" if critical_count else "healthy"),
                    ("Last abnormal", local_time(last_abnormal.get("time")) if last_abnormal else "None", str(last_abnormal.get("state", "")).upper() if last_abnormal else "Retained window clear", "warning" if last_abnormal else "healthy"),
                ])
                + "<div class=\"card\"><h2>Gateway CPU and RAM</h2><p class=\"muted\">Lightweight retained samples leading up to an incident.</p>"
                + multi_history_chart(samples, [("cpu_load", "CPU load"), ("ram", "RAM")], 0, 100, "%")
                + "</div>"
                + disclosure("Abnormal periods", abnormal_detail, opened=bool(last_abnormal))
                + disclosure("Temperature and disk trends", extra_charts)
                + disclosure("Service history", service_history_detail)
                + disclosure("History export and state counts", export_detail)
                + disclosure("Recent raw samples", samples_detail)
            )

        def diagnostics_page():
            service_status = _run(["systemctl", "is-active", "va-watchdog"], timeout=3)
            service_enabled = _run(["systemctl", "is-enabled", "va-watchdog"], timeout=3)
            bb = blackbox_summary(cfg)
            incident_archives = list_archives(cfg)
            pstore = pstore_status()
            baseline = baseline_status(cfg)
            active_value = str(service_status.get("stdout") or service_status.get("stderr") or "unknown")
            enabled_value = str(service_enabled.get("stdout") or service_enabled.get("stderr") or "unknown")
            baseline_state = str(baseline.get("state") or "idle")
            baseline_class = "healthy" if baseline_state == "complete" else "critical" if baseline_state == "failed" else "warning" if baseline_state in {"queued", "running"} else "muted"
            readiness = baseline.get("readiness") if isinstance(baseline.get("readiness"), dict) else {}
            readiness_rows = []
            for item in readiness.get("checks", []):
                advisory = bool(item.get("advisory"))
                item_ok = bool(item.get("ok"))
                item_class = "healthy" if item_ok else "warning" if advisory else "critical"
                item_status = "Ready" if item_ok else "Attention" if advisory else "Blocked"
                readiness_rows.append(
                    "<tr>"
                    f"<td>{escape(str(item.get('name', '-')))}</td>"
                    f"<td class=\"{item_class}\">{item_status}</td>"
                    f"<td>{escape(str(item.get('detail', '-')))}</td>"
                    "</tr>"
                )
            archive = baseline.get("archive") if isinstance(baseline.get("archive"), dict) else {}
            download_button = (
                "<a class=\"action\" href=\"/api/diagnostics/stage0-baseline.tar.gz\">Download completed baseline</a>"
                if baseline.get("download_ready") else ""
            )
            form_disabled = " disabled" if baseline.get("running") or not readiness.get("ready") else ""
            baseline_refresh = "<p class=\"warning\">Capture is running. Reload Evidence manually to check progress.</p>" if baseline.get("running") else ""
            baseline_card = (
                "<div class=\"card\"><h2>Stage 0 System Baseline</h2>"
                "<p class=\"section-lead\">Runs a low-impact performance and evidence capture in a separate systemd unit. It does not restart the watchdog or change monitoring configuration.</p>"
                f"<p class=\"{baseline_class}\"><strong>{escape(baseline_state.upper())}</strong> - {escape(str(baseline.get('message', 'No status available.')))}</p>"
                "<div class=\"detail-grid\"><div>"
                f"<div class=\"label\">Started</div><div class=\"value\">{escape(local_time(baseline.get('started_utc')))}</div>"
                f"<div class=\"label\">Duration</div><div class=\"value\">{escape(str(baseline.get('duration_label') or baseline.get('duration_seconds') or '-'))}</div>"
                f"<div class=\"label\">Elapsed</div><div class=\"value\">{escape(str(baseline.get('elapsed_seconds', 0)))} seconds</div>"
                "</div><div>"
                f"<div class=\"label\">Systemd unit</div><div class=\"value\">{escape(str(baseline.get('unit') or '-'))}</div>"
                f"<div class=\"label\">Archive</div><div class=\"value\">{escape(str(archive.get('name') or '-'))}</div>"
                f"<div class=\"label\">Archive size</div><div class=\"value\">{escape(human_size(archive.get('size_bytes', 0))) if archive else '-'}</div>"
                "</div></div>"
                "<form method=\"post\" action=\"/stage0-baseline-start\">"
                "<label class=\"label\">Capture duration</label><select name=\"duration\"><option value=\"900\">15 minutes</option><option value=\"3600\" selected>1 hour</option></select>"
                "<label class=\"option-row\"><input type=\"checkbox\" name=\"ack\" value=\"1\"> <span>I understand this starts a temporary low-impact diagnostic capture.</span></label>"
                f"<div class=\"button-row\"><button class=\"action\" type=\"submit\"{form_disabled}>Start baseline capture</button>{download_button}<a class=\"ghost\" href=\"/api/diagnostics/stage0-baseline\">Raw capture status</a></div>"
                "</form>"
                "<details><summary>Capture readiness checks</summary><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>"
                f"<tbody>{''.join(readiness_rows)}</tbody></table></details>"
                "<p class=\"muted\">Up to three completed baseline bundles are retained for seven days. CCTV recordings are never included.</p>"
                f"{baseline_refresh}</div>"
            )
            journal_state = persistent_status()
            advanced_detail = (
                tool_grid([
                    ("Live diagnostics JSON", "Current operating-system and watchdog diagnostic data.", "/api/diagnostics", ""),
                    ("Raw health status", "Unchanged /api/status payload used by integrations.", "/api/status", ""),
                ])
                + all_checks_table("All health-engine checks")
            )
            return (
                summary_strip([
                    ("Watchdog service", active_value.upper(), f"Enabled: {enabled_value}", "healthy" if active_value == "active" else "critical"),
                    ("Black-box recorder", "Enabled" if bb.get("enabled") else "Disabled", f"{bb.get('rows', 0)} snapshots", "healthy" if bb.get("enabled") else "warning"),
                    ("Latest snapshot", local_time(bb.get("last_time")), "Hang investigation evidence", "healthy" if bb.get("last_time") else "warning"),
                    ("Preserved incidents", str(len(incident_archives)), "Previous-boot evidence protected from rolling retention", "healthy" if incident_archives else "muted"),
                ])
                + "<div class=\"card action-panel\"><h2>Incident Evidence</h2>"
                f"<p class=\"{'healthy' if incident_archives else 'muted'}\">{len(incident_archives)} preserved incident archive(s). {escape(str(pstore.get('message') or 'pstore status unavailable'))}.</p>"
                "<p class=\"muted\">Start with the support bundle after a lockup or unexpected reboot. It combines the evidence needed for investigation.</p>"
                + tool_grid([
                    ("Download support bundle", "Best first step: logs, status, history, reboot, storage, network, and watchdog evidence.", "/api/diagnostics/support-bundle.zip", "primary"),
                    ("Black-box evidence", "Short-interval snapshots retained around a hang or reboot.", "/api/blackbox", ""),
                ])
                + "</div>"
                + f"<div class=\"card\"><h2>Persistent Journal</h2><p class=\"{'healthy' if journal_state.get('enabled') else 'warning'}\">{'Enabled' if journal_state.get('enabled') else 'Disabled or unavailable'}</p><p class=\"muted\">Persistent logging preserves kernel and service evidence across a reboot. Configuration is managed in Settings.</p><div class=\"button-row\"><a class=\"ghost\" href=\"/settings#persistent-journal\">Open logging settings</a></div></div>"
                + disclosure("Stage 0 baseline capture", baseline_card)
                + disclosure("Advanced technical data", advanced_detail)
            )

        error_html = ""
        if status.get("error"):
            error_html = f"<p class=\"critical\">{escape(str(status.get('error')))}</p>"
        if critical:
            issue_pill = "<span class=\"pill critical\">Critical issue</span>"
        elif has_any_critical:
            issue_pill = "<span class=\"pill warning\">Attention needed, watchdog feed safe</span>"
        elif has_warning:
            issue_pill = "<span class=\"pill warning\">Warning</span>"
        else:
            issue_pill = "<span class=\"pill\">No critical issues</span>"
        service_checks = [check for check in checks if str(check.get("name", "")).endswith(".service")]
        healthy_service_count = sum(1 for check in service_checks if check.get("state") == "healthy")
        feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
        heartbeat = status.get("heartbeat", {}) if isinstance(status.get("heartbeat", {}), dict) else {}
        reboot_evidence = status.get("reboot_evidence", {}) if isinstance(status.get("reboot_evidence", {}), dict) else {}
        journal = persistent_status()
        identity = version.get("identity", {}) if isinstance(version.get("identity", {}), dict) else {}
        recording = status.get("recording_storage", {}) if isinstance(status.get("recording_storage", {}), dict) else {}

        def worst_check_state(items):
            ranks = {"healthy": 0, "degraded": 1, "warning": 2, "unknown": 2, "critical": 3}
            worst = "healthy"
            for item in items:
                item_state = str(item.get("state", "unknown"))
                if ranks.get(item_state, 2) > ranks.get(worst, 2):
                    worst = item_state
            return worst

        def operational_row(area, detail, row_state, href, configured=True):
            if not configured:
                label, css_state = "Not configured", "unknown"
            elif row_state == "critical":
                label, css_state = "Failed", "critical"
            elif row_state == "healthy":
                label, css_state = "Correct", "healthy"
            else:
                label, css_state = "Warning", "warning"
            return (
                "<div class=\"operational-row\">"
                f"<div class=\"operational-area\">{escape(area)}</div>"
                f"<div class=\"operational-detail\">{escape(str(detail))}</div>"
                f"<div class=\"operational-state {css_state}\">{label}</div>"
                f"<a class=\"ghost operational-link\" href=\"{escape(href)}\">Details</a>"
                "</div>"
            )

        system_checks = [check_map[name] for name in ("temperature", "cpu_load", "ram", "root_disk", "write_test") if name in check_map]
        system_issue = next((check for check in system_checks if check.get("state") != "healthy"), None)
        service_issue = next((check for check in service_checks if check.get("state") != "healthy"), None)
        recording_check = check_map.get("recording_storage", {})
        network_check = check_map.get("network_module", {})
        network_message = str(network_check.get("message") or "Network checks have not been configured.")
        network_configured = bool(network_check) and "not configured" not in network_message.lower()
        watchdog_present = bool(check_value("hardware_watchdog_present", False))
        watchdog_configured = bool(feed.get("enabled"))
        watchdog_state = "healthy" if watchdog_present and feed.get("enabled") and feed.get("opened") else "warning"
        if watchdog_present and feed.get("enabled") and feed.get("opened"):
            watchdog_detail = f"Feeding {feed.get('device') or '/dev/wdt_dio'}"
        elif watchdog_present:
            watchdog_detail = "Device detected but hardware recovery is not active"
        else:
            watchdog_detail = "No verified hardware watchdog device"
        operational_rows = "".join(
            (
                operational_row(
                    "System",
                    (system_issue or {}).get("message") or "Operating system, CPU, memory and root storage checks are normal.",
                    worst_check_state(system_checks),
                    "/hardware",
                    bool(system_checks),
                ),
                operational_row(
                    "Services",
                    (service_issue or {}).get("message") or f"{healthy_service_count}/{len(service_checks)} monitored services running",
                    worst_check_state(service_checks),
                    "/services",
                    bool(service_checks),
                ),
                operational_row(
                    "Recording storage",
                    recording.get("message") or recording_check.get("message") or "Recording storage has not been configured.",
                    str(recording.get("status") or recording_check.get("state") or "unknown"),
                    "/hardware#storage",
                    bool(recording.get("mode") or recording.get("mountpoint") or recording_check),
                ),
                operational_row(
                    "Network",
                    network_message,
                    str(network_check.get("state") or "unknown"),
                    "/network",
                    network_configured,
                ),
                operational_row(
                    "Hardware watchdog",
                    watchdog_detail,
                    watchdog_state,
                    "/services#watchdog",
                    watchdog_configured,
                ),
            )
        )
        overview_html = (
            "<div class=\"card summary-card\">"
            "<div class=\"summary-panel summary-status\">"
            "<div class=\"summary-panel-title\">Overall state</div>"
            f"<div class=\"status-word {state}\">{word}</div>"
            f"{issue_pill}"
            f"{error_html}"
            "</div>"
            "<div class=\"summary-panel\">"
            "<div class=\"summary-panel-title\">Gateway identity</div>"
            f"<div class=\"summary-primary\">{escape(str(identity.get('display_name') or identity.get('site_name') or platform.node() or 'Site not configured'))}</div>"
            "<div class=\"summary-pairs\">"
            f"<div><div class=\"label\">Asset ID</div><div class=\"value\">{escape(str(identity.get('asset_id') or '-'))}</div></div>"
            f"<div><div class=\"label\">Hostname</div><div class=\"value\">{escape(str(identity.get('hostname') or platform.node() or '-'))}</div></div>"
            "</div>"
            "</div>"
            "<div class=\"summary-panel\">"
            "<div class=\"summary-panel-title\">Running software</div>"
            "<div class=\"label\">Build</div>"
            f"<div class=\"build-badge\">{escape(str(version.get('commit', '-')))}</div>"
            "<div class=\"label\">Build time and date</div>"
            f"<div class=\"value\">{escape(local_time(version.get('build_at')))}</div>"
            f"<div class=\"muted\">{escape(str(version.get('branch', '-')))}</div>"
            "<div class=\"label\">Last update</div>"
            f"<div class=\"value\">{escape(local_time(status.get('time')))}</div>"
            "</div>"
            "</div>"
            "<div class=\"card\"><h2>Operational Status</h2>"
            "<p class=\"muted\">This list shows what is ready and where attention is needed. Open Details for the relevant setup or evidence.</p>"
            f"<div class=\"operational-list\">{operational_rows}</div></div>"
            + metric_tiles()
            + "<div class=\"card\"><h2>Stability Evidence</h2><div class=\"table-scroll\"><table><tbody>"
            + f"<tr><th>Last health sample</th><td>{escape(local_time(status.get('time')))}</td></tr>"
            + f"<tr><th>Last watchdog feed</th><td>{escape(str(feed.get('last_feed_utc') or '-'))}</td></tr>"
            + f"<tr><th>Feed status</th><td>{escape(str(feed.get('feed_process_status') or 'unknown'))}; age {escape(str(feed.get('feed_age_seconds') if feed.get('feed_age_seconds') is not None else '-'))}s; threshold {escape(str(feed.get('stale_heartbeat_seconds') or '-'))}s</td></tr>"
            + f"<tr><th>Last heartbeat</th><td>{escape(local_time(heartbeat.get('time')))}</td></tr>"
            + f"<tr><th>Heartbeat age</th><td>{escape(str(heartbeat_age_seconds(heartbeat) if heartbeat else '-'))}s</td></tr>"
            + f"<tr><th>Previous reboot</th><td>{escape(str(reboot_evidence.get('reset_mechanism') or 'No previous reboot evidence'))}; confidence {escape(str(reboot_evidence.get('confidence') or '-'))}</td></tr>"
            + f"<tr><th>Persistent journal</th><td class=\"{'healthy' if journal.get('enabled') else 'warning'}\">{'Yes' if journal.get('enabled') else 'No'}</td></tr>"
            + "</tbody></table></div></div>"
            + operational_alerts_card()
            + disclosure("Services", services_card())
        )

        if page == "Overview":
            return page_help_html(page) + "<div class=\"overview-page\">" + overview_html + "</div>"
        if page == "Hardware":
            return (
                page_help_html(page)
                + hardware_page()
                + "<section id=\"storage\" class=\"moved-section\"><div class=\"moved-section-heading\"><h2>Recording Storage</h2><p>Mount health, recording availability, capacity, permissions, and storage setup.</p></div>"
                + storage_page()
                + "</section>"
            )
        if page == "Services":
            return (
                page_help_html(page)
                + services_card()
                + "<section id=\"watchdog\" class=\"moved-section\"><div class=\"moved-section-heading\"><h2>Watchdog Protection</h2><p>Hardware watchdog readiness, setup, ownership, and deliberate test controls.</p></div>"
                + watchdog_page()
                + "</section>"
            )
        if page == "Network":
            return page_help_html(page) + network_page()
        if page == "Events":
            query = getattr(request_context, "query", {}) or {}
            event_view = str(query.get("view", ["events"])[0]).lower()
            if event_view not in {"events", "history", "evidence"}:
                event_view = "events"
            tabs = (
                "<nav class=\"page-tabs\" aria-label=\"Events sections\">"
                f"<a class=\"{'active' if event_view == 'events' else ''}\" href=\"/events?view=events\">Events</a>"
                f"<a class=\"{'active' if event_view == 'history' else ''}\" href=\"/events?view=history\">History</a>"
                f"<a class=\"{'active' if event_view == 'evidence' else ''}\" href=\"/events?view=evidence\">Evidence</a>"
                "</nav>"
            )
            if event_view == "history":
                body = history_page()
            elif event_view == "evidence":
                body = diagnostics_page()
            else:
                body = events_page()
            return page_help_html(page) + tabs + body
        if page == "Settings":
            return (
                page_help_html(page)
                + settings_card()
                + "<section id=\"software-update\" class=\"moved-section\"><div class=\"moved-section-heading\"><h2>Software Update</h2><p>Running build, configured update target, last result, and update log.</p></div>"
                + updates_card()
                + "</section>"
                + "<section id=\"recovery\" class=\"moved-section\"><div class=\"moved-section-heading\"><h2>Recovery</h2><p>Repair, reinstall, reboot policy, and emergency support actions.</p></div>"
                + recovery_page()
                + "</section>"
            )
        return page_help_html("Overview") + overview_html

    def html_page(route_path="/"):
        page = page_name_for_path(route_path)
        try:
            body = basic_dashboard_html(page)
        except Exception as exc:
            body = (
                "<div class=\"card\">"
                f"<h2>{escape(page)} Page Error</h2>"
                "<p class=\"critical\">This page hit a runtime error while collecting live gateway details.</p>"
                f"<pre>{escape(str(exc))}</pre>"
                "<p class=\"muted\">The watchdog service can still be running even if this page failed. Use Evidence and Diagnostics or /api/status to check health while this is investigated.</p>"
                "<div class=\"button-row\"><a class=\"ghost\" href=\"/\">Overview</a><a class=\"ghost\" href=\"/events?view=evidence\">Evidence</a><a class=\"ghost\" href=\"/api/status\">Raw status</a></div>"
                "</div>"
            )
        return page_shell(body, page)

    def baseline_action_result_html(result):
        current = result.get("status") if isinstance(result.get("status"), dict) else baseline_status(cfg)
        state = str(current.get("state") or "unknown")
        body = (
            "<div class=\"card\"><h2>Stage 0 System Baseline</h2>"
            f"<p class=\"{'healthy' if result.get('ok') else 'critical'}\">{escape(str(result.get('message', 'Baseline request processed.')))}</p>"
            f"<p>Current state: <strong>{escape(state.upper())}</strong></p>"
            "<p class=\"muted\">The capture runs independently. You can leave this page and return to Evidence and Diagnostics later.</p>"
            "<div class=\"button-row\"><a class=\"action\" href=\"/events?view=evidence\">Back to Evidence</a></div>"
            "<script>setTimeout(function(){window.location.href='/events?view=evidence';},5000);</script>"
            "</div>"
        )
        return page_shell(body, "Diagnostics")

    def journal_enable_confirm_html():
        current = persistent_status()
        body = (
            "<div class=\"card\"><h2>Enable Persistent Journald</h2>"
            "<p>Current journal persistence status: <strong>" + escape("Enabled" if current.get("enabled") else "Disabled or unavailable") + "</strong></p>"
            "<p class=\"muted\">This creates /var/log/journal if required and writes a separate VA-Watchdog drop-in without editing unrelated journald settings. It caps journals at 512 MB, reserves 1 GB free on the OS disk, retains up to 30 days, flushes journald, and restarts only systemd-journald.</p>"
            "<form method=\"post\" action=\"/journal-enable\"><label><input type=\"checkbox\" name=\"ack\" value=\"1\"> I understand this changes system logging storage.</label>"
            "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Enable persistent logging</button><a class=\"ghost\" href=\"/settings\">Cancel</a></div></form></div>"
        )
        return page_shell(body, "Diagnostics")

    def journal_action_result_html(result):
        body = (
            "<div class=\"card\"><h2>Persistent Journald</h2>"
            f"<p class=\"{'healthy' if result.get('ok') else 'warning'}\">{escape(str(result.get('message', 'Action completed')))}</p>"
            f"<pre>{escape(json.dumps(result, indent=2))}</pre>"
            "<div class=\"button-row\"><a class=\"ghost\" href=\"/settings\">Back to Settings</a></div></div>"
        )
        return page_shell(body, "Diagnostics")

    def update_confirm_html():
        current = version_info()
        update_cfg = cfg.get("update", {}) if isinstance(cfg.get("update", {}), dict) else {}
        current_status = load_update_status(cfg)
        target_branch = update_cfg.get("branch") or current.get("branch", "-")
        body = (
            "<div class=\"card action-panel\"><h2>Confirm Watchdog Update</h2>"
            "<p class=\"warning\">The watchdog web page will be briefly unavailable while the update completes and the service restarts.</p>"
            "<p>This updates VA-Connect Watchdog only. It does not deliberately restart the four Videosoft services.</p>"
            f"<div class=\"label\">Running build</div><div class=\"build-badge\">{escape(str(current.get('commit', '-')))}</div>"
            f"<div class=\"label\">Current branch</div><div class=\"value\">{escape(str(current.get('branch', '-')))}</div>"
            f"<div class=\"label\">Update target</div><div class=\"value\">{escape(str(update_cfg.get('remote', 'origin')))}/{escape(str(target_branch))}</div>"
            f"<div class=\"label\">Previous update state</div><div class=\"value\">{escape(str(current_status.get('state', 'idle')).upper())} - {escape(str(current_status.get('message', 'No previous result.')))}</div>"
            "<div class=\"button-row\"><form class=\"inline\" method=\"post\" action=\"/update-now\"><button class=\"action\" type=\"submit\">Confirm update</button></form>"
            "<a class=\"ghost\" href=\"/settings\">Cancel</a><a class=\"ghost\" href=\"/updates\">View update log</a></div>"
            "</div>"
        )
        return page_shell(body, "Settings")

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
        return page_shell(body, "Updates")

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
        return page_shell(body, "Settings")

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
        return page_shell(body, "Storage")

    def storage_purge_result_html(result, mode):
        removed = result.get("removed", [])
        trimmed = result.get("trimmed", [])
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
        for item in trimmed:
            rows.append(
                "<tr>"
                f"<td>{escape(str(item.get('path', '-')))}</td>"
                f"<td>{escape(str(item.get('removed_rows', 0)))} old row(s)</td>"
                "</tr>"
            )
        if not rows:
            rows.append("<tr><td colspan=\"2\">No files matched the purge rule.</td></tr>")
        retention = result.get("retention", {})
        body = (
            "<meta http-equiv=\"refresh\" content=\"8;url=/hardware#storage\">"
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
        return page_shell(body, "Storage")

    def recording_storage_configure_html():
        candidates = recording_storage_candidates(cfg)
        rows = []
        blank_rows = []
        partition_options = []
        blank_options = []
        for item in candidates:
            allowed = bool(item.get("allowed"))
            blank_allowed = bool(item.get("blank_prepare_allowed"))
            device = str(item.get("device", ""))
            row_class = "selectable-row" if allowed else ""
            row_onclick = "onclick=\"selectStorageRadio(this, 'device')\"" if allowed else ""
            monitor_action = ""
            if allowed and item.get("mountpoint"):
                monitor_action = (
                    f"<a class=\"ghost\" href=\"/recording-storage-monitor-confirm/{quote(device, safe='')}\">Monitor only</a>"
                )
            rows.append(
                f"<tr class=\"{row_class}\" {row_onclick}>"
                f"<td><label><input type=\"radio\" name=\"device\" value=\"{escape(device)}\" {'disabled' if not allowed else ''}> Select</label></td>"
                f"<td>{escape(str(item.get('device', '-')))}</td>"
                f"<td>{escape(str(item.get('model', '-')))}</td>"
                f"<td>{escape(str(item.get('serial', '-')))}</td>"
                f"<td>{escape(str(item.get('size_gb', '-')))} GB</td>"
                f"<td>{escape(str(item.get('filesystem', '-') or '-'))}</td>"
                f"<td>{escape(str(item.get('label', '-') or '-'))}</td>"
                f"<td>{escape(str(item.get('mountpoint', '-') or '-'))}</td>"
                f"<td class=\"{'healthy' if allowed else 'warning'}\">{escape(str(item.get('existing_mode', 'Selectable')) if allowed else str(item.get('blocked_reason', 'Blocked')))} {monitor_action}</td>"
                "</tr>"
            )
            if allowed:
                partition_options.append(
                    f"<option value=\"{escape(device)}\">{escape(device)} - {escape(str(item.get('existing_mode', 'ext4 filesystem')))} - {escape(str(item.get('model', '-') or '-'))} - {escape(str(item.get('size_gb', '-')))} GB</option>"
                )
            if item.get("type") == "disk":
                blank_row_class = "selectable-row" if blank_allowed else ""
                blank_row_onclick = "onclick=\"selectStorageRadio(this, 'disk')\"" if blank_allowed else ""
                blank_rows.append(
                    f"<tr class=\"{blank_row_class}\" {blank_row_onclick}>"
                    f"<td><label><input type=\"radio\" name=\"disk\" value=\"{escape(device)}\" {'disabled' if not blank_allowed else ''}> Select</label></td>"
                    f"<td>{escape(str(item.get('device', '-')))}</td>"
                    f"<td>{escape(str(item.get('model', '-')))}</td>"
                    f"<td>{escape(str(item.get('serial', '-')))}</td>"
                    f"<td>{escape(str(item.get('size_gb', '-')))} GB</td>"
                    f"<td>{escape(str(item.get('filesystem', '-') or '-'))}</td>"
                    f"<td>{escape(str(item.get('label', '-') or '-'))}</td>"
                    f"<td>{escape(str(item.get('mountpoint', '-') or '-'))}</td>"
                    f"<td class=\"{'healthy' if blank_allowed else 'warning'}\">{escape('Can prepare as blank recording disk' if blank_allowed else str(item.get('blank_prepare_reason', 'Blocked')))}</td>"
                    "</tr>"
                )
                if blank_allowed:
                    blank_options.append(
                        f"<option value=\"{escape(device)}\">{escape(device)} - {escape(str(item.get('model', '-') or '-'))} - {escape(str(item.get('size_gb', '-')))} GB</option>"
                    )
        if not rows:
            rows.append("<tr><td colspan=\"9\">No block devices detected.</td></tr>")
        if not blank_rows:
            blank_rows.append("<tr><td colspan=\"9\">No whole disks detected.</td></tr>")
        rec = recording_storage_status(cfg)
        fstab_entry = rec.get("fstab_entry", "LABEL=CCTV_STORAGE /media/vsuser/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2")
        current_directory = rec.get("recordings_path") if rec.get("mode") == "system_directory" else "/home/vsuser/recordings"
        body = (
            "<div class=\"card\">"
            "<h2>One Drive: Monitor Existing Recording Folder</h2>"
            "<p class=\"section-lead\">Use this when the operating system and Videosoft recordings share the same physical drive. "
            "The OS disk remains protected and is never relabelled, repartitioned, formatted, mounted, or added to /etc/fstab.</p>"
            "<form method=\"post\" action=\"/recording-storage-system-directory\">"
            "<label class=\"label\">Existing Videosoft recording folder</label>"
            f"<input name=\"recording_path\" value=\"{escape(str(current_directory))}\" placeholder=\"/home/vsuser/recordings\">"
            "<label><input type=\"checkbox\" name=\"ack\" value=\"1\"> Monitor this folder without changing the operating-system disk</label>"
            "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Monitor one-drive recording folder</button><a class=\"ghost\" href=\"/storage\">Cancel</a></div>"
            "</form>"
            "<p class=\"muted\">Enter the path selected in Videosoft. It must already exist and be writable. The watchdog only performs a temporary write test.</p>"
            "</div>"
            "<div class=\"card\">"
            "<h2>Configure Recording Storage</h2>"
            "<p class=\"warning\">Existing filesystem setup does not format, erase, unmount, or automatically repair a drive. It only labels the selected ext4 partition or whole-disk ext4 filesystem after confirmation and writes a labelled /etc/fstab entry.</p>"
            "<div class=\"label\">Intended fstab entry</div>"
            f"<pre>{escape(str(fstab_entry))}</pre>"
            f"<div class=\"label\">Current status</div><div class=\"value {escape(str(rec.get('status', 'unknown')))}\">{escape(str(rec.get('message', '-')))}</div>"
            "<script>"
            "function selectStorageRadio(row,name){var input=row.querySelector('input[type=radio][name='+name+']');if(!input||input.disabled){return;}input.checked=true;var rows=row.closest('tbody').querySelectorAll('tr');for(var i=0;i<rows.length;i++){rows[i].classList.remove('selected');}row.classList.add('selected');}"
            "function selectStorageDropdown(select,name){var form=select.form;var inputs=form.querySelectorAll('input[type=radio][name='+name+']');for(var i=0;i<inputs.length;i++){if(inputs[i].value===select.value&&!inputs[i].disabled){inputs[i].checked=true;var row=inputs[i].closest('tr');if(row){selectStorageRadio(row,name);}break;}}}"
            "</script>"
            "<h3>Use Existing ext4 Filesystem</h3>"
            "<p class=\"muted\">Use selected storage if the watchdog is allowed to relabel and manage the fstab entry. Use Monitor only for an already-working recorder mount that must not be changed.</p>"
            "<form method=\"post\" action=\"/recording-storage-confirm\">"
            "<label class=\"label\">Choose existing ext4 storage</label>"
            f"<select onchange=\"selectStorageDropdown(this, 'device')\"><option value=\"\">Select existing storage...</option>{''.join(partition_options)}</select>"
            "<table><thead><tr><th>Select</th><th>Device</th><th>Model</th><th>Serial</th><th>Size</th><th>Filesystem</th><th>Label</th><th>Mountpoint</th><th>Safety</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Use selected partition</button><a class=\"ghost\" href=\"/storage\">Cancel</a></div>"
            "</form>"
            "</div>"
            "<div class=\"card\">"
            "<h2>Prepare New Blank Recording Disk</h2>"
            "<p class=\"critical\">This path creates a new partition and ext4 filesystem. Use it only for a new/empty recording disk. Existing data on the selected disk will be erased after confirmation.</p>"
            "<form method=\"post\" action=\"/recording-storage-blank-confirm\">"
            "<label class=\"label\">Choose blank disk</label>"
            f"<select onchange=\"selectStorageDropdown(this, 'disk')\"><option value=\"\">Select blank disk...</option>{''.join(blank_options)}</select>"
            "<table><thead><tr><th>Select</th><th>Disk</th><th>Model</th><th>Serial</th><th>Size</th><th>Filesystem</th><th>Label</th><th>Mountpoint</th><th>Safety</th></tr></thead>"
            f"<tbody>{''.join(blank_rows)}</tbody></table>"
            "<div class=\"button-row\"><button class=\"danger\" type=\"submit\">Prepare selected blank disk</button><a class=\"ghost\" href=\"/storage\">Cancel</a></div>"
            "</form>"
            "</div>"
        )
        return page_shell(body, "Storage")

    def recording_storage_confirm_html(device):
        candidates = recording_storage_candidates(cfg)
        selected = next((item for item in candidates if os.path.realpath(str(item.get("device", ""))) == os.path.realpath(str(device or ""))), None)
        if not selected:
            body = (
                "<div class=\"card\"><h2>Recording Storage Configuration</h2>"
                "<p class=\"critical\">Selected device was not detected.</p>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        if not selected.get("allowed"):
            body = (
                "<div class=\"card\"><h2>Recording Storage Configuration</h2>"
                f"<p class=\"critical\">Selected device is blocked: {escape(str(selected.get('blocked_reason', '-')))}</p>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Recording Storage Device</h2>"
            "<p class=\"critical\">Only continue if this is the CCTV recording filesystem. Changing the label can make existing recordings inaccessible until paths are updated.</p>"
            f"<div class=\"label\">Device</div><div class=\"value\">{escape(str(selected.get('device', '-')))}</div>"
            f"<div class=\"label\">Model</div><div class=\"value\">{escape(str(selected.get('model', '-')))}</div>"
            f"<div class=\"label\">Serial</div><div class=\"value\">{escape(str(selected.get('serial', '-')))}</div>"
            f"<div class=\"label\">Size</div><div class=\"value\">{escape(str(selected.get('size_gb', '-')))} GB</div>"
            f"<div class=\"label\">Filesystem</div><div class=\"value\">{escape(str(selected.get('filesystem', '-')))}</div>"
            f"<div class=\"label\">Type</div><div class=\"value\">{escape(str(selected.get('existing_mode', '-')))}</div>"
            f"<div class=\"label\">Current label</div><div class=\"value\">{escape(str(selected.get('label', '-') or '-'))}</div>"
            f"<div class=\"label\">Current mountpoint</div><div class=\"value\">{escape(str(selected.get('mountpoint', '-') or '-'))}</div>"
            "<form method=\"post\" action=\"/recording-storage-apply\">"
            f"<input type=\"hidden\" name=\"device\" value=\"{escape(str(selected.get('device', '')))}\">"
            "<label><input type=\"checkbox\" name=\"ack\" value=\"1\"> I understand this may change how existing recordings are accessed</label>"
            "<label class=\"label\">Type CCTV_STORAGE to confirm</label>"
            "<input name=\"confirm_label\" autocomplete=\"off\" placeholder=\"CCTV_STORAGE\">"
            "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Apply labelled fstab mount</button><a class=\"ghost\" href=\"/recording-storage-configure\">Cancel</a></div>"
            "</form>"
            "</div>"
        )
        return page_shell(body, "Storage")

    def recording_storage_blank_confirm_html(disk):
        candidates = recording_storage_candidates(cfg)
        selected = next((item for item in candidates if os.path.realpath(str(item.get("device", ""))) == os.path.realpath(str(disk or ""))), None)
        if not selected:
            body = (
                "<div class=\"card\"><h2>Prepare Blank Recording Disk</h2>"
                "<p class=\"critical\">Selected disk was not detected.</p>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        if not selected.get("blank_prepare_allowed"):
            body = (
                "<div class=\"card\"><h2>Prepare Blank Recording Disk</h2>"
                f"<p class=\"critical\">Selected disk is blocked: {escape(str(selected.get('blank_prepare_reason', '-')))}</p>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        device = str(selected.get("device", ""))
        body = (
            "<div class=\"card\">"
            "<h2>Final Confirmation: Prepare Blank Recording Disk</h2>"
            "<p class=\"critical\">This will erase the selected disk, create one ext4 partition labelled CCTV_STORAGE, add the labelled fstab entry, run mount -a, and confirm the mount is writable.</p>"
            f"<div class=\"label\">Disk</div><div class=\"value\">{escape(device)}</div>"
            f"<div class=\"label\">Model</div><div class=\"value\">{escape(str(selected.get('model', '-')))}</div>"
            f"<div class=\"label\">Serial</div><div class=\"value\">{escape(str(selected.get('serial', '-')))}</div>"
            f"<div class=\"label\">Size</div><div class=\"value\">{escape(str(selected.get('size_gb', '-')))} GB</div>"
            "<form method=\"post\" action=\"/recording-storage-blank-apply\">"
            f"<input type=\"hidden\" name=\"disk\" value=\"{escape(device)}\">"
            "<label><input type=\"checkbox\" name=\"ack\" value=\"1\"> I understand this will erase the selected disk</label>"
            "<label class=\"label\">Type the disk path exactly</label>"
            f"<input name=\"confirm_device\" autocomplete=\"off\" placeholder=\"{escape(device)}\">"
            "<label class=\"label\">Type CCTV_STORAGE to confirm</label>"
            "<input name=\"confirm_label\" autocomplete=\"off\" placeholder=\"CCTV_STORAGE\">"
            "<div class=\"button-row\"><button class=\"danger\" type=\"submit\">Erase and prepare recording disk</button><a class=\"ghost\" href=\"/recording-storage-configure\">Cancel</a></div>"
            "</form>"
            "</div>"
        )
        return page_shell(body, "Storage")

    def recording_storage_monitor_confirm_html(device):
        candidates = recording_storage_candidates(cfg)
        selected = next((item for item in candidates if os.path.realpath(str(item.get("device", ""))) == os.path.realpath(str(device or ""))), None)
        if not selected:
            body = (
                "<div class=\"card\"><h2>Monitor Existing Recording Storage</h2>"
                "<p class=\"critical\">Selected device was not detected.</p>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        if not selected.get("allowed") or not selected.get("mountpoint"):
            body = (
                "<div class=\"card\"><h2>Monitor Existing Recording Storage</h2>"
                "<p class=\"critical\">Selected device must be a mounted ext4 storage device larger than the minimum CCTV size.</p>"
                f"<pre>{escape(str(selected.get('blocked_reason') or 'No mountpoint detected'))}</pre>"
                "<a class=\"ghost\" href=\"/recording-storage-configure\">Back</a></div>"
            )
            return page_shell(body, "Storage")
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Monitor Only</h2>"
            "<p class=\"warning\">This does not relabel, remount, format, change ownership, or edit /etc/fstab. It only changes the watchdog config to monitor this existing mounted storage.</p>"
            f"<div class=\"label\">Device</div><div class=\"value\">{escape(str(selected.get('device', '-')))}</div>"
            f"<div class=\"label\">Mountpoint</div><div class=\"value\">{escape(str(selected.get('mountpoint', '-')))}</div>"
            f"<div class=\"label\">Filesystem</div><div class=\"value\">{escape(str(selected.get('filesystem', '-')))}</div>"
            f"<div class=\"label\">Current label</div><div class=\"value\">{escape(str(selected.get('label', '-') or '-'))}</div>"
            "<form method=\"post\" action=\"/recording-storage-monitor-only\">"
            f"<input type=\"hidden\" name=\"device\" value=\"{escape(str(selected.get('device', '')))}\">"
            "<label><input type=\"checkbox\" name=\"ack\" value=\"1\"> Monitor this existing mount without changing the disk</label>"
            "<div class=\"button-row\"><button class=\"action\" type=\"submit\">Use monitor-only mode</button><a class=\"ghost\" href=\"/recording-storage-configure\">Cancel</a></div>"
            "</form>"
            "</div>"
        )
        return page_shell(body, "Storage")

    def monitor_existing_recording_storage(device, ack):
        if not ack:
            return {"ok": False, "message": "Confirmation checkbox was not ticked.", "output": ""}
        candidates = recording_storage_candidates(cfg)
        selected = next((item for item in candidates if os.path.realpath(str(item.get("device", ""))) == os.path.realpath(str(device or ""))), None)
        if not selected:
            return {"ok": False, "message": f"Selected device was not detected: {device}", "output": ""}
        if not selected.get("allowed") or not selected.get("mountpoint"):
            return {"ok": False, "message": "Selected device is not a mounted ext4 CCTV storage candidate.", "output": selected.get("blocked_reason") or "No mountpoint detected"}
        label = str(selected.get("label") or "").strip()
        updates = {
            "recording_storage": {
                "enabled": True,
                "mode": "existing_mount",
                "directory_path": "",
                "expected_label": label,
                "mountpoint": str(selected.get("mountpoint")),
                "filesystem": str(selected.get("filesystem") or "ext4"),
                "managed_fstab": False,
            }
        }
        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        return {
            "ok": True,
            "message": "Watchdog is now monitoring the existing recording mount only.",
            "output": "No disk, label, mount, ownership, or fstab changes were made.",
            "backup": f"Config backup created automatically beside {saved_path}",
            "status": recording_storage_status(cfg),
        }

    def monitor_system_recording_directory(path, ack):
        if not ack:
            return {"ok": False, "message": "Confirmation checkbox was not ticked.", "output": ""}
        recording_cfg = cfg.get("recording_storage", {}) if isinstance(cfg.get("recording_storage", {}), dict) else {}
        validation = validate_system_recording_directory(path, recording_cfg.get("owner") or "vsuser")
        if not validation.get("ok"):
            return {
                "ok": False,
                "message": validation.get("message", "Recording directory validation failed."),
                "output": f"Requested path: {validation.get('path') or path}",
                "status": recording_storage_status(cfg),
            }
        updates = {
            "recording_storage": {
                "enabled": True,
                "mode": "system_directory",
                "directory_path": str(validation["path"]),
                "managed_fstab": False,
                "filesystem": str(validation.get("filesystem") or "ext4"),
            },
            "storage": {
                "recordings_path": str(validation["path"]),
            },
        }
        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        status = recording_storage_status(cfg)
        return {
            "ok": status.get("status") in {"healthy", "warning"},
            "message": "Watchdog is now monitoring the recording folder on the OS disk.",
            "output": (
                f"Path: {validation['path']}\n"
                f"Containing device: {validation.get('device') or '-'}\n"
                f"Filesystem mountpoint: {validation.get('mountpoint') or '-'}\n"
                "No partition, label, mount, ownership, or fstab changes were made."
            ),
            "backup": f"Config backup created automatically beside {saved_path}",
            "fstab_entry": "Not used - recording directory is on the OS filesystem",
            "status": status,
        }

    def recording_storage_result_html(result):
        ok = bool(result.get("ok"))
        status = result.get("status", {})
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/hardware#storage\">"
            "<div class=\"card\">"
            "<h2>Recording Storage Configuration</h2>"
            f"<p class=\"{'healthy' if ok else 'critical'}\">{escape(str(result.get('message', '-')))}</p>"
            f"<div class=\"label\">Backup</div><div class=\"value\">{escape(str(result.get('backup', '-')))}</div>"
            f"<div class=\"label\">fstab entry</div><pre>{escape(str(result.get('fstab_entry', 'LABEL=CCTV_STORAGE /media/vsuser/Storage ext4 defaults,nofail,x-systemd.device-timeout=5 0 2')))}</pre>"
            f"<div class=\"label\">Validation status</div><pre>{escape(json.dumps(status, indent=2))}</pre>"
            f"<div class=\"label\">Output</div><pre>{escape(str(result.get('output', '')))}</pre>"
            "<p class=\"muted\">This page returns to Storage automatically in 20 seconds.</p>"
            "<a class=\"ghost\" href=\"/hardware#storage\">Back to Recording Storage</a>"
            "</div>"
        )
        return page_shell(body, "Storage")

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
            "<a class=\"ghost\" href=\"/settings#recovery\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Recovery")

    def recovery_install_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/settings#recovery\">"
            "<div class=\"card\">"
            "<h2>Watchdog Reinstall</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Install request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Recovery automatically in 20 seconds. The watchdog service may restart during this time.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/settings#recovery\">Back to Recovery</a>"
            "</div>"
        )
        return page_shell(body, "Recovery")

    def neousys_install_confirm_html():
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Neousys Watchdog Driver Install</h2>"
            "<p class=\"warning\">This installs the bundled test driver for the running kernel. It does not start the hardware timer.</p>"
            "<p class=\"muted\">Activation is a separate attended action because it removes competing watchdog paths and enables hardware feeding.</p>"
            "<div class=\"label\">Expected driver</div><div class=\"value\">wdt_dio</div>"
            "<div class=\"label\">Expected device after success</div><div class=\"value\">/dev/wdt_dio</div>"
            "<div class=\"label\">Expected API</div><div class=\"value\">Neousys WDT_DIO 2.4.1.0</div>"
            "<form class=\"inline\" method=\"post\" action=\"/neousys-watchdog-install-now\"><button class=\"action\" type=\"submit\">Install Neousys driver</button></form> "
            "<a class=\"ghost\" href=\"/services#watchdog\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def hardware_watchdog_prepare_confirm_html():
        info = hardware_info()
        watchdog = info.get("watchdog", {})
        legacy = watchdog.get("legacy_daemon", {})
        systemd_wdt = watchdog.get("systemd_watchdog", systemd_watchdog_info())
        setup = watchdog_setup_rows(watchdog, systemd_wdt)
        check_rows = "".join(
            "<tr>"
            f"<td>{escape(str(item.get('name', '-')))}</td>"
            f"<td class=\"{escape(str(item.get('state', 'unknown')))}\">{escape(str(item.get('state', 'unknown')).upper())}</td>"
            f"<td>{escape(str(item.get('message', '-')))}</td>"
            "</tr>"
            for item in setup.get("checks", [])
        )
        body = (
            "<div class=\"card\">"
            "<h2>One-Click Hardware Watchdog Setup</h2>"
            "<p class=\"warning\">This is the recommended setup and cleanup path for POC-451VTC.</p>"
            "<p class=\"muted\">It installs the bundled Neousys driver, removes legacy and Intel hardware watchdog paths, writes the Neousys settings, and restarts both VA-Connect services with a safety window.</p>"
            "<div class=\"label\">Expected device</div><div class=\"value\">/dev/wdt_dio</div>"
            "<div class=\"label\">Expected driver</div><div class=\"value\">Neousys wdt_dio</div>"
            f"<div class=\"label\">Current legacy watchdog.service</div><div class=\"value\">{escape(str(legacy.get('active', '-')))} / {escape(str(legacy.get('enabled', '-')))}</div>"
            f"<div class=\"label\">Legacy package</div><div class=\"value\">{escape(str(legacy.get('package_status', '-')))}</div>"
            "<table><thead><tr><th>Check</th><th>Now</th><th>Meaning</th></tr></thead>"
            f"<tbody>{check_rows}</tbody></table>"
            "<p class=\"muted\">After confirming, wait about 30 seconds, then return to Hardware. The page may briefly disconnect while the service restarts.</p>"
            "<form class=\"inline\" method=\"post\" action=\"/hardware-watchdog-prepare-now\"><button class=\"action\" type=\"submit\">Run setup and cleanup</button></form> "
            "<a class=\"ghost\" href=\"/hardware\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Hardware")

    def neousys_install_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Neousys Watchdog Driver Install</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Setup request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Watchdog automatically in 20 seconds. Reload Watchdog after that to see module/device status.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/services#watchdog\">Back to Watchdog</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def watchdog_probe_confirm_html():
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Full Watchdog Hardware Probe</h2>"
            "<p class=\"warning\">This will inspect the Neousys driver, device, library, configuration, feeder ownership, and conflicts.</p>"
            "<p class=\"muted\">The probe is read-only and does not start or stop the hardware timer.</p>"
            "<form class=\"inline\" method=\"post\" action=\"/watchdog-hardware-probe-now\"><button class=\"action\" type=\"submit\">Run full watchdog probe</button></form> "
            "<a class=\"ghost\" href=\"/services#watchdog\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def watchdog_probe_started_html(result):
        status_class = "healthy" if result.get("ok") else "critical"
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Watchdog Hardware Probe</h2>"
            f"<p class=\"{status_class}\">{escape(str(result.get('message', 'Probe request sent.')))}</p>"
            "<p class=\"muted\">This page will return to Watchdog automatically in 20 seconds. Reload Watchdog to see the full probe log.</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            "<a class=\"ghost\" href=\"/services#watchdog\">Back to Watchdog</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def legacy_watchdog_disable_confirm_html():
        legacy = legacy_watchdog_daemon_info()
        unit_rows = "".join(
            "<tr>"
            f"<td>{escape(str(unit.get('unit', '-')))}</td>"
            f"<td>{escape(str(unit.get('active', '-')))}</td>"
            f"<td>{escape(str(unit.get('enabled', '-')))}</td>"
            "</tr>"
            for unit in legacy.get("units", [])
        )
        body = (
            "<div class=\"card\">"
            "<h2>Confirm Legacy Watchdog Cleanup</h2>"
            "<p class=\"warning\">This will stop, disable, mask, and remove Ubuntu's legacy watchdog daemon if it exists.</p>"
            "<p class=\"muted\">This is separate from the systemd process watchdog. It removes daemons that may compete with the Neousys hardware feeder.</p>"
            f"<div class=\"label\">Package</div><div class=\"value\">{escape(str(legacy.get('package_status', '-')))}</div>"
            "<table><thead><tr><th>Unit</th><th>Active</th><th>Enabled</th></tr></thead>"
            f"<tbody>{unit_rows}</tbody></table>"
            "<form class=\"inline\" method=\"post\" action=\"/watchdog-legacy-disable-now\"><button class=\"action\" type=\"submit\">Clean legacy watchdog daemon</button></form> "
            "<a class=\"ghost\" href=\"/watchdog\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def hardware_watchdog_enable_confirm_html():
        info = hardware_info()
        watchdog = info.get("watchdog", {})
        systemd_wdt = systemd_watchdog_info()
        wizard = hardware_watchdog_wizard_state(watchdog, systemd_wdt)
        body = (
            "<div class=\"card\">"
            "<h2>Confirm VA-Connect Hardware Watchdog Feeding</h2>"
            f"<p class=\"{escape(str(wizard.get('state', 'warning')))}\">{escape(str(wizard.get('message', '-')))}</p>"
            "<p class=\"muted\">This writes the Neousys backend settings, starts the configured safety window, then restarts both VA-Connect services.</p>"
            f"<div class=\"label\">Driver identity</div><div class=\"value\">{escape(str(watchdog.get('wdctl', {}).get('identity', '-')))}</div>"
            f"<div class=\"label\">Timeout</div><div class=\"value\">{escape(str(watchdog.get('wdctl', {}).get('timeout', '-')))}</div>"
            f"<div class=\"label\">Legacy watchdog.service</div><div class=\"value\">{escape(str(watchdog.get('legacy_daemon', {}).get('active', '-')))} / {escape(str(watchdog.get('legacy_daemon', {}).get('enabled', '-')))}</div>"
            f"<div class=\"label\">Prerequisites</div><pre>{escape(json.dumps(wizard.get('checks', []), indent=2))}</pre>"
        )
        pre_enable_ready = all(item.get("state") == "healthy" for item in wizard.get("checks", [])[:4])
        if pre_enable_ready:
            body += (
                "<form class=\"inline\" method=\"post\" action=\"/hardware-watchdog-enable-now\"><button class=\"action\" type=\"submit\">Enable VA-Connect hardware feeding</button></form> "
            )
        else:
            body += "<p class=\"warning\">Enable is blocked until the driver, device, identity, and legacy cleanup checks are healthy.</p>"
        body += "<a class=\"ghost\" href=\"/watchdog\">Back to Watchdog</a></div>"
        return page_shell(body, "Watchdog")

    def hardware_action_result_html(result):
        ok = bool(result.get("ok"))
        body = (
            "<meta http-equiv=\"refresh\" content=\"12;url=/hardware\">"
            "<div class=\"card\">"
            "<h2>Hardware Watchdog Action</h2>"
            f"<p class=\"{'healthy' if ok else 'critical'}\">{escape(str(result.get('message', '-')))}</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Output</div><pre>{escape(str(result.get('output', '')))}</pre>"
            "<p class=\"muted\">This page will return to Hardware automatically in 12 seconds.</p>"
            "<a class=\"ghost\" href=\"/hardware\">Back to Hardware</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def watchdog_action_result_html(result):
        ok = bool(result.get("ok"))
        body = (
            "<meta http-equiv=\"refresh\" content=\"20;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Watchdog Action</h2>"
            f"<p class=\"{'healthy' if ok else 'critical'}\">{escape(str(result.get('message', '-')))}</p>"
            f"<div class=\"label\">Command</div><div class=\"value\">{escape(str(result.get('command', '-')))}</div>"
            f"<div class=\"label\">Log</div><div class=\"value\">{escape(str(result.get('log_path', '-')))}</div>"
            f"<div class=\"label\">Output</div><pre>{escape(str(result.get('output', '')))}</pre>"
            "<p class=\"muted\">This page will return to Watchdog automatically in 20 seconds. Reload Watchdog after the service restarts to see the final owner/feed state.</p>"
            "<a class=\"ghost\" href=\"/watchdog\">Back to Watchdog</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

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
        return page_shell(body, "Services")

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
        return page_shell(body, "Services")

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
        return page_shell(body, "Services")

    def watchdog_test_armed_html(result):
        body = (
            "<meta http-equiv=\"refresh\" content=\"45;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Safe Watchdog Test Armed</h2>"
            "<p class=\"warning\">Second knock required.</p>"
            "<p class=\"muted\">This test is armed for 45 seconds. Confirming will verify watchdog config, device presence, and recent feed state. It will not intentionally reboot the gateway.</p>"
            f"<div class=\"label\">Armed at</div><div class=\"value\">{escape(str(result.get('armed_at', '-')))}</div>"
            "<form class=\"inline\" method=\"post\" action=\"/watchdog-test-run\">"
            f"<input type=\"hidden\" name=\"token\" value=\"{escape(str(result.get('token', '')))}\">"
            "<button class=\"action\" type=\"submit\">Second knock: run safe test</button>"
            "</form> "
            "<a class=\"ghost\" href=\"/watchdog\">Cancel</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

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
            "<meta http-equiv=\"refresh\" content=\"12;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Safe Watchdog Test Result</h2>"
            f"<p class=\"{'healthy' if ok else 'warning'}\">{escape(str(result.get('message', 'Test complete')))}</p>"
            f"<div class=\"label\">Test time</div><div class=\"value\">{escape(str(result.get('tested_at', '-')))}</div>"
            "<table><thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "<p class=\"muted\">This page will return to Watchdog automatically in 12 seconds.</p>"
            "<a class=\"ghost\" href=\"/watchdog\">Back to Watchdog</a>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def watchdog_trip_confirm_html():
        trip = trip_test_summary(cfg)
        info = hardware_info()
        watchdog = info.get("watchdog", {})
        setup = watchdog_setup_rows(watchdog, watchdog.get("systemd_watchdog", systemd_watchdog_info()))
        trip_ready = bool(setup.get("trip_ready"))
        trigger_disabled = "" if trip_ready and not trip.get("triggered") else "disabled"
        body_parts = [
            "<div class=\"card\">",
            "<h2>Run Deliberate Watchdog Trip Test</h2>",
            "<p class=\"critical\">This can reboot the gateway if the hardware watchdog is healthy.</p>",
            "<p class=\"muted\">The feeder first verifies that the hardware counter decreases. A static counter cancels the test safely and resumes feeding.</p>",
            f"<p class=\"{escape(str(setup.get('state', 'warning')))}\">{escape(str(setup.get('message', '-')))}</p>",
            f"<div class=\"label\">Current state</div><div class=\"value\">{escape('Triggered this boot' if trip.get('triggered') else ('Completed on previous boot' if trip.get('completed_previous_boot') else 'Ready'))}</div>",
            f"<div class=\"label\">Last result</div><div class=\"value\">{escape(str(trip.get('last_result_message', 'No trip test recorded yet')))}</div>",
            "<form method=\"post\" action=\"/watchdog-trip-run\">",
            "<label class=\"option-row\"><input type=\"checkbox\" name=\"ack_risk\" value=\"1\"><span><strong>I understand this test may reboot the gateway</strong><br><span class=\"muted\">Remote access may be unavailable until the gateway starts again.</span></span></label>",
            f"<div class=\"button-row\"><button class=\"danger\" type=\"submit\" {trigger_disabled}>Run deliberate trip test</button><a class=\"ghost\" href=\"/watchdog\">Cancel</a></div>",
            "</form>",
        ]
        if not trip_ready:
            body_parts.append("<p class=\"warning\">Trip test is blocked until the feeder owns /dev/wdt_dio and has a recent hardware feed. Run one-click setup and reload Watchdog first.</p>")
        if trip.get("triggered"):
            body_parts.append("<p class=\"warning\">A trip test is already active for this boot.</p>")
        body_parts.append("</div>")
        return page_shell("".join(body_parts), "Watchdog")

    def watchdog_arm_now_confirm_html():
        grace = startup_grace_status(cfg, trip_test_summary(cfg))
        feed = status_snapshot().get("hardware_watchdog_feed", {})
        can_arm = bool(cfg.get("hardware_watchdog", {}).get("enabled")) and bool(grace.get("active")) and not bool(feed.get("opened"))
        remaining = int(grace.get("remaining_seconds", 0) or 0)
        body = (
            "<div class=\"card\"><h2>Confirm Arm Hardware Watchdog Now</h2>"
            "<p class=\"warning\">This ends the startup safety window for this boot.</p>"
            "<p>The independent feeder will start the Neousys timer when the safety window ends. Once started, use only the attended controls on this page.</p>"
            f"<div class=\"label\">Safety time remaining</div><div class=\"value\">{remaining} seconds</div>"
            f"<div class=\"label\">Device currently opened</div><div class=\"value\">{'Yes' if feed.get('opened') else 'No'}</div>"
        )
        if can_arm:
            body += "<form class=\"inline\" method=\"post\" action=\"/watchdog-arm-now\"><button class=\"action\" type=\"submit\">Arm hardware watchdog now</button></form> "
        else:
            body += "<p class=\"warning\">Arm now is only available while an enabled watchdog is inside its startup safety window.</p>"
        body += "<a class=\"ghost\" href=\"/watchdog\">Cancel</a></div>"
        return page_shell(body, "Watchdog")

    def hardware_watchdog_disable_confirm_html():
        grace = startup_grace_status(cfg, trip_test_summary(cfg))
        feed = status_snapshot().get("hardware_watchdog_feed", {})
        remaining = int(grace.get("remaining_seconds", 0) or 0)
        safety_margin = max(15, int(cfg.get("poll_interval_seconds", 5) or 5) * 2)
        can_disable = bool(grace.get("active")) and remaining > safety_margin and not bool(feed.get("opened"))
        body = (
            "<div class=\"card\"><h2>Confirm Disable Hardware Watchdog Feed</h2>"
            "<p class=\"warning\">This disables hardware reboot protection in the saved configuration. The systemd process watchdog remains available.</p>"
            "<p>This action is deliberately blocked after /dev/wdt_dio has been opened. Stopping a live hardware timer is not a safe recovery method.</p>"
            f"<div class=\"label\">Safety time remaining</div><div class=\"value\">{remaining} seconds</div>"
            f"<div class=\"label\">Device currently opened</div><div class=\"value\">{'Yes' if feed.get('opened') else 'No'}</div>"
        )
        if can_disable:
            body += "<form class=\"inline\" method=\"post\" action=\"/hardware-watchdog-disable-now\"><button class=\"danger\" type=\"submit\">Disable hardware feed</button></form> "
        else:
            body += "<p class=\"critical\">Safe disable is not available now. Use this control earlier in the startup safety window.</p>"
        body += "<a class=\"ghost\" href=\"/watchdog\">Cancel</a></div>"
        return page_shell(body, "Watchdog")

    def watchdog_trip_armed_html(result):
        body = (
            "<meta http-equiv=\"refresh\" content=\"300;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Trip Test Armed</h2>"
            "<p class=\"warning\">The next page requires a checkbox and a typed TRIP confirmation before the test can be triggered.</p>"
            f"<div class=\"label\">Armed at</div><div class=\"value\">{escape(str(result.get('armed_at', '-')))}</div>"
            f"<div class=\"label\">Expires</div><div class=\"value\">{escape(str(result.get('expires_at_unix', '-')))}</div>"
            "<div class=\"button-row\"><a class=\"action\" href=\"/watchdog-trip-confirm\">Continue to confirm page</a><a class=\"ghost\" href=\"/services#watchdog\">Back to Watchdog</a></div>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def watchdog_trip_result_html(result):
        ok = bool(result.get("ok"))
        body = (
            "<meta http-equiv=\"refresh\" content=\"12;url=/services#watchdog\">"
            "<div class=\"card\">"
            "<h2>Deliberate Watchdog Trip Test</h2>"
            f"<p class=\"{'critical' if ok else 'warning'}\">{escape(str(result.get('message', 'Trip test processed.')))}</p>"
            f"<div class=\"label\">Test time</div><div class=\"value\">{escape(str(result.get('tested_at', '-')))}</div>"
            f"<div class=\"label\">Boot ID</div><div class=\"value\">{escape(str(result.get('triggered_boot_id', '-')))}</div>"
            "<p class=\"muted\">If the hardware watchdog is present and feeding was paused, the gateway should reboot soon. After it comes back, the test state will show as completed on the previous boot.</p>"
            "<div class=\"button-row\"><a class=\"ghost\" href=\"/watchdog\">Back to Watchdog</a></div>"
            "</div>"
        )
        return page_shell(body, "Watchdog")

    def settings_payload_from_form(form):
        def first(name, default=""):
            return form.get(name, [default])[0]

        def lines(name):
            return [line.strip() for line in first(name).splitlines() if line.strip()]

        return {
            "identity": {
                "site_name": first("site_name", ""),
                "asset_id": first("asset_id", ""),
            },
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
                "startup_grace_seconds": first("watchdog_startup_grace_seconds", "300"),
                "post_trip_grace_seconds": first("watchdog_post_trip_grace_seconds", "900"),
            },
            "recording_storage": {
                "expected_full": "recording_storage_expected_full" in form,
                "minimum_free_mb_warning": first("recording_storage_minimum_free_mb_warning", ""),
                "minimum_free_mb_critical": first("recording_storage_minimum_free_mb_critical", ""),
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
        device = str(hw_cfg.get("device", "/dev/wdt_dio"))
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
        startup_grace = feed.get("startup_grace", {}) if isinstance(feed.get("startup_grace", {}), dict) else {}
        if not feed_enabled:
            feed_state = "warning"
            last_feed_message = "Feed disabled in config/status"
        elif startup_grace.get("active"):
            feed_state = "waiting"
            last_feed_message = f"Startup safety window: {startup_grace.get('remaining_seconds', 0)}s remaining"
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
            "configured_timeout_seconds": feed.get("timeout_seconds") or hw_cfg.get("timeout_seconds", 30),
            "feed_state": feed_state,
            "last_feed_message": last_feed_message,
            "last_test_message": last_test_message,
            "startup_grace": startup_grace,
        }

    def watchdog_owner_info(device):
        device_path = Path(str(device or "/dev/wdt_dio"))
        owners = []
        if not device_path.exists():
            return {"device": str(device_path), "owners": [], "summary": "Device not present"}
        try:
            target = os.path.realpath(str(device_path))
        except OSError:
            target = str(device_path)
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            fd_dir = proc / "fd"
            try:
                fds = list(fd_dir.iterdir())
            except OSError:
                continue
            matched = False
            for fd in fds:
                try:
                    if os.path.realpath(str(fd)) == target:
                        matched = True
                        break
                except OSError:
                    continue
            if not matched:
                continue
            try:
                comm = (proc / "comm").read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                comm = "-"
            try:
                raw_cmd = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="ignore").strip()
            except OSError:
                raw_cmd = ""
            owners.append({"pid": proc.name, "name": comm, "cmdline": raw_cmd or comm})
        if owners:
            summary = ", ".join(f"{item['name']}({item['pid']})" for item in owners)
        else:
            summary = "No process currently has the watchdog device open"
        return {"device": str(device_path), "owners": owners, "summary": summary}

    def legacy_clean(legacy):
        units = legacy.get("units", [])
        if units:
            return all(unit.get("active") != "active" and unit.get("enabled") not in ("enabled", "static") for unit in units)
        return legacy.get("active") != "active" and legacy.get("enabled") not in ("enabled", "static")

    def watchdog_setup_rows(watchdog, systemd_wdt):
        modules = watchdog.get("modules", {})
        wdctl = watchdog.get("wdctl", {})
        legacy = watchdog.get("legacy_daemon", {})
        owner = watchdog.get("owners", {})
        wdt = watchdog_test_summary()
        hw_cfg = cfg.get("hardware_watchdog", {})
        backend = "neousys_wdt_dio"
        device = "/dev/wdt_dio"
        identity = str(wdctl.get("identity", ""))
        driver_loaded = bool(modules.get("wdt_dio"))
        identity_ready = "Neousys WDT_DIO" in identity
        feed_enabled = bool(hw_cfg.get("enabled"))
        feed_opened = bool(wdt.get("opened"))
        feed_recent = wdt.get("feed_state") == "healthy"
        startup_grace = wdt.get("startup_grace", {}) if isinstance(wdt.get("startup_grace", {}), dict) else {}
        grace_active = bool(startup_grace.get("active"))
        timeout = int(hw_cfg.get("timeout_seconds", 30) or 30)
        feed_interval = int(hw_cfg.get("feed_interval_seconds", 10) or 10)
        rows = [
            {
                "name": "Neousys WDT_DIO driver",
                "state": "healthy" if driver_loaded else "warning",
                "message": "Loaded" if driver_loaded else "Not loaded yet",
            },
            {
                "name": "Watchdog device",
                "state": "healthy" if Path(device).exists() else "warning",
                "message": f"{device} present" if Path(device).exists() else f"{device} missing",
            },
            {
                "name": "Driver identity",
                "state": "healthy" if identity_ready else "warning",
                "message": identity or "No Neousys identity reported yet",
            },
            {
                "name": "Legacy daemon",
                "state": "healthy" if legacy_clean(legacy) else "critical",
                "message": "Removed/disabled" if legacy_clean(legacy) else "Another watchdog daemon may still own the device",
            },
            {
                "name": "Watchdog config",
                "state": "healthy" if feed_enabled else "warning",
                "message": f"backend={backend}, enabled={feed_enabled}, device={device}, feed={feed_interval}s, timeout={timeout}s",
            },
            {
                "name": "Device owner",
                "state": "healthy" if feed_opened else ("waiting" if grace_active else "warning"),
                "message": "The watchdog service has opened the device" if feed_opened else ("Device intentionally remains closed during startup safety window" if grace_active else owner.get("summary", "The watchdog service has not opened the device")),
            },
            {
                "name": "Live feed",
                "state": "healthy" if feed_recent else ("waiting" if grace_active else "warning"),
                "message": str(wdt.get("last_feed_message", "No feed status yet")),
            },
            {
                "name": "Process watchdog",
                "state": systemd_wdt.get("state", "unknown"),
                "message": f"{systemd_wdt.get('message', '-')}; WatchdogSec {systemd_wdt.get('watchdog_sec', '-')}",
            },
        ]
        prerequisites_ready = all(row["state"] == "healthy" for row in rows[:5])
        feed_ready = feed_opened and feed_recent
        ready = prerequisites_ready and (feed_ready or grace_active)
        return {
            "ready": ready,
            "trip_ready": prerequisites_ready and feed_ready and not grace_active,
            "state": "waiting" if grace_active and ready else ("healthy" if ready else "warning"),
            "message": (f"Startup safety window active; hardware protection arms in {startup_grace.get('remaining_seconds', 0)}s" if grace_active and ready else ("Hardware watchdog is ready and owned by VA-Connect" if ready else "Setup incomplete: run the one-click setup, then reload this page")),
            "checks": rows,
            "owner": owner,
            "startup_grace": startup_grace,
            "config": {
                "path": str(active_config_path()),
                "enabled": feed_enabled,
                "backend": backend,
                "device": device,
                "feed_interval_seconds": feed_interval,
                "timeout_seconds": timeout,
                "opened": feed_opened,
                "feed_count": wdt.get("feed_count", 0),
                "last_feed": wdt.get("last_feed_message", "-"),
                "startup_grace_seconds": int(hw_cfg.get("startup_grace_seconds", 300) or 0),
                "post_trip_grace_seconds": int(hw_cfg.get("post_trip_grace_seconds", 900) or 0),
            },
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
            "-p",
            "MemoryMax",
            "-p",
            "TasksMax",
            "-p",
            "CPUAccounting",
            "-p",
            "MemoryAccounting",
            "-p",
            "NRestarts",
            "-p",
            "MainPID",
        ], timeout=3)
        values = {}
        for line in props["stdout"].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        raw_usec = str(values.get("WatchdogUSec", "0") or "0").strip()
        usec = 0
        try:
            usec = int(raw_usec)
        except ValueError:
            match = re.match(r"^\s*(\d+(?:\.\d+)?)([a-zA-Z]+)?\s*$", raw_usec)
            if match:
                amount = float(match.group(1))
                unit = (match.group(2) or "us").lower()
                factors = {
                    "us": 1,
                    "usec": 1,
                    "ms": 1000,
                    "msec": 1000,
                    "s": 1000000,
                    "sec": 1000000,
                    "m": 60 * 1000000,
                    "min": 60 * 1000000,
                    "h": 3600 * 1000000,
                    "hr": 3600 * 1000000,
                }
                if unit in factors:
                    usec = int(amount * factors[unit])
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
            "memory_max": values.get("MemoryMax", ""),
            "tasks_max": values.get("TasksMax", ""),
            "cpu_accounting": values.get("CPUAccounting", ""),
            "memory_accounting": values.get("MemoryAccounting", ""),
            "restarts": values.get("NRestarts", ""),
            "main_pid": values.get("MainPID", ""),
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
        device = str(hw_cfg.get("device", "/dev/wdt_dio"))
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

    def service_history_chart(rows, service_name, key, label, suffix=""):
        service_rows = []
        for row in rows:
            for metric in row.get("service_metrics", []) or []:
                if isinstance(metric, dict) and metric.get("name") == service_name:
                    service_rows.append({"time": row.get("time"), key: metric.get(key)})
        scale_max = 100 if key == "cpu_percent" else 512
        return f'<div class="service-trend"><div class="label">{escape(label)}</div>{multi_history_chart(service_rows, [(key, label)], 0, scale_max, suffix)}</div>'

    def service_combined_history_chart(rows, service_name):
        points = []
        for row in rows:
            metric = next(
                (
                    item for item in (row.get("service_metrics") or [])
                    if isinstance(item, dict) and item.get("name") == service_name
                ),
                None,
            )
            if not metric:
                continue
            try:
                cpu = float(metric.get("cpu_percent")) if metric.get("cpu_percent") is not None else None
            except (TypeError, ValueError):
                cpu = None
            try:
                memory = float(metric.get("memory_mb")) if metric.get("memory_mb") is not None else None
            except (TypeError, ValueError):
                memory = None
            if cpu is not None or memory is not None:
                points.append((cpu, memory))
        points = points[-160:]
        if not points:
            return '<div class="history-box">No CPU/RAM history yet</div>'
        width, height = 640, 190
        left, right, top, bottom = 42, 42, 18, 32
        plot_w, plot_h = width - left - right, height - top - bottom
        cpu_max = max(1.0, max((point[0] or 0) for point in points))
        memory_max = max(1.0, max((point[1] or 0) for point in points))
        cpu_coords, memory_coords = [], []
        for index, (cpu, memory) in enumerate(points):
            x = left + (index / max(1, len(points) - 1)) * plot_w
            if cpu is not None:
                cpu_coords.append(f"{x:.1f},{top + (1 - min(1, cpu / cpu_max)) * plot_h:.1f}")
            if memory is not None:
                memory_coords.append(f"{x:.1f},{top + (1 - min(1, memory / memory_max)) * plot_h:.1f}")
        cpu_latest = next((point[0] for point in reversed(points) if point[0] is not None), None)
        memory_latest = next((point[1] for point in reversed(points) if point[1] is not None), None)
        legend = (
            f'<span style="color:var(--green)">CPU: {escape(str(round(cpu_latest, 1) if cpu_latest is not None else "-"))}% '
            f'(max {escape(str(round(cpu_max, 1)))}%)</span> '
            f'<span style="color:var(--blue)">RAM: {escape(str(round(memory_latest, 1) if memory_latest is not None else "-"))} MB '
            f'(max {escape(str(round(memory_max, 1)))} MB)</span>'
        )
        svg = (
            f'<svg class="chart" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
            f'<line class="grid-line" x1="{left}" y1="{top}" x2="{width-right}" y2="{top}"></line>'
            f'<line class="grid-line" x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}"></line>'
            f'<text x="4" y="{top + 4}">100%</text><text x="4" y="{height-bottom}">0</text>'
            f'<polyline points="{" ".join(cpu_coords)}" style="stroke:var(--green)"></polyline>'
            f'<polyline points="{" ".join(memory_coords)}" style="stroke:var(--blue)"></polyline>'
            "</svg>"
        )
        return f'<div class="service-trend"><div class="chart-legend">{legend}</div>{svg}</div>'

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

    def neousys_install_status():
        log_path = data_dir / "neousys-watchdog-install.log"
        return {
            "script": str(repo_root() / "scripts" / "install_neousys_wdt.sh"),
            "log_path": str(log_path),
            "last_log": tail_file(log_path, lines=80).get("tail", ""),
        }

    def neousys_probe_status():
        log_path = data_dir / "neousys-watchdog-probe.log"
        return {
            "script": str(repo_root() / "scripts" / "probe_neousys_watchdog.sh"),
            "log_path": str(log_path),
            "last_log": tail_file(log_path, lines=200).get("tail", ""),
        }

    def launch_neousys_install():
        status = neousys_install_status()
        script = Path(status["script"])
        log_path = Path(status["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Neousys setup script not found: {script}", "log_path": str(log_path)}
        command = f"cd {repo_root()!s}; /bin/bash scripts/install_neousys_wdt.sh >> {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {"ok": False, "message": f"Could not start Neousys setup: {exc}", "command": command, "log_path": str(log_path)}
        append_web_event("info", "hardware_watchdog", "Neousys watchdog driver installation started", {"log_path": str(log_path)})
        return {
            "ok": True,
            "message": "Neousys watchdog driver installation started in the background without activating the timer.",
            "command": command,
            "log_path": str(log_path),
        }

    def launch_watchdog_probe():
        status = neousys_probe_status()
        script = Path(status["script"])
        log_path = Path(status["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Watchdog probe script not found: {script}", "log_path": str(log_path)}
        command = f"cd {repo_root()!s}; /bin/bash scripts/probe_neousys_watchdog.sh > {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {"ok": False, "message": f"Could not start watchdog probe: {exc}", "command": command, "log_path": str(log_path)}
        append_web_event("info", "hardware_watchdog", "Neousys watchdog probe started", {"log_path": str(log_path)})
        return {
            "ok": True,
            "message": "Neousys watchdog probe started in the background.",
            "command": command,
            "log_path": str(log_path),
        }

    def launch_hardware_watchdog_prepare():
        status = neousys_install_status()
        script = Path(status["script"])
        log_path = Path(status["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not script.exists():
            return {"ok": False, "message": f"Hardware watchdog prepare script not found: {script}", "log_path": str(log_path)}

        cleanup = disable_legacy_watchdog_daemon()
        if not cleanup.get("ok"):
            return cleanup
        command = f"cd {repo_root()!s}; /bin/bash scripts/install_neousys_wdt.sh --activate > {log_path!s} 2>&1"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Prepare job could not start: {exc}",
                "command": command,
                "output": str(exc),
                "log_path": str(log_path),
            }
        append_web_event(
            "info",
            "hardware_watchdog",
            "Neousys watchdog installation and activation started",
            {"log_path": str(log_path)},
        )
        return {
            "ok": True,
            "message": "Neousys watchdog setup started after legacy watchdog cleanup. The feeder will restart in the background.",
            "command": command,
            "output": "Setup flow: remove legacy daemons, install the bundled Neousys driver, select /dev/wdt_dio, and restart the independent feeder.",
            "log_path": str(log_path),
        }

    def disable_legacy_watchdog_daemon():
        command = (
            "set +e; "
            "for unit in watchdog.service wd_keepalive.service; do "
            "systemctl stop \"$unit\"; systemctl disable \"$unit\"; systemctl mask \"$unit\"; "
            "done; "
            "if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' watchdog 2>/dev/null | grep -q 'install ok installed'; then "
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y watchdog; "
            "else echo 'Ubuntu watchdog package is not installed.'; fi; "
            "systemctl is-active watchdog.service; systemctl is-enabled watchdog.service; "
            "systemctl is-active wd_keepalive.service; systemctl is-enabled wd_keepalive.service"
        )
        result = _run(["/bin/bash", "-lc", command], timeout=90)
        output = "\n".join(part for part in [result.get("stdout", ""), result.get("stderr", "")] if part)
        legacy = legacy_watchdog_daemon_info()
        ok = legacy_clean(legacy)
        append_web_event("info" if ok else "warning", "hardware_watchdog", "Legacy watchdog.service disable requested", {"ok": ok, "output": output})
        return {
            "ok": ok,
            "message": "Legacy watchdog daemon cleaned up" if ok else "Legacy watchdog daemon cleanup needs attention",
            "command": command,
            "output": output,
        }

    def enable_va_hardware_watchdog():
        info = hardware_info()
        wizard = hardware_watchdog_wizard_state(info.get("watchdog", {}), systemd_watchdog_info())
        pre_enable_ready = all(item.get("state") == "healthy" for item in wizard.get("checks", [])[:4])
        if not pre_enable_ready:
            return {
                "ok": False,
                "message": "Hardware watchdog prerequisites are not healthy yet. Run one-click setup first.",
                "command": "",
                "output": json.dumps(wizard.get("checks", []), indent=2),
            }
        updates = {
            "hardware_watchdog": {
                "enabled": True,
                "backend": "neousys_wdt_dio",
                "device": "/dev/wdt_dio",
                "library_path": "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
                "feed_interval_seconds": 10,
                "magic_close": False,
            }
        }
        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        delay_current_boot(cfg, int(cfg.get("hardware_watchdog", {}).get("startup_grace_seconds", 300) or 300), extend=False)
        command = "sleep 2; systemctl restart va-watchdog"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Config saved to {saved_path}, but service restart failed to start: {exc}",
                "command": command,
                "output": str(exc),
            }
        startup_delay = int(cfg.get("hardware_watchdog", {}).get("startup_grace_seconds", 300) or 300)
        append_web_event("info", "hardware_watchdog", "VA-Connect hardware watchdog configured with startup safety window", {"config_path": str(saved_path), "startup_grace_seconds": startup_delay})
        return {
            "ok": True,
            "message": f"Hardware watchdog configured. A {startup_delay // 60}-minute safety window starts before the device is opened; va-watchdog restart requested.",
            "command": command,
            "output": f"hardware_watchdog.enabled=true, backend=neousys_wdt_dio, device=/dev/wdt_dio, feed_interval_seconds=10, startup_grace_seconds={startup_delay}",
        }

    def set_watchdog_timeout(timeout_seconds):
        try:
            timeout_seconds = int(timeout_seconds)
        except (TypeError, ValueError):
            return {"ok": False, "message": "Invalid timeout value.", "command": "", "output": ""}
        if timeout_seconds < 10 or timeout_seconds > 600:
            return {"ok": False, "message": "Timeout must be between 10 and 600 seconds.", "command": "", "output": ""}

        updates = {
            "hardware_watchdog": {
                "timeout_seconds": timeout_seconds,
            }
        }
        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        command = "sleep 2; systemctl restart va-watchdog"
        try:
            subprocess.Popen(["/bin/bash", "-lc", command], start_new_session=True)
        except Exception as exc:
            return {
                "ok": False,
                "message": f"Timeout saved to {saved_path}, but restart failed to start: {exc}",
                "command": command,
                "output": str(exc),
            }
        append_web_event("info", "hardware_watchdog", "Hardware watchdog timeout updated", {"config_path": str(saved_path), "timeout_seconds": timeout_seconds})
        return {
            "ok": True,
            "message": f"Hardware watchdog timeout updated to {timeout_seconds} seconds. Config saved to {saved_path}; va-watchdog restart requested.",
            "command": command,
            "output": f"hardware_watchdog.timeout_seconds={timeout_seconds}",
        }

    def current_watchdog_grace():
        return startup_grace_status(cfg, trip_test_summary(cfg))

    def delay_watchdog_arming(delay_seconds):
        try:
            delay_seconds = int(delay_seconds)
        except (TypeError, ValueError):
            return {"ok": False, "message": "Invalid delay value.", "command": "", "output": ""}
        if delay_seconds < 60 or delay_seconds > 86400:
            return {"ok": False, "message": "Delay must be between 60 seconds and 24 hours.", "command": "", "output": ""}
        feed = status_snapshot().get("hardware_watchdog_feed", {})
        grace = current_watchdog_grace()
        safety_margin = max(15, int(cfg.get("poll_interval_seconds", 5) or 5) * 2)
        if feed.get("opened") or not grace.get("active") or int(grace.get("remaining_seconds", 0) or 0) <= safety_margin:
            return {
                "ok": False,
                "message": "The safety window is no longer safely extendable. The watchdog may already be arming.",
                "command": "",
                "output": json.dumps(grace, indent=2),
            }
        updated = delay_current_boot(cfg, delay_seconds)
        append_web_event("warning", "hardware_watchdog", f"Hardware watchdog arming delayed by {delay_seconds} seconds for this boot", updated)
        return {
            "ok": True,
            "message": f"Hardware watchdog arming delayed by another {delay_seconds // 60} minutes for this boot.",
            "command": "Current-boot safety override",
            "output": json.dumps(updated, indent=2),
        }

    def arm_hardware_watchdog_now():
        feed = status_snapshot().get("hardware_watchdog_feed", {})
        grace = current_watchdog_grace()
        if not cfg.get("hardware_watchdog", {}).get("enabled"):
            return {"ok": False, "message": "Hardware watchdog feed is disabled in configuration.", "command": "", "output": ""}
        if feed.get("opened"):
            return {"ok": False, "message": "The hardware watchdog device is already opened.", "command": "", "output": ""}
        if not grace.get("active"):
            return {"ok": False, "message": "There is no active startup safety window to end.", "command": "", "output": json.dumps(grace, indent=2)}
        updated = arm_current_boot(cfg)
        append_web_event("warning", "hardware_watchdog", "Hardware watchdog startup safety window ended manually", updated)
        return {
            "ok": True,
            "message": "Safety window ended. VA-Connect will open and feed the hardware watchdog on the next health loop.",
            "command": "Current-boot arm-now override",
            "output": json.dumps(updated, indent=2),
        }

    def disable_hardware_watchdog_during_grace():
        feed = status_snapshot().get("hardware_watchdog_feed", {})
        grace = current_watchdog_grace()
        remaining = int(grace.get("remaining_seconds", 0) or 0)
        safety_margin = max(15, int(cfg.get("poll_interval_seconds", 5) or 5) * 2)
        if feed.get("opened"):
            return {"ok": False, "message": "Safe disable blocked: /dev/wdt_dio is already opened.", "command": "", "output": "A live hardware watchdog is never closed from the webpage."}
        if not grace.get("active") or remaining <= safety_margin:
            return {"ok": False, "message": "Safe disable blocked: use this control earlier in the startup safety window.", "command": "", "output": json.dumps(grace, indent=2)}
        updates = {"hardware_watchdog": {"enabled": False}}
        saved_path = save_raw_config(deep_merge(load_raw_config(), updates))
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        append_web_event("warning", "hardware_watchdog", "Hardware watchdog feed disabled during startup safety window", {"config_path": str(saved_path)})
        return {
            "ok": True,
            "message": "Hardware watchdog feed disabled before the device was opened. The process watchdog remains enabled.",
            "command": f"Saved {saved_path}",
            "output": "hardware_watchdog.enabled=false",
        }

    def set_watchdog_grace_periods(startup_seconds, post_trip_seconds):
        try:
            startup_seconds = int(startup_seconds)
            post_trip_seconds = int(post_trip_seconds)
        except (TypeError, ValueError):
            return {"ok": False, "message": "Safety window values must be numbers.", "command": "", "output": ""}
        if startup_seconds < 60 or startup_seconds > 3600:
            return {"ok": False, "message": "Normal reboot delay must be between 1 and 60 minutes.", "command": "", "output": ""}
        if post_trip_seconds < 300 or post_trip_seconds > 7200:
            return {"ok": False, "message": "Post-trip delay must be between 5 minutes and 2 hours.", "command": "", "output": ""}
        current = current_watchdog_grace()
        updates = {"hardware_watchdog": {"startup_grace_seconds": startup_seconds, "post_trip_grace_seconds": post_trip_seconds}}
        saved_path = save_raw_config(deep_merge(load_raw_config(), updates))
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        if current.get("active"):
            updated_current = current_watchdog_grace()
            preserve_seconds = int(current.get("remaining_seconds", 0) or 0)
            updated_seconds = int(updated_current.get("remaining_seconds", 0) or 0)
            if updated_seconds < preserve_seconds:
                delay_current_boot(cfg, preserve_seconds, extend=False)
        append_web_event("info", "hardware_watchdog", "Hardware watchdog startup safety windows updated", {"startup_grace_seconds": startup_seconds, "post_trip_grace_seconds": post_trip_seconds})
        return {
            "ok": True,
            "message": "Startup safety windows saved. The current active window was not shortened.",
            "command": f"Saved {saved_path}",
            "output": f"normal={startup_seconds}s, post_trip={post_trip_seconds}s",
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
            "identity": identity_summary(cfg),
            "hostname": platform.node(),
            "os": platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "uptime_seconds": uptime_seconds,
            "timezone": time.tzname,
            "rtc": rtc_status(),
            "heartbeat": {
                "state": read_state(cfg),
                "age_seconds": heartbeat_age_seconds(read_state(cfg)),
                "history_tail": read_tail(cfg, 5),
            },
            "persistent_journal": persistent_status(),
            "reboot_evidence": _read_json_file(Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl").with_name("last-reboot-evidence.json")),
        }

    def _read_json_file(path):
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

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
        watchdog_devices = ["/dev/wdt_dio"] if Path("/dev/wdt_dio").exists() else []
        watchdog_summary = watchdog_driver_info(watchdog_devices)
        status = status_snapshot()
        live_feed = status.get("hardware_watchdog_feed", {}) if isinstance(status.get("hardware_watchdog_feed", {}), dict) else {}
        trip_summary = trip_test_summary(cfg)
        watchdog_summary["safe_test"] = watchdog_test_summary()
        watchdog_summary["trip_test"] = trip_summary
        watchdog_summary["startup_grace"] = live_feed.get("startup_grace") or startup_grace_status(cfg, trip_summary)
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
            "watchdog": watchdog_summary,
        }

    def watchdog_driver_info(watchdog_devices):
        modules = {
            "wdt_dio": False,
        }
        proc_modules = Path("/proc/modules")
        if proc_modules.exists():
            text = proc_modules.read_text(encoding="utf-8", errors="ignore")
            for name in modules:
                modules[name] = any(line.startswith(name + " ") for line in text.splitlines())
        hw_cfg = cfg.get("hardware_watchdog", {}) if isinstance(cfg.get("hardware_watchdog", {}), dict) else {}
        backend = "neousys_wdt_dio"
        configured_device = "/dev/wdt_dio"
        device = configured_device if configured_device in watchdog_devices else (watchdog_devices[0] if watchdog_devices else configured_device)
        wdctl = {
            "device": device,
            "state": "warning",
            "identity": "-",
            "timeout": "-",
            "raw": "",
        }
        if Path(device).exists():
            wdctl.update({
                "state": "healthy",
                "identity": "Neousys WDT_DIO",
                "timeout": str(hw_cfg.get("timeout_seconds") or 30),
                "raw": "Vendor API backend; Linux wdctl does not apply.",
            })
        return {
            "backend": backend,
            "expected_driver": "wdt_dio",
            "expected_identity": "Neousys WDT_DIO",
            "device": device,
            "modules": modules,
            "wdctl": wdctl,
            "owners": watchdog_owner_info(device),
            "legacy_daemon": legacy_watchdog_daemon_info(),
            "systemd_watchdog": systemd_watchdog_info(),
            "prepare_log": neousys_install_status().get("last_log", ""),
            "setup_log": neousys_install_status().get("last_log", ""),
            "probe_log": neousys_probe_status().get("last_log", ""),
        }

    def legacy_watchdog_daemon_info():
        units = []
        for unit in ["watchdog.service", "wd_keepalive.service"]:
            active = _run(["systemctl", "is-active", unit], timeout=3)
            enabled = _run(["systemctl", "is-enabled", unit], timeout=3)
            units.append({
                "unit": unit,
                "active": active["stdout"] or active["stderr"] or "unknown",
                "enabled": enabled["stdout"] or enabled["stderr"] or "unknown",
            })
        package = _run(["dpkg-query", "-W", "-f=${Status}", "watchdog"], timeout=3)
        package_status = package["stdout"] or package["stderr"] or "not installed"
        main = units[0]
        return {
            "active": main["active"],
            "enabled": main["enabled"],
            "units": units,
            "package_status": package_status,
            "package_installed": "install ok installed" in package_status,
        }

    def hardware_watchdog_wizard_state(watchdog, systemd_wdt):
        return watchdog_setup_rows(watchdog, systemd_wdt)

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
                "name": "Legacy Recordings Path",
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
            "recording_storage": status_snapshot().get("recording_storage") or recording_storage_status(cfg),
            "recording_storage_candidates": recording_storage_candidates(cfg),
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
        runtime = _runtime_stats(name) if pid and pid != "0" else {}
        cpu_percent = runtime.get("cpu_percent") if runtime.get("cpu_percent") is not None else "-"
        memory_mb = runtime.get("memory_mb") if runtime.get("memory_mb") is not None else "-"
        uptime = _format_duration(runtime.get("uptime_seconds")) if runtime.get("uptime_seconds") is not None else "-"
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
        services.insert(0, service_snapshot({"name": "va-watchdog", "critical": True, "restart": False}))
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
            "identity": identity_summary(cfg),
            "poll_interval_seconds": cfg.get("poll_interval_seconds"),
            "web": cfg.get("web", {}),
            "hardware_watchdog": cfg.get("hardware_watchdog", {}),
            "process_monitor": cfg.get("process_monitor", {}),
            "service_resource_limits": cfg.get("service_resource_limits", {}),
            "recording_storage": cfg.get("recording_storage", {}),
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

    def _nullable_float_range(payload, name, minimum, maximum):
        value = payload.get(name)
        if value in (None, ""):
            return None
        try:
            number = float(value)
        except Exception as exc:
            raise ValueError(f"{name} must be a number or blank") from exc
        if number < minimum or number > maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")
        return number

    def _string_list(value, name):
        if not isinstance(value, list):
            raise ValueError(f"{name} must be a list")
        cleaned = []
        for item in value:
            text = str(item).strip()
            if text:
                cleaned.append(text)
        return cleaned[:50]

    def _identity_text(value, name, maximum):
        text = str(value or "").strip()
        if any(ord(character) < 32 for character in text):
            raise ValueError(f"{name} must be a single line")
        if len(text) > maximum:
            raise ValueError(f"{name} must be {maximum} characters or fewer")
        return text

    def apply_settings(payload):
        if not isinstance(payload, dict):
            raise ValueError("settings payload must be an object")
        thresholds = payload.get("thresholds", {})
        retention = payload.get("retention", {})
        network = payload.get("network", {})
        update = payload.get("update", {})
        hardware = payload.get("hardware_watchdog", {})
        process_monitor = payload.get("process_monitor", {})
        recording_storage = payload.get("recording_storage", {})
        recovery = payload.get("recovery", {})
        identity = payload.get("identity", cfg.get("identity", {}))
        if not isinstance(identity, dict):
            raise ValueError("identity must be an object")

        updates = {
            "identity": {
                "site_name": _identity_text(identity.get("site_name", ""), "site_name", 80),
                "asset_id": _identity_text(identity.get("asset_id", ""), "asset_id", 64),
            },
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
                "startup_grace_seconds": _int_range(
                    {"startup_grace_seconds": hardware.get("startup_grace_seconds", cfg.get("hardware_watchdog", {}).get("startup_grace_seconds", 300))},
                    "startup_grace_seconds",
                    60,
                    3600,
                ),
                "post_trip_grace_seconds": _int_range(
                    {"post_trip_grace_seconds": hardware.get("post_trip_grace_seconds", cfg.get("hardware_watchdog", {}).get("post_trip_grace_seconds", 900))},
                    "post_trip_grace_seconds",
                    300,
                    7200,
                ),
            },
            "process_monitor": {
                "enabled": bool(process_monitor.get("enabled", cfg.get("process_monitor", {}).get("enabled", True))),
                "cpu_warning_percent": _int_range({"cpu_warning_percent": process_monitor.get("cpu_warning_percent", cfg.get("process_monitor", {}).get("cpu_warning_percent", 25))}, "cpu_warning_percent", 1, 100),
                "cpu_critical_percent": _int_range({"cpu_critical_percent": process_monitor.get("cpu_critical_percent", cfg.get("process_monitor", {}).get("cpu_critical_percent", 75))}, "cpu_critical_percent", 1, 100),
                "memory_warning_mb": _int_range({"memory_warning_mb": process_monitor.get("memory_warning_mb", cfg.get("process_monitor", {}).get("memory_warning_mb", 100))}, "memory_warning_mb", 16, 4096),
                "memory_critical_mb": _int_range({"memory_critical_mb": process_monitor.get("memory_critical_mb", cfg.get("process_monitor", {}).get("memory_critical_mb", 200))}, "memory_critical_mb", 32, 8192),
                "sustained_seconds": _int_range({"sustained_seconds": process_monitor.get("sustained_seconds", cfg.get("process_monitor", {}).get("sustained_seconds", 300))}, "sustained_seconds", 30, 3600),
            },
            "recording_storage": {
                "expected_full": bool(recording_storage.get("expected_full", False)),
                "minimum_free_mb_warning": _nullable_float_range(recording_storage, "minimum_free_mb_warning", 0, 1048576),
                "minimum_free_mb_critical": _nullable_float_range(recording_storage, "minimum_free_mb_critical", 0, 1048576),
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
        if updates["process_monitor"]["cpu_warning_percent"] >= updates["process_monitor"]["cpu_critical_percent"]:
            raise ValueError("watchdog CPU warning must be lower than critical")
        if updates["process_monitor"]["memory_warning_mb"] >= updates["process_monitor"]["memory_critical_mb"]:
            raise ValueError("watchdog memory warning must be lower than critical")
        if cfg.get("hardware_watchdog", {}).get("enabled") and not updates["hardware_watchdog"]["enabled"]:
            raise ValueError("hardware watchdog feed cannot be disabled from general Settings; use the guarded Watchdog startup safety control")
        rs_warning = updates["recording_storage"]["minimum_free_mb_warning"]
        rs_critical = updates["recording_storage"]["minimum_free_mb_critical"]
        if rs_warning is not None and rs_critical is not None and rs_warning <= rs_critical:
            raise ValueError("recording storage warning free MB must be higher than critical free MB")

        previous_identity = configured_identity(cfg)
        raw = load_raw_config()
        merged_raw = deep_merge(raw, updates)
        saved_path = save_raw_config(merged_raw)
        live_cfg = deep_merge(cfg, updates)
        cfg.clear()
        cfg.update(live_cfg)
        current_identity = configured_identity(cfg)
        if (
            previous_identity["site_name"] != current_identity["site_name"]
            or previous_identity["asset_id"] != current_identity["asset_id"]
        ):
            append_web_event(
                "info",
                "identity",
                "Gateway identity updated",
                {
                    "previous_site_name": previous_identity["site_name"],
                    "site_name": current_identity["site_name"],
                    "asset_id": current_identity["asset_id"],
                },
            )
        return {
            "ok": True,
            "path": str(saved_path),
            "settings": settings_summary(),
            "restart_required": False,
        }

    def recent_events(limit=500):
        return read_events(events_path, limit=limit)

    def filtered_events(query, limit=5000):
        def first(name, default=""):
            value = query.get(name, [default])
            return str(value[0] if isinstance(value, list) and value else value or default).strip()

        filters = {
            "level": first("level", "all").lower(),
            "search": first("search"),
            "source": first("source"),
            "from": first("from"),
            "to": first("to"),
        }

        def filter_time(value):
            if not value:
                return None
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None:
                    parsed = parsed.astimezone()
                return parsed.timestamp()
            except (TypeError, ValueError):
                return None

        from_time = filter_time(filters["from"])
        to_time = filter_time(filters["to"])
        matches = []
        for event in recent_events(limit=limit):
            level = str(event.get("level", "info")).lower()
            if filters["level"] == "attention" and level not in {"critical", "warning", "degraded"}:
                continue
            if filters["level"] not in {"", "all", "attention"} and level != filters["level"]:
                continue
            source = str(event.get("source", ""))
            if filters["source"] and filters["source"].lower() not in source.lower():
                continue
            searchable = f"{source} {event.get('message', '')} {json.dumps(event.get('data') or {}, default=str)}".lower()
            if filters["search"] and filters["search"].lower() not in searchable:
                continue
            try:
                event_time = datetime.fromisoformat(str(event.get("time", "")).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                event_time = None
            if from_time is not None and (event_time is None or event_time < from_time):
                continue
            if to_time is not None and (event_time is None or event_time > to_time):
                continue
            matches.append(event)
        return matches, filters

    def events_csv(limit=200, rows=None):
        rows = recent_events(limit=limit) if rows is None else rows[:limit]
        identity = configured_identity(cfg)
        lines = ["site_name,asset_id,time,level,source,message"]
        for event in rows:
            values = [
                identity["site_name"],
                identity["asset_id"],
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
            "site_name",
            "asset_id",
            "time",
            "state",
            "display_state",
            "score",
            "critical_failed",
            "boot_id",
            "uptime_seconds",
            "sample_gap_seconds",
            "temperature",
            "cpu_load",
            "ram",
            "root_disk",
            "recordings_disk",
            "warning_checks",
            "degraded_checks",
            "critical_checks",
            "service_states",
            "hardware_watchdog_present",
            "hardware_watchdog_feed_status",
            "hardware_watchdog_feed_message",
            "hardware_watchdog_feed_enabled",
            "hardware_watchdog_opened",
            "hardware_watchdog_feed_count",
            "hardware_watchdog_timeout_seconds",
            "recording_storage_status",
            "recording_storage_message",
            "recording_storage_mounted",
            "recording_storage_writable",
            "recording_storage_used_percent",
            "recording_storage_free_mb",
            "recording_storage_expected_full",
            "recording_storage_minimum_free_mb_warning",
            "recording_storage_minimum_free_mb_critical",
        ]
        lines = [",".join(columns)]
        identity = configured_identity(cfg)
        for row in rows:
            exported = {
                **row,
                "site_name": identity["site_name"],
                "asset_id": identity["asset_id"],
            }
            lines.append(",".join(_csv_cell(exported.get(column, "")) for column in columns))
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
            "blackbox": blackbox_summary(cfg),
            "persistent_journal": persistent_status(),
            "pstore": pstore_status(),
            "incident_archives": list_archives(cfg),
            "heartbeat": {"state": read_state(cfg), "age_seconds": heartbeat_age_seconds(read_state(cfg))},
            "reboot_evidence": _read_json_file(Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl").with_name("last-reboot-evidence.json")),
            "generated_at_unix": time.time(),
        }

    def support_bundle_bytes():
        generated = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        status = status_snapshot()
        gateway_identity = identity_summary(cfg)
        services = cfg.get("services", []) if isinstance(cfg.get("services", []), list) else []
        service_names = [str(item.get("name", "")).strip() for item in services if isinstance(item, dict) and item.get("name")]
        watched_services = ["va-watchdog", "va-watchdog-feed"] + service_names
        service_status_cmd = ["systemctl", "status", *watched_services, "--no-pager", "-l"]
        bundle = {
            "generated_utc": generated,
            "identity": gateway_identity,
            "version": version_info(),
            "active_config_path": str(active_config_path()),
            "data_dir": str(data_dir),
            "status_path": str(status_path),
            "events_path": str(events_path),
            "history_path": str(history_path(cfg)),
        }
        command_outputs = {
            "systemctl-status.txt": _run(service_status_cmd, timeout=10),
            "va-watchdog-journal.txt": _run(["journalctl", "-u", "va-watchdog", "--since", "7 days ago", "--no-pager"], timeout=15),
            "va-watchdog-feed-journal.txt": _run(["journalctl", "-u", "va-watchdog-feed", "--since", "7 days ago", "--no-pager"], timeout=15),
            "kernel-journal.txt": _run(["journalctl", "-k", "--since", "7 days ago", "--no-pager"], timeout=15),
            "reboots-last-x.txt": _run(["last", "-x"], timeout=10),
            "disk-lsblk.txt": _run(["lsblk", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL"], timeout=5),
            "mounts-findmnt.txt": _run(["findmnt"], timeout=5),
            "watchdog-device.txt": _run(["bash", "-lc", "ls -l /dev/wdt_dio 2>&1; fuser -v /dev/wdt_dio 2>&1 || true"], timeout=5),
            "watchdog-modules.txt": _run(["bash", "-lc", "grep -E '^wdt_dio ' /proc/modules || true"], timeout=5),
            "neousys-module.txt": _run(["modinfo", "wdt_dio"], timeout=5),
            "neousys-files.txt": _run(["bash", "-lc", "ls -l /dev/wdt_dio /usr/local/lib/va-watchdog/vendor/libwdt_dio.so 2>&1; sha256sum /usr/local/lib/va-watchdog/vendor/libwdt_dio.so 2>&1"], timeout=5),
            "network-ip-addr.txt": _run(["ip", "-4", "addr", "show"], timeout=5),
            "network-routes.txt": _run(["ip", "route"], timeout=5),
            "kernel-previous-boot.txt": _run(["journalctl", "-b", "-1", "-k", "--no-pager"], timeout=15),
            "journal-persistent-status.txt": {"stdout": json.dumps(persistent_status(), indent=2), "stderr": "", "returncode": 0},
            "pstore-status.txt": {"stdout": json.dumps(pstore_status(), indent=2), "stderr": "", "returncode": 0},
        }
        file_sources = {
            "status.json": status_path,
            "events.jsonl": events_path,
            "history.jsonl": history_path(cfg),
            "update-state.json": data_dir / "update-state.json",
            "update.log": Path(cfg.get("update", {}).get("log_path") or data_dir / "update.log"),
            "last-reboot-reason.json": Path(cfg.get("last_reboot_reason_path") or data_dir / "last-reboot-reason.json"),
            "hardware-watchdog-control.json": Path(cfg.get("hardware_watchdog_control_path") or data_dir / "hardware-watchdog-control.json"),
            "watchdog-trip-test.json": Path(cfg.get("trip_test_path") or data_dir / "watchdog-trip-test.json"),
            "heartbeat-state.json": Path(cfg.get("heartbeat_state_path") or data_dir / "heartbeat-state.json"),
            "heartbeat.jsonl": Path(cfg.get("heartbeat_path") or data_dir / "heartbeat.jsonl"),
            "reboot-evidence.jsonl": Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl"),
            "last-reboot-evidence.json": Path(cfg.get("reboot_evidence_path") or data_dir / "reboot-evidence.jsonl").with_name("last-reboot-evidence.json"),
            "hardware-watchdog-feed.json": Path(cfg.get("hardware_watchdog_feed_state_path") or data_dir / "hardware-watchdog-feed.json"),
            "kernel-fault-state.json": Path(cfg.get("kernel_fault_state_path") or data_dir / "kernel-fault-state.json"),
            "stage0-baseline-state.json": baseline_paths(cfg)[1],
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", "\n".join([
                "VA-Connect Watchdog support bundle",
                f"Site: {gateway_identity.get('display_name') or 'Site not configured'}",
                f"Asset ID: {gateway_identity.get('asset_id') or '-'}",
                f"Hardware fingerprint: {gateway_identity.get('hardware_fingerprint') or '-'}",
                f"Generated UTC: {generated}",
                "",
                "Use this bundle to investigate lockups, service failures, storage issues, network faults, and watchdog feed state.",
                "It does not include CCTV recordings.",
                "",
            ]))
            archive.writestr("bundle-summary.json", json.dumps(bundle, indent=2))
            archive.writestr("identity.json", json.dumps(gateway_identity, indent=2))
            archive.writestr("current-status.json", json.dumps(status, indent=2))
            archive.writestr("diagnostics-summary.json", json.dumps(diagnostics_summary(), indent=2))
            archive.writestr("storage-info.json", json.dumps(storage_info(), indent=2))
            archive.writestr("hardware-info.json", json.dumps(hardware_info(), indent=2))
            archive.writestr("network-info.json", json.dumps(network_info(), indent=2))
            archive.writestr("services-info.json", json.dumps(service_info(), indent=2))
            blackbox_state = blackbox_summary(cfg)
            blackbox_rows = read_blackbox(cfg, limit=blackbox_state.get("max_rows", 450))
            archive.writestr("blackbox-summary.json", json.dumps(blackbox_state, indent=2))
            archive.writestr(
                "blackbox-buffer.jsonl",
                "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in blackbox_rows),
            )
            archive.writestr("history-export.csv", history_csv(limit=5000))
            archive.writestr("events-export.csv", events_csv(limit=1000))
            for name, result in command_outputs.items():
                archive.writestr(name, json.dumps(result, indent=2) + "\n\nSTDOUT:\n" + str(result.get("stdout") or "") + "\n\nSTDERR:\n" + str(result.get("stderr") or ""))
            for name, path in file_sources.items():
                try:
                    target = Path(path)
                    if target.exists() and target.is_file():
                        archive.write(target, f"raw-files/{name}")
                    else:
                        archive.writestr(f"raw-files/{name}.missing.txt", f"{target} was not present")
                except Exception as exc:
                    archive.writestr(f"raw-files/{name}.error.txt", str(exc))
            incidents_dir = archive_config(cfg)["path"]
            if incidents_dir.is_dir():
                for incident_file in incidents_dir.rglob("*"):
                    if incident_file.is_file():
                        try:
                            archive.write(incident_file, f"incident-archives/{incident_file.relative_to(incidents_dir)}")
                        except OSError as exc:
                            archive.writestr(f"incident-archives/{incident_file.name}.error.txt", str(exc))
            pstore_dir = Path("/sys/fs/pstore")
            archived_pstore_dir = Path("/var/lib/systemd/pstore")
            for pstore_name, pstore_source in (("live", pstore_dir), ("archived", archived_pstore_dir)):
                if not pstore_source.is_dir():
                    continue
                try:
                    for pstore_file in pstore_source.iterdir():
                        if pstore_file.is_file():
                            archive.write(pstore_file, f"pstore/{pstore_name}/{pstore_file.name}")
                except OSError as exc:
                    archive.writestr(f"pstore/{pstore_name}/read-error.txt", str(exc))
        return buffer.getvalue(), f"va-watchdog-support-{identity_slug(cfg)}-{generated}.zip"

    def config_summary():
        hardware = cfg.get("hardware_watchdog", {})
        return {
            "identity": configured_identity(cfg),
            "hardware_watchdog": {
                "enabled": bool(hardware.get("enabled", False)),
                "device": str(hardware.get("device", "")),
                "timeout_seconds": hardware.get("timeout_seconds"),
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

        def _send_bytes(self, data, content_type="application/octet-stream", filename=None, status=200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            if filename:
                self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
            self._send_no_cache_headers()
            self.end_headers()
            self.wfile.write(data)

        def _send_file(self, path, content_type="application/octet-stream", filename=None):
            target = Path(path)
            size = target.stat().st_size
            with target.open("rb") as handle:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", f"attachment; filename=\"{filename or target.name}\"")
                self._send_no_cache_headers()
                self.end_headers()
                while True:
                    chunk = handle.read(64 * 1024)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except OSError:
                        break

        def _request_theme(self):
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                name, sep, value = part.strip().partition("=")
                if name == "va_watchdog_theme" and sep:
                    value = value.strip()
                    if value in {"dark", "light", "steel", "sand"}:
                        return value
            return "light"

        def do_GET(self):
            request_context.theme = self._request_theme()
            route_path = self.path.split("?", 1)[0]
            request_context.query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "", keep_blank_values=True)
            if route_path in LEGACY_PAGE_REDIRECTS:
                self.send_response(302)
                self.send_header("Location", LEGACY_PAGE_REDIRECTS[route_path])
                self._send_no_cache_headers()
                self.end_headers()
                return
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
            if route_path == "/update-confirm":
                body = update_confirm_html().encode("utf-8")
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
            if route_path == "/journal-enable-confirm":
                body = journal_enable_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-configure":
                body = recording_storage_configure_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path.startswith("/recording-storage-monitor-confirm/"):
                device = unquote(route_path.rsplit("/", 1)[-1])
                body = recording_storage_monitor_confirm_html(device).encode("utf-8")
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
            if route_path == "/neousys-watchdog-install-confirm":
                body = neousys_install_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-prepare-confirm":
                body = hardware_watchdog_prepare_confirm_html().encode("utf-8")
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
            if route_path == "/watchdog-trip-confirm":
                body = watchdog_trip_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-arm-now-confirm":
                body = watchdog_arm_now_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-disable-confirm":
                body = hardware_watchdog_disable_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-legacy-disable-confirm":
                body = legacy_watchdog_disable_confirm_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-enable-confirm":
                body = hardware_watchdog_enable_confirm_html().encode("utf-8")
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
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                try:
                    limit = int(query.get("limit", ["500"])[0])
                except (TypeError, ValueError):
                    limit = 500
                self._send_json(recent_events(limit=limit))
                return
            if route_path == "/api/config-summary":
                self._send_json(config_summary())
                return
            if route_path == "/api/version":
                self._send_json(version_info())
                return
            if route_path == "/api/identity":
                self._send_json(identity_summary(cfg))
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
                rows, _ = filtered_events(request_context.query, limit=5000)
                self._send_json({
                    "identity": configured_identity(cfg),
                    "events": rows,
                })
                return
            if route_path == "/api/events/export.csv":
                rows, _ = filtered_events(request_context.query, limit=5000)
                self._send_text(events_csv(limit=5000, rows=rows), content_type="text/csv")
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
            if route_path == "/api/diagnostics/stage0-baseline":
                self._send_json(baseline_status(cfg))
                return
            if route_path == "/api/diagnostics/stage0-baseline.tar.gz":
                archive = completed_archive(cfg)
                if not archive:
                    self._send_json({"error": "No completed Stage 0 baseline is available."}, status=404)
                    return
                try:
                    self._send_file(archive, content_type="application/gzip")
                except OSError as exc:
                    self._send_json({"error": str(exc)}, status=500)
                return
            if route_path == "/api/blackbox":
                summary = blackbox_summary(cfg)
                self._send_json({"summary": summary, "snapshots": read_blackbox(cfg, limit=summary.get("max_rows", 450))})
                return
            if route_path == "/api/diagnostics/support-bundle.zip":
                try:
                    data, filename = support_bundle_bytes()
                    self._send_bytes(data, content_type="application/zip", filename=filename)
                except Exception as exc:
                    self._send_json({"error": str(exc)}, status=500)
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
            if route_path == "/api/recording-activity":
                self._send_json(recording_activity(cfg))
                return
            if route_path == "/api/recording-storage-candidates":
                self._send_json({"candidates": recording_storage_candidates(cfg)})
                return
            if route_path == "/api/install-status":
                self._send_json(install_status())
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            request_context.theme = self._request_theme()
            route_path = self.path.split("?", 1)[0]
            if route_path == "/stage0-baseline-start":
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode("utf-8") if length else "", keep_blank_values=True)
                if form.get("ack", [""])[0] != "1":
                    result = {"ok": False, "message": "Confirmation was not selected."}
                else:
                    result = start_baseline(cfg, form.get("duration", [""])[0])
                    if result.get("ok"):
                        append_web_event(
                            "info",
                            "diagnostics",
                            "Stage 0 baseline capture started",
                            {"duration_seconds": int(form.get("duration", ["0"])[0])},
                        )
                body = baseline_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/network-speed-test":
                try:
                    result = run_speed_test()
                except Exception as exc:
                    result = {
                        "ok": False,
                        "tested_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "latency_ms": None,
                        "download_mbps": None,
                        "upload_mbps": None,
                        "duration_seconds": 0,
                        "errors": [str(exc)],
                    }
                body = speed_test_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/journal-enable":
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode("utf-8") if length else "", keep_blank_values=True)
                result = enable_persistent() if form.get("ack", [""])[0] == "1" else {"ok": False, "message": "Confirmation was not selected."}
                body = journal_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
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
            if route_path == "/api/events/purge":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
                    payload = json.loads(raw_body)
                    result = purge_events(
                        events_path,
                        before=payload.get("before"),
                        purge_all=payload.get("purge_all") is True,
                    )
                    self._send_json(result)
                except Exception as exc:
                    self._send_json({"ok": False, "error": str(exc)}, status=400)
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
            if route_path == "/recording-storage-confirm":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    device = form.get("device", [""])[0]
                    body = recording_storage_confirm_html(device).encode("utf-8")
                except Exception as exc:
                    body = recording_storage_result_html({"ok": False, "message": str(exc), "output": ""}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-blank-confirm":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    disk = form.get("disk", [""])[0]
                    body = recording_storage_blank_confirm_html(disk).encode("utf-8")
                except Exception as exc:
                    body = recording_storage_result_html({"ok": False, "message": str(exc), "output": ""}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-apply":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    device = form.get("device", [""])[0]
                    confirm_label = form.get("confirm_label", [""])[0]
                    ack = form.get("ack", [""])[0] in {"1", "on", "true", "True", "yes"}
                    result = configure_recording_storage(cfg, device, confirm_label, ack)
                    append_web_event("healthy" if result.get("ok") else "critical", "recording_storage", result.get("message", "Recording storage configure processed"), result)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "output": ""}
                body = recording_storage_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-blank-apply":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    disk = form.get("disk", [""])[0]
                    confirm_device = form.get("confirm_device", [""])[0]
                    confirm_label = form.get("confirm_label", [""])[0]
                    ack = form.get("ack", [""])[0] in {"1", "on", "true", "True", "yes"}
                    result = prepare_blank_recording_disk(cfg, disk, confirm_device, confirm_label, ack)
                    append_web_event("healthy" if result.get("ok") else "critical", "recording_storage", result.get("message", "Blank recording disk prepare processed"), result)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "output": ""}
                body = recording_storage_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-monitor-only":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    device = form.get("device", [""])[0]
                    ack = form.get("ack", [""])[0] in {"1", "on", "true", "True", "yes"}
                    result = monitor_existing_recording_storage(device, ack)
                    append_web_event("healthy" if result.get("ok") else "warning", "recording_storage", result.get("message", "Recording storage monitor-only processed"), result)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "output": ""}
                body = recording_storage_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-system-directory":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    recording_path = form.get("recording_path", [""])[0]
                    ack = form.get("ack", [""])[0] in {"1", "on", "true", "True", "yes"}
                    result = monitor_system_recording_directory(recording_path, ack)
                    append_web_event(
                        "healthy" if result.get("ok") else "warning",
                        "recording_storage",
                        result.get("message", "One-drive recording directory configuration processed"),
                        result,
                    )
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "output": ""}
                body = recording_storage_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/recording-storage-guard-apply":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    ack = form.get("ack", [""])[0] in {"1", "on", "true", "True", "yes"}
                    result = apply_recording_service_mount_guards(cfg, ack)
                    result.setdefault("status", recording_storage_status(cfg))
                    append_web_event("healthy" if result.get("ok") else "warning", "recording_storage", result.get("message", "Recording service mount guard processed"), result)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "output": "", "status": recording_storage_status(cfg)}
                body = recording_storage_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
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
            if route_path == "/neousys-watchdog-install-now":
                result = launch_neousys_install()
                body = neousys_install_started_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-prepare-now":
                result = launch_hardware_watchdog_prepare()
                body = watchdog_action_result_html(result).encode("utf-8")
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
            if route_path == "/watchdog-legacy-disable-now":
                result = disable_legacy_watchdog_daemon()
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-enable-now":
                result = enable_va_hardware_watchdog()
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-grace-delay":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    result = delay_watchdog_arming(form.get("delay_seconds", ["900"])[0])
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "command": "", "output": ""}
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 409)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-arm-now":
                result = arm_hardware_watchdog_now()
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 409)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/hardware-watchdog-disable-now":
                result = disable_hardware_watchdog_during_grace()
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 409)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-grace-config-set":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    result = set_watchdog_grace_periods(
                        form.get("startup_grace_seconds", ["300"])[0],
                        form.get("post_trip_grace_seconds", ["900"])[0],
                    )
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "command": "", "output": ""}
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 400)
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
            if route_path == "/watchdog-trip-run":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    ack_risk = form.get("ack_risk", [""])[0] in {"1", "on", "true", "True", "yes"}
                    info = hardware_info()
                    watchdog = info.get("watchdog", {})
                    setup = watchdog_setup_rows(watchdog, watchdog.get("systemd_watchdog", systemd_watchdog_info()))
                    if not setup.get("trip_ready"):
                        result = {
                            "ok": False,
                            "message": "Trip test blocked: the hardware watchdog is not ready and feeding.",
                            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                            "triggered_boot_id": "",
                        }
                    else:
                        result = trigger_trip_test(cfg, ack_risk)
                except Exception as exc:
                    result = {
                        "ok": False,
                        "message": str(exc),
                        "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        "triggered_boot_id": "",
                    }
                append_web_event(
                    "warning" if result.get("ok") else "critical",
                    "watchdog_test",
                    result.get("message", "Deliberate trip test processed"),
                    result,
                )
                body = watchdog_trip_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 409)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-trip-arm":
                info = hardware_info()
                watchdog = info.get("watchdog", {})
                setup = watchdog_setup_rows(watchdog, watchdog.get("systemd_watchdog", systemd_watchdog_info()))
                if not setup.get("trip_ready"):
                    result = {
                        "ok": False,
                        "message": "Trip test blocked: the service is not currently ready to trip the hardware watchdog. Run one-click setup and reload Watchdog first.",
                        "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        "triggered_boot_id": "",
                    }
                    append_web_event("warning", "watchdog_test", result["message"], setup)
                    body = watchdog_trip_result_html(result).encode("utf-8")
                    self.send_response(409)
                else:
                    result = arm_trip_test(cfg)
                    append_web_event("warning", "watchdog_test", "Deliberate watchdog trip test armed", result)
                    body = watchdog_trip_armed_html(result).encode("utf-8")
                    self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self._send_no_cache_headers()
                self.end_headers()
                self.wfile.write(body)
                return
            if route_path == "/watchdog-trip-now":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    token = form.get("token", [""])[0]
                    ack_risk = form.get("ack_risk", [""])[0] in {"1", "on", "true", "True", "yes"}
                    confirm_phrase = form.get("confirm_phrase", [""])[0]
                    info = hardware_info()
                    watchdog = info.get("watchdog", {})
                    setup = watchdog_setup_rows(watchdog, watchdog.get("systemd_watchdog", systemd_watchdog_info()))
                    if not setup.get("trip_ready"):
                        result = {
                            "ok": False,
                            "message": "Trip test blocked: the service is not currently ready to trip the hardware watchdog. Run one-click setup and reload Watchdog first.",
                            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                            "triggered_boot_id": "",
                        }
                    else:
                        result = confirm_trip_test(cfg, token, ack_risk, confirm_phrase)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "tested_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), "triggered_boot_id": ""}
                append_web_event("warning" if result.get("ok") else "critical", "watchdog_test", result.get("message", "Deliberate trip test processed"), result)
                body = watchdog_trip_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 409)
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
            if route_path == "/watchdog-timeout-set":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length).decode("utf-8") if length else ""
                    form = parse_qs(raw_body, keep_blank_values=True)
                    timeout_seconds = form.get("timeout_seconds", ["30"])[0]
                    result = set_watchdog_timeout(timeout_seconds)
                except Exception as exc:
                    result = {"ok": False, "message": str(exc), "command": "", "output": ""}
                body = watchdog_action_result_html(result).encode("utf-8")
                self.send_response(200 if result.get("ok") else 500)
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
