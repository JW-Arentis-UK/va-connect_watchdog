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
<title>VA-Connect Watchdog V3</title>
<style>
body { font-family: Arial, sans-serif; background:#111; color:#eee; margin:20px; }
.card { background:#1d1d1d; padding:14px; margin:10px 0; border-radius:8px; }
.healthy { color:#66d17a; }
.warning { color:#ffd166; }
.degraded { color:#ff9f1c; }
.critical { color:#ef476f; }
.unknown { color:#aaa; }
pre { white-space: pre-wrap; }
.button-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin: 10px 0; }
button { background:#2f6fed; color:#fff; border:0; border-radius:6px; padding:10px 14px; cursor:pointer; font-weight:700; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
</head>
<body>
<h1>VA-Connect Watchdog V3</h1>
<div id="app">Loading...</div>
<script>
function escapeHtml(value){
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderStartupSummary(summary){
  if (!summary) return '';
  const details = Array.isArray(summary.details) ? summary.details : [];
  const services = Array.isArray(summary.service_states) ? summary.service_states : [];
  let html = `<div class="card"><h2>Startup summary</h2><p class="${summary.critical_checks && summary.critical_checks.length ? 'critical' : (summary.warning_checks && summary.warning_checks.length ? 'warning' : 'healthy')}">${escapeHtml(summary.headline || 'Startup summary')}</p>`;
  if (details.length) {
    html += `<ul>`;
    for (const item of details) {
      html += `<li>${escapeHtml(item)}</li>`;
    }
    html += `</ul>`;
  }
  if (services.length) {
    html += `<h3>Service state</h3>`;
    for (const svc of services) {
      html += `<p><strong>${escapeHtml(svc.name)}</strong> - ${escapeHtml(svc.state)}: ${escapeHtml(svc.message || '')}</p>`;
    }
  }
  html += `</div>`;
  return html;
}

function renderUpdateCard(updateStatus){
  if (!updateStatus) return '';
  const state = updateStatus.state || 'unknown';
  const message = updateStatus.message || 'No update status available.';
  const branch = updateStatus.branch || '';
  const commit = updateStatus.commit || '';
  const updatedAt = updateStatus.updated_at || '';
  return `<div class="card"><h2>Watchdog update</h2><p class="${state}">${escapeHtml(state.toUpperCase())}</p><p>${escapeHtml(message)}</p><p>Branch: ${escapeHtml(branch || '-')}</p><p>Commit: ${escapeHtml(commit || '-')}</p><p>Updated: ${escapeHtml(updatedAt || '-')}</p><div class="button-row"><button id="update-button" onclick="triggerUpdate()">Update watchdog now</button></div><p id="update-feedback"></p></div>`;
}

function renderRecoveryCard(recovery){
  if (!recovery) return '';
  const state = recovery.state || 'unknown';
  const actions = Array.isArray(recovery.actions) ? recovery.actions : [];
  const details = recovery.details || {};
  let html = `<div class="card"><h2>Recovery</h2><p class="${state}">${escapeHtml(state.toUpperCase())}</p><p>${escapeHtml(recovery.message || '')}</p>`;
  if (actions.length) {
    html += `<h3>Actions</h3><ul>`;
    for (const action of actions) {
      html += `<li>${escapeHtml(action)}</li>`;
    }
    html += `</ul>`;
  }
  if (details && Object.keys(details).length) {
    html += `<pre>${escapeHtml(JSON.stringify(details, null, 2))}</pre>`;
  }
  html += `</div>`;
  return html;
}

async function load(){
  const [statusResponse, updateResponse] = await Promise.all([
    fetch('/api/status'),
    fetch('/api/update-status'),
  ]);
  const s = await statusResponse.json();
  const updateStatus = await updateResponse.json();
  let html = renderUpdateCard(updateStatus);
  html += renderRecoveryCard(s.recovery);
  html += renderStartupSummary(s.startup_summary);
  html += `<div class="card"><h2 class="${s.state}">${s.state.toUpperCase()} - ${s.score}%</h2><p>${escapeHtml(s.time)}</p><p>Critical failed: ${escapeHtml(s.critical_failed)}</p></div>`;
  for (const c of s.checks) {
    html += `<div class="card"><h3 class="${c.state}">${escapeHtml(c.name)}: ${escapeHtml(c.state)}</h3><p>${escapeHtml(c.message)}</p><pre>${escapeHtml(JSON.stringify(c.value, null, 2))}</pre></div>`;
  }
  document.getElementById('app').innerHTML = html;
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
load(); setInterval(load, 5000);
</script>
</body>
</html>
"""

def start_web(cfg):
    web_cfg = cfg["web"]
    if not web_cfg.get("enabled", True):
        return None

    status_path = Path(cfg["status_path"])

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
