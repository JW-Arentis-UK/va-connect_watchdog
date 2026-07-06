from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

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

async function load(){
  const r = await fetch('/api/status');
  const s = await r.json();
  let html = renderStartupSummary(s.startup_summary);
  html += `<div class="card"><h2 class="${s.state}">${s.state.toUpperCase()} - ${s.score}%</h2><p>${escapeHtml(s.time)}</p><p>Critical failed: ${escapeHtml(s.critical_failed)}</p></div>`;
  for (const c of s.checks) {
    html += `<div class="card"><h3 class="${c.state}">${escapeHtml(c.name)}: ${escapeHtml(c.state)}</h3><p>${escapeHtml(c.message)}</p><pre>${escapeHtml(JSON.stringify(c.value, null, 2))}</pre></div>`;
  }
  document.getElementById('app').innerHTML = html;
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
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                except Exception as e:
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer((web_cfg["host"], int(web_cfg["port"])), Handler)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
