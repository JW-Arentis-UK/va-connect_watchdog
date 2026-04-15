async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Request failed: ${url}`);
  }
  return response.json();
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = value;
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeStatus(value) {
  const status = String(value || "unknown").toLowerCase();
  if (status === "healthy" || status === "degraded" || status === "faulted" || status === "unknown") {
    return status;
  }
  return "unknown";
}

function formatMetricValue(value, suffix = "") {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (Number.isNaN(number)) {
    return `${escapeHtml(String(value))}${suffix}`;
  }
  return `${number.toFixed(1)}${suffix}`;
}

function formatLoad(sample) {
  const values = [sample?.load_1, sample?.load_5, sample?.load_15];
  if (!values.some((value) => value !== null && value !== undefined && value !== "")) {
    return "-";
  }
  return values
    .map((value) => {
      if (value === null || value === undefined || value === "") {
        return "-";
      }
      const number = Number(value);
      return Number.isNaN(number) ? String(value) : number.toFixed(2);
    })
    .join(" / ");
}

function formatTimestamp(value) {
  return value ? String(value) : "-";
}

function metricCards(sample) {
  return [
    {
      label: "CPU",
      value: formatMetricValue(sample?.cpu_percent, "%"),
      note: formatTimestamp(sample?.timestamp),
    },
    {
      label: "Memory",
      value: formatMetricValue(sample?.memory_percent, "%"),
      note: formatTimestamp(sample?.timestamp),
    },
    {
      label: "Disk",
      value: formatMetricValue(sample?.disk_percent, "%"),
      note: formatTimestamp(sample?.timestamp),
    },
    {
      label: "Temperature",
      value: formatMetricValue(sample?.temperature_c, "°C"),
      note: formatTimestamp(sample?.timestamp),
    },
    {
      label: "Load",
      value: formatLoad(sample),
      note: formatTimestamp(sample?.timestamp),
    },
  ];
}

function renderMetricGrid(containerId, sample) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }

  if (!sample) {
    container.innerHTML = '<div class="metric-card">No data available.</div>';
    return;
  }

  container.innerHTML = metricCards(sample)
    .map(
      (card) => `
        <div class="metric-card">
          <div class="metric-label">${escapeHtml(card.label)}</div>
          <div class="metric-value">${escapeHtml(card.value)}</div>
          <div class="metric-sub">${escapeHtml(card.note)}</div>
        </div>
      `,
    )
    .join("");
}

function renderSummary(deviceStatus) {
  setText("device-id", deviceStatus?.device_id || "Unknown device");
  setText("last-seen", `last seen: ${deviceStatus?.last_seen || "-"}`);

  const statusNode = document.getElementById("overall-status");
  if (statusNode) {
    const status = normalizeStatus(deviceStatus?.overall_status);
    statusNode.textContent = status;
    statusNode.className = `status status-${status}`;
  }
}

function renderBuildInfo(buildInfo) {
  const value = buildInfo || {};
  const buildNumber = value.build_number || "local-dev";
  const commitSha = value.commit_sha || "unknown";
  const builtAt = value.built_at || "";
  const branch = value.source_branch || "master";
  setText("build-info", `build: ${buildNumber} • ${commitSha}${builtAt ? ` • ${builtAt}` : ""} • ${branch}`);
}

function renderIncident(incident, keyEvents) {
  const container = document.getElementById("incident");
  if (!container) {
    return;
  }

  if (!incident) {
    container.innerHTML = '<div class="muted">No incident recorded yet.</div>';
    return;
  }

  const items = Array.isArray(keyEvents) ? keyEvents.filter(Boolean) : [];
  const keyEventsHtml = items.length
    ? `<ul class="key-list">${items.map((item) => `<li class="key-item">${escapeHtml(String(item))}</li>`).join("")}</ul>`
    : '<div class="muted">No key events available.</div>';

  container.innerHTML = `
    <div class="incident-row">
      <div class="incident-top">
        <div class="incident-label">${escapeHtml(String(incident.type || "-"))}</div>
        <div class="muted">${escapeHtml(String(incident.severity || "-"))}</div>
      </div>
      <div class="small">${escapeHtml(formatTimestamp(incident.timestamp))}</div>
      <div class="small">${escapeHtml(String(incident.status || "-"))}</div>
      <div class="small">${escapeHtml(String(incident.cause || "-"))}</div>
      <div class="section-title" style="margin-top: 14px; margin-bottom: 8px;">Key Events</div>
      ${keyEventsHtml}
    </div>
  `;
}

function renderActivityGraph(samples) {
  const container = document.getElementById("activity-graph");
  if (!container) {
    return;
  }

  const points = Array.isArray(samples) ? samples.slice(-48) : [];
  if (!points.length) {
    container.innerHTML = '<div class="muted">No activity data available.</div>';
    return;
  }

  const rows = [
    { key: "cpu_percent", label: "CPU", cls: "cpu" },
    { key: "memory_percent", label: "Memory", cls: "memory" },
    { key: "disk_percent", label: "Disk", cls: "disk" },
    { key: "temperature_c", label: "Temp", cls: "temperature" },
  ];

  container.innerHTML = rows
    .map((row) => {
      const values = points.map((point) => {
        const number = Number(point?.[row.key]);
        return Number.isNaN(number) ? 0 : number;
      });
      const maxValue = Math.max(1, ...values);
      const bars = values
        .map((value) => {
          const height = Math.max(4, Math.round((value / maxValue) * 42));
          return `<div class="activity-bar ${row.cls}" style="height:${height}px"></div>`;
        })
        .join("");
      const latest = points[points.length - 1] || {};
      const latestValue =
        row.key === "temperature_c"
          ? formatMetricValue(latest[row.key], "°C")
          : formatMetricValue(latest[row.key], "%");
      return `
        <div class="activity-row">
          <div class="activity-label">${escapeHtml(row.label)}</div>
          <div class="activity-bars">${bars}</div>
          <div class="activity-value">${escapeHtml(latestValue)}</div>
        </div>
      `;
    })
    .join("");
}

function renderTimeline(events) {
  const container = document.getElementById("timeline");
  if (!container) {
    return;
  }

  const rows = Array.isArray(events) ? events.slice(-50) : [];
  if (!rows.length) {
    container.innerHTML = '<div class="muted">No event timeline available.</div>';
    return;
  }

  container.innerHTML = rows
    .map((event) => {
      const level = String(event?.level || "info").toLowerCase();
      const levelClass = level === "error" ? "timeline-level-error" : level === "warning" ? "timeline-level-warning" : "";
      return `
        <div class="timeline-item ${levelClass}">
          <div class="timeline-meta">
            <span>${escapeHtml(formatTimestamp(event?.timestamp))}</span>
            <span>${escapeHtml(level)}</span>
          </div>
          <div>${escapeHtml(String(event?.message || "-"))}</div>
        </div>
      `;
    })
    .join("");
}

async function loadDashboard() {
  const data = await fetchJson("/debug/last-incident");
  console.log("API DATA:", data);

  const deviceStatus = data?.device_status || {};
  renderSummary(deviceStatus);
  renderBuildInfo(data?.build_info || {});
  renderMetricGrid("live-state", data?.system_state || null);
  renderIncident(data?.incident || null, data?.key_events || []);
  renderMetricGrid("snapshot-state", data?.pre_crash_snapshot || null);
  renderActivityGraph(data?.system_activity_24h || []);
  renderTimeline(data?.event_timeline || data?.pre_crash_timeline || []);
}

loadDashboard().catch((error) => {
  setText("device-id", "Unable to load dashboard");
  setText("last-seen", String(error.message || error));
  setText("build-info", "build: unavailable");

  const ids = ["live-state", "snapshot-state", "incident", "activity-graph", "timeline"];
  for (const id of ids) {
    const node = document.getElementById(id);
    if (node) {
      node.innerHTML = '<div class="muted">Dashboard data unavailable.</div>';
    }
  }
});
