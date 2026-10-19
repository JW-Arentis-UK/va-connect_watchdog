async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Request failed: ${url}`);
  }
  return response.json();
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const node = byId(id);
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
  if (["healthy", "warning", "degraded", "faulted", "critical", "unknown", "error"].includes(status)) {
    return status;
  }
  return "unknown";
}

function statusClass(status) {
  const normalized = normalizeStatus(status);
  if (normalized === "healthy") {
    return "pill-healthy";
  }
  if (normalized === "warning" || normalized === "degraded") {
    return "pill-degraded";
  }
  if (normalized === "faulted" || normalized === "critical" || normalized === "error") {
    return "pill-faulted";
  }
  return "pill-unknown";
}

function describeValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "boolean") {
    return value ? "yes" : "no";
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(1);
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function formatTimestamp(value) {
  return value ? String(value) : "-";
}

function compactObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  const entries = Object.entries(value)
    .filter(([, entryValue]) => entryValue !== null && entryValue !== undefined && entryValue !== "")
    .slice(0, 4)
    .map(([key, entryValue]) => `${key}: ${describeValue(entryValue)}`);
  return entries.join(" | ");
}

function scoreText(deviceStatus) {
  const score = deviceStatus?.score;
  return score === null || score === undefined ? "-" : `${score}`;
}

function formatBuildLabel(buildInfo) {
  const buildNumber = String(buildInfo?.build_number || buildInfo?.git_commit || buildInfo?.commit_sha || "local-dev").trim();
  const commitSha = String(buildInfo?.commit_sha || buildInfo?.git_commit || "unknown").trim();
  const builtAt = String(buildInfo?.built_at || buildInfo?.deployed_at || "").trim();
  const pieces = [`Build ${buildNumber}`];
  if (commitSha && commitSha !== buildNumber) {
    pieces.push(commitSha);
  }
  if (builtAt) {
    pieces.push(builtAt.slice(0, 10));
  }
  return pieces.join(" | ");
}

function recommendationFor(deviceStatus) {
  const state = normalizeStatus(deviceStatus?.state || deviceStatus?.overall_status);
  const checks = Array.isArray(deviceStatus?.checks) ? deviceStatus.checks : [];
  const warnings = checks.filter((check) => normalizeStatus(check?.state) !== "healthy");
  const storage = deviceStatus?.recording_storage || {};
  const watchdog = deviceStatus?.hardware_watchdog_feed || {};

  if (state === "faulted" || state === "critical" || deviceStatus?.critical_failed) {
    return {
      title: "Investigate the fault before changing settings",
      body:
        "Open Diagnostics, confirm the last incident, and check the affected service or storage path first. That keeps recovery work focused and avoids masking the root cause.",
    };
  }

  const storageUsed = Number(storage?.used_percent);
  if (normalizeStatus(storage?.status) !== "healthy" || storageUsed >= 90) {
    return {
      title: "Watch recording storage first",
      body:
        "Storage is the clearest operational risk on this page. Verify free space, mounting, and write access before leaving the site or relying on the system overnight.",
    };
  }

  if (normalizeStatus(watchdog?.enabled ? "healthy" : "warning") !== "healthy" || !watchdog?.opened) {
    return {
      title: "Confirm hardware watchdog feed state",
      body:
        "The hardware watchdog device may be present without active feeding. Confirm whether V3 is actually opening and feeding /dev/watchdog0 before treating it as protected.",
    };
  }

  if (warnings.length) {
    const first = warnings[0];
    return {
      title: "Review the warning checks",
      body: `${first?.name || "A check"} is the first item to inspect. The rest of the page is intentionally compact, so follow the warning labels rather than scanning every metric.`,
    };
  }

  return {
    title: "No immediate action needed",
    body:
      "The page looks steady. Keep the main view as a quick read, and use Diagnostics only when you need raw logs or deeper investigation.",
  };
}

function renderSummary(deviceStatus, buildInfo) {
  const overall = normalizeStatus(deviceStatus?.state || deviceStatus?.overall_status);
  const headline = deviceStatus?.startup_summary?.headline || "System status available";
  const lastSeen = deviceStatus?.time || deviceStatus?.last_seen || buildInfo?.built_at || "-";

  setText("device-id", deviceStatus?.device_id || "VA-Connect Watchdog");
  setText("headline", headline);
  setText("score", `Score ${scoreText(deviceStatus)}`);
  setText("updated", `Updated ${formatTimestamp(lastSeen)}`);
  setText("build-info", formatBuildLabel(buildInfo));

  const statusNode = byId("overall-status");
  if (statusNode) {
    statusNode.textContent = overall;
    statusNode.className = `pill ${statusClass(overall)}`;
  }
}

function renderRecommendation(deviceStatus) {
  const recommendation = recommendationFor(deviceStatus);
  setText("recommendation-title", recommendation.title);
  setText("recommendation-body", recommendation.body);
}

function renderStat(idValue, idNote, value, note) {
  setText(idValue, value);
  setText(idNote, note);
}

function renderStats(deviceStatus) {
  const overall = normalizeStatus(deviceStatus?.state || deviceStatus?.overall_status);
  const recovery = deviceStatus?.recovery || {};
  const storage = deviceStatus?.recording_storage || {};
  const watchdog = deviceStatus?.hardware_watchdog_feed || {};

  renderStat(
    "stat-overall",
    "stat-overall-note",
    overall,
    deviceStatus?.startup_summary?.headline || "Current summary state",
  );
  renderStat(
    "stat-recovery",
    "stat-recovery-note",
    recovery?.state || "unknown",
    recovery?.message || "Recovery engine status",
  );
  renderStat(
    "stat-storage",
    "stat-storage-note",
    normalizeStatus(storage?.status || storage?.state),
    storage?.mounted === false
      ? "Not mounted"
      : compactObject({
          mountpoint: storage?.mountpoint,
          used_percent: storage?.used_percent !== null && storage?.used_percent !== undefined ? `${storage.used_percent}% used` : null,
          free_gb: storage?.free_gb !== undefined ? `${storage.free_gb} GB free` : null,
        }) || "Recording storage status",
  );

  const wdtLabel = watchdog?.enabled ? "feeding" : watchdog?.opened ? "open" : "not feeding";
  renderStat(
    "stat-watchdog",
    "stat-watchdog-note",
    wdtLabel,
    compactObject({
      device: watchdog?.device,
      feeds: watchdog?.feed_count,
      timeout: watchdog?.timeout_seconds ? `${watchdog.timeout_seconds}s` : null,
    }) || "Feed state for /dev/watchdog0",
  );
}

function renderChecks(deviceStatus) {
  const container = byId("checks");
  if (!container) {
    return;
  }

  const checks = Array.isArray(deviceStatus?.checks) ? deviceStatus.checks.slice() : [];
  if (!checks.length) {
    container.innerHTML = '<div class="empty">No checks available.</div>';
    return;
  }

  const priority = (check) => {
    const state = normalizeStatus(check?.state);
    if (state === "faulted" || state === "critical" || state === "error") {
      return 0;
    }
    if (state === "warning" || state === "degraded") {
      return 1;
    }
    return 2;
  };

  const rows = checks
    .sort((left, right) => priority(left) - priority(right))
    .slice(0, 8)
    .map((check) => {
      const state = normalizeStatus(check?.state);
      const detail = describeValue(check?.value);
      return `
        <article class="check-item">
          <div class="check-top">
            <div class="check-name">${escapeHtml(String(check?.name || "check"))}</div>
            <div class="check-state state-${escapeHtml(state)}">${escapeHtml(state)}</div>
          </div>
          <div class="check-message">${escapeHtml(String(check?.message || "-"))}</div>
          <div class="check-meta">${escapeHtml(check?.critical ? "critical" : "optional")}</div>
          <div class="check-value">${escapeHtml(detail)}</div>
        </article>
      `;
    })
    .join("");

  container.innerHTML = rows;
}

function renderIncident(incident, keyEvents) {
  const container = byId("incident");
  if (!container) {
    return;
  }

  if (!incident) {
    container.innerHTML = '<div class="empty">No incident recorded yet.</div>';
    return;
  }

  const events = Array.isArray(keyEvents) ? keyEvents.filter(Boolean) : [];
  const eventsHtml = events.length
    ? `<div class="incident-body"><strong>Key events:</strong> ${escapeHtml(events.join(" | "))}</div>`
    : '<div class="incident-body">No key events available.</div>';

  container.innerHTML = `
    <article class="incident-row">
      <div class="incident-top">
        <div class="incident-label">${escapeHtml(String(incident?.type || "Incident"))}</div>
        <div class="incident-meta">${escapeHtml(String(incident?.severity || "-"))}</div>
      </div>
      <div class="incident-meta">${escapeHtml(formatTimestamp(incident?.timestamp))}</div>
      <div class="incident-body">${escapeHtml(String(incident?.cause || "No cause recorded."))}</div>
      ${eventsHtml}
    </article>
  `;
}

function renderTimeline(events) {
  const container = byId("timeline");
  if (!container) {
    return;
  }

  const rows = Array.isArray(events) ? events.slice(-8) : [];
  if (!rows.length) {
    container.innerHTML = '<div class="empty">No recent activity available.</div>';
    return;
  }

  container.innerHTML = rows
    .map((event) => {
      const level = normalizeStatus(event?.level);
      return `
        <article class="timeline-item">
          <div class="timeline-meta">
            <span>${escapeHtml(formatTimestamp(event?.timestamp))}</span>
            <span class="timeline-level state-${escapeHtml(level)}">${escapeHtml(level)}</span>
          </div>
          <div class="timeline-body">${escapeHtml(String(event?.message || "-"))}</div>
        </article>
      `;
    })
    .join("");
}

async function loadPage() {
  const data = await fetchJson("/debug/last-incident");
  const deviceStatus = data?.device_status || {};
  const buildInfo = data?.build_info || {};

  renderSummary(deviceStatus, buildInfo);
  renderRecommendation(deviceStatus);
  renderStats(deviceStatus);
  renderChecks(deviceStatus);
  renderIncident(data?.incident || null, data?.key_events || []);
  renderTimeline(data?.event_timeline || data?.pre_crash_timeline || []);
}

loadPage().catch((error) => {
  setText("device-id", "Unable to load lightweight dashboard");
  setText("headline", String(error.message || error));
  setText("score", "Score -");
  setText("updated", "Updated -");
  setText("build-info", "Build unavailable");

  const targets = ["recommendation", "checks", "incident", "timeline"];
  for (const id of targets) {
    const node = byId(id);
    if (node) {
      node.innerHTML = '<div class="empty">Dashboard data unavailable.</div>';
    }
  }
});
