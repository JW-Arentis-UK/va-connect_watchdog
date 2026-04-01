
    const initialStatus = {"config": {"monitoring_enabled": true, "app_restart_enabled": true, "restart_network_before_reboot": false, "reboot_enabled": false, "web_bind": "0.0.0.0", "web_port": 80, "web_token": "", "base_reboot_timeout_seconds": 300, "max_reboot_timeout_seconds": 3600, "internet_hosts": [], "tcp_targets": [], "systemd_services": [], "teamviewer_id_command": "teamviewer info", "teamviewer_password_reset_command": "teamviewer passwd {password}", "teamviewer_start_command": "systemctl start teamviewerd", "teamviewer_restart_command": "systemctl restart teamviewerd", "hik_enabled": false, "hik_scheme": "http", "hik_host": "", "hik_username": "", "hik_password": "", "hik_channel": 1, "hik_people_count_result_path": "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/result", "hik_people_count_capabilities_path": "/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities"}, "hostname": "TEST", "hardware_identity": {"serial": "TEST"}, "update_status": {"state": "idle", "message": "No web update run yet.", "from_build": "a", "to_build": "a", "finished_at": ""}, "update_console_lines": [], "diagnosis": {"title": "Healthy", "detail": "All good"}, "state": {"fault_active": false, "last_startup_at": "", "last_metrics": {}}, "reboot_counts": {"unexpected": 0, "detected": 0, "watchdog": 0}, "next_steps": [], "build_info": {"git_commit": "x"}, "required_tools": {"missing_required": [], "missing_important": [], "items": [], "install_status": {"state": "idle"}}, "recent_events": [], "timeline": [], "crash_review": {"title": "", "detail": "", "snapshot_path": "", "findings": [], "system_lines": [], "system_lines_all": [], "kernel_lines": [], "kernel_lines_all": []}, "suspect_scores": [], "hardware_review": {"checked_at": "", "findings": [], "warnings": [], "smart": [], "pstore_entries": []}, "fault_reporting": {"summary": "", "impact": "", "top_suspect": {"label": "", "score": 0}, "quick_actions": [], "stability_clues": []}, "clue_counters": [], "linux_stability": {"previous_boot_counts": {}, "current_warning_counts": {}, "strongest_previous_line": "", "strongest_current_line": "", "interpretation": [], "alert_rules": []}, "teamviewer": {"installed": false, "daemon_running": false, "gui_running": false, "summary": "", "id": "", "version": "", "status_text": "", "reset_supported": false}, "speedtest_status": {"state": "idle"}, "speedtest_history": [], "reboot_leadup": {"detail": "", "reference_at": "", "last_metrics": {}, "events": []}, "hik_status": {"state": "idle", "message": "", "checked_at": "", "parsed_counts": {}, "capabilities_excerpt": "", "result_excerpt": ""}, "memtest_status": {"state": "idle", "message": "", "finished_at": ""}, "memtest_info": {"installed": false, "available_mb": 0, "recommended_label": "1024M", "recommended_loops": 2, "recommended_mb": 1024}, "export_status": {"state": "idle", "message": "", "button_label": "Export incident pack"}, "export_console_lines": [], "paths": {"state": "", "events": "", "metrics": "", "build_info": "", "update_status": "", "update_log": "", "export_status": "", "export_log": "", "memtest_status": "", "memtest_log": "", "speedtest_status": "", "speedtest_log": ""}, "checks": {}, "latest_checks": {}, "hardware_health": {}, "targets": []};
    const authQuery = window.location.search || '';
    let latestMetrics = [];
    let latestMetricEvents = [];
    let metricsRangeHours = 24;

    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach((btn) => {
        btn.classList.toggle('active', btn.dataset.tab === name);
      });
      document.querySelectorAll('.tab-panel').forEach((panel) => {
        panel.classList.toggle('active', panel.dataset.tabPanel === name);
      });
    }

    function hardRefreshPage() {
      const url = new URL(window.location.href);
      url.searchParams.set('_refresh', String(Date.now()));
      window.location.replace(url.toString());
    }

    function buildAuthedUrl(path, extraParams = {}) {
      const url = new URL(path, window.location.origin);
      const currentParams = new URLSearchParams(window.location.search || '');
      currentParams.forEach((value, key) => {
        if (key !== '_refresh') {
          url.searchParams.set(key, value);
        }
      });
      Object.entries(extraParams || {}).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.set(key, String(value));
        }
      });
      return `${url.pathname}${url.search}`;
    }

    function badge(ok) {
      return ok ? 'badge' : 'badge danger';
    }

    function metricRangeLabel(hours) {
      if (hours === 1) {
        return 'PC Stats - Last Hour';
      }
      if (hours === 168) {
        return 'PC Stats - Last 7 Days';
      }
      return 'PC Stats - Last 24 Hours';
    }

    function formatLocalTimestamp(ts) {
      if (!ts) {
        return 'unknown';
      }
      const date = new Date(ts);
      if (Number.isNaN(date.getTime())) {
        return ts;
      }
      return date.toLocaleString([], {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    }

    function formatLocalDateTimeInput(ts) {
      if (!ts) {
        return '';
      }
      const date = new Date(ts);
      if (Number.isNaN(date.getTime())) {
        return '';
      }
      const pad = (value) => String(value).padStart(2, '0');
      return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
    }

    function isEditingAny(ids) {
      const active = document.activeElement;
      return !!active && ids.includes(active.id);
    }

    function movePanel(panelId, targetId) {
      const panel = document.getElementById(panelId);
      const target = document.getElementById(targetId);
      if (panel && target && panel.parentElement !== target) {
        target.appendChild(panel);
      }
    }

    function organizeLayout() {
      movePanel('faultSummaryPanel', 'investigationIntroPanels');
      movePanel('linuxCluesPanel', 'investigationIntroPanels');
      movePanel('leadupPanel', 'investigationActionPanels');
      movePanel('controlsPanel', 'investigationActionPanels');
      movePanel('teamviewerPanel', 'remotePanels');
      const overviewOpsGrid = document.getElementById('overviewOpsGrid');
      if (overviewOpsGrid) {
        overviewOpsGrid.style.gridTemplateColumns = '1fr';
      }
    }

    function render(status) {
      organizeLayout();
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
      document.getElementById('web_port').value = status.config.web_port || 80;
      document.getElementById('web_token').value = status.config.web_token || '';
      document.getElementById('network_restart_command').value = status.config.network_restart_command || '';
      document.getElementById('teamviewer_id_command').value = status.config.teamviewer_id_command || 'teamviewer info';
      document.getElementById('teamviewer_password_reset_command').value = status.config.teamviewer_password_reset_command || 'teamviewer passwd {password}';
      document.getElementById('teamviewer_start_command').value = status.config.teamviewer_start_command || 'systemctl start teamviewerd';
      document.getElementById('teamviewer_restart_command').value = status.config.teamviewer_restart_command || 'systemctl restart teamviewerd';
      const hikFieldIds = ['hik_enabled', 'hik_scheme', 'hik_host', 'hik_username', 'hik_password', 'hik_channel', 'hik_people_count_result_path', 'hik_people_count_capabilities_path'];
      if (!isEditingAny(hikFieldIds)) {
        document.getElementById('hik_enabled').checked = !!status.config.hik_enabled;
        document.getElementById('hik_scheme').value = status.config.hik_scheme || 'http';
        document.getElementById('hik_host').value = status.config.hik_host || '';
        document.getElementById('hik_username').value = status.config.hik_username || '';
        document.getElementById('hik_password').value = status.config.hik_password || '';
        document.getElementById('hik_channel').value = status.config.hik_channel || 1;
        document.getElementById('hik_people_count_result_path').value = status.config.hik_people_count_result_path || '/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/result';
        document.getElementById('hik_people_count_capabilities_path').value = status.config.hik_people_count_capabilities_path || '/ISAPI/Intelligent/channels/{channel}/framesPeopleCounting/capabilities';
      }
      if (!document.getElementById('export_since').value) {
        const startup = status.state.last_startup_at || '';
        if (startup) {
          const startupDate = new Date(startup);
          const sinceDate = new Date(startupDate.getTime() - (30 * 60000));
          document.getElementById('export_since').value = formatLocalDateTimeInput(sinceDate.toISOString());
          document.getElementById('export_until').value = formatLocalDateTimeInput(startupDate.toISOString());
        }
      }
      document.getElementById('internet_hosts').value = (status.config.internet_hosts || []).join('\n');
      document.getElementById('systemd_services').value = (status.config.systemd_services || []).join('\n');
      document.getElementById('tcp_targets').value = (status.config.tcp_targets || []).map((item) => `${item.host}:${item.port}`).join('\n');
      const checks = status.state.last_checks || { pings: [], ports: [], app_ok: null };
      const pingCount = checks.pings || [];
      const serviceCount = checks.services || [];
      const tcpCount = checks.ports || [];
      const pingOk = pingCount.filter((item) => item.ok).length;
      const serviceOk = serviceCount.filter((item) => item.ok).length;
      const tcpOk = tcpCount.filter((item) => item.ok).length;
      const detailBlock = (items, formatter) => items.length
        ? `<div class="check-list">${items.map(formatter).join('')}</div>`
        : `<div class="timeline-empty">No checks configured in this section.</div>`;
      document.getElementById('targets').innerHTML = `
        <div class="item"><strong>App process</strong><br><span class="${badge(!!checks.app_ok)}">${checks.app_ok ? 'Running' : 'Missing'}</span></div>
        <details class="check-group" ${pingOk !== pingCount.length ? 'open' : ''}>
          <summary>WAN pings: ${pingOk}/${pingCount.length} reachable</summary>
          ${detailBlock(pingCount, (item) => `<div class="item"><strong>${item.host}</strong><br><span class="${badge(!!item.ok)}">${item.ok ? 'Reachable' : 'Failed'}</span><br><code>${item.detail || ''}</code></div>`)}
        </details>
        <details class="check-group" ${serviceOk !== serviceCount.length ? 'open' : ''}>
          <summary>Services: ${serviceOk}/${serviceCount.length} active</summary>
          ${detailBlock(serviceCount, (item) => `<div class="item"><strong>${item.service}</strong><br><span class="${badge(!!item.ok)}">${item.ok ? 'Active' : 'Not active'}</span><br><code>${item.detail || ''}</code></div>`)}
        </details>
        <details class="check-group" ${tcpOk !== tcpCount.length ? 'open' : ''}>
          <summary>TCP targets: ${tcpOk}/${tcpCount.length} reachable</summary>
          ${detailBlock(tcpCount, (item) => `<div class="item"><strong>${item.host}:${item.port}</strong><br><span class="${badge(!!item.ok)}">${item.ok ? 'Reachable' : 'Failed'}</span><br><code>${item.detail || ''}</code></div>`)}
        </details>
      `;

      document.getElementById('events').innerHTML = (status.recent_events || []).map((event) => {
        const summary = event.summary || { title: (event.event || 'event'), detail: '', severity: 'info', ts: event.ts || '' };
        const raw = JSON.stringify(event, null, 2);
        return `<div class="item"><strong>${summary.title}</strong><br><span class="hint">${formatLocalTimestamp(summary.ts || '')}</span><br>${summary.detail || ''}<details><summary>Raw event</summary><code>${raw}</code></details></div>`;
      }).join('');
      document.getElementById('nextSteps').innerHTML = (status.next_steps || []).map((step) => `<li>${step}</li>`).join('');
      document.getElementById('timeline').innerHTML = (status.timeline || []).map((item) => (
        `<div class="timeline-card ${item.severity || ''}"><div class="timeline-time">${formatLocalTimestamp(item.ts || '')}</div><div class="timeline-title">${item.title || ''}</div><div>${item.detail || ''}</div></div>`
      )).join('') || '<div class="timeline-empty">No incident timeline entries yet.</div>';
      const crashReview = status.crash_review || {};
      document.getElementById('crashReviewTitle').textContent = crashReview.title || 'Crash review unavailable';
      document.getElementById('crashReviewDetail').textContent = crashReview.detail || '';
      document.getElementById('crashReviewPath').textContent = crashReview.snapshot_path || '';
      const hardwareReview = status.hardware_review || {};
      document.getElementById('suspectScores').innerHTML = (status.suspect_scores || []).map((item) => (
        `<div class="suspect-card"><div class="stat-label">${item.label || 'Cause'}</div><div class="suspect-score">${item.score || 0}</div><ul class="review-list">${(item.reasons || []).map((reason) => `<li>${reason}</li>`).join('')}</ul></div>`
      )).join('');
      document.getElementById('hardwareCheckedAt').textContent = formatLocalTimestamp(hardwareReview.checked_at || '');
      document.getElementById('hardwareFindings').innerHTML = (hardwareReview.findings || []).length
        ? (hardwareReview.findings || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No hardware findings yet.</li>';
      document.getElementById('hardwareWarnings').innerHTML = (hardwareReview.warnings || []).length
        ? (hardwareReview.warnings || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No hardware-warning lines surfaced yet.</li>';
      document.getElementById('hardwareSmart').innerHTML = (hardwareReview.smart || []).length
        ? (hardwareReview.smart || []).map((item) => `<div><strong>${item.device || 'disk'}</strong><br><code>${item.summary || ''}</code></div>`).join('')
        : '<div><code>No SMART summary yet.</code></div>';
      document.getElementById('hardwarePstore').innerHTML = (hardwareReview.pstore_entries || []).length
        ? (hardwareReview.pstore_entries || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No pstore entries present.</li>';
      const hardwareIdentity = status.hardware_identity || {};
      document.getElementById('hardwareIdentitySummary').innerHTML = `
        <li><strong>Vendor:</strong> ${hardwareIdentity.vendor || 'unknown'}</li>
        <li><strong>Model:</strong> ${hardwareIdentity.model || 'unknown'}</li>
        <li><strong>Serial:</strong> ${hardwareIdentity.serial || 'unknown'}</li>
        <li><strong>Board:</strong> ${hardwareIdentity.board_name || 'unknown'}</li>
        <li><strong>BIOS:</strong> ${(hardwareIdentity.bios_vendor || 'unknown')} ${(hardwareIdentity.bios_version || 'unknown')}</li>
        <li><strong>BIOS date:</strong> ${hardwareIdentity.bios_date || 'unknown'}</li>
      `;
      const currentMetrics = status.state.last_metrics || {};
      const formatMetricNumber = (value, digits = 1) => {
        if (value === null || value === undefined || Number.isNaN(Number(value))) {
          return 'unknown';
        }
        return Number(value).toFixed(digits);
      };
      const sensorSummary = (currentMetrics.temperature_sensors || [])
        .slice(0, 3)
        .map((item) => `${item.name || 'sensor'} ${item.value_c ?? 'unknown'} C`)
        .join(' | ');
      document.getElementById('currentStatsAt').textContent = currentMetrics.ts ? `Latest sample ${formatLocalTimestamp(currentMetrics.ts)}` : 'Latest sample unknown';
      document.getElementById('currentStatsGrid').innerHTML = `
        <div class="metric-chip"><div class="stat-label">CPU</div><strong>${formatMetricNumber(currentMetrics.cpu_percent)}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Memory</div><strong>${formatMetricNumber(currentMetrics.mem_percent)}%</strong></div>
        <div class="metric-chip"><div class="stat-label">MemAvailable</div><strong>${currentMetrics.mem_available_mb ?? 'unknown'} MB</strong></div>
        <div class="metric-chip"><div class="stat-label">Cached</div><strong>${currentMetrics.mem_cached_mb ?? 'unknown'} MB</strong></div>
        <div class="metric-chip"><div class="stat-label">Root disk</div><strong>${formatMetricNumber(currentMetrics.root_disk_percent)}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Recording disk</div><strong>${formatMetricNumber(currentMetrics.recording_disk_percent)}%</strong></div>
        <div class="metric-chip"><div class="stat-label">Temp max</div><strong>${currentMetrics.temperature_c ?? 'unknown'} C</strong></div>
        <div class="metric-chip"><div class="stat-label">Load</div><strong>${formatMetricNumber(currentMetrics.load_1, 2)}</strong></div>
      `;
      document.getElementById('metricsSampleAt').textContent = currentMetrics.ts ? `Latest sample ${formatLocalTimestamp(currentMetrics.ts)}` : 'Latest sample unknown';
      document.getElementById('metricsTempSummary').textContent = sensorSummary
        ? `Temperature: ${sensorSummary}`
        : `Temperature: ${currentMetrics.temperature_c ?? 'unknown'} C`;
      document.getElementById('memoryThermalSummary').innerHTML = `
        <li><strong>Memory used:</strong> ${Number(currentMetrics.mem_percent || 0).toFixed(1)}%</li>
        <li><strong>MemAvailable:</strong> ${currentMetrics.mem_available_mb ?? 'unknown'} MB</li>
        <li><strong>Cached:</strong> ${currentMetrics.mem_cached_mb ?? 'unknown'} MB</li>
        <li><strong>Temperature max:</strong> ${currentMetrics.temperature_c ?? 'unknown'} C</li>
        <li><strong>Thermal zones:</strong> ${currentMetrics.temperature_sensor_count ?? 0}</li>
        <li><strong>Top sensors:</strong> ${sensorSummary || 'unknown'}</li>
      `;
      const teamviewer = status.teamviewer || {};
      const speedtestStatus = status.speedtest_status || {};
      const teamviewerInstalledBadgeMain = document.getElementById('teamviewerInstalledBadgeMain');
      const teamviewerDaemonBadgeMain = document.getElementById('teamviewerDaemonBadgeMain');
      const teamviewerGuiBadgeMain = document.getElementById('teamviewerGuiBadgeMain');
      const teamviewerInstalledBadge = document.getElementById('teamviewerInstalledBadge');
      const teamviewerDaemonBadge = document.getElementById('teamviewerDaemonBadge');
      const teamviewerGuiBadge = document.getElementById('teamviewerGuiBadge');
      teamviewerInstalledBadgeMain.className = `badge ${teamviewer.installed ? '' : 'danger'}`;
      teamviewerInstalledBadgeMain.textContent = teamviewer.installed ? 'Installed' : 'Not installed';
      teamviewerDaemonBadgeMain.className = `badge ${teamviewer.daemon_running ? '' : 'danger'}`;
      teamviewerDaemonBadgeMain.textContent = teamviewer.daemon_running ? 'Daemon running' : 'Daemon stopped';
      teamviewerGuiBadgeMain.className = `badge ${teamviewer.gui_running ? '' : 'warn'}`;
      teamviewerGuiBadgeMain.textContent = teamviewer.gui_running ? 'GUI running' : 'GUI not running';
      document.getElementById('teamviewerSummaryMain').textContent = teamviewer.summary || 'No TeamViewer information available.';
      teamviewerInstalledBadge.className = `badge ${teamviewer.installed ? '' : 'danger'}`;
      teamviewerInstalledBadge.textContent = teamviewer.installed ? 'Installed' : 'Not installed';
      teamviewerDaemonBadge.className = `badge ${teamviewer.daemon_running ? '' : 'danger'}`;
      teamviewerDaemonBadge.textContent = teamviewer.daemon_running ? 'Daemon running' : 'Daemon stopped';
      teamviewerGuiBadge.className = `badge ${teamviewer.gui_running ? '' : 'warn'}`;
      teamviewerGuiBadge.textContent = teamviewer.gui_running ? 'GUI running' : 'GUI not running';
      document.getElementById('teamviewerSummary').textContent = teamviewer.summary || 'No TeamViewer information available.';
      document.getElementById('teamviewerId').textContent = teamviewer.id || (teamviewer.id_permission_issue ? 'Permission denied' : 'unknown');
      document.getElementById('teamviewerVersion').textContent = teamviewer.version || 'unknown';
      document.getElementById('teamviewerStatus').textContent = teamviewer.status_text || 'unknown';
      document.getElementById('remoteSpeedtestSummary').textContent = speedtestStatus.finished_at
        ? `Last speed test: Down ${speedtestStatus.download_mbps ?? 'n/a'} Mbps | Up ${speedtestStatus.upload_mbps ?? 'n/a'} Mbps | ${formatLocalTimestamp(speedtestStatus.finished_at)}`
        : 'No web speed test run yet.';
      document.getElementById('teamviewerResetButton').disabled = !teamviewer.reset_supported;
      if (!teamviewer.reset_supported) {
        document.getElementById('teamviewerResetResult').textContent = 'Password reset is unavailable because the TeamViewer CLI or reset command is not configured on this unit.';
      }
      const faultReporting = status.fault_reporting || {};
      const topSuspect = faultReporting.top_suspect || {};
      const clueCounters = status.clue_counters || [];
      document.getElementById('faultHeadline').textContent = faultReporting.headline || 'Healthy now';
      document.getElementById('faultSummaryText').textContent = faultReporting.summary || 'No summary yet.';
      document.getElementById('faultImpactText').textContent = faultReporting.impact || '';
      document.getElementById('faultTopSuspectBadge').textContent = topSuspect.label || 'No top suspect';
      document.getElementById('faultTopSuspectScore').textContent = `Score ${topSuspect.score || 0}`;
      document.getElementById('clueCounterStrip').innerHTML = clueCounters.map((item) => `<div class="counter-chip ${item.count ? 'hot' : ''}"><div class="stat-label">${item.label || 'Clue'}</div><div class="count">${item.count || 0}</div></div>`).join('') || '<div class="counter-chip"><div class="stat-label">Clues</div><div class="count">0</div></div>';
      document.getElementById('faultQuickActions').innerHTML = (faultReporting.quick_actions || []).map((item) => `<li>${item}</li>`).join('') || '<li>No quick actions suggested yet.</li>';
      document.getElementById('linuxStabilityClues').innerHTML = (faultReporting.stability_clues || []).map((item) => `<li>${item}</li>`).join('') || '<li>No Linux stability clues collected yet.</li>';
      const linuxStability = status.linux_stability || {};
      const previousCounts = linuxStability.previous_boot_counts || {};
      const currentCounts = linuxStability.current_warning_counts || {};
      document.getElementById('linuxPreviousCounts').innerHTML = `
        <li>Link flaps: ${previousCounts.link_flaps || 0}</li>
        <li>igc/reset clues: ${previousCounts.igc_errors || 0}</li>
        <li>PCIe clues: ${previousCounts.pcie_events || 0}</li>
        <li>EDAC/memory clues: ${previousCounts.memory_events || 0}</li>
      `;
      document.getElementById('linuxCurrentCounts').innerHTML = `
        <li>Link flaps: ${currentCounts.link_flaps || 0}</li>
        <li>igc/reset clues: ${currentCounts.igc_errors || 0}</li>
        <li>PCIe clues: ${currentCounts.pcie_events || 0}</li>
        <li>EDAC/memory clues: ${currentCounts.memory_events || 0}</li>
      `;
      document.getElementById('linuxPreviousLine').innerHTML = `<code>${linuxStability.strongest_previous_line || 'No highlighted previous-boot line yet.'}</code>`;
      document.getElementById('linuxCurrentLine').innerHTML = `<code>${linuxStability.strongest_current_line || 'No highlighted current-warning line yet.'}</code>`;
      document.getElementById('linuxInterpretation').innerHTML = (linuxStability.interpretation || []).map((item) => `<li>${item}</li>`).join('') || '<li>No Linux stability interpretation available yet.</li>';
      document.getElementById('linuxAlertRules').innerHTML = (linuxStability.alert_rules || []).map((item) => `<li><strong>${item.label || 'Rule'}:</strong> ${item.threshold || ''} - ${item.meaning || ''}</li>`).join('') || '<li>No alert rules configured.</li>';
      const memtestInfo = status.memtest_info || {};
      document.getElementById('memtestHint').textContent = `memtester ${memtestInfo.installed ? 'is installed' : 'is not installed'}. Free RAM: ${memtestInfo.available_mb || 0} MB. Suggested test: ${memtestInfo.recommended_label || '1024M'} x ${memtestInfo.recommended_loops || 2}.`;
      document.getElementById('memtest_size_mb').value = memtestInfo.recommended_mb || 1024;
      document.getElementById('memtest_loops').value = memtestInfo.recommended_loops || 2;
      const memtestStatus = status.memtest_status || {};
      const memtestBadge = document.getElementById('memtestState');
      memtestBadge.className = `badge ${memtestStatus.state === 'running' ? 'warn' : (memtestStatus.state === 'failed' ? 'danger' : '')}`;
      memtestBadge.textContent = (memtestStatus.state || 'idle').toUpperCase();
      document.getElementById('memtestMessage').textContent = memtestStatus.message || 'No web memory test run yet.';
      document.getElementById('memtestMeta').textContent = memtestStatus.finished_at ? formatLocalTimestamp(memtestStatus.finished_at) : 'not finished yet';
      document.getElementById('memtestLogLink').style.display = memtestStatus.log_path ? 'inline-block' : 'none';
      const speedtestBadge = document.getElementById('speedtestState');
      speedtestBadge.className = `badge ${speedtestStatus.state === 'running' ? 'warn' : (speedtestStatus.state === 'failed' ? 'danger' : '')}`;
      speedtestBadge.textContent = (speedtestStatus.state || 'idle').toUpperCase();
      document.getElementById('speedtestMessage').textContent = speedtestStatus.message || 'No web speed test run yet.';
      const speedtestMetaParts = [];
      if (speedtestStatus.download_mbps !== null && speedtestStatus.download_mbps !== undefined) {
        speedtestMetaParts.push(`Download ${speedtestStatus.download_mbps} Mbps`);
      }
      if (speedtestStatus.upload_mbps !== null && speedtestStatus.upload_mbps !== undefined) {
        speedtestMetaParts.push(`Upload ${speedtestStatus.upload_mbps} Mbps`);
      }
      if (speedtestStatus.cpu_percent !== null && speedtestStatus.cpu_percent !== undefined) {
        speedtestMetaParts.push(`CPU ${speedtestStatus.cpu_percent}%`);
      }
      if (speedtestStatus.memory_percent !== null && speedtestStatus.memory_percent !== undefined) {
        speedtestMetaParts.push(`Memory ${speedtestStatus.memory_percent}%`);
      }
      if (speedtestStatus.finished_at) {
        speedtestMetaParts.push(formatLocalTimestamp(speedtestStatus.finished_at));
      }
      document.getElementById('speedtestMeta').textContent = speedtestMetaParts.join(' | ') || 'not finished yet';
      document.getElementById('speedtestLogLink').style.display = speedtestStatus.log_path ? 'inline-block' : 'none';
      document.getElementById('speedtestHistory').innerHTML = (status.speedtest_history || []).map((item) => `<li>${formatLocalTimestamp(item.ts || '')} | ${item.state || 'unknown'} | Down ${item.download_mbps ?? 'n/a'} Mbps | Up ${item.upload_mbps ?? 'n/a'} Mbps</li>`).join('') || '<li>No speed test history yet.</li>';
      const hikStatus = status.hik_status || {};
      const hikBadge = document.getElementById('hikState');
      hikBadge.className = `badge ${hikStatus.state === 'failed' ? 'danger' : (hikStatus.state === 'idle' ? 'warn' : '')}`;
      hikBadge.textContent = (hikStatus.state || 'idle').toUpperCase();
      document.getElementById('hikMessage').textContent = hikStatus.message || 'No Hik probe run yet.';
      document.getElementById('hikMeta').textContent = hikStatus.checked_at ? formatLocalTimestamp(hikStatus.checked_at) : '';
      document.getElementById('hikCounts').innerHTML = Object.entries(hikStatus.parsed_counts || {}).map(([key, value]) => `<li><strong>${key}</strong>: ${value}</li>`).join('') || '<li>No people-count values parsed yet.</li>';
      document.getElementById('hikCapabilitiesRaw').textContent = hikStatus.capabilities_excerpt || '';
      document.getElementById('hikResultRaw').textContent = hikStatus.result_excerpt || '';
      document.getElementById('hikSavedSettings').innerHTML = `
        <li>Enabled: ${status.config.hik_enabled ? 'true' : 'false'}</li>
        <li>Scheme: ${status.config.hik_scheme || 'http'}</li>
        <li>Host: ${status.config.hik_host || ''}</li>
        <li>Username: ${status.config.hik_username || ''}</li>
        <li>Password: ${(status.config.hik_password || '').trim() ? 'set' : 'empty'}</li>
        <li>Channel: ${status.config.hik_channel || 1}</li>
        <li>Result path: ${status.config.hik_people_count_result_path || ''}</li>
        <li>Capabilities path: ${status.config.hik_people_count_capabilities_path || ''}</li>
      `;
      const rebootLeadup = status.reboot_leadup || {};
      const rebootLeadupMetrics = rebootLeadup.last_metrics || {};
      document.getElementById('rebootLeadupDetail').textContent = rebootLeadup.detail || 'No reboot lead-up yet.';
      document.getElementById('rebootLeadupAt').textContent = rebootLeadup.reference_at ? `Reference point ${formatLocalTimestamp(rebootLeadup.reference_at)}` : '';
      document.getElementById('rebootLeadupStats').innerHTML = `
        <section class="stat-card"><div class="stat-label">CPU</div><div class="stat-value">${rebootLeadupMetrics.cpu_percent ?? 'unknown'}%</div></section>
        <section class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">${rebootLeadupMetrics.mem_percent ?? 'unknown'}%</div></section>
        <section class="stat-card"><div class="stat-label">MemAvailable</div><div class="stat-value" style="font-size:1rem;">${rebootLeadupMetrics.mem_available_mb ?? 'unknown'} MB</div></section>
        <section class="stat-card"><div class="stat-label">Temp</div><div class="stat-value" style="font-size:1rem;">${rebootLeadupMetrics.temperature_c ?? 'unknown'} C</div></section>
      `;
      document.getElementById('rebootLeadupTimeline').innerHTML = (rebootLeadup.events || []).map((item) => `<div class="timeline-card ${item.severity || ''}"><div class="timeline-time">${formatLocalTimestamp(item.ts || '')}</div><div class="timeline-title">${item.title || ''}</div><div>${item.detail || ''}</div></div>`).join('') || '<div class="timeline-empty">No lead-up events captured yet.</div>';
      document.getElementById('crashReviewFindings').innerHTML = (crashReview.findings || []).length
        ? (crashReview.findings || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No crash-review findings yet.</li>';
      document.getElementById('crashReviewSystem').innerHTML = (crashReview.system_lines || []).length
        ? (crashReview.system_lines || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No notable system-log lines extracted yet.</li>';
      document.getElementById('crashReviewSystemAll').innerHTML = (crashReview.system_lines_all || []).length
        ? (crashReview.system_lines_all || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No extra system-log lines extracted yet.</li>';
      document.getElementById('crashReviewKernel').innerHTML = (crashReview.kernel_lines || []).length
        ? (crashReview.kernel_lines || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No notable kernel-log lines extracted yet.</li>';
      document.getElementById('crashReviewKernelAll').innerHTML = (crashReview.kernel_lines_all || []).length
        ? (crashReview.kernel_lines_all || []).map((line) => `<li>${line}</li>`).join('')
        : '<li>No extra kernel-log lines extracted yet.</li>';
      const updateState = status.update_status || {};
      const updateBadge = document.getElementById('updateState');
      const updateNowButton = document.getElementById('updateNowButton');
      updateBadge.className = `badge ${updateState.state === 'running' ? 'warn' : (updateState.state === 'failed' ? 'danger' : '')}`;
      updateBadge.textContent = ((updateState.mode === 'check' ? 'check' : (updateState.state || 'idle')) || 'idle').toUpperCase();
      document.getElementById('updateMessage').textContent = updateState.message || 'No web update run yet.';
      document.getElementById('updateMeta').textContent = `${updateState.from_build || 'unknown'} to ${updateState.to_build || 'unknown'} | ${updateState.finished_at ? formatLocalTimestamp(updateState.finished_at) : 'not finished yet'}`;
      document.getElementById('updateConsole').textContent = (status.update_console_lines || []).length
        ? (status.update_console_lines || []).join('
')
        : 'No update progress yet.';
      updateNowButton.style.display = updateState.update_available ? 'inline-block' : 'none';
      updateNowButton.disabled = updateState.state === 'running';
      const requiredTools = status.required_tools || {};
      const missingImportant = requiredTools.missing_important || [];
      const missingRequired = requiredTools.missing_required || [];
      const requiredHeadline = document.getElementById('requiredToolsHeadline');
      requiredHeadline.className = `badge ${missingRequired.length ? 'danger' : ''}`;
      requiredHeadline.textContent = missingRequired.length ? 'Missing tools' : 'Tools ready';
      const requiredMissingCount = document.getElementById('requiredToolsMissingCount');
      requiredMissingCount.textContent = `${missingImportant.length} missing`;
      requiredMissingCount.style.display = missingImportant.length ? 'inline-block' : 'none';
      document.getElementById('requiredToolsSummary').textContent = missingImportant.length
        ? `Missing: ${missingImportant.join(', ')}`
        : 'SMART, EDAC, TeamViewer CLI, and watchdog services look available.';
      document.getElementById('requiredToolsGrid').innerHTML = (requiredTools.items || []).map((item) => `
        <div class="tool-card">
          <div class="tool-head">
            <span class="tool-title">${item.label || 'Tool'}</span>
            <span class="tool-status ${item.ok ? 'ok' : 'bad'}">${item.ok ? 'Tick Ready' : 'Cross Missing'}</span>
          </div>
          <div class="tool-why">${item.why || ''}</div>
          <div class="tool-detail">${item.detail || ''}</div>
        </div>
      `).join('') || '<div class="timeline-empty">No tool status available yet.</div>';
      const toolsInstallState = requiredTools.install_status || {};
      const toolsInstallRow = document.getElementById('toolsInstallRow');
      const toolsInstallLinks = document.getElementById('toolsInstallLinks');
      const installToolsButton = document.getElementById('installToolsButton');
      const toolsBadge = document.getElementById('toolsInstallState');
      toolsBadge.className = `badge ${toolsInstallState.state === 'running' ? 'warn' : (toolsInstallState.state === 'failed' ? 'danger' : '')}`;
      toolsBadge.textContent = (toolsInstallState.state || 'idle').toUpperCase();
      document.getElementById('toolsInstallMessage').textContent = toolsInstallState.message || '';
      const toolsMetaParts = [];
      if ((toolsInstallState.packages || []).length) {
        toolsMetaParts.push((toolsInstallState.packages || []).join(', '));
      }
      if (toolsInstallState.finished_at) {
        toolsMetaParts.push(formatLocalTimestamp(toolsInstallState.finished_at));
      }
      const showInstallRow = missingImportant.length > 0 || toolsInstallState.state === 'running' || toolsInstallState.state === 'failed';
      toolsInstallRow.style.display = showInstallRow ? 'flex' : 'none';
      installToolsButton.style.display = missingImportant.length > 0 ? 'inline-block' : 'none';
      installToolsButton.disabled = toolsInstallState.state === 'running';
      document.getElementById('toolsInstallMeta').textContent = toolsMetaParts.join(' | ');
      document.getElementById('toolsInstallMeta').style.display = toolsMetaParts.length && showInstallRow ? 'block' : 'none';
      toolsInstallLinks.style.display = toolsInstallState.log_path && showInstallRow ? 'flex' : 'none';
      document.getElementById('toolsInstallLogLink').style.display = toolsInstallState.log_path && showInstallRow ? 'inline-block' : 'none';
      const exportState = status.export_status || {};
      const exportButton = document.getElementById('exportButton');
      const exportDownloadName = exportState.download_archive_name || 'incident pack';
      if (exportState.state === 'running') {
        exportButton.textContent = `Exporting ${exportDownloadName}`;
        exportButton.className = 'secondary status-running';
        exportButton.disabled = true;
      } else if (exportState.state === 'failed') {
        exportButton.textContent = 'Export failed, try again';
        exportButton.className = 'secondary status-failed';
        exportButton.disabled = false;
      } else if (exportState.state === 'ok') {
        exportButton.textContent = `Export ready: ${exportDownloadName}`;
        exportButton.className = 'secondary status-ready';
        exportButton.disabled = false;
      } else {
        exportButton.textContent = 'Export incident pack';
        exportButton.className = 'secondary';
        exportButton.disabled = false;
      }
      const exportMetaParts = [];
      if (exportState.message) {
        exportMetaParts.push(exportState.message);
      }
      if (exportState.export_label) {
        exportMetaParts.push(exportState.export_label);
      }
      if (exportState.folder) {
        exportMetaParts.push(exportState.folder);
      }
      if (exportState.since || exportState.until) {
        exportMetaParts.push(`${exportState.since || 'unknown'} to ${exportState.until || 'unknown'}`);
      }
      if (exportState.finished_at) {
        exportMetaParts.push(formatLocalTimestamp(exportState.finished_at));
      }
      document.getElementById('exportMeta').textContent = exportMetaParts.join(' | ') || 'No incident export run yet.';
      document.getElementById('exportConsole').textContent = (status.export_console_lines || []).length
        ? (status.export_console_lines || []).join('
')
        : 'No export progress yet.';
      const exportToken = exportState.request_id || exportState.finished_at || exportState.export_label || '';
      const exportArchiveLink = document.getElementById('exportArchiveLink');
      const exportReadmeLink = document.getElementById('exportReadmeLink');
      const exportLogLink = document.getElementById('exportLogLink');
      exportArchiveLink.href = buildAuthedUrl('/download/export-archive', { export: exportToken });
      exportReadmeLink.href = buildAuthedUrl('/download/export-readme', { export: exportToken });
      exportLogLink.href = buildAuthedUrl('/download/export-log', { export: exportToken });
      exportArchiveLink.style.display = exportState.archive ? 'inline-block' : 'none';
      exportReadmeLink.style.display = exportState.folder ? 'inline-block' : 'none';
      exportLogLink.style.display = exportState.log_path ? 'inline-block' : 'none';

      document.querySelector('.overview-grid').innerHTML = `
        <section class="stat-card"><div class="stat-label">Current state</div><div class="stat-value">${status.state.fault_active ? 'Fault' : 'Healthy'}</div></section>
        <section class="stat-card"><div class="stat-label">Watchdog reboot commands</div><div class="stat-value">${(status.reboot_counts && status.reboot_counts.watchdog) || 0}</div></section>
        <section class="stat-card"><div class="stat-label">Detected reboots</div><div class="stat-value">${(status.reboot_counts && status.reboot_counts.detected) || 0}</div></section>
        <section class="stat-card"><div class="stat-label">Unexpected reboots</div><div class="stat-value">${(status.reboot_counts && status.reboot_counts.unexpected) || 0}</div></section>
        <section class="stat-card"><div class="stat-label">Last reboot reason</div><div class="stat-value" style="font-size:1rem;">${status.state.last_reboot_reason || 'none'}</div></section>
        <section class="stat-card"><div class="stat-label">Last startup</div><div class="stat-value" style="font-size:1rem;">${formatLocalTimestamp(status.state.last_startup_at || '')}</div></section>
        <section class="stat-card"><div class="stat-label">Hardware ID</div><div class="stat-value" style="font-size:1rem;">${(status.hardware_identity && status.hardware_identity.serial) || 'unknown'}</div></section>
        <section class="stat-card"><div class="stat-label">Build</div><div class="stat-value" style="font-size:1rem;">${(status.build_info && status.build_info.git_commit) || 'unknown'}</div></section>
      `;

      const heroMain = document.querySelector('.hero-main');
      heroMain.innerHTML = `
        <div class="stat-label">Current diagnosis</div>
        <div class="hero-title">${status.diagnosis.title}</div>
        <div class="hero-detail">${status.diagnosis.detail}</div>
        <div class="status-strip">
          <span class="badge ${status.state.fault_active ? 'danger' : ''}">${status.state.fault_active ? 'Fault active' : 'Healthy now'}</span>
          <span class="badge ${status.reboot_counts && status.reboot_counts.unexpected ? 'warn' : ''}">Unexpected reboots: ${(status.reboot_counts && status.reboot_counts.unexpected) || 0}</span>
          <span class="badge">Detected reboots: ${(status.reboot_counts && status.reboot_counts.detected) || 0}</span>
          <span class="badge">Watchdog commands: ${(status.reboot_counts && status.reboot_counts.watchdog) || 0}</span>
        </div>
      `;
    }

    function drawMetrics(points, hoverIndex = null) {
      const canvas = document.getElementById('metricsChart');
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#0f1820';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const pad = 40;
      const chartWidth = canvas.width - pad * 2;
      const chartHeight = canvas.height - pad * 2;

      ctx.strokeStyle = '#29404f';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i += 1) {
        const y = pad + (chartHeight / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(pad + chartWidth, y);
        ctx.stroke();
      }

      ctx.fillStyle = '#8ea5b9';
      ctx.font = '12px Segoe UI';
      for (let i = 0; i <= 4; i += 1) {
        const value = 100 - (25 * i);
        const y = pad + (chartHeight / 4) * i + 4;
        ctx.fillText(`${value}%`, 6, y);
      }

      if (!points.length) {
        ctx.fillStyle = '#8ea5b9';
        ctx.font = '16px Segoe UI';
        ctx.fillText('No metrics collected yet.', pad, canvas.height / 2);
        return;
      }

      const series = [
        { key: 'cpu_percent', color: '#67a8db', label: 'CPU' },
        { key: 'mem_percent', color: '#e07b7b', label: 'Memory' },
        { key: 'root_disk_percent', color: '#7ab08a', label: 'Root disk' },
        { key: 'recording_disk_percent', color: '#d4a34a', label: 'Recording disk' },
        { key: 'temperature_c', color: '#ff9f6e', label: 'Temp C' }
      ];

      const epochs = points.map((point) => Date.parse(point.ts || '')).filter((epoch) => Number.isFinite(epoch));
      const firstEpoch = epochs.length ? epochs[0] : Date.now();
      const lastEpoch = epochs.length ? epochs[epochs.length - 1] : (firstEpoch + 1);
      const spanEpoch = Math.max(1, lastEpoch - firstEpoch);
      const xForEpoch = (epoch) => pad + (((epoch - firstEpoch) / spanEpoch) * chartWidth);
      const yFor = (value) => pad + chartHeight - ((Math.max(0, Math.min(100, Number(value || 0))) / 100) * chartHeight);

      series.forEach((line, idx) => {
        ctx.strokeStyle = line.color;
        ctx.lineWidth = 2;
        let started = false;
        points.forEach((point) => {
          const pointEpoch = Date.parse(point.ts || '');
          const value = point[line.key];
          if (!Number.isFinite(pointEpoch) || point.gap || value === null || value === undefined || Number.isNaN(Number(value))) {
            if (started) {
              ctx.stroke();
              started = false;
            }
            return;
          }
          const x = xForEpoch(pointEpoch);
          const y = yFor(value);
          if (!started) {
            ctx.beginPath();
            ctx.moveTo(x, y);
            started = true;
          } else {
            ctx.lineTo(x, y);
          }
        });
        if (started) {
          ctx.stroke();
        }
        ctx.fillStyle = line.color;
        ctx.fillRect(pad + idx * 140, 10, 12, 12);
        ctx.fillStyle = '#d8e6f1';
        ctx.fillText(line.label, pad + idx * 140 + 18, 20);
      });

      latestMetricEvents.forEach((event, index) => {
        const eventEpoch = Date.parse(event.ts || '');
        if (!Number.isFinite(eventEpoch)) {
          return;
        }
        const x = xForEpoch(eventEpoch);
        if (x < pad || x > pad + chartWidth) {
          return;
        }
        const markerColor = event.kind === 'command' ? '#d4a34a' : (event.kind === 'detected' ? '#e07b7b' : '#8ea5b9');
        ctx.strokeStyle = markerColor;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, pad);
        ctx.lineTo(x, pad + chartHeight);
        ctx.stroke();
        ctx.fillStyle = markerColor;
        ctx.beginPath();
        ctx.arc(x, pad + 8 + (index % 3) * 8, 3, 0, Math.PI * 2);
        ctx.fill();
      });

      if (hoverIndex !== null && points[hoverIndex]) {
        const hoverEpoch = Date.parse(points[hoverIndex].ts || '');
        if (Number.isFinite(hoverEpoch)) {
          const x = xForEpoch(hoverEpoch);
          ctx.strokeStyle = '#8ea5b9';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(x, pad);
          ctx.lineTo(x, pad + chartHeight);
          ctx.stroke();
        }
      }
    }

    function updateEventLegend() {
      const counts = latestMetricEvents.reduce((acc, item) => {
        const kind = item.kind || 'other';
        acc[kind] = (acc[kind] || 0) + 1;
        return acc;
      }, {});
      document.getElementById('legendTemp').innerHTML = '<span class="chart-event-dot temp"></span>Temperature';
      document.getElementById('legendGap').innerHTML = '<span class="chart-event-dot note"></span>No samples / watchdog offline';
      document.getElementById('legendCommand').innerHTML = '<span class="chart-event-dot command"></span>Watchdog reboot command (' + (counts.command || 0) + ')';
      document.getElementById('legendDetected').innerHTML = '<span class="chart-event-dot detected"></span>Detected or unexpected reboot (' + (counts.detected || 0) + ')';
      document.getElementById('legendNote').innerHTML = '<span class="chart-event-dot note"></span>Reboot counts acknowledged (' + (counts.note || 0) + ')';
    }

    async function fetchStatus() {
      const response = await fetch('/api/status' + authQuery);
      render(await response.json());
    }

    function setMetricRange(hours) {
      metricsRangeHours = hours;
      document.getElementById('range1hBtn').classList.toggle('active', hours === 1);
      document.getElementById('range24hBtn').classList.toggle('active', hours === 24);
      document.getElementById('range168hBtn').classList.toggle('active', hours === 168);
      document.getElementById('metricsTitle').textContent = metricRangeLabel(hours);
      fetchMetrics();
    }

    async function fetchMetrics() {
      const separator = authQuery ? '&' : '?';
      const response = await fetch(`/api/metrics${authQuery}${separator}hours=${metricsRangeHours}`);
      const payload = await response.json();
      latestMetrics = payload.points || [];
      latestMetricEvents = payload.events || [];
      updateEventLegend();
      drawMetrics(latestMetrics);
    }

    async function saveSettings() {
      await fetch('/api/config' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          monitoring_enabled: document.getElementById('monitoring_enabled').checked,
          app_restart_enabled: document.getElementById('app_restart_enabled').checked,
          restart_network_before_reboot: document.getElementById('restart_network_before_reboot').checked,
          reboot_enabled: document.getElementById('reboot_enabled').checked
        })
      });
      await fetchStatus();
    }

    function parseLines(id) {
      return document.getElementById(id).value
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    }

    function parseTcpTargets() {
      return parseLines('tcp_targets')
        .map((line) => {
          const lastColon = line.lastIndexOf(':');
          if (lastColon <= 0 || lastColon === line.length - 1) {
            throw new Error(`Invalid TCP target: ${line}`);
          }
          const host = line.slice(0, lastColon).trim();
          const port = Number(line.slice(lastColon + 1).trim());
          if (!host || !Number.isFinite(port) || port < 1 || port > 65535) {
            throw new Error(`Invalid TCP target: ${line}`);
          }
          return { host, port };
        });
    }

    async function saveConfig() {
      const payload = {
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
        web_port: Number(document.getElementById('web_port').value || 80),
        web_token: document.getElementById('web_token').value.trim(),
        network_restart_command: document.getElementById('network_restart_command').value.trim(),
        teamviewer_id_command: document.getElementById('teamviewer_id_command').value.trim(),
        teamviewer_password_reset_command: document.getElementById('teamviewer_password_reset_command').value.trim(),
        teamviewer_start_command: document.getElementById('teamviewer_start_command').value.trim(),
        teamviewer_restart_command: document.getElementById('teamviewer_restart_command').value.trim(),
        hik_enabled: document.getElementById('hik_enabled').checked,
        hik_scheme: document.getElementById('hik_scheme').value.trim(),
        hik_host: document.getElementById('hik_host').value.trim(),
        hik_username: document.getElementById('hik_username').value.trim(),
        hik_password: document.getElementById('hik_password').value.trim(),
        hik_channel: Number(document.getElementById('hik_channel').value || 1),
        hik_people_count_result_path: document.getElementById('hik_people_count_result_path').value.trim(),
        hik_people_count_capabilities_path: document.getElementById('hik_people_count_capabilities_path').value.trim(),
        internet_hosts: parseLines('internet_hosts'),
        systemd_services: parseLines('systemd_services'),
        tcp_targets: parseTcpTargets()
      };
      await fetch('/api/config' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      await fetchStatus();
    }

    async function saveHikConfig() {
      await fetch('/api/config' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hik_enabled: document.getElementById('hik_enabled').checked,
          hik_scheme: document.getElementById('hik_scheme').value.trim(),
          hik_host: document.getElementById('hik_host').value.trim(),
          hik_username: document.getElementById('hik_username').value.trim(),
          hik_password: document.getElementById('hik_password').value.trim(),
          hik_channel: Number(document.getElementById('hik_channel').value || 1),
          hik_people_count_result_path: document.getElementById('hik_people_count_result_path').value.trim(),
          hik_people_count_capabilities_path: document.getElementById('hik_people_count_capabilities_path').value.trim()
        })
      });
      await fetchStatus();
    }

    async function runHikProbe() {
      const response = await fetch('/api/action' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'hik_probe' })
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ message: 'Hik probe failed.' }));
        alert(payload.message || 'Hik probe failed.');
        return;
      }
      await fetchStatus();
    }

    async function runAction(action, extraPayload = {}) {
      const response = await fetch('/api/action' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ...extraPayload })
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ message: 'Action failed.' }));
        if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {
          document.getElementById('teamviewerResetResult').textContent = payload.detail ? `${payload.message} (${payload.detail})` : (payload.message || 'Action failed.');
        }
        alert(payload.message || 'Action failed.');
        return;
      }
      const payload = await response.json().catch(() => ({ ok: true }));
      if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {
        const detail = payload.password ? `New password: ${payload.password}` : (payload.message || 'TeamViewer action complete.');
        document.getElementById('teamviewerResetResult').textContent = detail;
      }
      await fetchStatus();
    }

    async function setTeamviewerPassword() {
      const password = document.getElementById('teamviewerManualPassword').value.trim();
      await runAction('reset_teamviewer_password', { password });
    }

    async function exportIncident() {
      const since = document.getElementById('export_since').value;
      const until = document.getElementById('export_until').value;
      const response = await fetch('/api/export' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          since: since ? since.replace('T', ' ') : '',
          until: until ? until.replace('T', ' ') : ''
        })
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ message: 'Export failed.' }));
        alert(payload.message || 'Export failed.');
        return;
      }
      await fetchStatus();
    }

    async function runMemtest() {
      const response = await fetch('/api/memtest' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          size_mb: Number(document.getElementById('memtest_size_mb').value || 1024),
          loops: Number(document.getElementById('memtest_loops').value || 2)
        })
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ message: 'Memory test failed to start.' }));
        alert(payload.message || 'Memory test failed to start.');
        return;
      }
      await fetchStatus();
    }

    async function runSpeedtest() {
      const response = await fetch('/api/speedtest' + authQuery, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({ message: 'Speed test failed to start.' }));
        alert(payload.message || 'Speed test failed to start.');
        return;
      }
      await fetchStatus();
    }

    async function installRequiredTools() {
      await runAction('install_required_tools');
    }

    function attachChartHover() {
      const canvas = document.getElementById('metricsChart');
      const hover = document.getElementById('metricsHover');
      if (!canvas || !hover) {
        return;
      }

      canvas.addEventListener('mousemove', (event) => {
        if (!latestMetrics.length) {
          return;
        }
        const rect = canvas.getBoundingClientRect();
        const ratioX = canvas.width / rect.width;
        const x = (event.clientX - rect.left) * ratioX;
        const pad = 40;
        const chartWidth = canvas.width - pad * 2;
        const clamped = Math.max(pad, Math.min(pad + chartWidth, x));
        const firstEpoch = Date.parse((latestMetrics[0] || {}).ts || '');
        const lastEpoch = Date.parse((latestMetrics[latestMetrics.length - 1] || {}).ts || '');
        const spanEpoch = Math.max(1, lastEpoch - firstEpoch);
        const targetEpoch = firstEpoch + (((clamped - pad) / chartWidth) * spanEpoch);
        let idx = 0;
        let bestDistance = Number.POSITIVE_INFINITY;
        latestMetrics.forEach((item, index) => {
          const epoch = Date.parse(item.ts || '');
          if (!Number.isFinite(epoch)) {
            return;
          }
          const distance = Math.abs(epoch - targetEpoch);
          if (distance < bestDistance) {
            bestDistance = distance;
            idx = index;
          }
        });
        const point = latestMetrics[idx];
        if (!point) {
          return;
        }
        const pointEpoch = Date.parse(point.ts || '');
        const nearbyWindowMs = metricsRangeHours > 24 ? 30 * 60 * 1000 : 5 * 60 * 1000;
        if (point.gap) {
          hover.textContent = `${formatLocalTimestamp(point.ts || '')} | No watchdog sample in this period.`;
          drawMetrics(latestMetrics, idx);
          return;
        }
        const nearbyEvents = latestMetricEvents
          .filter((item) => {
            const eventEpoch = Date.parse(item.ts || '');
            return Number.isFinite(eventEpoch) && Number.isFinite(pointEpoch) && Math.abs(eventEpoch - pointEpoch) <= nearbyWindowMs;
          })
          .map((item) => item.label);
        const eventText = nearbyEvents.length ? ` | Events: ${nearbyEvents.join(', ')}` : '';
        const memAvailText = point.mem_available_mb !== undefined && point.mem_available_mb !== null ? ` | MemAvailable ${point.mem_available_mb} MB` : '';
        const tempText = point.temperature_c !== undefined && point.temperature_c !== null ? ` | Temp ${Number(point.temperature_c).toFixed(1)} C` : '';
        hover.textContent = `${formatLocalTimestamp(point.ts || '')} | CPU ${Number(point.cpu_percent || 0).toFixed(1)}% | Memory ${Number(point.mem_percent || 0).toFixed(1)}%${memAvailText} | Root ${Number(point.root_disk_percent || 0).toFixed(1)}% | Recording ${Number(point.recording_disk_percent || 0).toFixed(1)}%${tempText}${eventText}`;
        drawMetrics(latestMetrics, idx);
      });

      canvas.addEventListener('mouseleave', () => {
        hover.textContent = 'Move across the graph to inspect time and values.';
        drawMetrics(latestMetrics);
      });
    }

    render(initialStatus);
    fetchMetrics();
    attachChartHover();
    setInterval(fetchStatus, 15000);
    setInterval(fetchMetrics, 60000);
  