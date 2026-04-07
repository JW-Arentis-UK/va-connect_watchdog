
    (function () {
      function authQuery() {
        return window.location.search || '';
      }

      function postJson(path, payload, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', path + authQuery(), true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          var body = {};
          try {
            body = JSON.parse(xhr.responseText || '{}');
          } catch (err) {
            body = {};
          }
          callback(xhr.status, body);
        };
        xhr.send(JSON.stringify(payload || {}));
      }

      function reloadSoon() {
        window.setTimeout(function () {
          var url = new URL(window.location.href);
          var activeBtn = document.querySelector('.tab-btn.active');
          var activeTab = activeBtn ? activeBtn.getAttribute('data-tab') : '';
          if (activeTab) {
            url.searchParams.set('tab', activeTab);
          }
          window.location.replace(url.toString());
        }, 900);
      }

      window.switchTab = function (name) {
        var buttons = document.getElementsByClassName('tab-btn');
        var panels = document.getElementsByClassName('tab-panel');
        var i;
        for (i = 0; i < buttons.length; i += 1) {
          buttons[i].classList[buttons[i].getAttribute('data-tab') === name ? 'add' : 'remove']('active');
        }
        for (i = 0; i < panels.length; i += 1) {
          panels[i].classList[panels[i].getAttribute('data-tab-panel') === name ? 'add' : 'remove']('active');
        }
        try {
          var url = new URL(window.location.href);
          url.searchParams.set('tab', name);
          window.history.replaceState(null, '', url.toString());
        } catch (_err) {
          // ignore URL rewrite issues in limited browsers
        }
      };

      window.hardRefreshPage = function () {
        try {
          var url = new URL(window.location.href);
          url.searchParams.set('_refresh', String(Date.now()));
          var activeBtn = document.querySelector('.tab-btn.active');
          var activeTab = activeBtn ? activeBtn.getAttribute('data-tab') : '';
          if (activeTab) {
            url.searchParams.set('tab', activeTab);
          }
          window.location.replace(url.toString());
        } catch (_err) {
          var joiner = window.location.search ? '&' : '?';
          window.location.href = window.location.pathname + (window.location.search || '') + joiner + '_refresh=' + new Date().getTime();
        }
      };

      window.runAction = function (action, extraPayload) {
        var payload = { action: action };
        var key;
        extraPayload = extraPayload || {};
        for (key in extraPayload) {
          if (Object.prototype.hasOwnProperty.call(extraPayload, key)) {
            payload[key] = extraPayload[key];
          }
        }
        postJson('/api/action', payload, function (status, body) {
          if (status >= 200 && status < 300) {
            if (action === 'reset_teamviewer_password' || action === 'start_teamviewer' || action === 'restart_teamviewer') {
              var result = document.getElementById('teamviewerResetResult');
              if (result) {
                result.textContent = body.password ? ('New password: ' + body.password) : (body.message || 'Action complete.');
              }
            }
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Action failed.');
        });
      };

      window.setTeamviewerPassword = function () {
        var input = document.getElementById('teamviewerManualPassword');
        window.runAction('reset_teamviewer_password', { password: input ? input.value : '' });
      };

      window.exportIncident = function () {
        var since = document.getElementById('export_since');
        var until = document.getElementById('export_until');
        postJson('/api/export', {
          since: since && since.value ? since.value.replace('T', ' ') : '',
          until: until && until.value ? until.value.replace('T', ' ') : ''
        }, function (status, body) {
          if (status >= 200 && status < 300) {
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Export failed.');
        });
      };

      window.quickExportIncident = function () {
        postJson('/api/action', { action: 'quick_export' }, function (status, body) {
          if (status >= 200 && status < 300) {
            var meta = document.getElementById('quickExportMeta');
            if (meta && body && body.message) {
              meta.textContent = body.message;
            }
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Quick export failed.');
        });
      };

      window.runIncidentExport = function (incidentId) {
        postJson('/api/action', { action: 'incident_export', incident_id: incidentId }, function (status, body) {
          if (status >= 200 && status < 300) {
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Incident export failed.');
        });
      };

      window.runSpeedtest = function () {
        postJson('/api/speedtest', {}, function (status, body) {
          if (status >= 200 && status < 300) {
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Speed test failed to start.');
        });
      };

      window.runMemtest = function () {
        var size = document.getElementById('memtest_size_mb');
        var loops = document.getElementById('memtest_loops');
        postJson('/api/memtest', {
          size_mb: size && size.value ? Number(size.value) : 1024,
          loops: loops && loops.value ? Number(loops.value) : 2
        }, function (status, body) {
          if (status >= 200 && status < 300) {
            reloadSoon();
            return;
          }
          alert((body && body.message) || 'Memory test failed to start.');
        });
      };

      window.installRequiredTools = function () {
        window.runAction('install_required_tools');
      };

      window.saveSettings = function () {
        postJson('/api/config', {
          monitoring_enabled: !!(document.getElementById('monitoring_enabled') || {}).checked,
          app_restart_enabled: !!(document.getElementById('app_restart_enabled') || {}).checked,
          restart_network_before_reboot: !!(document.getElementById('restart_network_before_reboot') || {}).checked,
          reboot_enabled: !!(document.getElementById('reboot_enabled') || {}).checked
        }, function () {
          reloadSoon();
        });
      };

      function fetchJson(path, callback) {
        var xhr = new XMLHttpRequest();
        var query = authQuery();
        var url = path;
        if (query) {
          url += (path.indexOf('?') >= 0 ? '&' : '?') + query.substring(1);
        }
        xhr.open('GET', url, true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) {
            return;
          }
          var body = {};
          try {
            body = JSON.parse(xhr.responseText || '{}');
          } catch (err) {
            body = {};
          }
          callback(xhr.status, body);
        };
        xhr.send();
      }

      function drawLegacyMetrics(points) {
        var canvas = document.getElementById('metricsChart');
        if (!canvas || !canvas.getContext) {
          return;
        }
        var ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#0f1820';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        var pad = 40;
        var chartWidth = canvas.width - pad * 2;
        var chartHeight = canvas.height - pad * 2;
        ctx.strokeStyle = '#29404f';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 4; i += 1) {
          var y = pad + (chartHeight / 4) * i;
          ctx.beginPath();
          ctx.moveTo(pad, y);
          ctx.lineTo(pad + chartWidth, y);
          ctx.stroke();
        }
        if (!points || !points.length) {
          ctx.fillStyle = '#8ea5b9';
          ctx.font = '16px Segoe UI';
          ctx.fillText('No metrics collected yet.', pad, canvas.height / 2);
          return;
        }
        var epochs = [];
        for (var j = 0; j < points.length; j += 1) {
          var epoch = Date.parse((points[j] || {}).ts || '');
          if (!isNaN(epoch)) {
            epochs.push(epoch);
          }
        }
        if (!epochs.length) {
          ctx.fillStyle = '#8ea5b9';
          ctx.font = '16px Segoe UI';
          ctx.fillText('No timestamped metrics available.', pad, canvas.height / 2);
          return;
        }
        var firstEpoch = epochs[0];
        var lastEpoch = epochs[epochs.length - 1];
        var spanEpoch = Math.max(1, lastEpoch - firstEpoch);
        ctx.strokeStyle = '#67a8db';
        ctx.lineWidth = 2;
        var started = false;
        for (var k = 0; k < points.length; k += 1) {
          var point = points[k] || {};
          if (point.gap) {
            if (started) {
              ctx.stroke();
              started = false;
            }
            continue;
          }
          var pointEpoch = Date.parse(point.ts || '');
          var value = Number(point.cpu_percent || 0);
          if (isNaN(pointEpoch) || isNaN(value)) {
            continue;
          }
          var x = pad + (((pointEpoch - firstEpoch) / spanEpoch) * chartWidth);
          var yPoint = pad + chartHeight - ((Math.max(0, Math.min(100, value)) / 100) * chartHeight);
          if (!started) {
            ctx.beginPath();
            ctx.moveTo(x, yPoint);
            started = true;
          } else {
            ctx.lineTo(x, yPoint);
          }
        }
        if (started) {
          ctx.stroke();
        }
      }

      window.setMetricRange = function (hours) {
        var h = Number(hours) || 24;
        var b1 = document.getElementById('range1hBtn');
        var b24 = document.getElementById('range24hBtn');
        var b168 = document.getElementById('range168hBtn');
        if (b1) b1.classList[h === 1 ? 'add' : 'remove']('active');
        if (b24) b24.classList[h === 24 ? 'add' : 'remove']('active');
        if (b168) b168.classList[h === 168 ? 'add' : 'remove']('active');
        var title = document.getElementById('metricsTitle');
        if (title) {
          title.textContent = h === 1 ? 'PC Stats - Last Hour' : (h === 168 ? 'PC Stats - Last 7 Days' : 'PC Stats - Last 24 Hours');
        }
        var sep = authQuery() ? '&' : '?';
        fetchJson('/api/metrics' + sep + 'hours=' + h, function (_status, body) {
          var points = (body && body.points) ? body.points : [];
          drawLegacyMetrics(points);
          var sample = document.getElementById('metricsSampleAt');
          if (sample) {
            var latest = points.length ? ((points[points.length - 1] || {}).ts || '') : '';
            sample.textContent = latest ? ('Latest sample ' + latest) : 'Latest sample unknown';
          }
        });
      };

      if (document.getElementById('metricsChart')) {
        window.setMetricRange(24);
      }
      try {
        var initialTab = new URLSearchParams(window.location.search || '').get('tab');
        if (initialTab) {
          window.switchTab(initialTab);
        }
      } catch (_err) {
        // ignore tab parse issues
      }
    })();
  