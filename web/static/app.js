/* ============================================================
   Epyon Web Interface — app.js
   Vanilla JS single-page application
   ============================================================ */

'use strict';

// ── Finding detail registry (populated in buildFindingsSection) ──
const _findingsRegistry     = new Map();
let   _findingNextId        = 0;

// ── Findings sort state (per severity) ───────────────────────
const _currentFindingsBySev = {};
const _sortState             = {};

// ── Security helpers ──────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Formatting helpers ────────────────────────────────────────
function fmtDate(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return esc(ts); }
}

function ucFirst(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }

const _SCAN_TYPE_LABELS = {
  full:        'Full',
  quick:       'Quick',
  nightly:     'Nightly',
  baseline:    'Baseline',
  stig:        'STIG',
  local_model: 'Local Model',
};
function scanTypeLabel(type) {
  return _SCAN_TYPE_LABELS[type] || ucFirst(type || 'full');
}

function computeStatus(scan) {
  if (!scan || typeof scan !== 'object') return 'unknown';
  if ((scan.critical || 0) > 0) return 'critical';
  if ((scan.high    || 0) > 0) return 'high';
  if ((scan.medium  || 0) > 0) return 'medium';
  if ((scan.low     || 0) > 0) return 'low';
  if (scan.scan_id)             return 'clean';
  return 'unknown';
}

// ── UI atoms ──────────────────────────────────────────────────
function sevBadge(severity, count) {
  return `<span class="sev-badge ${esc(severity)}">${esc(count)} ${ucFirst(severity)}</span>`;
}

function sevBadgeRow(scan) {
  const parts = [];
  if (scan.critical > 0) parts.push(sevBadge('critical', scan.critical));
  if (scan.high     > 0) parts.push(sevBadge('high',     scan.high));
  if (scan.medium   > 0) parts.push(sevBadge('medium',   scan.medium));
  if (scan.low      > 0) parts.push(sevBadge('low',      scan.low));
  if (parts.length === 0) parts.push('<span class="sev-badge clean">✓ Clean</span>');
  return parts.join('');
}

function hfStatusBadge(scan) {
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  if (!ps && !mc) return '';
  const parts = [];
  if (ps) {
    if (ps.flagged_count > 0)
      parts.push(`<span class="sev-badge critical" title="Pickle safety: ${ps.flagged_count} infected file(s)">🥒 ${ps.flagged_count} infected</span>`);
    else
      parts.push(`<span class="sev-badge clean" title="Pickle safety: clean">🥒 Safe</span>`);
  }
  if (mc) {
    if (mc.failed > 0)
      parts.push(`<span class="sev-badge medium" title="Model card: ${mc.failed} check(s) failed">📋 ${mc.failed} failed</span>`);
    else if (mc.warnings > 0)
      parts.push(`<span class="sev-badge low" title="Model card: ${mc.warnings} warning(s)">📋 ${mc.warnings} warn</span>`);
    else
      parts.push(`<span class="sev-badge clean" title="Model card: compliant">📋 OK</span>`);
  }
  return parts.join('');
}

function statusBadge(status) {
  const labels = {
    critical: 'Critical', high: 'High', medium: 'Medium',
    low: 'Low', clean: 'Clean', unknown: 'Unknown',
  };
  return `<span class="status-badge ${esc(status)}">${labels[status] || 'Unknown'}</span>`;
}

function loading() {
  return '<div class="loading"><div class="spinner"></div>Loading…</div>';
}

function errBanner(msg) {
  return `<div class="error-banner">⚠ ${esc(msg)}</div>`;
}

function emptyState(title, desc, action = '') {
  return `
    <div class="empty-state">
      <h3>${esc(title)}</h3>
      <p>${esc(desc)}</p>
      ${action}
    </div>`;
}

function dedupeTools(arr) {
  return [...new Set(arr || [])];
}

// ── Chart helpers ─────────────────────────────────────────────
const _CC = {
  critical: '#ff7b72', high: '#ffa657', medium: '#e3b341', low: '#79c0ff',
};

function drawDonutChart(canvas, segments) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const W = 200, H = 200;
  canvas.width = W * dpr; canvas.height = H * dpr;
  canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
  ctx.scale(dpr, dpr);
  const cx = W / 2, cy = H / 2, R = 78, ir = 50;
  const total = segments.reduce((s, x) => s + (x.value || 0), 0);
  if (!total) {
    ctx.fillStyle = '#21262d';
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#161b22';
    ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#6e7681'; ctx.font = '12px sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('No data', cx, cy);
    return;
  }
  let angle = -Math.PI / 2;
  for (const seg of segments) {
    if (!seg.value) continue;
    const slice = (seg.value / total) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, angle, angle + slice); ctx.closePath();
    ctx.fillStyle = seg.color; ctx.fill();
    angle += slice;
  }
  ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2);
  ctx.fillStyle = '#161b22'; ctx.fill();
  ctx.fillStyle = '#e6edf3'; ctx.font = 'bold 22px sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(total.toLocaleString(), cx, cy - 9);
  ctx.fillStyle = '#8b949e'; ctx.font = '11px sans-serif';
  ctx.fillText('findings', cx, cy + 10);
}

function drawHBarChart(canvas, items) {
  if (!items.length) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w   = (canvas.parentElement ? canvas.parentElement.clientWidth - 40 : 400);
  const rowH = 36, h = items.length * rowH + 8;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  const labelW = 100, countW = 44, barArea = w - labelW - countW;
  const maxTotal = Math.max(...items.map(x => x.total), 1);
  items.forEach((item, i) => {
    const barH = 20, barY = i * rowH + (rowH - barH) / 2;
    ctx.fillStyle = '#21262d';
    ctx.fillRect(labelW, barY, barArea, barH);
    let xOff = labelW;
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      const val = item[sev] || 0;
      if (!val) continue;
      const bw = Math.max(1, Math.round((val / maxTotal) * barArea));
      ctx.fillStyle = _CC[sev];
      ctx.fillRect(xOff, barY, bw, barH);
      xOff += bw;
    }
    ctx.fillStyle = '#8b949e';
    ctx.font = '12px -apple-system, sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    const lbl = item.label.length > 13 ? item.label.slice(0, 12) + '…' : item.label;
    ctx.fillText(lbl, labelW - 8, barY + barH / 2);
    ctx.textAlign = 'left';
    ctx.fillText(item.total, labelW + barArea + 8, barY + barH / 2);
  });
}

function drawLineChart(canvas, series, xLabels) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = (canvas.parentElement ? canvas.parentElement.clientWidth - 40 : 600);
  const h = 200;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  const n = xLabels.length;
  if (!n) return;
  const pad = { top: 16, right: 16, bottom: 36, left: 44 };
  const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
  const maxV = Math.max(...series.flatMap(s => s.data), 1);
  ctx.strokeStyle = '#21262d'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + ch * (1 - i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
    ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(maxV * i / 4), pad.left - 5, y);
  }
  const step = Math.max(1, Math.floor(n / 12));
  ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  for (let i = 0; i < n; i += step) {
    const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
    ctx.fillText(xLabels[i].slice(5, 10), x, pad.top + ch + 6);
  }
  for (const s of series) {
    if (!s.data.some(v => v > 0)) continue;
    ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
    ctx.beginPath();
    s.data.forEach((v, i) => {
      const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
      const y = pad.top + ch * (1 - v / maxV);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  }
}

// ── API client ────────────────────────────────────────────────
const api = {
  async _get(url) {
    const r = await fetch(url);
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  async _post(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  async _delete(url) {
    const r = await fetch(url, { method: 'DELETE' });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  getStats()          { return this._get('/api/stats'); },
  getApplications()   { return this._get('/api/applications'); },
  getHiddenApps()     { return this._get('/api/applications-hidden'); },
  hideApp(name)       { return this._delete(`/api/applications/${encodeURIComponent(name)}`); },
  restoreApp(name)    { return this._post(`/api/applications/${encodeURIComponent(name)}/restore`, {}); },
  deleteApp(name)     { return this._delete(`/api/applications/${encodeURIComponent(name)}/data`); },
  deleteScan(id)      { return this._delete(`/api/scans/${encodeURIComponent(id)}`); },
  registerApp(name, url) {
    return this._post('/api/applications', { name, url });
  },
  getAppScans(name)   { return this._get(`/api/applications/${encodeURIComponent(name)}/scans`); },
  getScan(id)         { return this._get(`/api/scans/${encodeURIComponent(id)}`); },
  getScanHistory()    { return this._get('/api/scan-history'); },
  getApprovedImages() { return this._get('/api/settings/approved-images'); },
  getGitHubConfig()   { return this._get('/api/github/config'); },
  saveGitHubConfig(d) { return this._post('/api/github/config', d); },
  triggerGitHubSync() { return this._post('/api/github/sync', {}); },
  getGitHubSyncStatus(){ return this._get('/api/github/sync'); },
  triggerScan(target, scanType, runGarak) {
    const body = { target, scan_type: scanType };
    if (runGarak) body.run_garak = true;
    return this._post('/api/scans', body);
  },
  getJob(id)    { return this._get(`/api/jobs/${encodeURIComponent(id)}`); },
  getJobs()     { return this._get('/api/jobs'); },
  getMetrics()  { return this._get('/api/metrics'); },
  getAiConfig() { return this._get('/api/ai/config'); },
  saveAiConfig(d){ return this._post('/api/ai/config', d); },
  getStigData(id){ return this._get(`/api/scans/${encodeURIComponent(id)}/stig-data`); },
};

// ── Navigation ────────────────────────────────────────────────
function setActive(routeKey) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeKey);
  });
  // Clear findings registry and close any open drawer on navigation
  _findingsRegistry.clear();
  _findingNextId = 0;
  for (const k of Object.keys(_currentFindingsBySev)) delete _currentFindingsBySev[k];
  for (const k of Object.keys(_sortState))             delete _sortState[k];
  closeFindingDetail();
}

function navigate(hash) {
  window.location.hash = hash;
}

// ── Views ─────────────────────────────────────────────────────

async function renderOverview() {
  setActive('overview');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [stats, apps] = await Promise.all([api.getStats(), api.getApplications()]);

    const appCards = apps.length
      ? apps.map(app => `
          <div class="app-card status-${esc(app.status)}"
               onclick="navigate('#/applications/${encodeURIComponent(app.name)}')">
            <div class="app-card-header">
              <span class="app-name">${esc(app.name)}</span>
              ${statusBadge(app.status)}
            </div>
            <div class="app-card-meta">
              ${app.last_scanned
                ? `Last scanned: ${fmtDate(app.last_scanned)} · ${esc(app.scan_type || 'full')}`
                : 'Never scanned'}
            </div>
            <div class="severity-row">${sevBadgeRow(app)}</div>
            <div class="app-card-footer">
              ${app.scan_count} scan${app.scan_count !== 1 ? 's' : ''} total
            </div>
          </div>`).join('')
      : emptyState(
          'No applications yet',
          'Run your first scan to see applications here.',
          `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">
             ▶ Run First Scan
           </button>`,
        );

    page.innerHTML = `
      <div class="page-header">
        <h1>Security Overview</h1>
        <button class="btn btn-primary" onclick="navigate('#/new-scan')">+ Run Scan</button>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${esc(stats.total_applications)}</div>
          <div class="stat-label">Applications</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(stats.total_scans)}</div>
          <div class="stat-label">Total Scans</div>
        </div>
        <div class="stat-card critical">
          <div class="stat-value">${esc(stats.critical)}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="stat-value">${esc(stats.high)}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-value">${esc(stats.medium)}</div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card low">
          <div class="stat-value">${esc(stats.low)}</div>
          <div class="stat-label">Low</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">
          Applications
          <button class="btn btn-sm" onclick="navigate('#/applications')">View all →</button>
        </div>
        <div class="app-grid">${appCards}</div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderApplications() {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [apps, hidden] = await Promise.all([api.getApplications(), api.getHiddenApps()]);

    const rows = apps.length
      ? apps.map(app => `
          <tr onclick="navigate('#/applications/${encodeURIComponent(app.name)}')"
              style="cursor:pointer">
            <td>
              <strong>${esc(app.name)}</strong>
              ${app.url ? `<div style="font-size:11px;color:var(--text-dim);margin-top:2px">${esc(app.url)}</div>` : ''}
            </td>
            <td>${app.last_scanned ? fmtDate(app.last_scanned) : '<span style="color:var(--text-dim)">Never</span>'}</td>
            <td>${esc(app.scan_count)}</td>
            <td>${app.critical > 0
                  ? `<span class="sev-badge critical">${app.critical}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.high > 0
                  ? `<span class="sev-badge high">${app.high}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.medium > 0
                  ? `<span class="sev-badge medium">${app.medium}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.low > 0
                  ? `<span class="sev-badge low">${app.low}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${statusBadge(app.status)}</td>
            <td>
              <button class="btn btn-sm"
                onclick="event.stopPropagation();navigate('#/new-scan')">
                Scan
              </button>
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();hideApplication('${esc(app.name)}')"
                title="Hide this application from the list">
                Hide
              </button>
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();deleteApplication('${esc(app.name)}')"
                title="Permanently delete all scan data for this application">
                Delete
              </button>
            </td>
          </tr>`).join('')
      : `<tr><td colspan="9" style="text-align:center;padding:48px;color:var(--text-muted)">
           No applications found. Run a scan to get started.
         </td></tr>`;

    const hiddenSection = hidden.length ? `
      <div class="section" style="margin-top:32px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
          <span>Hidden Applications <span style="font-size:12px;color:var(--text-muted);font-weight:400">(${hidden.length})</span></span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Application</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${hidden.map(name => `
                <tr>
                  <td style="color:var(--text-muted)">${esc(name)}</td>
                  <td>
                    <button class="btn btn-sm"
                      onclick="restoreApplication('${esc(name)}')">
                      Restore
                    </button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : '';

    page.innerHTML = `
      <div class="page-header">
        <h1>Applications</h1>
        <div style="display:flex;gap:8px">
          <button class="btn" onclick="showAddAppModal()">+ Add Application</button>
          <button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Application</th>
              <th>Last Scanned</th>
              <th>Scans</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${hiddenSection}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderAppDetail(name) {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    // Load scans and registered app info in parallel
    const [scans, allApps] = await Promise.all([
      api.getAppScans(name),
      api.getApplications(),
    ]);
    const appInfo = allApps.find(a => a.name === name) || {};
    const appUrl  = appInfo.url || '';
    const latest = scans[0] || {};
    const status  = computeStatus(latest);

    const timelineItems = scans.length
      ? scans.map(s => {
          const st = computeStatus(s);
          return `
            <div class="scan-timeline-item"
                 onclick="navigate('#/scans/${encodeURIComponent(s.scan_id)}')">
              <div class="scan-timeline-dot ${esc(st)}"></div>
              <div class="scan-timeline-content">
                <div class="scan-timeline-title">
                  ${esc(scanTypeLabel(s.scan_type))} scan
                  <span>${sevBadgeRow(s)}</span>
                  ${hfStatusBadge(s)}
                  ${s.ci_source ? `<span class="badge badge-ci" title="From GitHub Actions · ${esc(s.ci_source.repo)}${s.ci_source.branch ? ' · ' + esc(s.ci_source.branch) : ''}">GH Actions</span>` : ''}
                </div>
                <div class="scan-timeline-meta">
                  ${fmtDate(s.timestamp)}
                  ${s.user ? ` · ${esc(s.user)}` : ''}
                  ${s.location ? ` · <code>${esc(s.location)}</code>` : ''}
                </div>
                ${dedupeTools(s.tools_analyzed).length ? `
                  <div class="tools-list" style="margin-top:8px">
                    ${dedupeTools(s.tools_analyzed).map(t =>
                      `<span class="tool-tag">${esc(t)}</span>`).join('')}
                  </div>` : ''}
              </div>
              ${s.has_dashboard
                ? `<button class="btn btn-sm"
                     onclick="event.stopPropagation();window.open('/api/scans/${encodeURIComponent(s.scan_id)}/dashboard','_blank')">
                     Dashboard ↗
                   </button>`
                : ''}
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();deleteScan('${esc(s.scan_id)}', '${esc(name)}')"
                title="Permanently delete this scan">
                Delete
              </button>
            </div>`;
        }).join('')
      : emptyState(
          `No scans found for "${name}"`,
          appUrl ? `Repository: ${appUrl}` : 'Run a scan to populate history.',
          appUrl
            ? `<div style="display:flex;gap:8px;justify-content:center;margin-top:16px">
                 <button class="btn btn-primary"
                   onclick="navigate('#/new-scan?target=${encodeURIComponent(appUrl)}')">
                   ▶ Run First Scan
                 </button>
               </div>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">
                 ▶ Run Scan
               </button>`,
        );

    const statsSection = scans.length ? `
      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Total Scans</div>
          <div class="value">${esc(scans.length)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Last Scanned</div>
          <div class="value" style="font-size:13px">${fmtDate(latest.timestamp)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${latest.critical || 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${latest.high || 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${latest.medium || 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${latest.low || 0}</div>
        </div>
      </div>` : '';

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <span>${esc(name)}</span>
      </div>
      <div class="page-header">
        <h1>${esc(name)} ${statusBadge(status)}</h1>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary"
            onclick="navigate('#/new-scan?target=${encodeURIComponent(appUrl)}')">
            ▶ Run Scan
          </button>
          <button class="btn btn-danger"
            onclick="hideApplication('${esc(name)}')"
            title="Hide this application from the list">
            Hide
          </button>
          <button class="btn btn-danger"
            onclick="deleteApplication('${esc(name)}')"
            title="Permanently delete all scan data for this application">
            Delete All
          </button>
        </div>
      </div>
      ${statsSection}
      <div class="section">
        <div class="section-title">Scan History</div>
        <div class="scan-timeline">${timelineItems}</div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderScanDetail(scanId) {
  setActive('');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, allApps] = await Promise.all([api.getScan(scanId), api.getApplications()]);
    const status = computeStatus(scan);
    const appInfo = allApps.find(a => a.name === scan.target) || {};
    const repoUrl = appInfo.url || scan.ci_source?.repo || '';

    // Build STIG summary card if STIG data is present
    let stigCard = '';
    if ((scan.stig_total || 0) > 0) {
      const reports = scan.stig_reports || [];
      const multiStig = reports.length > 1;

      // Per-STIG rows (shown when multiple STIGs)
      const perStigRows = multiStig ? reports.map(r => {
        const slugLabel = r.slug.replace(/-/g, ' ').replace(/\bstig\b/gi, 'STIG');
        const mdBtn   = r.has_md   ? `<a class="btn btn-sm" href="${esc(r.md_url)}"   download>↓ .md</a>`   : '';
        const cklbBtn = r.has_cklb ? `<a class="btn btn-sm" href="${esc(r.cklb_url)}" download>↓ .cklb</a>` : '';
        return `
          <div class="stig-row">
            <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
            <span class="stig-row-counts">
              <span class="stig-mini open">${esc(r.open)} open</span>
              <span class="stig-mini pass">${esc(r.pass)} pass</span>
              <span class="stig-mini na">${esc(r.na)} n/a</span>
              <span class="stig-mini total">${esc(r.total)} total</span>
            </span>
            <span class="stig-row-btns">${mdBtn}${cklbBtn}</span>
          </div>`;
      }).join('') : '';

      // Primary (combined) download buttons
      const mdBtn = scan.has_stig_report
        ? `<a class="btn btn-sm" href="${esc(scan.stig_report_url)}" download>↓ findings.md</a>` : '';
      const cklbBtn = scan.has_stig_cklb
        ? `<a class="btn btn-sm" href="${esc(scan.stig_cklb_url)}" download>↓ findings.cklb</a>` : '';

      stigCard = `
        <div class="stig-summary-card">
          <div class="stig-summary-header">
            <div class="stig-summary-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              STIG Assessment ${multiStig ? `<span style="color:var(--text-muted);font-weight:400;font-size:12px">(${reports.length} STIGs)</span>` : ''}
            </div>
            <div class="stig-download-btns">${mdBtn}${cklbBtn}</div>
          </div>
          <div class="stig-counts">
            <div class="stig-count open">
              <span class="num">${esc(scan.stig_open || 0)}</span>
              <span class="lbl">Open</span>
            </div>
            <div class="stig-count pass">
              <span class="num">${esc(scan.stig_pass || 0)}</span>
              <span class="lbl">Not a Finding</span>
            </div>
            <div class="stig-count na">
              <span class="num">${esc(scan.stig_na || 0)}</span>
              <span class="lbl">N/A</span>
            </div>
            <div class="stig-count total">
              <span class="num">${esc(scan.stig_total || 0)}</span>
              <span class="lbl">Total</span>
            </div>
          </div>
          ${multiStig ? `<div class="stig-per-stig">${perStigRows}</div>` : ''}
          <div class="stig-view-btn-row">
            <button class="btn btn-primary btn-sm"
              onclick="navigate('#/stig-viewer/${encodeURIComponent(scanId)}')">
              ⊞ View Findings Inline
            </button>
          </div>
        </div>`;
    }

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <a href="#/applications/${encodeURIComponent(scan.target)}"
           onclick="navigate('#/applications/${encodeURIComponent(scan.target)}')">
          ${esc(scan.target)}
        </a>
        <span>›</span>
        <span>${esc(scan.scan_id)}</span>
      </div>

      <div class="page-header">
        <h1>Scan Details ${statusBadge(status)}</h1>
        <div style="display:flex;gap:8px">
          ${repoUrl
            ? `<button class="btn btn-primary"
                 onclick="navigate('#/new-scan?target=${encodeURIComponent(repoUrl)}')">
                 ▶ Run Scan
               </button>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>`}
          ${scan.has_dashboard
            ? `<button class="btn"
                 onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/dashboard','_blank')">
                 View Dashboard ↗
               </button>`
            : ''}
          <button class="btn btn-danger"
            onclick="deleteScan('${esc(scanId)}', '${esc(scan.target)}')"
            title="Permanently delete this scan">
            Delete Scan
          </button>
        </div>
      </div>

      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Application</div>
          <div class="value">${esc(scan.target)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Scan Type</div>
          <div class="value">${esc(scanTypeLabel(scan.scan_type))}</div>
        </div>
        <div class="detail-card">
          <div class="label">User</div>
          <div class="value">${esc(scan.user || '—')}</div>
        </div>
        <div class="detail-card">
          <div class="label">Timestamp</div>
          <div class="value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${esc(scan.critical)}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${esc(scan.high)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${esc(scan.medium)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${esc(scan.low)}</div>
        </div>
      </div>

      ${buildFindingsSection(scan.findings)}

      ${stigCard}

      ${buildModelSecurityCard(scan)}

      ${dedupeTools(scan.tools_analyzed).length ? `
        <div class="section">
          <div class="section-title">Tools Analyzed</div>
          <div class="tools-list">
            ${dedupeTools(scan.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}

      ${buildSBOMSection(scan.sbom)}

      ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
        <div class="section">
          <div class="section-title">File Statistics</div>
          <div class="detail-grid">
            ${Object.entries(scan.file_statistics).map(([k, v]) => `
              <div class="detail-card">
                <div class="label">${esc(k.replace(/_/g, ' '))}</div>
                <div class="value">${esc(v)}</div>
              </div>`).join('')}
          </div>
        </div>` : ''}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

function buildPicklescanCard(scan) { return ''; } // merged into buildModelSecurityCard

function buildModelCardCard(scan) { return ''; }  // merged into buildModelSecurityCard

function buildModelSecurityCard(scan) {
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  if (!ps && !mc) return '';

  // ── Pickle section ──
  let pickleSection = '';
  if (ps) {
    const statusClass = ps.flagged_count > 0 ? 'status-open' : 'status-clean';
    const statusLabel = ps.flagged_count > 0 ? `${ps.flagged_count} infected file(s)` : 'Clean';
    const icon = ps.flagged_count > 0 ? '🚨' : '✅';
    const totalWeightFiles = ps.total_weight_files ?? ps.file_count ?? 0;

    const RISK_CONFIG = {
      critical: { cls: 'fmt-risk-critical', label: 'CRITICAL' },
      high:     { cls: 'fmt-risk-high',     label: 'HIGH' },
      medium:   { cls: 'fmt-risk-medium',   label: 'MEDIUM' },
      low:      { cls: 'fmt-risk-low',      label: 'LOW' },
      safe:     { cls: 'fmt-risk-safe',     label: 'SAFE' },
    };

    const fmtRows = (ps.weight_formats || []).map(f => {
      const rc = RISK_CONFIG[f.risk] || RISK_CONFIG.medium;
      const pickleWarn = f.pickle_scannable
        ? `<span class="fmt-pickle-flag" title="Scanned by picklescan">🔬</span>`
        : `<span class="fmt-safe-flag" title="No pickle — not code-executable">🛡️</span>`;
      return `
        <div class="fmt-row fmt-row-${f.risk}">
          <code class="fmt-ext">${esc(f.label)}</code>
          <span class="fmt-risk-badge ${rc.cls}">${rc.label}</span>
          ${pickleWarn}
          <span class="fmt-count">${f.count} file${f.count !== 1 ? 's' : ''}</span>
          <span class="fmt-notes">${esc(f.notes)}</span>
        </div>`;
    }).join('');

    const psFindings = (ps.findings || []).map(f => `
      <div class="hf-finding-row">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.message || 'Malicious pickle opcode detected')}</span>
      </div>`).join('');

    pickleSection = `
      <div class="ms-layer">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🥒</span>
            <span>Layer 14 — Pickle / Serialization Safety</span>
            <span class="hf-tool-name">picklescan</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${totalWeightFiles}</span><span class="hf-stat-lbl">weight files</span></div>
          <div class="hf-stat"><span class="hf-stat-num">${ps.file_count ?? 0}</span><span class="hf-stat-lbl">pickle-scannable</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${ps.flagged_count > 0 ? 'danger' : ''}">${ps.flagged_count ?? 0}</span><span class="hf-stat-lbl">infected</span></div>
        </div>
        ${fmtRows ? `<div class="fmt-inventory" style="margin:10px -1px -1px">${'<div class="fmt-inventory-title">Weight Format Inventory</div>'}${fmtRows}</div>` : ''}
        ${psFindings ? `<div class="hf-findings" style="margin-top:10px">${psFindings}</div>` : ''}
      </div>`;
  }

  // ── Model card section ──
  let modelCardSection = '';
  if (mc) {
    const statusClass = mc.failed > 0 ? 'status-open' : mc.warnings > 0 ? 'status-warn' : 'status-clean';
    const statusLabel = mc.failed > 0 ? `${mc.failed} check(s) failed` : mc.warnings > 0 ? `${mc.warnings} warning(s)` : 'Compliant';
    const icon = mc.failed > 0 ? '❌' : mc.warnings > 0 ? '⚠️' : '✅';
    const fileLabel = mc.file_checked
      ? `<span class="hf-file-checked" title="${esc(mc.file_checked)}">${esc(mc.file_checked.split('/').pop())}</span>`
      : '';

    const mcFindings = (mc.findings || []).map(f => `
      <div class="hf-finding-row">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'medium')}">${esc(f.severity || 'medium')}</span>
        <span class="hf-finding-file">${esc(f.check || '—')}</span>
        <span class="hf-finding-msg">${esc(f.message || '')}${f.recommendation ? `<span class="hf-recommendation"> → ${esc(f.recommendation)}</span>` : ''}</span>
      </div>`).join('');

    modelCardSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">📋</span>
            <span>Layer 15 — Model Card Compliance</span>
            ${fileLabel}
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${(mc.passed ?? 0) + (mc.failed ?? 0) + (mc.warnings ?? 0)}</span><span class="hf-stat-lbl">checks</span></div>
          <div class="hf-stat"><span class="hf-stat-num clean">${mc.passed ?? 0}</span><span class="hf-stat-lbl">passed</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${mc.failed > 0 ? 'danger' : ''}">${mc.failed ?? 0}</span><span class="hf-stat-lbl">failed</span></div>
          <div class="hf-stat"><span class="hf-stat-num">${mc.warnings ?? 0}</span><span class="hf-stat-lbl">warnings</span></div>
        </div>
        ${mcFindings ? `<div class="hf-findings" style="margin-top:10px">${mcFindings}</div>` : ''}
      </div>`;
  }

  // ── Combined status for the summary line ──
  const hasIssues = (ps?.flagged_count > 0) || (mc?.failed > 0) || (mc?.warnings > 0);
  const summaryBadgeClass = (ps?.flagged_count > 0 || mc?.failed > 0) ? 'status-open' : mc?.warnings > 0 ? 'status-warn' : 'status-clean';
  const summaryIcon       = (ps?.flagged_count > 0 || mc?.failed > 0) ? '⚠' : '✓';
  const summaryLabel      = hasIssues ? 'Issues found' : 'All clear';

  return `
    <details class="ms-card" id="model-security-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Model Security</span>
          ${ps ? '<span class="tool-tag" style="font-size:11px">picklescan</span>' : ''}
          ${mc ? '<span class="tool-tag" style="font-size:11px">model card</span>' : ''}
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${summaryBadgeClass}">${summaryIcon} ${summaryLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        ${pickleSection}
        ${modelCardSection}
      </div>
    </details>`;
}

function buildSBOMSection(sbom) {
  if (!sbom || sbom.total === 0) return '';
  const byType = sbom.by_type || {};
  const typeChips = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<span class="tool-tag" style="cursor:default">${esc(t)} <strong>${n}</strong></span>`)
    .join('');
  const id = 'sbom-pkg-list-' + Math.random().toString(36).slice(2);
  const rows = (sbom.packages || []).map(p => {
    const lic = (p.licenses || []).filter(Boolean).join(', ') || '';
    return `<tr>
      <td style="font-family:monospace;font-size:12px">${esc(p.name)}</td>
      <td style="font-size:12px">${esc(p.version || '')}</td>
      <td><span class="tool-tag" style="font-size:11px;padding:1px 6px">${esc(p.type || '')}</span></td>
      <td style="font-size:11px;color:#888">${esc(lic)}</td>
    </tr>`;
  }).join('');
  return `
    <div class="section">
      <div class="section-title">📦 SBOM — ${esc(sbom.total)} Packages</div>
      <div class="tools-list" style="margin-bottom:10px">${typeChips}</div>
      <details id="${esc(id)}">
        <summary style="cursor:pointer;font-size:13px;color:#6b7280">Show all packages</summary>
        <div style="overflow-x:auto;margin-top:8px">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid #374151">
                <th style="padding:4px 8px">Name</th>
                <th style="padding:4px 8px">Version</th>
                <th style="padding:4px 8px">Type</th>
                <th style="padding:4px 8px">License</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </details>
    </div>`;
}

function _buildFindingRows(items) {
  return items.map(f => {
    const fid    = _registerFinding(f);
    const id     = esc(f.id    || f.cve_id || '—');
    const tool   = esc(f.tool  || '—');
    const pkg    = esc(f.package || f.component || f.target || '—');
    const ver    = esc(f.version || '');
    const fixed  = esc(f.fixed_version || '');
    const title  = esc((f.title || f.description || f.check_name || '').substring(0, 160));
    const target = esc((f.target || '').substring(0, 80));

    const idCell = id.startsWith('CVE-')
      ? `<a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer"
            onclick="event.stopPropagation()"><code>${id}</code></a>`
      : `<code>${id}</code>`;

    return `
      <tr class="finding-row" onclick="openFindingDetail(${fid})" title="Click to view details">
        <td><span class="tool-tag">${tool}</span></td>
        <td>${idCell}</td>
        <td style="max-width:360px">${title}</td>
        <td>${pkg}${ver ? ` <span style="color:var(--text-dim);font-size:11px">${ver}</span>` : ''}</td>
        <td>${fixed ? `<span style="color:var(--clean)">${fixed}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
        <td style="color:var(--text-muted);font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${target}">${target || '—'}</td>
      </tr>`;
  }).join('');
}

window.sortFindingsBy = function(sev, col) {
  const state = _sortState[sev] || { col: null, dir: 'asc' };
  if (state.col === col) {
    state.dir = state.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.col = col;
    state.dir = 'asc';
  }
  _sortState[sev] = state;

  const items = [...(_currentFindingsBySev[sev] || [])];
  const dir   = state.dir === 'asc' ? 1 : -1;

  items.sort((a, b) => {
    let av, bv;
    switch (col) {
      case 'tool':    av = (a.tool    || '').toLowerCase(); bv = (b.tool    || '').toLowerCase(); break;
      case 'id':      av = (a.id     || a.cve_id || '').toLowerCase(); bv = (b.id || b.cve_id || '').toLowerCase(); break;
      case 'title':   av = (a.title  || a.description || '').toLowerCase(); bv = (b.title || b.description || '').toLowerCase(); break;
      case 'package': av = (a.package || a.component || '').toLowerCase(); bv = (b.package || b.component || '').toLowerCase(); break;
      case 'fix':     av = a.fixed_version ? 1 : 0; bv = b.fixed_version ? 1 : 0; break;
      case 'target':  av = (a.target  || '').toLowerCase(); bv = (b.target  || '').toLowerCase(); break;
      default: return 0;
    }
    if (typeof av === 'string') return dir * av.localeCompare(bv);
    return dir * (av - bv);
  });

  const tbody = document.getElementById(`findings-tbody-${sev}`);
  if (tbody) tbody.innerHTML = _buildFindingRows(items);

  // Update sort-direction indicator on th elements
  const section = document.getElementById(`findings-section-${sev}`);
  if (section) {
    section.querySelectorAll('.sortable-th').forEach(th => {
      if (th.dataset.col === col) {
        th.dataset.sortDir = state.dir;
      } else {
        delete th.dataset.sortDir;
      }
    });
  }
};

function buildFindingsSection(findings) {
  const severities = ['critical', 'high', 'medium', 'low'];
  let html = '';
  let anyFindings = false;

  // Reset sort state for this render
  for (const sev of severities) {
    _currentFindingsBySev[sev] = [];
    _sortState[sev] = { col: null, dir: 'asc' };
  }

  for (const sev of severities) {
    const allItems = findings[`${sev}_findings`] || [];
    if (!allItems.length) continue;
    anyFindings = true;

    const items = allItems.slice(0, 200);
    _currentFindingsBySev[sev] = items;

    const overflow = allItems.length > 200
      ? `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:12px">
           … and ${allItems.length - 200} more. Open the Dashboard for the full list.
         </td></tr>` : '';

    html += `
      <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
            <span class="sev-badge ${esc(sev)}">${allItems.length}</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body">
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th class="sortable-th" data-col="tool"    onclick="sortFindingsBy('${sev}','tool')">Tool <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="id"      onclick="sortFindingsBy('${sev}','id')">CVE / ID <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="title"   onclick="sortFindingsBy('${sev}','title')">Title <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="package" onclick="sortFindingsBy('${sev}','package')">Package <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="fix"     onclick="sortFindingsBy('${sev}','fix')">Fix Available <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="target"  onclick="sortFindingsBy('${sev}','target')">Location <span class="sort-icon">⇅</span></th>
                </tr>
              </thead>
              <tbody id="findings-tbody-${esc(sev)}">${_buildFindingRows(items)}${overflow}</tbody>
            </table>
          </div>
        </div>
      </details>`;
  }

  if (!anyFindings) {
    return `
      <div class="section">
        <div class="section-title">Findings</div>
        <span class="sev-badge clean" style="padding:8px 16px">✓ No findings detected</span>
      </div>`;
  }

  return `
    <div class="section findings-section-wrapper">
      <div class="section-title">Findings</div>
      ${html}
    </div>`;
}

// ─────────────────────────────────────────────────────────────
// STIG page — shows all apps with their latest STIG scan status

async function renderStig() {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const apps = await api.getApplications();
    const stigApps = apps.filter(a => (a.stig_total || 0) > 0);

    const cards = stigApps.length
      ? stigApps.map(app => {
          const stigScanId = app.latest_stig_scan_id || app.latest_scan_id;
          const mdUrl   = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-md`;
          const cklbUrl = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-cklb`;
          const mdBtn   = app.has_stig_report
            ? `<a class="btn btn-sm" href="${esc(mdUrl)}" download>↓ findings.md</a>` : '';
          const cklbBtn = app.has_stig_cklb
            ? `<a class="btn btn-sm" href="${esc(cklbUrl)}" download>↓ findings.cklb</a>` : '';
          return `
            <div class="stig-app-card">
              <div class="stig-app-card-header">
                <span class="stig-app-name"
                      onclick="navigate('#/applications/${encodeURIComponent(app.name)}')">
                  ${esc(app.name)}
                </span>
                <div class="stig-download-btns">${mdBtn}${cklbBtn}</div>
              </div>
              <div class="stig-counts">
                <div class="stig-count open">
                  <span class="num">${esc(app.stig_open || 0)}</span>
                  <span class="lbl">Open</span>
                </div>
                <div class="stig-count pass">
                  <span class="num">${esc(app.stig_pass || 0)}</span>
                  <span class="lbl">Not a Finding</span>
                </div>
                <div class="stig-count na">
                  <span class="num">${esc(app.stig_na || 0)}</span>
                  <span class="lbl">N/A</span>
                </div>
                <div class="stig-count total">
                  <span class="num">${esc(app.stig_total || 0)}</span>
                  <span class="lbl">Total</span>
                </div>
              </div>
              <div style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                <span style="font-size:12px;color:var(--text-muted)">Last scanned: ${fmtDate(app.last_scanned)}</span>
                <button class="btn btn-primary btn-sm"
                  onclick="navigate('#/stig-viewer/${encodeURIComponent(stigScanId)}')">
                  ⊞ View Findings
                </button>
                <button class="btn btn-sm"
                  onclick="navigate('#/scans/${encodeURIComponent(stigScanId)}')">
                  Scan Details →
                </button>
              </div>
            </div>`;
        }).join('')
      : emptyState(
          'No STIG results yet',
          'STIG scans run automatically every Sunday night. You can also trigger one manually using Run Scan → STIG.',
          `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">
             ▶ Run STIG Scan
           </button>`,
        );

    // Aggregate totals
    const totOpen  = stigApps.reduce((s, a) => s + (a.stig_open  || 0), 0);
    const totPass  = stigApps.reduce((s, a) => s + (a.stig_pass  || 0), 0);
    const totNa    = stigApps.reduce((s, a) => s + (a.stig_na    || 0), 0);
    const totTotal = stigApps.reduce((s, a) => s + (a.stig_total || 0), 0);

    const summaryBar = stigApps.length ? `
      <div class="stats-grid" style="margin-bottom:24px">
        <div class="stat-card">
          <div class="stat-value">${esc(stigApps.length)}</div>
          <div class="stat-label">Apps with STIG data</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-open)">
          <div class="stat-value" style="color:var(--stig-open)">${esc(totOpen)}</div>
          <div class="stat-label">Total Open</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-pass)">
          <div class="stat-value" style="color:var(--stig-pass)">${esc(totPass)}</div>
          <div class="stat-label">Total Passing</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(totNa)}</div>
          <div class="stat-label">N/A</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--accent)">${esc(totTotal)}</div>
          <div class="stat-label">Total Controls</div>
        </div>
      </div>` : '';

    page.innerHTML = `
      <div class="page-header">
        <h1>STIG Compliance</h1>
        <button class="btn btn-primary"
          onclick="navigate('#/new-scan')">▶ Run STIG Scan</button>
      </div>
      <p class="section-desc">
        Application Security Developer (AppSecDev) STIG and Crunchy Data PostgreSQL STIG
        compliance results. Scans run every Sunday night automatically.
      </p>
      ${summaryBar}
      <div class="section">
        <div class="section-title">Applications</div>
        ${cards}
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

let _pollInterval = null;
let _lastLogLen   = 0;
let _activeJobId  = null;

async function renderNewScan(prefill = '') {
  setActive('new-scan');
  clearInterval(_pollInterval);
  _pollInterval = null;
  _lastLogLen   = 0;

  const page = document.getElementById('page');
  page.innerHTML = `
    <div class="page-header">
      <h1>Run New Scan</h1>
    </div>
    <p class="section-desc">
      Launch a security scan against a local directory or Git repository.
      Epyon orchestrates all applicable security layers based on the selected scan type.
    </p>

    <div class="scan-page-layout">
      <div class="form-card scan-form-col">
        <div class="form-group" id="std-target-field">
          <label for="scan-target">Target</label>
          <input type="text" id="scan-target" autocomplete="off" spellcheck="false"
            placeholder="/absolute/path/to/project  or  https://github.com/org/repo.git"
            value="${esc(prefill)}" />
          <small>Absolute local directory path, relative path, or Git repository URL (HTTPS/SSH)</small>
        </div>

        <div class="form-group">
          <label for="scan-type-sel">Scan Type</label>
          <select id="scan-type-sel" onchange="updateScanInfo(this.value); _onScanTypeChange(this.value)">
            <option value="full">Full — All security layers (recommended)</option>
            <option value="quick">Quick — Fast check: Trivy, TruffleHog, SBOM</option>
            <option value="nightly">Nightly — Scheduled comprehensive scan (layers 1–12)</option>
            <option value="baseline">Baseline — Establish initial security benchmark (all layers)</option>
            <option value="stig">STIG — STIG compliance assessment only (on demand)</option>
            <option value="local_model">Local Model — Scan model weights in a local directory (layers 14–15)</option>
          </select>
        </div>

        <div class="form-group" id="garak-checkbox-row">
          <label class="checkbox-label">
            <input type="checkbox" id="run-garak-chk" />
            Run Garak LLM security scan (Layer 12)
          </label>
          <small>Requires <code>OPENAI_API_KEY</code> to be set.</small>
        </div>

        <button id="run-btn" class="btn btn-primary" onclick="submitScan()">
          ▶ Run Scan
        </button>
      </div>

      <div class="scan-info-panel" id="scan-info-panel"></div>
    </div>

    <div id="scan-output" style="display:none">
      <div style="margin-top:28px;margin-bottom:12px;display:flex;align-items:center;gap:12px">
        <div id="job-status-bar"></div>
        <button id="cancel-btn" class="btn btn-sm" style="display:none"
                onclick="cancelScan()">✕ Cancel</button>
      </div>
      <div class="log-card" id="log-output"></div>
      <div id="scan-actions" style="display:none;gap:10px;margin-top:16px"></div>
    </div>`;

  updateScanInfo('full');
}

const _SCAN_MODE_INFO = {
  full: {
    label: 'Full Scan',
    desc: 'Comprehensive security assessment running all available layers. Recommended for thorough coverage.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layers 14–15 auto-run when model weight files are detected.'],
  },
  nightly: {
    label: 'Nightly Scan',
    desc: 'Identical to Full. Designed for scheduled overnight runs — layers 1–12 with optional Garak.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layers 14–15 auto-run when model weight files are detected.'],
  },
  quick: {
    label: 'Quick Scan',
    desc: 'Fast security check for rapid feedback. Skips heavier analysis tools to minimize runtime.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
    ],
    notes: ['Skips: SonarQube, ClamAV, Checkov, Anchore, Garak, STIG.'],
  },
  stig: {
    label: 'STIG Scan',
    desc: 'AI-assisted STIG compliance assessment only. Layers 1–11 are skipped; runs Garak and STIG assessment.',
    layers: [
      { n: 12, name: 'LLM Security',            tool: 'Garak',        apiKey: true },
      { n: 13, name: 'STIG Compliance',         tool: 'GPT-4.1-mini', apiKey: true },
    ],
    notes: [],
  },
  baseline: {
    label: 'Baseline Scan',
    desc: 'Establishes an initial security benchmark for a repository. Runs all layers — use this for a first-time scan before enabling nightly runs.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layers 14–15 auto-run when model weight files are detected.'],
  },
  local_model: {
    label: 'Local Model Scan',
    desc: 'Scan a local directory containing AI/ML model weight files. Inventories all weight formats, checks for malicious pickle opcodes, and validates model card compliance. No git clone needed.',
    layers: [
      { n: 4,  name: 'Malware Detection (ClamAV)',    tool: 'ClamAV' },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',         tool: 'modelcard' },
    ],
    notes: [
      'Point at the directory where model weights live (e.g. /opt/models/llama3).',
      'Detects .pkl, .pt, .bin, .ckpt and other risky formats.',
      'Reports safe alternatives: .safetensors, .onnx, .gguf.',
    ],
  },
};

function _onScanTypeChange(mode) {
  const inp = document.getElementById('scan-target');
  if (inp && !inp.value) {
    inp.placeholder = mode === 'local_model'
      ? '/absolute/path/to/models  (e.g. /opt/models/llama3)'
      : '/absolute/path/to/project  or  https://github.com/org/repo.git';
  }
  // Show Garak checkbox only for modes where Layer 12 applies
  const garakRow = document.getElementById('garak-checkbox-row');
  if (garakRow) {
    const showGarak = ['full', 'nightly', 'baseline'].includes(mode);
    garakRow.style.display = showGarak ? '' : 'none';
  }
}

window.updateScanInfo = (mode) => {
  const panel = document.getElementById('scan-info-panel');
  if (!panel) return;
  const info = _SCAN_MODE_INFO[mode];
  if (!info) { panel.innerHTML = ''; return; }

  const hasApiKey = info.layers.some(l => l.apiKey);
  const layerRows = info.layers.map(l => {
    const badge = l.apiKey
      ? `<span class="scan-info-key-badge" title="Requires OpenAI API key">API key</span>`
      : '';
    const optBadge = l.optional
      ? `<span class="scan-info-opt-badge">opt-in</span>`
      : '';
    return `
      <div class="scan-info-layer">
        <span class="scan-info-layer-num">${l.n}</span>
        <span class="scan-info-layer-name">${esc(l.name)}</span>
        <span class="scan-info-layer-tool">${esc(l.tool)}</span>
        <span class="scan-info-badges">${badge}${optBadge}</span>
      </div>`;
  }).join('');

  const apiKeyNotice = hasApiKey ? `
    <div class="scan-info-apikey-notice">
      <span class="scan-info-notice-icon">🔑</span>
      <span><strong>OpenAI API key required</strong> for Garak and STIG layers.
      Set the <code>OPENAI_API_KEY</code> environment variable before running.</span>
    </div>` : '';

  const notesHtml = info.notes.length
    ? info.notes.map(n => `<div class="scan-info-note">ℹ ${esc(n)}</div>`).join('')
    : '';

  panel.innerHTML = `
    <div class="scan-info-header">
      <div class="scan-info-title">${esc(info.label)}</div>
      <div class="scan-info-desc">${esc(info.desc)}</div>
    </div>
    <div class="scan-info-layers-label">Layers included</div>
    <div class="scan-info-layers">${layerRows}</div>
    ${notesHtml}
    ${apiKeyNotice}`;
};

async function submitScan() {
  const scanType  = document.getElementById('scan-type-sel').value;
  const runGarak  = !!(document.getElementById('run-garak-chk')?.checked);
  const btn       = document.getElementById('run-btn');

  const target = (document.getElementById('scan-target')?.value || '').trim();
  if (!target) {
    document.getElementById('scan-target').focus();
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Starting…';

  document.getElementById('scan-output').style.display = 'block';
  document.getElementById('log-output').innerHTML = '';
  document.getElementById('scan-actions').style.display = 'none';
  _lastLogLen  = 0;
  _activeJobId = null;

  try {
    const job = await api.triggerScan(target, scanType, runGarak);
    _activeJobId = job.job_id;
    clearInterval(_pollInterval);
    _pollInterval = setInterval(() => pollJob(job.job_id, btn), 2000);
    pollJob(job.job_id, btn);
    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
  } catch (e) {
    btn.disabled    = false;
    btn.textContent = '▶ Run Scan';
    document.getElementById('log-output').innerHTML =
      `<div class="log-line err">Error: ${esc(e.message)}</div>`;
  }
}

async function pollJob(jobId, btn) {
  try {
    const job = await api.getJob(jobId);

    const statusBar = document.getElementById('job-status-bar');
    const logOut    = document.getElementById('log-output');
    if (!statusBar || !logOut) { clearInterval(_pollInterval); return; }

    statusBar.innerHTML =
      `<span class="job-status ${esc(job.status)}">${ucFirst(job.status)}</span>
       <span style="color:var(--text-muted);font-size:12px">
         — ${esc(job.target)} (${esc(job.scan_type)})
       </span>`;

    const lines = job.output || [];
    if (lines.length > _lastLogLen) {
      const frag = lines.slice(_lastLogLen)
        .map(l => `<div class="log-line">${esc(l)}</div>`)
        .join('');
      logOut.insertAdjacentHTML('beforeend', frag);
      logOut.scrollTop = logOut.scrollHeight;
      _lastLogLen = lines.length;
    }

    if (['completed', 'failed', 'error', 'cancelled'].includes(job.status)) {
      clearInterval(_pollInterval);
      _pollInterval = null;
      _activeJobId  = null;
      if (btn) { btn.disabled = false; btn.textContent = '▶ Run Scan'; }

      const cancelBtn = document.getElementById('cancel-btn');
      if (cancelBtn) cancelBtn.style.display = 'none';

      const actionsDiv = document.getElementById('scan-actions');
      if (actionsDiv) {
        actionsDiv.style.display = 'flex';
        actionsDiv.innerHTML = job.status === 'completed'
          ? `<button class="btn btn-primary" onclick="navigate('#/applications')">
               View Applications
             </button>
             <button class="btn" onclick="navigate('#/new-scan')">Run Another Scan</button>`
          : `<div class="error-banner" style="margin:0">
               Scan ${
                 job.status === 'cancelled'
                   ? 'was cancelled'
                   : job.status === 'failed'
                   ? 'failed (non-zero exit code)'
                   : 'encountered an error'
               }.
               ${job.status !== 'cancelled' ? 'Check the log output above.' : ''}
             </div>
             <button class="btn" onclick="navigate('#/new-scan')">Run Another Scan</button>`;
      }
    }
  } catch (_) { /* ignore transient polling errors */ }
}

// ─────────────────────────────────────────────────────────────

async function cancelScan() {
  if (!_activeJobId) return;
  const btn = document.getElementById('cancel-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Cancelling…'; }
  try {
    await fetch(`/api/jobs/${encodeURIComponent(_activeJobId)}/cancel`, { method: 'POST' });
  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────

async function renderMetrics() {
  setActive('metrics');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const m = await api.getMetrics();

    const totalFindings = (m.fix_rate.with_fix || 0) + (m.fix_rate.without_fix || 0);
    const fixPct     = totalFindings > 0
      ? Math.round((m.fix_rate.with_fix / totalFindings) * 100) : 0;
    const topTool    = (m.by_tool[0] || {}).tool || '—';
    const activeApps = Object.keys(m.scan_frequency || {}).length;
    const toolH      = Math.max((m.by_tool.length || 1) * 36 + 8, 60);

    const topCveRows = m.top_cves.length
      ? m.top_cves.map(c => `
          <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}"
                   target="_blank" rel="noopener noreferrer"><code>${esc(c.cve_id)}</code></a></td>
            <td><span class="sev-badge ${esc(c.severity)}">${ucFirst(c.severity)}</span></td>
            <td>${esc(c.count)}</td>
            <td style="max-width:360px">${esc(c.title || '—')}</td>
            <td style="font-size:11px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`).join('')
      : '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No CVE data — run a scan to populate</td></tr>';

    const freqRows = Object.entries(m.scan_frequency || {})
      .sort((a, b) => b[1].total - a[1].total)
      .map(([name, f]) => {
        const firstDate = f.dates.length ? f.dates[0] : '—';
        const lastDate  = f.dates.length ? f.dates[f.dates.length - 1] : '—';
        return `
          <tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(f.total)}</td>
            <td>${esc(firstDate)}</td>
            <td>${esc(lastDate)}</td>
            <td><div class="freq-dots">${
              f.dates.map(d => `<span class="freq-dot" title="${esc(d)}"></span>`).join('')
            }</div></td>
          </tr>`;
      }).join('');

    const legendSevs = ['critical','high','medium','low'].map(s =>
      `<span class="legend-item"><span class="legend-dot" style="background:var(--${s})"></span>${ucFirst(s)}</span>`
    ).join('');

    page.innerHTML = `
      <div class="page-header">
        <h1>Metrics</h1>
        <button class="btn btn-sm" onclick="renderMetrics()">&#8635; Refresh</button>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${esc(String(totalFindings.toLocaleString()))}</div>
          <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--clean)">${esc(String(fixPct))}%</div>
          <div class="stat-label">Fixable</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(String(activeApps))}</div>
          <div class="stat-label">Active Apps</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="font-size:16px;padding-top:6px">${esc(topTool)}</div>
          <div class="stat-label">Top Finding Tool</div>
        </div>
      </div>

      <div class="metrics-two-col">
        <div class="chart-panel">
          <div class="section-title">Fix Rate</div>
          <div class="donut-wrap">
            <canvas id="donut-chart" width="200" height="200"></canvas>
          </div>
          <div class="chart-legend">
            <span class="legend-item">
              <span class="legend-dot" style="background:var(--clean)"></span>
              Fixable (${esc(String(m.fix_rate.with_fix))})
            </span>
            <span class="legend-item">
              <span class="legend-dot" style="background:#30363d;border:1px solid #6e7681"></span>
              No fix (${esc(String(m.fix_rate.without_fix))})
            </span>
          </div>
        </div>
        <div class="chart-panel" style="flex:2;min-width:0">
          <div class="section-title">Findings by Tool</div>
          <canvas id="tool-chart" style="display:block;width:100%;height:${toolH}px"></canvas>
          <div class="chart-legend" style="margin-top:12px">${legendSevs}</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">
          Vulnerability Trend
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">last ${m.trend.length} scans</span>
        </div>
        <div class="trend-wrap">
          <canvas id="trend-chart" style="display:block;width:100%;height:200px"></canvas>
        </div>
        <div class="chart-legend">${legendSevs}</div>
      </div>

      <div class="section">
        <div class="section-title">
          Top CVEs
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">from latest scan per application</span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr><th>CVE ID</th><th>Severity</th><th>Count</th><th>Title</th><th>Applications</th></tr>
            </thead>
            <tbody>${topCveRows}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Scan Frequency</div>
        <div class="table-container">
          <table>
            <thead>
              <tr><th>Application</th><th>Total Scans</th><th>First Scan</th><th>Latest Scan</th><th>History</th></tr>
            </thead>
            <tbody>${freqRows || '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No scan data available</td></tr>'}</tbody>
          </table>
        </div>
      </div>`;

    requestAnimationFrame(() => {
      const donut = document.getElementById('donut-chart');
      if (donut) drawDonutChart(donut, [
        { value: m.fix_rate.with_fix,    color: '#3fb950' },
        { value: m.fix_rate.without_fix, color: '#30363d' },
      ]);

      const toolCanvas = document.getElementById('tool-chart');
      if (toolCanvas) drawHBarChart(toolCanvas, m.by_tool.map(t => ({
        label: t.tool, critical: t.critical, high: t.high,
        medium: t.medium, low: t.low, total: t.total,
      })));

      const trendCanvas = document.getElementById('trend-chart');
      if (trendCanvas && m.trend.length) {
        drawLineChart(trendCanvas, [
          { color: '#ff7b72', data: m.trend.map(t => t.critical) },
          { color: '#ffa657', data: m.trend.map(t => t.high) },
          { color: '#e3b341', data: m.trend.map(t => t.medium) },
          { color: '#79c0ff', data: m.trend.map(t => t.low) },
        ], m.trend.map(t => t.timestamp.slice(0, 10)));
      }
    });
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderSettings() {
  setActive('settings');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [images, history, ghCfg, aiCfg] = await Promise.all([
      api.getApprovedImages(),
      api.getScanHistory(),
      api.getGitHubConfig(),
      api.getAiConfig(),
    ]);

    const tools = [
      'Trivy', 'Grype', 'TruffleHog', 'ClamAV', 'Checkov', 'Syft/SBOM',
      'SonarQube', 'Helm', 'Xeol', 'Anchore', 'API Discovery', 'Garak',
    ];

    page.innerHTML = `
      <div class="page-header"><h1>Settings</h1></div>

      <div class="section">
        <div class="section-title">Scan History Summary</div>
        <div class="detail-grid">
          <div class="detail-card">
            <div class="label">Generated At</div>
            <div class="value" style="font-size:13px">${fmtDate(history.generated_at)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Total Scans Recorded</div>
            <div class="value">${esc(history.total_scans || 0)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Tracked Targets</div>
            <div class="value" style="font-size:13px">
              ${(history.targets || []).map(t => esc(t)).join(', ') || '—'}
            </div>
          </div>
          <div class="detail-card">
            <div class="label">Users</div>
            <div class="value" style="font-size:13px">
              ${(history.users || []).map(u => esc(u)).join(', ') || '—'}
            </div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">AI Executive Summary</div>
        <p class="section-desc">
          Configure the OpenAI API key used for generating executive summaries of scan results.
        </p>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">OpenAI API Key</label>
            <input id="ai-key" type="password" class="field-input"
              placeholder="${aiCfg.key_set ? 'Key saved — enter new to replace' : 'sk-...'}"
              autocomplete="off"/>
            ${aiCfg.key_set ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Current: ${esc(aiCfg.key_hint)}</div>` : ''}
          </div>
          <div>
            <label class="field-label">Model</label>
            <select id="ai-model" class="field-input">
              <option value="gpt-4.1" ${aiCfg.model === 'gpt-4.1' ? 'selected' : ''}>gpt-4.1</option>
              <option value="gpt-4o" ${aiCfg.model === 'gpt-4o' ? 'selected' : ''}>gpt-4o</option>
              <option value="gpt-4o-mini" ${aiCfg.model === 'gpt-4o-mini' ? 'selected' : ''}>gpt-4o-mini</option>
              <option value="gpt-4-turbo" ${aiCfg.model === 'gpt-4-turbo' ? 'selected' : ''}>gpt-4-turbo</option>
            </select>
          </div>
          <div>
            <button class="btn btn-primary" onclick="saveAiConfig()">Save AI Config</button>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">GitHub Actions Integration</div>
        <p class="section-desc">
          Import scan results from GitHub Actions directly into this dashboard.
          Epyon workflows upload scan artifacts automatically — enter a
          <strong>Personal Access Token</strong> (needs <code>actions:read</code> scope)
          and the repositories to watch.
        </p>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">Personal Access Token</label>
            <input id="gh-token" type="password" class="field-input"
              placeholder="${ghCfg.token_set ? 'Token saved — enter new to replace' : 'ghp_... or github_pat_...'}"
              autocomplete="off"/>
            ${ghCfg.token_set ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Current: ${esc(ghCfg.token_hint)}</div>` : ''}
          </div>
          <div>
            <label class="field-label">Repositories <span style="color:var(--text-muted);font-weight:normal">(one per line: owner/repo)</span></label>
            <textarea id="gh-repos" class="field-input" rows="4"
              placeholder="MetroStar/sapphire&#10;MetroStar/comet-starter"
              style="resize:vertical">${(ghCfg.repos || []).map(r => esc(r)).join('\n')}</textarea>
          </div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="saveGitHubConfig()">Save</button>
            <button class="btn btn-primary" id="sync-btn" onclick="triggerGitHubSync()">
              ↓ Sync Now
            </button>
            <span id="sync-status" style="font-size:13px;color:var(--text-muted)">
              ${ghCfg.last_sync ? 'Last synced: ' + fmtDate(ghCfg.last_sync) : 'Not yet synced'}
            </span>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Approved Base Images</div>
        <p class="section-desc">
          Docker Hardened Images approved for scans and deployments.
          Managed in <code>configuration/approved-base-images.conf</code>.
        </p>
        <pre>${esc(images.content || '(No approved-base-images.conf found)')}</pre>
      </div>

      <div class="section">
        <div class="section-title">About Epyon</div>
        <div class="detail-grid">
          <div class="detail-card">
            <div class="label">Version</div>
            <div class="value">3.0.0</div>
          </div>
          <div class="detail-card">
            <div class="label">Security Layers</div>
            <div class="value">12 + STIG</div>
          </div>
          <div class="detail-card">
            <div class="label">Tagline</div>
            <div class="value" style="font-size:13px">Absolute Security Control</div>
          </div>
        </div>
        <div class="tools-list">
          ${tools.map(t => `<span class="tool-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

async function saveAiConfig() {
  const keyEl   = document.getElementById('ai-key');
  const modelEl = document.getElementById('ai-model');
  const key   = keyEl   ? keyEl.value.trim()   : '';
  const model = modelEl ? modelEl.value         : '';
  try {
    await api.saveAiConfig({ api_key: key || 'KEEP_EXISTING', model });
    if (keyEl) keyEl.value = '';
  } catch (e) {
    alert('Failed to save AI config: ' + e.message);
  }
}

async function saveGitHubConfig() {
  const tokenEl = document.getElementById('gh-token');
  const reposEl = document.getElementById('gh-repos');
  const token = tokenEl ? tokenEl.value.trim() : '';
  const repos = reposEl
    ? reposEl.value.split('\n').map(r => r.trim()).filter(Boolean)
    : [];
  try {
    await api.saveGitHubConfig({ token: token || 'KEEP_EXISTING', repos });
    tokenEl && (tokenEl.value = '');
    const statusEl = document.getElementById('sync-status');
    if (statusEl) statusEl.textContent = 'Configuration saved.';
  } catch (e) {
    alert('Failed to save GitHub config: ' + e.message);
  }
}

let _syncPoll = null;
async function triggerGitHubSync() {
  const btn = document.getElementById('sync-btn');
  const statusEl = document.getElementById('sync-status');
  if (btn) { btn.disabled = true; btn.textContent = '↓ Syncing…'; }
  if (statusEl) statusEl.textContent = 'Sync in progress…';
  try {
    await api.triggerGitHubSync();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
    return;
  }
  clearInterval(_syncPoll);
  _syncPoll = setInterval(async () => {
    try {
      const st = await api.getGitHubSyncStatus();
      if (st.status === 'running') return;
      clearInterval(_syncPoll);
      _syncPoll = null;
      if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
      if (st.status === 'done' && st.result) {
        const r = st.result;
        const msg = `Done — ${r.synced.length} new, ${r.skipped.length} already present, ${r.failed.length} failed`;
        if (statusEl) statusEl.textContent = msg;
      } else if (st.status === 'error') {
        if (statusEl) statusEl.textContent = 'Sync error: ' + (st.error || 'unknown');
      }
    } catch (_) {}
  }, 2000);
}

// ── STIG Inline Viewer ────────────────────────────────────────

async function renderStigViewer(scanId) {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, data] = await Promise.all([api.getScan(scanId), api.getStigData(scanId)]);

    const STATUS_ORDER = ['Open', 'Not a Finding', 'Not Applicable', 'Not Reviewed'];
    const STATUS_CLASS = {
      'Open':          'stig-status-open',
      'Not a Finding': 'stig-status-pass',
      'Not Applicable':'stig-status-na',
      'Not Reviewed':  'stig-status-nr',
    };
    const SEV_ORDER = ['high', 'medium', 'low', ''];

    // Flatten all controls from all STIGs with stig_name label
    const allControls = data.stigs.flatMap(s =>
      s.controls.map(c => ({ ...c, _stig_name: s.stig_name, _slug: s.slug }))
    );

    // Build filter bar state
    let filterStatus = 'all';
    let filterSeverity = 'all';
    let filterStig = 'all';
    let filterText = '';

    const stigNames = [...new Set(data.stigs.map(s => s.stig_name))];

    function filtered() {
      return allControls.filter(c => {
        if (filterStatus   !== 'all' && c.status   !== filterStatus)   return false;
        if (filterSeverity !== 'all' && c.severity !== filterSeverity) return false;
        if (filterStig     !== 'all' && c._slug    !== filterStig)     return false;
        if (filterText) {
          const q = filterText.toLowerCase();
          if (!c.vuln_id.toLowerCase().includes(q) &&
              !c.title.toLowerCase().includes(q)   &&
              !c.evidence.toLowerCase().includes(q)) return false;
        }
        return true;
      });
    }

    function countsByStatus() {
      const out = {};
      for (const c of allControls) out[c.status] = (out[c.status] || 0) + 1;
      return out;
    }

    function renderTable() {
      const rows = filtered();
      if (!rows.length) {
        return '<div class="stig-empty">No controls match the current filters.</div>';
      }
      return `
        <div class="stig-viewer-count">${rows.length} control${rows.length !== 1 ? 's' : ''}</div>
        <div class="stig-table-wrap">
          <table class="stig-table">
            <thead>
              <tr>
                <th style="width:100px">STIG #</th>
                <th style="width:70px">Severity</th>
                <th style="width:130px">Status</th>
                <th style="width:80px">Confidence</th>
                <th>Title</th>
                ${stigNames.length > 1 ? '<th style="width:140px">STIG</th>' : ''}
                <th style="width:40px"></th>
              </tr>
            </thead>
            <tbody>
              ${rows.map(c => {
                const rowId = `stig-row-${esc(c.vuln_id)}-${esc(c._slug)}`;
                const detId = `stig-det-${esc(c.vuln_id)}-${esc(c._slug)}`;
                const sname = c._stig_name.replace(/.*?(ASD|Postgres|STIG)/gi, '$1').trim().slice(0, 40);
                const conf  = c.confidence ?? 0;
                const confClass = conf >= 90 ? 'conf-high' : conf >= 70 ? 'conf-med' : conf >= 40 ? 'conf-low' : 'conf-none';
                return `
                  <tr class="stig-tr" id="${rowId}" onclick="toggleStigRow('${detId}', '${rowId}')">
                    <td><code class="stig-id">${esc(c.group_id || c.vuln_id)}</code></td>
                    <td><span class="stig-sev stig-sev-${esc(c.severity)}">${esc(c.severity || '—')}</span></td>
                    <td><span class="${esc(STATUS_CLASS[c.status] || 'stig-status-nr')}">${esc(c.status)}</span></td>
                    <td><span class="stig-confidence ${confClass}" title="${conf}/100">${conf}</span></td>
                    <td class="stig-title-cell">${esc(c.title)}</td>
                    ${stigNames.length > 1 ? `<td class="stig-stig-cell" title="${esc(c._stig_name)}">${esc(sname)}</td>` : ''}
                    <td class="stig-chevron-cell"><span class="stig-chevron" id="chev-${esc(c.vuln_id)}-${esc(c._slug)}">›</span></td>
                  </tr>
                  <tr class="stig-detail-row" id="${detId}" style="display:none">
                    <td colspan="${stigNames.length > 1 ? 7 : 6}">
                      <div class="stig-detail-body">
                        <div class="stig-detail-grid">
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Vuln ID</div>
                            <div class="stig-detail-val"><code>${esc(c.vuln_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Rule ID</div>
                            <div class="stig-detail-val"><code>${esc(c.rule_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Group ID</div>
                            <div class="stig-detail-val"><code>${esc(c.group_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Confidence</div>
                            <div class="stig-detail-val">
                              ${(() => {
                                const cv = c.confidence ?? 0;
                                const cls = cv >= 90 ? 'conf-high' : cv >= 70 ? 'conf-med' : cv >= 40 ? 'conf-low' : 'conf-none';
                                const lbl = cv >= 90 ? 'High' : cv >= 70 ? 'Medium' : cv >= 40 ? 'Low' : 'Insufficient';
                                return `<span class="stig-confidence ${cls}">${cv}/100</span> <span class="stig-conf-label">${lbl}</span>`;
                              })()}
                            </div>
                          </div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Evidence</div>
                          <div class="stig-detail-val stig-evidence">${esc(c.evidence || '—').replace(/\n/g, '<br>')}</div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Check</div>
                          <div class="stig-detail-val stig-check">${esc(c.check_content).replace(/\n/g, '<br>')}</div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Remediation</div>
                          <div class="stig-detail-val">${esc(c.fix_text || '—').replace(/\n/g, '<br>')}</div>
                        </div>
                      </div>
                    </td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`;
    }

    function renderFilters() {
      const counts = countsByStatus();
      return `
        <div class="stig-filters">
          <div class="stig-filter-group">
            <label class="stig-filter-label">Status</label>
            <div class="stig-filter-btns" id="filter-status">
              ${['all', ...STATUS_ORDER].map(s => `
                <button class="stig-filter-btn${filterStatus === s ? ' active' : ''}"
                  onclick="setStigFilter('status','${s}')">${s === 'all' ? 'All' : esc(s)}${s !== 'all' && counts[s] ? ` <span class="stig-filter-count">${counts[s]}</span>` : ''}</button>
              `).join('')}
            </div>
          </div>
          <div class="stig-filter-group">
            <label class="stig-filter-label">Severity</label>
            <div class="stig-filter-btns">
              ${['all', 'high', 'medium', 'low'].map(s => `
                <button class="stig-filter-btn${filterSeverity === s ? ' active' : ''}"
                  onclick="setStigFilter('severity','${s}')">${s === 'all' ? 'All' : ucFirst(s)}</button>
              `).join('')}
            </div>
          </div>
          ${stigNames.length > 1 ? `
          <div class="stig-filter-group">
            <label class="stig-filter-label">STIG</label>
            <div class="stig-filter-btns">
              <button class="stig-filter-btn${filterStig === 'all' ? ' active' : ''}"
                onclick="setStigFilter('stig','all')">All</button>
              ${data.stigs.map(s => `
                <button class="stig-filter-btn${filterStig === s.slug ? ' active' : ''}"
                  onclick="setStigFilter('stig','${esc(s.slug)}')"
                  title="${esc(s.stig_name)}">${esc(s.stig_name.slice(0, 30))}…</button>
              `).join('')}
            </div>
          </div>` : ''}
          <div class="stig-filter-group">
            <label class="stig-filter-label">Search</label>
            <input class="stig-search" type="text" placeholder="ID, title, or evidence…"
              value="${esc(filterText)}"
              oninput="setStigSearch(this.value)">
          </div>
        </div>`;
    }

    function repaint() {
      const el = document.getElementById('stig-viewer-filters');
      if (el) el.outerHTML = renderFilters().replace('<div class="stig-filters">', '<div class="stig-filters" id="stig-viewer-filters">');
      const tbody = document.getElementById('stig-viewer-body');
      if (tbody) tbody.innerHTML = renderTable();
    }

    // Expose callbacks to global scope for onclick handlers
    window.setStigFilter = (type, val) => {
      if (type === 'status')   filterStatus   = val;
      if (type === 'severity') filterSeverity = val;
      if (type === 'stig')     filterStig     = val;
      repaint();
    };
    window.setStigSearch = (val) => { filterText = val; repaint(); };
    window.toggleStigRow = (detId, rowId) => {
      const det  = document.getElementById(detId);
      const row  = document.getElementById(rowId);
      const parts = detId.replace('stig-det-', '').split('-');
      // Reconstruct vuln_id + slug for chevron id — use row IDs which embed them
      const chevId = 'chev-' + detId.replace('stig-det-', '');
      const chev = document.getElementById(chevId);
      if (!det) return;
      const open = det.style.display !== 'none';
      det.style.display = open ? 'none' : 'table-row';
      if (row) row.classList.toggle('stig-tr-open', !open);
      if (chev) chev.textContent = open ? '›' : '⌄';
    };

    const counts = countsByStatus();
    const backLink = scan.target
      ? `<a href="#/scans/${encodeURIComponent(scanId)}" onclick="navigate('#/scans/${encodeURIComponent(scanId)}')">${esc(scanId)}</a>`
      : esc(scanId);

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <a href="#/applications/${encodeURIComponent(scan.target)}"
           onclick="navigate('#/applications/${encodeURIComponent(scan.target)}')">${esc(scan.target)}</a>
        <span>›</span>
        <a href="#/scans/${encodeURIComponent(scanId)}"
           onclick="navigate('#/scans/${encodeURIComponent(scanId)}')">${esc(scanId)}</a>
        <span>›</span>
        <span>STIG Findings</span>
      </div>

      <div class="page-header">
        <h1>STIG Findings</h1>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          ${data.stigs.map(s => {
            const mdUrl   = `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.md`;
            const cklbUrl = `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.cklb`;
            return `
              <a class="btn btn-sm" href="${esc(mdUrl)}"   download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.md</a>
              <a class="btn btn-sm" href="${esc(cklbUrl)}" download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.cklb</a>`;
          }).join('')}
        </div>
      </div>

      <div class="stig-totals-bar">
        <div class="stig-total-chip open">
          <span class="num">${counts['Open'] || 0}</span><span class="lbl">Open</span>
        </div>
        <div class="stig-total-chip pass">
          <span class="num">${counts['Not a Finding'] || 0}</span><span class="lbl">Not a Finding</span>
        </div>
        <div class="stig-total-chip na">
          <span class="num">${counts['Not Applicable'] || 0}</span><span class="lbl">N/A</span>
        </div>
        <div class="stig-total-chip nr">
          <span class="num">${counts['Not Reviewed'] || 0}</span><span class="lbl">Not Reviewed</span>
        </div>
        <div class="stig-total-chip total">
          <span class="num">${allControls.length}</span><span class="lbl">Total</span>
        </div>
      </div>

      <div id="stig-viewer-filters">${renderFilters().replace('<div class="stig-filters">', '')}</div>

      <div id="stig-viewer-body">${renderTable()}</div>`;

    // Fix up filter container id after innerHTML set
    const fEl = page.querySelector('.stig-filters');
    if (fEl) fEl.id = 'stig-viewer-filters';

  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ── Destructive confirm modal ─────────────────────────────────
function showDestructiveModal({ title, body, target, confirmLabel = 'Delete', onConfirm }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <h2>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <span id="modal-title">${esc(title)}</span>
      </h2>
      <p>${esc(body)}</p>
      ${target ? `<div class="modal-target">${esc(target)}</div>` : ''}
      <div class="modal-actions">
        <button class="btn" id="modal-cancel">Cancel</button>
        <button class="btn btn-danger" id="modal-confirm">${esc(confirmLabel)}</button>
      </div>
    </div>`;

  function onKey(e) {
    if (e.key === 'Escape') close();
  }

  function close() {
    document.removeEventListener('keydown', onKey);
    overlay.remove();
  }

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  overlay.querySelector('#modal-cancel').addEventListener('click', close);
  overlay.querySelector('#modal-confirm').addEventListener('click', () => {
    close();
    onConfirm();
  });
  document.addEventListener('keydown', onKey);

  document.body.appendChild(overlay);
  overlay.querySelector('#modal-confirm').focus();
}

// ── Application management helpers ───────────────────────────
async function hideApplication(name) {
  if (!confirm(`Hide "${name}" from the applications list?\n\nThe scan data will be preserved and can be restored later.`)) return;
  try {
    await api.hideApp(name);
    renderApplications();
  } catch (e) {
    alert(`Failed to hide application: ${e.message}`);
  }
}

async function restoreApplication(name) {
  try {
    await api.restoreApp(name);
    renderApplications();
  } catch (e) {
    alert(`Failed to restore application: ${e.message}`);
  }
}

async function deleteApplication(name) {
  showDestructiveModal({
    title:        'Delete Application',
    body:         'This will permanently remove all scan data from disk. This action cannot be undone.',
    target:       name,
    confirmLabel: 'Delete All Scans',
    onConfirm:    async () => {
      try {
        await api.deleteApp(name);
        navigate('#/applications');
      } catch (e) {
        alert(`Failed to delete application: ${e.message}`);
      }
    },
  });
}

async function deleteScan(scanId, appName) {
  showDestructiveModal({
    title:        'Delete Scan',
    body:         'This will permanently remove the scan directory and all its reports from disk. This action cannot be undone.',
    target:       scanId,
    confirmLabel: 'Delete Scan',
    onConfirm:    async () => {
      try {
        await api.deleteScan(scanId);
        if (appName) {
          navigate(`#/applications/${encodeURIComponent(appName)}`);
        } else {
          navigate('#/applications');
        }
      } catch (e) {
        alert(`Failed to delete scan: ${e.message}`);
      }
    },
  });
}

function showAddAppModal() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  // ── Step 1 HTML ────────────────────────────────────────────
  const step1HTML = `
    <div id="add-app-step1">
      <h2 id="add-app-title" style="color:var(--text)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="16"/>
          <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
        Add Application
      </h2>
      <p style="color:var(--text-muted);font-size:13px;margin:0 0 16px">
        Register a GitHub repository with Epyon. A name will be auto-suggested from the URL.
      </p>

      <div class="form-group">
        <label for="add-app-url" style="font-size:13px;color:var(--text-muted);margin-bottom:4px;display:block">
          Repository URL <span style="color:var(--critical)">*</span>
        </label>
        <input type="text" id="add-app-url" autocomplete="off" spellcheck="false"
          placeholder="https://github.com/org/my-app.git"
          style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);
                 border-radius:var(--radius);color:var(--text);font-size:13px;outline:none" />
      </div>

      <div class="form-group" style="margin-top:12px">
        <label for="add-app-name" style="font-size:13px;color:var(--text-muted);margin-bottom:4px;display:block">
          Application Name <span style="color:var(--critical)">*</span>
        </label>
        <input type="text" id="add-app-name" autocomplete="off" spellcheck="false"
          placeholder="my-app"
          style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);
                 border-radius:var(--radius);color:var(--text);font-size:13px;outline:none" />
        <small style="font-size:11px;color:var(--text-dim)">Alphanumeric, hyphens, underscores, and dots only</small>
      </div>

      <div style="margin-top:12px;display:flex;align-items:center;gap:8px">
        <input type="checkbox" id="add-app-scan" style="accent-color:var(--accent)" />
        <label for="add-app-scan" style="font-size:13px;color:var(--text-muted);cursor:pointer">
          Run a full scan immediately after adding
        </label>
      </div>

      <div id="add-app-error" style="display:none;margin-top:12px;color:var(--critical);font-size:12px"></div>

      <div class="modal-actions" style="margin-top:20px">
        <button class="btn" id="add-app-cancel">Cancel</button>
        <button class="btn btn-primary" id="add-app-next">Next: Workflow Setup →</button>
      </div>
    </div>`;

  // ── Step 2 HTML ────────────────────────────────────────────
  const workflowYml = `name: Private Security Scan

# Epyon private-repo scanner entrypoint.
# This workflow delegates execution to the local reusable workflow.

permissions:
  contents: read

concurrency:
  group: epyon-scan-\${{ github.repository }}
  cancel-in-progress: false

on:
  schedule:
    # Nightly full scan — runs every night at 2 AM UTC (Mon-Sat)
    - cron: '0 2 * * 1-6'
    # Weekly STIG scan — runs Sunday night at 2 AM UTC
    - cron: '0 2 * * 0'
  # checkov:skip=CKV_GHA_7:Workflow inputs control scan parameters not build artifacts
  workflow_dispatch:
    inputs:
      subdirectory:
        description: 'Optional: Subdirectory path to scan (e.g., apps/api)'
        required: false
        type: string
      scan_mode:
        description: 'Scan mode (quick/full/nightly/baseline/stig)'
        required: false
        default: 'full'
        type: choice
        options:
          - quick
          - full
          - nightly
          - baseline
          - stig
      garak_target_type:
        description: 'Garak generator type (e.g. test, openai, huggingface)'
        required: false
        default: 'openai'
        type: string
      garak_target_name:
        description: 'Garak target model name (e.g. gpt-4o-mini)'
        required: false
        default: 'gpt-4o-mini'
        type: string
      garak_probes:
        description: 'Garak probe set (comma-separated, e.g. promptinject,dan,encoding)'
        required: false
        default: 'promptinject'
        type: string

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  security-scan-main:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    permissions:
      contents: read
      actions: read
      pull-requests: write
      security-events: write
      issues: write
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: \${{ github.event_name == 'schedule' && (github.event.schedule == '0 2 * * 0' && 'stig' || 'nightly') || github.event.inputs.scan_mode || 'full' }}
      subdirectory: \${{ github.event.inputs.subdirectory || '' }}
      garak_target_type: \${{ github.event.inputs.garak_target_type || 'openai' }}
      garak_target_name: \${{ github.event.inputs.garak_target_name || 'gpt-4o-mini' }}
      garak_probes: \${{ github.event.inputs.garak_probes || 'promptinject' }}
    secrets: inherit`;

  const step2HTML = `
    <div id="add-app-step2" style="display:none">
      <h2 id="add-app-title" style="color:var(--text)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
        </svg>
        GitHub Workflow Setup
      </h2>
      <p style="color:var(--text-muted);font-size:13px;margin:0 0 14px">
        To enable automated nightly scans, add the Epyon workflow file to your repository.
        Follow the steps below, then Epyon will pick up scan results automatically.
      </p>

      <ol style="padding-left:18px;margin:0 0 14px;font-size:13px;color:var(--text-muted);line-height:1.9">
        <li>In your repository, create the directory <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">.github/workflows/</code> if it doesn't exist.</li>
        <li>Add a new file named <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">scan-private-repo.yml</code> with the contents below.</li>
        <li>Review the workflow references and update the GitHub org or user only if the sample points to a different Epyon host than yours.</li>
        <li>Commit and push — the workflow will run nightly at 2 AM UTC and on manual dispatch.</li>
      </ol>

      <div style="position:relative">
        <pre id="add-app-yml" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);
             padding:12px;font-size:11px;line-height:1.6;overflow-x:auto;margin:0;white-space:pre;color:var(--text)">${workflowYml}</pre>
        <button id="add-app-copy"
          style="position:absolute;top:8px;right:8px;padding:3px 10px;font-size:11px;
                 background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
                 color:var(--text-muted);cursor:pointer">Copy</button>
      </div>

      <p style="font-size:12px;color:var(--text-dim);margin:10px 0 0">
        The full workflow with all optional parameters is available in
        <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">documentation/scan-private-repo.yml</code>
        in the Epyon repo.
      </p>

      <div class="modal-actions" style="margin-top:20px">
        <button class="btn" id="add-app-back">← Back</button>
        <button class="btn btn-primary" id="add-app-submit">Add Application</button>
      </div>
    </div>`;

  overlay.innerHTML = `
    <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="add-app-title"
         style="max-width:540px">
      ${step1HTML}
      ${step2HTML}
    </div>`;

  function onKey(e) { if (e.key === 'Escape') close(); }

  function close() {
    document.removeEventListener('keydown', onKey);
    overlay.remove();
  }

  // ── Step navigation ────────────────────────────────────────
  const s1 = overlay.querySelector('#add-app-step1');
  const s2 = overlay.querySelector('#add-app-step2');

  function showStep(n) {
    s1.style.display = n === 1 ? '' : 'none';
    s2.style.display = n === 2 ? '' : 'none';
  }

  // ── Step 1 inputs ──────────────────────────────────────────
  const urlInput  = overlay.querySelector('#add-app-url');
  const nameInput = overlay.querySelector('#add-app-name');

  urlInput.addEventListener('input', () => {
    const raw = urlInput.value.trim();
    const derived = raw
      .replace(/\.git$/i, '')
      .split('/')
      .filter(Boolean)
      .pop() || '';
    if (derived && !nameInput._manuallyEdited) {
      nameInput.value = derived.replace(/[^a-zA-Z0-9._-]/g, '-');
    }
  });
  nameInput.addEventListener('input', () => { nameInput._manuallyEdited = true; });

  overlay.querySelector('#add-app-cancel').addEventListener('click', close);

  overlay.querySelector('#add-app-next').addEventListener('click', () => {
    const errEl = overlay.querySelector('#add-app-error');
    errEl.style.display = 'none';
    if (!urlInput.value.trim()) {
      errEl.textContent = 'Repository URL is required.';
      errEl.style.display = 'block';
      urlInput.focus();
      return;
    }
    if (!nameInput.value.trim()) {
      errEl.textContent = 'Application name is required.';
      errEl.style.display = 'block';
      nameInput.focus();
      return;
    }
    showStep(2);
  });

  // ── Step 2 controls ────────────────────────────────────────
  overlay.querySelector('#add-app-back').addEventListener('click', () => showStep(1));

  overlay.querySelector('#add-app-copy').addEventListener('click', function () {
    navigator.clipboard.writeText(workflowYml).then(() => {
      this.textContent = 'Copied!';
      setTimeout(() => { this.textContent = 'Copy'; }, 2000);
    });
  });

  overlay.querySelector('#add-app-submit').addEventListener('click', async () => {
    const url     = urlInput.value.trim();
    const name    = nameInput.value.trim();
    const scanNow = overlay.querySelector('#add-app-scan').checked;
    const btn     = overlay.querySelector('#add-app-submit');

    btn.disabled = true;
    btn.textContent = 'Adding…';
    try {
      await api.registerApp(name, url);
      close();
      if (scanNow) {
        navigate(`#/new-scan?target=${encodeURIComponent(url)}`);
      } else {
        navigate('#/applications');
        renderApplications();
      }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Add Application';
      // Show error back on step 1
      showStep(1);
      const errEl = overlay.querySelector('#add-app-error');
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    }
  });

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', onKey);

  document.body.appendChild(overlay);
  urlInput.focus();
}

// ── Router ────────────────────────────────────────────────────
function resolve() {
  const hash = window.location.hash.slice(1) || '/';

  const qIdx   = hash.indexOf('?');
  const path   = qIdx === -1 ? hash : hash.slice(0, qIdx);
  const params = new URLSearchParams(qIdx === -1 ? '' : hash.slice(qIdx + 1));

  if (path === '/' || path === '') {
    renderOverview();
  } else if (path === '/applications') {
    renderApplications();
  } else if (path.startsWith('/applications/')) {
    const name = decodeURIComponent(path.slice('/applications/'.length));
    name ? renderAppDetail(name) : renderApplications();
  } else if (path.startsWith('/stig-viewer/')) {
    const scanId = decodeURIComponent(path.slice('/stig-viewer/'.length));
    scanId ? renderStigViewer(scanId) : renderStig();
  } else if (path.startsWith('/scans/')) {
    const scanId = decodeURIComponent(path.slice('/scans/'.length));
    scanId ? renderScanDetail(scanId) : renderApplications();
  } else if (path === '/new-scan') {
    renderNewScan(params.get('target') || '');
  } else if (path === '/metrics') {
    renderMetrics();
  } else if (path === '/stig') {
    renderStig();
  } else if (path === '/settings') {
    renderSettings();
  } else {
    renderOverview();
  }
}

window.addEventListener('hashchange', resolve);
window.addEventListener('load', resolve);

// ── Finding detail drawer ─────────────────────────────────────
function _registerFinding(f) {
  const id = _findingNextId++;
  _findingsRegistry.set(id, f);
  return id;
}

function openFindingDetail(id) {
  const f = _findingsRegistry.get(id);
  if (!f) return;

  // Close any existing drawer
  closeFindingDetail();

  const sev     = f.severity || 'unknown';
  const fid     = f.id || '—';
  const tool    = f.tool || '—';
  const title   = f.title || f.description || '—';
  const desc    = f.description || '';
  const pkg     = f.package || f.component || '';
  const ver     = f.version || '';
  const fixed   = f.fixed_version || '';
  const target  = f.target || '';
  const refs    = f.references || [];

  const idDisplay = fid.startsWith('CVE-')
    ? `<a class="finding-detail-id-link"
          href="https://nvd.nist.gov/vuln/detail/${esc(fid)}"
          target="_blank" rel="noopener noreferrer">
         ${esc(fid)}
         <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
           <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
           <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
         </svg>
       </a>`
    : `<code>${esc(fid)}</code>`;

  const refsHtml = refs.length
    ? `<div class="finding-detail-section">
         <div class="finding-detail-label">References</div>
         <div class="finding-detail-refs">
           ${refs.map(r => `<a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a>`).join('')}
         </div>
       </div>`
    : '';

  const descSection = desc && desc !== title
    ? `<div class="finding-detail-section">
         <div class="finding-detail-label">Description</div>
         <div class="finding-detail-desc">${esc(desc)}</div>
       </div>`
    : '';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Finding details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(title)}</h2>
        <div class="finding-drawer-badges">
          <span class="sev-badge ${esc(sev)}">${ucFirst(sev)}</span>
          <span class="tool-tag">${esc(tool)}</span>
          ${idDisplay}
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Package / Component</div>
          <div class="finding-detail-value">${pkg ? `<code>${esc(pkg)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Version</div>
          <div class="finding-detail-value">${ver ? `<code>${esc(ver)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Fix Available</div>
          <div class="finding-detail-value">${fixed
            ? `<code style="color:var(--clean)">${esc(fixed)}</code>`
            : '<span style="color:var(--text-dim)">None known</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Severity</div>
          <div class="finding-detail-value"><span class="sev-badge ${esc(sev)}">${ucFirst(sev)}</span></div>
        </div>
      </div>

      ${target ? `
        <div class="finding-detail-section">
          <div class="finding-detail-label">Location</div>
          <div class="finding-detail-value"><code>${esc(target)}</code></div>
        </div>` : ''}

      ${descSection}

      ${refsHtml}
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  // Trap Escape key
  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
}

function closeFindingDetail() {
  const overlay = document.getElementById('finding-drawer-overlay');
  const drawer  = document.getElementById('finding-drawer');
  if (drawer && drawer._onKey) document.removeEventListener('keydown', drawer._onKey);
  overlay?.remove();
  drawer?.remove();
}
