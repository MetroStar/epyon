/* ============================================================
   Epyon Web Interface — app.js
   Vanilla JS single-page application
   ============================================================ */

'use strict';

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
  getStats()          { return this._get('/api/stats'); },
  getApplications()   { return this._get('/api/applications'); },
  getAppScans(name)   { return this._get(`/api/applications/${encodeURIComponent(name)}/scans`); },
  getScan(id)         { return this._get(`/api/scans/${encodeURIComponent(id)}`); },
  getScanHistory()    { return this._get('/api/scan-history'); },
  getApprovedImages() { return this._get('/api/settings/approved-images'); },
  getGitHubConfig()   { return this._get('/api/github/config'); },
  saveGitHubConfig(d) { return this._post('/api/github/config', d); },
  triggerGitHubSync() { return this._post('/api/github/sync', {}); },
  getGitHubSyncStatus(){ return this._get('/api/github/sync'); },
  triggerScan(target, scanType) {
    return this._post('/api/scans', { target, scan_type: scanType });
  },
  getJob(id)    { return this._get(`/api/jobs/${encodeURIComponent(id)}`); },
  getJobs()     { return this._get('/api/jobs'); },
  getMetrics()  { return this._get('/api/metrics'); },
  getAiConfig() { return this._get('/api/ai/config'); },
  saveAiConfig(d){ return this._post('/api/ai/config', d); },
};

// ── Navigation ────────────────────────────────────────────────
function setActive(routeKey) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeKey);
  });
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
    const apps = await api.getApplications();

    const rows = apps.length
      ? apps.map(app => `
          <tr onclick="navigate('#/applications/${encodeURIComponent(app.name)}')"
              style="cursor:pointer">
            <td><strong>${esc(app.name)}</strong></td>
            <td>${app.last_scanned ? fmtDate(app.last_scanned) : '—'}</td>
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
            </td>
          </tr>`).join('')
      : `<tr><td colspan="9" style="text-align:center;padding:48px;color:var(--text-muted)">
           No applications found. Run a scan to get started.
         </td></tr>`;

    page.innerHTML = `
      <div class="page-header">
        <h1>Applications</h1>
        <button class="btn btn-primary" onclick="navigate('#/new-scan')">+ Run Scan</button>
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
      </div>`;
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
    const scans = await api.getAppScans(name);
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
                  ${esc(ucFirst(s.scan_type || 'full'))} scan
                  <span>${sevBadgeRow(s)}</span>
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
            </div>`;
        }).join('')
      : emptyState(`No scans found for "${name}"`, 'Run a scan to populate history.');

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
        <button class="btn btn-primary" onclick="navigate('#/new-scan')">+ Run Scan</button>
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
    const scan   = await api.getScan(scanId);
    const status = computeStatus(scan);

    // Build STIG summary card if STIG data is present
    let stigCard = '';
    if ((scan.stig_total || 0) > 0) {
      const mdBtn = scan.has_stig_report
        ? `<a class="btn btn-sm" href="${esc(scan.stig_report_url)}" download>
             ↓ findings.md
           </a>` : '';
      const cklbBtn = scan.has_stig_cklb
        ? `<a class="btn btn-sm" href="${esc(scan.stig_cklb_url)}" download>
             ↓ findings.cklb
           </a>` : '';
      stigCard = `
        <div class="stig-summary-card">
          <div class="stig-summary-header">
            <div class="stig-summary-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              STIG Assessment
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
        ${scan.has_dashboard
          ? `<button class="btn btn-primary"
               onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/dashboard','_blank')">
               View Dashboard ↗
             </button>`
          : ''}
      </div>

      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Application</div>
          <div class="value">${esc(scan.target)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Scan Type</div>
          <div class="value">${esc(ucFirst(scan.scan_type || 'full'))}</div>
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

      ${stigCard}

      ${dedupeTools(scan.tools_analyzed).length ? `
        <div class="section">
          <div class="section-title">Tools Analyzed</div>
          <div class="tools-list">
            ${dedupeTools(scan.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}

      ${buildFindingsSection(scan.findings)}

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

function buildFindingsSection(findings) {
  if (!findings) return '';

  const severities = ['critical', 'high', 'medium', 'low'];
  let html = '';
  let anyFindings = false;

  for (const sev of severities) {
    const items = (findings[`${sev}_findings`] || []);
    if (!items.length) continue;
    anyFindings = true;

    const rows = items.slice(0, 200).map(f => {
      const id    = esc(f.id    || f.cve_id || '—');
      const tool  = esc(f.tool  || '—');
      const pkg   = esc(f.package || f.component || f.target || '—');
      const ver   = esc(f.version || '');
      const fixed = esc(f.fixed_version || '');
      const title = esc((f.title || f.description || f.check_name || '').substring(0, 160));
      const target = esc((f.target || '').substring(0, 80));

      const idCell = id.startsWith('CVE-')
        ? `<a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer"><code>${id}</code></a>`
        : `<code>${id}</code>`;

      return `
        <tr>
          <td><span class="tool-tag">${tool}</span></td>
          <td>${idCell}</td>
          <td style="max-width:360px">${title}</td>
          <td>${pkg}${ver ? ` <span style="color:var(--text-dim);font-size:11px">${ver}</span>` : ''}</td>
          <td>${fixed ? `<span style="color:var(--clean)">${fixed}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
          <td style="color:var(--text-muted);font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${target}">${target || '—'}</td>
        </tr>`;
    }).join('');

    const overflow = items.length > 200
      ? `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:12px">
           … and ${items.length - 200} more. Open the Dashboard for the full list.
         </td></tr>` : '';

    html += `
      <div class="section">
        <div class="section-title">
          ${ucFirst(sev)} Findings
          <span class="sev-badge ${esc(sev)}">${items.length}</span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Tool</th><th>CVE / ID</th><th>Title</th>
                <th>Package</th><th>Fix Available</th><th>Location</th>
              </tr>
            </thead>
            <tbody>${rows}${overflow}</tbody>
          </table>
        </div>
      </div>`;
  }

  if (!anyFindings) {
    return `
      <div class="section">
        <div class="section-title">Findings</div>
        <span class="sev-badge clean" style="padding:8px 16px">✓ No findings detected</span>
      </div>`;
  }
  return html;
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
          const mdUrl  = `/api/scans/${encodeURIComponent(app.latest_scan_id)}/stig-findings-md`;
          const cklbUrl = `/api/scans/${encodeURIComponent(app.latest_scan_id)}/stig-findings-cklb`;
          return `
            <div class="stig-app-card">
              <div class="stig-app-card-header">
                <span class="stig-app-name"
                      onclick="navigate('#/applications/${encodeURIComponent(app.name)}')">
                  ${esc(app.name)}
                </span>
                <div class="stig-download-btns">
                  <a class="btn btn-sm" href="${esc(mdUrl)}" download>↓ findings.md</a>
                  <a class="btn btn-sm" href="${esc(cklbUrl)}" download>↓ findings.cklb</a>
                </div>
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
              <div style="margin-top:10px;font-size:12px;color:var(--text-muted)">
                Last scanned: ${fmtDate(app.last_scanned)}
                <button class="btn btn-sm" style="margin-left:12px"
                  onclick="navigate('#/scans/${encodeURIComponent(app.latest_scan_id)}')">
                  View Scan →
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

    <div class="form-card">
      <div class="form-group">
        <label for="scan-target">Target</label>
        <input type="text" id="scan-target" autocomplete="off" spellcheck="false"
          placeholder="/absolute/path/to/project  or  https://github.com/org/repo.git"
          value="${esc(prefill)}" />
        <small>Absolute local directory path, relative path, or Git repository URL (HTTPS/SSH)</small>
      </div>

      <div class="form-group">
        <label for="scan-type-sel">Scan Type</label>
        <select id="scan-type-sel">
          <option value="full">Full — All 12 security layers (recommended)</option>
          <option value="nightly">Nightly — Scheduled comprehensive scan (layers 1–12)</option>
          <option value="stig">STIG — STIG compliance assessment only (Sunday schedule)</option>
          <option value="quick">Quick — Trivy, TruffleHog, basic checks</option>
          <option value="images">Images — Container image vulnerability scanning</option>
          <option value="analysis">Analysis — SonarQube, Checkov, code quality</option>
        </select>
        <small>Full or Nightly scan provides comprehensive security coverage across all tool categories.</small>
      </div>

      <button id="run-btn" class="btn btn-primary" onclick="submitScan()">
        ▶ Run Scan
      </button>
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
}

async function submitScan() {
  const target  = (document.getElementById('scan-target').value || '').trim();
  const scanType = document.getElementById('scan-type-sel').value;
  const btn      = document.getElementById('run-btn');

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
    const job = await api.triggerScan(target, scanType);
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
