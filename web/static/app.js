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
  getStats()        { return this._get('/api/stats'); },
  getApplications() { return this._get('/api/applications'); },
  getAppScans(name) { return this._get(`/api/applications/${encodeURIComponent(name)}/scans`); },
  getScan(id)       { return this._get(`/api/scans/${encodeURIComponent(id)}`); },
  getScanHistory()  { return this._get('/api/scan-history'); },
  getApprovedImages(){ return this._get('/api/settings/approved-images'); },
  getGitHubConfig()  { return this._get('/api/github/config'); },
  saveGitHubConfig(data){ return this._post('/api/github/config', data); },
  triggerGitHubSync(){ return this._post('/api/github/sync', {}); },
  getGitHubSyncStatus(){ return this._get('/api/github/sync'); },
  triggerScan(target, scanType) {
    return this._post('/api/scans', { target, scan_type: scanType });
  },
  getJob(id)  { return this._get(`/api/jobs/${encodeURIComponent(id)}`); },
  getJobs()   { return this._get('/api/jobs'); },
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

      // Link CVE IDs to NVD
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
          <option value="quick">Quick — Trivy, TruffleHog, basic checks</option>
          <option value="images">Images — Container image vulnerability scanning</option>
          <option value="analysis">Analysis — SonarQube, Checkov, code quality</option>
        </select>
        <small>Full scan provides comprehensive security coverage across all tool categories.</small>
      </div>

      <button id="run-btn" class="btn btn-primary" onclick="submitScan()">
        ▶ Run Scan
      </button>
    </div>

    <div id="scan-output" style="display:none">
      <div style="margin-top:28px;margin-bottom:12px;display:flex;align-items:center;gap:12px">
        <div id="job-status-bar"></div>        <button id="cancel-btn" class="btn btn-sm" style="display:none"
                onclick="cancelScan()">✕ Cancel</button>      </div>
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

    // Append only new lines
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

async function renderSettings() {
  setActive('settings');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [images, history, ghCfg] = await Promise.all([
      api.getApprovedImages(),
      api.getScanHistory(),
      api.getGitHubConfig(),
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
            <div class="value">12</div>
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
  // Poll status
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

  // Split off query string within the hash fragment
  const qIdx    = hash.indexOf('?');
  const path    = qIdx === -1 ? hash : hash.slice(0, qIdx);
  const params  = new URLSearchParams(qIdx === -1 ? '' : hash.slice(qIdx + 1));

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
  } else if (path === '/settings') {
    renderSettings();
  } else {
    renderOverview();
  }
}

window.addEventListener('hashchange', resolve);
window.addEventListener('load', resolve);
