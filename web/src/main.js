/* ============================================================
   Epyon Web Interface — app.js
   Vanilla JS single-page application
   ============================================================ */

'use strict';


const _findingsRegistry     = new Map();
let   _findingNextId        = 0;

// ── Dependency detail registry (populated in sbomRender) ──────
const _depsRegistry         = new Map();
let   _depsNextId           = 0;

// ── API endpoint detail registry (populated in apiRender) ─────
const _apiRegistry          = new Map();
let   _apiNextId            = 0;

// ── GitHub Signals detail (populated in buildCiHealthSection) ──
// window._ghSignalData is set by pages/performance.js

// ── Findings sort state (per severity) ───────────────────────
const _currentFindingsBySev = {};
const _sortState             = {};
const _pageState             = {};
const FINDINGS_PAGE_SIZES    = [25, 50, 100, 200];

// ── Epyon workflow YAML (shared by Settings page + Add App modal) ─
const WORKFLOW_YML = `name: Private Security Scan

# Epyon private-repo scanner entrypoint.
# This workflow delegates execution to the local reusable workflow.

permissions:
  contents: read

concurrency:
  group: epyon-scan-\${{ github.repository }}
  cancel-in-progress: false

on:
  pull_request:
    types:
      - opened
      - synchronize
      - reopened
      - ready_for_review
    branches:
      - main
      - master
  schedule:
    # Scheduled nightly scan — runs every night at 2 AM UTC (Mon-Sat)
    - cron: '0 2 * * 1-6'
    # Weekly full scan — runs Sunday night at 2 AM UTC
    - cron: '0 2 * * 0'
  # checkov:skip=CKV_GHA_7:Workflow inputs control scan parameters not build artifacts
  workflow_dispatch:
    inputs:
      subdirectory:
        description: 'Optional: Subdirectory path to scan (e.g., apps/api)'
        required: false
        type: string
      scan_mode:
        description: 'Scan mode (quick/full/nightly/stig)'
        required: false
        default: 'full'
        type: choice
        options:
          - quick
          - full
          - nightly
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
  # Quick gate scan on pull requests — fast feedback, no full report generation.
  # Skipped for draft PRs; re-runs automatically once marked "Ready for review"
  # (which fires a synchronize/ready_for_review event) or on the next push.
  security-scan-pr:
    if: github.event_name == 'pull_request' && github.event.pull_request.draft == false
    permissions:
      contents: read
      actions: read
      pull-requests: write
      security-events: write
      issues: write
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: quick
      skip_garak: true
      # Note: STIG (Layer 13) is opt-in by default. Set run_stig: true to enable.
    secrets: inherit

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
      scan_mode: \${{ github.event_name == 'schedule' && (github.event.schedule == '0 2 * * 0' && 'full' || 'nightly') || github.event.inputs.scan_mode || 'full' }}
      # STIG uses AI tokens, so it runs only when explicitly chosen via workflow_dispatch
      run_stig: \${{ github.event.inputs.scan_mode == 'stig' }}
      subdirectory: \${{ github.event.inputs.subdirectory || '' }}
      garak_target_type: \${{ github.event.inputs.garak_target_type || 'openai' }}
      garak_target_name: \${{ github.event.inputs.garak_target_name || 'gpt-4o-mini' }}
      garak_probes: \${{ github.event.inputs.garak_probes || 'promptinject' }}
    secrets: inherit`;










// Manifest layer numbers that can be individually toggled for the
// self-diagnostic run (mirrors tests/fixtures/self-assessment/expected-
// findings.json and _SELF_ASSESSMENT_VALID_LAYERS in web/api/main.py).
// Layer 3 (SonarQube) and Layer 20 (ML Runtime, opt-in only) are excluded —
// they're never run by the harness regardless of selection.
const SELF_DIAG_LAYERS = [
  { n: '1',  name: 'SBOM Generation' },
  { n: '2',  name: 'Secret Detection' },
  { n: '4',  name: 'Malware Detection' },
  { n: '5',  name: 'Helm Chart Build' },
  { n: '6',  name: 'IaC Security' },
  { n: '7',  name: 'Container Security' },
  { n: '8',  name: 'Vulnerability Scanning' },
  { n: '8.5', name: 'Direct Dependency Scanning (pip-audit)' },
  { n: '9',  name: 'EOL Detection' },
  { n: '10', name: 'Container Analysis' },
  { n: '11', name: 'API Discovery' },
  { n: '13', name: 'STIG Compliance' },
  { n: '14', name: 'Model File Analysis' },
  { n: '15', name: 'Model Card Compliance' },
  { n: '16', name: 'Network Discovery' },
  { n: '18', name: 'Model Provenance & Threat Intel' },
  { n: '19', name: 'Inference Environment Security' },
  { n: '21', name: 'Compromised Source Detection' },
];

function renderSelfDiagLayerPicker() {
  const boxes = SELF_DIAG_LAYERS.map(l => `
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg-input)">
      <input type="checkbox" class="self-diag-layer-checkbox" value="${l.n}" checked>
      <span>L${l.n} — ${esc(l.name)}</span>
    </label>`).join('');
  return `
    <details style="margin-bottom:12px">
      <summary style="cursor:pointer;font-size:13px;color:var(--text-muted)">Select layers to validate (defaults to all)</summary>
      <div style="margin-top:10px">
        <div style="margin-bottom:8px">
          <button type="button" class="btn btn-sm" onclick="setSelfDiagLayers(true)">Select All</button>
          <button type="button" class="btn btn-sm" onclick="setSelfDiagLayers(false)">Select None</button>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">${boxes}</div>
      </div>
    </details>`;
}

function setSelfDiagLayers(checked) {
  document.querySelectorAll('.self-diag-layer-checkbox').forEach(cb => { cb.checked = checked; });
}

// Renders the Self-Assessment (cross-layer scanner validation) card body —
// used both on initial Performance page load and to refresh in place after
// a "Run Self-Diagnostic" job completes, without a full page re-render.
function renderSelfAssessmentBody(sa) {
  if (!sa || !sa.available) {
    return `<div style="color:var(--text-muted);font-size:13px">No self-assessment has run yet on this deployment. Click "Run Self-Diagnostic" above, or run <code>scripts/shell/run-self-assessment.sh</code> manually.</div>`;
  }
  const gumball = {
    pass:                { icon: '🟢', label: 'PASS',    cls: 'clean' },
    fail:                { icon: '🔴', label: 'FAIL',    cls: 'critical' },
    environment_limited: { icon: '🟡', label: 'ENV-LIMITED', cls: 'medium' },
    // "not_validated" (best-effort — the tool ran but this layer has no
    // deterministic pass/fail check) and "skipped" (layer wasn't selected
    // for this run) are functionally different but look identical if both
    // render as a gray "SKIP" gumball — label them distinctly so users
    // don't mistake "best-effort" for "you didn't select this".
    not_validated:       { icon: '⚪', label: 'N/A',     cls: '' },
    skipped:             { icon: '⚪', label: 'SKIPPED', cls: '' },
  };
  const rows = sa.layers.map(l => {
    const g = gumball[l.status] || { icon: '⚪', label: (l.status || '').toUpperCase(), cls: '' };
    let reason = '—';
    if (l.status === 'fail') {
      reason = `Expected ≥ ${l.expected_min}, found ${l.actual}`;
    } else if (l.status === 'pass') {
      reason = `Found ${l.actual} (expected ≥ ${l.expected_min})`;
    } else if (l.notes) {
      reason = esc(l.notes);
    }
    const ran = Number.isFinite(l.elapsed_seconds)
      ? `<span title="${esc(l.completed_at || '')}">+${l.elapsed_seconds}s</span>`
      : '<span style="color:var(--text-muted)">—</span>';
    return `
      <tr>
        <td>${esc(String(l.layer))}</td>
        <td>${esc(l.name)}</td>
        <td><span class="sev-badge ${g.cls}" style="font-size:12px">${g.icon} ${g.label}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${reason}</td>
        <td style="font-size:12px;color:var(--text-muted);white-space:nowrap">${ran}</td>
      </tr>`;
  }).join('');

  // Chronological step-by-step view — reconstructed from each layer's
  // output-file mtime (see compare-self-assessment.py::_layer_completed_at),
  // since run-self-assessment.sh has no live per-layer timing data the way
  // a regular CI scan does. Gives a genuine "when did each step run" trail
  // even after the run has finished and the live console log is gone.
  const timeline = Array.isArray(sa.timeline) ? sa.timeline : [];
  const timelineHtml = timeline.length ? `
    <div style="margin-top:16px">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">Step-by-step timeline</div>
      <div style="display:flex;flex-direction:column;gap:4px">
        ${timeline.map(t => {
          const g = gumball[t.status] || { icon: '⚪', label: (t.status || '').toUpperCase() };
          return `<div style="display:flex;gap:10px;align-items:center;font-size:12px;color:var(--text-muted)">
            <span style="min-width:48px;font-variant-numeric:tabular-nums">+${t.elapsed_seconds}s</span>
            <span>${g.icon}</span>
            <span style="color:var(--text-primary)">L${esc(String(t.layer))} ${esc(t.name)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>` : '';

  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:16px">
      <div class="stat-card">
        <div class="stat-label">Passed</div>
        <div class="stat-value" style="color:var(--clean)">${sa.summary.passed}/${sa.summary.validated_layers - sa.summary.environment_limited}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Failed</div>
        <div class="stat-value" style="color:${sa.summary.failed > 0 ? 'var(--critical)' : 'var(--text-primary)'}">${sa.summary.failed}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Environment-Limited</div>
        <div class="stat-value">${sa.summary.environment_limited}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Best-Effort (Not Validated)</div>
        <div class="stat-value">${sa.summary.not_validated}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Skipped (Not Selected)</div>
        <div class="stat-value">${sa.summary.skipped || 0}</div>
      </div>
    </div>
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">Last run: ${new Date(sa.generated_at).toLocaleString()} against ${esc(sa.scan_dir?.split('/').pop() || 'unknown scan')}</div>
    <div class="table-container">
      <table>
        <thead>
          <tr><th scope="col">Layer</th><th scope="col">Name</th><th scope="col">Status</th><th scope="col">Why</th><th scope="col">Ran at</th></tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
    ${timelineHtml}`;
}



















// ── API client ────────────────────────────────────────────────
// ── Frontend cache ───────────────────────────────────────────


// ── API client with caching ───────────────────────────────────



// ── Theme ────────────────────────────────────────────────────
function applyTheme(theme) {
  if (document && document.documentElement) {
    document.documentElement.setAttribute('data-theme', theme);
  }
  const moon = document.getElementById ? document.getElementById('theme-icon-moon') : null;
  const sun  = document.getElementById ? document.getElementById('theme-icon-sun') : null;
  if (moon && moon.style) moon.style.display = theme === 'dark'  ? '' : 'none';
  if (sun && sun.style)  sun.style.display  = theme === 'light' ? '' : 'none';
  try { localStorage.setItem('epyon-theme', theme); } catch (_) {}
}



function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

async function clearCacheAndReload() {
  // Show cache metrics before clearing
  const frontendMetrics = _cache.getMetrics();
  console.log('Frontend Cache Metrics:', frontendMetrics);
  
  const msg = `Clear all cached data and reload?\n\n` +
    `Frontend Cache:\n` +
    `  Hits: ${frontendMetrics.hits}\n` +
    `  Misses: ${frontendMetrics.misses}\n` +
    `  Hit Rate: ${frontendMetrics.hit_rate_pct || 'N/A'}%\n` +
    `  Avg Staleness: ${frontendMetrics.avg_staleness_ms || 'N/A'}ms`;
  
  if (await confirmDialog({ title: 'Clear cache and reload', body: msg, confirmLabel: 'Clear and reload', danger: false })) {
    _cache.invalidate();
    window.location.reload();
  }
}

(function initTheme() {
  try {
    const stored = localStorage.getItem('epyon-theme');
    if (stored === 'light' || stored === 'dark') {
      applyTheme(stored);
      return;
    }
  } catch (_) {}
  // Fall back to OS preference
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(prefersDark ? 'dark' : 'light');
})();

// ── Sidebar collapse ─────────────────────────────────────────
const _mobileNav = () => window.matchMedia('(max-width: 768px)').matches;

function _syncSidebarToggle() {
  const sidebar = document.getElementById('sidebar');
  const btn = document.getElementById('sidebar-toggle');
  if (sidebar && btn) btn.setAttribute('aria-expanded', String(!sidebar.classList.contains('collapsed')));
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const collapsed = sidebar.classList.toggle('collapsed');
  // On phones the menu always starts closed, so only desktop remembers the choice.
  if (!_mobileNav()) {
    try { localStorage.setItem('epyon-sidebar-collapsed', collapsed ? '1' : ''); } catch (_) {}
  }
  _syncSidebarToggle();
}

(function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  let collapsed = _mobileNav();
  if (!collapsed) {
    try { collapsed = localStorage.getItem('epyon-sidebar-collapsed') === '1'; } catch (_) {}
  }
  if (sidebar && collapsed) sidebar.classList.add('collapsed');
  _syncSidebarToggle();

  // Close the phone menu after choosing a page.
  sidebar?.addEventListener('click', e => {
    if (_mobileNav() && e.target.closest('.nav-link')) {
      sidebar.classList.add('collapsed');
      _syncSidebarToggle();
    }
  });
})();

// ── Navigation ────────────────────────────────────────────────
function setActive(routeKey) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeKey);
  });
  // Clear findings registry and close any open drawer on navigation
  _findingsRegistry.clear();
  _findingNextId = 0;
  _stigRegistry.clear();
  for (const k of Object.keys(_currentFindingsBySev)) delete _currentFindingsBySev[k];
  for (const k of Object.keys(_sortState))             delete _sortState[k];
  for (const k of Object.keys(_pageState))             delete _pageState[k];
  closeFindingDetail();
  closeStigDetail();
}

// ── Views ─────────────────────────────────────────────────────

async function renderOverview() {
  setActive('overview');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [stats, apps] = await Promise.all([api.getStats(), api.getApplications()]);

    const continuous  = apps.filter(a => a.monitored);
    const evaluation  = apps.filter(a => !a.monitored);
    const anyMonitored = continuous.length > 0;

    const makeCard = app => `
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
            <div class="severity-row">${gateBadge(app)} ${sevBadgeRow(app)}</div>
            <div class="app-card-footer">
              ${app.scan_count} scan${app.scan_count !== 1 ? 's' : ''} total
            </div>
          </div>`;

    const appSections = apps.length
      ? anyMonitored
        ? `<div class="section">
             <div class="section-title">
               <span>● Continuously Monitored <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${continuous.length})</span></span>
               <button class="btn btn-sm" onclick="navigate('#/applications')">View all →</button>
             </div>
             <div class="app-grid">${continuous.map(makeCard).join('')}</div>
           </div>
           ${evaluation.length ? `
           <div class="section" style="margin-top:24px">
             <div class="section-title">
               <span>◯ Evaluation <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${evaluation.length})</span></span>
             </div>
             <div class="app-grid">${evaluation.map(makeCard).join('')}</div>
           </div>` : ''}`
        : `<div class="section">
             <div class="section-title">
               Applications
               <button class="btn btn-sm" onclick="navigate('#/applications')">View all →</button>
             </div>
             <div class="app-grid">${apps.map(makeCard).join('')}</div>
           </div>`
      : `<div class="section">
           <div class="section-title">Applications</div>
           ${emptyState(
             'No applications yet',
             'Run your first scan to see applications here.',
             `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">▶ Run First Scan</button>`,
           )}
         </div>`;

    page.innerHTML = `
      ${pageHeader(`Security Overview`, { actions: `<button class="btn btn-primary" onclick="navigate('#/new-scan')">+ Run Scan</button>` })}

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

      ${buildCveSearchSection()}
      ${buildOverviewExecSection()}
      ${buildOverviewTechSection()}
      ${buildOverviewIssoSection()}

      ${appSections}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ── Cross-application CVE search (Overview) ───────────────────
function buildCveSearchSection() {
  return `
    <div class="section cve-search">
      <div class="section-title">Search a CVE across applications</div>
      <form class="cve-search-form" onsubmit="cveSearchRun(event)">
        <input id="cve-search-q" class="cve-search-input" type="text" minlength="3" maxlength="100"
               placeholder="CVE-2024-12345, GHSA-…, or package name" autocomplete="off" required>
        <select id="cve-search-field" class="cve-search-select" aria-label="Search by">
          <option value="id">CVE / advisory ID</option>
          <option value="package">Package name</option>
        </select>
        <label class="cve-search-history">
          <input id="cve-search-history" type="checkbox"> Include earlier scans
        </label>
        <button class="btn btn-primary" type="submit">Search</button>
      </form>
      <div id="cve-search-results"></div>
    </div>`;
}

let _cveSearchSeq = 0;
let _cveBulk = { data: null, selected: new Set() };

async function cveSearchRun(ev) {
  if (ev) ev.preventDefault();
  const out = document.getElementById('cve-search-results');
  if (!out) return;
  const q = document.getElementById('cve-search-q').value.trim();
  const field = document.getElementById('cve-search-field').value;
  const history = document.getElementById('cve-search-history').checked;
  const seq = ++_cveSearchSeq;
  out.innerHTML = loading();
  try {
    const params = new URLSearchParams({ q, field, include_history: history ? 'true' : 'false' });
    const r = await fetch(`/api/findings/search?${params}`);
    if (r.status === 400) throw new Error('Enter 3–100 characters: letters, digits and . _ : @ / + -');
    if (!r.ok) throw new Error('Search failed. Please try again.');
    const data = await r.json();
    if (seq !== _cveSearchSeq) return;
    _cveBulk = { data, selected: new Set() };
    out.innerHTML = cveSearchResultsHtml(data);
  } catch (e) {
    if (seq === _cveSearchSeq) out.innerHTML = errBanner(e.message, { retry: false });
  }
}

function cveBulkToggle(box) {
  if (box.checked) _cveBulk.selected.add(box.dataset.key); else _cveBulk.selected.delete(box.dataset.key);
  cveBulkRefreshButton();
}

function cveBulkToggleAll(master) {
  document.querySelectorAll('#cve-search-results .cve-select:not([disabled])').forEach(box => {
    box.checked = master.checked;
    cveBulkToggle(box);
  });
}

function cveBulkRefreshButton() {
  const btn = document.getElementById('cve-bulk-create');
  if (!btn) return;
  const n = _cveBulk.selected.size;
  btn.disabled = n === 0;
  btn.textContent = n ? `Create Jira tickets (${n})` : 'Create Jira tickets';
}

// Selected findings grouped by search entry (one scan per application).
function cveBulkGroups() {
  const groups = new Map();
  for (const key of _cveBulk.selected) {
    const [ai, fi] = key.split(':').map(Number);
    const entry = _cveBulk.data.applications[ai];
    if (!entry || !entry.findings[fi]) continue;
    if (!groups.has(ai)) groups.set(ai, { entry, findings: [], projectKey: entry.project_key || '', originalKey: entry.project_key || '' });
    groups.get(ai).findings.push(entry.findings[fi]);
  }
  return [...groups.values()];
}

// Resolve each selected finding to its current Jira candidate; sorts it into eligible or skipped.
async function cveBulkResolve(group) {
  group.eligible = [];
  group.skipped = [];
  group.error = '';
  if (!group.entry.jira_configured) {
    group.skipped = group.findings.map(f => ({ f, reason: 'Jira not configured for this application' }));
    return;
  }
  try {
    const data = await api.getJiraCandidates(group.entry.scan_id);
    for (const f of group.findings) {
      const norm = v => String(v || '').trim().toLowerCase();
      const matches = data.candidates.filter(c => norm(c.id) === norm(f.id) && norm(c.package) === norm(f.package));
      const pick = matches.find(c => c.selectable);
      if (matches.some(c => c.jira_ticket || c.selection_reason === 'already_ticketed')) group.skipped.push({ f, reason: 'already ticketed' });
      else if (pick) group.eligible.push({ f, fingerprint: pick.fingerprint });
      else if (matches.length) group.skipped.push({ f, reason: 'suppressed' });
      else group.skipped.push({ f, reason: 'no longer in this scan' });
    }
  } catch (e) {
    group.error = e.message;
  }
}

async function cveBulkOpen() {
  const groups = cveBulkGroups();
  if (!groups.length) return;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-container modal-lg"><div id="cve-bulk-body">${loading()}</div></div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) cveBulkClose(); });
  await Promise.all(groups.map(cveBulkResolve));
  let issueTypes = [], defaultType = 'Bug';
  const first = groups.find(g => g.entry.jira_configured && !g.error);
  if (first) {
    try {
      const epics = await api.getScanJiraEpics(first.entry.scan_id);
      issueTypes = (epics.issue_types || []).map(t => t.name);
      defaultType = epics.default_issue_type || 'Bug';
    } catch (e) { /* fall back to the default type */ }
  }
  _cveBulk.modal = { groups, issueTypes, issueType: defaultType, triagedBy: '', running: false };
  cveBulkRenderForm();
}

function cveBulkClose() {
  if (_cveBulk.modal?.running) return;
  document.querySelector('.modal-overlay')?.remove();
}

function cveBulkRenderForm() {
  const m = _cveBulk.modal;
  const body = document.getElementById('cve-bulk-body');
  if (!body) return;
  const total = m.groups.reduce((n, g) => n + g.eligible.length, 0);
  const types = m.issueTypes.length ? m.issueTypes : [m.issueType];
  const groupHtml = m.groups.map((g, i) => {
    const sk = g.skipped.length
      ? `<div class="cve-bulk-skipped">Skipped ${g.skipped.length}: ${esc([...new Set(g.skipped.map(s => s.reason))].join('; '))}</div>` : '';
    if (!g.entry.jira_configured || g.error) {
      return `<div class="cve-bulk-group"><strong>${esc(g.entry.app_name)}</strong>
        <div class="cve-bulk-skipped">${g.error ? `Could not load Jira state: ${esc(g.error)}` : 'Skipped — Jira is not configured for this application'}</div></div>`;
    }
    return `<div class="cve-bulk-group"><div class="cve-bulk-head"><strong>${esc(g.entry.app_name)}</strong>
        <span>${g.eligible.length} ticket${g.eligible.length === 1 ? '' : 's'} to create</span></div>
      <div class="cve-bulk-fields">
        <label class="field-label">Jira project (board key)
          <input class="field-input" type="text" maxlength="10" data-gi="${i}" value="${esc(g.projectKey)}"
            oninput="this.value=this.value.toUpperCase().replace(/[^A-Z0-9]/g,''); cveBulkKeyTyped(this)"></label>
        <label class="field-label">Epic key (optional)
          <input class="field-input" type="text" maxlength="30" placeholder="${esc(g.projectKey || 'PROJECT')}-123" data-gi="${i}" value="${esc(g.epicKey || '')}"
            oninput="this.value=this.value.toUpperCase(); cveBulkModalState().groups[${i}].epicKey=this.value.trim()"></label>
      </div>${sk}</div>`;
  }).join('');
  body.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="color:var(--text);margin:0">Create Jira tickets for ${esc(_cveBulk.data.query)}</h2>
      <button class="btn" onclick="cveBulkClose()" style="padding:6px 12px">✕</button>
    </div>
    <p style="color:var(--text-muted);font-size:13px;margin:0 0 12px">Confirm each application's Jira project before creating. Changing a key updates the Jira project for that whole application.</p>
    ${groupHtml}
    <div class="cve-bulk-fields" style="margin-top:12px">
      <label class="field-label">Ticket type
        <select class="field-input" onchange="cveBulkModalState().issueType=this.value">
          ${types.map(t => `<option value="${esc(t)}" ${t === m.issueType ? 'selected' : ''}>${esc(t)}</option>`).join('')}
        </select></label>
      <label class="field-label">Triaged by (optional)
        <input class="field-input" type="text" maxlength="200" value="${esc(m.triagedBy)}"
          oninput="cveBulkModalState().triagedBy=this.value"></label>
    </div>
    <div class="modal-actions" style="margin-top:20px;display:flex;justify-content:flex-end;gap:10px">
      <button class="btn" onclick="cveBulkClose()">Cancel</button>
      <button id="cve-bulk-confirm" class="btn btn-primary" onclick="cveBulkConfirm()" ${total ? '' : 'disabled'}>Create ${total} ticket${total === 1 ? '' : 's'}</button>
    </div>`;
}

function cveBulkModalState() { return _cveBulk.modal; }

function cveBulkKeyTyped(input) {
  _cveBulk.modal.groups[Number(input.dataset.gi)].projectKey = input.value.trim();
}

async function cveBulkConfirm() {
  const m = _cveBulk.modal;
  if (!m || m.running) return;
  const bad = m.groups.find(g => g.eligible.length && !/^[A-Z][A-Z0-9]{0,9}$/.test(g.projectKey));
  if (bad) { toast(`Enter a valid Jira project key for ${bad.entry.app_name}.`, 'warning'); return; }
  m.running = true;
  const body = document.getElementById('cve-bulk-body');
  const results = [];
  for (const [i, g] of m.groups.entries()) {
    if (!g.eligible.length) {
      results.push({ g, created: 0, existing: 0, failed: 0, skipped: g.findings.length, note: g.error || g.skipped[0]?.reason || '' });
      continue;
    }
    if (body) body.innerHTML = `<p>Creating tickets for ${esc(g.entry.app_name)} (${i + 1} of ${m.groups.length})…</p>${loading()}`;
    const r = { g, created: 0, existing: 0, failed: 0, skipped: g.skipped.length, note: '', keys: [] };
    try {
      let fingerprints = g.eligible.map(x => x.fingerprint);
      if (g.projectKey !== g.originalKey) {
        await api.setJiraProject(g.entry.scan_id, g.projectKey);
        g.originalKey = g.projectKey;
        await cveBulkResolve(g);
        if (g.error) {
          r.failed = g.findings.length;
          r.skipped = 0;
          r.note = g.error;
          results.push(r);
          continue;
        }
        fingerprints = g.eligible.map(x => x.fingerprint);
        r.skipped = g.skipped.length;
        if (!fingerprints.length) { results.push(r); continue; }
      }
      const extras = {
        ...(m.issueType ? { issue_type: m.issueType } : {}),
        ...(m.triagedBy ? { triaged_by: m.triagedBy } : {}),
        ...(g.epicKey ? { epic_key: g.epicKey } : {}),
      };
      for (let at = 0; at < fingerprints.length; at += 200) {
        const res = await api.createJiraTickets(g.entry.scan_id, fingerprints.slice(at, at + 200), extras);
        r.created += res.created.length;
        r.existing += res.already_exists.length;
        const bad = res.failed.concat(res.ineligible);
        r.failed += bad.length;
        if (bad.length) r.note = bad[0].reason || 'unknown';
        res.created.forEach(c => r.keys.push(c.issue_key || c.key));
      }
    } catch (e) {
      r.failed = g.eligible.length - r.created - r.existing;
      r.note = e.message;
    }
    results.push(r);
  }
  m.running = false;
  cveBulkRenderSummary(results);
}

function cveBulkRenderSummary(results) {
  const body = document.getElementById('cve-bulk-body');
  if (!body) return;
  const rows = results.map(r => `<tr>
      <td>${esc(r.g.entry.app_name)}</td><td>${esc(r.created)}</td><td>${esc(r.existing)}</td>
      <td>${esc(r.failed)}</td><td>${esc(r.skipped)}</td><td>${esc(r.note || '')}</td></tr>`).join('');
  body.innerHTML = `
    <h2 style="color:var(--text);margin:0 0 12px">Jira tickets</h2>
    <div class="table-container"><table>
      <thead><tr><th scope="col">Application</th><th scope="col">Created</th><th scope="col">Existing</th><th scope="col">Failed</th><th scope="col">Skipped</th><th scope="col">Reason</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
    <div class="modal-actions" style="margin-top:20px;display:flex;justify-content:flex-end">
      <button class="btn btn-primary" onclick="cveBulkClose(); cveSearchRun()">Done</button>
    </div>`;
}

function cveSearchResultsHtml(data) {
  if (!data.applications.length) {
    return `<div class="cve-search-empty">“${esc(data.query)}” was not found in any monitored application.</div>`;
  }
  const rows = data.applications.map((appEntry, ai) => appEntry.findings.map((f, fi) => {
    const query = new URLSearchParams({ finding: f.id, package: f.package || '' });
    const href = `#/scans/${encodeURIComponent(appEntry.scan_id)}?${query}`;
    const ticket = f.jira_issue_key
      ? (appEntry.jira_base_url
          ? `<a href="${esc(appEntry.jira_base_url)}/browse/${encodeURIComponent(f.jira_issue_key)}" target="_blank" rel="noopener">${esc(f.jira_issue_key)}</a>`
          : esc(f.jira_issue_key))
      : '—';
    return `
      <tr class="finding-row" title="Open finding in scan">
        <td><input type="checkbox" class="cve-select" data-key="${ai}:${fi}"
            aria-label="Select ${esc(f.id)} in ${esc(appEntry.app_name)}" onchange="cveBulkToggle(this)"></td>
        <td>${esc(appEntry.app_name)}${appEntry.is_latest ? '' : ' <span class="tool-tag">earlier scan</span>'}</td>
        <td><span class="sev-badge ${esc(f.severity)}">${esc(ucFirst(f.severity))}</span></td>
        <td><a href="${esc(href)}" data-href="${esc(href)}" onclick="if (event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey) { event.preventDefault(); navigate(this.dataset.href); }">${esc(f.id)}</a>${f.suppressed ? ' <span class="tool-tag">suppressed</span>' : ''}</td>
        <td>${(f.tools || []).map(t => `<span class="tool-tag">${esc(t)}</span>`).join(' ')}</td>
        <td>${esc(f.package || '—')}</td>
        <td>${esc(f.version || '—')}</td>
        <td>${esc(f.fixed_version || '—')}</td>
        <td>${esc(fmtDate(appEntry.timestamp))}</td>
        <td>${ticket}</td>
      </tr>`;
  }).join('')).join('');
  return `
    <div class="cve-search-summary">${esc(data.total_findings)} finding${data.total_findings === 1 ? '' : 's'} across ${esc(data.total_applications)} application${data.total_applications === 1 ? '' : 's'}
      <button id="cve-bulk-create" class="btn btn-primary btn-sm" onclick="cveBulkOpen()" disabled>Create Jira tickets</button>
    </div>
    <div class="table-container">
      <table>
        <thead><tr><th scope="col"><input type="checkbox" id="cve-select-all" aria-label="Select all eligible findings" onchange="cveBulkToggleAll(this)"></th><th scope="col">Application</th><th scope="col">Severity</th><th scope="col">ID</th><th scope="col">Tools</th><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Fixed in</th><th scope="col">Scanned</th><th scope="col">Jira</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

async function toggleMonitored(name, isCurrently) {
  try {
    if (isCurrently) {
      await api.unsetMonitored(name);
    } else {
      await api.setMonitored(name);
    }
    renderApplications();
  } catch (e) {
    toast('Failed to update monitoring status: ' + e.message, 'error');
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
              ${app.url ? `<div style="font-size:12px;color:var(--text-dim);margin-top:2px">${esc(app.url)}</div>` : ''}
            </td>
            <td onclick="event.stopPropagation();toggleMonitored('${esc(app.name)}',${!!app.monitored})">
              <button class="app-type-badge ${app.monitored ? 'monitored' : 'evaluation'}"
                      title="${app.monitored ? 'Continuous — click to set as Evaluation' : 'Evaluation — click to set as Continuous'}">
                ${app.monitored ? '● Continuous' : '○ Evaluation'}
              </button>
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
      : emptyRow(10, 'No applications found. Run a scan to get started.');

    const hiddenSection = hidden.length ? `
      <div class="section" style="margin-top:32px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
          <span>Hidden Applications <span style="font-size:12px;color:var(--text-muted);font-weight:400">(${hidden.length})</span></span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th scope="col">Application</th>
                <th scope="col"></th>
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
      ${pageHeader(`Applications`, { actions: `<button class="btn" onclick="showAddAppModal()">+ Add Application</button>
          <button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>` })}
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th scope="col">Application</th>
              <th scope="col">Type</th>
              <th scope="col">Last Scanned</th>
              <th scope="col">Scans</th>
              <th scope="col">Critical</th>
              <th scope="col">High</th>
              <th scope="col">Medium</th>
              <th scope="col">Low</th>
              <th scope="col">Status</th>
              <th scope="col"></th>
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

function buildScanTimelineItem(s, name) {
  const st = computeStatus(s);
  return `
    <div class="scan-timeline-item"
         onclick="navigate('#/scans/${encodeURIComponent(s.scan_id)}')">
      <div class="scan-timeline-dot ${esc(st)}"></div>
      <div class="scan-timeline-content">
        <div class="scan-timeline-title">
          ${esc(scanTypeLabel(s.scan_type))} scan
          <span>${gateBadge(s)} ${sevBadgeRow(s)}</span>
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
             HTML ↗
           </button>`
        : ''}
      <button class="btn btn-sm btn-danger"
        onclick="event.stopPropagation();deleteScan('${esc(s.scan_id)}', '${esc(name)}')"
        title="Permanently delete this scan">
        Delete
      </button>
    </div>`;
}

// Scan History tabs: Full/Nightly, Quick, STIG, Other (baseline, local model, container image, ...).
const SCAN_HISTORY_TABS = [
  { id: 'full',  label: 'Full / Nightly', types: ['full', 'nightly'] },
  { id: 'quick', label: 'Quick',          types: ['quick'] },
  { id: 'stig',  label: 'STIG',           types: ['stig'] },
  { id: 'other', label: 'Other',          types: null },
];
const SCAN_HISTORY_PAGE_SIZE = 15;
const _scanHistoryState = {};

function scanHistoryTabOf(scan) {
  const t = SCAN_HISTORY_TABS.find(tab => tab.types && tab.types.includes(scan.scan_type));
  return t ? t.id : 'other';
}

// Local calendar day (YYYY-MM-DD) of a scan, so the date filter matches what fmtDate shows.
function scanLocalDay(scan) {
  const d = new Date(scan.timestamp);
  if (isNaN(d)) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function scanHistoryFiltered(scans, st) {
  return scans.filter(s => {
    if (scanHistoryTabOf(s) !== st.tab) return false;
    const day = scanLocalDay(s);
    if (st.from && (!day || day < st.from)) return false;
    if (st.to && (!day || day > st.to)) return false;
    return true;
  });
}

function buildScanHistory(name, scans) {
  const saved = _scanHistoryState[name] || {};
  // Default to the tab holding the newest scan so the page never opens on an empty tab.
  const tab = SCAN_HISTORY_TABS.some(t => t.id === saved.tab) ? saved.tab : scanHistoryTabOf(scans[0]);
  const st = { tab, page: saved.page || 1, from: saved.from || '', to: saved.to || '' };
  _scanHistoryState[name] = st;
  window._scanHistoryScans = { name, scans };
  const counts = {};
  scans.forEach(s => { const id = scanHistoryTabOf(s); counts[id] = (counts[id] || 0) + 1; });
  const tabs = SCAN_HISTORY_TABS.map(t => `
    <button class="scan-history-tab${t.id === tab ? ' active' : ''}" role="tab"
      id="scan-tab-${t.id}" aria-selected="${t.id === tab}" aria-controls="scan-history-panel"
      data-tab="${t.id}" onclick="selectScanHistoryTab(this.dataset.tab)">
      ${esc(t.label)} <span class="scan-history-count">${counts[t.id] || 0}</span>
    </button>`).join('');
  return `
    <div class="scan-history-tabs" role="tablist" aria-label="Scan type">${tabs}</div>
    <div class="scan-history-filter">
      <label>From <input type="date" id="scan-filter-from" value="${esc(st.from)}"
        onchange="setScanHistoryDates()"></label>
      <label>To <input type="date" id="scan-filter-to" value="${esc(st.to)}"
        onchange="setScanHistoryDates()"></label>
      <button class="btn btn-sm" id="scan-filter-clear" onclick="clearScanHistoryDates()"
        ${st.from || st.to ? '' : 'hidden'}>Clear dates</button>
    </div>
    <div id="scan-history-panel" role="tabpanel">${scanHistoryPanel(name, scans, st)}</div>`;
}

function scanHistoryPanel(name, scans, st) {
  const items = scanHistoryFiltered(scans, st);
  const label = SCAN_HISTORY_TABS.find(t => t.id === st.tab).label;
  if (!items.length) {
    const why = st.from || st.to ? ' in this date range' : '';
    return `<div class="scan-history-empty">No ${esc(label)} scans${why} for this application.</div>`;
  }
  const pages = Math.ceil(items.length / SCAN_HISTORY_PAGE_SIZE);
  st.page = Math.min(Math.max(st.page, 1), pages);
  const start = (st.page - 1) * SCAN_HISTORY_PAGE_SIZE;
  const rows = items.slice(start, start + SCAN_HISTORY_PAGE_SIZE)
    .map(s => buildScanTimelineItem(s, name)).join('');
  const pager = items.length > SCAN_HISTORY_PAGE_SIZE ? `
    <div class="scan-history-pager">
      <button class="btn btn-sm" onclick="setScanHistoryPage(${st.page - 1})" ${st.page <= 1 ? 'disabled' : ''}>‹ Prev</button>
      <span>Showing ${start + 1}–${Math.min(start + SCAN_HISTORY_PAGE_SIZE, items.length)} of ${items.length} · Page ${st.page} of ${pages}</span>
      <button class="btn btn-sm" onclick="setScanHistoryPage(${st.page + 1})" ${st.page >= pages ? 'disabled' : ''}>Next ›</button>
    </div>` : '';
  return rows + pager;
}

function refreshScanHistory() {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  const st = _scanHistoryState[ctx.name];
  document.querySelectorAll('.scan-history-tab').forEach(btn => {
    const on = btn.dataset.tab === st.tab;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
  });
  const clear = document.getElementById('scan-filter-clear');
  if (clear) clear.hidden = !(st.from || st.to);
  document.getElementById('scan-history-panel').innerHTML = scanHistoryPanel(ctx.name, ctx.scans, st);
}

function selectScanHistoryTab(tabId) {
  const ctx = window._scanHistoryScans;
  if (!ctx || !SCAN_HISTORY_TABS.some(t => t.id === tabId)) return;
  Object.assign(_scanHistoryState[ctx.name], { tab: tabId, page: 1 });
  refreshScanHistory();
}

function setScanHistoryPage(page) {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  _scanHistoryState[ctx.name].page = page;
  refreshScanHistory();
}

function setScanHistoryDates() {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  Object.assign(_scanHistoryState[ctx.name], {
    from: document.getElementById('scan-filter-from').value,
    to: document.getElementById('scan-filter-to').value,
    page: 1,
  });
  refreshScanHistory();
}

function clearScanHistoryDates() {
  document.getElementById('scan-filter-from').value = '';
  document.getElementById('scan-filter-to').value = '';
  setScanHistoryDates();
}

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
      ? buildScanHistory(name, scans)
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

    // Use comprehensive-scan counts (same source as overview cards) so numbers match.
    // If the most recent scan was a quick/stig scan, flag it so the user knows the
    // vulnerability counts are from an earlier full scan.
    const compTs   = appInfo.comprehensive_timestamp || '';
    const compType = appInfo.comprehensive_scan_type  || '';
    const countsDiffer = compTs && compTs !== latest.timestamp;
    const countsNote = countsDiffer
      ? `<div style="grid-column:1/-1;font-size:12px;color:var(--text-muted);margin-top:4px">
           Vulnerability counts are from the last ${esc(scanTypeLabel(compType))} scan
           (${fmtDate(compTs)}) — quick scans do not run all tools.
         </div>`
      : '';

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
          <div class="value" style="color:var(--critical)">${appInfo.critical ?? latest.critical ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${appInfo.high ?? latest.high ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${appInfo.medium ?? latest.medium ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${appInfo.low ?? latest.low ?? 0}</div>
        </div>
        ${countsNote}
      </div>` : '';

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <span>${esc(name)}</span>
      </div>
      ${pageHeader(`${esc(name)} ${statusBadge(status)}`, { actions: `<button class="btn btn-primary"
            onclick="navigate('#/new-scan?target=${encodeURIComponent(appUrl)}')">
            ▶ Run Scan
          </button>
          <button class="btn app-type-badge ${appInfo.monitored ? 'monitored' : 'evaluation'}"
            onclick="(async()=>{
              try {
                ${appInfo.monitored
                  ? `await api.unsetMonitored('${esc(name)}')`
                  : `await api.setMonitored('${esc(name)}')`};
                renderAppDetail('${esc(name)}');
              } catch(e) { toast(e.message, 'error'); }
            })()"
            title="${appInfo.monitored ? 'Continuous \u2014 click to set as Evaluation' : 'Evaluation \u2014 click to set as Continuous'}">
            ${appInfo.monitored ? '● Continuous' : '◯ Evaluation'}
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
          </button>` })}
      ${statsSection}
      ${buildAppIssoSection(name)}
      <div class="section">
        <div class="section-title">Scan History</div>
        <div class="scan-timeline">${timelineItems}</div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────











async function renderScanDetail(scanId, openFindingId = '', openFindingPackage = '') {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, allApps] = await Promise.all([api.getScan(scanId), api.getApplications()]);
    const status = computeStatus(scan);
    const appInfo = allApps.find(a => a.name === scan.target) || {};
    const repoUrl = scan.source_url || appInfo.url || scan.ci_source?.repo || '';

    // Build STIG section: show full results when available, empty state for stig/nightly scans
    const hasStigData = (scan.stig_total || 0) > 0;
    const scanTypeHasStig = ['stig', 'nightly', 'full', 'baseline'].includes(scan.scan_type);
    let stigCard = '';
    if (hasStigData) {
      const reports = scan.stig_reports || [];
      const multiStig = reports.length > 1;

      // Per-STIG rows (shown when multiple STIGs)
      const perStigRows = multiStig ? reports.map(r => {
        const slugLabel = r.slug.replace(/-/g, ' ').replace(/\bstig\b/gi, 'STIG');
        const mdBtn   = r.has_md   ? `<a class="btn btn-sm" href="${esc(r.md_url)}"   download>↓ .md</a>`   : '';
        const cklbBtn = r.has_cklb ? `<a class="btn btn-sm" href="${esc(r.cklb_url)}" download>↓ .cklb</a>` : '';
        const jsonBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/stig-findings-json?slug=${encodeURIComponent(r.slug)}" download>↓ .json</a>`;
        return `
          <div class="stig-row">
            <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
            <span class="stig-row-counts">
              <span class="stig-mini open">${esc(r.open)} open</span>
              <span class="stig-mini pass">${esc(r.pass)} pass</span>
              <span class="stig-mini na">${esc(r.na)} n/a</span>
              <span class="stig-mini total">${esc(r.total)} total</span>
            </span>
            <span class="stig-row-btns">${mdBtn}${cklbBtn}${jsonBtn}</span>
          </div>`;
      }).join('') : '';

      // Primary (combined) download buttons
      const mdBtn = scan.has_stig_report
        ? `<a class="btn btn-sm" href="${esc(scan.stig_report_url)}" download>↓ findings.md</a>` : '';
      const cklbBtn = scan.has_stig_cklb
        ? `<a class="btn btn-sm" href="${esc(scan.stig_cklb_url)}" download>↓ findings.cklb</a>` : '';
      const jsonBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/stig-findings-json" download>↓ findings.json</a>`;

      stigCard = `
        <div class="section findings-section-wrapper">
          <details class="findings-collapsible" style="border-left-color:var(--accent)">
            <summary class="findings-summary">
              <span class="findings-summary-left">
                <span class="findings-chevron" aria-hidden="true"></span>
                <span class="findings-summary-title">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                       stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                       style="vertical-align:-2px;margin-right:5px">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  STIG Assessment${multiStig ? ` <span style="color:var(--text-muted);font-weight:400;font-size:12px">(${reports.length} STIGs)</span>` : ''}
                </span>
                <span class="stig-mini open">${esc(scan.stig_open || 0)} open</span>
                <span class="stig-mini pass">${esc(scan.stig_pass || 0)} pass</span>
                <span class="stig-mini na">${esc(scan.stig_na || 0)} n/a</span>
                ${(scan.stig_nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(scan.stig_nr || 0)} evidence needed</span>` : ''}
                <span class="stig-mini total">${esc(scan.stig_total || 0)} total</span>
              </span>
              <span style="display:flex;align-items:center;gap:8px">
                ${mdBtn ? mdBtn.replace('btn-sm', 'btn-sm').replace('>', ' onclick="event.stopPropagation()">') : ''}
                ${cklbBtn ? cklbBtn.replace('>', ' onclick="event.stopPropagation()">') : ''}
                ${jsonBtn.replace('>', ' onclick="event.stopPropagation()">')}
                <span class="findings-summary-hint">Click to expand</span>
              </span>
            </summary>
            <div class="findings-body" style="padding:0 18px 16px">
              <div class="stig-counts" style="margin-top:12px">
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
                  <span class="lbl">Not Applicable</span>
                </div>
                ${(scan.stig_nr || 0) > 0 ? `
                <div class="stig-count" style="background:var(--bg-input);border-color:var(--border)">
                  <span class="num" style="color:var(--text-muted)">${esc(scan.stig_nr || 0)}</span>
                  <span class="lbl" title="Not Reviewed: open until evidence is supplied">Evidence needed</span>
                </div>` : ''}
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
            </div>
          </details>
        </div>`;
    } else {
      const noStigMsg = scanTypeHasStig
        ? 'No STIG results were recorded for this scan. Verify that STIG definitions are configured in <code>configuration/stigs/</code> and that <code>OPENAI_API_KEY</code> is set.'
        : 'STIG assessment is not included in this scan type. Run a <strong>Nightly</strong> or <strong>STIG</strong> scan to get compliance results.';
      stigCard = `
        <div class="section findings-section-wrapper">
          <details class="findings-collapsible" style="border-left-color:var(--border)">
            <summary class="findings-summary">
              <span class="findings-summary-left">
                <span class="findings-chevron" aria-hidden="true"></span>
                <span class="findings-summary-title">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                       stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                       style="vertical-align:-2px;margin-right:5px">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  STIG Assessment
                </span>
              </span>
              <span class="findings-summary-hint">Click to expand</span>
            </summary>
            <div class="findings-body" style="padding:12px 18px 16px">
              <p style="color:var(--text-muted);font-size:13px;margin:0">${noStigMsg}</p>
            </div>
          </details>
        </div>`;
    }

    // Environment-dependent gaps (e.g. a baseline-image registry pull that
    // failed, or an auto-exclusion filter) mean this scan's counts may not
    // be directly comparable to another environment's run of the same
    // target. Surface them plainly instead of leaving users to guess why
    // two scans of the same app differ.
    const envNotes = scan.environment_notes || [];
    const envNotesBanner = envNotes.length ? `
      <div class="section" style="border-left:3px solid var(--medium);padding:12px 16px;margin-bottom:16px;background:rgba(245,158,11,0.08)">
        <div style="font-weight:600;font-size:13px;margin-bottom:6px;color:var(--medium)">⚠ Environment Notes — results may differ from other environments</div>
        ${envNotes.map(n => `<div style="font-size:12.5px;color:var(--text-muted);margin-top:4px"><strong>${esc(n.layer)}:</strong> ${esc(n.message)}</div>`).join('')}
      </div>` : '';

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

      ${pageHeader(`Scan Details ${statusBadge(status)} ${gateBadge(scan)}`, { subtitle: `Findings, compliance, and evidence collected for <strong>${esc(scan.target)}</strong> on ${fmtDate(scan.timestamp)}.`, actions: `<button class="btn" onclick="navigate('#/jira-review/${encodeURIComponent(scanId)}')"
            title="Select findings to create as Jira tickets">
            Jira Review
          </button>
          ${repoUrl
            ? `<button class="btn btn-primary"
                 onclick="navigate('#/new-scan?target=${encodeURIComponent(repoUrl)}')">
                 ▶ Run Scan
               </button>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>`}
          ${scan.has_dashboard
            ? `<button class="btn"
                 onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/dashboard','_blank')">
                 Export HTML ↗
               </button>`
            : ''}
          <div class="split-btn" id="download-split-btn">
            <a class="btn split-btn-main" href="/api/scans/${encodeURIComponent(scanId)}/download" download
               title="Download all scan artifacts as ZIP for ATO/IATT submission">
              ↓ Download ZIP
            </a>
            <button class="btn split-btn-toggle" onclick="toggleDownloadMenu(event)"
              title="More download options" aria-haspopup="true" aria-expanded="false">▾</button>
            <div class="split-btn-menu" id="download-split-menu" hidden>
              <a class="split-btn-menu-item" href="/api/scans/${encodeURIComponent(scanId)}/download" download>
                ↓ Download ZIP
                <span class="split-btn-menu-hint">All raw scan artifacts (ATO/IATT bundle)</span>
              </a>
              <a class="split-btn-menu-item" href="/api/scans/${encodeURIComponent(scanId)}/download-json" download>
                ↓ Download JSON
                <span class="split-btn-menu-hint">Full parsed scan result (findings, STIG, ML/AI)</span>
              </a>
            </div>
          </div>
          <button class="btn btn-danger"
            onclick="deleteScan('${esc(scanId)}', '${esc(scan.target)}')"
            title="Permanently delete this scan">
            Delete Scan
          </button>` })}

      ${envNotesBanner}

      <div class="stats-grid" style="margin-bottom:24px">
        <div class="stat-card">
          <div class="stat-label">Application</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.target)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Scan Type</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scanTypeLabel(scan.scan_type))}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">User</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.user || '—')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Timestamp</div>
          <div class="stat-value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
        </div>
      </div>

      <div class="result-section-box">
        <div class="result-section-box-title">Vulnerabilities</div>
        <div class="stats-grid" style="margin-bottom:0">
          <div class="stat-card critical">
            <div class="stat-label">Critical</div>
            <div class="stat-value">${esc(scan.critical)}</div>
          </div>
          <div class="stat-card high">
            <div class="stat-label">High</div>
            <div class="stat-value">${esc(scan.high)}</div>
          </div>
          <div class="stat-card medium">
            <div class="stat-label">Medium</div>
            <div class="stat-value">${esc(scan.medium)}</div>
          </div>
          <div class="stat-card low">
            <div class="stat-label">Low</div>
            <div class="stat-value">${esc(scan.low)}</div>
          </div>
        </div>
      </div>

      ${buildFindingsSection(scan.findings)}

      ${buildSuppressedSection(scan.suppressed_findings)}

      ${stigCard}

      ${buildPoamSection(scanId)}

      ${buildModelSecurityCard(scan)}

      ${buildMisconfigurationsCard(scan)}

      ${buildBuildEvidenceCard(scan)}

      ${buildSSPEvidenceCard(scan)}

      ${buildSBOMSection(scan.sbom, scanId)}

      ${buildAPISection(scan.api_discovery)}

      ${buildNetworkDiscoveryCard(scan)}

      ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
        <div class="result-section-box">
          <div class="result-section-box-title">File Statistics</div>
          <div class="stats-grid" style="margin-bottom:0">
            ${Object.entries(scan.file_statistics).map(([k, v]) => `
              <div class="stat-card">
                <div class="stat-label">${esc(k.replace(/_/g, ' '))}</div>
                <div class="stat-value" style="font-size:20px">${esc(v)}</div>
              </div>`).join('')}
          </div>
        </div>` : ''}

      <div id="scorecard-container"></div>

      ${dedupeTools(scan.tools_analyzed).length ? `
        <div class="result-section-box">
          <div class="result-section-box-title">Tools Analyzed</div>
          <div class="tools-list">
            ${dedupeTools(scan.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}`;
    if (window._sbomPendingUid) { sbomRender(window._sbomPendingUid); window._sbomPendingUid = null; }
    if (window._apiPendingUid) { apiRender(window._apiPendingUid); window._apiPendingUid = null; }
    
    // Automatically generate scorecard
    calculateScorecardForScan(scanId);

    if (openFindingId) {
      const wantId = openFindingId.toLowerCase();
      const wantPackage = openFindingPackage.toLowerCase();
      let findingId = null;
      for (const [rid, f] of _findingsRegistry) {
        const packageName = String(f.package || f.component || '').toLowerCase();
        if (String(f.id || '').toLowerCase() === wantId &&
            (!wantPackage || packageName === wantPackage)) {
          findingId = rid;
          break;
        }
      }
      if (findingId === null) {
        const severities = ['critical', 'high', 'medium', 'low'];
        for (const severity of severities) {
          const finding = (scan.findings[`${severity}_findings`] || []).find(f => {
            const packageName = String(f.package || f.component || '').toLowerCase();
            return String(f.id || '').toLowerCase() === wantId &&
              (!wantPackage || packageName === wantPackage);
          });
          if (finding) {
            findingId = _registerFinding(finding);
            break;
          }
        }
      }
      if (findingId !== null) openFindingDetail(findingId);
    }
    page.querySelectorAll('.poam-card').forEach(window.loadPoamCard);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

function buildPicklescanCard(scan) { return ''; } // merged into buildModelSecurityCard

function buildModelCardCard(scan) { return ''; }  // merged into buildModelSecurityCard

function buildEnrichmentCard(findings) {
  if (!findings) return '';
  const enr = findings.enrichment;
  if (!enr || (enr.cisa_kev_total == null && enr.nvd_total == null)) return '';
  const kevTotal = enr.cisa_kev_total || 0;
  const nvdTotal = enr.nvd_total || 0;
  if (kevTotal === 0 && nvdTotal === 0) return '';

  const hasKev = kevTotal > 0;
  const accentColor = hasKev ? 'var(--critical)' : 'var(--accent)';

  // Collect all KEV-matched findings across severity buckets for the detail table
  const kevFindings = [];
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    for (const f of (findings[`${sev}_findings`] || [])) {
      if (f.cisa_kev === true) kevFindings.push({ sev, ...f });
    }
  }

  // Format enriched_at timestamp
  let enrichedAt = '';
  if (enr.enriched_at) {
    try {
      enrichedAt = new Date(enr.enriched_at).toLocaleString(undefined,
        { dateStyle: 'medium', timeStyle: 'short' });
    } catch (_) { enrichedAt = enr.enriched_at; }
  }

  const kevTable = ''; // CVSS/KEV now shown inline in the main findings table

  const catalogLink = enr.kev_catalog_url
    ? `<a href="${esc(enr.kev_catalog_url)}" target="_blank" rel="noopener"
         style="font-size:12px;color:var(--accent)">↗ CISA KEV Catalog</a>`
    : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:${accentColor}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                   stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              Threat Intelligence Enrichment
            </span>
            ${hasKev ? `<span style="background:var(--critical-bg);color:var(--critical);border:1px solid #b91c1c;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(nvdTotal)} NVD enriched</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="detail-grid" style="margin-top:12px;margin-bottom:0">
            ${hasKev ? `
            <div class="detail-card" style="border-color:var(--critical-bg);background:rgba(127,29,29,0.12)">
              <div class="label" style="color:var(--critical)">CISA KEV Matches</div>
              <div class="value" style="color:var(--critical)">${esc(kevTotal)}</div>
            </div>` : ''}
            <div class="detail-card">
              <div class="label">NVD Enriched CVEs</div>
              <div class="value">${esc(nvdTotal)}</div>
            </div>
            ${enrichedAt ? `
            <div class="detail-card">
              <div class="label">Enriched At</div>
              <div class="value" style="font-size:12px">${enrichedAt}</div>
            </div>` : ''}
          </div>
          ${hasKev ? `
          <p style="color:var(--critical);font-size:12px;margin:12px 0 4px">
            ⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} match CISA's Known Exploited Vulnerabilities catalog —
            actively exploited in the wild. Findings marked <strong>KEV</strong> above require immediate attention.
          </p>` : ''}
          ${catalogLink ? `<div style="margin-top:8px">${catalogLink}</div>` : ''}
        </div>
      </details>
    </div>`;
}

function buildNetworkDiscoveryCard(scan) {
  const nd = scan.network_discovery;
  if (!nd) return '';
  const scanId = scan.scan_id || scan.id || '';
  _ppsmRegistry.set(scanId, nd);
  const ports    = (nd.unique_ports || []).join(', ') || '—';
  const protos   = (nd.protocols   || []).join(', ') || '—';
  const services = (nd.services    || []).join(', ') || '—';

  // Source breakdown rows
  const sourceRows = [
    { label: 'Docker Compose', items: nd.compose_ports   || [] },
    { label: 'Dockerfile',     items: nd.dockerfile_ports || [] },
    { label: 'Kubernetes/Helm',items: nd.k8s_ports       || [] },
    { label: 'App Config/.env',items: nd.config_ports    || [] },
  ].filter(r => r.items.length > 0);

  const sourceHtml = sourceRows.length ? sourceRows.map((r, idx) => {
    const tblId = `ppsm-tbl-${idx}`;
    return `
    <div style="margin-top:10px">
      <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px">${esc(r.label)}</div>
      <table id="${tblId}" style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="color:var(--text-muted)">
            <th scope="col" data-col="0" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',0)">File <span class="sort-icon">⇅</span></th>
            <th scope="col" data-col="1" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',1)">Service <span class="sort-icon">⇅</span></th>
            <th scope="col" data-col="2" class="sortable-th" style="text-align:left;padding:2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',2)">Port / Mapping <span class="sort-icon">⇅</span></th>
          </tr>
        </thead>
        <tbody>
          ${r.items.map(p => `
            <tr style="border-top:1px solid var(--border)">
              <td style="padding:3px 8px 3px 0;color:var(--text-muted);font-family:monospace;font-size:12px">${esc(p.file || '')}</td>
              <td style="padding:3px 8px 3px 0">${esc(p.service || '')}</td>
              <td style="padding:3px 0;font-family:monospace">${esc(p.mapping || String(p.port || ''))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  }).join('') : emptyNote('No static port definitions found.');

  const activeBadge = nd.active_scan_run
    ? '<span style="background:var(--low-bg,#fffbe6);color:var(--low);border:1px solid var(--low);border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600">nmap active</span>'
    : '<span style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:12px">static only</span>';

  const portsBadge = nd.total_ports
    ? `<span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(nd.total_ports))} ports</span>`
    : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">🔌 Network Discovery · PPSM</span>
            ${portsBadge}
            ${activeBadge}
          </span>
          <span class="findings-summary-right" onclick="event.stopPropagation()">
            <button class="btn btn-sm" onclick="downloadPpsmCsv('${esc(scanId)}')" title="Download PPSM as CSV">↓ PPSM</button>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="detail-grid" style="margin-bottom:12px;margin-top:12px">
            <div class="detail-card">
              <div class="label">Ports Found</div>
              <div class="value">${esc(nd.total_ports)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Scan Method</div>
              <div class="value" style="font-size:13px">${activeBadge}</div>
            </div>
            <div class="detail-card" style="grid-column:span 2">
              <div class="label">Unique Ports</div>
              <div class="value" style="font-size:13px;font-family:monospace">${esc(ports)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Protocols</div>
              <div class="value" style="font-size:13px">${esc(protos)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Inferred Services</div>
              <div class="value" style="font-size:13px">${esc(services)}</div>
            </div>
          </div>
          ${sourceHtml}
        </div>
      </details>
    </div>`;
}

function buildModelSecurityCard(scan) {
  // Enhanced to support 5 ML security layers - always show even if no findings
  // Layer 14: picklescan (enhanced), Layer 15: modelcard
  // Layer 18: model-provenance, Layer 19: inference-security, Layer 20: ml-runtime
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  const mp = scan.model_provenance;
  const is = scan.inference_security;
  const mr = scan.ml_runtime;
  
  // Always show the card to give visibility that ML security layers ran or are available

  // ── Layer 14: Enhanced Picklescan section ──
  let pickleSection = '';
  if (ps && Array.isArray(ps)) {
    // New enhanced schema: ps is an array of findings
    const findingsCount = ps.length;
    const criticalCount = ps.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = ps.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const psFindings = ps.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'picklescan',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Malicious content detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    pickleSection = `
      <div class="ms-layer">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🥒</span>
            <span>Layer 14 — Comprehensive Model File Analysis</span>
            <span class="hf-tool-name">picklescan-enhanced</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${psFindings ? `<div class="hf-findings" style="margin-top:10px">${psFindings}</div>` : ''}
      </div>`;
  } else if (ps && typeof ps === 'object') {
    // Legacy schema support: ps is an object
    const statusClass = ps.flagged_count > 0 ? 'status-open' : 'status-clean';
    const statusLabel = ps.flagged_count > 0 ? `${ps.flagged_count} infected file(s)` : 'Clean';
    const icon = ps.flagged_count > 0 ? '🚨' : '✅';
    const totalWeightFiles = ps.total_weight_files ?? ps.file_count ?? 0;

    const psFindings = (ps.findings || []).map(f => `
      <div class="hf-finding-row">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.message || f.description || 'Malicious pickle opcode detected')}</span>
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

    const mcFindings = (mc.findings || []).map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'medium',
        id:          f.check || '',
        tool:        'model card',
        title:       f.message || f.check || '—',
        description: f.recommendation || '',
        file:        mc.file_checked || '',
        target:      mc.file_checked || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'medium')}">${esc(f.severity || 'medium')}</span>
        <span class="hf-finding-file">${esc(f.check || '—')}</span>
        <span class="hf-finding-msg">${esc(f.message || '')}${f.recommendation ? `<span class="hf-recommendation"> → ${esc(f.recommendation)}</span>` : ''}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

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

  // ── Layer 18: Model Provenance & Threat Intelligence ──
  let provenanceSection = '';
  if (mp && Array.isArray(mp) && mp.length > 0) {
    const findingsCount = mp.length;
    const criticalCount = mp.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = mp.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const mpFindings = mp.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'model-provenance',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Provenance issue detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    provenanceSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🔐</span>
            <span>Layer 18 — Model Provenance & Threat Intelligence</span>
            <span class="hf-tool-name">model-provenance</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${mpFindings ? `<div class="hf-findings" style="margin-top:10px">${mpFindings}</div>` : ''}
      </div>`;
  }

  // ── Layer 19: Inference Environment Security ──
  let inferenceSection = '';
  if (is && Array.isArray(is) && is.length > 0) {
    const findingsCount = is.length;
    const criticalCount = is.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = is.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const isFindings = is.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'inference-security',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Infrastructure issue detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    inferenceSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🐳</span>
            <span>Layer 19 — Inference Environment Security</span>
            <span class="hf-tool-name">inference-security</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${isFindings ? `<div class="hf-findings" style="margin-top:10px">${isFindings}</div>` : ''}
      </div>`;
  }

  // ── Layer 20: ML Runtime Behavioral Analysis (Opt-in) ──
  let runtimeSection = '';
  if (mr && Array.isArray(mr) && mr.length > 0) {
    const findingsCount = mr.length;
    const criticalCount = mr.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = mr.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const mrFindings = mr.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'ml-runtime',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Malicious runtime behavior detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    runtimeSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">⚡</span>
            <span>Layer 20 — ML Runtime Behavioral Analysis</span>
            <span class="hf-tool-name">ml-runtime</span>
            <span class="tool-tag" style="background:var(--purple-bg);color:var(--purple);border:1px solid #7c3aed66;margin-left:6px">OPT-IN</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${mrFindings ? `<div class="hf-findings" style="margin-top:10px">${mrFindings}</div>` : ''}
      </div>`;
  }

  // ── Combined status for the summary line ──
  // Count issues from all ML layers
  const psIssues = Array.isArray(ps) ? ps.length : (ps?.flagged_count > 0);
  const mcIssues = mc?.failed > 0 || mc?.warnings > 0;
  const mpIssues = mp && mp.length > 0;
  const isIssues = is && is.length > 0;
  const mrIssues = mr && mr.length > 0;
  
  const hasIssues = psIssues || mcIssues || mpIssues || isIssues || mrIssues;
  const hasCritical = (Array.isArray(ps) && ps.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (mp && mp.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (is && is.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (mr && mr.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (ps?.flagged_count > 0) || (mc?.failed > 0);
  
  const summaryBadgeClass = hasCritical ? 'status-open' : hasIssues ? 'status-warn' : 'status-clean';
  const summaryIcon       = hasCritical ? '⚠' : hasIssues ? '⚠' : '✓';
  const summaryLabel      = hasIssues ? 'Issues found' : 'All clear';
  
  // Check if any ML layers ran
  const anyLayersRan = ps || mc || mp || is || mr;
  const emptyState = !anyLayersRan ? `
    <div style="padding:16px;text-align:center;color:var(--text-muted);font-size:13px">
      <div style="margin-bottom:8px">ℹ️ No ML/AI security layers detected in this scan</div>
      <div style="font-size:12px;color:var(--text-dim)">ML security scanning (layers 14, 15, 18, 19, 20) only runs for repositories containing ML models or AI artifacts</div>
    </div>` : '';

  return `
    <details class="ms-card" id="model-security-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">ML/AI Security</span>
          ${ps ? '<span class="tool-tag" style="font-size:12px">picklescan</span>' : ''}
          ${mc ? '<span class="tool-tag" style="font-size:12px">model card</span>' : ''}
          ${mp ? '<span class="tool-tag" style="font-size:12px">provenance</span>' : ''}
          ${is ? '<span class="tool-tag" style="font-size:12px">inference</span>' : ''}
          ${mr ? '<span class="tool-tag" style="font-size:12px;background:var(--purple-bg);color:var(--purple)">runtime</span>' : ''}
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${summaryBadgeClass}">${summaryIcon} ${summaryLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        ${emptyState}
        ${pickleSection}
        ${modelCardSection}
        ${provenanceSection}
        ${inferenceSection}
        ${runtimeSection}
      </div>
    </details>`;
}

// ── Misconfigurations Card (Checkov IaC findings) ─────────────

function buildMisconfigurationsCard(scan) {
  // Layers 2, 6 & 21: TruffleHog secret detection + Checkov IaC security + compromised-source supply chain detection - always show even if no findings
  const misconfigs = scan.misconfigurations;
  const summary = misconfigs?.summary || { total_critical: 0, total_high: 0, total_medium: 0, total_low: 0, tools_analyzed: [] };
  const totalIssues = summary.total_critical + summary.total_high + summary.total_medium + summary.total_low;
  
  // Build findings rows only if there are findings
  let findingsHtml = '';
  if (totalIssues > 0) {
    const buildMisconfigRow = (f) => {
      const fid = _registerFinding({
        severity:    f.severity || 'medium',
        id:          f.id || '',
        tool:        f.tool || 'Checkov',
        title:       f.title || f.description || '—',
        description: f.description || '',
        file:        f.file || '',
        target:      f.target || '',
      });
      
      return `
        <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
          <span class="hf-finding-sev hf-sev-${esc(f.severity || 'medium')}">${esc(f.severity || 'medium')}</span>
          ${findingSourceBadge(f)}
          <code class="hf-finding-file">${esc(f.file || f.target || '—')}</code>
          <span class="hf-finding-msg">${esc(f.title || f.description || 'Configuration issue detected')}</span>
          <span class="hf-finding-chevron">›</span>
        </div>`;
    };
    
    const allMisconfigItems = [
      ...(misconfigs.critical_findings || []),
      ...(misconfigs.high_findings || []),
      ...(misconfigs.medium_findings || []),
      ...(misconfigs.low_findings || [])
    ];
    
    const rows = allMisconfigItems.map(buildMisconfigRow).join('');
    
    findingsHtml = `
      <div class="hf-findings" style="margin-top:10px">
        ${rows}
      </div>`;
  } else {
    findingsHtml = `
      <div style="padding:12px;text-align:center;color:var(--text-muted);font-size:13px">
        ✓ No misconfigurations or secrets detected
      </div>`;
  }
  
  const statusClass = totalIssues === 0 ? 'status-clean' : summary.total_critical > 0 ? 'status-open' : summary.total_high > 0 ? 'status-warn' : 'status-clean';
  const statusIcon = totalIssues === 0 ? '✓' : summary.total_critical > 0 ? '🚨' : summary.total_high > 0 ? '⚠' : '✓';
  const statusLabel = totalIssues === 0 
    ? 'All clear'
    : summary.total_critical > 0 
    ? `${summary.total_critical} critical issue(s)` 
    : summary.total_high > 0 
    ? `${summary.total_high} high issue(s)` 
    : 'Minor issues';
  
  return `
    <details class="ms-card" id="misconfigurations-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Misconfigurations</span>
          <span class="tool-tag" style="font-size:12px">Layers 2, 6 & 21 — Secrets, IaC & Supply Chain</span>
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${statusClass}">${statusIcon} ${statusLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div class="ms-layer">
          <div class="ms-layer-header">
            <div class="ms-layer-title">
              <span class="hf-tool-icon">🔧</span>
              <span>Security Misconfigurations & Secrets</span>
              <span class="hf-tool-name">${(summary.tools_analyzed || []).join(', ') || 'Checkov, TruffleHog'}</span>
            </div>
            <span class="hf-status-badge ${statusClass}">${statusIcon} ${totalIssues} finding(s)</span>
          </div>
          <div class="hf-tool-stats" style="margin-bottom:0">
            <div class="hf-stat"><span class="hf-stat-num">${totalIssues}</span><span class="hf-stat-lbl">findings</span></div>
            <div class="hf-stat"><span class="hf-stat-num ${summary.total_critical > 0 ? 'danger' : ''}">${summary.total_critical}</span><span class="hf-stat-lbl">critical</span></div>
            <div class="hf-stat"><span class="hf-stat-num ${summary.total_high > 0 ? 'danger' : ''}">${summary.total_high}</span><span class="hf-stat-lbl">high</span></div>
            <div class="hf-stat"><span class="hf-stat-num">${summary.total_medium}</span><span class="hf-stat-lbl">medium</span></div>
            <div class="hf-stat"><span class="hf-stat-num">${summary.total_low}</span><span class="hf-stat-lbl">low</span></div>
          </div>
          ${findingsHtml}
        </div>
      </div>
    </details>`;
}

// ── Container Build & Supply Chain Evidence Card ────────────────

function buildBuildEvidenceCard(scan) {
  const be = scan.build_evidence || {};
  const build = be.build || {};
  const sig = be.signature || {};
  const prov = be.provenance || {};
  const arts = be.artifacts || {};
  const digest = be.digest || build.digest || '';
  const mode = build.mode || (build.status === 'success' ? 'container_build' : 'target_source_manifest');

  const isContainerBuild = mode === 'container_build';

  const statusBadge = isContainerBuild
    ? `<span class="badge" style="background:var(--pass);color:var(--bg);">✅ Image Built</span>`
    : `<span class="badge" style="background:var(--accent);color:var(--bg);">✅ Target Attested & Verified</span>`;

  const manifestBadge = arts.oci_manifest
    ? `<span class="badge" style="background:var(--accent);color:var(--bg);">📦 OCI Manifest</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">📦 OCI Manifest N/A</span>`;

  const provBadge = arts.slsa_provenance
    ? `<span class="badge" style="background:var(--purple);color:var(--bg);">📜 SLSA v1.0 Provenance</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">📜 SLSA Provenance N/A</span>`;

  const sigBadge = sig.status === 'signed' || arts.image_signature
    ? `<span class="badge" style="background:var(--pass);color:var(--bg);">🔏 Cosign Signed</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">🔏 Signature N/A</span>`;

  // Build 10-Artifact Inventory Table Rows — status reflects actual file presence
  // reported by parse_build_evidence()'s `artifacts` flags, not an assumed constant.
  const artifactRows = [
    { name: "1. Immutable Image Digest", spec: "SHA-256 Digest", present: !!arts.image_digest, file: "build/image-digest.txt" },
    { name: "2. OCI Image Manifest", spec: "OCI Image Specification v1/v2", present: !!arts.oci_manifest, file: "build/oci-manifest.json" },
    { name: "3. Dockerfile / Build Spec", spec: "Container Instructions", present: !!arts.dockerfile, file: "build/Dockerfile" },
    { name: "4. Build Execution Logs", spec: "Console & Execution Log", present: !!arts.build_log, file: "build/build.log" },
    { name: "5. SLSA Provenance", spec: "SLSA v1.0 in-toto Predicate", present: !!arts.slsa_provenance, file: "provenance.jsonl" },
    { name: "6. Cryptographic Signature", spec: "Cosign Signature Metadata", present: !!arts.image_signature, file: "image.sig" },
    { name: "7. Software Inventory (SBOM)", spec: "CycloneDX / SPDX JSON", present: !!arts.sbom, file: "sbom/filesystem.cyclonedx.json" },
    { name: "8. Vulnerability & Malware Scans", spec: "Grype / Trivy / ClamAV Reports", present: !!arts.vuln_scans, file: "grype/, trivy/, clamav/" },
    { name: "9. Scan Integrity Manifest", spec: "Cryptographic SHA-256 Hashes", present: !!arts.scan_manifest, file: "scan-manifest.json" },
    { name: "10. Policy & Suppression Audit", spec: "Exception Justifications", present: !!arts.suppression_audit, file: "suppressed-findings.md" }
  ].map(a => `
    <tr style="border-bottom:1px solid var(--border-muted);">
      <td style="padding:8px 12px;font-weight:500;">${esc(a.name)}</td>
      <td style="padding:8px 12px;color:var(--text-muted);font-size:12px;">${esc(a.spec)}</td>
      <td style="padding:8px 12px;">${a.present
        ? '<span style="color:var(--pass);font-weight:600;">✅ Captured</span>'
        : '<span style="color:var(--text-muted);">⚠️ Not Captured</span>'}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:var(--text-muted);">${esc(a.file)}</td>
    </tr>
  `).join('');

  return `
    <details class="ms-card" id="build-evidence-card" style="border-left-color:var(--purple);margin-top:20px;">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Build Artifacts & Supply Chain Evidence</span>
          <span class="tool-tag" style="font-size:12px">Phase 0 — Container Build & Attestation</span>
        </span>
        <span class="ms-summary-right">
          ${statusBadge}
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
          ${statusBadge}
          ${manifestBadge}
          ${provBadge}
          ${sigBadge}
        </div>
        
        <div class="detail-grid" style="margin-bottom:16px;">
          <div class="detail-card">
            <div class="label">Image Identifier</div>
            <div class="value" style="font-family:monospace;font-size:0.85rem;">${esc(build.full_image || build.image_name || scan.target || 'N/A')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Immutable SHA-256 Digest</div>
            <div class="value" style="font-family:monospace;font-size:0.8rem;word-break:break-all;">${esc(digest || 'N/A (Pre-built target)')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Build Runtime</div>
            <div class="value">${esc(build.runtime || 'N/A (Source scan)')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Dockerfile</div>
            <div class="value">${esc(build.dockerfile || 'Dockerfile')}</div>
          </div>
        </div>

        <div class="section-title" style="font-size:0.9rem;margin-bottom:8px;color:var(--text);">📦 Release & Evidence Artifact Inventory</div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:13px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;">
            <thead>
              <tr style="background:var(--bg-card);border-bottom:1px solid var(--border);text-align:left;">
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Artifact Name</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Specification / Format</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Pipeline Status</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Artifact Path</th>
              </tr>
            </thead>
            <tbody>
              ${artifactRows}
            </tbody>
          </table>
        </div>
      </div>
    </details>`;
}

// ── NIST SP 800-53 / FedRAMP SSP Evidence Matrix Card ─────────

function buildSSPEvidenceCard(scan) {
  const matrix = scan.ssp_evidence || {};
  const controls = matrix.controls || [];
  if (!controls.length) return '';

  const scanId = scan.scan_id || '';

  const rows = controls.map(c => {
    const isCap = c.status === 'captured';
    const hash = c.sha256_hash || 'N/A';
    const hashShort = hash.length > 20 ? hash.slice(0, 18) + '…' : hash;
    return `
      <tr style="border-bottom:1px solid var(--border-muted);">
        <td style="padding:8px 12px;font-weight:600;color:var(--accent);">${esc(c.control_id)}</td>
        <td style="padding:8px 12px;font-weight:500;">${esc(c.control_name)}</td>
        <td style="padding:8px 12px;color:var(--text-muted);font-size:12px;">${esc(c.epyon_layer)}</td>
        <td style="padding:8px 12px;font-family:monospace;font-size:12px;"><code style="color:var(--purple);">${esc(c.primary_artifact_path)}</code></td>
        <td style="padding:8px 12px;">${isCap ? '<span style="color:var(--pass);font-weight:600;">✅ Captured</span>' : '<span style="color:var(--medium);font-weight:600;">⚠️ Missing Evidence</span>'}</td>
        <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:var(--text-muted);" title="${esc(hash)}">${esc(hashShort)}</td>
      </tr>`;
  }).join('');

  const downloadMdBtn = scanId
    ? `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/ssp-evidence/md" download title="Download NIST SP 800-53 Control Evidence Matrix as Markdown">↓ Export Matrix (.md)</a>`
    : '';

  const downloadDocxBtn = scanId
    ? `<button type="button" class="btn btn-sm js-export-ssp-docx" data-scan-id="${esc(scanId)}" title="Export NIST SP 800-53 Control Evidence Matrix as Word .docx">↓ Export Word (.docx)</button>`
    : '';

  return `
    <details class="ms-card" id="ssp-evidence-card" style="border-left-color:var(--pass);margin-top:20px;">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">NIST SP 800-53 / FedRAMP Control Evidence Matrix</span>
          <span class="tool-tag" style="font-size:12px;background:var(--pass-bg);color:var(--pass);border:1px solid #10b98144">SSP / ATO Package</span>
        </span>
        <span class="ms-summary-right" onclick="event.stopPropagation()" style="gap:8px;display:flex;align-items:center;">
          ${downloadMdBtn}
          ${downloadDocxBtn}
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div style="padding:12px 18px 0;color:var(--text-muted);font-size:13px;">
          Maps Epyon's security scanning layers, build provenance, and scan manifests directly to NIST SP 800-53 Rev. 5 / FedRAMP control families for System Security Plans (SSP) and ATO submissions.
        </div>
        <div style="overflow-x:auto;padding:12px 18px 18px;">
          <table style="width:100%;border-collapse:collapse;font-size:13px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;">
            <thead>
              <tr style="background:var(--bg-card);border-bottom:1px solid var(--border);text-align:left;">
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Control</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">NIST Control Name</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Epyon Security Layer</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Primary Evidence Artifact Path</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Status</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Cryptographic SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      </div>
    </details>`;
}

if (!window.__sspDocxExportBound) {
  document.addEventListener('click', event => {
    const btn = event.target.closest('.js-export-ssp-docx');
    if (!btn) return;
    event.stopPropagation();
    const { scanId } = btn.dataset;
    if (scanId) window.exportSSPDocx(scanId);
  });
  window.__sspDocxExportBound = true;
}

window.exportSSPDocx = async function(scanId) {
  try {
    const res = await fetch('/api/scans/' + encodeURIComponent(scanId) + '/export/ssp-docx', { method: 'POST' });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ssp-ato-evidence-' + scanId + '.docx';
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    toast('Failed to export Word document: ' + err.message, 'error');
  }
};

// ── Overview AI Summary Section ──────────────────────────────



function buildOverviewExecSection() {
  const tip = 'Requires an OpenAI API key configured in Settings.';
  return `
    <div class="section" id="overview-summary-section">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="generateOverviewExecSummary()"
                title="Leadership brief across all tracked applications, split by monitoring status. ${tip}">
          ✦ Generate Executive Summary
        </button>
        <button class="btn btn-primary" onclick="generateOverviewTechSummary()"
                title="Detailed technical brief for engineering teams, with per-finding breakdown. ${tip}">
          ✦ Generate Technical Summary
        </button>
        <button class="btn btn-primary" onclick="generateOverviewIssoSummary()"
                title="ATO/cATO-ready brief covering NIST 800-53 control mapping, STIG validation status, evidence traceability, accepted risk, and POA&amp;M risk statements. ${tip}">
          ✦ Generate ISSO Compliance Brief
        </button>
      </div>
    </div>`;
}

function buildOverviewTechSection() { return ''; }
function buildOverviewIssoSection() { return ''; }

// Cache last-generated overview summary text for PDF/Word export
let _overviewSummaryCache = { exec: null, tech: null, isso: null };
// Cache per-app ISSO summaries keyed by app name
const _appIssoCache = {};

function _summaryLoadingHtml(label) {
  return `<div style="display:flex;align-items:center;gap:10px;padding:12px 0;color:var(--text-muted);font-size:13px">
    <div class="spinner" style="width:16px;height:16px;border-width:2px"></div>
    Generating ${label}… this may take 15–30 seconds
  </div>`;
}

function _summaryResultHtml(text, err, regenerateFn, exportFn, exportDocxFn) {
  const content = err
    ? `<div style="color:var(--critical);font-size:12px;padding:8px 0">⚠ ${esc(err)}</div>`
    : `<div style="line-height:1.6">${renderMarkdown(text)}</div>`;
  return `
    ${content}
    <div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" style="font-size:12px" onclick="${regenerateFn.includes('(') ? regenerateFn : regenerateFn + '()'}">↺ Regenerate</button>
      ${text ? `<button class="btn btn-primary" style="font-size:12px" onclick="${exportFn.includes('(') ? exportFn : exportFn + '()'}">↓ Export PDF</button>` : ''}
      ${text && exportDocxFn ? `<button class="btn" style="font-size:12px;background:var(--accent-bg);color:var(--accent);border-color:var(--accent-bg)" onclick="${exportDocxFn.includes('(') ? exportDocxFn : exportDocxFn + '()'}">↓ Export Word</button>` : ''}
    </div>`;
}

const _OVERVIEW_SUMMARY_KINDS = {
  exec: { title: 'Executive Summary',       label: 'executive summary',     fn: 'generateOverviewExecSummary', pdf: 'exportExecSummaryPdf', docx: 'exportExecSummaryDocx', call: () => api.getGlobalExecSummary() },
  tech: { title: 'Technical Summary',       label: 'technical summary',     fn: 'generateOverviewTechSummary', pdf: 'exportTechSummaryPdf', docx: 'exportTechSummaryDocx', call: () => api.getGlobalTechnicalSummary() },
  isso: { title: 'ISSO Compliance Brief',   label: 'ISSO compliance brief', fn: 'generateOverviewIssoSummary', pdf: 'exportIssoSummaryPdf', docx: 'exportIssoSummaryDocx', call: () => api.getGlobalIssoSummary() },
};

function closeSummaryModal() {
  document.getElementById('summary-modal')?.remove();
  document.removeEventListener('keydown', _summaryModalKey);
}
function _summaryModalKey(e) { if (e.key === 'Escape') closeSummaryModal(); }

function _openSummaryModal(title, bodyHtml) {
  let overlay = document.getElementById('summary-modal');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'summary-modal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal-container modal-xl" role="dialog" aria-modal="true" aria-labelledby="summary-modal-title">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 id="summary-modal-title" style="margin:0;font-size:18px"></h2>
        <button class="btn" onclick="closeSummaryModal()" aria-label="Close">✕</button>
      </div>
      <div id="summary-modal-body"></div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeSummaryModal(); });
    document.addEventListener('keydown', _summaryModalKey);
  }
  document.getElementById('summary-modal-title').textContent = title;
  const body = document.getElementById('summary-modal-body');
  body.innerHTML = bodyHtml;
  return body;
}

// Generates into a modal so results never push the Overview content down.
async function _runOverviewSummary(kind) {
  const cfg = _OVERVIEW_SUMMARY_KINDS[kind];
  const body = _openSummaryModal(cfg.title, _summaryLoadingHtml(cfg.label));
  try {
    const result = await cfg.call();
    _overviewSummaryCache[kind] = result.summary;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(result.summary, null, cfg.fn, cfg.pdf, cfg.docx);
  } catch (e) {
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', cfg.fn, cfg.pdf, cfg.docx);
  }
}

async function generateOverviewExecSummary() { await _runOverviewSummary('exec'); }
async function generateOverviewTechSummary() { await _runOverviewSummary('tech'); }
async function generateOverviewIssoSummary() { await _runOverviewSummary('isso'); }

// Keep the old combined function as an alias so any cached references still work
async function generateOverviewSummaries() {
  await Promise.all([generateOverviewExecSummary(), generateOverviewTechSummary()]);
}

function exportExecSummaryPdf() {
  exportOverviewSummaryPdf('exec');
}

function exportTechSummaryPdf() {
  exportOverviewSummaryPdf('tech');
}

async function exportSummaryDocx(which) {
  const { exec, tech, isso } = _overviewSummaryCache;
  const body = {
    exec_summary: which === 'exec' ? (exec || null) : null,
    tech_summary: which === 'tech' ? (tech || null) : null,
    isso_summary: which === 'isso' ? (isso || null) : null,
  };
  if (!body.exec_summary && !body.tech_summary && !body.isso_summary) return;
  try {
    const resp = await fetch('/api/export/summary-docx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`Server error ${resp.status}`);
    const blob = await resp.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = resp.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]
                 || 'epyon-security-report.docx';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    toast('Word export failed: ' + e.message, 'error');
  }
}

async function exportExecSummaryDocx() { await exportSummaryDocx('exec'); }
async function exportTechSummaryDocx() { await exportSummaryDocx('tech'); }
async function exportIssoSummaryDocx() { await exportSummaryDocx('isso'); }

function exportIssoSummaryPdf() { exportOverviewSummaryPdf('isso'); }

function buildAppIssoSection(name) {
  return `
    <div class="section" id="app-isso-section-${esc(name)}" style="border-left:3px solid var(--pass);padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        AI ISSO Compliance Brief — ${esc(name)}
      </div>
      <button class="btn btn-primary" onclick="generateAppIssoSummary('${esc(name)}')">
        ✦ Generate Application ISSO Brief
      </button>
      <p style="margin:8px 0 0;font-size:12px;color:var(--text-muted)">
        Per-application ATO/cATO brief: NIST 800-53 control mapping, STIG open controls,
        evidence traceability, accepted risk register, and POA&amp;M entries.
        Requires an OpenAI API key configured in Settings.
      </p>
    </div>`;
}

async function generateAppIssoSummary(name) {
  const body = _openSummaryModal(`ISSO Compliance Brief — ${name}`, _summaryLoadingHtml('ISSO compliance brief'));
  const fns = [`generateAppIssoSummary('${name}')`, `exportAppIssoSummaryPdf('${name}')`, `exportAppIssoSummaryDocx('${name}')`];
  try {
    const result = await api.getAppIssoSummary(name);
    const text = result.summary || '';
    _appIssoCache[name] = text;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(text, null, ...fns);
  } catch (e) {
    _appIssoCache[name] = null;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', ...fns);
  }
}

function exportAppIssoSummaryPdf(name) {
  const text = _appIssoCache[name];
  if (!text) { toast('Generate the ISSO brief first.', 'warning'); return; }
  const doc = new window.jspdf.jsPDF();
  doc.setFontSize(16);
  doc.text(`ISSO Compliance Brief — ${name}`, 14, 20);
  doc.setFontSize(10);
  const lines = doc.splitTextToSize(text.replace(/#+\s/g, '').replace(/[*_`]/g, ''), 180);
  doc.text(lines, 14, 30);
  doc.save(`isso-brief-${name}.pdf`);
}

async function exportAppIssoSummaryDocx(name) {
  const text = _appIssoCache[name];
  if (!text) { toast('Generate the ISSO brief first.', 'warning'); return; }
  try {
    const blob = await api.exportSummaryDocx({ isso_summary: text });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: `isso-brief-${name}.docx` });
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (e) {
    toast('Word export failed: ' + e.message, 'error');
  }
}

function exportOverviewSummaryPdf(only) {
  const { exec, tech, isso } = _overviewSummaryCache;
  const showExec = !only || only === 'exec';
  const showTech = !only || only === 'tech';
  const showIsso = !only || only === 'isso';
  if (!exec && !tech && !isso) return;

  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  function mdToHtml(text) {
    if (!text) return '<p style="color:var(--text-muted)">Not available.</p>';
    // Reuse inline rendering logic but produce standalone HTML
    const lines = text.split('\n');
    let html = '';
    let inList = false;
    for (const line of lines) {
      if (/^## /.test(line)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3>${line.replace(/^## /, '')}</h3>`;
        continue;
      }
      if (/^# /.test(line)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h2>${line.replace(/^# /, '')}</h2>`;
        continue;
      }
      if (/^[-*] /.test(line)) {
        if (!inList) { html += '<ul>'; inList = true; }
        html += `<li>${pdfInline(line.replace(/^[-*] /, ''))}</li>`;
        continue;
      }
      if (inList && line.trim() !== '') { html += '</ul>'; inList = false; }
      if (line.trim() === '') { if (!inList) html += '<br>'; continue; }
      html += `<p>${pdfInline(line)}</p>`;
    }
    if (inList) html += '</ul>';
    return html;
  }

  function pdfInline(s) {
    s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
    s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    return s;
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Epyon Security Analysis — ${dateStr}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 12pt;
      color: #1a1a1a;
      margin: 0;
      padding: 0;
    }
    .page { padding: 36px 48px; max-width: 900px; margin: 0 auto; }
    .report-header {
      border-bottom: 2px solid #1a1a1a;
      padding-bottom: 16px;
      margin-bottom: 28px;
    }
    .report-title { font-size: 22pt; font-weight: 700; margin: 0 0 4px; }
    .report-meta  { font-size: 10pt; color: var(--text-muted); margin: 0; }
    .section-heading {
      font-size: 14pt;
      font-weight: 700;
      margin: 28px 0 12px;
      padding: 8px 12px;
      border-radius: 4px;
    }
    :root {
      --text-muted: #656d76;
      --medium: #9a6700;
      --medium-bg: rgba(154, 103, 0, 0.1);
      --purple: #8250df;
      --purple-bg: rgba(130, 80, 223, 0.1);
      --pass: #1a7f37;
    }
    .exec-heading  { background: var(--medium-bg); border-left: 4px solid var(--medium); color: var(--medium); }
    .tech-heading  { background: var(--purple-bg); border-left: 4px solid var(--purple); color: var(--purple); }
    .isso-heading  { background: #ecfdf5; border-left: 4px solid var(--pass); color: var(--pass); }
    .section-body  { padding: 0 4px; }
    h2 { font-size: 13pt; margin: 18px 0 6px; }
    h3 { font-size: 11pt; margin: 14px 0 4px; }
    p  { margin: 4px 0 8px; line-height: 1.6; }
    ul { margin: 4px 0 8px 20px; padding: 0; }
    li { margin: 3px 0; line-height: 1.5; }
    code {
      background: #f3f4f6;
      padding: 1px 4px;
      border-radius: 3px;
      font-family: 'SF Mono', Consolas, monospace;
      font-size: 10pt;
    }
    .footer {
      margin-top: 40px;
      padding-top: 12px;
      border-top: 1px solid #ddd;
      font-size: 9pt;
      color: var(--text-muted);
      text-align: center;
    }
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page { padding: 24px 36px; }
      @page { margin: 18mm 15mm; }
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="report-header">
      <p class="report-title">Epyon Security Analysis</p>
      <p class="report-meta">Generated: ${dateStr} &nbsp;|&nbsp; AI-Assisted Report &nbsp;|&nbsp; Confidential</p>
    </div>

    ${showExec ? `<div class="section-heading exec-heading">📋 Executive Summary</div>
    <div class="section-body">${mdToHtml(exec)}</div>` : ''}

    ${showTech ? `<div class="section-heading tech-heading">🔧 Technical Summary</div>
    <div class="section-body">${mdToHtml(tech)}</div>` : ''}

    ${showIsso ? `<div class="section-heading isso-heading">🔒 ISSO Compliance Brief</div>
    <div class="section-body">${mdToHtml(isso)}</div>` : ''}

    <div class="footer">
      Generated by Epyon Security Scanner &nbsp;·&nbsp; ${dateStr} &nbsp;·&nbsp; AI-assisted — verify findings before acting
    </div>
  </div>
  <script>window.onload = function() { window.print(); };<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) {
    toast('Pop-up blocked — please allow pop-ups for this page and try again.', 'warning');
    return;
  }
  win.document.write(html);
  win.document.close();
}

function buildSuppressedSection(items) {
  if (!items || items.length === 0) return '';

  const rows = items.map(s => {
    const typeColor = s.type === 'tool' ? '#6366f1' : s.type === 'cve' ? '#f59e0b' : '#6b7280';
    return `<tr>
      <td style="padding:5px 10px;font-size:12px">
        <span class="tool-tag" style="font-size:12px;padding:1px 6px;background:${typeColor}22;color:${typeColor};border:1px solid ${typeColor}44">${esc(s.type || 'unknown')}</span>
      </td>
      <td style="padding:5px 10px;font-family:monospace;font-size:12px;font-weight:600">${esc(s.value || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:var(--text-muted)">${esc(s.tool || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;max-width:400px">${esc(s.reason || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:var(--text-muted)">${esc(s.approved_by || '—')}</td>
      <td style="padding:5px 10px;font-size:12px">
        ${s.severity && s.severity !== 'N/A'
          ? `<span class="sev-badge sev-${esc(s.severity.toLowerCase())}">${esc(s.severity)}</span>`
          : '<span style="color:var(--text-muted)">—</span>'}
      </td>
    </tr>`;
  }).join('');

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--medium)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">Suppressed Findings</span>
            <span class="sev-badge" style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent)">${items.length}</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px">Suppressed by <code>.epyon-ignore.yml</code> rules in the scanned repository.</div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Value / ID</th>
                  <th scope="col">Tool</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Approved By</th>
                  <th scope="col">Severity</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

function buildSBOMSection(sbom, scanId) {
  if (!sbom || sbom.total === 0) return '';
  const byType = sbom.by_type || {};
  const uid = 'sbom-' + Math.random().toString(36).slice(2);

  const typeChips = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<span class="tool-tag sbom-type-chip" style="cursor:pointer" data-sbom="${uid}" data-type="${esc(t)}" onclick="sbomFilterType('${uid}','${esc(t)}')">${esc(t)} <strong>${n}</strong></span>`)
    .join('');

  const allPackages = (sbom.packages || []).map(p => ({
    name:     p.name     || '',
    version:  p.version  || '',
    type:     p.type     || '',
    language: p.language || '',
    purl:     p.purl     || '',
    license:  (p.licenses || []).filter(Boolean).join(', ') || '',
    path:     p.path     || '',
  }));

  // Store data synchronously — script tags injected via innerHTML don't execute
  window._sbomData = window._sbomData || {};
  window._sbomData[uid] = { packages: allPackages, sortCol: null, sortDir: 'asc', filterType: null };
  window._sbomPendingUid = uid;

  const cdxUrl = scanId
    ? `/api/scans/${encodeURIComponent(scanId)}/sbom/cyclonedx`
    : null;

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">📦 SBOM</span>
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(sbom.total))} packages</span>
            ${typeChips}
          </span>
          <span style="display:flex;align-items:center;gap:10px">
            ${cdxUrl ? `<a class="btn btn-sm" href="${cdxUrl}" download style="font-size:12px" onclick="event.stopPropagation()">↓ CycloneDX JSON</a>` : ''}
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div style="margin-top:12px;display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <input id="${uid}-search" type="text" placeholder="Search packages…"
              style="flex:1;min-width:180px;max-width:320px;padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);font-size:13px"
              oninput="sbomRender('${uid}')" />
            <span id="${uid}-count" style="font-size:12px;color:var(--text-muted)"></span>
            <button class="btn btn-sm" onclick="sbomClearFilter('${uid}')">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','name')">Name <span id="${uid}-sort-name"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','version')">Version <span id="${uid}-sort-version"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','type')">Type <span id="${uid}-sort-type"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','license')">License <span id="${uid}-sort-license"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
                </tr>
              </thead>
              <tbody id="${uid}-tbody"></tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

window.sbomSort = function(uid, col) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  if (s.sortCol === col) {
    s.sortDir = s.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    s.sortCol = col;
    s.sortDir = 'asc';
  }
  sbomRender(uid);
};

window.sbomFilterType = function(uid, type) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  s.filterType = s.filterType === type ? null : type;
  // Toggle chip active style
  document.querySelectorAll(`.sbom-type-chip[data-sbom="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterType || el.dataset.type === s.filterType) ? '1' : '0.4';
    el.style.outline = el.dataset.type === s.filterType ? '2px solid #6366f1' : '';
  });
  sbomRender(uid);
};

window.sbomClearFilter = function(uid) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  s.filterType = null;
  s.sortCol = null;
  s.sortDir = 'asc';
  const input = document.getElementById(uid + '-search');
  if (input) input.value = '';
  document.querySelectorAll(`.sbom-type-chip[data-sbom="${uid}"]`).forEach(el => {
    el.style.opacity = '1';
    el.style.outline = '';
  });
  ['name','version','type','license','path'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) el.textContent = '';
  });
  sbomRender(uid);
};

window.sbomRender = function(uid) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  const tbody = document.getElementById(uid + '-tbody');
  const countEl = document.getElementById(uid + '-count');
  if (!tbody) return;

  const query = (document.getElementById(uid + '-search') || {}).value || '';
  const q = query.trim().toLowerCase();

  let items = s.packages.slice();

  // Filter by type chip
  if (s.filterType) {
    items = items.filter(p => p.type === s.filterType);
  }

  // Filter by search
  if (q) {
    items = items.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.version.toLowerCase().includes(q) ||
      p.type.toLowerCase().includes(q) ||
      p.license.toLowerCase().includes(q) ||
      p.path.toLowerCase().includes(q)
    );
  }

  // Sort
  if (s.sortCol) {
    const col = s.sortCol;
    const dir = s.sortDir === 'asc' ? 1 : -1;
    items.sort((a, b) => a[col].toLowerCase() < b[col].toLowerCase() ? -dir : a[col].toLowerCase() > b[col].toLowerCase() ? dir : 0);
  }

  // Update sort indicators
  ['name','version','type','license','path'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (!el) return;
    if (c === s.sortCol) {
      el.textContent = s.sortDir === 'asc' ? ' ▲' : ' ▼';
    } else {
      el.textContent = ' ⇅';
    }
  });

  if (countEl) {
    countEl.textContent = items.length === s.packages.length
      ? `${s.packages.length} packages`
      : `${items.length} of ${s.packages.length} packages`;
  }

  tbody.innerHTML = items.map(p => {
    const did = _depsNextId++;
    _depsRegistry.set(did, p);
    return `<tr class="finding-row" style="cursor:pointer" onclick="openDependencyDetail(${did})" title="Click to view details">
      <td style="font-family:monospace;font-size:12px;padding:3px 8px">${esc(p.name)}</td>
      <td style="font-size:12px;padding:3px 8px">${esc(p.version)}</td>
      <td style="padding:3px 8px"><span class="tool-tag" style="font-size:12px;padding:1px 6px">${esc(p.type)}</span></td>
      <td style="font-size:12px;color:var(--text-muted);padding:3px 8px">${esc(p.license)}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--text-muted);padding:3px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">${esc(p.path)}</td>
    </tr>`;
  }).join('');
};

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
    const isSuppressed = f.suppressed === true;

    const idCell = id.startsWith('CVE-')
      ? `<a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer"
            onclick="event.stopPropagation()"><code>${id}</code></a>`
      : `<code>${id}</code>`;

    const cvssNum  = f.nvd_cvss_v3_score != null ? f.nvd_cvss_v3_score : null;
    const cvssSev  = (f.nvd_cvss_v3_severity || '').toUpperCase();
    const cvssColor = cvssSev === 'CRITICAL' ? 'var(--critical)'
                    : cvssSev === 'HIGH'     ? '#f97316'
                    : cvssSev === 'MEDIUM'   ? '#f59e0b'
                    : cvssSev === 'LOW'      ? '#22d3ee'
                    : 'var(--text-muted)';
    const cvssCell = [
      cvssNum != null
        ? `<span style="font-weight:700;color:${cvssColor};font-size:12px" title="CVSS v3: ${cvssNum} ${cvssSev}">${cvssNum}</span>`
        : '',
      f.cisa_kev
        ? `<span style="background:var(--critical-bg);color:var(--critical);font-size:12px;font-weight:700;padding:1px 5px;border-radius:3px;vertical-align:middle;margin-left:${cvssNum != null ? 4 : 0}px" title="CISA Known Exploited Vulnerability">KEV</span>`
        : ''
    ].join('') || '<span style="color:var(--text-dim)">—</span>';

    // Suppressed badge
    const suppressedBadge = isSuppressed
      ? `<span style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent);border-radius:3px;padding:1px 6px;font-size:12px;font-weight:700;margin-left:6px" title="Suppressed by .epyon-ignore.yml">SUPPRESSED</span>`
      : '';

    // For IaC/Checkov findings, show file path and line numbers
    const isIaC = f.type === 'iac_misconfiguration' || f.tool === 'Checkov';
    let locationCell = '';
    if (isIaC && f.file) {
      const filePath = esc(f.file);
      const fileName = filePath.split('/').pop();
      let lineInfo = '';
      if (f.line && Array.isArray(f.line) && f.line.length === 2) {
        lineInfo = f.line[0] === f.line[1] ? `:${f.line[0]}` : `:${f.line[0]}-${f.line[1]}`;
      }
      locationCell = `<code style="font-size:12px;color:var(--accent)" title="${filePath}${lineInfo}">${fileName}${lineInfo}</code>`;
    }

    // Apply dimmed styling to suppressed findings
    const rowStyle = isSuppressed ? 'opacity:0.5' : '';

    return `
      <tr class="finding-row" onclick="openFindingDetail(${fid})" title="Click to view details" style="${rowStyle}">
        <td>
          <span class="tool-tag">${tool}</span>${suppressedBadge}
          <div style="margin-top:3px">${findingSourceBadge(f)}</div>
        </td>
        <td>${idCell}</td>
        <td style="max-width:360px">${title}${locationCell ? `<div style="margin-top:4px">${locationCell}</div>` : ''}</td>
        <td>${pkg}${ver ? ` <span style="color:var(--text-dim);font-size:12px">${ver}</span>` : ''}</td>
        <td style="white-space:nowrap">${cvssCell}</td>
        <td>${fixed ? `<span style="color:var(--clean)">${fixed}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
        <td style="color:var(--text-muted);font-size:12px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${target}">${target || '—'}</td>
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

  const items = _currentFindingsBySev[sev] || [];
  const dir   = state.dir === 'asc' ? 1 : -1;

  items.sort((a, b) => {
    let av, bv;
    switch (col) {
      case 'tool':    av = (a.tool    || '').toLowerCase(); bv = (b.tool    || '').toLowerCase(); break;
      case 'id':      av = (a.id     || a.cve_id || '').toLowerCase(); bv = (b.id || b.cve_id || '').toLowerCase(); break;
      case 'title':   av = (a.title  || a.description || '').toLowerCase(); bv = (b.title || b.description || '').toLowerCase(); break;
      case 'package': av = (a.package || a.component || '').toLowerCase(); bv = (b.package || b.component || '').toLowerCase(); break;
      case 'cvss':    av = a.nvd_cvss_v3_score ?? -1; bv = b.nvd_cvss_v3_score ?? -1; break;
      case 'fix':     av = a.fixed_version ? 1 : 0; bv = b.fixed_version ? 1 : 0; break;
      case 'target':  av = (a.target  || '').toLowerCase(); bv = (b.target  || '').toLowerCase(); break;
      default: return 0;
    }
    if (typeof av === 'string') return dir * av.localeCompare(bv);
    return dir * (av - bv);
  });

  (_pageState[sev] || (_pageState[sev] = { page: 1, size: 50 })).page = 1;
  renderFindingsPage(sev);

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

function buildAPISection(apiData) {
  if (!apiData || apiData.total === 0) return '';
  const uid = 'api-' + Math.random().toString(36).slice(2);

  // Create method filter chips
  const methodChips = Object.entries(apiData.by_method || {})
    .sort((a, b) => b[1] - a[1])
    .map(([method, count]) => {
      const color = {
        'GET': '#10b981',
        'POST': '#f59e0b',
        'PUT': '#3b82f6',
        'DELETE': '#ef4444',
        'PATCH': '#8b5cf6'
      }[method] || '#6b7280';
      return `<span class="tool-tag api-method-chip" style="cursor:pointer;background:${color};color:white" data-api="${uid}" data-method="${esc(method)}" onclick="apiFilterMethod('${uid}','${esc(method)}')">${esc(method)} <strong>${count}</strong></span>`;
    })
    .join('');

  // Create framework filter chips
  const frameworkChips = Object.entries(apiData.by_framework || {})
    .sort((a, b) => b[1] - a[1])
    .map(([fw, count]) => 
      `<span class="tool-tag api-fw-chip" style="cursor:pointer" data-api="${uid}" data-fw="${esc(fw)}" onclick="apiFilterFramework('${uid}','${esc(fw)}')">${esc(fw)} <strong>${count}</strong></span>`
    )
    .join('');

  const allEndpoints = (apiData.endpoints || []).map(ep => ({
    method:     ep.method || '',
    path:       ep.path || '',
    function:   ep.function || ep.handler || '',
    name:       ep.name || '',
    framework:  ep.framework || '',
    auth:       ep.auth || ep.authentication || '',
    tags:       ep.tags || '',
    file:       ep.file || ep.location || '',
  }));

  // Store data synchronously
  window._apiData = window._apiData || {};
  window._apiData[uid] = { endpoints: allEndpoints, sortCol: null, sortDir: 'asc', filterMethod: null, filterFramework: null };
  window._apiPendingUid = uid;

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--pass)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">🔌 API Discovery</span>
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(apiData.total))} endpoints</span>
            ${methodChips}
            ${frameworkChips}
          </span>
          <span class="findings-summary-right" onclick="event.stopPropagation()">
            <button class="btn btn-sm" onclick="downloadApiCsv('${uid}')" title="Download API endpoints as CSV">↓ API List</button>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div style="margin-top:12px;display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <input id="${uid}-search" type="text" placeholder="Search endpoints…"
              style="flex:1;min-width:180px;max-width:320px;padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);font-size:13px"
              oninput="apiRender('${uid}')" />
            <span id="${uid}-count" style="font-size:12px;color:var(--text-muted)"></span>
            <button class="btn btn-sm" onclick="apiClearFilter('${uid}')">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','method')">Method <span id="${uid}-sort-method"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','function')">Function <span id="${uid}-sort-function"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','framework')">Framework <span id="${uid}-sort-framework"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','auth')">Auth <span id="${uid}-sort-auth"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','file')">File <span id="${uid}-sort-file"></span></th>
                </tr>
              </thead>
              <tbody id="${uid}-tbody"></tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

window.apiSort = function(uid, col) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  if (s.sortCol === col) {
    s.sortDir = s.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    s.sortCol = col;
    s.sortDir = 'asc';
  }
  apiRender(uid);
};

window.apiFilterMethod = function(uid, method) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterMethod = s.filterMethod === method ? null : method;
  document.querySelectorAll(`.api-method-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterMethod || el.dataset.method === s.filterMethod) ? '1' : '0.4';
    el.style.outline = el.dataset.method === s.filterMethod ? '2px solid #6366f1' : '';
  });
  apiRender(uid);
};

window.apiFilterFramework = function(uid, fw) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterFramework = s.filterFramework === fw ? null : fw;
  document.querySelectorAll(`.api-fw-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterFramework || el.dataset.fw === s.filterFramework) ? '1' : '0.4';
    el.style.outline = el.dataset.fw === s.filterFramework ? '2px solid #6366f1' : '';
  });
  apiRender(uid);
};

window.apiClearFilter = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterMethod = null;
  s.filterFramework = null;
  s.sortCol = null;
  s.sortDir = 'asc';
  const input = document.getElementById(uid + '-search');
  if (input) input.value = '';
  document.querySelectorAll(`.api-method-chip[data-api="${uid}"],.api-fw-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = '1';
    el.style.outline = '';
  });
  ['method','path','function','framework','auth','file'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) el.textContent = '';
  });
  apiRender(uid);
};

window.downloadApiCsv = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s || !s.endpoints) return;
  const headers = ['Method','Path','Function','Name','Framework','Auth','Tags','File'];
  const rows = [headers, ...s.endpoints.map(ep => [
    ep.method, ep.path, ep.function, ep.name, ep.framework, ep.auth, ep.tags, ep.file,
  ])];
  const csv = rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: `api-endpoints-${uid}.csv` });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
};

window.apiRender = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  const tbody = document.getElementById(uid + '-tbody');
  const countEl = document.getElementById(uid + '-count');
  if (!tbody) return;

  const query = (document.getElementById(uid + '-search') || {}).value || '';
  const q = query.trim().toLowerCase();

  let items = s.endpoints.slice();

  // Filter by method
  if (s.filterMethod) {
    items = items.filter(ep => ep.method === s.filterMethod);
  }

  // Filter by framework
  if (s.filterFramework) {
    items = items.filter(ep => ep.framework === s.filterFramework);
  }

  // Filter by search
  if (q) {
    items = items.filter(ep =>
      ep.method.toLowerCase().includes(q) ||
      ep.path.toLowerCase().includes(q) ||
      ep.function.toLowerCase().includes(q) ||
      ep.framework.toLowerCase().includes(q) ||
      ep.auth.toLowerCase().includes(q) ||
      ep.file.toLowerCase().includes(q)
    );
  }

  // Sort
  if (s.sortCol) {
    const col = s.sortCol;
    const dir = s.sortDir === 'asc' ? 1 : -1;
    items.sort((a, b) => {
      const av = (a[col] || '').toLowerCase();
      const bv = (b[col] || '').toLowerCase();
      return av < bv ? -dir : av > bv ? dir : 0;
    });
  }

  // Update sort indicators
  ['method','path','function','framework','auth','file'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) {
      if (s.sortCol === c) {
        el.textContent = s.sortDir === 'asc' ? '▲' : '▼';
      } else {
        el.textContent = '';
      }
    }
  });

  // Render rows with registry and onclick handlers
  tbody.innerHTML = items.map(ep => {
    // Register endpoint for detail view
    const epId = _apiNextId++;
    _apiRegistry.set(epId, ep);

    const methodColor = {
      'GET': '#10b981',
      'POST': '#f59e0b',
      'PUT': '#3b82f6',
      'DELETE': '#ef4444',
      'PATCH': '#8b5cf6'
    }[ep.method] || '#6b7280';
    
    const shortFile = ep.file.split('/').slice(-2).join('/') || ep.file;

    return `
      <tr class="api-row" onclick="openAPIDetail(${epId})" title="Click to view details" style="cursor:pointer;border-bottom:1px solid var(--border-subtle)">
        <td style="padding:4px 8px"><span style="background:${methodColor};color:white;padding:2px 6px;border-radius:3px;font-size:12px;font-weight:600">${esc(ep.method)}</span></td>
        <td style="padding:4px 8px;font-family:monospace;font-size:12px">${esc(ep.path)}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:12px">${esc(ep.function) || '—'}</td>
        <td style="padding:4px 8px"><span class="tool-tag">${esc(ep.framework) || '—'}</span></td>
        <td style="padding:4px 8px;color:var(--text-dim);font-size:12px">${esc(ep.auth) || '—'}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:12px" title="${esc(ep.file)}">${esc(shortFile) || '—'}</td>
      </tr>`;
  }).join('');

  if (countEl) {
    const totalCount = s.endpoints.length;
    const filtered = items.length;
    countEl.textContent = filtered === totalCount
      ? `${totalCount} endpoints`
      : `${filtered} of ${totalCount} endpoints`;
  }
};

function _findingsPagerHtml(sev) {
  const all = _currentFindingsBySev[sev] || [];
  const st = _pageState[sev];
  if (all.length <= FINDINGS_PAGE_SIZES[0]) return '';
  const pages = Math.max(1, Math.ceil(all.length / st.size));
  const first = (st.page - 1) * st.size + 1;
  const last = Math.min(all.length, st.page * st.size);
  const btn = (label, page, disabled) =>
    `<button type="button" class="btn btn-sm" ${disabled ? 'disabled' : ''} onclick="setFindingsPage('${sev}', ${page})">${label}</button>`;
  const sizeOpts = FINDINGS_PAGE_SIZES.map(n => `<option value="${n}" ${n === st.size ? 'selected' : ''}>${n}</option>`).join('');
  return `<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:10px 4px;font-size:13px;color:var(--text-muted)">
    <span>Showing ${first}–${last} of ${all.length} findings</span>
    <span style="display:flex;gap:6px;align-items:center">
      <label>Per page <select onchange="setFindingsPageSize('${sev}', this.value)">${sizeOpts}</select></label>
      ${btn('« First', 1, st.page <= 1)}${btn('‹ Prev', st.page - 1, st.page <= 1)}
      <span>Page ${st.page} of ${pages}</span>
      ${btn('Next ›', st.page + 1, st.page >= pages)}${btn('Last »', pages, st.page >= pages)}
    </span>
  </div>`;
}

window.renderFindingsPage = function(sev) {
  const all = _currentFindingsBySev[sev] || [];
  const st = _pageState[sev] || (_pageState[sev] = { page: 1, size: 50 });
  const pages = Math.max(1, Math.ceil(all.length / st.size));
  st.page = Math.min(Math.max(1, st.page), pages);
  const tbody = document.getElementById(`findings-tbody-${sev}`);
  if (tbody) tbody.innerHTML = _buildFindingRows(all.slice((st.page - 1) * st.size, st.page * st.size));
  const pager = document.getElementById(`findings-pager-${sev}`);
  if (pager) {
    const controls = [...pager.querySelectorAll('button, select')];
    const focusIndex = controls.indexOf(document.activeElement);
    pager.innerHTML = _findingsPagerHtml(sev);
    if (focusIndex >= 0) {
      const updatedControls = [...pager.querySelectorAll('button, select')];
      const previousControl = updatedControls[focusIndex];
      const focusTarget = previousControl && !previousControl.disabled
        ? previousControl
        : updatedControls.find(control => !control.disabled);
      focusTarget?.focus({ preventScroll: true });
    }
  }
};

window.setFindingsPage = function(sev, page) {
  _pageState[sev].page = page;
  renderFindingsPage(sev);
};

window.setFindingsPageSize = function(sev, size) {
  _pageState[sev].size = parseInt(size, 10) || 50;
  _pageState[sev].page = 1;
  renderFindingsPage(sev);
};

function buildFindingsSection(findings) {
  const severities = ['critical', 'high', 'medium', 'low'];
  let html = '';
  let anyFindings = false;

  // Reset sort state for this render
  for (const sev of severities) {
    _currentFindingsBySev[sev] = [];
    _sortState[sev] = { col: null, dir: 'asc' };
    _pageState[sev] = { page: 1, size: 50 };
  }

  // Always show all severity levels, even if empty
  for (const sev of severities) {
    const allItems = findings[`${sev}_findings`] || [];
    _currentFindingsBySev[sev] = allItems;
    const items = allItems.slice(0, _pageState[sev].size);
    
    if (allItems.length > 0) {
      anyFindings = true;
      
      // Count suppressed findings
      const suppressedCount = allItems.filter(f => f.suppressed === true).length;
      const activeCount = allItems.length - suppressedCount;

      // Build count badge with suppressed indicator
      const countBadge = suppressedCount > 0
        ? `<span class="sev-badge ${esc(sev)}">${activeCount}</span><span style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent);border-radius:3px;padding:1px 6px;font-size:12px;font-weight:700;margin-left:4px" title="${suppressedCount} suppressed by .epyon-ignore.yml">${suppressedCount} suppressed</span>`
        : `<span class="sev-badge ${esc(sev)}">${allItems.length}</span>`;

      html += `
        <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
              ${countBadge}
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body">
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th scope="col" class="sortable-th" data-col="tool"    onclick="sortFindingsBy('${sev}','tool')">Tool <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="id"      onclick="sortFindingsBy('${sev}','id')">CVE / ID <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="title"   onclick="sortFindingsBy('${sev}','title')">Title <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="package" onclick="sortFindingsBy('${sev}','package')">Package <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="cvss"    onclick="sortFindingsBy('${sev}','cvss')" style="white-space:nowrap">CVSS / KEV <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="fix"     onclick="sortFindingsBy('${sev}','fix')">Fix Available <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="target"  onclick="sortFindingsBy('${sev}','target')">Location <span class="sort-icon">⇅</span></th>
                  </tr>
                </thead>
                <tbody id="findings-tbody-${esc(sev)}">${_buildFindingRows(items)}</tbody>
              </table>
            </div>
            <div id="findings-pager-${esc(sev)}">${_findingsPagerHtml(sev)}</div>
          </div>
        </details>`;
    } else {
      // Empty severity level - show with 0 badge
      html += `
        <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}" style="opacity:0.6">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
              <span class="sev-badge clean" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">0</span>
            </span>
            <span class="findings-summary-hint" style="color:var(--text-dim)">No findings</span>
          </summary>
          <div class="findings-body">
            <div style="padding:12px 18px;color:var(--text-muted);font-size:13px;text-align:center">
              ✓ No ${sev} severity findings detected
            </div>
          </div>
        </details>`;
    }
  }

  // ── Enrichment metadata banner ──────────────────────────────
  const enr = findings && findings.enrichment;
  let enrichmentBanner = '';
  if (enr && (enr.cisa_kev_total || enr.nvd_total)) {
    const kevTotal  = enr.cisa_kev_total || 0;
    const nvdTotal  = enr.nvd_total || 0;
    let enrichedAt = '';
    if (enr.enriched_at) {
      try { enrichedAt = new Date(enr.enriched_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); }
      catch (_) { enrichedAt = enr.enriched_at; }
    }
    const catalogLink = enr.kev_catalog_url
      ? ` &nbsp;<a href="${esc(enr.kev_catalog_url)}" target="_blank" rel="noopener"
           style="color:var(--accent);font-size:12px">↗ CISA KEV Catalog</a>`
      : '';
    enrichmentBanner = `
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px;font-size:12px;color:var(--text-muted)">
        ${kevTotal > 0 ? `<span style="background:var(--critical-bg);color:var(--critical);border:1px solid #b91c1c;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
        ${nvdTotal > 0 ? `<span style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:1px 8px;font-size:12px">${esc(nvdTotal)} NVD enriched</span>` : ''}
        ${enrichedAt ? `<span style="font-size:12px;color:var(--text-dim)">enriched ${enrichedAt}</span>` : ''}
        ${catalogLink}
        ${kevTotal > 0 ? `<span style="color:var(--critical);font-size:12px">⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} actively exploited in the wild — see <strong>KEV</strong> badges below</span>` : ''}
      </div>`;
  }

  // Add summary message when no findings at all
  const summaryMessage = !anyFindings
    ? '<div style="padding:12px 0;color:var(--text-muted);font-size:14px"><strong>✓ All vulnerability scans completed successfully with no findings.</strong></div>'
    : '';

  return `
    <div class="section findings-section-wrapper">
      <div class="section-title">Vulnerabilities</div>
      ${enrichmentBanner}
      ${summaryMessage}
      ${html}
    </div>`;
}

// ─────────────────────────────────────────────────────────────
// STIG page — shows all apps with their latest STIG scan status


// ─────────────────────────────────────────────────────────────

































// ─────────────────────────────────────────────────────────────
// Performance page — "Run Self-Diagnostic" (fixture-based self-assessment)
// Kicks off scripts/shell/run-self-assessment.sh in the background, streams
// its console output live, then re-fetches the final per-layer verdict so
// the table shows a green/red/yellow gumball per layer with a reason.






// ─────────────────────────────────────────────────────────────

function toggleSection(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('collapsed');
}

// Sort state for PPSM port tables: { [tableId]: { col: int, dir: 'asc'|'desc' } }
const _ppsmSortState = {};

// PPSM download registry: scanId -> network_discovery object
const _ppsmRegistry = new Map();

window.downloadPpsmCsv = function(scanId) {
  const nd = _ppsmRegistry.get(scanId);
  if (!nd) return;
  const sources = [
    { label: 'Docker Compose', items: nd.compose_ports   || [] },
    { label: 'Dockerfile',     items: nd.dockerfile_ports || [] },
    { label: 'Kubernetes/Helm',items: nd.k8s_ports       || [] },
    { label: 'App Config/.env',items: nd.config_ports    || [] },
  ];
  const rows = [['Source','File','Service','Port/Mapping','Protocol']];
  for (const src of sources) {
    for (const p of src.items) {
      rows.push([
        src.label,
        p.file    || '',
        p.service || '',
        p.mapping || String(p.port || ''),
        (nd.protocols || []).join(';'),
      ]);
    }
  }
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), {
    href: url,
    download: `ppsm-${scanId}.csv`,
  });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
};

window.sortPpsmTable = function(tableId, col) {
  const tbl = document.getElementById(tableId);
  if (!tbl) return;
  const tbody = tbl.querySelector('tbody');
  if (!tbody) return;

  const st = _ppsmSortState[tableId] || { col: -1, dir: 'asc' };
  const dir = (st.col === col && st.dir === 'asc') ? 'desc' : 'asc';
  _ppsmSortState[tableId] = { col, dir };

  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const av = (a.cells[col] ? a.cells[col].textContent : '').trim().toLowerCase();
    const bv = (b.cells[col] ? b.cells[col].textContent : '').trim().toLowerCase();
    // Numeric sort for port column (col 2)
    if (col === 2) {
      const an = parseInt(av, 10), bn = parseInt(bv, 10);
      if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
    }
    return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(r => tbody.appendChild(r));

  // Update sort indicators
  tbl.querySelectorAll('th[data-col]').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (!icon) return;
    if (parseInt(th.dataset.col, 10) === col) {
      icon.textContent = dir === 'asc' ? '↑' : '↓';
    } else {
      icon.textContent = '⇅';
    }
  });
};

const _SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

window.sortEnrichmentTable = function(col) {
  const items = window._enrichmentFindings;
  if (!items || !items.length) return;
  const st = window._enrichmentSortState || { col: null, dir: 'asc' };
  const dir = (st.col === col && st.dir === 'asc') ? 'desc' : 'asc';
  window._enrichmentSortState = { col, dir };
  const d = dir === 'asc' ? 1 : -1;

  items.sort((a, b) => {
    switch (col) {
      case 'sev':     return d * ((_SEV_ORDER[a.sev] ?? 4) - (_SEV_ORDER[b.sev] ?? 4));
      case 'id':      return d * (a.id || '').localeCompare(b.id || '');
      case 'package': return d * ((a.package || '').localeCompare(b.package || ''));
      case 'score': {
        const as = a.nvd_cvss_v3_score ?? -1, bs = b.nvd_cvss_v3_score ?? -1;
        return d * (as - bs);
      }
      default: return 0;
    }
  });

  const tbody = document.getElementById('enrichment-nvd-tbody');
  const tbl   = document.getElementById('enrichment-nvd-table');
  if (!tbody) return;

  // Re-render rows (reuse the same registered IDs)
  tbody.innerHTML = items.map(f => {
    const id  = esc(f.id || f.cve_id || '—');
    const pkg = esc((f.package || f.component || '—') + (f.version ? ` ${f.version}` : ''));
    const score = f.nvd_cvss_v3_score != null ? esc(String(f.nvd_cvss_v3_score)) : '—';
    const scoreColor = score !== '—'
      ? (parseFloat(score) >= 9 ? 'var(--critical)' : parseFloat(score) >= 7 ? 'var(--high)' : parseFloat(score) >= 4 ? 'var(--medium)' : 'var(--low)')
      : 'var(--text-muted)';
    const kevBadge = f.cisa_kev
      ? `<span style="background:var(--critical-bg);color:var(--critical);font-size:12px;font-weight:700;padding:1px 4px;border-radius:3px;vertical-align:middle;margin-left:4px">KEV</span>`
      : '';
    const fixed = f.fixed_version ? `<span style="color:var(--clean);font-size:12px">→ ${esc(f.fixed_version)}</span>` : '';
    return `
      <tr class="finding-row" onclick="openFindingDetail(${f._rid})" title="Click to view details">
        <td style="padding:5px 8px 5px 0"><span class="sev-badge sev-${esc(f.sev)}" style="font-size:12px">${esc(f.sev)}</span></td>
        <td style="padding:5px 8px 5px 0;font-family:monospace;font-size:12px;white-space:nowrap"><code>${id}</code>${kevBadge}</td>
        <td style="padding:5px 8px 5px 0;font-size:12px;color:var(--text-muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${pkg}</td>
        <td style="padding:5px 8px 5px 0;font-size:12px;font-weight:600;color:${scoreColor}">${score}</td>
        <td style="padding:5px 0;font-size:12px;color:var(--text-muted)">${fixed}</td>
      </tr>`;
  }).join('');

  if (tbl) tbl.querySelectorAll('th[data-col]').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.textContent = th.dataset.col === col ? (dir === 'asc' ? '↑' : '↓') : '⇅';
  });
};

// ── New metrics section builders ─────────────────────────────

// ── SLA detail registry ─────────────────────────────────────
let _slaDetailData = null;

function openSlaDetail() {
  if (!_slaDetailData) return;
  closeFindingDetail();

  const sla   = _slaDetailData.sla_compliance || {};
  const bySev = sla.by_severity || {};
  const ovPct = sla.overall_pct != null ? `${sla.overall_pct}%` : 'N/A';
  const ovColor = sla.overall_pct == null ? 'var(--text-muted)'
    : sla.overall_pct >= 80 ? 'var(--clean)' : sla.overall_pct >= 50 ? 'var(--medium)' : 'var(--critical)';

  const rows = ['critical','high','medium','low'].map(sev => {
    const d = bySev[sev] || {};
    const pct = d.pct != null ? `${d.pct}%` : '—';
    const fill = d.pct != null ? `<div class="sla-bar-track"><div class="sla-bar-fill ${sev}" style="width:${Math.min(d.pct,100)}%"></div></div>` : '<div class="sla-bar-track"></div>';
    const pctColor = d.pct == null ? 'var(--text-muted)' : d.pct >= 80 ? 'var(--clean)' : d.pct >= 50 ? 'var(--medium)' : 'var(--critical)';
    return `<tr>
      <td><span class="sev-badge ${sev}">${ucFirst(sev)}</span></td>
      <td class="sla-sla-days">≤ ${d.sla_days ?? '—'}d</td>
      <td>${fill}</td>
      <td style="color:${pctColor};font-weight:600">${pct}</td>
      <td style="color:var(--text-muted);font-size:12px">${d.within ?? 0} / ${(d.within??0)+(d.breached??0)}</td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'SLA Compliance Rate');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>SLA Compliance Rate</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">Overall</span>
          <span style="font-size:14px;color:${ovColor};font-weight:600">${ovPct}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <p style="font-size:13px;color:var(--text-muted);margin:0 0 16px">% of resolved findings fixed within severity-tiered SLA thresholds.</p>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Severity</th><th scope="col">SLA</th><th scope="col" style="min-width:140px">Compliance</th><th scope="col">Rate</th><th scope="col">Met / Total</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text-muted)">
        ${sla.total_within ?? 0} within SLA · ${sla.total_breached ?? 0} exceeded SLA
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

// ── Risk trend registry ───────────────────────────────────────
const _riskTrendRegistry = new Map();

function openRiskTrendDetail(app) {
  const pts = _riskTrendRegistry.get(app);
  if (!pts || !pts.length) return;
  closeFindingDetail();

  const latest = pts[pts.length - 1];
  const minScore = Math.min(...pts.map(p => p.score));
  const maxScore = Math.max(...pts.map(p => p.score));

  // Full-size SVG chart (480×120)
  const W = 480, H = 120, padX = 36, padY = 16;
  const innerW = W - padX * 2, innerH = H - padY * 2;
  const range = maxScore - minScore || 1;
  const sparkPts = pts.map((p, i) => {
    const x = padX + (i / Math.max(pts.length - 1, 1)) * innerW;
    const y = padY + innerH - ((p.score - minScore) / range) * innerH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  // Y-axis labels
  const yLabels = [minScore, Math.round((minScore + maxScore) / 2), maxScore].map((v, i) => {
    const y = padY + innerH - (i / 2) * innerH;
    return `<text x="${padX - 4}" y="${y.toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-muted)" dominant-baseline="middle">${v}</text>`;
  }).join('');
  // Dot on last point
  const lastPt = sparkPts.split(' ').at(-1).split(',');
  const dot = `<circle cx="${lastPt[0]}" cy="${lastPt[1]}" r="4" fill="var(--accent)"/>`;
  const chart = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="overflow:visible;display:block;max-width:100%">
    ${yLabels}
    <polyline points="${sparkPts}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dot}
  </svg>`;

  // History table rows
  const tableRows = [...pts].reverse().map(p => {
    return `<tr>
      <td style="color:var(--text-muted);font-size:12px">${esc(p.date)}</td>
      <td style="font-weight:600;color:var(--accent)">${esc(String(p.score))}</td>
      <td><span class="sev-badge critical" style="font-size:12px">${esc(String(p.critical ?? '—'))}</span></td>
      <td><span class="sev-badge high" style="font-size:12px">${esc(String(p.high ?? '—'))}</span></td>
      <td><span class="sev-badge medium" style="font-size:12px">${esc(String(p.medium ?? '—'))}</span></td>
      <td><span class="sev-badge low" style="font-size:12px">${esc(String(p.low ?? '—'))}</span></td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Risk score trend');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(app)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">Weighted Risk Score</span>
          <span style="font-size:12px;color:var(--accent);font-weight:600">Latest: ${esc(String(latest.score))}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div style="margin-bottom:20px">
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">Score over time (critical×10 + high×7 + medium×4 + low×1)</div>
        ${chart}
      </div>
      <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap">
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--accent)">${esc(String(latest.score))}</div>
          <div class="recurrence-label">Latest Score</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--clean)">${esc(String(minScore))}</div>
          <div class="recurrence-label">Best (lowest)</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--high)">${esc(String(maxScore))}</div>
          <div class="recurrence-label">Worst (highest)</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--text-muted)">${esc(String(pts.length))}</div>
          <div class="recurrence-label">Scans tracked</div>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Date</th><th scope="col">Score</th><th scope="col">Critical</th><th scope="col">High</th><th scope="col">Medium</th><th scope="col">Low</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table>
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

function buildRiskTrendSection(m) {
  const trend = m.risk_trend || [];
  if (!trend.length) {
    return `<div class="section collapsible-section collapsed" id="section-risk">
      <div class="section-title section-toggle" onclick="toggleSection('section-risk')">
        Weighted Risk Score Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body">${emptyNote('No trend data yet.')}</div>
    </div>`;
  }
  // Group by target and populate registry
  const byTarget = {};
  trend.forEach(pt => {
    if (!byTarget[pt.target]) byTarget[pt.target] = [];
    byTarget[pt.target].push(pt);
  });
  _riskTrendRegistry.clear();
  Object.entries(byTarget).forEach(([app, pts]) => _riskTrendRegistry.set(app, pts));

  const rows = Object.entries(byTarget).map(([app, pts]) => {
    const latest = pts[pts.length - 1];
    const prev = pts.length > 1 ? pts[pts.length - 2] : null;
    const delta = prev != null ? latest.score - prev.score : null;
    const arrow = delta == null ? '' : delta > 0 ? ' ▲' : delta < 0 ? ' ▼' : '';
    const color = delta == null ? 'var(--text-muted)' : delta > 0 ? 'var(--critical)' : delta < 0 ? 'var(--clean)' : 'var(--text-muted)';
    const minScore = Math.min(...pts.map(p => p.score));
    const maxScore = Math.max(...pts.map(p => p.score));
    const sparkPts = pts.map((p, i) => {
      const x = (i / Math.max(pts.length - 1, 1)) * 80;
      const y = maxScore > minScore ? 20 - ((p.score - minScore) / (maxScore - minScore)) * 16 : 10;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<tr class="clickable-row" onclick="openRiskTrendDetail('${esc(app)}')">
      <td><strong>${esc(app)}</strong></td>
      <td style="font-weight:600;color:${color}">${esc(String(latest.score))}${arrow}</td>
      <td style="color:var(--text-muted);font-size:12px">${esc(latest.date)}</td>
      <td><svg width="80" height="20" viewBox="0 0 80 20" style="overflow:visible">
        <polyline points="${sparkPts}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round"/>
      </svg></td>
    </tr>`;
  }).join('');
  return `
  <div class="section collapsible-section collapsed" id="section-risk">
    <div class="section-title section-toggle" onclick="toggleSection('section-risk')">
      Weighted Risk Score Trend
      <span class="section-title-right"><span style="font-size:12px;font-weight:normal;color:var(--text-muted)">critical×10 + high×7 + medium×4 + low×1</span><span class="section-chevron">▾</span></span>
    </div>
    <div class="section-body">
      <div class="table-container">
        <table><thead><tr><th scope="col">Application</th><th scope="col">Latest Score</th><th scope="col">Date</th><th scope="col">Trend</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

function buildSecretTrendSection(m) {
  const byTarget = m.secret_trend_by_target || {};
  const hasData = Object.values(byTarget).some(pts => pts.some(p => p.total > 0));
  const targets = Object.keys(byTarget).sort();
  if (!targets.length) {
    return `<div class="section collapsible-section collapsed" id="section-secrets">
      <div class="section-title section-toggle" onclick="toggleSection('section-secrets')">
        Secret Detection Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body">${emptyNote('No TruffleHog data found in scans.')}</div>
    </div>`;
  }
  const totalVerified   = (m.secret_trend || []).reduce((s,p) => s + (p.verified||0), 0);
  const totalUnverified = (m.secret_trend || []).reduce((s,p) => s + (p.unverified||0), 0);
  const rows = targets.map(app => {
    const pts = byTarget[app];
    const latest = pts[pts.length - 1] || {};
    const totalV  = latest.verified   || 0;
    const totalU  = latest.unverified || 0;
    const prev = pts.length > 1 ? pts[pts.length - 2] : null;
    const delta = prev != null ? latest.total - prev.total : null;
    const arrow = delta == null ? '' : delta > 0 ? ' ▲' : delta < 0 ? ' ▼' : '';
    const color = delta == null ? 'var(--text-muted)' : delta > 0 ? 'var(--critical)' : 'var(--clean)';
    return `<tr>
      <td><strong>${esc(app)}</strong></td>
      <td style="color:${totalV>0?'var(--critical)':'var(--text-muted)'}">
        ${totalV > 0 ? `<span class="sev-badge critical">${totalV} verified</span>` : '—'}
      </td>
      <td style="color:${totalU>0?'var(--high)':'var(--text-muted)'}">
        ${totalU > 0 ? `<span class="sev-badge high">${totalU} unverified</span>` : '—'}
      </td>
      <td style="color:${color};font-weight:600">${esc(String(latest.total || 0))}${arrow}</td>
      <td style="color:var(--text-muted);font-size:12px">${esc(latest.date || '—')}</td>
    </tr>`;
  }).join('');
  const badgeLine = totalVerified > 0
    ? `<span class="sev-badge critical" style="margin-right:8px">${totalVerified} verified secrets</span>` : '';
  return `
  <div class="section collapsible-section collapsed" id="section-secrets">
    <div class="section-title section-toggle" onclick="toggleSection('section-secrets')">
      Secret Detection Trend
      <span class="section-title-right">${badgeLine}<span class="section-chevron">▾</span></span>
    </div>
    <div class="section-body">
      <p class="metrics-note">TruffleHog findings per app from latest scan. Verified secrets indicate real credentials at risk.</p>
      <div class="table-container">
        <table><thead><tr><th scope="col">Application</th><th scope="col">Verified</th><th scope="col">Unverified</th><th scope="col">Total</th><th scope="col">Last Scan</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

function buildSuppressionSection(m) {
  const sup = m.suppression || {};
  const total = sup.total || 0;
  const rate  = sup.rate_pct != null ? `${sup.rate_pct}%` : 'N/A';
  const byTarget = sup.by_target || {};
  const appsSorted = Object.keys(byTarget).sort();

  const appRows = appsSorted.map(app => {
    const items = byTarget[app] || [];
    const rows = items.map(s => {
      const reason = s.reason ? `<div class="sup-reason">${esc(s.reason)}</div>` : '';
      const approver = s.approved_by ? `<span class="sup-approver">Approved by ${esc(s.approved_by)}</span>` : '';
      return `<tr>
        <td><code style="font-size:12px">${esc(s.value)}</code></td>
        <td style="color:var(--text-muted);font-size:12px">${esc(s.tool)}</td>
        <td style="color:var(--text-muted);font-size:12px;text-transform:capitalize">${esc(s.type)}</td>
        <td>${reason}${approver}</td>
      </tr>`;
    }).join('');
    return `<div class="sup-app-block">
      <div class="sup-app-header">
        <span class="sup-app-name">${esc(app)}</span>
        <span class="sup-app-count">${items.length} suppression${items.length !== 1 ? 's' : ''}</span>
      </div>
      <table class="sup-app-table">
        <thead><tr><th scope="col">Rule / ID</th><th scope="col">Tool</th><th scope="col">Type</th><th scope="col">Reason</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');

  const emptyState = !appsSorted.length
    ? `${emptyNote('No suppressions found across monitored apps.')}`
    : '';

  return `
  <div class="section collapsible-section collapsed" id="section-suppression">
    <div class="section-title section-toggle" onclick="toggleSection('section-suppression')">
      Suppression / Accepted Risk Rate
      <span class="section-title-right">
        <span style="font-size:13px;font-weight:600;color:var(--text-muted)">${esc(String(total))} suppressed · ${esc(String(m.total_resolved || 0))} resolved · ${rate} rate</span>
        <span class="section-chevron">▾</span>
      </span>
    </div>
    <div class="section-body">
      <p class="metrics-note">Findings suppressed via <code>suppressed-findings.md</code> (accepted risk) vs. actively remediated. Rate = suppressed ÷ (suppressed + resolved).</p>
      ${emptyState}
      ${appRows}
    </div>
  </div>`;
}

function buildRecurrenceSection(m) {
  const recPct  = m.recurrence_rate_pct;
  const ftfPct  = m.first_time_fix_pct;
  const resolved = m.total_resolved || 0;
  const fmt = v => v != null ? `${v}%` : 'N/A';
  const recColor = recPct == null ? 'var(--text-muted)' : recPct > 15 ? 'var(--critical)' : recPct > 5 ? 'var(--high)' : 'var(--clean)';
  const ftfColor = ftfPct == null ? 'var(--text-muted)' : ftfPct >= 50 ? 'var(--clean)' : ftfPct >= 25 ? 'var(--medium)' : 'var(--critical)';
  return `
  <div class="section collapsible-section collapsed" id="section-recurrence">
    <div class="section-title section-toggle" onclick="toggleSection('section-recurrence')">
      Recurrence &amp; First-Time Fix Rate
      <span class="section-chevron">▾</span>
    </div>
    <div class="section-body">
      <p class="metrics-note">Recurrence: findings resolved then seen again in a later scan. First-Time Fix: findings resolved within the very next scan after they appeared.</p>
      <div class="recurrence-grid">
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:${recColor}">${fmt(recPct)}</div>
          <div class="recurrence-label">Vulnerability Recurrence Rate</div>
          <div class="recurrence-sub">lower is better</div>
        </div>
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:${ftfColor}">${fmt(ftfPct)}</div>
          <div class="recurrence-label">First-Time Fix Rate</div>
          <div class="recurrence-sub">higher is better</div>
        </div>
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:var(--accent)">${esc(String(resolved))}</div>
          <div class="recurrence-label">Total Resolved (all time)</div>
          <div class="recurrence-sub">across monitored apps</div>
        </div>
      </div>
    </div>
  </div>`;
}

// Days → readable duration. Sub-day values show hours so a fast detection never renders as "0d".
const FREQ_KIND_LABEL = { pr: 'PR', nightly: 'Nightly', other: 'Push / manual' };
const FREQ_RESULT_LABEL = { pass: 'passed', fail: 'failed', unknown: 'result unknown' };

const FREQ_MAX_COLUMNS = 90;

// One shared day range across all rows, so every application's timeline lines up.
function freqRange(dateLists) {
  const days = [];
  dateLists.forEach(list => (list || []).forEach(d => {
    const t = Date.parse(String(d).slice(0, 10) + 'T00:00:00Z');
    if (!isNaN(t)) days.push(t);
  }));
  if (!days.length) return null;
  const start = Math.min(...days), end = Math.max(...days);
  const span = Math.round((end - start) / 86400000) + 1;
  const bin = Math.max(1, Math.ceil(span / FREQ_MAX_COLUMNS));
  return { start, end, bin, columns: Math.ceil(span / bin) };
}

// Horizontal heat strip: one cell per day (or per `bin` days) on a shared date range.
// Intensity = scans that day relative to the busiest cell; hue goes green -> red with the share of failed runs.
function freqTimeline(runs, range, peak) {
  if (!range) return '<span class="freq-empty">—</span>';
  const cells = Array.from({ length: range.columns }, () => ({ n: 0, fail: 0, tally: {} }));
  runs.forEach(r => {
    const t = Date.parse(String(r.date).slice(0, 10) + 'T00:00:00Z');
    if (isNaN(t)) return;
    const c = cells[Math.min(range.columns - 1, Math.floor((t - range.start) / 86400000 / range.bin))];
    c.n += 1;
    if (r.result === 'fail') c.fail += 1;
    const k = r.kind ? `${FREQ_KIND_LABEL[r.kind] || r.kind} ${FREQ_RESULT_LABEL[r.result] || r.result}` : 'scan';
    c.tally[k] = (c.tally[k] || 0) + 1;
  });
  const maxN = peak || Math.max(1, ...cells.map(c => c.n));
  const fmtDay = ms => new Date(ms).toISOString().slice(0, 10);
  const cellHtml = cells.map((c, i) => {
    const from = range.start + i * range.bin * 86400000;
    const label = range.bin > 1 ? `${fmtDay(from)} – ${fmtDay(Math.min(range.end, from + (range.bin - 1) * 86400000))}` : fmtDay(from);
    if (!c.n) return `<div class="freq-cell" title="${esc(label)} · no scans"></div>`;
    const alpha = (0.3 + 0.7 * Math.min(1, c.n / maxN)).toFixed(2);
    const colour = runs.some(r => r.kind)
      ? `hsl(${Math.round(130 * (1 - Math.min(1, (c.fail / c.n) * 2)))} 65% 45% / ${alpha})`
      : `rgb(88 166 255 / ${alpha})`;
    const title = `${label} · ${c.n} scan${c.n === 1 ? '' : 's'}` +
      (c.fail ? ` (${c.fail} failed)` : '') + '\n' +
      Object.entries(c.tally).map(([k, n]) => `${n} × ${k}`).join('\n');
    return `<div class="freq-cell" style="background:${colour}" title="${esc(title)}"></div>`;
  }).join('');
  const every = Math.max(1, Math.ceil(range.columns / 6));
  const ticks = [];
  for (let i = 0; i < range.columns; i += every) {
    ticks.push(`<span class="freq-tick" style="left:${(i / range.columns * 100).toFixed(2)}%">${esc(fmtDay(range.start + i * range.bin * 86400000).slice(5))}</span>`);
  }
  return `<div class="freq-timeline">
    <div class="freq-plot">${cellHtml}</div>
    <div class="freq-axis">${ticks.join('')}</div>
  </div>`;
}

// Shared date range and busiest-cell count for a set of [app, scan_frequency] entries, so
// every row's strip lines up on the same axis and intensity scale.
function freqScale(entries) {
  const range = freqRange(entries.map(([, f]) => f.dates));
  const peak = Math.max(1, ...entries.map(([, f]) => {
    const per = {};
    f.dates.forEach(d => { const k = String(d).slice(0, 10); per[k] = (per[k] || 0) + 1; });
    return Math.max(0, ...Object.values(per)) * (range ? range.bin : 1);
  }));
  return { range, peak };
}

function freqDots(f, range, peak) {
  const runs = f.runs && f.runs.length ? f.runs : f.dates.map(d => ({ date: d, kind: 'other', result: 'unknown' }));
  return freqTimeline(runs, range, peak);
}

function freqLegend() {
  return `<div class="freq-legend">
    <span class="legend-item">Scans per day:
      <span class="freq-swatch" style="background:hsl(130 65% 45% / 0.3)"></span> few
      <span class="freq-swatch" style="background:hsl(130 65% 45% / 1)"></span> many</span>
    <span class="legend-item">Failed share:
      <span class="freq-swatch" style="background:hsl(130 65% 45%)"></span> none
      <span class="freq-swatch" style="background:hsl(65 65% 45%)"></span> some
      <span class="freq-swatch" style="background:hsl(0 65% 45%)"></span> half or more</span>
    <span class="legend-item">Hover a day for the PR / nightly / push breakdown</span>
  </div>`;
}

function fmtDays(days) {
  if (days == null || isNaN(days)) return null;
  if (days >= 1) return { num: String(Math.round(days * 10) / 10), unit: 'days' };
  const hrs = days * 24;
  if (hrs >= 1) return { num: String(Math.round(hrs * 10) / 10), unit: 'hours' };
  return { num: '<1', unit: 'hour' };
}

function trendSparkline(points) {
  const vals = (points || []).map(p => p.risk_index);
  if (vals.length < 2) return '';
  const w = 90, h = 22, max = Math.max(...vals, 1), min = Math.min(...vals);
  const span = max - min || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1) * w).toFixed(1)},${(h - 2 - (v - min) / span * (h - 4)).toFixed(1)}`).join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--text-muted)" stroke-width="1.5"/></svg>`;
}

const _appTrendRegistry = new Map();

function openAppTrendDetail(name) {
  const t = _appTrendRegistry.get(name);
  if (!t) return;
  closeFindingDetail();
  const pts = t.points || [];
  const color = { Improving: 'var(--clean)', Declining: 'var(--critical)', Stable: 'var(--text-muted)' }[t.status] || 'var(--text-dim)';
  const fmt = n => (n > 0 ? '+' : '') + n;
  const hasWindow = t.delta !== undefined;

  let why;
  if (!hasWindow) {
    why = `Only ${pts.length} comparable nightly/full scan day${pts.length === 1 ? '' : 's'} so far. At least two are needed to call a direction.`;
  } else {
    const parts = [`Risk index went from ${t.baseline_risk_index} to ${t.risk_index} (${fmt(t.delta)}${t.delta_pct == null ? '' : `, ${fmt(t.delta_pct)}%`}) between ${esc(t.from)} and ${esc(t.to)}.`];
    parts.push(t.critical_high_delta === 0 ? 'Critical + high findings are unchanged.'
      : `Critical + high findings ${t.critical_high_delta > 0 ? 'rose' : 'fell'} by ${Math.abs(t.critical_high_delta)}.`);
    parts.push({
      Declining: 'Declining because critical/high findings rose or risk rose 10% or more.',
      Improving: 'Improving because critical/high findings fell or risk fell 10% or more.',
      Stable: 'Stable because risk moved less than 10% and critical/high findings did not rise or fall.',
    }[t.status] || '');
    why = parts.join(' ');
  }

  const vals = pts.map(p => p.risk_index);
  let chart = '';
  if (vals.length >= 2) {
    const W = 480, H = 120, padX = 36, padY = 16, iw = W - padX * 2, ih = H - padY * 2;
    const min = Math.min(...vals), max = Math.max(...vals), range = max - min || 1;
    const xy = vals.map((v, i) => [padX + i / (vals.length - 1) * iw, padY + ih - (v - min) / range * ih]);
    const labels = [min, Math.round((min + max) / 2), max].map((v, i) =>
      `<text x="${padX - 4}" y="${(padY + ih - i / 2 * ih).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-muted)" dominant-baseline="middle">${v}</text>`).join('');
    const last = xy[xy.length - 1];
    chart = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="overflow:visible;display:block;max-width:100%" role="img" aria-label="Risk index over time">
      ${labels}<polyline points="${xy.map(c => c[0].toFixed(1) + ',' + c[1].toFixed(1)).join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="4" fill="${color}"/></svg>`;
  }

  const rows = pts.map((p, i) => {
    const step = i === 0 ? '—' : fmt(Math.round((p.risk_index - pts[i - 1].risk_index) * 10) / 10);
    return `<tr>
      <td style="color:var(--text-muted);font-size:12px">${esc(p.date)}</td>
      <td style="font-weight:600">${esc(String(p.risk_index))}</td>
      <td>${esc(step)}</td>
      <td><span class="sev-badge critical" style="font-size:12px">${esc(String(p.critical ?? 0))}</span></td>
      <td><span class="sev-badge high" style="font-size:12px">${esc(String(p.high ?? 0))}</span></td>
      <td><span class="sev-badge medium" style="font-size:12px">${esc(String(p.medium ?? 0))}</span></td>
      <td><span class="sev-badge low" style="font-size:12px">${esc(String(p.low ?? 0))}</span></td>
    </tr>`;
  }).reverse().join('');

  const card = (val, label, c) => `<div class="recurrence-card" style="min-width:100px;padding:12px">
      <div class="recurrence-value" style="font-size:24px;color:${c}">${esc(String(val))}</div>
      <div class="recurrence-label">${label}</div></div>`;
  const cards = [
    card(t.risk_index ?? (pts.length ? pts[pts.length - 1].risk_index : '—'), 'Risk index now', 'var(--accent)'),
    hasWindow ? card(fmt(t.delta), 'Change in window', color) : '',
    hasWindow ? card(fmt(t.since_previous), 'Since previous scan', 'var(--text-muted)') : '',
    hasWindow ? card(fmt(t.critical_high_delta), 'Critical + high change', 'var(--text-muted)') : '',
    card(pts.length, 'Scans compared', 'var(--text-muted)'),
  ].join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', `${name} trend`);
  drawer.addEventListener('click', e => e.stopPropagation());
  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(name)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">nightly/full scans</span>
          <span style="font-size:13px;color:${color};font-weight:600">${esc(t.status)}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <p style="font-size:13px;margin:0 0 16px">${why}</p>
      ${chart ? `<div style="margin-bottom:20px"><div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">Risk index over time (15×critical + 5×high + 1×medium + 0.2×low; lower is better)</div>${chart}</div>` : ''}
      <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap">${cards}</div>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Date</th><th scope="col">Risk index</th><th scope="col">Change</th><th scope="col">Critical</th><th scope="col">High</th><th scope="col">Medium</th><th scope="col">Low</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text-muted)">One point per day (the day's latest scan). Only nightly and full scans are compared, so a quick or STIG-only scan is never read as an improvement or decline.</div>
    </div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
}

function buildAppTrendSection(m) {
  const trends = m.app_trends || {};
  _appTrendRegistry.clear();
  Object.entries(trends).forEach(([n, t]) => _appTrendRegistry.set(n, t));
  const order = { Declining: 0, Stable: 1, Improving: 2, 'Not enough data': 3 };
  const rows = Object.entries(trends)
    .sort((a, b) => (order[a[1].status] - order[b[1].status]) || a[0].localeCompare(b[0]))
    .map(([name, t]) => {
      const color = { Improving: 'var(--clean)', Declining: 'var(--critical)', Stable: 'var(--text-muted)' }[t.status] || 'var(--text-dim)';
      const icon = { Improving: '↗', Declining: '↘', Stable: '→' }[t.status] || '–';
      const fmt = n => (n > 0 ? '+' : '') + n;
      const change = t.delta === undefined ? '—'
        : `${fmt(t.delta)}${t.delta_pct === null || t.delta_pct === undefined ? '' : ` (${fmt(t.delta_pct)}%)`}`;
      const prev = t.since_previous === undefined ? '—' : fmt(t.since_previous);
      const period = t.from ? `${esc(t.from)} → ${esc(t.to)}` : '—';
      return `<tr class="clickable-row" tabindex="0" role="button" aria-label="Show ${esc(name)} trend details" style="cursor:pointer" onclick="openAppTrendDetail(this.dataset.app)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();openAppTrendDetail(this.dataset.app)}" data-app="${esc(name)}">
        <td>${esc(name)}</td>
        <td><span style="color:${color};font-weight:600">${icon} ${esc(t.status)}</span></td>
        <td>${t.risk_index === undefined ? '—' : esc(String(t.risk_index))}</td>
        <td>${esc(change)}</td>
        <td>${esc(prev)}</td>
        <td>${period}</td>
        <td>${esc(t.scan_type || '—')} · ${esc(String(t.scans_compared || 0))}</td>
        <td>${trendSparkline(t.points)}</td>
      </tr>`;
    }).join('');
  if (!rows) return '';
  return `
      <div class="section">
        <div class="section-title">
          Application Trend Status
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">are applications improving or declining over time</span>
        </div>
        <div class="table-container">
          <table id="tbl-app-trends">
            <thead><tr>
              <th scope="col">Application</th><th scope="col">Status</th><th scope="col">Risk index</th>
              <th scope="col">Change in window</th><th scope="col">Since previous scan</th>
              <th scope="col">Window</th><th scope="col">Scan type · points</th><th scope="col">Trend</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:8px">
          Risk index = 15×critical + 5×high + 1×medium + 0.2×low (the Score Card's vulnerability weights; lower is better).
          Only nightly and full scans are compared, one per day. Declining = risk up 10% or more, or more critical/high findings;
          Improving = risk down 10% or more, or fewer critical/high findings. Click a row for the full history.
        </div>
      </div>`;
}

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

    const fastestHtml = m.fastest_remediator
      ? `<div class="mttr-fastest">
           <span class="mttr-fastest-label">Fastest</span>
           <span class="mttr-fastest-app">${esc(m.fastest_remediator.target)}</span>
           <span class="mttr-fastest-days">${esc(String(m.fastest_remediator.mttr_days))}d avg</span>
         </div>`
      : '';

    const sevRows = (bySev) => ['critical','high','medium','low'].map(sev => {
      const val = (bySev || {})[sev];
      const d = fmtDays(val);
      const display = d ? `${d.num}${d.unit === 'days' ? 'd' : 'h'}` : 'No data';
      return `<div class="mttr-sev-row">
        <span class="sev-badge ${sev}">${ucFirst(sev)}</span>
        <span class="mttr-sev-days">${esc(display)}</span>
      </div>`;
    }).join('');

    function buildFixRateStats(m) {
      const sla      = m.sla_compliance || {};
      const ftfPct   = m.first_time_fix_pct;
      const slaPct   = sla.overall_pct;

      const fmt = (v, suffix = '%') => v != null ? `${v}${suffix}` : 'N/A';

      const slaColor = slaPct == null ? 'var(--text-muted)'
        : slaPct >= 80 ? 'var(--clean)' : slaPct >= 50 ? 'var(--medium)' : 'var(--critical)';
      const arPct    = m.accepted_risk_pct ?? null;
      const supColor = arPct == null ? 'var(--text-muted)'
        : arPct <= 10 ? 'var(--clean)' : arPct <= 25 ? 'var(--medium)' : 'var(--high)';
      const ftfColor = ftfPct == null ? 'var(--text-muted)'
        : ftfPct >= 50 ? 'var(--clean)' : ftfPct >= 25 ? 'var(--medium)' : 'var(--critical)';

      return `<div class="fix-rate-stats">
        <div class="fix-rate-stat-row fix-rate-stat-link" title="Click to view SLA breakdown by severity" onclick="openSlaDetail()">
          <span class="fix-rate-stat-label">SLA Compliance <span class="stat-link-arrow">›</span></span>
          <span class="fix-rate-stat-value" style="color:${slaColor}">${fmt(slaPct)}</span>
        </div>
        <div class="fix-rate-stat-row" title="First-time fix rate: % of resolved findings that were not seen again in a later scan">
          <span class="fix-rate-stat-label">First-Time Fix</span>
          <span class="fix-rate-stat-value" style="color:${ftfColor}">${fmt(ftfPct)}</span>
        </div>
        <div class="fix-rate-stat-row" title="Accepted risk rate: suppressed finding instances in latest scans as a % of open + suppressed findings">
          <span class="fix-rate-stat-label">Accepted Risk</span>
          <span class="fix-rate-stat-value" style="color:${supColor}">${fmt(arPct)}</span>
        </div>
      </div>`;
    }

    function buildMttrPanelHtml(data, fastestHtml) {
      const mttr = fmtDays(data.mttr_days);
      const mttrDisplay = mttr
        ? `<span class="mttr-number">${esc(mttr.num)}</span><span class="mttr-unit">${mttr.unit}</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttrSub = mttr ? 'avg across resolved findings' : 'No findings resolved yet in this period';
      const mttd = fmtDays(data.mttd_days);
      const mttdDisplay = mttd
        ? `<span class="mttr-number mttd-number">${esc(mttd.num)}</span><span class="mttr-unit">${mttd.unit}</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttdSub = mttd ? 'avg detection window across new findings' : 'No new findings detected yet in this period';
      return `
        <div class="mttr-display">${mttrDisplay}</div>
        <div class="mttr-sub">${esc(mttrSub)}</div>
        <div class="mttr-sev-grid">${sevRows(data.mttr_by_severity)}</div>
        ${fastestHtml || ''}
        <div class="mttr-divider"></div>
        <div class="section-title" style="margin-top:0">Mean Time to Detect</div>
        <div class="mttr-display">${mttdDisplay}</div>
        <div class="mttr-sub">${esc(mttdSub)}</div>
        <div class="mttr-sev-grid">${sevRows(data.mttd_by_severity)}</div>`;
    }

    const overallData = {
      mttr_days: m.mttr_days, mttr_by_severity: m.mttr_by_severity,
      mttd_days: m.mttd_days, mttd_by_severity: m.mttd_by_severity,
    };
    const appList = Object.keys(m.metrics_by_target || {}).sort();
    const appOptions = appList.map(a =>
      `<option value="${esc(a)}">${esc(a)}</option>`
    ).join('');

    const totalMerges = m.total_merges_to_main || 0;
    const mergesData = m.merges_to_main || {};
    const topCveRows = m.top_cves.length
      ? m.top_cves.map(c => `
          <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}"
                   target="_blank" rel="noopener noreferrer"><code>${esc(c.cve_id)}</code></a></td>
            <td><span class="sev-badge ${esc(c.severity)}">${ucFirst(c.severity)}</span></td>
            <td>${esc(c.count)}</td>
            <td style="max-width:280px">${esc(c.title || '—')}</td>
            <td>${sourcesBadges(c.sources)}</td>
            <td style="font-size:12px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`).join('')
      : emptyRow(6, 'No CVE data — run a scan to populate');

    const freqScaleAll = freqScale(Object.entries(m.scan_frequency || {}));
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
            <td>${freqDots(f, freqScaleAll.range, freqScaleAll.peak)}</td>
          </tr>`;
      }).join('');

    const legendSevs = ['critical','high','medium','low'].map(s =>
      `<span class="legend-item"><span class="legend-dot" style="background:var(--${s})"></span>${ucFirst(s)}</span>`
    ).join('');

    const filterNotice = m.metrics_filtered
      ? `<div class="metrics-filter-notice">
           Showing ${esc(String(m.monitored_count))} continuously monitored app${m.monitored_count !== 1 ? 's' : ''} ·
           <a href="#/applications" onclick="navigate('#/applications')">manage</a>
         </div>`
      : '';

    page.innerHTML = `
      ${pageHeader(`Metrics`, { actions: `<button class="btn btn-sm" onclick="renderMetrics()">&#8635; Refresh</button>` })}
      ${filterNotice}

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
        <div class="stat-card">
          <div class="stat-value">${esc(String(totalMerges))}</div>
          <div class="stat-label">Merges to Primary</div>
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
              <span class="legend-dot" style="background:var(--border);border:1px solid var(--text-dim)"></span>
              No fix (${esc(String(m.fix_rate.without_fix))})
            </span>
          </div>
          ${buildFixRateStats(m)}
        </div>
        <div class="chart-panel mttr-panel">
          <div class="mttr-panel-header">
            <div class="section-title" style="margin-bottom:0">Mean Time to Remediate</div>
            <select id="mttr-app-filter" class="mttr-app-select">
              <option value="">All Apps</option>
              ${appOptions}
            </select>
          </div>
          <div id="mttr-panel-body">${buildMttrPanelHtml(overallData, fastestHtml)}</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Findings by Tool</div>
        <div class="trend-wrap">
          <canvas id="tool-chart" style="display:block;width:100%;height:${toolH}px"></canvas>
        </div>
        <div class="chart-legend" style="margin-top:12px">${legendSevs}</div>
      </div>

      <div class="section">
        <div class="section-title">
          Vulnerability Trend
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">${m.trend.length} day${m.trend.length !== 1 ? 's' : ''} · last ${m.window_days || 90} days</span>
        </div>
        <div class="trend-wrap">
          <canvas id="trend-chart" style="display:block;width:100%;height:200px"></canvas>
        </div>
        <div class="chart-legend">${legendSevs}</div>
      </div>

      ${buildAppTrendSection(m)}

      <div class="section collapsible-section collapsed" id="section-cves">
        <div class="section-title section-toggle" onclick="toggleSection('section-cves')">
          Top CVEs
          <span class="section-title-right">
            <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">from latest scan per application</span>
            <span class="section-chevron">▾</span>
          </span>
        </div>
        <div class="section-body">
          <div class="table-container">
            <table id="tbl-cves">
              <thead>
                <tr>
                  <th scope="col" data-col="cve_id">CVE ID <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="severity">Severity <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="count">Count <span class="sort-icon">⇅</span></th>
                  <th scope="col">Title</th>
                  <th scope="col" data-col="source">Source <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="apps">Applications <span class="sort-icon">⇅</span></th>
                </tr>
              </thead>
              <tbody>${topCveRows}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="section collapsible-section collapsed" id="section-freq">
        <div class="section-title section-toggle" onclick="toggleSection('section-freq')">
          Scan Frequency
          <span class="section-chevron">▾</span>
        </div>
        <div class="section-body">
          ${freqLegend()}
          <div class="table-container">
            <table id="tbl-freq">
              <thead>
                <tr>
                  <th scope="col" data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="total">Total Scans <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="first">First Scan <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="last">Latest Scan <span class="sort-icon">⇅</span></th>
                  <th scope="col">History</th>
                </tr>
              </thead>
              <tbody>${freqRows || emptyRow(5, 'No scan data available')}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="section collapsible-section collapsed" id="section-merges">
        <div class="section-title section-toggle" onclick="toggleSection('section-merges')">
          Merges to Primary Branch
          <span class="section-chevron">▾</span>
        </div>
        <div class="section-body">
          <div style="display:flex;gap:8px;margin-bottom:14px;align-items:center">
            <span style="font-size:12px;color:var(--text-muted);margin-right:4px">Filter:</span>
            <button class="btn btn-sm merge-range-btn active" data-days="7">7 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="14">14 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="30">30 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="0">All time</button>
          </div>
          <div class="table-container">
            <table id="tbl-merges">
              <thead>
                <tr>
                  <th scope="col" data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="total">Merges <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="first">First Merge <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="last">Latest Merge <span class="sort-icon">⇅</span></th>
                  <th scope="col">History</th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>

      ${(_slaDetailData = m, '')}
      ${buildRiskTrendSection(m)}
      ${buildSecretTrendSection(m)}
      ${buildSuppressionSection(m)}
      ${buildRecurrenceSection(m)}`;

    requestAnimationFrame(() => {
      const donut = document.getElementById('donut-chart');
      if (donut) drawDonutChart(donut, [
        { value: m.fix_rate.with_fix,    color: '#3fb950' },
        { value: m.fix_rate.without_fix, color: '#30363d' },
      ]);

      // ── MTTR/MTTD app filter dropdown ──────────────────────
      const mttrFilter = document.getElementById('mttr-app-filter');
      const mttrBody   = document.getElementById('mttr-panel-body');
      if (mttrFilter && mttrBody) {
        mttrFilter.addEventListener('change', () => {
          const app = mttrFilter.value;
          if (!app) {
            mttrBody.innerHTML = buildMttrPanelHtml(overallData, fastestHtml);
          } else {
            const appData = (m.metrics_by_target || {})[app] || {};
            mttrBody.innerHTML = buildMttrPanelHtml(appData, '');
          }
        });
      }

      const toolCanvas = document.getElementById('tool-chart');
      if (toolCanvas) drawHBarChart(toolCanvas, m.by_tool.map(t => ({
        label: t.tool, critical: t.critical, high: t.high,
        medium: t.medium, low: t.low, total: t.total, top_app: t.top_app || '',
      })));

      const trendCanvas = document.getElementById('trend-chart');
      if (trendCanvas && m.trend.length) {
        drawStackedBarChart(trendCanvas, [
          { color: '#ff7b72', data: m.trend.map(t => t.critical) },
          { color: '#ffa657', data: m.trend.map(t => t.high) },
          { color: '#e3b341', data: m.trend.map(t => t.medium) },
          { color: '#79c0ff', data: m.trend.map(t => t.low) },
        ], m.trend.map(t => t.timestamp.slice(0, 10)), m.trend);
      }

      // ── Sortable: Top CVEs ──────────────────────────────────
      (function() {
        const tbl = document.getElementById('tbl-cves');
        if (!tbl || !m.top_cves.length) return;
        let sortCol = 'count', sortDir = -1;
        const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
        function cveRow(c) {
          return `<tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" rel="noopener noreferrer"><code>${esc(c.cve_id)}</code></a></td>
            <td><span class="sev-badge ${esc(c.severity)}">${ucFirst(c.severity)}</span></td>
            <td>${esc(c.count)}</td>
            <td style="max-width:280px">${esc(c.title || '\u2014')}</td>
            <td>${sourcesBadges(c.sources)}</td>
            <td style="font-size:12px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`;
        }
        function resort() {
          const rows = [...m.top_cves].sort((a, b) => {
            if (sortCol === 'severity') return sortDir * ((SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
            if (sortCol === 'count')    return sortDir * (a.count - b.count);
            if (sortCol === 'apps')     return sortDir * (a.apps.length - b.apps.length);
            if (sortCol === 'source')   return sortDir * ((a.sources||[]).join().localeCompare((b.sources||[]).join()));
            return sortDir * String(a[sortCol]).localeCompare(String(b[sortCol]));
          });
          tbl.querySelector('tbody').innerHTML = rows.map(cveRow).join('');
          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'count' || sortCol === 'apps' ? -1 : 1; }
            resort();
          };
        });
        resort();
      })();

      // ── Sortable: Scan Frequency ────────────────────────────
      (function() {
        const tbl = document.getElementById('tbl-freq');
        if (!tbl) return;
        let sortCol = 'total', sortDir = -1;
        const freqData = Object.entries(m.scan_frequency || {});
        const { range: freqSpan, peak: freqPeak } = freqScale(freqData);
        function freqRow([name, f]) {
          const first = f.dates.length ? f.dates[0] : '\u2014';
          const last  = f.dates.length ? f.dates[f.dates.length - 1] : '\u2014';
          return `<tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(f.total)}</td>
            <td>${esc(first)}</td>
            <td>${esc(last)}</td>
            <td>${freqDots(f, freqSpan, freqPeak)}</td>
          </tr>`;
        }
        function resort() {
          const rows = [...freqData].sort(([na, fa], [nb, fb]) => {
            if (sortCol === 'name')  return sortDir * na.localeCompare(nb);
            if (sortCol === 'total') return sortDir * (fa.total - fb.total);
            if (sortCol === 'first') return sortDir * (fa.dates[0] || '').localeCompare(fb.dates[0] || '');
            if (sortCol === 'last')  return sortDir * ((fa.dates[fa.dates.length-1]||'').localeCompare(fb.dates[fb.dates.length-1]||''));
            return 0;
          });
          tbl.querySelector('tbody').innerHTML = rows.map(freqRow).join('');
          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'total' ? -1 : 1; }
            resort();
          };
        });
        resort();
      })();

      // ── Merges to Primary Branch (filterable) ───────────────
      (function() {
        const tbl = document.getElementById('tbl-merges');
        if (!tbl) return;
        const allData = Object.entries(mergesData);
        const mergeSpan = freqRange(allData.map(([, f]) => f.dates));
        let activeDays = 7;
        let sortCol = 'total', sortDir = -1;

        function cutoffDate(days) {
          if (!days) return '';
          const d = new Date();
          d.setDate(d.getDate() - days);
          return d.toISOString().slice(0, 10);
        }

        function mergeRow([name, f], filteredDates) {
          const first = filteredDates.length ? filteredDates[0] : '—';
          const last  = filteredDates.length ? filteredDates[filteredDates.length - 1] : '—';
          return `<tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(filteredDates.length)}</td>
            <td>${esc(first)}</td>
            <td>${esc(last)}</td>
            <td>${freqTimeline(filteredDates.map(d => ({ date: d })), mergeSpan)}</td>
          </tr>`;
        }

        function resort() {
          const cutoff = cutoffDate(activeDays);
          const filtered = allData
            .map(([name, f]) => {
              const dates = cutoff ? f.dates.filter(d => d >= cutoff) : [...f.dates];
              return [name, f, dates];
            })
            .filter(([,, dates]) => dates.length > 0)
            .sort(([na,, da], [nb,, db]) => {
              if (sortCol === 'name')  return sortDir * na.localeCompare(nb);
              if (sortCol === 'total') return sortDir * (da.length - db.length);
              if (sortCol === 'first') return sortDir * (da[0]||'').localeCompare(db[0]||'');
              if (sortCol === 'last')  return sortDir * ((da[da.length-1]||'').localeCompare((db[db.length-1]||'')));
              return 0;
            });

          tbl.querySelector('tbody').innerHTML = filtered.length
            ? filtered.map(([name, f, dates]) => mergeRow([name, f], dates)).join('')
            : emptyRow(5, 'No merges in this period');

          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }

        // Filter buttons
        document.querySelectorAll('.merge-range-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            document.querySelectorAll('.merge-range-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeDays = parseInt(btn.dataset.days, 10);
            resort();
          });
        });

        // Column sort
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'total' ? -1 : 1; }
            resort();
          };
        });

        resort();
      })();

      buildCiHealthSection().then(html => {
        if (html && location.hash.startsWith('#/metrics')) page.insertAdjacentHTML('beforeend', html);
      });
    });
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}


// ─────────────────────────────────────────────────────────────



// ─────────────────────────────────────────────────────────────










// ── Jira Settings helpers ─────────────────────────────────────



// ── STIG History Matrix & MTTR ───────────────────────────────


// ── STIG Inline Viewer ────────────────────────────────────────


// ── Destructive confirm modal ─────────────────────────────────
function showDestructiveModal({ title, body, target, confirmLabel = 'Delete', onConfirm }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-box" aria-labelledby="modal-title">
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

  function close() {
    overlay.remove();
  }

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  overlay.querySelector('#modal-cancel').addEventListener('click', close);
  overlay.querySelector('#modal-confirm').addEventListener('click', () => {
    close();
    onConfirm();
  });

  document.body.appendChild(overlay);
  overlay.querySelector('#modal-confirm').focus();
}

// ── Application management helpers ───────────────────────────
async function hideApplication(name) {
  if (!await confirmDialog({
    title: `Hide "${name}"?`,
    body: 'It will be hidden from the applications list. The scan data is preserved and can be restored later.',
    confirmLabel: 'Hide',
  })) return;
  try {
    await api.hideApp(name);
    renderApplications();
  } catch (e) {
    toast(`Failed to hide application: ${e.message}`, 'error');
  }
}

async function restoreApplication(name) {
  try {
    await api.restoreApp(name);
    renderApplications();
  } catch (e) {
    toast(`Failed to restore application: ${e.message}`, 'error');
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
        toast(`Failed to delete application: ${e.message}`, 'error');
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
        toast(`Failed to delete scan: ${e.message}`, 'error');
      }
    },
  });
}

function toggleDownloadMenu(evt) {
  evt.stopPropagation();
  const menu = document.getElementById('download-split-menu');
  const toggleBtn = evt.currentTarget;
  if (!menu) return;
  const isOpen = !menu.hidden;
  menu.hidden = isOpen;
  toggleBtn.setAttribute('aria-expanded', String(!isOpen));
  if (!isOpen) {
    const closeOnOutsideClick = (e) => {
      const wrap = document.getElementById('download-split-btn');
      if (wrap && !wrap.contains(e.target)) {
        menu.hidden = true;
        toggleBtn.setAttribute('aria-expanded', 'false');
        document.removeEventListener('click', closeOnOutsideClick);
      }
    };
    setTimeout(() => document.addEventListener('click', closeOnOutsideClick), 0);
  }
}


async function calculateScorecardForScan(scanId) {
  // Find scorecard container
  let container = document.getElementById('scorecard-container');
  if (!container) return;

  // Show loading state
  container.innerHTML = `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <rect x="3" y="3" width="18" height="18" rx="2"/>
                <path d="M3 9h18"/>
                <path d="M9 21V9"/>
              </svg>
              Security Score Card
            </span>
          </span>
          <span class="loading-inline">Loading…</span>
        </summary>
      </details>
    </div>`;

  try {
    const scorecardData = await api.calculateScorecard(scanId);
    container.innerHTML = buildScorecardCard(scorecardData);
  } catch (e) {
    // 422 = "no consolidated findings data yet" — an expected state for older/
    // interrupted/partial scans, not a server bug. Render it as an informational
    // notice rather than a scary red "Error" so users aren't alarmed.
    const isUnavailable = e.status === 422;
    const accentColor = isUnavailable ? 'var(--text-muted)' : 'var(--critical)';
    const badgeLabel   = isUnavailable ? 'Unavailable' : 'Error';
    const bodyMessage  = isUnavailable
      ? esc(e.detail || e.message)
      : `<strong>Error:</strong> ${esc(e.detail || e.message)}`;
    container.innerHTML = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:${accentColor}">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <path d="M3 9h18"/>
                  <path d="M9 21V9"/>
                </svg>
                Security Score Card
              </span>
            </span>
            <span style="color:${accentColor};font-size:12px">${badgeLabel}</span>
          </summary>
          <div class="findings-body" style="padding:12px 18px 16px">
            <p style="color:${accentColor};font-size:13px;margin:0">${bodyMessage}</p>
          </div>
        </details>
      </div>`;
  }
}

// Store dimension data globally for modal access
window._scorecardDimensions = {};

function buildScorecardCard(scorecardData) {
  if (!scorecardData || !scorecardData.trl_level) return '';

  const level = scorecardData.trl_level;
  const score = (scorecardData.weighted_score || 0).toFixed(1);
  const dims = scorecardData.dimension_scores || {};
  const weights = scorecardData.weights || {};
  const blockers = scorecardData.blockers || [];

  // Map level to color and grade
  const gradeInfo = {
    9: { emoji: '🟢', label: 'A+', color: 'var(--pass, #10b981)' },
    8: { emoji: '🟢', label: 'A', color: 'var(--pass, #10b981)' },
    7: { emoji: '🟢', label: 'B+', color: 'var(--pass, #10b981)' },
    6: { emoji: '🔵', label: 'B', color: '#38bdf8' },
    5: { emoji: '🔵', label: 'C+', color: '#38bdf8' },
    4: { emoji: '🔵', label: 'C', color: '#38bdf8' },
    3: { emoji: '🟡', label: 'D', color: 'var(--medium, #f59e0b)' },
    2: { emoji: '🔴', label: 'F', color: 'var(--critical, #ef4444)' },
    1: { emoji: '🔴', label: 'F', color: 'var(--critical, #ef4444)' },
  };
  const info = gradeInfo[level] || gradeInfo[1];
  
  // Determine border color based on score
  const borderColor = score >= 70 ? 'var(--pass)' : score >= 50 ? '#38bdf8' : 'var(--critical)';

  // Build dimension cards
  const dimOrder = ['security', 'supply_chain', 'code_quality', 'compliance', 'operational', 'mosa'];
  const dimLabels = {
    security: 'Security',
    supply_chain: 'Supply Chain',
    code_quality: 'Code Quality',
    compliance: 'Compliance',
    operational: 'Operational',
    mosa: 'MOSA',
  };

  // Store dimension data globally
  window._scorecardDimensions = {};

  const dimCards = dimOrder.map(key => {
    const d = dims[key] || { score: 0, applicable: false, details: {}, evidence: [] };
    const applicable = d.applicable !== false && dims[key];
    const s = (d.score || 0).toFixed(0);
    const w = ((weights[key] || 0) * 100).toFixed(0);
    const barColor = s >= 70 ? 'var(--pass)' : s >= 50 ? 'var(--medium)' : 'var(--critical)';
    
    // Store dimension data for modal
    window._scorecardDimensions[key] = {
      key: key,
      label: dimLabels[key],
      score: s,
      weight: w,
      color: barColor,
      applicable: !!applicable,
      details: d.details || {},
      evidence: d.evidence || []
    };
    
    return `
      <div class="scorecard-dim-card" onclick="showDimensionModal('${key}')" style="cursor:pointer">
        <div class="scorecard-dim-label">${esc(dimLabels[key])}</div>
        ${applicable ? `<div class="scorecard-dim-score" style="color:${barColor}">${s}</div>
        <div class="scorecard-dim-weight">${w}% weight</div>
        <div class="scorecard-dim-bar">
          <div class="scorecard-dim-bar-fill" style="width:${s}%;background:${barColor}"></div>
        </div>` : `<div class="scorecard-dim-score" style="color:var(--text-muted);font-size:18px">Not scanned</div>
        <div class="scorecard-dim-weight">${w}% weight · scores 0</div>`}
        <div style="margin-top:8px;font-size:12px;color:var(--text-muted);text-align:center">Click for details</div>
      </div>`;
  }).join('');

  // Build blockers list
  const blockersHtml = blockers.length > 0 ? `
    <div class="scorecard-blockers">
      <div class="scorecard-blockers-title">⚠️ Critical Issues</div>
      <ul class="scorecard-blockers-list">
        ${blockers.map(b => `<li>${esc(b)}</li>`).join('')}
      </ul>
    </div>` : '';

  const scanId = scorecardData.scan_id || '';
  const prev = scorecardData.previous;
  const prevHtml = prev ? `
    <div class="scorecard-compare" style="margin-top:16px;font-size:13px;color:var(--text-muted)">
      <strong>Before this scoring update</strong> (v${esc(String(prev.scoring_version))}):
      ${esc(String(prev.weighted_score))} → <strong>${esc(score)}</strong>
      (TRL ${esc(String(prev.trl_level))} → ${esc(String(level))}).
      ${dimOrder.map(k => {
        const o = prev.dimension_scores && prev.dimension_scores[k] ? prev.dimension_scores[k].score : null;
        const n = (dims[k] || {}).score;
        if (o == null || n == null) return '';
        const diff = Math.round(n - o);
        return `<span style="margin-right:10px">${esc(dimLabels[k])} ${diff >= 0 ? '+' : ''}${diff}</span>`;
      }).join('')}
    </div>` : '';
  const so = scorecardData.signoff;
  const signoffHtml = `
    <div class="scorecard-signoff" data-scan="${esc(scanId)}" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
      <strong style="font-size:13px">Reviewer sign-off</strong>
      ${so ? `<div style="margin-top:6px;font-size:13px;color:${so.valid ? 'var(--pass)' : 'var(--medium)'}">
          ${so.valid ? '✓ Signed off' : '⚠ Sign-off no longer matches the current score'} by
          <strong>${esc(so.reviewer)}</strong> on ${esc(so.signed_at)} (score ${esc(String(so.weighted_score))})
          ${so.comment ? `<div style="color:var(--text-muted);margin-top:4px">${esc(so.comment)}</div>` : ''}
          <button class="btn btn-sm" style="margin-top:8px" onclick="revokeScorecardSignoff(this)">Revoke</button>
        </div>` : ''}
      ${so && so.valid ? '' : `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
          <input type="text" class="so-name" maxlength="100" placeholder="Reviewer name" style="padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text)">
          <input type="text" class="so-comment" maxlength="2000" placeholder="Comment (optional)" style="flex:1;min-width:200px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text)">
          <button class="btn btn-sm btn-primary" onclick="signOffScorecard(this)">Sign off this score</button>
        </div><div class="so-msg" style="font-size:12px;color:var(--critical);margin-top:6px"></div>`}
      <div style="margin-top:10px"><a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/scorecard/evidence" download>↓ Evidence package (.zip)</a></div>
    </div>`;

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:${borderColor}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <rect x="3" y="3" width="18" height="18" rx="2"/>
                <path d="M3 9h18"/>
                <path d="M9 21V9"/>
              </svg>
              Security Score Card
            </span>
            <span style="margin-left:8px;font-size:24px;vertical-align:middle">${info.emoji}</span>
            <span style="margin-left:8px;font-weight:700;font-size:15px;color:${info.color}">Grade ${info.label}</span>
          </span>
          <span style="display:flex;align-items:center;gap:12px">
            <button type="button" class="btn btn-sm" title="How the Score Card works" onclick="event.preventDefault();event.stopPropagation();showScorecardHelp()">ⓘ How it works</button>
            <span style="font-size:18px;font-weight:700;color:var(--accent)">${score}</span>
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:16px 18px">
          <div class="scorecard-dimensions" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:${blockersHtml ? '20px' : '0'}">
            ${dimCards}
          </div>
          ${blockersHtml}
          ${prevHtml}
          ${signoffHtml}
          <div style="font-size:12px;color:var(--text-muted);padding-top:16px;border-top:1px solid var(--border);margin-top:16px">
            <strong>About Scoring:</strong> Anything never scanned in any scan of this application scores 0 rather than being ignored, so skipping a scan can never raise the score. Findings come from the latest scan (earlier ones are treated as closed out); STIG results come from the last STIG run. It does not depend on the scan type. Six dimensions (Security, Supply Chain, Code Quality, Compliance, Operational, MOSA). 
            Scores 70+ are production-ready, 50-69 need improvements, below 50 require immediate attention.
            <br><small><strong>MOSA</strong> = Modular Open Systems Approach: modularity, open standards, interoperability, portability. <strong>Click dimension cards for detailed breakdowns.</strong></small>
          </div>
        </div>
      </details>
    </div>`;
}

window.showScorecardHelp = () => {
  const row = (a, b) => `<tr><td style="padding:6px 12px 6px 0;vertical-align:top;white-space:nowrap"><strong>${a}</strong></td><td style="padding:6px 0;color:var(--text-muted)">${b}</td></tr>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container modal-lg" style="max-height:85vh;overflow:auto;font-size:13px;line-height:1.5">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 style="margin:0;color:var(--text)">How the Score Card works</h2>
        <button class="btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
      </div>
      <h3>What it measures</h3>
      <p>The Score Card rates the <strong>application</strong>, not a single scan. Findings are those of the latest scan; earlier findings that are gone are treated as closed out, and history only feeds the trend. STIG results come from the last STIG run, since STIGs run on demand. Scan type does not change the score or weights.</p>
      <h3>Six dimensions, each 0–100</h3>
      <table>
        ${row('Security (30%)', 'Starts at 100. Critical −15, high −5, medium −1, low −0.2 per vulnerability (CVEs only). IaC misconfigurations (Checkov) are scored separately and more lightly: critical −5, high −2, medium −0.5, low −0.1, max −25. Semgrep SAST findings are code weaknesses, not CVEs, so they also get their own line (critical −3, high −1.5, medium −0.5, low −0.1, max −15) and still feed Code Quality. Findings under tests/fixtures-style directories (tests*, test, __tests__, fixtures, spec) are never scored — they are listed as "suppressed (test path)" at 0 weight unless the repo sets include_tests: true in .epyon-ignore.yml. Findings suppressed by approved .epyon-ignore.yml rules are listed as evidence ("suppressed") but carry 0 weight. Known-exploited (CISA KEV) −10 each, max −30. ML layers 14/18/19/20 −25 max each. <em>Caps:</em> leaked secrets → 30, malware → 20, dangerous model files or critical provenance → 40, LLM probe pass rate under 80% → 50.')}
        ${row('Supply Chain (20%)', 'Needs an SBOM (without one in any scan the dimension scores 0). Deducts for end-of-support (−20) and EOL (−5) components, vulnerability density, high/critical findings that already have a fix (−2 each, max −20) and typosquatted models.')}
        ${row('Code Quality (15%)', 'Weighted average of tools that have run: SonarQube gate 40, Checkov IaC pass rate 30, Semgrep SAST 30. Tools that never ran are listed as missing and their weight is redistributed.')}
        ${row('Compliance (15%)', 'Weighted average of STIG (70, pass rate = Not a Finding ÷ applicable controls; Not Applicable controls are excluded from the denominator, Open and Not Reviewed count against; always counted: no STIG assessment scores 0; includes a CAT I penalty and a penalty for “Not a Finding” controls with no written evidence), plus model card (20) and documented APIs (10) when present. No STIG assessment in any scan scores the STIG part 0.')}
        ${row('Operational (10%)', 'Helm chart builds, no non-standard open ports, and the trend against the previous scan (worse −20, better +10). A missing Helm result or earlier scan adds no bonus or penalty.')}
        ${row('MOSA (10%)', 'Modular open systems: standard SBOM, Helm chart, Dockerfile, documented API and open-source license ratio.')}
      </table>
      <h3>Overall score and TRL</h3>
      <p>Never scanned means scored 0: a dimension with no data shows “Not scanned”, scores 0 and keeps its weight. Overall = Σ(dimension score × weight). It maps to a Technology Readiness Level: 90+ → TRL 9, 80+ → 8, 70+ → 7, 60+ → 6, 50+ → 5, 40+ → 4, 30+ → 3, 20+ → 2, otherwise 1. Blockers (critical CVEs, secrets, malware, KEV, STIG under 70%) are listed separately.</p>
      <h3>Evidence</h3>
      <p>Click a dimension to see every line that moved its score: the points, the source file and its SHA-256, and the finding or control IDs behind it. <strong>Evidence package</strong> downloads the score, the source files and a hash manifest; files that changed since scoring are flagged.</p>
      <h3>Sign-off</h3>
      <p>A reviewer can sign off on the current score by name. If a rescore changes any number, the sign-off is shown as no longer matching and must be redone.</p>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
};

window.signOffScorecard = async (btn) => {
  const box = btn.closest('.scorecard-signoff'), msg = box.querySelector('.so-msg');
  const reviewer = box.querySelector('.so-name').value.trim();
  try {
    await poamSend(`/api/scans/${encodeURIComponent(box.dataset.scan)}/scorecard/signoff`, 'PUT',
      { reviewer, comment: box.querySelector('.so-comment').value.trim() });
    await calculateScorecardForScan(box.dataset.scan);
  } catch (e) { msg.textContent = e.message; }
};

window.revokeScorecardSignoff = async (btn) => {
  const box = btn.closest('.scorecard-signoff');
  const r = await fetch(`/api/scans/${encodeURIComponent(box.dataset.scan)}/scorecard/signoff`, { method: 'DELETE' });
  if (r.ok) await calculateScorecardForScan(box.dataset.scan);
};

function flattenScoreDetail(v) {
  if (v == null) return '';
  if (typeof v !== 'object') return String(v);
  return Object.entries(v).map(([k, x]) => `${k.replace(/[-_]/g, ' ')}: ${flattenScoreDetail(x)}`).join(' · ');
}

function showDimensionModal(dimensionKey) {
  const data = window._scorecardDimensions[dimensionKey];
  if (!data) {
    console.error('Dimension data not found:', dimensionKey);
    return;
  }
  
  const { key, label, score, weight, color, details, evidence, applicable } = data;

  const detailsHtml = Object.entries(details).map(([k, v]) => {
    const itemLabel = k.replace(/_/g, ' ');
    let value = v;
    if (typeof v === 'boolean') value = v ? '✓ Yes' : '✗ No';
    else if (typeof v === 'number') value = Number.isInteger(v) ? String(v) : v.toFixed(1);
    else if (v && typeof v === 'object') value = flattenScoreDetail(v);
    return `
      <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border-muted)">
        <span style="color:var(--text-muted);font-size:14px;text-transform:capitalize">${esc(itemLabel)}</span>
        <span style="color:var(--text);font-size:14px;font-weight:600">${esc(String(value))}</span>
      </div>`;
  }).join('');

  const kindLabel = { missing: 'not scanned' };
  const kindColor = { deduction: 'var(--critical)', cap: 'var(--critical)', missing: 'var(--medium)', bonus: 'var(--pass)', component: 'var(--accent)', info: 'var(--text-muted)' };
  const evidenceHtml = (evidence || []).map(e => {
    const impact = e.impact == null ? '' : `<span style="font-weight:700;color:${kindColor[e.kind] || 'inherit'}">${e.kind === 'cap' ? 'cap ' : (e.impact > 0 ? '+' : '')}${esc(String(e.impact))}</span>`;
    const refs = (e.refs || []).length ? `
      <details style="margin-top:4px"><summary style="cursor:pointer;font-size:12px;color:var(--text-muted)">${esc(String(e.refs_total || e.refs.length))} item(s)${e.refs_total > e.refs.length ? ` (first ${e.refs.length} shown)` : ''}</summary>
        <div style="font-size:12px;font-family:monospace;word-break:break-all;margin-top:4px">${e.refs.map(r => esc(r)).join('<br>')}</div></details>` : '';
    const src = e.source ? `<div style="font-size:11px;color:var(--text-dim);font-family:monospace;word-break:break-all">${esc(e.source)}${e.sha256 ? ' · sha256 ' + esc(e.sha256.slice(0, 12)) + '…' : ''}</div>` : '';
    return `
      <div style="padding:10px 0;border-bottom:1px solid var(--border-muted)">
        <div style="display:flex;justify-content:space-between;gap:12px">
          <span style="font-size:13px"><span style="color:${kindColor[e.kind] || 'inherit'};text-transform:uppercase;font-size:11px;margin-right:6px">${esc(kindLabel[e.kind] || e.kind)}</span>${esc(e.label)}</span>${impact}
        </div>
        ${e.note ? `<div style="font-size:12px;color:var(--text-muted)">${esc(e.note)}</div>` : ''}${src}${refs}
      </div>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container modal-lg">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
        <h2 style="color:var(--text);margin:0;display:flex;align-items:center;gap:12px">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
          ${esc(label)} Dimension
        </h2>
        <button class="btn" onclick="this.closest('.modal-overlay').remove()" style="padding:6px 12px">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <div style="background:var(--bg-card);border-radius:var(--radius);padding:24px;margin-bottom:24px;text-align:center;border:2px solid ${color}">
        ${applicable ? `<div style="font-size:64px;font-weight:700;color:${color};margin-bottom:8px">${score}</div>
        <div style="font-size:14px;color:var(--text-muted);margin-bottom:4px">Score out of 100</div>
        <div style="font-size:13px;color:var(--text-muted)">${weight}% of overall score</div>` : `<div style="font-size:28px;font-weight:700;color:var(--text-muted);margin-bottom:8px">Not scanned</div>
        <div style="font-size:13px;color:var(--text-muted)">No scan of this application has produced data for this dimension, so it scores 0 and keeps its weight.</div>`}
        <div style="margin:16px auto 0;max-width:300px;${applicable ? '' : 'display:none'}">
          <div style="height:16px;background:var(--bg);border-radius:8px;overflow:hidden">
            <div style="width:${score}%;height:100%;background:${color};transition:width 0.3s ease"></div>
          </div>
        </div>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px">
        <h3 style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 16px;text-transform:uppercase;letter-spacing:0.5px">Detailed Metrics</h3>
        ${detailsHtml || emptyNote('No detailed metrics available for this dimension.')}
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-top:16px">
        <h3 style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 4px;text-transform:uppercase;letter-spacing:0.5px">Evidence</h3>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Each line shows what moved the score, the artifact it came from and its hash.</div>
        ${evidenceHtml || emptyNote('No evidence recorded. Recalculate the Score Card to generate it.')}
      </div>
    </div>`;
  
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.remove();
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
        <small style="font-size:12px;color:var(--text-dim)">Alphanumeric, hyphens, underscores, and dots only</small>
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
  const workflowYml = WORKFLOW_YML;

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
             padding:12px;font-size:12px;line-height:1.6;overflow-x:auto;margin:0;white-space:pre;color:var(--text)">${workflowYml}</pre>
        <button id="add-app-copy" class="btn btn-sm" style="position:absolute;top:8px;right:8px">Copy</button>
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
    <div class="modal-box modal-md" aria-labelledby="add-app-title">
      ${step1HTML}
      ${step2HTML}
    </div>`;

  function close() {
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

  document.body.appendChild(overlay);
  urlInput.focus();
}





































// ── Scan watcher ─────────────────────────────────────────────
// Scans run on the server whether or not a page is open. This watcher polls
// a lightweight job list on every page so a finished scan is announced with a
// toast (and a desktop notification if the tab is hidden and permission was
// granted), and a badge on the Run Scan link shows how many are in flight.
const scanWatch = (() => {
  const ACTIVE = ['queued', 'running'];
  const known = {};
  let timer = null;
  let inflight = false;
  const baseTitle = document.title;

  function tracked(id) {
    return isScanJobTracked(id);
  }

  function announce(job) {
    const ok = job.status === 'completed';
    const msg = ok
      ? `Scan finished: ${job.target} (${job.scan_type})`
      : `Scan ${job.status}: ${job.target} (${job.scan_type})`;
    toast(msg, ok ? 'success' : 'error');
    if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
      try {
        const n = new Notification('Epyon scan ' + job.status, { body: msg, tag: 'epyon-scan-' + job.job_id });
        n.onclick = () => { window.focus(); navigate('#/applications'); n.close(); };
      } catch (_) {}
    }
  }

  function render(jobs) {
    const running = jobs.filter(j => j.status === 'running').length;
    const queued  = jobs.filter(j => j.status === 'queued').length;
    const badge = document.getElementById('scan-badge');
    if (badge) {
      badge.hidden = running + queued === 0;
      badge.textContent = String(running + queued);
      badge.title = `${running} running, ${queued} queued`;
    }
    document.title = running + queued ? `(${running + queued} scanning) ${baseTitle}` : baseTitle;
  }

  async function tick() {
    inflight = true;
    let delay = 20000;
    try {
      const res = await fetch('/api/jobs?summary=true');
      if (res.ok) {
        const jobs = await res.json();
        for (const j of jobs) {
          const prev = known[j.job_id];
          if (ACTIVE.includes(prev) && !ACTIVE.includes(j.status)) announce(j);
          known[j.job_id] = j.status;
        }
        render(jobs);
        if (jobs.some(j => ACTIVE.includes(j.status))) delay = 4000;
      }
    } catch (_) { /* server restarting or offline — try again later */ }
    inflight = false;
    timer = setTimeout(tick, delay);
  }

  // Re-poll now (e.g. right after a scan is submitted) so a short scan isn't missed.
  function poke() { if (inflight) return; clearTimeout(timer); tick(); }

  return { start: tick, poke };
})();

window.addEventListener('load', () => {
  // In static (offline) mode the scan is embedded — skip API-based routing
  if (window.__SCAN__) return;
  resolve();
  scanWatch.start();
  api._get('/api/health').then(h => {
    const el = document.getElementById('sidebar-version');
    if (el && h.version) el.textContent = 'Epyon v' + h.version;
  }).catch(() => {});
});

// ── Dependency detail drawer ────────────────────────────────────
window.openDependencyDetail = function(did) {
  const p = _depsRegistry.get(did);
  if (!p) return;

  closeFindingDetail();

  const purlUrl = (() => {
    if (!p.purl) return null;
    const m = p.purl.match(/^pkg:([^/]+)\/([^@?#]+)(?:@([^?#]+))?/);
    if (!m) return null;
    const [, eco, pkg] = m;
    const pkgName = pkg.includes('%2F') ? pkg.replace('%2F', '/') : pkg;
    if (eco === 'npm')    return `https://www.npmjs.com/package/${pkgName}`;
    if (eco === 'pypi')   return `https://pypi.org/project/${pkgName}`;
    if (eco === 'gem')    return `https://rubygems.org/gems/${pkgName}`;
    if (eco === 'cargo')  return `https://crates.io/crates/${pkgName}`;
    if (eco === 'maven')  return `https://mvnrepository.com/artifact/${pkgName.replace('%3A', '/')}`;
    if (eco === 'golang') return `https://pkg.go.dev/${pkgName}`;
    if (eco === 'nuget')  return `https://www.nuget.org/packages/${pkgName}`;
    if (eco === 'composer') return `https://packagist.org/packages/${pkgName}`;
    if (eco === 'apk' || eco === 'deb' || eco === 'rpm') return null;
    return null;
  })();

  const purlSection = p.purl ? `
    <div class="finding-detail-section" style="grid-column:1/-1">
      <div class="finding-detail-label">Package URL (PURL)</div>
      <div class="finding-detail-value" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <code style="font-size:12px;word-break:break-all">${esc(p.purl)}</code>
        ${purlUrl ? `<a href="${esc(purlUrl)}" target="_blank" rel="noopener noreferrer"
             style="font-size:12px;white-space:nowrap;color:var(--purple)">
             View registry
             <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:middle">
               <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
               <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
             </svg>
           </a>` : ''}
      </div>
    </div>` : '';

  const pathSection = p.path ? `
    <div class="finding-detail-section" style="grid-column:1/-1">
      <div class="finding-detail-label">File Path</div>
      <div class="finding-detail-value"><code style="word-break:break-all">${esc(p.path)}</code></div>
    </div>` : '';

  const licenseSection = p.license ? `
    <div class="finding-detail-section">
      <div class="finding-detail-label">License</div>
      <div class="finding-detail-value"><code>${esc(p.license)}</code></div>
    </div>` : '';

  const langSection = p.language ? `
    <div class="finding-detail-section">
      <div class="finding-detail-label">Language</div>
      <div class="finding-detail-value"><code>${esc(p.language)}</code></div>
    </div>` : '';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Dependency details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(p.name)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">${esc(p.type)}</span>
          ${p.version ? `<code style="font-size:12px">${esc(p.version)}</code>` : ''}
          ${p.language ? `<span class="tool-tag" style="background:var(--accent-bg);color:var(--accent)">${esc(p.language)}</span>` : ''}
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Name</div>
          <div class="finding-detail-value"><code>${esc(p.name)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Version</div>
          <div class="finding-detail-value">${p.version ? `<code>${esc(p.version)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Type</div>
          <div class="finding-detail-value"><span class="tool-tag" style="font-size:12px">${esc(p.type)}</span></div>
        </div>
        ${langSection}
        ${licenseSection}
      </div>

      ${pathSection}
      ${purlSection}

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

};

// ── STIG Viewer control detail drawer ────────────────────────
// Opened when the user clicks a row in the STIG Viewer (renderStigViewer).
// Uses the shared finding-drawer overlay so Escape / click-outside close it.
function openStigViewerDetail(regKey) {
  const entry = _stigRegistry.get(regKey);
  if (!entry) return;
  closeFindingDetail();

  const { c, scanId } = entry;

  const STATUS_CLASS_MAP = {
    'Open':          'stig-status-open',
    'Not a Finding': 'stig-status-pass',
    'Not Applicable':'stig-status-na',
    'Not Reviewed':  'stig-status-nr',
  };

  const conf    = c.confidence ?? 0;
  const confCls = conf >= 90 ? 'conf-high' : conf >= 70 ? 'conf-med' : conf >= 40 ? 'conf-low' : 'conf-none';
  const confLbl = conf >= 90 ? 'High' : conf >= 70 ? 'Medium' : conf >= 40 ? 'Low' : 'Insufficient';
  const sev     = (c.severity || 'unknown').toLowerCase();
  const statusCls = STATUS_CLASS_MAP[c.status] || 'stig-status-nr';

  const justPrefilled = c.locked_by_human && c.evidence
    ? esc(c.evidence.replace(/^\[Human override\] /, '').split('\n')[0])
    : '';
  const autoJustStatuses = ['Not a Finding', 'Not Applicable'];
  const autoJust = c.title || '';
  const justInitial = justPrefilled || (autoJustStatuses.includes(c.status) ? esc(autoJust) : '');

  const overrideOptions = ['Not a Finding', 'Not Applicable', 'Open', 'Not Reviewed']
    .map(s => `<option value="${esc(s)}"${c.status === s ? ' selected' : ''}>${esc(s)}</option>`).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'STIG control details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id)}</h2>
        <div class="finding-drawer-badges">
          <span class="stig-sev stig-sev-${esc(sev)}">${ucFirst(sev)}</span>
          <span class="${esc(statusCls)}">${esc(c.status)}</span>
          ${c.locked_by_human ? '<span class="stig-lock-badge" title="Manually locked by reviewer">🔒</span>' : ''}
          <code style="font-size:12px">${esc(c.group_id || c.vuln_id)}</code>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Vuln ID</div>
          <div class="finding-detail-value"><code>${esc(c.vuln_id)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Rule ID</div>
          <div class="finding-detail-value"><code>${esc(c.rule_id || '—')}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Group ID</div>
          <div class="finding-detail-value"><code>${esc(c.group_id || '—')}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Confidence</div>
          <div class="finding-detail-value">
            <span class="stig-confidence ${confCls}">${conf}/100</span>
            <span style="margin-left:6px;font-size:12px;color:var(--text-muted)">${confLbl}</span>
          </div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">STIG</div>
          <div class="finding-detail-value" style="font-size:12px;color:var(--text-muted)">${esc(c._stig_name || '—')}</div>
        </div>
      </div>

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Evidence</div>
        <div class="stig-evidence" style="margin-top:6px">${esc(c.evidence || '—').replace(/\n/g, '<br>')}</div>
      </div>

      ${stigRecordHtml(c)}

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Check Content</div>
        <div class="stig-check" style="margin-top:6px">${esc(c.check_content || '—').replace(/\n/g, '<br>')}</div>
      </div>

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Remediation</div>
        <div style="margin-top:6px;font-size:13px;line-height:1.6;color:var(--text)">${esc(c.fix_text || '—').replace(/\n/g, '<br>')}</div>
      </div>

      <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
        <button class="btn btn-primary" onclick="openStigJiraModal('${esc(scanId)}', ['${esc(regKey)}'])">Add to Jira</button>
        <span id="stig-jira-drawer-status" style="margin-left:10px;font-size:12px"></span>
      </div>

      <div class="stig-override-section" style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
        <div class="finding-detail-label" style="margin-bottom:10px">
          Manual Override
          ${c.locked_by_human ? '<span class="stig-lock-badge" style="margin-left:8px">🔒 Locked by reviewer</span>' : ''}
        </div>
        <div class="stig-override-form">
          <div class="stig-override-row">
            <label class="stig-override-label">Status</label>
            <select class="stig-override-select" id="sd-status-${esc(c.vuln_id)}-${esc(c._slug)}"
              data-auto-just="${esc(autoJust)}"
              onchange="stigOverrideStatusChanged(this, 'sd-just-${esc(c.vuln_id)}-${esc(c._slug)}')">
              ${overrideOptions}
            </select>
          </div>
          <div class="stig-override-row">
            <label class="stig-override-label">Justification</label>
            <textarea class="stig-override-textarea" id="sd-just-${esc(c.vuln_id)}-${esc(c._slug)}"
              placeholder="Explain why this control is met (required)" rows="3">${justInitial}</textarea>
          </div>
          <div class="stig-override-row stig-override-actions">
            <button class="btn btn-sm btn-success"
              onclick="saveStigOverrideFromDrawer('${esc(scanId)}','${esc(c._slug)}','${esc(c.vuln_id)}')"
            >🔒 Lock Override</button>
            ${c.locked_by_human
              ? `<button class="btn btn-sm"
                  onclick="clearStigOverrideFromDrawer('${esc(scanId)}','${esc(c._slug)}','${esc(c.vuln_id)}')"
                >Clear Lock</button>`
              : ''}
            <span class="stig-override-msg" id="sd-msg-${esc(c.vuln_id)}-${esc(c._slug)}"></span>
          </div>
        </div>
      </div>

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

// "Not Reviewed" is stored as-is (kept separate from N/A) but shown as
// "Evidence needed": the control is open until evidence is supplied.
function stigStatusLabel(status) {
  return status === 'Not Reviewed' ? 'Evidence needed' : (status || '');
}

function stigRecordHtml(c) {
  const rows = Array.isArray(c.changes_that_may_affect) ? c.changes_that_may_affect : [];
  const auto = c.automation_recommendation;
  const notes = [];
  if (c.evidence_needed) notes.push(['Evidence needed', c.evidence_needed]);
  if (c.verification_note) notes.push(['Verification', c.verification_note]);
  if (c.reopened_reason) notes.push(['Re-opened', c.reopened_reason]);
  if (c.downgraded_from) notes.push(['Downgraded from', c.downgraded_from]);
  if (c.needs_owner_confirmation) notes.push(['Owner', 'Needs owner confirmation']);
  (c.citation_failures || []).forEach(f => notes.push(['Citation failed', f]));
  if (!rows.length && !auto && !notes.length) return '';
  const noteHtml = notes.map(([k, v]) =>
    `<div style="font-size:13px;margin-top:4px"><strong>${esc(k)}:</strong> ${esc(v)}</div>`).join('');
  const tableHtml = rows.length ? `
    <table class="stig-table" style="margin-top:6px">
      <thead><tr><th scope="col">Change</th><th scope="col">Where</th><th scope="col">Re-check</th></tr></thead>
      <tbody>${rows.map(r => `<tr><td>${esc(r.change)}</td><td>${esc(r.where)}</td><td>${esc(r.recheck)}</td></tr>`).join('')}</tbody>
    </table>` : '';
  const autoHtml = auto ? `
    <div style="margin-top:8px;font-size:13px">
      <strong>Automation:</strong> ${esc(auto.check || '—')}
      ${auto.data_source ? `<div>Data source: ${esc(auto.data_source)}</div>` : ''}
      ${auto.pass_fail_rule ? `<div>Pass/fail: ${esc(auto.pass_fail_rule)}</div>` : ''}
      ${auto.where_it_runs ? `<div>Runs in: ${esc(auto.where_it_runs)}</div>` : ''}
    </div>` : '';
  return `
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Review Record</div>
        ${noteHtml}${rows.length ? '<div class="finding-detail-label" style="margin-top:10px">Changes that may affect this control</div>' : ''}${tableHtml}${autoHtml}
      </div>`;
}

function closeStigDetail() {
  closeFindingDetail();
}

// Auto-fill the justification with the control's requirement for Not a Finding /
// Not Applicable, without clobbering text the reviewer typed.
window.stigOverrideStatusChanged = (sel, justId) => {
  const just = document.getElementById(justId);
  if (!just) return;
  const auto = sel.dataset.autoJust || '';
  const val = just.value.trim();
  if (val && val !== auto) return;
  just.value = ['Not a Finding', 'Not Applicable'].includes(sel.value) ? auto : '';
};

window.saveStigOverrideFromDrawer = async (sid, slug, vulnId) => {
  const statusEl = document.getElementById(`sd-status-${vulnId}-${slug}`);
  const justEl   = document.getElementById(`sd-just-${vulnId}-${slug}`);
  const msgEl    = document.getElementById(`sd-msg-${vulnId}-${slug}`);
  if (!statusEl || !justEl || !msgEl) return;
  const justification = justEl.value.trim();
  if (!justification) {
    msgEl.textContent = 'Justification is required.';
    msgEl.className = 'stig-override-msg stig-override-err';
    return;
  }
  msgEl.textContent = 'Saving…';
  msgEl.className = 'stig-override-msg';
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(sid)}/stig-override`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, vuln_id: vulnId, status: statusEl.value, justification }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    msgEl.textContent = '✓ Locked';
    msgEl.className = 'stig-override-msg stig-override-ok';
    const newStatus = statusEl.value;
    setTimeout(() => {
      closeFindingDetail();
      const patch = { status: newStatus, confidence: 95, locked_by_human: true, evidence: `[Human override] ${justification}\n` };
      if (!window.updateStigControlInPlace?.(slug, vulnId, patch)) renderStigViewer(sid);
    }, 800);
  } catch (e) {
    msgEl.textContent = `Error: ${e.message}`;
    msgEl.className = 'stig-override-msg stig-override-err';
  }
};

window.clearStigOverrideFromDrawer = async (sid, slug, vulnId) => {
  const msgEl = document.getElementById(`sd-msg-${vulnId}-${slug}`);
  if (msgEl) { msgEl.textContent = 'Clearing…'; msgEl.className = 'stig-override-msg'; }
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(sid)}/stig-override`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, vuln_id: vulnId, status: 'Open', justification: '', clear_lock: true }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    if (msgEl) { msgEl.textContent = '✓ Lock cleared'; msgEl.className = 'stig-override-msg stig-override-ok'; }
    setTimeout(() => {
      closeFindingDetail();
      const patch = { status: 'Open', confidence: 0, locked_by_human: false, evidence: '' };
      if (!window.updateStigControlInPlace?.(slug, vulnId, patch)) renderStigViewer(sid);
    }, 800);
  } catch (e) {
    if (msgEl) { msgEl.textContent = `Error: ${e.message}`; msgEl.className = 'stig-override-msg stig-override-err'; }
  }
};

// ── STIG control detail drawer (History view) ────────────────
let _stigDetailNextId = 0;
const _stigDetailRegistry = new Map();

function _registerStigDetail(c) {
  const id = _stigDetailNextId++;
  _stigDetailRegistry.set(id, c);
  return id;
}

function openStigDetail(id) {
  const c = _stigDetailRegistry.get(id);
  if (!c) return;
  closeFindingDetail();

  const _SC = { 'Open': 'open', 'Not a Finding': 'not-a-finding', 'Not Applicable': 'na', 'Not Reviewed': 'not-reviewed' };
  const _SA = { 'Open': 'Open', 'Not a Finding': 'Pass', 'Not Applicable': 'N/A', 'Not Reviewed': 'Evid.' };

  const sev     = c.severity || 'unknown';
  const sevCls  = sev.toLowerCase();
  const latCls  = _SC[c.latest_status] || 'not-reviewed';
  const latLbl  = _SA[c.latest_status] || c.latest_status || '—';

  const tl = [...(c.timeline || [])].sort((a, b) => b.date.localeCompare(a.date));
  const timelineRows = tl.map((t, idx) => {
    const cls = _SC[t.status] || 'not-reviewed';
    const lbl = _SA[t.status] || t.status;
    const evidence = t.evidence || 'No evidence provided.';
    const confidence = t.confidence != null ? `${t.confidence}%` : '—';
    
    // Check if evidence changed from previous scan (next in array = older in time)
    const prevEvidence = idx < tl.length - 1 ? (tl[idx + 1].evidence || '') : '';
    const evidenceChanged = prevEvidence && evidence && prevEvidence !== evidence && t.status !== 'Not Reviewed';
    const changeClass = evidenceChanged ? ' style="background:var(--bg-hover)"' : '';
    const changeIcon = evidenceChanged ? ' <span style="color:var(--accent);font-size:12px" title="Evidence changed from previous scan">🔄 Changed</span>' : '';
    
    return `<tr${changeClass}>
      <td style="padding:8px 12px;font-size:12px;color:var(--text-muted);white-space:nowrap;vertical-align:top">${esc(t.date.slice(0, 10))}</td>
      <td style="padding:8px 12px;vertical-align:top"><span class="stig-status-chip ${cls}">${esc(lbl)}</span>${changeIcon}</td>
      <td style="padding:8px 12px;font-size:12px;color:var(--text-muted);text-align:center;vertical-align:top">${confidence}</td>
      <td style="padding:8px 12px;font-size:12px;color:var(--text);line-height:1.5;vertical-align:top">${esc(evidence).replace(/\n/g, '<br>')}</td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'STIG control details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id || '—')}</h2>
        <div class="finding-drawer-badges">
          <span class="sev-badge ${esc(sevCls)}">${ucFirst(sev)}</span>
          <span class="tool-tag">STIG</span>
          <code>${esc(c.vuln_id)}</code>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Current Status</div>
          <div class="finding-detail-value"><span class="stig-status-chip ${latCls}">${esc(latLbl)}</span></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Benchmark</div>
          <div class="finding-detail-value">${c.stig_name ? `<code style="font-size:12px">${esc(c.stig_name)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Open</div>
          <div class="finding-detail-value">${c.first_open ? esc(c.first_open.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Closed</div>
          <div class="finding-detail-value">${c.first_closed ? esc(c.first_closed.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">MTTR</div>
          <div class="finding-detail-value">${c.mttr_days != null ? `<strong>${c.mttr_days} days</strong>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
      </div>
      ${tl.length ? `
      <div class="finding-detail-section">
        <div class="finding-detail-label">Scan History</div>
        <div class="finding-detail-desc" style="padding:0;background:none;border:1px solid var(--border-muted);border-radius:var(--radius);overflow:hidden">
          <table style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="background:var(--bg-hover);border-bottom:1px solid var(--border)">
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:100px">Date</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:140px">Status</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:center;width:80px">Confidence</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left">Evidence / Reasoning</th>
              </tr>
            </thead>
            <tbody>${timelineRows}</tbody>
          </table>
        </div>
      </div>` : ''}
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

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
  const target  = f.target || f.file || '';
  const line    = f.line ? (Array.isArray(f.line) && f.line.length === 2 ? (f.line[0] === f.line[1] ? String(f.line[0]) : `${f.line[0]}-${f.line[1]}`) : String(f.line)) : '';
  const refs    = f.references || [];
  const cisaKev  = f.cisa_kev === true;
  const cvssScore = f.nvd_cvss_v3_score != null ? f.nvd_cvss_v3_score : null;
  const cvssSev   = f.nvd_cvss_v3_severity || '';
  const nvdUrl    = f.nvd_url || (fid.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${fid}` : '');
  const cveSource = f.cve_source || '';

  // CVE source badge
  const sourceIcons = {
    'GHSA': { icon: '🛡️', label: 'GitHub Advisory', color: '#6e40aa' },
    'NVD': { icon: '🏛️', label: 'NIST NVD', color: '#1e40af' },
    'OSV': { icon: '🔓', label: 'OSV', color: '#059669' },
    'Alpine': { icon: '🏔️', label: 'Alpine SecDB', color: '#0d9488' },
    'Debian': { icon: '🌀', label: 'Debian Security', color: '#a90e3c' },
    'Ubuntu': { icon: '🟠', label: 'Ubuntu Security', color: '#e95420' },
    'RHEL': { icon: '🎩', label: 'Red Hat', color: '#cc0000' },
    'Trivy': { icon: '🔍', label: 'Trivy DB', color: '#1f2937' },
    'Grype': { icon: '🦑', label: 'Grype DB', color: '#475569' },
  };
  
  const sourceInfo = sourceIcons[cveSource] || null;
  const sourceBadge = sourceInfo
    ? `<span style="display:inline-flex;align-items:center;gap:4px;background:${sourceInfo.color};color:#fff;font-size:12px;font-weight:600;padding:2px 6px;border-radius:3px;margin-left:6px" title="Source: ${sourceInfo.label}">
         ${sourceInfo.icon} ${cveSource}
       </span>`
    : '';

  const idDisplay = fid.startsWith('CVE-')
    ? `<a class="finding-detail-id-link"
          href="${esc(nvdUrl || 'https://nvd.nist.gov/vuln/detail/' + esc(fid))}"
          target="_blank" rel="noopener noreferrer">
         ${esc(fid)}
         <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
           <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
           <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
         </svg>
       </a>${cisaKev ? ' <span style="background:var(--critical-bg);color:var(--critical);font-size:12px;font-weight:700;padding:2px 7px;border-radius:4px" title="CISA Known Exploited Vulnerability">KEV</span>' : ''}${sourceBadge}`
    : `<code>${esc(fid)}</code>${sourceBadge}`;

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
          <div class="finding-detail-value"><span class="sev-badge ${esc(sev)}">${ucFirst(sev)}</span>${cvssScore != null ? ` <span style="color:var(--text-muted);font-size:12px">CVSS ${esc(String(cvssScore))}${cvssSev ? ' · ' + esc(cvssSev) : ''}</span>` : ''}</div>
        </div>
      </div>

      ${cisaKev ? `
        <div style="background:var(--critical-bg);border:1px solid var(--critical-bg);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px">
          <span style="font-size:16px">⚠️</span>
          <div>
            <div style="color:var(--critical);font-weight:600;font-size:13px">CISA Known Exploited Vulnerability (KEV)</div>
            <div style="color:var(--critical);font-size:12px;margin-top:2px">This CVE is actively exploited in the wild. CISA mandates remediation for federal agencies. Treat as highest priority.</div>
          </div>
        </div>` : ''}

      ${target ? `
        <div class="finding-detail-section">
          <div class="finding-detail-label">${findingSource(f) === 'container' ? 'Container Image' : 'File Path'}</div>
          <div class="finding-detail-value"><code style="word-break:break-all">${esc(target)}</code>${line ? ` <span style="color:var(--text-muted);font-size:12px">line ${esc(line)}</span>` : ''}</div>
        </div>` : ''}

      ${descSection}

      ${refsHtml}

      ${(_scanIdFromHash() && !window.__SCAN__) ? `
      <div id="finding-jira-section" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
        <button id="finding-jira-btn" class="btn btn-primary" onclick="jiraQuickAdd(${id})">Add to Jira</button>
        <div id="finding-jira-status" style="font-size:12px;margin-top:8px"></div>
      </div>` : ''}

      <div id="finding-fix-section" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
        <button id="finding-fix-btn" class="btn btn-ai" onclick="fetchFindingFix(${id})">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          Suggest Fix with AI
        </button>
        <div id="finding-fix-result"></div>
      </div>

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

function closeFindingDetail() {
  const overlay = document.getElementById('finding-drawer-overlay');
  const drawer  = document.getElementById('finding-drawer');
  overlay?.remove();
  drawer?.remove();
}

// ── GitHub Signals detail drawer ──────────────────────────────
function openGhSignalDetail(kind, idx) {
  if (!window._ghSignalData) return;
  closeGhSignalDetail();

  let title = '', bodyHtml = '', repoUrl = '';

  if (kind === 'run') {
    const r = window._ghSignalData.run[idx];
    if (!r) return;
    const repoShort = r.repo.split('/')[1] || r.repo;
    repoUrl = `https://github.com/${r.repo}/actions`;
    title = `Workflow Runs — ${repoShort}`;
    const rate = r.success_rate != null ? r.success_rate : null;
    const rateColor = rate == null ? 'var(--text-muted)' : rate >= 90 ? 'var(--clean)' : rate >= 70 ? '#e3b341' : 'var(--critical)';
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Repository</div>
          <div class="finding-detail-value"><code>${esc(r.repo)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Success Rate (30d)</div>
          <div class="finding-detail-value" style="color:${rateColor};font-weight:700;font-size:22px">${rate != null ? rate + '%' : '—'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Total Runs</div>
          <div class="finding-detail-value">${r.total_runs || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">In Progress / Queued</div>
          <div class="finding-detail-value">${r.in_progress || 0}</div>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Run Breakdown</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(63,185,80,.15);color:var(--clean);padding:4px 10px;border-radius:6px;font-weight:700">✓ Success: ${r.success||0}</span>
          <span style="background:rgba(248,81,73,.15);color:var(--critical);padding:4px 10px;border-radius:6px;font-weight:700">✗ Failed: ${r.failed||0}</span>
          <span style="background:rgba(139,148,158,.15);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">⊘ Skipped: ${r.skipped||0}</span>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <a href="${esc(repoUrl)}" target="_blank" rel="noopener noreferrer"
           style="display:inline-flex;align-items:center;gap:6px;color:var(--accent);font-size:13px;text-decoration:none">
          View Actions on GitHub
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
      </div>`;

  } else if (kind === 'cov') {
    const [name, v] = window._ghSignalData.cov[idx] || [];
    if (!name) return;
    title = `PR Scan Coverage — ${esc(name)}`;
    const pct = v.pr_coverage_pct;
    const barColor = pct >= 70 ? 'var(--clean)' : pct >= 40 ? '#e3b341' : 'var(--critical)';
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Application</div>
          <div class="finding-detail-value"><strong>${esc(name)}</strong></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">PR Scan Coverage</div>
          <div class="finding-detail-value" style="color:${barColor};font-weight:700;font-size:22px">${pct}%</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">PR-Triggered Scans</div>
          <div class="finding-detail-value">${v.pr_scans}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Total CI Scans</div>
          <div class="finding-detail-value">${v.total_ci_scans}</div>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Coverage Bar</div>
        <div style="display:flex;align-items:center;gap:10px;margin-top:8px">
          <div style="flex:1;background:var(--border);border-radius:6px;height:12px;overflow:hidden">
            <div style="width:${Math.min(pct,100)}%;background:${barColor};height:100%;border-radius:6px;transition:width .3s"></div>
          </div>
          <span style="font-weight:700;color:${barColor}">${pct}%</span>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Scan Breakdown</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(121,192,255,.12);color:var(--accent);padding:4px 10px;border-radius:6px;font-weight:700">PR: ${v.pr_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Push: ${v.push_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Other: ${v.other_scans}</span>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <button class="btn btn-ai" onclick="closeGhSignalDetail();navigate('#/applications/${encodeURIComponent(name)}')">
          View Application Scans
        </button>
      </div>`;
  }

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'gh-signal-drawer-overlay';
  overlay.addEventListener('click', closeGhSignalDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'gh-signal-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', title);
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${title}</h2>
      </div>
      <button class="finding-drawer-close" onclick="closeGhSignalDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">${bodyHtml}</div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

function closeGhSignalDetail() {
  const overlay = document.getElementById('gh-signal-drawer-overlay');
  const drawer  = document.getElementById('gh-signal-drawer');
  overlay?.remove();
  drawer?.remove();
}

// ── API endpoint detail drawer ────────────────────────────────
function openAPIDetail(id) {
  const ep = _apiRegistry.get(id);
  if (!ep) return;

  // Close any existing drawer
  closeAPIDetail();

  const method     = ep.method || 'UNKNOWN';
  const path       = ep.path || '—';
  const funcName   = ep.function || '—';
  const name       = ep.name || '—';
  const framework  = ep.framework || 'Unknown';
  const auth       = ep.auth || 'None';
  const tags       = ep.tags || '';
  const file       = ep.file || '—';
  const description = ep.description || '';
  const params     = ep.parameters || ep.params || [];
  const responses  = ep.responses || [];

  const methodColor = {
    'GET': '#10b981',
    'POST': '#f59e0b',
    'PUT': '#3b82f6',
    'DELETE': '#ef4444',
    'PATCH': '#8b5cf6'
  }[method] || '#6b7280';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'api-drawer-overlay';
  overlay.addEventListener('click', closeAPIDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'api-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'API endpoint details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2 style="font-family:monospace;font-size:16px">${esc(path)}</h2>
        <div class="finding-drawer-badges">
          <span style="background:${methodColor};color:white;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600">${esc(method)}</span>
          <span class="tool-tag">${esc(framework)}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeAPIDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Function</div>
          <div class="finding-detail-value"><code>${esc(funcName)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Name</div>
          <div class="finding-detail-value">${name !== '—' ? esc(name) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Framework</div>
          <div class="finding-detail-value"><span class="tool-tag">${esc(framework)}</span></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Authentication</div>
          <div class="finding-detail-value">${auth !== 'None' ? `<code style="font-size:12px">${esc(auth)}</code>` : '<span style="color:var(--text-dim)">None</span>'}</div>
        </div>
      </div>

      ${description ? `
        <div class="finding-detail-section" style="margin-top:12px">
          <div class="finding-detail-label">Description</div>
          <div class="finding-detail-desc">${esc(description)}</div>
        </div>` : ''}

      ${tags ? `
        <div class="finding-detail-section" style="margin-top:12px">
          <div class="finding-detail-label">Tags</div>
          <div class="finding-detail-value">${esc(tags)}</div>
        </div>` : ''}

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">File Location</div>
        <div class="finding-detail-value"><code style="font-size:12px;word-break:break-all">${esc(file)}</code></div>
      </div>

      ${Array.isArray(params) && params.length > 0 ? `
        <div class="finding-detail-section" style="margin-top:16px">
          <div class="finding-detail-label">Parameters</div>
          <div style="margin-top:6px">
            ${params.map(p => `
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                  <code style="color:var(--purple);font-size:12px">${esc(p.name || '')}</code>
                  ${p.required ? '<span style="color:var(--critical);font-size:12px;font-weight:600">REQUIRED</span>' : ''}
                </div>
                ${p.type ? `<div style="color:var(--text-muted);font-size:12px">Type: <code>${esc(p.type)}</code></div>` : ''}
                ${p.description ? `<div style="color:var(--text-dim);font-size:12px;margin-top:3px">${esc(p.description)}</div>` : ''}
              </div>
            `).join('')}
          </div>
        </div>` : ''}

      ${Array.isArray(responses) && responses.length > 0 ? `
        <div class="finding-detail-section" style="margin-top:16px">
          <div class="finding-detail-label">Responses</div>
          <div style="margin-top:6px">
            ${responses.map(r => `
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                  <code style="color:var(--pass);font-size:12px">${esc(String(r.status || r.code || ''))}</code>
                  <span style="color:var(--text-muted);font-size:12px">${esc(r.description || '')}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>` : ''}

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

function closeAPIDetail() {
  const overlay = document.getElementById('api-drawer-overlay');
  const drawer  = document.getElementById('api-drawer');
  overlay?.remove();
  drawer?.remove();
}

// ── AI fix suggestion ─────────────────────────────────────────
window.fetchFindingFix = async function(fid) {
  const f = _findingsRegistry.get(fid);
  if (!f) return;

  const btn    = document.getElementById('finding-fix-btn');
  const result = document.getElementById('finding-fix-result');
  if (!btn || !result) return;

  btn.disabled = true;
  btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-.08-4.04"/></svg> Generating…`;

  const payload = {
    id:            f.id || undefined,
    title:         f.title || f.description || undefined,
    description:   f.description !== f.title ? f.description : undefined,
    tool:          f.tool || undefined,
    severity:      f.severity || undefined,
    package:       f.package || f.component || undefined,
    version:       f.version || undefined,
    fixed_version: f.fixed_version || undefined,
    target:        f.target || undefined,
    references:    (f.references || []).slice(0, 3),
  };
  // strip undefined
  Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

  try {
    const data = await api.getFindingFix(payload);
    btn.style.display = 'none';
    result.innerHTML = `
      <div style="margin-top:12px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.25);border-radius:var(--radius);padding:14px 16px;font-size:13px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;color:var(--purple);font-size:12px;font-weight:600">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          AI-SUGGESTED FIX
        </div>
        <div class="ai-fix-body">${renderMarkdown(data.fix || '')}</div>
      </div>`;
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Suggest Fix with AI`;
    result.innerHTML = `<div style="margin-top:8px;color:var(--critical);font-size:12px">${esc(err.message)}</div>`;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// STATIC RENDER MODE
// When the page is a self-contained HTML file (generated by generate-dashboard.py),
// window.__SCAN__ is set to the full scan data object. We render the scan detail
// page directly without any API calls or navigation.
// ─────────────────────────────────────────────────────────────────────────────

function renderStaticScanDetail(scan) {
  const page = document.getElementById('page');
  if (!page) return;

  const status  = computeStatus(scan);
  const scanId  = scan.scan_id || '';

  // ── STIG card (same logic as renderScanDetail, minus navigate() buttons) ──
  const hasStigData    = (scan.stig_total || 0) > 0;
  const scanTypeHasStig = ['stig', 'nightly', 'full', 'baseline'].includes(scan.scan_type);
  let stigCard = '';
  if (hasStigData) {
    const reports  = scan.stig_reports || [];
    const multiStig = reports.length > 1;

      const perStigRows = multiStig ? reports.map(r => {
      const slugLabel = r.slug.replace(/-/g, ' ').replace(/\bstig\b/gi, 'STIG');
      return `
        <div class="stig-row">
          <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
          <span class="stig-row-counts">
            <span class="stig-mini open">${esc(r.open)} open</span>
            <span class="stig-mini pass">${esc(r.pass)} pass</span>
            <span class="stig-mini na">${esc(r.na)} n/a</span>
            ${(r.nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(r.nr)} evidence needed</span>` : ''}
            <span class="stig-mini total">${esc(r.total)} total</span>
          </span>
        </div>`;
    }).join('') : '';

    stigCard = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:var(--accent)">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                STIG Assessment${multiStig ? ` <span style="color:var(--text-muted);font-weight:400;font-size:12px">(${reports.length} STIGs)</span>` : ''}
              </span>
              <span class="stig-mini open">${esc(scan.stig_open || 0)} open</span>
              <span class="stig-mini pass">${esc(scan.stig_pass || 0)} pass</span>
              <span class="stig-mini na">${esc(scan.stig_na || 0)} n/a</span>
              ${(scan.stig_nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(scan.stig_nr || 0)} evidence needed</span>` : ''}
              <span class="stig-mini total">${esc(scan.stig_total || 0)} total</span>
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body" style="padding:0 18px 16px">
            <div class="stig-counts" style="margin-top:12px">
              <div class="stig-count open"><span class="num">${esc(scan.stig_open  || 0)}</span><span class="lbl">Open</span></div>
              <div class="stig-count pass"><span class="num">${esc(scan.stig_pass  || 0)}</span><span class="lbl">Not a Finding</span></div>
              <div class="stig-count na"  ><span class="num">${esc(scan.stig_na    || 0)}</span><span class="lbl">Not Applicable</span></div>
              ${(scan.stig_nr || 0) > 0 ? `<div class="stig-count" style="background:var(--bg-input);border-color:var(--border)"><span class="num" style="color:var(--text-muted)">${esc(scan.stig_nr || 0)}</span><span class="lbl">Evidence needed</span></div>` : ''}
              <div class="stig-count total"><span class="num">${esc(scan.stig_total|| 0)}</span><span class="lbl">Total</span></div>
            </div>
            ${multiStig ? `<div class="stig-per-stig">${perStigRows}</div>` : ''}
          </div>
        </details>
      </div>`;
  } else {
    const noStigMsg = scanTypeHasStig
      ? 'No STIG results were recorded for this scan.'
      : 'STIG assessment is not included in this scan type.';
    stigCard = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:var(--border)">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                STIG Assessment
              </span>
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body" style="padding:12px 18px 16px">
            <p style="color:var(--text-muted);font-size:13px;margin:0">${noStigMsg}</p>
          </div>
        </details>
      </div>`;
  }

  // ── CI source badge ────────────────────────────────────────────────────────
  const ci = scan.ci_source;
  const ciBadge = ci ? `
    <div class="stat-card">
      <div class="stat-label">CI Source</div>
      <div class="stat-value" style="font-size:12px">
        ${ci.repo ? `<a href="https://github.com/${esc(ci.repo)}" target="_blank" rel="noopener"
            style="color:var(--accent)">${esc(ci.repo)}</a>` : '—'}
        ${ci.branch ? `<span style="color:var(--text-muted)"> @ ${esc(ci.branch)}</span>` : ''}
      </div>
    </div>` : '';

  page.innerHTML = `
    <div class="breadcrumb">
      <span>${esc(scan.target || '—')}</span>
      <span>›</span>
      <span>${esc(scanId)}</span>
    </div>

    ${pageHeader(`Scan Details ${statusBadge(status)}`, { subtitle: `Findings, compliance, and evidence collected for <strong>${esc(scan.target || '—')}</strong> on ${fmtDate(scan.timestamp)}.` })}

    <div class="stats-grid" style="margin-bottom:24px">
      <div class="stat-card">
        <div class="stat-label">Application</div>
        <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.target || '—')}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Scan Type</div>
        <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scanTypeLabel(scan.scan_type))}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">User</div>
        <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.user || '—')}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Timestamp</div>
        <div class="stat-value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
      </div>
      ${ciBadge}
    </div>

    <div class="result-section-box">
      <div class="result-section-box-title">Vulnerabilities</div>
      <div class="stats-grid" style="margin-bottom:0">
        <div class="stat-card critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value">${esc(scan.critical)}</div>
        </div>
        <div class="stat-card high">
          <div class="stat-label">High</div>
          <div class="stat-value">${esc(scan.high)}</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-label">Medium</div>
          <div class="stat-value">${esc(scan.medium)}</div>
        </div>
        <div class="stat-card low">
          <div class="stat-label">Low</div>
          <div class="stat-value">${esc(scan.low)}</div>
        </div>
      </div>
    </div>

    ${buildFindingsSection(scan.findings)}

    ${buildSuppressedSection(scan.suppressed_findings)}

    ${stigCard}

    ${buildModelSecurityCard(scan)}

    ${buildMisconfigurationsCard(scan)}

    ${buildBuildEvidenceCard(scan)}

    ${buildSSPEvidenceCard(scan)}

    ${buildSBOMSection(scan.sbom, null)}

    ${buildAPISection(scan.api_discovery)}

    ${buildNetworkDiscoveryCard(scan)}

    ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
      <div class="result-section-box">
        <div class="result-section-box-title">File Statistics</div>
        <div class="stats-grid" style="margin-bottom:0">
          ${Object.entries(scan.file_statistics).map(([k, v]) => `
            <div class="stat-card">
              <div class="stat-label">${esc(k.replace(/_/g, ' '))}</div>
              <div class="stat-value" style="font-size:20px">${esc(v)}</div>
            </div>`).join('')}
        </div>
      </div>` : ''}

    <div id="scorecard-container">${scan.scorecard ? buildScorecardCard(scan.scorecard) : ''}</div>

    ${dedupeTools(scan.tools_analyzed || []).length ? `
      <div class="result-section-box">
        <div class="result-section-box-title">Tools Analyzed</div>
        <div class="tools-list">
          ${dedupeTools(scan.tools_analyzed).map(t =>
            `<span class="tool-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>` : ''}`;
  if (window._sbomPendingUid) { sbomRender(window._sbomPendingUid); window._sbomPendingUid = null; }
  if (window._apiPendingUid)  { apiRender(window._apiPendingUid);   window._apiPendingUid  = null; }
}

// ── Shared modal / drawer behaviour ──────────────────────────
// Every `.modal-overlay` and `.finding-drawer` added to the page gets
// role=dialog, aria-modal, Escape to close, a Tab focus trap, and focus
// returned to the element that opened it.
const _overlayStack = [];
let _lastOutsideFocus = null;
const _FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

function _overlayFocusables(dialog) {
  return [...dialog.querySelectorAll(_FOCUSABLE)].filter(el => el.offsetParent !== null);
}

function _registerOverlay(overlay, dialog) {
  if (!dialog || _overlayStack.some(o => o.overlay === overlay)) return;
  dialog.setAttribute('role', 'dialog');
  dialog.setAttribute('aria-modal', 'true');
  if (!dialog.hasAttribute('aria-labelledby') && !dialog.hasAttribute('aria-label')) {
    const heading = dialog.querySelector('h1,h2,h3');
    if (heading) dialog.setAttribute('aria-label', heading.textContent.trim());
  }
  dialog.setAttribute('tabindex', '-1');
  _overlayStack.push({ overlay, dialog, trigger: _lastOutsideFocus });
  (_overlayFocusables(dialog)[0] || dialog).focus({ preventScroll: true });
}

function _closeTopOverlay() {
  const top = _overlayStack[_overlayStack.length - 1];
  if (!top) return;
  // Click runs the overlay's own close handler (drawers clean up state there).
  top.overlay.click();
  if (top.overlay.isConnected) { top.overlay.remove(); top.dialog.remove(); }
}

function _scanOverlays(root) {
  if (root.nodeType !== 1) return;
  if (root.matches('.modal-overlay')) _registerOverlay(root, root.firstElementChild);
  else if (root.matches('.finding-drawer')) _registerOverlay(root.previousElementSibling?.classList.contains('finding-drawer-overlay') ? root.previousElementSibling : root, root);
  else root.querySelectorAll?.('.modal-overlay,.finding-drawer').forEach(_scanOverlays);
}

function _releaseOverlays() {
  while (_overlayStack.length) {
    const top = _overlayStack[_overlayStack.length - 1];
    if (top.dialog.isConnected && top.overlay.isConnected) return;
    _overlayStack.pop();
    if (top.trigger && top.trigger.isConnected && !document.querySelector('.modal-overlay,.finding-drawer')) {
      top.trigger.focus({ preventScroll: true });
    }
  }
}

if (typeof document !== 'undefined' && !window.__overlayA11y) {
  window.__overlayA11y = true;
  document.addEventListener('focusin', e => {
    if (!e.target.closest?.('.modal-overlay,.finding-drawer')) _lastOutsideFocus = e.target;
  });
  new MutationObserver(muts => {
    muts.forEach(m => m.addedNodes.forEach(_scanOverlays));
    _releaseOverlays();
  }).observe(document.body, { childList: true });

  document.addEventListener('keydown', e => {
    const top = _overlayStack[_overlayStack.length - 1];
    if (!top) return;
    if (e.key === 'Escape') { e.preventDefault(); _closeTopOverlay(); return; }
    if (e.key !== 'Tab') return;
    const items = _overlayFocusables(top.dialog);
    if (!items.length) { e.preventDefault(); top.dialog.focus(); return; }
    const first = items[0], last = items[items.length - 1];
    if (!top.dialog.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}

// ── Keyboard access for click-only elements ──────────────────
// Elements wired with onclick on non-interactive tags (rows, cards, spans)
// become focusable and respond to Enter / Space like a button.
const _NATIVE_INTERACTIVE = 'button,input,select,textarea,summary,a[href]';

function _makeKeyboardClickable(root) {
  if (root.nodeType !== 1) return;
  const els = root.matches('[onclick]') ? [root] : [];
  root.querySelectorAll?.('[onclick]').forEach(el => els.push(el));
  els.forEach(el => {
    if (el.matches(_NATIVE_INTERACTIVE) || el.hasAttribute('tabindex')) return;
    el.setAttribute('tabindex', '0');
    if (!el.hasAttribute('role') && !['TR', 'TD', 'TH'].includes(el.tagName)) el.setAttribute('role', 'button');
  });
}

if (typeof document !== 'undefined' && !window.__keyboardClickable) {
  window.__keyboardClickable = true;
  _makeKeyboardClickable(document.body);
  new MutationObserver(muts => muts.forEach(m => m.addedNodes.forEach(_makeKeyboardClickable)))
    .observe(document.body, { childList: true, subtree: true });

  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target;
    if (!el || el !== document.activeElement || !el.matches?.('[onclick][tabindex]') || el.matches(_NATIVE_INTERACTIVE)) return;
    e.preventDefault();
    el.click();
  });
}

// Static entry point — runs when this JS is embedded in a generated dashboard
if (typeof window !== 'undefined' && window.__SCAN__) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      renderStaticScanDetail(window.__SCAN__);
    });
  } else {
    renderStaticScanDetail(window.__SCAN__);
  }
}
