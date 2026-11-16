/* ============================================================
   Epyon Web Interface — app.js
   Vanilla JS single-page application
   ============================================================ */

'use strict';



// ── Dependency detail registry (populated in sbomRender) ──────

// ── API endpoint detail registry (populated in apiRender) ─────

// ── GitHub Signals detail (populated in buildCiHealthSection) ──
// window._ghSignalData is set by pages/performance.js


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
  _resetFindingsRegistry();
  _stigRegistry.clear();
  resetFindingsViewState();
  closeFindingDetail();
  closeStigDetail();
}

// ── Views ─────────────────────────────────────────────────────



















// ─────────────────────────────────────────────────────────────


// ─────────────────────────────────────────────────────────────














// ─────────────────────────────────────────────────────────────

















// ── Misconfigurations Card (Checkov IaC findings) ─────────────


// ── Container Build & Supply Chain Evidence Card ────────────────


// ── NIST SP 800-53 / FedRAMP SSP Evidence Matrix Card ─────────


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


// ── Overview AI Summary Section ──────────────────────────────












































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























// ─────────────────────────────────────────────────────────────



// ─────────────────────────────────────────────────────────────










// ── Jira Settings helpers ─────────────────────────────────────



// ── STIG History Matrix & MTTR ───────────────────────────────


// ── STIG Inline Viewer ────────────────────────────────────────
























































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
