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












// ── Finding detail drawer ─────────────────────────────────────








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
