import { esc } from '../lib/format.js';

// Manifest layer numbers that can be individually toggled for the
// self-diagnostic run (mirrors tests/fixtures/self-assessment/expected-
// findings.json and _SELF_ASSESSMENT_VALID_LAYERS in web/api/main.py).
// Layer 3 (SonarQube) and Layer 20 (ML Runtime, opt-in only) are excluded —
// they're never run by the harness regardless of selection.
export const SELF_DIAG_LAYERS = [
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

export function renderSelfDiagLayerPicker() {
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

export function setSelfDiagLayers(checked) {
  document.querySelectorAll('.self-diag-layer-checkbox').forEach(cb => { cb.checked = checked; });
}

// Renders the Self-Assessment (cross-layer scanner validation) card body —
// used both on initial Performance page load and to refresh in place after
// a "Run Self-Diagnostic" job completes, without a full page re-render.
export function renderSelfAssessmentBody(sa) {
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
