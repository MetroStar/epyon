import { toast } from '../components/feedback.js';
import { api } from '../lib/api.js';
import { esc, ucFirst } from '../lib/format.js';

// Legacy globals still provided by main.js (see index.js):
/* global renderSelfAssessmentBody */

let _saPollInterval = null;

let _saLastLogLen   = 0;

export async function startSelfDiagnostic() {
  const btn = document.getElementById('run-self-diag-btn');
  const progressDiv = document.getElementById('self-diag-progress');
  const statusDiv   = document.getElementById('self-diag-status');
  const logDiv      = document.getElementById('self-diag-log');
  if (!btn || !progressDiv || !statusDiv || !logDiv) return;

  const allBoxes = Array.from(document.querySelectorAll('.self-diag-layer-checkbox'));
  const checkedBoxes = allBoxes.filter(cb => cb.checked);
  if (allBoxes.length && checkedBoxes.length === 0) {
    toast('Select at least one layer to validate, or click "Select All".', 'warning');
    return;
  }
  // Only pass a layer filter if it's a strict subset — an empty/omitted
  // filter runs (and validates) everything, matching prior behavior.
  const layers = (checkedBoxes.length && checkedBoxes.length < allBoxes.length)
    ? checkedBoxes.map(cb => cb.value)
    : null;

  btn.disabled    = true;
  btn.textContent = '⏳ Starting…';
  progressDiv.style.display = 'block';
  logDiv.innerHTML = '';
  statusDiv.textContent = layers
    ? `Starting self-diagnostic for ${layers.length} selected layer(s)…`
    : 'Starting self-diagnostic (all layers)…';
  _saLastLogLen = 0;

  try {
    const job = await api.runSelfAssessment(layers);
    if (job.already_running) {
      statusDiv.textContent = 'A self-diagnostic is already running — showing its progress.';
    }
    clearInterval(_saPollInterval);
    _saPollInterval = setInterval(() => pollSelfDiagnosticJob(job.job_id), 2000);
    pollSelfDiagnosticJob(job.job_id);
  } catch (e) {
    btn.disabled    = false;
    btn.textContent = '▶ Run Self-Diagnostic';
    statusDiv.textContent = `Error: ${e.message}`;
  }
}

export async function pollSelfDiagnosticJob(jobId) {
  const btn        = document.getElementById('run-self-diag-btn');
  const statusDiv   = document.getElementById('self-diag-status');
  const logDiv      = document.getElementById('self-diag-log');
  if (!statusDiv || !logDiv) { clearInterval(_saPollInterval); return; }

  try {
    const job = await api.getJob(jobId);

    statusDiv.textContent = job.status === 'running'
      ? '⏳ Running full 21-layer scan against the self-assessment fixture…'
      : `Status: ${ucFirst(job.status)}`;

    const lines = job.output || [];
    if (lines.length > _saLastLogLen) {
      const frag = lines.slice(_saLastLogLen)
        .map(l => `<div class="log-line">${esc(l)}</div>`)
        .join('');
      logDiv.insertAdjacentHTML('beforeend', frag);
      logDiv.scrollTop = logDiv.scrollHeight;
      _saLastLogLen = lines.length;
    }

    if (['completed', 'failed', 'error', 'cancelled'].includes(job.status)) {
      clearInterval(_saPollInterval);
      _saPollInterval = null;
      if (btn) { btn.disabled = false; btn.textContent = '▶ Run Self-Diagnostic'; }

      // Re-fetch the freshly written per-layer verdict and re-render the
      // table in place (comparator writes web/data/self-assessment-latest.json
      // even when the overall job exit code is non-zero, as long as the
      // comparison step itself ran).
      try {
        const sa = await api._get('/api/metrics/self-assessment', false);
        const bodyDiv = document.getElementById('self-assessment-body');
        if (bodyDiv) bodyDiv.innerHTML = renderSelfAssessmentBody(sa);
        statusDiv.textContent = job.status === 'completed'
          ? '✅ Self-diagnostic finished — results updated below.'
          : `⚠️ Self-diagnostic ${job.status} (exit code ${job.exit_code ?? 'unknown'}) — see results below and log above for details.`;
      } catch (_) {
        statusDiv.textContent = `Self-diagnostic ${job.status}, but results could not be refreshed — reload the page.`;
      }
    }
  } catch (_) { /* ignore transient polling errors */ }
}
