import { scanWatch } from '../core/boot.js';
import { confirmDialog, toast } from '../components/feedback.js';
import { pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { esc, fmtDate, ucFirst, act, actOn } from '../lib/format.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

let _pollInterval = null;

let _scanJobs     = [];   // jobs submitted by the current run: { id, type, label, done, logLen, status }

// Sequential multi-scan-type queue state — when more than one Scan Type
// checkbox is selected, each type is submitted as its own job, one at a
// time, against the same target. Results are collected for the final
// PASS/FAIL summary table (mirrors the Self-Assessment layer results).
let _scanQueueResults   = [];   // [{ type, label, status, reason }]

let _scanQueueCancelled = false;

let _scanQueueTotal     = 0;

export async function renderNewScan(prefill = '') {
  setActive('new-scan');

  const page = document.getElementById('page');
  page.innerHTML = `
    ${pageHeader(`Run New Scan`, { subtitle: `Launch a security scan against a local directory or Git repository —
          Epyon orchestrates all applicable security layers based on the selected scan type.` })}

    <div class="section">
      <div class="section-title">Scan Configuration</div>
      <div class="result-section-box">
        <div class="form-group">
          <label>Source</label>
            <div class="seg-ctrl" id="target-mode-ctrl">
              <button type="button" class="seg-btn active" data-value="path" id="target-mode-path-btn"
                ${act('_setTargetMode', 'path')}>Path / Git URL</button>
              <button type="button" class="seg-btn" data-value="upload" id="target-mode-upload-btn"
                ${act('_setTargetMode', 'upload')}>Upload archive</button>
            </div>
            <small id="target-mode-hint">Deployed on a remote server? A typed absolute path is resolved on the
              <strong>server's</strong> own filesystem, not your machine — use
              "Upload archive" to scan a local, not-yet-pushed project instead.</small>
          </div>

          <div class="form-group" id="std-target-field">
            <label for="scan-target">Target</label>
            <input type="text" id="scan-target" autocomplete="off" spellcheck="false"
              placeholder="/absolute/path/to/project  or  https://github.com/org/repo.git"
              value="${esc(prefill)}" />
            <small id="scan-target-hint">Absolute local directory path, relative path, or Git repository URL (HTTPS/SSH)</small>
          </div>

          <div class="form-group" id="upload-target-field" style="display:none">
            <label for="scan-upload" id="scan-upload-label">Project archive (.zip / .tar.gz)</label>
            <input type="file" id="scan-upload" accept=".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz" />
            <small id="scan-upload-hint">Zip or tar the project directory (e.g. <code>zip -r project.zip project/</code> or <code>tar -czf project.tar.gz project/</code>) and
              upload it here. Extracted on the server and scanned like a local path.</small>
          </div>

          <div class="form-group">
            <label>Scan Types</label>
            <div style="margin-bottom:8px">
              <button type="button" class="btn btn-sm" ${act('setScanTypeCheckboxes', true)}>Select All</button>
              <button type="button" class="btn btn-sm" ${act('setScanTypeCheckboxes', false)}>Select None</button>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:8px">
              ${SCAN_TYPE_OPTIONS.map(t => `
                <label style="display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg-input)">
                  <input type="checkbox" class="scan-type-checkbox" value="${t.id}"
                    ${t.id === 'full' ? 'checked' : ''} ${actOn('change','_onScanTypeSelectionChange')}>
                  <span>${esc(t.label)}</span>
                </label>`).join('')}
            </div>
            <small>Select one or more scan types to run sequentially against the same target.</small>
          </div>

          <div class="form-group" id="scan-layer-picker-wrapper">
            <label>Scan Layers</label>
            ${renderScanLayerPicker()}
            <small>Only applies to Full, Nightly and Baseline scan types — Quick, STIG, and Local Model always run their fixed layer set.</small>
          </div>

          <div class="form-group" id="garak-checkbox-row">
            <label>Garak LLM Scan (Layer 12)</label>
            <div class="seg-ctrl" id="garak-ctrl">
              <button type="button" class="seg-btn active" data-value="off"
                ${act('_setGarak', 'off')}>Off</button>
              <button type="button" class="seg-btn" data-value="on"
                ${act('_setGarak', 'on')}>On</button>
            </div>
            <small>Requires <code>OPENAI_API_KEY</code> to be set.</small>
          </div>

          <div class="form-group" id="stig-checkbox-row">
            <label>STIG Compliance (Layer 13)</label>
            <div class="seg-ctrl" id="stig-ctrl">
              <button type="button" class="seg-btn active" data-value="off"
                ${act('_setStig', 'off')}>Off</button>
              <button type="button" class="seg-btn" data-value="on"
                ${act('_setStig', 'on')}>On</button>
            </div>
            <small>Requires <code>OPENAI_API_KEY</code> to be set.</small>
          </div>

          <div class="form-group">
            <label>Monitoring Type</label>
            <div class="seg-ctrl" id="monitoring-type-ctrl">
              <button type="button" class="seg-btn active" data-value="evaluation"
                ${act('_setMonitoringType', 'evaluation')}>
                &#9675; Evaluation
              </button>
              <button type="button" class="seg-btn" data-value="continuous"
                ${act('_setMonitoringType', 'continuous')}>
                &#9679; Continuous
              </button>
            </div>
            <small>Continuous apps are tracked in Metrics. Evaluation apps are excluded.</small>
          </div>

          <button id="run-btn" class="btn btn-primary" style="width:100%;justify-content:center" ${act('submitScan')}>
            ▶ Run Scan
          </button>
        </div>
      </div>
    </div>

    <div id="scan-output-section" class="section" style="display:none">
      <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <span>Scan Progress</span>
        <span style="display:flex;align-items:center;gap:12px">
          <div id="job-status-bar"></div>
          <button id="cancel-btn" class="btn btn-sm" style="display:none"
                  ${act('cancelScan')}>✕ Cancel</button>
        </span>
      </div>
      <div class="log-card" id="log-output"></div>
      <div id="scan-actions" style="display:none;gap:10px;margin-top:16px"></div>
      <div id="scan-type-results" style="margin-top:20px"></div>
    </div>

    <div id="jobs-section" class="section">
      <div class="section-title">Active &amp; recent scans</div>
      <div id="jobs-list"><div class="empty-state">Loading…</div></div>
      <div id="job-view" style="display:none;margin-top:16px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
          <span id="job-view-title"></span>
          <span style="display:flex;align-items:center;gap:8px">
            <button class="btn btn-sm" ${act('closeJobView')}>Close</button>
          </span>
        </div>
        <div class="log-card" id="job-view-log"></div>
      </div>
    </div>`;
  restoreScanRun();
  startJobList();
}

// Lists every job the server knows about, so scans started from another tab,
// before a reload, or by another run are still reachable from here.
let _jobListTimer = null;

let _viewJobId = null;

let _viewJobLen = 0;

const _JOB_ACTIVE = ['queued', 'running'];

export function startJobList() {
  clearTimeout(_jobListTimer);
  _viewJobId = null;
  refreshJobList();
}

export async function refreshJobList() {
  const list = document.getElementById('jobs-list');
  if (!list) return;  // left the page
  let delay = 15000;
  try {
    const res = await fetch('/api/jobs?summary=true');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const jobs = (await res.json()).slice(0, 20);
    if (!document.getElementById('jobs-list')) return;
    if (jobs.some(x => _JOB_ACTIVE.includes(x.status))) delay = 3000;
    renderJobList(jobs);
    if (_viewJobId) await refreshJobView();
  } catch (e) {
    const el = document.getElementById('jobs-list');
    if (el) el.innerHTML = `<div class="empty-state">Could not load scans (${esc(e.message)}). Retrying…</div>`;
  }
  clearTimeout(_jobListTimer);
  _jobListTimer = setTimeout(refreshJobList, delay);
}

export function renderJobList(jobs) {
  const list = document.getElementById('jobs-list');
  if (!list) return;
  if (!jobs.length) { list.innerHTML = '<div class="empty-state">No scans yet.</div>'; return; }
  list.innerHTML = `
    <div class="table-container"><table>
      <thead><tr><th>Status</th><th>Target</th><th>Type</th><th>Started</th><th></th></tr></thead>
      <tbody>${jobs.map(x => {
        const active = _JOB_ACTIVE.includes(x.status);
        const id = esc(x.job_id);
        return `<tr${x.job_id === _viewJobId ? ' style="background:var(--bg-hover)"' : ''}>
          <td><span class="job-status ${esc(x.status)}">${ucFirst(esc(x.status))}</span></td>
          <td>${esc(x.target)}</td>
          <td>${esc(x.scan_type)}</td>
          <td style="font-size:12px;color:var(--text-muted)">${fmtDate(x.started_at)}</td>
          <td style="text-align:right;white-space:nowrap">
            <button class="btn btn-sm" ${act('openJobView', `${id}`)}>${x.job_id === _viewJobId ? 'Viewing' : 'View log'}</button>
            ${active ? `<button class="btn btn-sm" ${act('cancelJobById', `${id}`)}>Cancel</button>` : ''}
          </td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`;
}

export async function openJobView(id) {
  _viewJobId = id;
  _viewJobLen = 0;
  const view = document.getElementById('job-view');
  const log = document.getElementById('job-view-log');
  if (!view || !log) return;
  log.innerHTML = '';
  view.style.display = 'block';
  await refreshJobView();
  view.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  refreshJobList();
}

export async function refreshJobView() {
  const id = _viewJobId;
  const log = document.getElementById('job-view-log');
  if (!id || !log) return;
  try {
    const job = await api.getJob(id);
    if (id !== _viewJobId) return;
    const lines = job.output || [];
    if (lines.length > _viewJobLen) {
      log.insertAdjacentHTML('beforeend', lines.slice(_viewJobLen).map(l => `<div class="log-line">${esc(l)}</div>`).join(''));
      _viewJobLen = lines.length;
      log.scrollTop = log.scrollHeight;
    }
    const title = document.getElementById('job-view-title');
    if (title) title.innerHTML = `${esc(job.target)} · ${esc(job.scan_type)} — <span class="job-status ${esc(job.status)}">${ucFirst(esc(job.status))}</span>`;
  } catch (e) {
    log.insertAdjacentHTML('beforeend', `<div class="log-line err">Could not load this scan: ${esc(e.message)}</div>`);
    _viewJobId = null;
  }
}

export function closeJobView() {
  _viewJobId = null;
  const view = document.getElementById('job-view');
  if (view) view.style.display = 'none';
  refreshJobList();
}

export async function cancelJobById(id) {
  if (!await confirmDialog({ title: 'Cancel scan', body: 'Stop this scan? Partial results are kept.', confirmLabel: 'Cancel scan' })) return;
  try {
    const res = await fetch(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
    if (!res.ok && res.status !== 409) throw new Error(`HTTP ${res.status}`);
    toast('Scan cancelled.', 'success');
  } catch (e) {
    toast(`Could not cancel the scan: ${e.message}. Try again.`, 'error');
  }
  scanWatch.poke();
  refreshJobList();
}

// The run lives in module state, not the DOM, so leaving Run Scan and coming
// back shows the same progress, logs and results.
export function restoreScanRun() {
  if (!_scanJobs.length) return;
  const running = _scanJobs.some(j => !j.done);
  document.getElementById('scan-output-section').style.display = 'block';
  const logOut = document.getElementById('log-output');
  logOut.innerHTML = _scanJobs.map(j =>
    `<div class="log-line" style="color:var(--text);font-weight:600;margin-top:10px">── ${esc(j.label)} ──</div>` +
    `<div id="log-job-${esc(j.id)}">${(j.lines || []).map(l => `<div class="log-line">${esc(l)}</div>`).join('')}</div>`
  ).join('');
  logOut.scrollTop = logOut.scrollHeight;
  renderScanJobStatus();
  const btn = document.getElementById('run-btn');
  if (running) {
    if (btn) { btn.disabled = false; btn.textContent = _runningLabel(); }
    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
  } else {
    finishScanQueue(btn);
  }
}

export function renderScanJobStatus() {
  const statusBar = document.getElementById('job-status-bar');
  if (!statusBar) return;
  statusBar.innerHTML = _scanJobs.map(j =>
    `<div><span class="job-status ${esc(j.status || 'queued')}">${ucFirst(j.status || 'queued')}</span>
       <span style="color:var(--text-muted);font-size:12px">— ${esc(j.label)}${j.target ? ' · ' + esc(j.target) : ''}</span></div>`).join('');
}

export function startNewScanRun() {
  _scanJobs = [];
  _scanQueueResults = [];
  renderNewScan();
}

// Scan types selectable in the "Scan Types" checkbox picker — mirrors the
// self-diagnostic layer picker's select-all/select-none + checkbox grid UX.
const SCAN_TYPE_OPTIONS = [
  { id: 'full',        label: 'Full — All security layers (recommended)' },
  { id: 'quick',       label: 'Quick — Fast check: Trivy, TruffleHog, SBOM' },
  { id: 'nightly',     label: 'Nightly — Scheduled comprehensive scan (layers 1–12)' },
  { id: 'baseline',    label: 'Baseline — Establish initial security benchmark (all layers)' },
  { id: 'stig',        label: 'STIG — STIG compliance assessment only (on demand)' },
  { id: 'local_model', label: 'Local Model — Scan model weights in a local directory (layers 14–15)' },
  { id: 'container_image', label: 'Container Image — Scan a local/registry/URL image (TruffleHog, Trivy, Grype, Xeol)' },
];

export function setScanTypeCheckboxes(checked) {
  document.querySelectorAll('.scan-type-checkbox').forEach(cb => { cb.checked = checked; });
  _onScanTypeSelectionChange();
}

// Layers selectable in the "Scan Layers" picker on the Run Scan page —
// mirrors the Performance page's self-diagnostic layer picker (SELF_DIAG_LAYERS)
// and the LAYER_SKIP_ENV mapping in web/api/jobs.py. Layer 3 (Sonar, gated on
// SONAR_TOKEN), Layer 12 (Garak) and Layer 13 (STIG) are deliberately excluded
// — they already have their own dedicated opt-in controls below — and Layer 20
// (ML Runtime) is opt-in-only and not yet exposed as a picker option.
const SCAN_LAYER_OPTIONS = [
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
  { n: '14', name: 'Model File Analysis' },
  { n: '15', name: 'Model Card Compliance' },
  { n: '16', name: 'Network Discovery' },
  { n: '18', name: 'Model Provenance & Threat Intel' },
  { n: '19', name: 'Inference Environment Security' },
  { n: '21', name: 'Compromised Source Detection' },
];

export function renderScanLayerPicker() {
  const boxes = SCAN_LAYER_OPTIONS.map(l => `
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg-input)">
      <input type="checkbox" class="scan-layer-checkbox" value="${l.n}" checked>
      <span>L${l.n} — ${esc(l.name)}</span>
    </label>`).join('');
  return `
    <details>
      <summary style="cursor:pointer;font-size:13px;color:var(--text-muted)">Select layers to run (defaults to all)</summary>
      <div style="margin-top:10px">
        <div style="margin-bottom:8px">
          <button type="button" class="btn btn-sm" ${act('setScanLayerCheckboxes', true)}>Select All</button>
          <button type="button" class="btn btn-sm" ${act('setScanLayerCheckboxes', false)}>Select None</button>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">${boxes}</div>
      </div>
    </details>`;
}

export function setScanLayerCheckboxes(checked) {
  document.querySelectorAll('.scan-layer-checkbox').forEach(cb => { cb.checked = checked; });
}

// Returns the checked layer numbers, or null if every layer is selected
// (the default — omit the override entirely so scan-type defaults apply
// unchanged, same as before this picker existed).
export function _getSelectedScanLayers() {
  const boxes = Array.from(document.querySelectorAll('.scan-layer-checkbox'));
  if (boxes.length === 0) return null;
  const checked = boxes.filter(cb => cb.checked).map(cb => cb.value);
  return checked.length === boxes.length ? null : checked;
}

export function _getSelectedScanTypes() {
  return Array.from(document.querySelectorAll('.scan-type-checkbox'))
    .filter(cb => cb.checked).map(cb => cb.value);
}

export function _onScanTypeSelectionChange() {
  const modes = _getSelectedScanTypes();

  const inp = document.getElementById('scan-target');
  const targetLabel = document.querySelector('label[for="scan-target"]');
  const targetHint = document.getElementById('scan-target-hint');
  const isImageOnly = modes.length === 1 && modes[0] === 'container_image';
  if (inp && !inp.value) {
    inp.placeholder = isImageOnly
      ? 'nginx:1.27-alpine  or  ghcr.io/org/app:tag  or  ./my-image.tar  or  https://example.com/app.tar.gz'
      : (modes.length === 1 && modes[0] === 'local_model')
        ? '/absolute/path/to/models  (e.g. /opt/models/llama3)'
        : '/absolute/path/to/project  or  https://github.com/org/repo.git';
  }
  if (targetLabel) targetLabel.textContent = isImageOnly ? 'Container Image Source' : 'Target';
  if (targetHint) {
    targetHint.textContent = isImageOnly
      ? 'A registry reference to pull (e.g. ghcr.io/org/app:tag) or an https:// URL to an image tarball. ' +
        'A local image name/tag or tarball path only works if it already exists on THIS SERVER\u2019s filesystem/Docker daemon — ' +
        'for an image on your own machine, use "Upload image tarball" below instead.'
      : 'Absolute local directory path, relative path, or Git repository URL (HTTPS/SSH)';
  }

  // Upload mode: repurpose the same "Path / Git URL" vs "Upload" toggle for
  // image sources when Container Image is the sole selected type — a local
  // tarball is as much a "not yet on the server" artifact as an unpushed
  // project directory, so it gets the same upload escape hatch.
  const uploadBtn   = document.getElementById('target-mode-upload-btn');
  const modeHint    = document.getElementById('target-mode-hint');
  const uploadLabel = document.getElementById('scan-upload-label');
  const uploadInput = document.getElementById('scan-upload');
  const uploadHint  = document.getElementById('scan-upload-hint');
  if (uploadBtn)  uploadBtn.textContent = isImageOnly ? 'Upload image tarball' : 'Upload archive';
  if (modeHint) {
    modeHint.innerHTML = isImageOnly
      ? 'Deployed on a remote server? A typed local tarball path is resolved on the <strong>server\u2019s</strong> ' +
        'own filesystem, not your machine — use "Upload image tarball" to scan a local <code>docker save</code> ' +
        'archive instead (registry references and https:// URLs work fine from the Target field either way).'
      : 'Deployed on a remote server? A typed absolute path is resolved on the <strong>server\u2019s</strong> ' +
        'own filesystem, not your machine — use "Upload archive" to scan a local, not-yet-pushed project instead.';
  }
  if (uploadLabel) uploadLabel.textContent = isImageOnly ? 'Image archive (.tar / .tar.gz / .tgz)' : 'Project archive (.zip / .tar.gz)';
  if (uploadInput) uploadInput.accept = isImageOnly ? '.tar,.tar.gz,.tgz' : '.zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz';
  if (uploadHint) {
    uploadHint.innerHTML = isImageOnly
      ? 'Produce one with <code>docker save -o image.tar name:tag</code> (or gzip it) and upload it here. ' +
        'Loaded into the server\u2019s Docker daemon and scanned like a registry/local image.'
      : 'Zip or tar the project directory (e.g. <code>zip -r project.zip project/</code> or <code>tar -czf project.tar.gz project/</code>) and ' +
        'upload it here. Extracted on the server and scanned like a local path.';
  }
  // Show Garak / STIG toggles and the layer picker only if any selected
  // type supports granular layer control (quick/stig/local_model always
  // run their own fixed, narrow layer set regardless of these controls).
  const optInModes = ['full', 'nightly', 'baseline'];
  const anyOptIn = modes.some(m => optInModes.includes(m));
  const garakRow = document.getElementById('garak-checkbox-row');
  if (garakRow) garakRow.style.display = anyOptIn ? '' : 'none';
  const stigRow = document.getElementById('stig-checkbox-row');
  if (stigRow) stigRow.style.display = anyOptIn ? '' : 'none';
  const layerPickerRow = document.getElementById('scan-layer-picker-wrapper');
  if (layerPickerRow) layerPickerRow.style.display = anyOptIn ? '' : 'none';
}

export function _setGarak(value) {
  document.querySelectorAll('#garak-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

export function _setStig(value) {
  document.querySelectorAll('#stig-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

export function _setMonitoringType(value) {
  document.querySelectorAll('#monitoring-type-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

export function _setTargetMode(value) {
  document.querySelectorAll('#target-mode-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
  const pathField   = document.getElementById('std-target-field');
  const uploadField = document.getElementById('upload-target-field');
  if (pathField)   pathField.style.display   = value === 'upload' ? 'none' : '';
  if (uploadField) uploadField.style.display = value === 'upload' ? '' : 'none';
}

export async function submitScan() {
  const selectedTypes = _getSelectedScanTypes();
  const activeGarak = document.querySelector('#garak-ctrl .seg-btn.active');
  const runGarak  = activeGarak?.dataset.value === 'on';
  const activeStig = document.querySelector('#stig-ctrl .seg-btn.active');
  const runStig   = activeStig ? activeStig.dataset.value === 'on' : false;
  const selectedLayers = _getSelectedScanLayers();
  const btn       = document.getElementById('run-btn');
  // Runs inside the click gesture, which browsers require for the permission prompt.
  if ('Notification' in window && Notification.permission === 'default') {
    try { Notification.requestPermission(); } catch (_) {}
  }

  const activeMode = document.querySelector('#target-mode-ctrl .seg-btn.active')?.dataset.value || 'path';
  const target = (document.getElementById('scan-target')?.value || '').trim();
  const uploadFile = document.getElementById('scan-upload')?.files?.[0] || null;

  if (selectedTypes.length === 0) {
    toast('Select at least one scan type to run.', 'warning');
    return;
  }
  if (selectedTypes.includes('container_image') && selectedTypes.length > 1) {
    toast('Container Image scans use the Target field for an image source (not a path/Git URL) and cannot be combined with other scan types in the same run. Run it on its own.', 'warning');
    return;
  }
  if (activeMode === 'upload') {
    if (!uploadFile) {
      document.getElementById('scan-upload')?.focus();
      return;
    }
  } else if (!target) {
    document.getElementById('scan-target').focus();
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Starting…';

  // Scans already running keep their logs and results; a new submission adds to them.
  const joining = _scanJobs.some(j => !j.done);
  document.getElementById('scan-output-section').style.display = 'block';
  document.getElementById('scan-actions').style.display = 'none';
  if (!joining) {
    document.getElementById('log-output').innerHTML = '';
    document.getElementById('scan-type-results').innerHTML = '';
    _scanJobs           = [];
    _scanQueueResults   = [];
    _scanQueueTotal     = 0;
  }
  _scanQueueCancelled = false;
  _scanQueueTotal += selectedTypes.length;

  const cancelBtn = document.getElementById('cancel-btn');
  if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.textContent = '✕ Cancel'; cancelBtn.style.display = 'inline-flex'; }

  const monitoring = document.querySelector('#monitoring-type-ctrl .seg-btn.active')?.dataset.value || '';
  runNextQueuedScan(btn, { queue: [...selectedTypes], activeMode, target, uploadFile, runGarak, runStig, selectedLayers, monitoring });
}

// Submits every selected scan type right away; the server runs up to its
// concurrency cap and holds the rest as "queued". Each job gets its own log
// section and is tracked by one shared poller.
export function _runningLabel() {
  const n = _scanJobs.filter(j => !j.done).length;
  return `▶ Run Another Scan (${n} running)`;
}

export async function runNextQueuedScan(btn, ctx) {
  const queue = ctx.queue;
  while (queue.length && !_scanQueueCancelled) {
    const scanType = queue.shift();
    const label = SCAN_TYPE_OPTIONS.find(t => t.id === scanType)?.label || scanType;
    try {
      // The layer picker only applies to scan types with a flexible layer
      // set (full/nightly/baseline) — quick/stig/local_model always run
      // their own fixed, narrow set regardless of checkbox state.
      const layersForThisType = ['full', 'nightly', 'baseline'].includes(scanType) ? ctx.selectedLayers : null;
      const job = ctx.activeMode === 'upload'
        ? (scanType === 'container_image'
            ? await api.triggerScanUploadImage(ctx.uploadFile, (pct, done) => {
                btn.textContent = done ? '⏳ Loading image on server…' : `⏳ Uploading… ${pct}%`;
              })
            : await api.triggerScanUpload(ctx.uploadFile, scanType, ctx.runGarak, ctx.runStig, (pct, done) => {
                btn.textContent = done ? '⏳ Extracting on server…' : `⏳ Uploading… ${pct}%`;
              }, layersForThisType))
        : await api.triggerScan(ctx.target, scanType, ctx.runGarak, ctx.runStig, layersForThisType);
      _scanJobs.push({ id: job.job_id, type: scanType, label, done: false, logLen: 0, lines: [], monitoring: ctx.monitoring });
      if (_scanQueueCancelled) {
        await fetch(`/api/jobs/${encodeURIComponent(job.job_id)}/cancel`, { method: 'POST' }).catch(() => {});
      }
      scanWatch.poke();
      const logOut = document.getElementById('log-output');
      if (logOut) {
        const head = document.createElement('div');
        head.className = 'log-line';
        head.style.cssText = `color:var(--text);font-weight:600;margin-top:${_scanJobs.length > 1 ? '10px' : '0'}`;
        head.textContent = `── ${label} ──`;
        const slot = document.createElement('div');
        slot.id = `log-job-${job.job_id}`;
        logOut.append(head, slot);
      }
    } catch (e) {
      _scanQueueResults.push({ type: scanType, label, status: 'error', reason: e.message });
      // nosemgrep: typescript.react.security.audit.react-unsanitized-method.react-unsanitized-method - every interpolated value goes through esc()
      document.getElementById('log-output')?.insertAdjacentHTML('beforeend',
        `<div class="log-line err">Error starting ${esc(label)}: ${esc(e.message)}</div>`);
    }
  }
  while (queue.length) {
    const skippedType = queue.shift();
    const skippedLabel = SCAN_TYPE_OPTIONS.find(t => t.id === skippedType)?.label || skippedType;
    _scanQueueResults.push({ type: skippedType, label: skippedLabel, status: 'fail', reason: 'Skipped (run cancelled)' });
  }
  if (!_scanJobs.some(j => !j.done)) { finishScanQueue(btn); return; }
  btn.disabled = false;
  btn.textContent = _runningLabel();
  clearInterval(_pollInterval);
  _pollInterval = setInterval(() => pollJobs(btn, ctx), 2000);
  pollJobs(btn, ctx);
}

export async function pollJobs(btn, ctx) {
  // Keep polling while the page is elsewhere so results are still recorded.
  await Promise.all(_scanJobs.filter(j => !j.done).map(async j => {
    try {
      const job = await api.getJob(j.id);
      j.status = job.status;
      j.target = job.target;
      const lines = job.output || [];
      if (lines.length > j.logLen) {
        const fresh = lines.slice(j.logLen);
        j.lines.push(...fresh);
        const section = document.getElementById(`log-job-${j.id}`);
        if (section) {
          // nosemgrep: typescript.react.security.audit.react-unsanitized-method.react-unsanitized-method - every interpolated value goes through esc()
          section.insertAdjacentHTML('beforeend', fresh.map(l => `<div class="log-line">${esc(l)}</div>`).join(''));
          const logOut = document.getElementById('log-output');
          if (logOut) logOut.scrollTop = logOut.scrollHeight;
        }
        j.logLen = lines.length;
      }
      if (['completed', 'failed', 'error', 'cancelled'].includes(job.status)) {
        j.done = true;
        _scanQueueResults.push({
          type: j.type, label: j.label,
          status: job.status === 'completed' ? 'pass' : 'fail',
          reason: job.status === 'completed' ? 'Completed successfully'
            : job.status === 'cancelled' ? 'Cancelled by user'
            : job.status === 'failed' ? 'Failed (non-zero exit code)'
            : 'Encountered an error',
        });
        // Apply monitoring classification on successful completion
        if (job.status === 'completed' && job.target) {
          try {
            if ((j.monitoring ?? ctx.monitoring) === 'continuous') await api.setMonitored(job.target);
            else await api.unsetMonitored(job.target);
          } catch (_) {}
        }
      }
    } catch (_) { /* ignore transient polling errors */ }
  }));

  renderScanJobStatus();

  if (_scanJobs.every(j => j.done)) {
    clearInterval(_pollInterval);
    _pollInterval = null;
    finishScanQueue(btn);
  }
}

// Called once the queue is empty (all selected scan types have run, or the
// run was cancelled) — restores the Run button, hides Cancel, shows the
// post-scan actions, and renders the PASS/FAIL summary table.
export function finishScanQueue() {
  const btn = document.getElementById('run-btn');
  if (btn) { btn.disabled = false; btn.textContent = '▶ Run Scan'; }

  const cancelBtn = document.getElementById('cancel-btn');
  if (cancelBtn) cancelBtn.style.display = 'none';

  const anyFailed = _scanQueueResults.some(r => r.status !== 'pass');
  const actionsDiv = document.getElementById('scan-actions');
  if (actionsDiv) {
    actionsDiv.style.display = 'flex';
    actionsDiv.innerHTML = !anyFailed
      ? `<button class="btn btn-primary" ${act('navigate', '#/applications')}>
           View Applications
         </button>
         <button class="btn" ${act('copyScanLogs')}>Copy Logs</button>
         <button class="btn" ${act('startNewScanRun')}>Run Another Scan</button>`
      : `<div class="error-banner" style="margin:0">
           One or more scan types did not complete successfully. Check the log output and results below.
         </div>
         <button class="btn" ${act('copyScanLogs')}>Copy Logs</button>
         <button class="btn" ${act('startNewScanRun')}>Run Another Scan</button>`;
  }

  renderScanQueueResults();
}

// Renders the PASS/FAIL summary table for the scan types just run — same
// stat-card + gumball-badge table pattern as the Self-Assessment results
// (renderSelfAssessmentBody) for a consistent feel across the two pages.
export function renderScanQueueResults() {
  const container = document.getElementById('scan-type-results');
  if (!container) return;
  if (_scanQueueResults.length === 0) { container.innerHTML = ''; return; }

  const passed  = _scanQueueResults.filter(r => r.status === 'pass').length;
  const failed  = _scanQueueResults.filter(r => r.status !== 'pass').length;

  const rows = _scanQueueResults.map(r => {
    const g = r.status === 'pass'
      ? { icon: '🟢', label: 'PASS', cls: 'clean' }
      : { icon: '🔴', label: 'FAIL', cls: 'critical' };
    return `
      <tr>
        <td>${esc(r.label)}</td>
        <td><span class="sev-badge ${g.cls}" style="font-size:12px">${g.icon} ${g.label}</span></td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(r.reason)}</td>
      </tr>`;
  }).join('');

  container.innerHTML = `
    <div class="section-title">Scan Type Results</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:16px">
      <div class="stat-card">
        <div class="stat-label">Passed</div>
        <div class="stat-value" style="color:var(--clean)">${passed}/${_scanQueueResults.length}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Failed</div>
        <div class="stat-value" style="color:${failed > 0 ? 'var(--critical)' : 'var(--text-primary)'}">${failed}</div>
      </div>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr><th scope="col">Scan Type</th><th scope="col">Status</th><th scope="col">Why</th></tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>`;
}

export async function cancelScan() {
  // Cancel every job in this run, including ones still waiting in the server queue.
  _scanQueueCancelled = true;
  const btn = document.getElementById('cancel-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Cancelling…'; }
  await Promise.all(_scanJobs.filter(j => !j.done).map(j =>
    fetch(`/api/jobs/${encodeURIComponent(j.id)}/cancel`, { method: 'POST' }).catch(() => {})));
}

export function copyScanLogs() {
  const logOut = document.getElementById('log-output');
  if (!logOut) return;
  
  // Get plain text from the log output
  const logText = logOut.innerText || logOut.textContent || '';
  
  navigator.clipboard.writeText(logText).then(() => {
    // Briefly show success feedback
    const btn = event?.target;
    if (btn) {
      const originalText = btn.textContent;
      btn.textContent = '✓ Copied!';
      btn.classList.add('btn-success');
      setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove('btn-success');
      }, 2000);
    }
  }).catch(err => {
    console.error('Failed to copy logs:', err);
    toast('Failed to copy logs to clipboard', 'error');
  });
}

// Lets the legacy scan watcher ask whether this page started (and is still polling) a job.
export function isScanJobTracked(id) {
  return !!_pollInterval && _scanJobs.some(j => j.id === id && !j.done);
}
