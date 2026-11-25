import { navigate } from '../core/router.js';
import { api } from '../lib/api.js';
import { esc, act } from '../lib/format.js';
import { _stigJiraSel, _stigRegistry } from '../state/registries.js';

// "Run STIG" for selected controls: reassess only those controls into a NEW scan that
// carries every other control forward. The scan being viewed is never modified.

const _running = new Map(); // `${vuln_id}__${slug}` → job id, shown as a row badge
let _state = null;

function closeModal() {
  document.querySelector('.modal-overlay')?.remove();
  _state = null;
}

export function stigRerunClose() {
  closeModal();
}

function body(html) {
  const el = document.getElementById('stig-rerun-body');
  if (el) el.innerHTML = html;
}

function shell(title) {
  document.querySelector('.modal-overlay')?.remove();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-container modal-md">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2 style="color:var(--text);margin:0">${esc(title)}</h2>
      <button class="btn" ${act('stigRerunClose')} style="padding:6px 12px" aria-label="Close">✕</button>
    </div>
    <div id="stig-rerun-body"></div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
}

function actions(primary) {
  return `<div style="display:flex;justify-content:flex-end;gap:10px;margin-top:14px">
    <button class="btn" ${act('stigRerunClose')}>Cancel</button>${primary || ''}</div>`;
}

function idList(ids) {
  const shown = ids.slice(0, 8).map(v => `<code>${esc(v)}</code>`).join(', ');
  return shown + (ids.length > 8 ? ` and ${ids.length - 8} more` : '');
}

// toolbar: no argument (uses the checked rows); drawer: an array with one regKey
export function openStigRerun(scanId, regKeys) {
  const keys = Array.isArray(regKeys) && regKeys.length ? regKeys : [..._stigJiraSel];
  const controls = keys.map(k => _stigRegistry.get(k)?.c).filter(Boolean);
  if (!controls.length) return;
  _state = { scanId, keys, ids: [...new Set(controls.map(c => c.vuln_id))], opts: {} };
  shell(`Run STIG for ${_state.ids.length} control${_state.ids.length === 1 ? '' : 's'}`);
  body(`
    <p style="font-size:13px;color:var(--text);margin:0 0 8px">${idList(_state.ids)}</p>
    <p style="font-size:13px;color:var(--text-muted);margin:0">Only these controls are reassessed by the AI. The result is saved as a
    new scan; every other control is carried forward unchanged and the scan you are viewing is left as it is.</p>
    ${actions(`<button class="btn btn-primary" ${act('stigRerunSubmit')}>Run STIG</button>`)}`);
}

export async function stigRerunSubmit(extra) {
  if (!_state) return;
  Object.assign(_state.opts, extra || {});
  const { scanId, ids, keys, opts } = _state;
  body('<p style="font-size:13px;color:var(--text-muted)">Starting…</p>');
  let res, data = {};
  try {
    res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/stig-run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vuln_ids: ids, ...opts }),
    });
    data = await res.json().catch(() => ({}));
  } catch (e) {
    body(`<p style="color:var(--critical);font-size:13px">${esc(e.message)}</p>${actions()}`);
    return;
  }
  if (res.status === 409 && data.code === 'newer_scan') {
    body(`<p style="font-size:13px;color:var(--text)">${esc(data.detail)}</p>
      <p style="font-size:12px;color:var(--text-muted)">Carried-forward controls come from the scan the re-run starts from.</p>
      ${actions(`<button class="btn btn-primary" ${act('stigRerunSubmit', { use_latest: true })}>Use newer scan</button>`)}`);
    return;
  }
  if (res.status === 409 && data.code === 'locked_controls') {
    body(`<p style="font-size:13px;color:var(--text)">${esc(data.detail)}</p>
      <p style="font-size:13px">${idList(data.controls || [])}</p>
      ${actions(`<button class="btn btn-primary" ${act('stigRerunSubmit', { confirm_override: true })}>Override locked control${(data.controls || []).length === 1 ? '' : 's'}</button>`)}`);
    return;
  }
  if (!res.ok) {
    body(`<p style="color:var(--critical);font-size:13px">${esc(data.detail || res.statusText)}</p>${actions()}`);
    return;
  }
  keys.forEach(k => _running.set(k, data.job_id));
  markRows();
  poll(data.job_id, keys);
}

function markRows() {
  _running.forEach((_, key) => {
    const [vid, slug] = key.split('__');
    const cell = document.querySelector(`#stig-row-${CSS.escape(vid)}-${CSS.escape(slug)} .stig-id`);
    if (cell && !cell.parentElement.querySelector('.stig-running')) {
      cell.insertAdjacentHTML('afterend', ' <span class="stig-running badge" title="Re-run in progress">⟳ re-running</span>');
    }
  });
}

async function poll(jobId, keys) {
  const jobsBox = () => document.getElementById('stig-rerun-body');
  for (;;) {
    let job;
    try { job = await api.getJob(jobId); } catch (_) { job = null; }
    if (!job) { await new Promise(r => setTimeout(r, 3000)); continue; }
    const tail = (job.output || []).slice(-6).map(esc).join('\n');
    if (jobsBox()) {
      body(`<p style="font-size:13px;color:var(--text)">${job.status === 'queued' ? 'Queued behind another scan…' : 'Re-running…'}</p>
        <pre style="font-size:11px;max-height:160px;overflow:auto;white-space:pre-wrap">${tail}</pre>
        ${actions()}`);
    }
    if (['completed', 'failed', 'error', 'cancelled'].includes(job.status)) {
      keys.forEach(k => _running.delete(k));
      document.querySelectorAll('.stig-running').forEach(n => n.remove());
      if (job.status === 'completed' && job.scan_name) {
        closeModal();
        navigate(`#/stig-viewer/${encodeURIComponent(job.scan_name)}`);
      } else if (jobsBox()) {
        body(`<p style="color:var(--critical);font-size:13px">${esc(job.error || `Re-run ${job.status}`)}</p>
          <pre style="font-size:11px;max-height:160px;overflow:auto;white-space:pre-wrap">${tail}</pre>${actions()}`);
      }
      return;
    }
    await new Promise(r => setTimeout(r, 3000));
  }
}
