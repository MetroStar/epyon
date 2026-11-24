import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { confirmDialog, toast } from '../components/feedback.js';
import { api } from '../lib/api.js';
import { esc, act, actOn, ARG, ucFirst } from '../lib/format.js';
import { closeFindingDetail } from '../components/drawers/finding.js';
import { stigRecordHtml } from '../components/drawers/stig.js';
import { _stigRegistry } from '../state/registries.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

let _projects = [];
let _roles = ['frontend', 'backend', 'infra', 'other'];
let _appNames = [];

const ROLE_LABEL = { frontend: 'Frontend', backend: 'Backend', infra: 'Infrastructure', other: 'Other' };

const externalBadges = list => (list && list.length) ? `
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px;align-items:center">
        <span style="font-size:12px;color:var(--text-dim)">Third-party (not STIG-assessed):</span>
        ${list.map(x => `<span class="app-type-badge" title="${esc(x.note || '')}">${esc(x.name)} <span style="opacity:.7">· ${esc(ROLE_LABEL[x.role] || x.role)}</span></span>`).join('')}
      </div>` : '';

export async function renderProjects() {
  setActive('projects');
  const page = document.getElementById('page');
  page.innerHTML = loading();
  try {
    const [data, apps] = await Promise.all([api.getProjects(), api.getApplications()]);
    _projects = data.projects || [];
    _roles = data.roles || _roles;
    _appNames = (apps || []).map(a => a.name).sort();
  } catch (e) {
    page.innerHTML = errBanner(e.message);
    return;
  }

  const cards = _projects.map(p => `
    <div class="card" style="margin-bottom:14px;padding:16px">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
        <div>
          <h3 style="margin:0">${esc(p.name)}</h3>
          ${p.description ? `<p style="margin:4px 0 0;color:var(--text-muted);font-size:13px">${esc(p.description)}</p>` : ''}
          ${p.jira_project_key ? `<div style="margin-top:6px;font-size:12px;color:var(--text-dim)">Jira board: ${esc(p.jira_project_key)}</div>` : ''}
        </div>
        <div style="display:flex;gap:8px">
          <a class="btn btn-primary" href="#/projects/${encodeURIComponent(p.id)}">STIG roll-up</a>
          <button class="btn" ${act('showProjectModal', p.id)}>Edit</button>
          <button class="btn btn-danger" ${act('deleteProject', p.id)}>Delete</button>
        </div>
      </div>
      ${externalBadges(p.external)}
      <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px">
        ${p.repos.length ? p.repos.map(r => `
          <a class="app-type-badge evaluation" href="#/applications/${encodeURIComponent(r.app)}" style="text-decoration:none">
            ${esc(r.app)} <span style="opacity:.7">· ${esc(ROLE_LABEL[r.role] || r.role)}</span>
          </a>`).join('') : '<span style="color:var(--text-dim);font-size:13px">No repositories yet</span>'}
      </div>
    </div>`).join('');

  page.innerHTML = `
    ${pageHeader('Projects', {
      subtitle: 'A project is one system (ATO boundary) made of several repositories built by different teams.',
      actions: `<button class="btn btn-primary" ${act('showProjectModal', '')}>New project</button>`,
    })}
    ${_projects.length ? cards : emptyState('No projects yet',
      'Create a project to group repositories that together satisfy one system\'s STIG controls.')}`;
}

const STATUS_CLASS = {
  'Open': 'stig-status-open',
  'Not a Finding': 'stig-status-pass',
  'Not Applicable': 'stig-status-na',
  'Not Reviewed': 'stig-status-nr',
};
const statusLabel = s => (s === 'Not Reviewed' ? 'Evidence needed' : s === 'missing' ? 'Not scanned' : s);
const statusPill = s => `<span class="${esc(STATUS_CLASS[s] || 'stig-status-nr')}">${esc(statusLabel(s))}</span>`;

// SV-222387r961863_rule -> SV-222387; falls back to the V-number when the rule id is missing
const svNumber = c => (String(c.rule_id || '').match(/^SV-\d+/i) || [c.group_id || c.vuln_id])[0];

const _rollupControls = new Map();
let _projectId = null;
const STATUSES = ['Not a Finding', 'Not Applicable', 'Open', 'Not Reviewed'];
let _rollupSeq = 0;

function partEditHtml(p, d, idx, seq) {
  const id = k => `pd-${k}-${seq}-${idx}`;
  const regKey = `project__${seq}__${idx}`;
  _stigRegistry.set(regKey, { c: { ...d, vuln_id: d.vuln_id, _slug: p.slug }, scanId: p.scan_id });
  return `
      <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px">
        <div class="finding-detail-label" style="margin-bottom:8px">Assessment (editable)</div>
        <div class="stig-override-form">
          <div class="stig-override-row"><label class="stig-override-label">Status</label>
            <select class="stig-override-select" id="${id('status')}">
              ${STATUSES.map(st => `<option value="${esc(st)}"${p.status === st ? ' selected' : ''}>${esc(st)}</option>`).join('')}
            </select></div>
          <div class="stig-override-row"><label class="stig-override-label">Evidence</label>
            <textarea class="stig-override-textarea" id="${id('evid')}" rows="5" maxlength="20000"
              placeholder="Cite the file and value that satisfy (or fail) this control">${esc(p.evidence || '')}</textarea></div>
          <div class="stig-override-row"><label class="stig-override-label">Justification (optional)</label>
            <textarea class="stig-override-textarea" id="${id('just')}" rows="2" maxlength="20000">${esc(d.justification || '')}</textarea></div>
          <div class="stig-override-row stig-override-actions">
            <button class="btn btn-sm btn-success" ${act('saveProjectPartEdit', p.scan_id, p.slug, d.vuln_id, seq, idx)}>Save edit</button>
            ${d.locked_by_human ? `<button class="btn btn-sm" ${act('discardProjectPartEdit', p.scan_id, p.slug, d.vuln_id)}>Discard edit</button>` : ''}
            <button class="btn btn-sm btn-primary" ${act('openStigJiraModal', p.scan_id, [regKey])}>Add to Jira</button>
            <span class="stig-override-msg" id="${id('msg')}"></span>
          </div>
        </div>
      </div>`;
}

async function patchOverride(scanId, body, msgEl, done) {
  msgEl.textContent = 'Saving…';
  msgEl.className = 'stig-override-msg';
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/stig-override`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    msgEl.textContent = '✓ Saved';
    msgEl.className = 'stig-override-msg stig-override-ok';
    await done();
  } catch (e) {
    msgEl.textContent = `Error: ${e.message}`;
    msgEl.className = 'stig-override-msg stig-override-err';
  }
}

// Re-render the roll-up (the project status may have changed) and reopen the same control
async function refreshAndReopen(slug, vulnId) {
  closeFindingDetail();
  await renderProjectStig(_projectId);
  for (const [key, { c, st }] of _rollupControls) {
    if (c.vuln_id === vulnId && c.parts.some(p => p.slug === slug)) { openProjectControl(key); break; }
  }
}

export function saveProjectPartEdit(scanId, slug, vulnId, seq, idx) {
  const el = k => document.getElementById(`pd-${k}-${seq}-${idx}`);
  return patchOverride(scanId, {
    slug, vuln_id: vulnId, status: el('status').value, evidence: el('evid').value.trim(), justification: el('just').value.trim(),
  }, el('msg'), () => refreshAndReopen(slug, vulnId));
}

export function discardProjectPartEdit(scanId, slug, vulnId) {
  const msg = document.querySelector('.finding-drawer .stig-override-msg') || document.createElement('span');
  return patchOverride(scanId, { slug, vuln_id: vulnId, status: 'Open', justification: '', clear_lock: true },
    msg, () => refreshAndReopen(slug, vulnId));
}

export function openProjectControl(key) {
  const entry = _rollupControls.get(key);
  if (!entry) return;
  const { c, st } = entry;
  closeFindingDetail();
  const sev = (c.severity || 'unknown').toLowerCase();
  const partHtml = c.parts.map((p, idx) => {
    const d = p.detail || {};
    const role = ROLE_LABEL[p.role] || p.role;
    if (p.required === false) {
      return `<section class="finding-detail-section" style="margin-top:16px;opacity:.6">
        <div class="finding-detail-label">${esc(p.app)} (${esc(role)}) · not required for this control</div></section>`;
    }
    const missing = p.status === 'missing';
    const conf = d.confidence ?? 0;
    return `<section class="finding-detail-section" style="margin-top:16px;border:1px solid var(--border);border-radius:8px;padding:12px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
        <strong>${esc(p.app)} <span style="opacity:.7">(${esc(role)})</span></strong>
        ${missing ? '<span class="stig-status-nr">Not scanned</span>' : statusPill(p.status)}
      </div>
      ${missing ? '<p style="font-size:13px;color:var(--text-muted)">This repository has no result for this control yet.</p>' : `
      <div class="finding-detail-label" style="margin-top:10px">Evidence</div>
      <div style="font-size:13px;line-height:1.6">${esc(p.evidence || 'No evidence recorded.').replace(/\n/g, '<br>')}</div>
      ${d.justification ? `<div class="finding-detail-label" style="margin-top:10px">Justification</div><div style="font-size:13px">${esc(d.justification)}</div>` : ''}
      <div style="font-size:12px;color:var(--text-muted);margin-top:8px">Confidence ${esc(conf)}/100${d.locked_by_human ? ' · 🔒 edited by a reviewer' : ''}</div>
      ${stigRecordHtml(d)}
      ${p.scan_id ? partEditHtml(p, { ...d, vuln_id: c.vuln_id }, idx, key) : ''}
      ${p.scan_id ? `<div style="margin-top:10px"><a class="btn btn-sm" href="#/stig-viewer/${encodeURIComponent(p.scan_id)}">Open in ${esc(p.app)} STIG viewer</a></div>` : ''}`}
    </section>`;
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
  drawer.setAttribute('aria-label', 'Project STIG control details');
  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id)}</h2>
        <div class="finding-drawer-badges">
          <span class="stig-sev stig-sev-${esc(sev)}">${ucFirst(sev)}</span>
          ${statusPill(c.status)}
          <code style="font-size:12px">${esc(svNumber(c))}</code>
          <span style="font-size:12px;color:var(--text-muted)">${esc(st.stig_name)}${st.release_info ? ` ${esc(st.release_info)}` : ''}</span>
        </div>
      </div>
      <button class="finding-drawer-close" ${act('closeFindingDetail')} aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div style="font-size:13px;color:var(--text-muted)">${esc(c.reason)}</div>
      <h3 style="margin:18px 0 0;font-size:14px">Project parts</h3>
      ${partHtml}
      <div class="finding-detail-section" style="margin-top:20px">
        <div class="finding-detail-label">Check Content</div>
        <div class="stig-check" style="margin-top:6px">${esc(c.check_content || '—').replace(/\n/g, '<br>')}</div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Remediation</div>
        <div style="margin-top:6px;font-size:13px;line-height:1.6">${esc(c.fix_text || '—').replace(/\n/g, '<br>')}</div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
}

export async function renderProjectStig(id) {
  _projectId = id;
  setActive('projects');
  const page = document.getElementById('page');
  page.innerHTML = loading();
  let data;
  try {
    data = await api.getProjectStigRollup(id);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
    return;
  }
  const sources = data.components.map(c => `
    <span class="app-type-badge evaluation">${esc(c.app)} <span style="opacity:.7">· ${esc(ROLE_LABEL[c.role] || c.role)}</span>
      ${c.scan_id ? `· ${esc((c.timestamp || '').slice(0, 10))}` : '· no STIG scan yet'}</span>`).join(' ');
  _rollupControls.clear();
  const tables = data.stigs.map(st => `
    <div class="section">
      <div class="section-title">${esc(st.stig_name)} ${st.release_info ? `<small style="color:var(--text-dim)">${esc(st.release_info)}</small>` : ''}</div>
      <div class="stig-counts" style="margin-bottom:12px">
        <div class="stig-count open"><span class="num">${esc(st.totals.open)}</span><span class="lbl">Open</span></div>
        <div class="stig-count pass"><span class="num">${esc(st.totals.pass)}</span><span class="lbl">Not a Finding</span></div>
        <div class="stig-count na"><span class="num">${esc(st.totals.na)}</span><span class="lbl">Not Applicable</span></div>
        <div class="stig-count"><span class="num">${esc(st.totals.nr)}</span><span class="lbl">Evidence needed</span></div>
        <div class="stig-count total"><span class="num">${esc(st.totals.total)}</span><span class="lbl">Total</span></div>
      </div>
      <table class="data-table"><thead><tr><th>Control (SV)</th><th>Title</th><th>Project</th><th>Parts</th></tr></thead><tbody>
        ${st.controls.map(c => { const key = _rollupSeq++; _rollupControls.set(key, { c, st }); return `<tr style="cursor:pointer" ${act('openProjectControl', key)}>
          <td style="white-space:nowrap">${esc(svNumber(c))}</td><td>${esc(c.title)}</td>
          <td>${statusPill(c.status)}<div style="font-size:12px;color:var(--text-muted);margin-top:4px">${esc(c.reason)}</div></td>
          <td>${c.parts.map(p => p.required === false
            ? `<div style="white-space:nowrap;opacity:.55" title="Not required for this control by configuration/stig-policy/project-roles.json">${esc(p.app)} <span>(${esc(ROLE_LABEL[p.role] || p.role)})</span> not required</div>`
            : `<div style="white-space:nowrap">${esc(p.app)} <span style="opacity:.7">(${esc(ROLE_LABEL[p.role] || p.role)})</span> ${statusPill(p.status)}</div>`).join('')}</td>
        </tr>`; }).join('')}
      </tbody></table>
    </div>`).join('');
  page.innerHTML = `
    ${pageHeader(`${data.project.name} — STIG roll-up`, {
      subtitle: 'A control is Not a Finding only when every repository in the project satisfies its part. Uses each repository\'s latest STIG scan.',
      actions: '<a class="btn" href="#/projects">← Projects</a>',
    })}
    ${data.policy_error ? `<div style="margin-bottom:12px;padding:10px 12px;border:1px solid var(--border);border-left:3px solid var(--stig-open);border-radius:6px;font-size:13px">Role policy not applied: ${esc(data.policy_error)}</div>` : ''}
    <div style="margin-bottom:16px;display:flex;flex-wrap:wrap;gap:8px">${sources}</div>
    ${data.external && data.external.length ? `<div style="margin:-6px 0 16px;font-size:13px;color:var(--text-muted)">${externalBadges(data.external)}They are listed for the project and do not affect the roll-up.</div>` : ''}
    ${tables || emptyState('No STIG results yet', 'Run a STIG scan on the project repositories to see the roll-up.')}`;
}

function externalRow(x = { name: '', role: 'other', note: '' }) {
  return `
    <div class="project-external-row" style="display:flex;gap:8px;margin-bottom:8px">
      <input class="field-input project-external-name" aria-label="Component name" maxlength="80" placeholder="e.g. Keycloak" value="${esc(x.name)}" style="flex:2">
      <select class="field-input project-external-role" style="flex:1">
        ${_roles.map(r => `<option value="${esc(r)}"${r === x.role ? ' selected' : ''}>${esc(ROLE_LABEL[r] || r)}</option>`).join('')}
      </select>
      <input class="field-input project-external-note" aria-label="Note" maxlength="200" placeholder="Note (optional)" value="${esc(x.note || '')}" style="flex:2">
      <button class="btn" type="button" ${act('removeProjectExternalRow', ARG.el)} aria-label="Remove component">✕</button>
    </div>`;
}

function repoRow(repo = { app: '', role: 'other' }) {
  return `
    <div class="project-repo-row" style="display:flex;gap:8px;margin-bottom:8px">
      <select class="field-input project-repo-app" aria-label="Application" style="flex:2">
        <option value="">Select an application…</option>
        ${[...new Set([..._appNames, ...(repo.app ? [repo.app] : [])])].map(n => `<option value="${esc(n)}"${n === repo.app ? ' selected' : ''}>${esc(n)}</option>`).join('')}
      </select>
      <select class="field-input project-repo-role" style="flex:1">
        ${_roles.map(r => `<option value="${esc(r)}"${r === repo.role ? ' selected' : ''}>${esc(ROLE_LABEL[r] || r)}</option>`).join('')}
      </select>
      <button class="btn" type="button" ${act('removeProjectRepoRow', ARG.el)} aria-label="Remove repository">✕</button>
    </div>`;
}

export function showProjectModal(id) {
  const project = _projects.find(p => p.id === id) || { name: '', description: '', jira_project_key: '', repos: [] };
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.id = 'project-modal';
  overlay.innerHTML = `
    <div class="modal-container modal-md" role="dialog" aria-modal="true" aria-label="${id ? 'Edit' : 'New'} project">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h2 style="color:var(--text);margin:0">${id ? 'Edit project' : 'New project'}</h2>
        <button class="btn" ${act('closeProjectModal')} style="padding:6px 12px" aria-label="Close">✕</button>
      </div>
      <input type="hidden" id="project-id" value="${esc(id || '')}">
      <div style="margin-bottom:14px">
        <label class="field-label" for="project-name">Name</label>
        <input id="project-name" class="field-input" maxlength="80" placeholder="e.g. Customer Portal" value="${esc(project.name)}"${id ? ' readonly' : ''}>
      </div>
      <div style="margin-bottom:14px">
        <label class="field-label" for="project-desc">Description (optional)</label>
        <input id="project-desc" class="field-input" maxlength="500" value="${esc(project.description)}">
      </div>
      <div style="margin-bottom:14px">
        <label class="field-label" for="project-jira">Jira board (project key, optional)</label>
        <input id="project-jira" class="field-input" maxlength="10" placeholder="MID" value="${esc(project.jira_project_key)}"
          ${actOn('input', 'upperAlnumInput', ARG.el)}>
      </div>
      <div style="margin-bottom:14px">
        <label class="field-label">Repositories and roles</label>
        <div id="project-repo-rows">${(project.repos.length ? project.repos : [undefined, undefined]).map(r => repoRow(r)).join('')}</div>
        <button class="btn" type="button" ${act('addProjectRepoRow')}>+ Add repository</button>
      </div>
      <div style="margin-bottom:14px">
        <label class="field-label">Third-party components (no STIG)</label>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px">Software you depend on but cannot assess, such as an identity provider or a vendor API. Listed on the project; they never block the roll-up.</div>
        <div id="project-external-rows">${(project.external || []).map(x => externalRow(x)).join('')}</div>
        <button class="btn" type="button" ${act('addProjectExternalRow')}>+ Add third-party component</button>
      </div>
      <div id="project-modal-error" style="color:var(--critical);font-size:13px;margin-bottom:10px" role="alert"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button class="btn" ${act('closeProjectModal')}>Cancel</button>
        <button class="btn btn-primary" ${act('saveProject')}>Save</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  (document.getElementById(id ? 'project-desc' : 'project-name'))?.focus();
}

export function closeProjectModal() {
  document.getElementById('project-modal')?.remove();
}

export function addProjectRepoRow() {
  document.getElementById('project-repo-rows')?.insertAdjacentHTML('beforeend', repoRow());
}

export function addProjectExternalRow() {
  document.getElementById('project-external-rows')?.insertAdjacentHTML('beforeend', externalRow());
}

export function removeProjectExternalRow(btn) {
  btn?.closest('.project-external-row')?.remove();
}

export function removeProjectRepoRow(btn) {
  btn?.closest('.project-repo-row')?.remove();
}

export async function saveProject() {
  const id = document.getElementById('project-id').value;
  const repos = [...document.querySelectorAll('.project-repo-row')]
    .map(row => ({
      app: row.querySelector('.project-repo-app').value.trim(),
      role: row.querySelector('.project-repo-role').value,
    }))
    .filter(r => r.app);
  const body = {
    name: document.getElementById('project-name').value.trim(),
    description: document.getElementById('project-desc').value.trim(),
    jira_project_key: document.getElementById('project-jira').value.trim(),
    repos,
    external: [...document.querySelectorAll('.project-external-row')]
      .map(row => ({
        name: row.querySelector('.project-external-name').value.trim(),
        role: row.querySelector('.project-external-role').value,
        note: row.querySelector('.project-external-note').value.trim(),
      }))
      .filter(x => x.name),
  };
  try {
    await (id ? api.updateProject(id, body) : api.createProject(body));
  } catch (e) {
    document.getElementById('project-modal-error').textContent = e.detail || e.message;
    return;
  }
  closeProjectModal();
  toast(id ? 'Project updated' : 'Project created', 'success');
  renderProjects();
}

export async function deleteProject(id) {
  const p = _projects.find(x => x.id === id);
  const ok = await confirmDialog({
    title: 'Delete project?',
    body: `${p ? p.name : id} will be removed. Its repositories and scans are not affected.`,
    confirmLabel: 'Delete',
  });
  if (!ok) return;
  try {
    await api.deleteProject(id);
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  renderProjects();
}
