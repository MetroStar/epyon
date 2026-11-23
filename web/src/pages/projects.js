import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { confirmDialog, toast } from '../components/feedback.js';
import { api } from '../lib/api.js';
import { esc, act, actOn, ARG } from '../lib/format.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

let _projects = [];
let _roles = ['frontend', 'backend', 'infra', 'other'];
let _appNames = [];

const ROLE_LABEL = { frontend: 'Frontend', backend: 'Backend', infra: 'Infrastructure', other: 'Other' };

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

export async function renderProjectStig(id) {
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
      <table class="data-table"><thead><tr><th>Control</th><th>Title</th><th>Project</th><th>Parts</th></tr></thead><tbody>
        ${st.controls.map(c => `<tr>
          <td>${esc(c.vuln_id)}</td><td>${esc(c.title)}</td>
          <td>${statusPill(c.status)}<div style="font-size:12px;color:var(--text-muted);margin-top:4px">${esc(c.reason)}</div></td>
          <td>${c.parts.map(p => `<div style="white-space:nowrap">${esc(p.app)} <span style="opacity:.7">(${esc(ROLE_LABEL[p.role] || p.role)})</span> ${statusPill(p.status)}</div>`).join('')}</td>
        </tr>`).join('')}
      </tbody></table>
    </div>`).join('');
  page.innerHTML = `
    ${pageHeader(`${data.project.name} — STIG roll-up`, {
      subtitle: 'A control is Not a Finding only when every repository in the project satisfies its part. Uses each repository\'s latest STIG scan.',
      actions: '<a class="btn" href="#/projects">← Projects</a>',
    })}
    <div style="margin-bottom:16px;display:flex;flex-wrap:wrap;gap:8px">${sources}</div>
    ${tables || emptyState('No STIG results yet', 'Run a STIG scan on the project repositories to see the roll-up.')}`;
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
        <input id="project-name" class="field-input" maxlength="80" placeholder="ATO Ready" value="${esc(project.name)}"${id ? ' readonly' : ''}>
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
