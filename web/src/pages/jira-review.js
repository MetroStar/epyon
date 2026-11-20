import { sevBadge } from '../components/badges.js';
import { toast } from '../components/feedback.js';
import { errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { upperAlnumInput } from '../core/ui-helpers.js';
import { esc, ucFirst, act, actOn, ARG } from '../lib/format.js';
import { _findingsRegistry, _registerFinding, _stigJiraSel, _stigRegistry } from '../state/registries.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

let _jiraReviewState = null;
let _jiraEpicModalState = null;

// ── Manual Jira ticket review ────────────────────────────────
export async function renderJiraReview(scanId) {
  setActive('');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const data = await api.getJiraCandidates(scanId);
    _jiraReviewState = {
      scanId,
      data,
      selected: new Set(),
      submitting: false,
    };
    renderJiraReviewPage();
  } catch (error) {
    page.innerHTML = errBanner(error.message);
  }
}

export function jiraReviewFilteredCandidates() {
  if (!_jiraReviewState) return [];
  const category = document.getElementById('jira-review-category')?.value || 'all';
  const severity = document.getElementById('jira-review-severity')?.value || 'all';
  const tool = document.getElementById('jira-review-tool')?.value || 'all';
  const query = (document.getElementById('jira-review-search')?.value || '').trim().toLowerCase();
  return _jiraReviewState.data.candidates.filter(candidate => {
    if (category !== 'all' && candidate.category !== category) return false;
    if (severity !== 'all' && candidate.severity !== severity) return false;
    if (tool !== 'all' && candidate.tool !== tool) return false;
    if (!query) return true;
    return [candidate.id, candidate.title, candidate.package, candidate.target, candidate.tool]
      .some(value => String(value || '').toLowerCase().includes(query));
  });
}

export function renderJiraReviewPage() {
  const state = _jiraReviewState;
  if (!state) return;
  const page = document.getElementById('page');
  const { data } = state;
  const tools = [...new Set(data.candidates.map(candidate => candidate.tool).filter(Boolean))].sort();

  page.innerHTML = `
    <div class="breadcrumb">
      <a href="#/scans/${encodeURIComponent(state.scanId)}">Scan Details</a>
      <span>›</span><span>Jira Review</span>
    </div>
    ${pageHeader(`Jira Ticket Review`, { subtitle: `${esc(data.app_name)} · ${esc(state.scanId)}`, actions: `<button class="btn" ${act('navigate', `#/scans/${encodeURIComponent(state.scanId)}`)}>Back to Scan</button>` })}
    <div class="jira-review-project">
      <div>
        <label class="field-label" for="jira-review-project-key">Jira project for ${esc(data.app_name)}</label>
        <div class="jira-review-subtitle">This key applies to this application and all of its scans.</div>
      </div>
      <input id="jira-review-project-key" class="field-input" type="text" maxlength="10"
        placeholder="PROJECT" value="${esc(data.project_key || '')}"
        ${actOn('input', 'upperAlnumInput', ARG.el)}>
      <button id="jira-review-project-save" class="btn" ${act('jiraReviewSaveProject')}>Save Project</button>
      <button id="jira-review-reassign" class="btn" ${act('jiraReviewCheckDeleted')}
        title="Detect tickets whose Jira issue was deleted and recreate them"
        ${data.jira_configured ? '' : 'disabled'}>Check for Deleted Tickets</button>
    </div>
    <div id="jira-review-reassign-status" class="jira-review-subtitle"></div>
    ${data.jira_configured ? '' : `
      <div class="alert alert-warning jira-review-config">
        Jira credentials and an application project key are required. Review is available, but ticket creation is disabled.
        <a href="#/settings">Open Settings</a>
      </div>`}
    <div class="jira-review-toolbar" aria-label="Finding filters">
      <label>Category
        <select id="jira-review-category" ${actOn('change','jiraReviewRefresh')}>
          <option value="all">All categories</option>
          <option value="vulnerability">Vulnerabilities</option>
          <option value="misconfiguration">Misconfigurations</option>
          <option value="ml">ML/AI Security</option>
        </select>
      </label>
      <label>Severity
        <select id="jira-review-severity" ${actOn('change','jiraReviewRefresh')}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
      </label>
      <label>Tool
        <select id="jira-review-tool" ${actOn('change','jiraReviewRefresh')}>
          <option value="all">All tools</option>
          ${tools.map(tool => `<option value="${esc(tool)}">${esc(tool)}</option>`).join('')}
        </select>
      </label>
      <label class="jira-review-search">Search
        <input id="jira-review-search" type="search" placeholder="ID, package, location"
          ${actOn('input','jiraReviewRefresh')}>
      </label>
    </div>
    <div class="jira-review-category-actions">
      <button class="btn btn-sm" ${act('jiraReviewSelectCategory', 'vulnerability')}>Select vulnerabilities</button>
      <button class="btn btn-sm" ${act('jiraReviewSelectCategory', 'misconfiguration')}>Select misconfigurations</button>
      <button class="btn btn-sm" ${act('jiraReviewSelectCategory', 'ml')}>Select ML/AI</button>
      <button class="btn btn-sm" ${act('jiraReviewClearSelection')}>Clear selection</button>
    </div>
    <div class="table-container jira-review-table-wrap">
      <table class="jira-review-table">
        <thead><tr>
          <th scope="col" class="jira-review-check"><input id="jira-review-select-all" type="checkbox"
            aria-label="Select all filtered findings" ${actOn('change','jiraReviewToggleAll', ARG.checked)}></th>
          <th scope="col">Category</th><th scope="col">Severity</th><th scope="col">Tool</th><th scope="col">Finding</th>
          <th scope="col">Package / Target</th><th scope="col">Status</th>
        </tr></thead>
        <tbody id="jira-review-rows"></tbody>
      </table>
    </div>
    <div class="jira-review-actionbar">
      <div><strong id="jira-review-selected-count">0 selected</strong>
        <span id="jira-review-visible-count" class="jira-review-subtitle"></span></div>
      <button id="jira-review-create" class="btn btn-primary" ${act('jiraReviewCreateTickets')}
        ${data.jira_configured ? '' : 'disabled title="Configure Jira in Settings first"'}>
        Create Jira Tickets
      </button>
    </div>`;
  jiraReviewRefresh();
}

export function jiraReviewRefresh() {
  const state = _jiraReviewState;
  if (!state) return;
  const candidates = jiraReviewFilteredCandidates();
  const rows = document.getElementById('jira-review-rows');
  rows.innerHTML = candidates.length ? candidates.map(candidate => {
    const detailId = _registerFinding(candidate);
    const selected = state.selected.has(candidate.fingerprint);
    const ticket = candidate.jira_ticket?.issue_key;
    const reason = candidate.selection_reason === 'suppressed'
      ? 'Suppressed' : candidate.selection_reason === 'already_ticketed'
        ? (ticket || 'Ticketed') : 'Ready';
    const location = candidate.package || candidate.target || '—';
    return `<tr class="jira-review-row${candidate.selectable ? '' : ' is-disabled'}"
        data-fingerprint="${esc(candidate.fingerprint)}">
      <td class="jira-review-check"><input type="checkbox" ${selected ? 'checked' : ''}
        ${candidate.selectable ? '' : 'disabled'} aria-label="Select ${esc(candidate.id || candidate.title)}"></td>
      <td>${esc(candidate.category === 'ml' ? 'ML/AI' : ucFirst(candidate.category))}</td>
      <td>${sevBadge(candidate.severity || 'low')}</td>
      <td><span class="tool-tag">${esc(candidate.tool || 'Unknown')}</span></td>
      <td><button class="jira-review-finding-link" ${act('openFindingDetail', detailId)}>
        ${esc(candidate.id || candidate.title || 'Finding')}</button>
        <div class="jira-review-title">${esc(candidate.title || '')}</div></td>
      <td title="${esc(candidate.target || '')}">${esc(location)}</td>
      <td>${ticket && state.data.jira_base_url
        ? `<a href="${esc(state.data.jira_base_url)}/browse/${esc(ticket)}" target="_blank" rel="noopener">${esc(ticket)}</a>`
        : esc(reason)}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="7" class="jira-review-empty">No findings match these filters.</td></tr>';

  rows.querySelectorAll('tr[data-fingerprint]').forEach(row => {
    const checkbox = row.querySelector('input[type="checkbox"]');
    if (!checkbox || checkbox.disabled) return;
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) state.selected.add(row.dataset.fingerprint);
      else state.selected.delete(row.dataset.fingerprint);
      jiraReviewUpdateSelection(candidates);
    });
  });
  jiraReviewUpdateSelection(candidates);
}

export function jiraReviewUpdateSelection(filtered = jiraReviewFilteredCandidates()) {
  const state = _jiraReviewState;
  if (!state) return;
  const selectable = filtered.filter(candidate => candidate.selectable);
  const selectedVisible = selectable.filter(candidate => state.selected.has(candidate.fingerprint)).length;
  const selectAll = document.getElementById('jira-review-select-all');
  if (selectAll) {
    selectAll.checked = selectable.length > 0 && selectedVisible === selectable.length;
    selectAll.indeterminate = selectedVisible > 0 && selectedVisible < selectable.length;
    selectAll.disabled = selectable.length === 0;
  }
  document.getElementById('jira-review-selected-count').textContent = `${state.selected.size} selected`;
  document.getElementById('jira-review-visible-count').textContent = ` · ${filtered.length} visible`;
  const createButton = document.getElementById('jira-review-create');
  createButton.disabled = !state.data.jira_configured || state.selected.size === 0 || state.submitting;
}

export function jiraReviewToggleAll(checked) {
  const state = _jiraReviewState;
  jiraReviewFilteredCandidates().filter(candidate => candidate.selectable).forEach(candidate => {
    if (checked) state.selected.add(candidate.fingerprint);
    else state.selected.delete(candidate.fingerprint);
  });
  jiraReviewRefresh();
}

export function jiraReviewSelectCategory(category) {
  const state = _jiraReviewState;
  state.data.candidates.filter(candidate => candidate.category === category && candidate.selectable)
    .forEach(candidate => state.selected.add(candidate.fingerprint));
  jiraReviewRefresh();
}

export function jiraReviewClearSelection() {
  _jiraReviewState?.selected.clear();
  jiraReviewRefresh();
}

export async function jiraReviewSaveProject() {
  const state = _jiraReviewState;
  if (!state || state.submitting) return;
  const input = document.getElementById('jira-review-project-key');
  const button = document.getElementById('jira-review-project-save');
  const projectKey = input.value.trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9]{0,9}$/.test(projectKey)) {
    toast('Project key must be 1-10 uppercase letters or numbers and start with a letter.', 'warning');
    input.focus();
    return;
  }
  button.disabled = true;
  button.textContent = 'Saving…';
  try {
    await api.setJiraProject(state.scanId, projectKey);
    await renderJiraReview(state.scanId);
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Save Project';
    toast(`Could not save Jira project: ${error.message}`, 'error');
  }
}

export async function jiraReviewCheckDeleted() {
  const state = _jiraReviewState;
  if (!state || state.submitting) return;
  const button = document.getElementById('jira-review-reassign');
  button.disabled = true;
  button.textContent = 'Checking…';
  const prevStatusEl = document.getElementById('jira-review-reassign-status');
  if (prevStatusEl) prevStatusEl.textContent = '';
  let message = '';
  let isError = false;
  try {
    const result = await api.reassignJiraTickets(state.data.app_name);
    message = result.reassigned.length
      ? `Checked ${result.checked} ticket(s) — ${result.reassigned.length} deleted ticket(s) reset to unsubmitted: ` +
        result.reassigned.map(r => r.old).join(', ') + '. You can manually re-submit them below.'
      : `Checked ${result.checked} ticket(s) — none were deleted.`;
    if (result.errors && result.errors.length) {
      message += ` ${result.errors.length} error(s): ${result.errors.join('; ')}`;
      isError = true;
    }
    // renderJiraReview() fully replaces the page DOM (including this status
    // element) to reload the refreshed candidate/ticket list, so the status
    // text must be (re-)applied to the *new* element afterwards — setting it
    // beforehand gets silently wiped out by the re-render.
    await renderJiraReview(state.scanId);
  } catch (error) {
    message = `Error: ${error.message}`;
    isError = true;
  } finally {
    const statusEl = document.getElementById('jira-review-reassign-status');
    if (statusEl) {
      statusEl.textContent = message;
      statusEl.style.color = isError ? 'var(--critical)' : '';
    }
    const freshButton = document.getElementById('jira-review-reassign');
    if (freshButton) {
      freshButton.disabled = false;
      freshButton.textContent = 'Check for Deleted Tickets';
    }
  }
}

export async function jiraReviewCreateTickets() {
  const state = _jiraReviewState;
  if (!state || state.submitting || state.selected.size === 0) return;
  await showJiraEpicModal();
}

// Set when the modal is opened from the finding drawer instead of the Jira review page.
let _jiraQuickCtx = null;

export function jiraEpicModalConfirm() {
  if (_jiraQuickCtx) return jiraQuickCreateConfirmed();
  return jiraReviewCreateTicketsConfirmed();
}

export async function showJiraEpicModal(quickCtx = null) {
  _jiraQuickCtx = quickCtx;
  const state = quickCtx ? { scanId: quickCtx.scanId } : _jiraReviewState;
  if (!state) return;
  const selectedCount = quickCtx ? 1 : state.selected.size;
  const projectKey = quickCtx ? quickCtx.projectKey : (state.data.project_key || '');

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container modal-md">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h2 style="color:var(--text);margin:0">Create Jira Ticket${selectedCount === 1 ? '' : 's'}</h2>
        <button class="btn" ${act('jiraEpicModalClose')} style="padding:6px 12px">✕</button>
      </div>
      <p style="color:var(--text-muted);font-size:13px;margin:0 0 16px">
        Creating ${selectedCount} ticket${selectedCount === 1 ? '' : 's'} for this scan. Confirm the Jira project,
        pick a ticket type, and optionally an Epic to link to.
      </p>
      <div style="margin-bottom:14px">
        <label class="field-label" for="jira-modal-project-key">Jira project (board key)</label>
        <div style="display:flex;gap:8px">
          <input id="jira-modal-project-key" class="field-input" type="text" maxlength="10" placeholder="PROJECT"
            value="${esc(projectKey)}" ${quickCtx ? '' : 'readonly'}
            ${actOn('input', 'jiraModalProjectTyped', ARG.el)}>
          ${quickCtx ? `<button id="jira-modal-project-save" class="btn" ${act('jiraModalProjectSave')} disabled>Change</button>` : ''}
        </div>
        <div id="jira-modal-project-note" style="font-size:12px;color:var(--text-muted);margin-top:4px">
          ${quickCtx
            ? 'Changing this updates the Jira project for this whole application (same as the Jira Review page).'
            : 'To use a different project, change it on this page before selecting findings.'}
        </div>
      </div>
      <div id="jira-epic-modal-body">${loading()}</div>
      <div class="modal-actions" style="margin-top:20px;display:flex;justify-content:flex-end;gap:10px">
        <button class="btn" ${act('jiraEpicModalClose')}>Cancel</button>
        <button id="jira-epic-modal-confirm" class="btn btn-primary" ${act('jiraEpicModalConfirm')}>
          Create Ticket${selectedCount === 1 ? '' : 's'}
        </button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) jiraEpicModalClose(); });
  if (quickCtx && !projectKey) {
    document.getElementById('jira-epic-modal-confirm').disabled = true;
    document.getElementById('jira-modal-project-note').textContent =
      'No Jira board is set for this application. Enter a project key and click Change to continue.';
  }
  await jiraEpicModalLoad(state.scanId);
}

export async function openStigJiraModal(scanId, regKeys) {
  const keys = regKeys || [..._stigJiraSel];
  const controls = keys.map(k => _stigRegistry.get(k)?.c).filter(Boolean);
  if (!controls.length) return;
  document.querySelector('.modal-overlay')?.remove();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-container modal-md"><div id="stig-jira-body">${loading()}</div></div>`;
  document.body.appendChild(overlay);
  const body = overlay.querySelector('#stig-jira-body');
  let ctx;
  try {
    ctx = await api.getStigJiraContext(scanId);
  } catch (e) {
    body.innerHTML = `<p style="color:var(--critical)">${esc(e.message)}</p><button class="btn" ${act('stigJiraClose')}>Close</button>`;
    return;
  }
  if (!ctx.jira_configured) {
    body.innerHTML = `<p style="color:var(--text)">Jira is not configured. Set it up on the Jira page first.</p><button class="btn" ${act('stigJiraClose')}>Close</button>`;
    return;
  }
  const n = controls.length;
  body.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2 style="color:var(--text);margin:0">Add ${n} STIG control${n === 1 ? '' : 's'} to Jira</h2>
      <button class="btn" ${act('stigJiraClose')} style="padding:6px 12px">✕</button>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-jira-project">Jira board (project key)</label>
      <input id="stig-jira-project" class="field-input" list="stig-jira-projects" maxlength="10" value="${esc(ctx.project_key)}"
        placeholder="MID, SAP, IRIS…" ${actOn('input', 'upperAlnumInput', ARG.el)} ${actOn('change','stigJiraProjectChanged', scanId)}>
      <datalist id="stig-jira-projects">${(ctx.known_projects || []).map(k => `<option value="${esc(k)}">`).join('')}</datalist>
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Tickets are created in this board. This does not change the application's saved board.</div>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-jira-type">Issue type</label>
      <select id="stig-jira-type" class="field-input"><option value="">Default</option></select>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-jira-epic">Epic (optional)</label>
      <select id="stig-jira-epic" class="field-input"><option value="">None</option></select>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-jira-tracker">Tracking ticket (optional)</label>
      <input id="stig-jira-tracker" class="field-input" maxlength="20" placeholder="e.g. MID-123"
        ${actOn('input', 'upperInput', ARG.el)}>
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Links each new ticket to this one. Must be in the chosen board.</div>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-jira-by">Triaged by (optional)</label>
      <input id="stig-jira-by" class="field-input" maxlength="100">
    </div>
    <div id="stig-jira-result" style="font-size:13px;margin-bottom:10px"></div>
    <div style="display:flex;justify-content:flex-end;gap:10px">
      <button class="btn" ${act('stigJiraClose')}>Close</button>
      <button id="stig-jira-submit" class="btn btn-primary">Create ticket${n === 1 ? '' : 's'}</button>
    </div>`;
  const fill = async () => {
    const pk = document.getElementById('stig-jira-project')?.value.trim();
    const typeSel = document.getElementById('stig-jira-type');
    const epicSel = document.getElementById('stig-jira-epic');
    if (!pk || !typeSel) return;
    try {
      const e = await api.getScanJiraEpics(scanId, pk);
      typeSel.innerHTML = '<option value="">Default</option>' +
        (e.issue_types || []).map(t => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join('');
      epicSel.innerHTML = '<option value="">None</option>' +
        (e.existing || []).map(x => `<option value="${esc(x.key)}">${esc(x.key)} — ${esc(x.summary || x.name || '')}</option>`).join('');
    } catch (_) { /* pickers stay at defaults */ }
  };
  window.stigJiraProjectChanged = fill;
  document.getElementById('stig-jira-submit').onclick = async () => {
    const btn = document.getElementById('stig-jira-submit');
    const out = document.getElementById('stig-jira-result');
    const val = id => document.getElementById(id).value.trim();
    const project = val('stig-jira-project');
    if (!project) { out.style.color = 'var(--critical)'; out.textContent = 'Choose a Jira board.'; return; }
    btn.disabled = true; btn.textContent = 'Creating…';
    try {
      const res = await api.createStigJiraTickets(scanId, {
        controls: controls.map(c => ({ slug: c._slug, vuln_id: c.vuln_id })),
        project_key: project,
        epic_key: val('stig-jira-epic') || null,
        issue_type: val('stig-jira-type') || null,
        tracker_key: val('stig-jira-tracker') || null,
        triaged_by: val('stig-jira-by') || null,
      });
      const link = t => {
        const href = ctx.jira_base_url ? `${ctx.jira_base_url}/browse/${encodeURIComponent(t.issue_key)}` : '';
        return href ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(t.issue_key)}</a>` : esc(t.issue_key);
      };
      const parts = [];
      if (res.created.length) parts.push(`Created in ${esc(res.project_key)}: ${res.created.map(link).join(', ')}`);
      if (res.already_exists.length) parts.push(`Already ticketed: ${res.already_exists.map(link).join(', ')}`);
      const bad = [...res.failed, ...res.ineligible];
      if (bad.length) parts.push(`Not created: ${bad.map(b => esc(`${b.vuln_id} (${b.reason})`)).join(', ')}`);
      out.style.color = bad.length ? 'var(--critical)' : 'var(--text)';
      out.innerHTML = parts.join('<br>');
      btn.textContent = 'Done';
      if (res.created.length) { _stigJiraSel.clear(); }
    } catch (e) {
      out.style.color = 'var(--critical)';
      out.textContent = `Ticket creation failed: ${e.message}`;
      btn.disabled = false; btn.textContent = 'Create tickets';
    }
  };
  fill();
}

export function openStigBulkLockModal(scanId) {
  const controls = [..._stigJiraSel].map(k => _stigRegistry.get(k)?.c).filter(Boolean);
  if (!controls.length) return;
  const n = controls.length;
  document.querySelector('.modal-overlay')?.remove();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal-container modal-md">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2 style="color:var(--text);margin:0">Lock / unlock ${n} STIG control${n === 1 ? '' : 's'}</h2>
      <button class="btn" ${act('stigJiraClose')} style="padding:6px 12px">✕</button>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-bulk-status">Status</label>
      <select id="stig-bulk-status" class="field-input">
        <option>Not a Finding</option><option>Not Applicable</option><option>Open</option><option>Not Reviewed</option>
      </select>
    </div>
    <div style="margin-bottom:14px">
      <label class="field-label" for="stig-bulk-just">Justification</label>
      <textarea id="stig-bulk-just" class="field-input" rows="3"
        placeholder="Leave blank to use each control's requirement as its justification"></textarea>
    </div>
    <div id="stig-bulk-result" style="font-size:13px;margin-bottom:10px"></div>
    <div style="display:flex;justify-content:flex-end;gap:10px">
      <button class="btn" ${act('stigJiraClose')}>Close</button>
      <button id="stig-bulk-unlock" class="btn" title="Remove the human lock so the next scan re-assesses these controls">Unlock ${n}</button>
      <button id="stig-bulk-submit" class="btn btn-primary">🔒 Lock ${n}</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) stigJiraClose(); });
  const run = async (clear) => {
    const btns = [document.getElementById('stig-bulk-submit'), document.getElementById('stig-bulk-unlock')];
    const out = document.getElementById('stig-bulk-result');
    const status = clear ? 'Open' : document.getElementById('stig-bulk-status').value;
    const shared = document.getElementById('stig-bulk-just').value.trim();
    btns.forEach(b => { b.disabled = true; });
    const updates = [], failed = [];
    for (let i = 0; i < controls.length; i++) {
      const c = controls[i];
      out.style.color = 'var(--text)';
      out.textContent = `${clear ? 'Unlocking' : 'Locking'} ${i + 1} of ${n}…`;
      const justification = clear ? '' : (shared || c.title || status);
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/stig-override`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ slug: c._slug, vuln_id: c.vuln_id, status, justification, clear_lock: clear }),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new Error(err.detail || res.statusText);
        }
        updates.push({ slug: c._slug, vulnId: c.vuln_id, patch: clear
          ? { status: 'Open', confidence: 0, locked_by_human: false, evidence: '' }
          : { status, confidence: 95, locked_by_human: true, evidence: `[Human override] ${justification}\n` } });
        _stigJiraSel.delete(`${c.vuln_id}__${c._slug}`);
      } catch (e) {
        failed.push(`${c.vuln_id} (${e.message})`);
      }
    }
    window.updateStigControlsInPlace?.(updates);
    out.style.color = failed.length ? 'var(--critical)' : 'var(--text)';
    out.textContent = `${clear ? 'Unlocked' : 'Locked'} ${updates.length} of ${n}.` + (failed.length ? ` Failed: ${failed.join(', ')}` : '');
    if (!failed.length) setTimeout(stigJiraClose, 800);
    else { btns.forEach(b => { b.disabled = false; }); }
  };
  document.getElementById('stig-bulk-submit').onclick = () => run(false);
  document.getElementById('stig-bulk-unlock').onclick = () => run(true);
}

export function stigJiraClose() {
  document.querySelector('.modal-overlay')?.remove();
}

export function jiraEpicModalClose() {
  document.querySelector('.modal-overlay')?.remove();
  _jiraQuickCtx = null;
}

export async function jiraEpicModalLoad(scanId) {
  const body = document.getElementById('jira-epic-modal-body');
  if (body) body.innerHTML = loading();
  try {
    const epics = await api.getScanJiraEpics(scanId);
    _jiraEpicModalState = {
      existing: epics.existing || [],
      suggested: epics.suggested || [],
      choice: null,
      issueTypes: epics.issue_types || [],
      defaultIssueType: epics.default_issue_type || 'Bug',
      issueType: epics.default_issue_type || 'Bug',
      triagedBy: '',
    };
    renderJiraEpicModalBody();
  } catch (error) {
    if (body) body.innerHTML =
      `<div class="alert alert-warning">Could not load existing Epics: ${esc(error.message)}. You can still create tickets unassigned or create a new Epic.</div>`;
    _jiraEpicModalState = {
      existing: [], suggested: [], choice: null,
      issueTypes: [], defaultIssueType: 'Bug', issueType: 'Bug',
      triagedBy: '',
    };
    renderJiraEpicModalBody();
  }
}

export function jiraModalProjectTyped(input) {
  if (input) upperAlnumInput(input);
  const ctx = _jiraQuickCtx;
  if (!ctx) return;
  const key = document.getElementById('jira-modal-project-key').value.trim();
  const dirty = key !== ctx.projectKey;
  document.getElementById('jira-modal-project-save').disabled = !dirty || !/^[A-Z][A-Z0-9]{0,9}$/.test(key);
  document.getElementById('jira-epic-modal-confirm').disabled = dirty || !ctx.projectKey;
}

export async function jiraModalProjectSave() {
  const ctx = _jiraQuickCtx;
  if (!ctx) return;
  const input = document.getElementById('jira-modal-project-key');
  const saveBtn = document.getElementById('jira-modal-project-save');
  const note = document.getElementById('jira-modal-project-note');
  const key = input.value.trim().toUpperCase();
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';
  try {
    await api.setJiraProject(ctx.scanId, key);
    const data = await api.getJiraCandidates(ctx.scanId);
    const candidate = jiraFindCandidate(data.candidates, ctx.finding);
    ctx.projectKey = data.project_key || key;
    ctx.baseUrl = data.jira_base_url;
    ctx.fingerprint = candidate?.fingerprint || '';
    note.style.color = 'var(--text-muted)';
    if (!candidate || !candidate.selectable) {
      const ticket = candidate?.jira_ticket?.issue_key;
      jiraEpicModalClose();
      jiraQuickMarkDone(ticket, data.jira_base_url);
      if (!ticket) {
        const status = document.getElementById('finding-jira-status');
        if (status) status.textContent = 'This finding is not eligible for ticketing in that project.';
      }
      return;
    }
    await jiraEpicModalLoad(ctx.scanId);
    jiraModalProjectTyped();
  } catch (error) {
    note.style.color = 'var(--critical)';
    note.textContent = `Could not change project: ${error.message}`;
  } finally {
    saveBtn.textContent = 'Change';
    jiraModalProjectTyped();
  }
}

export function renderJiraEpicModalBody() {
  const body = document.getElementById('jira-epic-modal-body');
  if (!body) return;
  const state = _jiraEpicModalState;
  const hasIssueTypes = state.issueTypes.length > 0;
  body.innerHTML = `
    <div style="display:grid;gap:14px">
      <div>
        <label class="field-label">Ticket type</label>
        <select id="jira-issue-type-select" class="field-input" ${actOn('change','jiraEpicModalPickIssueType', ARG.value)}
          ${hasIssueTypes ? '' : 'disabled'}>
          ${hasIssueTypes
            ? state.issueTypes.map(t => `<option value="${esc(t.name)}" ${t.name === state.issueType ? 'selected' : ''}>${esc(t.name)}</option>`).join('')
            : `<option>${esc(state.defaultIssueType)}</option>`}
        </select>
        ${hasIssueTypes
          ? ''
          : `<div style="font-size:12px;color:var(--text-muted);margin-top:4px">Could not load this project's ticket types — using the configured default (${esc(state.defaultIssueType)}).</div>`}
      </div>
      <div>
        <label class="field-label">Use an existing Epic</label>
        <select id="jira-epic-existing-select" class="field-input" ${actOn('change','jiraEpicModalPickExisting', ARG.value)}>
          <option value="">— None —</option>
          ${state.existing.map(e => `<option value="${esc(e.key)}">${esc(e.key)} — ${esc(e.summary)}</option>`).join('')}
        </select>
        ${state.existing.length === 0 ? '<div style="font-size:12px;color:var(--text-muted);margin-top:4px">No existing Epics found in this project.</div>' : ''}
      </div>
      <div>
        <label class="field-label">Or create a new Epic</label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          ${state.suggested.map(s => `<button type="button" class="btn btn-sm" ${act('jiraEpicModalQuickCreate', s.name)}>${esc(s.label)}</button>`).join('')}
        </div>
        <input id="jira-epic-new-name" class="field-input" type="text" maxlength="200"
          placeholder="Custom Epic name…" ${actOn('input','jiraEpicModalTypedName', ARG.value)}>
      </div>
      <div>
        <label class="field-label">Triage note (optional)</label>
        <input id="jira-triaged-by-input" class="field-input" type="text" maxlength="200"
          placeholder="Your name" value="${esc(state.triagedBy || '')}"
          ${actOn('input','jiraEpicModalTypedTriagedBy', ARG.value)}>
        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
          Posted as a Jira comment on each new ticket: "Triaged and added by: &lt;name&gt; on: ${esc(new Date().toISOString().slice(0, 10))}".
        </div>
      </div>
      <div id="jira-epic-modal-selection" style="font-size:13px;color:var(--text-muted)">No Epic selected — tickets will be created unassigned.</div>
    </div>`;
}

export function jiraEpicModalTypedTriagedBy(value) {
  const state = _jiraEpicModalState;
  if (!state) return;
  state.triagedBy = value.trim();
}

export function jiraEpicModalPickIssueType(name) {
  const state = _jiraEpicModalState;
  if (!state) return;
  state.issueType = name;
}

export function jiraEpicModalPickExisting(epicKey) {
  const state = _jiraEpicModalState;
  if (!state) return;
  if (epicKey) {
    state.choice = { epic_key: epicKey };
    document.getElementById('jira-epic-new-name').value = '';
  } else {
    state.choice = null;
  }
  jiraEpicModalUpdateSelectionText();
}

export function _findExistingEpicByName(state, name) {
  const needle = name.trim().toLowerCase();
  if (!needle) return null;
  return state.existing.find(e => (e.summary || '').trim().toLowerCase().startsWith(needle)) || null;
}

export function jiraEpicModalQuickCreate(name) {
  const state = _jiraEpicModalState;
  if (!state) return;
  const match = _findExistingEpicByName(state, name);
  document.getElementById('jira-epic-new-name').value = name;
  if (match) {
    // Reuse the existing Epic instead of creating a duplicate.
    document.getElementById('jira-epic-existing-select').value = match.key;
    state.choice = { epic_key: match.key };
  } else {
    document.getElementById('jira-epic-existing-select').value = '';
    state.choice = { epic_name: name };
  }
  jiraEpicModalUpdateSelectionText();
}

export function jiraEpicModalTypedName(name) {
  const state = _jiraEpicModalState;
  if (!state) return;
  const trimmed = name.trim();
  if (trimmed) {
    const match = _findExistingEpicByName(state, trimmed);
    if (match) {
      document.getElementById('jira-epic-existing-select').value = match.key;
      state.choice = { epic_key: match.key };
    } else {
      document.getElementById('jira-epic-existing-select').value = '';
      state.choice = { epic_name: trimmed };
    }
  } else {
    state.choice = null;
  }
  jiraEpicModalUpdateSelectionText();
}

export function jiraEpicModalUpdateSelectionText() {
  const el = document.getElementById('jira-epic-modal-selection');
  const state = _jiraEpicModalState;
  if (!el || !state) return;
  if (state.choice?.epic_key) {
    const match = state.existing.find(e => e.key === state.choice.epic_key);
    el.textContent = `Will link tickets to ${state.choice.epic_key}${match ? ' — ' + match.summary : ''}.`;
  } else if (state.choice?.epic_name) {
    el.textContent = `Will create a new Epic named "${state.choice.epic_name}" and link tickets to it.`;
  } else {
    el.textContent = 'No Epic selected — tickets will be created unassigned.';
  }
}

export function _scanIdFromHash() {
  const m = window.location.hash.match(/^#\/scans\/([^?]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

// "Add to Jira" from the finding drawer — same flow as the Jira review page, without leaving the scan.
export async function jiraQuickAdd(id) {
  const f = _findingsRegistry.get(id);
  const scanId = _scanIdFromHash();
  const btn = document.getElementById('finding-jira-btn');
  const status = document.getElementById('finding-jira-status');
  if (!f || !scanId || !btn) return;
  const setStatus = (msg, isError) => {
    if (!status) return;
    status.textContent = msg;
    status.style.color = isError ? 'var(--critical)' : 'var(--text-muted)';
  };
  btn.disabled = true;
  setStatus('Checking Jira…');
  try {
    const data = await api.getJiraCandidates(scanId);
    // A missing project key is fixable in the modal; missing credentials are not.
    if (!(data.credentials_configured ?? data.jira_configured)) {
      setStatus('Jira credentials are not configured (base URL, email, and JIRA_API_TOKEN). See the Jira page.', true);
      btn.disabled = false;
      return;
    }
    const candidate = jiraFindCandidate(data.candidates, f);
    if (!candidate) {
      setStatus('This finding is not eligible for ticketing in this scan.', true);
      btn.disabled = false;
      return;
    }
    if (candidate.selection_reason === 'already_ticketed') {
      jiraQuickMarkDone(candidate.jira_ticket?.issue_key, data.jira_base_url);
      return;
    }
    if (!candidate.selectable) {
      setStatus('This finding is suppressed by an ignore rule.', true);
      btn.disabled = false;
      return;
    }
    setStatus('');
    btn.disabled = false;
    await showJiraEpicModal({
      scanId, finding: f, fingerprint: candidate.fingerprint,
      baseUrl: data.jira_base_url, projectKey: data.project_key || '',
    });
  } catch (error) {
    setStatus(`Could not reach Jira: ${error.message}`, true);
    btn.disabled = false;
  }
}

export function jiraFindCandidate(candidates, f) {
  const norm = v => String(v || '').trim();
  return candidates.find(c =>
    norm(c.tool) === norm(f.tool) && norm(c.id) === norm(f.id) &&
    norm(c.package) === norm(f.package) && norm(c.target) === norm(f.target));
}

export function jiraQuickMarkDone(issueKey, baseUrl) {
  const btn = document.getElementById('finding-jira-btn');
  const status = document.getElementById('finding-jira-status');
  if (btn) { btn.disabled = true; btn.textContent = 'In Jira'; }
  if (!status) return;
  status.style.color = 'var(--text-muted)';
  status.textContent = '';
  if (issueKey && baseUrl) {
    const a = document.createElement('a');
    a.href = `${baseUrl}/browse/${encodeURIComponent(issueKey)}`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = issueKey;
    status.append('Ticket: ', a);
  } else {
    status.textContent = issueKey ? `Ticket: ${issueKey}` : 'Already ticketed.';
  }
}

export async function jiraQuickCreateConfirmed() {
  const ctx = _jiraQuickCtx;
  if (!ctx) return;
  const modalState = _jiraEpicModalState;
  const extras = {
    ...(modalState?.choice || {}),
    ...(modalState?.issueType ? { issue_type: modalState.issueType } : {}),
    ...(modalState?.triagedBy ? { triaged_by: modalState.triagedBy } : {}),
  };
  jiraEpicModalClose();
  const btn = document.getElementById('finding-jira-btn');
  const status = document.getElementById('finding-jira-status');
  if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
  try {
    const result = await api.createJiraTickets(ctx.scanId, [ctx.fingerprint], extras);
    const made = result.created?.[0] || result.already_exists?.[0];
    if (made) {
      jiraQuickMarkDone(made.issue_key || made.key, ctx.baseUrl);
    } else {
      const reason = (result.failed?.[0] || result.ineligible?.[0])?.reason || 'unknown';
      if (btn) { btn.disabled = false; btn.textContent = 'Add to Jira'; }
      if (status) {
        status.style.color = 'var(--critical)';
        status.textContent = `Ticket not created: ${reason}`;
      }
    }
  } catch (error) {
    if (btn) { btn.disabled = false; btn.textContent = 'Add to Jira'; }
    if (status) {
      status.style.color = 'var(--critical)';
      status.textContent = `Ticket creation failed: ${error.message}`;
    }
  }
}

export async function jiraReviewCreateTicketsConfirmed() {
  const state = _jiraReviewState;
  if (!state || state.submitting || state.selected.size === 0) return;
  const modalState = _jiraEpicModalState;
  const requestExtras = {
    ...(modalState?.choice || {}),
    ...(modalState?.issueType ? { issue_type: modalState.issueType } : {}),
    ...(modalState?.triagedBy ? { triaged_by: modalState.triagedBy } : {}),
  };
  const selected = [...state.selected];
  document.querySelector('.modal-overlay')?.remove();

  state.submitting = true;
  jiraReviewUpdateSelection();
  const button = document.getElementById('jira-review-create');
  if (button) button.textContent = 'Creating tickets…';
  const failed = new Set();
  const reasonCounts = {};
  let created = 0;
  let existing = 0;
  try {
    for (let index = 0; index < selected.length; index += 200) {
      const result = await api.createJiraTickets(state.scanId, selected.slice(index, index + 200), requestExtras);
      created += result.created.length;
      existing += result.already_exists.length;
      result.failed.concat(result.ineligible).forEach(item => {
        failed.add(item.fingerprint);
        const reason = item.reason || 'unknown';
        reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
      });
      if (button) button.textContent = `Creating ${Math.min(index + 200, selected.length)} of ${selected.length}…`;
    }
    const data = await api.getJiraCandidates(state.scanId);
    state.data = data;
    state.selected = failed;
    state.submitting = false;
    renderJiraReviewPage();
    const reasonLabels = {
      unknown_fingerprint: 'no longer eligible in this scan (e.g. remediated, or its fingerprint changed)',
      suppressed: 'suppressed by an ignore rule',
      jira_creation_failed: 'rejected by Jira (see server logs for the exact API error)',
    };
    const reasonText = Object.entries(reasonCounts)
      .map(([reason, count]) => `${count} ${reasonLabels[reason] || reason}`)
      .join('; ');
    toast(
      `Created ${created} ticket${created === 1 ? '' : 's'}. ${existing} already existed. ` +
      `${failed.size} failed or became ineligible${reasonText ? ` (${reasonText})` : ''}.`,
      failed.size ? 'warning' : 'success'
    );
  } catch (error) {
    state.submitting = false;
    if (button) button.textContent = 'Create Jira Tickets';
    jiraReviewUpdateSelection();
    toast(`Ticket creation failed: ${error.message}`, 'error');
  }
}
