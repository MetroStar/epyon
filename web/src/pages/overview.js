import { gateBadge, sevBadgeRow, statusBadge } from '../components/badges.js';
import { toast } from '../components/feedback.js';
import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { upperAlnumInput, upperInput } from '../core/ui-helpers.js';
import { esc, fmtDate, ucFirst, act, actOn, ARG } from '../lib/format.js';
import { renderApplications } from './applications.js';
import { buildOverviewExecSection, buildOverviewIssoSection, buildOverviewTechSection } from '../components/summaries.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

export async function renderOverview() {
  setActive('overview');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [stats, allApps, projectData] = await Promise.all([
      api.getStats(), api.getApplications(), api.getProjects().catch(() => ({ projects: [] })),
    ]);
    const projects = (projectData.projects || projectData || []).filter(p => Array.isArray(p.repos));
    const byName = new Map(allApps.map(a => [a.name, a]));
    const grouped = new Set(projects.flatMap(p => p.repos.map(r => r.app)));
    // Applications that belong to a project are shown inside it, not again below
    const apps = projects.length ? allApps.filter(a => !grouped.has(a.name)) : allApps;

    const continuous  = apps.filter(a => a.monitored);
    const evaluation  = apps.filter(a => !a.monitored);
    const anyMonitored = continuous.length > 0;

    const makeCard = app => `
          <div class="app-card status-${esc(app.status)}"
               ${act('navigate', `#/applications/${encodeURIComponent(app.name)}`)}>
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

    const ROLE = { frontend: 'Front end', backend: 'Back end', infra: 'Infrastructure', other: 'Other' };
    const projectSections = projects.map(p => {
      const cards = p.repos.map(r => byName.get(r.app)
        ? `<div>${makeCard(byName.get(r.app))}<div style="font-size:12px;color:var(--text-muted);margin:4px 0 0 4px">${esc(ROLE[r.role] || r.role)}</div></div>`
        : '').join('');
      return `<div class="section">
        <div class="section-title">
          <span>▣ ${esc(p.name)} <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${p.repos.length} repositor${p.repos.length === 1 ? 'y' : 'ies'})</span></span>
          <button class="btn btn-sm" ${act('navigate', `#/projects/${encodeURIComponent(p.id)}`)}>STIG roll-up →</button>
        </div>
        ${p.description ? `<div style="font-size:13px;color:var(--text-muted);margin-bottom:10px">${esc(p.description)}</div>` : ''}
        <div class="app-grid">${cards || '<div style="color:var(--text-muted)">No scanned repositories yet.</div>'}</div>
      </div>`;
    }).join('');

    const appSections = projectSections + (apps.length
      ? anyMonitored
        ? `<div class="section">
             <div class="section-title">
               <span>● Continuously Monitored <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${continuous.length})</span></span>
               <button class="btn btn-sm" ${act('navigate', '#/applications')}>View all →</button>
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
               ${projects.length ? 'Other applications' : 'Applications'}
               <button class="btn btn-sm" ${act('navigate', '#/applications')}>View all →</button>
             </div>
             <div class="app-grid">${apps.map(makeCard).join('')}</div>
           </div>`
      : projects.length ? '' : `<div class="section">
           <div class="section-title">Applications</div>
           ${emptyState(
             'No applications yet',
             'Run your first scan to see applications here.',
             `<button class="btn btn-primary" ${act('navigate', '#/new-scan')} style="margin-top:16px">▶ Run First Scan</button>`,
           )}
         </div>`);

    page.innerHTML = `
      ${pageHeader(`Security Overview`, { actions: `<button class="btn btn-primary" ${act('navigate', '#/new-scan')}>+ Run Scan</button>` })}

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
      ${buildSbomSearchSection()}
      ${buildOverviewExecSection()}
      ${buildOverviewTechSection()}
      ${buildOverviewIssoSection()}

      ${appSections}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ── Cross-application CVE search (Overview) ───────────────────
export function buildCveSearchSection() {
  return `
    <div class="section cve-search">
      <div class="section-title">Search a CVE across applications</div>
      <form class="cve-search-form" ${actOn('submit', 'cveSearchRun', ARG.event)}>
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

// ── Cross-application SBOM package search (Overview) ──────────
export function buildSbomSearchSection() {
  return `
    <div class="section cve-search">
      <div class="section-title">Search SBOMs across applications</div>
      <form class="cve-search-form" ${actOn('submit', 'sbomSearchRun', ARG.event)}>
        <input id="sbom-search-q" class="cve-search-input" type="text" minlength="3" maxlength="100"
               placeholder="Package name (e.g. log4j, lodash) or purl" autocomplete="off" required>
        <label class="cve-search-history">
          <input id="sbom-search-history" type="checkbox"> Include earlier scans
        </label>
        <button class="btn btn-primary" type="submit">Search</button>
      </form>
      <div id="sbom-search-results"></div>
    </div>`;
}

let _sbomSearchSeq = 0;

export async function sbomSearchRun(ev) {
  if (ev) ev.preventDefault();
  const out = document.getElementById('sbom-search-results');
  if (!out) return;
  const q = document.getElementById('sbom-search-q').value.trim();
  const history = document.getElementById('sbom-search-history').checked;
  const seq = ++_sbomSearchSeq;
  out.innerHTML = loading();
  try {
    const params = new URLSearchParams({ q, include_history: history ? 'true' : 'false' });
    const r = await fetch(`/api/sbom/search?${params}`);
    if (r.status === 400) throw new Error('Enter 3–100 characters: letters, digits and . _ : @ / + -');
    if (!r.ok) throw new Error('Search failed. Please try again.');
    const data = await r.json();
    if (seq !== _sbomSearchSeq) return;
    out.innerHTML = sbomSearchResultsHtml(data);
  } catch (e) {
    if (seq === _sbomSearchSeq) out.innerHTML = errBanner(e.message, { retry: false });
  }
}

export function sbomSearchResultsHtml(data) {
  if (!data.applications.length) {
    return `<div class="cve-search-empty">“${esc(data.query)}” was not found in any monitored application's SBOM.</div>`;
  }
  const rows = data.applications.map(appEntry => appEntry.packages.map(p => `
      <tr>
        <td>${esc(appEntry.app_name)}${appEntry.is_latest ? '' : ' <span class="tool-tag">earlier scan</span>'}</td>
        <td>${esc(p.name)}</td>
        <td>${esc(p.version || '—')}</td>
        <td><span class="tool-tag">${esc(p.type)}</span></td>
        <td>${esc((p.licenses || []).join(', ') || '—')}</td>
        <td>${esc(p.path || '—')}</td>
        <td>${esc(fmtDate(appEntry.timestamp))}</td>
      </tr>`).join('')).join('');
  return `
    <div class="cve-search-summary">${esc(data.total_packages)} package${data.total_packages === 1 ? '' : 's'} across ${esc(data.total_applications)} application${data.total_applications === 1 ? '' : 's'}</div>
    <div class="table-container">
      <table>
        <thead><tr><th scope="col">Application</th><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Type</th><th scope="col">License</th><th scope="col">Path</th><th scope="col">Scanned</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

let _cveSearchSeq = 0;

let _cveBulk = { data: null, selected: new Set() };

export async function cveSearchRun(ev) {
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

export function cveBulkToggle(box) {
  if (box.checked) _cveBulk.selected.add(box.dataset.key); else _cveBulk.selected.delete(box.dataset.key);
  cveBulkRefreshButton();
}

export function cveBulkToggleAll(master) {
  document.querySelectorAll('#cve-search-results .cve-select:not([disabled])').forEach(box => {
    box.checked = master.checked;
    cveBulkToggle(box);
  });
}

export function cveBulkRefreshButton() {
  const btn = document.getElementById('cve-bulk-create');
  if (!btn) return;
  const n = _cveBulk.selected.size;
  btn.disabled = n === 0;
  btn.textContent = n ? `Create Jira tickets (${n})` : 'Create Jira tickets';
}

// Selected findings grouped by search entry (one scan per application).
export function cveBulkGroups() {
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
export async function cveBulkResolve(group) {
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

export async function cveBulkOpen() {
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

export function cveBulkClose() {
  if (_cveBulk.modal?.running) return;
  document.querySelector('.modal-overlay')?.remove();
}

export function cveBulkRenderForm() {
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
            ${actOn('input', 'cveBulkKeyTyped', ARG.el)}></label>
        <label class="field-label">Epic key (optional)
          <input class="field-input" type="text" maxlength="30" placeholder="${esc(g.projectKey || 'PROJECT')}-123" data-gi="${i}" value="${esc(g.epicKey || '')}"
            ${actOn('input', 'cveBulkEpicTyped', ARG.el)}></label>
      </div>${sk}</div>`;
  }).join('');
  body.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h2 style="color:var(--text);margin:0">Create Jira tickets for ${esc(_cveBulk.data.query)}</h2>
      <button class="btn" ${act('cveBulkClose')} style="padding:6px 12px">✕</button>
    </div>
    <p style="color:var(--text-muted);font-size:13px;margin:0 0 12px">Confirm each application's Jira project before creating. Changing a key updates the Jira project for that whole application.</p>
    ${groupHtml}
    <div class="cve-bulk-fields" style="margin-top:12px">
      <label class="field-label">Ticket type
        <select class="field-input" ${actOn('change', 'cveBulkIssueTypeChanged', ARG.value)}>
          ${types.map(t => `<option value="${esc(t)}" ${t === m.issueType ? 'selected' : ''}>${esc(t)}</option>`).join('')}
        </select></label>
      <label class="field-label">Triaged by (optional)
        <input class="field-input" type="text" maxlength="200" value="${esc(m.triagedBy)}"
          ${actOn('input', 'cveBulkTriagedByChanged', ARG.value)}></label>
    </div>
    <div class="modal-actions" style="margin-top:20px;display:flex;justify-content:flex-end;gap:10px">
      <button class="btn" ${act('cveBulkClose')}>Cancel</button>
      <button id="cve-bulk-confirm" class="btn btn-primary" ${act('cveBulkConfirm')} ${total ? '' : 'disabled'}>Create ${total} ticket${total === 1 ? '' : 's'}</button>
    </div>`;
}

export function cveBulkModalState() { return _cveBulk.modal; }

export function cveBulkEpicTyped(input) {
  upperInput(input);
  _cveBulk.modal.groups[Number(input.dataset.gi)].epicKey = input.value.trim();
}

export function cveBulkIssueTypeChanged(value) { _cveBulk.modal.issueType = value; }

export function cveBulkTriagedByChanged(value) { _cveBulk.modal.triagedBy = value; }

export function cveBulkDone() {
  cveBulkClose();
  cveSearchRun();
}

export function cveBulkKeyTyped(input) {
  upperAlnumInput(input);
  _cveBulk.modal.groups[Number(input.dataset.gi)].projectKey = input.value.trim();
}

export async function cveBulkConfirm() {
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

export function cveBulkRenderSummary(results) {
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
      <button class="btn btn-primary" ${act('cveBulkDone')}>Done</button>
    </div>`;
}

export function cveSearchResultsHtml(data) {
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
            aria-label="Select ${esc(f.id)} in ${esc(appEntry.app_name)}" ${actOn('change','cveBulkToggle', ARG.el)}></td>
        <td>${esc(appEntry.app_name)}${appEntry.is_latest ? '' : ' <span class="tool-tag">earlier scan</span>'}</td>
        <td><span class="sev-badge ${esc(f.severity)}">${esc(ucFirst(f.severity))}</span></td>
        <td><a href="${esc(href)}" data-href="${esc(href)}" ${act('spaLinkClick', ARG.event, ARG.el)}>${esc(f.id)}</a>${f.suppressed ? ' <span class="tool-tag">suppressed</span>' : ''}</td>
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
      <button id="cve-bulk-create" class="btn btn-primary btn-sm" ${act('cveBulkOpen')} disabled>Create Jira tickets</button>
    </div>
    <div class="table-container">
      <table>
        <thead><tr><th scope="col"><input type="checkbox" id="cve-select-all" aria-label="Select all eligible findings" ${actOn('change','cveBulkToggleAll', ARG.el)}></th><th scope="col">Application</th><th scope="col">Severity</th><th scope="col">ID</th><th scope="col">Tools</th><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Fixed in</th><th scope="col">Scanned</th><th scope="col">Jira</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

export async function toggleMonitored(name, isCurrently) {
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
