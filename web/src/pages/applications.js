import { gateBadge, hfStatusBadge, sevBadgeRow, statusBadge } from '../components/badges.js';
import { emptyRow, emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { dedupeTools, esc, fmtDate, act, actOn, ARG } from '../lib/format.js';
import { computeStatus, scanTypeLabel } from '../lib/scans.js';
import { buildAppIssoSection } from '../components/summaries.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

export async function renderApplications() {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [apps, hidden] = await Promise.all([api.getApplications(), api.getHiddenApps()]);

    const rows = apps.length
      ? apps.map(app => `
          <tr ${act('navigate', `#/applications/${encodeURIComponent(app.name)}`)}
              style="cursor:pointer">
            <td>
              <strong>${esc(app.name)}</strong>
              ${app.url ? `<div style="font-size:12px;color:var(--text-dim);margin-top:2px">${esc(app.url)}</div>` : ''}
            </td>
            <td ${act('toggleMonitored', app.name, !!app.monitored)} data-stop>
              <button class="app-type-badge ${app.monitored ? 'monitored' : 'evaluation'}"
                      title="${app.monitored ? 'Continuous — click to set as Evaluation' : 'Evaluation — click to set as Continuous'}">
                ${app.monitored ? '● Continuous' : '○ Evaluation'}
              </button>
            </td>
            <td>${app.last_scanned ? fmtDate(app.last_scanned) : '<span style="color:var(--text-dim)">Never</span>'}</td>
            <td>${esc(app.scan_count)}</td>
            <td>${app.critical > 0
                  ? `<span class="sev-badge critical">${app.critical}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.high > 0
                  ? `<span class="sev-badge high">${app.high}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.medium > 0
                  ? `<span class="sev-badge medium">${app.medium}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.low > 0
                  ? `<span class="sev-badge low">${app.low}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${statusBadge(app.status)}</td>
            <td>
              <button class="btn btn-sm"
                ${act('navigate', '#/new-scan')} data-stop>
                Scan
              </button>
              <button class="btn btn-sm btn-danger"
                ${act('hideApplication', app.name)} data-stop
                title="Hide this application from the list">
                Hide
              </button>
              <button class="btn btn-sm btn-danger"
                ${act('deleteApplication', app.name)} data-stop
                title="Permanently delete all scan data for this application">
                Delete
              </button>
            </td>
          </tr>`).join('')
      : emptyRow(10, 'No applications found. Run a scan to get started.');

    const hiddenSection = hidden.length ? `
      <div class="section" style="margin-top:32px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
          <span>Hidden Applications <span style="font-size:12px;color:var(--text-muted);font-weight:400">(${hidden.length})</span></span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th scope="col">Application</th>
                <th scope="col"></th>
              </tr>
            </thead>
            <tbody>
              ${hidden.map(name => `
                <tr>
                  <td style="color:var(--text-muted)">${esc(name)}</td>
                  <td>
                    <button class="btn btn-sm"
                      ${act('restoreApplication', name)}>
                      Restore
                    </button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : '';

    page.innerHTML = `
      ${pageHeader(`Applications`, { actions: `<button class="btn" ${act('showAddAppModal')}>+ Add Application</button>
          <button class="btn btn-primary" ${act('navigate', '#/new-scan')}>▶ Run Scan</button>` })}
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th scope="col">Application</th>
              <th scope="col">Type</th>
              <th scope="col">Last Scanned</th>
              <th scope="col">Scans</th>
              <th scope="col">Critical</th>
              <th scope="col">High</th>
              <th scope="col">Medium</th>
              <th scope="col">Low</th>
              <th scope="col">Status</th>
              <th scope="col"></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${hiddenSection}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

export function buildScanTimelineItem(s, name) {
  const st = computeStatus(s);
  return `
    <div class="scan-timeline-item"
         ${act('navigate', `#/scans/${encodeURIComponent(s.scan_id)}`)}>
      <div class="scan-timeline-dot ${esc(st)}"></div>
      <div class="scan-timeline-content">
        <div class="scan-timeline-title">
          ${esc(scanTypeLabel(s.scan_type))} scan
          <span>${gateBadge(s)} ${sevBadgeRow(s)}</span>
          ${hfStatusBadge(s)}
          ${s.ci_source ? `<span class="badge badge-ci" title="From GitHub Actions · ${esc(s.ci_source.repo)}${s.ci_source.branch ? ' · ' + esc(s.ci_source.branch) : ''}">GH Actions</span>` : ''}
        </div>
        <div class="scan-timeline-meta">
          ${fmtDate(s.timestamp)}
          ${s.user ? ` · ${esc(s.user)}` : ''}
          ${s.location ? ` · <code>${esc(s.location)}</code>` : ''}
        </div>
        ${dedupeTools(s.tools_analyzed).length ? `
          <div class="tools-list" style="margin-top:8px">
            ${dedupeTools(s.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>` : ''}
      </div>
      ${s.has_dashboard
        ? `<button class="btn btn-sm"
             ${act('open', `/api/scans/${encodeURIComponent(s.scan_id)}/dashboard`, '_blank')} data-stop>
             HTML ↗
           </button>`
        : ''}
      <button class="btn btn-sm btn-danger"
        ${act('deleteScan', s.scan_id, name)} data-stop
        title="Permanently delete this scan">
        Delete
      </button>
    </div>`;
}

// Scan History tabs: Full/Nightly, Quick, STIG, Other (baseline, local model, container image, ...).
const SCAN_HISTORY_TABS = [
  { id: 'full',  label: 'Full / Nightly', types: ['full', 'nightly'] },
  { id: 'quick', label: 'Quick',          types: ['quick'] },
  { id: 'stig',  label: 'STIG',           types: ['stig'] },
  { id: 'other', label: 'Other',          types: null },
];

const SCAN_HISTORY_PAGE_SIZE = 15;

const _scanHistoryState = {};

export function scanHistoryTabOf(scan) {
  const t = SCAN_HISTORY_TABS.find(tab => tab.types && tab.types.includes(scan.scan_type));
  return t ? t.id : 'other';
}

// Local calendar day (YYYY-MM-DD) of a scan, so the date filter matches what fmtDate shows.
export function scanLocalDay(scan) {
  const d = new Date(scan.timestamp);
  if (isNaN(d)) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function scanHistoryFiltered(scans, st) {
  return scans.filter(s => {
    if (scanHistoryTabOf(s) !== st.tab) return false;
    const day = scanLocalDay(s);
    if (st.from && (!day || day < st.from)) return false;
    if (st.to && (!day || day > st.to)) return false;
    return true;
  });
}

export function buildScanHistory(name, scans) {
  const saved = _scanHistoryState[name] || {};
  // Default to the tab holding the newest scan so the page never opens on an empty tab.
  const tab = SCAN_HISTORY_TABS.some(t => t.id === saved.tab) ? saved.tab : scanHistoryTabOf(scans[0]);
  const st = { tab, page: saved.page || 1, from: saved.from || '', to: saved.to || '' };
  _scanHistoryState[name] = st;
  window._scanHistoryScans = { name, scans };
  const counts = {};
  scans.forEach(s => { const id = scanHistoryTabOf(s); counts[id] = (counts[id] || 0) + 1; });
  const tabs = SCAN_HISTORY_TABS.map(t => `
    <button class="scan-history-tab${t.id === tab ? ' active' : ''}" role="tab"
      id="scan-tab-${t.id}" aria-selected="${t.id === tab}" aria-controls="scan-history-panel"
      data-tab="${t.id}" ${actOn('click','selectScanHistoryTab', ARG.data('tab'))}>
      ${esc(t.label)} <span class="scan-history-count">${counts[t.id] || 0}</span>
    </button>`).join('');
  return `
    <div class="scan-history-tabs" role="tablist" aria-label="Scan type">${tabs}</div>
    <div class="scan-history-filter">
      <label>From <input type="date" id="scan-filter-from" value="${esc(st.from)}"
        ${actOn('change','setScanHistoryDates')}></label>
      <label>To <input type="date" id="scan-filter-to" value="${esc(st.to)}"
        ${actOn('change','setScanHistoryDates')}></label>
      <button class="btn btn-sm" id="scan-filter-clear" ${act('clearScanHistoryDates')}
        ${st.from || st.to ? '' : 'hidden'}>Clear dates</button>
    </div>
    <div id="scan-history-panel" role="tabpanel">${scanHistoryPanel(name, scans, st)}</div>`;
}

export function scanHistoryPanel(name, scans, st) {
  const items = scanHistoryFiltered(scans, st);
  const label = SCAN_HISTORY_TABS.find(t => t.id === st.tab).label;
  if (!items.length) {
    const why = st.from || st.to ? ' in this date range' : '';
    return `<div class="scan-history-empty">No ${esc(label)} scans${why} for this application.</div>`;
  }
  const pages = Math.ceil(items.length / SCAN_HISTORY_PAGE_SIZE);
  st.page = Math.min(Math.max(st.page, 1), pages);
  const start = (st.page - 1) * SCAN_HISTORY_PAGE_SIZE;
  const rows = items.slice(start, start + SCAN_HISTORY_PAGE_SIZE)
    .map(s => buildScanTimelineItem(s, name)).join('');
  const pager = items.length > SCAN_HISTORY_PAGE_SIZE ? `
    <div class="scan-history-pager">
      <button class="btn btn-sm" ${act('setScanHistoryPage', st.page - 1)} ${st.page <= 1 ? 'disabled' : ''}>‹ Prev</button>
      <span>Showing ${start + 1}–${Math.min(start + SCAN_HISTORY_PAGE_SIZE, items.length)} of ${items.length} · Page ${st.page} of ${pages}</span>
      <button class="btn btn-sm" ${act('setScanHistoryPage', st.page + 1)} ${st.page >= pages ? 'disabled' : ''}>Next ›</button>
    </div>` : '';
  return rows + pager;
}

export function refreshScanHistory() {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  const st = _scanHistoryState[ctx.name];
  document.querySelectorAll('.scan-history-tab').forEach(btn => {
    const on = btn.dataset.tab === st.tab;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
  });
  const clear = document.getElementById('scan-filter-clear');
  if (clear) clear.hidden = !(st.from || st.to);
  document.getElementById('scan-history-panel').innerHTML = scanHistoryPanel(ctx.name, ctx.scans, st);
}

export function selectScanHistoryTab(tabId) {
  const ctx = window._scanHistoryScans;
  if (!ctx || !SCAN_HISTORY_TABS.some(t => t.id === tabId)) return;
  Object.assign(_scanHistoryState[ctx.name], { tab: tabId, page: 1 });
  refreshScanHistory();
}

export function setScanHistoryPage(page) {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  _scanHistoryState[ctx.name].page = page;
  refreshScanHistory();
}

export function setScanHistoryDates() {
  const ctx = window._scanHistoryScans;
  if (!ctx) return;
  Object.assign(_scanHistoryState[ctx.name], {
    from: document.getElementById('scan-filter-from').value,
    to: document.getElementById('scan-filter-to').value,
    page: 1,
  });
  refreshScanHistory();
}

export function clearScanHistoryDates() {
  document.getElementById('scan-filter-from').value = '';
  document.getElementById('scan-filter-to').value = '';
  setScanHistoryDates();
}

export async function renderAppDetail(name) {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    // Load scans and registered app info in parallel
    const [scans, allApps] = await Promise.all([
      api.getAppScans(name),
      api.getApplications(),
    ]);
    const appInfo = allApps.find(a => a.name === name) || {};
    const appUrl  = appInfo.url || '';
    const latest = scans[0] || {};
    const status  = computeStatus(latest);

    const timelineItems = scans.length
      ? buildScanHistory(name, scans)
      : emptyState(
          `No scans found for "${name}"`,
          appUrl ? `Repository: ${appUrl}` : 'Run a scan to populate history.',
          appUrl
            ? `<div style="display:flex;gap:8px;justify-content:center;margin-top:16px">
                 <button class="btn btn-primary"
                   ${act('navigate', `#/new-scan?target=${encodeURIComponent(appUrl)}`)}>
                   ▶ Run First Scan
                 </button>
               </div>`
            : `<button class="btn btn-primary" ${act('navigate', '#/new-scan')} style="margin-top:16px">
                 ▶ Run Scan
               </button>`,
        );

    // Use comprehensive-scan counts (same source as overview cards) so numbers match.
    // If the most recent scan was a quick/stig scan, flag it so the user knows the
    // vulnerability counts are from an earlier full scan.
    const compTs   = appInfo.comprehensive_timestamp || '';
    const compType = appInfo.comprehensive_scan_type  || '';
    const countsDiffer = compTs && compTs !== latest.timestamp;
    const countsNote = countsDiffer
      ? `<div style="grid-column:1/-1;font-size:12px;color:var(--text-muted);margin-top:4px">
           Vulnerability counts are from the last ${esc(scanTypeLabel(compType))} scan
           (${fmtDate(compTs)}) — quick scans do not run all tools.
         </div>`
      : '';

    const statsSection = scans.length ? `
      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Total Scans</div>
          <div class="value">${esc(scans.length)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Last Scanned</div>
          <div class="value" style="font-size:13px">${fmtDate(latest.timestamp)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${appInfo.critical ?? latest.critical ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${appInfo.high ?? latest.high ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${appInfo.medium ?? latest.medium ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${appInfo.low ?? latest.low ?? 0}</div>
        </div>
        ${countsNote}
      </div>` : '';

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" ${act('navigate', '#/applications')}>Applications</a>
        <span>›</span>
        <span>${esc(name)}</span>
      </div>
      ${pageHeader(`${esc(name)} ${statusBadge(status)}`, { actions: `<button class="btn btn-primary"
            ${act('navigate', `#/new-scan?target=${encodeURIComponent(appUrl)}`)}>
            ▶ Run Scan
          </button>
          <button class="btn app-type-badge ${appInfo.monitored ? 'monitored' : 'evaluation'}"
            onclick="(async()=>{
              try {
                ${appInfo.monitored
                  ? `await api.unsetMonitored('${esc(name)}')`
                  : `await api.setMonitored('${esc(name)}')`};
                renderAppDetail('${esc(name)}');
              } catch(e) { toast(e.message, 'error'); }
            })()"
            title="${appInfo.monitored ? 'Continuous \u2014 click to set as Evaluation' : 'Evaluation \u2014 click to set as Continuous'}">
            ${appInfo.monitored ? '● Continuous' : '◯ Evaluation'}
          </button>
          <button class="btn btn-danger"
            ${act('hideApplication', name)}
            title="Hide this application from the list">
            Hide
          </button>
          <button class="btn btn-danger"
            ${act('deleteApplication', name)}
            title="Permanently delete all scan data for this application">
            Delete All
          </button>` })}
      ${statsSection}
      ${buildAppIssoSection(name)}
      <div class="section">
        <div class="section-title">Scan History</div>
        <div class="scan-timeline">${timelineItems}</div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}
