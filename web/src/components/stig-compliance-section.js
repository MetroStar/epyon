// STIG Compliance section for the Metrics page: summary cards, per-control history/MTTR
// matrix with sortable columns, and app/STIG/range/status filters. Extracted from the old
// standalone "History & MTTR" tab on the STIG page (see docs/FUTURE_IMPROVEMENTS.md item 5)
// so it lives alongside the rest of the cross-application metrics.
import { emptyState } from './layout.js';
import { api } from '../lib/api.js';
import { esc, act, actOn, ARG } from '../lib/format.js';
import { _registerStigDetail } from './drawers/stig.js';

// Globals that other modules put on window (see index.js):
/* global openStigDetail */

const STATUS_CLASSES = {
  'Open':           'open',
  'Not a Finding':  'not-a-finding',
  'Not Applicable': 'na',
  'Not Reviewed':   'not-reviewed',
};
const STATUS_ABBR = {
  'Open':           'O',
  'Not a Finding':  'P',
  'Not Applicable': 'N/A',
  'Not Reviewed':   '—',
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, '': 4 };

// Module-scoped state: only one Metrics page (and therefore one of these sections) is ever
// mounted at a time, matching the pattern the standalone page used before extraction.
let _data         = null;
let _statusFilter = 'all';   // 'all' | 'open' | 'pass' | 'na' | 'nr'
let _daysFilter   = 30;      // 7 | 14 | 30 | 35 | 0 (all)
let _sortKey      = 'sev';   // 'sev' | 'id' | 'title' | 'mttr' | 'status'
let _sortDir      = 1;

function filterControls(list) {
  if (_statusFilter === 'open') return list.filter(c => c.latest_status === 'Open');
  if (_statusFilter === 'pass') return list.filter(c => c.latest_status === 'Not a Finding');
  if (_statusFilter === 'na')   return list.filter(c => c.latest_status === 'Not Applicable');
  if (_statusFilter === 'nr')   return list.filter(c => c.latest_status === 'Not Reviewed');
  return list;
}

function sortControls(list) {
  return [...list].sort((a, b) => {
    let v = 0;
    if (_sortKey === 'sev')    v = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
    if (_sortKey === 'id')     v = a.vuln_id.localeCompare(b.vuln_id);
    if (_sortKey === 'title')  v = (a.title || '').localeCompare(b.title || '');
    if (_sortKey === 'mttr')   v = (a.mttr_days ?? 9999) - (b.mttr_days ?? 9999);
    if (_sortKey === 'status') v = (a.latest_status || '').localeCompare(b.latest_status || '');
    return v * _sortDir;
  });
}

function renderBody() {
  const data = _data;
  if (!data || (data.apps || []).length === 0) {
    return emptyState('No STIG scan data found', 'Run a STIG or nightly scan to start building the history matrix.');
  }

  const { apps = [], app: curApp, slugs = [], scans = [], controls = [], summary = {} } = data;

  const appOpts = apps.map(a =>
    `<option value="${esc(a)}" ${a === curApp ? 'selected' : ''}>${esc(a)}</option>`
  ).join('');
  const slugOpts = ['<option value="">All STIGs</option>',
    ...slugs.map(s => `<option value="${esc(s)}" ${s === (data.slug || '') ? 'selected' : ''}>${esc(s)}</option>`)
  ].join('');

  const cutoff = _daysFilter > 0
    ? new Date(Date.now() - _daysFilter * 86400000).toISOString().slice(0, 10)
    : null;
  const visibleScans = cutoff ? scans.filter(s => s.date >= cutoff) : scans;

  const dayBtns = [[7, '7d'], [14, '14d'], [30, '30d'], [35, '35d'], [0, 'All']].map(([d, l]) =>
    `<button class="btn btn-sm${_daysFilter === d ? ' btn-active' : ''}" ${act('_stigCompDays', d)}>${l}</button>`
  ).join('');

  const statusBtns = [
    ['all', 'All'], ['open', 'Open'], ['pass', 'Not a Finding'], ['na', 'N/A'], ['nr', 'Evidence needed'],
  ].map(([k, l]) =>
    `<button class="btn btn-sm${_statusFilter === k ? ' btn-active' : ''}" ${act('_stigCompStatus', `${k}`)}>${l}</button>`
  ).join('');

  const avgMttr = summary.avg_mttr_days != null ? `${summary.avg_mttr_days} days` : '—';

  const summaryStrip = `
    <div class="stig-history-summary">
      <div class="stig-hs-card">
        <span class="stig-hs-num">${esc(summary.total_controls ?? 0)}</span>
        <span class="stig-hs-lbl">Controls</span>
      </div>
      <div class="stig-hs-card open">
        <span class="stig-hs-num">${esc(summary.currently_open ?? 0)}</span>
        <span class="stig-hs-lbl">Currently Open</span>
      </div>
      <div class="stig-hs-card pass">
        <span class="stig-hs-num">${esc(summary.currently_satisfied ?? 0)}</span>
        <span class="stig-hs-lbl">Currently Satisfied</span>
      </div>
      <div class="stig-hs-card pass" style="opacity:0.7">
        <span class="stig-hs-num">${esc(summary.remediated ?? 0)}</span>
        <span class="stig-hs-lbl">Ever Remediated</span>
      </div>
      <div class="stig-hs-card mttr">
        <span class="stig-hs-num">${esc(avgMttr)}</span>
        <span class="stig-hs-lbl">Avg MTTR</span>
      </div>
    </div>`;

  const visible = sortControls(filterControls(controls));

  const thSort = (key, label) => {
    const active = _sortKey === key;
    const arrow = active ? (_sortDir === 1 ? ' ↑' : ' ↓') : '';
    return `<th scope="col" class="sortable-th${active ? ' sorted' : ''}" ${act('_stigCompSort', `${key}`)}>${label}${arrow}</th>`;
  };

  const dateHeaders = visibleScans.map(s =>
    `<th scope="col" class="stig-matrix-date-th" title="${esc(s.scan_id)}">${esc(s.label)}</th>`
  ).join('');

  const rows = visible.map(c => {
    const sevCls = c.severity || 'unknown';
    const cells = visibleScans.map((s, idx) => {
      const entry = c.timeline.find(t => t.scan_id === s.scan_id);
      const status = entry ? entry.status : '';
      const evidence = entry ? entry.evidence : '';
      const confidence = entry ? entry.confidence : null;
      const cls = STATUS_CLASSES[status] || 'not-reviewed';
      const abbr = STATUS_ABBR[status] || '';

      const prevEntry = idx > 0 ? c.timeline.find(t => t.scan_id === visibleScans[idx - 1].scan_id) : null;
      const evidenceChanged = prevEntry && prevEntry.evidence && evidence && prevEntry.evidence !== evidence && status !== 'Not Reviewed';
      const changeIndicator = evidenceChanged ? ' 🔄' : '';

      const tooltipLines = [
        `Status: ${status}`,
        confidence != null ? `Confidence: ${confidence}%` : '',
        evidence ? `\n${evidence.substring(0, 200)}${evidence.length > 200 ? '...' : ''}` : '',
      ].filter(Boolean).join('\n');

      return `<td class="stig-matrix-cell ${cls}${evidenceChanged ? ' evidence-changed' : ''}" title="${esc(tooltipLines)}">${esc(abbr)}${changeIndicator}</td>`;
    }).join('');

    const mttrBadge = c.mttr_days != null
      ? `<span class="mttr-badge">${c.mttr_days}d</span>`
      : `<span class="mttr-badge none">—</span>`;

    const latestCls = STATUS_CLASSES[c.latest_status] || 'not-reviewed';
    const cid = _registerStigDetail(c);

    return `
      <tr ${act('openStigDetail', cid)} style="cursor:pointer" title="Click to view details">
        <td class="stig-matrix-sev"><span class="sev-badge ${esc(sevCls)}">${esc(sevCls)}</span></td>
        <td class="stig-matrix-id">${esc(c.vuln_id)}</td>
        <td class="stig-matrix-title" title="${esc(c.title)}">${esc(c.title || '—')}</td>
        <td class="stig-matrix-status ${latestCls}">${esc(c.latest_status || '—')}</td>
        ${cells}
        <td class="stig-matrix-mttr">${mttrBadge}</td>
      </tr>`;
  }).join('');

  const emptyRow = visible.length === 0
    ? `<tr><td colspan="${5 + visibleScans.length}" style="text-align:center;padding:32px;color:var(--text-muted)">No controls match the current filter.</td></tr>`
    : '';

  const tableHtml = visibleScans.length === 0
    ? emptyState(`No STIG scans found for ${curApp || 'this app'}`, 'Run a STIG or nightly scan to start tracking history.')
    : `<div class="stig-matrix-wrap">
         <table class="stig-matrix-table">
           <thead>
             <tr>
               ${thSort('sev', 'Sev')}
               ${thSort('id', 'Vuln ID')}
               ${thSort('title', 'Title')}
               ${thSort('status', 'Status')}
               ${dateHeaders}
               ${thSort('mttr', 'MTTR')}
             </tr>
           </thead>
           <tbody>${rows}${emptyRow}</tbody>
         </table>
       </div>`;

  return `
    <div class="stig-history-filters">
      <div class="stig-hf-group">
        <label class="stig-hf-label">App</label>
        <select class="stig-hf-select" ${actOn('change', '_stigCompApp', ARG.value)}>
          ${apps.length === 0 ? '<option value="">No apps</option>' : appOpts}
        </select>
      </div>
      <div class="stig-hf-group">
        <label class="stig-hf-label">STIG</label>
        <select class="stig-hf-select" ${actOn('change', '_stigCompSlug', ARG.value)}>
          ${slugOpts}
        </select>
      </div>
      <div class="stig-hf-group">
        <label class="stig-hf-label">Range</label>
        <div class="stig-hf-btns">${dayBtns}</div>
      </div>
      <div class="stig-hf-group">
        <label class="stig-hf-label">Status</label>
        <div class="stig-hf-btns">${statusBtns}</div>
      </div>
    </div>
    ${summaryStrip}
    ${tableHtml}`;
}

function refreshBody() {
  const el = document.getElementById('stig-compliance-body');
  if (el) el.innerHTML = renderBody();
}

// Wires the global click/change handlers the rendered markup above refers to via act()/actOn().
// Re-registered on every call (each Metrics render), matching how the standalone page did it.
function wireHandlers() {
  window._stigCompApp = async (appVal) => {
    try { _data = await api.getStigHistory(appVal || null, null); } catch (_e) { return; }
    refreshBody();
  };
  window._stigCompSlug = async (slugVal) => {
    try { _data = await api.getStigHistory((_data && _data.app) || null, slugVal || null); } catch (_e) { return; }
    refreshBody();
  };
  window._stigCompDays = (d) => { _daysFilter = d; refreshBody(); };
  window._stigCompStatus = (k) => { _statusFilter = k; refreshBody(); };
  window._stigCompSort = (k) => {
    if (_sortKey === k) _sortDir = -_sortDir; else { _sortKey = k; _sortDir = 1; }
    refreshBody();
  };
}

// Returns the collapsible-section markup for the Metrics page. `data` is the result of
// api.getStigHistory(app, slug) (or null/errored — rendered as an empty state).
export function buildStigComplianceSection(data) {
  _data = data;
  wireHandlers();

  const hasApps = !!data && (data.apps || []).length > 0;
  const rightLabel = hasApps
    ? '<span style="font-size:12px;font-weight:normal;color:var(--text-muted)">history &amp; MTTR</span>'
    : '';

  return `
    <div class="section collapsible-section collapsed" id="section-stig-history">
      <div class="section-title section-toggle" ${act('toggleSection', 'section-stig-history')}>
        STIG Compliance
        <span class="section-title-right">${rightLabel}<span class="section-chevron">▾</span></span>
      </div>
      <div class="section-body">
        <div id="stig-compliance-body">${renderBody()}</div>
      </div>
    </div>`;
}
