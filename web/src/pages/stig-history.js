import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { esc } from '../lib/format.js';
import { navigate } from '../core/router.js';

// Globals that other modules put on window (see index.js):
/* global _registerStigDetail, setActive */

export async function renderStigHistory(selectedApp, selectedSlug) {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

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

  let data;
  try {
    data = await api.getStigHistory(selectedApp || null, selectedSlug || null);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
    return;
  }

  const { apps = [], app: curApp, slugs = [], scans = [], controls = [], summary = {} } = data;

  // ── Filter state ──────────────────────────────────────────
  let statusFilter = 'all';   // 'all' | 'open' | 'pass' | 'na' | 'nr'
  let daysFilter   = 30;      // 7 | 14 | 30 | 35 | 0 (all)
  let sortKey      = 'sev';   // 'sev' | 'id' | 'mttr' | 'status'
  let sortDir      = 1;

  // ── Render helpers ────────────────────────────────────────
  function filterControls(list) {
    if (statusFilter === 'open')   return list.filter(c => c.latest_status === 'Open');
    if (statusFilter === 'pass')   return list.filter(c => c.latest_status === 'Not a Finding');
    if (statusFilter === 'na')     return list.filter(c => c.latest_status === 'Not Applicable');
    if (statusFilter === 'nr')     return list.filter(c => c.latest_status === 'Not Reviewed');
    return list;
  }

  function sortControls(list) {
    return [...list].sort((a, b) => {
      let v = 0;
      if (sortKey === 'sev')    v = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
      if (sortKey === 'id')     v = a.vuln_id.localeCompare(b.vuln_id);
      if (sortKey === 'title')  v = (a.title || '').localeCompare(b.title || '');
      if (sortKey === 'mttr')   v = (a.mttr_days ?? 9999) - (b.mttr_days ?? 9999);
      if (sortKey === 'status') v = (a.latest_status || '').localeCompare(b.latest_status || '');
      return v * sortDir;
    });
  }

  function buildPage() {
    // ── Filters row ────────────────────────────────────────
    const appOpts = apps.map(a =>
      `<option value="${esc(a)}" ${a === curApp ? 'selected' : ''}>${esc(a)}</option>`
    ).join('');
    const slugOpts = ['<option value="">All STIGs</option>',
      ...slugs.map(s => `<option value="${esc(s)}" ${s === (selectedSlug||'') ? 'selected' : ''}>${esc(s)}</option>`)
    ].join('');

    const cutoff = daysFilter > 0
      ? new Date(Date.now() - daysFilter * 86400000).toISOString().slice(0, 10)
      : null;
    const visibleScans = cutoff ? scans.filter(s => s.date >= cutoff) : scans;

    const dayBtns = [[7,'7d'],[14,'14d'],[30,'30d'],[35,'35d'],[0,'All']].map(([d,l]) =>
      `<button class="btn btn-sm${daysFilter===d?' btn-active':''}" onclick="window._stigHistoryDays(${d})">${l}</button>`
    ).join('');

    const statusBtns = [
      ['all','All'],['open','Open'],['pass','Not a Finding'],['na','N/A'],['nr','Evidence needed']
    ].map(([k,l]) =>
      `<button class="btn btn-sm${statusFilter===k?' btn-active':''}" onclick="window._stigHistoryStatus('${k}')">${l}</button>`
    ).join('');

    const avgMttr = summary.avg_mttr_days != null
      ? summary.avg_mttr_days + ' days'
      : '—';

    // ── Summary strip ──────────────────────────────────────
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

    // ── Matrix table ────────────────────────────────────────
    const visible = sortControls(filterControls(controls));

    const thSort = (key, label) => {
      const active = sortKey === key;
      const arrow  = active ? (sortDir === 1 ? ' ↑' : ' ↓') : '';
      return `<th scope="col" class="sortable-th${active?' sorted':''}" onclick="window._stigHistorySort('${key}')">${label}${arrow}</th>`;
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
        const cls    = STATUS_CLASSES[status] || 'not-reviewed';
        const abbr   = STATUS_ABBR[status] || '';
        
        // Check if evidence changed from previous entry
        const prevEntry = idx > 0 ? c.timeline.find(t => t.scan_id === visibleScans[idx - 1].scan_id) : null;
        const evidenceChanged = prevEntry && prevEntry.evidence && evidence && prevEntry.evidence !== evidence && status !== 'Not Reviewed';
        const changeIndicator = evidenceChanged ? ' 🔄' : '';
        
        const tooltipLines = [
          `Status: ${status}`,
          confidence != null ? `Confidence: ${confidence}%` : '',
          evidence ? `\n${evidence.substring(0, 200)}${evidence.length > 200 ? '...' : ''}` : ''
        ].filter(Boolean).join('\n');
        
        return `<td class="stig-matrix-cell ${cls}${evidenceChanged ? ' evidence-changed' : ''}" title="${esc(tooltipLines)}">${esc(abbr)}${changeIndicator}</td>`;
      }).join('');

      const mttrBadge = c.mttr_days != null
        ? `<span class="mttr-badge">${c.mttr_days}d</span>`
        : `<span class="mttr-badge none">—</span>`;

      const latestCls = STATUS_CLASSES[c.latest_status] || 'not-reviewed';
      const cid = _registerStigDetail(c);

      return `
        <tr onclick="openStigDetail(${cid})" style="cursor:pointer" title="Click to view details">
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
                 ${thSort('sev','Sev')}
                 ${thSort('id','Vuln ID')}
                 ${thSort('title','Title')}
                 ${thSort('status','Status')}
                 ${dateHeaders}
                 ${thSort('mttr','MTTR')}
               </tr>
             </thead>
             <tbody>${rows}${emptyRow}</tbody>
           </table>
         </div>`;

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/stig">STIG Compliance</a>
        <span>›</span>
        <span>History</span>
      </div>
      ${pageHeader(`STIG Compliance`)}
      ${histTabs}
      <div class="stig-history-filters">
        <div class="stig-hf-group">
          <label class="stig-hf-label">App</label>
          <select class="stig-hf-select" onchange="window._stigHistoryApp(this.value)">
            ${apps.length === 0 ? '<option value="">No apps</option>' : appOpts}
          </select>
        </div>
        <div class="stig-hf-group">
          <label class="stig-hf-label">STIG</label>
          <select class="stig-hf-select" onchange="window._stigHistorySlug(this.value)">
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

  // ── Empty state (no apps with STIG data at all) ─────────
  const histTabs = `
    <div class="stig-tabs">
      <button class="stig-tab" onclick="navigate('#/stig')">Overview</button>
      <button class="stig-tab active" onclick="navigate('#/stig?view=history')">History &amp; MTTR</button>
    </div>`;

  if (apps.length === 0) {
    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/stig">STIG Compliance</a>
        <span>›</span>
        <span>History</span>
      </div>
      ${pageHeader(`STIG Compliance`)}
      ${histTabs}
      ${emptyState('No STIG scan data found', 'Run a STIG or nightly scan to start building the history matrix.')}`;
    return;
  }

  // ── Event handlers wired via window (inline onclick) ────
  window._stigHistoryApp = async (appVal) => {
    selectedApp  = appVal || null;
    selectedSlug = null;
    try { data = await api.getStigHistory(selectedApp, null); } catch (_) {}
    Object.assign(data, data);  // reassign outer var
    // re-render by re-calling
    const {
      apps: a2 = [], app: ca2, slugs: sl2 = [],
      scans: sc2 = [], controls: co2 = [], summary: su2 = {}
    } = data;
    Object.assign({ apps, app: curApp, slugs, scans, controls, summary },
      { apps: a2, app: ca2, slugs: sl2, scans: sc2, controls: co2, summary: su2 });
    // Simplest: just re-navigate
    navigate('#/stig?view=history&app=' + encodeURIComponent(appVal));
  };
  window._stigHistorySlug = async (slugVal) => {
    navigate('#/stig?view=history&app=' + encodeURIComponent(curApp || '') +
             (slugVal ? '&slug=' + encodeURIComponent(slugVal) : ''));
  };
  window._stigHistoryDays = (d) => {
    daysFilter = d;
    buildPage();
  };
  window._stigHistoryStatus = (key) => {
    statusFilter = key;
    buildPage();
  };
  window._stigHistorySort = (key) => {
    if (sortKey === key) sortDir = -sortDir;
    else { sortKey = key; sortDir = 1; }
    buildPage();
  };

  buildPage();
}
