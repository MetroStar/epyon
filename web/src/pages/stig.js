import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { esc, fmtDate, ucFirst, act, actOn, ARG } from '../lib/format.js';
import { _stigJiraSel, _stigRegistry } from '../state/registries.js';

// Globals that other modules put on window (see index.js):
/* global openStigViewerDetail, setActive, stigStatusLabel */

export async function renderStig() {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const apps = await api.getApplications();
    const stigApps = apps.filter(a => (a.stig_total || 0) > 0);

    const cards = stigApps.length
      ? stigApps.map(app => {
          const stigScanId = app.latest_stig_scan_id || app.latest_scan_id;
          const mdUrl   = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-md`;
          const cklbUrl = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-cklb`;
          const mdBtn   = app.has_stig_report
            ? `<a class="btn btn-sm" href="${esc(mdUrl)}" download>↓ findings.md</a>` : '';
          const cklbBtn = app.has_stig_cklb
            ? `<a class="btn btn-sm" href="${esc(cklbUrl)}" download>↓ findings.cklb</a>` : '';
          const jsonBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-json" download>↓ findings.json</a>`;
          const poamBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(stigScanId)}/poam" download title="Open STIG controls + Critical/High CVEs">↓ POA&amp;M.csv</a>`;
          return `
            <div class="stig-app-card" ${act('navigate', `#/scans/${encodeURIComponent(stigScanId)}`)} style="cursor:pointer">
              <div class="stig-app-card-header">
                <span class="stig-app-name">
                  ${esc(app.name)}
                </span>
                <div class="stig-download-btns" data-stop>${mdBtn}${cklbBtn}${jsonBtn}${poamBtn}</div>
              </div>
              <div class="stig-counts">
                <div class="stig-count open">
                  <span class="num">${esc(app.stig_open || 0)}</span>
                  <span class="lbl">Open</span>
                </div>
                <div class="stig-count pass">
                  <span class="num">${esc(app.stig_pass || 0)}</span>
                  <span class="lbl">Not a Finding</span>
                </div>
                <div class="stig-count na">
                  <span class="num">${esc(app.stig_na || 0)}</span>
                  <span class="lbl">Not Applicable</span>
                </div>
                ${(app.stig_nr || 0) > 0 ? `
                <div class="stig-count" style="background:var(--bg-input);border-color:var(--border)">
                  <span class="num" style="color:var(--text-muted)">${esc(app.stig_nr || 0)}</span>
                  <span class="lbl">Evidence needed</span>
                </div>` : ''}
                <div class="stig-count total">
                  <span class="num">${esc(app.stig_total || 0)}</span>
                  <span class="lbl">Total</span>
                </div>
              </div>
              <div style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap" data-stop>
                <span style="font-size:12px;color:var(--text-muted)">Last scanned: ${fmtDate(app.last_scanned)}</span>
                <button class="btn btn-primary btn-sm"
                  ${act('navigate', `#/stig-viewer/${encodeURIComponent(stigScanId)}`)}>
                  ⊞ View Findings
                </button>
                <button class="btn btn-sm"
                  ${act('navigate', `#/scans/${encodeURIComponent(stigScanId)}`)}>
                  Scan Details →
                </button>
              </div>
            </div>`;
        }).join('')
      : emptyState(
          'No STIG results yet',
          'STIG scans do not run on a schedule because they use AI tokens. Trigger one using Run Scan → STIG.',
          `<button class="btn btn-primary" ${act('navigate', '#/new-scan')} style="margin-top:16px">
             ▶ Run STIG Scan
           </button>`,
        );

    // Aggregate totals
    const totOpen  = stigApps.reduce((s, a) => s + (a.stig_open  || 0), 0);
    const totPass  = stigApps.reduce((s, a) => s + (a.stig_pass  || 0), 0);
    const totNa    = stigApps.reduce((s, a) => s + (a.stig_na    || 0), 0);
    const totTotal = stigApps.reduce((s, a) => s + (a.stig_total || 0), 0);

    const summaryBar = stigApps.length ? `
      <div class="stats-grid" style="margin-bottom:24px">
        <div class="stat-card">
          <div class="stat-value">${esc(stigApps.length)}</div>
          <div class="stat-label">Apps with STIG data</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-open)">
          <div class="stat-value" style="color:var(--stig-open)">${esc(totOpen)}</div>
          <div class="stat-label">Total Open</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-pass)">
          <div class="stat-value" style="color:var(--stig-pass)">${esc(totPass)}</div>
          <div class="stat-label">Total Passing</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(totNa)}</div>
          <div class="stat-label">N/A</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--accent)">${esc(totTotal)}</div>
          <div class="stat-label">Total Controls</div>
        </div>
      </div>` : '';

    const stigTabs = `
      <div class="stig-tabs">
        <button class="stig-tab active" ${act('navigate', '#/stig')}>Overview</button>
        <button class="stig-tab" ${act('navigate', '#/stig?view=history')}>History &amp; MTTR</button>
      </div>`;

    page.innerHTML = `
      ${pageHeader(`STIG Compliance`, { actions: `<button class="btn btn-primary"
          ${act('navigate', '#/new-scan')}>▶ Run STIG Scan</button>` })}
      ${stigTabs}
      <p class="section-desc">
        Application Security Developer (AppSecDev) STIG and Crunchy Data PostgreSQL STIG
        compliance results. STIG scans run only when you trigger them.
      </p>
      ${summaryBar}
      <div class="section">
        <div class="section-title">Applications</div>
        ${cards}
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

export async function renderStigViewer(scanId) {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, data] = await Promise.all([api.getScan(scanId), api.getStigData(scanId)]);

    const STATUS_ORDER = ['Open', 'Not a Finding', 'Not Applicable', 'Not Reviewed'];
    const STATUS_CLASS = {
      'Open':          'stig-status-open',
      'Not a Finding': 'stig-status-pass',
      'Not Applicable':'stig-status-na',
      'Not Reviewed':  'stig-status-nr',
    };
    const SEV_ORDER = ['high', 'medium', 'low', ''];

    // Flatten all controls from all STIGs with stig_name label
    const allControls = data.stigs.flatMap(s =>
      s.controls.map(c => ({ ...c, _stig_name: s.stig_name, _slug: s.slug }))
    );

    // Build filter bar state
    let filterStatus = 'all';
    let filterSeverity = 'all';
    let filterStig = 'all';
    let filterText = '';

    // Sort state
    let sortCol = null;   // 'vuln_id' | 'severity' | 'status' | 'confidence' | 'title'
    let sortDir = 'asc';  // 'asc' | 'desc'

    const stigNames = [...new Set(data.stigs.map(s => s.stig_name))];

    function filtered() {
      const rows = allControls.filter(c => {
        if (filterStatus   !== 'all' && c.status   !== filterStatus)   return false;
        if (filterSeverity !== 'all' && c.severity !== filterSeverity) return false;
        if (filterStig     !== 'all' && c._slug    !== filterStig)     return false;
        if (filterText) {
          const q = filterText.toLowerCase();
          if (!c.vuln_id.toLowerCase().includes(q) &&
              !c.title.toLowerCase().includes(q)   &&
              !c.evidence.toLowerCase().includes(q)) return false;
        }
        return true;
      });
      if (sortCol) {
        const dir = sortDir === 'asc' ? 1 : -1;
        rows.sort((a, b) => {
          let av, bv;
          if (sortCol === 'vuln_id') {
            av = (a.group_id || a.vuln_id || '').toLowerCase();
            bv = (b.group_id || b.vuln_id || '').toLowerCase();
          } else if (sortCol === 'severity') {
            av = SEV_ORDER.indexOf(a.severity ?? '');
            bv = SEV_ORDER.indexOf(b.severity ?? '');
            return dir * (av - bv);
          } else if (sortCol === 'status') {
            av = STATUS_ORDER.indexOf(a.status ?? '');
            bv = STATUS_ORDER.indexOf(b.status ?? '');
            return dir * (av - bv);
          } else if (sortCol === 'confidence') {
            av = a.confidence ?? 0;
            bv = b.confidence ?? 0;
            return dir * (av - bv);
          } else {
            av = (a[sortCol] || '').toLowerCase();
            bv = (b[sortCol] || '').toLowerCase();
          }
          return dir * (av < bv ? -1 : av > bv ? 1 : 0);
        });
      }
      return rows;
    }

    function countsByStatus() {
      const out = {};
      for (const c of allControls) out[c.status] = (out[c.status] || 0) + 1;
      return out;
    }

    function renderTable() {
      const rows = filtered();
      if (!rows.length) {
        return '<div class="stig-empty">No controls match the current filters.</div>';
      }
      return `
        <div class="stig-viewer-count" style="display:flex;align-items:center;gap:12px">
          <span>${rows.length} control${rows.length !== 1 ? 's' : ''}</span>
          <button class="btn" id="stig-jira-bulk" ${act('openStigJiraModal', scanId)} ${_stigJiraSel.size ? '' : 'disabled'}>Add ${_stigJiraSel.size || ''} to Jira</button>
          <button class="btn" id="stig-lock-bulk" ${act('openStigBulkLockModal', scanId)} ${_stigJiraSel.size ? '' : 'disabled'}>🔒 Lock ${_stigJiraSel.size || ''}</button>
        </div>
        <div class="stig-table-wrap">
          <table class="stig-table">
            <thead>
              <tr>
                <th scope="col" style="width:32px"><input type="checkbox" aria-label="Select all shown" ${actOn('click','stigJiraToggleAll', ARG.checked)} data-stop ${rows.length && rows.every(r => _stigJiraSel.has(`${r.vuln_id}__${r._slug}`)) ? 'checked' : ''}></th>
                ${[
                  ['vuln_id',    '100px', 'STIG #'],
                  ['severity',   '70px',  'Severity'],
                  ['status',     '130px', 'Status'],
                  ['confidence', '80px',  'Confidence'],
                  ['title',      null,    'Title'],
                ].map(([col, w, label]) => {
                  const active = sortCol === col;
                  const icon = active ? (sortDir === 'asc' ? '↑' : '↓') : '⇅';
                  const style = w ? `style="width:${w}"` : '';
                  return `<th scope="col" class="stig-sortable-th${active ? ' stig-sort-active' : ''}" ${style} ${act('setStigSort', `${col}`)}>${label} <span class="stig-sort-icon">${icon}</span></th>`;
                }).join('')}
                ${stigNames.length > 1 ? '<th scope="col" style="width:140px">STIG</th>' : ''}
              </tr>
            </thead>
            <tbody>
              ${rows.map(c => {
                const regKey = `${c.vuln_id}__${c._slug}`;
                _stigRegistry.set(regKey, { c, scanId });
                const rowId = `stig-row-${esc(c.vuln_id)}-${esc(c._slug)}`;
                const sname = c._stig_name.replace(/.*?(ASD|Postgres|STIG)/gi, '$1').trim().slice(0, 40);
                const conf  = c.confidence ?? 0;
                const confClass = conf >= 90 ? 'conf-high' : conf >= 70 ? 'conf-med' : conf >= 40 ? 'conf-low' : 'conf-none';
                return `
                  <tr class="stig-tr stig-tr-clickable" id="${rowId}" ${act('openStigDetail', regKey)}>
                    <td data-stop><input type="checkbox" aria-label="Select ${esc(c.vuln_id)}" ${_stigJiraSel.has(regKey) ? 'checked' : ''} ${actOn('click','stigJiraToggle', regKey, ARG.checked, ARG.shift)}></td>
                    <td><code class="stig-id">${esc(c.group_id || c.vuln_id)}</code></td>
                    <td><span class="stig-sev stig-sev-${esc(c.severity)}">${esc(c.severity || '—')}</span></td>
                    <td><span class="${esc(STATUS_CLASS[c.status] || 'stig-status-nr')}">${esc(stigStatusLabel(c.status))}</span>${c.locked_by_human ? ' <span class="stig-lock-badge" title="Human-reviewed; locked until a listed path changes">🔒</span>' : ''}${c.locked_by_stability ? ' <span class="stig-lock-badge" title="No repository evidence found across repeated scans — not re-assessed by AI to save time/tokens until code changes">💤</span>' : ''}</td>
                    <td><span class="stig-confidence ${confClass}" title="${conf}/100">${conf}</span></td>
                    <td class="stig-title-cell">${esc(c.title)}</td>
                    ${stigNames.length > 1 ? `<td class="stig-stig-cell" title="${esc(c._stig_name)}">${esc(sname)}</td>` : ''}
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`;
    }

    function renderFilters() {
      const counts = countsByStatus();
      return `
        <div class="stig-filters">
          <div class="stig-filter-group">
            <label class="stig-filter-label">Status</label>
            <div class="stig-filter-btns" id="filter-status">
              ${['all', ...STATUS_ORDER].map(s => `
                <button class="stig-filter-btn${filterStatus === s ? ' active' : ''}"
                  ${act('setStigFilter', 'status', `${s}`)}>${s === 'all' ? 'All' : esc(stigStatusLabel(s))}${s !== 'all' && counts[s] ? ` <span class="stig-filter-count">${counts[s]}</span>` : ''}</button>
              `).join('')}
            </div>
          </div>
          <div class="stig-filter-group">
            <label class="stig-filter-label">Severity</label>
            <div class="stig-filter-btns">
              ${['all', 'high', 'medium', 'low'].map(s => `
                <button class="stig-filter-btn${filterSeverity === s ? ' active' : ''}"
                  ${act('setStigFilter', 'severity', `${s}`)}>${s === 'all' ? 'All' : ucFirst(s)}</button>
              `).join('')}
            </div>
          </div>
          ${stigNames.length > 1 ? `
          <div class="stig-filter-group">
            <label class="stig-filter-label">STIG</label>
            <div class="stig-filter-btns">
              <button class="stig-filter-btn${filterStig === 'all' ? ' active' : ''}"
                ${act('setStigFilter', 'stig', 'all')}>All</button>
              ${data.stigs.map(s => `
                <button class="stig-filter-btn${filterStig === s.slug ? ' active' : ''}"
                  ${act('setStigFilter', 'stig', s.slug)}
                  title="${esc(s.stig_name)}">${esc(s.stig_name.slice(0, 30))}…</button>
              `).join('')}
            </div>
          </div>` : ''}
          <div class="stig-filter-group">
            <label class="stig-filter-label">Search</label>
            <input class="stig-search" type="text" placeholder="ID, title, or evidence…"
              value="${esc(filterText)}"
              ${actOn('input','setStigSearch', ARG.value)}>
          </div>
        </div>`;
    }

    function repaint() {
      const el = document.getElementById('stig-viewer-filters');
      if (el) el.outerHTML = renderFilters().replace('<div class="stig-filters">', '<div class="stig-filters" id="stig-viewer-filters">');
      const tbody = document.getElementById('stig-viewer-body');
      if (tbody) tbody.innerHTML = renderTable();
    }

    // Expose callbacks to global scope for onclick handlers
    window.setStigFilter = (type, val) => {
      if (type === 'status')   filterStatus   = val;
      if (type === 'severity') filterSeverity = val;
      if (type === 'stig')     filterStig     = val;
      repaint();
    };
    window.setStigSearch = (val) => { filterText = val; repaint(); };
    window.setStigSort   = (col) => {
      if (sortCol === col) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortCol = col;
        sortDir = 'asc';
      }
      repaint();
    };
    window.openStigDetail = (regKey) => {
      openStigViewerDetail(regKey);
    };
    window.updateStigControlsInPlace = (updates) => {
      let found = 0;
      for (const { slug, vulnId, patch } of updates) {
        const c = allControls.find(x => x.vuln_id === vulnId && x._slug === slug);
        if (c) { Object.assign(c, patch); found++; }
      }
      if (!found) return false;
      repaint();
      const cnt = countsByStatus();
      document.querySelectorAll('.stig-totals-bar .stig-total-chip').forEach(chip => {
        const num = chip.querySelector('.num');
        const key = chip.classList.contains('open') ? 'Open' : chip.classList.contains('pass') ? 'Not a Finding'
          : chip.classList.contains('na') ? 'Not Applicable' : chip.classList.contains('nr') ? 'Not Reviewed' : null;
        if (num && key) num.textContent = cnt[key] || 0;
      });
      return true;
    };
    window.updateStigControlInPlace = (slug, vulnId, patch) =>
      window.updateStigControlsInPlace([{ slug, vulnId, patch }]);
    _stigJiraSel.clear();
    let lastStigClicked = null;
    window.stigJiraToggle = (regKey, on, shift) => {
      const keys = filtered().map(r => `${r.vuln_id}__${r._slug}`);
      const from = shift && lastStigClicked ? keys.indexOf(lastStigClicked) : -1;
      const to = keys.indexOf(regKey);
      const range = from >= 0 && to >= 0 ? keys.slice(Math.min(from, to), Math.max(from, to) + 1) : [regKey];
      range.forEach(k => { if (on) _stigJiraSel.add(k); else _stigJiraSel.delete(k); });
      lastStigClicked = regKey;
      repaint();
    };
    window.stigJiraToggleAll = (on) => {
      filtered().forEach(r => {
        const k = `${r.vuln_id}__${r._slug}`;
        if (on) _stigJiraSel.add(k); else _stigJiraSel.delete(k);
      });
      repaint();
    };

    const counts = countsByStatus();
    const backLink = scan.target
      ? `<a href="#/scans/${encodeURIComponent(scanId)}" ${act('navigate', `#/scans/${encodeURIComponent(scanId)}`)}>${esc(scanId)}</a>`
      : esc(scanId);

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" ${act('navigate', '#/applications')}>Applications</a>
        <span>›</span>
        <a href="#/applications/${encodeURIComponent(scan.target)}"
           ${act('navigate', `#/applications/${encodeURIComponent(scan.target)}`)}>${esc(scan.target)}</a>
        <span>›</span>
        <a href="#/scans/${encodeURIComponent(scanId)}"
           ${act('navigate', `#/scans/${encodeURIComponent(scanId)}`)}>${esc(scanId)}</a>
        <span>›</span>
        <span>STIG Findings</span>
      </div>

      ${pageHeader(`STIG Findings`, { actions: `${data.stigs.map(s => {
            const mdUrl   = s.md_url   || `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.md`;
            const cklbUrl = s.cklb_url || `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.cklb`;
            return `
              <a class="btn btn-sm" href="${esc(mdUrl)}"   download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.md</a>
              <a class="btn btn-sm" href="${esc(cklbUrl)}" download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.cklb</a>
              <a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/stig-findings-json?slug=${encodeURIComponent(s.slug)}" download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.json</a>`;
          }).join('')}` })}

      <div class="stig-totals-bar">
        <div class="stig-total-chip open">
          <span class="num">${counts['Open'] || 0}</span><span class="lbl">Open</span>
        </div>
        <div class="stig-total-chip pass">
          <span class="num">${counts['Not a Finding'] || 0}</span><span class="lbl">Not a Finding</span>
        </div>
        <div class="stig-total-chip na">
          <span class="num">${counts['Not Applicable'] || 0}</span><span class="lbl">N/A</span>
        </div>
        <div class="stig-total-chip nr">
          <span class="num">${counts['Not Reviewed'] || 0}</span><span class="lbl">Evidence needed</span>
        </div>
        <div class="stig-total-chip total">
          <span class="num">${allControls.length}</span><span class="lbl">Total</span>
        </div>
      </div>

      <div id="stig-viewer-filters">${renderFilters().replace('<div class="stig-filters">', '')}</div>

      <div id="stig-viewer-body">${renderTable()}</div>`;

    // Fix up filter container id after innerHTML set
    const fEl = page.querySelector('.stig-filters');
    if (fEl) fEl.id = 'stig-viewer-filters';

  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}
