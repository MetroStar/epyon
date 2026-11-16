import { findingSourceBadge } from '../badges.js';
import { esc, ucFirst } from '../../lib/format.js';
import { _registerFinding } from '../../state/registries.js';

// Legacy globals still provided by main.js (see index.js):
/* global renderFindingsPage */

// ── Findings sort state (per severity) ───────────────────────
const _currentFindingsBySev = {};

const _sortState             = {};

const _pageState             = {};

const FINDINGS_PAGE_SIZES    = [25, 50, 100, 200];

export function _buildFindingRows(items) {
  return items.map(f => {
    const fid    = _registerFinding(f);
    const id     = esc(f.id    || f.cve_id || '—');
    const tool   = esc(f.tool  || '—');
    const pkg    = esc(f.package || f.component || f.target || '—');
    const ver    = esc(f.version || '');
    const fixed  = esc(f.fixed_version || '');
    const title  = esc((f.title || f.description || f.check_name || '').substring(0, 160));
    const target = esc((f.target || '').substring(0, 80));
    const isSuppressed = f.suppressed === true;

    const idCell = id.startsWith('CVE-')
      ? `<a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer"
            onclick="event.stopPropagation()"><code>${id}</code></a>`
      : `<code>${id}</code>`;

    const cvssNum  = f.nvd_cvss_v3_score != null ? f.nvd_cvss_v3_score : null;
    const cvssSev  = (f.nvd_cvss_v3_severity || '').toUpperCase();
    const cvssColor = cvssSev === 'CRITICAL' ? 'var(--critical)'
                    : cvssSev === 'HIGH'     ? '#f97316'
                    : cvssSev === 'MEDIUM'   ? '#f59e0b'
                    : cvssSev === 'LOW'      ? '#22d3ee'
                    : 'var(--text-muted)';
    const cvssCell = [
      cvssNum != null
        ? `<span style="font-weight:700;color:${cvssColor};font-size:12px" title="CVSS v3: ${cvssNum} ${cvssSev}">${cvssNum}</span>`
        : '',
      f.cisa_kev
        ? `<span style="background:var(--critical-bg);color:var(--critical);font-size:12px;font-weight:700;padding:1px 5px;border-radius:3px;vertical-align:middle;margin-left:${cvssNum != null ? 4 : 0}px" title="CISA Known Exploited Vulnerability">KEV</span>`
        : ''
    ].join('') || '<span style="color:var(--text-dim)">—</span>';

    // Suppressed badge
    const suppressedBadge = isSuppressed
      ? `<span style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent);border-radius:3px;padding:1px 6px;font-size:12px;font-weight:700;margin-left:6px" title="Suppressed by .epyon-ignore.yml">SUPPRESSED</span>`
      : '';

    // For IaC/Checkov findings, show file path and line numbers
    const isIaC = f.type === 'iac_misconfiguration' || f.tool === 'Checkov';
    let locationCell = '';
    if (isIaC && f.file) {
      const filePath = esc(f.file);
      const fileName = filePath.split('/').pop();
      let lineInfo = '';
      if (f.line && Array.isArray(f.line) && f.line.length === 2) {
        lineInfo = f.line[0] === f.line[1] ? `:${f.line[0]}` : `:${f.line[0]}-${f.line[1]}`;
      }
      locationCell = `<code style="font-size:12px;color:var(--accent)" title="${filePath}${lineInfo}">${fileName}${lineInfo}</code>`;
    }

    // Apply dimmed styling to suppressed findings
    const rowStyle = isSuppressed ? 'opacity:0.5' : '';

    return `
      <tr class="finding-row" onclick="openFindingDetail(${fid})" title="Click to view details" style="${rowStyle}">
        <td>
          <span class="tool-tag">${tool}</span>${suppressedBadge}
          <div style="margin-top:3px">${findingSourceBadge(f)}</div>
        </td>
        <td>${idCell}</td>
        <td style="max-width:360px">${title}${locationCell ? `<div style="margin-top:4px">${locationCell}</div>` : ''}</td>
        <td>${pkg}${ver ? ` <span style="color:var(--text-dim);font-size:12px">${ver}</span>` : ''}</td>
        <td style="white-space:nowrap">${cvssCell}</td>
        <td>${fixed ? `<span style="color:var(--clean)">${fixed}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
        <td style="color:var(--text-muted);font-size:12px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${target}">${target || '—'}</td>
      </tr>`;
  }).join('');
}

window.sortFindingsBy = function(sev, col) {
  const state = _sortState[sev] || { col: null, dir: 'asc' };
  if (state.col === col) {
    state.dir = state.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.col = col;
    state.dir = 'asc';
  }
  _sortState[sev] = state;

  const items = _currentFindingsBySev[sev] || [];
  const dir   = state.dir === 'asc' ? 1 : -1;

  items.sort((a, b) => {
    let av, bv;
    switch (col) {
      case 'tool':    av = (a.tool    || '').toLowerCase(); bv = (b.tool    || '').toLowerCase(); break;
      case 'id':      av = (a.id     || a.cve_id || '').toLowerCase(); bv = (b.id || b.cve_id || '').toLowerCase(); break;
      case 'title':   av = (a.title  || a.description || '').toLowerCase(); bv = (b.title || b.description || '').toLowerCase(); break;
      case 'package': av = (a.package || a.component || '').toLowerCase(); bv = (b.package || b.component || '').toLowerCase(); break;
      case 'cvss':    av = a.nvd_cvss_v3_score ?? -1; bv = b.nvd_cvss_v3_score ?? -1; break;
      case 'fix':     av = a.fixed_version ? 1 : 0; bv = b.fixed_version ? 1 : 0; break;
      case 'target':  av = (a.target  || '').toLowerCase(); bv = (b.target  || '').toLowerCase(); break;
      default: return 0;
    }
    if (typeof av === 'string') return dir * av.localeCompare(bv);
    return dir * (av - bv);
  });

  (_pageState[sev] || (_pageState[sev] = { page: 1, size: 50 })).page = 1;
  renderFindingsPage(sev);

  // Update sort-direction indicator on th elements
  const section = document.getElementById(`findings-section-${sev}`);
  if (section) {
    section.querySelectorAll('.sortable-th').forEach(th => {
      if (th.dataset.col === col) {
        th.dataset.sortDir = state.dir;
      } else {
        delete th.dataset.sortDir;
      }
    });
  }
};

export function _findingsPagerHtml(sev) {
  const all = _currentFindingsBySev[sev] || [];
  const st = _pageState[sev];
  if (all.length <= FINDINGS_PAGE_SIZES[0]) return '';
  const pages = Math.max(1, Math.ceil(all.length / st.size));
  const first = (st.page - 1) * st.size + 1;
  const last = Math.min(all.length, st.page * st.size);
  const btn = (label, page, disabled) =>
    `<button type="button" class="btn btn-sm" ${disabled ? 'disabled' : ''} onclick="setFindingsPage('${sev}', ${page})">${label}</button>`;
  const sizeOpts = FINDINGS_PAGE_SIZES.map(n => `<option value="${n}" ${n === st.size ? 'selected' : ''}>${n}</option>`).join('');
  return `<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:10px 4px;font-size:13px;color:var(--text-muted)">
    <span>Showing ${first}–${last} of ${all.length} findings</span>
    <span style="display:flex;gap:6px;align-items:center">
      <label>Per page <select onchange="setFindingsPageSize('${sev}', this.value)">${sizeOpts}</select></label>
      ${btn('« First', 1, st.page <= 1)}${btn('‹ Prev', st.page - 1, st.page <= 1)}
      <span>Page ${st.page} of ${pages}</span>
      ${btn('Next ›', st.page + 1, st.page >= pages)}${btn('Last »', pages, st.page >= pages)}
    </span>
  </div>`;
}

window.renderFindingsPage = function(sev) {
  const all = _currentFindingsBySev[sev] || [];
  const st = _pageState[sev] || (_pageState[sev] = { page: 1, size: 50 });
  const pages = Math.max(1, Math.ceil(all.length / st.size));
  st.page = Math.min(Math.max(1, st.page), pages);
  const tbody = document.getElementById(`findings-tbody-${sev}`);
  if (tbody) tbody.innerHTML = _buildFindingRows(all.slice((st.page - 1) * st.size, st.page * st.size));
  const pager = document.getElementById(`findings-pager-${sev}`);
  if (pager) {
    const controls = [...pager.querySelectorAll('button, select')];
    const focusIndex = controls.indexOf(document.activeElement);
    pager.innerHTML = _findingsPagerHtml(sev);
    if (focusIndex >= 0) {
      const updatedControls = [...pager.querySelectorAll('button, select')];
      const previousControl = updatedControls[focusIndex];
      const focusTarget = previousControl && !previousControl.disabled
        ? previousControl
        : updatedControls.find(control => !control.disabled);
      focusTarget?.focus({ preventScroll: true });
    }
  }
};

window.setFindingsPage = function(sev, page) {
  _pageState[sev].page = page;
  renderFindingsPage(sev);
};

window.setFindingsPageSize = function(sev, size) {
  _pageState[sev].size = parseInt(size, 10) || 50;
  _pageState[sev].page = 1;
  renderFindingsPage(sev);
};

export function buildFindingsSection(findings) {
  const severities = ['critical', 'high', 'medium', 'low'];
  let html = '';
  let anyFindings = false;

  // Reset sort state for this render
  for (const sev of severities) {
    _currentFindingsBySev[sev] = [];
    _sortState[sev] = { col: null, dir: 'asc' };
    _pageState[sev] = { page: 1, size: 50 };
  }

  // Always show all severity levels, even if empty
  for (const sev of severities) {
    const allItems = findings[`${sev}_findings`] || [];
    _currentFindingsBySev[sev] = allItems;
    const items = allItems.slice(0, _pageState[sev].size);
    
    if (allItems.length > 0) {
      anyFindings = true;
      
      // Count suppressed findings
      const suppressedCount = allItems.filter(f => f.suppressed === true).length;
      const activeCount = allItems.length - suppressedCount;

      // Build count badge with suppressed indicator
      const countBadge = suppressedCount > 0
        ? `<span class="sev-badge ${esc(sev)}">${activeCount}</span><span style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent);border-radius:3px;padding:1px 6px;font-size:12px;font-weight:700;margin-left:4px" title="${suppressedCount} suppressed by .epyon-ignore.yml">${suppressedCount} suppressed</span>`
        : `<span class="sev-badge ${esc(sev)}">${allItems.length}</span>`;

      html += `
        <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
              ${countBadge}
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body">
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th scope="col" class="sortable-th" data-col="tool"    onclick="sortFindingsBy('${sev}','tool')">Tool <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="id"      onclick="sortFindingsBy('${sev}','id')">CVE / ID <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="title"   onclick="sortFindingsBy('${sev}','title')">Title <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="package" onclick="sortFindingsBy('${sev}','package')">Package <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="cvss"    onclick="sortFindingsBy('${sev}','cvss')" style="white-space:nowrap">CVSS / KEV <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="fix"     onclick="sortFindingsBy('${sev}','fix')">Fix Available <span class="sort-icon">⇅</span></th>
                    <th scope="col" class="sortable-th" data-col="target"  onclick="sortFindingsBy('${sev}','target')">Location <span class="sort-icon">⇅</span></th>
                  </tr>
                </thead>
                <tbody id="findings-tbody-${esc(sev)}">${_buildFindingRows(items)}</tbody>
              </table>
            </div>
            <div id="findings-pager-${esc(sev)}">${_findingsPagerHtml(sev)}</div>
          </div>
        </details>`;
    } else {
      // Empty severity level - show with 0 badge
      html += `
        <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}" style="opacity:0.6">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
              <span class="sev-badge clean" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">0</span>
            </span>
            <span class="findings-summary-hint" style="color:var(--text-dim)">No findings</span>
          </summary>
          <div class="findings-body">
            <div style="padding:12px 18px;color:var(--text-muted);font-size:13px;text-align:center">
              ✓ No ${sev} severity findings detected
            </div>
          </div>
        </details>`;
    }
  }

  // ── Enrichment metadata banner ──────────────────────────────
  const enr = findings && findings.enrichment;
  let enrichmentBanner = '';
  if (enr && (enr.cisa_kev_total || enr.nvd_total)) {
    const kevTotal  = enr.cisa_kev_total || 0;
    const nvdTotal  = enr.nvd_total || 0;
    let enrichedAt = '';
    if (enr.enriched_at) {
      try { enrichedAt = new Date(enr.enriched_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); }
      catch (_) { enrichedAt = enr.enriched_at; }
    }
    const catalogLink = enr.kev_catalog_url
      ? ` &nbsp;<a href="${esc(enr.kev_catalog_url)}" target="_blank" rel="noopener"
           style="color:var(--accent);font-size:12px">↗ CISA KEV Catalog</a>`
      : '';
    enrichmentBanner = `
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px;font-size:12px;color:var(--text-muted)">
        ${kevTotal > 0 ? `<span style="background:var(--critical-bg);color:var(--critical);border:1px solid #b91c1c;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
        ${nvdTotal > 0 ? `<span style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:1px 8px;font-size:12px">${esc(nvdTotal)} NVD enriched</span>` : ''}
        ${enrichedAt ? `<span style="font-size:12px;color:var(--text-dim)">enriched ${enrichedAt}</span>` : ''}
        ${catalogLink}
        ${kevTotal > 0 ? `<span style="color:var(--critical);font-size:12px">⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} actively exploited in the wild — see <strong>KEV</strong> badges below</span>` : ''}
      </div>`;
  }

  // Add summary message when no findings at all
  const summaryMessage = !anyFindings
    ? '<div style="padding:12px 0;color:var(--text-muted);font-size:14px"><strong>✓ All vulnerability scans completed successfully with no findings.</strong></div>'
    : '';

  return `
    <div class="section findings-section-wrapper">
      <div class="section-title">Vulnerabilities</div>
      ${enrichmentBanner}
      ${summaryMessage}
      ${html}
    </div>`;
}

// Called on every navigation (setActive) so one scan's sort/page state never leaks into the next.
export function resetFindingsViewState() {
  for (const state of [_currentFindingsBySev, _sortState, _pageState]) {
    for (const k of Object.keys(state)) delete state[k];
  }
}
