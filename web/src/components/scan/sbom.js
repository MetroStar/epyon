import { esc } from '../../lib/format.js';
import { _depsRegistry } from '../../state/registries.js';

// Legacy globals still provided by main.js (see index.js):
/* global sbomRender */

let _depsNextId = 0;

export function buildSBOMSection(sbom, scanId) {
  if (!sbom || sbom.total === 0) return '';
  const byType = sbom.by_type || {};
  const uid = 'sbom-' + Math.random().toString(36).slice(2);

  const typeChips = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<span class="tool-tag sbom-type-chip" style="cursor:pointer" data-sbom="${uid}" data-type="${esc(t)}" onclick="sbomFilterType('${uid}','${esc(t)}')">${esc(t)} <strong>${n}</strong></span>`)
    .join('');

  const allPackages = (sbom.packages || []).map(p => ({
    name:     p.name     || '',
    version:  p.version  || '',
    type:     p.type     || '',
    language: p.language || '',
    purl:     p.purl     || '',
    license:  (p.licenses || []).filter(Boolean).join(', ') || '',
    path:     p.path     || '',
  }));

  // Store data synchronously — script tags injected via innerHTML don't execute
  window._sbomData = window._sbomData || {};
  window._sbomData[uid] = { packages: allPackages, sortCol: null, sortDir: 'asc', filterType: null };
  window._sbomPendingUid = uid;

  const cdxUrl = scanId
    ? `/api/scans/${encodeURIComponent(scanId)}/sbom/cyclonedx`
    : null;

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">📦 SBOM</span>
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(sbom.total))} packages</span>
            ${typeChips}
          </span>
          <span style="display:flex;align-items:center;gap:10px">
            ${cdxUrl ? `<a class="btn btn-sm" href="${cdxUrl}" download style="font-size:12px" onclick="event.stopPropagation()">↓ CycloneDX JSON</a>` : ''}
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div style="margin-top:12px;display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <input id="${uid}-search" type="text" placeholder="Search packages…"
              style="flex:1;min-width:180px;max-width:320px;padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);font-size:13px"
              oninput="sbomRender('${uid}')" />
            <span id="${uid}-count" style="font-size:12px;color:var(--text-muted)"></span>
            <button class="btn btn-sm" onclick="sbomClearFilter('${uid}')">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','name')">Name <span id="${uid}-sort-name"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','version')">Version <span id="${uid}-sort-version"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','type')">Type <span id="${uid}-sort-type"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','license')">License <span id="${uid}-sort-license"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
                </tr>
              </thead>
              <tbody id="${uid}-tbody"></tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

window.sbomSort = function(uid, col) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  if (s.sortCol === col) {
    s.sortDir = s.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    s.sortCol = col;
    s.sortDir = 'asc';
  }
  sbomRender(uid);
};

window.sbomFilterType = function(uid, type) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  s.filterType = s.filterType === type ? null : type;
  // Toggle chip active style
  document.querySelectorAll(`.sbom-type-chip[data-sbom="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterType || el.dataset.type === s.filterType) ? '1' : '0.4';
    el.style.outline = el.dataset.type === s.filterType ? '2px solid #6366f1' : '';
  });
  sbomRender(uid);
};

window.sbomClearFilter = function(uid) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  s.filterType = null;
  s.sortCol = null;
  s.sortDir = 'asc';
  const input = document.getElementById(uid + '-search');
  if (input) input.value = '';
  document.querySelectorAll(`.sbom-type-chip[data-sbom="${uid}"]`).forEach(el => {
    el.style.opacity = '1';
    el.style.outline = '';
  });
  ['name','version','type','license','path'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) el.textContent = '';
  });
  sbomRender(uid);
};

window.sbomRender = function(uid) {
  const s = window._sbomData && window._sbomData[uid];
  if (!s) return;
  const tbody = document.getElementById(uid + '-tbody');
  const countEl = document.getElementById(uid + '-count');
  if (!tbody) return;

  const query = (document.getElementById(uid + '-search') || {}).value || '';
  const q = query.trim().toLowerCase();

  let items = s.packages.slice();

  // Filter by type chip
  if (s.filterType) {
    items = items.filter(p => p.type === s.filterType);
  }

  // Filter by search
  if (q) {
    items = items.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.version.toLowerCase().includes(q) ||
      p.type.toLowerCase().includes(q) ||
      p.license.toLowerCase().includes(q) ||
      p.path.toLowerCase().includes(q)
    );
  }

  // Sort
  if (s.sortCol) {
    const col = s.sortCol;
    const dir = s.sortDir === 'asc' ? 1 : -1;
    items.sort((a, b) => a[col].toLowerCase() < b[col].toLowerCase() ? -dir : a[col].toLowerCase() > b[col].toLowerCase() ? dir : 0);
  }

  // Update sort indicators
  ['name','version','type','license','path'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (!el) return;
    if (c === s.sortCol) {
      el.textContent = s.sortDir === 'asc' ? ' ▲' : ' ▼';
    } else {
      el.textContent = ' ⇅';
    }
  });

  if (countEl) {
    countEl.textContent = items.length === s.packages.length
      ? `${s.packages.length} packages`
      : `${items.length} of ${s.packages.length} packages`;
  }

  tbody.innerHTML = items.map(p => {
    const did = _depsNextId++;
    _depsRegistry.set(did, p);
    return `<tr class="finding-row" style="cursor:pointer" onclick="openDependencyDetail(${did})" title="Click to view details">
      <td style="font-family:monospace;font-size:12px;padding:3px 8px">${esc(p.name)}</td>
      <td style="font-size:12px;padding:3px 8px">${esc(p.version)}</td>
      <td style="padding:3px 8px"><span class="tool-tag" style="font-size:12px;padding:1px 6px">${esc(p.type)}</span></td>
      <td style="font-size:12px;color:var(--text-muted);padding:3px 8px">${esc(p.license)}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--text-muted);padding:3px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">${esc(p.path)}</td>
    </tr>`;
  }).join('');
};
