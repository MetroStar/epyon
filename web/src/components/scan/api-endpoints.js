import { esc } from '../../lib/format.js';
import { _apiRegistry } from '../../state/registries.js';

// Globals that other modules put on window (see index.js):
/* global apiRender */

let _apiNextId = 0;

export function buildAPISection(apiData) {
  if (!apiData || apiData.total === 0) return '';
  const uid = 'api-' + Math.random().toString(36).slice(2);

  // Create method filter chips
  const methodChips = Object.entries(apiData.by_method || {})
    .sort((a, b) => b[1] - a[1])
    .map(([method, count]) => {
      const color = {
        'GET': '#10b981',
        'POST': '#f59e0b',
        'PUT': '#3b82f6',
        'DELETE': '#ef4444',
        'PATCH': '#8b5cf6'
      }[method] || '#6b7280';
      return `<span class="tool-tag api-method-chip" style="cursor:pointer;background:${color};color:white" data-api="${uid}" data-method="${esc(method)}" onclick="apiFilterMethod('${uid}','${esc(method)}')">${esc(method)} <strong>${count}</strong></span>`;
    })
    .join('');

  // Create framework filter chips
  const frameworkChips = Object.entries(apiData.by_framework || {})
    .sort((a, b) => b[1] - a[1])
    .map(([fw, count]) => 
      `<span class="tool-tag api-fw-chip" style="cursor:pointer" data-api="${uid}" data-fw="${esc(fw)}" onclick="apiFilterFramework('${uid}','${esc(fw)}')">${esc(fw)} <strong>${count}</strong></span>`
    )
    .join('');

  const allEndpoints = (apiData.endpoints || []).map(ep => ({
    method:     ep.method || '',
    path:       ep.path || '',
    function:   ep.function || ep.handler || '',
    name:       ep.name || '',
    framework:  ep.framework || '',
    auth:       ep.auth || ep.authentication || '',
    tags:       ep.tags || '',
    file:       ep.file || ep.location || '',
  }));

  // Store data synchronously
  window._apiData = window._apiData || {};
  window._apiData[uid] = { endpoints: allEndpoints, sortCol: null, sortDir: 'asc', filterMethod: null, filterFramework: null };
  window._apiPendingUid = uid;

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--pass)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">🔌 API Discovery</span>
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(apiData.total))} endpoints</span>
            ${methodChips}
            ${frameworkChips}
          </span>
          <span class="findings-summary-right" onclick="event.stopPropagation()">
            <button class="btn btn-sm" onclick="downloadApiCsv('${uid}')" title="Download API endpoints as CSV">↓ API List</button>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div style="margin-top:12px;display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <input id="${uid}-search" type="text" placeholder="Search endpoints…"
              style="flex:1;min-width:180px;max-width:320px;padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);font-size:13px"
              oninput="apiRender('${uid}')" />
            <span id="${uid}-count" style="font-size:12px;color:var(--text-muted)"></span>
            <button class="btn btn-sm" onclick="apiClearFilter('${uid}')">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','method')">Method <span id="${uid}-sort-method"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','function')">Function <span id="${uid}-sort-function"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','framework')">Framework <span id="${uid}-sort-framework"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','auth')">Auth <span id="${uid}-sort-auth"></span></th>
                  <th scope="col" style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','file')">File <span id="${uid}-sort-file"></span></th>
                </tr>
              </thead>
              <tbody id="${uid}-tbody"></tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

window.apiSort = function(uid, col) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  if (s.sortCol === col) {
    s.sortDir = s.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    s.sortCol = col;
    s.sortDir = 'asc';
  }
  apiRender(uid);
};

window.apiFilterMethod = function(uid, method) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterMethod = s.filterMethod === method ? null : method;
  document.querySelectorAll(`.api-method-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterMethod || el.dataset.method === s.filterMethod) ? '1' : '0.4';
    el.style.outline = el.dataset.method === s.filterMethod ? '2px solid #6366f1' : '';
  });
  apiRender(uid);
};

window.apiFilterFramework = function(uid, fw) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterFramework = s.filterFramework === fw ? null : fw;
  document.querySelectorAll(`.api-fw-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = (!s.filterFramework || el.dataset.fw === s.filterFramework) ? '1' : '0.4';
    el.style.outline = el.dataset.fw === s.filterFramework ? '2px solid #6366f1' : '';
  });
  apiRender(uid);
};

window.apiClearFilter = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  s.filterMethod = null;
  s.filterFramework = null;
  s.sortCol = null;
  s.sortDir = 'asc';
  const input = document.getElementById(uid + '-search');
  if (input) input.value = '';
  document.querySelectorAll(`.api-method-chip[data-api="${uid}"],.api-fw-chip[data-api="${uid}"]`).forEach(el => {
    el.style.opacity = '1';
    el.style.outline = '';
  });
  ['method','path','function','framework','auth','file'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) el.textContent = '';
  });
  apiRender(uid);
};

window.downloadApiCsv = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s || !s.endpoints) return;
  const headers = ['Method','Path','Function','Name','Framework','Auth','Tags','File'];
  const rows = [headers, ...s.endpoints.map(ep => [
    ep.method, ep.path, ep.function, ep.name, ep.framework, ep.auth, ep.tags, ep.file,
  ])];
  const csv = rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: `api-endpoints-${uid}.csv` });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
};

window.apiRender = function(uid) {
  const s = window._apiData && window._apiData[uid];
  if (!s) return;
  const tbody = document.getElementById(uid + '-tbody');
  const countEl = document.getElementById(uid + '-count');
  if (!tbody) return;

  const query = (document.getElementById(uid + '-search') || {}).value || '';
  const q = query.trim().toLowerCase();

  let items = s.endpoints.slice();

  // Filter by method
  if (s.filterMethod) {
    items = items.filter(ep => ep.method === s.filterMethod);
  }

  // Filter by framework
  if (s.filterFramework) {
    items = items.filter(ep => ep.framework === s.filterFramework);
  }

  // Filter by search
  if (q) {
    items = items.filter(ep =>
      ep.method.toLowerCase().includes(q) ||
      ep.path.toLowerCase().includes(q) ||
      ep.function.toLowerCase().includes(q) ||
      ep.framework.toLowerCase().includes(q) ||
      ep.auth.toLowerCase().includes(q) ||
      ep.file.toLowerCase().includes(q)
    );
  }

  // Sort
  if (s.sortCol) {
    const col = s.sortCol;
    const dir = s.sortDir === 'asc' ? 1 : -1;
    items.sort((a, b) => {
      const av = (a[col] || '').toLowerCase();
      const bv = (b[col] || '').toLowerCase();
      return av < bv ? -dir : av > bv ? dir : 0;
    });
  }

  // Update sort indicators
  ['method','path','function','framework','auth','file'].forEach(c => {
    const el = document.getElementById(uid + '-sort-' + c);
    if (el) {
      if (s.sortCol === c) {
        el.textContent = s.sortDir === 'asc' ? '▲' : '▼';
      } else {
        el.textContent = '';
      }
    }
  });

  // Render rows with registry and onclick handlers
  tbody.innerHTML = items.map(ep => {
    // Register endpoint for detail view
    const epId = _apiNextId++;
    _apiRegistry.set(epId, ep);

    const methodColor = {
      'GET': '#10b981',
      'POST': '#f59e0b',
      'PUT': '#3b82f6',
      'DELETE': '#ef4444',
      'PATCH': '#8b5cf6'
    }[ep.method] || '#6b7280';
    
    const shortFile = ep.file.split('/').slice(-2).join('/') || ep.file;

    return `
      <tr class="api-row" onclick="openAPIDetail(${epId})" title="Click to view details" style="cursor:pointer;border-bottom:1px solid var(--border-subtle)">
        <td style="padding:4px 8px"><span style="background:${methodColor};color:white;padding:2px 6px;border-radius:3px;font-size:12px;font-weight:600">${esc(ep.method)}</span></td>
        <td style="padding:4px 8px;font-family:monospace;font-size:12px">${esc(ep.path)}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:12px">${esc(ep.function) || '—'}</td>
        <td style="padding:4px 8px"><span class="tool-tag">${esc(ep.framework) || '—'}</span></td>
        <td style="padding:4px 8px;color:var(--text-dim);font-size:12px">${esc(ep.auth) || '—'}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:12px" title="${esc(ep.file)}">${esc(shortFile) || '—'}</td>
      </tr>`;
  }).join('');

  if (countEl) {
    const totalCount = s.endpoints.length;
    const filtered = items.length;
    countEl.textContent = filtered === totalCount
      ? `${totalCount} endpoints`
      : `${filtered} of ${totalCount} endpoints`;
  }
};
