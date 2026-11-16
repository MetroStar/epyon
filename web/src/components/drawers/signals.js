import { closeFindingDetail } from './finding.js';
import { esc, act } from '../../lib/format.js';
import { navigate } from '../../core/router.js';
import { _apiRegistry, _depsRegistry } from '../../state/registries.js';


// ── GitHub Signals detail drawer ──────────────────────────────
export function openGhSignalDetail(kind, idx) {
  if (!window._ghSignalData) return;
  closeGhSignalDetail();

  let title = '', bodyHtml = '', repoUrl = '';

  if (kind === 'run') {
    const r = window._ghSignalData.run[idx];
    if (!r) return;
    const repoShort = r.repo.split('/')[1] || r.repo;
    repoUrl = `https://github.com/${r.repo}/actions`;
    title = `Workflow Runs — ${repoShort}`;
    const rate = r.success_rate != null ? r.success_rate : null;
    const rateColor = rate == null ? 'var(--text-muted)' : rate >= 90 ? 'var(--clean)' : rate >= 70 ? '#e3b341' : 'var(--critical)';
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Repository</div>
          <div class="finding-detail-value"><code>${esc(r.repo)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Success Rate (30d)</div>
          <div class="finding-detail-value" style="color:${rateColor};font-weight:700;font-size:22px">${rate != null ? rate + '%' : '—'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Total Runs</div>
          <div class="finding-detail-value">${r.total_runs || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">In Progress / Queued</div>
          <div class="finding-detail-value">${r.in_progress || 0}</div>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Run Breakdown</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(63,185,80,.15);color:var(--clean);padding:4px 10px;border-radius:6px;font-weight:700">✓ Success: ${r.success||0}</span>
          <span style="background:rgba(248,81,73,.15);color:var(--critical);padding:4px 10px;border-radius:6px;font-weight:700">✗ Failed: ${r.failed||0}</span>
          <span style="background:rgba(139,148,158,.15);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">⊘ Skipped: ${r.skipped||0}</span>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <a href="${esc(repoUrl)}" target="_blank" rel="noopener noreferrer"
           style="display:inline-flex;align-items:center;gap:6px;color:var(--accent);font-size:13px;text-decoration:none">
          View Actions on GitHub
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
      </div>`;

  } else if (kind === 'cov') {
    const [name, v] = window._ghSignalData.cov[idx] || [];
    if (!name) return;
    title = `PR Scan Coverage — ${esc(name)}`;
    const pct = v.pr_coverage_pct;
    const barColor = pct >= 70 ? 'var(--clean)' : pct >= 40 ? '#e3b341' : 'var(--critical)';
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Application</div>
          <div class="finding-detail-value"><strong>${esc(name)}</strong></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">PR Scan Coverage</div>
          <div class="finding-detail-value" style="color:${barColor};font-weight:700;font-size:22px">${pct}%</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">PR-Triggered Scans</div>
          <div class="finding-detail-value">${v.pr_scans}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Total CI Scans</div>
          <div class="finding-detail-value">${v.total_ci_scans}</div>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Coverage Bar</div>
        <div style="display:flex;align-items:center;gap:10px;margin-top:8px">
          <div style="flex:1;background:var(--border);border-radius:6px;height:12px;overflow:hidden">
            <div style="width:${Math.min(pct,100)}%;background:${barColor};height:100%;border-radius:6px;transition:width .3s"></div>
          </div>
          <span style="font-weight:700;color:${barColor}">${pct}%</span>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Scan Breakdown</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(121,192,255,.12);color:var(--accent);padding:4px 10px;border-radius:6px;font-weight:700">PR: ${v.pr_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Push: ${v.push_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Other: ${v.other_scans}</span>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <button class="btn btn-ai" ${act('openAppFromSignalDrawer', name)}>
          View Application Scans
        </button>
      </div>`;
  }

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'gh-signal-drawer-overlay';
  overlay.addEventListener('click', closeGhSignalDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'gh-signal-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', title);
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${title}</h2>
      </div>
      <button class="finding-drawer-close" ${act('closeGhSignalDetail')} aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">${bodyHtml}</div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

export function openAppFromSignalDrawer(name) {
  closeGhSignalDetail();
  navigate(`#/applications/${encodeURIComponent(name)}`);
}

export function closeGhSignalDetail() {
  const overlay = document.getElementById('gh-signal-drawer-overlay');
  const drawer  = document.getElementById('gh-signal-drawer');
  overlay?.remove();
  drawer?.remove();
}

// ── API endpoint detail drawer ────────────────────────────────
export function openAPIDetail(id) {
  const ep = _apiRegistry.get(id);
  if (!ep) return;

  // Close any existing drawer
  closeAPIDetail();

  const method     = ep.method || 'UNKNOWN';
  const path       = ep.path || '—';
  const funcName   = ep.function || '—';
  const name       = ep.name || '—';
  const framework  = ep.framework || 'Unknown';
  const auth       = ep.auth || 'None';
  const tags       = ep.tags || '';
  const file       = ep.file || '—';
  const description = ep.description || '';
  const params     = ep.parameters || ep.params || [];
  const responses  = ep.responses || [];

  const methodColor = {
    'GET': '#10b981',
    'POST': '#f59e0b',
    'PUT': '#3b82f6',
    'DELETE': '#ef4444',
    'PATCH': '#8b5cf6'
  }[method] || '#6b7280';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'api-drawer-overlay';
  overlay.addEventListener('click', closeAPIDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'api-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'API endpoint details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2 style="font-family:monospace;font-size:16px">${esc(path)}</h2>
        <div class="finding-drawer-badges">
          <span style="background:${methodColor};color:white;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600">${esc(method)}</span>
          <span class="tool-tag">${esc(framework)}</span>
        </div>
      </div>
      <button class="finding-drawer-close" ${act('closeAPIDetail')} aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Function</div>
          <div class="finding-detail-value"><code>${esc(funcName)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Name</div>
          <div class="finding-detail-value">${name !== '—' ? esc(name) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Framework</div>
          <div class="finding-detail-value"><span class="tool-tag">${esc(framework)}</span></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Authentication</div>
          <div class="finding-detail-value">${auth !== 'None' ? `<code style="font-size:12px">${esc(auth)}</code>` : '<span style="color:var(--text-dim)">None</span>'}</div>
        </div>
      </div>

      ${description ? `
        <div class="finding-detail-section" style="margin-top:12px">
          <div class="finding-detail-label">Description</div>
          <div class="finding-detail-desc">${esc(description)}</div>
        </div>` : ''}

      ${tags ? `
        <div class="finding-detail-section" style="margin-top:12px">
          <div class="finding-detail-label">Tags</div>
          <div class="finding-detail-value">${esc(tags)}</div>
        </div>` : ''}

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">File Location</div>
        <div class="finding-detail-value"><code style="font-size:12px;word-break:break-all">${esc(file)}</code></div>
      </div>

      ${Array.isArray(params) && params.length > 0 ? `
        <div class="finding-detail-section" style="margin-top:16px">
          <div class="finding-detail-label">Parameters</div>
          <div style="margin-top:6px">
            ${params.map(p => `
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                  <code style="color:var(--purple);font-size:12px">${esc(p.name || '')}</code>
                  ${p.required ? '<span style="color:var(--critical);font-size:12px;font-weight:600">REQUIRED</span>' : ''}
                </div>
                ${p.type ? `<div style="color:var(--text-muted);font-size:12px">Type: <code>${esc(p.type)}</code></div>` : ''}
                ${p.description ? `<div style="color:var(--text-dim);font-size:12px;margin-top:3px">${esc(p.description)}</div>` : ''}
              </div>
            `).join('')}
          </div>
        </div>` : ''}

      ${Array.isArray(responses) && responses.length > 0 ? `
        <div class="finding-detail-section" style="margin-top:16px">
          <div class="finding-detail-label">Responses</div>
          <div style="margin-top:6px">
            ${responses.map(r => `
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                  <code style="color:var(--pass);font-size:12px">${esc(String(r.status || r.code || ''))}</code>
                  <span style="color:var(--text-muted);font-size:12px">${esc(r.description || '')}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>` : ''}

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

export function closeAPIDetail() {
  const overlay = document.getElementById('api-drawer-overlay');
  const drawer  = document.getElementById('api-drawer');
  overlay?.remove();
  drawer?.remove();
}

// ── Dependency detail drawer ────────────────────────────────────
window.openDependencyDetail = function(did) {
  const p = _depsRegistry.get(did);
  if (!p) return;

  closeFindingDetail();

  const purlUrl = (() => {
    if (!p.purl) return null;
    const m = p.purl.match(/^pkg:([^/]+)\/([^@?#]+)(?:@([^?#]+))?/);
    if (!m) return null;
    const [, eco, pkg] = m;
    const pkgName = pkg.includes('%2F') ? pkg.replace('%2F', '/') : pkg;
    if (eco === 'npm')    return `https://www.npmjs.com/package/${pkgName}`;
    if (eco === 'pypi')   return `https://pypi.org/project/${pkgName}`;
    if (eco === 'gem')    return `https://rubygems.org/gems/${pkgName}`;
    if (eco === 'cargo')  return `https://crates.io/crates/${pkgName}`;
    if (eco === 'maven')  return `https://mvnrepository.com/artifact/${pkgName.replace('%3A', '/')}`;
    if (eco === 'golang') return `https://pkg.go.dev/${pkgName}`;
    if (eco === 'nuget')  return `https://www.nuget.org/packages/${pkgName}`;
    if (eco === 'composer') return `https://packagist.org/packages/${pkgName}`;
    if (eco === 'apk' || eco === 'deb' || eco === 'rpm') return null;
    return null;
  })();

  const purlSection = p.purl ? `
    <div class="finding-detail-section" style="grid-column:1/-1">
      <div class="finding-detail-label">Package URL (PURL)</div>
      <div class="finding-detail-value" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <code style="font-size:12px;word-break:break-all">${esc(p.purl)}</code>
        ${purlUrl ? `<a href="${esc(purlUrl)}" target="_blank" rel="noopener noreferrer"
             style="font-size:12px;white-space:nowrap;color:var(--purple)">
             View registry
             <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:middle">
               <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
               <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
             </svg>
           </a>` : ''}
      </div>
    </div>` : '';

  const pathSection = p.path ? `
    <div class="finding-detail-section" style="grid-column:1/-1">
      <div class="finding-detail-label">File Path</div>
      <div class="finding-detail-value"><code style="word-break:break-all">${esc(p.path)}</code></div>
    </div>` : '';

  const licenseSection = p.license ? `
    <div class="finding-detail-section">
      <div class="finding-detail-label">License</div>
      <div class="finding-detail-value"><code>${esc(p.license)}</code></div>
    </div>` : '';

  const langSection = p.language ? `
    <div class="finding-detail-section">
      <div class="finding-detail-label">Language</div>
      <div class="finding-detail-value"><code>${esc(p.language)}</code></div>
    </div>` : '';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Dependency details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(p.name)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">${esc(p.type)}</span>
          ${p.version ? `<code style="font-size:12px">${esc(p.version)}</code>` : ''}
          ${p.language ? `<span class="tool-tag" style="background:var(--accent-bg);color:var(--accent)">${esc(p.language)}</span>` : ''}
        </div>
      </div>
      <button class="finding-drawer-close" ${act('closeFindingDetail')} aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Name</div>
          <div class="finding-detail-value"><code>${esc(p.name)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Version</div>
          <div class="finding-detail-value">${p.version ? `<code>${esc(p.version)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Type</div>
          <div class="finding-detail-value"><span class="tool-tag" style="font-size:12px">${esc(p.type)}</span></div>
        </div>
        ${langSection}
        ${licenseSection}
      </div>

      ${pathSection}
      ${purlSection}

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

};
