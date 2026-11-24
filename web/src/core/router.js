import { _abortPageLoads } from '../lib/api.js';
import { renderPoam, renderPoamViewer } from '../pages/poam.js';
import { renderSettings } from '../pages/settings.js';
import { renderPerformanceDashboard } from '../pages/performance.js';
import { renderStig, renderStigViewer } from '../pages/stig.js';
import { renderJiraReview } from '../pages/jira-review.js';
import { renderMetrics } from '../pages/metrics.js';
import { renderOverview } from '../pages/overview.js';
import { renderApplications, renderAppDetail } from '../pages/applications.js';
import { renderScanDetail } from '../pages/scan-detail.js';
import { renderNewScan } from '../pages/new-scan.js';
import { renderProjects, renderProjectStig } from '../pages/projects.js';
import { renderStigHistory } from '../pages/stig-history.js';

// Hash routes, first match wins. `exact` routes match the whole path; `prefix` routes pass
// the decoded remainder as `arg` (empty falls back to the section's list page). `title`
// is the header text. Renderers are looked up at call time so pages can load lazily.
const ROUTES = [
  { exact: ['/', ''], title: 'Overview', render: () => renderOverview() },
  { exact: ['/applications'], title: 'Applications', render: () => renderApplications() },
  { prefix: '/applications/', title: 'Application',
    render: name => (name ? renderAppDetail(name) : renderApplications()) },
  { exact: ['/poam'], title: 'POA&M', render: () => renderPoam() },
  { prefix: '/poam-viewer/', title: 'POA&M',
    render: app => (app ? renderPoamViewer(app) : renderPoam()) },
  { prefix: '/stig-viewer/', title: 'STIG',
    render: scanId => (scanId ? renderStigViewer(scanId) : renderStig()) },
  { prefix: '/jira-review/', title: 'Jira Review',
    render: scanId => (scanId ? renderJiraReview(scanId) : renderApplications()) },
  { prefix: '/scans/', title: 'Scan',
    render: (scanId, params) => (scanId
      ? renderScanDetail(scanId, params.get('finding') || '', params.get('package') || '')
      : renderApplications()) },
  { exact: ['/projects'], title: 'Projects', render: () => renderProjects() },
  { prefix: '/projects/', title: 'Project STIG',
    render: id => (id ? renderProjectStig(id) : renderProjects()) },
  { exact: ['/new-scan'], title: 'Run Scan', render: (_, params) => renderNewScan(params.get('target') || '') },
  { exact: ['/metrics'], title: 'Metrics', render: () => renderMetrics() },
  { exact: ['/performance'], title: 'Performance', render: () => renderPerformanceDashboard() },
  { exact: ['/stig'], title: 'STIG',
    render: (_, params) => (params.get('view') === 'history'
      ? renderStigHistory(params.get('app') || null, params.get('slug') || null)
      : renderStig()) },
  { exact: ['/settings'], title: 'Settings', render: () => renderSettings() },
];

function matchRoute(path) {
  for (const r of ROUTES) {
    if (r.exact && r.exact.includes(path)) return { route: r, arg: '' };
    if (r.prefix && path.startsWith(r.prefix)) {
      return { route: r, arg: decodeURIComponent(path.slice(r.prefix.length)) };
    }
  }
  return null;
}

function setHeaderTitle(title) {
  const el = document.getElementById('header-title');
  if (el) el.textContent = title;
}

export function navigate(hash) {
  window.location.hash = hash;
}

// Render the page for the current location.hash. Unknown paths show the Overview.
export function resolve() {
  _abortPageLoads();
  const hash = window.location.hash.slice(1) || '/';
  const q = hash.indexOf('?');
  const path = q === -1 ? hash : hash.slice(0, q);
  const params = new URLSearchParams(q === -1 ? '' : hash.slice(q + 1));
  const hit = matchRoute(path);
  setHeaderTitle(hit ? hit.route.title : 'Epyon');
  if (hit) hit.route.render(hit.arg, params);
  else renderOverview();
}

window.addEventListener('hashchange', resolve);
