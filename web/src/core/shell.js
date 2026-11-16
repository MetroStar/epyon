import { closeFindingDetail } from '../components/drawers/finding.js';
import { closeStigDetail } from '../components/drawers/stig.js';
import { confirmDialog } from '../components/feedback.js';
import { resetFindingsViewState } from '../components/scan/findings.js';
import { _cache } from '../lib/cache.js';
import { _resetFindingsRegistry, _stigRegistry } from '../state/registries.js';


// ── Theme ────────────────────────────────────────────────────
export function applyTheme(theme) {
  if (document && document.documentElement) {
    document.documentElement.setAttribute('data-theme', theme);
  }
  const moon = document.getElementById ? document.getElementById('theme-icon-moon') : null;
  const sun  = document.getElementById ? document.getElementById('theme-icon-sun') : null;
  if (moon && moon.style) moon.style.display = theme === 'dark'  ? '' : 'none';
  if (sun && sun.style)  sun.style.display  = theme === 'light' ? '' : 'none';
  try { localStorage.setItem('epyon-theme', theme); } catch (_) {}
}

export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

export async function clearCacheAndReload() {
  // Show cache metrics before clearing
  const frontendMetrics = _cache.getMetrics();
  console.log('Frontend Cache Metrics:', frontendMetrics);
  
  const msg = `Clear all cached data and reload?\n\n` +
    `Frontend Cache:\n` +
    `  Hits: ${frontendMetrics.hits}\n` +
    `  Misses: ${frontendMetrics.misses}\n` +
    `  Hit Rate: ${frontendMetrics.hit_rate_pct || 'N/A'}%\n` +
    `  Avg Staleness: ${frontendMetrics.avg_staleness_ms || 'N/A'}ms`;
  
  if (await confirmDialog({ title: 'Clear cache and reload', body: msg, confirmLabel: 'Clear and reload', danger: false })) {
    _cache.invalidate();
    window.location.reload();
  }
}

(function initTheme() {
  try {
    const stored = localStorage.getItem('epyon-theme');
    if (stored === 'light' || stored === 'dark') {
      applyTheme(stored);
      return;
    }
  } catch (_) {}
  // Fall back to OS preference
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(prefersDark ? 'dark' : 'light');
})();

// ── Sidebar collapse ─────────────────────────────────────────
export const _mobileNav = () => window.matchMedia('(max-width: 768px)').matches;

export function _syncSidebarToggle() {
  const sidebar = document.getElementById('sidebar');
  const btn = document.getElementById('sidebar-toggle');
  if (sidebar && btn) btn.setAttribute('aria-expanded', String(!sidebar.classList.contains('collapsed')));
}

export function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const collapsed = sidebar.classList.toggle('collapsed');
  // On phones the menu always starts closed, so only desktop remembers the choice.
  if (!_mobileNav()) {
    try { localStorage.setItem('epyon-sidebar-collapsed', collapsed ? '1' : ''); } catch (_) {}
  }
  _syncSidebarToggle();
}

(function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  let collapsed = _mobileNav();
  if (!collapsed) {
    try { collapsed = localStorage.getItem('epyon-sidebar-collapsed') === '1'; } catch (_) {}
  }
  if (sidebar && collapsed) sidebar.classList.add('collapsed');
  _syncSidebarToggle();

  // Close the phone menu after choosing a page.
  sidebar?.addEventListener('click', e => {
    if (_mobileNav() && e.target.closest('.nav-link')) {
      sidebar.classList.add('collapsed');
      _syncSidebarToggle();
    }
  });
})();

// ── Navigation ────────────────────────────────────────────────
export function setActive(routeKey) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeKey);
  });
  // Clear findings registry and close any open drawer on navigation
  _resetFindingsRegistry();
  _stigRegistry.clear();
  resetFindingsViewState();
  closeFindingDetail();
  closeStigDetail();
}
