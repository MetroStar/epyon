import { navigate, resolve } from './router.js';
import { renderStaticScanDetail } from './static-dashboard.js';
import { toast } from '../components/feedback.js';
import { api } from '../lib/api.js';
import { isScanJobTracked } from '../pages/new-scan.js';

// Legacy globals still provided by main.js (see index.js):

// ── Scan watcher ─────────────────────────────────────────────
// Scans run on the server whether or not a page is open. This watcher polls
// a lightweight job list on every page so a finished scan is announced with a
// toast (and a desktop notification if the tab is hidden and permission was
// granted), and a badge on the Run Scan link shows how many are in flight.
export const scanWatch = (() => {
  const ACTIVE = ['queued', 'running'];
  const known = {};
  let timer = null;
  let inflight = false;
  const baseTitle = document.title;

  function tracked(id) {
    return isScanJobTracked(id);
  }

  function announce(job) {
    const ok = job.status === 'completed';
    const msg = ok
      ? `Scan finished: ${job.target} (${job.scan_type})`
      : `Scan ${job.status}: ${job.target} (${job.scan_type})`;
    toast(msg, ok ? 'success' : 'error');
    if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
      try {
        const n = new Notification('Epyon scan ' + job.status, { body: msg, tag: 'epyon-scan-' + job.job_id });
        n.onclick = () => { window.focus(); navigate('#/applications'); n.close(); };
      } catch (_) {}
    }
  }

  function render(jobs) {
    const running = jobs.filter(j => j.status === 'running').length;
    const queued  = jobs.filter(j => j.status === 'queued').length;
    const badge = document.getElementById('scan-badge');
    if (badge) {
      badge.hidden = running + queued === 0;
      badge.textContent = String(running + queued);
      badge.title = `${running} running, ${queued} queued`;
    }
    document.title = running + queued ? `(${running + queued} scanning) ${baseTitle}` : baseTitle;
  }

  async function tick() {
    inflight = true;
    let delay = 20000;
    try {
      const res = await fetch('/api/jobs?summary=true');
      if (res.ok) {
        const jobs = await res.json();
        for (const j of jobs) {
          const prev = known[j.job_id];
          if (ACTIVE.includes(prev) && !ACTIVE.includes(j.status)) announce(j);
          known[j.job_id] = j.status;
        }
        render(jobs);
        if (jobs.some(j => ACTIVE.includes(j.status))) delay = 4000;
      }
    } catch (_) { /* server restarting or offline — try again later */ }
    inflight = false;
    timer = setTimeout(tick, delay);
  }

  // Re-poll now (e.g. right after a scan is submitted) so a short scan isn't missed.
  function poke() { if (inflight) return; clearTimeout(timer); tick(); }

  return { start: tick, poke };
})();

// Initial route + version label once the page has loaded.
window.addEventListener('load', () => {
  // In static (offline) mode the scan is embedded — skip API-based routing
  if (window.__SCAN__) return;
  resolve();
  scanWatch.start();
  api._get('/api/health').then(h => {
    const el = document.getElementById('sidebar-version');
    if (el && h.version) el.textContent = 'Epyon v' + h.version;
  }).catch(() => {});
});

// Static entry point — runs when this JS is embedded in a generated dashboard
if (typeof window !== 'undefined' && window.__SCAN__) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      renderStaticScanDetail(window.__SCAN__);
    });
  } else {
    renderStaticScanDetail(window.__SCAN__);
  }
}
