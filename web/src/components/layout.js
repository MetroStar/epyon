import { esc, act } from '../lib/format.js';

// Shared page header: title (HTML), optional subtitle and action buttons (HTML).
export function pageHeader(title, { subtitle = '', actions = '' } = {}) {
  return `<div class="page-header">
    <div class="page-header-main">
      <h1>${title}</h1>
      ${subtitle ? `<p class="page-subtitle">${subtitle}</p>` : ''}
    </div>
    ${actions ? `<div class="page-actions">${actions}</div>` : ''}
  </div>`;
}

export function loading(label = 'Loading…') {
  return `<div class="loading" role="status"><div class="loading-row"><div class="spinner"></div>${esc(label)}</div></div>`;
}

// A load that runs past a few seconds is usually a cold server cache (after a
// deploy or a long idle period). Explain it and show a timer with an estimate
// taken from the last slow load on this browser.
(function slowLoadNotice() {
  const SHOW_AFTER_S = 4, DEFAULT_EST_S = 120, KEY = 'epyon.coldLoadSecs';
  const tracked = new Map(); // element -> { start, hash }
  const estimate = () => {
    const v = parseInt(localStorage.getItem(KEY) || '', 10);
    return v > 0 ? v : DEFAULT_EST_S;
  };
  const fmt = s => (s >= 90 ? `${Math.round(s / 60)} minutes` : `${s}s`);
  const tick = () => {
    const now = Date.now();
    tracked.forEach((t, el) => {
      if (el.isConnected) return;
      tracked.delete(el);
      const secs = Math.round((now - t.start) / 1000);
      // Only a load that finished on its own counts, not one abandoned by navigating.
      if (secs >= SHOW_AFTER_S && t.hash === location.hash) {
        try { localStorage.setItem(KEY, String(secs)); } catch (_) {}
      }
    });
    document.querySelectorAll('.loading').forEach(el => {
      if (!tracked.has(el)) tracked.set(el, { start: now, hash: location.hash });
      const secs = Math.round((now - tracked.get(el).start) / 1000);
      if (secs < SHOW_AFTER_S) return;
      let note = el.querySelector('.loading-note');
      if (!note) {
        note = document.createElement('div');
        note.className = 'loading-note';
        note.setAttribute('aria-live', 'off');
        el.appendChild(note);
      }
      const est = estimate();
      note.textContent = secs <= est
        ? `The server is rebuilding its data cache after being idle. This usually takes about ${fmt(est)}. ${secs}s elapsed. You can switch to another page at any time.`
        : `Still working: ${secs}s elapsed, longer than the usual ${fmt(est)}. You can switch to another page or retry.`;
    });
  };
  setInterval(tick, 1000);
})();

// Error panel with a Retry action that re-renders the current view.
export function errBanner(msg, { retry = true } = {}) {
  return `<div class="error-banner" role="alert">
    <div>⚠ ${esc(msg)}</div>
    ${retry ? `<button class="btn btn-sm" ${act('resolve')}>Retry</button>` : ''}
  </div>`;
}

// Compact empty messages for tables and sections.
export function emptyRow(colspan, msg) {
  return `<tr><td colspan="${colspan}" class="empty-cell">${esc(msg)}</td></tr>`;
}

export function emptyNote(msg) {
  return `<p class="empty-note">${esc(msg)}</p>`;
}

export function emptyState(title, desc, action = '') {
  return `
    <div class="empty-state">
      <h3>${esc(title)}</h3>
      <p>${esc(desc)}</p>
      ${action}
    </div>`;
}
