import { emptyState, errBanner, loading, pageHeader } from '../components/layout.js';
import { esc, fmtDate, ucFirst, act, actOn, ARG } from '../lib/format.js';
import { scanTypeLabel } from '../lib/scans.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

// ── POA&M ─────────────────────────────────────────────────────
// A ".poam-host" element carries data-base (/api/scans/{id} or /api/applications/{name}); the preview
// table, SLA form and date pickers all read/write through that base.
// Which scans a POA&M was built from, plus any caveats (no full scan yet, partial scan, ...).
export function poamSourceLine(sources, notes) {
  const src = sources || {};
  const link = r => `<a href="#/scans/${encodeURIComponent(r.scan_id)}" data-stop>${esc(scanTypeLabel(r.scan_type))} scan · ${fmtDate(r.timestamp)}</a>`;
  const parts = [];
  if (src.vuln) parts.push(`CVEs from the ${link(src.vuln)}`);
  if (src.stig && !(src.vuln && src.stig.scan_id === src.vuln.scan_id)) parts.push(`STIG items from the ${link(src.stig)}`);
  else if (src.stig) parts.push('STIG items from the same scan');
  if (src.latest_full) parts.push(`Latest full scan: ${link(src.latest_full)}`);
  const warn = (notes || []).map(n => `<div class="poam-source-note">⚠ ${esc(n)}</div>`).join('');
  if (!parts.length && !warn) return '';
  return `<div class="poam-source">${parts.length ? `<div>Source: ${parts.join(' · ')}</div>` : ''}${warn}</div>`;
}

export function buildPoamSection(scanId) {
  const base = `/api/scans/${encodeURIComponent(scanId)}`;
  const viewHref = `#/poam-viewer/scan/${encodeURIComponent(scanId)}`;
  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible poam-card" data-base="${esc(base)}" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">POA&amp;M</span>
            <span class="poam-pills"><span class="stig-mini total">…</span></span>
          </span>
          <span style="display:flex;align-items:center;gap:8px">
            <a class="btn btn-sm" href="${esc(base)}/poam" download data-stop>↓ POA&amp;M.csv</a>
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="poam-source-slot" style="margin-top:12px"></div>
          <div class="stig-counts poam-tiles" style="margin-top:12px"></div>
          <div class="stig-view-btn-row">
            <button class="btn btn-primary btn-sm" ${act('navigate', `${viewHref}`)}>⊞ View POA&amp;M Inline</button>
          </div>
        </div>
      </details>
    </div>`;
}

// Fill a POA&M card's pills and tiles from the preview endpoint (table lives on the viewer page).
window.loadPoamCard = async (card) => {
  try {
    const res = await fetch(`${card.dataset.base}/poam?preview=true`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    const today = new Date().toISOString().slice(0, 10);
    const sev = d.by_severity || {}, src = d.by_source || {};
    const overdue = d.rows.filter(r => r['Scheduled Completion Date'] < today).length;
    card.querySelector('.poam-pills').innerHTML = `
      <span class="stig-mini open">${esc((sev.Critical || 0) + (sev.High || 0))} crit/high</span>
      ${overdue ? `<span class="stig-mini open">${esc(overdue)} overdue</span>` : ''}
      <span class="stig-mini total">${esc(d.total)} items</span>`;
    card.querySelector('.poam-source-slot').innerHTML = poamSourceLine(d.sources, d.notes);
    const tile = (n, lbl, cls) => `<div class="stig-count ${cls}"><span class="num">${esc(n)}</span><span class="lbl">${esc(lbl)}</span></div>`;
    card.querySelector('.poam-tiles').innerHTML =
      tile(sev.Critical || 0, 'Critical', 'open') + tile(sev.High || 0, 'High', 'open') +
      tile(sev.Medium || 0, 'Medium', 'na') + tile(sev.Low || 0, 'Low', 'na') +
      tile(src.STIG || 0, 'STIG items', 'pass') + tile(src.CVE || 0, 'CVE items', 'pass') +
      tile(overdue, 'Overdue', overdue ? 'open' : 'na') + tile(d.total, 'Total', 'total');
  } catch (e) {
    card.querySelector('.poam-pills').innerHTML = `<span class="stig-mini">unavailable</span>`;
  }
};

window.loadPoamPreview = async (host, force = false) => {
  if (host.dataset.loaded && !force) return;
  host.dataset.loaded = '1';
  const base = host.dataset.base;
  const body = host.querySelector('.poam-body');
  try {
    const res = await fetch(`${base}/poam?preview=true`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    const sev = d.by_severity || {}, src = d.by_source || {};
    const counts = host.querySelector('.poam-counts');
    if (counts) counts.textContent = d.total
      ? `${d.total} items · ${src.STIG || 0} STIG · ${src.CVE || 0} CVE · ${sev.Critical || 0} critical · ${sev.High || 0} high · ${sev.Medium || 0} medium`
      : 'Open STIG controls + Critical/High CVEs';
    const sla = d.sla_days || {};
    const slaForm = `
      <div class="poam-sla" style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:12px;font-size:12px">
        <strong>SLA (days to complete):</strong>
        ${['critical', 'high', 'medium', 'low'].map(k => `
          <label style="display:flex;align-items:center;gap:4px">${ucFirst(k)}
            <input type="number" min="1" max="3650" data-sla="${k}" value="${esc(sla[k])}" style="width:64px">
          </label>`).join('')}
        <button class="btn btn-sm" ${actOn('click','savePoamSla', ARG.el)}>Save SLA</button>
        <span class="poam-sla-msg" style="color:var(--text-muted)"></span>
      </div>`;
    if (!d.total) {
      body.innerHTML = poamSourceLine(d.sources, d.notes) + slaForm + '<div style="color:var(--text-muted)">No open STIG controls or Critical/High CVEs — nothing to add to a POA&amp;M.</div>';
      return;
    }
    const cols = ['POA&M ID', 'Weakness Identifier', 'Weakness Name', 'Raw Severity', 'Detection Source', 'Affected Component', 'Remediation / Mitigation', 'Scheduled Completion Date', 'Status'];
    const clip = (v) => { const t = String(v ?? ''); return t.length > 160 ? t.slice(0, 160) + '…' : t; };
    const today = new Date().toISOString().slice(0, 10);
    const cell = (r, c) => {
      if (c === 'Raw Severity') return `<span class="sev-badge ${esc(String(r[c]).toLowerCase())}">${esc(r[c])}</span>`;
      if (c === 'Scheduled Completion Date') {
        const manual = r['Due Date Basis'] === 'Manual';
        const overdue = r[c] < today;
        return `<input type="date" value="${esc(r[c])}" data-key="${esc(r['Item Key'])}" data-default="${esc(r['Default Due Date'])}"
                  title="${manual ? 'Manual date' : esc(r['Due Date Basis'])} — change to set manually"
                  ${actOn('change','savePoamDueDate', ARG.el)}
                  style="${manual ? 'font-weight:700;' : ''}${overdue ? 'color:var(--stig-open, #c0392b)' : ''}">
                ${overdue ? '<span title="Past its completion date" style="color:var(--stig-open, #c0392b);font-size:11px"> overdue</span>' : ''}
                ${manual ? `<a href="#" title="Reset to SLA date (${esc(r['Default Due Date'])})" ${actOn('click','resetPoamDueDate', ARG.event, ARG.el)}>↺</a>` : ''}`;
      }
      return `<span title="${esc(r[c] ?? '')}">${esc(clip(r[c]))}</span>`;
    };
    body.innerHTML = poamSourceLine(d.sources, d.notes) + slaForm + `
      <div style="overflow-x:auto;max-height:${host.tagName === 'DETAILS' ? '480px' : '70vh'};overflow-y:auto">
        <table>
          <thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead>
          <tbody>${d.rows.map(r => `<tr>${cols.map(c => `<td>${cell(r, c)}</td>`).join('')}</tr>`).join('')}</tbody>
        </table>
      </div>
      <div style="margin-top:8px;color:var(--text-muted);font-size:12px">Dates default to the SLA above, counted from the scan date. Pick a date to set it manually (bold); it is kept across rescans. Point of contact, resources and milestones are left blank in the CSV for you to complete.</div>`;
  } catch (e) {
    host.dataset.loaded = '';
    body.textContent = `Could not load POA&M preview (${e.message}).`;
  }
};

export async function poamSend(url, method, payload) {
  const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch (_) { /* keep status */ }
    throw new Error(msg);
  }
}

window.savePoamSla = async (btn) => {
  const wrap = btn.closest('.poam-sla'), msg = wrap.querySelector('.poam-sla-msg');
  const sla = {};
  wrap.querySelectorAll('input[data-sla]').forEach(i => { sla[i.dataset.sla] = parseInt(i.value, 10); });
  try {
    await poamSend('/api/poam/config', 'PUT', { sla_days: sla });
    window.loadPoamPreview(btn.closest('.poam-host'), true);
  } catch (e) { msg.textContent = `Not saved: ${e.message}`; }
};

window.savePoamDueDate = async (input) => {
  const host = input.closest('.poam-host');
  try {
    // Choosing the default date again clears the override
    const due = (!input.value || input.value === input.dataset.default) ? null : input.value;
    await poamSend(`${host.dataset.base}/poam/due-date`, 'PUT', { key: input.dataset.key, due_date: due });
    window.loadPoamPreview(host, true);
  } catch (e) { input.title = `Not saved: ${e.message}`; input.style.outline = '2px solid var(--stig-open, red)'; }
};

window.resetPoamDueDate = async (ev, link) => {
  ev.preventDefault();
  const host = link.closest('.poam-host');
  const input = link.parentElement.querySelector('input[type=date]');
  try {
    await poamSend(`${host.dataset.base}/poam/due-date`, 'PUT', { key: input.dataset.key, due_date: null });
    window.loadPoamPreview(host, true);
  } catch (e) { link.title = `Not reset: ${e.message}`; }
};

// POA&M roll-up across applications (own nav page, like STIG Compliance)
export async function renderPoam() {
  setActive('poam');
  const page = document.getElementById('page');
  page.innerHTML = loading();
  try {
    const res = await fetch('/api/poam/summary');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    const t = d.totals || {}, sev = t.by_severity || {};
    const stat = (v, label, color) => `
      <div class="stat-card"${color ? ` style="border-left:3px solid ${color}"` : ''}>
        <div class="stat-value"${color ? ` style="color:${color}"` : ''}>${esc(v)}</div>
        <div class="stat-label">${esc(label)}</div>
      </div>`;
    const summaryBar = d.apps.length ? `
      <div class="stats-grid" style="margin-bottom:24px">
        ${stat(d.apps.length, 'Apps with POA&M items')}
        ${stat(t.total || 0, 'Total POA&M items', 'var(--accent)')}
        ${stat(t.overdue || 0, 'Overdue', (t.overdue || 0) ? 'var(--stig-open)' : '')}
        ${stat(sev.Critical || 0, 'Critical')}
        ${stat(sev.High || 0, 'High')}
        ${stat(t.stig || 0, 'STIG items')}
        ${stat(t.cve || 0, 'CVE items')}
      </div>` : '';
    const cards = d.apps.length ? d.apps.map(a => {
      const s = a.by_severity || {};
      const base = `/api/applications/${encodeURIComponent(a.name)}`;
      return `
        <div class="stig-app-card" ${act('navigate', `#/poam-viewer/${encodeURIComponent(a.name)}`)} style="cursor:pointer">
          <div class="stig-app-card-header">
            <span class="stig-app-name">${esc(a.name)}</span>
            <div class="stig-download-btns" data-stop>
              <a class="btn btn-sm" href="${esc(base)}/poam" download>↓ POA&amp;M.csv</a>
            </div>
          </div>
          <div class="stig-counts">
            <div class="stig-count total"><span class="num">${esc(a.total)}</span><span class="lbl">Items</span></div>
            <div class="stig-count open"><span class="num">${esc(s.Critical || 0)}</span><span class="lbl">Critical</span></div>
            <div class="stig-count open"><span class="num">${esc(s.High || 0)}</span><span class="lbl">High</span></div>
            <div class="stig-count na"><span class="num">${esc(s.Medium || 0)}</span><span class="lbl">Medium</span></div>
            <div class="stig-count na"><span class="num">${esc(s.Low || 0)}</span><span class="lbl">Low</span></div>
          </div>
          <div style="margin-top:10px;font-size:12px;color:var(--text-muted)">
            ${esc(a.stig)} STIG · ${esc(a.cve)} CVE ·
            <span style="${a.overdue ? 'color:var(--stig-open);font-weight:600' : ''}">${esc(a.overdue)} overdue</span>
            ${a.next_due ? ` · earliest due ${esc(a.next_due)}` : ''}
            ${a.manual_dates ? ` · ${esc(a.manual_dates)} manual date${a.manual_dates === 1 ? '' : 's'}` : ''}
          </div>
          ${poamSourceLine(a.sources, a.notes)}
          <div style="margin-top:12px" data-stop>
            <button class="btn btn-primary btn-sm" ${act('navigate', `#/poam-viewer/${encodeURIComponent(a.name)}`)}>⊞ View POA&amp;M</button>
          </div>
        </div>`;
    }).join('') : emptyState(
      'Nothing on a POA&M yet',
      'No application has open STIG controls or Critical/High CVEs in its latest scans.',
      `<button class="btn btn-primary" ${act('navigate', '#/stig')} style="margin-top:16px">View STIG Compliance</button>`,
    );
    page.innerHTML = `
      ${pageHeader('POA&M')}
      <p class="section-desc">
        Plan of Action &amp; Milestones per application: Open STIG controls from the latest STIG scan plus
        Critical/High CVEs from the latest full/nightly scan. Completion dates follow the SLA
        (critical ${esc(d.sla_days.critical)}d · high ${esc(d.sla_days.high)}d · medium ${esc(d.sla_days.medium)}d · low ${esc(d.sla_days.low)}d)
        unless set manually; change it on any application's POA&amp;M page.
      </p>
      ${summaryBar}
      <div class="section"><div class="section-title">Applications</div>${cards}</div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

export async function renderPoamViewer(target) {
  setActive('poam');
  const page = document.getElementById('page');
  const isScan = target.startsWith('scan/');
  const appName = isScan ? target.slice(5) : target;
  const base = `${isScan ? '/api/scans' : '/api/applications'}/${encodeURIComponent(appName)}`;
  page.innerHTML = `
    ${pageHeader(`POA&M — ${esc(appName)}`, { actions: `
      <a class="btn" href="${esc(base)}/poam" download>↓ POA&amp;M.csv</a>
      <button class="btn" ${act('navigate', isScan ? `#/scans/${encodeURIComponent(appName)}` : '#/poam')}>${isScan ? '← Scan details' : '← All applications'}</button>` })}
    <div class="section poam-host" data-base="${esc(base)}"><div class="poam-body">${loading()}</div></div>`;
  window.loadPoamPreview(page.querySelector('.poam-host'));
}
