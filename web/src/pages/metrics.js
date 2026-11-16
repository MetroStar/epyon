import { sourcesBadges } from '../components/badges.js';
import { drawDonutChart, drawHBarChart, drawStackedBarChart } from '../components/charts.js';
import { emptyNote, emptyRow, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { esc, ucFirst } from '../lib/format.js';
import { buildCiHealthSection } from './performance.js';

// Globals that other modules put on window (see index.js):
/* global closeFindingDetail, setActive */

// ── SLA detail registry ─────────────────────────────────────
let _slaDetailData = null;

export function openSlaDetail() {
  if (!_slaDetailData) return;
  closeFindingDetail();

  const sla   = _slaDetailData.sla_compliance || {};
  const bySev = sla.by_severity || {};
  const ovPct = sla.overall_pct != null ? `${sla.overall_pct}%` : 'N/A';
  const ovColor = sla.overall_pct == null ? 'var(--text-muted)'
    : sla.overall_pct >= 80 ? 'var(--clean)' : sla.overall_pct >= 50 ? 'var(--medium)' : 'var(--critical)';

  const rows = ['critical','high','medium','low'].map(sev => {
    const d = bySev[sev] || {};
    const pct = d.pct != null ? `${d.pct}%` : '—';
    const fill = d.pct != null ? `<div class="sla-bar-track"><div class="sla-bar-fill ${sev}" style="width:${Math.min(d.pct,100)}%"></div></div>` : '<div class="sla-bar-track"></div>';
    const pctColor = d.pct == null ? 'var(--text-muted)' : d.pct >= 80 ? 'var(--clean)' : d.pct >= 50 ? 'var(--medium)' : 'var(--critical)';
    return `<tr>
      <td><span class="sev-badge ${sev}">${ucFirst(sev)}</span></td>
      <td class="sla-sla-days">≤ ${d.sla_days ?? '—'}d</td>
      <td>${fill}</td>
      <td style="color:${pctColor};font-weight:600">${pct}</td>
      <td style="color:var(--text-muted);font-size:12px">${d.within ?? 0} / ${(d.within??0)+(d.breached??0)}</td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'SLA Compliance Rate');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>SLA Compliance Rate</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">Overall</span>
          <span style="font-size:14px;color:${ovColor};font-weight:600">${ovPct}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <p style="font-size:13px;color:var(--text-muted);margin:0 0 16px">% of resolved findings fixed within severity-tiered SLA thresholds.</p>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Severity</th><th scope="col">SLA</th><th scope="col" style="min-width:140px">Compliance</th><th scope="col">Rate</th><th scope="col">Met / Total</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text-muted)">
        ${sla.total_within ?? 0} within SLA · ${sla.total_breached ?? 0} exceeded SLA
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

// ── Risk trend registry ───────────────────────────────────────
const _riskTrendRegistry = new Map();

export function openRiskTrendDetail(app) {
  const pts = _riskTrendRegistry.get(app);
  if (!pts || !pts.length) return;
  closeFindingDetail();

  const latest = pts[pts.length - 1];
  const minScore = Math.min(...pts.map(p => p.score));
  const maxScore = Math.max(...pts.map(p => p.score));

  // Full-size SVG chart (480×120)
  const W = 480, H = 120, padX = 36, padY = 16;
  const innerW = W - padX * 2, innerH = H - padY * 2;
  const range = maxScore - minScore || 1;
  const sparkPts = pts.map((p, i) => {
    const x = padX + (i / Math.max(pts.length - 1, 1)) * innerW;
    const y = padY + innerH - ((p.score - minScore) / range) * innerH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  // Y-axis labels
  const yLabels = [minScore, Math.round((minScore + maxScore) / 2), maxScore].map((v, i) => {
    const y = padY + innerH - (i / 2) * innerH;
    return `<text x="${padX - 4}" y="${y.toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-muted)" dominant-baseline="middle">${v}</text>`;
  }).join('');
  // Dot on last point
  const lastPt = sparkPts.split(' ').at(-1).split(',');
  const dot = `<circle cx="${lastPt[0]}" cy="${lastPt[1]}" r="4" fill="var(--accent)"/>`;
  const chart = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="overflow:visible;display:block;max-width:100%">
    ${yLabels}
    <polyline points="${sparkPts}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dot}
  </svg>`;

  // History table rows
  const tableRows = [...pts].reverse().map(p => {
    return `<tr>
      <td style="color:var(--text-muted);font-size:12px">${esc(p.date)}</td>
      <td style="font-weight:600;color:var(--accent)">${esc(String(p.score))}</td>
      <td><span class="sev-badge critical" style="font-size:12px">${esc(String(p.critical ?? '—'))}</span></td>
      <td><span class="sev-badge high" style="font-size:12px">${esc(String(p.high ?? '—'))}</span></td>
      <td><span class="sev-badge medium" style="font-size:12px">${esc(String(p.medium ?? '—'))}</span></td>
      <td><span class="sev-badge low" style="font-size:12px">${esc(String(p.low ?? '—'))}</span></td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Risk score trend');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(app)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">Weighted Risk Score</span>
          <span style="font-size:12px;color:var(--accent);font-weight:600">Latest: ${esc(String(latest.score))}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div style="margin-bottom:20px">
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">Score over time (critical×10 + high×7 + medium×4 + low×1)</div>
        ${chart}
      </div>
      <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap">
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--accent)">${esc(String(latest.score))}</div>
          <div class="recurrence-label">Latest Score</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--clean)">${esc(String(minScore))}</div>
          <div class="recurrence-label">Best (lowest)</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--high)">${esc(String(maxScore))}</div>
          <div class="recurrence-label">Worst (highest)</div>
        </div>
        <div class="recurrence-card" style="min-width:100px;padding:12px">
          <div class="recurrence-value" style="font-size:24px;color:var(--text-muted)">${esc(String(pts.length))}</div>
          <div class="recurrence-label">Scans tracked</div>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Date</th><th scope="col">Score</th><th scope="col">Critical</th><th scope="col">High</th><th scope="col">Medium</th><th scope="col">Low</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table>
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

export function buildRiskTrendSection(m) {
  const trend = m.risk_trend || [];
  if (!trend.length) {
    return `<div class="section collapsible-section collapsed" id="section-risk">
      <div class="section-title section-toggle" onclick="toggleSection('section-risk')">
        Weighted Risk Score Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body">${emptyNote('No trend data yet.')}</div>
    </div>`;
  }
  // Group by target and populate registry
  const byTarget = {};
  trend.forEach(pt => {
    if (!byTarget[pt.target]) byTarget[pt.target] = [];
    byTarget[pt.target].push(pt);
  });
  _riskTrendRegistry.clear();
  Object.entries(byTarget).forEach(([app, pts]) => _riskTrendRegistry.set(app, pts));

  const rows = Object.entries(byTarget).map(([app, pts]) => {
    const latest = pts[pts.length - 1];
    const prev = pts.length > 1 ? pts[pts.length - 2] : null;
    const delta = prev != null ? latest.score - prev.score : null;
    const arrow = delta == null ? '' : delta > 0 ? ' ▲' : delta < 0 ? ' ▼' : '';
    const color = delta == null ? 'var(--text-muted)' : delta > 0 ? 'var(--critical)' : delta < 0 ? 'var(--clean)' : 'var(--text-muted)';
    const minScore = Math.min(...pts.map(p => p.score));
    const maxScore = Math.max(...pts.map(p => p.score));
    const sparkPts = pts.map((p, i) => {
      const x = (i / Math.max(pts.length - 1, 1)) * 80;
      const y = maxScore > minScore ? 20 - ((p.score - minScore) / (maxScore - minScore)) * 16 : 10;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<tr class="clickable-row" onclick="openRiskTrendDetail('${esc(app)}')">
      <td><strong>${esc(app)}</strong></td>
      <td style="font-weight:600;color:${color}">${esc(String(latest.score))}${arrow}</td>
      <td style="color:var(--text-muted);font-size:12px">${esc(latest.date)}</td>
      <td><svg width="80" height="20" viewBox="0 0 80 20" style="overflow:visible">
        <polyline points="${sparkPts}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round"/>
      </svg></td>
    </tr>`;
  }).join('');
  return `
  <div class="section collapsible-section collapsed" id="section-risk">
    <div class="section-title section-toggle" onclick="toggleSection('section-risk')">
      Weighted Risk Score Trend
      <span class="section-title-right"><span style="font-size:12px;font-weight:normal;color:var(--text-muted)">critical×10 + high×7 + medium×4 + low×1</span><span class="section-chevron">▾</span></span>
    </div>
    <div class="section-body">
      <div class="table-container">
        <table><thead><tr><th scope="col">Application</th><th scope="col">Latest Score</th><th scope="col">Date</th><th scope="col">Trend</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

export function buildSecretTrendSection(m) {
  const byTarget = m.secret_trend_by_target || {};
  const hasData = Object.values(byTarget).some(pts => pts.some(p => p.total > 0));
  const targets = Object.keys(byTarget).sort();
  if (!targets.length) {
    return `<div class="section collapsible-section collapsed" id="section-secrets">
      <div class="section-title section-toggle" onclick="toggleSection('section-secrets')">
        Secret Detection Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body">${emptyNote('No TruffleHog data found in scans.')}</div>
    </div>`;
  }
  const totalVerified   = (m.secret_trend || []).reduce((s,p) => s + (p.verified||0), 0);
  const totalUnverified = (m.secret_trend || []).reduce((s,p) => s + (p.unverified||0), 0);
  const rows = targets.map(app => {
    const pts = byTarget[app];
    const latest = pts[pts.length - 1] || {};
    const totalV  = latest.verified   || 0;
    const totalU  = latest.unverified || 0;
    const prev = pts.length > 1 ? pts[pts.length - 2] : null;
    const delta = prev != null ? latest.total - prev.total : null;
    const arrow = delta == null ? '' : delta > 0 ? ' ▲' : delta < 0 ? ' ▼' : '';
    const color = delta == null ? 'var(--text-muted)' : delta > 0 ? 'var(--critical)' : 'var(--clean)';
    return `<tr>
      <td><strong>${esc(app)}</strong></td>
      <td style="color:${totalV>0?'var(--critical)':'var(--text-muted)'}">
        ${totalV > 0 ? `<span class="sev-badge critical">${totalV} verified</span>` : '—'}
      </td>
      <td style="color:${totalU>0?'var(--high)':'var(--text-muted)'}">
        ${totalU > 0 ? `<span class="sev-badge high">${totalU} unverified</span>` : '—'}
      </td>
      <td style="color:${color};font-weight:600">${esc(String(latest.total || 0))}${arrow}</td>
      <td style="color:var(--text-muted);font-size:12px">${esc(latest.date || '—')}</td>
    </tr>`;
  }).join('');
  const badgeLine = totalVerified > 0
    ? `<span class="sev-badge critical" style="margin-right:8px">${totalVerified} verified secrets</span>` : '';
  return `
  <div class="section collapsible-section collapsed" id="section-secrets">
    <div class="section-title section-toggle" onclick="toggleSection('section-secrets')">
      Secret Detection Trend
      <span class="section-title-right">${badgeLine}<span class="section-chevron">▾</span></span>
    </div>
    <div class="section-body">
      <p class="metrics-note">TruffleHog findings per app from latest scan. Verified secrets indicate real credentials at risk.</p>
      <div class="table-container">
        <table><thead><tr><th scope="col">Application</th><th scope="col">Verified</th><th scope="col">Unverified</th><th scope="col">Total</th><th scope="col">Last Scan</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

export function buildSuppressionSection(m) {
  const sup = m.suppression || {};
  const total = sup.total || 0;
  const rate  = sup.rate_pct != null ? `${sup.rate_pct}%` : 'N/A';
  const byTarget = sup.by_target || {};
  const appsSorted = Object.keys(byTarget).sort();

  const appRows = appsSorted.map(app => {
    const items = byTarget[app] || [];
    const rows = items.map(s => {
      const reason = s.reason ? `<div class="sup-reason">${esc(s.reason)}</div>` : '';
      const approver = s.approved_by ? `<span class="sup-approver">Approved by ${esc(s.approved_by)}</span>` : '';
      return `<tr>
        <td><code style="font-size:12px">${esc(s.value)}</code></td>
        <td style="color:var(--text-muted);font-size:12px">${esc(s.tool)}</td>
        <td style="color:var(--text-muted);font-size:12px;text-transform:capitalize">${esc(s.type)}</td>
        <td>${reason}${approver}</td>
      </tr>`;
    }).join('');
    return `<div class="sup-app-block">
      <div class="sup-app-header">
        <span class="sup-app-name">${esc(app)}</span>
        <span class="sup-app-count">${items.length} suppression${items.length !== 1 ? 's' : ''}</span>
      </div>
      <table class="sup-app-table">
        <thead><tr><th scope="col">Rule / ID</th><th scope="col">Tool</th><th scope="col">Type</th><th scope="col">Reason</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');

  const emptyState = !appsSorted.length
    ? `${emptyNote('No suppressions found across monitored apps.')}`
    : '';

  return `
  <div class="section collapsible-section collapsed" id="section-suppression">
    <div class="section-title section-toggle" onclick="toggleSection('section-suppression')">
      Suppression / Accepted Risk Rate
      <span class="section-title-right">
        <span style="font-size:13px;font-weight:600;color:var(--text-muted)">${esc(String(total))} suppressed · ${esc(String(m.total_resolved || 0))} resolved · ${rate} rate</span>
        <span class="section-chevron">▾</span>
      </span>
    </div>
    <div class="section-body">
      <p class="metrics-note">Findings suppressed via <code>suppressed-findings.md</code> (accepted risk) vs. actively remediated. Rate = suppressed ÷ (suppressed + resolved).</p>
      ${emptyState}
      ${appRows}
    </div>
  </div>`;
}

export function buildRecurrenceSection(m) {
  const recPct  = m.recurrence_rate_pct;
  const ftfPct  = m.first_time_fix_pct;
  const resolved = m.total_resolved || 0;
  const fmt = v => v != null ? `${v}%` : 'N/A';
  const recColor = recPct == null ? 'var(--text-muted)' : recPct > 15 ? 'var(--critical)' : recPct > 5 ? 'var(--high)' : 'var(--clean)';
  const ftfColor = ftfPct == null ? 'var(--text-muted)' : ftfPct >= 50 ? 'var(--clean)' : ftfPct >= 25 ? 'var(--medium)' : 'var(--critical)';
  return `
  <div class="section collapsible-section collapsed" id="section-recurrence">
    <div class="section-title section-toggle" onclick="toggleSection('section-recurrence')">
      Recurrence &amp; First-Time Fix Rate
      <span class="section-chevron">▾</span>
    </div>
    <div class="section-body">
      <p class="metrics-note">Recurrence: findings resolved then seen again in a later scan. First-Time Fix: findings resolved within the very next scan after they appeared.</p>
      <div class="recurrence-grid">
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:${recColor}">${fmt(recPct)}</div>
          <div class="recurrence-label">Vulnerability Recurrence Rate</div>
          <div class="recurrence-sub">lower is better</div>
        </div>
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:${ftfColor}">${fmt(ftfPct)}</div>
          <div class="recurrence-label">First-Time Fix Rate</div>
          <div class="recurrence-sub">higher is better</div>
        </div>
        <div class="recurrence-card">
          <div class="recurrence-value" style="color:var(--accent)">${esc(String(resolved))}</div>
          <div class="recurrence-label">Total Resolved (all time)</div>
          <div class="recurrence-sub">across monitored apps</div>
        </div>
      </div>
    </div>
  </div>`;
}

// Days → readable duration. Sub-day values show hours so a fast detection never renders as "0d".
const FREQ_KIND_LABEL = { pr: 'PR', nightly: 'Nightly', other: 'Push / manual' };

const FREQ_RESULT_LABEL = { pass: 'passed', fail: 'failed', unknown: 'result unknown' };

const FREQ_MAX_COLUMNS = 90;

// One shared day range across all rows, so every application's timeline lines up.
export function freqRange(dateLists) {
  const days = [];
  dateLists.forEach(list => (list || []).forEach(d => {
    const t = Date.parse(String(d).slice(0, 10) + 'T00:00:00Z');
    if (!isNaN(t)) days.push(t);
  }));
  if (!days.length) return null;
  const start = Math.min(...days), end = Math.max(...days);
  const span = Math.round((end - start) / 86400000) + 1;
  const bin = Math.max(1, Math.ceil(span / FREQ_MAX_COLUMNS));
  return { start, end, bin, columns: Math.ceil(span / bin) };
}

// Horizontal heat strip: one cell per day (or per `bin` days) on a shared date range.
// Intensity = scans that day relative to the busiest cell; hue goes green -> red with the share of failed runs.
export function freqTimeline(runs, range, peak) {
  if (!range) return '<span class="freq-empty">—</span>';
  const cells = Array.from({ length: range.columns }, () => ({ n: 0, fail: 0, tally: {} }));
  runs.forEach(r => {
    const t = Date.parse(String(r.date).slice(0, 10) + 'T00:00:00Z');
    if (isNaN(t)) return;
    const c = cells[Math.min(range.columns - 1, Math.floor((t - range.start) / 86400000 / range.bin))];
    c.n += 1;
    if (r.result === 'fail') c.fail += 1;
    const k = r.kind ? `${FREQ_KIND_LABEL[r.kind] || r.kind} ${FREQ_RESULT_LABEL[r.result] || r.result}` : 'scan';
    c.tally[k] = (c.tally[k] || 0) + 1;
  });
  const maxN = peak || Math.max(1, ...cells.map(c => c.n));
  const fmtDay = ms => new Date(ms).toISOString().slice(0, 10);
  const cellHtml = cells.map((c, i) => {
    const from = range.start + i * range.bin * 86400000;
    const label = range.bin > 1 ? `${fmtDay(from)} – ${fmtDay(Math.min(range.end, from + (range.bin - 1) * 86400000))}` : fmtDay(from);
    if (!c.n) return `<div class="freq-cell" title="${esc(label)} · no scans"></div>`;
    const alpha = (0.3 + 0.7 * Math.min(1, c.n / maxN)).toFixed(2);
    const colour = runs.some(r => r.kind)
      ? `hsl(${Math.round(130 * (1 - Math.min(1, (c.fail / c.n) * 2)))} 65% 45% / ${alpha})`
      : `rgb(88 166 255 / ${alpha})`;
    const title = `${label} · ${c.n} scan${c.n === 1 ? '' : 's'}` +
      (c.fail ? ` (${c.fail} failed)` : '') + '\n' +
      Object.entries(c.tally).map(([k, n]) => `${n} × ${k}`).join('\n');
    return `<div class="freq-cell" style="background:${colour}" title="${esc(title)}"></div>`;
  }).join('');
  const every = Math.max(1, Math.ceil(range.columns / 6));
  const ticks = [];
  for (let i = 0; i < range.columns; i += every) {
    ticks.push(`<span class="freq-tick" style="left:${(i / range.columns * 100).toFixed(2)}%">${esc(fmtDay(range.start + i * range.bin * 86400000).slice(5))}</span>`);
  }
  return `<div class="freq-timeline">
    <div class="freq-plot">${cellHtml}</div>
    <div class="freq-axis">${ticks.join('')}</div>
  </div>`;
}

// Shared date range and busiest-cell count for a set of [app, scan_frequency] entries, so
// every row's strip lines up on the same axis and intensity scale.
export function freqScale(entries) {
  const range = freqRange(entries.map(([, f]) => f.dates));
  const peak = Math.max(1, ...entries.map(([, f]) => {
    const per = {};
    f.dates.forEach(d => { const k = String(d).slice(0, 10); per[k] = (per[k] || 0) + 1; });
    return Math.max(0, ...Object.values(per)) * (range ? range.bin : 1);
  }));
  return { range, peak };
}

export function freqDots(f, range, peak) {
  const runs = f.runs && f.runs.length ? f.runs : f.dates.map(d => ({ date: d, kind: 'other', result: 'unknown' }));
  return freqTimeline(runs, range, peak);
}

export function freqLegend() {
  return `<div class="freq-legend">
    <span class="legend-item">Scans per day:
      <span class="freq-swatch" style="background:hsl(130 65% 45% / 0.3)"></span> few
      <span class="freq-swatch" style="background:hsl(130 65% 45% / 1)"></span> many</span>
    <span class="legend-item">Failed share:
      <span class="freq-swatch" style="background:hsl(130 65% 45%)"></span> none
      <span class="freq-swatch" style="background:hsl(65 65% 45%)"></span> some
      <span class="freq-swatch" style="background:hsl(0 65% 45%)"></span> half or more</span>
    <span class="legend-item">Hover a day for the PR / nightly / push breakdown</span>
  </div>`;
}

export function fmtDays(days) {
  if (days == null || isNaN(days)) return null;
  if (days >= 1) return { num: String(Math.round(days * 10) / 10), unit: 'days' };
  const hrs = days * 24;
  if (hrs >= 1) return { num: String(Math.round(hrs * 10) / 10), unit: 'hours' };
  return { num: '<1', unit: 'hour' };
}

export function trendSparkline(points) {
  const vals = (points || []).map(p => p.risk_index);
  if (vals.length < 2) return '';
  const w = 90, h = 22, max = Math.max(...vals, 1), min = Math.min(...vals);
  const span = max - min || 1;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1) * w).toFixed(1)},${(h - 2 - (v - min) / span * (h - 4)).toFixed(1)}`).join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--text-muted)" stroke-width="1.5"/></svg>`;
}

const _appTrendRegistry = new Map();

export function openAppTrendDetail(name) {
  const t = _appTrendRegistry.get(name);
  if (!t) return;
  closeFindingDetail();
  const pts = t.points || [];
  const color = { Improving: 'var(--clean)', Declining: 'var(--critical)', Stable: 'var(--text-muted)' }[t.status] || 'var(--text-dim)';
  const fmt = n => (n > 0 ? '+' : '') + n;
  const hasWindow = t.delta !== undefined;

  let why;
  if (!hasWindow) {
    why = `Only ${pts.length} comparable nightly/full scan day${pts.length === 1 ? '' : 's'} so far. At least two are needed to call a direction.`;
  } else {
    const parts = [`Risk index went from ${t.baseline_risk_index} to ${t.risk_index} (${fmt(t.delta)}${t.delta_pct == null ? '' : `, ${fmt(t.delta_pct)}%`}) between ${esc(t.from)} and ${esc(t.to)}.`];
    parts.push(t.critical_high_delta === 0 ? 'Critical + high findings are unchanged.'
      : `Critical + high findings ${t.critical_high_delta > 0 ? 'rose' : 'fell'} by ${Math.abs(t.critical_high_delta)}.`);
    parts.push({
      Declining: 'Declining because critical/high findings rose or risk rose 10% or more.',
      Improving: 'Improving because critical/high findings fell or risk fell 10% or more.',
      Stable: 'Stable because risk moved less than 10% and critical/high findings did not rise or fall.',
    }[t.status] || '');
    why = parts.join(' ');
  }

  const vals = pts.map(p => p.risk_index);
  let chart = '';
  if (vals.length >= 2) {
    const W = 480, H = 120, padX = 36, padY = 16, iw = W - padX * 2, ih = H - padY * 2;
    const min = Math.min(...vals), max = Math.max(...vals), range = max - min || 1;
    const xy = vals.map((v, i) => [padX + i / (vals.length - 1) * iw, padY + ih - (v - min) / range * ih]);
    const labels = [min, Math.round((min + max) / 2), max].map((v, i) =>
      `<text x="${padX - 4}" y="${(padY + ih - i / 2 * ih).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-muted)" dominant-baseline="middle">${v}</text>`).join('');
    const last = xy[xy.length - 1];
    chart = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="overflow:visible;display:block;max-width:100%" role="img" aria-label="Risk index over time">
      ${labels}<polyline points="${xy.map(c => c[0].toFixed(1) + ',' + c[1].toFixed(1)).join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="4" fill="${color}"/></svg>`;
  }

  const rows = pts.map((p, i) => {
    const step = i === 0 ? '—' : fmt(Math.round((p.risk_index - pts[i - 1].risk_index) * 10) / 10);
    return `<tr>
      <td style="color:var(--text-muted);font-size:12px">${esc(p.date)}</td>
      <td style="font-weight:600">${esc(String(p.risk_index))}</td>
      <td>${esc(step)}</td>
      <td><span class="sev-badge critical" style="font-size:12px">${esc(String(p.critical ?? 0))}</span></td>
      <td><span class="sev-badge high" style="font-size:12px">${esc(String(p.high ?? 0))}</span></td>
      <td><span class="sev-badge medium" style="font-size:12px">${esc(String(p.medium ?? 0))}</span></td>
      <td><span class="sev-badge low" style="font-size:12px">${esc(String(p.low ?? 0))}</span></td>
    </tr>`;
  }).reverse().join('');

  const card = (val, label, c) => `<div class="recurrence-card" style="min-width:100px;padding:12px">
      <div class="recurrence-value" style="font-size:24px;color:${c}">${esc(String(val))}</div>
      <div class="recurrence-label">${label}</div></div>`;
  const cards = [
    card(t.risk_index ?? (pts.length ? pts[pts.length - 1].risk_index : '—'), 'Risk index now', 'var(--accent)'),
    hasWindow ? card(fmt(t.delta), 'Change in window', color) : '',
    hasWindow ? card(fmt(t.since_previous), 'Since previous scan', 'var(--text-muted)') : '',
    hasWindow ? card(fmt(t.critical_high_delta), 'Critical + high change', 'var(--text-muted)') : '',
    card(pts.length, 'Scans compared', 'var(--text-muted)'),
  ].join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', `${name} trend`);
  drawer.addEventListener('click', e => e.stopPropagation());
  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(name)}</h2>
        <div class="finding-drawer-badges">
          <span class="tool-tag">nightly/full scans</span>
          <span style="font-size:13px;color:${color};font-weight:600">${esc(t.status)}</span>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <p style="font-size:13px;margin:0 0 16px">${why}</p>
      ${chart ? `<div style="margin-bottom:20px"><div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">Risk index over time (15×critical + 5×high + 1×medium + 0.2×low; lower is better)</div>${chart}</div>` : ''}
      <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap">${cards}</div>
      <div class="table-container">
        <table>
          <thead><tr><th scope="col">Date</th><th scope="col">Risk index</th><th scope="col">Change</th><th scope="col">Critical</th><th scope="col">High</th><th scope="col">Medium</th><th scope="col">Low</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text-muted)">One point per day (the day's latest scan). Only nightly and full scans are compared, so a quick or STIG-only scan is never read as an improvement or decline.</div>
    </div>`;
  document.body.appendChild(overlay);
  document.body.appendChild(drawer);
}

export function buildAppTrendSection(m) {
  const trends = m.app_trends || {};
  _appTrendRegistry.clear();
  Object.entries(trends).forEach(([n, t]) => _appTrendRegistry.set(n, t));
  const order = { Declining: 0, Stable: 1, Improving: 2, 'Not enough data': 3 };
  const rows = Object.entries(trends)
    .sort((a, b) => (order[a[1].status] - order[b[1].status]) || a[0].localeCompare(b[0]))
    .map(([name, t]) => {
      const color = { Improving: 'var(--clean)', Declining: 'var(--critical)', Stable: 'var(--text-muted)' }[t.status] || 'var(--text-dim)';
      const icon = { Improving: '↗', Declining: '↘', Stable: '→' }[t.status] || '–';
      const fmt = n => (n > 0 ? '+' : '') + n;
      const change = t.delta === undefined ? '—'
        : `${fmt(t.delta)}${t.delta_pct === null || t.delta_pct === undefined ? '' : ` (${fmt(t.delta_pct)}%)`}`;
      const prev = t.since_previous === undefined ? '—' : fmt(t.since_previous);
      const period = t.from ? `${esc(t.from)} → ${esc(t.to)}` : '—';
      return `<tr class="clickable-row" tabindex="0" role="button" aria-label="Show ${esc(name)} trend details" style="cursor:pointer" onclick="openAppTrendDetail(this.dataset.app)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();openAppTrendDetail(this.dataset.app)}" data-app="${esc(name)}">
        <td>${esc(name)}</td>
        <td><span style="color:${color};font-weight:600">${icon} ${esc(t.status)}</span></td>
        <td>${t.risk_index === undefined ? '—' : esc(String(t.risk_index))}</td>
        <td>${esc(change)}</td>
        <td>${esc(prev)}</td>
        <td>${period}</td>
        <td>${esc(t.scan_type || '—')} · ${esc(String(t.scans_compared || 0))}</td>
        <td>${trendSparkline(t.points)}</td>
      </tr>`;
    }).join('');
  if (!rows) return '';
  return `
      <div class="section">
        <div class="section-title">
          Application Trend Status
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">are applications improving or declining over time</span>
        </div>
        <div class="table-container">
          <table id="tbl-app-trends">
            <thead><tr>
              <th scope="col">Application</th><th scope="col">Status</th><th scope="col">Risk index</th>
              <th scope="col">Change in window</th><th scope="col">Since previous scan</th>
              <th scope="col">Window</th><th scope="col">Scan type · points</th><th scope="col">Trend</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:8px">
          Risk index = 15×critical + 5×high + 1×medium + 0.2×low (the Score Card's vulnerability weights; lower is better).
          Only nightly and full scans are compared, one per day. Declining = risk up 10% or more, or more critical/high findings;
          Improving = risk down 10% or more, or fewer critical/high findings. Click a row for the full history.
        </div>
      </div>`;
}

export async function renderMetrics() {
  setActive('metrics');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const m = await api.getMetrics();

    const totalFindings = (m.fix_rate.with_fix || 0) + (m.fix_rate.without_fix || 0);
    const fixPct     = totalFindings > 0
      ? Math.round((m.fix_rate.with_fix / totalFindings) * 100) : 0;
    const topTool    = (m.by_tool[0] || {}).tool || '—';
    const activeApps = Object.keys(m.scan_frequency || {}).length;
    const toolH      = Math.max((m.by_tool.length || 1) * 36 + 8, 60);

    const fastestHtml = m.fastest_remediator
      ? `<div class="mttr-fastest">
           <span class="mttr-fastest-label">Fastest</span>
           <span class="mttr-fastest-app">${esc(m.fastest_remediator.target)}</span>
           <span class="mttr-fastest-days">${esc(String(m.fastest_remediator.mttr_days))}d avg</span>
         </div>`
      : '';

    const sevRows = (bySev) => ['critical','high','medium','low'].map(sev => {
      const val = (bySev || {})[sev];
      const d = fmtDays(val);
      const display = d ? `${d.num}${d.unit === 'days' ? 'd' : 'h'}` : 'No data';
      return `<div class="mttr-sev-row">
        <span class="sev-badge ${sev}">${ucFirst(sev)}</span>
        <span class="mttr-sev-days">${esc(display)}</span>
      </div>`;
    }).join('');

    function buildFixRateStats(m) {
      const sla      = m.sla_compliance || {};
      const ftfPct   = m.first_time_fix_pct;
      const slaPct   = sla.overall_pct;

      const fmt = (v, suffix = '%') => v != null ? `${v}${suffix}` : 'N/A';

      const slaColor = slaPct == null ? 'var(--text-muted)'
        : slaPct >= 80 ? 'var(--clean)' : slaPct >= 50 ? 'var(--medium)' : 'var(--critical)';
      const arPct    = m.accepted_risk_pct ?? null;
      const supColor = arPct == null ? 'var(--text-muted)'
        : arPct <= 10 ? 'var(--clean)' : arPct <= 25 ? 'var(--medium)' : 'var(--high)';
      const ftfColor = ftfPct == null ? 'var(--text-muted)'
        : ftfPct >= 50 ? 'var(--clean)' : ftfPct >= 25 ? 'var(--medium)' : 'var(--critical)';

      return `<div class="fix-rate-stats">
        <div class="fix-rate-stat-row fix-rate-stat-link" title="Click to view SLA breakdown by severity" onclick="openSlaDetail()">
          <span class="fix-rate-stat-label">SLA Compliance <span class="stat-link-arrow">›</span></span>
          <span class="fix-rate-stat-value" style="color:${slaColor}">${fmt(slaPct)}</span>
        </div>
        <div class="fix-rate-stat-row" title="First-time fix rate: % of resolved findings that were not seen again in a later scan">
          <span class="fix-rate-stat-label">First-Time Fix</span>
          <span class="fix-rate-stat-value" style="color:${ftfColor}">${fmt(ftfPct)}</span>
        </div>
        <div class="fix-rate-stat-row" title="Accepted risk rate: suppressed finding instances in latest scans as a % of open + suppressed findings">
          <span class="fix-rate-stat-label">Accepted Risk</span>
          <span class="fix-rate-stat-value" style="color:${supColor}">${fmt(arPct)}</span>
        </div>
      </div>`;
    }

    function buildMttrPanelHtml(data, fastestHtml) {
      const mttr = fmtDays(data.mttr_days);
      const mttrDisplay = mttr
        ? `<span class="mttr-number">${esc(mttr.num)}</span><span class="mttr-unit">${mttr.unit}</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttrSub = mttr ? 'avg across resolved findings' : 'No findings resolved yet in this period';
      const mttd = fmtDays(data.mttd_days);
      const mttdDisplay = mttd
        ? `<span class="mttr-number mttd-number">${esc(mttd.num)}</span><span class="mttr-unit">${mttd.unit}</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttdSub = mttd ? 'avg detection window across new findings' : 'No new findings detected yet in this period';
      return `
        <div class="mttr-display">${mttrDisplay}</div>
        <div class="mttr-sub">${esc(mttrSub)}</div>
        <div class="mttr-sev-grid">${sevRows(data.mttr_by_severity)}</div>
        ${fastestHtml || ''}
        <div class="mttr-divider"></div>
        <div class="section-title" style="margin-top:0">Mean Time to Detect</div>
        <div class="mttr-display">${mttdDisplay}</div>
        <div class="mttr-sub">${esc(mttdSub)}</div>
        <div class="mttr-sev-grid">${sevRows(data.mttd_by_severity)}</div>`;
    }

    const overallData = {
      mttr_days: m.mttr_days, mttr_by_severity: m.mttr_by_severity,
      mttd_days: m.mttd_days, mttd_by_severity: m.mttd_by_severity,
    };
    const appList = Object.keys(m.metrics_by_target || {}).sort();
    const appOptions = appList.map(a =>
      `<option value="${esc(a)}">${esc(a)}</option>`
    ).join('');

    const totalMerges = m.total_merges_to_main || 0;
    const mergesData = m.merges_to_main || {};
    const topCveRows = m.top_cves.length
      ? m.top_cves.map(c => `
          <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}"
                   target="_blank" rel="noopener noreferrer"><code>${esc(c.cve_id)}</code></a></td>
            <td><span class="sev-badge ${esc(c.severity)}">${ucFirst(c.severity)}</span></td>
            <td>${esc(c.count)}</td>
            <td style="max-width:280px">${esc(c.title || '—')}</td>
            <td>${sourcesBadges(c.sources)}</td>
            <td style="font-size:12px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`).join('')
      : emptyRow(6, 'No CVE data — run a scan to populate');

    const freqScaleAll = freqScale(Object.entries(m.scan_frequency || {}));
    const freqRows = Object.entries(m.scan_frequency || {})
      .sort((a, b) => b[1].total - a[1].total)
      .map(([name, f]) => {
        const firstDate = f.dates.length ? f.dates[0] : '—';
        const lastDate  = f.dates.length ? f.dates[f.dates.length - 1] : '—';
        return `
          <tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(f.total)}</td>
            <td>${esc(firstDate)}</td>
            <td>${esc(lastDate)}</td>
            <td>${freqDots(f, freqScaleAll.range, freqScaleAll.peak)}</td>
          </tr>`;
      }).join('');

    const legendSevs = ['critical','high','medium','low'].map(s =>
      `<span class="legend-item"><span class="legend-dot" style="background:var(--${s})"></span>${ucFirst(s)}</span>`
    ).join('');

    const filterNotice = m.metrics_filtered
      ? `<div class="metrics-filter-notice">
           Showing ${esc(String(m.monitored_count))} continuously monitored app${m.monitored_count !== 1 ? 's' : ''} ·
           <a href="#/applications" onclick="navigate('#/applications')">manage</a>
         </div>`
      : '';

    page.innerHTML = `
      ${pageHeader(`Metrics`, { actions: `<button class="btn btn-sm" onclick="renderMetrics()">&#8635; Refresh</button>` })}
      ${filterNotice}

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${esc(String(totalFindings.toLocaleString()))}</div>
          <div class="stat-label">Total Findings</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--clean)">${esc(String(fixPct))}%</div>
          <div class="stat-label">Fixable</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(String(activeApps))}</div>
          <div class="stat-label">Active Apps</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="font-size:16px;padding-top:6px">${esc(topTool)}</div>
          <div class="stat-label">Top Finding Tool</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(String(totalMerges))}</div>
          <div class="stat-label">Merges to Primary</div>
        </div>
      </div>

      <div class="metrics-two-col">
        <div class="chart-panel">
          <div class="section-title">Fix Rate</div>
          <div class="donut-wrap">
            <canvas id="donut-chart" width="200" height="200"></canvas>
          </div>
          <div class="chart-legend">
            <span class="legend-item">
              <span class="legend-dot" style="background:var(--clean)"></span>
              Fixable (${esc(String(m.fix_rate.with_fix))})
            </span>
            <span class="legend-item">
              <span class="legend-dot" style="background:var(--border);border:1px solid var(--text-dim)"></span>
              No fix (${esc(String(m.fix_rate.without_fix))})
            </span>
          </div>
          ${buildFixRateStats(m)}
        </div>
        <div class="chart-panel mttr-panel">
          <div class="mttr-panel-header">
            <div class="section-title" style="margin-bottom:0">Mean Time to Remediate</div>
            <select id="mttr-app-filter" class="mttr-app-select">
              <option value="">All Apps</option>
              ${appOptions}
            </select>
          </div>
          <div id="mttr-panel-body">${buildMttrPanelHtml(overallData, fastestHtml)}</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Findings by Tool</div>
        <div class="trend-wrap">
          <canvas id="tool-chart" style="display:block;width:100%;height:${toolH}px"></canvas>
        </div>
        <div class="chart-legend" style="margin-top:12px">${legendSevs}</div>
      </div>

      <div class="section">
        <div class="section-title">
          Vulnerability Trend
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">${m.trend.length} day${m.trend.length !== 1 ? 's' : ''} · last ${m.window_days || 90} days</span>
        </div>
        <div class="trend-wrap">
          <canvas id="trend-chart" style="display:block;width:100%;height:200px"></canvas>
        </div>
        <div class="chart-legend">${legendSevs}</div>
      </div>

      ${buildAppTrendSection(m)}

      <div class="section collapsible-section collapsed" id="section-cves">
        <div class="section-title section-toggle" onclick="toggleSection('section-cves')">
          Top CVEs
          <span class="section-title-right">
            <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">from latest scan per application</span>
            <span class="section-chevron">▾</span>
          </span>
        </div>
        <div class="section-body">
          <div class="table-container">
            <table id="tbl-cves">
              <thead>
                <tr>
                  <th scope="col" data-col="cve_id">CVE ID <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="severity">Severity <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="count">Count <span class="sort-icon">⇅</span></th>
                  <th scope="col">Title</th>
                  <th scope="col" data-col="source">Source <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="apps">Applications <span class="sort-icon">⇅</span></th>
                </tr>
              </thead>
              <tbody>${topCveRows}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="section collapsible-section collapsed" id="section-freq">
        <div class="section-title section-toggle" onclick="toggleSection('section-freq')">
          Scan Frequency
          <span class="section-chevron">▾</span>
        </div>
        <div class="section-body">
          ${freqLegend()}
          <div class="table-container">
            <table id="tbl-freq">
              <thead>
                <tr>
                  <th scope="col" data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="total">Total Scans <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="first">First Scan <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="last">Latest Scan <span class="sort-icon">⇅</span></th>
                  <th scope="col">History</th>
                </tr>
              </thead>
              <tbody>${freqRows || emptyRow(5, 'No scan data available')}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="section collapsible-section collapsed" id="section-merges">
        <div class="section-title section-toggle" onclick="toggleSection('section-merges')">
          Merges to Primary Branch
          <span class="section-chevron">▾</span>
        </div>
        <div class="section-body">
          <div style="display:flex;gap:8px;margin-bottom:14px;align-items:center">
            <span style="font-size:12px;color:var(--text-muted);margin-right:4px">Filter:</span>
            <button class="btn btn-sm merge-range-btn active" data-days="7">7 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="14">14 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="30">30 days</button>
            <button class="btn btn-sm merge-range-btn" data-days="0">All time</button>
          </div>
          <div class="table-container">
            <table id="tbl-merges">
              <thead>
                <tr>
                  <th scope="col" data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="total">Merges <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="first">First Merge <span class="sort-icon">⇅</span></th>
                  <th scope="col" data-col="last">Latest Merge <span class="sort-icon">⇅</span></th>
                  <th scope="col">History</th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>

      ${(_slaDetailData = m, '')}
      ${buildRiskTrendSection(m)}
      ${buildSecretTrendSection(m)}
      ${buildSuppressionSection(m)}
      ${buildRecurrenceSection(m)}`;

    requestAnimationFrame(() => {
      const donut = document.getElementById('donut-chart');
      if (donut) drawDonutChart(donut, [
        { value: m.fix_rate.with_fix,    color: '#3fb950' },
        { value: m.fix_rate.without_fix, color: '#30363d' },
      ]);

      // ── MTTR/MTTD app filter dropdown ──────────────────────
      const mttrFilter = document.getElementById('mttr-app-filter');
      const mttrBody   = document.getElementById('mttr-panel-body');
      if (mttrFilter && mttrBody) {
        mttrFilter.addEventListener('change', () => {
          const app = mttrFilter.value;
          if (!app) {
            mttrBody.innerHTML = buildMttrPanelHtml(overallData, fastestHtml);
          } else {
            const appData = (m.metrics_by_target || {})[app] || {};
            mttrBody.innerHTML = buildMttrPanelHtml(appData, '');
          }
        });
      }

      const toolCanvas = document.getElementById('tool-chart');
      if (toolCanvas) drawHBarChart(toolCanvas, m.by_tool.map(t => ({
        label: t.tool, critical: t.critical, high: t.high,
        medium: t.medium, low: t.low, total: t.total, top_app: t.top_app || '',
      })));

      const trendCanvas = document.getElementById('trend-chart');
      if (trendCanvas && m.trend.length) {
        drawStackedBarChart(trendCanvas, [
          { color: '#ff7b72', data: m.trend.map(t => t.critical) },
          { color: '#ffa657', data: m.trend.map(t => t.high) },
          { color: '#e3b341', data: m.trend.map(t => t.medium) },
          { color: '#79c0ff', data: m.trend.map(t => t.low) },
        ], m.trend.map(t => t.timestamp.slice(0, 10)), m.trend);
      }

      // ── Sortable: Top CVEs ──────────────────────────────────
      (function() {
        const tbl = document.getElementById('tbl-cves');
        if (!tbl || !m.top_cves.length) return;
        let sortCol = 'count', sortDir = -1;
        const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
        function cveRow(c) {
          return `<tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" rel="noopener noreferrer"><code>${esc(c.cve_id)}</code></a></td>
            <td><span class="sev-badge ${esc(c.severity)}">${ucFirst(c.severity)}</span></td>
            <td>${esc(c.count)}</td>
            <td style="max-width:280px">${esc(c.title || '\u2014')}</td>
            <td>${sourcesBadges(c.sources)}</td>
            <td style="font-size:12px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`;
        }
        function resort() {
          const rows = [...m.top_cves].sort((a, b) => {
            if (sortCol === 'severity') return sortDir * ((SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
            if (sortCol === 'count')    return sortDir * (a.count - b.count);
            if (sortCol === 'apps')     return sortDir * (a.apps.length - b.apps.length);
            if (sortCol === 'source')   return sortDir * ((a.sources||[]).join().localeCompare((b.sources||[]).join()));
            return sortDir * String(a[sortCol]).localeCompare(String(b[sortCol]));
          });
          tbl.querySelector('tbody').innerHTML = rows.map(cveRow).join('');
          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'count' || sortCol === 'apps' ? -1 : 1; }
            resort();
          };
        });
        resort();
      })();

      // ── Sortable: Scan Frequency ────────────────────────────
      (function() {
        const tbl = document.getElementById('tbl-freq');
        if (!tbl) return;
        let sortCol = 'total', sortDir = -1;
        const freqData = Object.entries(m.scan_frequency || {});
        const { range: freqSpan, peak: freqPeak } = freqScale(freqData);
        function freqRow([name, f]) {
          const first = f.dates.length ? f.dates[0] : '\u2014';
          const last  = f.dates.length ? f.dates[f.dates.length - 1] : '\u2014';
          return `<tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(f.total)}</td>
            <td>${esc(first)}</td>
            <td>${esc(last)}</td>
            <td>${freqDots(f, freqSpan, freqPeak)}</td>
          </tr>`;
        }
        function resort() {
          const rows = [...freqData].sort(([na, fa], [nb, fb]) => {
            if (sortCol === 'name')  return sortDir * na.localeCompare(nb);
            if (sortCol === 'total') return sortDir * (fa.total - fb.total);
            if (sortCol === 'first') return sortDir * (fa.dates[0] || '').localeCompare(fb.dates[0] || '');
            if (sortCol === 'last')  return sortDir * ((fa.dates[fa.dates.length-1]||'').localeCompare(fb.dates[fb.dates.length-1]||''));
            return 0;
          });
          tbl.querySelector('tbody').innerHTML = rows.map(freqRow).join('');
          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'total' ? -1 : 1; }
            resort();
          };
        });
        resort();
      })();

      // ── Merges to Primary Branch (filterable) ───────────────
      (function() {
        const tbl = document.getElementById('tbl-merges');
        if (!tbl) return;
        const allData = Object.entries(mergesData);
        const mergeSpan = freqRange(allData.map(([, f]) => f.dates));
        let activeDays = 7;
        let sortCol = 'total', sortDir = -1;

        function cutoffDate(days) {
          if (!days) return '';
          const d = new Date();
          d.setDate(d.getDate() - days);
          return d.toISOString().slice(0, 10);
        }

        function mergeRow([name, f], filteredDates) {
          const first = filteredDates.length ? filteredDates[0] : '—';
          const last  = filteredDates.length ? filteredDates[filteredDates.length - 1] : '—';
          return `<tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(filteredDates.length)}</td>
            <td>${esc(first)}</td>
            <td>${esc(last)}</td>
            <td>${freqTimeline(filteredDates.map(d => ({ date: d })), mergeSpan)}</td>
          </tr>`;
        }

        function resort() {
          const cutoff = cutoffDate(activeDays);
          const filtered = allData
            .map(([name, f]) => {
              const dates = cutoff ? f.dates.filter(d => d >= cutoff) : [...f.dates];
              return [name, f, dates];
            })
            .filter(([,, dates]) => dates.length > 0)
            .sort(([na,, da], [nb,, db]) => {
              if (sortCol === 'name')  return sortDir * na.localeCompare(nb);
              if (sortCol === 'total') return sortDir * (da.length - db.length);
              if (sortCol === 'first') return sortDir * (da[0]||'').localeCompare(db[0]||'');
              if (sortCol === 'last')  return sortDir * ((da[da.length-1]||'').localeCompare((db[db.length-1]||'')));
              return 0;
            });

          tbl.querySelector('tbody').innerHTML = filtered.length
            ? filtered.map(([name, f, dates]) => mergeRow([name, f], dates)).join('')
            : emptyRow(5, 'No merges in this period');

          tbl.querySelectorAll('th[data-col]').forEach(th => {
            const ic = th.querySelector('.sort-icon');
            if (ic) ic.textContent = th.dataset.col === sortCol ? (sortDir > 0 ? '▲' : '▼') : '⇅';
          });
        }

        // Filter buttons
        document.querySelectorAll('.merge-range-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            document.querySelectorAll('.merge-range-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeDays = parseInt(btn.dataset.days, 10);
            resort();
          });
        });

        // Column sort
        tbl.querySelectorAll('th[data-col]').forEach(th => {
          th.onclick = () => {
            if (sortCol === th.dataset.col) sortDir *= -1;
            else { sortCol = th.dataset.col; sortDir = sortCol === 'total' ? -1 : 1; }
            resort();
          };
        });

        resort();
      })();

      buildCiHealthSection().then(html => {
        if (html && location.hash.startsWith('#/metrics')) page.insertAdjacentHTML('beforeend', html);
      });
    });
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}
