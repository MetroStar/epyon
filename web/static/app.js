/* ============================================================
   Epyon Web Interface — app.js
   Vanilla JS single-page application
   ============================================================ */

'use strict';

// ── Inactivity timeout (APSC-DV-000070 / APSC-DV-000080) ─────
// 15 minutes for standard users; resets on any user interaction.
// Displays a 60-second warning modal before expiry.
(function _inactivityGuard() {
  const IDLE_MS    = 15 * 60 * 1000;   // 15 min
  const WARNING_MS = 60 * 1000;        // warn 1 min before expiry

  let _warningTimer = null;
  let _expireTimer  = null;
  let _warnEl       = null;

  function _clearTimers() {
    clearTimeout(_warningTimer);
    clearTimeout(_expireTimer);
  }

  function _showExpired() {
    if (_warnEl) _warnEl.remove();
    const overlay = document.createElement('div');
    overlay.id = 'epyon-session-expired';
    overlay.innerHTML = `
      <div class="epyon-session-modal">
        <div class="epyon-session-icon">&#9201;</div>
        <h2>Session Expired</h2>
        <p>Your session has expired due to inactivity (15 minutes).</p>
        <button onclick="location.reload()" class="btn btn-primary">Reload</button>
      </div>`;
    document.body.appendChild(overlay);
  }

  function _showWarning(secsLeft) {
    if (!_warnEl) {
      _warnEl = document.createElement('div');
      _warnEl.id = 'epyon-session-warning';
      document.body.appendChild(_warnEl);
    }
    _warnEl.innerHTML = `
      <span>&#9888; Session expiring in <strong>${secsLeft}s</strong> due to inactivity.</span>
      <button onclick="window._epyonResetIdle()" class="btn btn-sm">Stay Active</button>`;
  }

  function _reset() {
    _clearTimers();
    if (_warnEl) { _warnEl.remove(); _warnEl = null; }
    _warningTimer = setTimeout(function() {
      _showWarning(60);
      // tick countdown
      let s = 59;
      const tick = setInterval(function() {
        if (s <= 0) { clearInterval(tick); return; }
        _showWarning(s--);
      }, 1000);
      _expireTimer = setTimeout(function() {
        clearInterval(tick);
        _clearTimers();
        _showExpired();
      }, WARNING_MS);
    }, IDLE_MS - WARNING_MS);
  }

  // Reset on any meaningful user interaction (throttled to 5 s)
  let _lastReset = 0;
  function _throttledReset() {
    const now = Date.now();
    if (now - _lastReset > 5000) { _lastReset = now; _reset(); }
  }

  window._epyonResetIdle = _reset;

  window.addEventListener('load', function() {
    // Don't run in static / offline dashboard mode
    if (window.__SCAN__) return;
    _reset();
    ['mousemove','keydown','click','touchstart','scroll'].forEach(function(evt) {
      document.addEventListener(evt, _throttledReset, { passive: true });
    });
  });
}());


const _findingsRegistry     = new Map();
let   _findingNextId        = 0;

// ── Dependency detail registry (populated in sbomRender) ──────
const _depsRegistry         = new Map();
let   _depsNextId           = 0;

// ── API endpoint detail registry (populated in apiRender) ─────
const _apiRegistry          = new Map();
let   _apiNextId            = 0;

// ── GitHub Signals detail (populated in renderGitHubSignals) ──
let _ghSignalData = null;

// ── Findings sort state (per severity) ───────────────────────
const _currentFindingsBySev = {};
const _sortState             = {};

// ── Epyon workflow YAML (shared by Settings page + Add App modal) ─
const WORKFLOW_YML = `name: Private Security Scan

# Epyon private-repo scanner entrypoint.
# This workflow delegates execution to the local reusable workflow.

permissions:
  contents: read

concurrency:
  group: epyon-scan-\${{ github.repository }}
  cancel-in-progress: false

on:
  schedule:
    # Nightly full scan — runs every night at 2 AM UTC (Mon-Sat)
    - cron: '0 2 * * 1-6'
    # Weekly full scan — runs Sunday night at 2 AM UTC
    - cron: '0 2 * * 0'
  # checkov:skip=CKV_GHA_7:Workflow inputs control scan parameters not build artifacts
  workflow_dispatch:
    inputs:
      subdirectory:
        description: 'Optional: Subdirectory path to scan (e.g., apps/api)'
        required: false
        type: string
      scan_mode:
        description: 'Scan mode (quick/full/nightly/baseline/stig)'
        required: false
        default: 'full'
        type: choice
        options:
          - quick
          - full
          - nightly
          - baseline
          - stig
      garak_target_type:
        description: 'Garak generator type (e.g. test, openai, huggingface)'
        required: false
        default: 'openai'
        type: string
      garak_target_name:
        description: 'Garak target model name (e.g. gpt-4o-mini)'
        required: false
        default: 'gpt-4o-mini'
        type: string
      garak_probes:
        description: 'Garak probe set (comma-separated, e.g. promptinject,dan,encoding)'
        required: false
        default: 'promptinject'
        type: string

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  security-scan-main:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    permissions:
      contents: read
      actions: read
      pull-requests: write
      security-events: write
      issues: write
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: \${{ github.event_name == 'schedule' && (github.event.schedule == '0 2 * * 0' && 'full' || 'nightly') || github.event.inputs.scan_mode || 'full' }}
      subdirectory: \${{ github.event.inputs.subdirectory || '' }}
      garak_target_type: \${{ github.event.inputs.garak_target_type || 'openai' }}
      garak_target_name: \${{ github.event.inputs.garak_target_name || 'gpt-4o-mini' }}
      garak_probes: \${{ github.event.inputs.garak_probes || 'promptinject' }}
    secrets: inherit`;

// ── Security helpers ──────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Formatting helpers ────────────────────────────────────────
function fmtDate(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return esc(ts); }
}

function ucFirst(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }

const _SCAN_TYPE_LABELS = {
  full:        'Full',
  quick:       'Quick',
  nightly:     'Nightly',
  baseline:    'Baseline',
  stig:        'STIG',
  local_model: 'Local Model',
};
function scanTypeLabel(type) {
  return _SCAN_TYPE_LABELS[type] || ucFirst(type || 'full');
}

function computeStatus(scan) {
  if (!scan || typeof scan !== 'object') return 'unknown';
  if ((scan.critical || 0) > 0) return 'critical';
  if ((scan.high    || 0) > 0) return 'high';
  if ((scan.medium  || 0) > 0) return 'medium';
  if ((scan.low     || 0) > 0) return 'low';
  if (scan.scan_id)             return 'clean';
  return 'unknown';
}

// ── UI atoms ──────────────────────────────────────────────────
function sevBadge(severity, count) {
  return `<span class="sev-badge ${esc(severity)}">${esc(count)} ${ucFirst(severity)}</span>`;
}

// ── Finding source classification ────────────────────────────
function findingSource(f) {
  const type = (f.type || '').toLowerCase();
  const tool = (f.tool || '').toLowerCase();
  if (type === 'container_vulnerability' || tool === 'anchore') return 'container';
  if (type === 'iac_misconfiguration' || tool === 'checkov')   return 'iac';
  if (type.includes('credential') || type.includes('secret') || tool === 'trufflehog') return 'secret';
  if (type === 'eol_package' || tool === 'xeol')               return 'eol';
  return 'code';
}

function findingSourceBadge(f) {
  const src = findingSource(f);
  const cfg = {
    container: { style: 'background:#0f4c8a22;color:#60a5fa;border:1px solid #1d4ed866', label: '📦 Container' },
    code:      { style: 'background:#16521622;color:#4ade80;border:1px solid #15803d66', label: '💻 Code'      },
    iac:       { style: 'background:#4a1d9622;color:#c084fc;border:1px solid #7e22ce66', label: '🔧 IaC'       },
    secret:    { style: 'background:#7f1d1d22;color:#fca5a5;border:1px solid #b91c1c66', label: '🔑 Secret'    },
    eol:       { style: 'background:#92400022;color:#fbbf24;border:1px solid #b4530066', label: '⏱ EOL'        },
  };
  const { style, label } = cfg[src] || cfg.code;
  return `<span style="font-size:10px;padding:1px 6px;border-radius:3px;white-space:nowrap;${style}">${label}</span>`;
}

// Returns a source badge from a sources array (top_cves aggregated data)
function sourcesBadges(sources) {
  return (sources || []).map(s => findingSourceBadge({ type: s === 'container' ? 'container_vulnerability' : 'vulnerability' })).join(' ');
}

function sevBadgeRow(scan) {
  const parts = [];
  if (scan.critical > 0) parts.push(sevBadge('critical', scan.critical));
  if (scan.high     > 0) parts.push(sevBadge('high',     scan.high));
  if (scan.medium   > 0) parts.push(sevBadge('medium',   scan.medium));
  if (scan.low      > 0) parts.push(sevBadge('low',      scan.low));
  if (parts.length === 0) parts.push('<span class="sev-badge clean">✓ Clean</span>');
  return parts.join('');
}

function hfStatusBadge(scan) {
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  if (!ps && !mc) return '';
  const parts = [];
  if (ps) {
    if (ps.flagged_count > 0)
      parts.push(`<span class="sev-badge critical" title="Pickle safety: ${ps.flagged_count} infected file(s)">🥒 ${ps.flagged_count} infected</span>`);
    else
      parts.push(`<span class="sev-badge clean" title="Pickle safety: clean">🥒 Safe</span>`);
  }
  if (mc) {
    if (mc.failed > 0)
      parts.push(`<span class="sev-badge medium" title="Model card: ${mc.failed} check(s) failed">📋 ${mc.failed} failed</span>`);
    else if (mc.warnings > 0)
      parts.push(`<span class="sev-badge low" title="Model card: ${mc.warnings} warning(s)">📋 ${mc.warnings} warn</span>`);
    else
      parts.push(`<span class="sev-badge clean" title="Model card: compliant">📋 OK</span>`);
  }
  return parts.join('');
}

function statusBadge(status) {
  const labels = {
    critical: 'Critical', high: 'High', medium: 'Medium',
    low: 'Low', clean: 'Clean', unknown: 'Unknown',
  };
  return `<span class="status-badge ${esc(status)}">${labels[status] || 'Unknown'}</span>`;
}

function loading() {
  return '<div class="loading"><div class="spinner"></div>Loading…</div>';
}

function errBanner(msg) {
  return `<div class="error-banner">⚠ ${esc(msg)}</div>`;
}

function emptyState(title, desc, action = '') {
  return `
    <div class="empty-state">
      <h3>${esc(title)}</h3>
      <p>${esc(desc)}</p>
      ${action}
    </div>`;
}

function dedupeTools(arr) {
  return [...new Set(arr || [])];
}

// ── Chart helpers ─────────────────────────────────────────────
const _CC = {
  critical: '#ff7b72', high: '#ffa657', medium: '#e3b341', low: '#79c0ff',
};

function _getTooltip() {
  let tt = document.getElementById('chart-tooltip');
  if (!tt) {
    tt = document.createElement('div');
    tt.id = 'chart-tooltip';
    tt.className = 'chart-tooltip';
    document.body.appendChild(tt);
  }
  return tt;
}
function _showTooltip(e, html) {
  const tt = _getTooltip();
  tt.innerHTML = html;
  tt.style.display = 'block';
  const offset = 14;
  let left = e.clientX + offset;
  let top  = e.clientY - 10;
  if (left + 200 > window.innerWidth)  left = e.clientX - 200 - offset;
  if (top  + 80  > window.innerHeight) top  = e.clientY - 80;
  tt.style.left = left + 'px';
  tt.style.top  = top  + 'px';
}
function _hideTooltip() {
  const tt = document.getElementById('chart-tooltip');
  if (tt) tt.style.display = 'none';
}

function drawDonutChart(canvas, segments) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const W = 200, H = 200;
  canvas.width = W * dpr; canvas.height = H * dpr;
  canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
  ctx.scale(dpr, dpr);
  const cx = W / 2, cy = H / 2, R = 78, ir = 50;
  const total = segments.reduce((s, x) => s + (x.value || 0), 0);
  if (!total) {
    ctx.fillStyle = '#21262d';
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#161b22';
    ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#6e7681'; ctx.font = '12px sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('No data', cx, cy);
    return;
  }
  let angle = -Math.PI / 2;
  for (const seg of segments) {
    if (!seg.value) continue;
    const slice = (seg.value / total) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, angle, angle + slice); ctx.closePath();
    ctx.fillStyle = seg.color; ctx.fill();
    angle += slice;
  }
  ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2);
  ctx.fillStyle = '#161b22'; ctx.fill();
  ctx.fillStyle = '#e6edf3'; ctx.font = 'bold 22px sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(total.toLocaleString(), cx, cy - 9);
  ctx.fillStyle = '#8b949e'; ctx.font = '11px sans-serif';
  ctx.fillText('findings', cx, cy + 10);
}

function drawHBarChart(canvas, items) {
  if (!items.length) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w   = (canvas.parentElement ? canvas.parentElement.clientWidth - 40 : 400);
  const rowH = 36, h = items.length * rowH + 8;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  const labelW = 100, countW = 44, barArea = w - labelW - countW;
  const maxTotal = Math.max(...items.map(x => x.total), 1);
  items.forEach((item, i) => {
    const barH = 20, barY = i * rowH + (rowH - barH) / 2;
    ctx.fillStyle = '#21262d';
    ctx.fillRect(labelW, barY, barArea, barH);
    let xOff = labelW;
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      const val = item[sev] || 0;
      if (!val) continue;
      const bw = Math.max(1, Math.round((val / maxTotal) * barArea));
      ctx.fillStyle = _CC[sev];
      ctx.fillRect(xOff, barY, bw, barH);
      xOff += bw;
    }
    ctx.fillStyle = '#8b949e';
    ctx.font = '12px -apple-system, sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    const lbl = item.label.length > 13 ? item.label.slice(0, 12) + '…' : item.label;
    ctx.fillText(lbl, labelW - 8, barY + barH / 2);
    ctx.textAlign = 'left';
    ctx.fillText(item.total, labelW + barArea + 8, barY + barH / 2);
  });

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const my = e.clientY - rect.top;
    const i  = Math.floor(my / rowH);
    if (i < 0 || i >= items.length) { _hideTooltip(); return; }
    const ta = items[i].top_app;
    if (!ta) { _hideTooltip(); return; }
    _showTooltip(e, `Top contributing app<br><strong>${esc(ta)}</strong>`);
  };
  canvas.onmouseleave = _hideTooltip;
  canvas.onclick = (e) => {
    const rect = canvas.getBoundingClientRect();
    const my = e.clientY - rect.top;
    const i  = Math.floor(my / rowH);
    if (i < 0 || i >= items.length) return;
    const ta = items[i].top_app;
    if (ta) navigate('#/applications/' + encodeURIComponent(ta));
  };
  canvas.style.cursor = 'pointer';
}

function drawLineChart(canvas, series, xLabels) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = (canvas.parentElement ? canvas.parentElement.clientWidth - 40 : 600);
  const h = 200;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  const n = xLabels.length;
  if (!n) return;
  const pad = { top: 16, right: 16, bottom: 36, left: 44 };
  const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
  const maxV = Math.max(...series.flatMap(s => s.data), 1);
  ctx.strokeStyle = '#21262d'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + ch * (1 - i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
    ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(maxV * i / 4), pad.left - 5, y);
  }
  const step = Math.max(1, Math.floor(n / 12));
  ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  for (let i = 0; i < n; i += step) {
    const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
    ctx.fillText(xLabels[i].slice(5, 10), x, pad.top + ch + 6);
  }
  for (const s of series) {
    if (!s.data.some(v => v > 0)) continue;
    ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
    ctx.beginPath();
    s.data.forEach((v, i) => {
      const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
      const y = pad.top + ch * (1 - v / maxV);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  }
}

function drawStackedBarChart(canvas, series, xLabels, barData) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = (canvas.parentElement ? canvas.parentElement.clientWidth - 40 : 600);
  const h = 200;
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  const n = xLabels.length;
  if (!n) return;
  const pad = { top: 16, right: 16, bottom: 36, left: 44 };
  const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;

  // Compute per-bar totals for y-axis scale
  const totals = xLabels.map((_, i) => series.reduce((sum, s) => sum + (s.data[i] || 0), 0));
  const maxV = Math.max(...totals, 1);

  // Horizontal grid lines + y-axis labels
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + ch * (1 - i / 4);
    ctx.strokeStyle = '#21262d';
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
    ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(maxV * i / 4), pad.left - 5, y);
  }

  // X-axis labels (show ~12 evenly spaced)
  const slotW = cw / n;
  const barW = Math.max(2, slotW - 2);
  const labelStep = Math.max(1, Math.floor(n / 12));
  ctx.fillStyle = '#6e7681'; ctx.font = '10px sans-serif';
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  for (let i = 0; i < n; i += labelStep) {
    const x = pad.left + (i + 0.5) * slotW;
    ctx.fillText(xLabels[i].slice(5, 10), x, pad.top + ch + 6);
  }

  // Stacked bars — reverse series so lowest severity sits at the bottom
  const reversed = [...series].reverse();
  for (let i = 0; i < n; i++) {
    const x = pad.left + i * slotW + (slotW - barW) / 2;
    let floor = pad.top + ch;
    for (const s of reversed) {
      const val = s.data[i] || 0;
      if (val <= 0) continue;
      const segH = (val / maxV) * ch;
      ctx.fillStyle = s.color;
      ctx.fillRect(x, floor - segH, barW, segH);
      floor -= segH;
    }
  }

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    if (mx < pad.left || mx > pad.left + cw || my < pad.top || my > pad.top + ch) {
      _hideTooltip(); return;
    }
    const i = Math.floor((mx - pad.left) / slotW);
    if (i < 0 || i >= n) { _hideTooltip(); return; }
    const bd    = barData && barData[i];
    const label = bd ? esc(bd.target) : xLabels[i];
    const date  = xLabels[i];
    const c  = series[0].data[i] || 0;
    const hv = series[1].data[i] || 0;
    const mv = series[2].data[i] || 0;
    const lv = series[3].data[i] || 0;
    _showTooltip(e,
      `<strong>${label}</strong> <span class="tt-date">${date}</span><br>` +
      `<span style="color:#ff7b72">■</span> ${c}&ensp;` +
      `<span style="color:#ffa657">■</span> ${hv}&ensp;` +
      `<span style="color:#e3b341">■</span> ${mv}&ensp;` +
      `<span style="color:#79c0ff">■</span> ${lv}`
    );
  };
  canvas.onmouseleave = _hideTooltip;
  canvas.onclick = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    if (mx < pad.left || mx > pad.left + cw || my < pad.top || my > pad.top + ch) return;
    const i = Math.floor((mx - pad.left) / slotW);
    if (i < 0 || i >= n) return;
    const bd = barData && barData[i];
    const target = bd ? bd.target : null;
    if (target) navigate('#/applications/' + encodeURIComponent(target));
  };
  canvas.style.cursor = 'pointer';
}

// ── API client ────────────────────────────────────────────────
const api = {
  async _get(url) {
    const r = await fetch(url);
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  async _post(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  async _delete(url) {
    const r = await fetch(url, { method: 'DELETE' });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.json();
  },
  getStats()          { return this._get('/api/stats'); },
  getApplications()   { return this._get('/api/applications'); },
  getHiddenApps()     { return this._get('/api/applications-hidden'); },
  hideApp(name)       { return this._post('/api/applications/hide', { name }); },
  restoreApp(name)    { return this._post('/api/applications/restore', { name }); },
  deleteApp(name)     { return this._delete(`/api/applications/data?name=${encodeURIComponent(name)}`); },
  deleteScan(id)      { return this._delete(`/api/scans/${encodeURIComponent(id)}`); },
  setMonitored(name)   { return this._post('/api/applications/monitored', { name }); },
  unsetMonitored(name) { return this._delete(`/api/applications/monitored?name=${encodeURIComponent(name)}`); },
  registerApp(name, url) {
    return this._post('/api/applications', { name, url });
  },
  getAppScans(name)   { return this._get(`/api/applications/${encodeURIComponent(name)}/scans`); },
  getScan(id)         { return this._get(`/api/scans/${encodeURIComponent(id)}`); },
  getScanHistory()    { return this._get('/api/scan-history'); },
  getApprovedImages() { return this._get('/api/settings/approved-images'); },
  getGitHubConfig()   { return this._get('/api/github/config'); },
  saveGitHubConfig(d) { return this._post('/api/github/config', d); },
  triggerGitHubSync() { return this._post('/api/github/sync', {}); },
  getGitHubSyncStatus(){ return this._get('/api/github/sync'); },
  triggerScan(target, scanType, runGarak, runStig = true) {
    const body = { target, scan_type: scanType };
    if (runGarak) body.run_garak = true;
    if (runStig)  body.run_stig  = true;
    return this._post('/api/scans', body);
  },
  getJob(id)    { return this._get(`/api/jobs/${encodeURIComponent(id)}`); },
  getJobs()     { return this._get('/api/jobs'); },
  getMetrics()       { return this._get('/api/metrics'); },
  getGitHubMetrics()         { return this._get('/api/github-metrics'); },
  getGitHubSignalsHistory()  { return this._get('/api/github-signals-history'); },
  getAiConfig() { return this._get('/api/ai/config'); },
  saveAiConfig(d){ return this._post('/api/ai/config', d); },
  getExecSummary(id)      { return this._post(`/api/scans/${encodeURIComponent(id)}/executive-summary`, {}); },
  getTechnicalSummary(id) { return this._post(`/api/scans/${encodeURIComponent(id)}/technical-summary`, {}); },
  getGlobalExecSummary()      { return this._post('/api/executive-summary', {}); },
  getGlobalTechnicalSummary() { return this._post('/api/technical-summary', {}); },
  getGlobalIssoSummary()      { return this._post('/api/isso-summary', {}); },
  getAppIssoSummary(name)     { return this._post(`/api/applications/${encodeURIComponent(name)}/isso-summary`, {}); },
  async exportSummaryDocx(body) {
    const r = await fetch('/api/export/summary-docx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.blob();
  },
  getFindingFix(finding)      { return this._post('/api/findings/fix', finding); },
  calculateScorecard(id)      { return this._post(`/api/scans/${encodeURIComponent(id)}/scorecard`, {}); },
  getStigData(id){ return this._get(`/api/scans/${encodeURIComponent(id)}/stig-data`); },
  getStigHistory(app, slug) {
    const p = new URLSearchParams();
    if (app)  p.set('app', app);
    if (slug) p.set('slug', slug);
    const qs = p.toString();
    return this._get('/api/stig/history' + (qs ? '?' + qs : ''));
  },
  getJiraConfig()      { return this._get('/api/jira/config'); },
  saveJiraConfig(d)    { return this._post('/api/jira/config', d); },
  testJiraConnection() { return this._post('/api/jira/test', {}); },
  getJiraTickets()     { return this._get('/api/jira/tickets'); },
  syncJiraApp(name)    { return this._post(`/api/jira/sync/${encodeURIComponent(name)}`, {}); },
};

// ── Theme ────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const moon = document.getElementById('theme-icon-moon');
  const sun  = document.getElementById('theme-icon-sun');
  if (moon) moon.style.display = theme === 'dark'  ? '' : 'none';
  if (sun)  sun.style.display  = theme === 'light' ? '' : 'none';
  try { localStorage.setItem('epyon-theme', theme); } catch (_) {}
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
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
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const content = document.getElementById('content');
  if (!sidebar) return;
  const collapsed = sidebar.classList.toggle('collapsed');
  if (content) content.style.marginLeft = collapsed ? '0' : '';
  try { localStorage.setItem('epyon-sidebar-collapsed', collapsed ? '1' : ''); } catch (_) {}
}

(function initSidebar() {
  try {
    if (localStorage.getItem('epyon-sidebar-collapsed') === '1') {
      const sidebar = document.getElementById('sidebar');
      const content = document.getElementById('content');
      if (sidebar) sidebar.classList.add('collapsed');
      if (content) content.style.marginLeft = '0';
    }
  } catch (_) {}
})();

// ── Navigation ────────────────────────────────────────────────
function setActive(routeKey) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.route === routeKey);
  });
  // Clear findings registry and close any open drawer on navigation
  _findingsRegistry.clear();
  _findingNextId = 0;
  for (const k of Object.keys(_currentFindingsBySev)) delete _currentFindingsBySev[k];
  for (const k of Object.keys(_sortState))             delete _sortState[k];
  closeFindingDetail();
}

function navigate(hash) {
  window.location.hash = hash;
}

// ── Views ─────────────────────────────────────────────────────

async function renderOverview() {
  setActive('overview');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [stats, apps] = await Promise.all([api.getStats(), api.getApplications()]);

    const continuous  = apps.filter(a => a.monitored);
    const evaluation  = apps.filter(a => !a.monitored);
    const anyMonitored = continuous.length > 0;

    const makeCard = app => `
          <div class="app-card status-${esc(app.status)}"
               onclick="navigate('#/applications/${encodeURIComponent(app.name)}')">
            <div class="app-card-header">
              <span class="app-name">${esc(app.name)}</span>
              ${statusBadge(app.status)}
            </div>
            <div class="app-card-meta">
              ${app.last_scanned
                ? `Last scanned: ${fmtDate(app.last_scanned)} · ${esc(app.scan_type || 'full')}`
                : 'Never scanned'}
            </div>
            <div class="severity-row">${sevBadgeRow(app)}</div>
            <div class="app-card-footer">
              ${app.scan_count} scan${app.scan_count !== 1 ? 's' : ''} total
            </div>
          </div>`;

    const appSections = apps.length
      ? anyMonitored
        ? `<div class="section">
             <div class="section-title">
               <span>● Continuously Monitored <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${continuous.length})</span></span>
               <button class="btn btn-sm" onclick="navigate('#/applications')">View all →</button>
             </div>
             <div class="app-grid">${continuous.map(makeCard).join('')}</div>
           </div>
           ${evaluation.length ? `
           <div class="section" style="margin-top:24px">
             <div class="section-title">
               <span>◯ Evaluation <span style="font-size:12px;font-weight:400;color:var(--text-muted)">(${evaluation.length})</span></span>
             </div>
             <div class="app-grid">${evaluation.map(makeCard).join('')}</div>
           </div>` : ''}`
        : `<div class="section">
             <div class="section-title">
               Applications
               <button class="btn btn-sm" onclick="navigate('#/applications')">View all →</button>
             </div>
             <div class="app-grid">${apps.map(makeCard).join('')}</div>
           </div>`
      : `<div class="section">
           <div class="section-title">Applications</div>
           ${emptyState(
             'No applications yet',
             'Run your first scan to see applications here.',
             `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">▶ Run First Scan</button>`,
           )}
         </div>`;

    page.innerHTML = `
      <div class="page-header">
        <h1>Security Overview</h1>
        <button class="btn btn-primary" onclick="navigate('#/new-scan')">+ Run Scan</button>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${esc(stats.total_applications)}</div>
          <div class="stat-label">Applications</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(stats.total_scans)}</div>
          <div class="stat-label">Total Scans</div>
        </div>
        <div class="stat-card critical">
          <div class="stat-value">${esc(stats.critical)}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="stat-value">${esc(stats.high)}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-card medium">
          <div class="stat-value">${esc(stats.medium)}</div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card low">
          <div class="stat-value">${esc(stats.low)}</div>
          <div class="stat-label">Low</div>
        </div>
      </div>

      ${buildOverviewExecSection()}
      ${buildOverviewTechSection()}
      ${buildOverviewIssoSection()}

      ${appSections}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

async function toggleMonitored(name, isCurrently) {
  try {
    if (isCurrently) {
      await api.unsetMonitored(name);
    } else {
      await api.setMonitored(name);
    }
    renderApplications();
  } catch (e) {
    alert('Failed to update monitoring status: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderApplications() {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [apps, hidden] = await Promise.all([api.getApplications(), api.getHiddenApps()]);

    const rows = apps.length
      ? apps.map(app => `
          <tr onclick="navigate('#/applications/${encodeURIComponent(app.name)}')"
              style="cursor:pointer">
            <td>
              <strong>${esc(app.name)}</strong>
              ${app.url ? `<div style="font-size:11px;color:var(--text-dim);margin-top:2px">${esc(app.url)}</div>` : ''}
            </td>
            <td onclick="event.stopPropagation();toggleMonitored('${esc(app.name)}',${!!app.monitored})">
              <button class="app-type-badge ${app.monitored ? 'monitored' : 'evaluation'}"
                      title="${app.monitored ? 'Continuous — click to set as Evaluation' : 'Evaluation — click to set as Continuous'}">
                ${app.monitored ? '● Continuous' : '○ Evaluation'}
              </button>
            </td>
            <td>${app.last_scanned ? fmtDate(app.last_scanned) : '<span style="color:var(--text-dim)">Never</span>'}</td>
            <td>${esc(app.scan_count)}</td>
            <td>${app.critical > 0
                  ? `<span class="sev-badge critical">${app.critical}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.high > 0
                  ? `<span class="sev-badge high">${app.high}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.medium > 0
                  ? `<span class="sev-badge medium">${app.medium}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${app.low > 0
                  ? `<span class="sev-badge low">${app.low}</span>`
                  : '<span style="color:var(--text-dim)">0</span>'}</td>
            <td>${statusBadge(app.status)}</td>
            <td>
              <button class="btn btn-sm"
                onclick="event.stopPropagation();navigate('#/new-scan')">
                Scan
              </button>
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();hideApplication('${esc(app.name)}')"
                title="Hide this application from the list">
                Hide
              </button>
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();deleteApplication('${esc(app.name)}')"
                title="Permanently delete all scan data for this application">
                Delete
              </button>
            </td>
          </tr>`).join('')
      : `<tr><td colspan="10" style="text-align:center;padding:48px;color:var(--text-muted)">
           No applications found. Run a scan to get started.
         </td></tr>`;

    const hiddenSection = hidden.length ? `
      <div class="section" style="margin-top:32px">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
          <span>Hidden Applications <span style="font-size:12px;color:var(--text-muted);font-weight:400">(${hidden.length})</span></span>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Application</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${hidden.map(name => `
                <tr>
                  <td style="color:var(--text-muted)">${esc(name)}</td>
                  <td>
                    <button class="btn btn-sm"
                      onclick="restoreApplication('${esc(name)}')">
                      Restore
                    </button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : '';

    page.innerHTML = `
      <div class="page-header">
        <h1>Applications</h1>
        <div style="display:flex;gap:8px">
          <button class="btn" onclick="showAddAppModal()">+ Add Application</button>
          <button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Application</th>
              <th>Type</th>
              <th>Last Scanned</th>
              <th>Scans</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${hiddenSection}`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderAppDetail(name) {
  setActive('applications');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    // Load scans and registered app info in parallel
    const [scans, allApps] = await Promise.all([
      api.getAppScans(name),
      api.getApplications(),
    ]);
    const appInfo = allApps.find(a => a.name === name) || {};
    const appUrl  = appInfo.url || '';
    const latest = scans[0] || {};
    const status  = computeStatus(latest);

    const timelineItems = scans.length
      ? scans.map(s => {
          const st = computeStatus(s);
          return `
            <div class="scan-timeline-item"
                 onclick="navigate('#/scans/${encodeURIComponent(s.scan_id)}')">
              <div class="scan-timeline-dot ${esc(st)}"></div>
              <div class="scan-timeline-content">
                <div class="scan-timeline-title">
                  ${esc(scanTypeLabel(s.scan_type))} scan
                  <span>${sevBadgeRow(s)}</span>
                  ${hfStatusBadge(s)}
                  ${s.ci_source ? `<span class="badge badge-ci" title="From GitHub Actions · ${esc(s.ci_source.repo)}${s.ci_source.branch ? ' · ' + esc(s.ci_source.branch) : ''}">GH Actions</span>` : ''}
                </div>
                <div class="scan-timeline-meta">
                  ${fmtDate(s.timestamp)}
                  ${s.user ? ` · ${esc(s.user)}` : ''}
                  ${s.location ? ` · <code>${esc(s.location)}</code>` : ''}
                </div>
                ${dedupeTools(s.tools_analyzed).length ? `
                  <div class="tools-list" style="margin-top:8px">
                    ${dedupeTools(s.tools_analyzed).map(t =>
                      `<span class="tool-tag">${esc(t)}</span>`).join('')}
                  </div>` : ''}
              </div>
              ${s.has_dashboard
                ? `<button class="btn btn-sm"
                     onclick="event.stopPropagation();window.open('/api/scans/${encodeURIComponent(s.scan_id)}/dashboard','_blank')">
                     Dashboard ↗
                   </button>`
                : ''}
              <button class="btn btn-sm btn-danger"
                onclick="event.stopPropagation();deleteScan('${esc(s.scan_id)}', '${esc(name)}')"
                title="Permanently delete this scan">
                Delete
              </button>
            </div>`;
        }).join('')
      : emptyState(
          `No scans found for "${name}"`,
          appUrl ? `Repository: ${appUrl}` : 'Run a scan to populate history.',
          appUrl
            ? `<div style="display:flex;gap:8px;justify-content:center;margin-top:16px">
                 <button class="btn btn-primary"
                   onclick="navigate('#/new-scan?target=${encodeURIComponent(appUrl)}')">
                   ▶ Run First Scan
                 </button>
               </div>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">
                 ▶ Run Scan
               </button>`,
        );

    // Use comprehensive-scan counts (same source as overview cards) so numbers match.
    // If the most recent scan was a quick/stig scan, flag it so the user knows the
    // vulnerability counts are from an earlier full scan.
    const compTs   = appInfo.comprehensive_timestamp || '';
    const compType = appInfo.comprehensive_scan_type  || '';
    const countsDiffer = compTs && compTs !== latest.timestamp;
    const countsNote = countsDiffer
      ? `<div style="grid-column:1/-1;font-size:11px;color:var(--text-muted);margin-top:4px">
           Vulnerability counts are from the last ${esc(scanTypeLabel(compType))} scan
           (${fmtDate(compTs)}) — quick scans do not run all tools.
         </div>`
      : '';

    const statsSection = scans.length ? `
      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Total Scans</div>
          <div class="value">${esc(scans.length)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Last Scanned</div>
          <div class="value" style="font-size:13px">${fmtDate(latest.timestamp)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${appInfo.critical ?? latest.critical ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${appInfo.high ?? latest.high ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${appInfo.medium ?? latest.medium ?? 0}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${appInfo.low ?? latest.low ?? 0}</div>
        </div>
        ${countsNote}
      </div>` : '';

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <span>${esc(name)}</span>
      </div>
      <div class="page-header">
        <h1>${esc(name)} ${statusBadge(status)}</h1>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary"
            onclick="navigate('#/new-scan?target=${encodeURIComponent(appUrl)}')">
            ▶ Run Scan
          </button>
          <button class="btn app-type-badge ${appInfo.monitored ? 'monitored' : 'evaluation'}"
            onclick="(async()=>{
              try {
                ${appInfo.monitored
                  ? `await api.unsetMonitored('${esc(name)}')`
                  : `await api.setMonitored('${esc(name)}')`};
                renderAppDetail('${esc(name)}');
              } catch(e) { alert(e.message); }
            })()"
            title="${appInfo.monitored ? 'Continuous \u2014 click to set as Evaluation' : 'Evaluation \u2014 click to set as Continuous'}">
            ${appInfo.monitored ? '● Continuous' : '◯ Evaluation'}
          </button>
          <button class="btn btn-danger"
            onclick="hideApplication('${esc(name)}')"
            title="Hide this application from the list">
            Hide
          </button>
          <button class="btn btn-danger"
            onclick="deleteApplication('${esc(name)}')"
            title="Permanently delete all scan data for this application">
            Delete All
          </button>
        </div>
      </div>
      ${statsSection}
      ${buildAppIssoSection(name)}
      <div class="section">
        <div class="section-title">Scan History</div>
        <div class="scan-timeline">${timelineItems}</div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderScanDetail(scanId) {
  setActive('');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, allApps] = await Promise.all([api.getScan(scanId), api.getApplications()]);
    const status = computeStatus(scan);
    const appInfo = allApps.find(a => a.name === scan.target) || {};
    const repoUrl = scan.source_url || appInfo.url || scan.ci_source?.repo || '';

    // Build STIG section: show full results when available, empty state for stig/nightly scans
    const hasStigData = (scan.stig_total || 0) > 0;
    const scanTypeHasStig = ['stig', 'nightly', 'full', 'baseline'].includes(scan.scan_type);
    let stigCard = '';
    if (hasStigData) {
      const reports = scan.stig_reports || [];
      const multiStig = reports.length > 1;

      // Per-STIG rows (shown when multiple STIGs)
      const perStigRows = multiStig ? reports.map(r => {
        const slugLabel = r.slug.replace(/-/g, ' ').replace(/\bstig\b/gi, 'STIG');
        const mdBtn   = r.has_md   ? `<a class="btn btn-sm" href="${esc(r.md_url)}"   download>↓ .md</a>`   : '';
        const cklbBtn = r.has_cklb ? `<a class="btn btn-sm" href="${esc(r.cklb_url)}" download>↓ .cklb</a>` : '';
        return `
          <div class="stig-row">
            <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
            <span class="stig-row-counts">
              <span class="stig-mini open">${esc(r.open)} open</span>
              <span class="stig-mini pass">${esc(r.pass)} pass</span>
              <span class="stig-mini na">${esc(r.na)} n/a</span>
              <span class="stig-mini total">${esc(r.total)} total</span>
            </span>
            <span class="stig-row-btns">${mdBtn}${cklbBtn}</span>
          </div>`;
      }).join('') : '';

      // Primary (combined) download buttons
      const mdBtn = scan.has_stig_report
        ? `<a class="btn btn-sm" href="${esc(scan.stig_report_url)}" download>↓ findings.md</a>` : '';
      const cklbBtn = scan.has_stig_cklb
        ? `<a class="btn btn-sm" href="${esc(scan.stig_cklb_url)}" download>↓ findings.cklb</a>` : '';

      stigCard = `
        <div class="section findings-section-wrapper">
          <details class="findings-collapsible" style="border-left-color:#38bdf8">
            <summary class="findings-summary">
              <span class="findings-summary-left">
                <span class="findings-chevron" aria-hidden="true"></span>
                <span class="findings-summary-title">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                       stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                       style="vertical-align:-2px;margin-right:5px">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  STIG Assessment${multiStig ? ` <span style="color:var(--text-muted);font-weight:400;font-size:12px">(${reports.length} STIGs)</span>` : ''}
                </span>
                <span class="stig-mini open">${esc(scan.stig_open || 0)} open</span>
                <span class="stig-mini pass">${esc(scan.stig_pass || 0)} pass</span>
                <span class="stig-mini na">${esc(scan.stig_na || 0)} n/a</span>
                ${(scan.stig_nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(scan.stig_nr || 0)} not reviewed</span>` : ''}
                <span class="stig-mini total">${esc(scan.stig_total || 0)} total</span>
              </span>
              <span style="display:flex;align-items:center;gap:8px">
                ${mdBtn ? mdBtn.replace('btn-sm', 'btn-sm').replace('>', ' onclick="event.stopPropagation()">') : ''}
                ${cklbBtn ? cklbBtn.replace('>', ' onclick="event.stopPropagation()">') : ''}
                <span class="findings-summary-hint">Click to expand</span>
              </span>
            </summary>
            <div class="findings-body" style="padding:0 18px 16px">
              <div class="stig-counts" style="margin-top:12px">
                <div class="stig-count open">
                  <span class="num">${esc(scan.stig_open || 0)}</span>
                  <span class="lbl">Open</span>
                </div>
                <div class="stig-count pass">
                  <span class="num">${esc(scan.stig_pass || 0)}</span>
                  <span class="lbl">Not a Finding</span>
                </div>
                <div class="stig-count na">
                  <span class="num">${esc(scan.stig_na || 0)}</span>
                  <span class="lbl">Not Applicable</span>
                </div>
                ${(scan.stig_nr || 0) > 0 ? `
                <div class="stig-count" style="background:var(--bg-input);border-color:var(--border)">
                  <span class="num" style="color:var(--text-muted)">${esc(scan.stig_nr || 0)}</span>
                  <span class="lbl">Not Reviewed</span>
                </div>` : ''}
                <div class="stig-count total">
                  <span class="num">${esc(scan.stig_total || 0)}</span>
                  <span class="lbl">Total</span>
                </div>
              </div>
              ${multiStig ? `<div class="stig-per-stig">${perStigRows}</div>` : ''}
              <div class="stig-view-btn-row">
                <button class="btn btn-primary btn-sm"
                  onclick="navigate('#/stig-viewer/${encodeURIComponent(scanId)}')">
                  ⊞ View Findings Inline
                </button>
              </div>
            </div>
          </details>
        </div>`;
    } else {
      const noStigMsg = scanTypeHasStig
        ? 'No STIG results were recorded for this scan. Verify that STIG definitions are configured in <code>configuration/stigs/</code> and that <code>OPENAI_API_KEY</code> is set.'
        : 'STIG assessment is not included in this scan type. Run a <strong>Nightly</strong> or <strong>STIG</strong> scan to get compliance results.';
      stigCard = `
        <div class="section findings-section-wrapper">
          <details class="findings-collapsible" style="border-left-color:var(--border)">
            <summary class="findings-summary">
              <span class="findings-summary-left">
                <span class="findings-chevron" aria-hidden="true"></span>
                <span class="findings-summary-title">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                       stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                       style="vertical-align:-2px;margin-right:5px">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                  STIG Assessment
                </span>
              </span>
              <span class="findings-summary-hint">Click to expand</span>
            </summary>
            <div class="findings-body" style="padding:12px 18px 16px">
              <p style="color:var(--text-muted);font-size:13px;margin:0">${noStigMsg}</p>
            </div>
          </details>
        </div>`;
    }

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <a href="#/applications/${encodeURIComponent(scan.target)}"
           onclick="navigate('#/applications/${encodeURIComponent(scan.target)}')">
          ${esc(scan.target)}
        </a>
        <span>›</span>
        <span>${esc(scan.scan_id)}</span>
      </div>

      <div class="page-header">
        <h1>Scan Details ${statusBadge(status)}</h1>
        <div style="display:flex;gap:8px">
          ${repoUrl
            ? `<button class="btn btn-primary"
                 onclick="navigate('#/new-scan?target=${encodeURIComponent(repoUrl)}')">
                 ▶ Run Scan
               </button>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>`}
          ${scan.has_dashboard
            ? `<button class="btn"
                 onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/dashboard','_blank')">
                 View Dashboard ↗
               </button>`
            : ''}
          <a class="btn" href="/api/scans/${encodeURIComponent(scanId)}/download" download
             title="Download all scan artifacts as ZIP for ATO/IATT submission">
            ↓ Download ZIP
          </a>
          <button class="btn btn-danger"
            onclick="deleteScan('${esc(scanId)}', '${esc(scan.target)}')"
            title="Permanently delete this scan">
            Delete Scan
          </button>
        </div>
      </div>

      <div class="detail-grid">
        <div class="detail-card">
          <div class="label">Application</div>
          <div class="value">${esc(scan.target)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Scan Type</div>
          <div class="value">${esc(scanTypeLabel(scan.scan_type))}</div>
        </div>
        <div class="detail-card">
          <div class="label">User</div>
          <div class="value">${esc(scan.user || '—')}</div>
        </div>
        <div class="detail-card">
          <div class="label">Timestamp</div>
          <div class="value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
        </div>
      </div>

      <div class="result-section-box">
        <div class="result-section-box-title">Vulnerabilities</div>
        <div class="detail-grid" style="margin-bottom:0">
          <div class="detail-card">
            <div class="label">Critical</div>
            <div class="value" style="color:var(--critical)">${esc(scan.critical)}</div>
          </div>
          <div class="detail-card">
            <div class="label">High</div>
            <div class="value" style="color:var(--high)">${esc(scan.high)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Medium</div>
            <div class="value" style="color:var(--medium)">${esc(scan.medium)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Low</div>
            <div class="value" style="color:var(--low)">${esc(scan.low)}</div>
          </div>
        </div>
      </div>

      ${buildFindingsSection(scan.findings)}

      ${buildSuppressedSection(scan.suppressed_findings)}

      ${stigCard}

      ${buildModelSecurityCard(scan)}

      ${buildSBOMSection(scan.sbom, scanId)}

      ${buildAPISection(scan.api_discovery)}

      ${buildNetworkDiscoveryCard(scan)}

      ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
        <div class="section">
          <div class="section-title">File Statistics</div>
          <div class="detail-grid">
            ${Object.entries(scan.file_statistics).map(([k, v]) => `
              <div class="detail-card">
                <div class="label">${esc(k.replace(/_/g, ' '))}</div>
                <div class="value">${esc(v)}</div>
              </div>`).join('')}
          </div>
        </div>` : ''}

      <div id="scorecard-container"></div>

      ${dedupeTools(scan.tools_analyzed).length ? `
        <div class="section">
          <div class="section-title">Tools Analyzed</div>
          <div class="tools-list">
            ${dedupeTools(scan.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}`;
    if (window._sbomPendingUid) { sbomRender(window._sbomPendingUid); window._sbomPendingUid = null; }
    if (window._apiPendingUid) { apiRender(window._apiPendingUid); window._apiPendingUid = null; }
    
    // Automatically generate scorecard
    calculateScorecardForScan(scanId);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

function buildPicklescanCard(scan) { return ''; } // merged into buildModelSecurityCard

function buildModelCardCard(scan) { return ''; }  // merged into buildModelSecurityCard

function buildEnrichmentCard(findings) {
  if (!findings) return '';
  const enr = findings.enrichment;
  if (!enr || (enr.cisa_kev_total == null && enr.nvd_total == null)) return '';
  const kevTotal = enr.cisa_kev_total || 0;
  const nvdTotal = enr.nvd_total || 0;
  if (kevTotal === 0 && nvdTotal === 0) return '';

  const hasKev = kevTotal > 0;
  const accentColor = hasKev ? 'var(--critical)' : 'var(--accent,#38bdf8)';

  // Collect all KEV-matched findings across severity buckets for the detail table
  const kevFindings = [];
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    for (const f of (findings[`${sev}_findings`] || [])) {
      if (f.cisa_kev === true) kevFindings.push({ sev, ...f });
    }
  }

  // Format enriched_at timestamp
  let enrichedAt = '';
  if (enr.enriched_at) {
    try {
      enrichedAt = new Date(enr.enriched_at).toLocaleString(undefined,
        { dateStyle: 'medium', timeStyle: 'short' });
    } catch (_) { enrichedAt = enr.enriched_at; }
  }

  const kevTable = ''; // CVSS/KEV now shown inline in the main findings table

  const catalogLink = enr.kev_catalog_url
    ? `<a href="${esc(enr.kev_catalog_url)}" target="_blank" rel="noopener"
         style="font-size:12px;color:var(--accent)">↗ CISA KEV Catalog</a>`
    : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:${accentColor}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                   stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              Threat Intelligence Enrichment
            </span>
            ${hasKev ? `<span style="background:#7f1d1d;color:#fca5a5;border:1px solid #b91c1c;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(nvdTotal)} NVD enriched</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="detail-grid" style="margin-top:12px;margin-bottom:0">
            ${hasKev ? `
            <div class="detail-card" style="border-color:#7f1d1d;background:rgba(127,29,29,0.12)">
              <div class="label" style="color:#fca5a5">CISA KEV Matches</div>
              <div class="value" style="color:#fca5a5">${esc(kevTotal)}</div>
            </div>` : ''}
            <div class="detail-card">
              <div class="label">NVD Enriched CVEs</div>
              <div class="value">${esc(nvdTotal)}</div>
            </div>
            ${enrichedAt ? `
            <div class="detail-card">
              <div class="label">Enriched At</div>
              <div class="value" style="font-size:12px">${enrichedAt}</div>
            </div>` : ''}
          </div>
          ${hasKev ? `
          <p style="color:#fca5a5;font-size:12px;margin:12px 0 4px">
            ⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} match CISA's Known Exploited Vulnerabilities catalog —
            actively exploited in the wild. Findings marked <strong>KEV</strong> above require immediate attention.
          </p>` : ''}
          ${catalogLink ? `<div style="margin-top:8px">${catalogLink}</div>` : ''}
        </div>
      </details>
    </div>`;
}

function buildNetworkDiscoveryCard(scan) {
  const nd = scan.network_discovery;
  if (!nd) return '';
  const scanId = scan.scan_id || scan.id || '';
  _ppsmRegistry.set(scanId, nd);
  const ports    = (nd.unique_ports || []).join(', ') || '—';
  const protos   = (nd.protocols   || []).join(', ') || '—';
  const services = (nd.services    || []).join(', ') || '—';

  // Source breakdown rows
  const sourceRows = [
    { label: 'Docker Compose', items: nd.compose_ports   || [] },
    { label: 'Dockerfile',     items: nd.dockerfile_ports || [] },
    { label: 'Kubernetes/Helm',items: nd.k8s_ports       || [] },
    { label: 'App Config/.env',items: nd.config_ports    || [] },
  ].filter(r => r.items.length > 0);

  const sourceHtml = sourceRows.length ? sourceRows.map((r, idx) => {
    const tblId = `ppsm-tbl-${idx}`;
    return `
    <div style="margin-top:10px">
      <div style="font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px">${esc(r.label)}</div>
      <table id="${tblId}" style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="color:var(--text-muted)">
            <th data-col="0" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',0)">File <span class="sort-icon">⇅</span></th>
            <th data-col="1" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',1)">Service <span class="sort-icon">⇅</span></th>
            <th data-col="2" class="sortable-th" style="text-align:left;padding:2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',2)">Port / Mapping <span class="sort-icon">⇅</span></th>
          </tr>
        </thead>
        <tbody>
          ${r.items.map(p => `
            <tr style="border-top:1px solid var(--border)">
              <td style="padding:3px 8px 3px 0;color:var(--text-muted);font-family:monospace;font-size:11px">${esc(p.file || '')}</td>
              <td style="padding:3px 8px 3px 0">${esc(p.service || '')}</td>
              <td style="padding:3px 0;font-family:monospace">${esc(p.mapping || String(p.port || ''))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  }).join('') : '<p style="color:var(--text-muted);font-size:13px;margin:8px 0 0">No static port definitions found.</p>';

  const activeBadge = nd.active_scan_run
    ? '<span style="background:var(--low-bg,#fffbe6);color:var(--low,#b8860b);border:1px solid var(--low,#b8860b);border-radius:4px;padding:1px 7px;font-size:11px;font-weight:600">nmap active</span>'
    : '<span style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px">static only</span>';

  const portsBadge = nd.total_ports
    ? `<span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(nd.total_ports))} ports</span>`
    : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent,#38bdf8)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">🔌 Network Discovery · PPSM</span>
            ${portsBadge}
            ${activeBadge}
          </span>
          <span class="findings-summary-right" onclick="event.stopPropagation()">
            <button class="btn btn-sm" onclick="downloadPpsmCsv('${esc(scanId)}')" title="Download PPSM as CSV">↓ PPSM</button>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="detail-grid" style="margin-bottom:12px;margin-top:12px">
            <div class="detail-card">
              <div class="label">Ports Found</div>
              <div class="value">${esc(nd.total_ports)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Scan Method</div>
              <div class="value" style="font-size:13px">${activeBadge}</div>
            </div>
            <div class="detail-card" style="grid-column:span 2">
              <div class="label">Unique Ports</div>
              <div class="value" style="font-size:13px;font-family:monospace">${esc(ports)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Protocols</div>
              <div class="value" style="font-size:13px">${esc(protos)}</div>
            </div>
            <div class="detail-card">
              <div class="label">Inferred Services</div>
              <div class="value" style="font-size:13px">${esc(services)}</div>
            </div>
          </div>
          ${sourceHtml}
        </div>
      </details>
    </div>`;
}

function buildModelSecurityCard(scan) {
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  if (!ps && !mc) return '';

  // ── Pickle section ──
  let pickleSection = '';
  if (ps) {
    const statusClass = ps.flagged_count > 0 ? 'status-open' : 'status-clean';
    const statusLabel = ps.flagged_count > 0 ? `${ps.flagged_count} infected file(s)` : 'Clean';
    const icon = ps.flagged_count > 0 ? '🚨' : '✅';
    const totalWeightFiles = ps.total_weight_files ?? ps.file_count ?? 0;

    const RISK_CONFIG = {
      critical: { cls: 'fmt-risk-critical', label: 'CRITICAL' },
      high:     { cls: 'fmt-risk-high',     label: 'HIGH' },
      medium:   { cls: 'fmt-risk-medium',   label: 'MEDIUM' },
      low:      { cls: 'fmt-risk-low',      label: 'LOW' },
      safe:     { cls: 'fmt-risk-safe',     label: 'SAFE' },
    };

    const fmtRows = (ps.weight_formats || []).map(f => {
      const rc = RISK_CONFIG[f.risk] || RISK_CONFIG.medium;
      const pickleWarn = f.pickle_scannable
        ? `<span class="fmt-pickle-flag" title="Scanned by picklescan">🔬</span>`
        : `<span class="fmt-safe-flag" title="No pickle — not code-executable">🛡️</span>`;
      const fileList = (f.files && f.files.length > 0)
        ? `<div class="fmt-file-list">${f.files.map(fp => `<code class="fmt-file-path">${esc(fp)}</code>`).join('')}</div>`
        : '';
      return `
        <div class="fmt-row fmt-row-${f.risk}">
          <code class="fmt-ext">${esc(f.label)}</code>
          <span class="fmt-risk-badge ${rc.cls}">${rc.label}</span>
          ${pickleWarn}
          <span class="fmt-count">${f.count} file${f.count !== 1 ? 's' : ''}</span>
          <span class="fmt-notes">${esc(f.notes)}</span>
          ${fileList}
        </div>`;
    }).join('');

    const psFindings = (ps.findings || []).map(f => `
      <div class="hf-finding-row">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.message || 'Malicious pickle opcode detected')}</span>
      </div>`).join('');

    const psTargetDisplay = ps.target
      ? (() => {
          const parts = ps.target.replace(/\\/g, '/').split('/');
          const short = parts.slice(-3).join('/');
          return `<div class="ms-scan-target" title="${esc(ps.target)}"><span class="ms-scan-target-lbl">Scanned:</span> <code>${esc(short)}</code></div>`;
        })()
      : '';

    pickleSection = `
      <div class="ms-layer">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🥒</span>
            <span>Layer 14 — Pickle / Serialization Safety</span>
            <span class="hf-tool-name">picklescan</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        ${psTargetDisplay}
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${totalWeightFiles}</span><span class="hf-stat-lbl">weight files</span></div>
          <div class="hf-stat"><span class="hf-stat-num">${ps.file_count ?? 0}</span><span class="hf-stat-lbl">pickle-scannable</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${ps.flagged_count > 0 ? 'danger' : ''}">${ps.flagged_count ?? 0}</span><span class="hf-stat-lbl">infected</span></div>
        </div>
        ${fmtRows ? `<div class="fmt-inventory" style="margin:10px -1px -1px">${'<div class="fmt-inventory-title">Weight Format Inventory</div>'}${fmtRows}</div>` : ''}
        ${psFindings ? `<div class="hf-findings" style="margin-top:10px">${psFindings}</div>` : ''}
      </div>`;
  }

  // ── Model card section ──
  let modelCardSection = '';
  if (mc) {
    const statusClass = mc.failed > 0 ? 'status-open' : mc.warnings > 0 ? 'status-warn' : 'status-clean';
    const statusLabel = mc.failed > 0 ? `${mc.failed} check(s) failed` : mc.warnings > 0 ? `${mc.warnings} warning(s)` : 'Compliant';
    const icon = mc.failed > 0 ? '❌' : mc.warnings > 0 ? '⚠️' : '✅';
    const fileLabel = mc.file_checked
      ? `<span class="hf-file-checked" title="${esc(mc.file_checked)}">${esc(mc.file_checked.split('/').pop())}</span>`
      : '';

    const mcFindings = (mc.findings || []).map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'medium',
        id:          f.check || '',
        tool:        'model card',
        title:       f.message || f.check || '—',
        description: f.recommendation || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'medium')}">${esc(f.severity || 'medium')}</span>
        <span class="hf-finding-file">${esc(f.check || '—')}</span>
        <span class="hf-finding-msg">${esc(f.message || '')}${f.recommendation ? `<span class="hf-recommendation"> → ${esc(f.recommendation)}</span>` : ''}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    modelCardSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">📋</span>
            <span>Layer 15 — Model Card Compliance</span>
            ${fileLabel}
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${(mc.passed ?? 0) + (mc.failed ?? 0) + (mc.warnings ?? 0)}</span><span class="hf-stat-lbl">checks</span></div>
          <div class="hf-stat"><span class="hf-stat-num clean">${mc.passed ?? 0}</span><span class="hf-stat-lbl">passed</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${mc.failed > 0 ? 'danger' : ''}">${mc.failed ?? 0}</span><span class="hf-stat-lbl">failed</span></div>
          <div class="hf-stat"><span class="hf-stat-num">${mc.warnings ?? 0}</span><span class="hf-stat-lbl">warnings</span></div>
        </div>
        ${mcFindings ? `<div class="hf-findings" style="margin-top:10px">${mcFindings}</div>` : ''}
      </div>`;
  }

  // ── Combined status for the summary line ──
  const hasIssues = (ps?.flagged_count > 0) || (mc?.failed > 0) || (mc?.warnings > 0);
  const summaryBadgeClass = (ps?.flagged_count > 0 || mc?.failed > 0) ? 'status-open' : mc?.warnings > 0 ? 'status-warn' : 'status-clean';
  const summaryIcon       = (ps?.flagged_count > 0 || mc?.failed > 0) ? '⚠' : '✓';
  const summaryLabel      = hasIssues ? 'Issues found' : 'All clear';

  return `
    <details class="ms-card" id="model-security-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Model Security</span>
          ${ps ? '<span class="tool-tag" style="font-size:11px">picklescan</span>' : ''}
          ${mc ? '<span class="tool-tag" style="font-size:11px">model card</span>' : ''}
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${summaryBadgeClass}">${summaryIcon} ${summaryLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        ${pickleSection}
        ${modelCardSection}
      </div>
    </details>`;
}

// ── Overview AI Summary Section ──────────────────────────────

// Minimal markdown → HTML renderer (no external library)
function renderMarkdown(text) {
  if (!text) return '';
  const safe = t => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const lines = text.split('\n');
  let html = '';
  let inUl = false;
  let inOl = false;
  let inCode = false;
  let codeLines = [];

  function closeList() {
    if (inUl) { html += '</ul>'; inUl = false; }
    if (inOl) { html += '</ol>'; inOl = false; }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Fenced code blocks
    if (/^```/.test(line)) {
      if (!inCode) {
        closeList();
        inCode = true;
        codeLines = [];
      } else {
        html += `<pre><code>${safe(codeLines.join('\n'))}</code></pre>`;
        inCode = false;
        codeLines = [];
      }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      closeList();
      html += '<hr>';
      continue;
    }

    // Headings (### before ## before #)
    if (/^### /.test(line)) {
      closeList();
      html += `<h3>${inlineMarkdown(safe(line.replace(/^### /, '')))}</h3>`;
      continue;
    }
    if (/^## /.test(line)) {
      closeList();
      html += `<h2>${inlineMarkdown(safe(line.replace(/^## /, '')))}</h2>`;
      continue;
    }
    if (/^# /.test(line)) {
      closeList();
      html += `<h2>${inlineMarkdown(safe(line.replace(/^# /, '')))}</h2>`;
      continue;
    }

    // Blockquote
    if (/^> /.test(line)) {
      closeList();
      html += `<blockquote>${inlineMarkdown(safe(line.replace(/^> /, '')))}</blockquote>`;
      continue;
    }

    // Ordered list
    if (/^\d+\. /.test(line)) {
      if (inUl) { html += '</ul>'; inUl = false; }
      if (!inOl) { html += '<ol>'; inOl = true; }
      html += `<li>${inlineMarkdown(safe(line.replace(/^\d+\. /, '')))}</li>`;
      continue;
    }

    // Unordered list
    if (/^[-*] /.test(line)) {
      if (inOl) { html += '</ol>'; inOl = false; }
      if (!inUl) { html += '<ul>'; inUl = true; }
      html += `<li>${inlineMarkdown(safe(line.replace(/^[-*] /, '')))}</li>`;
      continue;
    }

    // Blank line — close any open list
    if (line.trim() === '') {
      closeList();
      continue;
    }

    // Normal paragraph — close list first
    closeList();
    html += `<p>${inlineMarkdown(safe(line))}</p>`;
  }

  closeList();
  if (inCode) html += `<pre><code>${safe(codeLines.join('\n'))}</code></pre>`;
  return html;
}

function inlineMarkdown(s) {
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  return s;
}

function buildOverviewExecSection() {
  return `
    <div class="section" id="overview-exec-section" style="border-left:3px solid #f59e0b;padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#f59e0b"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
        </svg>
        AI Executive Summary
      </div>
      <div id="overview-exec-body">
        <button class="btn btn-primary" onclick="generateOverviewExecSummary()">
          ✦ Generate Executive Summary
        </button>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text-muted)">
          Leadership brief across all tracked applications, split by monitoring status.
          Requires an OpenAI API key configured in Settings.
        </p>
      </div>
    </div>`;
}

function buildOverviewTechSection() {
  return `
    <div class="section" id="overview-tech-section" style="border-left:3px solid #6366f1;padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#6366f1"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
        </svg>
        AI Technical Summary
      </div>
      <div id="overview-tech-body">
        <button class="btn btn-primary" onclick="generateOverviewTechSummary()">
          ✦ Generate Technical Summary
        </button>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text-muted)">
          Detailed technical brief for engineering teams, with per-finding breakdown.
          Requires an OpenAI API key configured in Settings.
        </p>
      </div>
    </div>`;
}

function buildOverviewIssoSection() {
  return `
    <div class="section" id="overview-isso-section" style="border-left:3px solid #10b981;padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        AI ISSO Compliance Brief
      </div>
      <div id="overview-isso-body">
        <button class="btn btn-primary" onclick="generateOverviewIssoSummary()">
          ✦ Generate ISSO Compliance Brief
        </button>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text-muted)">
          ATO/cATO-ready brief covering NIST 800-53 control mapping, STIG validation status,
          evidence traceability, accepted risk, and POA&amp;M risk statements.
          Requires an OpenAI API key configured in Settings.
        </p>
      </div>
    </div>`;
}

// Cache last-generated overview summary text for PDF/Word export
let _overviewSummaryCache = { exec: null, tech: null, isso: null };
// Cache per-app ISSO summaries keyed by app name
const _appIssoCache = {};

function _summaryLoadingHtml(label) {
  return `<div style="display:flex;align-items:center;gap:10px;padding:12px 0;color:var(--text-muted);font-size:13px">
    <div class="spinner" style="width:16px;height:16px;border-width:2px"></div>
    Generating ${label}… this may take 15–30 seconds
  </div>`;
}

function _summaryResultHtml(text, err, regenerateFn, exportFn, exportDocxFn) {
  const content = err
    ? `<div style="color:#ef4444;font-size:12px;padding:8px 0">⚠ ${esc(err)}</div>`
    : `<div style="line-height:1.6">${renderMarkdown(text)}</div>`;
  return `
    ${content}
    <div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" style="font-size:11px" onclick="${regenerateFn.includes('(') ? regenerateFn : regenerateFn + '()'}">↺ Regenerate</button>
      ${text ? `<button class="btn btn-primary" style="font-size:11px" onclick="${exportFn.includes('(') ? exportFn : exportFn + '()'}">↓ Export PDF</button>` : ''}
      ${text && exportDocxFn ? `<button class="btn" style="font-size:11px;background:#1e3a5f;color:#93c5fd;border-color:#1e4976" onclick="${exportDocxFn.includes('(') ? exportDocxFn : exportDocxFn + '()'}">↓ Export Word</button>` : ''}
    </div>`;
}

async function generateOverviewExecSummary() {
  const body = document.getElementById('overview-exec-body');
  if (!body) return;
  body.innerHTML = _summaryLoadingHtml('executive summary');
  try {
    const result = await api.getGlobalExecSummary();
    _overviewSummaryCache.exec = result.summary;
    body.innerHTML = _summaryResultHtml(result.summary, null, 'generateOverviewExecSummary', 'exportExecSummaryPdf', 'exportExecSummaryDocx');
  } catch (e) {
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', 'generateOverviewExecSummary', 'exportExecSummaryPdf', 'exportExecSummaryDocx');
  }
}

async function generateOverviewTechSummary() {
  const body = document.getElementById('overview-tech-body');
  if (!body) return;
  body.innerHTML = _summaryLoadingHtml('technical summary');
  try {
    const result = await api.getGlobalTechnicalSummary();
    _overviewSummaryCache.tech = result.summary;
    body.innerHTML = _summaryResultHtml(result.summary, null, 'generateOverviewTechSummary', 'exportTechSummaryPdf', 'exportTechSummaryDocx');
  } catch (e) {
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', 'generateOverviewTechSummary', 'exportTechSummaryPdf', 'exportTechSummaryDocx');
  }
}

// Keep the old combined function as an alias so any cached references still work
async function generateOverviewSummaries() {
  await Promise.all([generateOverviewExecSummary(), generateOverviewTechSummary()]);
}

async function generateOverviewIssoSummary() {
  const body = document.getElementById('overview-isso-body');
  if (!body) return;
  body.innerHTML = _summaryLoadingHtml('ISSO compliance brief');
  try {
    const result = await api.getGlobalIssoSummary();
    _overviewSummaryCache.isso = result.summary;
    body.innerHTML = _summaryResultHtml(result.summary, null, 'generateOverviewIssoSummary', 'exportIssoSummaryPdf', 'exportIssoSummaryDocx');
  } catch (e) {
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', 'generateOverviewIssoSummary', 'exportIssoSummaryPdf', 'exportIssoSummaryDocx');
  }
}

function exportExecSummaryPdf() {
  exportOverviewSummaryPdf('exec');
}

function exportTechSummaryPdf() {
  exportOverviewSummaryPdf('tech');
}

async function exportSummaryDocx(which) {
  const { exec, tech, isso } = _overviewSummaryCache;
  const body = {
    exec_summary: which === 'exec' ? (exec || null) : null,
    tech_summary: which === 'tech' ? (tech || null) : null,
    isso_summary: which === 'isso' ? (isso || null) : null,
  };
  if (!body.exec_summary && !body.tech_summary && !body.isso_summary) return;
  try {
    const resp = await fetch('/api/export/summary-docx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`Server error ${resp.status}`);
    const blob = await resp.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = resp.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]
                 || 'epyon-security-report.docx';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('Word export failed: ' + e.message);
  }
}

async function exportExecSummaryDocx() { await exportSummaryDocx('exec'); }
async function exportTechSummaryDocx() { await exportSummaryDocx('tech'); }
async function exportIssoSummaryDocx() { await exportSummaryDocx('isso'); }

function exportIssoSummaryPdf() { exportOverviewSummaryPdf('isso'); }

function buildAppIssoSection(name) {
  return `
    <div class="section" id="app-isso-section-${esc(name)}" style="border-left:3px solid #10b981;padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        AI ISSO Compliance Brief — ${esc(name)}
      </div>
      <div id="app-isso-body-${esc(name)}">
        <button class="btn btn-primary" onclick="generateAppIssoSummary('${esc(name)}')">
          ✦ Generate Application ISSO Brief
        </button>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text-muted)">
          Per-application ATO/cATO brief: NIST 800-53 control mapping, STIG open controls,
          evidence traceability, accepted risk register, and POA&amp;M entries.
          Requires an OpenAI API key configured in Settings.
        </p>
      </div>
    </div>`;
}

async function generateAppIssoSummary(name) {
  const bodyId = `app-isso-body-${name}`;
  const body = document.getElementById(bodyId);
  if (!body) return;
  body.innerHTML = _summaryLoadingHtml('ISSO compliance brief');
  try {
    const result = await api.getAppIssoSummary(name);
    const text = result.summary || '';
    _appIssoCache[name] = text;
    body.innerHTML = _summaryResultHtml(
      text, null,
      `generateAppIssoSummary('${name}')`,
      `exportAppIssoSummaryPdf('${name}')`,
      `exportAppIssoSummaryDocx('${name}')`
    );
  } catch (e) {
    _appIssoCache[name] = null;
    body.innerHTML = _summaryResultHtml(
      null, e.message || 'Generation failed',
      `generateAppIssoSummary('${name}')`,
      `exportAppIssoSummaryPdf('${name}')`,
      `exportAppIssoSummaryDocx('${name}')`
    );
  }
}

function exportAppIssoSummaryPdf(name) {
  const text = _appIssoCache[name];
  if (!text) { alert('Generate the ISSO brief first.'); return; }
  const doc = new window.jspdf.jsPDF();
  doc.setFontSize(16);
  doc.text(`ISSO Compliance Brief — ${name}`, 14, 20);
  doc.setFontSize(10);
  const lines = doc.splitTextToSize(text.replace(/#+\s/g, '').replace(/[*_`]/g, ''), 180);
  doc.text(lines, 14, 30);
  doc.save(`isso-brief-${name}.pdf`);
}

async function exportAppIssoSummaryDocx(name) {
  const text = _appIssoCache[name];
  if (!text) { alert('Generate the ISSO brief first.'); return; }
  try {
    const blob = await api.exportSummaryDocx({ isso_summary: text });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: `isso-brief-${name}.docx` });
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (e) {
    alert('Word export failed: ' + e.message);
  }
}

function exportOverviewSummaryPdf(only) {
  const { exec, tech, isso } = _overviewSummaryCache;
  const showExec = !only || only === 'exec';
  const showTech = !only || only === 'tech';
  const showIsso = !only || only === 'isso';
  if (!exec && !tech && !isso) return;

  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  function mdToHtml(text) {
    if (!text) return '<p style="color:#888">Not available.</p>';
    // Reuse inline rendering logic but produce standalone HTML
    const lines = text.split('\n');
    let html = '';
    let inList = false;
    for (const line of lines) {
      if (/^## /.test(line)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3>${line.replace(/^## /, '')}</h3>`;
        continue;
      }
      if (/^# /.test(line)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h2>${line.replace(/^# /, '')}</h2>`;
        continue;
      }
      if (/^[-*] /.test(line)) {
        if (!inList) { html += '<ul>'; inList = true; }
        html += `<li>${pdfInline(line.replace(/^[-*] /, ''))}</li>`;
        continue;
      }
      if (inList && line.trim() !== '') { html += '</ul>'; inList = false; }
      if (line.trim() === '') { if (!inList) html += '<br>'; continue; }
      html += `<p>${pdfInline(line)}</p>`;
    }
    if (inList) html += '</ul>';
    return html;
  }

  function pdfInline(s) {
    s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
    s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    return s;
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Epyon Security Analysis — ${dateStr}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 12pt;
      color: #1a1a1a;
      margin: 0;
      padding: 0;
    }
    .page { padding: 36px 48px; max-width: 900px; margin: 0 auto; }
    .report-header {
      border-bottom: 2px solid #1a1a1a;
      padding-bottom: 16px;
      margin-bottom: 28px;
    }
    .report-title { font-size: 22pt; font-weight: 700; margin: 0 0 4px; }
    .report-meta  { font-size: 10pt; color: #555; margin: 0; }
    .section-heading {
      font-size: 14pt;
      font-weight: 700;
      margin: 28px 0 12px;
      padding: 8px 12px;
      border-radius: 4px;
    }
    .exec-heading  { background: #fff8e8; border-left: 4px solid #f59e0b; color: #92400e; }
    .tech-heading  { background: #eef2ff; border-left: 4px solid #6366f1; color: #3730a3; }
    .isso-heading  { background: #ecfdf5; border-left: 4px solid #10b981; color: #065f46; }
    .section-body  { padding: 0 4px; }
    h2 { font-size: 13pt; margin: 18px 0 6px; }
    h3 { font-size: 11pt; margin: 14px 0 4px; }
    p  { margin: 4px 0 8px; line-height: 1.6; }
    ul { margin: 4px 0 8px 20px; padding: 0; }
    li { margin: 3px 0; line-height: 1.5; }
    code {
      background: #f3f4f6;
      padding: 1px 4px;
      border-radius: 3px;
      font-family: 'SF Mono', Consolas, monospace;
      font-size: 10pt;
    }
    .footer {
      margin-top: 40px;
      padding-top: 12px;
      border-top: 1px solid #ddd;
      font-size: 9pt;
      color: #888;
      text-align: center;
    }
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page { padding: 24px 36px; }
      @page { margin: 18mm 15mm; }
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="report-header">
      <p class="report-title">Epyon Security Analysis</p>
      <p class="report-meta">Generated: ${dateStr} &nbsp;|&nbsp; AI-Assisted Report &nbsp;|&nbsp; Confidential</p>
    </div>

    ${showExec ? `<div class="section-heading exec-heading">📋 Executive Summary</div>
    <div class="section-body">${mdToHtml(exec)}</div>` : ''}

    ${showTech ? `<div class="section-heading tech-heading">🔧 Technical Summary</div>
    <div class="section-body">${mdToHtml(tech)}</div>` : ''}

    ${showIsso ? `<div class="section-heading isso-heading">🔒 ISSO Compliance Brief</div>
    <div class="section-body">${mdToHtml(isso)}</div>` : ''}

    <div class="footer">
      Generated by Epyon Security Scanner &nbsp;·&nbsp; ${dateStr} &nbsp;·&nbsp; AI-assisted — verify findings before acting
    </div>
  </div>
  <script>window.onload = function() { window.print(); };<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) {
    alert('Pop-up blocked — please allow pop-ups for this page and try again.');
    return;
  }
  win.document.write(html);
  win.document.close();
}

function buildSuppressedSection(items) {
  if (!items || items.length === 0) return '';

  const rows = items.map(s => {
    const typeColor = s.type === 'tool' ? '#6366f1' : s.type === 'cve' ? '#f59e0b' : '#6b7280';
    return `<tr>
      <td style="padding:5px 10px;font-size:12px">
        <span class="tool-tag" style="font-size:11px;padding:1px 6px;background:${typeColor}22;color:${typeColor};border:1px solid ${typeColor}44">${esc(s.type || 'unknown')}</span>
      </td>
      <td style="padding:5px 10px;font-family:monospace;font-size:12px;font-weight:600">${esc(s.value || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:#9ca3af">${esc(s.tool || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;max-width:400px">${esc(s.reason || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:#6b7280">${esc(s.approved_by || '—')}</td>
      <td style="padding:5px 10px;font-size:12px">
        ${s.severity && s.severity !== 'N/A'
          ? `<span class="sev-badge sev-${esc(s.severity.toLowerCase())}">${esc(s.severity)}</span>`
          : '<span style="color:#4b5563">—</span>'}
      </td>
    </tr>`;
  }).join('');

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:#f59e0b">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">Suppressed Findings</span>
            <span class="sev-badge" style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44">${items.length}</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body">
          <div style="font-size:12px;color:#6b7280;margin-bottom:10px">Suppressed by <code>.epyon-ignore.yml</code> rules in the scanned repository.</div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value / ID</th>
                  <th>Tool</th>
                  <th>Reason</th>
                  <th>Approved By</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}

function buildSBOMSection(sbom, scanId) {
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
      <details class="findings-collapsible" style="border-left-color:var(--accent,#38bdf8)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">📦 SBOM</span>
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(sbom.total))} packages</span>
            ${typeChips}
          </span>
          <span style="display:flex;align-items:center;gap:10px">
            ${cdxUrl ? `<a class="btn btn-sm" href="${cdxUrl}" download style="font-size:11px" onclick="event.stopPropagation()">↓ CycloneDX JSON</a>` : ''}
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div style="margin-top:12px;display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <input id="${uid}-search" type="text" placeholder="Search packages…"
              style="flex:1;min-width:180px;max-width:320px;padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);font-size:13px"
              oninput="sbomRender('${uid}')" />
            <span id="${uid}-count" style="font-size:12px;color:var(--text-muted)"></span>
            <button onclick="sbomClearFilter('${uid}')" style="font-size:11px;padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','name')">Name <span id="${uid}-sort-name"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','version')">Version <span id="${uid}-sort-version"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','type')">Type <span id="${uid}-sort-type"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','license')">License <span id="${uid}-sort-license"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="sbomSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
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
      <td style="padding:3px 8px"><span class="tool-tag" style="font-size:11px;padding:1px 6px">${esc(p.type)}</span></td>
      <td style="font-size:11px;color:#888;padding:3px 8px">${esc(p.license)}</td>
      <td style="font-family:monospace;font-size:11px;color:#6b7280;padding:3px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">${esc(p.path)}</td>
    </tr>`;
  }).join('');
};

function _buildFindingRows(items) {
  return items.map(f => {
    const fid    = _registerFinding(f);
    const id     = esc(f.id    || f.cve_id || '—');
    const tool   = esc(f.tool  || '—');
    const pkg    = esc(f.package || f.component || f.target || '—');
    const ver    = esc(f.version || '');
    const fixed  = esc(f.fixed_version || '');
    const title  = esc((f.title || f.description || f.check_name || '').substring(0, 160));
    const target = esc((f.target || '').substring(0, 80));

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
        ? `<span style="background:#7f1d1d;color:#fca5a5;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;vertical-align:middle;margin-left:${cvssNum != null ? 4 : 0}px" title="CISA Known Exploited Vulnerability">KEV</span>`
        : ''
    ].join('') || '<span style="color:var(--text-dim)">—</span>';

    return `
      <tr class="finding-row" onclick="openFindingDetail(${fid})" title="Click to view details">
        <td>
          <span class="tool-tag">${tool}</span>
          <div style="margin-top:3px">${findingSourceBadge(f)}</div>
        </td>
        <td>${idCell}</td>
        <td style="max-width:360px">${title}</td>
        <td>${pkg}${ver ? ` <span style="color:var(--text-dim);font-size:11px">${ver}</span>` : ''}</td>
        <td style="white-space:nowrap">${cvssCell}</td>
        <td>${fixed ? `<span style="color:var(--clean)">${fixed}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
        <td style="color:var(--text-muted);font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${target}">${target || '—'}</td>
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

  const items = [...(_currentFindingsBySev[sev] || [])];
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

  const tbody = document.getElementById(`findings-tbody-${sev}`);
  if (tbody) tbody.innerHTML = _buildFindingRows(items);

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

function buildAPISection(apiData) {
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
      <details class="findings-collapsible" style="border-left-color:#10b981">
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
            <button onclick="apiClearFilter('${uid}')" style="font-size:11px;padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer">Clear filters</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="text-align:left;border-bottom:1px solid var(--border)">
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','method')">Method <span id="${uid}-sort-method"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','path')">Path <span id="${uid}-sort-path"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','function')">Function <span id="${uid}-sort-function"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','framework')">Framework <span id="${uid}-sort-framework"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none" onclick="apiSort('${uid}','auth')">Auth <span id="${uid}-sort-auth"></span></th>
                  <th style="padding:4px 8px;cursor:pointer;user-select:none;white-space:nowrap" onclick="apiSort('${uid}','file')">File <span id="${uid}-sort-file"></span></th>
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
        <td style="padding:4px 8px"><span style="background:${methodColor};color:white;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:600">${esc(ep.method)}</span></td>
        <td style="padding:4px 8px;font-family:monospace;font-size:12px">${esc(ep.path)}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:12px">${esc(ep.function) || '—'}</td>
        <td style="padding:4px 8px"><span class="tool-tag">${esc(ep.framework) || '—'}</span></td>
        <td style="padding:4px 8px;color:var(--text-dim);font-size:11px">${esc(ep.auth) || '—'}</td>
        <td style="padding:4px 8px;color:var(--text-muted);font-size:11px" title="${esc(ep.file)}">${esc(shortFile) || '—'}</td>
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

function buildFindingsSection(findings) {
  const severities = ['critical', 'high', 'medium', 'low'];
  let html = '';
  let anyFindings = false;

  // Reset sort state for this render
  for (const sev of severities) {
    _currentFindingsBySev[sev] = [];
    _sortState[sev] = { col: null, dir: 'asc' };
  }

  for (const sev of severities) {
    const allItems = findings[`${sev}_findings`] || [];
    if (!allItems.length) continue;
    anyFindings = true;

    const items = allItems.slice(0, 200);
    _currentFindingsBySev[sev] = items;

    const overflow = allItems.length > 200
      ? `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:12px">
           … and ${allItems.length - 200} more. Open the Dashboard for the full list.
         </td></tr>` : '';

    html += `
      <details class="findings-collapsible findings-${esc(sev)}" id="findings-section-${esc(sev)}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">${ucFirst(sev)} Findings</span>
            <span class="sev-badge ${esc(sev)}">${allItems.length}</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body">
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th class="sortable-th" data-col="tool"    onclick="sortFindingsBy('${sev}','tool')">Tool <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="id"      onclick="sortFindingsBy('${sev}','id')">CVE / ID <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="title"   onclick="sortFindingsBy('${sev}','title')">Title <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="package" onclick="sortFindingsBy('${sev}','package')">Package <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="cvss"    onclick="sortFindingsBy('${sev}','cvss')" style="white-space:nowrap">CVSS / KEV <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="fix"     onclick="sortFindingsBy('${sev}','fix')">Fix Available <span class="sort-icon">⇅</span></th>
                  <th class="sortable-th" data-col="target"  onclick="sortFindingsBy('${sev}','target')">Location <span class="sort-icon">⇅</span></th>
                </tr>
              </thead>
              <tbody id="findings-tbody-${esc(sev)}">${_buildFindingRows(items)}${overflow}</tbody>
            </table>
          </div>
        </div>
      </details>`;
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
           style="color:var(--accent);font-size:11px">↗ CISA KEV Catalog</a>`
      : '';
    enrichmentBanner = `
      <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px;font-size:12px;color:var(--text-muted)">
        ${kevTotal > 0 ? `<span style="background:#7f1d1d;color:#fca5a5;border:1px solid #b91c1c;border-radius:4px;padding:1px 8px;font-size:11px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
        ${nvdTotal > 0 ? `<span style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:1px 8px;font-size:11px">${esc(nvdTotal)} NVD enriched</span>` : ''}
        ${enrichedAt ? `<span style="font-size:11px;color:var(--text-dim)">enriched ${enrichedAt}</span>` : ''}
        ${catalogLink}
        ${kevTotal > 0 ? `<span style="color:#fca5a5;font-size:11px">⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} actively exploited in the wild — see <strong>KEV</strong> badges below</span>` : ''}
      </div>`;
  }

  if (!anyFindings) {
    return `
      <div class="section">
        <div class="section-title">Findings</div>
        ${enrichmentBanner}
        <span class="sev-badge clean" style="padding:8px 16px">✓ No findings detected</span>
      </div>`;
  }

  return `
    <div class="section findings-section-wrapper">
      <div class="section-title">Findings</div>
      ${enrichmentBanner}
      ${html}
    </div>`;
}

// ─────────────────────────────────────────────────────────────
// STIG page — shows all apps with their latest STIG scan status

async function renderStig() {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const apps = await api.getApplications();
    const stigApps = apps.filter(a => (a.stig_total || 0) > 0);

    const cards = stigApps.length
      ? stigApps.map(app => {
          const stigScanId = app.latest_stig_scan_id || app.latest_scan_id;
          const mdUrl   = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-md`;
          const cklbUrl = `/api/scans/${encodeURIComponent(stigScanId)}/stig-findings-cklb`;
          const mdBtn   = app.has_stig_report
            ? `<a class="btn btn-sm" href="${esc(mdUrl)}" download>↓ findings.md</a>` : '';
          const cklbBtn = app.has_stig_cklb
            ? `<a class="btn btn-sm" href="${esc(cklbUrl)}" download>↓ findings.cklb</a>` : '';
          return `
            <div class="stig-app-card" onclick="navigate('#/scans/${encodeURIComponent(stigScanId)}')" style="cursor:pointer">
              <div class="stig-app-card-header">
                <span class="stig-app-name">
                  ${esc(app.name)}
                </span>
                <div class="stig-download-btns" onclick="event.stopPropagation()">${mdBtn}${cklbBtn}</div>
              </div>
              <div class="stig-counts">
                <div class="stig-count open">
                  <span class="num">${esc(app.stig_open || 0)}</span>
                  <span class="lbl">Open</span>
                </div>
                <div class="stig-count pass">
                  <span class="num">${esc(app.stig_pass || 0)}</span>
                  <span class="lbl">Not a Finding</span>
                </div>
                <div class="stig-count na">
                  <span class="num">${esc(app.stig_na || 0)}</span>
                  <span class="lbl">Not Applicable</span>
                </div>
                ${(app.stig_nr || 0) > 0 ? `
                <div class="stig-count" style="background:var(--bg-input);border-color:var(--border)">
                  <span class="num" style="color:var(--text-muted)">${esc(app.stig_nr || 0)}</span>
                  <span class="lbl">Not Reviewed</span>
                </div>` : ''}
                <div class="stig-count total">
                  <span class="num">${esc(app.stig_total || 0)}</span>
                  <span class="lbl">Total</span>
                </div>
              </div>
              <div style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap" onclick="event.stopPropagation()">
                <span style="font-size:12px;color:var(--text-muted)">Last scanned: ${fmtDate(app.last_scanned)}</span>
                <button class="btn btn-primary btn-sm"
                  onclick="navigate('#/stig-viewer/${encodeURIComponent(stigScanId)}')">
                  ⊞ View Findings
                </button>
                <button class="btn btn-sm"
                  onclick="navigate('#/scans/${encodeURIComponent(stigScanId)}')">
                  Scan Details →
                </button>
              </div>
            </div>`;
        }).join('')
      : emptyState(
          'No STIG results yet',
          'STIG scans run automatically every Sunday night. You can also trigger one manually using Run Scan → STIG.',
          `<button class="btn btn-primary" onclick="navigate('#/new-scan')" style="margin-top:16px">
             ▶ Run STIG Scan
           </button>`,
        );

    // Aggregate totals
    const totOpen  = stigApps.reduce((s, a) => s + (a.stig_open  || 0), 0);
    const totPass  = stigApps.reduce((s, a) => s + (a.stig_pass  || 0), 0);
    const totNa    = stigApps.reduce((s, a) => s + (a.stig_na    || 0), 0);
    const totTotal = stigApps.reduce((s, a) => s + (a.stig_total || 0), 0);

    const summaryBar = stigApps.length ? `
      <div class="stats-grid" style="margin-bottom:24px">
        <div class="stat-card">
          <div class="stat-value">${esc(stigApps.length)}</div>
          <div class="stat-label">Apps with STIG data</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-open)">
          <div class="stat-value" style="color:var(--stig-open)">${esc(totOpen)}</div>
          <div class="stat-label">Total Open</div>
        </div>
        <div class="stat-card" style="border-left:3px solid var(--stig-pass)">
          <div class="stat-value" style="color:var(--stig-pass)">${esc(totPass)}</div>
          <div class="stat-label">Total Passing</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${esc(totNa)}</div>
          <div class="stat-label">N/A</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--accent)">${esc(totTotal)}</div>
          <div class="stat-label">Total Controls</div>
        </div>
      </div>` : '';

    const stigTabs = `
      <div class="stig-tabs">
        <button class="stig-tab active" onclick="navigate('#/stig')">Overview</button>
        <button class="stig-tab" onclick="navigate('#/stig?view=history')">History &amp; MTTR</button>
      </div>`;

    page.innerHTML = `
      <div class="page-header">
        <h1>STIG Compliance</h1>
        <button class="btn btn-primary"
          onclick="navigate('#/new-scan')">▶ Run STIG Scan</button>
      </div>
      ${stigTabs}
      <p class="section-desc">
        Application Security Developer (AppSecDev) STIG and Crunchy Data PostgreSQL STIG
        compliance results. Scans run every Sunday night automatically.
      </p>
      ${summaryBar}
      <div class="section">
        <div class="section-title">Applications</div>
        ${cards}
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

let _pollInterval = null;
let _lastLogLen   = 0;
let _activeJobId  = null;

async function renderNewScan(prefill = '') {
  setActive('new-scan');
  clearInterval(_pollInterval);
  _pollInterval = null;
  _lastLogLen   = 0;

  const page = document.getElementById('page');
  page.innerHTML = `
    <div class="page-header">
      <h1>Run New Scan</h1>
    </div>
    <p class="section-desc">
      Launch a security scan against a local directory or Git repository.
      Epyon orchestrates all applicable security layers based on the selected scan type.
    </p>

    <div class="scan-page-layout">
      <div class="form-card scan-form-col">
        <div class="form-group" id="std-target-field">
          <label for="scan-target">Target</label>
          <input type="text" id="scan-target" autocomplete="off" spellcheck="false"
            placeholder="/absolute/path/to/project  or  https://github.com/org/repo.git"
            value="${esc(prefill)}" />
          <small>Absolute local directory path, relative path, or Git repository URL (HTTPS/SSH)</small>
        </div>

        <div class="form-group">
          <label for="scan-type-sel">Scan Type</label>
          <select id="scan-type-sel" onchange="updateScanInfo(this.value); _onScanTypeChange(this.value)">
            <option value="full">Full — All security layers (recommended)</option>
            <option value="quick">Quick — Fast check: Trivy, TruffleHog, SBOM</option>
            <option value="nightly">Nightly — Scheduled comprehensive scan (layers 1–12)</option>
            <option value="baseline">Baseline — Establish initial security benchmark (all layers)</option>
            <option value="stig">STIG — STIG compliance assessment only (on demand)</option>
            <option value="local_model">Local Model — Scan model weights in a local directory (layers 14–15)</option>
          </select>
        </div>

        <div class="form-group" id="garak-checkbox-row">
          <label>Garak LLM Scan (Layer 12)</label>
          <div class="seg-ctrl" id="garak-ctrl">
            <button type="button" class="seg-btn active" data-value="off"
              onclick="_setGarak('off')">Off</button>
            <button type="button" class="seg-btn" data-value="on"
              onclick="_setGarak('on')">On</button>
          </div>
          <small>Requires <code>OPENAI_API_KEY</code> to be set.</small>
        </div>

        <div class="form-group" id="stig-checkbox-row">
          <label>STIG Compliance (Layer 13)</label>
          <div class="seg-ctrl" id="stig-ctrl">
            <button type="button" class="seg-btn active" data-value="off"
              onclick="_setStig('off')">Off</button>
            <button type="button" class="seg-btn" data-value="on"
              onclick="_setStig('on')">On</button>
          </div>
          <small>Requires <code>OPENAI_API_KEY</code> to be set.</small>
        </div>

        <div class="form-group">
          <label>Monitoring Type</label>
          <div class="seg-ctrl" id="monitoring-type-ctrl">
            <button type="button" class="seg-btn active" data-value="evaluation"
              onclick="_setMonitoringType('evaluation')">
              &#9675; Evaluation
            </button>
            <button type="button" class="seg-btn" data-value="continuous"
              onclick="_setMonitoringType('continuous')">
              &#9679; Continuous
            </button>
          </div>
          <small>Continuous apps are tracked in Metrics. Evaluation apps are excluded.</small>
        </div>

        <button id="run-btn" class="btn btn-primary" onclick="submitScan()">
          ▶ Run Scan
        </button>
      </div>

      <div class="scan-info-panel" id="scan-info-panel"></div>
    </div>

    <div id="scan-output" style="display:none">
      <div style="margin-top:28px;margin-bottom:12px;display:flex;align-items:center;gap:12px">
        <div id="job-status-bar"></div>
        <button id="cancel-btn" class="btn btn-sm" style="display:none"
                onclick="cancelScan()">✕ Cancel</button>
      </div>
      <div class="log-card" id="log-output"></div>
      <div id="scan-actions" style="display:none;gap:10px;margin-top:16px"></div>
    </div>`;

  updateScanInfo('full');
}

const _SCAN_MODE_INFO = {
  full: {
    label: 'Full Scan',
    desc: 'Comprehensive security assessment running all available layers. Recommended for thorough coverage.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 13, name: 'STIG Compliance',         tool: 'GPT-4.1-mini', apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
      { n: 16, name: 'Network Discovery',        tool: 'nmap + Static' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layer 13 (STIG) requires OPENAI_API_KEY. Runs unless SKIP_STIG=true.', 'Layer 16 active nmap scan is opt-in: set NMAP_TARGET=<host>.'],
  },
  nightly: {
    label: 'Nightly Scan',
    desc: 'Identical to Full. Designed for scheduled overnight runs — all 16 layers including STIG.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 13, name: 'STIG Compliance',         tool: 'GPT-4.1-mini', apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
      { n: 16, name: 'Network Discovery',        tool: 'nmap + Static' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layer 13 (STIG) requires OPENAI_API_KEY. Runs unless SKIP_STIG=true.', 'Layer 16 active nmap scan is opt-in: set NMAP_TARGET=<host>.'],
  },
  quick: {
    label: 'Quick Scan',
    desc: 'Fast security check for rapid feedback. Skips heavier analysis tools to minimize runtime.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
    ],
    notes: ['Skips: SonarQube, ClamAV, Checkov, Anchore, Garak, STIG.'],
  },
  stig: {
    label: 'STIG Scan',
    desc: 'STIG compliance assessment only (Layer 13). All other layers are skipped.',
    layers: [
      { n: 13, name: 'STIG Compliance',         tool: 'GPT-4.1-mini', apiKey: true },
    ],
    notes: [],
  },
  baseline: {
    label: 'Baseline Scan',
    desc: 'Establishes an initial security benchmark for a repository. Runs all layers — use this for a first-time scan before enabling nightly runs.',
    layers: [
      { n: 1,  name: 'SBOM Generation',        tool: 'Syft' },
      { n: 2,  name: 'Secret Detection',        tool: 'TruffleHog' },
      { n: 3,  name: 'Code Quality',            tool: 'SonarQube' },
      { n: 4,  name: 'Malware Detection',       tool: 'ClamAV' },
      { n: 5,  name: 'Helm Chart Build',        tool: 'Helm' },
      { n: 6,  name: 'Infrastructure Security', tool: 'Checkov' },
      { n: 7,  name: 'Container Security',      tool: 'Trivy' },
      { n: 8,  name: 'Vulnerability Detection', tool: 'Grype' },
      { n: 9,  name: 'End-of-Life Detection',   tool: 'Xeol' },
      { n: 10, name: 'Anchore Security',        tool: 'Anchore' },
      { n: 11, name: 'API Discovery',           tool: 'Custom' },
      { n: 12, name: 'LLM Security',            tool: 'Garak',      apiKey: true, optional: true },
      { n: 13, name: 'STIG Compliance',         tool: 'GPT-4.1-mini', apiKey: true, optional: true },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',    tool: 'modelcard' },
      { n: 16, name: 'Network Discovery',        tool: 'nmap + Static' },
    ],
    notes: ['Layer 12 (Garak) is opt-in. Set RUN_GARAK=true to enable.', 'Layer 13 (STIG) requires OPENAI_API_KEY. Runs unless SKIP_STIG=true.', 'Layer 16 active nmap scan is opt-in: set NMAP_TARGET=<host>.'],
  },
  local_model: {
    label: 'Local Model Scan',
    desc: 'Scan a local directory containing AI/ML model weight files. Inventories all weight formats, checks for malicious pickle opcodes, and validates model card compliance. No git clone needed.',
    layers: [
      { n: 4,  name: 'Malware Detection (ClamAV)',    tool: 'ClamAV' },
      { n: 14, name: 'Pickle / Serialization Safety', tool: 'picklescan' },
      { n: 15, name: 'Model Card Compliance',         tool: 'modelcard' },
    ],
    notes: [
      'Point at the directory where model weights live (e.g. /opt/models/llama3).',
      'Detects .pkl, .pt, .bin, .ckpt and other risky formats.',
      'Reports safe alternatives: .safetensors, .onnx, .gguf.',
    ],
  },
};

function _onScanTypeChange(mode) {
  const inp = document.getElementById('scan-target');
  if (inp && !inp.value) {
    inp.placeholder = mode === 'local_model'
      ? '/absolute/path/to/models  (e.g. /opt/models/llama3)'
      : '/absolute/path/to/project  or  https://github.com/org/repo.git';
  }
  // Show Garak / STIG toggles only for modes where those layers apply
  const optInModes = ['full', 'nightly', 'baseline'];
  const garakRow = document.getElementById('garak-checkbox-row');
  if (garakRow) garakRow.style.display = optInModes.includes(mode) ? '' : 'none';
  const stigRow = document.getElementById('stig-checkbox-row');
  if (stigRow) stigRow.style.display = optInModes.includes(mode) ? '' : 'none';
}

window.updateScanInfo = (mode) => {
  const panel = document.getElementById('scan-info-panel');
  if (!panel) return;
  const info = _SCAN_MODE_INFO[mode];
  if (!info) { panel.innerHTML = ''; return; }

  const hasApiKey = info.layers.some(l => l.apiKey);
  const layerRows = info.layers.map(l => {
    const badge = l.apiKey
      ? `<span class="scan-info-key-badge" title="Requires OpenAI API key">API key</span>`
      : '';
    const optBadge = l.optional
      ? `<span class="scan-info-opt-badge">opt-in</span>`
      : '';
    return `
      <div class="scan-info-layer">
        <span class="scan-info-layer-num">${l.n}</span>
        <span class="scan-info-layer-name">${esc(l.name)}</span>
        <span class="scan-info-layer-tool">${esc(l.tool)}</span>
        <span class="scan-info-badges">${badge}${optBadge}</span>
      </div>`;
  }).join('');

  const apiKeyNotice = hasApiKey ? `
    <div class="scan-info-apikey-notice">
      <span class="scan-info-notice-icon">🔑</span>
      <span><strong>OpenAI API key required</strong> for Garak and STIG layers.
      Set the <code>OPENAI_API_KEY</code> environment variable before running.</span>
    </div>` : '';

  const notesHtml = info.notes.length
    ? info.notes.map(n => `<div class="scan-info-note">ℹ ${esc(n)}</div>`).join('')
    : '';

  panel.innerHTML = `
    <div class="scan-info-header">
      <div class="scan-info-title">${esc(info.label)}</div>
      <div class="scan-info-desc">${esc(info.desc)}</div>
    </div>
    <div class="scan-info-layers-label">Layers included</div>
    <div class="scan-info-layers">${layerRows}</div>
    ${notesHtml}
    ${apiKeyNotice}`;
};

function _setGarak(value) {
  document.querySelectorAll('#garak-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

function _setStig(value) {
  document.querySelectorAll('#stig-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

function _setMonitoringType(value) {
  document.querySelectorAll('#monitoring-type-ctrl .seg-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === value);
  });
}

async function submitScan() {
  const scanType  = document.getElementById('scan-type-sel').value;
  const activeGarak = document.querySelector('#garak-ctrl .seg-btn.active');
  const runGarak  = activeGarak?.dataset.value === 'on';
  const activeStig = document.querySelector('#stig-ctrl .seg-btn.active');
  const runStig   = activeStig ? activeStig.dataset.value === 'on' : false;
  const btn       = document.getElementById('run-btn');

  const target = (document.getElementById('scan-target')?.value || '').trim();
  if (!target) {
    document.getElementById('scan-target').focus();
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Starting…';

  document.getElementById('scan-output').style.display = 'block';
  document.getElementById('log-output').innerHTML = '';
  document.getElementById('scan-actions').style.display = 'none';
  _lastLogLen  = 0;
  _activeJobId = null;

  try {
    const job = await api.triggerScan(target, scanType, runGarak, runStig);
    _activeJobId = job.job_id;
    clearInterval(_pollInterval);
    _pollInterval = setInterval(() => pollJob(job.job_id, btn), 2000);
    pollJob(job.job_id, btn);
    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
  } catch (e) {
    btn.disabled    = false;
    btn.textContent = '▶ Run Scan';
    document.getElementById('log-output').innerHTML =
      `<div class="log-line err">Error: ${esc(e.message)}</div>`;
  }
}

async function pollJob(jobId, btn) {
  try {
    const job = await api.getJob(jobId);

    const statusBar = document.getElementById('job-status-bar');
    const logOut    = document.getElementById('log-output');
    if (!statusBar || !logOut) { clearInterval(_pollInterval); return; }

    statusBar.innerHTML =
      `<span class="job-status ${esc(job.status)}">${ucFirst(job.status)}</span>
       <span style="color:var(--text-muted);font-size:12px">
         — ${esc(job.target)} (${esc(job.scan_type)})
       </span>`;

    const lines = job.output || [];
    if (lines.length > _lastLogLen) {
      const frag = lines.slice(_lastLogLen)
        .map(l => `<div class="log-line">${esc(l)}</div>`)
        .join('');
      logOut.insertAdjacentHTML('beforeend', frag);
      logOut.scrollTop = logOut.scrollHeight;
      _lastLogLen = lines.length;
    }

    if (['completed', 'failed', 'error', 'cancelled'].includes(job.status)) {
      clearInterval(_pollInterval);
      _pollInterval = null;
      _activeJobId  = null;
      if (btn) { btn.disabled = false; btn.textContent = '▶ Run Scan'; }

      // Apply monitoring classification on successful completion
      if (job.status === 'completed' && job.target) {
        const activeBtn = document.querySelector('#monitoring-type-ctrl .seg-btn.active');
        if (activeBtn?.dataset.value === 'continuous') {
          try { await api.setMonitored(job.target); } catch (_) {}
        } else {
          try { await api.unsetMonitored(job.target); } catch (_) {}
        }
      }

      const cancelBtn = document.getElementById('cancel-btn');
      if (cancelBtn) cancelBtn.style.display = 'none';

      const actionsDiv = document.getElementById('scan-actions');
      if (actionsDiv) {
        actionsDiv.style.display = 'flex';
        actionsDiv.innerHTML = job.status === 'completed'
          ? `<button class="btn btn-primary" onclick="navigate('#/applications')">
               View Applications
             </button>
             <button class="btn" onclick="navigate('#/new-scan')">Run Another Scan</button>`
          : `<div class="error-banner" style="margin:0">
               Scan ${
                 job.status === 'cancelled'
                   ? 'was cancelled'
                   : job.status === 'failed'
                   ? 'failed (non-zero exit code)'
                   : 'encountered an error'
               }.
               ${job.status !== 'cancelled' ? 'Check the log output above.' : ''}
             </div>
             <button class="btn" onclick="navigate('#/new-scan')">Run Another Scan</button>`;
      }
    }
  } catch (_) { /* ignore transient polling errors */ }
}

// ─────────────────────────────────────────────────────────────

async function cancelScan() {
  if (!_activeJobId) return;
  const btn = document.getElementById('cancel-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Cancelling…'; }
  try {
    await fetch(`/api/jobs/${encodeURIComponent(_activeJobId)}/cancel`, { method: 'POST' });
  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────

function toggleSection(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('collapsed');
}

// Sort state for PPSM port tables: { [tableId]: { col: int, dir: 'asc'|'desc' } }
const _ppsmSortState = {};

// PPSM download registry: scanId -> network_discovery object
const _ppsmRegistry = new Map();

window.downloadPpsmCsv = function(scanId) {
  const nd = _ppsmRegistry.get(scanId);
  if (!nd) return;
  const sources = [
    { label: 'Docker Compose', items: nd.compose_ports   || [] },
    { label: 'Dockerfile',     items: nd.dockerfile_ports || [] },
    { label: 'Kubernetes/Helm',items: nd.k8s_ports       || [] },
    { label: 'App Config/.env',items: nd.config_ports    || [] },
  ];
  const rows = [['Source','File','Service','Port/Mapping','Protocol']];
  for (const src of sources) {
    for (const p of src.items) {
      rows.push([
        src.label,
        p.file    || '',
        p.service || '',
        p.mapping || String(p.port || ''),
        (nd.protocols || []).join(';'),
      ]);
    }
  }
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), {
    href: url,
    download: `ppsm-${scanId}.csv`,
  });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
};

window.sortPpsmTable = function(tableId, col) {
  const tbl = document.getElementById(tableId);
  if (!tbl) return;
  const tbody = tbl.querySelector('tbody');
  if (!tbody) return;

  const st = _ppsmSortState[tableId] || { col: -1, dir: 'asc' };
  const dir = (st.col === col && st.dir === 'asc') ? 'desc' : 'asc';
  _ppsmSortState[tableId] = { col, dir };

  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const av = (a.cells[col] ? a.cells[col].textContent : '').trim().toLowerCase();
    const bv = (b.cells[col] ? b.cells[col].textContent : '').trim().toLowerCase();
    // Numeric sort for port column (col 2)
    if (col === 2) {
      const an = parseInt(av, 10), bn = parseInt(bv, 10);
      if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
    }
    return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(r => tbody.appendChild(r));

  // Update sort indicators
  tbl.querySelectorAll('th[data-col]').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (!icon) return;
    if (parseInt(th.dataset.col, 10) === col) {
      icon.textContent = dir === 'asc' ? '↑' : '↓';
    } else {
      icon.textContent = '⇅';
    }
  });
};

const _SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

window.sortEnrichmentTable = function(col) {
  const items = window._enrichmentFindings;
  if (!items || !items.length) return;
  const st = window._enrichmentSortState || { col: null, dir: 'asc' };
  const dir = (st.col === col && st.dir === 'asc') ? 'desc' : 'asc';
  window._enrichmentSortState = { col, dir };
  const d = dir === 'asc' ? 1 : -1;

  items.sort((a, b) => {
    switch (col) {
      case 'sev':     return d * ((_SEV_ORDER[a.sev] ?? 4) - (_SEV_ORDER[b.sev] ?? 4));
      case 'id':      return d * (a.id || '').localeCompare(b.id || '');
      case 'package': return d * ((a.package || '').localeCompare(b.package || ''));
      case 'score': {
        const as = a.nvd_cvss_v3_score ?? -1, bs = b.nvd_cvss_v3_score ?? -1;
        return d * (as - bs);
      }
      default: return 0;
    }
  });

  const tbody = document.getElementById('enrichment-nvd-tbody');
  const tbl   = document.getElementById('enrichment-nvd-table');
  if (!tbody) return;

  // Re-render rows (reuse the same registered IDs)
  tbody.innerHTML = items.map(f => {
    const id  = esc(f.id || f.cve_id || '—');
    const pkg = esc((f.package || f.component || '—') + (f.version ? ` ${f.version}` : ''));
    const score = f.nvd_cvss_v3_score != null ? esc(String(f.nvd_cvss_v3_score)) : '—';
    const scoreColor = score !== '—'
      ? (parseFloat(score) >= 9 ? 'var(--critical)' : parseFloat(score) >= 7 ? 'var(--high)' : parseFloat(score) >= 4 ? 'var(--medium)' : 'var(--low)')
      : 'var(--text-muted)';
    const kevBadge = f.cisa_kev
      ? `<span style="background:#7f1d1d;color:#fca5a5;font-size:9px;font-weight:700;padding:1px 4px;border-radius:3px;vertical-align:middle;margin-left:4px">KEV</span>`
      : '';
    const fixed = f.fixed_version ? `<span style="color:var(--clean);font-size:11px">→ ${esc(f.fixed_version)}</span>` : '';
    return `
      <tr class="finding-row" onclick="openFindingDetail(${f._rid})" title="Click to view details">
        <td style="padding:5px 8px 5px 0"><span class="sev-badge sev-${esc(f.sev)}" style="font-size:10px">${esc(f.sev)}</span></td>
        <td style="padding:5px 8px 5px 0;font-family:monospace;font-size:12px;white-space:nowrap"><code>${id}</code>${kevBadge}</td>
        <td style="padding:5px 8px 5px 0;font-size:12px;color:var(--text-muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${pkg}</td>
        <td style="padding:5px 8px 5px 0;font-size:12px;font-weight:600;color:${scoreColor}">${score}</td>
        <td style="padding:5px 0;font-size:11px;color:var(--text-muted)">${fixed}</td>
      </tr>`;
  }).join('');

  if (tbl) tbl.querySelectorAll('th[data-col]').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.textContent = th.dataset.col === col ? (dir === 'asc' ? '↑' : '↓') : '⇅';
  });
};

// ── New metrics section builders ─────────────────────────────

// ── SLA detail registry ─────────────────────────────────────
let _slaDetailData = null;

function openSlaDetail() {
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
          <thead><tr><th>Severity</th><th>SLA</th><th style="min-width:140px">Compliance</th><th>Rate</th><th>Met / Total</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:14px;font-size:12px;color:var(--text-muted)">
        ${sla.total_within ?? 0} within SLA · ${sla.total_breached ?? 0} exceeded SLA
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
}

// ── Risk trend registry ───────────────────────────────────────
const _riskTrendRegistry = new Map();

function openRiskTrendDetail(app) {
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
      <td><span class="sev-badge critical" style="font-size:10px">${esc(String(p.critical ?? '—'))}</span></td>
      <td><span class="sev-badge high" style="font-size:10px">${esc(String(p.high ?? '—'))}</span></td>
      <td><span class="sev-badge medium" style="font-size:10px">${esc(String(p.medium ?? '—'))}</span></td>
      <td><span class="sev-badge low" style="font-size:10px">${esc(String(p.low ?? '—'))}</span></td>
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
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px">Score over time (critical×10 + high×7 + medium×4 + low×1)</div>
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
          <thead><tr><th>Date</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
          <tbody>${tableRows}</tbody>
        </table>
      </div>
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
}

function buildRiskTrendSection(m) {
  const trend = m.risk_trend || [];
  if (!trend.length) {
    return `<div class="section collapsible-section collapsed" id="section-risk">
      <div class="section-title section-toggle" onclick="toggleSection('section-risk')">
        Weighted Risk Score Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body"><p class="metrics-note" style="color:var(--text-muted)">No trend data yet.</p></div>
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
      <td style="color:var(--text-muted);font-size:11px">${esc(latest.date)}</td>
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
        <table><thead><tr><th>Application</th><th>Latest Score</th><th>Date</th><th>Trend</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

function buildSecretTrendSection(m) {
  const byTarget = m.secret_trend_by_target || {};
  const hasData = Object.values(byTarget).some(pts => pts.some(p => p.total > 0));
  const targets = Object.keys(byTarget).sort();
  if (!targets.length) {
    return `<div class="section collapsible-section collapsed" id="section-secrets">
      <div class="section-title section-toggle" onclick="toggleSection('section-secrets')">
        Secret Detection Trend <span class="section-chevron">▾</span>
      </div>
      <div class="section-body"><p class="metrics-note" style="color:var(--text-muted)">No TruffleHog data found in scans.</p></div>
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
      <td style="color:var(--text-muted);font-size:11px">${esc(latest.date || '—')}</td>
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
        <table><thead><tr><th>Application</th><th>Verified</th><th>Unverified</th><th>Total</th><th>Last Scan</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </div>
  </div>`;
}

function buildSuppressionSection(m) {
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
        <thead><tr><th>Rule / ID</th><th>Tool</th><th>Type</th><th>Reason</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');

  const emptyState = !appsSorted.length
    ? `<p style="color:var(--text-muted);text-align:center;padding:24px 0">No suppressions found across monitored apps.</p>`
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

function buildRecurrenceSection(m) {
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

async function renderMetrics() {
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
      const display = val != null ? `${val}d` : '—';
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
      const mttrVal = data.mttr_days != null ? `${data.mttr_days}` : null;
      const mttrDisplay = mttrVal != null
        ? `<span class="mttr-number">${esc(mttrVal)}</span><span class="mttr-unit">days</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttrSub = data.mttr_days != null ? 'avg across resolved findings' : 'Not enough scan history';
      const mttdVal = data.mttd_days != null ? `${data.mttd_days}` : null;
      const mttdDisplay = mttdVal != null
        ? `<span class="mttr-number mttd-number">${esc(mttdVal)}</span><span class="mttr-unit">days</span>`
        : `<span class="mttr-number mttr-na">N/A</span>`;
      const mttdSub = data.mttd_days != null ? 'avg detection window across new findings' : 'Not enough scan history';
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
            <td style="font-size:11px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted)">No CVE data — run a scan to populate</td></tr>';

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
            <td><div class="freq-dots">${
              f.dates.map(d => `<span class="freq-dot" title="${esc(d)}"></span>`).join('')
            }</div></td>
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
      <div class="page-header">
        <h1>Metrics</h1>
        <button class="btn btn-sm" onclick="renderMetrics()">&#8635; Refresh</button>
      </div>
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
              <span class="legend-dot" style="background:#30363d;border:1px solid #6e7681"></span>
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
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">last ${m.trend.length} scans</span>
        </div>
        <div class="trend-wrap">
          <canvas id="trend-chart" style="display:block;width:100%;height:200px"></canvas>
        </div>
        <div class="chart-legend">${legendSevs}</div>
      </div>

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
                  <th data-col="cve_id">CVE ID <span class="sort-icon">⇅</span></th>
                  <th data-col="severity">Severity <span class="sort-icon">⇅</span></th>
                  <th data-col="count">Count <span class="sort-icon">⇅</span></th>
                  <th>Title</th>
                  <th data-col="source">Source <span class="sort-icon">⇅</span></th>
                  <th data-col="apps">Applications <span class="sort-icon">⇅</span></th>
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
          <div class="table-container">
            <table id="tbl-freq">
              <thead>
                <tr>
                  <th data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th data-col="total">Total Scans <span class="sort-icon">⇅</span></th>
                  <th data-col="first">First Scan <span class="sort-icon">⇅</span></th>
                  <th data-col="last">Latest Scan <span class="sort-icon">⇅</span></th>
                  <th>History</th>
                </tr>
              </thead>
              <tbody>${freqRows || '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No scan data available</td></tr>'}</tbody>
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
                  <th data-col="name">Application <span class="sort-icon">⇅</span></th>
                  <th data-col="total">Merges <span class="sort-icon">⇅</span></th>
                  <th data-col="first">First Merge <span class="sort-icon">⇅</span></th>
                  <th data-col="last">Latest Merge <span class="sort-icon">⇅</span></th>
                  <th>History</th>
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
            <td style="font-size:11px;color:var(--text-muted)">${c.apps.map(a => esc(a)).join(', ')}</td>
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
        function freqRow([name, f]) {
          const first = f.dates.length ? f.dates[0] : '\u2014';
          const last  = f.dates.length ? f.dates[f.dates.length - 1] : '\u2014';
          return `<tr onclick="navigate('#/applications/${encodeURIComponent(name)}')" style="cursor:pointer">
            <td><strong>${esc(name)}</strong></td>
            <td>${esc(f.total)}</td>
            <td>${esc(first)}</td>
            <td>${esc(last)}</td>
            <td><div class="freq-dots">${f.dates.map(d => `<span class="freq-dot" title="${esc(d)}"></span>`).join('')}</div></td>
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
            <td><div class="freq-dots">${filteredDates.map(d => `<span class="freq-dot" title="${esc(d)}"></span>`).join('')}</div></td>
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
            : '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No merges in this period</td></tr>';

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


    });
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

// ── GitHub Signals sparkline helper ──────────────────────────
function _ghSparkline(history, field, color, labelFn) {
  if (!history || history.length < 2) {
    return `<div style="display:flex;align-items:center;justify-content:center;height:60px;color:var(--text-muted);font-size:12px">Not enough history yet</div>`;
  }
  const vals = history.map(e => e[field]);
  const dates = history.map(e => e.date);
  const min = Math.min(...vals.filter(v => v != null));
  const max = Math.max(...vals.filter(v => v != null));
  const range = max - min || 1;
  const W = 320, H = 60, pad = 6;
  const pts = vals.map((v, i) => {
    const x = pad + (i / (vals.length - 1)) * (W - pad * 2);
    const y = v == null ? null : H - pad - ((v - min) / range) * (H - pad * 2);
    return y == null ? null : `${x.toFixed(1)},${y.toFixed(1)}`;
  }).filter(Boolean).join(' ');
  const last = vals.filter(v => v != null).at(-1);
  const first = vals.filter(v => v != null)[0];
  const delta = last - first;
  const deltaStr = (delta > 0 ? '+' : '') + delta + (labelFn ? '' : '');
  const deltaColor = delta === 0 ? 'var(--text-muted)' : (
    // For "open" signals, lower is better; for coverage/success, higher is better
    (field === 'dep_open' || field === 'sec_open') ? (delta < 0 ? 'var(--clean)' : 'var(--critical)') : (delta > 0 ? 'var(--clean)' : 'var(--critical)')
  );
  return `
    <div style="display:flex;align-items:center;gap:16px">
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="flex-shrink:0">
        <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
        <circle cx="${(pad + (vals.length-1)/(vals.length-1)*(W-pad*2)).toFixed(1)}" cy="${(H-pad-((last-min)/range)*(H-pad*2)).toFixed(1)}" r="3" fill="${color}"/>
      </svg>
      <div style="text-align:right;min-width:64px">
        <div style="font-size:20px;font-weight:700;color:${color}">${labelFn ? labelFn(last) : last}</div>
        <div style="font-size:11px;color:${deltaColor}">${deltaStr !== '+0' && deltaStr !== '0' ? deltaStr : '—'} vs ${dates[0]}</div>
      </div>
    </div>`;
}

async function renderGitHubSignals() {
  setActive('github-signals');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [g, history] = await Promise.all([
      api.getGitHubMetrics(),
      api.getGitHubSignalsHistory().catch(() => []),
    ]);

    // ── Helpers ──────────────────────────────────────────────
    const noData = g.error && !g.dependabot.length
      ? `<div class="metrics-filter-notice" style="border-color:#f59e0b;color:#f59e0b">
           ⚠ ${esc(g.error)} — Configure a GitHub token and repos in Settings to enable GitHub API metrics.
           PR Scan Coverage is available without a token.
         </div>` : '';

    // ── Dependabot summary ───────────────────────────────────
    const totalDepOpen = g.dependabot.reduce((s, r) => s + (r.open || 0), 0);
    const totalDepFixed = g.dependabot.reduce((s, r) => s + (r.fixed || 0), 0);
    const _depList = g.dependabot.filter(r => !r.error);
    const depRows = _depList.map((r, i) => {
      const sev = r.by_severity || {};
      const topPkg = (r.top_packages || []).map(p => `${esc(p.package)} (${p.count})`).join(', ') || '—';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('dep',${i})" title="Click to view details">
        <td><strong>${esc(r.repo.split('/')[1] || r.repo)}</strong><div style="font-size:11px;color:var(--text-muted)">${esc(r.repo)}</div></td>
        <td style="text-align:center"><span style="color:${(r.open||0)>0?'var(--critical)':'var(--clean)'};font-weight:700">${r.open || 0}</span></td>
        <td style="text-align:center;font-size:12px">
          <span style="color:#ff7b72">${sev.critical||0} C</span> ·
          <span style="color:#ffa657">${sev.high||0} H</span> ·
          <span style="color:#e3b341">${sev.medium||0} M</span> ·
          <span style="color:#79c0ff">${sev.low||0} L</span>
        </td>
        <td style="text-align:center;color:var(--clean)">${r.fixed || 0}</td>
        <td style="font-size:11px;color:var(--text-muted);max-width:220px">${topPkg}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No Dependabot data — check token permissions (security_events scope)</td></tr>';

    // ── Security issues summary ──────────────────────────────
    const totalOpenSec = g.security_issues.reduce((s, r) => s + (r.open_security || 0), 0);
    const _secList = g.security_issues.filter(r => !r.error);
    const issueRows = _secList.map((r, i) => {
      const avgClose = r.avg_close_days != null ? `${r.avg_close_days}d` : '—';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('sec',${i})" title="Click to view details">
        <td><strong>${esc(r.repo.split('/')[1] || r.repo)}</strong><div style="font-size:11px;color:var(--text-muted)">${esc(r.repo)}</div></td>
        <td style="text-align:center"><span style="color:${(r.open_security||0)>0?'var(--high)':'var(--clean)'};font-weight:700">${r.open_security || 0}</span></td>
        <td style="text-align:center">${r.closed_security || 0}</td>
        <td style="text-align:center;color:var(--text-muted)">${avgClose}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="4" style="text-align:center;padding:32px;color:var(--text-muted)">No security issue data</td></tr>';

    // ── Workflow success rate ────────────────────────────────
    const _runList = g.workflow_runs.filter(r => !r.error);
    const runRows = _runList.map((r, i) => {
      const rate = r.success_rate != null ? `${r.success_rate}%` : '—';
      const rateColor = r.success_rate == null ? 'var(--text-muted)' : r.success_rate >= 90 ? 'var(--clean)' : r.success_rate >= 70 ? '#e3b341' : 'var(--critical)';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('run',${i})" title="Click to view details">
        <td><strong>${esc(r.repo.split('/')[1] || r.repo)}</strong><div style="font-size:11px;color:var(--text-muted)">${esc(r.repo)}</div></td>
        <td style="text-align:center;font-weight:700;color:${rateColor}">${rate}</td>
        <td style="text-align:center">${r.total_runs || 0}</td>
        <td style="text-align:center;color:var(--clean)">${r.success || 0}</td>
        <td style="text-align:center;color:var(--critical)">${r.failed || 0}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No workflow run data</td></tr>';

    // ── PR scan coverage ────────────────────────────────────
    const covEntries = Object.entries(g.pr_scan_coverage || {}).sort((a, b) => b[1].pr_coverage_pct - a[1].pr_coverage_pct);
    const totalPRScans = covEntries.reduce((s, [, v]) => s + v.pr_scans, 0);
    const totalCIScans = covEntries.reduce((s, [, v]) => s + v.total_ci_scans, 0);
    const overallCovPct = totalCIScans > 0 ? Math.round((totalPRScans / totalCIScans) * 100) : 0;
    const covRows = covEntries.map(([name, v], i) => {
      const pct = v.pr_coverage_pct;
      const barColor = pct >= 70 ? 'var(--clean)' : pct >= 40 ? '#e3b341' : 'var(--critical)';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('cov',${i})" title="Click to view details">
        <td><strong>${esc(name)}</strong></td>
        <td style="text-align:center">${v.pr_scans}</td>
        <td style="text-align:center">${v.push_scans}</td>
        <td style="text-align:center">${v.other_scans}</td>
        <td style="text-align:center">${v.total_ci_scans}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:#30363d;border-radius:4px;height:8px;overflow:hidden">
              <div style="width:${Math.min(pct,100)}%;background:${barColor};height:100%;border-radius:4px;transition:width .3s"></div>
            </div>
            <span style="font-size:12px;font-weight:700;color:${barColor};min-width:40px;text-align:right">${pct}%</span>
          </div>
        </td>
      </tr>`;
    }).join('') || '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted)">No CI scan data available yet</td></tr>';

    // Store data for detail drawer
    _ghSignalData = { dep: _depList, sec: _secList, run: _runList, cov: covEntries };

    page.innerHTML = `
      <div class="page-header">
        <h1>GitHub Signals</h1>
        <button class="btn btn-sm" onclick="renderGitHubSignals()">&#8635; Refresh</button>
      </div>
      ${noData}

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value" style="color:${totalDepOpen > 0 ? 'var(--critical)' : 'var(--clean)'}">${esc(String(totalDepOpen))}</div>
          <div class="stat-label">Open Dependabot Alerts</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:var(--clean)">${esc(String(totalDepFixed))}</div>
          <div class="stat-label">Fixed by Dependabot</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:${totalOpenSec > 0 ? 'var(--high)' : 'var(--clean)'}">${esc(String(totalOpenSec))}</div>
          <div class="stat-label">Open Security Issues</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" style="color:${overallCovPct >= 70 ? 'var(--clean)' : 'var(--high)'}">${esc(String(overallCovPct))}%</div>
          <div class="stat-label">PR Scan Coverage</div>
        </div>
      </div>

      ${history.length >= 2 ? `
      <div class="section">
        <div class="section-title">
          Historical Trends
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">${history.length} daily snapshot${history.length !== 1 ? 's' : ''} · earliest ${esc(history[0].date)}</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px">
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Open Dependabot Alerts</div>
            ${_ghSparkline(history, 'dep_open', 'var(--critical)', null)}
          </div>
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Open Security Issues</div>
            ${_ghSparkline(history, 'sec_open', 'var(--high)', null)}
          </div>
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Workflow Success Rate</div>
            ${_ghSparkline(history, 'workflow_success_rate', '#79c0ff', v => v != null ? v + '%' : '—')}
          </div>
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">PR Scan Coverage</div>
            ${_ghSparkline(history, 'pr_coverage_pct', 'var(--clean)', v => v + '%')}
          </div>
        </div>
      </div>` : ''}

      <div class="section">
        <div class="section-title">Dependabot Alerts</div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th>Repository</th>
              <th style="text-align:center">Open</th>
              <th style="text-align:center">By Severity</th>
              <th style="text-align:center">Fixed</th>
              <th>Top Affected Packages</th>
            </tr></thead>
            <tbody>${depRows}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Security Issues</div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th>Repository</th>
              <th style="text-align:center">Open</th>
              <th style="text-align:center">Closed</th>
              <th style="text-align:center">Avg Days to Close</th>
            </tr></thead>
            <tbody>${issueRows}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">
          Workflow Success Rate
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">last 30 days · security workflows</span>
        </div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th>Repository</th>
              <th style="text-align:center">Success Rate</th>
              <th style="text-align:center">Total Runs</th>
              <th style="text-align:center">✓ Success</th>
              <th style="text-align:center">✗ Failed</th>
            </tr></thead>
            <tbody>${runRows}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">
          PR Scan Coverage
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">% of CI scans triggered by pull requests</span>
        </div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th>Application</th>
              <th style="text-align:center">PR Scans</th>
              <th style="text-align:center">Push Scans</th>
              <th style="text-align:center">Other</th>
              <th style="text-align:center">Total CI</th>
              <th>Coverage</th>
            </tr></thead>
            <tbody>${covRows}</tbody>
          </table>
        </div>
      </div>`;

  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ─────────────────────────────────────────────────────────────

async function renderSettings() {
  setActive('settings');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [images, history, ghCfg, aiCfg, health, jiraCfg] = await Promise.all([
      api.getApprovedImages(),
      api.getScanHistory(),
      api.getGitHubConfig(),
      api.getAiConfig(),
      api._get('/api/health'),
      api.getJiraConfig().catch(() => ({})),
    ]);
    const epyonVersion = health.version || '—';

    const tools = [
      'Trivy', 'Grype', 'TruffleHog', 'ClamAV', 'Checkov', 'Syft/SBOM',
      'SonarQube', 'Helm', 'Xeol', 'Anchore', 'API Discovery', 'Garak',
    ];

    page.innerHTML = `
      <div class="page-header"><h1>Settings</h1></div>

      <div class="section">
        <div class="section-title">Scan History Summary</div>
        <div class="detail-grid">
          <div class="detail-card">
            <div class="label">Generated At</div>
            <div class="value" style="font-size:13px">${fmtDate(history.generated_at)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Total Scans Recorded</div>
            <div class="value">${esc(history.total_scans || 0)}</div>
          </div>
          <div class="detail-card">
            <div class="label">Tracked Targets</div>
            <div class="value" style="font-size:13px">
              ${(history.targets || []).map(t => esc(t)).join(', ') || '—'}
            </div>
          </div>
          <div class="detail-card">
            <div class="label">Users</div>
            <div class="value" style="font-size:13px">
              ${(history.users || []).map(u => esc(u)).join(', ') || '—'}
            </div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">AI Executive Summary</div>
        <p class="section-desc">
          Configure the OpenAI API key used for generating executive summaries of scan results.
        </p>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">OpenAI API Key</label>
            <input id="ai-key" type="password" class="field-input"
              placeholder="${aiCfg.key_set ? 'Key saved — enter new to replace' : 'sk-...'}"
              autocomplete="off"/>
            ${aiCfg.key_set ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Current: ${esc(aiCfg.key_hint)}</div>` : ''}
          </div>
          <div>
            <label class="field-label">Model</label>
            <select id="ai-model" class="field-input">
              <option value="gpt-4.1" ${aiCfg.model === 'gpt-4.1' ? 'selected' : ''}>gpt-4.1</option>
              <option value="gpt-4o" ${aiCfg.model === 'gpt-4o' ? 'selected' : ''}>gpt-4o</option>
              <option value="gpt-4o-mini" ${aiCfg.model === 'gpt-4o-mini' ? 'selected' : ''}>gpt-4o-mini</option>
              <option value="gpt-4-turbo" ${aiCfg.model === 'gpt-4-turbo' ? 'selected' : ''}>gpt-4-turbo</option>
            </select>
          </div>
          <div>
            <button class="btn btn-primary" onclick="saveAiConfig()">Save AI Config</button>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">GitHub Actions Integration</div>
        <p class="section-desc">
          Import scan results from GitHub Actions directly into this dashboard.
          Epyon workflows upload scan artifacts automatically — enter a
          <strong>Personal Access Token</strong> (needs <code>actions:read</code> scope)
          and the repositories to watch.
        </p>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">Default Personal Access Token</label>
            <input id="gh-token" type="password" class="field-input"
              placeholder="${ghCfg.token_set ? 'Token saved — enter new to replace' : 'ghp_... or github_pat_...'}"
              autocomplete="off"/>
            ${ghCfg.token_set ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Current: ${esc(ghCfg.token_hint)}</div>` : ''}
          </div>
          <div>
            <label class="field-label">Repositories <span style="color:var(--text-muted);font-weight:normal">(one per line: owner/repo)</span></label>
            <textarea id="gh-repos" class="field-input" rows="4"
              placeholder="MetroStar/sapphire&#10;MetroStar/comet-starter"
              style="resize:vertical">${(ghCfg.repos || []).map(r => esc(r)).join('\n')}</textarea>
          </div>

          <div>
            <label class="field-label" style="margin-bottom:8px">Additional PATs
              <span style="color:var(--text-muted);font-weight:normal"> — for external orgs that need a separate token</span>
            </label>
            <div id="gh-extra-tokens" style="display:flex;flex-direction:column;gap:10px">
              ${(ghCfg.extra_tokens || []).map((e, i) => `
              <div class="gh-extra-row" data-idx="${i}" style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:start">
                <div>
                  <div style="font-size:11px;color:var(--text-muted);margin-bottom:3px">Repositories (one per line)</div>
                  <textarea class="field-input gh-extra-repos" rows="2" style="resize:vertical;font-size:12px"
                    placeholder="other-org/repo">${(e.repos || []).map(r => esc(r)).join('\n')}</textarea>
                </div>
                <div>
                  <div style="font-size:11px;color:var(--text-muted);margin-bottom:3px">Token${e.token_set ? ` (${esc(e.token_hint)})` : ''}</div>
                  <input type="password" class="field-input gh-extra-token"
                    placeholder="${e.token_set ? 'Saved — enter new to replace' : 'ghp_...'}"
                    autocomplete="off"/>
                </div>
                <button class="btn btn-sm" style="margin-top:18px;color:var(--critical)" onclick="this.closest('.gh-extra-row').remove()" title="Remove">✕</button>
              </div>`).join('')}
            </div>
            <button class="btn btn-sm" style="margin-top:8px" onclick="addGhExtraToken()">+ Add PAT</button>
          </div>

          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="saveGitHubConfig()">Save</button>
            <button class="btn btn-primary" id="sync-btn" onclick="triggerGitHubSync()">
              ↓ Sync Now
            </button>
            <span id="sync-status" style="font-size:13px;color:var(--text-muted)">
              ${ghCfg.last_sync ? 'Last synced: ' + fmtDate(ghCfg.last_sync) : 'Not yet synced'}
            </span>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Jira Integration</div>
        <p class="section-desc">
          Automatically close Jira tickets when security findings are remediated in a subsequent scan.
          Requires a Jira Cloud account with an API token (Atlassian account settings → Security → API tokens).
        </p>
        ${jiraCfg._from_env ? `
        <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>Credentials loaded from environment variables (<code style="background:var(--bg-input);padding:1px 4px;border-radius:3px">JIRA_BASE_URL</code>, <code style="background:var(--bg-input);padding:1px 4px;border-radius:3px">JIRA_USER_EMAIL</code>, <code style="background:var(--bg-input);padding:1px 4px;border-radius:3px">JIRA_API_TOKEN</code>). Fill in the form below to override with saved settings.</span>
        </div>` : ''}
        <div style="display:grid;gap:14px;max-width:600px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
            <div>
              <label class="field-label">Jira Base URL</label>
              <input id="jira-url" type="url" class="field-input"
                placeholder="https://your-org.atlassian.net"
                value="${esc(jiraCfg.base_url || '')}"/>
            </div>
            <div>
              <label class="field-label">Email</label>
              <input id="jira-email" type="email" class="field-input"
                placeholder="user@company.com"
                value="${esc(jiraCfg.email || '')}"/>
            </div>
          </div>
          <div>
            <label class="field-label">API Token</label>
            <input id="jira-token" type="password" class="field-input"
              placeholder="${jiraCfg.token_set ? 'Token saved — enter new to replace' : (jiraCfg._from_env ? 'Set via JIRA_API_TOKEN env var' : 'Atlassian API token')}"
              autocomplete="off"/>
            ${jiraCfg.token_set ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Token saved</div>` : ''}
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
            <div>
              <label class="field-label">Project Key</label>
              <input id="jira-project" type="text" class="field-input"
                placeholder="SEC"
                value="${esc(jiraCfg.project_key || '')}"/>
            </div>
            <div>
              <label class="field-label">Issue Type</label>
              <input id="jira-issue-type" type="text" class="field-input"
                placeholder="Bug"
                value="${esc(jiraCfg.issue_type || 'Bug')}"/>
            </div>
            <div>
              <label class="field-label">Done Transition</label>
              <input id="jira-done" type="text" class="field-input"
                placeholder="Done"
                value="${esc(jiraCfg.done_transition || 'Done')}"/>
            </div>
          </div>
          <div>
            <label class="field-label">Minimum Severity to Track</label>
            <select id="jira-minsev" class="field-input" style="max-width:200px">
              <option value="critical" ${jiraCfg.min_severity === 'critical' ? 'selected' : ''}>Critical only</option>
              <option value="high" ${(jiraCfg.min_severity || 'high') === 'high' ? 'selected' : ''}>High and above</option>
              <option value="medium" ${jiraCfg.min_severity === 'medium' ? 'selected' : ''}>Medium and above</option>
              <option value="low" ${jiraCfg.min_severity === 'low' ? 'selected' : ''}>All severities</option>
            </select>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <label style="display:flex;gap:8px;align-items:center;cursor:pointer;font-size:13px">
              <input type="checkbox" id="jira-auto-close" ${jiraCfg.auto_close ? 'checked' : ''}/>
              Auto-close tickets when findings are remediated (runs after each scan)
            </label>
            <label style="display:flex;gap:8px;align-items:center;cursor:pointer;font-size:13px">
              <input type="checkbox" id="jira-create-new" ${jiraCfg.create_on_new ? 'checked' : ''}/>
              Auto-create tickets for new findings
            </label>
          </div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="saveJiraConfig()">Save</button>
            <button class="btn" id="jira-test-btn" onclick="testJiraConnection()">Test Connection</button>
            <span id="jira-status" style="font-size:13px;color:var(--text-muted)"></span>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Workflow File Setup</div>
        <p class="section-desc">
          Each repository needs the Epyon workflow file added once so that scans run
          automatically and results are uploaded to this dashboard.
        </p>
        <ol style="padding-left:18px;margin:0 0 14px;font-size:13px;color:var(--text-muted);line-height:1.9">
          <li>In your repository, create the directory <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">.github/workflows/</code> if it doesn't exist.</li>
          <li>Add a new file named <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">scan-private-repo.yml</code> with the contents below.</li>
          <li>Review the <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">uses:</code> line and update the GitHub org only if your Epyon instance is hosted under a different org than <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">MetroStar/epyon</code>.</li>
          <li>Commit and push — the workflow will run nightly at 2 AM UTC and on manual dispatch.</li>
        </ol>
        <div style="position:relative;max-width:700px">
          <pre id="settings-yml" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);
               padding:12px;font-size:11px;line-height:1.6;overflow-x:auto;margin:0;white-space:pre;color:var(--text)">${esc(WORKFLOW_YML)}</pre>
          <button id="settings-yml-copy"
            style="position:absolute;top:8px;right:8px;padding:3px 10px;font-size:11px;
                   background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
                   color:var(--text-muted);cursor:pointer"
            onclick="navigator.clipboard.writeText(WORKFLOW_YML).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})">Copy</button>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Approved Base Images</div>
        <p class="section-desc">
          Docker Hardened Images approved for scans and deployments.
          Managed in <code>configuration/approved-base-images.conf</code>.
        </p>
        <pre>${esc(images.content || '(No approved-base-images.conf found)')}</pre>
      </div>

      <div class="section">
        <div class="section-title">About Epyon</div>
        <div class="detail-grid">
          <div class="detail-card">
            <div class="label">Version</div>
            <div class="value">${epyonVersion}</div>
          </div>
          <div class="detail-card">
            <div class="label">Security Layers</div>
            <div class="value">12 + STIG</div>
          </div>
          <div class="detail-card">
            <div class="label">Tagline</div>
            <div class="value" style="font-size:13px">Absolute Security Control</div>
          </div>
        </div>
        <div class="tools-list">
          ${tools.map(t => `<span class="tool-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>`;
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

async function saveAiConfig() {
  const keyEl   = document.getElementById('ai-key');
  const modelEl = document.getElementById('ai-model');
  const key   = keyEl   ? keyEl.value.trim()   : '';
  const model = modelEl ? modelEl.value         : '';
  try {
    await api.saveAiConfig({ api_key: key || 'KEEP_EXISTING', model });
    if (keyEl) keyEl.value = '';
  } catch (e) {
    alert('Failed to save AI config: ' + e.message);
  }
}

async function saveGitHubConfig() {
  const tokenEl = document.getElementById('gh-token');
  const reposEl = document.getElementById('gh-repos');
  const token = tokenEl ? tokenEl.value.trim() : '';
  const repos = reposEl
    ? reposEl.value.split('\n').map(r => r.trim()).filter(Boolean)
    : [];

  // Collect extra PAT rows
  const extraTokens = [];
  document.querySelectorAll('#gh-extra-tokens .gh-extra-row').forEach(row => {
    const reposTa = row.querySelector('.gh-extra-repos');
    const tokenIn = row.querySelector('.gh-extra-token');
    const rowRepos = reposTa ? reposTa.value.split('\n').map(r => r.trim()).filter(Boolean) : [];
    const rowToken = tokenIn ? tokenIn.value.trim() : '';
    extraTokens.push({ repos: rowRepos, token: rowToken || 'KEEP_EXISTING' });
  });

  try {
    await api.saveGitHubConfig({ token: token || 'KEEP_EXISTING', repos, extra_tokens: extraTokens });
    tokenEl && (tokenEl.value = '');
    document.querySelectorAll('#gh-extra-tokens .gh-extra-token').forEach(el => { el.value = ''; });
    // Auto-mark all configured repos as Continuously Monitored
    await Promise.allSettled(
      repos.map(r => api.setMonitored(r.includes('/') ? r.split('/').pop() : r))
    );
    const statusEl = document.getElementById('sync-status');
    if (statusEl) statusEl.textContent = 'Configuration saved.';
  } catch (e) {
    alert('Failed to save GitHub config: ' + e.message);
  }
}

let _syncPoll = null;

window.addGhExtraToken = function() {
  const container = document.getElementById('gh-extra-tokens');
  if (!container) return;
  const idx = container.querySelectorAll('.gh-extra-row').length;
  const row = document.createElement('div');
  row.className = 'gh-extra-row';
  row.dataset.idx = idx;
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:start';
  row.innerHTML = `
    <div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:3px">Repositories (one per line)</div>
      <textarea class="field-input gh-extra-repos" rows="2" style="resize:vertical;font-size:12px"
        placeholder="other-org/repo"></textarea>
    </div>
    <div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:3px">Token</div>
      <input type="password" class="field-input gh-extra-token"
        placeholder="ghp_..." autocomplete="off"/>
    </div>
    <button class="btn btn-sm" style="margin-top:18px;color:var(--critical)" onclick="this.closest('.gh-extra-row').remove()" title="Remove">\u2715</button>`;
  container.appendChild(row);
};

async function triggerGitHubSync() {
  const btn = document.getElementById('sync-btn');
  const statusEl = document.getElementById('sync-status');
  if (btn) { btn.disabled = true; btn.textContent = '↓ Syncing…'; }
  if (statusEl) statusEl.textContent = 'Sync in progress…';
  try {
    await api.triggerGitHubSync();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
    return;
  }
  clearInterval(_syncPoll);
  _syncPoll = setInterval(async () => {
    try {
      const st = await api.getGitHubSyncStatus();
      if (st.status === 'running') return;
      clearInterval(_syncPoll);
      _syncPoll = null;
      if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
      if (st.status === 'done' && st.result) {
        const r = st.result;
        const msg = `Done — ${r.synced.length} new, ${r.skipped.length} already present, ${r.failed.length} failed`;
        if (statusEl) statusEl.textContent = msg;
      } else if (st.status === 'error') {
        if (statusEl) statusEl.textContent = 'Sync error: ' + (st.error || 'unknown');
      }
    } catch (_) {}
  }, 2000);
}

// ── Jira Settings helpers ─────────────────────────────────────

async function saveJiraConfig() {
  const statusEl = document.getElementById('jira-status');
  if (statusEl) statusEl.textContent = 'Saving…';
  const body = {
    base_url:        (document.getElementById('jira-url')?.value   || '').trim(),
    email:           (document.getElementById('jira-email')?.value  || '').trim(),
    api_token:       (document.getElementById('jira-token')?.value  || '').trim() || 'KEEP_EXISTING',
    project_key:     (document.getElementById('jira-project')?.value || '').trim(),
    issue_type:      (document.getElementById('jira-issue-type')?.value || '').trim() || 'Bug',
    done_transition: (document.getElementById('jira-done')?.value   || '').trim() || 'Done',
    min_severity:    document.getElementById('jira-minsev')?.value  || 'high',
    auto_close:      document.getElementById('jira-auto-close')?.checked ?? false,
    create_on_new:   document.getElementById('jira-create-new')?.checked ?? false,
  };
  try {
    await api.saveJiraConfig(body);
    const tokenEl = document.getElementById('jira-token');
    if (tokenEl) tokenEl.value = '';
    if (statusEl) statusEl.textContent = 'Saved.';
  } catch (e) {
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
  }
}

async function testJiraConnection() {
  const btn      = document.getElementById('jira-test-btn');
  const statusEl = document.getElementById('jira-status');
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  if (statusEl) statusEl.textContent = '';
  // Save current form values first so the test uses the latest credentials
  await saveJiraConfig().catch(() => {});
  try {
    const result = await api.testJiraConnection();
    if (statusEl) {
      statusEl.style.color = result.ok ? 'var(--pass)' : 'var(--critical)';
      statusEl.textContent = result.message || (result.ok ? 'Connected' : 'Failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--critical)'; statusEl.textContent = e.message; }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Test Connection'; }
  }
}

// ── STIG History Matrix & MTTR ───────────────────────────────

async function renderStigHistory(selectedApp, selectedSlug) {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  const STATUS_CLASSES = {
    'Open':           'open',
    'Not a Finding':  'not-a-finding',
    'Not Applicable': 'na',
    'Not Reviewed':   'not-reviewed',
  };
  const STATUS_ABBR = {
    'Open':           'O',
    'Not a Finding':  'P',
    'Not Applicable': 'N/A',
    'Not Reviewed':   '—',
  };
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, '': 4 };

  let data;
  try {
    data = await api.getStigHistory(selectedApp || null, selectedSlug || null);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
    return;
  }

  const { apps = [], app: curApp, slugs = [], scans = [], controls = [], summary = {} } = data;

  // ── Filter state ──────────────────────────────────────────
  let statusFilter = 'all';   // 'all' | 'open' | 'pass' | 'na'
  let daysFilter   = 30;      // 7 | 14 | 30 | 90 | 0 (all)
  let sortKey      = 'sev';   // 'sev' | 'id' | 'mttr' | 'status'
  let sortDir      = 1;

  // ── Render helpers ────────────────────────────────────────
  function filterControls(list) {
    if (statusFilter === 'open')   return list.filter(c => c.latest_status === 'Open');
    if (statusFilter === 'pass')   return list.filter(c => c.latest_status === 'Not a Finding');
    if (statusFilter === 'na')     return list.filter(c => ['Not Applicable','Not Reviewed'].includes(c.latest_status));
    return list;
  }

  function sortControls(list) {
    return [...list].sort((a, b) => {
      let v = 0;
      if (sortKey === 'sev')    v = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
      if (sortKey === 'id')     v = a.vuln_id.localeCompare(b.vuln_id);
      if (sortKey === 'title')  v = (a.title || '').localeCompare(b.title || '');
      if (sortKey === 'mttr')   v = (a.mttr_days ?? 9999) - (b.mttr_days ?? 9999);
      if (sortKey === 'status') v = (a.latest_status || '').localeCompare(b.latest_status || '');
      return v * sortDir;
    });
  }

  function buildPage() {
    // ── Filters row ────────────────────────────────────────
    const appOpts = apps.map(a =>
      `<option value="${esc(a)}" ${a === curApp ? 'selected' : ''}>${esc(a)}</option>`
    ).join('');
    const slugOpts = ['<option value="">All STIGs</option>',
      ...slugs.map(s => `<option value="${esc(s)}" ${s === (selectedSlug||'') ? 'selected' : ''}>${esc(s)}</option>`)
    ].join('');

    const cutoff = daysFilter > 0
      ? new Date(Date.now() - daysFilter * 86400000).toISOString().slice(0, 10)
      : null;
    const visibleScans = cutoff ? scans.filter(s => s.date >= cutoff) : scans;

    const dayBtns = [[7,'7d'],[14,'14d'],[30,'30d'],[90,'90d'],[0,'All']].map(([d,l]) =>
      `<button class="btn btn-sm${daysFilter===d?' btn-active':''}" onclick="window._stigHistoryDays(${d})">${l}</button>`
    ).join('');

    const statusBtns = [
      ['all','All'],['open','Open'],['pass','Not a Finding'],['na','N/A / NR']
    ].map(([k,l]) =>
      `<button class="btn btn-sm${statusFilter===k?' btn-active':''}" onclick="window._stigHistoryStatus('${k}')">${l}</button>`
    ).join('');

    const avgMttr = summary.avg_mttr_days != null
      ? summary.avg_mttr_days + ' days'
      : '—';

    // ── Summary strip ──────────────────────────────────────
    const summaryStrip = `
      <div class="stig-history-summary">
        <div class="stig-hs-card">
          <span class="stig-hs-num">${esc(summary.total_controls ?? 0)}</span>
          <span class="stig-hs-lbl">Controls</span>
        </div>
        <div class="stig-hs-card open">
          <span class="stig-hs-num">${esc(summary.currently_open ?? 0)}</span>
          <span class="stig-hs-lbl">Currently Open</span>
        </div>
        <div class="stig-hs-card pass">
          <span class="stig-hs-num">${esc(summary.currently_satisfied ?? 0)}</span>
          <span class="stig-hs-lbl">Currently Satisfied</span>
        </div>
        <div class="stig-hs-card pass" style="opacity:0.7">
          <span class="stig-hs-num">${esc(summary.remediated ?? 0)}</span>
          <span class="stig-hs-lbl">Ever Remediated</span>
        </div>
        <div class="stig-hs-card mttr">
          <span class="stig-hs-num">${esc(avgMttr)}</span>
          <span class="stig-hs-lbl">Avg MTTR</span>
        </div>
      </div>`;

    // ── Matrix table ────────────────────────────────────────
    const visible = sortControls(filterControls(controls));

    const thSort = (key, label) => {
      const active = sortKey === key;
      const arrow  = active ? (sortDir === 1 ? ' ↑' : ' ↓') : '';
      return `<th class="sortable-th${active?' sorted':''}" onclick="window._stigHistorySort('${key}')">${label}${arrow}</th>`;
    };

    const dateHeaders = visibleScans.map(s =>
      `<th class="stig-matrix-date-th" title="${esc(s.scan_id)}">${esc(s.label)}</th>`
    ).join('');

    const rows = visible.map(c => {
      const sevCls = c.severity || 'unknown';
      const cells = visibleScans.map((s, idx) => {
        const entry = c.timeline.find(t => t.scan_id === s.scan_id);
        const status = entry ? entry.status : '';
        const evidence = entry ? entry.evidence : '';
        const confidence = entry ? entry.confidence : null;
        const cls    = STATUS_CLASSES[status] || 'not-reviewed';
        const abbr   = STATUS_ABBR[status] || '';
        
        // Check if evidence changed from previous entry
        const prevEntry = idx > 0 ? c.timeline.find(t => t.scan_id === visibleScans[idx - 1].scan_id) : null;
        const evidenceChanged = prevEntry && prevEntry.evidence && evidence && prevEntry.evidence !== evidence && status !== 'Not Reviewed';
        const changeIndicator = evidenceChanged ? ' 🔄' : '';
        
        const tooltipLines = [
          `Status: ${status}`,
          confidence != null ? `Confidence: ${confidence}%` : '',
          evidence ? `\n${evidence.substring(0, 200)}${evidence.length > 200 ? '...' : ''}` : ''
        ].filter(Boolean).join('\n');
        
        return `<td class="stig-matrix-cell ${cls}${evidenceChanged ? ' evidence-changed' : ''}" title="${esc(tooltipLines)}">${esc(abbr)}${changeIndicator}</td>`;
      }).join('');

      const mttrBadge = c.mttr_days != null
        ? `<span class="mttr-badge">${c.mttr_days}d</span>`
        : `<span class="mttr-badge none">—</span>`;

      const latestCls = STATUS_CLASSES[c.latest_status] || 'not-reviewed';
      const cid = _registerStigDetail(c);

      return `
        <tr onclick="openStigDetail(${cid})" style="cursor:pointer" title="Click to view details">
          <td class="stig-matrix-sev"><span class="sev-badge ${esc(sevCls)}">${esc(sevCls)}</span></td>
          <td class="stig-matrix-id">${esc(c.vuln_id)}</td>
          <td class="stig-matrix-title" title="${esc(c.title)}">${esc(c.title || '—')}</td>
          <td class="stig-matrix-status ${latestCls}">${esc(c.latest_status || '—')}</td>
          ${cells}
          <td class="stig-matrix-mttr">${mttrBadge}</td>
        </tr>`;
    }).join('');

    const emptyRow = visible.length === 0
      ? `<tr><td colspan="${5 + visibleScans.length}" style="text-align:center;padding:32px;color:var(--text-muted)">No controls match the current filter.</td></tr>`
      : '';

    const tableHtml = visibleScans.length === 0
      ? `<div class="empty-state" style="margin-top:32px">
           <p>No STIG scans found for <strong>${esc(curApp || 'this app')}</strong>.</p>
           <p style="color:var(--text-muted);font-size:13px">Run a STIG or nightly scan to start tracking history.</p>
         </div>`
      : `<div class="stig-matrix-wrap">
           <table class="stig-matrix-table">
             <thead>
               <tr>
                 ${thSort('sev','Sev')}
                 ${thSort('id','Vuln ID')}
                 ${thSort('title','Title')}
                 ${thSort('status','Status')}
                 ${dateHeaders}
                 ${thSort('mttr','MTTR')}
               </tr>
             </thead>
             <tbody>${rows}${emptyRow}</tbody>
           </table>
         </div>`;

    page.innerHTML = `
      <div class="page-header">
        <h1>STIG Compliance</h1>
      </div>
      ${histTabs}
      <div class="stig-history-filters">
        <div class="stig-hf-group">
          <label class="stig-hf-label">App</label>
          <select class="stig-hf-select" onchange="window._stigHistoryApp(this.value)">
            ${apps.length === 0 ? '<option value="">No apps</option>' : appOpts}
          </select>
        </div>
        <div class="stig-hf-group">
          <label class="stig-hf-label">STIG</label>
          <select class="stig-hf-select" onchange="window._stigHistorySlug(this.value)">
            ${slugOpts}
          </select>
        </div>
        <div class="stig-hf-group">
          <label class="stig-hf-label">Range</label>
          <div class="stig-hf-btns">${dayBtns}</div>
        </div>
        <div class="stig-hf-group">
          <label class="stig-hf-label">Status</label>
          <div class="stig-hf-btns">${statusBtns}</div>
        </div>
      </div>
      ${summaryStrip}
      ${tableHtml}`;
  }

  // ── Empty state (no apps with STIG data at all) ─────────
  const histTabs = `
    <div class="stig-tabs">
      <button class="stig-tab" onclick="navigate('#/stig')">Overview</button>
      <button class="stig-tab active" onclick="navigate('#/stig?view=history')">History &amp; MTTR</button>
    </div>`;

  if (apps.length === 0) {
    page.innerHTML = `
      <div class="page-header"><h1>STIG Compliance</h1></div>
      ${histTabs}
      <div class="empty-state" style="margin-top:48px">
        <p>No STIG scan data found.</p>
        <p style="color:var(--text-muted);font-size:13px">Run a STIG or nightly scan to start building the history matrix.</p>
      </div>`;
    return;
  }

  // ── Event handlers wired via window (inline onclick) ────
  window._stigHistoryApp = async (appVal) => {
    selectedApp  = appVal || null;
    selectedSlug = null;
    try { data = await api.getStigHistory(selectedApp, null); } catch (_) {}
    Object.assign(data, data);  // reassign outer var
    // re-render by re-calling
    const {
      apps: a2 = [], app: ca2, slugs: sl2 = [],
      scans: sc2 = [], controls: co2 = [], summary: su2 = {}
    } = data;
    Object.assign({ apps, app: curApp, slugs, scans, controls, summary },
      { apps: a2, app: ca2, slugs: sl2, scans: sc2, controls: co2, summary: su2 });
    // Simplest: just re-navigate
    navigate('#/stig?view=history&app=' + encodeURIComponent(appVal));
  };
  window._stigHistorySlug = async (slugVal) => {
    navigate('#/stig?view=history&app=' + encodeURIComponent(curApp || '') +
             (slugVal ? '&slug=' + encodeURIComponent(slugVal) : ''));
  };
  window._stigHistoryDays = (d) => {
    daysFilter = d;
    buildPage();
  };
  window._stigHistoryStatus = (key) => {
    statusFilter = key;
    buildPage();
  };
  window._stigHistorySort = (key) => {
    if (sortKey === key) sortDir = -sortDir;
    else { sortKey = key; sortDir = 1; }
    buildPage();
  };

  buildPage();
}

// ── STIG Inline Viewer ────────────────────────────────────────

async function renderStigViewer(scanId) {
  setActive('stig');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [scan, data] = await Promise.all([api.getScan(scanId), api.getStigData(scanId)]);

    const STATUS_ORDER = ['Open', 'Not a Finding', 'Not Applicable', 'Not Reviewed'];
    const STATUS_CLASS = {
      'Open':          'stig-status-open',
      'Not a Finding': 'stig-status-pass',
      'Not Applicable':'stig-status-na',
      'Not Reviewed':  'stig-status-nr',
    };
    const SEV_ORDER = ['high', 'medium', 'low', ''];

    // Flatten all controls from all STIGs with stig_name label
    const allControls = data.stigs.flatMap(s =>
      s.controls.map(c => ({ ...c, _stig_name: s.stig_name, _slug: s.slug }))
    );

    // Build filter bar state
    let filterStatus = 'all';
    let filterSeverity = 'all';
    let filterStig = 'all';
    let filterText = '';

    // Sort state
    let sortCol = null;   // 'vuln_id' | 'severity' | 'status' | 'confidence' | 'title'
    let sortDir = 'asc';  // 'asc' | 'desc'

    const stigNames = [...new Set(data.stigs.map(s => s.stig_name))];

    function filtered() {
      const rows = allControls.filter(c => {
        if (filterStatus   !== 'all' && c.status   !== filterStatus)   return false;
        if (filterSeverity !== 'all' && c.severity !== filterSeverity) return false;
        if (filterStig     !== 'all' && c._slug    !== filterStig)     return false;
        if (filterText) {
          const q = filterText.toLowerCase();
          if (!c.vuln_id.toLowerCase().includes(q) &&
              !c.title.toLowerCase().includes(q)   &&
              !c.evidence.toLowerCase().includes(q)) return false;
        }
        return true;
      });
      if (sortCol) {
        const dir = sortDir === 'asc' ? 1 : -1;
        rows.sort((a, b) => {
          let av, bv;
          if (sortCol === 'vuln_id') {
            av = (a.group_id || a.vuln_id || '').toLowerCase();
            bv = (b.group_id || b.vuln_id || '').toLowerCase();
          } else if (sortCol === 'severity') {
            av = SEV_ORDER.indexOf(a.severity ?? '');
            bv = SEV_ORDER.indexOf(b.severity ?? '');
            return dir * (av - bv);
          } else if (sortCol === 'status') {
            av = STATUS_ORDER.indexOf(a.status ?? '');
            bv = STATUS_ORDER.indexOf(b.status ?? '');
            return dir * (av - bv);
          } else if (sortCol === 'confidence') {
            av = a.confidence ?? 0;
            bv = b.confidence ?? 0;
            return dir * (av - bv);
          } else {
            av = (a[sortCol] || '').toLowerCase();
            bv = (b[sortCol] || '').toLowerCase();
          }
          return dir * (av < bv ? -1 : av > bv ? 1 : 0);
        });
      }
      return rows;
    }

    function countsByStatus() {
      const out = {};
      for (const c of allControls) out[c.status] = (out[c.status] || 0) + 1;
      return out;
    }

    function renderTable() {
      const rows = filtered();
      if (!rows.length) {
        return '<div class="stig-empty">No controls match the current filters.</div>';
      }
      return `
        <div class="stig-viewer-count">${rows.length} control${rows.length !== 1 ? 's' : ''}</div>
        <div class="stig-table-wrap">
          <table class="stig-table">
            <thead>
              <tr>
                ${[
                  ['vuln_id',    '100px', 'STIG #'],
                  ['severity',   '70px',  'Severity'],
                  ['status',     '130px', 'Status'],
                  ['confidence', '80px',  'Confidence'],
                  ['title',      null,    'Title'],
                ].map(([col, w, label]) => {
                  const active = sortCol === col;
                  const icon = active ? (sortDir === 'asc' ? '↑' : '↓') : '⇅';
                  const style = w ? `style="width:${w}"` : '';
                  return `<th class="stig-sortable-th${active ? ' stig-sort-active' : ''}" ${style} onclick="setStigSort('${col}')">${label} <span class="stig-sort-icon">${icon}</span></th>`;
                }).join('')}
                ${stigNames.length > 1 ? '<th style="width:140px">STIG</th>' : ''}
                <th style="width:40px"></th>
              </tr>
            </thead>
            <tbody>
              ${rows.map(c => {
                const rowId = `stig-row-${esc(c.vuln_id)}-${esc(c._slug)}`;
                const detId = `stig-det-${esc(c.vuln_id)}-${esc(c._slug)}`;
                const sname = c._stig_name.replace(/.*?(ASD|Postgres|STIG)/gi, '$1').trim().slice(0, 40);
                const conf  = c.confidence ?? 0;
                const confClass = conf >= 90 ? 'conf-high' : conf >= 70 ? 'conf-med' : conf >= 40 ? 'conf-low' : 'conf-none';
                return `
                  <tr class="stig-tr" id="${rowId}" onclick="toggleStigRow('${detId}', '${rowId}')">
                    <td><code class="stig-id">${esc(c.group_id || c.vuln_id)}</code></td>
                    <td><span class="stig-sev stig-sev-${esc(c.severity)}">${esc(c.severity || '—')}</span></td>
                    <td><span class="${esc(STATUS_CLASS[c.status] || 'stig-status-nr')}">${esc(c.status)}</span></td>
                    <td><span class="stig-confidence ${confClass}" title="${conf}/100">${conf}</span></td>
                    <td class="stig-title-cell">${esc(c.title)}</td>
                    ${stigNames.length > 1 ? `<td class="stig-stig-cell" title="${esc(c._stig_name)}">${esc(sname)}</td>` : ''}
                    <td class="stig-chevron-cell"><span class="stig-chevron" id="chev-${esc(c.vuln_id)}-${esc(c._slug)}">›</span></td>
                  </tr>
                  <tr class="stig-detail-row" id="${detId}" style="display:none">
                    <td colspan="${stigNames.length > 1 ? 7 : 6}">
                      <div class="stig-detail-body">
                        <div class="stig-detail-grid">
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Vuln ID</div>
                            <div class="stig-detail-val"><code>${esc(c.vuln_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Rule ID</div>
                            <div class="stig-detail-val"><code>${esc(c.rule_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Group ID</div>
                            <div class="stig-detail-val"><code>${esc(c.group_id)}</code></div>
                          </div>
                          <div class="stig-detail-section">
                            <div class="stig-detail-label">Confidence</div>
                            <div class="stig-detail-val">
                              ${(() => {
                                const cv = c.confidence ?? 0;
                                const cls = cv >= 90 ? 'conf-high' : cv >= 70 ? 'conf-med' : cv >= 40 ? 'conf-low' : 'conf-none';
                                const lbl = cv >= 90 ? 'High' : cv >= 70 ? 'Medium' : cv >= 40 ? 'Low' : 'Insufficient';
                                return `<span class="stig-confidence ${cls}">${cv}/100</span> <span class="stig-conf-label">${lbl}</span>`;
                              })()}
                            </div>
                          </div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Evidence</div>
                          <div class="stig-detail-val stig-evidence">${esc(c.evidence || '—').replace(/\n/g, '<br>')}</div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Check</div>
                          <div class="stig-detail-val stig-check">${esc(c.check_content).replace(/\n/g, '<br>')}</div>
                        </div>
                        <div class="stig-detail-section">
                          <div class="stig-detail-label">Remediation</div>
                          <div class="stig-detail-val">${esc(c.fix_text || '—').replace(/\n/g, '<br>')}</div>
                        </div>
                      </div>
                    </td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`;
    }

    function renderFilters() {
      const counts = countsByStatus();
      return `
        <div class="stig-filters">
          <div class="stig-filter-group">
            <label class="stig-filter-label">Status</label>
            <div class="stig-filter-btns" id="filter-status">
              ${['all', ...STATUS_ORDER].map(s => `
                <button class="stig-filter-btn${filterStatus === s ? ' active' : ''}"
                  onclick="setStigFilter('status','${s}')">${s === 'all' ? 'All' : esc(s)}${s !== 'all' && counts[s] ? ` <span class="stig-filter-count">${counts[s]}</span>` : ''}</button>
              `).join('')}
            </div>
          </div>
          <div class="stig-filter-group">
            <label class="stig-filter-label">Severity</label>
            <div class="stig-filter-btns">
              ${['all', 'high', 'medium', 'low'].map(s => `
                <button class="stig-filter-btn${filterSeverity === s ? ' active' : ''}"
                  onclick="setStigFilter('severity','${s}')">${s === 'all' ? 'All' : ucFirst(s)}</button>
              `).join('')}
            </div>
          </div>
          ${stigNames.length > 1 ? `
          <div class="stig-filter-group">
            <label class="stig-filter-label">STIG</label>
            <div class="stig-filter-btns">
              <button class="stig-filter-btn${filterStig === 'all' ? ' active' : ''}"
                onclick="setStigFilter('stig','all')">All</button>
              ${data.stigs.map(s => `
                <button class="stig-filter-btn${filterStig === s.slug ? ' active' : ''}"
                  onclick="setStigFilter('stig','${esc(s.slug)}')"
                  title="${esc(s.stig_name)}">${esc(s.stig_name.slice(0, 30))}…</button>
              `).join('')}
            </div>
          </div>` : ''}
          <div class="stig-filter-group">
            <label class="stig-filter-label">Search</label>
            <input class="stig-search" type="text" placeholder="ID, title, or evidence…"
              value="${esc(filterText)}"
              oninput="setStigSearch(this.value)">
          </div>
        </div>`;
    }

    function repaint() {
      const el = document.getElementById('stig-viewer-filters');
      if (el) el.outerHTML = renderFilters().replace('<div class="stig-filters">', '<div class="stig-filters" id="stig-viewer-filters">');
      const tbody = document.getElementById('stig-viewer-body');
      if (tbody) tbody.innerHTML = renderTable();
    }

    // Expose callbacks to global scope for onclick handlers
    window.setStigFilter = (type, val) => {
      if (type === 'status')   filterStatus   = val;
      if (type === 'severity') filterSeverity = val;
      if (type === 'stig')     filterStig     = val;
      repaint();
    };
    window.setStigSearch = (val) => { filterText = val; repaint(); };
    window.setStigSort   = (col) => {
      if (sortCol === col) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortCol = col;
        sortDir = 'asc';
      }
      repaint();
    };
    window.toggleStigRow = (detId, rowId) => {
      const det  = document.getElementById(detId);
      const row  = document.getElementById(rowId);
      const parts = detId.replace('stig-det-', '').split('-');
      // Reconstruct vuln_id + slug for chevron id — use row IDs which embed them
      const chevId = 'chev-' + detId.replace('stig-det-', '');
      const chev = document.getElementById(chevId);
      if (!det) return;
      const open = det.style.display !== 'none';
      det.style.display = open ? 'none' : 'table-row';
      if (row) row.classList.toggle('stig-tr-open', !open);
      if (chev) chev.textContent = open ? '›' : '⌄';
    };

    const counts = countsByStatus();
    const backLink = scan.target
      ? `<a href="#/scans/${encodeURIComponent(scanId)}" onclick="navigate('#/scans/${encodeURIComponent(scanId)}')">${esc(scanId)}</a>`
      : esc(scanId);

    page.innerHTML = `
      <div class="breadcrumb">
        <a href="#/applications" onclick="navigate('#/applications')">Applications</a>
        <span>›</span>
        <a href="#/applications/${encodeURIComponent(scan.target)}"
           onclick="navigate('#/applications/${encodeURIComponent(scan.target)}')">${esc(scan.target)}</a>
        <span>›</span>
        <a href="#/scans/${encodeURIComponent(scanId)}"
           onclick="navigate('#/scans/${encodeURIComponent(scanId)}')">${esc(scanId)}</a>
        <span>›</span>
        <span>STIG Findings</span>
      </div>

      <div class="page-header">
        <h1>STIG Findings</h1>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          ${data.stigs.map(s => {
            const mdUrl   = s.md_url   || `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.md`;
            const cklbUrl = s.cklb_url || `/api/scans/${encodeURIComponent(scanId)}/stig-findings/${s.slug}.cklb`;
            return `
              <a class="btn btn-sm" href="${esc(mdUrl)}"   download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.md</a>
              <a class="btn btn-sm" href="${esc(cklbUrl)}" download title="${esc(s.stig_name)}">↓ ${esc(s.slug.slice(0,20))}.cklb</a>`;
          }).join('')}
        </div>
      </div>

      <div class="stig-totals-bar">
        <div class="stig-total-chip open">
          <span class="num">${counts['Open'] || 0}</span><span class="lbl">Open</span>
        </div>
        <div class="stig-total-chip pass">
          <span class="num">${counts['Not a Finding'] || 0}</span><span class="lbl">Not a Finding</span>
        </div>
        <div class="stig-total-chip na">
          <span class="num">${counts['Not Applicable'] || 0}</span><span class="lbl">N/A</span>
        </div>
        <div class="stig-total-chip nr">
          <span class="num">${counts['Not Reviewed'] || 0}</span><span class="lbl">Not Reviewed</span>
        </div>
        <div class="stig-total-chip total">
          <span class="num">${allControls.length}</span><span class="lbl">Total</span>
        </div>
      </div>

      <div id="stig-viewer-filters">${renderFilters().replace('<div class="stig-filters">', '')}</div>

      <div id="stig-viewer-body">${renderTable()}</div>`;

    // Fix up filter container id after innerHTML set
    const fEl = page.querySelector('.stig-filters');
    if (fEl) fEl.id = 'stig-viewer-filters';

  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

// ── Destructive confirm modal ─────────────────────────────────
function showDestructiveModal({ title, body, target, confirmLabel = 'Delete', onConfirm }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <h2>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <span id="modal-title">${esc(title)}</span>
      </h2>
      <p>${esc(body)}</p>
      ${target ? `<div class="modal-target">${esc(target)}</div>` : ''}
      <div class="modal-actions">
        <button class="btn" id="modal-cancel">Cancel</button>
        <button class="btn btn-danger" id="modal-confirm">${esc(confirmLabel)}</button>
      </div>
    </div>`;

  function onKey(e) {
    if (e.key === 'Escape') close();
  }

  function close() {
    document.removeEventListener('keydown', onKey);
    overlay.remove();
  }

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  overlay.querySelector('#modal-cancel').addEventListener('click', close);
  overlay.querySelector('#modal-confirm').addEventListener('click', () => {
    close();
    onConfirm();
  });
  document.addEventListener('keydown', onKey);

  document.body.appendChild(overlay);
  overlay.querySelector('#modal-confirm').focus();
}

// ── Application management helpers ───────────────────────────
async function hideApplication(name) {
  if (!confirm(`Hide "${name}" from the applications list?\n\nThe scan data will be preserved and can be restored later.`)) return;
  try {
    await api.hideApp(name);
    renderApplications();
  } catch (e) {
    alert(`Failed to hide application: ${e.message}`);
  }
}

async function restoreApplication(name) {
  try {
    await api.restoreApp(name);
    renderApplications();
  } catch (e) {
    alert(`Failed to restore application: ${e.message}`);
  }
}

async function deleteApplication(name) {
  showDestructiveModal({
    title:        'Delete Application',
    body:         'This will permanently remove all scan data from disk. This action cannot be undone.',
    target:       name,
    confirmLabel: 'Delete All Scans',
    onConfirm:    async () => {
      try {
        await api.deleteApp(name);
        navigate('#/applications');
      } catch (e) {
        alert(`Failed to delete application: ${e.message}`);
      }
    },
  });
}

async function deleteScan(scanId, appName) {
  showDestructiveModal({
    title:        'Delete Scan',
    body:         'This will permanently remove the scan directory and all its reports from disk. This action cannot be undone.',
    target:       scanId,
    confirmLabel: 'Delete Scan',
    onConfirm:    async () => {
      try {
        await api.deleteScan(scanId);
        if (appName) {
          navigate(`#/applications/${encodeURIComponent(appName)}`);
        } else {
          navigate('#/applications');
        }
      } catch (e) {
        alert(`Failed to delete scan: ${e.message}`);
      }
    },
  });
}

async function calculateScorecardForScan(scanId) {
  // Find scorecard container
  let container = document.getElementById('scorecard-container');
  if (!container) return;

  // Show loading state
  container.innerHTML = `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <rect x="3" y="3" width="18" height="18" rx="2"/>
                <path d="M3 9h18"/>
                <path d="M9 21V9"/>
              </svg>
              Security Score Card
            </span>
          </span>
          <span style="color:var(--text-muted);font-size:12px">Loading...</span>
        </summary>
      </details>
    </div>`;

  try {
    const scorecardData = await api.calculateScorecard(scanId);
    container.innerHTML = buildScorecardCard(scorecardData);
  } catch (e) {
    container.innerHTML = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:var(--critical)">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <path d="M3 9h18"/>
                  <path d="M9 21V9"/>
                </svg>
                Security Score Card
              </span>
            </span>
            <span style="color:var(--critical);font-size:12px">Error</span>
          </summary>
          <div class="findings-body" style="padding:12px 18px 16px">
            <p style="color:var(--critical);font-size:13px;margin:0"><strong>Error:</strong> ${esc(e.message)}</p>
          </div>
        </details>
      </div>`;
  }
}

// Store dimension data globally for modal access
window._scorecardDimensions = {};

function buildScorecardCard(scorecardData) {
  if (!scorecardData || !scorecardData.trl_level) return '';

  const level = scorecardData.trl_level;
  const score = (scorecardData.weighted_score || 0).toFixed(1);
  const dims = scorecardData.dimension_scores || {};
  const weights = scorecardData.weights || {};
  const blockers = scorecardData.blockers || [];

  // Map level to color and grade
  const gradeInfo = {
    9: { emoji: '🟢', label: 'A+', color: 'var(--pass, #10b981)' },
    8: { emoji: '🟢', label: 'A', color: 'var(--pass, #10b981)' },
    7: { emoji: '🟢', label: 'B+', color: 'var(--pass, #10b981)' },
    6: { emoji: '🔵', label: 'B', color: '#38bdf8' },
    5: { emoji: '🔵', label: 'C+', color: '#38bdf8' },
    4: { emoji: '🔵', label: 'C', color: '#38bdf8' },
    3: { emoji: '🟡', label: 'D', color: 'var(--medium, #f59e0b)' },
    2: { emoji: '🔴', label: 'F', color: 'var(--critical, #ef4444)' },
    1: { emoji: '🔴', label: 'F', color: 'var(--critical, #ef4444)' },
  };
  const info = gradeInfo[level] || gradeInfo[1];
  
  // Determine border color based on score
  const borderColor = score >= 70 ? 'var(--pass)' : score >= 50 ? '#38bdf8' : 'var(--critical)';

  // Build dimension cards
  const dimOrder = ['security', 'supply_chain', 'code_quality', 'compliance', 'operational', 'mosa'];
  const dimLabels = {
    security: 'Security',
    supply_chain: 'Supply Chain',
    code_quality: 'Code Quality',
    compliance: 'Compliance',
    operational: 'Operational',
    mosa: 'MOSA',
  };

  // Store dimension data globally
  window._scorecardDimensions = {};

  const dimCards = dimOrder.map(key => {
    const d = dims[key] || { score: 0, weight: 0, details: {} };
    const s = (d.score || 0).toFixed(0);
    const w = ((weights[key] || 0) * 100).toFixed(0);
    const barColor = s >= 70 ? 'var(--pass)' : s >= 50 ? 'var(--medium)' : 'var(--critical)';
    
    // Store dimension data for modal
    window._scorecardDimensions[key] = {
      key: key,
      label: dimLabels[key],
      score: s,
      weight: w,
      color: barColor,
      details: d.details || {}
    };
    
    return `
      <div class="scorecard-dim-card" onclick="showDimensionModal('${key}')" style="cursor:pointer">
        <div class="scorecard-dim-label">${esc(dimLabels[key])}</div>
        <div class="scorecard-dim-score" style="color:${barColor}">${s}</div>
        <div class="scorecard-dim-weight">${w}% weight</div>
        <div class="scorecard-dim-bar">
          <div class="scorecard-dim-bar-fill" style="width:${s}%;background:${barColor}"></div>
        </div>
        <div style="margin-top:8px;font-size:11px;color:var(--text-muted);text-align:center">Click for details</div>
      </div>`;
  }).join('');

  // Build blockers list
  const blockersHtml = blockers.length > 0 ? `
    <div class="scorecard-blockers">
      <div class="scorecard-blockers-title">⚠️ Critical Issues</div>
      <ul class="scorecard-blockers-list">
        ${blockers.map(b => `<li>${esc(b)}</li>`).join('')}
      </ul>
    </div>` : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:${borderColor}">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                   style="vertical-align:-2px;margin-right:5px">
                <rect x="3" y="3" width="18" height="18" rx="2"/>
                <path d="M3 9h18"/>
                <path d="M9 21V9"/>
              </svg>
              Security Score Card
            </span>
            <span style="margin-left:8px;font-size:24px;vertical-align:middle">${info.emoji}</span>
            <span style="margin-left:8px;font-weight:700;font-size:15px;color:${info.color}">Grade ${info.label}</span>
          </span>
          <span style="display:flex;align-items:center;gap:12px">
            <span style="font-size:18px;font-weight:700;color:var(--accent)">${score}</span>
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:16px 18px">
          <div class="scorecard-dimensions" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:${blockersHtml ? '20px' : '0'}">
            ${dimCards}
          </div>
          ${blockersHtml}
          <div style="font-size:12px;color:var(--text-muted);padding-top:16px;border-top:1px solid var(--border);margin-top:16px">
            <strong>About Scoring:</strong> Comprehensive security assessment across 6 dimensions (Security, Supply Chain, Code Quality, Compliance, Operational, MOSA). 
            Scores 70+ are production-ready, 50-69 need improvements, below 50 require immediate attention.
            <br><small><strong>MOSA</strong> = Modular Open Systems Approach: modularity, open standards, interoperability, portability. <strong>Click dimension cards for detailed breakdowns.</strong></small>
          </div>
        </div>
      </details>
    </div>`;
}

function showDimensionModal(dimensionKey) {
  const data = window._scorecardDimensions[dimensionKey];
  if (!data) {
    console.error('Dimension data not found:', dimensionKey);
    return;
  }
  
  const { key, label, score, weight, color, details } = data;

  const detailsHtml = Object.entries(details).map(([k, v]) => {
    const itemLabel = k.replace(/_/g, ' ');
    let value = v;
    if (typeof v === 'boolean') value = v ? '✓ Yes' : '✗ No';
    else if (typeof v === 'number') value = v.toFixed(1);
    return `
      <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border-muted)">
        <span style="color:var(--text-muted);font-size:14px;text-transform:capitalize">${esc(itemLabel)}</span>
        <span style="color:var(--text);font-size:14px;font-weight:600">${esc(String(value))}</span>
      </div>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container" style="max-width:600px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
        <h2 style="color:var(--text);margin:0;display:flex;align-items:center;gap:12px">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 6v6l4 2"/>
          </svg>
          ${esc(label)} Dimension
        </h2>
        <button class="btn" onclick="this.closest('.modal-overlay').remove()" style="padding:6px 12px">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>

      <div style="background:var(--bg-card);border-radius:var(--radius);padding:24px;margin-bottom:24px;text-align:center;border:2px solid ${color}">
        <div style="font-size:64px;font-weight:700;color:${color};margin-bottom:8px">${score}</div>
        <div style="font-size:14px;color:var(--text-muted);margin-bottom:4px">Score out of 100</div>
        <div style="font-size:13px;color:var(--text-muted)">${weight}% of overall score</div>
        <div style="margin:16px auto 0;max-width:300px">
          <div style="height:16px;background:var(--bg);border-radius:8px;overflow:hidden">
            <div style="width:${score}%;height:100%;background:${color};transition:width 0.3s ease"></div>
          </div>
        </div>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px">
        <h3 style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 16px;text-transform:uppercase;letter-spacing:0.5px">Detailed Metrics</h3>
        ${detailsHtml || '<div style="color:var(--text-muted);font-size:13px;text-align:center;padding:20px 0">No detailed metrics available for this dimension.</div>'}
      </div>
    </div>`;
  
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.remove();
  });
}



function showAddAppModal() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  // ── Step 1 HTML ────────────────────────────────────────────
  const step1HTML = `
    <div id="add-app-step1">
      <h2 id="add-app-title" style="color:var(--text)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="16"/>
          <line x1="8" y1="12" x2="16" y2="12"/>
        </svg>
        Add Application
      </h2>
      <p style="color:var(--text-muted);font-size:13px;margin:0 0 16px">
        Register a GitHub repository with Epyon. A name will be auto-suggested from the URL.
      </p>

      <div class="form-group">
        <label for="add-app-url" style="font-size:13px;color:var(--text-muted);margin-bottom:4px;display:block">
          Repository URL <span style="color:var(--critical)">*</span>
        </label>
        <input type="text" id="add-app-url" autocomplete="off" spellcheck="false"
          placeholder="https://github.com/org/my-app.git"
          style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);
                 border-radius:var(--radius);color:var(--text);font-size:13px;outline:none" />
      </div>

      <div class="form-group" style="margin-top:12px">
        <label for="add-app-name" style="font-size:13px;color:var(--text-muted);margin-bottom:4px;display:block">
          Application Name <span style="color:var(--critical)">*</span>
        </label>
        <input type="text" id="add-app-name" autocomplete="off" spellcheck="false"
          placeholder="my-app"
          style="width:100%;padding:8px 10px;background:var(--bg-input);border:1px solid var(--border);
                 border-radius:var(--radius);color:var(--text);font-size:13px;outline:none" />
        <small style="font-size:11px;color:var(--text-dim)">Alphanumeric, hyphens, underscores, and dots only</small>
      </div>

      <div style="margin-top:12px;display:flex;align-items:center;gap:8px">
        <input type="checkbox" id="add-app-scan" style="accent-color:var(--accent)" />
        <label for="add-app-scan" style="font-size:13px;color:var(--text-muted);cursor:pointer">
          Run a full scan immediately after adding
        </label>
      </div>

      <div id="add-app-error" style="display:none;margin-top:12px;color:var(--critical);font-size:12px"></div>

      <div class="modal-actions" style="margin-top:20px">
        <button class="btn" id="add-app-cancel">Cancel</button>
        <button class="btn btn-primary" id="add-app-next">Next: Workflow Setup →</button>
      </div>
    </div>`;

  // ── Step 2 HTML ────────────────────────────────────────────
  const workflowYml = WORKFLOW_YML;

  const step2HTML = `
    <div id="add-app-step2" style="display:none">
      <h2 id="add-app-title" style="color:var(--text)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
        </svg>
        GitHub Workflow Setup
      </h2>
      <p style="color:var(--text-muted);font-size:13px;margin:0 0 14px">
        To enable automated nightly scans, add the Epyon workflow file to your repository.
        Follow the steps below, then Epyon will pick up scan results automatically.
      </p>

      <ol style="padding-left:18px;margin:0 0 14px;font-size:13px;color:var(--text-muted);line-height:1.9">
        <li>In your repository, create the directory <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">.github/workflows/</code> if it doesn't exist.</li>
        <li>Add a new file named <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">scan-private-repo.yml</code> with the contents below.</li>
        <li>Review the workflow references and update the GitHub org or user only if the sample points to a different Epyon host than yours.</li>
        <li>Commit and push — the workflow will run nightly at 2 AM UTC and on manual dispatch.</li>
      </ol>

      <div style="position:relative">
        <pre id="add-app-yml" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);
             padding:12px;font-size:11px;line-height:1.6;overflow-x:auto;margin:0;white-space:pre;color:var(--text)">${workflowYml}</pre>
        <button id="add-app-copy"
          style="position:absolute;top:8px;right:8px;padding:3px 10px;font-size:11px;
                 background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
                 color:var(--text-muted);cursor:pointer">Copy</button>
      </div>

      <p style="font-size:12px;color:var(--text-dim);margin:10px 0 0">
        The full workflow with all optional parameters is available in
        <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">documentation/scan-private-repo.yml</code>
        in the Epyon repo.
      </p>

      <div class="modal-actions" style="margin-top:20px">
        <button class="btn" id="add-app-back">← Back</button>
        <button class="btn btn-primary" id="add-app-submit">Add Application</button>
      </div>
    </div>`;

  overlay.innerHTML = `
    <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="add-app-title"
         style="max-width:540px">
      ${step1HTML}
      ${step2HTML}
    </div>`;

  function onKey(e) { if (e.key === 'Escape') close(); }

  function close() {
    document.removeEventListener('keydown', onKey);
    overlay.remove();
  }

  // ── Step navigation ────────────────────────────────────────
  const s1 = overlay.querySelector('#add-app-step1');
  const s2 = overlay.querySelector('#add-app-step2');

  function showStep(n) {
    s1.style.display = n === 1 ? '' : 'none';
    s2.style.display = n === 2 ? '' : 'none';
  }

  // ── Step 1 inputs ──────────────────────────────────────────
  const urlInput  = overlay.querySelector('#add-app-url');
  const nameInput = overlay.querySelector('#add-app-name');

  urlInput.addEventListener('input', () => {
    const raw = urlInput.value.trim();
    const derived = raw
      .replace(/\.git$/i, '')
      .split('/')
      .filter(Boolean)
      .pop() || '';
    if (derived && !nameInput._manuallyEdited) {
      nameInput.value = derived.replace(/[^a-zA-Z0-9._-]/g, '-');
    }
  });
  nameInput.addEventListener('input', () => { nameInput._manuallyEdited = true; });

  overlay.querySelector('#add-app-cancel').addEventListener('click', close);

  overlay.querySelector('#add-app-next').addEventListener('click', () => {
    const errEl = overlay.querySelector('#add-app-error');
    errEl.style.display = 'none';
    if (!urlInput.value.trim()) {
      errEl.textContent = 'Repository URL is required.';
      errEl.style.display = 'block';
      urlInput.focus();
      return;
    }
    if (!nameInput.value.trim()) {
      errEl.textContent = 'Application name is required.';
      errEl.style.display = 'block';
      nameInput.focus();
      return;
    }
    showStep(2);
  });

  // ── Step 2 controls ────────────────────────────────────────
  overlay.querySelector('#add-app-back').addEventListener('click', () => showStep(1));

  overlay.querySelector('#add-app-copy').addEventListener('click', function () {
    navigator.clipboard.writeText(workflowYml).then(() => {
      this.textContent = 'Copied!';
      setTimeout(() => { this.textContent = 'Copy'; }, 2000);
    });
  });

  overlay.querySelector('#add-app-submit').addEventListener('click', async () => {
    const url     = urlInput.value.trim();
    const name    = nameInput.value.trim();
    const scanNow = overlay.querySelector('#add-app-scan').checked;
    const btn     = overlay.querySelector('#add-app-submit');

    btn.disabled = true;
    btn.textContent = 'Adding…';
    try {
      await api.registerApp(name, url);
      close();
      if (scanNow) {
        navigate(`#/new-scan?target=${encodeURIComponent(url)}`);
      } else {
        navigate('#/applications');
        renderApplications();
      }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Add Application';
      // Show error back on step 1
      showStep(1);
      const errEl = overlay.querySelector('#add-app-error');
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    }
  });

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', onKey);

  document.body.appendChild(overlay);
  urlInput.focus();
}

// ── Router ────────────────────────────────────────────────────
function resolve() {
  const hash = window.location.hash.slice(1) || '/';

  const qIdx   = hash.indexOf('?');
  const path   = qIdx === -1 ? hash : hash.slice(0, qIdx);
  const params = new URLSearchParams(qIdx === -1 ? '' : hash.slice(qIdx + 1));

  if (path === '/' || path === '') {
    renderOverview();
  } else if (path === '/applications') {
    renderApplications();
  } else if (path.startsWith('/applications/')) {
    const name = decodeURIComponent(path.slice('/applications/'.length));
    name ? renderAppDetail(name) : renderApplications();
  } else if (path.startsWith('/stig-viewer/')) {
    const scanId = decodeURIComponent(path.slice('/stig-viewer/'.length));
    scanId ? renderStigViewer(scanId) : renderStig();
  } else if (path.startsWith('/scans/')) {
    const scanId = decodeURIComponent(path.slice('/scans/'.length));
    scanId ? renderScanDetail(scanId) : renderApplications();
  } else if (path === '/new-scan') {
    renderNewScan(params.get('target') || '');
  } else if (path === '/metrics') {
    renderMetrics();
  } else if (path === '/github-signals') {
    renderGitHubSignals();
  } else if (path === '/stig') {
    if (params.get('view') === 'history') {
      renderStigHistory(params.get('app') || null, params.get('slug') || null);
    } else {
      renderStig();
    }
  } else if (path === '/settings') {
    renderSettings();
  } else {
    renderOverview();
  }
}

window.addEventListener('hashchange', resolve);
window.addEventListener('load', () => {
  // In static (offline) mode the scan is embedded — skip API-based routing
  if (window.__SCAN__) return;
  resolve();
  api._get('/api/health').then(h => {
    const el = document.getElementById('sidebar-version');
    if (el && h.version) el.textContent = 'Epyon v' + h.version;
  }).catch(() => {});
});

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
        <code style="font-size:11px;word-break:break-all">${esc(p.purl)}</code>
        ${purlUrl ? `<a href="${esc(purlUrl)}" target="_blank" rel="noopener noreferrer"
             style="font-size:11px;white-space:nowrap;color:#6366f1">
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
          ${p.language ? `<span class="tool-tag" style="background:#1e3a5f;color:#93c5fd">${esc(p.language)}</span>` : ''}
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
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

  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
};

// ── STIG control detail drawer ────────────────────────────────
let _stigDetailNextId = 0;
const _stigDetailRegistry = new Map();

function _registerStigDetail(c) {
  const id = _stigDetailNextId++;
  _stigDetailRegistry.set(id, c);
  return id;
}

function openStigDetail(id) {
  const c = _stigDetailRegistry.get(id);
  if (!c) return;
  closeFindingDetail();

  const _SC = { 'Open': 'open', 'Not a Finding': 'not-a-finding', 'Not Applicable': 'na', 'Not Reviewed': 'not-reviewed' };
  const _SA = { 'Open': 'Open', 'Not a Finding': 'Pass', 'Not Applicable': 'N/A', 'Not Reviewed': 'Not Reviewed' };

  const sev     = c.severity || 'unknown';
  const sevCls  = sev.toLowerCase();
  const latCls  = _SC[c.latest_status] || 'not-reviewed';
  const latLbl  = _SA[c.latest_status] || c.latest_status || '—';

  const tl = [...(c.timeline || [])].sort((a, b) => b.date.localeCompare(a.date));
  const timelineRows = tl.map((t, idx) => {
    const cls = _SC[t.status] || 'not-reviewed';
    const lbl = _SA[t.status] || t.status;
    const evidence = t.evidence || 'No evidence provided.';
    const confidence = t.confidence != null ? `${t.confidence}%` : '—';
    
    // Check if evidence changed from previous scan (next in array = older in time)
    const prevEvidence = idx < tl.length - 1 ? (tl[idx + 1].evidence || '') : '';
    const evidenceChanged = prevEvidence && evidence && prevEvidence !== evidence && t.status !== 'Not Reviewed';
    const changeClass = evidenceChanged ? ' style="background:var(--bg-hover)"' : '';
    const changeIcon = evidenceChanged ? ' <span style="color:var(--accent);font-size:10px" title="Evidence changed from previous scan">🔄 Changed</span>' : '';
    
    return `<tr${changeClass}>
      <td style="padding:8px 12px;font-size:12px;color:var(--text-muted);white-space:nowrap;vertical-align:top">${esc(t.date.slice(0, 10))}</td>
      <td style="padding:8px 12px;vertical-align:top"><span class="stig-status-chip ${cls}">${esc(lbl)}</span>${changeIcon}</td>
      <td style="padding:8px 12px;font-size:11px;color:var(--text-muted);text-align:center;vertical-align:top">${confidence}</td>
      <td style="padding:8px 12px;font-size:11px;color:var(--text);line-height:1.5;vertical-align:top">${esc(evidence).replace(/\n/g, '<br>')}</td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'STIG control details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id || '—')}</h2>
        <div class="finding-drawer-badges">
          <span class="sev-badge ${esc(sevCls)}">${ucFirst(sev)}</span>
          <span class="tool-tag">STIG</span>
          <code>${esc(c.vuln_id)}</code>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Current Status</div>
          <div class="finding-detail-value"><span class="stig-status-chip ${latCls}">${esc(latLbl)}</span></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Benchmark</div>
          <div class="finding-detail-value">${c.stig_name ? `<code style="font-size:11px">${esc(c.stig_name)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Open</div>
          <div class="finding-detail-value">${c.first_open ? esc(c.first_open.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Closed</div>
          <div class="finding-detail-value">${c.first_closed ? esc(c.first_closed.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">MTTR</div>
          <div class="finding-detail-value">${c.mttr_days != null ? `<strong>${c.mttr_days} days</strong>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
      </div>
      ${tl.length ? `
      <div class="finding-detail-section">
        <div class="finding-detail-label">Scan History</div>
        <div class="finding-detail-desc" style="padding:0;background:none;border:1px solid var(--border-muted);border-radius:var(--radius);overflow:hidden">
          <table style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="background:var(--bg-hover);border-bottom:1px solid var(--border)">
                <th style="padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:100px">Date</th>
                <th style="padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:140px">Status</th>
                <th style="padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:center;width:80px">Confidence</th>
                <th style="padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left">Evidence / Reasoning</th>
              </tr>
            </thead>
            <tbody>${timelineRows}</tbody>
          </table>
        </div>
      </div>` : ''}
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
}

// ── Finding detail drawer ─────────────────────────────────────
function _registerFinding(f) {
  const id = _findingNextId++;
  _findingsRegistry.set(id, f);
  return id;
}

function openFindingDetail(id) {
  const f = _findingsRegistry.get(id);
  if (!f) return;

  // Close any existing drawer
  closeFindingDetail();

  const sev     = f.severity || 'unknown';
  const fid     = f.id || '—';
  const tool    = f.tool || '—';
  const title   = f.title || f.description || '—';
  const desc    = f.description || '';
  const pkg     = f.package || f.component || '';
  const ver     = f.version || '';
  const fixed   = f.fixed_version || '';
  const target  = f.target || '';
  const line    = f.line ? String(f.line) : '';
  const refs    = f.references || [];
  const cisaKev  = f.cisa_kev === true;
  const cvssScore = f.nvd_cvss_v3_score != null ? f.nvd_cvss_v3_score : null;
  const cvssSev   = f.nvd_cvss_v3_severity || '';
  const nvdUrl    = f.nvd_url || (fid.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${fid}` : '');

  const idDisplay = fid.startsWith('CVE-')
    ? `<a class="finding-detail-id-link"
          href="${esc(nvdUrl || 'https://nvd.nist.gov/vuln/detail/' + esc(fid))}"
          target="_blank" rel="noopener noreferrer">
         ${esc(fid)}
         <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
           <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
           <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
         </svg>
       </a>${cisaKev ? ' <span style="background:#7f1d1d;color:#fca5a5;font-size:11px;font-weight:700;padding:2px 7px;border-radius:4px" title="CISA Known Exploited Vulnerability">KEV</span>' : ''}`
    : `<code>${esc(fid)}</code>`;

  const refsHtml = refs.length
    ? `<div class="finding-detail-section">
         <div class="finding-detail-label">References</div>
         <div class="finding-detail-refs">
           ${refs.map(r => `<a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a>`).join('')}
         </div>
       </div>`
    : '';

  const descSection = desc && desc !== title
    ? `<div class="finding-detail-section">
         <div class="finding-detail-label">Description</div>
         <div class="finding-detail-desc">${esc(desc)}</div>
       </div>`
    : '';

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'Finding details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(title)}</h2>
        <div class="finding-drawer-badges">
          <span class="sev-badge ${esc(sev)}">${ucFirst(sev)}</span>
          <span class="tool-tag">${esc(tool)}</span>
          ${idDisplay}
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Package / Component</div>
          <div class="finding-detail-value">${pkg ? `<code>${esc(pkg)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Version</div>
          <div class="finding-detail-value">${ver ? `<code>${esc(ver)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Fix Available</div>
          <div class="finding-detail-value">${fixed
            ? `<code style="color:var(--clean)">${esc(fixed)}</code>`
            : '<span style="color:var(--text-dim)">None known</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Severity</div>
          <div class="finding-detail-value"><span class="sev-badge ${esc(sev)}">${ucFirst(sev)}</span>${cvssScore != null ? ` <span style="color:var(--text-muted);font-size:12px">CVSS ${esc(String(cvssScore))}${cvssSev ? ' · ' + esc(cvssSev) : ''}</span>` : ''}</div>
        </div>
      </div>

      ${cisaKev ? `
        <div style="background:#450a0a;border:1px solid #7f1d1d;border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px">
          <span style="font-size:16px">⚠️</span>
          <div>
            <div style="color:#fca5a5;font-weight:600;font-size:13px">CISA Known Exploited Vulnerability (KEV)</div>
            <div style="color:#fca5a5;font-size:12px;margin-top:2px">This CVE is actively exploited in the wild. CISA mandates remediation for federal agencies. Treat as highest priority.</div>
          </div>
        </div>` : ''}

      ${target ? `
        <div class="finding-detail-section">
          <div class="finding-detail-label">File Path</div>
          <div class="finding-detail-value"><code style="word-break:break-all">${esc(target)}</code>${line ? ` <span style="color:var(--text-muted);font-size:11px">line ${esc(line)}</span>` : ''}</div>
        </div>` : ''}

      ${descSection}

      ${refsHtml}

      <div id="finding-fix-section" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
        <button id="finding-fix-btn" onclick="fetchFindingFix(${id})" style="display:flex;align-items:center;gap:6px;padding:7px 14px;border-radius:var(--radius);border:1px solid #6366f1;background:rgba(99,102,241,0.08);color:#818cf8;font-size:12.5px;cursor:pointer;font-weight:500;transition:background 0.12s">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          Suggest Fix with AI
        </button>
        <div id="finding-fix-result"></div>
      </div>

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  // Trap Escape key
  const _onKey = e => { if (e.key === 'Escape') { closeFindingDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
}

function closeFindingDetail() {
  const overlay = document.getElementById('finding-drawer-overlay');
  const drawer  = document.getElementById('finding-drawer');
  if (drawer && drawer._onKey) document.removeEventListener('keydown', drawer._onKey);
  overlay?.remove();
  drawer?.remove();
}

// ── GitHub Signals detail drawer ──────────────────────────────
function openGhSignalDetail(kind, idx) {
  if (!_ghSignalData) return;
  closeGhSignalDetail();

  let title = '', bodyHtml = '', repoUrl = '';

  if (kind === 'dep') {
    const r = _ghSignalData.dep[idx];
    if (!r) return;
    const sev = r.by_severity || {};
    const repoShort = r.repo.split('/')[1] || r.repo;
    repoUrl = `https://github.com/${r.repo}/security/dependabot`;
    title = `Dependabot — ${repoShort}`;
    const pkgRows = (r.top_packages || []).map(p =>
      `<tr><td><code>${esc(p.package)}</code></td><td style="text-align:right;padding-left:16px">${p.count} alert${p.count !== 1 ? 's' : ''}</td></tr>`
    ).join('');
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Repository</div>
          <div class="finding-detail-value"><code>${esc(r.repo)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Open Alerts</div>
          <div class="finding-detail-value" style="color:${(r.open||0)>0?'var(--critical)':'var(--clean)'};font-weight:700;font-size:22px">${r.open || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Fixed by Dependabot</div>
          <div class="finding-detail-value" style="color:var(--clean);font-weight:600">${r.fixed || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Dismissed</div>
          <div class="finding-detail-value">${r.dismissed || 0}</div>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">By Severity</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(255,123,114,.15);color:#ff7b72;padding:4px 10px;border-radius:6px;font-weight:700">Critical: ${sev.critical||0}</span>
          <span style="background:rgba(255,166,87,.15);color:#ffa657;padding:4px 10px;border-radius:6px;font-weight:700">High: ${sev.high||0}</span>
          <span style="background:rgba(227,179,65,.15);color:#e3b341;padding:4px 10px;border-radius:6px;font-weight:700">Medium: ${sev.medium||0}</span>
          <span style="background:rgba(121,192,255,.15);color:#79c0ff;padding:4px 10px;border-radius:6px;font-weight:700">Low: ${sev.low||0}</span>
        </div>
      </div>
      ${pkgRows ? `
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Top Affected Packages</div>
        <table style="margin-top:8px;width:100%;font-size:13px"><tbody>${pkgRows}</tbody></table>
      </div>` : ''}
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <a href="${esc(repoUrl)}" target="_blank" rel="noopener noreferrer"
           style="display:inline-flex;align-items:center;gap:6px;color:#79c0ff;font-size:13px;text-decoration:none">
          View on GitHub
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
      </div>`;

  } else if (kind === 'sec') {
    const r = _ghSignalData.sec[idx];
    if (!r) return;
    const repoShort = r.repo.split('/')[1] || r.repo;
    repoUrl = `https://github.com/${r.repo}/issues?q=is%3Aissue+label%3Asecurity`;
    title = `Security Issues — ${repoShort}`;
    const mttr = r.avg_close_days != null
      ? `<span style="color:${r.avg_close_days <= 7 ? 'var(--clean)' : r.avg_close_days <= 30 ? '#e3b341' : 'var(--critical)'};font-weight:600">${r.avg_close_days} days</span>`
      : '<span style="color:var(--text-muted)">—</span>';
    bodyHtml = `
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Repository</div>
          <div class="finding-detail-value"><code>${esc(r.repo)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Open Security Issues</div>
          <div class="finding-detail-value" style="color:${(r.open_security||0)>0?'var(--high)':'var(--clean)'};font-weight:700;font-size:22px">${r.open_security || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Closed Security Issues</div>
          <div class="finding-detail-value" style="color:var(--clean);font-weight:600">${r.closed_security || 0}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Avg Days to Close (MTTR)</div>
          <div class="finding-detail-value">${mttr}</div>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <a href="${esc(repoUrl)}" target="_blank" rel="noopener noreferrer"
           style="display:inline-flex;align-items:center;gap:6px;color:#79c0ff;font-size:13px;text-decoration:none">
          View on GitHub
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
      </div>`;

  } else if (kind === 'run') {
    const r = _ghSignalData.run[idx];
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
           style="display:inline-flex;align-items:center;gap:6px;color:#79c0ff;font-size:13px;text-decoration:none">
          View Actions on GitHub
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </a>
      </div>`;

  } else if (kind === 'cov') {
    const [name, v] = _ghSignalData.cov[idx] || [];
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
          <div style="flex:1;background:#30363d;border-radius:6px;height:12px;overflow:hidden">
            <div style="width:${Math.min(pct,100)}%;background:${barColor};height:100%;border-radius:6px;transition:width .3s"></div>
          </div>
          <span style="font-weight:700;color:${barColor}">${pct}%</span>
        </div>
      </div>
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Scan Breakdown</div>
        <div style="display:flex;gap:12px;margin-top:6px;flex-wrap:wrap">
          <span style="background:rgba(121,192,255,.12);color:#79c0ff;padding:4px 10px;border-radius:6px;font-weight:700">PR: ${v.pr_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Push: ${v.push_scans}</span>
          <span style="background:rgba(139,148,158,.12);color:var(--text-muted);padding:4px 10px;border-radius:6px;font-weight:700">Other: ${v.other_scans}</span>
        </div>
      </div>
      <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
        <button onclick="closeGhSignalDetail();navigate('#/applications/${encodeURIComponent(name)}')"
          style="display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:rgba(99,102,241,0.08);color:#818cf8;font-size:12.5px;cursor:pointer;font-weight:500">
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
      <button class="finding-drawer-close" onclick="closeGhSignalDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">${bodyHtml}</div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  const _onKey = e => { if (e.key === 'Escape') { closeGhSignalDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
}

function closeGhSignalDetail() {
  const overlay = document.getElementById('gh-signal-drawer-overlay');
  const drawer  = document.getElementById('gh-signal-drawer');
  if (drawer && drawer._onKey) document.removeEventListener('keydown', drawer._onKey);
  overlay?.remove();
  drawer?.remove();
}

// ── API endpoint detail drawer ────────────────────────────────
function openAPIDetail(id) {
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
      <button class="finding-drawer-close" onclick="closeAPIDetail()" aria-label="Close">✕</button>
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
          <div class="finding-detail-value">${auth !== 'None' ? `<code style="font-size:11px">${esc(auth)}</code>` : '<span style="color:var(--text-dim)">None</span>'}</div>
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
        <div class="finding-detail-value"><code style="font-size:11px;word-break:break-all">${esc(file)}</code></div>
      </div>

      ${Array.isArray(params) && params.length > 0 ? `
        <div class="finding-detail-section" style="margin-top:16px">
          <div class="finding-detail-label">Parameters</div>
          <div style="margin-top:6px">
            ${params.map(p => `
              <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                  <code style="color:#818cf8;font-size:12px">${esc(p.name || '')}</code>
                  ${p.required ? '<span style="color:#ef4444;font-size:10px;font-weight:600">REQUIRED</span>' : ''}
                </div>
                ${p.type ? `<div style="color:var(--text-muted);font-size:11px">Type: <code>${esc(p.type)}</code></div>` : ''}
                ${p.description ? `<div style="color:var(--text-dim);font-size:11px;margin-top:3px">${esc(p.description)}</div>` : ''}
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
                  <code style="color:#10b981;font-size:12px">${esc(String(r.status || r.code || ''))}</code>
                  <span style="color:var(--text-muted);font-size:11px">${esc(r.description || '')}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>` : ''}

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

  // Trap Escape key
  const _onKey = e => { if (e.key === 'Escape') { closeAPIDetail(); document.removeEventListener('keydown', _onKey); } };
  document.addEventListener('keydown', _onKey);
  drawer._onKey = _onKey;
}

function closeAPIDetail() {
  const overlay = document.getElementById('api-drawer-overlay');
  const drawer  = document.getElementById('api-drawer');
  if (drawer && drawer._onKey) document.removeEventListener('keydown', drawer._onKey);
  overlay?.remove();
  drawer?.remove();
}

// ── AI fix suggestion ─────────────────────────────────────────
window.fetchFindingFix = async function(fid) {
  const f = _findingsRegistry.get(fid);
  if (!f) return;

  const btn    = document.getElementById('finding-fix-btn');
  const result = document.getElementById('finding-fix-result');
  if (!btn || !result) return;

  btn.disabled = true;
  btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-.08-4.04"/></svg> Generating…`;

  const payload = {
    id:            f.id || undefined,
    title:         f.title || f.description || undefined,
    description:   f.description !== f.title ? f.description : undefined,
    tool:          f.tool || undefined,
    severity:      f.severity || undefined,
    package:       f.package || f.component || undefined,
    version:       f.version || undefined,
    fixed_version: f.fixed_version || undefined,
    target:        f.target || undefined,
    references:    (f.references || []).slice(0, 3),
  };
  // strip undefined
  Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

  try {
    const data = await api.getFindingFix(payload);
    btn.style.display = 'none';
    result.innerHTML = `
      <div style="margin-top:12px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.25);border-radius:var(--radius);padding:14px 16px;font-size:13px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;color:#818cf8;font-size:12px;font-weight:600">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          AI-SUGGESTED FIX
        </div>
        <div class="ai-fix-body">${renderMarkdown(data.fix || '')}</div>
      </div>`;
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Suggest Fix with AI`;
    result.innerHTML = `<div style="margin-top:8px;color:var(--critical);font-size:12px">${esc(err.message)}</div>`;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// STATIC RENDER MODE
// When the page is a self-contained HTML file (generated by generate-dashboard.py),
// window.__SCAN__ is set to the full scan data object. We render the scan detail
// page directly without any API calls or navigation.
// ─────────────────────────────────────────────────────────────────────────────

function renderStaticScanDetail(scan) {
  const page = document.getElementById('page');
  if (!page) return;

  const status  = computeStatus(scan);
  const scanId  = scan.scan_id || '';

  // ── STIG card (same logic as renderScanDetail, minus navigate() buttons) ──
  const hasStigData    = (scan.stig_total || 0) > 0;
  const scanTypeHasStig = ['stig', 'nightly', 'full', 'baseline'].includes(scan.scan_type);
  let stigCard = '';
  if (hasStigData) {
    const reports  = scan.stig_reports || [];
    const multiStig = reports.length > 1;

      const perStigRows = multiStig ? reports.map(r => {
      const slugLabel = r.slug.replace(/-/g, ' ').replace(/\bstig\b/gi, 'STIG');
      return `
        <div class="stig-row">
          <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
          <span class="stig-row-counts">
            <span class="stig-mini open">${esc(r.open)} open</span>
            <span class="stig-mini pass">${esc(r.pass)} pass</span>
            <span class="stig-mini na">${esc(r.na)} n/a</span>
            ${(r.nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(r.nr)} not reviewed</span>` : ''}
            <span class="stig-mini total">${esc(r.total)} total</span>
          </span>
        </div>`;
    }).join('') : '';

    stigCard = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:#38bdf8">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                STIG Assessment${multiStig ? ` <span style="color:var(--text-muted);font-weight:400;font-size:12px">(${reports.length} STIGs)</span>` : ''}
              </span>
              <span class="stig-mini open">${esc(scan.stig_open || 0)} open</span>
              <span class="stig-mini pass">${esc(scan.stig_pass || 0)} pass</span>
              <span class="stig-mini na">${esc(scan.stig_na || 0)} n/a</span>
              ${(scan.stig_nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(scan.stig_nr || 0)} not reviewed</span>` : ''}
              <span class="stig-mini total">${esc(scan.stig_total || 0)} total</span>
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body" style="padding:0 18px 16px">
            <div class="stig-counts" style="margin-top:12px">
              <div class="stig-count open"><span class="num">${esc(scan.stig_open  || 0)}</span><span class="lbl">Open</span></div>
              <div class="stig-count pass"><span class="num">${esc(scan.stig_pass  || 0)}</span><span class="lbl">Not a Finding</span></div>
              <div class="stig-count na"  ><span class="num">${esc(scan.stig_na    || 0)}</span><span class="lbl">Not Applicable</span></div>
              ${(scan.stig_nr || 0) > 0 ? `<div class="stig-count" style="background:var(--bg-input);border-color:var(--border)"><span class="num" style="color:var(--text-muted)">${esc(scan.stig_nr || 0)}</span><span class="lbl">Not Reviewed</span></div>` : ''}
              <div class="stig-count total"><span class="num">${esc(scan.stig_total|| 0)}</span><span class="lbl">Total</span></div>
            </div>
            ${multiStig ? `<div class="stig-per-stig">${perStigRows}</div>` : ''}
          </div>
        </details>
      </div>`;
  } else {
    const noStigMsg = scanTypeHasStig
      ? 'No STIG results were recorded for this scan.'
      : 'STIG assessment is not included in this scan type.';
    stigCard = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:var(--border)">
          <summary class="findings-summary">
            <span class="findings-summary-left">
              <span class="findings-chevron" aria-hidden="true"></span>
              <span class="findings-summary-title">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                     style="vertical-align:-2px;margin-right:5px">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                STIG Assessment
              </span>
            </span>
            <span class="findings-summary-hint">Click to expand</span>
          </summary>
          <div class="findings-body" style="padding:12px 18px 16px">
            <p style="color:var(--text-muted);font-size:13px;margin:0">${noStigMsg}</p>
          </div>
        </details>
      </div>`;
  }

  // ── CI source badge ────────────────────────────────────────────────────────
  const ci = scan.ci_source;
  const ciBadge = ci ? `
    <div class="detail-card">
      <div class="label">CI Source</div>
      <div class="value" style="font-size:12px">
        ${ci.repo ? `<a href="https://github.com/${esc(ci.repo)}" target="_blank" rel="noopener"
            style="color:var(--accent)">${esc(ci.repo)}</a>` : '—'}
        ${ci.branch ? `<span style="color:var(--text-muted)"> @ ${esc(ci.branch)}</span>` : ''}
      </div>
    </div>` : '';

  page.innerHTML = `
    <div class="breadcrumb">
      <span>${esc(scan.target || '—')}</span>
      <span>›</span>
      <span>${esc(scanId)}</span>
    </div>

    <div class="page-header">
      <h1>Scan Details ${statusBadge(status)}</h1>
    </div>

    <div class="detail-grid">
      <div class="detail-card">
        <div class="label">Application</div>
        <div class="value">${esc(scan.target || '—')}</div>
      </div>
      <div class="detail-card">
        <div class="label">Scan Type</div>
        <div class="value">${esc(scanTypeLabel(scan.scan_type))}</div>
      </div>
      <div class="detail-card">
        <div class="label">User</div>
        <div class="value">${esc(scan.user || '—')}</div>
      </div>
      <div class="detail-card">
        <div class="label">Timestamp</div>
        <div class="value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
      </div>
      ${ciBadge}
    </div>

    <div class="result-section-box">
      <div class="result-section-box-title">Vulnerabilities</div>
      <div class="detail-grid" style="margin-bottom:0">
        <div class="detail-card">
          <div class="label">Critical</div>
          <div class="value" style="color:var(--critical)">${esc(scan.critical)}</div>
        </div>
        <div class="detail-card">
          <div class="label">High</div>
          <div class="value" style="color:var(--high)">${esc(scan.high)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Medium</div>
          <div class="value" style="color:var(--medium)">${esc(scan.medium)}</div>
        </div>
        <div class="detail-card">
          <div class="label">Low</div>
          <div class="value" style="color:var(--low)">${esc(scan.low)}</div>
        </div>
      </div>
    </div>

    ${buildFindingsSection(scan.findings)}

    ${buildSuppressedSection(scan.suppressed_findings)}

    ${stigCard}

    ${buildModelSecurityCard(scan)}

    ${buildSBOMSection(scan.sbom, null)}

    ${buildAPISection(scan.api_discovery)}

    ${buildNetworkDiscoveryCard(scan)}

    ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
      <div class="section">
        <div class="section-title">File Statistics</div>
        <div class="detail-grid">
          ${Object.entries(scan.file_statistics).map(([k, v]) => `
            <div class="detail-card">
              <div class="label">${esc(k.replace(/_/g, ' '))}</div>
              <div class="value">${esc(v)}</div>
            </div>`).join('')}
        </div>
      </div>` : ''}

    <div id="scorecard-container">${scan.scorecard ? buildScorecardCard(scan.scorecard) : ''}</div>

    ${dedupeTools(scan.tools_analyzed || []).length ? `
      <div class="section">
        <div class="section-title">Tools Analyzed</div>
        <div class="tools-list">
          ${dedupeTools(scan.tools_analyzed).map(t =>
            `<span class="tool-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>` : ''}`;
  if (window._sbomPendingUid) { sbomRender(window._sbomPendingUid); window._sbomPendingUid = null; }
  if (window._apiPendingUid)  { apiRender(window._apiPendingUid);   window._apiPendingUid  = null; }
}

// Static entry point — runs when this JS is embedded in a generated dashboard
if (typeof window !== 'undefined' && window.__SCAN__) {
  document.addEventListener('DOMContentLoaded', function () {
    renderStaticScanDetail(window.__SCAN__);
  });
}
