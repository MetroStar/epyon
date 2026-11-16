import { esc } from '../lib/format.js';
import { navigate } from '../core/router.js';

// ── Chart helpers ─────────────────────────────────────────────
export const _CC = {
  critical: '#ff7b72', high: '#ffa657', medium: '#e3b341', low: '#79c0ff',
};

export function _getTooltip() {
  let tt = document.getElementById('chart-tooltip');
  if (!tt) {
    tt = document.createElement('div');
    tt.id = 'chart-tooltip';
    tt.className = 'chart-tooltip';
    document.body.appendChild(tt);
  }
  return tt;
}

export function _showTooltip(e, html) {
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

export function _hideTooltip() {
  const tt = document.getElementById('chart-tooltip');
  if (tt) tt.style.display = 'none';
}

export function drawDonutChart(canvas, segments) {
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

export function drawHBarChart(canvas, items) {
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

export function drawLineChart(canvas, series, xLabels) {
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

export function drawStackedBarChart(canvas, series, xLabels, barData) {
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
      `<span style="color:var(--critical)">■</span> ${c}&ensp;` +
      `<span style="color:var(--high)">■</span> ${hv}&ensp;` +
      `<span style="color:var(--medium)">■</span> ${mv}&ensp;` +
      `<span style="color:var(--accent)">■</span> ${lv}`
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
