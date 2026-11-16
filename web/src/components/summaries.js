import { toast } from './feedback.js';
import { api } from '../lib/api.js';
import { esc, renderMarkdown, act } from '../lib/format.js';

export function buildOverviewExecSection() {
  const tip = 'Requires an OpenAI API key configured in Settings.';
  return `
    <div class="section" id="overview-summary-section">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-primary" ${act('generateOverviewExecSummary')}
                title="Leadership brief across all tracked applications, split by monitoring status. ${tip}">
          ✦ Generate Executive Summary
        </button>
        <button class="btn btn-primary" ${act('generateOverviewTechSummary')}
                title="Detailed technical brief for engineering teams, with per-finding breakdown. ${tip}">
          ✦ Generate Technical Summary
        </button>
        <button class="btn btn-primary" ${act('generateOverviewIssoSummary')}
                title="ATO/cATO-ready brief covering NIST 800-53 control mapping, STIG validation status, evidence traceability, accepted risk, and POA&amp;M risk statements. ${tip}">
          ✦ Generate ISSO Compliance Brief
        </button>
      </div>
    </div>`;
}

export function buildOverviewTechSection() { return ''; }

export function buildOverviewIssoSection() { return ''; }

// Cache last-generated overview summary text for PDF/Word export
let _overviewSummaryCache = { exec: null, tech: null, isso: null };

// Cache per-app ISSO summaries keyed by app name
const _appIssoCache = {};

export function _summaryLoadingHtml(label) {
  return `<div style="display:flex;align-items:center;gap:10px;padding:12px 0;color:var(--text-muted);font-size:13px">
    <div class="spinner" style="width:16px;height:16px;border-width:2px"></div>
    Generating ${label}… this may take 15–30 seconds
  </div>`;
}

export function _summaryResultHtml(text, err, regenerateFn, exportFn, exportDocxFn) {
  const content = err
    ? `<div style="color:var(--critical);font-size:12px;padding:8px 0">⚠ ${esc(err)}</div>`
    : `<div style="line-height:1.6">${renderMarkdown(text)}</div>`;
  return `
    ${content}
    <div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" style="font-size:12px" onclick="${regenerateFn.includes('(') ? regenerateFn : regenerateFn + '()'}">↺ Regenerate</button>
      ${text ? `<button class="btn btn-primary" style="font-size:12px" onclick="${exportFn.includes('(') ? exportFn : exportFn + '()'}">↓ Export PDF</button>` : ''}
      ${text && exportDocxFn ? `<button class="btn" style="font-size:12px;background:var(--accent-bg);color:var(--accent);border-color:var(--accent-bg)" onclick="${exportDocxFn.includes('(') ? exportDocxFn : exportDocxFn + '()'}">↓ Export Word</button>` : ''}
    </div>`;
}

const _OVERVIEW_SUMMARY_KINDS = {
  exec: { title: 'Executive Summary',       label: 'executive summary',     fn: 'generateOverviewExecSummary', pdf: 'exportExecSummaryPdf', docx: 'exportExecSummaryDocx', call: () => api.getGlobalExecSummary() },
  tech: { title: 'Technical Summary',       label: 'technical summary',     fn: 'generateOverviewTechSummary', pdf: 'exportTechSummaryPdf', docx: 'exportTechSummaryDocx', call: () => api.getGlobalTechnicalSummary() },
  isso: { title: 'ISSO Compliance Brief',   label: 'ISSO compliance brief', fn: 'generateOverviewIssoSummary', pdf: 'exportIssoSummaryPdf', docx: 'exportIssoSummaryDocx', call: () => api.getGlobalIssoSummary() },
};

export function closeSummaryModal() {
  document.getElementById('summary-modal')?.remove();
  document.removeEventListener('keydown', _summaryModalKey);
}

export function _summaryModalKey(e) { if (e.key === 'Escape') closeSummaryModal(); }

export function _openSummaryModal(title, bodyHtml) {
  let overlay = document.getElementById('summary-modal');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'summary-modal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal-container modal-xl" role="dialog" aria-modal="true" aria-labelledby="summary-modal-title">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 id="summary-modal-title" style="margin:0;font-size:18px"></h2>
        <button class="btn" ${act('closeSummaryModal')} aria-label="Close">✕</button>
      </div>
      <div id="summary-modal-body"></div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeSummaryModal(); });
    document.addEventListener('keydown', _summaryModalKey);
  }
  document.getElementById('summary-modal-title').textContent = title;
  const body = document.getElementById('summary-modal-body');
  body.innerHTML = bodyHtml;
  return body;
}

// Generates into a modal so results never push the Overview content down.
export async function _runOverviewSummary(kind) {
  const cfg = _OVERVIEW_SUMMARY_KINDS[kind];
  const body = _openSummaryModal(cfg.title, _summaryLoadingHtml(cfg.label));
  try {
    const result = await cfg.call();
    _overviewSummaryCache[kind] = result.summary;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(result.summary, null, cfg.fn, cfg.pdf, cfg.docx);
  } catch (e) {
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', cfg.fn, cfg.pdf, cfg.docx);
  }
}

export async function generateOverviewExecSummary() { await _runOverviewSummary('exec'); }

export async function generateOverviewTechSummary() { await _runOverviewSummary('tech'); }

export async function generateOverviewIssoSummary() { await _runOverviewSummary('isso'); }

// Keep the old combined function as an alias so any cached references still work
export async function generateOverviewSummaries() {
  await Promise.all([generateOverviewExecSummary(), generateOverviewTechSummary()]);
}

export function exportExecSummaryPdf() {
  exportOverviewSummaryPdf('exec');
}

export function exportTechSummaryPdf() {
  exportOverviewSummaryPdf('tech');
}

export async function exportSummaryDocx(which) {
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
    toast('Word export failed: ' + e.message, 'error');
  }
}

export async function exportExecSummaryDocx() { await exportSummaryDocx('exec'); }

export async function exportTechSummaryDocx() { await exportSummaryDocx('tech'); }

export async function exportIssoSummaryDocx() { await exportSummaryDocx('isso'); }

export function exportIssoSummaryPdf() { exportOverviewSummaryPdf('isso'); }

export function buildAppIssoSection(name) {
  return `
    <div class="section" id="app-isso-section-${esc(name)}" style="border-left:3px solid var(--pass);padding-left:16px">
      <div class="section-title" style="display:flex;align-items:center;gap:10px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        AI ISSO Compliance Brief — ${esc(name)}
      </div>
      <button class="btn btn-primary" ${act('generateAppIssoSummary', name)}>
        ✦ Generate Application ISSO Brief
      </button>
      <p style="margin:8px 0 0;font-size:12px;color:var(--text-muted)">
        Per-application ATO/cATO brief: NIST 800-53 control mapping, STIG open controls,
        evidence traceability, accepted risk register, and POA&amp;M entries.
        Requires an OpenAI API key configured in Settings.
      </p>
    </div>`;
}

export async function generateAppIssoSummary(name) {
  const body = _openSummaryModal(`ISSO Compliance Brief — ${name}`, _summaryLoadingHtml('ISSO compliance brief'));
  const fns = [`generateAppIssoSummary('${name}')`, `exportAppIssoSummaryPdf('${name}')`, `exportAppIssoSummaryDocx('${name}')`];
  try {
    const result = await api.getAppIssoSummary(name);
    const text = result.summary || '';
    _appIssoCache[name] = text;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(text, null, ...fns);
  } catch (e) {
    _appIssoCache[name] = null;
    if (!document.getElementById('summary-modal')) return;
    body.innerHTML = _summaryResultHtml(null, e.message || 'Generation failed', ...fns);
  }
}

export function exportAppIssoSummaryPdf(name) {
  const text = _appIssoCache[name];
  if (!text) { toast('Generate the ISSO brief first.', 'warning'); return; }
  const doc = new window.jspdf.jsPDF();
  doc.setFontSize(16);
  doc.text(`ISSO Compliance Brief — ${name}`, 14, 20);
  doc.setFontSize(10);
  const lines = doc.splitTextToSize(text.replace(/#+\s/g, '').replace(/[*_`]/g, ''), 180);
  doc.text(lines, 14, 30);
  doc.save(`isso-brief-${name}.pdf`);
}

export async function exportAppIssoSummaryDocx(name) {
  const text = _appIssoCache[name];
  if (!text) { toast('Generate the ISSO brief first.', 'warning'); return; }
  try {
    const blob = await api.exportSummaryDocx({ isso_summary: text });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: `isso-brief-${name}.docx` });
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (e) {
    toast('Word export failed: ' + e.message, 'error');
  }
}

export function exportOverviewSummaryPdf(only) {
  const { exec, tech, isso } = _overviewSummaryCache;
  const showExec = !only || only === 'exec';
  const showTech = !only || only === 'tech';
  const showIsso = !only || only === 'isso';
  if (!exec && !tech && !isso) return;

  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  function mdToHtml(text) {
    if (!text) return '<p style="color:var(--text-muted)">Not available.</p>';
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
    .report-meta  { font-size: 10pt; color: var(--text-muted); margin: 0; }
    .section-heading {
      font-size: 14pt;
      font-weight: 700;
      margin: 28px 0 12px;
      padding: 8px 12px;
      border-radius: 4px;
    }
    :root {
      --text-muted: #656d76;
      --medium: #9a6700;
      --medium-bg: rgba(154, 103, 0, 0.1);
      --purple: #8250df;
      --purple-bg: rgba(130, 80, 223, 0.1);
      --pass: #1a7f37;
    }
    .exec-heading  { background: var(--medium-bg); border-left: 4px solid var(--medium); color: var(--medium); }
    .tech-heading  { background: var(--purple-bg); border-left: 4px solid var(--purple); color: var(--purple); }
    .isso-heading  { background: #ecfdf5; border-left: 4px solid var(--pass); color: var(--pass); }
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
      color: var(--text-muted);
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
    toast('Pop-up blocked — please allow pop-ups for this page and try again.', 'warning');
    return;
  }
  win.document.write(html);
  win.document.close();
}
