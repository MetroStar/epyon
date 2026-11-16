import { emptyNote } from './layout.js';
import { api } from '../lib/api.js';
import { esc, act, actOn, ARG } from '../lib/format.js';
import { poamSend } from '../pages/poam.js';

export async function calculateScorecardForScan(scanId) {
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
          <span class="loading-inline">Loading…</span>
        </summary>
      </details>
    </div>`;

  try {
    const scorecardData = await api.calculateScorecard(scanId);
    container.innerHTML = buildScorecardCard(scorecardData);
  } catch (e) {
    // 422 = "no consolidated findings data yet" — an expected state for older/
    // interrupted/partial scans, not a server bug. Render it as an informational
    // notice rather than a scary red "Error" so users aren't alarmed.
    const isUnavailable = e.status === 422;
    const accentColor = isUnavailable ? 'var(--text-muted)' : 'var(--critical)';
    const badgeLabel   = isUnavailable ? 'Unavailable' : 'Error';
    const bodyMessage  = isUnavailable
      ? esc(e.detail || e.message)
      : `<strong>Error:</strong> ${esc(e.detail || e.message)}`;
    container.innerHTML = `
      <div class="section findings-section-wrapper">
        <details class="findings-collapsible" style="border-left-color:${accentColor}">
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
            <span style="color:${accentColor};font-size:12px">${badgeLabel}</span>
          </summary>
          <div class="findings-body" style="padding:12px 18px 16px">
            <p style="color:${accentColor};font-size:13px;margin:0">${bodyMessage}</p>
          </div>
        </details>
      </div>`;
  }
}

// Store dimension data globally for modal access
window._scorecardDimensions = {};

export function buildScorecardCard(scorecardData) {
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
    const d = dims[key] || { score: 0, applicable: false, details: {}, evidence: [] };
    const applicable = d.applicable !== false && dims[key];
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
      applicable: !!applicable,
      details: d.details || {},
      evidence: d.evidence || []
    };
    
    return `
      <div class="scorecard-dim-card" ${act('showDimensionModal', `${key}`)} style="cursor:pointer">
        <div class="scorecard-dim-label">${esc(dimLabels[key])}</div>
        ${applicable ? `<div class="scorecard-dim-score" style="color:${barColor}">${s}</div>
        <div class="scorecard-dim-weight">${w}% weight</div>
        <div class="scorecard-dim-bar">
          <div class="scorecard-dim-bar-fill" style="width:${s}%;background:${barColor}"></div>
        </div>` : `<div class="scorecard-dim-score" style="color:var(--text-muted);font-size:18px">Not scanned</div>
        <div class="scorecard-dim-weight">${w}% weight · scores 0</div>`}
        <div style="margin-top:8px;font-size:12px;color:var(--text-muted);text-align:center">Click for details</div>
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

  const scanId = scorecardData.scan_id || '';
  const prev = scorecardData.previous;
  const prevHtml = prev ? `
    <div class="scorecard-compare" style="margin-top:16px;font-size:13px;color:var(--text-muted)">
      <strong>Before this scoring update</strong> (v${esc(String(prev.scoring_version))}):
      ${esc(String(prev.weighted_score))} → <strong>${esc(score)}</strong>
      (TRL ${esc(String(prev.trl_level))} → ${esc(String(level))}).
      ${dimOrder.map(k => {
        const o = prev.dimension_scores && prev.dimension_scores[k] ? prev.dimension_scores[k].score : null;
        const n = (dims[k] || {}).score;
        if (o == null || n == null) return '';
        const diff = Math.round(n - o);
        return `<span style="margin-right:10px">${esc(dimLabels[k])} ${diff >= 0 ? '+' : ''}${diff}</span>`;
      }).join('')}
    </div>` : '';
  const so = scorecardData.signoff;
  const signoffHtml = `
    <div class="scorecard-signoff" data-scan="${esc(scanId)}" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
      <strong style="font-size:13px">Reviewer sign-off</strong>
      ${so ? `<div style="margin-top:6px;font-size:13px;color:${so.valid ? 'var(--pass)' : 'var(--medium)'}">
          ${so.valid ? '✓ Signed off' : '⚠ Sign-off no longer matches the current score'} by
          <strong>${esc(so.reviewer)}</strong> on ${esc(so.signed_at)} (score ${esc(String(so.weighted_score))})
          ${so.comment ? `<div style="color:var(--text-muted);margin-top:4px">${esc(so.comment)}</div>` : ''}
          <button class="btn btn-sm" style="margin-top:8px" ${actOn('click','revokeScorecardSignoff', ARG.el)}>Revoke</button>
        </div>` : ''}
      ${so && so.valid ? '' : `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
          <input type="text" class="so-name" maxlength="100" placeholder="Reviewer name" style="padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text)">
          <input type="text" class="so-comment" maxlength="2000" placeholder="Comment (optional)" style="flex:1;min-width:200px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text)">
          <button class="btn btn-sm btn-primary" ${actOn('click','signOffScorecard', ARG.el)}>Sign off this score</button>
        </div><div class="so-msg" style="font-size:12px;color:var(--critical);margin-top:6px"></div>`}
      <div style="margin-top:10px"><a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/scorecard/evidence" download>↓ Evidence package (.zip)</a></div>
    </div>`;

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
            <button type="button" class="btn btn-sm" title="How the Score Card works" onclick="event.preventDefault();event.stopPropagation();showScorecardHelp()">ⓘ How it works</button>
            <span style="font-size:18px;font-weight:700;color:var(--accent)">${score}</span>
            <span class="findings-summary-hint">Click to expand</span>
          </span>
        </summary>
        <div class="findings-body" style="padding:16px 18px">
          <div class="scorecard-dimensions" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:${blockersHtml ? '20px' : '0'}">
            ${dimCards}
          </div>
          ${blockersHtml}
          ${prevHtml}
          ${signoffHtml}
          <div style="font-size:12px;color:var(--text-muted);padding-top:16px;border-top:1px solid var(--border);margin-top:16px">
            <strong>About Scoring:</strong> Anything never scanned in any scan of this application scores 0 rather than being ignored, so skipping a scan can never raise the score. Findings come from the latest scan (earlier ones are treated as closed out); STIG results come from the last STIG run. It does not depend on the scan type. Six dimensions (Security, Supply Chain, Code Quality, Compliance, Operational, MOSA). 
            Scores 70+ are production-ready, 50-69 need improvements, below 50 require immediate attention.
            <br><small><strong>MOSA</strong> = Modular Open Systems Approach: modularity, open standards, interoperability, portability. <strong>Click dimension cards for detailed breakdowns.</strong></small>
          </div>
        </div>
      </details>
    </div>`;
}

window.showScorecardHelp = () => {
  const row = (a, b) => `<tr><td style="padding:6px 12px 6px 0;vertical-align:top;white-space:nowrap"><strong>${a}</strong></td><td style="padding:6px 0;color:var(--text-muted)">${b}</td></tr>`;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container modal-lg" style="max-height:85vh;overflow:auto;font-size:13px;line-height:1.5">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 style="margin:0;color:var(--text)">How the Score Card works</h2>
        <button class="btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
      </div>
      <h3>What it measures</h3>
      <p>The Score Card rates the <strong>application</strong>, not a single scan. Findings are those of the latest scan; earlier findings that are gone are treated as closed out, and history only feeds the trend. STIG results come from the last STIG run, since STIGs run on demand. Scan type does not change the score or weights.</p>
      <h3>Six dimensions, each 0–100</h3>
      <table>
        ${row('Security (30%)', 'Starts at 100. Critical −15, high −5, medium −1, low −0.2 per vulnerability (CVEs only). IaC misconfigurations (Checkov) are scored separately and more lightly: critical −5, high −2, medium −0.5, low −0.1, max −25. Semgrep SAST findings are code weaknesses, not CVEs, so they also get their own line (critical −3, high −1.5, medium −0.5, low −0.1, max −15) and still feed Code Quality. Findings under tests/fixtures-style directories (tests*, test, __tests__, fixtures, spec) are never scored — they are listed as "suppressed (test path)" at 0 weight unless the repo sets include_tests: true in .epyon-ignore.yml. Findings suppressed by approved .epyon-ignore.yml rules are listed as evidence ("suppressed") but carry 0 weight. Known-exploited (CISA KEV) −10 each, max −30. ML layers 14/18/19/20 −25 max each. <em>Caps:</em> leaked secrets → 30, malware → 20, dangerous model files or critical provenance → 40, LLM probe pass rate under 80% → 50.')}
        ${row('Supply Chain (20%)', 'Needs an SBOM (without one in any scan the dimension scores 0). Deducts for end-of-support (−20) and EOL (−5) components, vulnerability density, high/critical findings that already have a fix (−2 each, max −20) and typosquatted models.')}
        ${row('Code Quality (15%)', 'Weighted average of tools that have run: SonarQube gate 40, Checkov IaC pass rate 30, Semgrep SAST 30. Tools that never ran are listed as missing and their weight is redistributed.')}
        ${row('Compliance (15%)', 'Weighted average of STIG (70, pass rate = Not a Finding ÷ applicable controls; Not Applicable controls are excluded from the denominator, Open and Not Reviewed count against; always counted: no STIG assessment scores 0; includes a CAT I penalty and a penalty for “Not a Finding” controls with no written evidence), plus model card (20) and documented APIs (10) when present. No STIG assessment in any scan scores the STIG part 0.')}
        ${row('Operational (10%)', 'Helm chart builds, no non-standard open ports, and the trend against the previous scan (worse −20, better +10). A missing Helm result or earlier scan adds no bonus or penalty.')}
        ${row('MOSA (10%)', 'Modular open systems: standard SBOM, Helm chart, Dockerfile, documented API and open-source license ratio.')}
      </table>
      <h3>Overall score and TRL</h3>
      <p>Never scanned means scored 0: a dimension with no data shows “Not scanned”, scores 0 and keeps its weight. Overall = Σ(dimension score × weight). It maps to a Technology Readiness Level: 90+ → TRL 9, 80+ → 8, 70+ → 7, 60+ → 6, 50+ → 5, 40+ → 4, 30+ → 3, 20+ → 2, otherwise 1. Blockers (critical CVEs, secrets, malware, KEV, STIG under 70%) are listed separately.</p>
      <h3>Evidence</h3>
      <p>Click a dimension to see every line that moved its score: the points, the source file and its SHA-256, and the finding or control IDs behind it. <strong>Evidence package</strong> downloads the score, the source files and a hash manifest; files that changed since scoring are flagged.</p>
      <h3>Sign-off</h3>
      <p>A reviewer can sign off on the current score by name. If a rescore changes any number, the sign-off is shown as no longer matching and must be redone.</p>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
};

window.signOffScorecard = async (btn) => {
  const box = btn.closest('.scorecard-signoff'), msg = box.querySelector('.so-msg');
  const reviewer = box.querySelector('.so-name').value.trim();
  try {
    await poamSend(`/api/scans/${encodeURIComponent(box.dataset.scan)}/scorecard/signoff`, 'PUT',
      { reviewer, comment: box.querySelector('.so-comment').value.trim() });
    await calculateScorecardForScan(box.dataset.scan);
  } catch (e) { msg.textContent = e.message; }
};

window.revokeScorecardSignoff = async (btn) => {
  const box = btn.closest('.scorecard-signoff');
  const r = await fetch(`/api/scans/${encodeURIComponent(box.dataset.scan)}/scorecard/signoff`, { method: 'DELETE' });
  if (r.ok) await calculateScorecardForScan(box.dataset.scan);
};

export function flattenScoreDetail(v) {
  if (v == null) return '';
  if (typeof v !== 'object') return String(v);
  return Object.entries(v).map(([k, x]) => `${k.replace(/[-_]/g, ' ')}: ${flattenScoreDetail(x)}`).join(' · ');
}

export function showDimensionModal(dimensionKey) {
  const data = window._scorecardDimensions[dimensionKey];
  if (!data) {
    console.error('Dimension data not found:', dimensionKey);
    return;
  }
  
  const { key, label, score, weight, color, details, evidence, applicable } = data;

  const detailsHtml = Object.entries(details).map(([k, v]) => {
    const itemLabel = k.replace(/_/g, ' ');
    let value = v;
    if (typeof v === 'boolean') value = v ? '✓ Yes' : '✗ No';
    else if (typeof v === 'number') value = Number.isInteger(v) ? String(v) : v.toFixed(1);
    else if (v && typeof v === 'object') value = flattenScoreDetail(v);
    return `
      <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border-muted)">
        <span style="color:var(--text-muted);font-size:14px;text-transform:capitalize">${esc(itemLabel)}</span>
        <span style="color:var(--text);font-size:14px;font-weight:600">${esc(String(value))}</span>
      </div>`;
  }).join('');

  const kindLabel = { missing: 'not scanned' };
  const kindColor = { deduction: 'var(--critical)', cap: 'var(--critical)', missing: 'var(--medium)', bonus: 'var(--pass)', component: 'var(--accent)', info: 'var(--text-muted)' };
  const evidenceHtml = (evidence || []).map(e => {
    const impact = e.impact == null ? '' : `<span style="font-weight:700;color:${kindColor[e.kind] || 'inherit'}">${e.kind === 'cap' ? 'cap ' : (e.impact > 0 ? '+' : '')}${esc(String(e.impact))}</span>`;
    const refs = (e.refs || []).length ? `
      <details style="margin-top:4px"><summary style="cursor:pointer;font-size:12px;color:var(--text-muted)">${esc(String(e.refs_total || e.refs.length))} item(s)${e.refs_total > e.refs.length ? ` (first ${e.refs.length} shown)` : ''}</summary>
        <div style="font-size:12px;font-family:monospace;word-break:break-all;margin-top:4px">${e.refs.map(r => esc(r)).join('<br>')}</div></details>` : '';
    const src = e.source ? `<div style="font-size:11px;color:var(--text-dim);font-family:monospace;word-break:break-all">${esc(e.source)}${e.sha256 ? ' · sha256 ' + esc(e.sha256.slice(0, 12)) + '…' : ''}</div>` : '';
    return `
      <div style="padding:10px 0;border-bottom:1px solid var(--border-muted)">
        <div style="display:flex;justify-content:space-between;gap:12px">
          <span style="font-size:13px"><span style="color:${kindColor[e.kind] || 'inherit'};text-transform:uppercase;font-size:11px;margin-right:6px">${esc(kindLabel[e.kind] || e.kind)}</span>${esc(e.label)}</span>${impact}
        </div>
        ${e.note ? `<div style="font-size:12px;color:var(--text-muted)">${esc(e.note)}</div>` : ''}${src}${refs}
      </div>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-container modal-lg">
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
        ${applicable ? `<div style="font-size:64px;font-weight:700;color:${color};margin-bottom:8px">${score}</div>
        <div style="font-size:14px;color:var(--text-muted);margin-bottom:4px">Score out of 100</div>
        <div style="font-size:13px;color:var(--text-muted)">${weight}% of overall score</div>` : `<div style="font-size:28px;font-weight:700;color:var(--text-muted);margin-bottom:8px">Not scanned</div>
        <div style="font-size:13px;color:var(--text-muted)">No scan of this application has produced data for this dimension, so it scores 0 and keeps its weight.</div>`}
        <div style="margin:16px auto 0;max-width:300px;${applicable ? '' : 'display:none'}">
          <div style="height:16px;background:var(--bg);border-radius:8px;overflow:hidden">
            <div style="width:${score}%;height:100%;background:${color};transition:width 0.3s ease"></div>
          </div>
        </div>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px">
        <h3 style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 16px;text-transform:uppercase;letter-spacing:0.5px">Detailed Metrics</h3>
        ${detailsHtml || emptyNote('No detailed metrics available for this dimension.')}
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-top:16px">
        <h3 style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 4px;text-transform:uppercase;letter-spacing:0.5px">Evidence</h3>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Each line shows what moved the score, the artifact it came from and its hash.</div>
        ${evidenceHtml || emptyNote('No evidence recorded. Recalculate the Score Card to generate it.')}
      </div>
    </div>`;
  
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.remove();
  });
}
