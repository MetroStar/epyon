import { esc, act } from '../../lib/format.js';

// Globals that other modules put on window (see index.js):
/* global _registerFinding */

export function buildPicklescanCard(scan) { return ''; } // merged into buildModelSecurityCard

export function buildModelCardCard(scan) { return ''; }  // merged into buildModelSecurityCard

export function buildModelSecurityCard(scan) {
  // Enhanced to support 5 ML security layers - always show even if no findings
  // Layer 14: picklescan (enhanced), Layer 15: modelcard
  // Layer 18: model-provenance, Layer 19: inference-security, Layer 20: ml-runtime
  const ps = scan.picklescan;
  const mc = scan.modelcard;
  const mp = scan.model_provenance;
  const is = scan.inference_security;
  const mr = scan.ml_runtime;
  
  // Always show the card to give visibility that ML security layers ran or are available

  // ── Layer 14: Enhanced Picklescan section ──
  let pickleSection = '';
  if (ps && Array.isArray(ps)) {
    // New enhanced schema: ps is an array of findings
    const findingsCount = ps.length;
    const criticalCount = ps.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = ps.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const psFindings = ps.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'picklescan',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" ${act('openFindingDetail', fid)} title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Malicious content detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    pickleSection = `
      <div class="ms-layer">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🥒</span>
            <span>Layer 14 — Comprehensive Model File Analysis</span>
            <span class="hf-tool-name">picklescan-enhanced</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${psFindings ? `<div class="hf-findings" style="margin-top:10px">${psFindings}</div>` : ''}
      </div>`;
  } else if (ps && typeof ps === 'object') {
    // Legacy schema support: ps is an object
    const statusClass = ps.flagged_count > 0 ? 'status-open' : 'status-clean';
    const statusLabel = ps.flagged_count > 0 ? `${ps.flagged_count} infected file(s)` : 'Clean';
    const icon = ps.flagged_count > 0 ? '🚨' : '✅';
    const totalWeightFiles = ps.total_weight_files ?? ps.file_count ?? 0;

    const psFindings = (ps.findings || []).map(f => `
      <div class="hf-finding-row">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.message || f.description || 'Malicious pickle opcode detected')}</span>
      </div>`).join('');

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
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${totalWeightFiles}</span><span class="hf-stat-lbl">weight files</span></div>
          <div class="hf-stat"><span class="hf-stat-num">${ps.file_count ?? 0}</span><span class="hf-stat-lbl">pickle-scannable</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${ps.flagged_count > 0 ? 'danger' : ''}">${ps.flagged_count ?? 0}</span><span class="hf-stat-lbl">infected</span></div>
        </div>
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
        file:        mc.file_checked || '',
        target:      mc.file_checked || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" ${act('openFindingDetail', fid)} title="Click to view details">
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

  // ── Layer 18: Model Provenance & Threat Intelligence ──
  let provenanceSection = '';
  if (mp && Array.isArray(mp) && mp.length > 0) {
    const findingsCount = mp.length;
    const criticalCount = mp.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = mp.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const mpFindings = mp.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'model-provenance',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" ${act('openFindingDetail', fid)} title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Provenance issue detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    provenanceSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🔐</span>
            <span>Layer 18 — Model Provenance & Threat Intelligence</span>
            <span class="hf-tool-name">model-provenance</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${mpFindings ? `<div class="hf-findings" style="margin-top:10px">${mpFindings}</div>` : ''}
      </div>`;
  }

  // ── Layer 19: Inference Environment Security ──
  let inferenceSection = '';
  if (is && Array.isArray(is) && is.length > 0) {
    const findingsCount = is.length;
    const criticalCount = is.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = is.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const isFindings = is.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'inference-security',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" ${act('openFindingDetail', fid)} title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Infrastructure issue detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    inferenceSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">🐳</span>
            <span>Layer 19 — Inference Environment Security</span>
            <span class="hf-tool-name">inference-security</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${isFindings ? `<div class="hf-findings" style="margin-top:10px">${isFindings}</div>` : ''}
      </div>`;
  }

  // ── Layer 20: ML Runtime Behavioral Analysis (Opt-in) ──
  let runtimeSection = '';
  if (mr && Array.isArray(mr) && mr.length > 0) {
    const findingsCount = mr.length;
    const criticalCount = mr.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const highCount = mr.filter(f => (f.severity || '').toLowerCase() === 'high').length;
    
    const statusClass = criticalCount > 0 || highCount > 0 ? 'status-open' : 'status-clean';
    const statusLabel = findingsCount > 0 ? `${findingsCount} finding(s)` : 'Clean';
    const icon = findingsCount > 0 ? '🚨' : '✅';

    const mrFindings = mr.map(f => {
      const fid = _registerFinding({
        severity:    f.severity || 'high',
        id:          f.id || f.type || '',
        tool:        'ml-runtime',
        title:       f.description || f.type || '—',
        description: f.evidence || '',
        file:        f.file || '',
        target:      f.file || '',
      });
      return `
      <div class="hf-finding-row hf-finding-row--clickable" ${act('openFindingDetail', fid)} title="Click to view details">
        <span class="hf-finding-sev hf-sev-${esc(f.severity || 'high')}">${esc(f.severity || 'high')}</span>
        <code class="hf-finding-file">${esc(f.file || '—')}</code>
        <span class="hf-finding-msg">${esc(f.description || f.type || 'Malicious runtime behavior detected')}</span>
        <span class="hf-finding-chevron">›</span>
      </div>`;
    }).join('');

    runtimeSection = `
      <div class="ms-layer ms-layer-border">
        <div class="ms-layer-header">
          <div class="ms-layer-title">
            <span class="hf-tool-icon">⚡</span>
            <span>Layer 20 — ML Runtime Behavioral Analysis</span>
            <span class="hf-tool-name">ml-runtime</span>
            <span class="tool-tag" style="background:var(--purple-bg);color:var(--purple);border:1px solid #7c3aed66;margin-left:6px">OPT-IN</span>
          </div>
          <span class="hf-status-badge ${statusClass}">${icon} ${esc(statusLabel)}</span>
        </div>
        <div class="hf-tool-stats" style="margin-bottom:0">
          <div class="hf-stat"><span class="hf-stat-num">${findingsCount}</span><span class="hf-stat-lbl">findings</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${criticalCount > 0 ? 'danger' : ''}">${criticalCount}</span><span class="hf-stat-lbl">critical</span></div>
          <div class="hf-stat"><span class="hf-stat-num ${highCount > 0 ? 'danger' : ''}">${highCount}</span><span class="hf-stat-lbl">high</span></div>
        </div>
        ${mrFindings ? `<div class="hf-findings" style="margin-top:10px">${mrFindings}</div>` : ''}
      </div>`;
  }

  // ── Combined status for the summary line ──
  // Count issues from all ML layers
  const psIssues = Array.isArray(ps) ? ps.length : (ps?.flagged_count > 0);
  const mcIssues = mc?.failed > 0 || mc?.warnings > 0;
  const mpIssues = mp && mp.length > 0;
  const isIssues = is && is.length > 0;
  const mrIssues = mr && mr.length > 0;
  
  const hasIssues = psIssues || mcIssues || mpIssues || isIssues || mrIssues;
  const hasCritical = (Array.isArray(ps) && ps.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (mp && mp.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (is && is.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (mr && mr.some(f => (f.severity || '').toLowerCase() === 'critical')) ||
                      (ps?.flagged_count > 0) || (mc?.failed > 0);
  
  const summaryBadgeClass = hasCritical ? 'status-open' : hasIssues ? 'status-warn' : 'status-clean';
  const summaryIcon       = hasCritical ? '⚠' : hasIssues ? '⚠' : '✓';
  const summaryLabel      = hasIssues ? 'Issues found' : 'All clear';
  
  // Check if any ML layers ran
  const anyLayersRan = ps || mc || mp || is || mr;
  const emptyState = !anyLayersRan ? `
    <div style="padding:16px;text-align:center;color:var(--text-muted);font-size:13px">
      <div style="margin-bottom:8px">ℹ️ No ML/AI security layers detected in this scan</div>
      <div style="font-size:12px;color:var(--text-dim)">ML security scanning (layers 14, 15, 18, 19, 20) only runs for repositories containing ML models or AI artifacts</div>
    </div>` : '';

  return `
    <details class="ms-card" id="model-security-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">ML/AI Security</span>
          ${ps ? '<span class="tool-tag" style="font-size:12px">picklescan</span>' : ''}
          ${mc ? '<span class="tool-tag" style="font-size:12px">model card</span>' : ''}
          ${mp ? '<span class="tool-tag" style="font-size:12px">provenance</span>' : ''}
          ${is ? '<span class="tool-tag" style="font-size:12px">inference</span>' : ''}
          ${mr ? '<span class="tool-tag" style="font-size:12px;background:var(--purple-bg);color:var(--purple)">runtime</span>' : ''}
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${summaryBadgeClass}">${summaryIcon} ${summaryLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        ${emptyState}
        ${pickleSection}
        ${modelCardSection}
        ${provenanceSection}
        ${inferenceSection}
        ${runtimeSection}
      </div>
    </details>`;
}
