import { findingSourceBadge } from '../badges.js';
import { toast } from '../feedback.js';
import { esc } from '../../lib/format.js';

// Legacy globals still provided by main.js (see index.js):
/* global _registerFinding */

export function buildMisconfigurationsCard(scan) {
  // Layers 2, 6 & 21: TruffleHog secret detection + Checkov IaC security + compromised-source supply chain detection - always show even if no findings
  const misconfigs = scan.misconfigurations;
  const summary = misconfigs?.summary || { total_critical: 0, total_high: 0, total_medium: 0, total_low: 0, tools_analyzed: [] };
  const totalIssues = summary.total_critical + summary.total_high + summary.total_medium + summary.total_low;
  
  // Build findings rows only if there are findings
  let findingsHtml = '';
  if (totalIssues > 0) {
    const buildMisconfigRow = (f) => {
      const fid = _registerFinding({
        severity:    f.severity || 'medium',
        id:          f.id || '',
        tool:        f.tool || 'Checkov',
        title:       f.title || f.description || '—',
        description: f.description || '',
        file:        f.file || '',
        target:      f.target || '',
      });
      
      return `
        <div class="hf-finding-row hf-finding-row--clickable" onclick="openFindingDetail(${fid})" title="Click to view details">
          <span class="hf-finding-sev hf-sev-${esc(f.severity || 'medium')}">${esc(f.severity || 'medium')}</span>
          ${findingSourceBadge(f)}
          <code class="hf-finding-file">${esc(f.file || f.target || '—')}</code>
          <span class="hf-finding-msg">${esc(f.title || f.description || 'Configuration issue detected')}</span>
          <span class="hf-finding-chevron">›</span>
        </div>`;
    };
    
    const allMisconfigItems = [
      ...(misconfigs.critical_findings || []),
      ...(misconfigs.high_findings || []),
      ...(misconfigs.medium_findings || []),
      ...(misconfigs.low_findings || [])
    ];
    
    const rows = allMisconfigItems.map(buildMisconfigRow).join('');
    
    findingsHtml = `
      <div class="hf-findings" style="margin-top:10px">
        ${rows}
      </div>`;
  } else {
    findingsHtml = `
      <div style="padding:12px;text-align:center;color:var(--text-muted);font-size:13px">
        ✓ No misconfigurations or secrets detected
      </div>`;
  }
  
  const statusClass = totalIssues === 0 ? 'status-clean' : summary.total_critical > 0 ? 'status-open' : summary.total_high > 0 ? 'status-warn' : 'status-clean';
  const statusIcon = totalIssues === 0 ? '✓' : summary.total_critical > 0 ? '🚨' : summary.total_high > 0 ? '⚠' : '✓';
  const statusLabel = totalIssues === 0 
    ? 'All clear'
    : summary.total_critical > 0 
    ? `${summary.total_critical} critical issue(s)` 
    : summary.total_high > 0 
    ? `${summary.total_high} high issue(s)` 
    : 'Minor issues';
  
  return `
    <details class="ms-card" id="misconfigurations-card">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Misconfigurations</span>
          <span class="tool-tag" style="font-size:12px">Layers 2, 6 & 21 — Secrets, IaC & Supply Chain</span>
        </span>
        <span class="ms-summary-right">
          <span class="hf-status-badge ${statusClass}">${statusIcon} ${statusLabel}</span>
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div class="ms-layer">
          <div class="ms-layer-header">
            <div class="ms-layer-title">
              <span class="hf-tool-icon">🔧</span>
              <span>Security Misconfigurations & Secrets</span>
              <span class="hf-tool-name">${(summary.tools_analyzed || []).join(', ') || 'Checkov, TruffleHog'}</span>
            </div>
            <span class="hf-status-badge ${statusClass}">${statusIcon} ${totalIssues} finding(s)</span>
          </div>
          <div class="hf-tool-stats" style="margin-bottom:0">
            <div class="hf-stat"><span class="hf-stat-num">${totalIssues}</span><span class="hf-stat-lbl">findings</span></div>
            <div class="hf-stat"><span class="hf-stat-num ${summary.total_critical > 0 ? 'danger' : ''}">${summary.total_critical}</span><span class="hf-stat-lbl">critical</span></div>
            <div class="hf-stat"><span class="hf-stat-num ${summary.total_high > 0 ? 'danger' : ''}">${summary.total_high}</span><span class="hf-stat-lbl">high</span></div>
            <div class="hf-stat"><span class="hf-stat-num">${summary.total_medium}</span><span class="hf-stat-lbl">medium</span></div>
            <div class="hf-stat"><span class="hf-stat-num">${summary.total_low}</span><span class="hf-stat-lbl">low</span></div>
          </div>
          ${findingsHtml}
        </div>
      </div>
    </details>`;
}

export function buildBuildEvidenceCard(scan) {
  const be = scan.build_evidence || {};
  const build = be.build || {};
  const sig = be.signature || {};
  const prov = be.provenance || {};
  const arts = be.artifacts || {};
  const digest = be.digest || build.digest || '';
  const mode = build.mode || (build.status === 'success' ? 'container_build' : 'target_source_manifest');

  const isContainerBuild = mode === 'container_build';

  const statusBadge = isContainerBuild
    ? `<span class="badge" style="background:var(--pass);color:var(--bg);">✅ Image Built</span>`
    : `<span class="badge" style="background:var(--accent);color:var(--bg);">✅ Target Attested & Verified</span>`;

  const manifestBadge = arts.oci_manifest
    ? `<span class="badge" style="background:var(--accent);color:var(--bg);">📦 OCI Manifest</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">📦 OCI Manifest N/A</span>`;

  const provBadge = arts.slsa_provenance
    ? `<span class="badge" style="background:var(--purple);color:var(--bg);">📜 SLSA v1.0 Provenance</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">📜 SLSA Provenance N/A</span>`;

  const sigBadge = sig.status === 'signed' || arts.image_signature
    ? `<span class="badge" style="background:var(--pass);color:var(--bg);">🔏 Cosign Signed</span>`
    : `<span class="badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);">🔏 Signature N/A</span>`;

  // Build 10-Artifact Inventory Table Rows — status reflects actual file presence
  // reported by parse_build_evidence()'s `artifacts` flags, not an assumed constant.
  const artifactRows = [
    { name: "1. Immutable Image Digest", spec: "SHA-256 Digest", present: !!arts.image_digest, file: "build/image-digest.txt" },
    { name: "2. OCI Image Manifest", spec: "OCI Image Specification v1/v2", present: !!arts.oci_manifest, file: "build/oci-manifest.json" },
    { name: "3. Dockerfile / Build Spec", spec: "Container Instructions", present: !!arts.dockerfile, file: "build/Dockerfile" },
    { name: "4. Build Execution Logs", spec: "Console & Execution Log", present: !!arts.build_log, file: "build/build.log" },
    { name: "5. SLSA Provenance", spec: "SLSA v1.0 in-toto Predicate", present: !!arts.slsa_provenance, file: "provenance.jsonl" },
    { name: "6. Cryptographic Signature", spec: "Cosign Signature Metadata", present: !!arts.image_signature, file: "image.sig" },
    { name: "7. Software Inventory (SBOM)", spec: "CycloneDX / SPDX JSON", present: !!arts.sbom, file: "sbom/filesystem.cyclonedx.json" },
    { name: "8. Vulnerability & Malware Scans", spec: "Grype / Trivy / ClamAV Reports", present: !!arts.vuln_scans, file: "grype/, trivy/, clamav/" },
    { name: "9. Scan Integrity Manifest", spec: "Cryptographic SHA-256 Hashes", present: !!arts.scan_manifest, file: "scan-manifest.json" },
    { name: "10. Policy & Suppression Audit", spec: "Exception Justifications", present: !!arts.suppression_audit, file: "suppressed-findings.md" }
  ].map(a => `
    <tr style="border-bottom:1px solid var(--border-muted);">
      <td style="padding:8px 12px;font-weight:500;">${esc(a.name)}</td>
      <td style="padding:8px 12px;color:var(--text-muted);font-size:12px;">${esc(a.spec)}</td>
      <td style="padding:8px 12px;">${a.present
        ? '<span style="color:var(--pass);font-weight:600;">✅ Captured</span>'
        : '<span style="color:var(--text-muted);">⚠️ Not Captured</span>'}</td>
      <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:var(--text-muted);">${esc(a.file)}</td>
    </tr>
  `).join('');

  return `
    <details class="ms-card" id="build-evidence-card" style="border-left-color:var(--purple);margin-top:20px;">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">Build Artifacts & Supply Chain Evidence</span>
          <span class="tool-tag" style="font-size:12px">Phase 0 — Container Build & Attestation</span>
        </span>
        <span class="ms-summary-right">
          ${statusBadge}
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
          ${statusBadge}
          ${manifestBadge}
          ${provBadge}
          ${sigBadge}
        </div>
        
        <div class="detail-grid" style="margin-bottom:16px;">
          <div class="detail-card">
            <div class="label">Image Identifier</div>
            <div class="value" style="font-family:monospace;font-size:0.85rem;">${esc(build.full_image || build.image_name || scan.target || 'N/A')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Immutable SHA-256 Digest</div>
            <div class="value" style="font-family:monospace;font-size:0.8rem;word-break:break-all;">${esc(digest || 'N/A (Pre-built target)')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Build Runtime</div>
            <div class="value">${esc(build.runtime || 'N/A (Source scan)')}</div>
          </div>
          <div class="detail-card">
            <div class="label">Dockerfile</div>
            <div class="value">${esc(build.dockerfile || 'Dockerfile')}</div>
          </div>
        </div>

        <div class="section-title" style="font-size:0.9rem;margin-bottom:8px;color:var(--text);">📦 Release & Evidence Artifact Inventory</div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:13px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;">
            <thead>
              <tr style="background:var(--bg-card);border-bottom:1px solid var(--border);text-align:left;">
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Artifact Name</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Specification / Format</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Pipeline Status</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Artifact Path</th>
              </tr>
            </thead>
            <tbody>
              ${artifactRows}
            </tbody>
          </table>
        </div>
      </div>
    </details>`;
}

export function buildSSPEvidenceCard(scan) {
  const matrix = scan.ssp_evidence || {};
  const controls = matrix.controls || [];
  if (!controls.length) return '';

  const scanId = scan.scan_id || '';

  const rows = controls.map(c => {
    const isCap = c.status === 'captured';
    const hash = c.sha256_hash || 'N/A';
    const hashShort = hash.length > 20 ? hash.slice(0, 18) + '…' : hash;
    return `
      <tr style="border-bottom:1px solid var(--border-muted);">
        <td style="padding:8px 12px;font-weight:600;color:var(--accent);">${esc(c.control_id)}</td>
        <td style="padding:8px 12px;font-weight:500;">${esc(c.control_name)}</td>
        <td style="padding:8px 12px;color:var(--text-muted);font-size:12px;">${esc(c.epyon_layer)}</td>
        <td style="padding:8px 12px;font-family:monospace;font-size:12px;"><code style="color:var(--purple);">${esc(c.primary_artifact_path)}</code></td>
        <td style="padding:8px 12px;">${isCap ? '<span style="color:var(--pass);font-weight:600;">✅ Captured</span>' : '<span style="color:var(--medium);font-weight:600;">⚠️ Missing Evidence</span>'}</td>
        <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:var(--text-muted);" title="${esc(hash)}">${esc(hashShort)}</td>
      </tr>`;
  }).join('');

  const downloadMdBtn = scanId
    ? `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/ssp-evidence/md" download title="Download NIST SP 800-53 Control Evidence Matrix as Markdown">↓ Export Matrix (.md)</a>`
    : '';

  const downloadDocxBtn = scanId
    ? `<button type="button" class="btn btn-sm js-export-ssp-docx" data-scan-id="${esc(scanId)}" title="Export NIST SP 800-53 Control Evidence Matrix as Word .docx">↓ Export Word (.docx)</button>`
    : '';

  return `
    <details class="ms-card" id="ssp-evidence-card" style="border-left-color:var(--pass);margin-top:20px;">
      <summary class="ms-summary">
        <span class="ms-summary-left">
          <span class="findings-chevron" aria-hidden="true"></span>
          <span class="ms-summary-title">NIST SP 800-53 / FedRAMP Control Evidence Matrix</span>
          <span class="tool-tag" style="font-size:12px;background:var(--pass-bg);color:var(--pass);border:1px solid #10b98144">SSP / ATO Package</span>
        </span>
        <span class="ms-summary-right" onclick="event.stopPropagation()" style="gap:8px;display:flex;align-items:center;">
          ${downloadMdBtn}
          ${downloadDocxBtn}
          <span class="findings-summary-hint" style="margin-left:8px">Click to expand</span>
        </span>
      </summary>
      <div class="ms-body">
        <div style="padding:12px 18px 0;color:var(--text-muted);font-size:13px;">
          Maps Epyon's security scanning layers, build provenance, and scan manifests directly to NIST SP 800-53 Rev. 5 / FedRAMP control families for System Security Plans (SSP) and ATO submissions.
        </div>
        <div style="overflow-x:auto;padding:12px 18px 18px;">
          <table style="width:100%;border-collapse:collapse;font-size:13px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;">
            <thead>
              <tr style="background:var(--bg-card);border-bottom:1px solid var(--border);text-align:left;">
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Control</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">NIST Control Name</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Epyon Security Layer</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Primary Evidence Artifact Path</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Status</th>
                <th scope="col" style="padding:8px 12px;color:var(--text-muted);font-weight:600;">Cryptographic SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      </div>
    </details>`;
}

window.exportSSPDocx = async function(scanId) {
  try {
    const res = await fetch('/api/scans/' + encodeURIComponent(scanId) + '/export/ssp-docx', { method: 'POST' });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ssp-ato-evidence-' + scanId + '.docx';
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    toast('Failed to export Word document: ' + err.message, 'error');
  }
};
