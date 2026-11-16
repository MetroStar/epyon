import { gateBadge, statusBadge } from '../components/badges.js';
import { errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { dedupeTools, esc, fmtDate } from '../lib/format.js';
import { computeStatus, scanTypeLabel } from '../lib/scans.js';
import { buildPoamSection } from './poam.js';
import { buildModelSecurityCard } from '../components/scan/model-security.js';
import { buildNetworkDiscoveryCard } from '../components/scan/network-enrichment.js';
import { buildBuildEvidenceCard, buildMisconfigurationsCard, buildSSPEvidenceCard } from '../components/scan/evidence.js';
import { _findingsRegistry, _registerFinding } from '../state/registries.js';
import { buildSBOMSection } from '../components/scan/sbom.js';
import { buildAPISection } from '../components/scan/api-endpoints.js';
import { buildFindingsSection } from '../components/scan/findings.js';
import { buildSuppressedSection } from '../components/scan/suppressed.js';
import { calculateScorecardForScan } from '../components/scorecard.js';

// Globals that other modules put on window (see index.js):
/* global apiRender, openFindingDetail, sbomRender, setActive */

export async function renderScanDetail(scanId, openFindingId = '', openFindingPackage = '') {
  setActive('applications');
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
        const jsonBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/stig-findings-json?slug=${encodeURIComponent(r.slug)}" download>↓ .json</a>`;
        return `
          <div class="stig-row">
            <span class="stig-row-label" title="${esc(r.slug)}">${esc(slugLabel)}</span>
            <span class="stig-row-counts">
              <span class="stig-mini open">${esc(r.open)} open</span>
              <span class="stig-mini pass">${esc(r.pass)} pass</span>
              <span class="stig-mini na">${esc(r.na)} n/a</span>
              <span class="stig-mini total">${esc(r.total)} total</span>
            </span>
            <span class="stig-row-btns">${mdBtn}${cklbBtn}${jsonBtn}</span>
          </div>`;
      }).join('') : '';

      // Primary (combined) download buttons
      const mdBtn = scan.has_stig_report
        ? `<a class="btn btn-sm" href="${esc(scan.stig_report_url)}" download>↓ findings.md</a>` : '';
      const cklbBtn = scan.has_stig_cklb
        ? `<a class="btn btn-sm" href="${esc(scan.stig_cklb_url)}" download>↓ findings.cklb</a>` : '';
      const jsonBtn = `<a class="btn btn-sm" href="/api/scans/${encodeURIComponent(scanId)}/stig-findings-json" download>↓ findings.json</a>`;

      stigCard = `
        <div class="section findings-section-wrapper">
          <details class="findings-collapsible" style="border-left-color:var(--accent)">
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
                ${(scan.stig_nr || 0) > 0 ? `<span class="stig-mini" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(scan.stig_nr || 0)} evidence needed</span>` : ''}
                <span class="stig-mini total">${esc(scan.stig_total || 0)} total</span>
              </span>
              <span style="display:flex;align-items:center;gap:8px">
                ${mdBtn ? mdBtn.replace('btn-sm', 'btn-sm').replace('>', ' onclick="event.stopPropagation()">') : ''}
                ${cklbBtn ? cklbBtn.replace('>', ' onclick="event.stopPropagation()">') : ''}
                ${jsonBtn.replace('>', ' onclick="event.stopPropagation()">')}
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
                  <span class="lbl" title="Not Reviewed: open until evidence is supplied">Evidence needed</span>
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

    // Environment-dependent gaps (e.g. a baseline-image registry pull that
    // failed, or an auto-exclusion filter) mean this scan's counts may not
    // be directly comparable to another environment's run of the same
    // target. Surface them plainly instead of leaving users to guess why
    // two scans of the same app differ.
    const envNotes = scan.environment_notes || [];
    const envNotesBanner = envNotes.length ? `
      <div class="section" style="border-left:3px solid var(--medium);padding:12px 16px;margin-bottom:16px;background:rgba(245,158,11,0.08)">
        <div style="font-weight:600;font-size:13px;margin-bottom:6px;color:var(--medium)">⚠ Environment Notes — results may differ from other environments</div>
        ${envNotes.map(n => `<div style="font-size:12.5px;color:var(--text-muted);margin-top:4px"><strong>${esc(n.layer)}:</strong> ${esc(n.message)}</div>`).join('')}
      </div>` : '';

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

      ${pageHeader(`Scan Details ${statusBadge(status)} ${gateBadge(scan)}`, { subtitle: `Findings, compliance, and evidence collected for <strong>${esc(scan.target)}</strong> on ${fmtDate(scan.timestamp)}.`, actions: `<button class="btn" onclick="navigate('#/jira-review/${encodeURIComponent(scanId)}')"
            title="Select findings to create as Jira tickets">
            Jira Review
          </button>
          ${repoUrl
            ? `<button class="btn btn-primary"
                 onclick="navigate('#/new-scan?target=${encodeURIComponent(repoUrl)}')">
                 ▶ Run Scan
               </button>`
            : `<button class="btn btn-primary" onclick="navigate('#/new-scan')">▶ Run Scan</button>`}
          ${scan.has_dashboard
            ? `<button class="btn"
                 onclick="window.open('/api/scans/${encodeURIComponent(scanId)}/dashboard','_blank')">
                 Export HTML ↗
               </button>`
            : ''}
          <div class="split-btn" id="download-split-btn">
            <a class="btn split-btn-main" href="/api/scans/${encodeURIComponent(scanId)}/download" download
               title="Download all scan artifacts as ZIP for ATO/IATT submission">
              ↓ Download ZIP
            </a>
            <button class="btn split-btn-toggle" onclick="toggleDownloadMenu(event)"
              title="More download options" aria-haspopup="true" aria-expanded="false">▾</button>
            <div class="split-btn-menu" id="download-split-menu" hidden>
              <a class="split-btn-menu-item" href="/api/scans/${encodeURIComponent(scanId)}/download" download>
                ↓ Download ZIP
                <span class="split-btn-menu-hint">All raw scan artifacts (ATO/IATT bundle)</span>
              </a>
              <a class="split-btn-menu-item" href="/api/scans/${encodeURIComponent(scanId)}/download-json" download>
                ↓ Download JSON
                <span class="split-btn-menu-hint">Full parsed scan result (findings, STIG, ML/AI)</span>
              </a>
            </div>
          </div>
          <button class="btn btn-danger"
            onclick="deleteScan('${esc(scanId)}', '${esc(scan.target)}')"
            title="Permanently delete this scan">
            Delete Scan
          </button>` })}

      ${envNotesBanner}

      <div class="stats-grid" style="margin-bottom:24px">
        <div class="stat-card">
          <div class="stat-label">Application</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.target)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Scan Type</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scanTypeLabel(scan.scan_type))}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">User</div>
          <div class="stat-value" style="font-size:17px;word-break:break-word">${esc(scan.user || '—')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Timestamp</div>
          <div class="stat-value" style="font-size:13px">${fmtDate(scan.timestamp)}</div>
        </div>
      </div>

      <div class="result-section-box">
        <div class="result-section-box-title">Vulnerabilities</div>
        <div class="stats-grid" style="margin-bottom:0">
          <div class="stat-card critical">
            <div class="stat-label">Critical</div>
            <div class="stat-value">${esc(scan.critical)}</div>
          </div>
          <div class="stat-card high">
            <div class="stat-label">High</div>
            <div class="stat-value">${esc(scan.high)}</div>
          </div>
          <div class="stat-card medium">
            <div class="stat-label">Medium</div>
            <div class="stat-value">${esc(scan.medium)}</div>
          </div>
          <div class="stat-card low">
            <div class="stat-label">Low</div>
            <div class="stat-value">${esc(scan.low)}</div>
          </div>
        </div>
      </div>

      ${buildFindingsSection(scan.findings)}

      ${buildSuppressedSection(scan.suppressed_findings)}

      ${stigCard}

      ${buildPoamSection(scanId)}

      ${buildModelSecurityCard(scan)}

      ${buildMisconfigurationsCard(scan)}

      ${buildBuildEvidenceCard(scan)}

      ${buildSSPEvidenceCard(scan)}

      ${buildSBOMSection(scan.sbom, scanId)}

      ${buildAPISection(scan.api_discovery)}

      ${buildNetworkDiscoveryCard(scan)}

      ${scan.file_statistics && Object.keys(scan.file_statistics).length ? `
        <div class="result-section-box">
          <div class="result-section-box-title">File Statistics</div>
          <div class="stats-grid" style="margin-bottom:0">
            ${Object.entries(scan.file_statistics).map(([k, v]) => `
              <div class="stat-card">
                <div class="stat-label">${esc(k.replace(/_/g, ' '))}</div>
                <div class="stat-value" style="font-size:20px">${esc(v)}</div>
              </div>`).join('')}
          </div>
        </div>` : ''}

      <div id="scorecard-container"></div>

      ${dedupeTools(scan.tools_analyzed).length ? `
        <div class="result-section-box">
          <div class="result-section-box-title">Tools Analyzed</div>
          <div class="tools-list">
            ${dedupeTools(scan.tools_analyzed).map(t =>
              `<span class="tool-tag">${esc(t)}</span>`).join('')}
          </div>
        </div>` : ''}`;
    if (window._sbomPendingUid) { sbomRender(window._sbomPendingUid); window._sbomPendingUid = null; }
    if (window._apiPendingUid) { apiRender(window._apiPendingUid); window._apiPendingUid = null; }
    
    // Automatically generate scorecard
    calculateScorecardForScan(scanId);

    if (openFindingId) {
      const wantId = openFindingId.toLowerCase();
      const wantPackage = openFindingPackage.toLowerCase();
      let findingId = null;
      for (const [rid, f] of _findingsRegistry) {
        const packageName = String(f.package || f.component || '').toLowerCase();
        if (String(f.id || '').toLowerCase() === wantId &&
            (!wantPackage || packageName === wantPackage)) {
          findingId = rid;
          break;
        }
      }
      if (findingId === null) {
        const severities = ['critical', 'high', 'medium', 'low'];
        for (const severity of severities) {
          const finding = (scan.findings[`${severity}_findings`] || []).find(f => {
            const packageName = String(f.package || f.component || '').toLowerCase();
            return String(f.id || '').toLowerCase() === wantId &&
              (!wantPackage || packageName === wantPackage);
          });
          if (finding) {
            findingId = _registerFinding(finding);
            break;
          }
        }
      }
      if (findingId !== null) openFindingDetail(findingId);
    }
    page.querySelectorAll('.poam-card').forEach(window.loadPoamCard);
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}
