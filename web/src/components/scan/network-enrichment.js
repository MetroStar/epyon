import { emptyNote } from '../layout.js';
import { esc } from '../../lib/format.js';

// Legacy globals still provided by main.js (see index.js):
/* global _ppsmRegistry */

export function buildEnrichmentCard(findings) {
  if (!findings) return '';
  const enr = findings.enrichment;
  if (!enr || (enr.cisa_kev_total == null && enr.nvd_total == null)) return '';
  const kevTotal = enr.cisa_kev_total || 0;
  const nvdTotal = enr.nvd_total || 0;
  if (kevTotal === 0 && nvdTotal === 0) return '';

  const hasKev = kevTotal > 0;
  const accentColor = hasKev ? 'var(--critical)' : 'var(--accent)';

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
            ${hasKev ? `<span style="background:var(--critical-bg);color:var(--critical);border:1px solid #b91c1c;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:700">${esc(kevTotal)} KEV</span>` : ''}
            <span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(nvdTotal)} NVD enriched</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body" style="padding:0 18px 16px">
          <div class="detail-grid" style="margin-top:12px;margin-bottom:0">
            ${hasKev ? `
            <div class="detail-card" style="border-color:var(--critical-bg);background:rgba(127,29,29,0.12)">
              <div class="label" style="color:var(--critical)">CISA KEV Matches</div>
              <div class="value" style="color:var(--critical)">${esc(kevTotal)}</div>
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
          <p style="color:var(--critical);font-size:12px;margin:12px 0 4px">
            ⚠ ${esc(kevTotal)} finding${kevTotal > 1 ? 's' : ''} match CISA's Known Exploited Vulnerabilities catalog —
            actively exploited in the wild. Findings marked <strong>KEV</strong> above require immediate attention.
          </p>` : ''}
          ${catalogLink ? `<div style="margin-top:8px">${catalogLink}</div>` : ''}
        </div>
      </details>
    </div>`;
}

export function buildNetworkDiscoveryCard(scan) {
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
            <th scope="col" data-col="0" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',0)">File <span class="sort-icon">⇅</span></th>
            <th scope="col" data-col="1" class="sortable-th" style="text-align:left;padding:2px 8px 2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',1)">Service <span class="sort-icon">⇅</span></th>
            <th scope="col" data-col="2" class="sortable-th" style="text-align:left;padding:2px 0;font-weight:500" onclick="sortPpsmTable('${tblId}',2)">Port / Mapping <span class="sort-icon">⇅</span></th>
          </tr>
        </thead>
        <tbody>
          ${r.items.map(p => `
            <tr style="border-top:1px solid var(--border)">
              <td style="padding:3px 8px 3px 0;color:var(--text-muted);font-family:monospace;font-size:12px">${esc(p.file || '')}</td>
              <td style="padding:3px 8px 3px 0">${esc(p.service || '')}</td>
              <td style="padding:3px 0;font-family:monospace">${esc(p.mapping || String(p.port || ''))}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  }).join('') : emptyNote('No static port definitions found.');

  const activeBadge = nd.active_scan_run
    ? '<span style="background:var(--low-bg,#fffbe6);color:var(--low);border:1px solid var(--low);border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600">nmap active</span>'
    : '<span style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:12px">static only</span>';

  const portsBadge = nd.total_ports
    ? `<span class="sev-badge" style="background:var(--bg-input);color:var(--text-muted);border:1px solid var(--border)">${esc(String(nd.total_ports))} ports</span>`
    : '';

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--accent)">
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
