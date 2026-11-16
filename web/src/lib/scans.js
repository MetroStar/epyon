import { ucFirst } from './format.js';

export const _SCAN_TYPE_LABELS = {
  full:        'Full',
  quick:       'Quick',
  nightly:     'Nightly',
  baseline:    'Baseline',
  stig:        'STIG',
  local_model: 'Local Model',
  container_image: 'Container Image',
};

export function scanTypeLabel(type) {
  return _SCAN_TYPE_LABELS[type] || ucFirst(type || 'full');
}

export function computeStatus(scan) {
  if (!scan || typeof scan !== 'object') return 'unknown';
  if ((scan.critical || 0) > 0) return 'critical';
  if ((scan.high    || 0) > 0) return 'high';
  if ((scan.medium  || 0) > 0) return 'medium';
  if ((scan.low     || 0) > 0) return 'low';
  if (scan.scan_id)             return 'clean';
  return 'unknown';
}

// ── Finding source classification ────────────────────────────
export function findingSource(f) {
  const type = (f.type || '').toLowerCase();
  const tool = (f.tool || '').toLowerCase();
  
  // ML Security findings
  if (tool === 'picklescan' || tool === 'model-provenance' || tool === 'inference-security' || tool === 'ml-runtime') return 'ml';
  
  // Traditional sources
  // "-base-" covers Trivy/Grype base-image scans (tool names like
  // "trivy-base-python-3.12-slim-bookworm") — they're container-origin CVEs,
  // not application code, even though their "type" predates the
  // container_vulnerability tagging added in generate-scan-findings-summary.sh.
  if (type === 'container_vulnerability' || tool === 'anchore' || tool.includes('-base-')) return 'container';
  if (type === 'iac_misconfiguration' || tool === 'checkov')   return 'iac';
  if (type.includes('credential') || type.includes('secret') || tool === 'trufflehog') return 'secret';
  if (type === 'eol_package' || tool === 'xeol')               return 'eol';
  if (type === 'supply_chain_misconfiguration' || tool === 'compromisedsourcecheck') return 'supply_chain';
  return 'code';
}
