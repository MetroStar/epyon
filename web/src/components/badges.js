import { esc, ucFirst } from '../lib/format.js';
import { findingSource } from '../lib/scans.js';

// ── UI atoms ──────────────────────────────────────────────────
export function sevBadge(severity, count) {
  return `<span class="sev-badge ${esc(severity)}">${esc(count)} ${ucFirst(severity)}</span>`;
}

export function findingSourceBadge(f) {
  const src = findingSource(f);
  const cfg = {
    container: { style: 'background:var(--accent-bg);color:var(--accent);border:1px solid #1d4ed866', label: '📦 Container' },
    code:      { style: 'background:var(--pass-bg);color:var(--pass);border:1px solid #15803d66', label: '💻 Code'      },
    iac:       { style: 'background:var(--purple-bg);color:var(--purple);border:1px solid #7e22ce66', label: '🔧 IaC'       },
    secret:    { style: 'background:var(--critical-bg);color:var(--critical);border:1px solid #b91c1c66', label: '🔑 Secret'    },
    eol:       { style: 'background:var(--medium-bg);color:var(--medium);border:1px solid #b4530066', label: '⏱ EOL'        },
    ml:        { style: 'background:var(--purple-bg);color:var(--purple);border:1px solid #7c3aed66', label: '🧠 ML'         },
    supply_chain: { style: 'background:var(--accent-bg);color:var(--accent);border:1px solid #0369a166', label: '🔗 Supply Chain' },
  };
  const { style, label } = cfg[src] || cfg.code;
  // For container-origin findings, surface *which* image caused the CVE
  // (container_image set by generate-scan-findings-summary.sh, falling back
  // to target) so it's never mistaken for an app-code finding.
  let containerName = '';
  if (src === 'container') {
    containerName = (f && (f.container_image || f.target)) || '';
  }
  const title = containerName ? ` title="Container: ${esc(containerName)}"` : '';
  const nameSuffix = containerName
    ? `<span style="opacity:0.85"> · ${esc(containerName.length > 28 ? containerName.slice(0, 28) + '…' : containerName)}</span>`
    : '';
  return `<span style="font-size:12px;padding:1px 6px;border-radius:3px;white-space:nowrap;${style}"${title}>${label}${nameSuffix}</span>`;
}

// Returns a source badge from a sources array (top_cves aggregated data)
export function sourcesBadges(sources) {
  return (sources || []).map(s => findingSourceBadge({ type: s === 'container' ? 'container_vulnerability' : 'vulnerability' })).join(' ');
}

export function gateBadge(scan) {
  // Overall PASS/FAIL gate: FAILs on any Critical vulnerability, malware hit,
  // or secret, or when High vulnerabilities (Checkov
  // misconfigurations excluded) reach 5. Dashboard-only (see compute_gate_status() in
  // web/api/parsers.py) — does not affect CI/GitHub Actions exit codes.
  if (!scan || scan.gate_status == null) return '';
  return scan.gate_status === 'fail'
    ? '<span class="sev-badge critical" title="Critical vulnerability/malware/secret found, or 5 or more High vulnerabilities">🔴 FAIL</span>'
    : '<span class="sev-badge clean" title="No Critical findings and fewer than 5 High vulnerabilities">🟢 PASS</span>';
}

export function sevBadgeRow(scan) {
  const parts = [];
  if (scan.critical > 0) parts.push(sevBadge('critical', scan.critical));
  if (scan.high     > 0) parts.push(sevBadge('high',     scan.high));
  if (scan.medium   > 0) parts.push(sevBadge('medium',   scan.medium));
  if (scan.low      > 0) parts.push(sevBadge('low',      scan.low));
  if (parts.length === 0) parts.push('<span class="sev-badge clean">✓ Clean</span>');
  return parts.join('');
}

export function hfStatusBadge(scan) {
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

export function statusBadge(status) {
  const labels = {
    critical: 'Critical', high: 'High', medium: 'Medium',
    low: 'Low', clean: 'Clean', unknown: 'Unknown',
  };
  return `<span class="status-badge ${esc(status)}">${labels[status] || 'Unknown'}</span>`;
}
