import { esc } from '../../lib/format.js';

export function buildSuppressedSection(items) {
  if (!items || items.length === 0) return '';

  const rows = items.map(s => {
    const typeColor = s.type === 'tool' ? '#6366f1' : s.type === 'cve' ? '#f59e0b' : '#6b7280';
    return `<tr>
      <td style="padding:5px 10px;font-size:12px">
        <span class="tool-tag" style="font-size:12px;padding:1px 6px;background:${typeColor}22;color:${typeColor};border:1px solid ${typeColor}44">${esc(s.type || 'unknown')}</span>
      </td>
      <td style="padding:5px 10px;font-family:monospace;font-size:12px;font-weight:600">${esc(s.value || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:var(--text-muted)">${esc(s.tool || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;max-width:400px">${esc(s.reason || '—')}</td>
      <td style="padding:5px 10px;font-size:12px;color:var(--text-muted)">${esc(s.approved_by || '—')}</td>
      <td style="padding:5px 10px;font-size:12px">
        ${s.severity && s.severity !== 'N/A'
          ? `<span class="sev-badge sev-${esc(s.severity.toLowerCase())}">${esc(s.severity)}</span>`
          : '<span style="color:var(--text-muted)">—</span>'}
      </td>
    </tr>`;
  }).join('');

  return `
    <div class="section findings-section-wrapper">
      <details class="findings-collapsible" style="border-left-color:var(--medium)">
        <summary class="findings-summary">
          <span class="findings-summary-left">
            <span class="findings-chevron" aria-hidden="true"></span>
            <span class="findings-summary-title">Suppressed Findings</span>
            <span class="sev-badge" style="background:var(--medium-bg);color:var(--medium);border:1px solid color-mix(in srgb, var(--medium) 27%, transparent)">${items.length}</span>
          </span>
          <span class="findings-summary-hint">Click to expand</span>
        </summary>
        <div class="findings-body">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px">Suppressed by <code>.epyon-ignore.yml</code> rules in the scanned repository.</div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Value / ID</th>
                  <th scope="col">Tool</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Approved By</th>
                  <th scope="col">Severity</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </details>
    </div>`;
}
