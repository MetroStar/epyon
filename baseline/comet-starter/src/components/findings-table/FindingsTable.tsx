import React from 'react';
import type { Finding } from '@src/api/types';
import { SeverityBadge } from '../severity-badge/SeverityBadge';

interface Props {
  title: string;
  findings: Finding[];
  severity: string;
}

const NVD_URL = 'https://nvd.nist.gov/vuln/detail/';
const MAX_ROWS = 200;

export const FindingsTable = ({ title, findings, severity }: Props): React.ReactElement | null => {
  if (!findings.length) return null;
  const rows = findings.slice(0, MAX_ROWS);
  const overflow = findings.length - MAX_ROWS;

  return (
    <div className="epyon-section">
      <div className="epyon-section-title">
        <SeverityBadge severity={severity} count={findings.length} />
        <span style={{ marginLeft: 8 }}>{title}</span>
      </div>
      <div className="epyon-table-wrap">
        <table className="usa-table usa-table--striped usa-table--borderless width-full">
          <thead>
            <tr>
              <th>Tool</th>
              <th>ID / CVE</th>
              <th>Title</th>
              <th>Package</th>
              <th>Fixed In</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f, i) => (
              <tr key={`${f.tool}-${f.id}-${i}`}>
                <td>
                  <span className="epyon-badge epyon-badge--unknown">{f.tool}</span>
                </td>
                <td>
                  {f.id && f.id.match(/^CVE-/) ? (
                    <a
                      className="epyon-link"
                      href={`${NVD_URL}${f.id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {f.id}
                    </a>
                  ) : (
                    f.id || '—'
                  )}
                </td>
                <td style={{ maxWidth: 300, wordBreak: 'break-word' }}>
                  {f.title || f.description || '—'}
                </td>
                <td>
                  {f.package || '—'}
                  {f.version ? <span className="epyon-muted"> {f.version}</span> : null}
                </td>
                <td>{f.fixed_version || <span className="epyon-muted">—</span>}</td>
                <td style={{ maxWidth: 200, wordBreak: 'break-all', fontSize: 11 }}>
                  {f.target || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {overflow > 0 && (
        <p className="epyon-muted" style={{ fontSize: 12, marginTop: 4 }}>
          …and {overflow} more rows not shown. Use the dashboard for full details.
        </p>
      )}
    </div>
  );
};
