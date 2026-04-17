import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useApplications, useHideApplication } from '@src/api/hooks';
import { SeverityBadge } from '@src/components/severity-badge/SeverityBadge';

function fmtDate(ts: string) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleDateString(); } catch { return ts; }
}

export const Applications = (): React.ReactElement => {
  const { data: apps, isLoading } = useApplications();
  const hideApp = useHideApplication();
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const handleDelete = (name: string) => {
    hideApp.mutate(name, { onSuccess: () => setConfirmDelete(null) });
  };

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>Applications</h1>
        <Link to="/new-scan"><button className="usa-button">+ Run Scan</button></Link>
      </div>

      {isLoading ? (
        <div className="epyon-loading"><div className="epyon-spinner" /> Loading…</div>
      ) : !apps?.length ? (
        <div className="epyon-empty">
          <h3>No applications found</h3>
          <p>Scans will appear here automatically after running.</p>
          <Link to="/new-scan"><button className="usa-button">Run First Scan</button></Link>
        </div>
      ) : (
        <div className="epyon-table-wrap">
          <table className="usa-table usa-table--striped usa-table--borderless width-full">
            <thead>
              <tr>
                <th>Application</th>
                <th>Scans</th>
                <th>Last Scanned</th>
                <th>Type</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => (
                <tr key={app.name}>
                  <td>
                    <Link to={`/applications/${app.name}`} className="epyon-link">
                      {app.name}
                    </Link>
                  </td>
                  <td>{app.scan_count}</td>
                  <td>{fmtDate(app.last_scanned)}</td>
                  <td className="epyon-muted">{app.scan_type || '—'}</td>
                  <td>{app.critical > 0 ? <SeverityBadge severity="critical" count={app.critical} /> : <span className="epyon-muted">0</span>}</td>
                  <td>{app.high > 0     ? <SeverityBadge severity="high"     count={app.high} />     : <span className="epyon-muted">0</span>}</td>
                  <td>{app.medium > 0   ? <SeverityBadge severity="medium"   count={app.medium} />   : <span className="epyon-muted">0</span>}</td>
                  <td>{app.low > 0      ? <SeverityBadge severity="low"      count={app.low} />      : <span className="epyon-muted">0</span>}</td>
                  <td><SeverityBadge severity={app.status} label={app.status} /></td>
                  <td>
                    {confirmDelete === app.name ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                        <span style={{ color: 'var(--epyon-text-muted)' }}>Remove?</span>
                        <button
                          className="usa-button usa-button--secondary"
                          style={{ padding: '2px 8px', fontSize: 11 }}
                          onClick={() => handleDelete(app.name)}
                          disabled={hideApp.isPending}
                        >Yes</button>
                        <button
                          className="usa-button usa-button--unstyled"
                          style={{ fontSize: 11, color: 'var(--epyon-text-muted)' }}
                          onClick={() => setConfirmDelete(null)}
                        >Cancel</button>
                      </span>
                    ) : (
                      <span style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                        <Link to={`/applications/${app.name}`} className="epyon-link" style={{ fontSize: 12 }}>
                          View →
                        </Link>
                        <button
                          className="usa-button usa-button--unstyled"
                          style={{ fontSize: 12, color: 'var(--epyon-text-dim)' }}
                          title="Hide from dashboard"
                          onClick={() => setConfirmDelete(app.name)}
                        >✕</button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
