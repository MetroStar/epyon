import React from 'react';
import { Link } from 'react-router-dom';
import { useStats, useApplications } from '@src/api/hooks';
import { StatCard } from '@src/components/stat-card/StatCard';
import { SeverityBadge } from '@src/components/severity-badge/SeverityBadge';

function fmtDate(ts: string) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleDateString(); } catch { return ts; }
}

export const Overview = (): React.ReactElement => {
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: apps, isLoading: appsLoading } = useApplications();

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>⚡ Epyon Dashboard</h1>
        <Link to="/new-scan">
          <button className="usa-button">+ Run Scan</button>
        </Link>
      </div>

      {/* Stats row */}
      <div className="epyon-section">
        <div className="epyon-section-title">Overview</div>
        {statsLoading ? (
          <div className="epyon-loading"><div className="epyon-spinner" /> Loading…</div>
        ) : stats ? (
          <div className="epyon-grid-stats">
            <StatCard value={stats.total_applications} label="Applications" variant="default" />
            <StatCard value={stats.total_scans}        label="Total Scans"  variant="default" />
            <StatCard value={stats.critical}           label="Critical"     variant="critical" />
            <StatCard value={stats.high}               label="High"         variant="high" />
            <StatCard value={stats.medium}             label="Medium"       variant="medium" />
            <StatCard value={stats.low}                label="Low"          variant="low" />
          </div>
        ) : null}
      </div>

      {/* Applications grid */}
      <div className="epyon-section">
        <div className="epyon-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          Applications
          <Link to="/applications" className="epyon-link" style={{ fontSize: 12 }}>View all →</Link>
        </div>
        {appsLoading ? (
          <div className="epyon-loading"><div className="epyon-spinner" /> Loading…</div>
        ) : !apps?.length ? (
          <div className="epyon-empty">
            <h3>No applications yet</h3>
            <p>Run a scan to get started.</p>
            <Link to="/new-scan"><button className="usa-button">Run First Scan</button></Link>
          </div>
        ) : (
          <div className="epyon-grid-auto">
            {apps.map((app) => (
              <Link key={app.name} to={`/applications/${app.name}`} className="epyon-app-card epyon-app-card--${app.status}"
                style={{ borderLeftColor: severityColor(app.status) }}>
                <div className="epyon-app-card__name">{app.name}</div>
                <div className="epyon-app-card__meta">
                  {app.scan_count} scan{app.scan_count !== 1 ? 's' : ''} · Last: {fmtDate(app.last_scanned)}
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {app.critical > 0 && <SeverityBadge severity="critical" count={app.critical} />}
                  {app.high > 0     && <SeverityBadge severity="high"     count={app.high} />}
                  {app.medium > 0   && <SeverityBadge severity="medium"   count={app.medium} />}
                  {app.low > 0      && <SeverityBadge severity="low"      count={app.low} />}
                  {!app.critical && !app.high && !app.medium && !app.low && (
                    <SeverityBadge severity="clean" label="Clean" />
                  )}
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

function severityColor(status: string): string {
  const map: Record<string, string> = {
    critical: 'var(--epyon-critical)',
    high:     'var(--epyon-high)',
    medium:   'var(--epyon-medium)',
    low:      'var(--epyon-low)',
    clean:    'var(--epyon-clean)',
  };
  return map[status] ?? 'var(--epyon-border)';
}
