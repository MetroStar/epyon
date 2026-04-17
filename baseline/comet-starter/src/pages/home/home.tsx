import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useStats, useApplications, useHideApplication } from '@src/api/hooks';
import { StatCard } from '@src/components/stat-card/StatCard';
import { SeverityBadge } from '@src/components/severity-badge/SeverityBadge';
import { KebabMenu } from '@src/components/kebab-menu/KebabMenu';
import type { Application } from '@src/api/types';

function fmtDate(ts: string) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleDateString(); } catch { return ts; }
}

function borderClass(status: string) {
  if (status === 'critical') return 'epyon-app-card--critical';
  if (status === 'high')     return 'epyon-app-card--high';
  if (status === 'medium')   return 'epyon-app-card--medium';
  if (status === 'low')      return 'epyon-app-card--low';
  if (status === 'clean')    return 'epyon-app-card--clean';
  return '';
}

function AppCard({ app, onHide }: { app: Application; onHide: (name: string) => void }) {
  const navigate = useNavigate();
  return (
    <div className={`epyon-app-card ${borderClass(app.status)}`}>
      <div className="epyon-app-card__header">
        <div>
          <div className="epyon-app-card__name">
            <Link to={`/applications/${app.name}`} className="epyon-link">{app.name}</Link>
          </div>
          <div className="epyon-app-card__meta">
            {fmtDate(app.last_scanned)} · {app.scan_count} scan{app.scan_count !== 1 ? 's' : ''} · {app.scan_type || 'full'}
          </div>
        </div>
        <KebabMenu items={[
          { label: 'View Details', onClick: () => navigate(`/applications/${app.name}`) },
          { label: 'Run Scan',     onClick: () => navigate(`/new-scan?app=${encodeURIComponent(app.name)}`) },
          { label: 'Hide',         onClick: () => onHide(app.name), danger: true },
        ]} />
      </div>
      <div className="epyon-app-card__badges">
        {app.critical > 0 && <SeverityBadge severity="critical" count={app.critical} />}
        {app.high     > 0 && <SeverityBadge severity="high"     count={app.high} />}
        {app.medium   > 0 && <SeverityBadge severity="medium"   count={app.medium} />}
        {app.low      > 0 && <SeverityBadge severity="low"      count={app.low} />}
        {app.critical === 0 && app.high === 0 && app.medium === 0 && app.low === 0 && (
          <SeverityBadge severity="clean" label="Clean" />
        )}
      </div>
    </div>
  );
}

export const Home = (): React.ReactElement => {
  const { data: stats }         = useStats();
  const { data: apps, isLoading } = useApplications();
  const hideApp                 = useHideApplication();

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>Dashboard</h1>
        <Link to="/new-scan"><button className="usa-button">+ Run Scan</button></Link>
      </div>

      {/* Summary stats */}
      <div className="epyon-section">
        <div className="epyon-grid-stats">
          <StatCard value={stats?.total_applications ?? 0} label="Applications" variant="default" />
          <StatCard value={stats?.total_scans        ?? 0} label="Total Scans"  variant="default" />
          <StatCard value={stats?.critical           ?? 0} label="Critical"     variant="critical" />
          <StatCard value={stats?.high               ?? 0} label="High"         variant="high" />
          <StatCard value={stats?.medium             ?? 0} label="Medium"       variant="medium" />
          <StatCard value={stats?.low                ?? 0} label="Low"          variant="low" />
        </div>
      </div>

      {/* App cards */}
      <div className="epyon-section">
        <div className="epyon-section-title">Applications</div>
        {isLoading ? (
          <div className="epyon-loading"><div className="epyon-spinner" /> Loading…</div>
        ) : !apps?.length ? (
          <div className="epyon-empty">
            <h3>No applications found</h3>
            <p>Run a scan to get started.</p>
            <Link to="/new-scan"><button className="usa-button">Run First Scan</button></Link>
          </div>
        ) : (
          <div className="epyon-app-grid">
            {apps.map((app) => (
              <AppCard key={app.name} app={app} onHide={(name) => hideApp.mutate(name)} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

