import React from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAppScans } from '@src/api/hooks';
import { ScanTimeline } from '@src/components/scan-timeline/ScanTimeline';
import { StatCard } from '@src/components/stat-card/StatCard';

function repoUrl(scans: import('@src/api/types').Scan[] | undefined): string {
  // Prefer the ci_source repo from the latest scan, fall back to app name
  const ci = scans?.[0]?.ci_source;
  if (ci?.repo) return `https://github.com/${ci.repo}`;
  return '';
}

export const AppDetail = (): React.ReactElement => {
  const { name = '' } = useParams<{ name: string }>();
  const { data: scans, isLoading, error } = useAppScans(name);

  const latest = scans?.[0];

  return (
    <div className="grid-container">
      {/* Breadcrumb */}
      <nav className="usa-breadcrumb" aria-label="Breadcrumbs">
        <ol className="usa-breadcrumb__list">
          <li className="usa-breadcrumb__list-item">
            <Link to="/" className="usa-breadcrumb__link">Home</Link>
          </li>
          <li className="usa-breadcrumb__list-item">
            <Link to="/applications" className="usa-breadcrumb__link">Applications</Link>
          </li>
          <li className="usa-breadcrumb__list-item usa-current" aria-current="page">
            {name}
          </li>
        </ol>
      </nav>

      <div className="epyon-page-header">
        <h1>{name}</h1>
        <Link to={`/new-scan?target=${encodeURIComponent(repoUrl(scans))}&app=${encodeURIComponent(name)}`}>
          <button className="usa-button">Run New Scan</button>
        </Link>
      </div>

      {/* Latest scan summary */}
      {latest && (
        <div className="epyon-section">
          <div className="epyon-section-title">Latest Scan Summary</div>
          <div className="epyon-grid-stats">
            <StatCard value={latest.critical} label="Critical" variant="critical" />
            <StatCard value={latest.high}     label="High"     variant="high" />
            <StatCard value={latest.medium}   label="Medium"   variant="medium" />
            <StatCard value={latest.low}      label="Low"      variant="low" />
            <StatCard value={latest.total}    label="Total"    variant="default" />
            <StatCard value={scans?.length ?? 0} label="Total Scans" variant="default" />
          </div>
        </div>
      )}

      {/* STIG compliance summary (only shown when Layer 13 data is present) */}
      {latest?.stig_total != null && (
        <div className="epyon-section">
          <div className="epyon-section-title">STIG Compliance — App Sec Dev STIG R4V6</div>
          <div className="epyon-grid-stats">
            <StatCard value={latest.stig_pass  ?? 0} label="Not a Finding" variant="clean" />
            <StatCard value={latest.stig_open  ?? 0} label="Open"          variant="critical" />
            <StatCard value={latest.stig_na    ?? 0} label="Not Applicable" variant="default" />
            <StatCard value={latest.stig_total ?? 0} label="Controls Assessed" variant="default" />
          </div>
        </div>
      )}

      {/* Scan history timeline */}
      <div className="epyon-section">
        <div className="epyon-section-title">Scan History</div>
        {isLoading ? (
          <div className="epyon-loading"><div className="epyon-spinner" /> Loading…</div>
        ) : error ? (
          <div className="usa-alert usa-alert--error">
            <div className="usa-alert__body">Failed to load scans.</div>
          </div>
        ) : (
          <div style={{ background: 'var(--epyon-bg-card)', border: '1px solid var(--epyon-border)', borderRadius: 8, padding: '0 1rem' }}>
            <ScanTimeline scans={scans ?? []} />
          </div>
        )}
      </div>
    </div>
  );
};
