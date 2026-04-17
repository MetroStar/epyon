import React from 'react';
import { Link, useParams } from 'react-router-dom';
import { useScan } from '@src/api/hooks';
import { StatCard } from '@src/components/stat-card/StatCard';
import { FindingsTable } from '@src/components/findings-table/FindingsTable';

function fmtDate(ts: string) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export const ScanDetail = (): React.ReactElement => {
  const { id = '' } = useParams<{ id: string }>();
  const { data: scan, isLoading, error } = useScan(id);

  if (isLoading) return <div className="grid-container"><div className="epyon-loading"><div className="epyon-spinner" /> Loading scan…</div></div>;
  if (error || !scan) return (
    <div className="grid-container">
      <div className="usa-alert usa-alert--error" style={{ marginTop: '2rem' }}>
        <div className="usa-alert__body">Scan not found.</div>
      </div>
    </div>
  );

  const f = scan.findings;

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
          <li className="usa-breadcrumb__list-item">
            <Link to={`/applications/${scan.target}`} className="usa-breadcrumb__link">{scan.target}</Link>
          </li>
          <li className="usa-breadcrumb__list-item usa-current" aria-current="page">
            Scan Detail
          </li>
        </ol>
      </nav>

      <div className="epyon-page-header">
        <h1 style={{ fontSize: '1.1rem', wordBreak: 'break-all' }}>{scan.scan_id}</h1>
        {scan.has_dashboard && (
          <a href={scan.dashboard_url ?? '#'} target="_blank" rel="noopener noreferrer">
            <button className="usa-button usa-button--secondary">View Dashboard ↗</button>
          </a>
        )}
      </div>

      {/* Metadata */}
      <div className="epyon-section">
        <div className="epyon-section-title">Scan Info</div>
        <div className="epyon-grid-stats" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))' }}>
          <StatCard value={scan.critical} label="Critical" variant="critical" />
          <StatCard value={scan.high}     label="High"     variant="high" />
          <StatCard value={scan.medium}   label="Medium"   variant="medium" />
          <StatCard value={scan.low}      label="Low"      variant="low" />
          <StatCard value={scan.total}    label="Total"    variant="default" />
        </div>
        <div style={{ marginTop: '1rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.75rem' }}>
          {[
            ['Target',    scan.target],
            ['User',      scan.user || '—'],
            ['Type',      scan.scan_type],
            ['Timestamp', fmtDate(scan.timestamp)],
            ['Tools',     scan.tools_analyzed?.join(', ') || '—'],
            ...(scan.ci_source ? [
              ['CI Source',  scan.ci_source.repo],
              ['Branch',     scan.ci_source.branch],
              ['Commit',     scan.ci_source.commit],
            ] : []),
          ].map(([label, value]) => (
            <div key={label} style={{ background: 'var(--epyon-bg-card)', border: '1px solid var(--epyon-border)', borderRadius: 6, padding: '0.75rem' }}>
              <div style={{ fontSize: 11, color: 'var(--epyon-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</div>
              <div style={{ fontSize: 13, color: 'var(--epyon-text)', wordBreak: 'break-all' }}>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      {f ? (
        <>
          <FindingsTable title="Critical Findings" findings={f.critical_findings} severity="critical" />
          <FindingsTable title="High Findings"     findings={f.high_findings}     severity="high" />
          <FindingsTable title="Medium Findings"   findings={f.medium_findings}   severity="medium" />
          <FindingsTable title="Low Findings"      findings={f.low_findings}      severity="low" />
          {!f.critical_findings.length && !f.high_findings.length && !f.medium_findings.length && !f.low_findings.length && (
            <div className="epyon-empty">
              <h3>No findings</h3>
              <p>This scan returned no security issues.</p>
            </div>
          )}
        </>
      ) : (
        <div className="epyon-loading"><div className="epyon-spinner" /> Loading findings…</div>
      )}
    </div>
  );
};
