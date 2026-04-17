import React from 'react';
import { useNavigate } from 'react-router-dom';
import type { Scan } from '@src/api/types';
import { SeverityBadge } from '../severity-badge/SeverityBadge';

interface Props {
  scans: Scan[];
}

function getStatus(scan: Scan): string {
  if (scan.critical > 0) return 'critical';
  if (scan.high > 0) return 'high';
  if (scan.medium > 0) return 'medium';
  if (scan.low > 0) return 'low';
  return 'clean';
}

function fmtDate(ts: string): string {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export const ScanTimeline = ({ scans }: Props): React.ReactElement => {
  const navigate = useNavigate();

  if (!scans.length) {
    return (
      <div className="epyon-empty">
        <h3>No scans yet</h3>
        <p>Run a scan to see results here.</p>
      </div>
    );
  }

  return (
    <ul className="epyon-timeline">
      {scans.map((scan) => {
        const status = getStatus(scan);
        return (
          <li
            key={scan.scan_id}
            className="epyon-timeline__item"
            onClick={() => navigate(`/scans/${scan.scan_id}`)}
          >
            <div className={`epyon-timeline__dot epyon-timeline__dot--${status}`} />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--epyon-text)' }}>
                  {scan.scan_id}
                </span>
                {scan.ci_source && (() => {
                  const ci = scan.ci_source;
                  const runUrl = ci.repo && ci.run_id
                    ? `https://github.com/${ci.repo}/actions/runs/${ci.run_id}`
                    : ci.repo
                    ? `https://github.com/${ci.repo}/actions`
                    : null;
                  const label = ci.event === 'schedule'
                    ? 'Nightly ↗'
                    : ci.event === 'pull_request' || ci.event === 'pull_request_target'
                    ? 'PR ↗'
                    : ci.event === 'push'
                    ? 'Push ↗'
                    : 'GH Actions ↗';
                  return (
                    <a
                      href={runUrl ?? '#'}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="epyon-badge epyon-badge--ci"
                      style={{ textDecoration: 'none' }}
                      title={[ci.repo, ci.workflow, ci.branch, ci.run_id ? `Run #${ci.run_id}` : ''].filter(Boolean).join(' · ')}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {label}
                    </a>
                  );
                })()}
              </div>
              <div className="epyon-timeline__badges">
                {scan.critical > 0 && <SeverityBadge severity="critical" count={scan.critical} />}
                {scan.high > 0     && <SeverityBadge severity="high"     count={scan.high} />}
                {scan.medium > 0   && <SeverityBadge severity="medium"   count={scan.medium} />}
                {scan.low > 0      && <SeverityBadge severity="low"      count={scan.low} />}
                {!scan.total && <SeverityBadge severity="clean" label="Clean" />}
              </div>
              <div className="epyon-timeline__meta">
                {fmtDate(scan.timestamp)}
                {scan.user && ` · ${scan.user}`}
                {scan.scan_type && ` · ${scan.scan_type}`}
                {scan.tools_analyzed?.length > 0 && ` · ${scan.tools_analyzed.join(', ')}`}
                {scan.ci_source?.repo && ` · ${scan.ci_source.repo}`}
              </div>
            </div>
            {scan.has_dashboard && (
              <a
                className="epyon-link"
                style={{ fontSize: 12, flexShrink: 0 }}
                href={scan.dashboard_url ?? '#'}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
              >
                Dashboard ↗
              </a>
            )}
          </li>
        );
      })}
    </ul>
  );
};
