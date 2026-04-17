import React, { useEffect, useRef } from 'react';
import type { Job } from '@src/api/types';

interface Props {
  job: Job;
  onCancel?: () => void;
}

export const JobOutput = ({ job, onCancel }: Props): React.ReactElement => {
  const logRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom as lines come in
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [job.output.length]);

  const isActive = job.status === 'running' || job.status === 'queued';

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <span className={`epyon-job-status epyon-job-status--${job.status}`}>
          {isActive && <span className="epyon-pulse" />}
          {job.status.toUpperCase()}
        </span>
        {isActive && onCancel && (
          <button
            className="usa-button usa-button--secondary"
            style={{ padding: '4px 12px', fontSize: 12 }}
            onClick={onCancel}
          >
            Cancel
          </button>
        )}
        {job.exit_code !== null && (
          <span className="epyon-muted" style={{ fontSize: 12 }}>
            exit {job.exit_code}
          </span>
        )}
      </div>
      <div className="epyon-log" ref={logRef}>
        {job.output.length === 0 ? (
          <span className="epyon-muted">Waiting for output…</span>
        ) : (
          job.output.map((line, i) => (
            <div
              key={i}
              className={
                line.toLowerCase().includes('error') || line.toLowerCase().includes('fail')
                  ? 'epyon-log__line--err'
                  : undefined
              }
            >
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
