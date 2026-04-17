import React, { useState } from 'react';
import { useTriggerScan, useJob, useCancelJob } from '@src/api/hooks';
import { JobOutput } from '@src/components/job-output/JobOutput';
import { Link } from 'react-router-dom';

const SCAN_TYPES = ['full', 'quick', 'images', 'analysis'];

export const NewScan = (): React.ReactElement => {
  const [target, setTarget]       = useState('');
  const [scanType, setScanType]   = useState('full');
  const [jobId, setJobId]         = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  const trigger    = useTriggerScan();
  const cancelMut  = useCancelJob();
  const isRunning  = jobId !== null && submitted;
  const { data: job } = useJob(jobId, isRunning && (
    (jobId !== null) ? true : false
  ));

  const isDone = job && ['completed', 'failed', 'error', 'cancelled'].includes(job.status);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    try {
      const res = await trigger.mutateAsync({ target: target.trim(), scan_type: scanType });
      setJobId(res.job_id);
      setSubmitted(true);
    } catch {
      // error shown via trigger.error
    }
  };

  const handleCancel = () => {
    if (jobId) cancelMut.mutate(jobId);
  };

  const handleReset = () => {
    setTarget('');
    setScanType('full');
    setJobId(null);
    setSubmitted(false);
    trigger.reset();
  };

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>Run Scan</h1>
      </div>

      {!submitted ? (
        <div style={{ maxWidth: 600 }}>
          <form onSubmit={handleSubmit}>
            <div className="usa-form-group">
              <label className="usa-label" htmlFor="scan-target">
                Target <span style={{ color: 'var(--epyon-critical)' }}>*</span>
              </label>
              <span className="usa-hint">Absolute path, relative path, or Git URL</span>
              <input
                id="scan-target"
                className="usa-input"
                type="text"
                placeholder="/path/to/project or https://github.com/org/repo"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
              />
            </div>

            <div className="usa-form-group">
              <label className="usa-label" htmlFor="scan-type">Scan Type</label>
              <select
                id="scan-type"
                className="usa-select"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              >
                {SCAN_TYPES.map((t) => (
                  <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                ))}
              </select>
            </div>

            {trigger.error && (
              <div className="usa-alert usa-alert--error" style={{ marginBottom: '1rem' }}>
                <div className="usa-alert__body">
                  {(trigger.error as Error).message}
                </div>
              </div>
            )}

            <button
              type="submit"
              className="usa-button"
              disabled={trigger.isPending || !target.trim()}
            >
              {trigger.isPending ? 'Starting…' : 'Run Scan'}
            </button>
          </form>
        </div>
      ) : (
        <div>
          <div style={{ marginBottom: '1rem' }}>
            <strong style={{ color: 'var(--epyon-text)' }}>Target:</strong>{' '}
            <span className="epyon-muted">{target}</span>
            {' · '}
            <strong style={{ color: 'var(--epyon-text)' }}>Type:</strong>{' '}
            <span className="epyon-muted">{scanType}</span>
          </div>

          {job ? (
            <JobOutput job={job} onCancel={!isDone ? handleCancel : undefined} />
          ) : (
            <div className="epyon-loading"><div className="epyon-spinner" /> Starting…</div>
          )}

          {isDone && (
            <div style={{ display: 'flex', gap: 12, marginTop: '1.5rem' }}>
              <Link to="/applications">
                <button className="usa-button">View Applications</button>
              </Link>
              <button className="usa-button usa-button--secondary" onClick={handleReset}>
                Run Another Scan
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
