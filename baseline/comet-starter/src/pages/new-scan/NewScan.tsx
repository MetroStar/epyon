import React, { useState } from 'react';
import { useTriggerScan, useJob, useCancelJob, useGitHubConfig } from '@src/api/hooks';
import { JobOutput } from '@src/components/job-output/JobOutput';
import { Link, useSearchParams } from 'react-router-dom';
import { EpyonSelect } from '@src/components/epyon-select/EpyonSelect';

const SCAN_TYPES = ['full', 'quick', 'images', 'analysis'];

export const NewScan = (): React.ReactElement => {
  const [searchParams] = useSearchParams();
  const prefillTarget  = searchParams.get('target') ?? '';
  const prefillApp     = searchParams.get('app') ?? '';

  const { data: ghConfig } = useGitHubConfig();

  // Build quick-select options from tracked GitHub repos
  const ghRepos   = (ghConfig?.repos ?? []).map((r) => `https://github.com/${r}`);
  const quickOpts = Array.from(new Set(ghRepos));

  const [target, setTarget]       = useState(prefillTarget);
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
          {prefillApp && (
            <div style={{ marginBottom: '1.25rem', padding: '10px 14px', background: 'var(--epyon-bg-card)', border: '1px solid var(--epyon-border)', borderRadius: 6, fontSize: 13, color: 'var(--epyon-text-muted)' }}>
              Scanning <strong style={{ color: 'var(--epyon-text)' }}>{prefillApp}</strong>
              {prefillTarget && <> · <a href={prefillTarget} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--epyon-accent)' }}>{prefillTarget}</a></>}
              <button
                type="button"
                className="usa-button usa-button--unstyled"
                style={{ marginLeft: 12, fontSize: 12 }}
                onClick={() => { setTarget(''); }}
              >
                Change target
              </button>
            </div>
          )}
          <form onSubmit={handleSubmit}>
            {/* Target input — shown when not prefilled or user clicked change */}
            {(!prefillApp || !target) && (
              <>
                {quickOpts.length > 0 && (
                  <div className="usa-form-group">
                    <label className="usa-label" htmlFor="scan-quick">Quick Select</label>
                    <span className="usa-hint">Pick a tracked repository</span>
                    <EpyonSelect
                      id="scan-quick"
                      value={quickOpts.includes(target) ? target : ''}
                      options={[
                        { value: '', label: '— choose a repo —' },
                        ...quickOpts.map((url) => ({ value: url, label: url.replace('https://github.com/', '') })),
                      ]}
                      onChange={(v) => { if (v) setTarget(v); }}
                    />
                  </div>
                )}
                <div className="usa-form-group">
                  <label className="usa-label" htmlFor="scan-target">
                    {quickOpts.length > 0 ? 'Or enter a custom target' : 'Target'}
                    {quickOpts.length === 0 && <span style={{ color: 'var(--epyon-critical)' }}> *</span>}
                  </label>
                  <span className="usa-hint">Absolute path, relative path, or Git URL</span>
                  <input
                    id="scan-target"
                    className="usa-input"
                    type="text"
                    placeholder="/path/to/project or https://github.com/org/repo"
                    value={quickOpts.includes(target) ? '' : target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>
              </>
            )}
            <div className="usa-form-group" style={{ marginBottom: '1rem' }}>
              <label className="usa-label" htmlFor="scan-add-repo" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Add New Repository</span>
              </label>
              <span className="usa-hint">Add a repo to track (owner/repo) — saves to GitHub config</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  id="scan-add-repo"
                  className="usa-input"
                  type="text"
                  placeholder="MetroStar/my-repo"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      const val = (e.target as HTMLInputElement).value.trim();
                      if (val && val.includes('/')) {
                        const url = `https://github.com/${val}`;
                        setTarget(url);
                        (e.target as HTMLInputElement).value = '';
                      }
                    }
                  }}
                />
                <button
                  type="button"
                  className="usa-button usa-button--secondary"
                  style={{ whiteSpace: 'nowrap' }}
                  onClick={(e) => {
                    const input = (e.currentTarget.previousElementSibling as HTMLInputElement);
                    const val = input.value.trim();
                    if (val && val.includes('/')) {
                      setTarget(`https://github.com/${val}`);
                      input.value = '';
                    }
                  }}
                >
                  Use
                </button>
              </div>
            </div>

            <div className="usa-form-group">
              <label className="usa-label" htmlFor="scan-type">Scan Type</label>
              <EpyonSelect
                id="scan-type"
                value={scanType}
                options={SCAN_TYPES.map((t) => ({ value: t, label: t.charAt(0).toUpperCase() + t.slice(1) }))}
                onChange={setScanType}
              />
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
              style={{ marginTop: '1.5rem' }}
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
