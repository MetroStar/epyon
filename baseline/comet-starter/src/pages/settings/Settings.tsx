import React, { useState } from 'react';
import {
  useApprovedImages,
  useGitHubConfig,
  useSaveGitHubConfig,
  useScanHistory,
  useTriggerGitHubSync,
  useGitHubSyncStatus,
} from '@src/api/hooks';
import { StatCard } from '@src/components/stat-card/StatCard';

function fmtDate(ts: string | null) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export const Settings = (): React.ReactElement => {
  const { data: images }  = useApprovedImages();
  const { data: history } = useScanHistory();
  const { data: ghCfg }   = useGitHubConfig();
  const saveGh            = useSaveGitHubConfig();
  const triggerSync       = useTriggerGitHubSync();

  const [syncing, setSyncing]         = useState(false);
  const { data: syncStatus }          = useGitHubSyncStatus(syncing);

  const [token, setToken]   = useState('');
  const [repos, setRepos]   = useState('');
  const [saved, setSaved]   = useState(false);

  // Stop polling when done
  React.useEffect(() => {
    if (syncStatus && ['done', 'error', 'idle'].includes(syncStatus.status)) {
      setSyncing(false);
    }
  }, [syncStatus]);

  const handleSaveGitHub = async (e: React.FormEvent) => {
    e.preventDefault();
    const repoList = repos
      .split('\n')
      .map((r) => r.trim())
      .filter(Boolean);
    await saveGh.mutateAsync({
      token: token || 'KEEP_EXISTING',
      repos: repoList,
    });
    setToken('');
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleSync = async () => {
    await triggerSync.mutateAsync();
    setSyncing(true);
  };

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>Settings</h1>
      </div>

      {/* Scan History Summary */}
      <div className="epyon-section">
        <div className="epyon-section-title">Scan History Summary</div>
        <div className="epyon-grid-stats">
          <StatCard value={history?.total_scans ?? 0}   label="Total Scans"      variant="default" />
          <StatCard value={history?.targets?.length ?? 0} label="Tracked Targets" variant="default" />
          <StatCard value={history?.users?.length ?? 0}   label="Users"           variant="default" />
        </div>
        {history && (
          <div style={{ marginTop: '0.75rem', fontSize: 13, color: 'var(--epyon-text-muted)' }}>
            <strong>Targets:</strong> {history.targets.join(', ') || '—'} &nbsp;·&nbsp;
            <strong>As of:</strong> {fmtDate(history.generated_at)}
          </div>
        )}
      </div>

      {/* GitHub Integration */}
      <div className="epyon-section">
        <div className="epyon-section-title">GitHub Actions Integration</div>
        <p style={{ fontSize: 13, color: 'var(--epyon-text-muted)', marginBottom: '1rem' }}>
          Import scan results from GitHub Actions directly. Epyon workflows upload scan artifacts
          automatically. Enter a <strong style={{ color: 'var(--epyon-text)' }}>Personal Access Token</strong> with{' '}
          <code>actions:read</code> scope.
        </p>

        {ghCfg?.token_set && (
          <div className="usa-alert usa-alert--info" style={{ marginBottom: '1rem' }}>
            <div className="usa-alert__body" style={{ fontSize: 13 }}>
              Token configured: <code>{ghCfg.token_hint}</code>
              {ghCfg.last_sync && <> · Last sync: {fmtDate(ghCfg.last_sync)}</>}
            </div>
          </div>
        )}

        <form onSubmit={handleSaveGitHub} style={{ maxWidth: 600 }}>
          <div className="usa-form-group">
            <label className="usa-label" htmlFor="gh-token">Personal Access Token</label>
            <span className="usa-hint">Leave blank to keep existing token</span>
            <input
              id="gh-token"
              className="usa-input"
              type="password"
              placeholder={ghCfg?.token_set ? '(token already set — paste to replace)' : 'ghp_xxxx...'}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              autoComplete="off"
            />
          </div>

          <div className="usa-form-group">
            <label className="usa-label" htmlFor="gh-repos">Repositories</label>
            <span className="usa-hint">One per line, format: owner/repo</span>
            <textarea
              id="gh-repos"
              className="usa-textarea"
              rows={4}
              placeholder={`MetroStar/iris\nMetroStar/comet-starter`}
              value={repos}
              onChange={(e) => setRepos(e.target.value)}
              defaultValue={ghCfg?.repos?.join('\n')}
            />
          </div>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <button type="submit" className="usa-button" disabled={saveGh.isPending}>
              {saveGh.isPending ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              className="usa-button usa-button--secondary"
              onClick={handleSync}
              disabled={syncing || triggerSync.isPending || !ghCfg?.token_set}
            >
              {syncing ? 'Syncing…' : 'Sync Now'}
            </button>
            {saved && <span style={{ color: 'var(--epyon-clean)', fontSize: 13 }}>✓ Saved</span>}
          </div>
        </form>

        {syncStatus && syncStatus.status !== 'idle' && (
          <div style={{ marginTop: '1rem', fontSize: 13 }}>
            <strong style={{ color: 'var(--epyon-text)' }}>Sync status:</strong>{' '}
            <span style={{ color: syncStatus.status === 'error' ? 'var(--epyon-critical)' : 'var(--epyon-text-muted)' }}>
              {syncStatus.status}
            </span>
            {syncStatus.result && (
              <span className="epyon-muted" style={{ marginLeft: 8 }}>
                · {syncStatus.result.synced.length} new
                · {syncStatus.result.skipped.length} skipped
                · {syncStatus.result.failed.length} failed
              </span>
            )}
            {syncStatus.error && (
              <span style={{ color: 'var(--epyon-critical)', marginLeft: 8 }}>{syncStatus.error}</span>
            )}
          </div>
        )}
      </div>

      {/* Approved Images */}
      {images?.content && (
        <div className="epyon-section">
          <div className="epyon-section-title">Approved Base Images</div>
          <pre style={{
            background: 'var(--epyon-bg-card)', border: '1px solid var(--epyon-border)',
            borderRadius: 6, padding: '1rem', fontSize: 12,
            color: 'var(--epyon-text-muted)', overflow: 'auto', maxHeight: 300,
          }}>
            {images.content}
          </pre>
        </div>
      )}
    </div>
  );
};
