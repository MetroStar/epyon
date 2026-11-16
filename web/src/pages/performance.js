import { renderSelfAssessmentBody, renderSelfDiagLayerPicker } from './self-assessment.js';
import { emptyRow, errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { _cache } from '../lib/cache.js';
import { esc } from '../lib/format.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

// ── GitHub Signals sparkline helper ──────────────────────────
export function _ghSparkline(history, field, color, labelFn) {
  if (!history || history.filter(e => e[field] != null).length < 2) {
    return `<div style="display:flex;align-items:center;justify-content:center;height:60px;color:var(--text-muted);font-size:12px">Not enough history yet</div>`;
  }
  const vals = history.map(e => e[field]);
  const dates = history.map(e => e.date);
  const min = Math.min(...vals.filter(v => v != null));
  const max = Math.max(...vals.filter(v => v != null));
  const range = max - min || 1;
  const W = 320, H = 60, pad = 6;
  const pts = vals.map((v, i) => {
    const x = pad + (i / (vals.length - 1)) * (W - pad * 2);
    const y = v == null ? null : H - pad - ((v - min) / range) * (H - pad * 2);
    return y == null ? null : `${x.toFixed(1)},${y.toFixed(1)}`;
  }).filter(Boolean).join(' ');
  const last = vals.filter(v => v != null).at(-1);
  const first = vals.filter(v => v != null)[0];
  const delta = last - first;
  const deltaStr = (delta > 0 ? '+' : '') + delta + (labelFn ? '' : '');
  const deltaColor = delta === 0 ? 'var(--text-muted)' : (delta > 0 ? 'var(--clean)' : 'var(--critical)');
  return `
    <div style="display:flex;align-items:center;gap:16px">
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" style="flex-shrink:0">
        <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
        <circle cx="${(pad + (vals.length-1)/(vals.length-1)*(W-pad*2)).toFixed(1)}" cy="${(H-pad-((last-min)/range)*(H-pad*2)).toFixed(1)}" r="3" fill="${color}"/>
      </svg>
      <div style="text-align:right;min-width:64px">
        <div style="font-size:20px;font-weight:700;color:${color}">${labelFn ? labelFn(last) : last}</div>
        <div style="font-size:12px;color:${deltaColor}">${deltaStr !== '+0' && deltaStr !== '0' ? deltaStr : '—'} vs ${dates[0]}</div>
      </div>
    </div>`;
}

// CI Health section for the Metrics page: workflow success rate + PR scan coverage.
export async function buildCiHealthSection() {
  try {
    const [g, history] = await Promise.all([
      api.getGitHubMetrics(),
      api.getGitHubSignalsHistory().catch(() => []),
    ]);

    const runsCollected = (g.workflow_runs || []).some(r => (r.total_runs || 0) > 0);
    const noData = !runsCollected
      ? `<div class="metrics-filter-notice" style="border-color:var(--medium);color:var(--medium)">
           ⚠ ${esc(g.error || 'No workflow runs were collected')} — set a GitHub token and repos in Settings to collect workflow success rates.
           PR Scan Coverage is calculated from synced scans and doesn't need a token.
         </div>` : '';

    // ── Workflow success rate ────────────────────────────────
    const _runList = (g.workflow_runs || []).filter(r => !r.error);
    const runRows = _runList.map((r, i) => {
      const rate = r.success_rate != null ? `${r.success_rate}%` : 'No runs';
      const rateColor = r.success_rate == null ? 'var(--text-muted)' : r.success_rate >= 90 ? 'var(--clean)' : r.success_rate >= 70 ? '#e3b341' : 'var(--critical)';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('run',${i})" title="Click to view details">
        <td><strong>${esc(r.repo.split('/')[1] || r.repo)}</strong><div style="font-size:12px;color:var(--text-muted)">${esc(r.repo)}</div></td>
        <td style="text-align:center;font-weight:700;color:${rateColor}">${rate}</td>
        <td style="text-align:center">${r.total_runs || 0}</td>
        <td style="text-align:center;color:var(--clean)">${r.success || 0}</td>
        <td style="text-align:center;color:var(--critical)">${r.failed || 0}</td>
      </tr>`;
    }).join('') || emptyRow(5, 'No workflow run data');

    // ── PR scan coverage ────────────────────────────────────
    const covEntries = Object.entries(g.pr_scan_coverage || {}).sort((a, b) => b[1].pr_coverage_pct - a[1].pr_coverage_pct);
    const totalPRScans = covEntries.reduce((s, [, v]) => s + v.pr_scans, 0);
    const totalCIScans = covEntries.reduce((s, [, v]) => s + v.total_ci_scans, 0);
    const overallCovPct = totalCIScans > 0 ? Math.round((totalPRScans / totalCIScans) * 100) : 0;
    const covRows = covEntries.map(([name, v], i) => {
      const pct = v.pr_coverage_pct;
      const barColor = pct >= 70 ? 'var(--clean)' : pct >= 40 ? '#e3b341' : 'var(--critical)';
      return `<tr class="finding-row" style="cursor:pointer" onclick="openGhSignalDetail('cov',${i})" title="Click to view details">
        <td><strong>${esc(name)}</strong></td>
        <td style="text-align:center">${v.pr_scans}</td>
        <td style="text-align:center">${v.push_scans}</td>
        <td style="text-align:center">${v.other_scans}</td>
        <td style="text-align:center">${v.total_ci_scans}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:var(--border);border-radius:4px;height:8px;overflow:hidden">
              <div style="width:${Math.min(pct,100)}%;background:${barColor};height:100%;border-radius:4px;transition:width .3s"></div>
            </div>
            <span style="font-size:12px;font-weight:700;color:${barColor};min-width:40px;text-align:right">${pct}%</span>
          </div>
        </td>
      </tr>`;
    }).join('') || emptyRow(6, 'No CI scan data available yet');

    // Store data for detail drawer
    window._ghSignalData = { run: _runList, cov: covEntries };

    return `
      <div class="section-title" style="margin-top:32px">CI Health</div>
      ${noData}

      ${history.length >= 2 ? `
      <div class="section">
        <div class="section-title">
          Historical Trends
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">${history.length} daily snapshot${history.length !== 1 ? 's' : ''} · earliest ${esc(history[0].date)}</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px">
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Workflow Success Rate</div>
            ${_ghSparkline(history, 'workflow_success_rate', '#79c0ff', v => v != null ? v + '%' : '—')}
          </div>
          <div class="stat-card" style="padding:16px 20px">
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">PR Scan Coverage</div>
            ${_ghSparkline(history, 'pr_coverage_pct', 'var(--clean)', v => v + '%')}
          </div>
        </div>
      </div>` : ''}

      <div class="section">
        <div class="section-title">
          Workflow Success Rate
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">last ${g.window_days || 90} days · security workflows</span>
        </div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th scope="col">Repository</th>
              <th scope="col" style="text-align:center">Success Rate</th>
              <th scope="col" style="text-align:center">Total Runs</th>
              <th scope="col" style="text-align:center">✓ Success</th>
              <th scope="col" style="text-align:center">✗ Failed</th>
            </tr></thead>
            <tbody>${runRows}</tbody>
          </table>
        </div>
      </div>

      <div class="section">
        <div class="section-title">
          PR Scan Coverage
          <span style="font-size:12px;font-weight:normal;color:var(--text-muted)">% of CI scans triggered by pull requests</span>
        </div>
        <div class="table-container">
          <table>
            <thead><tr>
              <th scope="col">Application</th>
              <th scope="col" style="text-align:center">PR Scans</th>
              <th scope="col" style="text-align:center">Push Scans</th>
              <th scope="col" style="text-align:center">Other</th>
              <th scope="col" style="text-align:center">Total CI</th>
              <th scope="col">Coverage</th>
            </tr></thead>
            <tbody>${covRows}</tbody>
          </table>
        </div>
      </div>`;

  } catch (e) {
    return `<div class="section"><div class="section-title">CI Health</div>${errBanner(e.message)}</div>`;
  }
}

// ── Performance Dashboard ────────────────────────────────────
export async function renderPerformanceDashboard() {
  setActive('performance');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    // Fetch cache metrics, scanner validation history, live mobile code
    // scanner accuracy (computed on-demand against its labeled test corpus),
    // a scan-integrity check (flags scans that likely ran against an
    // empty/unreachable target instead of genuinely finding nothing), and
    // the latest cross-layer self-assessment result (validates every
    // scanner layer actually detects its planted fixture issue).
    const [cacheMetrics, frontendMetrics, mobileCodeAccuracy, scanIntegrity, selfAssessment] = await Promise.all([
      api._get('/api/metrics/cache'),
      Promise.resolve(_cache.getMetrics()),
      api._get('/api/metrics/mobile-code-accuracy').catch(() => null),
      api._get('/api/metrics/scan-integrity').catch(() => null),
      api._get('/api/metrics/self-assessment').catch(() => null)
    ]);

    // Combine backend and frontend metrics
    const combined = {
      backend: cacheMetrics,
      frontend: frontendMetrics,
      timestamp: new Date().toISOString()
    };

    // Calculate aggregate hit rate (average of scan cache and frontend)
    const backendHitRate = cacheMetrics.hit_rates?.scan || 0;
    const frontendHitRate = frontendMetrics.hit_rate_pct || 0;
    const avgHitRate = ((backendHitRate + frontendHitRate) / 2).toFixed(1);

    // Build cache performance summary
    const cacheStatusClass = avgHitRate >= 70 ? 'clean' : avgHitRate >= 50 ? 'medium' : 'critical';
    const cacheStatusText = avgHitRate >= 70 ? 'Good' : avgHitRate >= 50 ? 'Fair' : 'Poor';

    // Build mobile code scanner accuracy card from live metrics (or a
    // graceful "unavailable" state if the endpoint couldn't be reached).
    const mca = mobileCodeAccuracy;
    const mcaBody = mca ? `
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
            <span style="font-size:48px;font-weight:700;color:var(--text-primary)">${mca.f1_score.toFixed(3)}</span>
            <div>
              <div style="font-weight:600;color:var(--text-primary)">Current F1 Score</div>
              <div style="font-size:12px;color:var(--text-muted)">Target: ≥ 0.90</div>
            </div>
            <span class="sev-badge ${mca.f1_score >= 0.9 ? 'clean' : 'critical'}" style="margin-left:auto">${mca.f1_score >= 0.9 ? 'PASS' : 'FAIL'}</span>
          </div>
          <div class="resp-grid resp-grid-2" style="gap:16px">
            <div>
              <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">Precision</div>
              <div style="font-size:20px;font-weight:600;color:var(--text-primary)">${(mca.precision * 100).toFixed(1)}%</div>
              <div style="font-size:12px;color:var(--text-muted)">${mca.true_positives} true positives, ${mca.false_positives} false positives</div>
            </div>
            <div>
              <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">Recall</div>
              <div style="font-size:20px;font-weight:600;color:var(--text-primary)">${(mca.recall * 100).toFixed(1)}%</div>
              <div style="font-size:12px;color:var(--text-muted)">${mca.false_negatives} false negatives</div>
            </div>
          </div>
          <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
            <div style="font-size:12px;color:var(--text-muted)">Computed live against ${mca.total_expected_findings} labeled findings in tests/fixtures/mobile-code (${mca.total_actual_findings} findings detected).</div>
          </div>
    ` : `
          <div style="color:var(--text-muted);font-size:13px">Accuracy metrics unavailable — the mobile code scanner test corpus could not be reached on this deployment.</div>
    `;

    // Build the Scan Integrity Check section — the whole point is to catch
    // a scan silently running against an empty/unreachable target (the
    // Docker-in-Docker false-clean class of bug) before someone has to
    // notice a suspiciously quiet dashboard on their own.
    const si = scanIntegrity;
    const siBody = !si ? `
          <div style="color:var(--text-muted);font-size:13px">Scan integrity data unavailable on this deployment.</div>
    ` : `
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:16px">
            <div class="stat-card">
              <div class="stat-label">Scans Checked</div>
              <div class="stat-value">${si.summary.total}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Healthy</div>
              <div class="stat-value" style="color:var(--clean)">${si.summary.healthy}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Suspicious</div>
              <div class="stat-value" style="color:var(--sev-medium,#eab308)">${si.summary.suspicious}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">Empty Target</div>
              <div class="stat-value" style="color:var(--critical)">${si.summary.empty_target}</div>
            </div>
          </div>
          ${si.flagged.length === 0 ? `
            <div style="color:var(--text-muted);font-size:13px">No flagged scans in the last check — every recent scan saw real target content.</div>
          ` : `
            <div class="table-container">
              <table>
                <thead>
                  <tr><th scope="col">Scan</th><th scope="col">Target</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Reason(s)</th></tr>
                </thead>
                <tbody>
                  ${si.flagged.map(f => `
                    <tr>
                      <td><a href="#/scans/${esc(f.scan_id)}" style="color:var(--link)">${esc(f.scan_id)}</a></td>
                      <td>${esc(f.target || '—')}</td>
                      <td>${esc(f.scan_type || '—')}</td>
                      <td><span class="sev-badge ${f.status === 'empty_target' ? 'critical' : f.status === 'suspicious' ? 'medium' : ''}" style="font-size:12px">${esc(f.status.replace('_', ' ').toUpperCase())}</span></td>
                      <td style="font-size:12px">${f.reasons.map(esc).join('; ')}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `}
    `;

    // Build the Self-Assessment section — cross-layer validation that every
    // scanner actually detects its known-planted issue in
    // tests/fixtures/self-assessment/, not just that it ran without error.
    const sa = selfAssessment;
    const saBody = renderSelfAssessmentBody(sa);

    page.innerHTML = `
      ${pageHeader(`Performance Dashboard`, { subtitle: `How Epyon itself is performing — cache efficiency, scanner accuracy, and validation that recent scans actually ran against real content.` })}

      <div class="section">
        <div class="section-title">Scan Integrity Check</div>
        <div style="padding:20px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
          ${siBody}
        </div>
      </div>

      <div class="section">
        <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
          <span>Self-Assessment (All Scanner Layers)</span>
          <button id="run-self-diag-btn" class="btn btn-sm" onclick="startSelfDiagnostic()">▶ Run Self-Diagnostic</button>
        </div>
        <div style="padding:20px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
          ${renderSelfDiagLayerPicker()}
          <div id="self-diag-progress" style="display:none;margin-bottom:16px">
            <div id="self-diag-status" style="font-size:13px;margin-bottom:8px;color:var(--text-muted)"></div>
            <div id="self-diag-log" style="max-height:220px;overflow-y:auto;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:monospace;font-size:12px;line-height:1.5"></div>
          </div>
          <div id="self-assessment-body">${saBody}</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Cache Performance</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px">
          <div class="stat-card">
            <div class="stat-label">Overall Hit Rate</div>
            <div class="stat-value" style="display:flex;align-items:center;gap:8px">
              ${avgHitRate}%
              <span class="sev-badge ${cacheStatusClass}" style="font-size:12px">${cacheStatusText}</span>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Backend Hit Rate</div>
            <div class="stat-value">${backendHitRate.toFixed(1)}%</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Frontend Hit Rate</div>
            <div class="stat-value">${frontendHitRate.toFixed(1)}%</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Backend Cache Size</div>
            <div class="stat-value">${cacheMetrics.cache_sizes?.scan || 0} scans</div>
          </div>
        </div>

        <div class="resp-grid resp-grid-2" style="gap:20px">
          <div>
            <h4 style="margin:0 0 12px 0;font-size:14px;color:var(--text-primary)">Backend Metrics</h4>
            <table class="info-table">
              <tr><td>Total Hits</td><td>${cacheMetrics.hits?.scan || 0}</td></tr>
              <tr><td>Total Misses</td><td>${cacheMetrics.misses?.scan || 0}</td></tr>
              <tr><td>Cache Writes</td><td>${cacheMetrics.writes?.scan || 0}</td></tr>
              <tr><td>Recent Invalidations</td><td>${cacheMetrics.recent_invalidations?.length || 0}</td></tr>
            </table>
          </div>
          <div>
            <h4 style="margin:0 0 12px 0;font-size:14px;color:var(--text-primary)">Frontend Metrics</h4>
            <table class="info-table">
              <tr><td>Total Hits</td><td>${frontendMetrics.hits || 0}</td></tr>
              <tr><td>Total Misses</td><td>${frontendMetrics.misses || 0}</td></tr>
              <tr><td>Cache Writes</td><td>${frontendMetrics.writes || 0}</td></tr>
              <tr><td>Version Mismatches</td><td>${frontendMetrics.version_mismatches || 0}</td></tr>
              <tr><td>TTL Expirations</td><td>${frontendMetrics.ttl_expirations || 0}</td></tr>
              <tr><td>Quota Errors</td><td>${frontendMetrics.quota_errors || 0}</td></tr>
              <tr><td>Avg Staleness</td><td>${frontendMetrics.avg_staleness_ms ? `${frontendMetrics.avg_staleness_ms.toFixed(0)}ms` : 'N/A'}</td></tr>
            </table>
          </div>
        </div>

        <div style="margin-top:20px">
          <button class="btn" onclick="api.clearCacheAndReload()" style="margin-right:8px">
            Clear All Caches & Reload
          </button>
          <button class="btn" onclick="location.reload()">
            Refresh Metrics
          </button>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Mobile Code Scanner Accuracy</div>
        <div style="padding:20px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
          ${mcaBody}
        </div>
      </div>
    `;

  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}
