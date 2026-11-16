import { WORKFLOW_YML } from '../lib/workflow.js';
import { toast } from '../components/feedback.js';
import { errBanner, loading, pageHeader } from '../components/layout.js';
import { api } from '../lib/api.js';
import { esc, fmtDate, act, actOn } from '../lib/format.js';

// Globals that other modules put on window (see index.js):
/* global setActive */

export async function renderSettings() {
  setActive('settings');
  const page = document.getElementById('page');
  page.innerHTML = loading();

  try {
    const [images, ghCfg, aiCfg, nvdCfg, health, jiraCfg, concCfg] = await Promise.all([
      api.getApprovedImages(),
      api.getGitHubConfig(),
      api.getAiConfig(),
      api.getNvdConfig(),
      api._get('/api/health'),
      api.getJiraConfig().catch(() => ({})),
      api.getScanConcurrency().catch(() => null),
    ]);
    const epyonVersion = health.version || '—';

    const tools = [
      'Trivy', 'Grype', 'TruffleHog', 'ClamAV', 'Checkov', 'Syft/SBOM',
      'SonarQube', 'Helm', 'Xeol', 'Anchore', 'API Discovery', 'Garak',
    ];

    page.innerHTML = `
      ${pageHeader(`Settings`)}

      <div class="settings-group-title">AI</div>
      <details class="section settings-section">
        <summary class="section-title">AI Executive Summary</summary>
        <p class="section-desc">
          Point the primary endpoint at a locally hosted, OpenAI-compatible server such as
          <a href="https://ollama.com" target="_blank" rel="noopener">Ollama</a>
          (<code>http://localhost:11434/v1</code>) to keep scan data on-premises, or leave it blank
          to use the public OpenAI API. Set <code>OPENAI_API_KEY</code> in the server environment
          when the selected endpoint requires authentication.
        </p>
        <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>${aiCfg.key_set
            ? 'OpenAI authentication is configured through the server environment.'
            : 'No <code>OPENAI_API_KEY</code> is configured. Self-hosted no-auth endpoints can still operate.'}</span>
        </div>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">Provider</label>
            <select id="ai-provider" class="field-input" ${actOn('change','aiProviderChanged')}>
              <option value="auto" ${aiCfg.provider === 'auto' ? 'selected' : ''}>Auto (settings, then environment)</option>
              <option value="local" ${aiCfg.provider === 'local' ? 'selected' : ''}>Local / self-hosted (Ollama, vLLM…)</option>
              <option value="openai" ${aiCfg.provider === 'openai' ? 'selected' : ''} ${aiCfg.key_set ? '' : 'disabled'}>OpenAI (uses OPENAI_API_KEY)${aiCfg.key_set ? '' : ' — key not loaded; restart server with .env.local sourced'}</option>
            </select>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
              Applies to summaries and STIG scans. OpenAI ignores the local URL below; Local never sends your OpenAI key.
            </div>
          </div>
          <div id="ai-openai-model-row" style="display:${aiCfg.provider === 'openai' ? 'block' : 'none'}">
            <label class="field-label">OpenAI Model</label>
            <select id="ai-openai-model" class="field-input">
              ${[...new Set([aiCfg.openai_model || 'gpt-4o-mini', 'gpt-5.5', 'gpt-5.4', 'gpt-5.4-mini', 'gpt-5', 'o3', 'gpt-4.1', 'gpt-4o', 'gpt-4o-mini'])]
                .map(m => `<option value="${esc(m)}" ${m === (aiCfg.openai_model || 'gpt-4o-mini') ? 'selected' : ''}>${esc(m)}</option>`).join('')}
            </select>
          </div>
          <div>
            <label class="field-label">Primary Base URL <span style="color:var(--text-muted);font-weight:normal">(blank = public OpenAI API)</span></label>
            <input id="ai-base-url" type="text" class="field-input"
              placeholder="http://localhost:11434/v1"
              ${actOn('change','loadLocalModels')}
              value="${esc(aiCfg.base_url || '')}"/>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
              Active: <code>${esc(aiCfg.active_base_url || 'https://api.openai.com/v1 (default)')}</code>
            </div>
          </div>
          <div>
            <label class="field-label">Primary Model</label>
            <div style="display:flex;gap:8px;align-items:center">
              <select id="ai-model-select" class="field-input" style="display:none"></select>
              <input id="ai-model" type="text" class="field-input"
                placeholder="gpt-4o-mini, llama3.1:8b, gemma4:26b, ..."
                value="${esc(aiCfg.model || '')}"/>
              <button type="button" class="btn" id="ai-model-refresh" ${act('loadLocalModels')}
                      title="Fetch the models available at the base URL" style="white-space:nowrap">↻ Refresh</button>
            </div>
            <div id="ai-model-status" style="font-size:12px;color:var(--text-muted);margin-top:4px"></div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
              Active: <code>${esc(aiCfg.active_model || '')}</code>
            </div>
          </div>
        </div>

        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border)">
          <div style="font-weight:600;font-size:13px;margin-bottom:6px">Secondary (Fallback) — OpenAI</div>
          <p class="section-desc" style="margin-top:0">
            If the primary endpoint above is self-hosted (e.g. Ollama) and fails or is unreachable,
            optionally retry once against the public OpenAI API using <code>OPENAI_API_KEY</code>.
          </p>
          <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>${aiCfg.fallback_available
              ? 'Fallback is active — the primary endpoint is self-hosted and OPENAI_API_KEY is set.'
              : 'Fallback is inactive — requires a self-hosted primary Base URL and OPENAI_API_KEY in the server environment.'}</span>
          </div>
          <div style="display:grid;gap:14px;max-width:600px">
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer">
              <input type="checkbox" id="ai-fallback-enabled" ${aiCfg.fallback_enabled ? 'checked' : ''}/>
              Enable OpenAI fallback when the primary endpoint fails
            </label>
            <div>
              <label class="field-label">Fallback Model</label>
              <select id="ai-fallback-model" class="field-input">
                <option value="gpt-4.1" ${aiCfg.fallback_model === 'gpt-4.1' ? 'selected' : ''}>gpt-4.1</option>
                <option value="gpt-4o" ${aiCfg.fallback_model === 'gpt-4o' ? 'selected' : ''}>gpt-4o</option>
                <option value="gpt-4o-mini" ${aiCfg.fallback_model === 'gpt-4o-mini' ? 'selected' : ''}>gpt-4o-mini</option>
                <option value="gpt-4-turbo" ${aiCfg.fallback_model === 'gpt-4-turbo' ? 'selected' : ''}>gpt-4-turbo</option>
              </select>
            </div>
          </div>
        </div>

        <div style="margin-top:16px">
          <button class="btn btn-primary" ${act('saveAiConfig')}>Save AI Config</button>
        </div>
      </details>

      <div class="settings-group-title">Integrations</div>
      <details class="section settings-section">
        <summary class="section-title">Jira Integration</summary>
        <p class="section-desc">
          Automatically close Jira tickets when security findings are remediated in a subsequent scan.
          Requires a Jira Cloud account with an API token (Atlassian account settings → Security → API tokens).
        </p>
        <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>${jiraCfg.token_set
            ? 'Jira authentication is configured through <code>JIRA_API_TOKEN</code> in the server environment.'
            : 'Jira authentication is not configured. Set <code>JIRA_API_TOKEN</code> in the server environment.'}</span>
        </div>
        <div style="display:grid;gap:14px;max-width:600px">
          <div class="resp-grid resp-grid-2" style="gap:12px">
            <div>
              <label class="field-label">Jira Base URL</label>
              <input id="jira-url" type="url" class="field-input"
                placeholder="https://your-org.atlassian.net"
                value="${esc(jiraCfg.base_url || '')}"/>
            </div>
            <div>
              <label class="field-label">Email</label>
              <input id="jira-email" type="email" class="field-input"
                placeholder="user@company.com"
                value="${esc(jiraCfg.email || '')}"/>
            </div>
          </div>
          <div class="resp-grid resp-grid-3" style="gap:12px">
            <div>
              <label class="field-label">Default Project Key</label>
              <input id="jira-project" type="text" class="field-input"
                placeholder="SEC"
                value="${esc(jiraCfg.project_key || '')}"/>
            </div>
            <div>
              <label class="field-label">Issue Type</label>
              <input id="jira-issue-type" type="text" class="field-input"
                placeholder="Bug"
                value="${esc(jiraCfg.issue_type || 'Bug')}"/>
            </div>
            <div>
              <label class="field-label">Done Transition</label>
              <input id="jira-done" type="text" class="field-input"
                placeholder="Done"
                value="${esc(jiraCfg.done_transition || 'Done')}"/>
            </div>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <label style="display:flex;gap:8px;align-items:center;cursor:not-allowed;font-size:13px;opacity:0.7">
              <input type="checkbox" id="jira-auto-close" checked disabled/>
              Auto-close tickets when findings are remediated (always enabled)
            </label>
            <div style="font-size:12px;color:var(--text-muted)">
              New tickets can only be created from a scan's Jira Review screen.
            </div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary" ${act('saveJiraConfig')}>Save</button>
            <button class="btn" id="jira-test-btn" ${act('testJiraConnection')}>Test Connection</button>
            <span id="jira-status" style="font-size:13px;color:var(--text-muted)"></span>
          </div>
        </div>
      </details>

      <details class="section settings-section">
        <summary class="section-title">GitHub Actions Integration</summary>
        <p class="section-desc">
          Import scan results from GitHub Actions directly into this dashboard.
          Epyon workflows upload scan artifacts automatically. Configure
          <code>GITHUB_TOKEN</code> or <code>GH_PAT</code> in the server environment
          and list the repositories to watch below.
        </p>
        <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>${ghCfg.token_set
            ? 'GitHub authentication is configured through the server environment.'
            : 'GitHub authentication is not configured. Set <code>GITHUB_TOKEN</code> or <code>GH_PAT</code> in the server environment.'}</span>
        </div>
        <div style="display:grid;gap:14px;max-width:600px">
          <div>
            <label class="field-label">Repositories <span style="color:var(--text-muted);font-weight:normal">(one per line: owner/repo)</span></label>
            <textarea id="gh-repos" class="field-input" rows="4"
              placeholder="MetroStar/sapphire&#10;MetroStar/comet-starter"
              style="resize:vertical">${(ghCfg.repos || []).map(r => esc(r)).join('\n')}</textarea>
          </div>

          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-primary" ${act('saveGitHubConfig')}>Save</button>
            <button class="btn btn-primary" id="sync-btn" ${act('triggerGitHubSync')}>
              ↓ Sync Now
            </button>
            <span id="sync-status" style="font-size:13px;color:var(--text-muted)">
              ${ghCfg.last_sync ? 'Last synced: ' + fmtDate(ghCfg.last_sync) : 'Not yet synced'}
            </span>
          </div>
        </div>
      </details>

      <details class="section settings-section">
        <summary class="section-title">NVD API Key</summary>
        <p class="section-desc">
          Set <code>NVD_API_KEY</code> in the server environment to increase CVSS enrichment rate from 5 requests per 30 seconds to 50 requests per 30 seconds.
        </p>
        <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;background:color-mix(in srgb,var(--accent) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:6px;margin-bottom:12px;font-size:13px;max-width:600px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>${nvdCfg.key_set
            ? 'NVD authentication is configured through the server environment.'
            : 'No <code>NVD_API_KEY</code> is configured; enrichment will use the unauthenticated rate limit.'}</span>
        </div>
      </details>

      <div class="settings-group-title">Scanning</div>
      ${concCfg ? `<details class="section settings-section">
        <summary class="section-title">Scan Concurrency</summary>
        <p class="section-desc">
          How many scans run at the same time. Extra scans wait as <em>queued</em> and start in order.
          Each scan runs several container tools, so raise this only if the host has the CPU and memory for it.
          Two scans of the same target and scan type never overlap. Changes apply to queued scans immediately.
        </p>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <label class="field-label" for="scan-concurrency" style="margin:0">Max concurrent scans</label>
          <input id="scan-concurrency" type="number" class="field-input" style="width:90px"
                 min="1" max="${esc(concCfg.ceiling)}" step="1" value="${esc(concCfg.max_concurrent_scans)}" />
          <button class="btn btn-primary" ${act('saveScanConcurrency')}>Save</button>
          <span style="font-size:13px;color:var(--text-muted)">
            ${esc(concCfg.running)} running, ${esc(concCfg.queued)} queued ·
            ${concCfg.source === 'saved' ? 'set here' : concCfg.source === 'env' ? 'from <code>EPYON_MAX_CONCURRENT_SCANS</code>' : 'default (' + esc(concCfg.default) + ')'}
          </span>
        </div>
      </details>` : ''}

      <details class="section settings-section">
        <summary class="section-title">Workflow File Setup</summary>
        <p class="section-desc">
          Each repository needs the Epyon workflow file added once so that scans run
          automatically and results are uploaded to this dashboard.
        </p>
        <div style="font-size:13px;color:var(--text-muted);margin:0 0 6px;font-weight:600">Option A — npm (recommended)</div>
        <pre style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;font-size:12px;margin:0 0 14px;max-width:700px;overflow-x:auto">npm install github:MetroStar/epyon --save-dev</pre>
        <p style="font-size:13px;color:var(--text-muted);margin:0 0 14px;line-height:1.7">The postinstall script writes <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">.github/workflows/scan-private-repo.yml</code> into your project. Re-running <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">npm install</code> or <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">npm update</code> pulls the latest workflow.</p>
        <div style="font-size:13px;color:var(--text-muted);margin:0 0 6px;font-weight:600">Option B — pip</div>
        <pre style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;font-size:12px;margin:0 0 14px;max-width:700px;overflow-x:auto">pip install git+https://github.com/MetroStar/epyon.git
epyon install-workflow</pre>
        <div style="font-size:13px;color:var(--text-muted);margin:0 0 6px;font-weight:600">Option C — manual</div>
        <ol style="padding-left:18px;margin:0 0 14px;font-size:13px;color:var(--text-muted);line-height:1.9">
          <li>Create <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">.github/workflows/scan-private-repo.yml</code> in your repository with the contents below.</li>
          <li>Review the <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">uses:</code> line and change the GitHub org only if your Epyon instance is hosted outside <code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">MetroStar/epyon</code>.</li>
        </ol>
        <div style="font-size:13px;color:var(--text-muted);margin:0 0 14px;line-height:1.7">Then commit and push (<code style="background:var(--bg-input);padding:1px 5px;border-radius:3px">git add .github/workflows/scan-private-repo.yml &amp;&amp; git commit -m "Add Epyon security scanning" &amp;&amp; git push</code>). Pull requests get a quick scan; the workflow also runs nightly at 2 AM UTC (full on Sundays; STIG only when triggered manually) and on manual dispatch.</div>
        <div style="position:relative;max-width:700px">
          <pre id="settings-yml" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);
               padding:12px;font-size:12px;line-height:1.6;overflow-x:auto;margin:0;white-space:pre;color:var(--text)">${esc(WORKFLOW_YML)}</pre>
          <button id="settings-yml-copy" class="btn btn-sm" style="position:absolute;top:8px;right:8px"
            onclick="navigator.clipboard.writeText(WORKFLOW_YML).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})">Copy</button>
        </div>
      </details>

      <div class="section">
        <div class="section-title">About Epyon</div>
        <div class="detail-grid">
          <div class="detail-card">
            <div class="label">Version</div>
            <div class="value">${epyonVersion}</div>
          </div>
          <div class="detail-card">
            <div class="label">Security Layers</div>
            <div class="value">17 + STIG</div>
          </div>
          <div class="detail-card">
            <div class="label">Tagline</div>
            <div class="value" style="font-size:13px">Absolute Security Control</div>
          </div>
        </div>
        <div class="tools-list">
          ${tools.map(t => `<span class="tool-tag">${esc(t)}</span>`).join('')}
        </div>
      </div>`;
    if (aiCfg.key_set) loadOpenAiModels();
    if (aiCfg.provider !== 'openai') loadLocalModels();
  } catch (e) {
    page.innerHTML = errBanner(e.message);
  }
}

export async function loadOpenAiModels() {
  const sel = document.getElementById('ai-openai-model');
  if (!sel) return;
  try {
    const { models } = await api.getOpenAiModels();
    if (!models || !models.length) return;
    const cur = sel.value;
    const all = [...new Set([cur, ...models])];
    sel.innerHTML = all.map(m => `<option value="${esc(m)}" ${m === cur ? 'selected' : ''}>${esc(m)}</option>`).join('');
  } catch (_) { /* keep the static list */ }
}

// Poll the primary endpoint for its models and offer them in a dropdown; falls
// back to the free-text input when the endpoint can't be reached.
export async function loadLocalModels() {
  const input  = document.getElementById('ai-model');
  const select = document.getElementById('ai-model-select');
  const status = document.getElementById('ai-model-status');
  if (!input || !select || !status) return;
  const provider = document.getElementById('ai-provider')?.value;
  const baseUrl  = (document.getElementById('ai-base-url')?.value || '').trim();
  const showInput = () => { select.style.display = 'none'; input.style.display = ''; };
  if (provider === 'openai' || !baseUrl) {
    showInput();
    status.textContent = provider === 'openai' ? '' : 'Enter a base URL to list its models.';
    return;
  }
  status.textContent = 'Looking for models…';
  try {
    const { models } = await api.getLocalModels(baseUrl);
    if (!models.length) { showInput(); status.textContent = 'The endpoint reports no models. Enter a model name.'; return; }
    const cur = select.style.display === 'none' ? input.value.trim() : select.value;
    const pick = models.includes(cur) ? cur : models[0];
    select.innerHTML = models.map(m => `<option value="${esc(m)}" ${m === pick ? 'selected' : ''}>${esc(m)}</option>`).join('');
    input.value = select.value;
    select.onchange = () => { input.value = select.value; };
    select.style.display = '';
    input.style.display = 'none';
    status.textContent = `${models.length} model${models.length === 1 ? '' : 's'} found.` + (cur && pick !== cur ? ` “${cur}” is not served here, so ${pick} is selected — save to keep it.` : '');
  } catch (e) {
    showInput();
    status.textContent = `Could not list models (${e.message}). Enter a model name manually.`;
  }
}

export function aiProviderChanged() {
  const p = document.getElementById('ai-provider')?.value;
  const row = document.getElementById('ai-openai-model-row');
  if (row) row.style.display = p === 'openai' ? 'block' : 'none';
  loadLocalModels();
}

export async function saveAiConfig() {
  const provider        = document.getElementById('ai-provider')?.value || 'auto';
  const openaiModel     = document.getElementById('ai-openai-model')?.value || '';
  const model          = document.getElementById('ai-model')?.value           || '';
  const baseUrl         = document.getElementById('ai-base-url')?.value       || '';
  const fallbackEnabled = document.getElementById('ai-fallback-enabled')?.checked || false;
  const fallbackModel   = document.getElementById('ai-fallback-model')?.value  || '';
  try {
    await api.saveAiConfig({
      provider,
      openai_model: openaiModel.trim(),
      model,
      base_url: baseUrl.trim(),
      fallback_enabled: fallbackEnabled,
      fallback_model: fallbackModel,
    });
    await renderSettings();
  } catch (e) {
    toast('Failed to save AI config: ' + e.message, 'error');
  }
}

export async function saveScanConcurrency() {
  const n = parseInt(document.getElementById('scan-concurrency')?.value, 10);
  try {
    await api.saveScanConcurrency(n);
    toast('Scan concurrency saved', 'success');
    await renderSettings();
  } catch (e) {
    toast('Failed to save scan concurrency: ' + e.message, 'error');
  }
}

export async function saveGitHubConfig() {
  const reposEl = document.getElementById('gh-repos');
  const repos = reposEl
    ? reposEl.value.split('\n').map(r => r.trim()).filter(Boolean)
    : [];

  try {
    await api.saveGitHubConfig({ repos });
    // Note: this only configures which repos to pull GitHub signals
    // (Dependabot/security issues/workflow runs) for — it intentionally does
    // NOT change any app's "Continuously Monitored" status in Metrics. That
    // classification is a separate, explicit per-app/per-scan choice (see
    // the Monitoring Type toggle on "Run New Scan" and the app list), so
    // configuring GitHub tracking here no longer silently monitors apps the
    // user never opted into.
    const statusEl = document.getElementById('sync-status');
    if (statusEl) statusEl.textContent = 'Configuration saved.';
  } catch (e) {
    toast('Failed to save GitHub config: ' + e.message, 'error');
  }
}

export let _syncPoll = null;

export async function triggerGitHubSync() {
  const btn = document.getElementById('sync-btn');
  const statusEl = document.getElementById('sync-status');
  if (btn) { btn.disabled = true; btn.textContent = '↓ Syncing…'; }
  if (statusEl) statusEl.textContent = 'Sync in progress…';
  try {
    await api.triggerGitHubSync();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
    return;
  }
  clearInterval(_syncPoll);
  _syncPoll = setInterval(async () => {
    try {
      const st = await api.getGitHubSyncStatus();
      if (st.status === 'running') return;
      clearInterval(_syncPoll);
      _syncPoll = null;
      if (btn) { btn.disabled = false; btn.textContent = '↓ Sync Now'; }
      if (st.status === 'done' && st.result) {
        const r = st.result;
        const msg = `Done — ${r.synced.length} new, ${r.skipped.length} already present, ${r.failed.length} failed`;
        if (statusEl) statusEl.textContent = msg;
      } else if (st.status === 'error') {
        if (statusEl) statusEl.textContent = 'Sync error: ' + (st.error || 'unknown');
      }
    } catch (_) {}
  }, 2000);
}

export async function saveJiraConfig() {
  const statusEl = document.getElementById('jira-status');
  if (statusEl) statusEl.textContent = 'Saving…';
  const body = {
    base_url:        (document.getElementById('jira-url')?.value   || '').trim(),
    email:           (document.getElementById('jira-email')?.value  || '').trim(),
    project_key:     (document.getElementById('jira-project')?.value || '').trim(),
    issue_type:      (document.getElementById('jira-issue-type')?.value || '').trim() || 'Bug',
    done_transition: (document.getElementById('jira-done')?.value   || '').trim() || 'Done',
    auto_close:      true,  // Always enabled - not configurable
  };
  try {
    await api.saveJiraConfig(body);
    if (statusEl) statusEl.textContent = 'Saved.';
  } catch (e) {
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
  }
}

export async function testJiraConnection() {
  const btn      = document.getElementById('jira-test-btn');
  const statusEl = document.getElementById('jira-status');
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  if (statusEl) statusEl.textContent = '';
  // Save current form values first so the test uses the latest credentials
  await saveJiraConfig().catch(() => {});
  try {
    const result = await api.testJiraConnection();
    if (statusEl) {
      statusEl.style.color = result.ok ? 'var(--pass)' : 'var(--critical)';
      statusEl.textContent = result.message || (result.ok ? 'Connected' : 'Failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--critical)'; statusEl.textContent = e.message; }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Test Connection'; }
  }
}
