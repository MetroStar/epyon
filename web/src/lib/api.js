import { _cache } from './cache.js';

// Page loads started by the previous route are aborted on navigation so a slow
// request never blocks the next page or paints over it.
let _navAbort = new AbortController();

export function _abortPageLoads() {
  _navAbort.abort();
  _navAbort = new AbortController();
}

export const api = {
  async _get(url, useCache = true) {
    // Try cache first
    if (useCache) {
      const cached = _cache.get(url);
      if (cached !== null) {
        return cached;
      }
    }

    const signal = _navAbort.signal;
    let r, data;
    try {
      r = await fetch(url, { signal });
      if (!r.ok) {
        let detail = r.statusText;
        try { detail = (await r.json()).detail || detail; } catch (_) {}
        throw new Error(`${detail} (${r.status})`);
      }
      data = await r.json();
    } catch (e) {
      // The user navigated away: leave the abandoned render pending so it
      // neither shows an error nor overwrites the page now on screen.
      if (signal.aborted) return new Promise(() => {});
      throw e;
    }

    // Store in cache if this is a cacheable endpoint
    if (useCache) {
      const serverVersion = r.headers.get('X-Cache-Version');
      _cache.set(url, data, serverVersion ? parseInt(serverVersion, 10) : undefined);
    }

    return data;
  },
  
  async _post(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      const err = new Error(`${detail} (${r.status})`);
      err.status = r.status;
      err.detail = detail;
      throw err;
    }
    
    // Invalidate cache on mutations
    if (url.includes('/scans') || url.includes('/applications') || 
        url.includes('/hide') || url.includes('/restore') || url.includes('/monitored')) {
      _cache.invalidate();
    }
    
    return r.json();
  },
  async _put(url, body) {
    const r = await fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      const err = new Error(`${detail} (${r.status})`);
      err.detail = detail;
      throw err;
    }
    return r.json();
  },
  async _delete(url) {
    const r = await fetch(url, { method: 'DELETE' });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    
    // Invalidate cache on deletions
    _cache.invalidate();
    
    return r.json();
  },
  getStats()          { return this._get('/api/stats'); },
  getApplications()   { return this._get('/api/applications'); },
  getProjects()          { return this._get('/api/projects', false); },
  createProject(body)    { return this._post('/api/projects', body); },
  updateProject(id, body){ return this._put(`/api/projects/${encodeURIComponent(id)}`, body); },
  deleteProject(id)      { return this._delete(`/api/projects/${encodeURIComponent(id)}`); },
  getHiddenApps()     { return this._get('/api/applications-hidden'); },
  hideApp(name)       { return this._post('/api/applications/hide', { name }); },
  restoreApp(name)    { return this._post('/api/applications/restore', { name }); },
  deleteApp(name)     { return this._delete(`/api/applications/data?name=${encodeURIComponent(name)}`); },
  deleteScan(id)      { return this._delete(`/api/scans/${encodeURIComponent(id)}`); },
  setMonitored(name)   { return this._post('/api/applications/monitored', { name }); },
  unsetMonitored(name) { return this._delete(`/api/applications/monitored?name=${encodeURIComponent(name)}`); },
  registerApp(name, url) {
    return this._post('/api/applications', { name, url });
  },
  getAppScans(name)   { return this._get(`/api/applications/${encodeURIComponent(name)}/scans`); },
  getScan(id)         { return this._get(`/api/scans/${encodeURIComponent(id)}`); },
  getScanHistory()    { return this._get('/api/scan-history'); },
  getApprovedImages() { return this._get('/api/settings/approved-images'); },
  getGitHubConfig()   { return this._get('/api/github/config'); },
  saveGitHubConfig(d) { return this._post('/api/github/config', d); },
  triggerGitHubSync() { return this._post('/api/github/sync', {}); },
  getGitHubSyncStatus(){ return this._get('/api/github/sync'); },
  triggerScan(target, scanType, runGarak, runStig = true, layers = null) {
    const body = { target, scan_type: scanType };
    if (runGarak) body.run_garak = true;
    if (runStig)  body.run_stig  = true;
    if (layers && layers.length) body.layers = layers;
    return this._post('/api/scans', body);
  },
  triggerScanUpload(file, scanType, runGarak, runStig = true, onProgress = null, layers = null) {
    // Uses XMLHttpRequest (rather than fetch) specifically so we can surface
    // upload progress — a project zip can be tens/hundreds of MB, and with
    // no feedback the UI just looks frozen on "Starting..." the whole time.
    const form = new FormData();
    form.append('file', file);
    form.append('scan_type', scanType);
    if (runGarak) form.append('run_garak', 'true');
    if (runStig)  form.append('run_stig', 'true');
    if (layers && layers.length) form.append('layers', JSON.stringify(layers));
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/scans/upload');
      xhr.upload.onprogress = (e) => {
        if (onProgress && e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.upload.onload = () => { if (onProgress) onProgress(100, true); };
      xhr.onload = () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText || '{}'); } catch (_) {}
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error(`${data.detail || xhr.statusText || 'Upload failed'} (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error('Network error during upload'));
      xhr.send(form);
    });
  },
  triggerScanUploadImage(file, onProgress = null) {
    // Same upload-with-progress approach as triggerScanUpload, but hits the
    // dedicated container-image endpoint (tarball instead of project zip,
    // always scan_type=container_image, no Garak/STIG/layer options since
    // those layers don't apply to an image-only scan).
    const form = new FormData();
    form.append('file', file);
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/scans/upload-image');
      xhr.upload.onprogress = (e) => {
        if (onProgress && e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.upload.onload = () => { if (onProgress) onProgress(100, true); };
      xhr.onload = () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText || '{}'); } catch (_) {}
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error(`${data.detail || xhr.statusText || 'Upload failed'} (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error('Network error during upload'));
      xhr.send(form);
    });
  },
  getJob(id)    { return this._get(`/api/jobs/${encodeURIComponent(id)}`, false); },
  getJobs()     { return this._get('/api/jobs', false); },
  runSelfAssessment(layers) { return this._post('/api/self-assessment/run', layers && layers.length ? { layers } : {}); },
  getMetrics()       { return this._get('/api/metrics'); },
  getGitHubMetrics()         { return this._get('/api/github-metrics'); },
  getGitHubSignalsHistory()  { return this._get('/api/github-signals-history'); },
  getOpenAiModels() { return this._get('/api/ai/openai-models'); },
  getLocalModels(baseUrl) { return this._get('/api/ai/local-models?base_url=' + encodeURIComponent(baseUrl || '')); },
  getAiConfig() { return this._get('/api/ai/config'); },
  saveAiConfig(d){ return this._post('/api/ai/config', d); },
  getNvdConfig() { return this._get('/api/nvd/config'); },
  getScanConcurrency() { return this._get('/api/settings/scan-concurrency'); },
  saveScanConcurrency(n) { return this._post('/api/settings/scan-concurrency', { max_concurrent_scans: n }); },
  getStigPolicy() { return this._get('/api/stig/policy'); },
  saveStigPolicy(content) { return this._post('/api/stig/policy', { content }); },
  deleteStigPolicy() { return this._delete('/api/stig/policy'); },
  getStigReference(name) { return this._get(`/api/applications/${encodeURIComponent(name)}/stig-reference`); },
  saveStigReference(name, content) { return this._post(`/api/applications/${encodeURIComponent(name)}/stig-reference`, { content }); },
  deleteStigReference(name) { return this._delete(`/api/applications/${encodeURIComponent(name)}/stig-reference`); },
  getExecSummary(id)      { return this._post(`/api/scans/${encodeURIComponent(id)}/executive-summary`, {}); },
  getTechnicalSummary(id) { return this._post(`/api/scans/${encodeURIComponent(id)}/technical-summary`, {}); },
  getGlobalExecSummary()      { return this._post('/api/executive-summary', {}); },
  getGlobalTechnicalSummary() { return this._post('/api/technical-summary', {}); },
  getGlobalIssoSummary()      { return this._post('/api/isso-summary', {}); },
  getAppIssoSummary(name)     { return this._post(`/api/applications/${encodeURIComponent(name)}/isso-summary`, {}); },
  async exportSummaryDocx(body) {
    const r = await fetch('/api/export/summary-docx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail || detail; } catch (_) {}
      throw new Error(`${detail} (${r.status})`);
    }
    return r.blob();
  },
  getFindingFix(finding)      { return this._post('/api/findings/fix', finding); },
  calculateScorecard(id)      { return this._post(`/api/scans/${encodeURIComponent(id)}/scorecard`, {}); },
  getStigData(id){ return this._get(`/api/scans/${encodeURIComponent(id)}/stig-data`); },
  getStigHistory(app, slug) {
    const p = new URLSearchParams();
    if (app)  p.set('app', app);
    if (slug) p.set('slug', slug);
    const qs = p.toString();
    return this._get('/api/stig/history' + (qs ? '?' + qs : ''));
  },
  getJiraConfig()      { return this._get('/api/jira/config'); },
  saveJiraConfig(d)    { return this._post('/api/jira/config', d); },
  testJiraConnection() { return this._post('/api/jira/test', {}); },
  getJiraTickets()     { return this._get('/api/jira/tickets'); },
  reassignJiraTickets(name) { return this._post(`/api/jira/reassign/${encodeURIComponent(name)}`, {}); },
  syncJiraApp(name)    { return this._post(`/api/jira/sync/${encodeURIComponent(name)}`, {}); },
  getJiraCandidates(id) { return this._get(`/api/scans/${encodeURIComponent(id)}/jira-candidates`, false); },
  getScanJiraEpics(id, projectKey) {
    const q = projectKey ? `?project_key=${encodeURIComponent(projectKey)}` : '';
    return this._get(`/api/scans/${encodeURIComponent(id)}/jira-epics${q}`, false);
  },
  getStigJiraContext(id) { return this._get(`/api/scans/${encodeURIComponent(id)}/stig-jira-context`, false); },
  createStigJiraTickets(id, body) { return this._post(`/api/scans/${encodeURIComponent(id)}/stig-jira-tickets`, body); },
  createJiraTickets(id, fingerprints, epicChoice) {
    return this._post(`/api/scans/${encodeURIComponent(id)}/jira-tickets`, {
      fingerprints,
      ...(epicChoice || {}),
    });
  },
  setJiraProject(id, projectKey) {
    return this._post(`/api/scans/${encodeURIComponent(id)}/jira-project`, { project_key: projectKey });
  },
  getCacheMetrics()         { return this._get('/api/metrics/cache', false); },  // Don't cache cache metrics
};
