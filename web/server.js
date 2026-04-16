#!/usr/bin/env node
'use strict';

const http     = require('http');
const https    = require('https');
const fs       = require('fs');
const path     = require('path');
const os       = require('os');
const readline = require('readline');
const { spawn } = require('child_process');
const { URL }  = require('url');

// ── Config ────────────────────────────────────────────────────
const PORT      = parseInt(process.env.EPYON_PORT || '8000', 10);
const HOST      = process.env.EPYON_HOST || '127.0.0.1';

const EPYON_ROOT          = path.resolve(__dirname, '..');
const SCRIPTS_DIR         = path.join(EPYON_ROOT, 'scripts', 'shell');
const STATIC_DIR          = path.join(__dirname, 'static');
const SCAN_HISTORY_FILE   = path.join(EPYON_ROOT, 'scan-history.json');
const APPROVED_IMAGES_FILE = path.join(EPYON_ROOT, 'configuration', 'approved-base-images.conf');

const GITHUB_CONFIG_FILE  = path.join(__dirname, 'github-config.json');

const SCAN_SEARCH_PATHS = [
  path.join(EPYON_ROOT, 'scans'),
  path.join(EPYON_ROOT, 'baseline', 'scans'),
  path.join(EPYON_ROOT, 'scripts', 'scans'),
];

const VALID_SCAN_TYPES = new Set(['quick', 'full', 'images', 'analysis']);
const SAFE_ID_RE       = /^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$/;
const JOB_ID_RE        = /^\d{14}$/;
const JOB_TIMEOUT_MS   = 7_200_000; // 2 hours

// ── In-memory job store ───────────────────────────────────────
const jobs  = {};  // jobId → job object
const procs = {};  // jobId → ChildProcess

// ── MIME types ────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
};

// ── Security helpers ──────────────────────────────────────────
/**
 * Returns true if filePath is strictly inside dir (or is dir itself).
 * Resolves both paths to prevent traversal attacks.
 */
function isInsideDir(filePath, dir) {
  const resolved = path.resolve(filePath);
  const base     = path.resolve(dir);
  return resolved === base || resolved.startsWith(base + path.sep);
}

// ── Data helpers ──────────────────────────────────────────────
function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

const DATE_PART_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_PART_RE = /^\d{2}-\d{2}-\d{2}$/;

function parseDirName(name) {
  const parts = name.split('_');
  const timePart = parts[parts.length - 1];
  const datePart = parts[parts.length - 2];
  if (parts.length >= 3 && DATE_PART_RE.test(datePart) && TIME_PART_RE.test(timePart)) {
    // 3-part: target_date_time (CI artifacts with no user)
    if (parts.length === 3) {
      return { target: parts[0], user: '', timestamp: `${datePart}T${timePart.replace(/-/g, ':')}` };
    }
    // 4+ part: target_user_date_time (local scans)
    const user   = parts[parts.length - 3];
    const target = parts.slice(0, -3).join('_');
    return { target, user, timestamp: `${datePart}T${timePart.replace(/-/g, ':')}` };
  }
  return { target: name, user: '', timestamp: '' };
}

function findScanDirs() {
  const dirs = [];
  for (const base of SCAN_SEARCH_PATHS) {
    if (!fs.existsSync(base)) continue;
    let entries;
    try { entries = fs.readdirSync(base); } catch { continue; }
    for (const name of [...entries].sort()) {
      if (name.startsWith('.')) continue;
      const d = path.join(base, name);
      try {
        if (!fs.statSync(d).isDirectory()) continue;
        if (!isInsideDir(d, EPYON_ROOT)) continue;
        dirs.push(d);
      } catch { /* skip unreadable entries */ }
    }
  }
  return dirs;
}

// ── Raw tool findings parser ──────────────────────────────────
// Reads the same source files the HTML dashboard uses so findings
// match exactly between the two views.

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function normSev(s) {
  if (!s) return 'unknown';
  const l = s.toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium' || l === 'moderate') return 'medium';
  if (l === 'low' || l === 'negligible' || l === 'info') return 'low';
  return 'unknown';
}

function jsonFilesIn(dir, skipSymlinks = true) {
  if (!fs.existsSync(dir)) return [];
  try {
    return fs.readdirSync(dir)
      .filter(f => f.endsWith('.json') && !f.includes('statistics'))
      .map(f => path.join(dir, f))
      .filter(f => {
        try {
          const st = fs.lstatSync(f);
          if (skipSymlinks && st.isSymbolicLink()) return false;
          return st.isFile();
        } catch { return false; }
      });
  } catch { return []; }
}

function parseTrivyDir(scanDir) {
  const findings = [];
  for (const file of jsonFilesIn(path.join(scanDir, 'trivy'))) {
    const raw = readJSON(file);
    if (!raw || !raw.SchemaVersion) continue;
    for (const result of (raw.Results || [])) {
      for (const v of (result.Vulnerabilities || [])) {
        findings.push({
          tool:        'Trivy',
          id:          v.VulnerabilityID || '',
          severity:    normSev(v.Severity),
          package:     v.PkgName || '',
          version:     v.InstalledVersion || '',
          fixed_version: v.FixedVersion || '',
          title:       v.Title || v.Description || '',
          description: v.Description || '',
          target:      result.Target || '',
          references:  (v.References || []).slice(0, 3),
        });
      }
    }
  }
  return findings;
}

function parseGrypeDir(scanDir) {
  const findings = [];
  for (const file of jsonFilesIn(path.join(scanDir, 'grype'))) {
    const raw = readJSON(file);
    if (!raw || !Array.isArray(raw.matches)) continue;
    for (const m of raw.matches) {
      const vuln = m.vulnerability || {};
      const art  = m.artifact      || {};
      findings.push({
        tool:        'Grype',
        id:          vuln.id || '',
        severity:    normSev(vuln.severity),
        package:     art.name    || '',
        version:     art.version || '',
        fixed_version: (vuln.fix && vuln.fix.versions && vuln.fix.versions[0]) || '',
        title:       vuln.description || '',
        description: vuln.description || '',
        target:      (art.locations && art.locations[0] && art.locations[0].path) || '',
        references:  (vuln.urls || []).slice(0, 3),
      });
    }
  }
  return findings;
}

function parseTruffleHogDir(scanDir) {
  const findings = [];
  const dir = path.join(scanDir, 'trufflehog');
  if (!fs.existsSync(dir)) return findings;
  const scanId = path.basename(scanDir);
  for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.json') && !f.startsWith(scanId + '_'))) {
    const fullPath = path.join(dir, file);
    try {
      const lines = fs.readFileSync(fullPath, 'utf8').split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        let obj;
        try { obj = JSON.parse(line); } catch { continue; }
        // Skip info/progress lines — real findings have a DetectorName
        if (!obj.DetectorName) continue;
        const meta   = obj.SourceMetadata && obj.SourceMetadata.Data;
        const fsData = (meta && meta.Filesystem) || (meta && meta.Git) || {};
        findings.push({
          tool:        'TruffleHog',
          id:          obj.DetectorName || 'SECRET',
          severity:    obj.Verified ? 'critical' : 'high',
          package:     obj.DetectorName || '',
          version:     '',
          fixed_version: '',
          title:       `${obj.Verified ? 'Verified' : 'Unverified'} secret: ${obj.DetectorName}`,
          description: `Detector: ${obj.DetectorName}. File: ${fsData.file || fsData.path || 'unknown'}. Line: ${fsData.line || '?'}`,
          target:      fsData.file || fsData.path || '',
          references:  [],
        });
      }
    } catch { /* skip unreadable files */ }
  }
  return findings;
}

function parseCheckovDir(scanDir) {
  const findings = [];
  const dir = path.join(scanDir, 'checkov');
  if (!fs.existsSync(dir)) return findings;

  const scanId = path.basename(scanDir);
  const candidates = [];
  // Checkov sometimes writes a directory named *.json with results_json.json inside
  for (const entry of fs.readdirSync(dir)) {
    if (entry.startsWith(scanId + '_')) continue; // skip prefixed duplicate copies
    const full = path.join(dir, entry);
    try {
      // Use statSync (follows symlinks) so canonical symlinks like checkov-results.json → prefixed file are readable
      const st = fs.statSync(full);
      if (st.isDirectory() && entry.endsWith('.json')) {
        const inner = path.join(full, 'results_json.json');
        if (fs.existsSync(inner)) candidates.push(inner);
      } else if (st.isFile() && entry.endsWith('.json') && !entry.includes('statistics')) {
        candidates.push(full);
      }
    } catch { /* skip */ }
  }

  for (const file of candidates) {
    const raw = readJSON(file);
    if (!Array.isArray(raw)) continue;
    for (const section of raw) {
      for (const check of (section.results && section.results.failed_checks) || []) {
        // Checkov severity: some checks have it, many don't — treat all as medium
        const rawSev = check.severity || check.check_result && check.check_result.severity;
        findings.push({
          tool:        'Checkov',
          id:          check.check_id || '',
          severity:    normSev(rawSev) === 'unknown' ? 'medium' : normSev(rawSev),
          package:     check.file_path || '',
          version:     '',
          fixed_version: '',
          title:       check.check_name || check.check_id || '',
          description: `${check.check_name || ''} — ${check.file_path || ''}:${(check.file_line_range || []).join('-')}`,
          target:      check.file_path || '',
          references:  check.guideline ? [check.guideline] : [],
        });
      }
    }
  }
  return findings;
}

function parseClamAVDir(scanDir) {
  const findings = [];
  const dir = path.join(scanDir, 'clamav');
  if (!fs.existsSync(dir)) return findings;

  // Look for detailed log first, fall back to scan.log
  let logContent = '';
  for (const candidate of ['clamav-detailed.log', 'scan.log']) {
    const f = path.join(dir, candidate);
    if (fs.existsSync(f)) { try { logContent = fs.readFileSync(f, 'utf8'); break; } catch {} }
  }

  // Lines like: /path/to/file: VirusName FOUND
  const foundRe = /^(.+?):\s+(.+?)\s+FOUND\s*$/m;
  for (const line of logContent.split('\n')) {
    const m = line.match(foundRe);
    if (m) {
      findings.push({
        tool:        'ClamAV',
        id:          m[2].trim(),
        severity:    'critical',
        package:     path.basename(m[1].trim()),
        version:     '',
        fixed_version: '',
        title:       `Malware detected: ${m[2].trim()}`,
        description: `File: ${m[1].trim()}  Signature: ${m[2].trim()}`,
        target:      m[1].trim(),
        references:  [],
      });
    }
  }
  return findings;
}

function parseAnchoreDir(scanDir) {
  const findings = [];
  const anchoreDir = path.join(scanDir, 'anchore');
  // Read filesystem results + image results; skip sbom results (duplicates filesystem)
  const files = [];
  const fsFile = path.join(anchoreDir, 'anchore-filesystem-results.json');
  if (fs.existsSync(fsFile)) files.push(fsFile);
  const imagesDir = path.join(anchoreDir, 'images');
  if (fs.existsSync(imagesDir)) {
    for (const f of jsonFilesIn(imagesDir)) files.push(f);
  }
  for (const file of files) {
    const raw = readJSON(file);
    if (!raw) continue;
    for (const m of (raw.matches || [])) {
      const vuln = m.vulnerability || {};
      const art  = m.artifact      || {};
      findings.push({
        tool:          'Anchore',
        id:            vuln.id   || '',
        severity:      (vuln.severity || 'unknown').toLowerCase(),
        package:       art.name    || '',
        version:       art.version || '',
        fixed_version: (vuln.fix && vuln.fix.versions && vuln.fix.versions[0]) || '',
        title:         vuln.description || vuln.id || '',
        description:   vuln.description || '',
        target:        (art.locations && art.locations[0] && art.locations[0].path) || '',
        references:    vuln.urls || [],
      });
    }
  }
  return findings;
}

function parseXeolDir(scanDir) {
  const findings = [];
  for (const file of jsonFilesIn(path.join(scanDir, 'xeol'))) {
    const raw = readJSON(file);
    if (!raw) continue;
    for (const m of (raw.matches || [])) {
      const pkg = m.artifact || m.package || {};
      findings.push({
        tool:        'Xeol',
        id:          (m.eol && m.eol.eolDate) ? `EOL:${m.eol.eolDate}` : 'EOL',
        severity:    'high',
        package:     pkg.name    || '',
        version:     pkg.version || '',
        fixed_version: '',
        title:       `End-of-life: ${pkg.name || ''}@${pkg.version || ''}`,
        description: `${pkg.name || ''}@${pkg.version || ''} reached end-of-life${m.eol && m.eol.eolDate ? ' on ' + m.eol.eolDate : ''}`,
        target:      (pkg.locations && pkg.locations[0] && pkg.locations[0].path) || '',
        references:  [],
      });
    }
  }
  return findings;
}

/**
 * Parse all raw tool output files and return a structured findings object
 * matching the shape the frontend already expects.
 */
function parseScanFindings(scanDir) {
  const all = [
    ...parseTrivyDir(scanDir),
    ...parseGrypeDir(scanDir),
    ...parseAnchoreDir(scanDir),
    ...parseTruffleHogDir(scanDir),
    ...parseCheckovDir(scanDir),
    ...parseClamAVDir(scanDir),
    ...parseXeolDir(scanDir),
  ];

  const byTool = new Set(all.map(f => f.tool));
  const bySev  = { critical: [], high: [], medium: [], low: [] };
  for (const f of all) {
    const s = f.severity === 'unknown' ? 'low' : f.severity;
    (bySev[s] = bySev[s] || []).push(f);
  }

  return {
    summary: {
      total_critical: bySev.critical.length,
      total_high:     bySev.high.length,
      total_medium:   bySev.medium.length,
      total_low:      bySev.low.length,
      tools_analyzed: [...byTool],
    },
    critical_findings: bySev.critical,
    high_findings:     bySev.high,
    medium_findings:   bySev.medium,
    low_findings:      bySev.low,
  };
}

// ── GitHub Artifact Sync ──────────────────────────────────────

function readGitHubConfig() {
  try { return JSON.parse(fs.readFileSync(GITHUB_CONFIG_FILE, 'utf8')); } catch { return {}; }
}

function saveGitHubConfig(cfg) {
  fs.writeFileSync(GITHUB_CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

/** Make a GitHub API GET request, returns parsed JSON. */
function githubGet(apiPath, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.github.com',
      path: apiPath,
      method: 'GET',
      headers: {
        'Authorization':        `Bearer ${token}`,
        'Accept':               'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent':           'epyon-web/3.0.0',
      },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return reject(new Error(`GitHub API ${res.statusCode}: ${data.slice(0, 200)}`));
        }
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Invalid JSON from GitHub API`)); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

/** Download a URL (following up to 5 redirects) and write to destPath. */
function githubDownload(url, destPath, token, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
    const parsed = new URL(url);
    // Only send auth header to api.github.com — strip it for CDN redirects
    const isGitHubApi = parsed.hostname === 'api.github.com';
    const options = {
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers: {
        ...(isGitHubApi ? {
          'Authorization':        `Bearer ${token}`,
          'Accept':               'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        } : {}),
        'User-Agent': 'epyon-web/3.0.0',
      },
    };
    const req = https.request(options, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
        res.resume();
        return githubDownload(res.headers.location, destPath, token, redirectsLeft - 1)
          .then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} downloading artifact`));
      }
      const out = fs.createWriteStream(destPath);
      res.pipe(out);
      out.on('finish', () => out.close(() => resolve()));
      out.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

// Scan ID pattern: target_YYYY-MM-DD_HH-MM-SS  OR  target_user_YYYY-MM-DD_HH-MM-SS
const GITHUB_SCAN_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$/;

// Global sync state
let syncState = { status: 'idle', started_at: null, result: null, error: null };

async function runGitHubSync() {
  const cfg = readGitHubConfig();
  if (!cfg.token) throw new Error('GitHub token not configured');
  const repos = (cfg.repos || []).filter(r => r && r.includes('/'));
  if (!repos.length) throw new Error('No repositories configured');

  const result = { synced: [], skipped: [], failed: [] };

  for (const repoSpec of repos) {
    const [owner, repo] = repoSpec.trim().split('/');
    try {
      const runsData = await githubGet(
        `/repos/${owner}/${repo}/actions/runs?status=completed&per_page=30`,
        cfg.token
      );
      for (const run of (runsData.workflow_runs || [])) {
        const artsData = await githubGet(
          `/repos/${owner}/${repo}/actions/runs/${run.id}/artifacts?per_page=50`,
          cfg.token
        );
        for (const artifact of (artsData.artifacts || [])) {
          if (!GITHUB_SCAN_ID_RE.test(artifact.name)) continue;
          if (artifact.name.startsWith('metrics-')) continue;
          if (artifact.expired) continue;
          const scanId = artifact.name;
          // Skip if already downloaded
          if (findScanDirs().some(d => path.basename(d) === scanId)) {
            result.skipped.push(scanId);
            continue;
          }
          const tmpZip = path.join(os.tmpdir(), `epyon-gh-${scanId}.zip`);
          try {
            await githubDownload(
              `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifact.id}/zip`,
              tmpZip, cfg.token
            );
            const destDir = path.join(EPYON_ROOT, 'scans', scanId);
            fs.mkdirSync(destDir, { recursive: true });
            await new Promise((resolve, reject) => {
              const proc = spawn('unzip', ['-o', tmpZip, '-d', destDir], {
                stdio: ['ignore', 'pipe', 'pipe'],
              });
              proc.on('close', code => code === 0 ? resolve() : reject(new Error(`unzip exited ${code}`)));
            });
            fs.writeFileSync(path.join(destDir, 'ci-metadata.json'), JSON.stringify({
              source: 'github', repo: `${owner}/${repo}`,
              run_id: run.id, artifact_id: artifact.id,
              workflow: run.name || '',
              branch: run.head_branch || '',
              commit: run.head_sha ? run.head_sha.slice(0, 7) : '',
              synced_at: new Date().toISOString(),
            }, null, 2));
            result.synced.push(scanId);
          } catch (e) {
            result.failed.push({ scan_id: scanId, error: e.message });
          } finally {
            try { fs.unlinkSync(tmpZip); } catch {}
          }
        }
      }
    } catch (e) {
      result.failed.push({ repo: `${owner}/${repo}`, error: e.message });
    }
  }

  cfg.last_sync = new Date().toISOString();
  saveGitHubConfig(cfg);
  return result;
}

function loadScan(scanDir) {
  const scanId = path.basename(scanDir);
  const parsed = parseDirName(scanId);
  const data = {
    scan_id:        scanId,
    target:         parsed.target,
    user:           parsed.user,
    timestamp:      parsed.timestamp,
    scan_type:      'full',
    critical: 0, high: 0, medium: 0, low: 0, total: 0,
    tools_analyzed: [],
    has_dashboard:  false,
    dashboard_url:  null,
    location:       path.relative(EPYON_ROOT, path.dirname(scanDir)),
  };

  const meta = readJSON(path.join(scanDir, 'scan-metadata.json'));
  if (meta) {
    data.scan_type        = meta.scan_type        || 'full';
    data.target           = meta.target_name      || parsed.target;
    data.timestamp        = meta.scan_timestamp   || parsed.timestamp;
    data.target_directory = meta.target_directory || '';
    data.file_statistics  = meta.file_statistics  || {};
  }

  // Use raw tool files as the source of truth (same as generate-security-dashboard.sh).
  // Fall back to security-findings-summary.json counts only when no tool dirs exist yet.
  const rawFindings = parseScanFindings(scanDir);
  const hasRaw = rawFindings.summary.tools_analyzed.length > 0;

  if (hasRaw) {
    data.critical       = rawFindings.summary.total_critical;
    data.high           = rawFindings.summary.total_high;
    data.medium         = rawFindings.summary.total_medium;
    data.low            = rawFindings.summary.total_low;
    data.total          = data.critical + data.high + data.medium + data.low;
    data.tools_analyzed = rawFindings.summary.tools_analyzed;
  } else {
    const findings = readJSON(path.join(scanDir, 'security-findings-summary.json'));
    if (findings) {
      const s = findings.summary || findings;
      data.critical       = s.total_critical || 0;
      data.high           = s.total_high     || 0;
      data.medium         = s.total_medium   || 0;
      data.low            = s.total_low      || 0;
      data.total          = data.critical + data.high + data.medium + data.low;
      data.tools_analyzed = s.tools_analyzed || [];
    }
  }

  const dashboard = path.join(scanDir, 'consolidated-reports', 'dashboards', 'security-dashboard.html');
  if (fs.existsSync(dashboard)) {
    data.has_dashboard = true;
    data.dashboard_url = `/api/scans/${encodeURIComponent(scanId)}/dashboard`;
  }

  // Check for GitHub Actions CI provenance
  const ciMeta = readJSON(path.join(scanDir, 'ci-metadata.json'));
  if (ciMeta && ciMeta.source === 'github') {
    data.ci_source = {
      source:   'github',
      repo:     ciMeta.repo     || '',
      branch:   ciMeta.branch   || '',
      commit:   ciMeta.commit   || '',
      workflow: ciMeta.workflow || '',
      run_id:   ciMeta.run_id   || null,
    };
  }

  return data;
}

function getStatus(scan) {
  if (!scan || !scan.scan_id) return 'unknown';
  if (scan.critical > 0) return 'critical';
  if (scan.high     > 0) return 'high';
  if (scan.medium   > 0) return 'medium';
  if (scan.low      > 0) return 'low';
  return 'clean';
}

// ── Response helpers ──────────────────────────────────────────
function jsonResponse(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':           'application/json; charset=utf-8',
    'Content-Length':         Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function errResponse(res, status, detail) {
  jsonResponse(res, { detail }, status);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 65_536) reject(new Error('Request body too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── Static file serving ───────────────────────────────────────
function serveFile(res, filePath, contentType) {
  const body = fs.readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': contentType, 'Content-Length': body.length });
  res.end(body);
}

function serveStatic(res, urlPath) {
  // Normalize and resolve candidate path, preventing traversal
  const normalized = path.normalize(urlPath);
  const candidate  = path.resolve(STATIC_DIR, normalized.replace(/^[/\\]/, ''));

  if (!isInsideDir(candidate, STATIC_DIR)) {
    return errResponse(res, 403, 'Forbidden');
  }

  if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
    const ext  = path.extname(candidate).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    return serveFile(res, candidate, mime);
  }

  // SPA fallback → index.html
  return serveFile(res, path.join(STATIC_DIR, 'index.html'), 'text/html; charset=utf-8');
}

// ── Job runner ────────────────────────────────────────────────
function runScanJob(jobId, target, scanType, scriptPath) {
  jobs[jobId].status = 'running';

  const env = Object.assign({}, process.env, {
    CI:                 'true',
    NONINTERACTIVE:     '1',
    DEBIAN_FRONTEND:    'noninteractive',
    TERM:               'dumb',
    SKIP_GARAK:         'true',   // skip LLM layer — blocks without API keys
  });

  const child = spawn('bash', [scriptPath, target, scanType], {
    cwd:   EPYON_ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],  // stdin closed; capture stdout+stderr
  });

  procs[jobId] = child;

  // Strip ANSI colour codes and append a line to the job's output buffer
  const appendLine = (line) => {
    const clean = line.replace(/\x1b\[[0-9;]*[mGKHF]/g, '').trimEnd();
    if (!clean) return;
    jobs[jobId].output.push(clean);
    if (jobs[jobId].output.length > 1000) {
      jobs[jobId].output = jobs[jobId].output.slice(-1000);
    }
  };

  // readline handles partial-line buffering and the echo -n "." problem
  for (const stream of [child.stdout, child.stderr]) {
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    rl.on('line', appendLine);
  }

  // Hard timeout
  const timer = setTimeout(() => {
    appendLine(`[epyon-web] Job timed out after ${JOB_TIMEOUT_MS / 60_000} minutes`);
    child.kill('SIGTERM');
    setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 5000);
  }, JOB_TIMEOUT_MS);

  child.on('close', (code) => {
    clearTimeout(timer);
    delete procs[jobId];
    if (jobs[jobId].status === 'running') {
      jobs[jobId].exit_code    = code;
      jobs[jobId].status       = code === 0 ? 'completed' : 'failed';
      jobs[jobId].completed_at = new Date().toISOString();
    }
  });

  child.on('error', (error) => {
    clearTimeout(timer);
    delete procs[jobId];
    jobs[jobId].status       = 'error';
    jobs[jobId].error        = error.message;
    jobs[jobId].completed_at = new Date().toISOString();
  });
}

// ── Request logger ────────────────────────────────────────────
function logRequest(method, url, status) {
  const time = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`${time}  ${method.padEnd(6)} ${String(status).padStart(3)}  ${url}`);
}

// ── Router ────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const base     = `http://${req.headers.host || 'localhost'}`;
  const parsed   = new URL(req.url, base);
  const pathname = parsed.pathname;
  const method   = req.method.toUpperCase();

  // Security headers on every response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  // ── Static assets ─────────────────────────────────────────
  if (pathname.startsWith('/static/')) {
    return serveStatic(res, pathname.slice('/static'.length));
  }

  // ── Health ────────────────────────────────────────────────
  if (pathname === '/api/health' && method === 'GET') {
    return jsonResponse(res, { status: 'ok', epyon_root: EPYON_ROOT });
  }

  // ── Stats ─────────────────────────────────────────────────
  if (pathname === '/api/stats' && method === 'GET') {
    const scans   = findScanDirs().map(loadScan);
    const targets = new Set(scans.map(s => s.target));
    const history = readJSON(SCAN_HISTORY_FILE);
    if (history) for (const t of (history.targets || [])) targets.add(t);
    return jsonResponse(res, {
      total_applications: targets.size,
      total_scans:        scans.length,
      critical: scans.reduce((a, s) => a + s.critical, 0),
      high:     scans.reduce((a, s) => a + s.high,     0),
      medium:   scans.reduce((a, s) => a + s.medium,   0),
      low:      scans.reduce((a, s) => a + s.low,       0),
    });
  }

  // ── Applications list ─────────────────────────────────────
  if (pathname === '/api/applications' && method === 'GET') {
    const scans    = findScanDirs().map(loadScan);
    const byTarget = {};
    for (const s of scans) {
      (byTarget[s.target] = byTarget[s.target] || []).push(s);
    }
    const history = readJSON(SCAN_HISTORY_FILE);
    if (history) {
      for (const e of (history.trend || [])) {
        const t = e.target_name || '';
        if (t && !byTarget[t]) byTarget[t] = [];
      }
    }
    const result = Object.entries(byTarget).map(([name, tscans]) => {
      tscans.sort((a, b) => (b.timestamp > a.timestamp ? 1 : -1));
      const latest = tscans[0] || {};
      return {
        name,
        scan_count:     tscans.length,
        last_scanned:   latest.timestamp  || '',
        scan_type:      latest.scan_type  || '',
        critical:       latest.critical   || 0,
        high:           latest.high       || 0,
        medium:         latest.medium     || 0,
        low:            latest.low        || 0,
        status:         getStatus(latest),
        latest_scan_id: latest.scan_id    || '',
      };
    });
    result.sort((a, b) => (b.last_scanned > a.last_scanned ? 1 : -1));
    return jsonResponse(res, result);
  }

  // ── App scans  /api/applications/:name/scans ──────────────
  const appScansMatch = pathname.match(/^\/api\/applications\/([^/]+)\/scans$/);
  if (appScansMatch && method === 'GET') {
    const name = decodeURIComponent(appScansMatch[1]);
    if (!SAFE_ID_RE.test(name)) return errResponse(res, 400, 'Invalid application name');
    const scans = findScanDirs()
      .filter(d => parseDirName(path.basename(d)).target === name)
      .map(loadScan)
      .sort((a, b) => (b.timestamp > a.timestamp ? 1 : -1));
    return jsonResponse(res, scans);
  }

  // ── Scan dashboard  /api/scans/:id/dashboard ─────────────
  const dashMatch = pathname.match(/^\/api\/scans\/([^/]+)\/dashboard$/);
  if (dashMatch && method === 'GET') {
    const scanId = decodeURIComponent(dashMatch[1]);
    if (!SAFE_ID_RE.test(scanId)) return errResponse(res, 400, 'Invalid scan_id');
    const dir = findScanDirs().find(d => path.basename(d) === scanId);
    if (!dir) return errResponse(res, 404, 'Scan not found');
    const dashboard = path.join(dir, 'consolidated-reports', 'dashboards', 'security-dashboard.html');
    if (!isInsideDir(dashboard, EPYON_ROOT)) return errResponse(res, 403, 'Access denied');
    if (!fs.existsSync(dashboard)) return errResponse(res, 404, 'Dashboard not generated for this scan');
    return serveFile(res, dashboard, 'text/html; charset=utf-8');
  }

  // ── Scan detail  /api/scans/:id ───────────────────────────
  const scanMatch = pathname.match(/^\/api\/scans\/([^/]+)$/);
  if (scanMatch && method === 'GET') {
    const scanId = decodeURIComponent(scanMatch[1]);
    if (!SAFE_ID_RE.test(scanId)) return errResponse(res, 400, 'Invalid scan_id');
    const dir = findScanDirs().find(d => path.basename(d) === scanId);
    if (!dir) return errResponse(res, 404, 'Scan not found');
    const data = loadScan(dir);
    // Always use raw parsed findings — same source as generate-security-dashboard.sh
    data.findings = parseScanFindings(dir);
    return jsonResponse(res, data);
  }

  // ── Trigger scan  POST /api/scans ─────────────────────────
  if (pathname === '/api/scans' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return errResponse(res, 400, e.message); }

    const { target, scan_type: scanType = 'full' } = body;
    if (!target || typeof target !== 'string') return errResponse(res, 400, 'target is required');
    const trimmed = target.trim();
    const validPrefixes = ['/', './', '../', 'https://', 'http://', 'git@'];
    if (!validPrefixes.some(p => trimmed.startsWith(p))) {
      return errResponse(res, 400, 'target must be an absolute path, relative path, or Git URL');
    }
    if (/[;&|`$\(\)\n\r<>]/.test(trimmed)) return errResponse(res, 400, 'target contains invalid characters');
    if (!VALID_SCAN_TYPES.has(scanType)) {
      return errResponse(res, 400, `scan_type must be one of: ${[...VALID_SCAN_TYPES].sort().join(', ')}`);
    }

    const scriptPath = path.join(SCRIPTS_DIR, 'run-target-security-scan.sh');
    if (!fs.existsSync(scriptPath)) return errResponse(res, 500, 'Scan script not found');

    // 14-digit job ID: YYYYMMDDHHmmss
    const jobId = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    jobs[jobId] = {
      job_id:       jobId,
      target:       trimmed,
      scan_type:    scanType,
      status:       'queued',
      started_at:   new Date().toISOString(),
      completed_at: null,
      exit_code:    null,
      output:       [],
      error:        null,
    };
    setImmediate(() => runScanJob(jobId, trimmed, scanType, scriptPath));
    return jsonResponse(res, { job_id: jobId, status: 'queued' }, 202);
  }

  // ── Scan history ──────────────────────────────────────────
  if (pathname === '/api/scan-history' && method === 'GET') {
    const scans = findScanDirs().map(loadScan);
    const targets = [...new Set(scans.map(s => s.target))].sort();
    const users   = [...new Set(scans.map(s => s.user).filter(Boolean))].sort();
    return jsonResponse(res, {
      generated_at: new Date().toISOString(),
      total_scans:  scans.length,
      targets,
      users,
    });
  }

  // ── Settings ──────────────────────────────────────────────
  if (pathname === '/api/settings/approved-images' && method === 'GET') {
    let content = '';
    try { content = fs.readFileSync(APPROVED_IMAGES_FILE, 'utf8'); } catch {}
    return jsonResponse(res, { content });
  }

  // ── GitHub config  GET /api/github/config ─────────────────
  if (pathname === '/api/github/config' && method === 'GET') {
    const cfg = readGitHubConfig();
    // Mask token — never send the raw token to the browser
    const masked = cfg.token ? cfg.token.replace(/(?<=.{7}).(?=.{4})/g, '*') : '';
    return jsonResponse(res, {
      token_set:  !!cfg.token,
      token_hint: masked,
      repos:      cfg.repos || [],
      last_sync:  cfg.last_sync || null,
    });
  }

  // ── GitHub config  POST /api/github/config ────────────────
  if (pathname === '/api/github/config' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return errResponse(res, 400, e.message); }
    const cfg = readGitHubConfig();
    // Only update token if a non-empty one is provided (sentinel "keep" means no change)
    if (body.token && body.token !== 'KEEP_EXISTING') {
      if (!/^(ghp_|github_pat_|ghs_|gho_)[a-zA-Z0-9_]+$/.test(body.token.trim())) {
        return errResponse(res, 400, 'Token does not look like a valid GitHub token');
      }
      cfg.token = body.token.trim();
    }
    if (Array.isArray(body.repos)) {
      cfg.repos = body.repos
        .map(r => r.trim())
        .filter(r => /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(r));
    }
    saveGitHubConfig(cfg);
    return jsonResponse(res, { ok: true });
  }

  // ── GitHub sync  POST /api/github/sync ────────────────────
  if (pathname === '/api/github/sync' && method === 'POST') {
    if (syncState.status === 'running') {
      return jsonResponse(res, { ok: false, message: 'Sync already in progress' });
    }
    syncState = { status: 'running', started_at: new Date().toISOString(), result: null, error: null };
    // Run async, don't await
    runGitHubSync().then(result => {
      syncState = { status: 'done', started_at: syncState.started_at, result, error: null };
    }).catch(err => {
      syncState = { status: 'error', started_at: syncState.started_at, result: null, error: err.message };
    });
    return jsonResponse(res, { ok: true, message: 'Sync started' });
  }

  // ── GitHub sync status  GET /api/github/sync ──────────────
  if (pathname === '/api/github/sync' && method === 'GET') {
    return jsonResponse(res, syncState);
  }

  // ── Jobs list ─────────────────────────────────────────────
  if (pathname === '/api/jobs' && method === 'GET') {
    const list = Object.values(jobs).sort((a, b) => (b.started_at > a.started_at ? 1 : -1));
    return jsonResponse(res, list);
  }

  // ── Cancel job  POST /api/jobs/:id/cancel ─────────────────
  const cancelMatch = pathname.match(/^\/api\/jobs\/([^/]+)\/cancel$/);
  if (cancelMatch && method === 'POST') {
    const jobId = decodeURIComponent(cancelMatch[1]);
    if (!JOB_ID_RE.test(jobId)) return errResponse(res, 400, 'Invalid job_id');
    if (!jobs[jobId]) return errResponse(res, 404, 'Job not found');
    if (!['queued', 'running'].includes(jobs[jobId].status)) return errResponse(res, 409, 'Job is not running');
    const proc = procs[jobId];
    if (proc) { try { proc.kill('SIGTERM'); } catch {} }
    jobs[jobId].status       = 'cancelled';
    jobs[jobId].completed_at = new Date().toISOString();
    jobs[jobId].output.push('[epyon-web] Job cancelled by user');
    return jsonResponse(res, { job_id: jobId, status: 'cancelled' });
  }

  // ── Job detail  GET /api/jobs/:id ─────────────────────────
  const jobMatch = pathname.match(/^\/api\/jobs\/([^/]+)$/);
  if (jobMatch && method === 'GET') {
    const jobId = decodeURIComponent(jobMatch[1]);
    if (!JOB_ID_RE.test(jobId)) return errResponse(res, 400, 'Invalid job_id');
    if (!jobs[jobId]) return errResponse(res, 404, 'Job not found');
    return jsonResponse(res, jobs[jobId]);
  }

  // ── SPA fallback (all non-API routes → index.html) ────────
  if (!pathname.startsWith('/api/')) {
    return serveStatic(res, '/index.html');
  }

  return errResponse(res, 404, 'Not found');
}

// ── HTTP server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (e) {
    console.error('Unhandled error:', e);
    if (!res.headersSent) errResponse(res, 500, 'Internal server error');
  }
  logRequest(req.method, req.url, res.statusCode);
});

// ── Graceful shutdown ─────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n${signal} received — shutting down`);
  for (const proc of Object.values(procs)) {
    try { proc.kill('SIGTERM'); } catch {}
  }
  server.close(() => {
    console.log('Server stopped.');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// ── Start ─────────────────────────────────────────────────────
server.listen(PORT, HOST, () => {
  const url = `http://${HOST}:${PORT}`;
  const pad = ' '.repeat(Math.max(0, 42 - url.length));
  console.log('');
  console.log('┌──────────────────────────────────────────────────────┐');
  console.log('│                                                      │');
  console.log('│   ⚡  EPYON  Web Interface                           │');
  console.log('│   Absolute Security Control                          │');
  console.log('│                                                      │');
  console.log(`│   ${url}${pad}│`);
  console.log('│                                                      │');
  console.log('│   Press Ctrl+C to stop                              │');
  console.log('└──────────────────────────────────────────────────────┘');
  console.log('');

  // ── Auto-sync GitHub Actions artifacts every 3 hours ─────
  const SYNC_INTERVAL_MS = 3 * 60 * 60 * 1000; // 3 hours
  function scheduledSync() {
    const cfg = readGitHubConfig();
    if (!cfg.token || !(cfg.repos || []).length) return;
    if (syncState.status === 'running') return;
    console.log('[github-sync] Starting scheduled sync…');
    syncState = { status: 'running', started_at: new Date().toISOString(), result: null, error: null };
    runGitHubSync().then(result => {
      syncState = { status: 'done', started_at: syncState.started_at, result, error: null };
      const r = result;
      console.log(`[github-sync] Done — ${r.synced.length} new, ${r.skipped.length} skipped, ${r.failed.length} failed`);
    }).catch(err => {
      syncState = { status: 'error', started_at: syncState.started_at, result: null, error: err.message };
      console.log(`[github-sync] Error — ${err.message}`);
    });
  }

  // Run once shortly after startup, then every 3 hours
  setTimeout(scheduledSync, 10_000).unref();
  setInterval(scheduledSync, SYNC_INTERVAL_MS).unref();
});
