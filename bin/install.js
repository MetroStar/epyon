#!/usr/bin/env node
/**
 * Epyon postinstall script
 *
 * Copies the Epyon GitHub Actions workflow into the consuming project's
 * .github/workflows/ directory so security scanning starts working
 * immediately after `npm install github:MetroStar/epyon`.
 *
 * Behaviour:
 *   - Resolves the consumer project root via INIT_CWD (npm/yarn) or cwd (pnpm)
 *   - Skips silently when run inside the epyon repo itself
 *   - Creates .github/workflows/ if it does not yet exist
 *   - Always writes the latest workflow file (overwrites on upgrade)
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Source (inside the installed package) ─────────────────────────────────────
// bin/templates/ is included via the "files" field and kept fresh by bin/prepare.js.
const SOURCE = path.join(__dirname, 'templates', 'scan-private-repo.yml');

// ── Consumer project root ─────────────────────────────────────────────────────
// INIT_CWD = the directory from which `npm install` was invoked (npm ≥ 5, yarn)
// Falls back to process.cwd() which works for pnpm and direct node invocations.
const projectRoot = process.env.INIT_CWD || process.cwd();

// ── Guard: skip when installing epyon into itself ────────────────────────────
const selfRoot = path.resolve(__dirname, '..');
if (path.resolve(projectRoot) === selfRoot) {
  process.exit(0);
}

// ── Destination ───────────────────────────────────────────────────────────────
const destDir  = path.join(projectRoot, '.github', 'workflows');
const destFile = path.join(destDir, 'scan-private-repo.yml');

// ── Verify source exists (GitHub installs always have it; registry packs may not) ─
if (!fs.existsSync(SOURCE)) {
  console.warn(
    '\n[epyon] Warning: workflow template not found at:\n  ' + SOURCE +
    '\n  Skipping automatic workflow installation.\n' +
    '  To install manually, copy .github/workflows/scan-private-repo.yml from\n' +
    '  https://github.com/MetroStar/epyon into your .github/workflows/ directory.\n'
  );
  process.exit(0);
}

// ── Create destination directory ──────────────────────────────────────────────
fs.mkdirSync(destDir, { recursive: true });

// ── Copy (overwrite) ──────────────────────────────────────────────────────────
const existed = fs.existsSync(destFile);
fs.copyFileSync(SOURCE, destFile);

// ── Success message ───────────────────────────────────────────────────────────
const tag = existed ? 'updated' : 'installed';
console.log(
  '\n╔══════════════════════════════════════════════════════════════╗\n' +
  '║  Epyon Security Scanner — workflow ' + tag.padEnd(26) + '║\n' +
  '╚══════════════════════════════════════════════════════════════╝\n' +
  '\n  ✅  ' + destFile + '\n' +
  '\n  Next steps:\n' +
  '    1. Commit the workflow file:  git add ' + path.join('.github', 'workflows', 'scan-private-repo.yml') + '\n' +
  '    2. Configure required secrets in your GitHub repo settings:\n' +
  '         SONAR_TOKEN, SONAR_HOST_URL  (optional — enables SonarQube layer)\n' +
  '         JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY\n' +
  '                                      (optional — enables Jira ticket creation)\n' +
  '         OPENAI_API_KEY               (optional — enables Garak + STIG layers)\n' +
  '    3. Push to GitHub — scans will run automatically on push and pull requests.\n' +
  '\n  Full documentation: https://github.com/MetroStar/epyon\n'
);
