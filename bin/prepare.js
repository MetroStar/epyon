#!/usr/bin/env node
/**
 * Epyon prepare script
 *
 * Keeps bin/templates/epyon-security-scan.yml in sync with the canonical
 * workflow at .github/workflows/scan-private-repo.yml.
 *
 * Runs automatically via the "prepare" npm lifecycle hook:
 *   - On `npm install github:MetroStar/epyon` (before the package is packed)
 *   - On `npm install` inside the epyon repo itself (local development)
 *   - On `npm publish` / `npm pack`
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const root   = path.resolve(__dirname, '..');
const source = path.join(root, '.github', 'workflows', 'scan-private-repo.yml');
const destDir = path.join(__dirname, 'templates');
const dest   = path.join(destDir, 'scan-private-repo.yml');

if (!fs.existsSync(source)) {
  // Not present in a registry-published pack — skip silently.
  process.exit(0);
}

fs.mkdirSync(destDir, { recursive: true });
fs.copyFileSync(source, dest);
