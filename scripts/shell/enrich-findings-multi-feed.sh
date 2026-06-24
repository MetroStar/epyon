#!/usr/bin/env bash
# enrich-findings-multi-feed.sh
# Extended enrichment with multiple international CVE feeds
#
# This script supplements enrich-findings.sh by adding data from:
#   - OSV.dev
#   - GitHub Security Advisories (GHSA)
#   - GitLab Advisory Database
#   - EUVD (ENISA)
#   - JVN (Japan)
#
# It enriches security-findings-summary.json with additional feed data
# under a "feed_sources" field for each CVE finding.
#
# Usage:
#   enrich-findings-multi-feed.sh [--scan-dir <path>] [--quiet] [--max-cves N]
#
# Environment variables:
#   SCAN_DIR          – path to scan directory
#   GITHUB_TOKEN      – GitHub Personal Access Token for GHSA API access
#   MULTI_FEED_CACHE  – cache directory for feed data (default: /tmp/epyon_cve_feeds)
#   MAX_FEED_CVES     – maximum number of CVEs to enrich (default: 50, 0 = all)

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_DIR_ARG=""
QUIET="${QUIET:-false}"
MAX_CVES="${MAX_FEED_CVES:-50}"
FEED_CACHE="${MULTI_FEED_CACHE:-/tmp/epyon_cve_feeds}"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan-dir)   SCAN_DIR_ARG="$2"; shift 2 ;;
        --quiet|-q)   QUIET=true; shift ;;
        --max-cves)   MAX_CVES="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

log()  { [[ "$QUIET" == false ]] && echo -e "$*" >&2 || true; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}" >&2; }
info() { log "${CYAN}ℹ️  $*${NC}"; }
ok()   { log "${GREEN}✅ $*${NC}"; }

# ── Resolve scan directory ────────────────────────────────────────────────────
if [[ -n "$SCAN_DIR_ARG" ]]; then
    SCAN_DIR="$SCAN_DIR_ARG"
elif [[ -n "${SCAN_DIR:-}" ]]; then
    : # use env var
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    LATEST=$(ls -td "$REPO_ROOT"/scans/*/ 2>/dev/null | head -1 || true)
    if [[ -z "$LATEST" ]]; then
        warn "No scan directory found and SCAN_DIR not set — skipping multi-feed enrichment"
        exit 0
    fi
    SCAN_DIR="${LATEST%/}"
fi
SCAN_DIR=$(realpath "${SCAN_DIR}" 2>/dev/null) || { echo "ERROR: Scan directory invalid: ${SCAN_DIR}" >&2; exit 1; }

FINDINGS_FILE="$SCAN_DIR/security-findings-summary.json"
if [[ ! -f "$FINDINGS_FILE" ]]; then
    warn "security-findings-summary.json not found — skipping multi-feed enrichment"
    exit 0
fi

# ── Tool checks ───────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    warn "python3 not found — skipping multi-feed enrichment"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED_SCRIPT="$SCRIPT_DIR/fetch-cve-feeds.py"

if [[ ! -f "$FEED_SCRIPT" ]]; then
    warn "fetch-cve-feeds.py not found — skipping multi-feed enrichment"
    exit 0
fi

log ""
log "${CYAN}═══════════════════════════════════════════════${NC}"
log "${CYAN}   🌐 Multi-Feed CVE Enrichment               ${NC}"
log "${CYAN}═══════════════════════════════════════════════${NC}"
log "${CYAN}Scan dir: $SCAN_DIR${NC}"

# ── Run Python enrichment script ─────────────────────────────────────────────
python3 - "$FINDINGS_FILE" "$FEED_SCRIPT" "$FEED_CACHE" "$MAX_CVES" <<'PYEOF'
import json
import sys
import subprocess
from pathlib import Path

findings_file = sys.argv[1]
feed_script   = sys.argv[2]
cache_dir     = sys.argv[3]
max_cves      = int(sys.argv[4])

# Load findings
with open(findings_file) as f:
    data = json.load(f)

# Collect unique CVE IDs
import re
CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)

severity_keys = ["critical_findings", "high_findings", "medium_findings", "low_findings"]
cve_findings = []  # List of (severity, index, cve_id)

for sk in severity_keys:
    for idx, finding in enumerate(data.get(sk, [])):
        vid = finding.get("vulnerability_id") or finding.get("id") or ""
        if CVE_RE.match(vid):
            cve_findings.append((sk, idx, vid.upper()))

print(f"  Found {len(cve_findings)} CVE findings to enrich", file=sys.stderr)

if max_cves > 0 and len(cve_findings) > max_cves:
    print(f"  Limiting to {max_cves} CVEs (set MAX_FEED_CVES=0 for all)", file=sys.stderr)
    cve_findings = cve_findings[:max_cves]

# Enrich each CVE with multi-feed data
enriched_count = 0
for severity_key, idx, cve_id in cve_findings:
    try:
        result = subprocess.run(
            [sys.executable, feed_script, "--cve", cve_id, "--cache-dir", cache_dir],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout:
            feed_data = json.loads(result.stdout)
            feeds = feed_data.get("feeds", {})
            
            if feeds:
                # Add feed sources to the finding
                finding = data[severity_key][idx]
                finding["feed_sources"] = {
                    "feeds": list(feeds.keys()),
                    "feeds_count": len(feeds),
                    "enriched_at": feed_data["timestamp"],
                }
                
                # Add summary data from each feed
                if "osv" in feeds:
                    finding["osv_summary"] = feeds["osv"].get("summary")
                if "ghsa" in feeds:
                    ghsa_advisories = feeds["ghsa"].get("advisories", [])
                    if ghsa_advisories:
                        finding["ghsa_count"] = len(ghsa_advisories)
                        finding["ghsa_severity"] = ghsa_advisories[0].get("severity")
                
                enriched_count += 1
                print(f"  ✅ Enriched {cve_id} ({len(feeds)} feeds)", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  Timeout fetching {cve_id}", file=sys.stderr)
    except Exception as e:
        print(f"  ⚠️  Error enriching {cve_id}: {e}", file=sys.stderr)

# Save enriched findings
with open(findings_file, "w") as f:
    json.dump(data, f, indent=2)

print(f"\n  Enriched {enriched_count}/{len(cve_findings)} CVE findings with multi-feed data", file=sys.stderr)
PYEOF

if [[ $? -eq 0 ]]; then
    ok "Multi-feed enrichment completed"
else
    warn "Multi-feed enrichment encountered errors"
fi
