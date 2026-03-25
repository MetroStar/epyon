#!/usr/bin/env bash
# enrich-findings.sh
# Enriches security-findings-summary.json with data from:
#   - CISA Known Exploited Vulnerabilities (KEV) catalog
#   - NIST NVD 2.0 API (CVSS v3 scores, CWE IDs, references, published date)
#
# Usage:
#   enrich-findings.sh [--scan-dir <path>] [--nvd-api-key <key>] [--quiet] [--dry-run]
#
# Environment variables:
#   SCAN_DIR        – path to scan directory (overridden by --scan-dir)
#   NVD_API_KEY     – optional NVD API key (boosts rate limit to 50 req/30s)
#   QUIET           – suppress non-error output when set to "true"
#
# Exit codes:
#   0 – enrichment completed (or skipped gracefully due to network/missing files)
#   1 – bad arguments or missing required tools

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_DIR_ARG=""
NVD_API_KEY="${NVD_API_KEY:-}"
QUIET="${QUIET:-false}"
DRY_RUN=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan-dir)     SCAN_DIR_ARG="$2"; shift 2 ;;
        --nvd-api-key)  NVD_API_KEY="$2"; shift 2 ;;
        --quiet|-q)     QUIET=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --help|-h)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
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
    # Auto-detect latest scan under ./scans/
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    LATEST=$(ls -td "$REPO_ROOT"/scans/*/ 2>/dev/null | head -1 || true)
    if [[ -z "$LATEST" ]]; then
        warn "No scan directory found and SCAN_DIR not set — skipping enrichment"
        exit 0
    fi
    SCAN_DIR="${LATEST%/}"
fi

FINDINGS_FILE="$SCAN_DIR/security-findings-summary.json"
if [[ ! -f "$FINDINGS_FILE" ]]; then
    warn "security-findings-summary.json not found at $FINDINGS_FILE — skipping enrichment"
    exit 0
fi

# ── Tool checks ───────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    warn "python3 not found — skipping enrichment"
    exit 0
fi
if ! command -v curl &>/dev/null; then
    warn "curl not found — skipping enrichment"
    exit 0
fi

log ""
log "${CYAN}═══════════════════════════════════════════════${NC}"
log "${CYAN}   🔍 Enriching Findings with NVD + CISA KEV   ${NC}"
log "${CYAN}═══════════════════════════════════════════════${NC}"
log "${CYAN}Scan dir: $SCAN_DIR${NC}"

# ── Download CISA KEV catalog ─────────────────────────────────────────────────
KEV_CACHE="/tmp/epyon_cisa_kev_$$.json"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
info "Downloading CISA KEV catalog..."
if curl -sf --max-time 30 -o "$KEV_CACHE" "$KEV_URL" 2>/dev/null; then
    kev_count=$(python3 -c "import json,sys; d=json.load(open('$KEV_CACHE')); print(len(d.get('vulnerabilities',[])))" 2>/dev/null || echo "?")
    ok "CISA KEV catalog downloaded ($kev_count entries)"
else
    warn "Could not download CISA KEV catalog — KEV enrichment will be skipped"
    echo "[]" > "$KEV_CACHE"
    # Make it a valid format so the Python script handles gracefully
    echo '{"vulnerabilities":[]}' > "$KEV_CACHE"
fi

# ── Run Python enrichment script ─────────────────────────────────────────────
# All NVD API calls are in Python to handle rate-limiting, retries, and JSON
# merging in a single pass.

if [[ "$DRY_RUN" == true ]]; then
    log "${YELLOW}[dry-run] Would enrich $FINDINGS_FILE — skipping actual writes${NC}"
    rm -f "$KEV_CACHE"
    exit 0
fi

python3 - "$FINDINGS_FILE" "$KEV_CACHE" "${NVD_API_KEY}" <<'PYEOF'
import json
import sys
import os
import time
import urllib.request
import urllib.parse
import urllib.error
import re

findings_file = sys.argv[1]
kev_cache     = sys.argv[2]
nvd_api_key   = sys.argv[3] if len(sys.argv) > 3 else ""

# ── Load KEV catalog ──────────────────────────────────────────────────────────
try:
    with open(kev_cache) as f:
        kev_raw = json.load(f)
    kev_by_cve = {v["cveID"]: v for v in kev_raw.get("vulnerabilities", [])}
except Exception as e:
    print(f"⚠️  Failed to parse KEV catalog: {e}", file=sys.stderr)
    kev_by_cve = {}

print(f"  KEV entries loaded: {len(kev_by_cve)}", file=sys.stderr)

# ── Load findings ─────────────────────────────────────────────────────────────
with open(findings_file) as f:
    data = json.load(f)

severity_keys = ["critical_findings", "high_findings", "medium_findings", "low_findings"]

# Collect unique CVE IDs (skip non-CVE identifiers like GHSA, CKV_*, detector names)
CVE_RE = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)

cve_set = set()
for sk in severity_keys:
    for finding in data.get(sk, []):
        vid = finding.get("vulnerability_id") or finding.get("id") or ""
        if CVE_RE.match(vid):
            cve_set.add(vid.upper())

print(f"  Unique CVEs to enrich: {len(cve_set)}", file=sys.stderr)

# ── NVD 2.0 API helpers ───────────────────────────────────────────────────────
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Unauthenticated: 5 requests / 30 s  → sleep 6 s between calls
# Authenticated:  50 requests / 30 s  → sleep 0.7 s between calls
SLEEP_INTERVAL = 0.7 if nvd_api_key else 6.0

nvd_cache: dict = {}

def fetch_nvd(cve_id: str) -> dict | None:
    """Return the NVD CVE item dict or None on failure."""
    params = {"cveId": cve_id}
    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "epyon-security-scanner/1.0"}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.load(resp)
        vulns = body.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # CVE not in NVD
        print(f"  NVD HTTP {e.code} for {cve_id}", file=sys.stderr)
    except Exception as e:
        print(f"  NVD error for {cve_id}: {e}", file=sys.stderr)
    return None

def nvd_enrich(cve_id: str) -> dict:
    """Fetch NVD data for a CVE and return an enrichment dict."""
    if cve_id in nvd_cache:
        return nvd_cache[cve_id]

    cve_data = fetch_nvd(cve_id)
    time.sleep(SLEEP_INTERVAL)

    if not cve_data:
        result = {"nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
        nvd_cache[cve_id] = result
        return result

    # CVSS v3 — prefer CVSSv31 over CVSSv30
    metrics = cve_data.get("metrics", {})
    cvss3_score = None
    cvss3_severity = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            cvss_data = primary.get("cvssData", {})
            cvss3_score    = cvss_data.get("baseScore")
            cvss3_severity = cvss_data.get("baseSeverity")
            break

    # References — first 5 URLs
    references = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")][:5]

    # CWE IDs
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    cwe_ids = list(dict.fromkeys(cwe_ids))[:5]  # deduplicate, limit 5

    # Published date (YYYY-MM-DD)
    published = (cve_data.get("published") or "")[:10]

    result = {
        "nvd_url":            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "nvd_published":      published,
        "nvd_cvss_v3_score":  cvss3_score,
        "nvd_cvss_v3_severity": cvss3_severity,
        "nvd_references":     references,
        "nvd_cwe_ids":        cwe_ids,
    }
    nvd_cache[cve_id] = result
    return result

# ── Enrich each CVE ───────────────────────────────────────────────────────────
kev_enriched = 0
nvd_enriched = 0

# Pre-fetch NVD for all unique CVEs
print(f"  Fetching NVD data (sleep {SLEEP_INTERVAL}s between calls)...", file=sys.stderr)
for i, cve_id in enumerate(sorted(cve_set), 1):
    print(f"  [{i}/{len(cve_set)}] NVD: {cve_id}", file=sys.stderr)
    nvd_enrich(cve_id)

# Apply enrichment to all findings
def enrich_finding(finding: dict) -> dict:
    global kev_enriched, nvd_enriched
    vid = (finding.get("vulnerability_id") or finding.get("id") or "").upper()
    if not CVE_RE.match(vid):
        return finding

    # CISA KEV
    kev_entry = kev_by_cve.get(vid)
    if kev_entry:
        finding["cisa_kev"]              = True
        finding["cisa_kev_date_added"]   = kev_entry.get("dateAdded", "")
        finding["cisa_known_ransomware"] = kev_entry.get("knownRansomwareCampaignUse", "Unknown").lower() == "known"
        finding["cisa_required_action"]  = kev_entry.get("requiredAction", "")
        finding["cisa_due_date"]         = kev_entry.get("dueDate", "")
        kev_enriched += 1
    else:
        finding["cisa_kev"] = False

    # NVD
    nvd = nvd_cache.get(vid, {})
    if nvd:
        finding.update(nvd)
        if nvd.get("nvd_cvss_v3_score") is not None:
            nvd_enriched += 1

    return finding

for sk in severity_keys:
    data[sk] = [enrich_finding(f) for f in data.get(sk, [])]

# Update summary metadata
data.setdefault("enrichment", {})
data["enrichment"]["enriched_at"]   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
data["enrichment"]["cisa_kev_total"] = kev_enriched
data["enrichment"]["nvd_total"]      = nvd_enriched
data["enrichment"]["kev_catalog_url"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# ── Write back atomically ─────────────────────────────────────────────────────
tmp = findings_file + ".enrich_tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.replace(tmp, findings_file)

print(f"  ✅ NVD: enriched {nvd_enriched} CVEs", file=sys.stderr)
print(f"  🔥 CISA KEV: {kev_enriched} findings flagged as actively exploited", file=sys.stderr)
PYEOF

EXIT=$?
rm -f "$KEV_CACHE"

if [[ $EXIT -ne 0 ]]; then
    warn "Enrichment Python script exited with code $EXIT — findings JSON left unchanged"
    exit 0  # best-effort; don't fail the pipeline
fi

ok "Findings enriched: $FINDINGS_FILE"
log ""
