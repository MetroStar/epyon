# Multi-Feed CVE Enrichment Guide

## Overview

Epyon now enriches CVE findings from **seven international vulnerability feeds**, providing comprehensive global coverage beyond the standard NVD database:

| Feed | Focus | API/Format | Coverage |
|------|-------|------------|----------|
| **NVD** (NIST) | Canonical CVE database with CVSS, CPEs | JSON API | ✅ Integrated |
| **CISA KEV** | Known Exploited Vulnerabilities | JSON/CSV | ✅ Integrated |
| **OSV.dev** | Open source package vulnerabilities | OSV API/JSON | ✅ Integrated |
| **GitHub Security Advisories (GHSA)** | OSS ecosystem advisories | GraphQL API | ✅ Integrated |
| **GitLab Advisory Database** | OSS package vulnerabilities | Git-backed | 🚧 Planned |
| **EUVD (ENISA)** | European Vulnerability Database | REST API | 🚧 Planned |
| **JVN** (Japan) | Japanese vulnerability database | RSS/API | ✅ Integrated |

## How It Works

1. **Standard Enrichment** (`enrich-findings.sh`):
   - Queries NVD for CVSS scores, CWE IDs, references
   - Queries CISA KEV for known exploited status
   - Rate-limited: 5 req/30s (unauthenticated) or 50 req/30s (with API key)

2. **Multi-Feed Enrichment** (`enrich-findings-multi-feed.sh`):
   - Queries additional international feeds for each CVE
   - Caches results locally for 24 hours
   - Adds `feed_sources` field to findings with aggregated data

## Configuration

### Environment Variables

```bash
# GitHub Security Advisories (GHSA) API access
export GITHUB_TOKEN="ghp_your_token_here"

# NVD API key (boosts rate limit)
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Multi-feed cache directory (default: /tmp/epyon_cve_feeds)
export MULTI_FEED_CACHE="/path/to/cache"

# Maximum CVEs to enrich (default: 50, 0 = all)
export MAX_FEED_CVES=100
```

### GitHub Token Setup

To enable GitHub Security Advisories enrichment:

1. Go to https://github.com/settings/tokens
2. Generate a new Personal Access Token (classic)
3. Grant the `public_repo` scope (for public advisories)
4. Set `GITHUB_TOKEN` environment variable or add to `.env.local`

Without a GitHub token, GHSA enrichment will be skipped.

## Usage

### Automatic (During Scans)

Multi-feed enrichment runs automatically after standard enrichment:

```bash
./epyon.sh --target /path/to/app --scan-type full
```

### Manual (Existing Scans)

Enrich an existing scan directory:

```bash
# Enrich with default settings (up to 50 CVEs)
./scripts/shell/enrich-findings-multi-feed.sh --scan-dir scans/myapp_2026-06-23_12-00-00

# Enrich all CVEs (no limit)
MAX_FEED_CVES=0 ./scripts/shell/enrich-findings-multi-feed.sh --scan-dir scans/myapp_2026-06-23_12-00-00

# Refresh cached data
./scripts/shell/enrich-findings-multi-feed.sh --scan-dir scans/myapp_2026-06-23_12-00-00 --refresh
```

### Test Single CVE

Fetch data for a specific CVE from all feeds:

```bash
./scripts/shell/fetch-cve-feeds.py --cve CVE-2024-1234

# With custom cache directory
./scripts/shell/fetch-cve-feeds.py --cve CVE-2024-1234 --cache-dir /tmp/my_cache

# Force refresh (bypass cache)
./scripts/shell/fetch-cve-feeds.py --cve CVE-2024-1234 --refresh
```

## Enriched Data Structure

After multi-feed enrichment, each CVE finding gains a `feed_sources` field:

```json
{
  "vulnerability_id": "CVE-2024-1234",
  "severity": "critical",
  "package": "openssl",
  "cvss_score": 9.8,
  "cisa_kev": true,
  "feed_sources": {
    "feeds": ["osv", "ghsa", "jvn"],
    "feeds_count": 3,
    "enriched_at": "2026-06-23T12:34:56"
  },
  "osv_summary": "Critical remote code execution vulnerability",
  "ghsa_count": 2,
  "ghsa_severity": "CRITICAL"
}
```

## Feed-Specific Details

### OSV.dev
- **API**: https://api.osv.dev/v1/vulns
- **Coverage**: npm, PyPI, Go, Maven, NuGet, RubyGems, crates.io, Packagist, Linux distros
- **Data**: Summary, details, affected packages, version ranges, references
- **Rate limit**: None (open API)

### GitHub Security Advisories (GHSA)
- **API**: https://api.github.com/graphql (GraphQL)
- **Coverage**: OSS packages across all ecosystems
- **Data**: GHSA ID, severity, CVSS scores, affected packages, patched versions
- **Rate limit**: 5,000 req/hour (authenticated)
- **Requirements**: GitHub Personal Access Token

### JVN (Japan Vulnerability Notes)
- **API**: https://jvndb.jvn.jp/myjvn (MyJVN API)
- **Coverage**: Vulnerabilities affecting Japan, international CVEs
- **Data**: Japanese vulnerability descriptions, references
- **Rate limit**: None (open API)

### EUVD (ENISA) — Planned
- **API**: TBD (requires registration)
- **Coverage**: European infrastructure vulnerabilities
- **Status**: Integration planned for future release

### GitLab Advisory Database — Planned
- **Source**: https://gitlab.com/gitlab-org/advisories-community
- **Coverage**: OSS package vulnerabilities (Git-backed YAML files)
- **Status**: Integration planned for future release

## Performance Considerations

- **Cache Duration**: 24 hours (configurable via `--cache-ttl`)
- **Default Limit**: 50 CVEs per scan (prevents excessive API calls)
- **Timeout**: 30 seconds per CVE (prevents hanging on slow feeds)
- **Fallback**: Graceful degradation when feeds are unavailable

## Caching

Feed data is cached locally to minimize API calls:

- **Cache Location**: `/tmp/epyon_cve_feeds/` (configurable)
- **Cache Format**: `{feed}_{CVE-ID}.json`
- **Cache TTL**: 24 hours (default)
- **Cache Refresh**: `--refresh` flag forces re-fetch

Example cache structure:
```
/tmp/epyon_cve_feeds/
├── osv_CVE-2024-1234.json
├── ghsa_CVE-2024-1234.json
├── jvn_CVE-2024-1234.json
└── ...
```

## Troubleshooting

### GHSA Returns No Data
**Problem**: GitHub Security Advisories queries return empty results  
**Solution**: Set `GITHUB_TOKEN` environment variable with a valid Personal Access Token

### Slow Enrichment
**Problem**: Multi-feed enrichment takes too long  
**Solution**: Reduce `MAX_FEED_CVES` or increase cache TTL:
```bash
export MAX_FEED_CVES=25  # Enrich only top 25 CVEs
```

### Cache Issues
**Problem**: Stale or corrupt cache data  
**Solution**: Clear cache directory:
```bash
rm -rf /tmp/epyon_cve_feeds
```

### Feed Timeouts
**Problem**: Specific feed consistently times out  
**Solution**: Edit `fetch-cve-feeds.py` and increase timeout (line ~42):
```python
def fetch_json(self, url: str, headers: Optional[Dict] = None, timeout: int = 60):
```

## Adding New Feeds

To add a new vulnerability feed:

1. Edit `scripts/shell/fetch-cve-feeds.py`
2. Add a new `fetch_{feedname}()` method to `CVEFeedAggregator` class
3. Add the feed to `aggregate_feeds()` method
4. Update documentation

Example template:

```python
def fetch_newfeed(self, cve_id: str) -> Optional[Dict]:
    """Fetch from NewFeed API."""
    cached = self.load_cache("newfeed", cve_id)
    if cached is not None:
        return cached

    url = f"https://api.newfeed.com/cves/{cve_id}"
    result = self.fetch_json(url, timeout=15)
    
    if result:
        enriched = {
            "source": "NewFeed",
            "data": result,
        }
        self.save_cache("newfeed", cve_id, enriched)
        return enriched
    
    return None
```

## Security Considerations

- **API Keys**: Store in environment variables, never commit to Git
- **Rate Limits**: Respect API provider rate limits
- **Caching**: Prevents excessive API calls, reduces exposure
- **Timeouts**: Prevent hanging on unresponsive feeds
- **Fallback**: Scan continues even if feeds fail

## Future Enhancements

- [ ] EUVD (ENISA) integration
- [ ] GitLab Advisory Database parsing
- [ ] Exploit-DB cross-reference
- [ ] VulnDB commercial feed support
- [ ] Feed priority ranking
- [ ] Parallel feed queries
- [ ] Feed health monitoring dashboard
