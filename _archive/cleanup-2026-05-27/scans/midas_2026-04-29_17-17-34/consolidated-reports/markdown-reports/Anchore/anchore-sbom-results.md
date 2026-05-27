<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Anchore Security Report

**Scan Type:** anchore-sbom-results  
**Generated:** Wed Apr 29 17:22:35 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-mj87-hwqh-73pj",
        "dataSource": "https://github.com/advisories/GHSA-mj87-hwqh-73pj",
        "namespace": "github:language:python",
        "severity": "Medium",
        "urls": [
          "https://github.com/Kludex/python-multipart/security/advisories/GHSA-mj87-hwqh-73pj",
          "https://github.com/Kludex/python-multipart/releases/tag/0.0.26",
          "https://nvd.nist.gov/vuln/detail/CVE-2026-40347"
        ],
        "description": "python-multipart affected by Denial of Service via large multipart preamble or epilogue data",
        "cvss": [
          {
            "type": "Secondary",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "metrics": {
              "baseScore": 5.3,
              "exploitabilityScore": 3.9,
              "impactScore": 1.5
            },
            "vendorMetadata": {}
          }
        ],
        "epss": [
          {
            "cve": "CVE-2026-40347",
            "epss": 0.0002,
            "percentile": 0.05487,
            "date": "2026-04-28"
          }
        ],
        "cwes": [
          {
            "cve": "CVE-2026-40347",
            "cwe": "CWE-400",
            "source": "security-advisories@github.com",
            "type": "Primary"
          },
          {
            "cve": "CVE-2026-40347",
            "cwe": "CWE-834",
            "source": "security-advisories@github.com",
            "type": "Primary"
          }
        ],
        "fix": {
          "versions": [
            "0.0.26"
          ],
          "state": "fixed",
          "available": [
            {
              "version": "0.0.26",
              "date": "2026-04-16",
              "kind": "first-observed"
            }
          ]
        },
        "advisories": [],
        "risk": 0.0103
      },
      "relatedVulnerabilities": [
        {
          "id": "CVE-2026-40347",
          "dataSource"
```


---

> **INTERNAL USE ONLY**
