<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Anchore Security Report

**Scan Type:** anchore-sbom-results  
**Generated:** Mon Apr 27 17:08:51 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-qx2v-qp2m-jg93",
        "dataSource": "https://github.com/advisories/GHSA-qx2v-qp2m-jg93",
        "namespace": "github:language:javascript",
        "severity": "Medium",
        "urls": [
          "https://github.com/postcss/postcss/security/advisories/GHSA-qx2v-qp2m-jg93",
          "https://nvd.nist.gov/vuln/detail/CVE-2026-41305",
          "https://github.com/postcss/postcss/releases/tag/8.5.10"
        ],
        "description": "PostCSS has XSS via Unescaped </style> in its CSS Stringify Output",
        "cvss": [
          {
            "type": "Secondary",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "metrics": {
              "baseScore": 6.1,
              "exploitabilityScore": 2.9,
              "impactScore": 2.8
            },
            "vendorMetadata": {}
          }
        ],
        "epss": [
          {
            "cve": "CVE-2026-41305",
            "epss": 0.00029,
            "percentile": 0.08242,
            "date": "2026-04-26"
          }
        ],
        "cwes": [
          {
            "cve": "CVE-2026-41305",
            "cwe": "CWE-79",
            "source": "security-advisories@github.com",
            "type": "Secondary"
          }
        ],
        "fix": {
          "versions": [
            "8.5.10"
          ],
          "state": "fixed",
          "available": [
            {
              "version": "8.5.10",
              "date": "2026-04-24",
              "kind": "first-observed"
            }
          ]
        },
        "advisories": [],
        "risk": 0.016094999999999998
      },
      "relatedVulnerabilities": [
        {
          "id": "CVE-2026-41305",
          "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2026-41305",
          "namespace": "nvd:cpe",
          "severity": "Medium",
          "urls": [
            "https://github.com/postcss/postcss/releases/tag/
```


---

> **INTERNAL USE ONLY**
