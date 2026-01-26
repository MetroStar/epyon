# SBOM Security Report

**Scan Type:** filesystem  
**Generated:** Fri Jan 23 10:29:14 CST 2026  

## Summary

**Total Items:** 1

```json
{
  "artifacts": [
    {
      "id": "ca437a25a98f5579",
      "name": "@babel/code-frame",
      "version": "7.27.1",
      "type": "npm",
      "foundBy": "javascript-lock-cataloger",
      "locations": [
        {
          "path": "/package-lock.json",
          "accessPath": "/package-lock.json",
          "annotations": {
            "evidence": "primary"
          }
        }
      ],
      "licenses": [
        {
          "value": "MIT",
          "spdxExpression": "MIT",
          "type": "declared",
          "urls": [],
          "locations": [
            {
              "path": "/package-lock.json",
              "accessPath": "/package-lock.json",
              "annotations": {
                "evidence": "primary"
              }
            }
          ]
        }
      ],
      "language": "javascript",
      "cpes": [
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code-frame:\\@babel\\/code-frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        },
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code-frame:\\@babel\\/code_frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        },
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code_frame:\\@babel\\/code-frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        },
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code_frame:\\@babel\\/code_frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        },
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code:\\@babel\\/code-frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        },
        {
          "cpe": "cpe:2.3:a:\\@babel\\/code:\\@babel\\/code_frame:7.27.1:*:*:*:*:*:*:*",
          "source": "syft-generated"
        }
      ],
      "purl": "pkg:npm/%40babel/code-frame@7.27.1",
      "metadataType": "javascript-npm-package-lock-entry",
      "metadata": {
        "resolved": "https://registry.npmjs.org/@babel/code-frame/-/code-frame-7.27.1.tgz",
        "integ
```
