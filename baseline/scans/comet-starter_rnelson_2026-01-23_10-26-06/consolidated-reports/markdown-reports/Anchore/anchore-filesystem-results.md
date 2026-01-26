# Anchore Security Report

**Scan Type:** anchore-filesystem-results  
**Generated:** Fri Jan 23 10:29:14 CST 2026  

## Summary

**Total Items:** 1

```json
{
  "matches": [],
  "source": {
    "type": "directory",
    "target": "/scan"
  },
  "distro": {
    "name": "",
    "version": "",
    "idLike": null
  },
  "descriptor": {
    "name": "grype",
    "version": "0.103.0",
    "configuration": {
      "output": [
        "json"
      ],
      "file": "/output/anchore-filesystem-results.json",
      "pretty": false,
      "distro": "",
      "add-cpes-if-none": false,
      "output-template-file": "",
      "check-for-app-update": true,
      "only-fixed": false,
      "only-notfixed": false,
      "ignore-wontfix": "",
      "platform": "",
      "search": {
        "scope": "squashed",
        "unindexed-archives": false,
        "indexed-archives": true
      },
      "ignore": [
        {
          "vulnerability": "",
          "include-aliases": false,
          "reason": "",
          "namespace": "",
          "fix-state": "",
          "package": {
            "name": "kernel-headers",
            "version": "",
            "language": "",
            "type": "rpm",
            "location": "",
            "upstream-name": "kernel"
          },
          "vex-status": "",
          "vex-justification": "",
          "match-type": "exact-indirect-match"
        },
        {
          "vulnerability": "",
          "include-aliases": false,
          "reason": "",
          "namespace": "",
          "fix-state": "",
          "package": {
            "name": "linux(-.*)?-headers-.*",
            "version": "",
            "language": "",
            "type": "deb",
            "location": "",
            "upstream-name": "linux.*"
          },
          "vex-status": "",
          "vex-justification": "",
          "match-type": "exact-indirect-match"
        },
        {
          "vulnerability": "",
          "include-aliases": false,
          "reason": "",
          "namespace": "",
          "fix-state": "",
          "package": {
            "name": "linux-libc-dev",
            "version": "",
          
```
