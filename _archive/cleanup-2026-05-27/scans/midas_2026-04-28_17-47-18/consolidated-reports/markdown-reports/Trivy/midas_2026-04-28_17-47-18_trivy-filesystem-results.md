<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** midas_2026-04-28_17-47-18_trivy-filesystem-results  
**Generated:** Tue Apr 28 17:51:59 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dd535-70cc-7bc5-90fe-554cb4219cd0",
  "CreatedAt": "2026-04-28T17:49:02.540773528Z",
  "ArtifactID": "sha256:a545d1b064ac9ff69f27307dab1a7e5752a47e511ef4853a272a6ad1d117a156",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/midas",
    "Branch": "MID-993-export-toolspec-from-lib-tooling",
    "Commit": "28dbaad77143a1daa30b117a4896f37b5ca9aea9",
    "CommitMsg": "MID-993: export ToolSpec from lib.tooling\n\nImport ToolSpec from core.facet in lib/tooling.py so consumers\ncan import it from a single module. No circular dependency exists\n(core.facet imports lib.clio and lib.prng, not lib.tooling).\n\nRemove outdated circular-dependency comment from mcp_to_oai_tools.",
    "Author": "Austin Herrling <adherrling@gmail.com>",
    "Committer": "Austin Herrling <adherrling@gmail.com>"
  }
}
```


---

> **INTERNAL USE ONLY**
