<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** midas_2026-04-30_18-59-57_trivy-filesystem-results  
**Generated:** Thu Apr 30 19:05:47 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019ddfc5-912d-7189-8683-8311a9ed162e",
  "CreatedAt": "2026-04-30T19:02:40.173102746Z",
  "ArtifactID": "sha256:371f312dfffacfdbed1f84326b814325a023182a433e9ece9f786db5e7daa4f6",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/midas",
    "Branch": "main",
    "Commit": "b2ce5cd47e9db4c7dfa43a728ec5fc7d7a9c5527",
    "CommitMsg": "MID-993: export ToolSpec from lib.tooling (#702)\n\n* MID-993: export ToolSpec from lib.tooling\n\nImport ToolSpec from core.facet in lib/tooling.py so consumers\ncan import it from a single module. No circular dependency exists\n(core.facet imports lib.clio and lib.prng, not lib.tooling).\n\nRemove outdated circular-dependency comment from mcp_to_oai_tools.\n\n* MID-1006: add client_options to persona config for SDK-level tuning\n\nSupports top-level defaults (max_retries, timeout) with per-provider\noverrides. Resolves the need for hardcoded retry values.\n\nclient_options:\n  max_retries: 5\n  timeout: 600\n  azure:\n    timeout: 300\n\n* MID-993: fix ruff and pyright errors across codebase",
    "Author": "Austin Herrling <adherrling@gmail.com>",
    "Committer": "GitHub <noreply@github.com>"
  }
}
```


---

> **INTERNAL USE ONLY**
