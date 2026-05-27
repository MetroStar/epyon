<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** midas_2026-04-25_01-13-50_trivy-filesystem-results  
**Generated:** Sat Apr 25 01:18:32 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dc234-c8a2-72b5-90ae-8d39aae0b8b3",
  "CreatedAt": "2026-04-25T01:15:32.386179717Z",
  "ArtifactID": "sha256:2494616998b1a32307d45a0ce2103b8d7f916be94434d68a22c1f1c42f555a10",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/midas",
    "Branch": "main",
    "Commit": "ef9b5d89a612aa39bf385db19e967f4e714eaa1c",
    "CommitMsg": "MID-772: add tool invocation audit events to Hermes dispatch (#694)\n\n* MID-772: add tool invocation audit events to Hermes dispatch\n\n* MID-772: address review feedback from PR #694\n\n- Add error_message to both tool_error audit paths (exception + isError)\n- Extract error text from CallToolResult.content via TextContent\n- Remove redundant has_duration_ms / has_ts boolean prints\n- Print duration_ms type and ts length for transparency\n- Add token-leak checks (bearer/token not in audit JSON)\n- Rename tool_audit_basic -> tool_audit per naming convention\n\n* MID-772: update sbom baseline after main merge (92 components)",
    "Author": "Austin Herrling <adherrling@gmail.com>",
    "Committer": "GitHub <noreply@github.com>"
  }
}
```


---

> **INTERNAL USE ONLY**
