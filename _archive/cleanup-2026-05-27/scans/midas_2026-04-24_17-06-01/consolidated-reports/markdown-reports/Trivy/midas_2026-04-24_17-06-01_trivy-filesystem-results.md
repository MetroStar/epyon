<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** midas_2026-04-24_17-06-01_trivy-filesystem-results  
**Generated:** Fri Apr 24 17:10:52 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dc076-3c37-73a2-967c-22d9caa5ab9d",
  "CreatedAt": "2026-04-24T17:07:47.383240139Z",
  "ArtifactID": "sha256:1319eb8884c71b9ceb284810ab8d16259e227d3eb3760aa29ee1aa49fed83010",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/midas",
    "Branch": "main",
    "Commit": "803b2b76216b0863ae68dcdd7592238d1e29d144",
    "CommitMsg": "Feature/mid 967 remove future annotations (#690)\n\n* Initial Removal\n\n* test fixes step 1\n\n* MID-967: Fix forward references and update baselines\n\n- Quote self-referencing class annotations (56 forward refs across 23 files)\n- Quote TYPE_CHECKING import annotations (30 refs across 11 files)\n- Quote cross-class forward references (4 refs across 3 files)\n- Quote non-subscriptable generic annotations (nx.DiGraph[str])\n- Quote Transducer generic return types in lib/functional.py\n- Quote ConverterRegistry forward ref in ConversionConfig\n- Update ruff_check, sbom_snapshot, and prop_manage_git_auth baselines\n\n* minor revert\n\n* Update core/facet.py\n\nCo-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>\n\n* fix: remove unnecessary annotated local variable in Facet.kb_spec, update ruff baseline\n\nAgent-Logs-Url: https://github.com/MetroStar/midas/sessions/88baac01-b0d2-4f7e-9c18-057b1a342ddf\n\nCo-authored-by: ndoll-metrostar <201170907+ndoll-metrostar@users.noreply.github.com>\n\n* switch to typing self\n\n* corrections\n\n* MID-967: replace quoted self-returns with typing.Self, unquote unnecessary types, bump pyright to py313\n\n- Convert 33 quoted self-referential return annotations to typing.Self\n  (classmethods returning own type, builder-pattern methods, etc.)\n- Skip Self for @staticmethod (invalid per PEP 673), Enum classmethods\n  (pyright rejects Self for literal members), and Span methods that\n  construct instances directly (pyright strict rejects
```


---

> **INTERNAL USE ONLY**
