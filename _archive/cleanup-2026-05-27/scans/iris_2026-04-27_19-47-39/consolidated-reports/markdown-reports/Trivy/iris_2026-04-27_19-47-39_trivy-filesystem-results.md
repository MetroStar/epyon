<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** iris_2026-04-27_19-47-39_trivy-filesystem-results  
**Generated:** Mon Apr 27 19:49:21 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dd07c-1119-7369-9299-3859034451a9",
  "CreatedAt": "2026-04-27T19:48:05.017224788Z",
  "ArtifactID": "sha256:e74e156b64263d510bb72e94d65aa4b98475abec7c7273958fa5470b4eda6266",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/iris",
    "Commit": "56188dd92404636749645813dd7866cea0f0ff93",
    "CommitMsg": "Merge 404d8b9b2eec7d0c85547202da6f9e6e5d3aa5c7 into 0d1c3c3124995406522e6b53066a7fb3c47534e6",
    "Author": "Ronnie Nelson <33059841+sketch0395@users.noreply.github.com>",
    "Committer": "GitHub <noreply@github.com>"
  },
  "Results": [
    {
      "Target": "api/environment.yaml",
      "Class": "lang-pkgs",
      "Type": "conda-environment",
      "Packages": [
        {
          "Name": "alembic",
          "Identifier": {
            "PURL": "pkg:conda/alembic",
            "UID": "bf3c0dfff4126403"
          },
          "Locations": [
            {
              "StartLine": 15,
              "EndLine": 15
            }
          ],
          "AnalyzedBy": "conda-environment"
        },
        {
          "Name": "boto3",
          "Identifier": {
            "PURL": "pkg:conda/boto3",
            "UID": "fde6869348753176"
          },
          "Locations": [
            {
              "StartLine": 26,
              "EndLine": 26
            }
          ],
          "AnalyzedBy": "conda-environment"
        },
        {
          "Name": "coverage",
          "Identifier": {
            "PURL": "pkg:conda/coverage",
            "UID": "c9dfb5c2f86ac36"
          },
          "Locations": [
            {
              "StartLine": 45,
              "EndLine": 45
            }
          ],
          "AnalyzedBy": "conda-environment"
        },
        {
          "Name": "cudnn",
          "Identifier": {
            "PURL": "pkg:conda/cudnn",
            "UID": "ebdecf5f33ebe1a3"
          },
  
```


---

> **INTERNAL USE ONLY**
