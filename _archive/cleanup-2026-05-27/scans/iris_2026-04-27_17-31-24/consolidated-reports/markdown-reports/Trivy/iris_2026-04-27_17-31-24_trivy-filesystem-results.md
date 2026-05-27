<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** iris_2026-04-27_17-31-24_trivy-filesystem-results  
**Generated:** Mon Apr 27 17:33:18 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dcfff-6649-768a-bc9b-44d5dd6f02f3",
  "CreatedAt": "2026-04-27T17:31:54.825429671Z",
  "ArtifactID": "sha256:3129685f7bc1fb790a41438470ae78d3daec154546bbc71708cde820dd15db4d",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/iris",
    "Commit": "2a7146ba72ce59d012d1a30b711b76a16a4feb7f",
    "CommitMsg": "Merge 1f496659ac340243f4ad782e5daf74d19d024e55 into 0d1c3c3124995406522e6b53066a7fb3c47534e6",
    "Author": "Pedram Adili <padili@metrostar.com>",
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
          "Locations": [
  
```


---

> **INTERNAL USE ONLY**
