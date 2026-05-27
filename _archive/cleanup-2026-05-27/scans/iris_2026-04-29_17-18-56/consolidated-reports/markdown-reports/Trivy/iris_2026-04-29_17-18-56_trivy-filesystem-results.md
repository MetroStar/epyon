<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** iris_2026-04-29_17-18-56_trivy-filesystem-results  
**Generated:** Wed Apr 29 17:20:41 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dda40-acea-75af-8764-fd1927f1da7b",
  "CreatedAt": "2026-04-29T17:19:24.906373605Z",
  "ArtifactID": "sha256:150a9afa41e172caf06ee6107f8a90cd752b16f78f17c6adbe225f443b68e79a",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/iris",
    "Commit": "1b54ccd7c404a6b0e3da8b6358d1e2f281716ef3",
    "CommitMsg": "Merge 59f706df97de2743ec463b7d351cff9adb2a2c31 into 596c1c560670174e6174b9977d156362081c68e3",
    "Author": "jscearce3 <50394104+jscearce3@users.noreply.github.com>",
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
