<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** iris_2026-04-28_15-34-25_trivy-filesystem-results  
**Generated:** Tue Apr 28 15:36:22 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dd4ba-aafe-7591-804d-1d480e18e68e",
  "CreatedAt": "2026-04-28T15:34:56.510367222Z",
  "ArtifactID": "sha256:24cc1793f64fd749b14e5720b39eeeb16622703f514e99a16fe05a15c93995a9",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/iris",
    "Commit": "9e4c10caca5d733389da79d79369865ac0529ce9",
    "CommitMsg": "Merge 7c2068ec0a30ff8eaa6e13fc7764f50c7d4a7e8c into 596c1c560670174e6174b9977d156362081c68e3",
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
