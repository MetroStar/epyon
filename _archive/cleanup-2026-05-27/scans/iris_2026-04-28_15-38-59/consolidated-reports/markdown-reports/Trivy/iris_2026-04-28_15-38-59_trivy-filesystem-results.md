<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** iris_2026-04-28_15-38-59_trivy-filesystem-results  
**Generated:** Tue Apr 28 15:40:45 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dd4be-cb10-703b-9b36-bf5385d0377b",
  "CreatedAt": "2026-04-28T15:39:26.86401637Z",
  "ArtifactID": "sha256:ff63d3d3689e660db726a80187745d70f6ccbf6f9c2427f13663b2e128bb70b3",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/iris",
    "Commit": "9e430cd6758eb44acc92da56e2a1733c6c2c9763",
    "CommitMsg": "Merge 895a58ed7934e6c49d4d606b6af94329332bd12f into 596c1c560670174e6174b9977d156362081c68e3",
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
