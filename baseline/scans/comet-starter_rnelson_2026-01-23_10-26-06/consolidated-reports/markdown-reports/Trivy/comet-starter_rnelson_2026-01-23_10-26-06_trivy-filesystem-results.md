# Trivy Security Report

**Scan Type:** comet-starter_rnelson_2026-01-23_10-26-06_trivy-filesystem-results  
**Generated:** Fri Jan 23 10:29:14 CST 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-01-23T16:27:50.16306142Z",
  "ArtifactName": "/workspace",
  "ArtifactType": "filesystem",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/comet-starter.git",
    "Branch": "main",
    "Commit": "a46f32b3ca1419781d12b9d02f8fe290b04452c4",
    "CommitMsg": "Merge pull request #502 from MetroStar/dependabot/npm_and_yarn/lodash-4.17.23\n\nBump lodash from 4.17.21 to 4.17.23",
    "Author": "Johnny Bouder <61591423+jbouder@users.noreply.github.com>",
    "Committer": "GitHub <noreply@github.com>"
  },
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Packages": [
        {
          "ID": "@metrostar/comet-data-viz@1.2.2",
          "Name": "@metrostar/comet-data-viz",
          "Identifier": {
            "PURL": "pkg:npm/%40metrostar/comet-data-viz@1.2.2",
            "UID": "38fbdc7ba2db1375"
          },
          "Version": "1.2.2",
          "Relationship": "direct",
          "DependsOn": [
            "react-dom@19.2.1",
            "react@19.2.1",
            "victory@37.3.6"
          ],
          "Locations": [
            {
              "StartLine": 1711,
              "EndLine": 1726
            }
          ]
        },
        {
          "ID": "@metrostar/comet-extras@1.8.1",
          "Name": "@metrostar/comet-extras",
          "Identifier": {
            "PURL": "pkg:npm/%40metrostar/comet-extras@1.8.1",
            "UID": "b2936aedf432b279"
          },
          "Version": "1.8.1",
          "Relationship": "direct",
          "DependsOn": [
            "@tanstack/react-table@8.21.3",
            "react-dom@19.2.1",
            "react@19.2.1"
          ],
          "Locations": [
            {
              "StartLine": 1727,
              "EndLine": 1743
            }
          ]
        },
        {
          "ID": "@metrostar/comet-uswds@3.8.0",
          "Name": "@metrostar/comet-uswds",
          "Identifier": {
            
```
