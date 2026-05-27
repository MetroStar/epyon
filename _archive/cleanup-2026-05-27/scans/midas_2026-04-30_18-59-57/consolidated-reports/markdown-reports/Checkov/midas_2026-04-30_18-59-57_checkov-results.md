<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Checkov Security Report

**Scan Type:** midas_2026-04-30_18-59-57_checkov-results  
**Generated:** Thu Apr 30 19:05:47 UTC 2026  

## Summary

**Total Items:** 1

```json
[
  {
    "check_type": "github_actions",
    "results": {
      "passed_checks": [
        {
          "check_id": "CKV_GHA_7",
          "bc_check_id": null,
          "check_name": "The build output cannot be affected by user parameters other than the build entry point and the top-level source location. GitHub Actions workflow_dispatch inputs MUST be empty. ",
          "check_result": {
            "result": "PASSED",
            "results_configuration": {
              "workflow_dispatch": null,
              "push": {
                "branches": [
                  "main"
                ],
                "__startline__": 6,
                "__endline__": 9
              },
              "__startline__": 4,
              "__endline__": 9
            }
          },
          "code_block": [
            [
              4,
              "  workflow_dispatch:\n"
            ],
            [
              5,
              "  push:\n"
            ],
            [
              6,
              "    branches:\n"
            ],
            [
              7,
              "      - main\n"
            ],
            [
              8,
              "\n"
            ],
            [
              9,
              "permissions:\n"
            ],
            [
              10,
              "  actions: write\n"
            ]
          ],
          "file_path": "/.github/workflows/rerun-ci-on-main-update.yml",
          "file_abs_path": "/workspace/.github/workflows/rerun-ci-on-main-update.yml",
          "repo_file_path": "/workspace/.github/workflows/rerun-ci-on-main-update.yml",
          "file_line_range": [
            4,
            10
          ],
          "resource": "on(Re-run CI on open PRs when main updates)",
          "evaluations": null,
          "check_class": "checkov.github_actions.checks.job.EmptyWorkflowDispatch",
          "fixed_definition": null,
          "entity_tags": null,
          "caller_file_path": null,
          "caller_file_line_range":
```


---

> **INTERNAL USE ONLY**
