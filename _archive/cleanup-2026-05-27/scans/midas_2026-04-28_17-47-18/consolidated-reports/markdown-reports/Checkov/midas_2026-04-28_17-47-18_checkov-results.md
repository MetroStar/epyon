<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Checkov Security Report

**Scan Type:** midas_2026-04-28_17-47-18_checkov-results  
**Generated:** Tue Apr 28 17:51:59 UTC 2026  

## Summary

**Total Items:** 1

```json
[
  {
    "check_type": "github_actions",
    "results": {
      "passed_checks": [
        {
          "check_id": "CKV_GHA_5",
          "bc_check_id": null,
          "check_name": "Found artifact build without evidence of cosign sign execution in pipeline",
          "check_result": {
            "result": "PASSED",
            "results_configuration": {
              "release": {
                "runs-on": "self-hosted",
                "steps": [
                  {
                    "name": "Clean stale git config",
                    "run": "git config --global --list 2>/dev/null | grep -i '\\.insteadof=' | sed 's/\\.insteadof=.*//' | sort -u | while read -r key; do\n  git config --global --remove-section \"$key\" 2>/dev/null || true\ndone || true\ngit config --global --get-regexp 'http\\..*\\.extraheader' 2>/dev/null | awk '{print $1}' | sort -u | while read -r key; do\n  git config --global --unset-all \"$key\" 2>/dev/null || true\ndone || true\n",
                    "__startline__": 25,
                    "__endline__": 34
                  },
                  {
                    "name": "Checkout",
                    "uses": "actions/checkout@v6",
                    "with": {
                      "persist-credentials": false,
                      "fetch-depth": 0,
                      "__startline__": 37,
                      "__endline__": 40
                    },
                    "__startline__": 34,
                    "__endline__": 40
                  },
                  {
                    "name": "Setup Python",
                    "uses": "./.github/actions/setup-python",
                    "__startline__": 40,
                    "__endline__": 43
                  },
                  {
                    "name": "Build package",
                    "run": "python3 -m pip install build==1.2.2.post1\npython3 -m build\n",
                    "__startline__": 43,
                    "__endline__": 48
                  },
  
```


---

> **INTERNAL USE ONLY**
