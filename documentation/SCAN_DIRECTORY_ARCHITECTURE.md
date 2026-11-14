# Scan Directory Architecture

Every scan writes all of its output into one self-contained directory. This guide describes the layout, how the directory is named, and which files other parts of Epyon (the web UI, the Score Card, the STIG engine) read from it.

## Naming

```
scans/{app}_{YYYY-MM-DD_HH-MM-SS}/          # CI and the web UI
scans/{app}_{user}_{YYYY-MM-DD_HH-MM-SS}/   # local ./epyon.sh run (run-target-security-scan.sh)
```

- The timestamp is generated **once** when the scan starts and shared with every tool through `SCAN_ID` and `SCAN_DIR`, so all outputs of a run have the same identity.
- Directory names sort chronologically per application. The web API and the Score Card treat everything before the last two `_` separated parts as the application name, and use name order to find "older" and "newer" scans of the same app.
- Each scan is self-contained: deleting the directory removes that scan completely.

## Environment contract

| Variable | Meaning |
|---|---|
| `SCAN_ID` | Name of the scan directory |
| `SCAN_DIR` | Absolute path of the scan directory |
| `TARGET_DIR` | Directory being scanned |

Scan scripts accept `--target`, `--scan-dir` and `--app-name`, and helper functions for output files live in `scripts/shell/scan-directory-template.sh` (`init_scan_environment`, `create_result_file`, `finalize_scan_results`, …).

## Layout

A typical scan directory (which tool directories appear depends on the scan mode, see [SCAN_MATRIX.md](SCAN_MATRIX.md)):

```
scans/myapp_2026-11-14_16-02-08/
├── sbom/                          # Syft SBOMs (CycloneDX + SPDX)
├── trufflehog/  grype/  trivy/    # one directory per tool, each with its raw results
├── pip-audit/  npm-audit/  semgrep/  checkov/  xeol/  clamav/  anchore/  sonar/  helm/ ...
├── picklescan/  model-provenance/  inference-security/  ml-runtime/   # ML/AI layers 14, 18, 19, 20
├── build/                         # container build evidence (when a build ran)
├── parallel-logs/                 # per-tool logs
├── consolidated-reports/          # dashboards and per-tool Markdown reports
├── scan-metadata.json             # scan type, timestamp, target
├── ci-metadata.json               # CI context (when run in CI)
├── layer-timing.json              # how long each layer took
├── ignore-rules.json              # snapshot of the .epyon-ignore.yml rules used (incl. include_tests)
├── security-findings-summary.json # every finding, deduplicated within the scan
├── security-findings-filtered.json# the same without suppressed findings (what the UI and gate use)
├── suppressed-findings.md         # what was suppressed, and why
├── stig-results-{slug}.json       # STIG state (STIG scans)
├── trl-assessment.json            # Score Card (calculated on demand)
├── trl-assessment.previous.json   # kept once when the scoring version changed
├── scan-manifest.json             # SHA-256 integrity manifest
├── ssp-ato-evidence-*.{md,json}   # SSP / ATO evidence
└── image.sig / provenance.jsonl   # signing and provenance records (when produced)
```

## Who reads what

| Consumer | Reads |
|---|---|
| Web UI scan pages | `security-findings-filtered.json`, per-tool directories via `web/api/parsers.py` |
| Severity gate | `security-findings-filtered.json` |
| Score Card | findings from the **latest** scan only, plus the newest copy of other artifacts across the application's history (see [SCORE_CARD_GUIDE.md](SCORE_CARD_GUIDE.md)) |
| STIG engine | the previous `stig-results-{slug}.json` for freeze logic (see [STIG_COMPLIANCE_GUIDE.md](STIG_COMPLIANCE_GUIDE.md)) |
| Integrity verification | `scan-manifest.json` (see [SCAN_MANIFEST_GUIDE.md](SCAN_MANIFEST_GUIDE.md)) |

## Retention

Scans are plain directories: remove old ones with `rm -r scans/<scan-id>`. The web UI lists scans from a rolling window and some features (such as calculating a Score Card) only look at recent scans, so very old scan directories are not offered there.
