# Epyon Scan Matrix

This table shows which layers run in each scan mode. Layers marked ✅ run by default; ⬜ means skipped; 🔧 means opt-in only (requires an explicit flag).

| # | Layer | Tool | `quick` | `nightly` | `full` | `stig` | Override Flag |
|---|-------|------|:-------:|:---------:|:------:|:------:|---------------|
| 1  | SBOM Generation        | Syft          | ✅ | ✅ | ✅ | ⬜ | `SKIP_SBOM=true` |
| 2  | Secret Detection       | TruffleHog    | ✅ | ✅ | ✅ | ⬜ | `SKIP_TRUFFLEHOG=true` |
| 3  | Code Quality           | SonarQube     | ⬜ | ✅ | ✅ | ⬜ | `SKIP_SONAR=true` / `RUN_SONAR_IN_QUICK=true` |
| 4  | Malware Detection      | ClamAV        | ⬜ | ✅ | ✅ | ⬜ | `SKIP_CLAMAV=true` |
| 5  | Helm Chart Build       | Helm          | ⬜ | ✅ | ✅ | ⬜ | `SKIP_HELM=true` |
| 6  | IaC Security           | Checkov       | ⬜ | ✅ | ✅ | ⬜ | `SKIP_CHECKOV=true` |
| 7  | Container Security     | Trivy         | ✅ | ✅ | ✅ | ⬜ | `SKIP_TRIVY=true` |
| 8  | Vulnerability Scanning | Grype         | ✅ | ✅ | ✅ | ⬜ | `SKIP_GRYPE=true` |
| 8.5| Direct Dependency Scan | pip-audit     | ✅ | ✅ | ✅ | ⬜ | `SKIP_PIP_AUDIT=true` |
| 9  | EOL Detection          | Xeol          | ⬜ | ✅ | ✅ | ⬜ | `SKIP_XEOL=true` |
| 10 | Container Analysis     | Anchore       | ⬜ | ✅ | ✅ | ⬜ | `SKIP_ANCHORE=true` |
| 11 | API Discovery          | Custom        | ⬜ | ✅ | ✅ | ⬜ | `SKIP_API_DISCOVERY=true` |
| 12 | LLM Security Probing   | Garak         | ⬜ | ⬜ | ⬜ | ⬜ | `RUN_GARAK=true` (always opt-in) |
| 13 | STIG Compliance        | AI Assessment | ⬜ | ⬜ | ✅ | ✅ | `SKIP_STIG=true` |
| 14 | Pickle Safety          | picklescan    | ⬜ | ✅ | ✅ | ⬜ | `RUN_PICKLESCAN=true/false` |
| 15 | Model Card Compliance  | Custom        | ⬜ | ✅ | ✅ | ⬜ | `RUN_MODELCARD=true/false` |
| 16 | Network Discovery      | nmap/static   | ⬜ | ✅ | ✅ | ⬜ | `SKIP_NETWORK_DISCOVERY=true` |

## Scheduled Scan Modes (scan-private-repo.yml)

| Schedule | Mode | STIG |
|----------|------|------|
| Mon–Sat 02:00 UTC | `nightly` | ⬜ Skipped |
| Sun 02:00 UTC | `full` | ✅ Runs |
| Manual dispatch | Selected mode | ✅ Only if `scan_mode=stig` |
| CI push to main | `full` | ⬜ Skipped (`skip_stig: true`) |
| CI pull request | `quick` | ⬜ Skipped |

## Notes

- **`quick`** — Fast feedback on PRs. Runs only the dependency and secrets layers (1, 2, 7, 8, 8.5). Completes in ~3–5 minutes.
- **`nightly`** — Full vulnerability coverage without the expensive AI-powered layers. Ideal for Mon–Sat automated runs.
- **`full`** — All layers including STIG. Used for the weekly Sunday scheduled scan and on-demand assessments.
- **`stig`** — STIG-only run. Skips layers 1–12 entirely and runs only the Layer 13 compliance assessment.
- **Layer 8.5 (pip-audit)** complements Layer 8 (Grype) by scanning Python dependency files directly. Catches CVEs that SBOM-based scanners (Syft/Grype) miss, especially recently published advisories. Requires `pip-audit` to be installed.
- **Layer 12 (Garak)** is always opt-in regardless of scan mode — requires `RUN_GARAK=true` and `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
- **Layer 13 (STIG)** requires `OPENAI_API_KEY`. Without it, all controls are marked `Not Reviewed`.
- **Layers 14–15** (Pickle, Model Card) auto-enable in `full`/`nightly` but are no-ops if no model weight files or README are found.
- **Layer 16 (Network Discovery)** runs static config analysis in all modes. Active nmap scanning requires `NMAP_TARGET=<host>`.
- All layers respect a per-tool `SKIP_<LAYER>=true` environment variable for manual opt-out in any mode.
