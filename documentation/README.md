# Epyon Documentation

Index of the guides in this directory. Start with the architecture and scan matrix, then jump to the area you need.

## Start here

| Document | Purpose |
|---|---|
| [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) | Components, scan layers and data flow |
| [SCAN_MATRIX.md](SCAN_MATRIX.md) | Which layers run in quick / nightly / full / stig modes and how to skip them |
| [MASTER_EPYON_MATRIX.md](MASTER_EPYON_MATRIX.md) | Landing page for scan modes, release evidence and platform capabilities |
| [SCAN_DIRECTORY_ARCHITECTURE.md](SCAN_DIRECTORY_ARCHITECTURE.md) | Scan output layout, naming and who reads what |

## Scoring and compliance

| Document | Purpose |
|---|---|
| [SCORE_CARD_GUIDE.md](SCORE_CARD_GUIDE.md) | How the Score Card is calculated, where its numbers come from, and how to verify them |
| [STIG_COMPLIANCE_GUIDE.md](STIG_COMPLIANCE_GUIDE.md) | STIG assessment workflow, statuses and freeze logic |
| [STIG_SCANNING_TECHNICAL_REFERENCE.md](STIG_SCANNING_TECHNICAL_REFERENCE.md) | STIG engine internals |
| [MANUAL_STIG_DOCUMENTATION_GUIDE.md](MANUAL_STIG_DOCUMENTATION_GUIDE.md) | Human-authored STIG documentation that takes priority over AI assessments |
| [IGNORE_RULES_GUIDE.md](IGNORE_RULES_GUIDE.md) | `.epyon-ignore.yml` suppression rules |

## Scanners and findings

| Document | Purpose |
|---|---|
| [ANCHORE_CONFIGURATION_GUIDE.md](ANCHORE_CONFIGURATION_GUIDE.md) | Anchore configuration and false-positive prevention |
| [GRYPE_SCAN_TROUBLESHOOTING.md](GRYPE_SCAN_TROUBLESHOOTING.md) | Grype troubleshooting |
| [MULTI_FEED_CVE_ENRICHMENT.md](MULTI_FEED_CVE_ENRICHMENT.md) | CVE enrichment feeds |
| [ML_SECURITY_GUIDE.md](ML_SECURITY_GUIDE.md) | ML/AI security layers (14, 18, 19, 20) |
| [CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md](CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md) | Container build and evidence-based scanning |
| [DEDUPLICATION_IMPLEMENTATION.md](DEDUPLICATION_IMPLEMENTATION.md) | Finding deduplication |
| [PARSER_FUNCTIONS_REFERENCE.md](PARSER_FUNCTIONS_REFERENCE.md) | Parser function reference (not exhaustive) |

## Integrity, integrations and releases

| Document | Purpose |
|---|---|
| [SCAN_MANIFEST_GUIDE.md](SCAN_MANIFEST_GUIDE.md) | Scan manifest and integrity verification |
| [WEBHOOK_INTEGRATION_GUIDE.md](WEBHOOK_INTEGRATION_GUIDE.md) | Real-time scan progress webhooks |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Tagging and publishing a release |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities in Epyon |
| [SECURITY_REVIEW_AND_TEST_COVERAGE.md](SECURITY_REVIEW_AND_TEST_COVERAGE.md) | Security review and test coverage snapshot |

## Plans and strategy (not implemented)

| Document | Purpose |
|---|---|
| [WEB_UI_POST_SCAN_PARITY.md](WEB_UI_POST_SCAN_PARITY.md) | Plan for web UI post-scan step parity |
| [AI Integration Strategy for Epyon.md](AI%20Integration%20Strategy%20for%20Epyon.md) | AI/ML integration roadmap (April 2026 memo) |

## Maintenance

- Update a guide in the same change that alters the behavior it describes.
- Remove one-off status reports instead of letting them go stale; the CHANGELOG is the history.
