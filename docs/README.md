# Epyon Documentation

Guides grouped by topic. Start with `architecture/` and the scan matrix, then jump to the area you need.

## Layout

| Folder | What lives there |
|---|---|
| [`architecture/`](architecture/) | System and scan-directory design, parsers, deduplication, draw.io diagrams |
| [`scanning/`](scanning/) | Scan modes and layers, ignore rules, scanner configuration, CVE feeds, container evidence |
| [`compliance/`](compliance/) | STIG engine, manual STIG documentation, Score Card, security review |
| [`ml-security/`](ml-security/) | ML/AI security layers |
| [`integrations/`](integrations/) | Webhooks and the private-repo workflow template |
| [`releases/`](releases/) | Release process |
| [`plans/`](plans/) | Roadmap and plans that are not implemented |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability in Epyon (kept at the top level so GitHub finds it) |

## architecture/

| Document | Purpose |
|---|---|
| [SYSTEM_ARCHITECTURE.md](architecture/SYSTEM_ARCHITECTURE.md) | Components, scan layers and data flow |
| [SCAN_DIRECTORY_ARCHITECTURE.md](architecture/SCAN_DIRECTORY_ARCHITECTURE.md) | Scan output layout, naming and who reads what |
| [PARSER_FUNCTIONS_REFERENCE.md](architecture/PARSER_FUNCTIONS_REFERENCE.md) | Parser function reference (not exhaustive) |
| [DEDUPLICATION_IMPLEMENTATION.md](architecture/DEDUPLICATION_IMPLEMENTATION.md) | Finding deduplication |
| [diagrams/](architecture/diagrams/) | `system-architecture`, `epyon-full-workflow` and `stig-selection-workflow` draw.io files |

## scanning/

| Document | Purpose |
|---|---|
| [SCAN_MATRIX.md](scanning/SCAN_MATRIX.md) | Which layers run in quick / nightly / full / stig modes and how to skip them |
| [MASTER_EPYON_MATRIX.md](scanning/MASTER_EPYON_MATRIX.md) | Landing page for scan modes, release evidence and platform capabilities |
| [SCAN_MANIFEST_GUIDE.md](scanning/SCAN_MANIFEST_GUIDE.md) | Scan manifest and integrity verification |
| [IGNORE_RULES_GUIDE.md](scanning/IGNORE_RULES_GUIDE.md) | `.epyon-ignore.yml` suppression rules |
| [ANCHORE_CONFIGURATION_GUIDE.md](scanning/ANCHORE_CONFIGURATION_GUIDE.md) | Anchore configuration and false-positive prevention |
| [GRYPE_SCAN_TROUBLESHOOTING.md](scanning/GRYPE_SCAN_TROUBLESHOOTING.md) | Grype troubleshooting |
| [MULTI_FEED_CVE_ENRICHMENT.md](scanning/MULTI_FEED_CVE_ENRICHMENT.md) | CVE enrichment feeds |
| [CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md](scanning/CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md) | Container build and evidence-based scanning |
| [SCAN_WORKFLOW_COMPARISON.md](scanning/SCAN_WORKFLOW_COMPARISON.md) | Public vs private repo scan workflows |
| [SCAN_COVERAGE_ANALYSIS.md](scanning/SCAN_COVERAGE_ANALYSIS.md) | Point-in-time analysis of full-scan layer coverage (midas, July 2026) |

## compliance/

| Document | Purpose |
|---|---|
| [STIG_SCANNING_TECHNICAL_REFERENCE.md](compliance/STIG_SCANNING_TECHNICAL_REFERENCE.md) | STIG assessment workflow, statuses, freeze logic and engine internals |
| [MANUAL_STIG_DOCUMENTATION_GUIDE.md](compliance/MANUAL_STIG_DOCUMENTATION_GUIDE.md) | Human-authored STIG documentation that takes priority over AI assessments |
| [SCORE_CARD_GUIDE.md](compliance/SCORE_CARD_GUIDE.md) | How the Score Card is calculated, where its numbers come from, and how to verify them |
| [SECURITY_REVIEW_AND_TEST_COVERAGE.md](compliance/SECURITY_REVIEW_AND_TEST_COVERAGE.md) | Security review and test coverage snapshot |

## ml-security/, integrations/, releases/

| Document | Purpose |
|---|---|
| [ML_SECURITY_GUIDE.md](ml-security/ML_SECURITY_GUIDE.md) | ML/AI security layers (14, 18, 19, 20) |
| [WEBHOOK_INTEGRATION_GUIDE.md](integrations/WEBHOOK_INTEGRATION_GUIDE.md) | Real-time scan progress webhooks |
| [scan-private-repo.yml](integrations/scan-private-repo.yml) | Workflow template for scanning a private repository |
| [RELEASE_CHECKLIST.md](releases/RELEASE_CHECKLIST.md) | Tagging and publishing a release |

## plans/ (not implemented)

| Document | Purpose |
|---|---|
| [WEB_UI_POST_SCAN_PARITY.md](plans/WEB_UI_POST_SCAN_PARITY.md) | Plan for web UI post-scan step parity |
| [AI Integration Strategy for Epyon.md](plans/AI%20Integration%20Strategy%20for%20Epyon.md) | AI/ML integration roadmap (April 2026 memo) |
| [Epyon Road Map.pptx](plans/Epyon%20Road%20Map.pptx) | Roadmap deck |

## Maintenance

- Update a guide in the same change that alters the behavior it describes.
- Put a new guide in the folder that matches its topic and add it to this index.
- Remove one-off status reports instead of letting them go stale; the CHANGELOG is the history.
