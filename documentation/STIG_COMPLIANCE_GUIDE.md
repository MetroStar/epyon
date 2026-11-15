# Epyon STIG Compliance Guide

How Epyon's STIG assessment (Layer 13) works and how to control it. This guide
intentionally contains **no per-control results**: Epyon reads every Markdown file
under `documentation/` as human-authored STIG context, so a stored copy of earlier
results would be treated as a priority assessment and skew later runs. Current
results are produced by each scan (`stig-results-{slug}.json` and the findings
Markdown in the scan directory) and shown in the web UI.

## Statuses

`Not a Finding` | `Not Applicable` | `Open` | `Not Reviewed`. `Not Reviewed` is
reserved for runtime-only controls with no static indicators; use `Open` when in doubt.

## Review Record Format and Rollback

Set `EPYON_STIG_FORMAT=etk` to get one review record per control (`stig-reviews-{slug}/v-xxxxx.md` plus an index) and a PR that publishes them to `docs/stig-reviews/` in your repository. Each record lists the evidence, the changes that may affect the control, and an automation recommendation; every `File:` citation is checked against your repository, and a failed check leaves the control Open. Entries a human has reviewed are locked on the next scan unless a file the entry lists has changed.

The default is `legacy` (the original `docs/stig-findings.md` flow) until the new format is validated. To roll back, unset the variable or set `EPYON_STIG_FORMAT=legacy`; your overrides and scan history are unaffected. Details: [STIG_SCANNING_TECHNICAL_REFERENCE.md](STIG_SCANNING_TECHNICAL_REFERENCE.md).

## Manual STIG Documentation

Target repositories can provide manual STIG assessments and overrides by creating documentation files like `docs/stig-findings.md` or `docs/security/stig-findings.md`. The Epyon STIG assessment engine (Layer 13) automatically collects and reads these files as **priority context** when performing AI-powered assessments.

**Key Points**:
- Manual documentation in `docs/stig-findings.md`, `docs/security/stig-findings.md`, `COMPLIANCE.md`, or `STIG.md` takes priority over AI assessments
- Human-authored evidence is respected unless specific code changes invalidate it
- Use manual documentation for runtime-only controls, policy-based controls, and complex architectural assessments
- Keep these files current or delete them: stale verdicts in them are followed by the engine

**See**: [Manual STIG Documentation Guide](MANUAL_STIG_DOCUMENTATION_GUIDE.md) for detailed guidance.

## Freeze Logic

Controls with `confidence >= 85` and status `Not a Finding` or `Not Applicable` carry forward from the previous scan without re-assessment. See [Freeze Logic & Status Validation](STIG_SCANNING_TECHNICAL_REFERENCE.md#freeze-logic--status-validation) in the technical reference.
