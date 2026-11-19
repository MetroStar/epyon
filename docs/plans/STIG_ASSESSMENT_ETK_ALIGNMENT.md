# STIG assessment: align with the ETK `stig-review` skill

Status: phase 1 implemented (3.74.0); phases 2 and 3 pending. Source comparison: `epyon-stig-system-prompts.md` (Epyon
`SYSTEM_PROMPT`, `scripts/shell/run-stig-assessment.py`) against
`etk/skills/stig-review/` (SKILL.md, references/record-template.md).

## Context

Epyon's `EPYON_STIG_FORMAT=etk` mode already adopted the skill's output shape
(six fields, records, citation verification, `docs/stig-reviews/`). The
remaining gaps are in method: how evidence is cited, how prior results are
reused, and what the record says about scope and ownership.

## Skill or prompt?

They are not interchangeable. The skill drives an interactive agent with
grep, file reads, Jira and PR tools. Epyon's assessment is a tool-less batch
API call over a pre-built context window, run in CI.

Direction:

1. Keep a prompt for the batch pass.
2. Move assessment policy (status rules, evidence format, Not Applicable
   proof, out-of-scope owners) into versioned data so Epyon and the skill
   share one source of truth (phase 3).
3. Use the skill for the human step: review of Open and low-confidence
   controls, follow-up tickets, PR.
4. Optional later: an agentic mode with grep/read tools that produces real
   `path:line` citations, validated by the existing citation checker.

## Gaps and changes

| # | Gap | Change | Phase |
|---|-----|--------|-------|
| 1 | CONFIRM rule defaults to the previous status; the skill says assess fresh | Re-verify the previously cited `path:line` against current source; status may only carry over when the cited artifact is re-found | 1 |
| 2 | Citations are `file + literal`, no line numbers | Require `path:line` per code bullet | 1 |
| 3 | Not Applicable accepts an architectural claim | Require a "searched for X, no match" statement | 1 |
| 4 | No owner for controls outside the repo | New `owner` field (identity provider, infrastructure, vendor, backend, or empty) | 1 |
| 5 | One status per control | `component_statuses`: optional list of `{component, status, note}` for mode/component splits | 1 |
| 6 | No record of what was checked | New `assessment_method` field: files read, searches made, what was not run | 1 |
| 7 | Generic context ranking only | Per-repo reference file (where to look, known traps) | 2 |
| 8 | No gap-to-ticket step | Follow-up ticket drafts titled `V-xxxxx: <gap>` with `stig` label | 2 |
| 9 | Policy hard-coded in the script | Load policy text from `configuration/` | 3 |

Phase 1 is implemented first; 2 and 3 follow as separate changes.

## Phase 1 design

- Only the `etk` format changes. `legacy` keeps the four-field prompt and
  output byte for byte.
- New fields are optional on parse: a response without them is accepted and
  defaulted, so older model output and stored results keep working.
- Stored assessments gain `owner`, `assessment_method`,
  `component_statuses`; existing JSON without them loads unchanged.
- The ETK record writer renders the new fields into each
  `docs/stig-reviews/v-*.md` entry.
- Freeze logic (`confidence >= 85` and Not a Finding / Not Applicable) is
  untouched.
- Evidence must stay ASCII and secret-free, as today.

## Acceptance

- ETK prompt requires `path:line`, search-based Not Applicable evidence, and
  fresh re-verification of prior evidence.
- Parsed assessments carry `owner`, `assessment_method`,
  `component_statuses` with safe defaults.
- Records show the new fields; legacy output is unchanged.
- BATS/pytest coverage for prompt switching, parsing defaults and rendering.

## Tracking

Jira: MID ticket, labels `repo-epyon`, `kind-compliance`; to be created
(credentials were not configured when this was written).
