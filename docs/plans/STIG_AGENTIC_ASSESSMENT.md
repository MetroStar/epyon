# STIG assessment: optional agentic mode (read-only tools)

Status: proposed. Follows `STIG_ASSESSMENT_ETK_ALIGNMENT.md` (phases 1-3 done).

## Problem

Layer 13 sends a pre-built context window to a tool-less model. The model
cannot search, so `path:line` citations and `assessment_method` are its own
claims, and a control whose evidence did not make it into the window is
marked Open even when the repository settles it. The ETK `stig-review` skill
avoids both by searching the repository with exact commands.

## Proposal

A second, opt-in pass (`EPYON_STIG_AGENTIC=true`, ETK format only) in which
the model assesses a control by calling read-only tools against the target
repository.

Scope the pass to controls that benefit: those left `Open`, or with
confidence below the freeze threshold (85), after the normal batch pass.
Frozen and human-reviewed controls are never re-assessed.

### Tools (all read-only, scoped to the target directory)

| Tool | Arguments | Limits |
|------|-----------|--------|
| `grep` | pattern, optional glob | max matches and bytes per call |
| `read_file` | path, optional line range | max bytes per call |
| `list_files` | glob | max entries |

Denied: `.env` (except `.env.example`/`.env.template`), paths escaping the
target (including via symlinks), `.git`, `node_modules`, lockfiles,
generated and vendored directories, binary files.

### Evidence integrity

- The executed tool calls are recorded and written to `assessment_method`
  by Epyon, so the record shows real commands rather than the model's claim.
- Existing citation verification (`stig_citations.py`) runs unchanged on the
  final evidence; unverifiable citations still downgrade the status.
- Results are labelled `method: agentic` so reviewers can tell the passes
  apart.

### Safety

- Repository content is untrusted input and can contain prompt injection.
  Tool output is delimited and the system prompt states that file contents
  are data. Tools cannot write, execute or reach the network, so the blast
  radius is limited to a wrong assessment, which citation checks catch.
- Secrets: tool output is passed through the same redaction as record text
  before it is sent to the model and stored.

### Cost and limits

- Per-control caps on tool calls, total tool-output bytes and wall time.
- Hard cap on agentic controls per scan (configurable), reported in the
  scan log with token usage.
- Requires a provider that supports tool calling. If the configured endpoint
  does not (for example some local models), log it and skip the pass; the
  batch results stand.

## Out of scope

- Changing status rules, freeze logic or the record layout.
- Writing to the target repository, running tests or commands.
- Using the pass in `legacy` format.

## Acceptance

- With the flag off, behaviour and prompts are unchanged.
- With it on, an Open control whose evidence exists in the repository but was
  outside the batch window can become Not a Finding with verified `path:line`
  citations.
- `assessment_method` lists the real tool calls made.
- Tool sandbox rejects `.env`, `..` traversal and symlink escapes (tests).
- Caps stop a runaway loop; a provider without tool calling is skipped
  cleanly.

## Open questions

- Which providers/models in use support tool calling reliably (hosted OpenAI
  and the default local model)?
- Should the pass run in CI by default for `stig` mode, or only on request?
- Per-scan token budget a team is willing to accept.
