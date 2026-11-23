# STIG assessment: checklist of verified statements

Status: proposed, for discussion. Nothing here is implemented.
Scope: Layer 13 AI STIG assessment only (`scripts/shell/run-stig-assessment.py`,
`stig_citations.py`, `stig_records.py`). Other layers are unaffected.

Builds on `STIG_ASSESSMENT_ETK_ALIGNMENT.md` (done) and
`STIG_AGENTIC_ASSESSMENT.md` (proposed). Draws on the strategy draft in
MetroStar/midas-labs#218 (MID-5947), which uses Epyon STIG runs as its example.

## Problem

Today one model call returns a status, evidence prose and a confidence for a
whole control. Code then checks the prose with regexes and downgrades
failures. Observed consequences (midas-ui, 286 controls):

- Most downgrades came from the check, not the model: cited quotes were
  present but at the wrong line, so correct answers became Open at
  confidence 60 with no visible reason.
- The model's own evidence and its status disagreed (for example Open with
  evidence saying SATISFIED).
- Reported confidence carried little information (almost always 90-100).
- A control the model never saw the right file for was marked Open.
- A downgrade fallback and a real Open look identical downstream.

The model is often right. The system around it turns missing input and
formatting errors into verdicts.

## Principles

1. **The model does not choose a STIG status.** It answers small, closed
   questions. A status is a label for a result and is assigned only by a
   human or by a deterministic rule (see "Who may assign a status").
2. **Test, do not discover.** Turn each control into a set of checkable
   statements. Run deterministic probes first; ask the model only about what
   a probe cannot decide.
3. **Evidence and judgment stay labeled apart** through to the output.
4. **Every step is small, closed-format and independently checkable.**
5. **Unknown is a first-class result,** never a silent fallback verdict.

## Pipeline

Each stage has a closed output format and a check before the next stage runs.

### Stage 0: Applicability (small steps, deterministic first)

Replace the single applicability opinion with an ordered list of checks, each
recorded with its result:

1. STIG selected by detected technology (existing `is_stig_applicable`).
2. Control scope probe: does the artifact the control is about exist in the
   repository (a file type, config key, dependency, endpoint)? Answered by
   code (path glob, parser, SBOM lookup).
3. Ownership probe: is the control owned outside the repository (identity
   provider, infrastructure, vendor)? Taken from `.epyon-stig-reference.md`
   and the policy file, not from the model's opinion.
4. Only if 2 and 3 cannot decide: one model question with fixed options
   `IN_SCOPE | OUT_OF_SCOPE | INSUFFICIENT_INFORMATION | OTHER(explain)`.

Output: `applicability = {result, steps[]}`. "Not applicable" is never
stated without the probe that found no match and what it searched.

### Stage 1: Criteria (the checklist)

Break the control's check text into criteria. Each criterion is one
specific, answerable statement that can be true or false of the repository.

- Source: derive from `check_content` / `fix_text` deterministically where
  the text already lists steps (numbered, "if ... then finding"). Otherwise a
  model drafts them.
- Every criterion stores the span of check text it came from. A criterion
  without a source span is rejected. This keeps criteria tied to the
  requirement instead of the model's invention.
- Criteria are versioned and cached per STIG release and control, so they are
  generated once, reviewed once and reused. A changed check text invalidates
  them.
- Criteria are labeled `derived` or `model-drafted`. Model-drafted criteria
  are the least trusted artifact in the pipeline because their errors reach
  every later step. They are covered by the validation work below.

### Stage 2: Evidence gathering (deterministic)

For each criterion, code gathers candidate evidence: path/glob and grep
probes, config parsers, symbol lookup for definitions and references,
dependency and SBOM lookup. Each item is pinned: path, line range, commit,
content hash, retrieved by code.

- Each criterion declares the facts it needs. If none can be gathered, its
  answer is `INSUFFICIENT_INFORMATION` with no model call.
- A search coverage record lists the files, symbols and patterns examined, so
  "not found" means "not found in these places".
- Where a target test or an executable probe can decide a criterion, it is
  preferred over a model (only if shown to exercise the relevant code).
- Optional later: the agentic search in `STIG_AGENTIC_ASSESSMENT.md` feeds
  this stage. Its tool calls are recorded by code; the evidence it finds is
  pinned the same way.

### Stage 3: One determination per call (constrained)

One criterion per call, in a fresh call. Input: the criterion text and the
pinned evidence items, referenced by evidence ID. Output, enforced by a
strict schema and constrained decoding where the endpoint supports it:

```
{ "criterion_id": "...",
  "answer": "TRUE | FALSE | INSUFFICIENT_INFORMATION | OTHER",
  "evidence_ids": ["e1", "e3"],     // from the supplied set only
  "explanation": "..." }             // required for OTHER, optional otherwise
```

- No free-text citations. The model references evidence IDs, so invented
  paths and wrong line numbers cannot occur.
- `OTHER` and `INSUFFICIENT_INFORMATION` are never treated as TRUE or FALSE.
- No confidence is requested. Confidence, where shown, is derived (Stage 6).

### Stage 4: Confirmation

For each TRUE answer, a fresh call sees only the retrieved evidence content
and the criterion and answers `SHOWS | DOES_NOT_SHOW | UNCLEAR`. A
`DOES_NOT_SHOW` returns the criterion to Stage 2 once (more evidence), then
resolves to undetermined. This is the "cite, retrieve, confirm" step that the
current code only half does (it checks that a quote exists, not that it
supports the claim).

### Stage 5: Consistency checks (code)

Structural rules that hold for any control:

- TRUE must reference at least one evidence ID that resolves to pinned
  content.
- Every evidence ID must exist in the supplied set.
- FALSE needs the evidence or probe result that shows the condition is not
  met, or a coverage record entry showing what was searched.
- OTHER must carry an explanation; INSUFFICIENT_INFORMATION must name what is
  missing.
- Criteria for one control must not contradict each other (mutually
  exclusive pairs declared with the criteria).
- Content hashes still match the pinned source at the end of the run.

A rule failure marks that criterion `INVALID` with the rule name. It never
changes another criterion's answer, and never becomes a status.

### Stage 6: Derived result (code)

Code combines criterion answers into a **checklist result**:

- `criteria`: each with answer, evidence IDs, who or what decided it
  (probe, model, confirmed, human).
- `summary`: counts by answer, for example 5 TRUE (confirmed), 1 FALSE,
  1 INSUFFICIENT_INFORMATION.
- `derived_confidence`: computed from observable inputs: share of criteria
  confirmed, evidence found, stability across repeats. Never the model's own
  number.
- `complete`: true only when every criterion is TRUE or FALSE and confirmed.

## Who may assign a status

The statuses Not a Finding, Open, Not Applicable, partial and other are
**reserved for a human, or for a deterministic rule applied once the checklist
is complete.** The model never emits one.

| Source | May assign | Condition |
|---|---|---|
| Human reviewer | Any status | Recorded with reviewer and date; locked on later scans unless a path they list changed (existing ETK behavior) |
| Backend rule (code) | Not a Finding, Open | Checklist `complete`, and the control's declared combination rule (for example "all criteria TRUE") is satisfied or violated. Labeled `status_source: rule` |
| Backend rule (code) | Not Applicable | Stage 0 scope probe found no match and recorded what was searched |
| Nothing yet | (none) | Checklist incomplete: the control is reported as `Undetermined` with the checklist attached, not as Open |

How the combination rule is declared (per control in versioned data, or per
STIG) is an open question below.

`Undetermined` is a new display state. It stands for "no status has been
assigned" and is distinct from Open ("a finding exists"). This removes the
current ambiguity between a failed check and a real Open.

## Interaction with existing behavior

- Format switch: new behavior sits behind `EPYON_STIG_FORMAT=checklist`.
  `legacy` and `etk` stay byte for byte unchanged.
- Freeze logic: only statuses with `status_source` of human or rule freeze,
  keyed on pinned evidence hashes and criteria version (Decision 5), not on
  a confidence threshold.
- Scorecard, `stig_na` / `stig_nr` split, STIG history, records and the web
  UI: `Undetermined` is its own bucket (Decision 4). Do not fold it into
  Open or Not Reviewed, which already carry compliance meaning.
  `generate-trl-score.py` currently counts only Not a Finding and Open as
  pass/fail and must change to the assigned-controls pass rate.
- `Not Reviewed` stays reserved for runtime-only controls with no static
  indicators.
- Existing `stig_citations.py` stays for the `etk` path. In `checklist`
  mode citation text is generated by code from pinned evidence, so prose
  parsing is no longer needed.
- Records: each `docs/stig-reviews/v-*.md` gains the checklist table. ASCII
  only; redaction unchanged.

## Phases

1. **Schema and records.** Define the checklist result schema, the
   `Undetermined` state and `status_source`, and render them in records and
   the UI. No model changes. Tests for schema validation and rendering.
2. **Criteria.** Deterministic extraction from check text, source-span
   requirement, versioned cache. Review a sample of generated criteria by
   hand before trusting them.
3. **Probes and evidence pinning.** Scope, ownership and evidence probes,
   coverage record. Controls fully decided by probes need no model call.
4. **Constrained determinations and confirmation.** Stage 3 and 4 behind the
   format flag.
5. **Consistency checks and derived result.** Stage 5 and 6.
6. **Validation harness** (below). Gate every later rollout on it.
7. **Agentic search** (optional): wire `STIG_AGENTIC_ASSESSMENT.md` into
   Stage 2.

## Validation

- **Synthetic ground truth.** Make a copy of a fixture repository, inject a
  known defect (remove a setting) or fix (add one), and check the checklist
  result changes the expected criterion. The right answer is known by
  construction, so no human labels are needed. This also measures what the
  pipeline misses, which grounding checks alone cannot.
- **Unit tests** for each rule in Stage 5, schema rejection of invented
  evidence IDs, and `OTHER` / `INSUFFICIENT_INFORMATION` never counting as a
  decided answer.
- **Trend metrics per run:** share of criteria by answer and decider, share
  of `INVALID`, share `Undetermined`, and whether results cluster on one
  value. A run with a suspicious trend is flagged instead of published.
- **Stability:** repeat Stage 3 on a sample and report disagreement. Treat
  agreement as a trigger for more evidence, not proof (several runs can be
  wrong together).
- **Comparison:** run `compare-stig-formats.py` against `etk` on midas-ui
  and review the controls whose outcome differs.
- Tests that exercise this path must set `EPYON_STIG_FORMAT=checklist`.

## Cost

More, smaller calls: one per criterion plus one confirmation per TRUE.
Mitigations: probes decide many criteria with no call, criteria are cached,
results are reused while pinned content hashes are unchanged, and a
per-scan cap on model calls is reported in the scan log with token usage.

## Safety

- Repository content is untrusted input. Evidence is delimited and the
  prompt states it is data. The model never writes, executes or reaches the
  network.
- Evidence text is redacted by the existing record redaction before it is
  sent to the model and stored. `.env` stays unreadable.
- The model references evidence by ID, which also removes most prompt-injection
  room in citations.

## Out of scope

- Changing ML control assessment (`assess_ml_controls`).
- Replacing human review or the freeze behavior for human-reviewed controls.
- Writing to the target repository, running its tests or commands.
- Choosing models, or changing the `legacy` and `etk` paths.

## Decisions

Agreed in discussion (not yet implemented):

1. **Combination rule.** A small fixed vocabulary chosen per control
   (`ALL_TRUE`, `ANY_FALSE_IS_FINDING`, and not-applicable-first). The
   default is derived from the check text's "If ..., this is a finding"
   sentences (285 of 286 ASD v6r5 controls use that form, by rough regex
   count). Hand-written overrides only for the minority with several
   finding conditions.
2. **Backend STIGs are inheritance.** A criterion that the app repo cannot
   show (database encryption, server logging, TLS termination) is marked
   `inheritable` and points at the backend control that decides it (Tomcat,
   Postgres, Database SRG). When that control has a human or rule-assigned
   status, the criterion resolves from it with decider
   `inherited:<stig>:<V-id>`, and the checklist can become `complete`.
   - Mapping data is mostly deterministic: controls carry `ccis` and
     `srg_id`. Exceptions go in a versioned override file under
     `configuration/stig-policy/`, owned and reviewed by Epyon maintainers.
   - The backend status comes from whoever assesses that system.
3. **Criteria source.** Two tiers. Tier A is deterministic: split the check
   text on its "If ... finding" and "not applicable" sentences. Tier B is
   model-drafted for remaining steps, each quoting its source span; a human
   approves it once per STIG release, and unapproved criteria leave the
   control `Undetermined`.
4. **Score card.** `Undetermined` is its own bucket. Pass rate is Not a
   Finding / (Not a Finding + Open) over assigned controls only, shown with
   an assigned-coverage percentage (for example 120 of 286 assigned).
5. **Freeze and confidence.** Human and rule-assigned statuses freeze on
   pinned evidence hashes plus criteria version, not on a confidence
   threshold. Derived confidence is display-only.
6. **Expressibility.** Not every control is a checklist. Each criterion
   declares `evidence_kind`: `static`, `document`, `runtime` or `interview`.
   A runtime or interview criterion is `INSUFFICIENT_INFORMATION` unless it
   is inherited or a human supplies it, so a control containing one cannot
   be `complete` from the repository alone. `Not Reviewed` means exactly
   that.
7. **Cost.** A configurable per-scan cap on model calls. At the cap,
   remaining controls stay `Undetermined` and the scan log says so. Actual
   values are set after the Phase 6 measurements.

## Open questions

1. Is the backend system assessed by Epyon in the same scan, or does
   inheritance come from an imported result or a human attestation?
   `configuration/stigs/` currently holds only the ASD STIG and the ML
   checklist, so the CCI/SRG overlap is unverified.
2. How is a human-approved Tier B criterion stored and invalidated when the
   STIG release changes?
3. What call cap and per-control cost are acceptable once measured?
