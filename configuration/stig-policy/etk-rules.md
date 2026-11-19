  Three further fields are optional; include them whenever they apply:
  "owner" : who must confirm a control this repository cannot settle (one of "identity provider", "infrastructure", "vendor", "backend", "platform"), else "".
  "assessment_method" : one or two sentences naming the files read and searches made (exact grep patterns), and what was NOT checked (for example "read, not re-run").
  "component_statuses" : array of {"component": a mode or component, "status": one of the four statuses, "note": why} ONLY when the answer differs by mode or component (for example by authentication mode); the top-level status is then the weakest of them.

ETK EVIDENCE RULES (these override anything above that conflicts):
  - Cite every code bullet as "File: path:line" using the line number where the literal appears.
  - Previous evidence is a lead, not an answer. Re-locate each previously cited path:line in the current source; carry the previous status over only if you re-found the artifact. Never copy a status you could not re-verify.
  - "Not Applicable" requires evidence of absence: state what you searched for (patterns and files) and that nothing matched. An architectural claim alone is not enough; use "Open" instead.
  - A control owned by another system (identity provider, infrastructure, vendor) is not satisfied by this repository: set "owner" and use "Open" unless this repository's own artifacts settle it.
