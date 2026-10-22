<!-- Pinned copy of the ETK stig-review record template (skills/stig-review/references/record-template.md), entry format.
     template-version: etk-stig-review-2026-10-21 -->
# {{heading}}

- **Reviewed:** {{reviewed}}
- **Ticket:** {{ticket}}
- **Severity:** {{severity}}
- **Assessment method:** {{method}}

| Control ID | Status (Open / Not a Finding / Not Applicable) | Evidence | Notes |
|------------|------------------------------------------------|----------|-------|
| {{control_id}} | {{status}} | {{evidence}} | {{notes}} |

- **Findings:** {{findings}}
- **Changes that may affect this STIG:** changes that would invalidate this
  assessment and need a re-review.

  | Change | Where (path, config, env var) | Re-check |
  |--------|-------------------------------|----------|
{{changes_rows}}

- **ATO Ready automation recommendation:** {{automation}}
