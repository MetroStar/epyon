#!/usr/bin/env bash
# create-jira-tickets.sh — Create or update JIRA tickets for Epyon security findings.
#
# All inputs are passed via environment variables (set by the calling workflow step):
#
#   FINDINGS_FILE          — path to security-findings-summary.json
#   JIRA_URL               — Jira Cloud base URL (e.g. https://org.atlassian.net)
#   PROJECT_KEY            — Jira project key (e.g. SEC)
#   ISSUE_TYPE             — Jira issue type (default: Bug)
#   AUTH                   — base64-encoded "email:token" string
#   REPO_NAME              — GitHub repository (owner/repo)
#   REPO_SLUG              — URL-safe version of REPO_NAME
#   TODAY                  — current UTC date (YYYY-MM-DD)
#   RUN_URL                — URL of the GitHub Actions run
#   CRITICAL_COUNT         — integer count of critical findings
#   HIGH_COUNT             — integer count of high findings
#   MEDIUM_COUNT           — integer count of medium findings
#   LOW_COUNT              — integer count of low findings
#   GITHUB_ISSUE_URL       — URL of the associated GitHub issue (optional)
#   GITHUB_ISSUE_NUMBER    — number of the associated GitHub issue (optional)
#   GITHUB_TOKEN           — GitHub token for reading/updating the issue body (dedup)
#   GITHUB_STEP_SUMMARY    — path to the GitHub step summary file

set -euo pipefail

show_help() {
  cat <<'EOF'
Usage: create-jira-tickets.sh [--help]

Creates or updates Jira tickets from security findings.
Inputs are provided via environment variables by the workflow.

Required environment:
  FINDINGS_FILE, JIRA_URL, PROJECT_KEY, AUTH, REPO_NAME

Ticket modes (TICKET_MODE):
  severity  (default) — one ticket per severity tier (critical/high/medium/low)
  hybrid              — severity parent ticket + one child ticket per unique CVE

Hybrid-mode options:
  CVE_ISSUE_TYPE   — issue type for child CVE tickets (default: Subtask)
  MAX_CVE_TICKETS  — max CVE child tickets per severity tier (default: 50)

Options:
  -h, --help    Show this help text and exit.
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

# ── Helper: fetch current GitHub issue body via API ──────────────────────────
get_github_issue_body() {
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && echo "" && return
  [[ -z "${GITHUB_TOKEN:-}" ]]        && echo "" && return
  curl -s \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${REPO_NAME}/issues/${GITHUB_ISSUE_NUMBER}" \
    | jq -r '.body // ""'
}

# ── Helper: find existing open Jira ticket via key stored in GitHub issue body ─
# Avoids Jira search entirely. After creating a ticket we embed
# <!--epyon-jira-{label}:KEY--> in the GitHub issue body. On subsequent runs we
# extract that key and call GET /rest/api/3/issue/{key} to check if still open.
# All status messages go to stderr; only the key (or empty string) goes to stdout.
find_existing_jira_ticket() {
  local label_severity="$1"
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && echo "" && return
  [[ -z "${GITHUB_TOKEN:-}" ]]        && echo "" && return

  local issue_body
  issue_body=$(get_github_issue_body)
  [[ -z "${issue_body}" ]] && echo "" && return

  echo "${issue_body}" > /tmp/epyon_issue_body.txt
  local stored_key
  stored_key=$(python3 - "${label_severity}" /tmp/epyon_issue_body.txt <<'PYEOF'
import sys, re
label, body_file = sys.argv[1], sys.argv[2]
with open(body_file) as f:
    body = f.read()
m = re.search(r'<!--epyon-jira-' + re.escape(label) + r':([A-Z]+-\d+)-->', body)
print(m.group(1) if m else '')
PYEOF
  )

  if [[ -z "${stored_key}" ]]; then
    echo "    No stored Jira key for ${label_severity} — will create new ticket" >&2
    echo ""
    return
  fi

  echo "    Stored key '${stored_key}' found — verifying it is still open..." >&2
  local ticket_http
  ticket_http=$(curl -s -o /tmp/jira_ticket.json -w "%{http_code}" \
    -H "Authorization: Basic ${AUTH}" \
    -H "Accept: application/json" \
    "${JIRA_URL}/rest/api/3/issue/${stored_key}?fields=status,summary")

  if [[ "${ticket_http}" == "200" ]]; then
    # Check by statusCategory.key (Jira Cloud standard: "undefined","indeterminate","done")
    local status_cat status_cat_name status_name
    status_cat=$(jq -r '.fields.status.statusCategory.key // ""' /tmp/jira_ticket.json 2>/dev/null || true)
    status_cat_name=$(jq -r '.fields.status.statusCategory.name // ""' /tmp/jira_ticket.json 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    status_name=$(jq -r '.fields.status.name // ""' /tmp/jira_ticket.json 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    echo "    Ticket ${stored_key} status — category.key='${status_cat}' category.name='${status_cat_name}' status.name='${status_name}'" >&2

    local is_done="false"
    [[ "${status_cat}" == "done" ]] && is_done="true"
    [[ "${status_cat_name}" == "done" ]] && is_done="true"
    case "${status_name}" in
      done|closed|resolved|complete|completed|"won't fix"|wontfix|invalid) is_done="true" ;;
    esac

    if [[ "${is_done}" == "false" ]]; then
      echo "${stored_key}"
    else
      echo "    Ticket ${stored_key} is closed (status: '${status_name}') — clearing stale marker and will create new" >&2
      # Clear the stale marker now so subsequent runs don't re-check this key
      clear_jira_key_in_github "${label_severity}"
      echo ""
    fi
  else
    echo "    Ticket ${stored_key} lookup returned HTTP ${ticket_http} — will create new" >&2
    clear_jira_key_in_github "${label_severity}"
    echo ""
  fi
}

# ── Helper: embed Jira ticket key in GitHub issue body for future runs ─────────
store_jira_key_in_github() {
  local label_severity="$1"
  local jira_key="$2"
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && return 0
  [[ -z "${GITHUB_TOKEN:-}" ]]        && return 0

  local current_body
  current_body=$(get_github_issue_body)
  echo "${current_body}" > /tmp/epyon_issue_body.txt

  local new_body
  new_body=$(python3 - "${label_severity}" "${jira_key}" /tmp/epyon_issue_body.txt <<'PYEOF'
import sys, re
label, key, body_file = sys.argv[1], sys.argv[2], sys.argv[3]
with open(body_file) as f:
    body = f.read()
marker  = f'<!--epyon-jira-{label}:{key}-->'
pattern = r'<!--epyon-jira-' + re.escape(label) + r':[A-Z]+-\d+-->'
if re.search(pattern, body):
    new_body = re.sub(pattern, marker, body)
else:
    new_body = body.rstrip('\n') + '\n' + marker
print(new_body, end='')
PYEOF
  )

  local update_payload
  update_payload=$(jq -n --arg body "${new_body}" '{body: $body}')
  local update_http
  update_http=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    --data "${update_payload}" \
    "https://api.github.com/repos/${REPO_NAME}/issues/${GITHUB_ISSUE_NUMBER}")
  if [[ "${update_http}" == "200" ]]; then
    echo "📎 Stored Jira key ${jira_key} in GitHub issue #${GITHUB_ISSUE_NUMBER}"
  else
    echo "⚠️  Could not store Jira key in GitHub issue (HTTP ${update_http}) — continuing"
  fi
}

# ── Helper: remove Jira ticket key from GitHub issue body ────────────────────
clear_jira_key_in_github() {
  local label_severity="$1"
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && return 0
  [[ -z "${GITHUB_TOKEN:-}" ]]        && return 0

  local current_body
  current_body=$(get_github_issue_body)
  echo "${current_body}" > /tmp/epyon_issue_body.txt

  local new_body
  new_body=$(python3 - "${label_severity}" /tmp/epyon_issue_body.txt <<'PYEOF'
import sys, re
label, body_file = sys.argv[1], sys.argv[2]
with open(body_file) as f:
    body = f.read()
pattern = r'\n?<!--epyon-jira-' + re.escape(label) + r':[A-Z]+-\d+-->'
print(re.sub(pattern, '', body), end='')
PYEOF
  )

  local update_payload
  update_payload=$(jq -n --arg body "${new_body}" '{body: $body}')
  local update_http
  update_http=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    --data "${update_payload}" \
    "https://api.github.com/repos/${REPO_NAME}/issues/${GITHUB_ISSUE_NUMBER}")
  if [[ "${update_http}" == "200" ]]; then
    echo "📎 Cleared Jira key for ${label_severity} from GitHub issue #${GITHUB_ISSUE_NUMBER}"
  else
    echo "⚠️  Could not clear Jira key in GitHub issue (HTTP ${update_http}) — continuing"
  fi
}

# ── Helper: close a Jira ticket when all findings for a severity are resolved ─
# Finds the first "done" category transition and executes it, then adds a comment.
close_jira_ticket() {
  local jira_key="$1"
  local label_severity="$2"

  # Fetch available transitions.
  local trans_http
  trans_http=$(curl -s -o /tmp/jira_transitions.json -w "%{http_code}" \
    -H "Authorization: Basic ${AUTH}" \
    -H "Accept: application/json" \
    "${JIRA_URL}/rest/api/3/issue/${jira_key}/transitions") || true

  if [[ "${trans_http}" != "200" ]]; then
    echo "⚠️  Could not fetch transitions for ${jira_key} (HTTP ${trans_http}) — skipping auto-close"
    return 0
  fi

  # Pick the first transition whose statusCategory is "done".
  local transition_id
  transition_id=$(jq -r '
    [.transitions[] | select(.to.statusCategory.key == "done")] | first | .id // empty
  ' /tmp/jira_transitions.json 2>/dev/null || true)

  if [[ -z "${transition_id}" ]]; then
    echo "⚠️  No 'done' transition found for ${jira_key} — skipping auto-close"
    return 0
  fi

  # Execute the transition.
  local close_http
  close_http=$(curl -s -o /tmp/jira_close_resp.json -w "%{http_code}" \
    -X POST \
    -H "Authorization: Basic ${AUTH}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data "{\"transition\":{\"id\":\"${transition_id}\"}}" \
    "${JIRA_URL}/rest/api/3/issue/${jira_key}/transitions") || true

  if [[ "${close_http}" == "204" ]]; then
    echo "✅ Closed ${jira_key} — no ${label_severity} findings remain"
    echo "## ✅ JIRA Ticket Auto-Closed" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Ticket: [${jira_key}](${JIRA_URL}/browse/${jira_key})" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Reason: no findings in latest Epyon scan" >> "${GITHUB_STEP_SUMMARY}"
  else
    echo "⚠️  Could not close ${jira_key} (HTTP ${close_http}) — leaving open"
    cat /tmp/jira_close_resp.json 2>/dev/null || true
    return 0
  fi

  # Add a closing comment.
  jq -n '{
    "body": {
      "type": "doc", "version": 1,
      "content": [{
        "type": "paragraph",
        "content": [{
          "type": "text",
          "text": "Epyon scan on '"$(date -u +%Y-%m-%d)"' found no remaining findings for this severity level in '"${REPO_NAME}"'. Ticket auto-closed by Epyon. Run: '"${RUN_URL}"'"
        }]
      }]
    }
  }' > /tmp/jira_close_comment.json
  curl -s -o /dev/null \
    -X POST \
    -H "Authorization: Basic ${AUTH}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data @/tmp/jira_close_comment.json \
    "${JIRA_URL}/rest/api/3/issue/${jira_key}/comment" || true

  clear_jira_key_in_github "${label_severity}"
}

# ── Helper: check and auto-close ticket if severity count is now zero ─────────
maybe_close_jira_ticket() {
  local label_severity="$1"
  local count="$2"
  [[ "${count}" -gt 0 ]] && return 0

  local existing_key
  existing_key=$(find_existing_jira_ticket "${label_severity}")
  [[ -z "${existing_key}" ]] && return 0

  echo "--- ${label_severity}: count is 0 — checking for open ticket to close ---"
  close_jira_ticket "${existing_key}" "${label_severity}"
}

# ── Helper: build ADF body from a severity section of findings JSON ───────────
# Args: severity_key summary_line [filter_ids_json] [all_current_ids_json]
build_adf_body() {
  local severity_key="$1"
  local summary_line="$2"
  local filter_ids_json="${3:-}"
  local all_current_ids_json="${4:-[]}"
  python3 - "${FINDINGS_FILE}" "${severity_key}" "${summary_line}" "${RUN_URL}" "${REPO_NAME}" "${filter_ids_json}" "${all_current_ids_json}" <<'PYEOF'
import json, sys

findings_file, severity_key, summary_line, run_url, repo_name = sys.argv[1:6]
filter_ids_raw  = sys.argv[6] if len(sys.argv) > 6 else ''
all_current_raw = sys.argv[7] if len(sys.argv) > 7 else '[]'

filter_ids      = set(json.loads(filter_ids_raw)) if filter_ids_raw and filter_ids_raw not in ('', '[]') else None
all_tracked_ids = json.loads(all_current_raw) if all_current_raw else []

with open(findings_file) as f:
    data = json.load(f)

findings = data.get(severity_key, [])

if filter_ids:
    findings = [f for f in findings if (
        f.get("vulnerability_id") or f.get("check_id")
        or f.get("detector") or "unknown"
    ) in filter_ids]

rows = []
kev_findings = []
for finding in findings:
    vuln_id = (finding.get("vulnerability_id") or finding.get("check_id")
               or finding.get("detector") or "N/A")
    pkg     = (finding.get("package_name") or finding.get("file_path")
               or finding.get("file") or "N/A")
    version = finding.get("package_version") or "-"
    tool    = finding.get("tool") or "N/A"
    desc    = (finding.get("description") or "")[:120]
    nvd_url = finding.get("nvd_url") or ""
    is_kev  = finding.get("cisa_kev") is True
    rows.append({"id": vuln_id, "pkg": pkg, "ver": version, "tool": tool,
                 "desc": desc, "nvd_url": nvd_url, "is_kev": is_kev})
    if is_kev:
        kev_findings.append({
            "id": vuln_id,
            "due_date": finding.get("cisa_due_date") or "N/A",
            "required_action": (finding.get("cisa_required_action") or "")[:200],
            "ransomware": finding.get("cisa_known_ransomware") is True,
        })

def cell_text(text):
    return {"type": "tableCell", "attrs": {},
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": str(text)[:200]}]}]}

def cell_link(text, url):
    if url:
        return {"type": "tableCell", "attrs": {},
                "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": str(text)[:200],
                     "marks": [{"type": "link", "attrs": {"href": url}}]}]}]}
    return cell_text(text)

def header_cell(text):
    return {"type": "tableHeader", "attrs": {},
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": str(text), "marks": [{"type": "strong"}]}]}]}

header_row = {"type": "tableRow",
              "content": [header_cell(h) for h in
                          ["ID / CVE", "Package / File", "Version", "Tool", "Description"]]}

data_rows = []
for r in rows:
    kev_prefix = "\U0001f525 " if r["is_kev"] else ""
    id_cell = cell_link(kev_prefix + r["id"], r["nvd_url"]) if r["nvd_url"] else cell_text(kev_prefix + r["id"])
    data_rows.append({"type": "tableRow",
                      "content": [id_cell, cell_text(r["pkg"]), cell_text(r["ver"]),
                                  cell_text(r["tool"]), cell_text(r["desc"])]})

table = {"type": "table",
         "attrs": {"isNumberColumnEnabled": False, "layout": "full-width"},
         "content": [header_row] + data_rows}

kev_panel_blocks = []
if kev_findings:
    kev_lines = []
    for k in kev_findings:
        line_text = f"\U0001f525 {k['id']} \u2014 Due: {k['due_date']}"
        if k["ransomware"]:
            line_text += " \u26a0\ufe0f Ransomware"
        if k["required_action"]:
            line_text += f"\n   Action: {k['required_action']}"
        kev_lines.append({"type": "paragraph", "content": [{"type": "text", "text": line_text}]})
    kev_panel_blocks = [{"type": "panel", "attrs": {"panelType": "error"},
                         "content": [
                             {"type": "paragraph", "content": [
                                 {"type": "text",
                                  "text": f"\U0001f525 {len(kev_findings)} CISA Known Exploited Vulnerabilities Detected",
                                  "marks": [{"type": "strong"}]}]},
                             *kev_lines,
                             {"type": "paragraph", "content": [
                                 {"type": "text", "text": "CISA KEV Catalog",
                                  "marks": [{"type": "link", "attrs": {
                                      "href": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}]}]}
                         ]}]

ac_heading = {"type": "heading", "attrs": {"level": 3},
              "content": [{"type": "text", "text": "Acceptance Criteria"}]}
ac_list = {"type": "bulletList", "content": [
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "All listed vulnerabilities have been remediated, formally accepted with documented risk, or are tracked in an approved exception workflow"}]}]},
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": f"A follow-up Epyon scan of {repo_name} returns zero unresolved findings at this severity tier"}]}]},
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "Any CISA KEV items are addressed on or before their published due dates"}]}]},
]}
dod_heading = {"type": "heading", "attrs": {"level": 3},
               "content": [{"type": "text", "text": "Definition of Done"}]}
dod_list = {"type": "bulletList", "content": [
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "Remediation changes reviewed, approved, and merged to the default branch"}]}]},
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "Re-scan completed with this severity tier showing no remaining unresolved findings"}]}]},
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "If risk accepted: exception documented with approver name, justification, and scheduled review date"}]}]},
    {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
        "text": "Ticket resolved only after re-scan confirmation"}]}]},
]}

adf = {"version": 1, "type": "doc",
       "content": [
           *kev_panel_blocks,
           {"type": "paragraph", "content": [{"type": "text", "text": summary_line}]},
           table,
           ac_heading,
           ac_list,
           dod_heading,
           dod_list,
           {"type": "paragraph", "content": [
               {"type": "text", "text": "Repository: "},
               {"type": "text", "text": repo_name, "marks": [{"type": "code"}]}]},
           {"type": "paragraph", "content": [
               {"type": "text", "text": "Workflow run: "},
               {"type": "text", "text": run_url,
                "marks": [{"type": "link", "attrs": {"href": run_url}}]}]},
           {"type": "paragraph", "content": [
               {"type": "text", "text": "\U0001f916 Automated ticket created by Epyon Security Scanner"}]}
       ]}

if all_tracked_ids:
    adf["content"].append({
        "type": "codeBlock", "attrs": {"language": "text"},
        "content": [{"type": "text",
                     "text": "[epyon-tracked-vuln-ids:" + json.dumps(all_tracked_ids) + "]"}]
    })

print(json.dumps(adf))
PYEOF
}

# ── Helper: add a Jira Remote Link pointing back to the GitHub issue ──────────
link_jira_to_github() {
  local jira_key="$1"
  [[ -z "${GITHUB_ISSUE_URL:-}" ]] && return 0
  local link_payload
  link_payload=$(jq -n \
    --arg global_id "github-issue-${GITHUB_ISSUE_NUMBER:-0}" \
    --arg gh_url    "${GITHUB_ISSUE_URL}" \
    --arg gh_title  "GitHub Issue #${GITHUB_ISSUE_NUMBER:-}" \
    '{globalId: $global_id, relationship: "GitHub Issue",
      object: {url: $gh_url, title: $gh_title,
               icon: {url16x16: "https://github.com/favicon.ico", title: "GitHub"}}}')
  local link_http
  link_http=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Authorization: Basic ${AUTH}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data "${link_payload}" \
    "${JIRA_URL}/rest/api/3/issue/${jira_key}/remotelink")
  if [[ "${link_http}" == "201" ]]; then
    echo "✅ Linked ${jira_key} → GitHub issue #${GITHUB_ISSUE_NUMBER}"
  else
    echo "⚠️  Remote link on ${jira_key} returned HTTP ${link_http} — continuing"
  fi
}

# ── Helper: create or update one JIRA ticket for a severity level ─────────────
create_jira_ticket() {
  local title="$1"
  local label_severity="$2"  # epyon-critical / epyon-high / epyon-medium / epyon-low
  local priority="$3"        # Highest / High / Medium / Low
  local severity_key="$4"    # critical_findings / high_findings / etc.
  local summary_line="$5"

  # Collect current vuln IDs for the tracking marker embedded in new tickets.
  local current_ids_json='[]'
  if [[ -f "${FINDINGS_FILE}" ]]; then
    current_ids_json=$(python3 - "${severity_key}" "${FINDINGS_FILE}" <<'JIRA_GETIDS'
import json, sys
skey, fpath = sys.argv[1], sys.argv[2]
with open(fpath) as f:
    data = json.load(f)
ids = []
for x in data.get(skey, []):
    vid = (x.get('vulnerability_id') or x.get('check_id') or x.get('detector') or 'unknown')
    if vid not in ids:
        ids.append(vid)
print(json.dumps(ids))
JIRA_GETIDS
    ) 2>/dev/null || current_ids_json='[]'
  fi

  echo "--- Checking for existing open ticket: ${label_severity} ---"
  local existing_key
  existing_key=$(find_existing_jira_ticket "${label_severity}")

  if [[ -n "${existing_key}" ]]; then
      echo "${existing_key}" > /tmp/epyon_last_jira_key.txt
      echo "🔄  Found open ticket ${existing_key} — adding update comment"
      echo "## 🔄 JIRA: Update comment added to ${existing_key}" >> "${GITHUB_STEP_SUMMARY}"
      echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
      echo "- Ticket: [${existing_key}](${JIRA_URL}/browse/${existing_key})" >> "${GITHUB_STEP_SUMMARY}"

      local update_summary="Epyon scan on $(date -u +%Y-%m-%d): ${summary_line} (run: ${RUN_URL})"
      local comment_adf
      comment_adf=$(build_adf_body "${severity_key}" "${update_summary}" "" "${current_ids_json}")
      echo "${comment_adf}" > /tmp/jira_adf_body.json
      jq -n --slurpfile body /tmp/jira_adf_body.json '{body: $body[0]}' > /tmp/jira_comment_body.json 2>/dev/null || true
      local comment_http
      comment_http=$(curl -s -o /tmp/jira_comment_resp.json -w "%{http_code}" \
        -X POST \
        -H "Authorization: Basic ${AUTH}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data @/tmp/jira_comment_body.json \
        "${JIRA_URL}/rest/api/3/issue/${existing_key}/comment") || true
      if [[ "${comment_http}" == "201" ]]; then
        echo "✅ Comment added to ${existing_key}"
      else
        echo "⚠️  Comment on ${existing_key} returned HTTP ${comment_http}"
        cat /tmp/jira_comment_resp.json 2>/dev/null || true
      fi
      echo "${existing_key}|${JIRA_URL}/browse/${existing_key}" >> /tmp/jira_created_tickets.txt
      return 0
  fi

  echo "--- Creating new ticket for ${label_severity} ---"
  local adf_body
  adf_body=$(build_adf_body "${severity_key}" "${summary_line}" "" "${current_ids_json}")
  echo "${adf_body}" > /tmp/jira_adf_body.json

  jq -n \
    --arg project  "${PROJECT_KEY}" \
    --arg title    "${title}" \
    --arg itype    "${ISSUE_TYPE}" \
    --arg priority "${priority}" \
    --arg lsev     "${label_severity}" \
    --arg lrepo    "${REPO_SLUG}" \
    --slurpfile desc /tmp/jira_adf_body.json \
    '{fields: {project: {key: $project}, summary: $title, issuetype: {name: $itype},
               priority: {name: $priority}, description: $desc[0],
               labels: ["epyon", "security", $lsev, $lrepo]}}' > /tmp/jira_payload.json

  local create_http
  create_http=$(curl -s -o /tmp/jira_create.json -w "%{http_code}" \
    -X POST \
    -H "Authorization: Basic ${AUTH}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data @/tmp/jira_payload.json \
    "${JIRA_URL}/rest/api/3/issue")

  if [[ "${create_http}" == "201" ]]; then
    local new_key
    new_key=$(jq -r '.key' /tmp/jira_create.json)
    echo "${new_key}" > /tmp/epyon_last_jira_key.txt
    echo "✅ Created JIRA ticket: ${new_key}"
    echo "## ✅ JIRA Ticket Created" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Ticket: [${new_key}](${JIRA_URL}/browse/${new_key})" >> "${GITHUB_STEP_SUMMARY}"
    echo "${new_key}|${JIRA_URL}/browse/${new_key}" >> /tmp/jira_created_tickets.txt
    link_jira_to_github "${new_key}"
    store_jira_key_in_github "${label_severity}" "${new_key}"

    # Assign to active sprint (best-effort).
    local boards_http
    boards_http=$(curl -s -o /tmp/jira_boards.json -w "%{http_code}" \
      -H "Authorization: Basic ${AUTH}" \
      -H "Accept: application/json" \
      "${JIRA_URL}/rest/agile/1.0/board?projectKeyOrId=${PROJECT_KEY}&type=scrum&maxResults=1")
    if [[ "${boards_http}" == "200" ]]; then
      local board_id
      board_id=$(jq -r '.values[0].id // empty' /tmp/jira_boards.json)
      if [[ -n "${board_id}" ]]; then
        local sprints_http
        sprints_http=$(curl -s -o /tmp/jira_sprints.json -w "%{http_code}" \
          -H "Authorization: Basic ${AUTH}" \
          -H "Accept: application/json" \
          "${JIRA_URL}/rest/agile/1.0/board/${board_id}/sprint?state=active&maxResults=1")
        if [[ "${sprints_http}" == "200" ]]; then
          local sprint_id sprint_name
          sprint_id=$(jq -r '.values[0].id // empty' /tmp/jira_sprints.json)
          sprint_name=$(jq -r '.values[0].name // "active sprint"' /tmp/jira_sprints.json)
          if [[ -n "${sprint_id}" ]]; then
            local move_http
            move_http=$(curl -s -o /dev/null -w "%{http_code}" \
              -X POST \
              -H "Authorization: Basic ${AUTH}" \
              -H "Content-Type: application/json" \
              --data "{\"issues\":[\"${new_key}\"]}" \
              "${JIRA_URL}/rest/agile/1.0/sprint/${sprint_id}/issue")
            if [[ "${move_http}" == "204" ]]; then
              echo "✅ Assigned ${new_key} to sprint: ${sprint_name}"
              echo "- Sprint: **${sprint_name}**" >> "${GITHUB_STEP_SUMMARY}"
            else
              echo "⚠️  Could not assign to sprint (HTTP ${move_http}) — ticket in backlog"
            fi
          else
            echo "⚠️  No active sprint for board ${board_id} — ticket in backlog"
          fi
        fi
      fi
    fi
  else
    echo "❌ Failed to create JIRA ticket (HTTP ${create_http})"
    echo "$(cat /tmp/jira_create.json)"
    echo "## ❌ JIRA Ticket Creation Failed" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
    echo "- HTTP status: ${create_http}" >> "${GITHUB_STEP_SUMMARY}"
  fi
}

# ── Hybrid mode: per-CVE child ticket helpers ─────────────────────────────────

# Read the CVE→key map for a severity from the GitHub issue body.
# Outputs a JSON object: {"CVE-2024-1234": "SEC-45", ...}
get_cve_map_from_github() {
  local severity="$1"
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && echo '{}' && return
  [[ -z "${GITHUB_TOKEN:-}" ]]        && echo '{}' && return
  local issue_body
  issue_body=$(get_github_issue_body)
  echo "${issue_body}" > /tmp/epyon_issue_body.txt
  python3 - "${severity}" /tmp/epyon_issue_body.txt <<'PYEOF'
import sys, re, json
severity, body_file = sys.argv[1], sys.argv[2]
with open(body_file) as f:
    body = f.read()
m = re.search(r'<!--epyon-cve-map-' + re.escape(severity) + r':(\{.*?\})-->', body, re.DOTALL)
if m:
    try:
        parsed = json.loads(m.group(1))
        print(json.dumps(parsed))
        sys.exit(0)
    except Exception:
        pass
print('{}')
PYEOF
}

# Write an updated CVE→key map for a severity into the GitHub issue body.
store_cve_map_in_github() {
  local severity="$1"
  local map_json_file="$2"   # path to a file containing the JSON map
  [[ -z "${GITHUB_ISSUE_NUMBER:-}" ]] && return 0
  [[ -z "${GITHUB_TOKEN:-}" ]]        && return 0

  local current_body
  current_body=$(get_github_issue_body)
  echo "${current_body}" > /tmp/epyon_issue_body.txt

  local new_body
  new_body=$(python3 - "${severity}" /tmp/epyon_issue_body.txt "${map_json_file}" <<'PYEOF'
import sys, re, json
severity, body_file, map_file = sys.argv[1], sys.argv[2], sys.argv[3]
with open(body_file) as f:
    body = f.read()
with open(map_file) as f:
    map_json = f.read().strip()
marker  = f'<!--epyon-cve-map-{severity}:{map_json}-->'
pattern = r'<!--epyon-cve-map-' + re.escape(severity) + r':\{.*?\}-->'
if re.search(pattern, body, re.DOTALL):
    new_body = re.sub(pattern, marker, body, flags=re.DOTALL)
else:
    new_body = body.rstrip('\n') + '\n' + marker
print(new_body, end='')
PYEOF
  )

  local update_payload
  update_payload=$(jq -n --arg body "${new_body}" '{body: $body}')
  local update_http
  update_http=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    --data "${update_payload}" \
    "https://api.github.com/repos/${REPO_NAME}/issues/${GITHUB_ISSUE_NUMBER}")
  if [[ "${update_http}" == "200" ]]; then
    echo "📎 Updated CVE map for ${severity} in GitHub issue #${GITHUB_ISSUE_NUMBER}"
  else
    echo "⚠️  Could not update CVE map in GitHub issue (HTTP ${update_http}) — continuing"
  fi
}

# Build ADF body for a single CVE child ticket.
# Args: findings_for_cve_json_file cve_id sev_label parent_key
build_cve_adf_body() {
  local findings_file="$1"
  local cve_id="$2"
  local sev_label="$3"
  local parent_key="$4"
  python3 - "${findings_file}" "${cve_id}" "${sev_label}" "${parent_key}" \
            "${RUN_URL}" "${REPO_NAME}" "${JIRA_URL}" <<'PYEOF'
import json, sys

findings_file, cve_id, sev_label, parent_key = sys.argv[1:5]
run_url, repo_name, jira_url = sys.argv[5:8]

with open(findings_file) as f:
    findings = json.load(f)

def cell_text(text):
    return {"type": "tableCell", "attrs": {},
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": str(text)[:300]}]}]}

def cell_link(text, url):
    if url:
        return {"type": "tableCell", "attrs": {},
                "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": str(text)[:300],
                     "marks": [{"type": "link", "attrs": {"href": url}}]}]}]}
    return cell_text(text)

def header_cell(text):
    return {"type": "tableHeader", "attrs": {},
            "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": str(text), "marks": [{"type": "strong"}]}]}]}

header_row = {"type": "tableRow",
              "content": [header_cell(h) for h in
                          ["Package / File", "Version", "Fixed In", "Tool"]]}

data_rows = []
is_kev = False
cisa_kev_data = None
for f in findings:
    pkg     = f.get("package_name") or f.get("file_path") or f.get("file") or "N/A"
    ver     = f.get("package_version") or "-"
    fixed   = f.get("fix_version") or f.get("fixed_version") or "—"
    tool    = f.get("tool") or "N/A"
    if f.get("cisa_kev"):
        is_kev = True
        cisa_kev_data = f
    data_rows.append({"type": "tableRow",
                      "content": [cell_text(pkg), cell_text(ver),
                                  cell_text(fixed), cell_text(tool)]})

table = {"type": "table",
         "attrs": {"isNumberColumnEnabled": False, "layout": "full-width"},
         "content": [header_row] + data_rows}

desc_text = (findings[0].get("description") or "") if findings else ""
nvd_url   = (findings[0].get("nvd_url") or "") if findings else ""

kev_panel_blocks = []
if is_kev and cisa_kev_data:
    due  = cisa_kev_data.get("cisa_due_date") or "N/A"
    ra   = (cisa_kev_data.get("cisa_required_action") or "")[:300]
    rw   = cisa_kev_data.get("cisa_known_ransomware") is True
    kev_panel_blocks = [{"type": "panel", "attrs": {"panelType": "error"},
                         "content": [
                             {"type": "paragraph", "content": [{"type": "text",
                                 "text": f"\U0001f525 CISA Known Exploited Vulnerability — Due: {due}",
                                 "marks": [{"type": "strong"}]}]},
                             *([{"type": "paragraph", "content": [{"type": "text",
                                 "text": f"\u26a0\ufe0f Associated with ransomware campaigns",
                                 "marks": [{"type": "strong"}]}]}] if rw else []),
                             *([{"type": "paragraph", "content": [{"type": "text",
                                 "text": f"Required action: {ra}"}]}] if ra else []),
                             {"type": "paragraph", "content": [{"type": "text",
                                 "text": "CISA KEV Catalog",
                                 "marks": [{"type": "link", "attrs": {
                                     "href": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}]}]},
                         ]}]

intro_content = [{"type": "text", "text": f"{cve_id} ({sev_label}) — affecting {len(findings)} package(s) in {repo_name}"}]
if nvd_url:
    intro_content.append({"type": "text", "text": " [NVD]",
                           "marks": [{"type": "link", "attrs": {"href": nvd_url}}]})

content_blocks = [
    *kev_panel_blocks,
    {"type": "paragraph", "content": intro_content},
]
if desc_text:
    content_blocks.append({"type": "paragraph", "content": [
        {"type": "text", "text": desc_text[:500]}]})
content_blocks.append(table)

if parent_key:
    content_blocks.append({"type": "paragraph", "content": [
        {"type": "text", "text": "Parent ticket: "},
        {"type": "text", "text": parent_key,
         "marks": [{"type": "link", "attrs": {"href": f"{jira_url}/browse/{parent_key}"}}]}]})

content_blocks += [
    {"type": "heading", "attrs": {"level": 3},
     "content": [{"type": "text", "text": "Acceptance Criteria"}]},
    {"type": "bulletList", "content": [
        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
            "text": f"All packages affected by {cve_id} are patched, updated to a fixed version, or formally risk-accepted"}]}]},
        {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
            "text": f"Follow-up Epyon scan shows {cve_id} no longer present at this severity"}]}]},
        *([{"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text",
            "text": f"CISA KEV due date ({cisa_kev_data.get('cisa_due_date')}) is met"}]}]}]
          if is_kev and cisa_kev_data else []),
    ]},
    {"type": "paragraph", "content": [
        {"type": "text", "text": "Repository: "},
        {"type": "text", "text": repo_name, "marks": [{"type": "code"}]}]},
    {"type": "paragraph", "content": [
        {"type": "text", "text": "Workflow run: "},
        {"type": "text", "text": run_url,
         "marks": [{"type": "link", "attrs": {"href": run_url}}]}]},
    {"type": "paragraph", "content": [
        {"type": "text", "text": "\U0001f916 Automated ticket created by Epyon Security Scanner"}]},
]

adf = {"version": 1, "type": "doc", "content": content_blocks}
print(json.dumps(adf))
PYEOF
}

# Create or update CVE-level child tickets under a parent severity ticket.
# Args: parent_key severity_label priority severity_key
# e.g.: create_cve_tickets "SEC-42" "critical" "Highest" "critical_findings"
create_cve_tickets() {
  local parent_key="$1"
  local sev_label="$2"
  local priority="$3"
  local severity_key="$4"

  echo "--- Hybrid mode: processing CVE child tickets for ${sev_label} (parent: ${parent_key}) ---"

  # Extract unique CVE IDs and their findings from FINDINGS_FILE
  python3 - "${FINDINGS_FILE}" "${severity_key}" <<'PYEOF' > /tmp/epyon_cve_groups.json
import json, sys
fpath, skey = sys.argv[1], sys.argv[2]
with open(fpath) as f:
    data = json.load(f)
groups = {}
for finding in data.get(skey, []):
    cve_id = (finding.get("vulnerability_id") or finding.get("check_id")
              or finding.get("detector") or "UNKNOWN")
    if cve_id not in groups:
        groups[cve_id] = []
    groups[cve_id].append(finding)
print(json.dumps(groups))
PYEOF

  local cve_count
  cve_count=$(jq 'keys | length' /tmp/epyon_cve_groups.json 2>/dev/null || echo 0)
  echo "  Found ${cve_count} unique CVE(s) for ${sev_label}"

  # Load existing CVE→key map from GitHub issue
  local cve_map_json
  cve_map_json=$(get_cve_map_from_github "${sev_label}")
  echo "${cve_map_json}" > /tmp/epyon_cve_map_current.json

  # Get current CVE IDs
  local current_cve_ids
  current_cve_ids=$(jq -r 'keys[]' /tmp/epyon_cve_groups.json 2>/dev/null || true)

  local cap="${MAX_CVE_TICKETS:-50}"
  local processed=0

  # --- Create/update tickets for current CVEs ---
  while IFS= read -r cve_id; do
    [[ -z "${cve_id}" ]] && continue
    if [[ "${processed}" -ge "${cap}" ]]; then
      echo "  ⚠️  Reached MAX_CVE_TICKETS (${cap}) — stopping. Remaining CVEs skipped."
      break
    fi

    # Write findings for this CVE to a temp file
    jq --arg cve "${cve_id}" '.[$cve]' /tmp/epyon_cve_groups.json > /tmp/epyon_cve_findings.json

    # Sanitize CVE ID for use as a map key (already safe, but be explicit)
    local safe_key="${cve_id}"

    # Check if we already have a ticket for this CVE
    local existing_cve_key
    existing_cve_key=$(python3 -c "
import json, sys
with open('/tmp/epyon_cve_map_current.json') as f:
    m = json.load(f)
print(m.get(sys.argv[1], ''))
" "${safe_key}" 2>/dev/null || echo "")

    if [[ -n "${existing_cve_key}" ]]; then
      # Verify ticket is still open
      local ticket_http
      ticket_http=$(curl -s -o /tmp/jira_cve_check.json -w "%{http_code}" \
        -H "Authorization: Basic ${AUTH}" \
        -H "Accept: application/json" \
        "${JIRA_URL}/rest/api/3/issue/${existing_cve_key}?fields=status,summary")
      local cve_is_done="false"
      if [[ "${ticket_http}" == "200" ]]; then
        local _sc _scn _sn
        _sc=$(jq -r '.fields.status.statusCategory.key // ""' /tmp/jira_cve_check.json 2>/dev/null || true)
        _scn=$(jq -r '.fields.status.statusCategory.name // ""' /tmp/jira_cve_check.json 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
        _sn=$(jq -r '.fields.status.name // ""' /tmp/jira_cve_check.json 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
        [[ "${_sc}" == "done" ]] && cve_is_done="true"
        [[ "${_scn}" == "done" ]] && cve_is_done="true"
        case "${_sn}" in
          done|closed|resolved|complete|completed|"won't fix"|wontfix|invalid) cve_is_done="true" ;;
        esac
      fi

      if [[ "${cve_is_done}" == "false" ]]; then
        echo "  🔄  ${cve_id} — updating existing ticket ${existing_cve_key}"
        # Add update comment
        local comment_adf
        comment_adf=$(build_cve_adf_body /tmp/epyon_cve_findings.json "${cve_id}" "${sev_label}" "${parent_key}") || true
        echo "${comment_adf}" > /tmp/jira_cve_adf.json
        jq -n --slurpfile body /tmp/jira_cve_adf.json '{body: $body[0]}' > /tmp/jira_cve_comment.json 2>/dev/null || true
        curl -s -o /dev/null \
          -X POST \
          -H "Authorization: Basic ${AUTH}" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json" \
          --data @/tmp/jira_cve_comment.json \
          "${JIRA_URL}/rest/api/3/issue/${existing_cve_key}/comment" || true
        processed=$((processed + 1))
        continue
      else
        echo "  🔁  ${cve_id} — ticket ${existing_cve_key} was closed but CVE reappeared — creating new"
        # Remove old key from map so we create fresh
        python3 -c "
import json
with open('/tmp/epyon_cve_map_current.json') as f: m=json.load(f)
m.pop('${safe_key}', None)
with open('/tmp/epyon_cve_map_current.json','w') as f: json.dump(m,f)
" 2>/dev/null || true
        existing_cve_key=""
      fi
    fi

    # --- Create new CVE ticket ---
    local pkg_count
    pkg_count=$(jq 'length' /tmp/epyon_cve_findings.json 2>/dev/null || echo 1)
    local first_pkg
    first_pkg=$(jq -r '.[0].package_name // .[0].file_path // "unknown"' /tmp/epyon_cve_findings.json 2>/dev/null || echo "unknown")
    local more_label=""
    if [[ "${pkg_count}" -gt 1 ]]; then
      more_label=" (+$((pkg_count - 1)) more)"
    fi
    local is_kev
    is_kev=$(jq -r '[.[] | select(.cisa_kev == true)] | length > 0' /tmp/epyon_cve_findings.json 2>/dev/null || echo "false")
    local kev_prefix=""
    [[ "${is_kev}" == "true" ]] && kev_prefix="🔥 KEV | "

    local ticket_title="${kev_prefix}${cve_id} — ${first_pkg}${more_label} [${sev_label}] ${REPO_NAME##*/}"

    local adf_body
    adf_body=$(build_cve_adf_body /tmp/epyon_cve_findings.json "${cve_id}" "${sev_label}" "${parent_key}") || true
    echo "${adf_body}" > /tmp/jira_cve_adf.json

    # Build payload — include parent key for Jira next-gen hierarchy
    if [[ -n "${parent_key}" ]]; then
      jq -n \
        --arg project  "${PROJECT_KEY}" \
        --arg title    "${ticket_title}" \
        --arg itype    "${CVE_ISSUE_TYPE}" \
        --arg priority "${priority}" \
        --arg lsev     "epyon-${sev_label}" \
        --arg lrepo    "${REPO_SLUG}" \
        --arg parent   "${parent_key}" \
        --slurpfile desc /tmp/jira_cve_adf.json \
        '{fields: {project: {key: $project}, summary: $title, issuetype: {name: $itype},
                   priority: {name: $priority}, description: $desc[0],
                   parent: {key: $parent},
                   labels: ["epyon", "security", "cve", $lsev, $lrepo]}}' > /tmp/jira_cve_payload.json
    else
      jq -n \
        --arg project  "${PROJECT_KEY}" \
        --arg title    "${ticket_title}" \
        --arg itype    "${CVE_ISSUE_TYPE}" \
        --arg priority "${priority}" \
        --arg lsev     "epyon-${sev_label}" \
        --arg lrepo    "${REPO_SLUG}" \
        --slurpfile desc /tmp/jira_cve_adf.json \
        '{fields: {project: {key: $project}, summary: $title, issuetype: {name: $itype},
                   priority: {name: $priority}, description: $desc[0],
                   labels: ["epyon", "security", "cve", $lsev, $lrepo]}}' > /tmp/jira_cve_payload.json
    fi

    local create_http
    create_http=$(curl -s -o /tmp/jira_cve_create.json -w "%{http_code}" \
      -X POST \
      -H "Authorization: Basic ${AUTH}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data @/tmp/jira_cve_payload.json \
      "${JIRA_URL}/rest/api/3/issue")

    if [[ "${create_http}" == "201" ]]; then
      local new_cve_key
      new_cve_key=$(jq -r '.key' /tmp/jira_cve_create.json)
      echo "  ✅  ${cve_id} → ${new_cve_key}"
      echo "- \`${cve_id}\` → [${new_cve_key}](${JIRA_URL}/browse/${new_cve_key}) (${sev_label})" >> "${GITHUB_STEP_SUMMARY}"
      # Store in map
      python3 -c "
import json
with open('/tmp/epyon_cve_map_current.json') as f: m=json.load(f)
m['${safe_key}'] = '${new_cve_key}'
with open('/tmp/epyon_cve_map_current.json','w') as f: json.dump(m,f)
" 2>/dev/null || true
    else
      # If parent field rejected (classic Jira), retry without parent
      if [[ "${create_http}" == "400" ]] && jq -e '.errors.parent' /tmp/jira_cve_create.json >/dev/null 2>&1; then
        echo "  ⚠️  ${cve_id} — parent field rejected (classic Jira?), retrying without parent link"
        jq 'del(.fields.parent)' /tmp/jira_cve_payload.json > /tmp/jira_cve_payload_noparent.json
        create_http=$(curl -s -o /tmp/jira_cve_create.json -w "%{http_code}" \
          -X POST \
          -H "Authorization: Basic ${AUTH}" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json" \
          --data @/tmp/jira_cve_payload_noparent.json \
          "${JIRA_URL}/rest/api/3/issue")
        if [[ "${create_http}" == "201" ]]; then
          local new_cve_key
          new_cve_key=$(jq -r '.key' /tmp/jira_cve_create.json)
          echo "  ✅  ${cve_id} → ${new_cve_key} (standalone)"
          echo "- \`${cve_id}\` → [${new_cve_key}](${JIRA_URL}/browse/${new_cve_key}) (${sev_label}, standalone)" >> "${GITHUB_STEP_SUMMARY}"
          # Add issue link to parent as fallback
          if [[ -n "${parent_key}" ]]; then
            jq -n --arg inward "${new_cve_key}" --arg outward "${parent_key}" \
              '{"type":{"name":"Relates"},"inwardIssue":{"key":$inward},"outwardIssue":{"key":$outward}}' \
              > /tmp/jira_link_payload.json
            curl -s -o /dev/null \
              -X POST \
              -H "Authorization: Basic ${AUTH}" \
              -H "Content-Type: application/json" \
              "${JIRA_URL}/rest/api/3/issueLink" \
              --data @/tmp/jira_link_payload.json || true
          fi
          python3 -c "
import json
with open('/tmp/epyon_cve_map_current.json') as f: m=json.load(f)
m['${safe_key}'] = '${new_cve_key}'
with open('/tmp/epyon_cve_map_current.json','w') as f: json.dump(m,f)
" 2>/dev/null || true
        else
          echo "  ❌  ${cve_id} — failed to create ticket (HTTP ${create_http})"
        fi
      else
        echo "  ❌  ${cve_id} — failed to create ticket (HTTP ${create_http})"
        cat /tmp/jira_cve_create.json 2>/dev/null | head -5 || true
      fi
    fi
    processed=$((processed + 1))
  done <<< "${current_cve_ids}"

  # --- Close tickets for CVEs that are no longer present ---
  local old_cve_ids
  old_cve_ids=$(jq -r 'keys[]' /tmp/epyon_cve_map_current.json 2>/dev/null || true)
  while IFS= read -r old_cve; do
    [[ -z "${old_cve}" ]] && continue
    # Check if still present in current scan
    local still_present
    still_present=$(jq --arg cve "${old_cve}" 'has($cve)' /tmp/epyon_cve_groups.json 2>/dev/null || echo "false")
    if [[ "${still_present}" == "false" ]]; then
      local old_key
      old_key=$(python3 -c "
import json
with open('/tmp/epyon_cve_map_current.json') as f: m=json.load(f)
print(m.get('${old_cve}', ''))
" 2>/dev/null || echo "")
      if [[ -n "${old_key}" ]]; then
        echo "  🔒  ${old_cve} resolved — auto-closing ${old_key}"
        close_jira_ticket "${old_key}" "epyon-${sev_label}-${old_cve}"
        # Remove from map
        python3 -c "
import json
with open('/tmp/epyon_cve_map_current.json') as f: m=json.load(f)
m.pop('${old_cve}', None)
with open('/tmp/epyon_cve_map_current.json','w') as f: json.dump(m,f)
" 2>/dev/null || true
      fi
    fi
  done <<< "${old_cve_ids}"

  # Persist updated CVE map to GitHub issue
  store_cve_map_in_github "${sev_label}" /tmp/epyon_cve_map_current.json
  echo "--- CVE child tickets complete for ${sev_label}: ${processed} processed ---"
}

# ── Main ──────────────────────────────────────────────────────────────────────
# Apply defaults for optional env vars.
ISSUE_TYPE="${ISSUE_TYPE:-Epic}"
TICKET_MODE="${TICKET_MODE:-hybrid}"          # severity | hybrid
CVE_ISSUE_TYPE="${CVE_ISSUE_TYPE:-Story}"     # child issue type for hybrid mode
MAX_CVE_TICKETS="${MAX_CVE_TICKETS:-50}"      # safety cap per severity tier
# Strip any trailing slash from JIRA_URL to prevent double-slash in API paths.
JIRA_URL="${JIRA_URL%/}"

# ── Prefer post-suppression filtered findings if available ───────────────────
# check-severity-gate.sh (and run-epyon-scan-ci.sh) write a -filtered.json
# sibling when .epyon-ignore.yml suppression rules are applied.  Using it here
# ensures JIRA tickets only reflect non-suppressed findings.
_FILTERED_FILE="${FINDINGS_FILE%.json}-filtered.json"
if [[ -f "${_FILTERED_FILE}" ]]; then
  echo "✅ Post-suppression findings found — using: ${_FILTERED_FILE}"
  FINDINGS_FILE="${_FILTERED_FILE}"
  # Re-derive severity counts from the filtered file so ticket creation
  # thresholds match the suppressed-findings view.
  CRITICAL_COUNT=$(jq -r '.summary.total_critical // 0' "${FINDINGS_FILE}" 2>/dev/null || echo "0")
  HIGH_COUNT=$(jq -r     '.summary.total_high     // 0' "${FINDINGS_FILE}" 2>/dev/null || echo "0")
  MEDIUM_COUNT=$(jq -r   '.summary.total_medium   // 0' "${FINDINGS_FILE}" 2>/dev/null || echo "0")
  LOW_COUNT=$(jq -r      '.summary.total_low      // 0' "${FINDINGS_FILE}" 2>/dev/null || echo "0")
  echo "  Filtered counts — Critical: ${CRITICAL_COUNT} | High: ${HIGH_COUNT} | Medium: ${MEDIUM_COUNT} | Low: ${LOW_COUNT}"
else
  echo "ℹ️  No filtered findings file found — using raw findings: ${FINDINGS_FILE}"
fi

echo "=== JIRA Ticket Creation ==="
echo "Project: ${PROJECT_KEY} | Repo: ${REPO_SLUG}"

# Verify auth and project access.
auth_http=$(curl -s -o /tmp/jira_myself.json -w "%{http_code}" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Accept: application/json" \
  "${JIRA_URL}/rest/api/3/myself")
if [[ "${auth_http}" != "200" ]]; then
  echo "❌ JIRA authentication failed (HTTP ${auth_http})."
  cat /tmp/jira_myself.json
  exit 1
fi
echo "✅ JIRA auth OK"

proj_http=$(curl -s -o /tmp/jira_project.json -w "%{http_code}" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Accept: application/json" \
  "${JIRA_URL}/rest/api/3/project/${PROJECT_KEY}")
if [[ "${proj_http}" != "200" ]]; then
  echo "❌ JIRA project '${PROJECT_KEY}' not found (HTTP ${proj_http})."
  cat /tmp/jira_project.json
  exit 1
fi
echo "✅ JIRA project '${PROJECT_KEY}' accessible"

if [[ "${TICKET_MODE}" == "hybrid" ]]; then
  echo "🔀 Ticket mode: hybrid (severity parent + per-CVE child tickets)"
  echo "## Hybrid Ticket Mode" >> "${GITHUB_STEP_SUMMARY}"
  echo "One parent ticket per severity tier with individual child tickets per CVE." >> "${GITHUB_STEP_SUMMARY}"
else
  echo "🎟️  Ticket mode: severity (one ticket per severity tier)"
fi

# Titles intentionally omit the date — one stable title per severity+repo so label
# searches reliably find the existing open ticket across multiple scan runs.
# The date appears in the ticket description and in update comments.
if [[ "${CRITICAL_COUNT:-0}" -gt 0 ]]; then
  rm -f /tmp/epyon_last_jira_key.txt
  create_jira_ticket \
    "Epyon Critical Security Findings - ${REPO_NAME##*/}" \
    "epyon-critical" "Highest" "critical_findings" \
    "Epyon found ${CRITICAL_COUNT} critical severity finding(s) in ${REPO_NAME} on ${TODAY}." || true
  if [[ "${TICKET_MODE}" == "hybrid" ]] && [[ -f /tmp/epyon_last_jira_key.txt ]]; then
    _parent_key=$(cat /tmp/epyon_last_jira_key.txt)
    create_cve_tickets "${_parent_key}" "critical" "Highest" "critical_findings" || true
  fi
else
  maybe_close_jira_ticket "epyon-critical" "${CRITICAL_COUNT:-0}" || true
fi

if [[ "${HIGH_COUNT:-0}" -gt 0 ]]; then
  rm -f /tmp/epyon_last_jira_key.txt
  create_jira_ticket \
    "Epyon High Security Findings - ${REPO_NAME##*/}" \
    "epyon-high" "High" "high_findings" \
    "Epyon found ${HIGH_COUNT} high severity finding(s) in ${REPO_NAME} on ${TODAY}." || true
  if [[ "${TICKET_MODE}" == "hybrid" ]] && [[ -f /tmp/epyon_last_jira_key.txt ]]; then
    _parent_key=$(cat /tmp/epyon_last_jira_key.txt)
    create_cve_tickets "${_parent_key}" "high" "High" "high_findings" || true
  fi
else
  maybe_close_jira_ticket "epyon-high" "${HIGH_COUNT:-0}" || true
fi

if [[ "${MEDIUM_COUNT:-0}" -gt 0 ]]; then
  rm -f /tmp/epyon_last_jira_key.txt
  create_jira_ticket \
    "Epyon Medium Security Findings - ${REPO_NAME##*/}" \
    "epyon-medium" "Medium" "medium_findings" \
    "Epyon found ${MEDIUM_COUNT} medium severity finding(s) in ${REPO_NAME} on ${TODAY}." || true
  if [[ "${TICKET_MODE}" == "hybrid" ]] && [[ -f /tmp/epyon_last_jira_key.txt ]]; then
    _parent_key=$(cat /tmp/epyon_last_jira_key.txt)
    create_cve_tickets "${_parent_key}" "medium" "Medium" "medium_findings" || true
  fi
else
  maybe_close_jira_ticket "epyon-medium" "${MEDIUM_COUNT:-0}" || true
fi

if [[ "${LOW_COUNT:-0}" -gt 0 ]]; then
  rm -f /tmp/epyon_last_jira_key.txt
  create_jira_ticket \
    "Epyon Low Security Findings - ${REPO_NAME##*/}" \
    "epyon-low" "Low" "low_findings" \
    "Epyon found ${LOW_COUNT} low severity finding(s) in ${REPO_NAME} on ${TODAY}." || true
  if [[ "${TICKET_MODE}" == "hybrid" ]] && [[ -f /tmp/epyon_last_jira_key.txt ]]; then
    _parent_key=$(cat /tmp/epyon_last_jira_key.txt)
    create_cve_tickets "${_parent_key}" "low" "Low" "low_findings" || true
  fi
else
  maybe_close_jira_ticket "epyon-low" "${LOW_COUNT:-0}" || true
fi
