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
#   GITHUB_STEP_SUMMARY    — path to the GitHub step summary file

set -euo pipefail

# ── Helper: search for an existing open JIRA ticket by label ──────────────────
jira_search_open() {
  local label="$1"
  # Use statusCategory != Done — works on all Jira Cloud instances unlike 'resolution = Unresolved'
  local jql="project = \"${PROJECT_KEY}\" AND labels = \"${label}\" AND labels = \"${REPO_SLUG}\" AND statusCategory != Done ORDER BY created DESC"
  local encoded_jql
  encoded_jql=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "${jql}")
  curl -s -o /tmp/jira_search.json -w "%{http_code}" \
    -H "Authorization: Basic ${AUTH}" \
    -H "Accept: application/json" \
    "${JIRA_URL}/rest/api/3/issue/search?jql=${encoded_jql}&maxResults=1"
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

adf = {"version": 1, "type": "doc",
       "content": [
           *kev_panel_blocks,
           {"type": "paragraph", "content": [{"type": "text", "text": summary_line}]},
           table,
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

  # Collect all current vuln IDs for this severity (dedup + tracking marker).
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

  echo "--- Checking for existing open ticket: ${label_severity} / ${REPO_SLUG} ---"
  local http_code
  http_code=$(jira_search_open "${label_severity}")

  if [[ "${http_code}" == "200" ]]; then
    local total
    total=$(jq '.total // 0' /tmp/jira_search.json)
    if [[ "${total}" -gt 0 ]]; then
      local existing_key
      existing_key=$(jq -r '.issues[0].key' /tmp/jira_search.json)

      # Fetch comments (newest-first) and extract the stored tracking marker.
      local stored_ids_json='[]'
      local comments_http
      comments_http=$(curl -s -o /tmp/jira_comments.json -w "%{http_code}" \
        -H "Authorization: Basic ${AUTH}" \
        -H "Accept: application/json" \
        "${JIRA_URL}/rest/api/3/issue/${existing_key}/comment?maxResults=50&orderBy=-created" 2>/dev/null || echo "")
      if [[ "${comments_http}" == "200" ]] && [[ -f /tmp/jira_comments.json ]]; then
        stored_ids_json=$(python3 - <<'JIRA_EXTCMT'
import json, re, sys
def extract_text(node):
    if isinstance(node, dict):
        if node.get('type') == 'text':
            yield node.get('text', '')
        for child in (node.get('content') or []):
            yield from extract_text(child)
with open('/tmp/jira_comments.json') as f:
    data = json.load(f)
for comment in data.get('comments', []):
    body_text = ' '.join(extract_text(comment.get('body', {})))
    m = re.search(r'\[epyon-tracked-vuln-ids:(\[.*?\])\]', body_text)
    if m:
        print(m.group(1))
        sys.exit(0)
print('[]')
JIRA_EXTCMT
        ) 2>/dev/null || stored_ids_json='[]'
      fi

      # Fall back to ticket description if no comment tracking marker found.
      if [[ "${stored_ids_json}" == "[]" ]]; then
        local issue_http
        issue_http=$(curl -s -o /tmp/jira_issue_desc.json -w "%{http_code}" \
          -H "Authorization: Basic ${AUTH}" \
          -H "Accept: application/json" \
          "${JIRA_URL}/rest/api/3/issue/${existing_key}?fields=description" 2>/dev/null || echo "")
        if [[ "${issue_http}" == "200" ]] && [[ -f /tmp/jira_issue_desc.json ]]; then
          stored_ids_json=$(python3 - <<'JIRA_EXTDESC'
import json, re
def extract_text(node):
    if isinstance(node, dict):
        if node.get('type') == 'text':
            yield node.get('text', '')
        for child in (node.get('content') or []):
            yield from extract_text(child)
with open('/tmp/jira_issue_desc.json') as f:
    data = json.load(f)
desc = data.get('fields', {}).get('description') or {}
body_text = ' '.join(extract_text(desc))
m = re.search(r'\[epyon-tracked-vuln-ids:(\[.*?\])\]', body_text)
print(m.group(1) if m else '[]')
JIRA_EXTDESC
          ) 2>/dev/null || stored_ids_json='[]'
        fi
      fi

      # Diff: IDs present now but not yet tracked.
      local new_vuln_ids_json
      new_vuln_ids_json=$(python3 - "${current_ids_json}" "${stored_ids_json}" <<'JIRA_DIFF'
import json, sys
current    = json.loads(sys.argv[1])
stored_set = set(json.loads(sys.argv[2]))
print(json.dumps([i for i in current if i not in stored_set]))
JIRA_DIFF
      ) 2>/dev/null || new_vuln_ids_json='[]'
      local new_vuln_count
      new_vuln_count=$(python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())))" <<< "${new_vuln_ids_json}" 2>/dev/null || echo "0")

      if [[ "${new_vuln_count}" -eq 0 ]]; then
        echo "⏭️  JIRA ticket ${existing_key}: no new vulnerabilities — skipping comment"
        echo "${existing_key}|${JIRA_URL}/browse/${existing_key}" >> /tmp/jira_created_tickets.txt
        return 0
      fi

      echo "🔄  Open ticket ${existing_key} — ${new_vuln_count} new vuln(s), adding update comment"
      echo "## 🔄 JIRA: Updated findings comment added" >> "${GITHUB_STEP_SUMMARY}"
      echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
      echo "- Ticket: [${existing_key}](${JIRA_URL}/browse/${existing_key})" >> "${GITHUB_STEP_SUMMARY}"

      local update_summary="Epyon detected ${new_vuln_count} new ${label_severity} finding(s) in ${REPO_NAME} on $(date -u +%Y-%m-%d)."
      local comment_adf
      comment_adf=$(build_adf_body "${severity_key}" "${update_summary}" "${new_vuln_ids_json}" "${current_ids_json}")
      curl -s -o /dev/null \
        -X POST \
        -H "Authorization: Basic ${AUTH}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$(jq -n --argjson body "${comment_adf}" '{body: $body}')" \
        "${JIRA_URL}/rest/api/3/issue/${existing_key}/comment"
      echo "${existing_key}|${JIRA_URL}/browse/${existing_key}" >> /tmp/jira_created_tickets.txt
      return 0
    fi
  elif [[ "${http_code}" == "404" || "${http_code}" == "400" ]]; then
    # 404/400 = labels don't exist in this project yet — no open ticket, proceed to create.
    echo "ℹ️  No existing label '${label_severity}' in project (HTTP ${http_code}) — creating new ticket"
  else
    echo "⚠️  JIRA search returned HTTP ${http_code} — proceeding to create ticket anyway"
  fi

  echo "--- Creating new ticket for ${label_severity} ---"
  local adf_body
  adf_body=$(build_adf_body "${severity_key}" "${summary_line}" "" "${current_ids_json}")

  jq -n \
    --arg project  "${PROJECT_KEY}" \
    --arg title    "${title}" \
    --arg itype    "${ISSUE_TYPE}" \
    --arg priority "${priority}" \
    --arg lsev     "${label_severity}" \
    --arg lrepo    "${REPO_SLUG}" \
    --argjson desc "${adf_body}" \
    '{fields: {project: {key: $project}, summary: $title, issuetype: {name: $itype},
               priority: {name: $priority}, description: $desc,
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
    echo "✅ Created JIRA ticket: ${new_key}"
    echo "## ✅ JIRA Ticket Created" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Severity group: **${label_severity}**" >> "${GITHUB_STEP_SUMMARY}"
    echo "- Ticket: [${new_key}](${JIRA_URL}/browse/${new_key})" >> "${GITHUB_STEP_SUMMARY}"
    echo "${new_key}|${JIRA_URL}/browse/${new_key}" >> /tmp/jira_created_tickets.txt
    link_jira_to_github "${new_key}"

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

# ── Main ──────────────────────────────────────────────────────────────────────
# Apply defaults for optional env vars.
ISSUE_TYPE="${ISSUE_TYPE:-Bug}"
# Strip any trailing slash from JIRA_URL to prevent double-slash in API paths.
JIRA_URL="${JIRA_URL%/}"

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

# Titles intentionally omit the date — one stable title per severity+repo so label
# searches reliably find the existing open ticket across multiple scan runs.
# The date appears in the ticket description and in update comments.
if [[ "${CRITICAL_COUNT:-0}" -gt 0 ]]; then
  create_jira_ticket \
    "🔴 [Epyon] Critical Security Findings — ${REPO_NAME##*/}" \
    "epyon-critical" "Highest" "critical_findings" \
    "Epyon found ${CRITICAL_COUNT} critical severity finding(s) in ${REPO_NAME} on ${TODAY}."
fi

if [[ "${HIGH_COUNT:-0}" -gt 0 ]]; then
  create_jira_ticket \
    "🟠 [Epyon] High Security Findings — ${REPO_NAME##*/}" \
    "epyon-high" "High" "high_findings" \
    "Epyon found ${HIGH_COUNT} high severity finding(s) in ${REPO_NAME} on ${TODAY}."
fi

if [[ "${MEDIUM_COUNT:-0}" -gt 0 ]]; then
  create_jira_ticket \
    "🟡 [Epyon] Medium Security Findings — ${REPO_NAME##*/}" \
    "epyon-medium" "Medium" "medium_findings" \
    "Epyon found ${MEDIUM_COUNT} medium severity finding(s) in ${REPO_NAME} on ${TODAY}."
fi

if [[ "${LOW_COUNT:-0}" -gt 0 ]]; then
  create_jira_ticket \
    "🔵 [Epyon] Low Security Findings — ${REPO_NAME##*/}" \
    "epyon-low" "Low" "low_findings" \
    "Epyon found ${LOW_COUNT} low severity finding(s) in ${REPO_NAME} on ${TODAY}."
fi
