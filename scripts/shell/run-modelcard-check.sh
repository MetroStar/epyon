#!/bin/bash

# Layer 15 — Model Card Compliance Checker
# Validates HuggingFace-style model cards (README.md) against required documentation
# standards. Checks for required sections, YAML frontmatter fields, and license info.
# No Docker required — pure bash + Python.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Layer 15 — Model Card Compliance Checker${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Validates HuggingFace model card documentation against required standards."
    echo "Checks for required sections, metadata fields, and license information."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Directory to scan (default: current directory)"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Required sections checked:"
    echo "  - Model Details / About"
    echo "  - Intended Use"
    echo "  - Limitations / Out of Scope"
    echo "  - Training Data"
    echo "  - Bias, Risks, and Limitations"
    echo "  - License (YAML frontmatter)"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/modelcard/"
    echo "  - modelcard-results.json    Normalized compliance report"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Check current directory"
    echo "  TARGET_DIR=/path/to/hf-model-repo $0   # Check specific repo"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "modelcard"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "ERROR: Target path does not exist or is invalid: ${TARGET_SCAN_DIR}" >&2
    exit 1
}

if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_$(whoami)_${TIMESTAMP}"
fi

RESULTS_FILE="$OUTPUT_DIR/modelcard-results.json"
SCAN_LOG_FILE="$OUTPUT_DIR/modelcard.log"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Layer 15 — Model Card Compliance Checker${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory : $TARGET_SCAN_DIR"
echo "Output Directory : $OUTPUT_DIR"
echo "Timestamp        : $TIMESTAMP"
echo "" | tee "$SCAN_LOG_FILE"

# ── Locate model card file ───────────────────────────────────────────────────
MODEL_CARD_FILE=""
for candidate in "README.md" "MODEL_CARD.md" "model_card.md" "MODELCARD.md"; do
    if [[ -f "$TARGET_SCAN_DIR/$candidate" ]]; then
        MODEL_CARD_FILE="$TARGET_SCAN_DIR/$candidate"
        break
    fi
done

if [[ -z "$MODEL_CARD_FILE" ]]; then
    echo -e "${YELLOW}⚠️  No model card found (README.md or MODEL_CARD.md) — skipping${NC}" | tee -a "$SCAN_LOG_FILE"
    cat > "$RESULTS_FILE" <<EOF
{
  "tool":           "modelcard",
  "status":         "skipped",
  "reason":         "no model card file found (README.md or MODEL_CARD.md)",
  "scan_id":        "${SCAN_ID}",
  "target":         "${TARGET_SCAN_DIR}",
  "generated_at":   "${GENERATED_AT}",
  "file_checked":   null,
  "passed":         0,
  "failed":         0,
  "warnings":       0,
  "findings":       []
}
EOF
    record_scan_status "skipped" "no model card file found"
    exit 0
fi

echo "Model card file  : $MODEL_CARD_FILE" | tee -a "$SCAN_LOG_FILE"
echo "" | tee -a "$SCAN_LOG_FILE"

# ── Run compliance checks via Python ─────────────────────────────────────────
python3 - <<PYEOF 2>&1 | tee -a "$SCAN_LOG_FILE"
import json
import re
import sys

MODEL_CARD_FILE = "${MODEL_CARD_FILE}"
RESULTS_FILE    = "${RESULTS_FILE}"
SCAN_ID         = "${SCAN_ID}"
TARGET          = "${TARGET_SCAN_DIR}"
GENERATED_AT    = "${GENERATED_AT}"

# ── Read file ────────────────────────────────────────────────────────────────
try:
    content = open(MODEL_CARD_FILE, encoding="utf-8", errors="replace").read()
except OSError as e:
    print(f"ERROR: Cannot read {MODEL_CARD_FILE}: {e}")
    sys.exit(1)

content_lower = content.lower()
findings = []
passed   = 0

def check(name, severity, condition, message, recommendation):
    global passed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        findings.append({
            "check":          name,
            "severity":       severity,
            "message":        message,
            "recommendation": recommendation,
        })
        icon = "FAIL" if severity in ("high", "medium") else "WARN"
        print(f"  {icon}  {name}: {message}")

# ── Parse YAML frontmatter ───────────────────────────────────────────────────
frontmatter = {}
fm_match = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
if fm_match:
    fm_text = fm_match.group(1)
    for line in fm_text.splitlines():
        m = re.match(r'^(\w[\w-]*):\s*(.+)', line.strip())
        if m:
            frontmatter[m.group(1).lower()] = m.group(2).strip()

print("Checking model card compliance...")
print("")

# ── Section checks ───────────────────────────────────────────────────────────
SECTION_CHECKS = [
    (
        "model-details",
        "medium",
        r'#+\s*(model\s+details?|about\s+the\s+model|overview|description|key\s+feature|specification|capabilit|parameter|architecture|model\s+info|introduction|summary)',
        "Missing 'Model Details' section",
        "Add a '## Model Details' section (or similar: 'Key Features', 'Overview', 'Architecture') describing the model.",
    ),
    (
        "intended-use",
        "high",
        r'#+\s*(intended\s+use|use\s+cases?|primary\s+use|direct\s+use|downstream\s+use|\busage\b|quickstart|getting\s+started|how\s+to\s+use|inference|fine.?tun|deploy|application)',
        "Missing 'Intended Use' section",
        "Add an '## Intended Use' or '## Usage' section describing what the model is designed for.",
    ),
    (
        "limitations",
        "medium",
        r'#+\s*(limitation|out[\s-]+of[\s-]+scope|known[\s-]+issue|caveat|restriction|not\s+suitable|disclaimer|what.{0,20}model\s+can.t|cannot\s+do)',
        "No 'Limitations' section found",
        "Add a '## Limitations' section describing known model limitations and out-of-scope uses.",
    ),
    (
        "training-data",
        "low",
        r'#+\s*(training[\s-]+data|dataset|data[\s-]+source|pretraining|pretrain|base[\s-]+model|data[\s-]+mix|corpus|training[\s-]+detail)',
        "No 'Training Data' section found",
        "Add a '## Training Data' section (or mention datasets/pretraining) describing training data provenance.",
    ),
    (
        "bias-risks",
        "high",
        r'#+\s*(bias|risk|fairness|harm|ethic|responsible|safety[\s-]+consideration|content[\s-]+polic|alignment|trust|misuse)',
        "No 'Bias/Risks' section found",
        "Add a '## Bias, Risks, and Limitations' section covering known biases and ethical considerations.",
    ),
    (
        "evaluation",
        "low",
        r'#+\s*(evaluat|benchmark|performance|metric|result)',
        "Missing 'Evaluation' section",
        "Add an '## Evaluation' section with benchmark results and performance metrics.",
    ),
]

for check_id, severity, pattern, message, recommendation in SECTION_CHECKS:
    check(check_id, severity, bool(re.search(pattern, content_lower)), message, recommendation)

# ── Frontmatter checks ───────────────────────────────────────────────────────
check(
    "license-field",
    "high",
    "license" in frontmatter and bool(frontmatter["license"].strip()),
    "No 'license' field in YAML frontmatter",
    "Add 'license: <spdx-id>' to the YAML frontmatter (e.g. 'license: apache-2.0').",
)

check(
    "language-field",
    "low",
    "language" in frontmatter or "languages" in frontmatter,
    "No 'language' field in YAML frontmatter",
    "Add 'language: en' (or appropriate BCP-47 codes) to the YAML frontmatter.",
)

check(
    "tags-field",
    "low",
    "tags" in frontmatter or bool(re.search(r'^tags:', content_lower, re.MULTILINE)),
    "No 'tags' field in YAML frontmatter",
    "Add 'tags:' to the YAML frontmatter to improve model discoverability.",
)

# ── Safetensors recommendation ───────────────────────────────────────────────
has_bin_mention    = bool(re.search(r'\.bin|pytorch_model', content_lower))
has_safe_mention   = bool(re.search(r'safetensors', content_lower))
pickle_risk_mention = has_bin_mention and not has_safe_mention

check(
    "safetensors-format",
    "medium",
    not pickle_risk_mention,
    "Model appears to use .bin (pickle) format without mentioning safetensors",
    "Consider providing weights in .safetensors format (immune to pickle code execution) and document the format used.",
)

# ── Summary ──────────────────────────────────────────────────────────────────
total   = passed + len(findings)
failed  = len([f for f in findings if f["severity"] in ("high", "medium")])
warnings = len([f for f in findings if f["severity"] == "low"])
status  = "open" if failed > 0 else ("warning" if warnings > 0 else "success")

print("")
print(f"Results: {passed}/{total} checks passed — {failed} failure(s), {warnings} warning(s)")

result = {
    "tool":         "modelcard",
    "status":       status,
    "scan_id":      SCAN_ID,
    "target":       TARGET,
    "generated_at": GENERATED_AT,
    "file_checked": MODEL_CARD_FILE,
    "passed":       passed,
    "failed":       failed,
    "warnings":     warnings,
    "findings":     findings,
}

with open(RESULTS_FILE, "w") as f:
    json.dump(result, f, indent=2)

print(f"Results written to {RESULTS_FILE}")
sys.exit(0 if status == "success" else (1 if failed > 0 else 0))
PYEOF

PYEXIT=$?

echo ""

if [[ ! -f "$RESULTS_FILE" ]]; then
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "modelcard",
  "status": "failed",
  "reason": "compliance check script failed unexpectedly",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "${GENERATED_AT}",
  "file_checked": null,
  "passed": 0,
  "failed": 0,
  "warnings": 0,
  "findings": []
}
EOF
fi

STATUS=$(python3 -c "import json; print(json.load(open('${RESULTS_FILE}')).get('status','success'))" 2>/dev/null || echo "success")
FAILED=$(python3 -c "import json; print(json.load(open('${RESULTS_FILE}')).get('failed',0))" 2>/dev/null || echo "0")
WARNINGS=$(python3 -c "import json; print(json.load(open('${RESULTS_FILE}')).get('warnings',0))" 2>/dev/null || echo "0")

if [[ "$STATUS" == "open" ]]; then
    record_scan_status "failed" "${FAILED} compliance check(s) failed"
    echo -e "${RED}❌ Model card compliance: ${FAILED} failure(s), ${WARNINGS} warning(s)${NC}"
    exit 1
elif [[ "$STATUS" == "warning" ]]; then
    record_scan_status "success" "${WARNINGS} low-severity warning(s)"
    echo -e "${YELLOW}⚠️  Model card compliance: ${WARNINGS} warning(s) — review recommended${NC}"
    exit 0
else
    record_scan_status "success" ""
    echo -e "${GREEN}✅ Model card compliance check passed${NC}"
    exit 0
fi
