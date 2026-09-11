#!/bin/bash
set -euo pipefail

# Export SSP / ATO Control Evidence & Artifact Mapping Matrix
# Maps NIST SP 800-53 / FedRAMP controls to Epyon scan artifacts

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    echo "Usage: $0 <scan_directory>"
    echo ""
    echo "Exports NIST SP 800-53 / FedRAMP control evidence matrix for SSP / ATO documentation."
    echo ""
    echo "Outputs:"
    echo "  - {scan_dir}/ssp-ato-evidence-package.json"
    echo "  - {scan_dir}/ssp-ato-evidence-matrix.md"
    exit 0
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_help
fi

if [[ $# -lt 1 ]]; then
    echo -e "${RED}❌ Error: Scan directory argument required.${NC}"
    show_help
fi

SCAN_DIR="$1"
if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: Directory not found: $SCAN_DIR${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo -e "${PURPLE}============================================${NC}"
echo -e "${PURPLE}📑 Exporting SSP / ATO Control Evidence Package${NC}"
echo -e "${PURPLE}============================================${NC}"

python3 -c "
import sys, json, pathlib
sys.path.insert(0, '$REPO_ROOT/web/api')
try:
    import parsers
    scan_path = pathlib.Path('$SCAN_DIR')
    matrix_data = parsers.parse_ssp_evidence_matrix(scan_path)
    md_content = parsers.generate_ssp_evidence_markdown(matrix_data)
    
    json_out = scan_path / 'ssp-ato-evidence-package.json'
    md_out = scan_path / 'ssp-ato-evidence-matrix.md'
    
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(matrix_data, f, indent=2)
        
    with open(md_out, 'w', encoding='utf-8') as f:
        f.write(md_content)
        
    print('  ✅ JSON Package: ' + str(json_out))
    print('  ✅ Markdown Matrix: ' + str(md_out))
except Exception as e:
    print('  ❌ Error exporting SSP evidence:', str(e), file=sys.stderr)
    sys.exit(1)
"

echo -e "${GREEN}✅ SSP / ATO Evidence Package exported successfully${NC}"
