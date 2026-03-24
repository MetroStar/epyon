#!/usr/bin/env bash

# Embed Metrics Chart in Security Dashboard
# Takes aggregated metrics JSON and injects it as an interactive chart
# into the security dashboard HTML

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat << 'EOF'
Embed Metrics Chart in Security Dashboard

Usage: embed-metrics-in-dashboard.sh [OPTIONS]

Reads aggregated metrics JSON and injects a time-series chart
into the security dashboard HTML for visualization.

Options:
  -m, --metrics FILE          Path to metrics JSON (required)
  -d, --dashboard FILE        Path to dashboard HTML (or use DASHBOARD_FILE env var)
  -o, --output FILE           Output HTML file (default: replaces input)
    --chart-type TYPE           Chart type: line, area, bar (default: bar)
  --max-points NUM            Max data points to display (default: 90)
  -q, --quiet                 Suppress output
  -h, --help                  Show this help message

Examples:
  embed-metrics-in-dashboard.sh --metrics metrics-90d.json --dashboard dashboard.html
  embed-metrics-in-dashboard.sh -m metrics-90d.json -d dashboard.html -o dashboard-with-metrics.html

Requirements:
  - jq for JSON processing
  - Metrics JSON from collect-metrics-from-github.sh

EOF
    exit 0
}

# ─── Defaults ────────────────────────────────────────────────────────
METRICS_FILE=""
DASHBOARD_FILE=""
OUTPUT_FILE=""
CHART_TYPE="bar"
MAX_POINTS=90
QUIET=false

# ─── Parse Arguments ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--metrics)       METRICS_FILE="$2"; shift 2 ;;
        -d|--dashboard)     DASHBOARD_FILE="$2"; shift 2 ;;
        -o|--output)        OUTPUT_FILE="$2"; shift 2 ;;
        --chart-type)       CHART_TYPE="$2"; shift 2 ;;
        --max-points)       MAX_POINTS="$2"; shift 2 ;;
        -q|--quiet)         QUIET=true; shift ;;
        -h|--help)          show_help ;;
        *)                  echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ─── Validate inputs ────────────────────────────────────────────────
if [[ ! -f "$METRICS_FILE" ]]; then
    echo "❌ Metrics file not found: $METRICS_FILE" >&2
    exit 1
fi

if [[ -z "$DASHBOARD_FILE" ]]; then
    DASHBOARD_FILE="${DASHBOARD_FILE:-.}"
fi

if [[ ! -f "$DASHBOARD_FILE" ]]; then
    echo "❌ Dashboard file not found: $DASHBOARD_FILE" >&2
    exit 1
fi

# Set output file
OUTPUT_FILE="${OUTPUT_FILE:-$DASHBOARD_FILE}"

# ─── Extract metrics data for chart ────────────────────────────────
[[ "$QUIET" == false ]] && echo -e "${BLUE}📊 Extracting metrics for dashboard...${NC}" >&2

METRICS=$(jq -c --argjson max_points "$MAX_POINTS" '
        (.trend // .metrics // [])
        | map({
                scan_id: .scan_id,
                timestamp: .scan_timestamp,
                date: ((.scan_timestamp // "")[:10]),
                target: .target_name,
                critical: (.critical // 0),
                high: (.high // 0),
                medium: (.medium // 0),
                low: (.low // 0),
                total: ((.critical // 0) + (.high // 0) + (.medium // 0) + (.low // 0))
            })
        | map(select(.date != ""))
        | sort_by(.date, .timestamp)
        | group_by(.date)
        | map({
                scan_id: (max_by(.total).scan_id),
                timestamp: (.[-1].timestamp),
                target: (max_by(.total).target),
                critical: ((map(.critical) | max) // 0),
                high: ((map(.high) | max) // 0),
                medium: ((map(.medium) | max) // 0),
                low: ((map(.low) | max) // 0)
            })
        | sort_by(.timestamp)
        | .[-$max_points:]
' "$METRICS_FILE" 2>/tmp/jq-error.log)

if [[ "$METRICS" == "[]" ]] || [[ -z "$METRICS" ]]; then
    [[ "$QUIET" == false ]] && echo -e "${YELLOW}⚠️  No metrics data to chart${NC}" >&2
    [[ "$QUIET" == false ]] && echo "    Checking metrics file: $METRICS_FILE" >&2
    if [[ "$QUIET" == false ]]; then
        # Debug: show what we actually extracted
        echo "    Raw extraction: $(jq '(.trend // .metrics // []) | length' "$METRICS_FILE" 2>/dev/null || echo "ERROR")" >&2
        if [[ -f /tmp/jq-error.log ]] && [[ -s /tmp/jq-error.log ]]; then
            echo "    jq error: $(cat /tmp/jq-error.log)" >&2
        fi
    fi
    exit 0
fi

# ─── Generate Chart Container HTML ─────────────────────────────────
CHART_HTML=$(cat << 'CHART_EOF'
        <!-- Metrics Time-Series Chart -->
        <div class="metrics-chart-section" style="margin: 30px 0; padding: 20px; background: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb;">
            <h2 style="font-size: 1.5em; margin-bottom: 20px; color: #1f2937;">📊 90-Day Metrics Trend</h2>
            
            <div style="overflow-x: auto;">
                <canvas id="metricsChart" width="400" height="100"></canvas>
            </div>
            
            <div id="metricsStats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
                <!-- Stats will be populated by JavaScript -->
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
        <script>
        (function() {
            const metricsData = METRICS_DATA_PLACEHOLDER;
            
            if (!metricsData || metricsData.length === 0) {
                document.getElementById('metricsChart').style.display = 'none';
                return;
            }
            
            // Prepare data for Chart.js
            const labels = metricsData.map(m => {
                const date = new Date(m.timestamp);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const criticalData = metricsData.map(m => m.critical || 0);
            const highData = metricsData.map(m => m.high || 0);
            const mediumData = metricsData.map(m => m.medium || 0);
            const lowData = metricsData.map(m => m.low || 0);
            
            // Create Chart
            const ctx = document.getElementById('metricsChart').getContext('2d');
            const chart = new Chart(ctx, {
                type: 'CHART_TYPE_PLACEHOLDER',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Critical',
                            data: criticalData,
                            borderColor: '#DC2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.75)',
                            borderWidth: 2,
                            tension: 0.4,
                            fill: false,
                            stack: 'severity'
                        },
                        {
                            label: 'High',
                            data: highData,
                            borderColor: '#F97316',
                            backgroundColor: 'rgba(249, 115, 22, 0.75)',
                            borderWidth: 2,
                            tension: 0.4,
                            fill: false,
                            stack: 'severity'
                        },
                        {
                            label: 'Medium',
                            data: mediumData,
                            borderColor: '#EAB308',
                            backgroundColor: 'rgba(234, 179, 8, 0.75)',
                            borderWidth: 2,
                            tension: 0.4,
                            fill: false,
                            stack: 'severity'
                        },
                        {
                            label: 'Low',
                            data: lowData,
                            borderColor: '#22C55E',
                            backgroundColor: 'rgba(34, 197, 94, 0.75)',
                            borderWidth: 2,
                            tension: 0.4,
                            fill: false,
                            stack: 'severity'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                font: { size: 12 },
                                padding: 15,
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(31, 41, 55, 0.9)',
                            titleColor: '#fff',
                            bodyColor: '#f3f4f6',
                            borderColor: '#4b5563',
                            borderWidth: 1,
                            padding: 12,
                            displayColors: true,
                            callbacks: {
                                afterLabel: function(ctx) {
                                    const dataIndex = ctx.dataIndex;
                                    const metric = metricsData[dataIndex];
                                    return '→ ' + metric.target;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            stacked: true,
                            title: { display: true, text: 'Findings Count' },
                            ticks: { color: '#6b7280' },
                            grid: { color: 'rgba(0,0,0,0.05)' }
                        },
                        x: {
                            stacked: true,
                            ticks: { color: '#6b7280' },
                            grid: { color: 'rgba(0,0,0,0.05)' }
                        }
                    }
                }
            });
            
            // Populate stats
            const statsDiv = document.getElementById('metricsStats');
            const latestMetric = metricsData[metricsData.length - 1];
            const avgCritical = (criticalData.reduce((a, b) => a + b, 0) / criticalData.length).toFixed(1);
            const avgHigh = (highData.reduce((a, b) => a + b, 0) / highData.length).toFixed(1);
            
            statsDiv.innerHTML = `
                <div style="background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #DC2626;">
                    <div style="color: #6b7280; font-size: 0.85em; margin-bottom: 5px;">Latest Critical</div>
                    <div style="font-size: 1.8em; font-weight: bold; color: #DC2626;">${latestMetric.critical}</div>
                </div>
                <div style="background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #F97316;">
                    <div style="color: #6b7280; font-size: 0.85em; margin-bottom: 5px;">Latest High</div>
                    <div style="font-size: 1.8em; font-weight: bold; color: #F97316;">${latestMetric.high}</div>
                </div>
                <div style="background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #EAB308;">
                    <div style="color: #6b7280; font-size: 0.85em; margin-bottom: 5px;">Avg Critical</div>
                    <div style="font-size: 1.8em; font-weight: bold; color: #EAB308;">${avgCritical}</div>
                </div>
                <div style="background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #22C55E;">
                    <div style="color: #6b7280; font-size: 0.85em; margin-bottom: 5px;">Avg High</div>
                    <div style="font-size: 1.8em; font-weight: bold; color: #22C55E;">${avgHigh}</div>
                </div>
            `;
        })();
        </script>
CHART_EOF
)

# ─── Inject into dashboard ──────────────────────────────────────────
[[ "$QUIET" == false ]] && echo -e "${BLUE}💉 Injecting metrics chart into dashboard...${NC}" >&2

# Replace placeholders
CHART_HTML="${CHART_HTML//METRICS_DATA_PLACEHOLDER/$(echo "$METRICS" | jq -c '.')}"
CHART_HTML="${CHART_HTML//CHART_TYPE_PLACEHOLDER/$CHART_TYPE}"

# Find injection point (before closing </body> tag or append if absent)
if grep -q "</body>" "$DASHBOARD_FILE"; then
    # Write chart HTML to a temp file, then use awk to insert it before </body>
    TEMP_HTML=$(mktemp)
    echo "$CHART_HTML" > "$TEMP_HTML"
    awk -v chart_file="$TEMP_HTML" '
        /<\/body>/ {
            while ((getline line < chart_file) > 0) print line
            close(chart_file)
        }
        { print }
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp" && mv "${DASHBOARD_FILE}.tmp" "$DASHBOARD_FILE"
    rm -f "$TEMP_HTML"
else
    # Append to file
    echo "$CHART_HTML" >> "$DASHBOARD_FILE"
fi

# ─── Save output ────────────────────────────────────────────────────
if [[ "$OUTPUT_FILE" != "$DASHBOARD_FILE" ]]; then
    cp "$DASHBOARD_FILE" "$OUTPUT_FILE"
fi

[[ "$QUIET" == false ]] && echo -e "${GREEN}✅ Metrics chart embedded successfully${NC}" >&2
[[ "$QUIET" == false ]] && echo -e "${GREEN}📄 Updated dashboard: $OUTPUT_FILE${NC}" >&2

exit 0
