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
  --pr-repo REPO              GitHub repo to count merged PRs (e.g. owner/repo; optional)
  --pr-base-branch BRANCH     Base branch for PR counts (default: main)
  --pr-since DATE             Only count PRs merged on or after DATE (YYYY-MM-DD)
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
PR_REPO=""
PR_BASE_BRANCH="main"
PR_SINCE=""
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
        --pr-repo)          PR_REPO="$2"; shift 2 ;;
        --pr-base-branch)   PR_BASE_BRANCH="$2"; shift 2 ;;
        --pr-since)         PR_SINCE="$2"; shift 2 ;;
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


# ─── Fetch PR merge counts (optional) ──────────────────────────────
if [[ -n "$PR_REPO" ]] && command -v gh &>/dev/null; then
    [[ "$QUIET" == false ]] && echo -e "${BLUE}🔀 Fetching PR merges from ${PR_REPO} (base: ${PR_BASE_BRANCH})...${NC}" >&2
    PR_DATES="[]"
    PR_PAGE=1
    while true; do
        PR_PAGE_DATA=$(gh api "repos/${PR_REPO}/pulls?state=closed&base=${PR_BASE_BRANCH}&per_page=100&page=${PR_PAGE}" 2>/dev/null || echo "[]")
        PR_COUNT=$(echo "$PR_PAGE_DATA" | jq 'length' 2>/dev/null || echo 0)
        [[ "$PR_COUNT" -eq 0 ]] && break
        CHUNK=$(echo "$PR_PAGE_DATA" | jq --arg since "${PR_SINCE}" \
            '[.[] | select(.merged_at != null) | select($since == "" or .merged_at[:10] >= $since) | .merged_at[:10]]')
        PR_DATES=$(printf '%s\n%s' "$PR_DATES" "$CHUNK" | jq -s 'add // []')
        if [[ -n "$PR_SINCE" ]]; then
            OLDEST=$(echo "$PR_PAGE_DATA" | jq -r '[.[] | select(.merged_at != null) | .merged_at[:10]] | min // ""')
            [[ -n "$OLDEST" && "$OLDEST" < "$PR_SINCE" ]] && break
        fi
        PR_PAGE=$((PR_PAGE + 1))
    done
    PR_MAP=$(echo "$PR_DATES" | jq 'group_by(.) | map({key: .[0], value: length}) | from_entries')
    METRICS=$(echo "$METRICS" | jq --argjson pr "$PR_MAP" \
        'map(. + {pr_merges: ($pr[(.timestamp // "")[:10]] // $pr[(.date // "")] // 0)})')
    [[ "$QUIET" == false ]] && echo -e "${GREEN}✅ PR merge data fetched${NC}" >&2
fi

# ─── Generate Chart Container HTML ─────────────────────────────────
CHART_HTML=$(cat << 'CHART_EOF'
        <!-- 90 Day Vulnerability Metrics Chart -->
        <div class="metrics-chart-section" style="margin: 30px 0; padding: 24px; background: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb;">
            <div style="display: flex; align-items: baseline; gap: 12px; margin-bottom: 6px;">
                <h2 style="font-size: 1.4em; margin: 0; color: #111827; font-weight: 700;">📈 90 Day Vulnerability Metrics</h2>
            </div>
            <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 0.9em;">Daily vulnerability counts by severity over the past 90 days. Each bar reflects the highest scan result for that day. The line shows PRs merged to PR_BASE_BRANCH_PLACEHOLDER.</p>

            <div id="metricsStory" style="margin-bottom: 20px;"></div>

            <div style="overflow-x: auto;">
                <canvas id="metricsChart" width="400" height="110"></canvas>
            </div>

            <div id="metricsStats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px;"></div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
        <script>
        (function() {
            const metricsData = METRICS_DATA_PLACEHOLDER;

            const storyDiv  = document.getElementById('metricsStory');
            const statsDiv  = document.getElementById('metricsStats');
            const chartEl   = document.getElementById('metricsChart');

            if (!metricsData || metricsData.length === 0) {
                if (chartEl)  chartEl.style.display  = 'none';
                if (storyDiv) storyDiv.innerHTML = '<p style="color:#6b7280;">No scan data available yet.</p>';
                return;
            }

            // Derived series
            const fmt = d => new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
                                  .format(new Date(d + 'T12:00:00Z'));

            const labels       = metricsData.map(m => fmt(m.timestamp ? m.timestamp.slice(0,10) : m.date));
            const criticalData = metricsData.map(m => m.critical   || 0);
            const highData     = metricsData.map(m => m.high       || 0);
            const mediumData   = metricsData.map(m => m.medium     || 0);
            const lowData      = metricsData.map(m => m.low        || 0);
            const prData       = metricsData.map(m => m.pr_merges  || 0);
            const totalData    = metricsData.map((_,i) => criticalData[i]+highData[i]+mediumData[i]+lowData[i]);

            const latest      = metricsData[metricsData.length - 1];
            const latestTotal = totalData[totalData.length - 1];
            const latestPRs   = prData[prData.length - 1];
            const latestDate  = fmt(latest.timestamp ? latest.timestamp.slice(0,10) : latest.date);

            const peakTotal   = Math.max(...totalData);
            const peakIndex   = totalData.indexOf(peakTotal);
            const peakDate    = labels[peakIndex];

            const avgTotal    = (totalData.reduce((a,b) => a+b, 0) / totalData.length).toFixed(1);
            const avgCritical = (criticalData.reduce((a,b) => a+b, 0) / criticalData.length).toFixed(1);
            const totalPRs    = prData.reduce((a,b) => a+b, 0);

            // Story banner
            let statusColor, statusBg, statusBorder, statusIcon, headline, detail;

            if (latest.critical > 0) {
                statusColor  = '#991B1B'; statusBg = '#FEF2F2'; statusBorder = '#FCA5A5';
                statusIcon   = '🔴';
                headline     = latest.critical + ' critical vulnerabilit' + (latest.critical === 1 ? 'y requires' : 'ies require') + ' immediate attention.';
                detail       = 'Your latest scan on ' + latestDate + ' found ' + latestTotal + ' total findings — ' + latest.critical + ' critical and ' + latest.high + ' high.';
            } else if (latest.high > 0) {
                statusColor  = '#92400E'; statusBg = '#FFFBEB'; statusBorder = '#FCD34D';
                statusIcon   = '🟠';
                headline     = 'No critical vulnerabilities, but ' + latest.high + ' high-severity finding' + (latest.high === 1 ? '' : 's') + ' need review.';
                detail       = 'Your latest scan on ' + latestDate + ' shows ' + latestTotal + ' total findings. Addressing high-severity issues reduces your attack surface.';
            } else if (latestTotal > 0) {
                statusColor  = '#1E40AF'; statusBg = '#EFF6FF'; statusBorder = '#93C5FD';
                statusIcon   = '🔵';
                headline     = 'No critical or high vulnerabilities detected in the latest scan.';
                detail       = 'Your latest scan on ' + latestDate + ' found ' + latestTotal + ' medium/low findings. Keep monitoring to catch regressions early.';
            } else {
                statusColor  = '#166534'; statusBg = '#F0FDF4'; statusBorder = '#86EFAC';
                statusIcon   = '✅';
                headline     = 'Clean scan — no vulnerabilities detected.';
                detail       = 'Your latest scan on ' + latestDate + ' found zero findings across all severity levels.';
            }

            if (metricsData.length > 1 && peakTotal > 0 && peakTotal !== latestTotal) {
                const pct = Math.round(Math.abs(peakTotal - latestTotal) / peakTotal * 100);
                detail += ' Peak was ' + peakTotal + ' vulnerabilities on ' + peakDate;
                detail += latestTotal < peakTotal
                    ? ' — current total is ' + pct + '% lower.'
                    : ' — current total is ' + pct + '% higher than peak.';
            }
            if (totalPRs > 0) {
                detail += ' ' + totalPRs + ' PR' + (totalPRs === 1 ? '' : 's') + ' merged to PR_BASE_BRANCH_PLACEHOLDER in this period.';
            }

            storyDiv.innerHTML =
                '<div style="background:' + statusBg + '; border:1px solid ' + statusBorder + '; border-left:5px solid ' + statusColor + '; border-radius:8px; padding:14px 18px;">' +
                '<div style="font-weight:700; font-size:1em; color:' + statusColor + '; margin-bottom:4px;">' + statusIcon + ' ' + headline + '</div>' +
                '<div style="font-size:0.88em; color:#374151;">' + detail + '</div></div>';

            // Chart
            const ctx = chartEl.getContext('2d');
            new Chart(ctx, {
                type: 'CHART_TYPE_PLACEHOLDER',
                data: {
                    labels,
                    datasets: [
                        { label: 'Critical', data: criticalData, backgroundColor: '#B91C1C', borderColor: '#B91C1C', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                        { label: 'High',     data: highData,     backgroundColor: '#C2410C', borderColor: '#C2410C', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                        { label: 'Medium',   data: mediumData,   backgroundColor: '#B45309', borderColor: '#B45309', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                        { label: 'Low',      data: lowData,      backgroundColor: '#15803D', borderColor: '#15803D', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                        { type: 'line', label: 'PRs Merged (PR_BASE_BRANCH_PLACEHOLDER)', data: prData,
                          borderColor: '#1D4ED8', backgroundColor: 'rgba(29,78,216,0.12)',
                          borderWidth: 2, pointRadius: 4, pointHoverRadius: 6,
                          tension: 0.3, fill: false, yAxisID: 'y1' }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        legend: { display: true, position: 'top', labels: { font: { size: 12 }, padding: 15, usePointStyle: true } },
                        tooltip: {
                            backgroundColor: 'rgba(17,24,39,0.93)',
                            titleColor: '#f9fafb', bodyColor: '#e5e7eb',
                            borderColor: '#374151', borderWidth: 1, padding: 12,
                            callbacks: {
                                footer: function(items) {
                                    const vulnTotal = items
                                        .filter(function(i){ return i.dataset.yAxisID === 'y'; })
                                        .reduce(function(s,i){ return s + i.parsed.y; }, 0);
                                    return 'Vuln Total: ' + vulnTotal;
                                }
                            }
                        }
                    },
                    scales: {
                        y:  { beginAtZero: true, stacked: true, title: { display: true, text: 'Findings Count' },
                              ticks: { color: '#6b7280' }, grid: { color: 'rgba(0,0,0,0.05)' } },
                        y1: { type: 'linear', position: 'right', beginAtZero: true,
                              title: { display: true, text: 'PRs Merged' },
                              ticks: { color: '#1D4ED8' }, grid: { drawOnChartArea: false } },
                        x:  { stacked: true, ticks: { color: '#6b7280', maxRotation: 45 }, grid: { color: 'rgba(0,0,0,0.05)' } }
                    }
                }
            });

            // Stat cards
            const trendVsAvg   = latestTotal - parseFloat(avgTotal);
            const trendArrow   = trendVsAvg < 0 ? '↓' : trendVsAvg > 0 ? '↑' : '→';
            const trendCaption = trendVsAvg === 0 ? 'at 90-day average'
                               : Math.abs(trendVsAvg).toFixed(1) + ' ' + (trendVsAvg < 0 ? 'below' : 'above') + ' avg';
            const trendCol     = trendVsAvg < 0 ? '#166534' : trendVsAvg > 0 ? '#991B1B' : '#6b7280';

            statsDiv.innerHTML =
                '<div style="background:white;padding:15px;border-radius:8px;border-left:4px solid #B91C1C;">' +
                '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest Critical</div>' +
                '<div style="font-size:2em;font-weight:800;color:#B91C1C;line-height:1;">' + latest.critical + '</div>' +
                '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">90-day avg: ' + avgCritical + '</div></div>' +

                '<div style="background:white;padding:15px;border-radius:8px;border-left:4px solid #C2410C;">' +
                '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest High</div>' +
                '<div style="font-size:2em;font-weight:800;color:#C2410C;line-height:1;">' + latest.high + '</div>' +
                '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">90-day avg: ' + (highData.reduce(function(a,b){return a+b;},0)/highData.length).toFixed(1) + '</div></div>' +

                '<div style="background:white;padding:15px;border-radius:8px;border-left:4px solid #1D4ED8;">' +
                '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest Total</div>' +
                '<div style="font-size:2em;font-weight:800;color:#1D4ED8;line-height:1;">' + latestTotal + '</div>' +
                '<div style="font-size:0.78em;color:' + trendCol + ';margin-top:4px;">' + trendArrow + ' ' + trendCaption + '</div></div>' +

                '<div style="background:white;padding:15px;border-radius:8px;border-left:4px solid #6D28D9;">' +
                '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Peak Day</div>' +
                '<div style="font-size:2em;font-weight:800;color:#6D28D9;line-height:1;">' + peakTotal + '</div>' +
                '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">' + peakDate + '</div></div>' +

                '<div style="background:white;padding:15px;border-radius:8px;border-left:4px solid #1D4ED8;">' +
                '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">PRs Merged (90d)</div>' +
                '<div style="font-size:2em;font-weight:800;color:#1D4ED8;line-height:1;">' + totalPRs + '</div>' +
                '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">to PR_BASE_BRANCH_PLACEHOLDER' + (latestPRs > 0 ? ' · ' + latestPRs + ' latest day' : '') + '</div></div>';
        })();
        </script>
CHART_EOF
)

# ─── Inject into dashboard ──────────────────────────────────────────
[[ "$QUIET" == false ]] && echo -e "${BLUE}💉 Injecting metrics chart into dashboard...${NC}" >&2

# Replace placeholders
CHART_HTML="${CHART_HTML//METRICS_DATA_PLACEHOLDER/$(echo "$METRICS" | jq -c '.')}"
CHART_HTML="${CHART_HTML//CHART_TYPE_PLACEHOLDER/$CHART_TYPE}"
CHART_HTML="${CHART_HTML//PR_BASE_BRANCH_PLACEHOLDER/$PR_BASE_BRANCH}"

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
