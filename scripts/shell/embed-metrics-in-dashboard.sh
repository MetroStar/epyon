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
    [[ "$QUIET" == false ]] && echo -e "${BLUE}🔀 Fetching PR merges to ${PR_BASE_BRANCH:-main} from ${PR_REPO}...${NC}" >&2
    PR_DATES="[]"
    PR_PAGE=1
    while true; do
        PR_PAGE_DATA=$(gh api "repos/${PR_REPO}/pulls?state=closed&per_page=100&page=${PR_PAGE}" 2>/dev/null || echo "[]")
        # Normalize to array — gh api may return an error object/string on auth or rate-limit failures
        PR_PAGE_DATA=$(echo "$PR_PAGE_DATA" | jq 'if type == "array" then . else [] end' 2>/dev/null || echo "[]")
        PR_COUNT=$(echo "$PR_PAGE_DATA" | jq 'length' 2>/dev/null | tr -d '[:space:]' || echo 0)
        [[ "${PR_COUNT:-0}" -eq 0 ]] && break
        CHUNK=$(echo "$PR_PAGE_DATA" | jq --arg since "${PR_SINCE}" --arg base "${PR_BASE_BRANCH:-main}" \
            '[.[] | select(.merged_at != null) | select($since == "" or .merged_at[:10] >= $since) | select($base == "" or .base.ref == $base) | .merged_at[:10]]')
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
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
        <script>
        (function() {
            const metricsData = METRICS_DATA_PLACEHOLDER;
            const prBaseBranch = 'PR_BASE_BRANCH_PLACEHOLDER';

            // Wait for DOM to be ready and modal to open before rendering
            function renderMetricsContent() {
                const modalBody = document.getElementById('metricsModalBody');
                if (!modalBody) return;

                if (!metricsData || metricsData.length === 0) {
                    modalBody.innerHTML = '<p style="color:#6b7280;">No scan data available yet.</p>';
                    return;
                }

                // Create the metrics sections
                modalBody.innerHTML =
                    '<div class="metrics-chart-section" style="margin: 0 0 30px 0; padding: 24px; background: #1e2530; border-radius: 12px; border: 1px solid #2a3441;">' +
                    '<div style="display: flex; align-items: baseline; gap: 12px; margin-bottom: 6px;">' +
                    '<h2 style="font-size: 1.4em; margin: 0; color: #e2e8f0; font-weight: 700;">📈 90 Day Vulnerability Metrics</h2>' +
                    '</div>' +
                    '<p style="margin: 0 0 16px 0; color: #8892a4; font-size: 0.9em;">Daily vulnerability counts by severity over the past 90 days. Each bar reflects the highest scan result for that day.</p>' +
                    '<div id="metricsStory" style="margin-bottom: 20px;"></div>' +
                    '<div style="overflow-x: auto;">' +
                    '<canvas id="metricsChart" width="400" height="110"></canvas>' +
                    '</div>' +
                    '<div id="metricsStats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px;"></div>' +
                    '</div>' +
                    '<div class="metrics-chart-section" style="margin: 0; padding: 24px; background: #1e2530; border-radius: 12px; border: 1px solid #2a3441;">' +
                    '<div style="display: flex; align-items: baseline; gap: 12px; margin-bottom: 6px;">' +
                    '<h2 style="font-size: 1.4em; margin: 0; color: #e2e8f0; font-weight: 700;">🔀 Merges to ' + prBaseBranch + '</h2>' +
                    '</div>' +
                    '<p style="margin: 0 0 16px 0; color: #8892a4; font-size: 0.9em;">Daily PR merges into the ' + prBaseBranch + ' branch.</p>' +
                    '<div id="prStory" style="margin-bottom: 20px;"></div>' +
                    '<div style="overflow-x: auto;">' +
                    '<canvas id="prChart" width="400" height="110"></canvas>' +
                    '</div>' +
                    '<div id="prStats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px;"></div>' +
                    '</div>';

                const storyDiv  = document.getElementById('metricsStory');
                const statsDiv  = document.getElementById('metricsStats');
                const chartEl   = document.getElementById('metricsChart');

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
                            { label: 'Critical', data: criticalData, backgroundColor: '#C41E3A', borderColor: '#C41E3A', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                            { label: 'High',     data: highData,     backgroundColor: '#FF1493', borderColor: '#FF1493', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                            { label: 'Medium',   data: mediumData,   backgroundColor: '#f97316', borderColor: '#f97316', borderWidth: 1, stack: 'severity', yAxisID: 'y' },
                            { label: 'Low',      data: lowData,      backgroundColor: '#10b981', borderColor: '#10b981', borderWidth: 1, stack: 'severity', yAxisID: 'y' }
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
                                        const total = items.reduce(function(s,i){ return s + i.parsed.y; }, 0);
                                        return 'Total: ' + total;
                                    }
                                }
                            }
                        },
                        scales: {
                            y: { beginAtZero: true, stacked: true, title: { display: true, text: 'Findings Count' },
                                 ticks: { color: '#8892a4' }, grid: { color: 'rgba(255,255,255,0.06)' } },
                            x: { stacked: true, ticks: { color: '#8892a4', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.06)' } }
                        }
                    }
                });

                // ── Stat cards (chart 1) ───────────────────────────────────────
                const trendVsAvg   = latestTotal - parseFloat(avgTotal);
                const trendArrow   = trendVsAvg < 0 ? '↓' : trendVsAvg > 0 ? '↑' : '→';
                const trendCaption = trendVsAvg === 0 ? 'at 90-day average'
                                   : Math.abs(trendVsAvg).toFixed(1) + ' ' + (trendVsAvg < 0 ? 'below' : 'above') + ' avg';
                const trendCol     = trendVsAvg < 0 ? '#10b981' : trendVsAvg > 0 ? '#C41E3A' : '#8892a4';

                statsDiv.innerHTML =
                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #C41E3A;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest Critical</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#C41E3A;line-height:1;">' + latest.critical + '</div>' +
                    '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">90-day avg: ' + avgCritical + '</div></div>' +

                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #FF1493;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest High</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#FF1493;line-height:1;">' + latest.high + '</div>' +
                    '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">90-day avg: ' + (highData.reduce(function(a,b){return a+b;},0)/highData.length).toFixed(1) + '</div></div>' +

                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #60a5fa;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Latest Total</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#60a5fa;line-height:1;">' + latestTotal + '</div>' +
                    '<div style="font-size:0.78em;color:' + trendCol + ';margin-top:4px;">' + trendArrow + ' ' + trendCaption + '</div></div>' +

                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #a78bfa;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">Peak Day</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#a78bfa;line-height:1;">' + peakTotal + '</div>' +
                    '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">' + peakDate + '</div></div>';

                // ── Chart 2 — PR Activity & CVE Discipline ────────────────────────
                const prChartEl  = document.getElementById('prChart');
                const prStoryDiv = document.getElementById('prStory');
                const prStatsDiv = document.getElementById('prStats');
                if (!prChartEl) return;

                // PRs in last 7 days
                const cutoff7d = new Date(new Date() - 7 * 86400000);
                const prs7d    = metricsData.filter(function(m) {
                    return new Date((m.timestamp ? m.timestamp.slice(0,10) : m.date) + 'T12:00:00Z') >= cutoff7d;
                }).reduce(function(s,m){ return s + (m.pr_merges || 0); }, 0);

                // Story banner for chart 2
                var prIcon, prHeadline, prDetail, prBorderColor;
                if (totalPRs === 0) {
                    prIcon = '📭'; prBorderColor = '#4b5563';
                    prHeadline = 'No PR data available for this period.';
                    prDetail   = 'Pass --pr-repo to the embed script to enable PR merge tracking.';
                } else {
                    prIcon = '🔀'; prBorderColor = '#60a5fa';
                    prHeadline = totalPRs + ' PRs merged to ' + prBaseBranch + ' in the last 90 days.';
                    prDetail   = prs7d + ' merged to ' + prBaseBranch + ' in the last 7 days.';
                }

                prStoryDiv.innerHTML =
                    '<div style="border-left:5px solid ' + prBorderColor + '; background:#16202e; border-radius:8px; padding:14px 18px;">' +
                    '<div style="font-weight:700;font-size:1em;color:#e2e8f0;margin-bottom:4px;">' + prIcon + ' ' + prHeadline + '</div>' +
                    '<div style="font-size:0.88em;color:#8892a4;">' + prDetail + '</div></div>';

                const prCtx = prChartEl.getContext('2d');
                new Chart(prCtx, {
                    type: 'bar',
                    data: {
                        labels,
                        datasets: [
                            { label: 'PRs Merged', data: prData,
                              backgroundColor: '#60a5fa', borderColor: '#60a5fa', borderWidth: 1 }
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
                                borderColor: '#374151', borderWidth: 1, padding: 12
                            }
                        },
                        scales: {
                            y: { beginAtZero: true, title: { display: true, text: 'PRs Merged' },
                                 ticks: { color: '#60a5fa', precision: 0 }, grid: { color: 'rgba(255,255,255,0.06)' } },
                            x: { ticks: { color: '#8892a4', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.06)' } }
                        }
                    }
                });

                // Stat cards (chart 2)
                prStatsDiv.innerHTML =
                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #60a5fa;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">PRs Merged (90d)</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#60a5fa;line-height:1;">' + totalPRs + '</div>' +
                    '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">merged to ' + prBaseBranch + '</div></div>' +

                    '<div style="background:#1a1d23;padding:15px;border-radius:8px;border-left:4px solid #60a5fa;">' +
                    '<div style="color:#6b7280;font-size:0.82em;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;">PRs Last 7 Days</div>' +
                    '<div style="font-size:2em;font-weight:800;color:#60a5fa;line-height:1;">' + prs7d + '</div>' +
                    '<div style="font-size:0.78em;color:#9ca3af;margin-top:4px;">merged recently</div></div>';
            }

            // Render when modal opens
            const originalOpenMetricsModal = window.openMetricsModal;
            window.openMetricsModal = function() {
                if (originalOpenMetricsModal) originalOpenMetricsModal();
                renderMetricsContent();
            };

            // Also render on DOMContentLoaded if modal is already open
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', function() {
                    if (document.getElementById('metricsOverlay') &&
                        document.getElementById('metricsOverlay').classList.contains('open')) {
                        renderMetricsContent();
                    }
                });
            }
        })();
        </script>
CHART_EOF
)

# ─── Inject into dashboard ──────────────────────────────────────────
[[ "$QUIET" == false ]] && echo -e "${BLUE}💉 Injecting metrics chart into dashboard...${NC}" >&2

# Replace placeholders
CHART_HTML="${CHART_HTML//METRICS_DATA_PLACEHOLDER/$(echo "$METRICS" | jq -c '.')}"
CHART_HTML="${CHART_HTML//CHART_TYPE_PLACEHOLDER/$CHART_TYPE}"
CHART_HTML="${CHART_HTML//PR_BASE_BRANCH_PLACEHOLDER/${PR_BASE_BRANCH:-main}}"


# Find injection point — use the unique marker left by generate-dashboard.py.
# Falling back to </body> risks hitting the one inside the embedded app.js
# template literal (print report HTML), which lives inside a <script> block.
if grep -q "<!-- __EPYON_METRICS__ -->" "$DASHBOARD_FILE"; then
    # Replace the marker with the chart HTML
    TEMP_HTML=$(mktemp)
    echo "$CHART_HTML" > "$TEMP_HTML"
    awk -v chart_file="$TEMP_HTML" '
        /<!-- __EPYON_METRICS__ -->/ {
            while ((getline line < chart_file) > 0) print line
            close(chart_file)
            next
        }
        { print }
    ' "$DASHBOARD_FILE" > "${DASHBOARD_FILE}.tmp" && mv "${DASHBOARD_FILE}.tmp" "$DASHBOARD_FILE"
    rm -f "$TEMP_HTML"
elif grep -q "</body>" "$DASHBOARD_FILE"; then
    # Legacy fallback: insert before the LAST </body> in the file to avoid
    # hitting </body> tags inside embedded JavaScript template literals.
    TEMP_HTML=$(mktemp)
    echo "$CHART_HTML" > "$TEMP_HTML"
    awk -v chart_file="$TEMP_HTML" '
        { lines[NR] = $0 }
        END {
            last = 0
            for (i = NR; i >= 1; i--) {
                if (lines[i] ~ /<\/body>/) { last = i; break }
            }
            for (i = 1; i <= NR; i++) {
                if (i == last) {
                    while ((getline line < chart_file) > 0) print line
                    close(chart_file)
                }
                print lines[i]
            }
        }
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
