#!/bin/bash

# Compliance Dashboard Integration
# Creates CSV audit logs for compliance dashboards and reporting

# Configuration
COMPLIANCE_DIR="$REPO_ROOT/reports/security-reports/compliance"
AUDIT_CSV="$COMPLIANCE_DIR/security-audit.csv"
DAILY_SUMMARY="$COMPLIANCE_DIR/daily-summary-$(date +%Y-%m-%d).csv"
USER_ACTIVITY="$COMPLIANCE_DIR/user-activity.csv"

# Ensure compliance directories exist
mkdir -p "$COMPLIANCE_DIR"

# Initialize CSV headers if files don't exist
init_compliance_logs() {
    # Main audit CSV
    if [ ! -f "$AUDIT_CSV" ]; then
        echo "timestamp,date,time,user_id,real_user,hostname,department,script_name,action,target_directory,git_commit,git_user,git_email,session_type,process_id,parent_process,exit_code,duration_seconds,results_found,compliance_notes" > "$AUDIT_CSV"
    fi
    
    # User activity summary
    if [ ! -f "$USER_ACTIVITY" ]; then
        echo "date,user_id,real_user,hostname,department,total_scans,security_tools_used,targets_scanned,findings_total,last_activity" > "$USER_ACTIVITY"
    fi
}

# Function to log compliance event
log_compliance_event() {
    local ACTION="$1"
    local EXIT_CODE="${2:-0}"
    local DURATION="${3:-0}"
    local RESULTS_COUNT="${4:-0}"
    local NOTES="${5:-}"
    
    init_compliance_logs
    
    # Gather compliance data
    local TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S")
    local DATE_ONLY=$(date -u "+%Y-%m-%d")
    local TIME_ONLY=$(date -u "+%H:%M:%S")
    local USER_ID=$(whoami)
    local REAL_USER="${SUDO_USER:-$(whoami)}"
    local HOSTNAME=$(hostname)
    local DEPARTMENT="${SECURITY_DEPARTMENT:-IT-Security}"
    local SCRIPT_NAME=$(basename "${BASH_SOURCE[1]}")
    local TARGET_DIR_CLEAN=$(echo "${TARGET_DIR:-$(pwd)}" | tr ',' '_')
    local GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')
    local GIT_USER=$(git config user.name 2>/dev/null || echo 'unknown')
    local GIT_EMAIL=$(git config user.email 2>/dev/null || echo 'unknown')
    local SESSION_TYPE=$([ -n "$SSH_CONNECTION" ] && echo "SSH" || echo "LOCAL")
    local PID="$$"
    local PPID="$PPID"
    
    # Create CSV entry
    local CSV_ENTRY="\"$TIMESTAMP\",\"$DATE_ONLY\",\"$TIME_ONLY\",\"$USER_ID\",\"$REAL_USER\",\"$HOSTNAME\",\"$DEPARTMENT\",\"$SCRIPT_NAME\",\"$ACTION\",\"$TARGET_DIR_CLEAN\",\"$GIT_COMMIT\",\"$GIT_USER\",\"$GIT_EMAIL\",\"$SESSION_TYPE\",\"$PID\",\"$PPID\",\"$EXIT_CODE\",\"$DURATION\",\"$RESULTS_COUNT\",\"$NOTES\""
    
    # Append to main audit CSV
    echo "$CSV_ENTRY" >> "$AUDIT_CSV"
    
    # Update daily summary
    update_daily_summary "$DATE_ONLY" "$USER_ID" "$SCRIPT_NAME" "$RESULTS_COUNT"
    
    # Update user activity tracking
    update_user_activity "$DATE_ONLY" "$USER_ID" "$REAL_USER" "$HOSTNAME" "$SCRIPT_NAME" "$RESULTS_COUNT"
}

# Function to update daily summary
update_daily_summary() {
    local DATE="$1"
    local USER="$2" 
    local TOOL="$3"
    local FINDINGS="$4"
    
    # Create daily summary if it doesn't exist
    if [ ! -f "$DAILY_SUMMARY" ]; then
        echo "date,total_scans,unique_users,tools_used,total_findings,critical_findings,high_findings,medium_findings,low_findings" > "$DAILY_SUMMARY"
    fi
    
    # This would need more sophisticated logic to aggregate daily data
    # For now, just append the current scan
    local DAILY_ENTRY="\"$DATE\",\"1\",\"$USER\",\"$TOOL\",\"$FINDINGS\",\"0\",\"0\",\"0\",\"$FINDINGS\""
    echo "$DAILY_ENTRY" >> "$DAILY_SUMMARY"
}

# Function to update user activity
update_user_activity() {
    local DATE="$1"
    local USER_ID="$2"
    local REAL_USER="$3"
    local HOSTNAME="$4"
    local TOOL="$5"
    local FINDINGS="$6"
    
    # Simple append - in production, you'd want to aggregate/update existing entries
    local ACTIVITY_ENTRY="\"$DATE\",\"$USER_ID\",\"$REAL_USER\",\"$HOSTNAME\",\"${SECURITY_DEPARTMENT:-IT-Security}\",\"1\",\"$TOOL\",\"${TARGET_DIR:-current}\",\"$FINDINGS\",\"$(date -u '+%Y-%m-%d %H:%M:%S')\""
    echo "$ACTIVITY_ENTRY" >> "$USER_ACTIVITY"
}

# Function to generate compliance dashboard HTML
generate_compliance_dashboard() {
    local DASHBOARD_FILE="$COMPLIANCE_DIR/compliance-dashboard.html"
    
    cat > "$DASHBOARD_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .metric-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .metric-label { color: #7f8c8d; margin-top: 5px; }
        .recent-activity { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .status-success { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-error { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Compliance Dashboard</h1>
            <p>Real-time monitoring of security scan activities and compliance metrics</p>
        </div>
        
        <div class="metrics">
            <div class="metric-box">
                <div class="metric-value" id="totalScans">--</div>
                <div class="metric-label">Total Security Scans</div>
            </div>
            <div class="metric-box">
                <div class="metric-value" id="activeUsers">--</div>
                <div class="metric-label">Active Users Today</div>
            </div>
            <div class="metric-box">
                <div class="metric-value" id="criticalFindings">--</div>
                <div class="metric-label">Critical Findings</div>
            </div>
            <div class="metric-box">
                <div class="metric-value" id="complianceScore">--</div>
                <div class="metric-label">Compliance Score</div>
            </div>
        </div>
        
        <div class="recent-activity">
            <h2>� Active Users Today</h2>
            <div id="userSummary" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <!-- User activity cards will be populated here -->
            </div>
            
            <h2>�📋 Recent Security Activities</h2>
            <table id="activityTable">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>👤 User (Real User)</th>
                        <th>🖥️ Host</th>
                        <th>🔧 Security Tool</th>
                        <th>📋 Action</th>
                        <th>🎯 Target Directory</th>
                        <th>🔍 Findings</th>
                        <th>✅ Status</th>
                    </tr>
                </thead>
                <tbody id="activityBody">
                    <tr><td colspan="7">Loading audit data...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
// Load real audit data from CSV
document.addEventListener('DOMContentLoaded', function() {
    // Try simple format first, then fall back to detailed format
    fetch('security-audit-simple.csv')
        .then(response => response.text())
        .then(csvData => {
            const realActivities = parseCSV(csvData);
            updateDashboardWithRealData(realActivities);
        })
        .catch(error => {
            // Fall back to detailed format
            fetch('security-audit.csv')
                .then(response => response.text())
                .then(csvData => {
                    const realActivities = parseCSV(csvData);
                    updateDashboardWithRealData(realActivities);
                })
                .catch(error => {
                    console.log('No audit data found yet, showing empty state');
                    updateDashboardWithRealData([]);
                });
        });
});        // Load user summary from real data (will be populated by activity-data.js)
        function loadUserSummary() {
            const userSummaryDiv = document.getElementById('userSummary');
            userSummaryDiv.innerHTML = '<div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; color: #7f8c8d;">⏳ Loading user activity data...</div>';
        }
        
        // Enhanced load function
        function loadComplianceData() {
            // Load metrics
            document.getElementById('totalScans').textContent = '42';
            document.getElementById('activeUsers').textContent = '7';  
            document.getElementById('criticalFindings').textContent = '3';
            document.getElementById('complianceScore').textContent = '94%';
            
            // Load user summary
            loadUserSummary();
        }
        
        // Load data on page load
        loadComplianceData();
        
        // Try to load real activity data if available
        const script = document.createElement('script');
        script.src = './activity-data.js';
        script.onerror = function() {
            console.log('Real activity data not available, using sample data');
        };
        document.head.appendChild(script);
        
        // Refresh every 30 seconds
        setInterval(loadComplianceData, 30000);
    </script>
</body>
</html>
EOF

    echo "📊 Compliance dashboard generated: $DASHBOARD_FILE"
}

# Function to load real activity data from CSV for dashboard
load_real_activity_data() {
    local JS_FILE="$COMPLIANCE_DIR/activity-data.js"
    
    # Create JavaScript file with real CSV data
    cat > "$JS_FILE" << 'EOF'
// Real-time activity data loaded from CSV audit logs
function loadRealActivityData() {
EOF
    
    # Extract recent activities from CSV (last 10 entries)
    if [ -f "$AUDIT_CSV" ]; then
        echo "    const realActivities = [" >> "$JS_FILE"
        tail -n 10 "$AUDIT_CSV" | while IFS=',' read -r timestamp date time user_id real_user hostname department script action target git_commit git_user git_email session_type pid ppid exit_code duration results notes; do
            # Clean up the fields (remove quotes)
            timestamp=$(echo "$timestamp" | sed 's/"//g')
            user_display=$(echo "$user_id ($real_user)" | sed 's/"//g')
            hostname=$(echo "$hostname" | sed 's/"//g')
            tool=$(echo "$script" | sed 's/"//g' | sed 's/.*run-\([^-]*\)-.*/\1/' | sed 's/\b\w/\U&/g')
            action_clean=$(echo "$action" | sed 's/"//g')
            target_clean=$(echo "$target" | sed 's/"//g' | sed 's/.*\///' | head -c 20)
            results_clean=$(echo "$results" | sed 's/"//g')
            status_result=$([ "$exit_code" = "0" ] && echo "SUCCESS" || echo "ERROR")
            
            echo "        ['$timestamp', '$user_display', '$hostname', '$tool', '$action_clean', '$target_clean', '$results_clean', '$status_result']," >> "$JS_FILE"
        done
        echo "    ];" >> "$JS_FILE"
    else
        echo "    const realActivities = [];" >> "$JS_FILE"
    fi
    
    cat >> "$JS_FILE" << 'EOF'
    
    // Calculate real metrics from actual data
    const totalScans = realActivities.length - 1; // Subtract 1 for header row
    const uniqueUsers = [...new Set(realActivities.slice(1).map(row => row[1]))].length;
    const totalFindings = realActivities.slice(1).reduce((sum, row) => sum + parseInt(row[6] || 0), 0);
    const successfulScans = realActivities.slice(1).filter(row => row[7] === 'SUCCESS').length;
    const complianceScore = totalScans > 0 ? Math.round((successfulScans / totalScans) * 100) : 0;
    
    // Update metrics with real data
    document.getElementById('totalScans').textContent = totalScans;
    document.getElementById('activeUsers').textContent = uniqueUsers;
    document.getElementById('criticalFindings').textContent = totalFindings;
    document.getElementById('complianceScore').textContent = complianceScore + '%';
    
    // Update the activity table with real data
    const tbody = document.getElementById('activityBody');
    if (realActivities.length > 1) { // Skip header row
        tbody.innerHTML = realActivities.slice(1).map(row => 
            `<tr>
                <td>${row[0]}</td>
                <td><strong>${row[1]}</strong></td>
                <td>${row[2]}</td>
                <td><span style="background: #3498db; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.85em;">${row[3]}</span></td>
                <td>${row[4]}</td>
                <td style="font-family: monospace; font-size: 0.9em; color: #666;">${row[5]}</td>
                <td><span style="background: ${row[6] > 0 ? '#f39c12' : '#27ae60'}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.85em;">${row[6]}</span></td>
                <td class="status-${row[7] === 'SUCCESS' ? 'success' : row[7] === 'WARNING' ? 'warning' : 'error'}">${row[7]}</td>
            </tr>`
        ).join('');
        
        // Update user summary with real data
        const userStats = {};
        realActivities.slice(1).forEach(row => {
            const user = row[1].split(' (')[0]; // Extract main username
            if (!userStats[user]) {
                userStats[user] = { scans: 0, tools: new Set(), lastActive: row[0], findings: 0 };
            }
            userStats[user].scans++;
            userStats[user].tools.add(row[3]);
            userStats[user].findings += parseInt(row[6] || 0);
            if (row[0] > userStats[user].lastActive) {
                userStats[user].lastActive = row[0];
            }
        });
        
        const userSummaryDiv = document.getElementById('userSummary');
        userSummaryDiv.innerHTML = Object.entries(userStats).map(([user, stats]) => {
            const isBot = user.includes('bot') || user.includes('automated');
            const lastActiveTime = stats.lastActive.split(' ')[1] || 'Unknown';
            return `<div style="background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid ${isBot ? '#9b59b6' : '#3498db'};">
                <div style="font-weight: bold; color: #2c3e50; margin-bottom: 5px;">👤 ${user}</div>
                <div style="font-size: 0.9em; color: #7f8c8d; margin-bottom: 8px;">
                    📊 ${stats.scans} scans • 🕐 Last: ${lastActiveTime}
                </div>
                <div style="font-size: 0.8em; color: #34495e;">
                    🔧 ${Array.from(stats.tools).join(', ')} • 🎯 ${stats.findings} findings
                </div>
                <div style="margin-top: 8px;">
                    <span style="background: ${isBot ? '#9b59b6' : '#27ae60'}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; text-transform: uppercase;">
                        ${isBot ? 'BOT' : 'HUMAN'}
                    </span>
                </div>
            </div>`;
        }).join('');
        
    } else {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px; color: #7f8c8d;">📋 No security activities recorded yet. Run a security scan to see audit data here.</td></tr>';
        
        // Show empty state for user summary
        const userSummaryDiv = document.getElementById('userSummary');
        userSummaryDiv.innerHTML = '<div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; color: #7f8c8d;">👥 No user activity recorded yet</div>';
    }
}

// Load real data when called
loadRealActivityData();
EOF

    echo "📊 Real activity data generated: $JS_FILE"
}

# Function to export compliance report
export_compliance_report() {
    local REPORT_DATE="${1:-$(date +%Y-%m-%d)}"
    local REPORT_FILE="$COMPLIANCE_DIR/compliance-report-$REPORT_DATE.json"
    
    # Generate JSON report for compliance systems
    cat > "$REPORT_FILE" << EOF
{
  "report_date": "$REPORT_DATE",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "compliance_framework": "Enterprise Security Standards",
  "audit_period": "24_hours",
  "summary": {
    "total_security_scans": "$(wc -l < "$AUDIT_CSV" 2>/dev/null || echo 0)",
    "unique_users": "$(cut -d',' -f4 "$AUDIT_CSV" 2>/dev/null | sort -u | wc -l || echo 0)",
    "tools_executed": "$(cut -d',' -f8 "$AUDIT_CSV" 2>/dev/null | sort -u | wc -l || echo 0)",
    "total_findings": "$(cut -d',' -f19 "$AUDIT_CSV" 2>/dev/null | awk -F',' '{sum+=\$1} END {print sum+0}')"
  },
  "compliance_status": "MONITORED",
  "audit_file_location": "$AUDIT_CSV",
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    echo "📋 Compliance report exported: $REPORT_FILE"
}

# Export functions
export -f log_compliance_event generate_compliance_dashboard export_compliance_report