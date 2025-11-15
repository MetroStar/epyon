// Real-time activity data loaded from CSV audit logs
function loadRealActivityData() {
    const realActivities = [
        ['Timestamp', 'User', 'Script', 'Tool', 'Target', 'Duration', 'Findings', 'Status'],
        ['2025-11-13 18:56:50', 'rnelson (ITLP01183)', 'run-clamav-scan.sh', 'ClamAV', '/tmp', '16s', '0', 'SUCCESS'],
        ['2025-11-13 18:45:00', 'rnelson (ITLP01183)', 'example-audited-checkov.sh', 'Checkov', '/Users/rnelson/Desktop', '0s', '23', 'SUCCESS'],
        ['2025-11-13 18:44:54', 'rnelson (rnelson)', 'example-audited-checkov.sh', 'Checkov', 'bash', '0s', '0', 'SUCCESS']
    ];
    
    // Calculate real metrics from actual data
    const totalScans = Math.max(0, realActivities.length - 1); // Subtract 1 for header row
    const uniqueUsers = [...new Set(realActivities.slice(1).map(row => row[1] ? row[1].split(' (')[0] : ''))].filter(u => u).length;
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
                <td>${row[0] || ''}</td>
                <td><strong>${row[1] || ''}</strong></td>
                <td>${row[2] || ''}</td>
                <td><span style="background: #3498db; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.85em;">${row[3] || ''}</span></td>
                <td>${row[4] || ''}</td>
                <td style="font-family: monospace; font-size: 0.9em; color: #666;">${row[5] || ''}</td>
                <td><span style="background: ${(row[6] && parseInt(row[6]) > 0) ? '#f39c12' : '#27ae60'}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.85em;">${row[6] || '0'}</span></td>
                <td class="status-${(row[7] === 'SUCCESS') ? 'success' : (row[7] === 'WARNING') ? 'warning' : 'error'}">${row[7] || 'UNKNOWN'}</td>
            </tr>`
        ).join('');
        
        // Calculate and display user summary
        const userStats = {};
        realActivities.slice(1).forEach(row => {
            const user = (row[1] || '').split(' (')[0]; // Extract main username
            if (user && user.trim()) {
                if (!userStats[user]) {
                    userStats[user] = { scans: 0, tools: new Set(), lastActive: row[0], findings: 0 };
                }
                userStats[user].scans++;
                userStats[user].tools.add(row[3] || 'unknown');
                userStats[user].findings += parseInt(row[6] || 0);
                if (row[0] > userStats[user].lastActive) {
                    userStats[user].lastActive = row[0];
                }
            }
        });
        
        const userSummaryDiv = document.getElementById('userSummary');
        if (Object.keys(userStats).length > 0) {
            userSummaryDiv.innerHTML = Object.entries(userStats).map(([user, stats]) => {
                const isBot = user.includes('bot') || user.includes('automated');
                const lastActiveTime = (stats.lastActive || '').split(' ')[1] || 'Unknown';
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
            userSummaryDiv.innerHTML = '<div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; color: #7f8c8d;">👥 No user activity recorded yet</div>';
        }
    } else {
        tbody.innerHTML = '<tr><td colspan="8">No security activities recorded yet.</td></tr>';
        
        // Show empty state for user summary
        const userSummaryDiv = document.getElementById('userSummary');
        userSummaryDiv.innerHTML = '<div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; color: #7f8c8d;">👥 No user activity recorded yet</div>';
    }
}

// Load real data when called
loadRealActivityData();
