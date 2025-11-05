# Security Dashboard Launcher
# Opens the comprehensive security dashboard from the new location

# Color definitions
$GREEN = "Green"
$BLUE = "Cyan"
$WHITE = "White"
$RED = "Red"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$DashboardPath = Join-Path $RepoRoot "reports\security-reports\dashboards\security-dashboard.html"

Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "🛡️  Security Dashboard Launcher" -ForegroundColor $WHITE
Write-Host "============================================" -ForegroundColor $WHITE
Write-Host ""

if (Test-Path $DashboardPath) {
    Write-Host "✅ Dashboard found: $DashboardPath" -ForegroundColor $GREEN
    Write-Host "🚀 Opening security dashboard..." -ForegroundColor $BLUE
    
    # Add cache-busting parameter to force browser refresh
    $Timestamp = [int][double]::Parse((Get-Date -UFormat %s))
    $DashboardUrl = "file:///$($DashboardPath.Replace('\', '/'))?v=$Timestamp"
    
    # Open the dashboard in default browser
    Start-Process $DashboardPath
    
    Write-Host ""
    Write-Host "✅ Security dashboard launched!" -ForegroundColor $GREEN
    Write-Host ""
    Write-Host "📊 Dashboard Features:" -ForegroundColor $BLUE
    Write-Host "• Overview of all 8 security tools"
    Write-Host "• Interactive status indicators"
    Write-Host "• Direct links to detailed reports"
    Write-Host "• Professional security summaries"
    
} else {
    Write-Host "❌ Dashboard not found at: $DashboardPath" -ForegroundColor $RED
    Write-Host "💡 To regenerate the dashboard, run:" -ForegroundColor $BLUE
    Write-Host "   .\consolidate-security-reports.ps1"
}

Write-Host ""
Write-Host "============================================" -ForegroundColor $WHITE
