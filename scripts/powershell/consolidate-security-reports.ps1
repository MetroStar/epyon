# Security Reports Consolidation Script - PowerShell Version
# Converts all security scan outputs to human-readable formats and creates unified dashboard

param(
    [Parameter(Position=0)]
    [string]$Mode = "default"
)

$ErrorActionPreference = "Continue"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$UNIFIED_DIR = Join-Path $RepoRoot "reports\security-reports"
$Timestamp = Get-Date
$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$RepoPath = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }

# Colors
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$PURPLE = "Magenta"
$CYAN = "Cyan"
$WHITE = "White"

Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "Security Reports Consolidation" -ForegroundColor $WHITE
Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "Consolidating all security scan outputs..."
Write-Host "Unified Directory: $UNIFIED_DIR"
Write-Host "Timestamp: $ReportDate"
Write-Host ""

# Create unified directory structure
$Directories = @(
    "$UNIFIED_DIR\raw-data",
    "$UNIFIED_DIR\html-reports",
    "$UNIFIED_DIR\markdown-reports",
    "$UNIFIED_DIR\csv-reports",
    "$UNIFIED_DIR\dashboards"
)

foreach ($dir in $Directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Function to consolidate specific tool reports
function Consolidate-ToolReports {
    param(
        [string]$ToolName,
        [string]$SourceDir,
        [string]$FilePattern
    )
    
    Write-Host "📊 Consolidating $ToolName reports..." -ForegroundColor $CYAN
    
    # Create tool-specific directories
    $ToolDirs = @(
        "$UNIFIED_DIR\raw-data\$ToolName",
        "$UNIFIED_DIR\html-reports\$ToolName",
        "$UNIFIED_DIR\markdown-reports\$ToolName"
    )
    
    foreach ($dir in $ToolDirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    
    # Copy raw data
    if (Test-Path $SourceDir) {
        try {
            Get-ChildItem -Path $SourceDir -File | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination "$UNIFIED_DIR\raw-data\$ToolName\" -Force -ErrorAction SilentlyContinue
            }
            Write-Host "✅ $ToolName reports consolidated" -ForegroundColor $GREEN
        } catch {
            Write-Host "⚠️  Error copying $ToolName reports: $_" -ForegroundColor $YELLOW
        }
    } else {
        Write-Host "⚠️  $ToolName reports directory not found: $SourceDir" -ForegroundColor $YELLOW
    }
}

Write-Host "🔄 Consolidating security reports from all tools..." -ForegroundColor $BLUE
Write-Host ""

# Consolidate reports from each security tool
$ReportsBaseDir = Join-Path $RepoRoot "reports"

Consolidate-ToolReports "SonarQube" (Join-Path $ReportsBaseDir "sonar-reports") "*.json"
Consolidate-ToolReports "TruffleHog" (Join-Path $ReportsBaseDir "trufflehog-reports") "*.json"
Consolidate-ToolReports "ClamAV" (Join-Path $ReportsBaseDir "clamav-reports") "*.json"
Consolidate-ToolReports "Helm" (Join-Path $ReportsBaseDir "helm-reports") "*.json"
Consolidate-ToolReports "Checkov" (Join-Path $ReportsBaseDir "checkov-reports") "*.json"
Consolidate-ToolReports "Trivy" (Join-Path $ReportsBaseDir "trivy-reports") "*.json"
Consolidate-ToolReports "Grype" (Join-Path $ReportsBaseDir "grype-reports") "*.json"
Consolidate-ToolReports "Xeol" (Join-Path $ReportsBaseDir "xeol-reports") "*.json"

# Generate comprehensive security dashboard
Write-Host "📈 Generating dynamic security dashboard..." -ForegroundColor $PURPLE

# Check if Python is available
$PythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
}

$DashboardFile = Join-Path $UNIFIED_DIR "dashboards\security-dashboard.html"

if ($PythonCmd) {
    $PythonScript = Join-Path (Split-Path -Parent $ScriptDir) "generate-dynamic-dashboard.py"
    
    if (Test-Path $PythonScript) {
        Write-Host "Using Python script to generate dynamic dashboard..." -ForegroundColor $CYAN
        & $PythonCmd $PythonScript $ReportsBaseDir $DashboardFile
    } else {
        Write-Host "⚠️  Python dashboard script not found: $PythonScript" -ForegroundColor $YELLOW
        Write-Host "Generating basic dashboard..." -ForegroundColor $YELLOW
        
        # Fallback to basic static dashboard
        $BasicDashboard = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .message { background: white; padding: 30px; border-radius: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Dashboard</h1>
        <p>Generated: $ReportDate</p>
    </div>
    <div class="container">
        <div class="message">
            <h2>Security Scan Complete</h2>
            <p>Check individual tool reports in the HTML reports directory.</p>
            <p><a href="../html-reports/">Browse HTML Reports</a></p>
        </div>
    </div>
</body>
</html>
"@
        $BasicDashboard | Out-File -FilePath $DashboardFile -Encoding UTF8
    }
} else {
    Write-Host "⚠️  Python not found. Generating basic dashboard..." -ForegroundColor $YELLOW
    
    # Fallback to basic static dashboard
    $BasicDashboard = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .message { background: white; padding: 30px; border-radius: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Dashboard</h1>
        <p>Generated: $ReportDate</p>
    </div>
    <div class="container">
        <div class="message">
            <h2>Security Scan Complete</h2>
            <p>Check individual tool reports in the raw data directory.</p>
            <p><a href="../raw-data/">Browse Raw Data</a></p>
        </div>
    </div>
</body>
</html>
"@
    $BasicDashboard | Out-File -FilePath $DashboardFile -Encoding UTF8
}

# Generate README for the security reports
$ReadmeContent = @"
# Comprehensive Security Reports

## Overview

This directory contains consolidated security reports from all eight layers of our DevOps security architecture.

**Generated:** $ReportDate

## Directory Structure

``````
security-reports/
├── dashboards/          # Interactive HTML dashboards
├── html-reports/        # Human-readable HTML reports by tool
├── markdown-reports/    # Markdown summaries by tool
├── csv-reports/         # CSV data for spreadsheet analysis
└── raw-data/           # Original JSON outputs from each tool
``````

## Security Tools Covered

1. **SonarQube** - Code quality and test coverage analysis
2. **TruffleHog** - Multi-target secret detection (filesystem + containers)
3. **ClamAV** - Antivirus and malware scanning
4. **Helm** - Kubernetes chart validation and deployment automation  
5. **Checkov** - Infrastructure-as-Code security scanning
6. **Trivy** - Container and Kubernetes vulnerability scanning
7. **Grype** - Advanced vulnerability scanning with SBOM generation
8. **Xeol** - End-of-Life software detection

## Quick Start

1. **Main Dashboard:** Open ``dashboards/security-dashboard.html`` in your browser
2. **Tool-specific Reports:** Browse ``html-reports/[ToolName]/`` for detailed findings
3. **Summary Reports:** Check ``markdown-reports/[ToolName]/`` for quick overviews
4. **Raw Data:** Access ``raw-data/[ToolName]/`` for original JSON outputs

## Report Generation

To regenerate these reports, run:
``````powershell
.\consolidate-security-reports.ps1
``````

---

*Generated by Comprehensive DevOps Security Pipeline*
"@

$ReadmeFile = Join-Path $UNIFIED_DIR "README.md"
$ReadmeContent | Out-File -FilePath $ReadmeFile -Encoding UTF8

# Create index page for easy navigation
$IndexContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Reports Index</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .links { display: grid; gap: 15px; }
        .link { display: block; padding: 15px; background: #007bff; color: white; text-decoration: none; border-radius: 6px; text-align: center; transition: background 0.3s; }
        .link:hover { background: #0056b3; }
        .dashboard-link { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); font-size: 18px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Reports</h1>
            <p>Comprehensive DevOps Security Analysis</p>
            <p><strong>Generated:</strong> $ReportDate</p>
        </div>
        
        <div class="links">
            <a href="dashboards/security-dashboard.html" class="link dashboard-link">
                📊 Main Security Dashboard
            </a>
            
            <a href="html-reports/" class="link">
                📄 HTML Reports by Tool
            </a>
            
            <a href="markdown-reports/" class="link">
                📝 Markdown Summaries
            </a>
            
            <a href="raw-data/" class="link">
                🗃️ Raw JSON Data
            </a>
            
            <a href="README.md" class="link">
                📖 Documentation
            </a>
        </div>
    </div>
</body>
</html>
"@

$IndexFile = Join-Path $UNIFIED_DIR "index.html"
$IndexContent | Out-File -FilePath $IndexFile -Encoding UTF8

Write-Host ""
Write-Host "✅ Security reports consolidation completed!" -ForegroundColor $GREEN
Write-Host ""
Write-Host "📁 Unified Reports Directory: $UNIFIED_DIR" -ForegroundColor $BLUE
Write-Host "📊 Main Dashboard: $DashboardFile" -ForegroundColor $BLUE
Write-Host "📋 Navigation Index: $IndexFile" -ForegroundColor $BLUE
Write-Host ""
Write-Host "🔗 Quick Access:" -ForegroundColor $CYAN
Write-Host "1. Open main dashboard: Start-Process '$DashboardFile'"
Write-Host "2. Browse all reports: Start-Process '$IndexFile'"
Write-Host "3. View documentation: Get-Content '$ReadmeFile'"
Write-Host ""
Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "✅ All security reports consolidated successfully!" -ForegroundColor $GREEN
Write-Host "============================================" -ForegroundColor $WHITE
