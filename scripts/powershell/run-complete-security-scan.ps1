# Complete Security Scan Orchestration Script
# Runs all eight security layers with multi-target scanning capabilities
# Usage: .\run-complete-security-scan.ps1 [quick|full|images|analysis]

param(
    [Parameter(Position=0)]
    [ValidateSet("quick", "full", "images", "analysis")]
    [string]$ScanType = "full"
)

$ErrorActionPreference = "Stop"

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$PURPLE = "Magenta"
$CYAN = "Cyan"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptsRoot = Split-Path -Parent $ScriptDir
$RepoRoot = Split-Path -Parent $ScriptsRoot
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

Write-Host "============================================"
Write-Host "🛡️  Complete Security Scan Orchestrator"
Write-Host "============================================"
Write-Host "Repository: $RepoRoot"
Write-Host "Scan Type: $ScanType"
Write-Host "Timestamp: $(Get-Date)"
Write-Host ""

# Function to print section headers
function Write-Section {
    param([string]$Message)
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $BLUE
    Write-Host "🔹 $Message" -ForegroundColor $CYAN
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $BLUE
    Write-Host ""
}

# Function to run security tools
function Invoke-SecurityTool {
    param(
        [string]$ToolName,
        [string]$ScriptPath,
        [string]$Args = ""
    )
    
    Write-Host "🔍 Running $ToolName..." -ForegroundColor $YELLOW
    Write-Host "Command: $ScriptPath $Args"
    Write-Host "Started: $(Get-Date)"
    Write-Host ""
    
    if (Test-Path $ScriptPath) {
        try {
            if ($Args) {
                & $ScriptPath $Args.Split(' ')
            } else {
                & $ScriptPath
            }
            Write-Host "✅ $ToolName completed successfully" -ForegroundColor $GREEN
        } catch {
            Write-Host "❌ $ToolName failed: $_" -ForegroundColor $RED
            return $false
        }
    } else {
        Write-Host "❌ $ToolName script not found: $ScriptPath" -ForegroundColor $RED
        return $false
    }
    Write-Host ""
    return $true
}

# Main security scan execution
switch ($ScanType) {
    "quick" {
        Write-Section "Quick Security Scan (Core Tools Only)"
        
        # Core security tools - filesystem only
        Invoke-SecurityTool "TruffleHog Secret Detection" "$ScriptDir\run-trufflehog-scan.ps1"
        Invoke-SecurityTool "ClamAV Antivirus Scan" "$ScriptDir\run-clamav-scan.ps1"
        Invoke-SecurityTool "SonarQube Code Quality" "$ScriptDir\run-sonar-analysis.ps1"
        Invoke-SecurityTool "Grype Vulnerability Scanning" "$ScriptDir\run-grype-scan.ps1" "filesystem"
        Invoke-SecurityTool "Trivy Security Analysis" "$ScriptDir\run-trivy-scan.ps1" "filesystem"
    }
    
    "images" {
        Write-Section "Container Image Security Scan (All Image Types)"
        
        # Multi-target container image scanning
        Invoke-SecurityTool "TruffleHog Container Images" "$ScriptDir\run-trufflehog-scan.ps1"
        Invoke-SecurityTool "Grype Container Images" "$ScriptDir\run-grype-scan.ps1" "images"
        Invoke-SecurityTool "Grype Base Images" "$ScriptDir\run-grype-scan.ps1" "base"
        Invoke-SecurityTool "Trivy Container Images" "$ScriptDir\run-trivy-scan.ps1" "images"
        Invoke-SecurityTool "Trivy Base Images" "$ScriptDir\run-trivy-scan.ps1" "base"
        Invoke-SecurityTool "Xeol End-of-Life Detection" "$ScriptDir\run-xeol-scan.ps1"
    }
    
    "analysis" {
        Write-Section "Security Analysis & Reporting"
        
        Write-Host "📊 Running analysis tools..." -ForegroundColor $BLUE
        # Analysis tools would go here
        Write-Host "ℹ️  Analysis mode processes existing scan results" -ForegroundColor $YELLOW
    }
    
    "full" {
        Write-Section "Complete Eight-Layer Security Architecture Scan"
        
        Write-Host "🏗️  Layer 1: Code Quality & Test Coverage" -ForegroundColor $PURPLE
        Invoke-SecurityTool "SonarQube Analysis" "$ScriptDir\run-sonar-analysis.ps1"
        
        Write-Host "🔐 Layer 2: Secret Detection (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "TruffleHog Filesystem" "$ScriptDir\run-trufflehog-scan.ps1"
        Invoke-SecurityTool "TruffleHog Container Images" "$ScriptDir\run-trufflehog-scan.ps1"
        
        Write-Host "🦠 Layer 3: Malware Detection" -ForegroundColor $PURPLE
        Invoke-SecurityTool "ClamAV Antivirus Scan" "$ScriptDir\run-clamav-scan.ps1"
        
        Write-Host "🏗️  Layer 4: Helm Chart Building" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Helm Chart Build" "$ScriptDir\run-helm-build.ps1"
        
        Write-Host "☸️  Layer 5: Infrastructure Security" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Checkov IaC Security" "$ScriptDir\run-checkov-scan.ps1"
        
        Write-Host "🔍 Layer 6: Vulnerability Detection (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Grype Filesystem" "$ScriptDir\run-grype-scan.ps1" "filesystem"
        Invoke-SecurityTool "Grype Container Images" "$ScriptDir\run-grype-scan.ps1" "images"
        Invoke-SecurityTool "Grype Base Images" "$ScriptDir\run-grype-scan.ps1" "base"
        
        Write-Host "🛡️  Layer 7: Container Security (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Trivy Filesystem" "$ScriptDir\run-trivy-scan.ps1" "filesystem"
        Invoke-SecurityTool "Trivy Container Images" "$ScriptDir\run-trivy-scan.ps1" "images"
        Invoke-SecurityTool "Trivy Base Images" "$ScriptDir\run-trivy-scan.ps1" "base"
        Invoke-SecurityTool "Trivy Kubernetes" "$ScriptDir\run-trivy-scan.ps1" "kubernetes"
        
        Write-Host "⚰️  Layer 8: End-of-Life Detection" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Xeol EOL Detection" "$ScriptDir\run-xeol-scan.ps1"
    }
}

# Final consolidation
Write-Section "Security Report Consolidation"
Write-Host "📊 Consolidating all security reports..." -ForegroundColor $CYAN

$ConsolidateScript = Join-Path $ScriptDir "consolidate-security-reports.ps1"
if (Test-Path $ConsolidateScript) {
    & $ConsolidateScript
    Write-Host "✅ Security reports consolidated" -ForegroundColor $GREEN
} else {
    Write-Host "⚠️  Consolidation script not found" -ForegroundColor $YELLOW
}

Write-Host ""
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "🎉 Complete Security Scan Finished!" -ForegroundColor $GREEN
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Scan Type: $ScanType"
Write-Host "Completed: $(Get-Date)"
Write-Host ""
Write-Host "📊 View the security dashboard:" -ForegroundColor $CYAN
Write-Host "   .\open-dashboard.ps1"
Write-Host ""
