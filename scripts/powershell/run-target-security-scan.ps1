# Target-Aware Complete Security Scan Orchestration Script
# Runs all eight security layers with multi-target scanning capabilities on external directories
# Usage: .\run-target-security-scan.ps1 <target_directory> [quick|full|images|analysis]

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetDir,
    
    [Parameter(Position=1)]
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

# Validate inputs
if (-not $TargetDir) {
    Write-Host "❌ Error: Target directory is required" -ForegroundColor $RED
    Write-Host "Usage: .\run-target-security-scan.ps1 <target_directory> [quick|full|images|analysis]"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run-target-security-scan.ps1 'C:\Users\rnelson\Desktop\CDAO Marketplace\advana-marketplace-monolith-node' full"
    Write-Host "  .\run-target-security-scan.ps1 '.\my-project' quick"
    Write-Host "  .\run-target-security-scan.ps1 'C:\path\to\project' images"
    exit 1
}

# Resolve absolute path
if (-not (Test-Path $TargetDir)) {
    Write-Host "❌ Error: Target directory does not exist: $TargetDir" -ForegroundColor $RED
    exit 1
}
$TargetDir = (Resolve-Path $TargetDir).Path

Write-Host "============================================"
Write-Host "🛡️  Target-Aware Security Scan Orchestrator"
Write-Host "============================================"
Write-Host "Security Tools Dir: $RepoRoot"
Write-Host "Target Directory: $TargetDir"
Write-Host "Scan Type: $ScanType"
Write-Host "Timestamp: $(Get-Date)"
Write-Host ""

# Export TARGET_DIR for all child scripts
$env:TARGET_DIR = $TargetDir

# Function to print section headers
function Write-Section {
    param([string]$Message)
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $BLUE
    Write-Host "🔹 $Message" -ForegroundColor $CYAN
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor $BLUE
    Write-Host ""
}

# Function to run security tools with target directory
function Invoke-SecurityTool {
    param(
        [string]$ToolName,
        [string]$ScriptPath,
        [string]$Args = ""
    )
    
    Write-Host "🔍 Running $ToolName..." -ForegroundColor $YELLOW
    Write-Host "Command: $ScriptPath $Args"
    Write-Host "Target: $TargetDir"
    Write-Host "Started: $(Get-Date)"
    Write-Host ""
    
    if (Test-Path $ScriptPath) {
        Push-Location $RepoRoot
        
        try {
            if ($Args) {
                & $ScriptPath $Args.Split(' ')
            } else {
                & $ScriptPath
            }
            
            if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
                Write-Host "✅ $ToolName completed successfully" -ForegroundColor $GREEN
            } else {
                Write-Host "⚠️  $ToolName completed with warnings" -ForegroundColor $YELLOW
            }
        } catch {
            Write-Host "❌ $ToolName failed: $_" -ForegroundColor $RED
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "❌ $ToolName script not found: $ScriptPath" -ForegroundColor $RED
        return $false
    }
    Write-Host ""
    return $true
}

# Validate target directory content
Write-Section "Target Directory Analysis"
Write-Host "📂 Analyzing target directory..." -ForegroundColor $CYAN
Write-Host "Directory: $TargetDir"

$DirSize = (Get-ChildItem -Path $TargetDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
$DirSizeGB = [math]::Round($DirSize / 1GB, 2)
$FileCount = (Get-ChildItem -Path $TargetDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host "Size: $DirSizeGB GB"
Write-Host "Files: $FileCount"

if (Test-Path (Join-Path $TargetDir "package.json")) {
    Write-Host "✅ Node.js project detected" -ForegroundColor $GREEN
    $PackageJson = Get-Content (Join-Path $TargetDir "package.json") -Raw | ConvertFrom-Json
    Write-Host "Package: $($PackageJson.name)"
    Write-Host "Version: $($PackageJson.version)"
}

if (Test-Path (Join-Path $TargetDir "Dockerfile")) {
    Write-Host "✅ Docker project detected" -ForegroundColor $GREEN
}

if (Test-Path (Join-Path $TargetDir ".git")) {
    Write-Host "✅ Git repository detected" -ForegroundColor $GREEN
}

Write-Host ""

# Main security scan execution
switch ($ScanType) {
    "quick" {
        Write-Section "Quick Security Scan (Core Tools Only) - Target: $(Split-Path $TargetDir -Leaf)"
        
        # Core security tools - filesystem only
        Invoke-SecurityTool "TruffleHog Secret Detection" "$ScriptDir\run-trufflehog-scan.ps1"
        Invoke-SecurityTool "ClamAV Antivirus Scan" "$ScriptDir\run-clamav-scan.ps1"
        Invoke-SecurityTool "Grype Vulnerability Scanning" "$ScriptDir\run-grype-scan.ps1" "filesystem"
        Invoke-SecurityTool "Trivy Security Analysis" "$ScriptDir\run-trivy-scan.ps1" "filesystem"
    }
    
    "images" {
        Write-Section "Container Image Security Scan (All Image Types) - Target: $(Split-Path $TargetDir -Leaf)"
        
        # Multi-target container image scanning
        Invoke-SecurityTool "TruffleHog Container Images" "$ScriptDir\run-trufflehog-scan.ps1"
        Invoke-SecurityTool "Grype Container Images" "$ScriptDir\run-grype-scan.ps1" "images"
        Invoke-SecurityTool "Grype Base Images" "$ScriptDir\run-grype-scan.ps1" "base"
        Invoke-SecurityTool "Trivy Container Images" "$ScriptDir\run-trivy-scan.ps1" "images"
        Invoke-SecurityTool "Trivy Base Images" "$ScriptDir\run-trivy-scan.ps1" "base"
        Invoke-SecurityTool "Xeol End-of-Life Detection" "$ScriptDir\run-xeol-scan.ps1"
    }
    
    "analysis" {
        Write-Section "Security Analysis & Reporting - Target: $(Split-Path $TargetDir -Leaf)"
        
        # Analysis mode - process existing reports without running new scans
        Write-Host "📊 Processing existing security reports for analysis..." -ForegroundColor $BLUE
        Write-Host "ℹ️  Analysis mode processes existing scan results without running new scans" -ForegroundColor $YELLOW
        Write-Host ""
    }
    
    "full" {
        Write-Section "Complete Eight-Layer Security Architecture Scan - Target: $(Split-Path $TargetDir -Leaf)"
        
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
    Push-Location $RepoRoot
    & $ConsolidateScript
    Pop-Location
    Write-Host "✅ Security reports consolidated" -ForegroundColor $GREEN
} else {
    Write-Host "⚠️  Consolidation script not found" -ForegroundColor $YELLOW
}

Write-Host ""
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "🎉 Target Security Scan Complete!" -ForegroundColor $GREEN
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Target: $TargetDir"
Write-Host "Scan Type: $ScanType"
Write-Host "Completed: $(Get-Date)"
Write-Host ""
Write-Host "📊 View the security dashboard:" -ForegroundColor $CYAN
Write-Host "   .\open-dashboard.ps1"
Write-Host ""
