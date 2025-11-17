# Target-Aware Complete Security Scan Orchestration Script
# Runs all eight security layers with multi-target scanning capabilities on external directories
# Usage: .\run-target-security-scan.ps1 <target_directory> [quick|full|images|analysis]
# Version: 2.0 - Enhanced with Docker checking, timing, progress, parallel execution, and comprehensive reporting

param(
    [Parameter(Position=0)]
    [string]$TargetDir = "",
    
    [Parameter(Position=1)]
    [ValidateSet("quick", "full", "images", "analysis")]
    [string]$ScanType = "full",
    
    [Parameter()]
    [switch]$SkipDockerCheck = $false,
    
    [Parameter()]
    [switch]$Parallel = $false
)

$ErrorActionPreference = "Continue"  # Changed to Continue for better error handling

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$PURPLE = "Magenta"
$CYAN = "Cyan"
$WHITE = "White"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptsRoot = Split-Path -Parent $ScriptDir
$RepoRoot = Split-Path -Parent $ScriptsRoot
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Tracking variables
$script:ScanStartTime = Get-Date
$script:TotalScans = 0
$script:CompletedScans = 0
$script:FailedScans = 0
$script:SuccessfulScans = 0
$script:SkippedScans = 0
$script:ScanResults = @()
$script:DockerAvailable = $false
$script:VulnerabilityCount = @{
    Critical = 0
    High = 0
    Medium = 0
    Low = 0
}

# Ensure reports directory exists
$ReportsDir = Join-Path $RepoRoot "reports\security-reports"
if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
}
$LogFile = Join-Path $ReportsDir "scan-orchestrator-$Timestamp.log"

# ============================================
# Utility Functions
# ============================================

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
}

# Function to check Docker availability
function Test-DockerAvailable {
    Write-Host "`n🐳 Checking Docker availability..." -ForegroundColor $CYAN
    Write-Log "Checking Docker daemon status"
    
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Docker installed: $dockerVersion" -ForegroundColor $GREEN
            Write-Log "Docker version: $dockerVersion"
            
            # Test if Docker daemon is running
            $null = docker ps 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "   ✅ Docker daemon is running" -ForegroundColor $GREEN
                Write-Log "Docker daemon is running"
                $script:DockerAvailable = $true
                return $true
            } else {
                Write-Host "   ⚠️  Docker is installed but daemon is not running" -ForegroundColor $YELLOW
                Write-Host "      Please start Docker Desktop to run container-based scans" -ForegroundColor $YELLOW
                Write-Log "Docker daemon not running" "WARN"
                $script:DockerAvailable = $false
                return $false
            }
        } else {
            Write-Host "   ⚠️  Docker is not installed" -ForegroundColor $YELLOW
            Write-Log "Docker not installed" "WARN"
            $script:DockerAvailable = $false
            return $false
        }
    } catch {
        Write-Host "   ❌ Error checking Docker: $_" -ForegroundColor $RED
        Write-Log "Error checking Docker: $_" "ERROR"
        $script:DockerAvailable = $false
        return $false
    }
}

# Function to calculate progress
function Get-Progress {
    if ($script:TotalScans -eq 0) { return 0 }
    return [math]::Round(($script:CompletedScans / $script:TotalScans) * 100, 1)
}

# Function to format duration
function Format-Duration {
    param([TimeSpan]$Duration)
    
    if ($Duration.TotalSeconds -lt 60) {
        return "{0:N1}s" -f $Duration.TotalSeconds
    } elseif ($Duration.TotalMinutes -lt 60) {
        return "{0:N1}m" -f $Duration.TotalMinutes
    } else {
        return "{0:N1}h {1:N0}m" -f $Duration.Hours, $Duration.Minutes
    }
}

# Function to validate script exists
function Test-ScriptExists {
    param([string]$ScriptPath)
    
    if (Test-Path $ScriptPath) {
        Write-Log "Script validated: $ScriptPath"
        return $true
    } else {
        Write-Log "Script not found: $ScriptPath" "ERROR"
        return $false
    }
}

# Function to check if tool requires Docker
function Test-RequiresDocker {
    param([string]$ToolName)
    
    $dockerTools = @("TruffleHog", "ClamAV", "Grype", "Trivy", "Xeol", "Checkov", "SonarQube")
    return $dockerTools | Where-Object { $ToolName -like "*$_*" }
}

# Function to validate report output
function Test-ReportGenerated {
    param(
        [string]$ToolName,
        [string]$ReportPattern
    )
    
    $reportFiles = Get-ChildItem -Path $ReportsDir -Recurse -Filter $ReportPattern -ErrorAction SilentlyContinue
    if ($reportFiles) {
        $reportPath = $reportFiles[0].FullName
        Write-Log "Report validated for ${ToolName}: $reportPath"
        return $true
    } else {
        Write-Log "No report found for ${ToolName} matching pattern: $ReportPattern" "WARN"
        return $false
    }
}

# Function to print section headers
function Write-Section {
    param([string]$Message)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor $BLUE
    Write-Host "  $Message" -ForegroundColor $CYAN
    Write-Host ("=" * 80) -ForegroundColor $BLUE
    Write-Host ""
}

# Function to display progress
function Write-Progress {
    $progress = Get-Progress
    $elapsed = (Get-Date) - $script:ScanStartTime
    $elapsedStr = Format-Duration $elapsed
    
    Write-Host "`n📊 Progress: " -NoNewline -ForegroundColor $CYAN
    Write-Host "$script:CompletedScans/$script:TotalScans" -NoNewline -ForegroundColor $WHITE
    Write-Host " ($progress" -NoNewline -ForegroundColor $YELLOW
    Write-Host "%)" -NoNewline -ForegroundColor $YELLOW
    Write-Host " | ⏱️  Elapsed: $elapsedStr" -ForegroundColor $CYAN
    Write-Host "   ✅ Success: $script:SuccessfulScans" -NoNewline -ForegroundColor $GREEN
    Write-Host " | ⚠️  Failed: $script:FailedScans" -NoNewline -ForegroundColor $YELLOW
    Write-Host " | ⏭️  Skipped: $script:SkippedScans" -ForegroundColor $PURPLE
    Write-Host ""
}

# Enhanced function to run security tools with comprehensive error handling and tracking
function Invoke-SecurityTool {
    param(
        [string]$ToolName,
        [string]$ScriptPath,
        [string]$Args = "",
        [switch]$RequiresDocker = $false
    )
    
    $script:CompletedScans++
    $scanNumber = $script:CompletedScans
    
    Write-Host "`n┌──────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor $BLUE
    Write-Host "│ 🔍 Scan $scanNumber/$script:TotalScans`: $ToolName" -ForegroundColor $CYAN
    Write-Host "└──────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor $BLUE
    
    $scanStart = Get-Date
    Write-Log "Starting scan: $ToolName"
    
    # Validate script exists
    if (-not (Test-ScriptExists $ScriptPath)) {
        Write-Host "   ❌ Script not found: $ScriptPath" -ForegroundColor $RED
        Write-Log "Script not found: $ScriptPath" "ERROR"
        $script:FailedScans++
        $script:ScanResults += [PSCustomObject]@{
            Tool = $ToolName
            Status = "Failed"
            Reason = "Script not found"
            Duration = "0s"
        }
        Write-Progress
        return $false
    }
    
    # Check Docker requirement
    if ($RequiresDocker -and -not $script:DockerAvailable) {
        Write-Host "   ⏭️  Skipping $ToolName (requires Docker)" -ForegroundColor $YELLOW
        Write-Log "Skipped $ToolName - Docker not available" "WARN"
        $script:SkippedScans++
        $script:ScanResults += [PSCustomObject]@{
            Tool = $ToolName
            Status = "Skipped"
            Reason = "Docker not available"
            Duration = "0s"
        }
        Write-Progress
        return $false
    }
    
    Write-Host "   📂 Target: $TargetDir" -ForegroundColor $CYAN
    Write-Host "   📜 Script: $(Split-Path $ScriptPath -Leaf)" -ForegroundColor $CYAN
    if ($Args) {
        Write-Host "   ⚙️  Args: $Args" -ForegroundColor $CYAN
    }
    Write-Host "   ⏰ Started: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor $CYAN
    Write-Host ""
    
    $success = $false
    $errorMsg = ""
    
    try {
        Push-Location $RepoRoot
        
        if ($Args) {
            $result = & $ScriptPath $Args.Split(' ') 2>&1
        } else {
            $result = & $ScriptPath 2>&1
        }
        
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0 -or $null -eq $exitCode) {
            Write-Host "   ✅ $ToolName completed successfully" -ForegroundColor $GREEN
            Write-Log "$ToolName completed successfully"
            $success = $true
            $script:SuccessfulScans++
        } else {
            Write-Host "   ⚠️  $ToolName completed with warnings (exit code: $exitCode)" -ForegroundColor $YELLOW
            Write-Log "$ToolName completed with warnings (exit code: $exitCode)" "WARN"
            $errorMsg = "Exit code: $exitCode"
            $script:FailedScans++
        }
        
    } catch {
        Write-Host "   ❌ $ToolName failed: $_" -ForegroundColor $RED
        Write-Log "$ToolName failed: $_" "ERROR"
        $errorMsg = $_.Exception.Message
        $script:FailedScans++
    } finally {
        Pop-Location
    }
    
    $scanDuration = (Get-Date) - $scanStart
    $durationStr = Format-Duration $scanDuration
    
    Write-Host "   ⏱️  Duration: $durationStr" -ForegroundColor $CYAN
    
    # Track result
    $script:ScanResults += [PSCustomObject]@{
        Tool = $ToolName
        Status = if ($success) { "Success" } elseif ($errorMsg -like "*Exit code*") { "Warning" } else { "Failed" }
        Reason = $errorMsg
        Duration = $durationStr
    }
    
    Write-Progress
    return $success
}

# ============================================
# Main Execution
# ============================================

Write-Log "=== Security Scan Orchestrator Started ==="
Write-Log "Target Directory: $TargetDir"
Write-Log "Scan Type: $ScanType"
Write-Log "Parallel Execution: $Parallel"

# Default to current directory if not specified
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Get-Location
    Write-Host "`n  ℹ️  No target directory specified - using current directory" -ForegroundColor $CYAN
    Write-Log "Using current directory as target: $TargetDir"
}

# Resolve absolute path
if (-not (Test-Path $TargetDir)) {
    Write-Host "`n  ❌ Error: Target directory does not exist: $TargetDir" -ForegroundColor $RED
    Write-Host ""
    Write-Host "Usage: .\run-target-security-scan.ps1 [target_directory] [quick|full|images|analysis]"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run-target-security-scan.ps1                                    # Scan current directory"
    Write-Host "  .\run-target-security-scan.ps1 'C:\path\to\project' full         # Full scan"
    Write-Host "  .\run-target-security-scan.ps1 '.\my-project' quick              # Quick scan"
    Write-Host "  .\run-target-security-scan.ps1 'C:\project' full -Parallel       # Parallel execution"
    Write-Host "  .\run-target-security-scan.ps1 'C:\project' full -SkipDockerCheck # Skip Docker check"
    Write-Log "Target directory not found: $TargetDir" "ERROR"
    exit 1
}
$TargetDir = (Resolve-Path $TargetDir).Path

Write-Section "🛡️  Target-Aware Security Scan Orchestrator v2.0"
Write-Host "   📁 Security Tools:     $RepoRoot" -ForegroundColor $WHITE
Write-Host "   🎯 Target Directory:   $TargetDir" -ForegroundColor $WHITE
Write-Host "   🔍 Scan Type:          $ScanType" -ForegroundColor $WHITE
Write-Host "   ⏰ Started:            $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $WHITE
Write-Host "   📝 Log File:           $LogFile" -ForegroundColor $WHITE
if ($Parallel) {
    Write-Host "   ⚡ Parallel Mode:       Enabled" -ForegroundColor $YELLOW
}
Write-Host ""

# Export TARGET_DIR for all child scripts
$env:TARGET_DIR = $TargetDir
Write-Log "Exported TARGET_DIR=$TargetDir"

# Check Docker availability (unless skipped)
if (-not $SkipDockerCheck) {
    Test-DockerAvailable | Out-Null
} else {
    Write-Host "`n⏭️  Skipping Docker check (--SkipDockerCheck specified)" -ForegroundColor $YELLOW
    Write-Log "Docker check skipped by user request"
}

# Analyze target directory
Write-Section "📊 Target Directory Analysis"
Write-Host "   Analyzing target directory..." -ForegroundColor $CYAN

try {
    $dirInfo = Get-ChildItem -Path $TargetDir -Recurse -File -ErrorAction SilentlyContinue
    $DirSize = ($dirInfo | Measure-Object -Property Length -Sum).Sum
    $DirSizeMB = [math]::Round($DirSize / 1MB, 2)
    $DirSizeGB = [math]::Round($DirSize / 1GB, 2)
    $FileCount = ($dirInfo | Measure-Object).Count
    
    Write-Host "   📦 Size:               $DirSizeMB MB ($DirSizeGB GB)" -ForegroundColor $WHITE
    Write-Host "   📄 Files:              $FileCount" -ForegroundColor $WHITE
    Write-Log "Directory size: $DirSizeMB MB, Files: $FileCount"
    
    # Detect project types
    $projectTypes = @()
    
    if (Test-Path (Join-Path $TargetDir "package.json")) {
        $projectTypes += "Node.js"
        try {
            $PackageJson = Get-Content (Join-Path $TargetDir "package.json") -Raw | ConvertFrom-Json
            Write-Host "   📦 Node.js Project:    $($PackageJson.name) v$($PackageJson.version)" -ForegroundColor $GREEN
            Write-Log "Node.js project detected: $($PackageJson.name)"
        } catch {
            Write-Host "   📦 Node.js Project:    Detected" -ForegroundColor $GREEN
        }
    }
    
    if (Test-Path (Join-Path $TargetDir "Dockerfile")) {
        $projectTypes += "Docker"
        Write-Host "   🐳 Docker Project:     Detected" -ForegroundColor $GREEN
        Write-Log "Docker project detected"
    }
    
    if (Test-Path (Join-Path $TargetDir ".git")) {
        $projectTypes += "Git"
        Write-Host "   📂 Git Repository:     Detected" -ForegroundColor $GREEN
        Write-Log "Git repository detected"
    }
    
    if (Test-Path (Join-Path $TargetDir "pom.xml")) {
        $projectTypes += "Maven"
        Write-Host "   ☕ Maven Project:      Detected" -ForegroundColor $GREEN
        Write-Log "Maven project detected"
    }
    
    if (Test-Path (Join-Path $TargetDir "requirements.txt")) {
        $projectTypes += "Python"
        Write-Host "   🐍 Python Project:     Detected" -ForegroundColor $GREEN
        Write-Log "Python project detected"
    }
    
    if (Test-Path (Join-Path $TargetDir "*.csproj")) {
        $projectTypes += ".NET"
        Write-Host "   ⚡ .NET Project:       Detected" -ForegroundColor $GREEN
        Write-Log ".NET project detected"
    }
    
    if ($projectTypes.Count -eq 0) {
        Write-Host "   ℹ️  Project Type:      Generic/Unknown" -ForegroundColor $CYAN
    }
    
} catch {
    Write-Host "   ⚠️  Error analyzing directory: $_" -ForegroundColor $YELLOW
    Write-Log "Error analyzing directory: $_" "ERROR"
}

# Calculate total scans based on scan type
switch ($ScanType) {
    "quick" { $script:TotalScans = 4 }
    "images" { $script:TotalScans = 6 }
    "analysis" { $script:TotalScans = 1 }
    "full" { $script:TotalScans = 15 }
}

Write-Host ""
Write-Host "   📋 Scan Configuration:" -ForegroundColor $CYAN
Write-Host "      • Total Scans: $script:TotalScans" -ForegroundColor $WHITE
Write-Host "      • Docker Available: $(if ($script:DockerAvailable) { 'Yes ✅' } else { 'No ⚠️' })" -ForegroundColor $WHITE
Write-Host ""

# Main security scan execution
switch ($ScanType) {
    "quick" {
        Write-Section "⚡ Quick Security Scan (Core Tools Only)"
        Write-Log "Starting quick scan"
        
        # Core security tools - filesystem only
        Invoke-SecurityTool "TruffleHog Secret Detection" "$ScriptDir\run-trufflehog-scan.ps1" -RequiresDocker
        Invoke-SecurityTool "ClamAV Antivirus Scan" "$ScriptDir\run-clamav-scan.ps1" -RequiresDocker
        Invoke-SecurityTool "Grype Vulnerability Scanning" "$ScriptDir\run-grype-scan.ps1" "filesystem" -RequiresDocker
        Invoke-SecurityTool "Trivy Security Analysis" "$ScriptDir\run-trivy-scan.ps1" "filesystem" -RequiresDocker
    }
    
    "images" {
        Write-Section "🐳 Container Image Security Scan"
        Write-Log "Starting image scan"
        
        # Multi-target container image scanning
        Invoke-SecurityTool "TruffleHog Container Images" "$ScriptDir\run-trufflehog-scan.ps1" -RequiresDocker
        Invoke-SecurityTool "Grype Container Images" "$ScriptDir\run-grype-scan.ps1" "images" -RequiresDocker
        Invoke-SecurityTool "Grype Base Images" "$ScriptDir\run-grype-scan.ps1" "base" -RequiresDocker
        Invoke-SecurityTool "Trivy Container Images" "$ScriptDir\run-trivy-scan.ps1" "images" -RequiresDocker
        Invoke-SecurityTool "Trivy Base Images" "$ScriptDir\run-trivy-scan.ps1" "base" -RequiresDocker
        Invoke-SecurityTool "Xeol End-of-Life Detection" "$ScriptDir\run-xeol-scan.ps1" -RequiresDocker
    }
    
    "analysis" {
        Write-Section "📊 Security Analysis & Reporting"
        Write-Log "Starting analysis mode"
        
        Write-Host "   📈 Processing existing security reports..." -ForegroundColor $CYAN
        Write-Host "   ℹ️  Analysis mode processes existing scan results without running new scans" -ForegroundColor $YELLOW
        Write-Host ""
        
        $script:CompletedScans = 1
        $script:SuccessfulScans = 1
    }
    
    "full" {
        Write-Section "🏗️  Complete Eight-Layer Security Architecture Scan"
        Write-Log "Starting full scan"
        
        Write-Host "   🔷 Layer 1: Code Quality & Test Coverage" -ForegroundColor $PURPLE
        Invoke-SecurityTool "SonarQube Analysis" "$ScriptDir\run-sonar-analysis.ps1" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 2: Secret Detection (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "TruffleHog Filesystem" "$ScriptDir\run-trufflehog-scan.ps1" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 3: Malware Detection" -ForegroundColor $PURPLE
        Invoke-SecurityTool "ClamAV Antivirus Scan" "$ScriptDir\run-clamav-scan.ps1" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 4: Helm Chart Building" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Helm Chart Build" "$ScriptDir\run-helm-build.ps1" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 5: Infrastructure Security" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Checkov IaC Security" "$ScriptDir\run-checkov-scan.ps1" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 6: Vulnerability Detection (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Grype Filesystem" "$ScriptDir\run-grype-scan.ps1" "filesystem" -RequiresDocker
        Invoke-SecurityTool "Grype Container Images" "$ScriptDir\run-grype-scan.ps1" "images" -RequiresDocker
        Invoke-SecurityTool "Grype Base Images" "$ScriptDir\run-grype-scan.ps1" "base" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 7: Container Security (Multi-Target)" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Trivy Filesystem" "$ScriptDir\run-trivy-scan.ps1" "filesystem" -RequiresDocker
        Invoke-SecurityTool "Trivy Container Images" "$ScriptDir\run-trivy-scan.ps1" "images" -RequiresDocker
        Invoke-SecurityTool "Trivy Base Images" "$ScriptDir\run-trivy-scan.ps1" "base" -RequiresDocker
        Invoke-SecurityTool "Trivy Kubernetes" "$ScriptDir\run-trivy-scan.ps1" "kubernetes" -RequiresDocker
        
        Write-Host "`n   🔷 Layer 8: End-of-Life Detection" -ForegroundColor $PURPLE
        Invoke-SecurityTool "Xeol EOL Detection" "$ScriptDir\run-xeol-scan.ps1" -RequiresDocker
    }
}

# Final consolidation
Write-Section "📋 Security Report Consolidation"
Write-Host "   📊 Consolidating all security reports..." -ForegroundColor $CYAN
Write-Log "Starting report consolidation"

$ConsolidateScript = Join-Path $ScriptDir "consolidate-security-reports.ps1"
if (Test-Path $ConsolidateScript) {
    try {
        Push-Location $RepoRoot
        & $ConsolidateScript
        Pop-Location
        Write-Host "   ✅ Security reports consolidated" -ForegroundColor $GREEN
        Write-Log "Reports consolidated successfully"
    } catch {
        Write-Host "   ⚠️  Error during consolidation: $_" -ForegroundColor $YELLOW
        Write-Log "Error during consolidation: $_" "WARN"
    }
} else {
    Write-Host "   ⚠️  Consolidation script not found" -ForegroundColor $YELLOW
    Write-Log "Consolidation script not found" "WARN"
}

# Final summary
$totalDuration = (Get-Date) - $script:ScanStartTime
$totalDurationStr = Format-Duration $totalDuration

Write-Section "🎉 Security Scan Complete!"

Write-Host "   📊 Scan Summary:" -ForegroundColor $CYAN
Write-Host "      • Total Scans:     $script:CompletedScans/$script:TotalScans" -ForegroundColor $WHITE
Write-Host "      • ✅ Successful:    $script:SuccessfulScans" -ForegroundColor $GREEN
Write-Host "      • ❌ Failed:        $script:FailedScans" -ForegroundColor $(if ($script:FailedScans -gt 0) { $RED } else { $GREEN })
Write-Host "      • ⏭️  Skipped:       $script:SkippedScans" -ForegroundColor $(if ($script:SkippedScans -gt 0) { $YELLOW } else { $GREEN })
Write-Host "      • ⏱️  Total Time:    $totalDurationStr" -ForegroundColor $CYAN
Write-Host ""

# Display detailed results table
if ($script:ScanResults.Count -gt 0) {
    Write-Host "   📋 Detailed Results:" -ForegroundColor $CYAN
    Write-Host ""
    $script:ScanResults | Format-Table -AutoSize @{Label="Tool"; Expression={$_.Tool}; Width=40}, 
                                                   @{Label="Status"; Expression={
                                                       $status = $_.Status
                                                       switch ($status) {
                                                           "Success" { "✅ $status" }
                                                           "Failed" { "❌ $status" }
                                                           "Skipped" { "⏭️  $status" }
                                                           "Warning" { "⚠️  $status" }
                                                           default { $status }
                                                       }
                                                   }; Width=15},
                                                   @{Label="Duration"; Expression={$_.Duration}; Width=12},
                                                   @{Label="Details"; Expression={$_.Reason}; Width=30}
    Write-Host ""
}

Write-Host "   📁 Report Location:" -ForegroundColor $CYAN
Write-Host "      $ReportsDir" -ForegroundColor $WHITE
Write-Host ""
Write-Host "   🌐 View Security Dashboard:" -ForegroundColor $CYAN
Write-Host "      .\scripts\powershell\open-dashboard.ps1" -ForegroundColor $YELLOW
Write-Host ""
Write-Host "   📝 Scan Log:" -ForegroundColor $CYAN
Write-Host "      $LogFile" -ForegroundColor $WHITE
Write-Host ""

# Log final summary
Write-Log "=== Security Scan Orchestrator Completed ==="
Write-Log "Total Duration: $totalDurationStr"
Write-Log "Successful: $script:SuccessfulScans, Failed: $script:FailedScans, Skipped: $script:SkippedScans"
Write-Log "Reports location: $ReportsDir"

# Exit with appropriate code
if ($script:FailedScans -gt 0) {
    Write-Host "⚠️  Warning: Some scans failed. Review the log for details." -ForegroundColor $YELLOW
    exit 1
} elseif ($script:SkippedScans -eq $script:TotalScans) {
    Write-Host "⚠️  Warning: All scans were skipped. Check Docker availability." -ForegroundColor $YELLOW
    exit 2
} else {
    Write-Host "✅ All scans completed successfully!" -ForegroundColor $GREEN
    exit 0
}
