# Universal Scan Directory Security Tool Template (PowerShell)
# This template shows how each security tool should be structured to use scan directories

<#
.SYNOPSIS
    Initialize scan environment for security tools with scan directory support
    
.DESCRIPTION
    Provides functions to manage scan directories, output paths, and result file naming
    for security scanning tools in a consistent manner
    
.EXAMPLE
    . .\Scan-Directory-Template.ps1
    Initialize-ScanEnvironment -ToolName "grype"
    $resultsFile = New-ResultFilePath -ToolName "grype" -ResultType "results"
    # ... run tool and save to $resultsFile ...
    Complete-ScanResults -ToolName "grype"
#>

function Initialize-ScanEnvironment {
    <#
    .SYNOPSIS
        Initialize scan environment for a security tool
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ToolName
    )
    
    # Use SCAN_DIR if provided (from orchestrator), otherwise create individual structure
    if ($env:SCAN_DIR) {
        # Orchestrated scan - use centralized scan directory
        $script:OUTPUT_DIR = Join-Path $env:SCAN_DIR $ToolName
        $script:SCAN_LOG = Join-Path $script:OUTPUT_DIR "scan.log"
        
        $scansParent = Split-Path -Parent $env:SCAN_DIR
        $reportsRoot = Split-Path -Parent $scansParent
        $script:CURRENT_LINK_DIR = Join-Path $reportsRoot "reports" "$ToolName-reports"
        
        # Create tool-specific directory within scan
        New-Item -ItemType Directory -Path $script:OUTPUT_DIR -Force | Out-Null
        New-Item -ItemType Directory -Path $script:CURRENT_LINK_DIR -Force | Out-Null
        
        Write-Host "🗂️  Using scan directory: $env:SCAN_DIR" -ForegroundColor Cyan
        Write-Host "📁 Tool output: $script:OUTPUT_DIR" -ForegroundColor Cyan
    }
    else {
        # Standalone execution - use traditional reports structure
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) {
            $scriptPath = $MyInvocation.PSCommandPath
        }
        $scriptDir = Split-Path -Parent $scriptPath
        $scriptsRoot = Split-Path -Parent $scriptDir
        $reportsRoot = Split-Path -Parent $scriptsRoot
        
        # Generate scan ID for standalone execution
        $targetDir = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
        $targetName = Split-Path -Leaf $targetDir
        $username = $env:USERNAME
        if (-not $username) { $username = $env:USER }
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $script:SCAN_ID = "${targetName}_${username}_${timestamp}"
        
        $script:OUTPUT_DIR = Join-Path $reportsRoot "reports" "$ToolName-reports"
        $script:SCAN_LOG = Join-Path $script:OUTPUT_DIR "${script:SCAN_ID}_${ToolName}-scan.log"
        $script:CURRENT_LINK_DIR = $script:OUTPUT_DIR
        
        New-Item -ItemType Directory -Path $script:OUTPUT_DIR -Force | Out-Null
        
        Write-Host "📁 Standalone mode - using reports directory: $script:OUTPUT_DIR" -ForegroundColor Cyan
    }
    
    # Export variables for use in tool scripts
    $global:OUTPUT_DIR = $script:OUTPUT_DIR
    $global:SCAN_LOG = $script:SCAN_LOG
    $global:CURRENT_LINK_DIR = $script:CURRENT_LINK_DIR
    
    return @{
        OutputDir = $script:OUTPUT_DIR
        ScanLog = $script:SCAN_LOG
        CurrentLinkDir = $script:CURRENT_LINK_DIR
    }
}

function New-ResultFilePath {
    <#
    .SYNOPSIS
        Create result file path with proper naming convention
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ToolName,
        
        [Parameter(Mandatory=$true)]
        [string]$ResultType,  # e.g., "results", "summary", "scan"
        
        [string]$Extension = "json"
    )
    
    if ($env:SCAN_DIR) {
        # Scan directory mode - simpler naming
        return Join-Path $script:OUTPUT_DIR "$ResultType.$Extension"
    }
    else {
        # Traditional mode - with scan ID prefix
        return Join-Path $script:OUTPUT_DIR "${script:SCAN_ID}_${ToolName}-${ResultType}.${Extension}"
    }
}

function New-CurrentLinks {
    <#
    .SYNOPSIS
        Create symlinks/shortcuts for current results
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ToolName
    )
    
    if ($env:SCAN_DIR) {
        # Create symlinks in reports directory pointing to scan directory
        Push-Location $script:CURRENT_LINK_DIR
        
        $scanId = Split-Path -Leaf $env:SCAN_DIR
        $resultsTarget = "..\..\scans\$scanId\$ToolName\results.json"
        $logTarget = "..\..\scans\$scanId\$ToolName\scan.log"
        $summaryTarget = "..\..\scans\$scanId\$ToolName\summary.json"
        
        # Windows symbolic links (requires admin) or use shortcuts
        # For cross-platform compatibility, we'll create relative path references
        try {
            if (Test-Path "$ToolName-results.json") { Remove-Item "$ToolName-results.json" -Force }
            if (Test-Path "$ToolName-scan.log") { Remove-Item "$ToolName-scan.log" -Force }
            if (Test-Path "$ToolName-summary.json") { Remove-Item "$ToolName-summary.json" -Force }
            
            # On Windows, try to create symlinks (requires elevated permissions)
            if ($IsWindows -or $env:OS -match "Windows") {
                New-Item -ItemType SymbolicLink -Path "$ToolName-results.json" -Target $resultsTarget -ErrorAction SilentlyContinue | Out-Null
                New-Item -ItemType SymbolicLink -Path "$ToolName-scan.log" -Target $logTarget -ErrorAction SilentlyContinue | Out-Null
                New-Item -ItemType SymbolicLink -Path "$ToolName-summary.json" -Target $summaryTarget -ErrorAction SilentlyContinue | Out-Null
            }
            else {
                # On Unix-like systems, use ln command
                & ln -sf $resultsTarget "$ToolName-results.json" 2>$null
                & ln -sf $logTarget "$ToolName-scan.log" 2>$null
                & ln -sf $summaryTarget "$ToolName-summary.json" 2>$null
            }
        }
        catch {
            # Silently continue if symlink creation fails
        }
        
        Pop-Location
    }
    else {
        # Traditional symlink creation
        Push-Location $script:OUTPUT_DIR
        
        $resultsFile = "${script:SCAN_ID}_${ToolName}-results.json"
        $logFile = "${script:SCAN_ID}_${ToolName}-scan.log"
        
        if (Test-Path $resultsFile) {
            if (Test-Path "$ToolName-results.json") { Remove-Item "$ToolName-results.json" -Force }
            New-Item -ItemType SymbolicLink -Path "$ToolName-results.json" -Target $resultsFile -ErrorAction SilentlyContinue | Out-Null
        }
        
        if (Test-Path $logFile) {
            if (Test-Path "$ToolName-scan.log") { Remove-Item "$ToolName-scan.log" -Force }
            New-Item -ItemType SymbolicLink -Path "$ToolName-scan.log" -Target $logFile -ErrorAction SilentlyContinue | Out-Null
        }
        
        Pop-Location
    }
}

function Complete-ScanResults {
    <#
    .SYNOPSIS
        Finalize scan results by creating symlinks and displaying summary
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ToolName
    )
    
    New-CurrentLinks -ToolName $ToolName
    
    Write-Host "✅ $ToolName scan completed" -ForegroundColor Green
    Write-Host "📁 Results stored in: $script:OUTPUT_DIR" -ForegroundColor Cyan
    
    if ($env:SCAN_DIR) {
        Write-Host "🗂️  Scan directory: $env:SCAN_DIR" -ForegroundColor Cyan
    }
}

# Functions are available when dot-sourced (Export-ModuleMember only needed for .psm1 modules)

# If run directly, show usage
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "This is a template/library script for security tools."
    Write-Host "Usage: Dot-source this script in security tool scripts"
    Write-Host ""
    Write-Host "Example usage in a security tool:"
    Write-Host "  . .\Scan-Directory-Template.ps1"
    Write-Host "  Initialize-ScanEnvironment -ToolName 'grype'"
    Write-Host "  `$resultsFile = New-ResultFilePath -ToolName 'grype' -ResultType 'results'"
    Write-Host "  # ... run tool and save to `$resultsFile ..."
    Write-Host "  Complete-ScanResults -ToolName 'grype'"
}
