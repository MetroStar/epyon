# Grype Multi-Target Vulnerability Scanner
# Advanced container image and filesystem vulnerability scanning with SBOM generation

param(
    [Parameter(Position=0)]
    [ValidateSet("filesystem", "images", "base", "all")]
    [string]$ScanMode = "all"
)

$ErrorActionPreference = "Continue"

# Initialize scan environment using scan directory approach
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Source the scan directory template
. "$ScriptDir\Scan-Directory-Template.ps1"

# Initialize scan environment for grype
$scanEnv = Initialize-ScanEnvironment -ToolName "grype"

# Extract scan information
if ($env:SCAN_ID) {
    $parts = $env:SCAN_ID -split '_'
    $TARGET_NAME = $parts[0]
    $USERNAME = $parts[1]
    $TIMESTAMP = $parts[2..($parts.Length-1)] -join '_'
    $SCAN_ID = $env:SCAN_ID
}
else {
    $targetPath = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
    $TARGET_NAME = Split-Path -Leaf $targetPath
    $USERNAME = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
    $TIMESTAMP = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $SCAN_ID = "${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
}

# Configuration
# $OUTPUT_DIR set by Initialize-ScanEnvironment
$Timestamp = Get-Date
# $SCAN_LOG set by Initialize-ScanEnvironment
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
Write-Host "Grype Multi-Target Vulnerability Scanner" -ForegroundColor $WHITE
Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "Repository: $RepoPath"
Write-Host "Output Directory: $OUTPUT_DIR"
Write-Host "Timestamp: $Timestamp"
Write-Host ""

# Create output directory
# Output directory created by template

# Initialize scan log
@"
Grype Vulnerability Scan Log
Timestamp: $Timestamp
Output Directory: $OUTPUT_DIR
========================================
"@ | Out-File -FilePath $SCAN_LOG -Encoding UTF8

Write-Host "Output Directory: " -NoNewline
Write-Host $OUTPUT_DIR -ForegroundColor $BLUE
Write-Host "Scan Log: " -NoNewline
Write-Host $SCAN_LOG -ForegroundColor $BLUE
Write-Host ""

# Function to check Docker
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "  Docker not found" -ForegroundColor $RED
        Write-Host "Please install Docker to use Grype vulnerability scanning."
        exit 1
    }
    
    try {
        docker info | Out-Null
    } catch {
        Write-Host "  Docker daemon not running" -ForegroundColor $RED
        Write-Host "Please start Docker daemon before running Grype scan."
        exit 1
    }
}

Write-Host "   Docker and Grype Information:" -ForegroundColor $BLUE
Write-Host "Docker version:"
docker --version
Write-Host "Pulling Grype and Syft images..."
docker pull anchore/grype:latest
docker pull anchore/syft:latest
Write-Host ""

# Function to scan Docker image
function Invoke-GrypeImageScan {
    param(
        [string]$ImageName,
        [string]$ScanType,
        [string]$OutputFile,
        [string]$SbomFile
    )
    
    Write-Host "   Scanning Docker image: " -NoNewline -ForegroundColor $CYAN
    Write-Host $ImageName -ForegroundColor $YELLOW
    "Scan type: $ScanType" | Out-File -FilePath $SCAN_LOG -Append
    "Image: $ImageName" | Out-File -FilePath $SCAN_LOG -Append
    
    Write-Host "   Generating Software Bill of Materials (SBOM)..."
    docker run --rm `
        -v /var/run/docker.sock:/var/run/docker.sock `
        -v "${PWD}/${OutputDir}:/output" `
        anchore/grype:latest `
        $ImageName `
        -o json `
        --file "/output/$OutputFile" `
        --add-cpes-if-none `
        --by-cve 2>&1 | Tee-Object -FilePath $SCAN_LOG -Append | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Image scan completed" -ForegroundColor $GREEN
        
        Write-Host "   Generating detailed SBOM..."
        docker run --rm `
            -v /var/run/docker.sock:/var/run/docker.sock `
            -v "${PWD}/${OutputDir}:/output" `
            anchore/syft:latest `
            $ImageName `
            -o spdx-json="/output/$SbomFile" 2>&1 | Tee-Object -FilePath $SCAN_LOG -Append | Out-Null
    } else {
        Write-Host "    Image scan completed with warnings" -ForegroundColor $YELLOW
    }
}

# Function to scan container images
function Invoke-ContainerImageScan {
    Write-Host "     Step 2: Container Image Vulnerability Scan" -ForegroundColor $PURPLE
    Write-Host "=============================================="
    
    $DockerFiles = Get-ChildItem -Path . -Filter "Dockerfile*" -File -ErrorAction SilentlyContinue
    
    if ($DockerFiles.Count -gt 0) {
        Write-Host "   Found $($DockerFiles.Count) Docker file(s): $($DockerFiles.Name -join ', ')"
        
        foreach ($dockerfile in $DockerFiles) {
            Write-Host "   Processing Docker file: $($dockerfile.Name)"
            
            $CleanName = $dockerfile.BaseName.ToLower() -replace '\.', '-'
            $ImageName = "advana-marketplace:${CleanName}-grype-scan"
            
            Write-Host "   Building image from $($dockerfile.Name) for vulnerability scanning..."
            docker build -f $dockerfile.FullName -t $ImageName . 2>&1 | Out-File -FilePath $SCAN_LOG -Append
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Image built successfully from $($dockerfile.Name)" -ForegroundColor $GREEN
                Write-Host "   Scanning built image for vulnerabilities..."
                
                Invoke-GrypeImageScan -ImageName $ImageName -ScanType "container-${CleanName}" `
                    -OutputFile "grype-${CleanName}-results.json" -SbomFile "sbom-${CleanName}.json"
                
                docker rmi $ImageName 2>&1 | Out-File -FilePath $SCAN_LOG -Append
            } else {
                Write-Host "  Failed to build image from $($dockerfile.Name)" -ForegroundColor $RED
            }
        }
        Write-Host "  Built container image vulnerability scanning completed" -ForegroundColor $GREEN
    } else {
        Write-Host "    No Docker files found" -ForegroundColor $YELLOW
    }
    
    Invoke-BaseImageScan
}

# Function to scan base images
function Invoke-BaseImageScan {
    Write-Host "   Scanning common base images for vulnerabilities..."
    
    $BaseImages = @("nginx:alpine", "node:18-alpine", "python:3.11-alpine", "ubuntu:22.04", "alpine:latest")
    
    foreach ($image in $BaseImages) {
        Write-Host "   Scanning base image: " -NoNewline
        Write-Host $image -ForegroundColor $CYAN
        
        try {
            docker image inspect $image 2>&1 | Out-Null
        } catch {
            Write-Host "   Pulling image $image..."
            docker pull $image 2>&1 | Out-File -FilePath $SCAN_LOG -Append
        }
        
        $SafeImageName = $image -replace '[:/]', '-'
        Invoke-GrypeImageScan -ImageName $image -ScanType "base-image" `
            -OutputFile "grype-base-$SafeImageName-results.json" -SbomFile "sbom-base-$SafeImageName.json"
        
        Write-Host "  Base image $image vulnerability scan completed" -ForegroundColor $GREEN
    }
}

# Function to scan filesystem
function Invoke-FilesystemScan {
    param([string]$TargetDir = ".", [string]$OutputFile = "grype-filesystem-results.json")
    
    Write-Host "   Scanning filesystem: " -NoNewline -ForegroundColor $CYAN
    Write-Host $TargetDir -ForegroundColor $YELLOW
    
    docker run --rm `
        -v "${PWD}:/workspace" `
        -v "${PWD}/${OutputDir}:/output" `
        anchore/grype:latest `
        dir:"/workspace/$TargetDir" `
        -o json `
        --file "/output/$OutputFile" 2>&1 | Tee-Object -FilePath $SCAN_LOG -Append | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Filesystem scan completed" -ForegroundColor $GREEN
    } else {
        Write-Host "    Filesystem scan completed with warnings" -ForegroundColor $YELLOW
    }
}

# Main execution
Test-Docker

switch ($ScanMode) {
    "filesystem" {
        Write-Host "Running filesystem scan only..." -ForegroundColor $CYAN
        Invoke-FilesystemScan
    }
    "images" {
        Write-Host "Running container image scan only..." -ForegroundColor $CYAN
        Invoke-ContainerImageScan
    }
    "base" {
        Write-Host "Running base image scan only..." -ForegroundColor $CYAN
        Invoke-BaseImageScan
    }
    "all" {
        Write-Host "Running complete Grype vulnerability scan..." -ForegroundColor $CYAN
        Invoke-FilesystemScan
        Invoke-ContainerImageScan
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Grype Vulnerability Scan Complete" -ForegroundColor $GREEN
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Results saved to: $OUTPUT_DIR" -ForegroundColor $CYAN
Write-Host "Scan log: $SCAN_LOG" -ForegroundColor $CYAN
Write-Host ""
