# Trivy Multi-Target Vulnerability Scanner
# Comprehensive container image, Kubernetes, and filesystem security scanning

param(
    [Parameter(Position=0)]
    [ValidateSet("filesystem", "images", "base", "kubernetes", "all")]
    [string]$ScanMode = "all"
)

$ErrorActionPreference = "Continue"

# Configuration
$OutputDir = "..\..\reports\trivy-reports"
$Timestamp = Get-Date
$ScanLog = Join-Path $OutputDir "trivy-scan.log"
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
Write-Host "Trivy Multi-Target Security Scanner" -ForegroundColor $WHITE
Write-Host "============================================" -ForegroundColor $WHITE
Write-Host "Repository: $RepoPath"
Write-Host "Output Directory: $OutputDir"
Write-Host "Timestamp: $Timestamp"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Initialize scan log
@"
Trivy Security Scan Log
Timestamp: $Timestamp
Output Directory: $OutputDir
========================================
"@ | Out-File -FilePath $ScanLog -Encoding UTF8

Write-Host "Output Directory: " -NoNewline
Write-Host $OutputDir -ForegroundColor $BLUE
Write-Host "Scan Log: " -NoNewline
Write-Host $ScanLog -ForegroundColor $BLUE
Write-Host "Timestamp: " -NoNewline
Write-Host $Timestamp -ForegroundColor $CYAN
Write-Host ""

# Function to check Docker
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "  Docker not found" -ForegroundColor $RED
        Write-Host "Please install Docker to use Trivy security scanning."
        exit 1
    }
    
    try {
        docker info | Out-Null
    } catch {
        Write-Host "  Docker daemon not running" -ForegroundColor $RED
        Write-Host "Please start Docker daemon before running Trivy scan."
        exit 1
    }
}

Write-Host "   Docker and Trivy Information:" -ForegroundColor $BLUE
Write-Host "Docker version:"
docker --version
Write-Host "Pulling Trivy image..."
docker pull aquasec/trivy:latest
Write-Host ""

# Function to scan Docker image
function Invoke-TrivyImageScan {
    param(
        [string]$ImageName,
        [string]$ScanType,
        [string]$OutputFile
    )
    
    Write-Host "   Scanning Docker image: " -NoNewline -ForegroundColor $CYAN
    Write-Host $ImageName -ForegroundColor $YELLOW
    "Scan type: $ScanType" | Out-File -FilePath $ScanLog -Append
    "Image: $ImageName" | Out-File -FilePath $ScanLog -Append
    
    $outputPath = Join-Path $OutputDir $OutputFile
    docker run --rm `
        -v /var/run/docker.sock:/var/run/docker.sock `
        -v "${PWD}/${OutputDir}:/output" `
        aquasec/trivy:latest image `
        --format json `
        --output "/output/$OutputFile" `
        --severity HIGH,CRITICAL `
        $ImageName 2>&1 | Tee-Object -FilePath $ScanLog -Append | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Image scan completed" -ForegroundColor $GREEN
        "Image scan completed successfully" | Out-File -FilePath $ScanLog -Append
    } else {
        Write-Host "    Image scan completed with warnings" -ForegroundColor $YELLOW
        "Image scan completed with warnings" | Out-File -FilePath $ScanLog -Append
    }
}

# Function to scan container images
function Invoke-ContainerImageScan {
    Write-Host "     Step 2: Container Image Security Scan" -ForegroundColor $PURPLE
    Write-Host "=========================================="
    
    $DockerFiles = Get-ChildItem -Path . -Filter "Dockerfile*" -File -ErrorAction SilentlyContinue
    
    if ($DockerFiles.Count -gt 0) {
        Write-Host "   Found $($DockerFiles.Count) Docker file(s): $($DockerFiles.Name -join ', ')"
        "Found Docker files: $($DockerFiles.Name -join ', ')" | Out-File -FilePath $ScanLog -Append
        
        foreach ($dockerfile in $DockerFiles) {
            Write-Host "   Processing Docker file: $($dockerfile.Name)"
            
            $CleanName = $dockerfile.BaseName.ToLower() -replace '\.', '-'
            $ImageName = "advana-marketplace:${CleanName}-trivy-scan"
            
            Write-Host "   Building image from $($dockerfile.Name) for security scanning..."
            docker build -f $dockerfile.FullName -t $ImageName . 2>&1 | Out-File -FilePath $ScanLog -Append
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Image built successfully from $($dockerfile.Name)" -ForegroundColor $GREEN
                Write-Host "   Scanning built image for security vulnerabilities..."
                
                Invoke-TrivyImageScan -ImageName $ImageName -ScanType "container-${CleanName}" -OutputFile "trivy-${CleanName}-results.json"
                
                docker rmi $ImageName 2>&1 | Out-File -FilePath $ScanLog -Append
            } else {
                Write-Host "  Failed to build image from $($dockerfile.Name)" -ForegroundColor $RED
                "Failed to build image from $($dockerfile.Name)" | Out-File -FilePath $ScanLog -Append
            }
        }
        Write-Host "  Built container image security scanning completed" -ForegroundColor $GREEN
    } else {
        Write-Host "    No Docker files found" -ForegroundColor $YELLOW
    }
    
    Invoke-BaseImageScan
}

# Function to scan base images
function Invoke-BaseImageScan {
    Write-Host "   Scanning common base images for security vulnerabilities..."
    
    $BaseImages = @("nginx:alpine", "node:18-alpine", "python:3.11-alpine", "ubuntu:22.04", "alpine:latest")
    
    foreach ($image in $BaseImages) {
        Write-Host "   Scanning base image: " -NoNewline
        Write-Host $image -ForegroundColor $CYAN
        
        try {
            docker image inspect $image 2>&1 | Out-Null
        } catch {
            Write-Host "   Pulling image $image..."
            docker pull $image 2>&1 | Out-File -FilePath $ScanLog -Append
        }
        
        $SafeImageName = $image -replace '[:/]', '-'
        Invoke-TrivyImageScan -ImageName $image -ScanType "base-image" -OutputFile "trivy-base-$SafeImageName-results.json"
        
        Write-Host "  Base image $image security scan completed" -ForegroundColor $GREEN
    }
}

# Function to scan filesystem
function Invoke-FilesystemScan {
    param([string]$TargetDir = ".", [string]$OutputFile = "trivy-filesystem-results.json")
    
    Write-Host "   Scanning filesystem: " -NoNewline -ForegroundColor $CYAN
    Write-Host $TargetDir -ForegroundColor $YELLOW
    "Filesystem scan target: $TargetDir" | Out-File -FilePath $ScanLog -Append
    
    docker run --rm `
        -v "${PWD}:/workspace" `
        -v "${PWD}/${OutputDir}:/output" `
        aquasec/trivy:latest fs `
        --format json `
        --output "/output/$OutputFile" `
        --severity HIGH,CRITICAL `
        "/workspace/$TargetDir" 2>&1 | Tee-Object -FilePath $ScanLog -Append | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Filesystem scan completed" -ForegroundColor $GREEN
    } else {
        Write-Host "    Filesystem scan completed with warnings" -ForegroundColor $YELLOW
    }
}

# Function to scan Kubernetes
function Invoke-KubernetesScan {
    param([string]$TargetDir = "./chart", [string]$OutputFile = "trivy-kubernetes-results.json")
    
    Write-Host "   Scanning Kubernetes manifests: " -NoNewline -ForegroundColor $CYAN
    Write-Host $TargetDir -ForegroundColor $YELLOW
    
    if (-not (Test-Path $TargetDir)) {
        Write-Host "    Kubernetes directory not found: $TargetDir" -ForegroundColor $YELLOW
        return
    }
    
    docker run --rm `
        -v "${PWD}:/workspace" `
        -v "${PWD}/${OutputDir}:/output" `
        aquasec/trivy:latest config `
        --format json `
        --output "/output/$OutputFile" `
        --severity HIGH,CRITICAL `
        "/workspace/$TargetDir" 2>&1 | Tee-Object -FilePath $ScanLog -Append | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Kubernetes scan completed" -ForegroundColor $GREEN
    } else {
        Write-Host "    Kubernetes scan completed with warnings" -ForegroundColor $YELLOW
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
    "kubernetes" {
        Write-Host "Running Kubernetes scan only..." -ForegroundColor $CYAN
        Invoke-KubernetesScan
    }
    "all" {
        Write-Host "Running complete Trivy security scan..." -ForegroundColor $CYAN
        Invoke-FilesystemScan
        Invoke-ContainerImageScan
        Invoke-KubernetesScan
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Trivy Security Scan Complete" -ForegroundColor $GREEN
Write-Host "============================================" -ForegroundColor $GREEN
Write-Host "Results saved to: $OutputDir" -ForegroundColor $CYAN
Write-Host "Scan log: $ScanLog" -ForegroundColor $CYAN
Write-Host ""
