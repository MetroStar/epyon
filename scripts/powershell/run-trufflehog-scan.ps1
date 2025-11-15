# TruffleHog Security Scan Script
# Comprehensive secret scanning for filesystems and container images

# Configuration - Support target directory override
$RepoPath = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
# Configuration
$OutputDir = "..\..\reports\trufflehog-reports"
$ReportFormat = "json"  # Options: json, sarif, github
$Timestamp = Get-Date
$ScanLog = Join-Path $OutputDir "trufflehog-scan.log"

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$PURPLE = "Magenta"
$CYAN = "Cyan"

# Create output directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Initialize scan log
@"
TruffleHog Security Scan Log
Timestamp: $Timestamp
Repository Path: $RepoPath
Output Directory: $OutputDir
========================================
"@ | Out-File -FilePath $ScanLog -Encoding UTF8

Write-Host "============================================"
Write-Host "TruffleHog Multi-Target Security Scan" -ForegroundColor $PURPLE
Write-Host "============================================"
Write-Host "Repository: $RepoPath" -ForegroundColor $BLUE
Write-Host "Output Directory: $OutputDir" -ForegroundColor $BLUE
Write-Host "Report Format: $ReportFormat" -ForegroundColor $CYAN
Write-Host "Timestamp: $Timestamp" -ForegroundColor $CYAN
Write-Host ""

# Function to check Docker availability
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "  Docker not found" -ForegroundColor $RED
        Write-Host "Please install Docker to use TruffleHog scanning."
        exit 1
    }
    
    try {
        docker info | Out-Null
    } catch {
        Write-Host "  Docker daemon not running" -ForegroundColor $RED
        Write-Host "Please start Docker daemon before running TruffleHog scan."
        exit 1
    }
}

# Function to scan filesystem
function Invoke-FilesystemScan {
    Write-Host "     Step 1: Filesystem Secret Scan" -ForegroundColor $BLUE
    Write-Host "=================================="
    Write-Host "   Scanning repository filesystem for secrets..."
    "Filesystem scan started" | Out-File -FilePath $ScanLog -Append
    
    # Run TruffleHog filesystem scan using Docker with exclusions
    docker run --rm `
      -v "${RepoPath}:/repo" `
      -v "${RepoPath}\exclude-paths.txt:/exclude-paths.txt" `
      trufflesecurity/trufflehog:latest `
      filesystem /repo `
      --json `
      --no-update `
      --exclude-paths=/exclude-paths.txt `
      | Out-File -FilePath (Join-Path $OutputDir "trufflehog-filesystem-results.json")
    
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host "  Filesystem scan completed" -ForegroundColor $GREEN
        "Filesystem scan completed successfully" | Out-File -FilePath $ScanLog -Append
        return 0
    } else {
        Write-Host "    Filesystem scan completed with warnings" -ForegroundColor $YELLOW
        "Filesystem scan completed with warnings" | Out-File -FilePath $ScanLog -Append
        return $exitCode
    }
}

# Function to scan container images
function Invoke-ContainerImageScan {
    Write-Host "     Step 2: Container Image Secret Scan" -ForegroundColor $BLUE
    Write-Host "======================================="
    
    # Check for Docker files (various naming patterns)
    $DockerFiles = Get-ChildItem -Path . -Filter "Dockerfile*" -File -ErrorAction SilentlyContinue
    
    if ($DockerFiles.Count -gt 0) {
        Write-Host "   Found $($DockerFiles.Count) Docker file(s): $($DockerFiles.Name -join ', ')"
        "Found Docker files: $($DockerFiles.Name -join ', ')" | Out-File -FilePath $ScanLog -Append
        
        # Scan each Docker file found
        foreach ($dockerfile in $DockerFiles) {
            Write-Host "   Processing Docker file: $($dockerfile.Name)"
            
            # Extract a clean name for the image
            $CleanName = $dockerfile.BaseName.ToLower() -replace '\.', '-'
            $ImageName = "advana-marketplace:${CleanName}-scan"
            
            Write-Host "   Building image from $($dockerfile.Name)..."
            docker build -f $dockerfile.FullName -t $ImageName . 2>&1 | Out-File -FilePath $ScanLog -Append
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Image built successfully from $($dockerfile.Name)" -ForegroundColor $GREEN
                Write-Host "   Scanning built image for embedded secrets..."
                
                # Create specific output file for this Docker file
                $DockerResultsFile = Join-Path $OutputDir "trufflehog-${CleanName}-results.json"
                
                # Scan the built image
                docker run --rm `
                  -v /var/run/docker.sock:/var/run/docker.sock `
                  trufflesecurity/trufflehog:latest `
                  docker --image="$ImageName" `
                  --json `
                  --no-update `
                  | Out-File -FilePath $DockerResultsFile
                
                $exitCode = $LASTEXITCODE
                if ($exitCode -eq 0) {
                    Write-Host "  Image scan completed for $($dockerfile.Name)" -ForegroundColor $GREEN
                    "Image scan completed successfully for $($dockerfile.Name)" | Out-File -FilePath $ScanLog -Append
                } else {
                    Write-Host "    Image scan completed with warnings for $($dockerfile.Name)" -ForegroundColor $YELLOW
                    "Image scan completed with warnings for $($dockerfile.Name)" | Out-File -FilePath $ScanLog -Append
                }
                
                # Clean up the built image to save space
                docker rmi $ImageName 2>&1 | Out-File -FilePath $ScanLog -Append
                
            } else {
                Write-Host "  Failed to build image from $($dockerfile.Name)" -ForegroundColor $RED
                "Failed to build image from $($dockerfile.Name)" | Out-File -FilePath $ScanLog -Append
            }
        }
        Write-Host "  Built container image scanning completed" -ForegroundColor $GREEN
        
    } else {
        Write-Host "    No Docker files found (searched for: Dockerfile, Dockerfile.*, etc.)" -ForegroundColor $YELLOW
        Write-Host "   Available files in repository root:" -ForegroundColor $BLUE
        Get-ChildItem -Path . | Where-Object { $_.Name -match "(Dockerfile|docker)" } | Select-Object -First 5 | ForEach-Object { Write-Host "  $($_.Name)" }
    }
}

# Main execution
Test-Docker

Write-Host ""
Invoke-FilesystemScan

Write-Host ""
Invoke-ContainerImageScan

Write-Host ""
Write-Host "============================================"
Write-Host "TruffleHog Security Scan Complete" -ForegroundColor $GREEN
Write-Host "============================================"
Write-Host "Results saved to: $OutputDir" -ForegroundColor $CYAN
Write-Host "Scan log: $ScanLog" -ForegroundColor $CYAN
Write-Host ""
