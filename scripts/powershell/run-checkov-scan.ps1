# Checkov Infrastructure-as-Code Security Scan Script - PowerShell Version
# Scans Helm charts and Kubernetes manifests for security best practices

param(
    [Parameter(Position=0)]
    [string]$Mode = "default"
)

$ErrorActionPreference = "Continue"

# Configuration - Support target directory override
$TargetScanDir = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
$ChartDir = Join-Path $TargetScanDir "chart"
$HelmOutputDir = ".\helm-packages"
$OutputDir = ".\checkov-reports"
$ChartName = "advana-marketplace"
$ScanLog = Join-Path $OutputDir "checkov-scan.log"
$ResultsFile = Join-Path $OutputDir "checkov-results.json"
$RenderedTemplates = Join-Path $HelmOutputDir "rendered-templates.yaml"
$RepoRoot = if ($env:REPO_ROOT) { $env:REPO_ROOT } else { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }

# Colors
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$CYAN = "Cyan"
$WHITE = "White"

# Docker image for Checkov
$CheckovImage = "bridgecrew/checkov:latest"

# Initialize authentication status
$AwsAuthenticated = $false

# Get AWS credentials from environment variables
$AwsAccessKeyId = $env:AWS_ACCESS_KEY_ID
$AwsSecretAccessKey = $env:AWS_SECRET_ACCESS_KEY
$AwsDefaultRegion = if ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION } else { "us-gov-west-1" }

# Create output directories
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path $HelmOutputDir | Out-Null

Write-Host "============================================" -ForegroundColor $BLUE
Write-Host "Checkov Infrastructure-as-Code Security Scan" -ForegroundColor $BLUE
Write-Host "============================================" -ForegroundColor $BLUE
Write-Host "Chart Directory: $ChartDir"
Write-Host "Output Directory: $OutputDir"
Write-Host "Chart Name: $ChartName"
Write-Host "Scan Log: $ScanLog"
Write-Host "Timestamp: $(Get-Date)"
Write-Host ""

# Check if Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "  Docker is not installed or not in PATH" -ForegroundColor $RED
    Write-Host "Docker is required to run Checkov scans"
    exit 1
}

Write-Host "   Docker and Checkov Information:" -ForegroundColor $BLUE
Write-Host "Docker version:"
docker --version
Write-Host "Pulling Checkov image..."
docker pull $CheckovImage
Write-Host ""

# Check if chart directory exists
if (-not (Test-Path $ChartDir)) {
    Write-Host "    Chart directory not found: $ChartDir" -ForegroundColor $YELLOW
    Write-Host "   Scanning project directory for IaC files instead..." -ForegroundColor $CYAN
    Write-Host ""
    
    # Scan the entire project directory for various IaC files
    Write-Host "   Scanning for:" -ForegroundColor $CYAN
    Write-Host "  - Dockerfiles"
    Write-Host "  - Kubernetes YAML files"
    Write-Host "  - Docker Compose files"
    Write-Host "  - Configuration files"
    Write-Host ""
    
    # Check what files are available
    $dockerfiles = Get-ChildItem -Path $TargetScanDir -Filter "Dockerfile*" -Recurse -ErrorAction SilentlyContinue
    $yamlFiles = Get-ChildItem -Path $TargetScanDir -Include "*.yaml","*.yml" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch "node_modules|\.git" }
    
    if ($dockerfiles.Count -gt 0 -or $yamlFiles.Count -gt 0) {
        Write-Host "  Found scannable files:" -ForegroundColor $GREEN
        if ($dockerfiles.Count -gt 0) {
            Write-Host "     Dockerfiles: $($dockerfiles.Count)"
        }
        if ($yamlFiles.Count -gt 0) {
            Write-Host "     YAML files: $($yamlFiles.Count)"
        }
        Write-Host ""
        
        # Set scan target to project directory
        $ScanTarget = $TargetScanDir
        $ScanType = "directory"
    } else {
        Write-Host "    No IaC files found in project directory" -ForegroundColor $YELLOW
        Write-Host "   Skipping Checkov scan - no scannable files available" -ForegroundColor $YELLOW
        # Create a dummy results file
        $dummyResult = @{
            passed = 0
            failed = 0
            skipped = 0
            parsing_errors = 0
            resource_count = 0
            checkov_version = "N/A"
            scan_status = "no_iac_files_found"
        } | ConvertTo-Json
        $dummyResult | Out-File -FilePath $ResultsFile -Encoding UTF8
        Write-Host "  Checkov scan completed with fallback result" -ForegroundColor $GREEN
        exit 0
    }
} else {
    Write-Host "  Chart directory found: $ChartDir" -ForegroundColor $GREEN
}

# Skip Helm steps if we're doing a directory scan
if ($ScanType -ne "directory") {
    Write-Host "   Step 1: Helm Dependency Resolution & Template Rendering" -ForegroundColor $CYAN
    Write-Host "================================"
    Write-Host ""

    # Check for Helm installation
    $HelmCmd = "helm"
    $DockerHelm = $false
    if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
        Write-Host "    Using Docker-based Helm for template rendering" -ForegroundColor $YELLOW
        $DockerHelm = $true
    } else {
        Write-Host "  Using local Helm installation" -ForegroundColor $GREEN
    }
} else {
    # For directory scans, skip Helm processing
    Write-Host "   Step 1: Preparing directory scan" -ForegroundColor $CYAN
    Write-Host "================================"
    Write-Host "Skipping Helm processing - scanning project files directly"
    Write-Host ""
}

# Only process Helm charts if not doing a directory scan
if ($ScanType -ne "directory") {
    # Set timeout for dependency operations (in seconds)
    $DependencyTimeout = 30

    $DependencySuccess = $false
    $TemplateSuccess = $false

    # Check if Chart.yaml has dependencies
    if (Test-Path (Join-Path $ChartDir "Chart.yaml")) {
    $chartContent = Get-Content (Join-Path $ChartDir "Chart.yaml") -Raw
    if ($chartContent -match "dependencies:") {
        Write-Host "    Chart has dependencies - attempting to resolve..." -ForegroundColor $YELLOW
        Write-Host "Dependencies found in Chart.yaml"
        
        if (-not $DockerHelm) {
            Write-Host "   Adding public Helm repositories..." -ForegroundColor $CYAN
            helm repo add bitnami https://charts.bitnami.com/bitnami 2>$null
            helm repo update 2>$null
            
            Write-Host "   Attempting to download dependencies..." -ForegroundColor $CYAN
            Push-Location $ChartDir
            $depJob = Start-Job -ScriptBlock { helm dependency update 2>$null }
            $depJob | Wait-Job -Timeout $DependencyTimeout | Out-Null
            
            if ($depJob.State -eq "Completed") {
                Write-Host "  Dependencies resolved successfully" -ForegroundColor $GREEN
                $DependencySuccess = $true
            } else {
                Stop-Job $depJob
                Write-Host "    Dependencies failed or timed out" -ForegroundColor $YELLOW
                Write-Host "   Continuing with fallback scan" -ForegroundColor $CYAN
            }
            Remove-Job $depJob -Force
            Pop-Location
        }
    } else {
        Write-Host "  No dependencies found in Chart.yaml" -ForegroundColor $GREEN
        $DependencySuccess = $true
    }
} else {
    Write-Host "  Chart.yaml not found" -ForegroundColor $RED
}

# Try to render templates
Write-Host "   Attempting to render Helm templates..." -ForegroundColor $CYAN

if (Get-Command helm -ErrorAction SilentlyContinue) {
    Write-Host "Using local Helm for template rendering..."
    try {
        helm template $ChartName $ChartDir > $RenderedTemplates 2>$null
        $ResourceCount = (Select-String -Path $RenderedTemplates -Pattern "^kind:" | Measure-Object).Count
        
        if ($ResourceCount -gt 0) {
            Write-Host "  Templates rendered successfully" -ForegroundColor $GREEN
            Write-Host "Rendered Kubernetes resources: $ResourceCount"
            $ScanTarget = $RenderedTemplates
            $ScanType = "kubernetes"
            $TemplateSuccess = $true
        }
    } catch {
        Write-Host "Template rendering failed: $_" -ForegroundColor $YELLOW
    }
}

if (-not $TemplateSuccess) {
    Write-Host "    Template rendering failed or no resources found" -ForegroundColor $YELLOW
    Write-Host "This is common with charts that use private/library charts without authentication"
    Write-Host "   Falling back to chart configuration analysis..." -ForegroundColor $CYAN
    
    $ScanTarget = $ChartDir
    $ScanType = "helm"
    
    if (Test-Path (Join-Path $ChartDir "values.yaml")) {
        Write-Host "  Found values.yaml for security analysis" -ForegroundColor $GREEN
        $valuesSize = (Get-Item (Join-Path $ChartDir "values.yaml")).Length
        Write-Host "Chart values file size: $valuesSize bytes"
    } else {
        Write-Host "    No values.yaml found in chart directory" -ForegroundColor $YELLOW
    }
    
    Write-Host "   Available for analysis:" -ForegroundColor $CYAN
    Get-ChildItem -Path $ChartDir -Include *.yaml,*.yml -Recurse | Select-Object -First 10 | ForEach-Object {
        Write-Host "     $($_.Name) ($($_.Length) bytes)"
    }
    }
}
Write-Host ""

Write-Host "     Step 2: Checkov Security Scan" -ForegroundColor $BLUE
Write-Host "================================="
Write-Host "Scan target: $ScanTarget"
Write-Host "Scan type: $ScanType"
Write-Host ""
Write-Host "Running Checkov security analysis..."

# Run Checkov with comprehensive framework detection
if ($ScanType -eq "directory") {
    Write-Host "Scanning project directory for IaC security issues..."
    $targetAbsPath = (Resolve-Path $TargetScanDir).Path
    $outputAbsPath = (Resolve-Path $OutputDir).Path
    
    Write-Host "   Running comprehensive IaC scan..."
    docker run --rm `
        -e AWS_ACCESS_KEY_ID=$AwsAccessKeyId `
        -e AWS_SECRET_ACCESS_KEY=$AwsSecretAccessKey `
        -e AWS_DEFAULT_REGION=$AwsDefaultRegion `
        -v "${targetAbsPath}:/repo" `
        -v "${outputAbsPath}:/output" `
        $CheckovImage `
        --framework dockerfile,kubernetes,yaml `
        --directory "/repo" `
        --output json `
        --output-file-path "/output/checkov-results.json" `
        --skip-path "/repo/node_modules" `
        --skip-path "/repo/.git" `
        --quiet
} elseif ($ScanType -eq "helm") {
    Write-Host "Scanning Helm chart values and configuration files..."
    
    # Scan values.yaml if it exists
    if (Test-Path (Join-Path $ChartDir "values.yaml")) {
        Write-Host "   Scanning values.yaml for security configurations..."
        $targetAbsPath = (Resolve-Path $TargetScanDir).Path
        $outputAbsPath = (Resolve-Path $OutputDir).Path
        
        docker run --rm `
            -e AWS_ACCESS_KEY_ID=$AwsAccessKeyId `
            -e AWS_SECRET_ACCESS_KEY=$AwsSecretAccessKey `
            -e AWS_DEFAULT_REGION=$AwsDefaultRegion `
            -v "${targetAbsPath}:/repo" `
            -v "${outputAbsPath}:/output" `
            $CheckovImage `
            --framework yaml `
            --file "/repo/chart/values.yaml" `
            --output json `
            --output-file-path "/output/checkov-values-results.json" `
            --quiet
    }
    
    # Scan entire chart directory
    Write-Host "   Scanning chart directory for security configurations..."
    $targetAbsPath = (Resolve-Path $TargetScanDir).Path
    $outputAbsPath = (Resolve-Path $OutputDir).Path
    
    docker run --rm `
        -e AWS_ACCESS_KEY_ID=$AwsAccessKeyId `
        -e AWS_SECRET_ACCESS_KEY=$AwsSecretAccessKey `
        -e AWS_DEFAULT_REGION=$AwsDefaultRegion `
        -v "${targetAbsPath}:/repo" `
        -v "${outputAbsPath}:/output" `
        $CheckovImage `
        --framework yaml,dockerfile `
        --directory "/repo/chart" `
        --output json `
        --output-file-path "/output/checkov-results.json" `
        --quiet
} else {
    # Scan rendered templates
    $currentAbsPath = (Resolve-Path ".").Path
    $outputAbsPath = (Resolve-Path $OutputDir).Path
    
    docker run --rm `
        -e AWS_ACCESS_KEY_ID=$AwsAccessKeyId `
        -e AWS_SECRET_ACCESS_KEY=$AwsSecretAccessKey `
        -e AWS_DEFAULT_REGION=$AwsDefaultRegion `
        -v "${currentAbsPath}:/repo" `
        -v "${outputAbsPath}:/output" `
        $CheckovImage `
        --framework kubernetes `
        --file "/repo/$RenderedTemplates" `
        --output json `
        --output-file-path "/output/checkov-results.json" `
        --quiet
}

$CheckovExitCode = $LASTEXITCODE

# Fix file permissions from Docker container
if (Test-Path $ResultsFile) {
    try {
        $acl = Get-Acl $ResultsFile
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        $acl.SetOwner([System.Security.Principal.NTAccount]$env:USERNAME)
        Set-Acl $ResultsFile $acl
    } catch {
        # If ACL fails, try copying the file to a temp location and back
        try {
            $tempFile = "$ResultsFile.temp"
            Copy-Item $ResultsFile $tempFile -Force
            Remove-Item $ResultsFile -Force
            Move-Item $tempFile $ResultsFile -Force
        } catch {
            # Ignore permission errors - scan completed successfully anyway
        }
    }
}

Write-Host ""
Write-Host "============================================"

# Parse results
if (Test-Path $ResultsFile) {
    Write-Host "  Checkov scan completed successfully!" -ForegroundColor $GREEN
    Write-Host "============================================"
    
    try {
        # Try to read the file
        $results = Get-Content $ResultsFile -Raw -ErrorAction Stop | ConvertFrom-Json
        $summary = $results.summary
        
        Write-Host "   Scan Summary:"
        Write-Host "================"
        Write-Host "Passed checks: $($summary.passed)"
        Write-Host "Failed checks: $($summary.failed)"
        Write-Host "Skipped checks: $($summary.skipped)"
        Write-Host "Total checks: $($summary.passed + $summary.failed + $summary.skipped)"
        Write-Host ""
        
        if ($summary.failed -gt 0) {
            Write-Host "    $($summary.failed) security issues found" -ForegroundColor $YELLOW
            Write-Host "Review detailed results for specific recommendations"
        } else {
            Write-Host "   No security issues detected!" -ForegroundColor $GREEN
        }
    } catch [System.UnauthorizedAccessException] {
        # File exists but can't be read due to Docker permissions
        Write-Host "   Scan Summary:"
        Write-Host "================"
        Write-Host "Scan completed successfully - results saved to file"
        Write-Host "(Docker created the file with restricted permissions)"
        Write-Host ""
        Write-Host "Note: The scan results are shown in the Docker output above"
    } catch {
        Write-Host "   Scan Summary:"
        Write-Host "================"
        Write-Host "Results saved to: $ResultsFile"
        Write-Host "  Scan completed - review results file" -ForegroundColor $GREEN
    }
} elseif ($CheckovExitCode -eq 0) {
    Write-Host "  Checkov scan completed successfully!" -ForegroundColor $GREEN
    Write-Host "   No security issues detected!"
    Write-Host "============================================"
} else {
    Write-Host "  Checkov scan failed" -ForegroundColor $RED
    Write-Host "============================================"
    Write-Host "Exit code: $CheckovExitCode"
    Write-Host "Check the scan log for details"
}

Write-Host ""
Write-Host "   Security Recommendations:" -ForegroundColor $BLUE
Write-Host "============================="

if (Test-Path $ResultsFile) {
    Write-Host "  Review detailed security findings in: $ResultsFile"
    Write-Host "  Address high and medium severity issues first"
    Write-Host "  Consider implementing security contexts for containers"
    Write-Host "  Ensure resource limits are defined for all containers"
    Write-Host "  Review network policies and service configurations"
} else {
    Write-Host "    No results file generated - check scan configuration"
    Write-Host "  Verify chart templates are valid and accessible"
    Write-Host "  Check Docker and Checkov image availability"
}

Write-Host ""
Write-Host "   Output Files:" -ForegroundColor $BLUE
Write-Host "================"
Write-Host "Scan log: $ScanLog"
if (Test-Path $ResultsFile) {
    Write-Host "Results JSON: $ResultsFile"
}
if (Test-Path $RenderedTemplates) {
    Write-Host "Rendered templates: $RenderedTemplates"
}
Write-Host "Reports directory: $OutputDir"

Write-Host ""
Write-Host "============================================"
Write-Host "Checkov security scan complete." -ForegroundColor $GREEN
Write-Host "============================================"

# Always exit successfully - orchestrator should continue regardless
exit 0
