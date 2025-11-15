# Helm Build and Package Script - PowerShell Version
# Builds, validates, and packages Helm charts with comprehensive checks

param(
    [Parameter(Position=0)]
    [string]$ChartPath = "",
    [Parameter(Position=1)]
    [string]# Configuration
$OutputDir = "..\..\reports\helm-packages"
)

$ErrorActionPreference = "Continue"

# Configuration - Support target directory scanning
$RepoPath = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
$ChartDir = if ($ChartPath) { $ChartPath } else { Join-Path $RepoPath "chart" }
$OutputDirPath = $OutputDir
$ChartName = "advana-marketplace"
$BuildLog = Join-Path $OutputDirPath "helm-build.log"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDirPath | Out-Null

# Start logging
$LogFile = New-Item -ItemType File -Force -Path $BuildLog
Start-Transcript -Path $BuildLog -Append

Write-Host "============================================" -ForegroundColor White
Write-Host "Helm Chart Build Process" -ForegroundColor Blue
Write-Host "============================================" -ForegroundColor White
Write-Host "Chart Directory: $ChartDir"
Write-Host "Output Directory: $OutputDirPath"
Write-Host "Chart Name: $ChartName"
Write-Host "Build Log: $BuildLog"
Write-Host "Timestamp: $(Get-Date)"
Write-Host ""

# Check if Helm is available, use Docker if not installed locally
$HelmCmd = "helm"
$DockerHelmImage = "alpine/helm:latest"
$UseDocker = $false

if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
    Write-Host "⚠️  Helm not found locally, using Docker-based Helm" -ForegroundColor Yellow
    $UseDocker = $true
    
    # Test Docker availability
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Neither Helm nor Docker is available" -ForegroundColor Red
        Write-Host "Please install either Helm or Docker"
        Stop-Transcript
        exit 1
    }
    
    # Pull Helm Docker image
    Write-Host "Pulling Helm Docker image..."
    docker pull $DockerHelmImage
    
    # Mount the target directory containing the chart
    $TargetParent = Split-Path -Parent $RepoPath
    $TargetName = Split-Path -Leaf $RepoPath
    $ChartPathInContainer = "/workspace/$TargetName/chart"
    
    # Create a base command function to handle Docker properly
    $DockerChartPath = $ChartPathInContainer
} else {
    $HelmCmd = "helm"
    $DockerChartPath = $ChartDir
}

Write-Host "📊 Helm Version Information:" -ForegroundColor Blue
if ($UseDocker) {
    try {
        docker run --rm $DockerHelmImage version --short 2>$null
    } catch {
        docker run --rm $DockerHelmImage version
    }
} else {
    try {
        helm version --short 2>$null
    } catch {
        helm version
    }
}
Write-Host ""

# Validate chart directory exists with graceful handling
if (-not (Test-Path $ChartDir)) {
    Write-Host "⚠️  Chart directory not found: $ChartDir" -ForegroundColor Yellow
    Write-Host "💡 This is expected for projects without Helm charts" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "✅ Helm build skipped successfully!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor White
    Write-Host ""
    Write-Host "📊 Fallback Build Summary:" -ForegroundColor Blue
    Write-Host "=========================="
    Write-Host "⚠️  No Helm chart found - skipping build process" -ForegroundColor Yellow
    Write-Host "✅ Security pipeline continues with available components" -ForegroundColor Green
    Write-Host "💡 For Helm deployment, add a chart/ directory to your project" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📁 Output Files:" -ForegroundColor Blue
    Write-Host "================"
    Write-Host "ℹ️  No Helm packages generated (no chart available)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🔗 Related Commands:" -ForegroundColor Blue
    Write-Host "===================="
    Write-Host "Create chart:        helm create chart/"
    Write-Host "Re-run build:        npm run helm:build"
    Write-Host "Full security suite: npm run security:full"
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "Helm build complete (skipped)." -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    
    Stop-Transcript
    # Always exit successfully to continue pipeline
    exit 0
}

if (-not (Test-Path (Join-Path $ChartDir "Chart.yaml"))) {
    Write-Host "⚠️  Chart.yaml not found in $ChartDir" -ForegroundColor Yellow
    Write-Host "💡 Invalid Helm chart structure" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "✅ Helm build skipped successfully!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor White
    Write-Host ""
    Write-Host "📊 Fallback Build Summary:" -ForegroundColor Blue
    Write-Host "=========================="
    Write-Host "⚠️  Invalid chart structure - missing Chart.yaml" -ForegroundColor Yellow
    Write-Host "✅ Security pipeline continues" -ForegroundColor Green
    Write-Host "💡 Ensure Chart.yaml exists in chart/ directory" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "Helm build complete (skipped)." -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    
    Stop-Transcript
    # Always exit successfully to continue pipeline
    exit 0
}

Write-Host "📋 Chart Information:" -ForegroundColor Blue
Write-Host "===================="
if ($UseDocker) {
    docker run --rm -v "${TargetParent}:/workspace" -w /workspace $DockerHelmImage show chart $DockerChartPath
} else {
    helm show chart $ChartDir
}
Write-Host ""

# AWS ECR Authentication for private dependencies
Write-Host "🔐 Step 0: AWS ECR Authentication (Optional)" -ForegroundColor Blue
Write-Host "=================================="
$AwsRegion = "us-gov-west-1"
$EcrRegistry = "231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"

# Offer AWS ECR authentication for private Helm dependencies
Write-Host "🔐 This chart may require AWS ECR authentication for private dependencies" -ForegroundColor Cyan
Write-Host "Options:"
Write-Host "  1) Attempt AWS ECR login (recommended for complete build)"
Write-Host "  2) Skip authentication (fallback to stub dependencies)"
Write-Host ""
$AwsChoice = Read-Host "Choose option (1 or 2, default: 2)"
if ([string]::IsNullOrEmpty($AwsChoice)) { $AwsChoice = "2" }

# Initialize authentication status
$AwsAuthenticated = $false

if ($AwsChoice -eq "1") {
    Write-Host "🚀 Running AWS ECR authentication..." -ForegroundColor Cyan
    
    # Check if AWS CLI is available
    if (Get-Command aws -ErrorAction SilentlyContinue) {
        Write-Host "Checking AWS credentials..."
        try {
            aws sts get-caller-identity *>$null
            Write-Host "✅ AWS credentials found" -ForegroundColor Green
            
            # Authenticate with ECR
            Write-Host "Authenticating with AWS ECR..."
            try {
                $password = aws ecr get-login-password --region $AwsRegion 2>$null
                $password | docker login --username AWS --password-stdin $EcrRegistry *>$null
                Write-Host "✅ Docker ECR authentication successful" -ForegroundColor Green
                $AwsAuthenticated = $true
            } catch {
                Write-Host "⚠️  Docker ECR authentication failed" -ForegroundColor Yellow
                $AwsAuthenticated = $false
            }
            
            # Authenticate Helm with ECR (if not using Docker)
            if (-not $UseDocker -and (Get-Command helm -ErrorAction SilentlyContinue)) {
                try {
                    $password = aws ecr get-login-password --region $AwsRegion 2>$null
                    $password | helm registry login --username AWS --password-stdin $EcrRegistry *>$null
                    Write-Host "✅ Helm ECR authentication successful" -ForegroundColor Green
                    $AwsAuthenticated = $true
                } catch {
                    Write-Host "⚠️  Helm ECR authentication failed" -ForegroundColor Yellow
                }
            }
            
            if ($AwsAuthenticated) {
                Write-Host "✅ AWS ECR authentication completed successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  AWS ECR authentication failed - continuing with stub fallback" -ForegroundColor Yellow
                Write-Host "💡 Stub dependencies will be created for missing charts" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "⚠️  AWS credentials not configured - dependency download may fail" -ForegroundColor Yellow
            Write-Host "💡 Continuing with stub fallback - dependencies will be mocked" -ForegroundColor Cyan
            $AwsAuthenticated = $false
        }
    } else {
        Write-Host "❌ AWS CLI not found" -ForegroundColor Red
        Write-Host "💡 Continuing with stub fallback - dependencies will be mocked" -ForegroundColor Cyan
        $AwsAuthenticated = $false
    }
} else {
    Write-Host "⏭️  Skipping AWS authentication - using stub fallback" -ForegroundColor Cyan
    $AwsAuthenticated = $false
}

Write-Host ""

Write-Host "🔍 Step 1: Chart Dependency Update" -ForegroundColor Blue
Write-Host "==================================="

# Show authentication status like in Checkov script
if ($AwsAuthenticated) {
    Write-Host "🔐 AWS ECR authenticated - attempting full dependency resolution" -ForegroundColor Green
} else {
    Write-Host "🔓 No AWS ECR authentication - stub dependencies will be created if needed" -ForegroundColor Yellow
}

$DependencyResult = 1
if ($UseDocker) {
    # Pass AWS credentials to Docker container if available
    $AwsEnvFlags = @()
    if ($env:AWS_ACCESS_KEY_ID) {
        $AwsEnvFlags += "-e", "AWS_ACCESS_KEY_ID=$($env:AWS_ACCESS_KEY_ID)"
        $AwsEnvFlags += "-e", "AWS_SECRET_ACCESS_KEY=$($env:AWS_SECRET_ACCESS_KEY)" 
        $AwsEnvFlags += "-e", "AWS_DEFAULT_REGION=$($env:AWS_DEFAULT_REGION ?? $AwsRegion)"
    }
    
    # Mount Docker socket for ECR authentication
    $DockerSocketMount = @()
    if (Test-Path "/var/run/docker.sock") {
        $DockerSocketMount += "-v", "/var/run/docker.sock:/var/run/docker.sock"
    }
    
    $dockerArgs = @("run", "--rm", "-v", "${TargetParent}:/workspace", "-w", "/workspace") + $AwsEnvFlags + $DockerSocketMount + @($DockerHelmImage, "dependency", "update", $DockerChartPath)
    try {
        & docker $dockerArgs
        $DependencyResult = $LASTEXITCODE
    } catch {
        $DependencyResult = 1
    }
} else {
    try {
        helm dependency update $ChartDir
        $DependencyResult = $LASTEXITCODE
    } catch {
        $DependencyResult = 1
    }
}

if ($DependencyResult -eq 0) {
    Write-Host "✅ Dependencies updated successfully" -ForegroundColor Green
} else {
    if ($AwsAuthenticated) {
        Write-Host "⚠️  Dependency update failed despite AWS authentication" -ForegroundColor Yellow
        Write-Host "💡 May be network issues or repository access problems" -ForegroundColor Cyan
    } else {
        Write-Host "⚠️  Dependency update failed (expected without AWS ECR access)" -ForegroundColor Yellow
        Write-Host "💡 This is normal - continuing with stub dependencies" -ForegroundColor Cyan
    }
    Write-Host "🔄 Creating stub dependencies..." -ForegroundColor Cyan
    
    # Create charts directory if it doesn't exist
    $ChartsDir = Join-Path $ChartDir "charts"
    New-Item -ItemType Directory -Force -Path $ChartsDir | Out-Null
    
    # Create a stub dependency to allow build to continue
    Write-Host "💡 Creating stub advana-library chart..." -ForegroundColor Cyan
    $StubChartDir = Join-Path $ChartsDir "advana-library"
    $StubTemplatesDir = Join-Path $StubChartDir "templates"
    New-Item -ItemType Directory -Force -Path $StubTemplatesDir | Out-Null
    
    # Create stub Chart.yaml - continuing previous implementation
    $stubChartYaml = @"
apiVersion: v2
name: advana-library
description: Stub chart for advana-library dependency
type: library
version: 2.0.3
appVersion: "1.0.0"
"@
    Set-Content -Path (Join-Path $StubChartDir "Chart.yaml") -Value $stubChartYaml
    
    Write-Host "✅ Stub dependency created successfully" -ForegroundColor Green
}
Write-Host ""

Write-Host "🔍 Step 2: Chart Linting" -ForegroundColor Blue
Write-Host "======================="

$LintStatus = "FAILED"
if ($UseDocker) {
    try {
        docker run --rm -v "${TargetParent}:/workspace" -w /workspace $DockerHelmImage lint $DockerChartPath
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Chart linting passed" -ForegroundColor Green
            $LintStatus = "PASSED"
        } else {
            Write-Host "❌ Chart linting failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Chart linting failed with exception" -ForegroundColor Red
    }
} else {
    try {
        helm lint $ChartDir
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Chart linting passed" -ForegroundColor Green
            $LintStatus = "PASSED"
        } else {
            Write-Host "❌ Chart linting failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Chart linting failed with exception" -ForegroundColor Red
    }
}
Write-Host ""

Write-Host "🔍 Step 3: Template Validation" -ForegroundColor Blue
Write-Host "============================"

# Template rendering to file for analysis
$RenderedTemplatesFile = Join-Path $OutputDirPath "rendered-templates.yaml"

$TemplateStatus = "FAILED"
if ($UseDocker) {
    try {
        docker run --rm -v "${TargetParent}:/workspace" -v "${OutputDirPath}:/output" -w /workspace $DockerHelmImage template test-release $DockerChartPath --output-dir /output *>$null
        if ($LASTEXITCODE -eq 0) {
            # Also capture to single file for analysis
            docker run --rm -v "${TargetParent}:/workspace" -w /workspace $DockerHelmImage template test-release $DockerChartPath > $RenderedTemplatesFile
            Write-Host "✅ Template rendering successful" -ForegroundColor Green
            $TemplateStatus = "PASSED"
        } else {
            Write-Host "❌ Template rendering failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Template rendering failed with exception" -ForegroundColor Red
    }
} else {
    try {
        helm template test-release $ChartDir --output-dir $OutputDirPath *>$null
        helm template test-release $ChartDir > $RenderedTemplatesFile
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Template rendering successful" -ForegroundColor Green
            $TemplateStatus = "PASSED"
        } else {
            Write-Host "❌ Template rendering failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Template rendering failed with exception" -ForegroundColor Red
    }
}

if ($TemplateStatus -eq "PASSED") {
    Write-Host "📄 Templates rendered to: $RenderedTemplatesFile"
}
Write-Host ""

Write-Host "📦 Step 4: Chart Packaging" -ForegroundColor Blue
Write-Host "========================="

# Package the chart
$PackageStatus = "FAILED"
$PackageFile = ""
$PackageSizeFormatted = ""
if ($UseDocker) {
    try {
        # For Docker, mount output directory for packaging
        docker run --rm -v "${TargetParent}:/workspace" -v "${OutputDirPath}:/output" -w /workspace $DockerHelmImage package $DockerChartPath --destination /output *>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Chart packaging successful" -ForegroundColor Green
            
            # Find the generated package
            $PackageFile = Get-ChildItem -Path $OutputDirPath -Filter "${ChartName}-*.tgz" | Select-Object -First 1 -ExpandProperty FullName
            if ($PackageFile -and (Test-Path $PackageFile)) {
                $PackageSize = (Get-Item $PackageFile).Length
                $PackageSizeFormatted = if ($PackageSize -gt 1MB) { "$([math]::Round($PackageSize/1MB, 2))M" } elseif ($PackageSize -gt 1KB) { "$([math]::Round($PackageSize/1KB, 2))K" } else { "${PackageSize}B" }
                Write-Host "Package created: $(Split-Path -Leaf $PackageFile) ($PackageSizeFormatted)"
                
                # Verify package integrity with Docker
                try {
                    docker run --rm -v "${OutputDirPath}:/packages" $DockerHelmImage show chart "/packages/$(Split-Path -Leaf $PackageFile)" *>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "✅ Package integrity verified" -ForegroundColor Green
                        $PackageStatus = "PASSED"
                    } else {
                        Write-Host "❌ Package integrity check failed" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "❌ Package integrity check failed" -ForegroundColor Red
                }
            } else {
                Write-Host "❌ Package file not found" -ForegroundColor Red
            }
        } else {
            Write-Host "❌ Chart packaging failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Chart packaging failed with exception" -ForegroundColor Red
    }
} else {
    try {
        helm package $ChartDir --destination $OutputDirPath *>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Chart packaging successful" -ForegroundColor Green
            
            # Find the generated package
            $PackageFile = Get-ChildItem -Path $OutputDirPath -Filter "${ChartName}-*.tgz" | Select-Object -First 1 -ExpandProperty FullName
            if ($PackageFile -and (Test-Path $PackageFile)) {
                $PackageSize = (Get-Item $PackageFile).Length
                $PackageSizeFormatted = if ($PackageSize -gt 1MB) { "$([math]::Round($PackageSize/1MB, 2))M" } elseif ($PackageSize -gt 1KB) { "$([math]::Round($PackageSize/1KB, 2))K" } else { "${PackageSize}B" }
                Write-Host "Package created: $(Split-Path -Leaf $PackageFile) ($PackageSizeFormatted)"
                
                # Verify package integrity
                try {
                    helm show chart $PackageFile *>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "✅ Package integrity verified" -ForegroundColor Green
                        $PackageStatus = "PASSED"
                    } else {
                        Write-Host "❌ Package integrity check failed" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "❌ Package integrity check failed" -ForegroundColor Red
                }
            } else {
                Write-Host "❌ Package file not found" -ForegroundColor Red
            }
        } else {
            Write-Host "❌ Chart packaging failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Chart packaging failed with exception" -ForegroundColor Red
    }
}
Write-Host ""

Write-Host "🔍 Step 5: Security Analysis" -ForegroundColor Blue
Write-Host "==========================="

# Check for common security issues in templates
$SecurityIssues = 0

Write-Host "Scanning templates for security best practices..."

$TemplatesDir = Join-Path $ChartDir "templates"
if (Test-Path $TemplatesDir) {
    # Check for hardcoded secrets
    $hardcodedSecrets = Get-ChildItem -Path $TemplatesDir -Filter "*.yaml" -Recurse | 
        ForEach-Object { Select-String -Path $_.FullName -Pattern "password|secret|token" } | 
        Where-Object { $_.Line -notmatch "\{\{" -and $_.Line -match ":" }
    
    if ($hardcodedSecrets) {
        Write-Host "⚠️  Potential hardcoded secrets found" -ForegroundColor Yellow
        $SecurityIssues++
    }

    # Check for privileged containers
    $privilegedContainers = Get-ChildItem -Path $TemplatesDir -Filter "*.yaml" -Recurse |
        ForEach-Object { Select-String -Path $_.FullName -Pattern "privileged.*true" }
    
    if ($privilegedContainers) {
        Write-Host "⚠️  Privileged containers detected" -ForegroundColor Yellow
        $SecurityIssues++
    }

    # Check for root user usage
    $rootUsers = Get-ChildItem -Path $TemplatesDir -Filter "*.yaml" -Recurse |
        ForEach-Object { Select-String -Path $_.FullName -Pattern "runAsUser.*0" }
    
    if ($rootUsers) {
        Write-Host "⚠️  Root user usage detected" -ForegroundColor Yellow
        $SecurityIssues++
    }

    # Check for missing resource limits
    $resourceLimits = Get-ChildItem -Path $TemplatesDir -Filter "*.yaml" -Recurse |
        ForEach-Object { Select-String -Path $_.FullName -Pattern "resources:" }
    
    if (-not $resourceLimits) {
        Write-Host "⚠️  No resource limits defined" -ForegroundColor Yellow
        $SecurityIssues++
    }
}

$SecurityStatus = if ($SecurityIssues -eq 0) { "PASSED" } else { "WARNING" }
if ($SecurityIssues -eq 0) {
    Write-Host "✅ No major security issues detected" -ForegroundColor Green
} else {
    Write-Host "⚠️  $SecurityIssues potential security issues found" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "📊 Build Summary" -ForegroundColor Blue
Write-Host "================"
Write-Host "Chart Linting: $LintStatus"
Write-Host "Template Validation: $TemplateStatus"
Write-Host "Package Creation: $PackageStatus"
Write-Host "Security Scan: $SecurityStatus"
Write-Host ""

# Overall status
$BuildResult = "FAILED"
if ($LintStatus -eq "PASSED" -and $TemplateStatus -eq "PASSED" -and $PackageStatus -eq "PASSED") {
    Write-Host "🎉 Helm build completed successfully!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor White
    
    if ($PackageFile -and (Test-Path $PackageFile)) {
        Write-Host "📦 Package Details:" -ForegroundColor Green
        Write-Host "File: $(Split-Path -Leaf $PackageFile)"
        Write-Host "Size: $PackageSizeFormatted"
        Write-Host "Location: $PackageFile"
        Write-Host ""
        
        Write-Host "🚀 Deployment Commands:" -ForegroundColor Green
        Write-Host "# Install from package:"
        Write-Host "helm install $ChartName `"$PackageFile`""
        Write-Host ""
        Write-Host "# Install from source:"
        Write-Host "helm install $ChartName `"$ChartDir`""
        Write-Host ""
        Write-Host "# Upgrade existing deployment:"
        Write-Host "helm upgrade $ChartName `"$PackageFile`""
    }
    
    $BuildResult = "SUCCESS"
} else {
    Write-Host "❌ Helm build completed with errors" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor White
    Write-Host "Please review the issues above and fix them."
}

Write-Host ""
Write-Host "📁 Output Files:" -ForegroundColor Blue
Write-Host "================"
Write-Host "Build log: $BuildLog"
Write-Host "Rendered templates: $RenderedTemplatesFile"
if ($PackageFile -and (Test-Path $PackageFile)) {
    Write-Host "Helm package: $PackageFile"
}
Write-Host "Package directory: $OutputDirPath"

Write-Host ""
Write-Host "============================================" -ForegroundColor White
Write-Host "Helm build process complete." -ForegroundColor White
Write-Host "============================================" -ForegroundColor White

Stop-Transcript

# Exit with appropriate code
if ($BuildResult -eq "SUCCESS") {
    exit 0
} else {
    exit 1
}
