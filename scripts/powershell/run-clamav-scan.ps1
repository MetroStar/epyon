# ClamAV Antivirus Scan Script
# Scans for malware and viruses in the codebase using Docker

# Configuration - Support target directory override
$RepoPath = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { Get-Location }
# Configuration
$OutputDir = "..\..\reports\clamav-reports"
$ScanLog = Join-Path $OutputDir "clamav-scan.log"
$InfectedLog = Join-Path $OutputDir "clamav-infected.log"

# Create output directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "============================================"
Write-Host "Starting ClamAV antivirus scan..."
Write-Host "============================================"
Write-Host "Repository: $RepoPath"
Write-Host "Output Directory: $OutputDir"
Write-Host "Scan Log: $ScanLog"
Write-Host ""

Write-Host "Updating ClamAV virus definitions..."
Write-Host ""

# First, update virus definitions
docker run --rm `
  -v clamav-db:/var/lib/clamav `
  clamav/clamav-debian:latest `
  freshclam

if ($LASTEXITCODE -ne 0) {
  Write-Host "    Warning: Failed to update virus definitions. Proceeding with existing definitions..."
}

Write-Host ""
Write-Host "Running ClamAV scan..."
Write-Host ""

# Run ClamAV scan using Docker
# --infected: Only show infected files
# --recursive: Scan directories recursively
# --log: Log scan results
# --exclude-dir: Exclude specific directories
docker run --rm `
  -v "${RepoPath}:/scan" `
  -v clamav-db:/var/lib/clamav `
  -v "${PWD}\${OutputDir}:/reports" `
  clamav/clamav-debian:latest `
  clamscan `
  --recursive `
  --infected `
  --log=/reports/clamav-scan.log `
  --exclude-dir=node_modules `
  --exclude-dir=.git `
  --exclude-dir=dist `
  --exclude-dir=build `
  --exclude-dir=coverage `
  --exclude-dir=clamav-reports `
  --exclude-dir=trufflehog-reports `
  /scan 2>&1

$ScanExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "============================================"

# Parse results based on exit code
if ($ScanExitCode -eq 0) {
  Write-Host "  ClamAV scan completed successfully!" -ForegroundColor Green
  Write-Host "============================================"
  Write-Host "   No malware or viruses detected!" -ForegroundColor Green
} elseif ($ScanExitCode -eq 1) {
  Write-Host "    ClamAV scan completed with threats detected!" -ForegroundColor Yellow
  Write-Host "============================================"
  Write-Host "   MALWARE/VIRUSES FOUND! Check the detailed logs." -ForegroundColor Red
  
  # Extract infected files from log
  if (Test-Path $ScanLog) {
    Write-Host ""
    Write-Host "Infected files:"
    Write-Host "==============="
    Select-String -Path $ScanLog -Pattern "FOUND" | Tee-Object -FilePath $InfectedLog
  }
} else {
  Write-Host "  ClamAV scan failed with error code: $ScanExitCode" -ForegroundColor Red
  Write-Host "============================================"
}

# Display summary if scan log exists
if (Test-Path $ScanLog) {
  Write-Host ""
  Write-Host "Scan Summary:"
  Write-Host "============="
  
  # Extract summary information from log
  $LogContent = Get-Content $ScanLog -Raw
  if ($LogContent -match "SCAN SUMMARY") {
    $LogContent -split "`n" | Select-String -Pattern "SCAN SUMMARY|End Date:" -Context 0,10
  } else {
    # Fallback: count files and infected
    $ScannedFiles = (Select-String -Path $ScanLog -Pattern "OK$" -AllMatches).Matches.Count
    $InfectedFiles = (Select-String -Path $ScanLog -Pattern "FOUND$" -AllMatches).Matches.Count
    
    Write-Host "Scanned files: $ScannedFiles"
    Write-Host "Infected files: $InfectedFiles"
  }
  
  Write-Host ""
  Write-Host "Detailed results saved to: $ScanLog"
  
  if ((Test-Path $InfectedLog) -and ((Get-Item $InfectedLog).Length -gt 0)) {
    Write-Host "Infected files list: $InfectedLog"
  }
} else {
  Write-Host ""
  Write-Host "    No scan log generated. Check Docker configuration." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================"
Write-Host "ClamAV scan complete."
Write-Host "============================================"
