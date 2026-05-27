# Epyon Cleanup Archive - May 27, 2026

## Archive Information
- **Date Created**: 2026-05-27 07:43:39
- **Archive Path**: `_archive/cleanup-2026-05-27/`
- **Retention Policy**: Keep scans from last 30 days (since 2026-04-27)
- **Safety**: All files preserved, can be restored if needed

## What's Archived

### Scan Directories (`scans/`)
Old scan directories from before 2026-04-27

### Temporary Clones (`tmp-clones/`)
Git clone directories from `tmp/clone-*/` used during testing

### Scripts (`scripts/`)
- Old backup directory: `backup-20251115-194319/`
- Old version files: `*.old`
- Stale utilities: `cleanup-scripts.sh`

### Root Files (`root-files/`)
Test and demo files that were at repository root

### Miscellaneous (`misc/`)
Empty directories and other cleanup items

## Restoration Instructions

To restore any archived files:
```bash
# Restore a specific scan
cp -r _archive/cleanup-2026-05-27/scans/SCAN_NAME scans/

# Restore all scans
cp -r _archive/cleanup-2026-05-27/scans/* scans/

# Restore scripts
cp -r _archive/cleanup-2026-05-27/scripts/* scripts/shell/
```

## Detailed Inventory

See sections below for complete file listings.


---

## Pre-Cleanup Discovery Summary

**Discovered on**: 2026-05-27

### Scan Directories
- **Total**: 465 scan directories
- **To Archive**: 87 scans (before 2026-04-27)
- **To Keep**: 378 scans (from last 30 days)

### Temporary Clones
- **To Archive**: 67 directories in `tmp/clone-*/`

### Old Script Versions
- **To Archive**: 1 `*.old` file
- **To Archive**: 1 backup directory (`backup-20251115-194319/`)
- **To Archive**: `cleanup-scripts.sh` (references non-existent files)

### Nested Scans (Wrong Location)
- **To Archive**: 2 scan directories in `scripts/shell/scans/`

### Root Test Files
- **To Archive**: `test-approved-by.sh`
- **To Archive**: `test-workflow.yml`

### Other Items
- **To Remove**: `Users/` (empty directory)
- **To Archive**: 2 old garak report files in `runs/`

### Estimated Space Impact
- Archiving will move ~87 old scan directories + 67 clone directories
- Recent scans (378) remain accessible in `scans/`

---

## Archived Files Inventory


### Scan Directories (89 archived)
All scan directories from before 2026-04-27 have been moved here.
These include scans for: iris, midas, comet-starter, epyon, and other targets.

### Temporary Clone Directories (67 archived)
All `tmp/clone-*` directories used for Git repository scanning.
Format: `clone-YYYYMMDDHHMMSS/`
Date range: April-May 2026

### Script Files (3 archived)
- `backup-20251115-194319/` - Old backup directory with historical scripts
- `run-sonar-analysis.sh.old` - Previous version of SonarQube scanner
- `cleanup-scripts.sh` - Stale cleanup utility (referenced non-existent files)

### Root-Level Files (2 archived)
- `test-approved-by.sh` - Test script for .epyon-ignore approval tracking
- `test-workflow.yml` - GitHub Actions workflow test file

### Miscellaneous Files (2 archived)
- `garak.27a3977a-1553-4034-baf6-67be7df074b7.report.jsonl`
- `garak.bad52ee8-f6b9-4de2-b230-f38fbd994206.report.jsonl`
Old garak LLM security probe reports from runs/

### Removed Items
- `Users/` - Empty directory
- `scripts/shell/scans/` - Empty directory (after archiving misplaced scans)

---

## Post-Cleanup Status

**Archive Created**: 2026-05-27
**Total Items Archived**: 163 (89 scans + 67 clones + 7 other files/directories)
**Remaining Active Scans**: 380 (from last 30 days)
**Test Suite Status**: ✅ All 773 tests passing
**Web UI Status**: ✅ Functional

**Archive Location**: `_archive/cleanup-2026-05-27/`
**Archive Size**: See du -sh output above

All archived files are preserved and can be restored at any time using the instructions in this manifest.
