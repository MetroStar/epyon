# Changelog

All notable changes to the EPYON Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-02-12

### Added
- Version control system with VERSION file
- Version display in security dashboard footer
- Version display in consolidated reports
- SonarQube GitHub secrets support with .env.sonar fallback
- Suppressed findings display on security dashboard
- Vulnerability summary in GitHub Actions output

### Changed
- Reordered workflow steps: severity gate now runs before dashboard generation
- Removed duplicate vulnerability summary from GitHub Actions (kept severity gate output only)
- Removed "Next Steps" section from executive summary

### Fixed
- Invalid cron expression in baseline-scan workflow
- Missing find-scan step ID in baseline workflow
- ClamAV virus detection already counted as CRITICAL (verified)

## [Unreleased]

### Planned
- Automated version bumping script
- Git tag synchronization
- Release automation workflow

---

## Version Format

EPYON follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version: Incompatible API/breaking changes
- **MINOR** version: New functionality (backwards compatible)
- **PATCH** version: Bug fixes (backwards compatible)
