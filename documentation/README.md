# Epyon Documentation

**Last Updated:** February 6, 2026

This directory contains the essential documentation for the Epyon security scanning platform.

## 📚 Available Documentation

### 🔒 [Security Review & Test Coverage](SECURITY_REVIEW_AND_TEST_COVERAGE.md)
**Comprehensive security analysis and testing documentation**
- Complete test coverage report (304 tests)
- Security architecture review
- Threat model and mitigations
- Vulnerability management
- Compliance mapping
- Fixed CVEs and bugs

**Audience:** Security teams, DevOps engineers, compliance officers  
**Status:** ✅ Current (Feb 2026)

---

### 📁 [Scan Directory Architecture](SCAN_DIRECTORY_ARCHITECTURE.md)
**Implementation details for scan result organization**
- Scan directory structure and layout
- Timestamp consistency approach
- Result isolation and organization
- Legacy compatibility and symlinks

**Audience:** Developers, DevOps engineers  
**Status:** ✅ Current

---

### 🔌 [Offline & Air-Gapped Setup](OFFLINE_AIR_GAPPED_SETUP.md)
**Complete guide for deploying Epyon in restricted environments**
- Docker image requirements and export procedures
- Vulnerability database management
- Air-gapped bundle structure
- Implementation timeline (8-12 days)
- Database freshness recommendations
- Security considerations

**Audience:** Enterprise deployment teams, government contractors  
**Status:** ✅ Current (Jan 2026)

---

## 🚀 Quick Start

For most users, start with the **Security Review & Test Coverage** document to understand:
- What Epyon does
- How it's architected
- What security controls are in place
- How to validate the installation

Then refer to specific guides as needed:
- **Deploying offline?** → See Offline & Air-Gapped Setup
- **Understanding scan organization?** → See Scan Directory Architecture

---

## 📝 Documentation Maintenance

### What's Included
- Security and architecture documentation
- Deployment guides for special scenarios
- Implementation reference materials

### What's NOT Included
- Historical summaries (removed)
- PowerShell migration documents (removed)
- Project-specific validation guides (removed)
- Outdated dashboards and reports (removed)

### Contribution Guidelines
- Keep documentation current with code changes
- Update "Last Updated" dates when modifying
- Remove outdated content proactively
- Focus on operational value, not historical context

---

## 🔗 Additional Resources

### In Repository
- `README.md` - Main project overview and getting started
- `.github/workflows/` - GitHub Actions workflow examples
- `tests/shell/` - Test suite documentation and examples
- `scripts/shell/` - Shell script inline documentation

### External
- [BATS Testing Framework](https://github.com/bats-core/bats-core)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

---

## 📊 Documentation Status

| Document | Lines | Last Updated | Status |
|----------|-------|--------------|--------|
| Security Review | ~850 | Feb 2026 | ✅ Current |
| Scan Architecture | ~170 | Current | ✅ Current |
| Offline Setup | ~310 | Jan 2026 | ✅ Current |

**Total:** 3 active documents

---

## 🗑️ Recently Removed

Cleaned up **24 outdated documents** on Feb 6, 2026:
- 5 PowerShell parity documents
- 5 deployment summaries
- 9 implementation notes
- 5 miscellaneous outdated guides

Focus is now on **actionable, current documentation** that supports ongoing operations.

---

**For questions or improvements to documentation, please open an issue in the repository.**
