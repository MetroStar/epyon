# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in EPYON, please report it responsibly.

### How to Report

**Please DO NOT create a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities through one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](../../security/advisories/new) of this repository
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email**
   - Send details to: [YOUR-EMAIL@example.com]
   - Use subject line: `[SECURITY] EPYON Vulnerability Report`
   - Include PGP key if available for encrypted communication

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker accomplish?
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions of EPYON are affected?
- **Environment**: OS, shell version, tool versions if relevant
- **Proof of Concept**: Code, scripts, or commands demonstrating the issue
- **Suggested Fix**: If you have ideas for remediation (optional)

### What to Expect

After you submit a report, you can expect:

1. **Acknowledgment**: We will acknowledge receipt within **48 hours**
2. **Initial Assessment**: We will provide an initial assessment within **5 business days**
3. **Updates**: We will keep you informed of our progress
4. **Resolution**: We aim to resolve critical issues within **30 days**
5. **Credit**: With your permission, we will credit you in the security advisory and changelog

### Security Response Process

1. **Triage**: We assess severity using CVSS scoring
2. **Investigation**: We reproduce and investigate the issue
3. **Development**: We develop and test a fix
4. **Disclosure**: We coordinate disclosure timing with the reporter
5. **Release**: We release a patched version
6. **Advisory**: We publish a security advisory

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.5.x   | :white_check_mark: |
| < 2.5   | :x:                |

**Recommendation**: Always use the latest version to ensure you have the latest security patches.

## Security Best Practices

When using EPYON Security Scanner:

### For Operators

1. **Keep Updated**: Regularly update to the latest EPYON version
2. **Secure Credentials**: Store API tokens and secrets securely
   - Use GitHub Secrets for CI/CD environments
   - Use `.env` files with proper permissions for local use
   - Never commit credentials to version control
3. **Review Permissions**: Ensure EPYON runs with minimal required permissions
4. **Scan Results**: Treat scan results as sensitive - they may contain vulnerability details
5. **Network Security**: When using SonarQube or external scanners, use secure connections (HTTPS)

### For Developers

1. **Input Validation**: All scan inputs are validated before processing
2. **Dependency Management**: Keep security tool dependencies updated
3. **Isolation**: Scans run in isolated environments when possible
4. **Output Sanitization**: Dashboard and reports sanitize user-controlled data

### For Security Researchers

1. **Scope**: Security testing should be performed on your own installations only
2. **Data Privacy**: Do not include real vulnerability data from production systems
3. **Responsible Disclosure**: Follow our vulnerability reporting process above
4. **Legal Compliance**: Ensure your testing complies with applicable laws

## Security Features

EPYON includes several security-focused features:

- **Multi-layer scanning**: 11 integrated security tools covering different attack vectors
- **Suppression management**: Controlled exception handling with `.epyon-ignore.yml`
- **Audit trails**: Comprehensive scan manifests and metadata tracking
- **Severity gating**: Configurable thresholds to fail builds on critical findings
- **Air-gapped support**: Can operate in offline/restricted environments
- **Integrity verification**: File hashing and manifest validation
- **STIG compliance**: Alignment with security technical implementation guides

## Known Security Considerations

### Scan Artifacts

Scan results contain security findings and may reveal:
- Vulnerable dependencies in your codebase
- Exposed secrets or credentials (TruffleHog findings)
- Infrastructure misconfigurations (Checkov findings)
- Malware detections (ClamAV findings)

**Action**: Treat all scan artifacts as sensitive. Restrict access appropriately.

### Tool Dependencies

EPYON depends on third-party security tools:
- Trivy, Grype, Syft (Anchore)
- TruffleHog (Truffle Security)
- Checkov (Bridgecrew/Prisma Cloud)
- ClamAV
- SonarQube (optional)

**Action**: Monitor security advisories for these tools and update regularly.

### Execution Environment

EPYON executes in your environment with file system access.

**Action**: 
- Review scripts before execution
- Use containerization or VMs for untrusted targets
- Apply principle of least privilege

## Security Update Policy

- **Critical vulnerabilities** (CVSS 9.0-10.0): Patched within 7 days
- **High vulnerabilities** (CVSS 7.0-8.9): Patched within 30 days
- **Medium vulnerabilities** (CVSS 4.0-6.9): Patched within 90 days
- **Low vulnerabilities** (CVSS 0.1-3.9): Addressed in next release

Security patches will be released as:
- Patch versions for current minor version (e.g., 2.5.1)
- Backports for supported versions if applicable

## Security Hall of Fame

We appreciate security researchers who help make EPYON more secure:

<!-- This section will list researchers who responsibly disclosed vulnerabilities -->
*No vulnerabilities reported yet*

---

## Contact

For non-security issues:
- GitHub Issues: [github.com/your-org/epyon/issues](../../issues)
- Documentation: [See README.md](README.md)

For security issues only:
- **GitHub Security Advisory**: [Report a vulnerability](../../security/advisories/new)
- **Email**: [YOUR-EMAIL@example.com]

---

*This security policy is effective as of February 12, 2026*  
*Last updated: February 12, 2026*
