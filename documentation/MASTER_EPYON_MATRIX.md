# Master Epyon Capabilities & Scan Matrix

This document provides a single landing page for Epyon's scan-mode matrix, release evidence coverage, and major platform capabilities.

## Primary References

- **[Scan Matrix](SCAN_MATRIX.md)** — authoritative layer-by-layer coverage for `quick`, `nightly`, `full`, and `stig` runs.
- **[Container Build & Evidence Guide](CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md)** — Layer 0 build flow, release artifacts, provenance, and signing outputs.

## Scan Mode Summary

| Mode | Primary Purpose | Key Coverage |
|------|------------------|--------------|
| `quick` | Fast pull request feedback | Dependency, container, and secret scanning |
| `nightly` | Scheduled broad security coverage | Most static security layers without STIG |
| `full` | Deep application security review | Full standard layer set with optional STIG |
| `stig` | Compliance-only execution | STIG assessment and evidence generation |

## Release & Evidence Coverage

| Capability Area | Reference |
|-----------------|-----------|
| Container image build evidence | [Container Build & Evidence Guide](CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md) |
| Security layer execution matrix | [Scan Matrix](SCAN_MATRIX.md) |
| Dashboard and reporting outputs | [README.md](../README.md) |

## Platform Capability Areas

- Multi-layer DevSecOps scanning across code, containers, dependencies, IaC, and ML assets
- Self-contained stakeholder reporting through the generated security dashboard
- STIG compliance assessment with persisted evidence and review workflow support
- CI/CD integration for scheduled, pull request, and manually triggered scans
