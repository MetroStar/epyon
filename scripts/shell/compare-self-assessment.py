#!/usr/bin/env python3
"""Compare a completed Epyon scan of the self-assessment fixture against
tests/fixtures/self-assessment/expected-findings.json ground truth, and
write a pass/fail-per-layer results file.

Usage:
    compare-self-assessment.py --scan-dir scans/self-assessment_2026-.../ \
        --manifest tests/fixtures/self-assessment/expected-findings.json \
        --output web/data/self-assessment-latest.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Each tool's own raw output file, read directly, rather than the aggregated
# security-findings-summary.json. The summary file normalizes/suffixes tool
# names inconsistently (e.g. "Grype-sbom", "Trivy-filesystem") and can drop
# or dedupe findings during consolidation — reading the raw per-tool file
# validates "did the tool detect X", which is what self-assessment is for.
RAW_RESULT_FILES = {
    "trufflehog": "trufflehog/trufflehog-filesystem-results.json",
    "checkov": "checkov/checkov-results.json",
    "trivy": "trivy/trivy-filesystem-results.json",
    "grype": "grype/grype-sbom-results.json",
    "pip-audit": "pip-audit/pip-audit-consolidated-results.json",
    # Self-assessment's own dedicated image-mode Xeol scan (see
    # run-self-assessment.sh) — the regular filesystem-mode scan
    # (xeol-filesystem-results.json, written by run-xeol-scan.sh) can never
    # match anything for this fixture, since Xeol's binary/package
    # catalogers only detect real installed runtimes inside an actual
    # container image, not a Dockerfile FROM line in a source tree.
    "xeol": "xeol/xeol-image-results.json",
    "clamav": "clamav/clamav-results.json",
    # Unlike most tools, run-picklescan.py writes directly to the scan
    # dir's root rather than a dedicated subdirectory.
    "picklescan-enhanced": "picklescan-results.json",
}


def _load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _load_ndjson_or_json(path: Path):
    """TruffleHog writes either NDJSON (one JSON object per line) when it
    finds results, or an empty file when it finds none."""
    if not path.exists():
        return []
    text = path.read_text().strip()
    if not text:
        return []
    try:
        # Some invocations wrap results in a single JSON array/object.
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _count_trufflehog_findings(scan_dir: Path) -> int:
    return len(_load_ndjson_or_json(scan_dir / RAW_RESULT_FILES["trufflehog"]))


def _count_checkov_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / RAW_RESULT_FILES["checkov"])
    if not isinstance(data, list):
        return 0
    total = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        total += len(entry.get("results", {}).get("failed_checks", []) or [])
    return total


def _count_trivy_dockerfile_findings(scan_dir: Path) -> int:
    """Counts Trivy filesystem-scan misconfigurations specifically for the
    planted inference/Dockerfile (Layer 7: Container Security)."""
    data = _load_json(scan_dir / RAW_RESULT_FILES["trivy"])
    if not isinstance(data, dict):
        return 0
    total = 0
    for result in data.get("Results", []) or []:
        if result.get("Type") == "dockerfile":
            total += len(result.get("Misconfigurations") or [])
    return total


def _count_grype_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / RAW_RESULT_FILES["grype"])
    if not isinstance(data, dict):
        return 0
    return len(data.get("matches") or [])


def _anchore_policy_gate_stopped(scan_dir: Path) -> int:
    """Layer 10's source of truth is the policy GATE (stop/warn/go), not a
    raw CVE count — Anchore's actual differentiator from Trivy/Grype is
    policy-based compliance gating, not another vulnerability list. Returns
    1 if the policy evaluation ran and its gate correctly STOPped on this
    fixture's planted critical CVE, 0 otherwise (missing file, gate
    didn't fire, etc.) — evaluated as a finding_min: 1 check.
    """
    data = _load_json(scan_dir / "anchore" / "anchore-policy-evaluation.json")
    if not isinstance(data, dict):
        return 0
    return 1 if data.get("gate_action") == "stop" else 0


def _count_api_discovery_endpoints(scan_dir: Path) -> int:
    data = _load_json(scan_dir / "api" / "api-discovery.json")
    if not isinstance(data, dict):
        return 0
    return int(data.get("summary", {}).get("total_endpoints_discovered") or 0)


def _count_pip_audit_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / RAW_RESULT_FILES["pip-audit"])
    if not isinstance(data, dict):
        return 0
    if "total_vulnerabilities" in data:
        return data["total_vulnerabilities"]
    return sum(len(r.get("results") or []) for r in data.get("scan_results", []) or [])


def _count_xeol_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / RAW_RESULT_FILES["xeol"])
    if not isinstance(data, dict):
        return 0
    return len(data.get("matches") or [])


def _stig_tool_ran(scan_dir: Path) -> bool:
    """Best-effort "did the STIG assessment actually execute" check for
    Layer 13. Its manifest entry is permanently validate:false (STIG status
    isn't a plantable finding-count problem), but that previously meant the
    UI reported "not_validated" identically whether the layer was properly
    selected+run or silently never invoked. Look for any
    stig-results-*.json produced in the scan dir with at least one
    assessed control, regardless of exact STIG slug.
    """
    for f in scan_dir.glob("stig-results-*.json"):
        data = _load_json(f)
        if isinstance(data, dict) and data.get("assessments"):
            return True
    return False


def _count_clamav_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / RAW_RESULT_FILES["clamav"])
    if not isinstance(data, dict):
        return 0
    return len(data.get("detections") or [])


def _count_dedicated_findings(scan_dir: Path, rel_path: str) -> int:
    data = _load_json(scan_dir / rel_path)
    if data is None:
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        # Both {"findings": [...]} and flat-object schemas are used across
        # the ML layers; fall back to counting any list-valued key.
        if "findings" in data and isinstance(data["findings"], list):
            return len(data["findings"])
        for v in data.values():
            if isinstance(v, list):
                return len(v)
    return 0


def _count_sbom_components(scan_dir: Path) -> int:
    sbom_dir = scan_dir / "sbom"
    if not sbom_dir.is_dir():
        return 0
    # Each scan_type (e.g. "filesystem") can produce a CycloneDX file
    # ("<type>.cyclonedx.json", using "components") AND/OR a syft-native
    # file ("<type>.json", using "artifacts") representing the SAME
    # underlying SBOM — summing both would double-count. Prefer the
    # CycloneDX variant per scan_type; fall back to the syft-native
    # "artifacts" count only when no CycloneDX conversion exists for it
    # (e.g. the local `syft convert`/container-convert step failed).
    cyclonedx_stems: set[str] = set()
    total = 0
    for f in sorted(sbom_dir.glob("*.cyclonedx.json")):
        data = _load_json(f)
        if not data:
            continue
        cyclonedx_stems.add(f.name[: -len(".cyclonedx.json")])
        total += len(data.get("components") or data.get("packages") or [])
    for f in sorted(sbom_dir.glob("*.json")):
        if f.name.endswith(".cyclonedx.json"):
            continue
        stem = f.name[: -len(".json")]
        if stem in cyclonedx_stems:
            continue  # already counted via its CycloneDX conversion above
        data = _load_json(f)
        if not data:
            continue
        total += len(data.get("components") or data.get("packages") or data.get("artifacts") or [])
    return total


def _count_helm_charts_built(scan_dir: Path) -> int:
    data = _load_json(scan_dir / "helm" / "helm-results.json")
    if not isinstance(data, dict):
        return 0
    return int(data.get("summary", {}).get("charts_built") or 0)


def _count_model_provenance_typosquat(scan_dir: Path) -> int:
    data = _load_json(scan_dir / "model-provenance" / "model-provenance-results.json")
    if not data:
        return 0
    findings = data.get("findings", data) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        return 0
    return sum(1 for f in findings if "typosquat" in json.dumps(f).lower())


def _count_model_card_findings(scan_dir: Path) -> int:
    """Layer 15 (Model Card Compliance) is implemented by
    run-modelcard-check.sh, writing modelcard/modelcard-results.json —
    a distinct, more thorough check than model-provenance's own internal
    _check_model_cards() helper."""
    data = _load_json(scan_dir / "modelcard" / "modelcard-results.json")
    if not isinstance(data, dict):
        return 0
    findings = data.get("findings")
    return len(findings) if isinstance(findings, list) else 0


def _count_inference_security_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / "inference-security" / "inference-security-results.json")
    if not data:
        return 0
    findings = data.get("findings", data) if isinstance(data, dict) else data
    return len(findings) if isinstance(findings, list) else 0


def _count_compromised_source_findings(scan_dir: Path) -> int:
    data = _load_json(scan_dir / "compromised-source" / "compromised-source-results.json")
    if not data:
        return 0
    findings = data.get("findings", data) if isinstance(data, dict) else data
    return len(findings) if isinstance(findings, list) else 0


# Per-tool raw-file counters, keyed by manifest tool identifier.
RAW_COUNTERS = {
    "trufflehog": _count_trufflehog_findings,
    "checkov": _count_checkov_findings,
    "trivy": _count_trivy_dockerfile_findings,
    "grype": _count_grype_findings,
    "pip-audit": _count_pip_audit_findings,
    "xeol": _count_xeol_findings,
    "clamav": _count_clamav_findings,
    "picklescan-enhanced": lambda scan_dir: _count_dedicated_findings(
        scan_dir, RAW_RESULT_FILES["picklescan-enhanced"]
    ),
}


def evaluate_layer(
    layer: dict,
    scan_dir: Path,
    environment_limited_layers: set[float],
    only_layers: set[str] | None,
) -> dict:
    result = {
        "layer": layer["layer"],
        "name": layer["name"],
        "tool": layer["tool"],
        "validated": layer.get("validate", False),
    }

    if only_layers is not None and str(layer["layer"]) not in only_layers:
        result["status"] = "skipped"
        result["validated"] = False
        result["notes"] = "Skipped for this run — not selected."
        return result

    if not layer.get("validate"):
        result["status"] = "not_validated"
        notes = layer.get("notes", "")
        if layer["name"] == "STIG Compliance":
            if _stig_tool_ran(scan_dir):
                notes = f"Tool ran and produced assessed controls (best-effort — no deterministic finding count checked). {notes}".strip()
            else:
                notes = f"⚠️ No stig-results-*.json with assessed controls found in this scan dir — the tool may not have run. {notes}".strip()
        result["notes"] = notes
        return result

    if layer["layer"] in environment_limited_layers:
        # The planted artifact for this layer could not survive on this
        # machine (e.g. endpoint AV/EDR quarantines the EICAR test file
        # before Epyon's own scanner ever sees it) — this reflects a local
        # environment limitation, not a broken scanner, so it's reported
        # separately from a real pass/fail rather than counted as a failure.
        result["status"] = "environment_limited"
        result["notes"] = (
            "Planted artifact could not persist on this machine (likely "
            "removed by host antivirus/EDR before the scan ran). Run in "
            "CI or another environment without desktop AV to validate "
            "this layer end-to-end."
        )
        return result

    expect = layer.get("expect", {})
    min_expected = expect.get("min", 1)

    if expect.get("type") == "sbom_component_min":
        actual = _count_sbom_components(scan_dir)
    elif layer["name"] == "Helm Chart Build":
        actual = _count_helm_charts_built(scan_dir)
    elif layer["name"] == "Container Analysis":
        actual = _anchore_policy_gate_stopped(scan_dir)
    elif layer["name"] == "API Discovery":
        actual = _count_api_discovery_endpoints(scan_dir)
    elif layer["name"] == "Model Provenance & Threat Intelligence":
        actual = _count_model_provenance_typosquat(scan_dir)
    elif layer["name"] == "Model Card Compliance":
        actual = _count_model_card_findings(scan_dir)
    elif layer["name"] == "Inference Environment Security":
        actual = _count_inference_security_findings(scan_dir)
    elif layer["name"] == "Compromised Source Detection":
        actual = _count_compromised_source_findings(scan_dir)
    elif layer["tool"] in RAW_COUNTERS:
        actual = RAW_COUNTERS[layer["tool"]](scan_dir)
    else:
        result["status"] = "unknown_tool_mapping"
        result["actual"] = None
        return result

    result["expected_min"] = min_expected
    result["actual"] = actual
    result["status"] = "pass" if actual >= min_expected else "fail"
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-dir", required=True, type=Path)
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument(
        "--environment-limited-layer",
        type=float,
        action="append",
        default=[],
        help="Layer number(s) whose planted artifact couldn't persist on "
             "this machine (e.g. EICAR quarantined by host AV/EDR before "
             "the scan ran) — reported separately, not counted as a fail. "
             "May be repeated.",
    )
    ap.add_argument(
        "--only-layers",
        default=None,
        help="Comma-separated manifest layer numbers (e.g. '1,2,7,8,8.5') "
             "to restrict validation to. Any layer not in this list is "
             "reported with status 'skipped' rather than pass/fail/"
             "not_validated. Omit to validate every layer (default).",
    )
    args = ap.parse_args()
    environment_limited = set(args.environment_limited_layer)
    only_layers = None
    if args.only_layers:
        only_layers = {s.strip() for s in args.only_layers.split(",") if s.strip()}

    manifest = json.loads(args.manifest.read_text())

    layers = [
        evaluate_layer(layer, args.scan_dir, environment_limited, only_layers)
        for layer in manifest["layers"]
    ]

    validated = [l for l in layers if l["validated"]]
    passed = [l for l in validated if l["status"] == "pass"]
    failed = [l for l in validated if l["status"] == "fail"]
    env_limited = [l for l in validated if l["status"] == "environment_limited"]
    skipped = [l for l in layers if l["status"] == "skipped"]
    not_validated = [l for l in layers if not l["validated"] and l["status"] != "skipped"]

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_dir": str(args.scan_dir),
        "summary": {
            "total_layers": len(layers),
            "validated_layers": len(validated),
            "passed": len(passed),
            "failed": len(failed),
            "environment_limited": len(env_limited),
            "not_validated": len(not_validated),
            "skipped": len(skipped),
        },
        "layers": layers,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2))

    print(f"\nSelf-Assessment Results ({args.scan_dir.name})")
    print(f"  {len(passed)}/{len(validated) - len(env_limited)} validated layers passed "
          f"({len(not_validated)} best-effort/not validated, "
          f"{len(env_limited)} environment-limited, "
          f"{len(skipped)} skipped by selection)\n")
    for l in layers:
        if l["status"] == "skipped":
            print(f"  ⚪ SKIPPED L{l['layer']:<4} {l['name']} — not selected for this run")
        elif not l["validated"]:
            print(f"  ⚪ N/A   L{l['layer']:<4} {l['name']} — {l['notes']}")
        elif l["status"] == "environment_limited":
            print(f"  🚧 ENV   L{l['layer']:<4} {l['name']} — {l['notes']}")
        elif l["status"] == "pass":
            print(f"  ✅ PASS  L{l['layer']:<4} {l['name']} "
                  f"(found {l['actual']}, expected >= {l['expected_min']})")
        else:
            print(f"  ❌ FAIL  L{l['layer']:<4} {l['name']} "
                  f"(found {l['actual']}, expected >= {l['expected_min']})")

    if failed:
        print(f"\n{len(failed)} layer(s) FAILED self-assessment — a scanner may be silently broken.")
        return 1
    print("\nAll validated layers passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
