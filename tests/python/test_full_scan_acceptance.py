import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(filename):
    spec = importlib.util.spec_from_file_location(
        filename, ROOT / "scripts" / "shell" / filename
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assess = load("run-stig-assessment.py")
build = load("import-build-archive.py")
CONTROL = {"vuln_id": "V-1"}
RESULT = {"vuln_id": "V-1", "status": "Open", "evidence": "src/auth.java lacks logout", "confidence": 90}


def test_structured_output_is_opt_in_and_disables_reasoning(monkeypatch):
    monkeypatch.delenv("EPYON_AI_STRUCTURED_OUTPUT", raising=False)
    assert assess._structured_kwargs({}) == {}
    monkeypatch.setenv("EPYON_AI_STRUCTURED_OUTPUT", "true")
    options = assess._structured_kwargs(assess._assessment_schema([CONTROL]))
    assert options["reasoning_effort"] == "none"
    assert options["response_format"]["type"] == "json_schema"
    schema = options["response_format"]["json_schema"]["schema"]
    assert schema["type"] == "object"
    assert schema["required"] == ["V-1"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["V-1"]["properties"]["vuln_id"]["enum"] == ["V-1"]


def test_keyed_batch_preserves_all_assessments_in_requested_order(monkeypatch):
    monkeypatch.setenv("EPYON_AI_STRUCTURED_OUTPUT", "true")
    controls = [{"vuln_id": f"V-{i}"} for i in range(5)]
    response = {c["vuln_id"]: {**RESULT, **c} for c in reversed(controls)}
    decoded = assess._decode_assessments(json.dumps(response), controls)
    assert [r["vuln_id"] for r in decoded] == [c["vuln_id"] for c in controls]
    assert all(r["evidence"] == RESULT["evidence"] for r in decoded)


def test_local_manual_context_retrieves_relevant_sections_of_large_documents(monkeypatch):
    monkeypatch.setattr(assess, "_LOCAL_MODEL", True)
    control = {**CONTROL, "check_content": "Review authentication logout"}
    content = "# Unrelated\n" + "ordinary text " * 12000 + "\n# Logout V-1\nRequire authentication and logout."
    selected = assess._manual_context_for_batch([("COMPLIANCE.md", content)], [control])
    assert "Require authentication and logout." in selected
    assert "COMPLIANCE.md" in selected
    assert len(selected.encode()) < 6200


def test_local_output_budget_leaves_room_for_input_without_changing_explicit_limit(monkeypatch):
    monkeypatch.setattr(assess, "_LOCAL_MODEL", True)
    monkeypatch.setenv("EPYON_AI_STRUCTURED_OUTPUT", "true")
    controls = [{**CONTROL, "vuln_id": f"V-{i}", "title": "Logout", "check_content": "Review logout", "fix_text": "Logout"}
                for i in range(5)]
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        results = {c["vuln_id"]: {**RESULT, "vuln_id": c["vuln_id"]} for c in controls}
        return SimpleNamespace(usage=None, choices=[
            SimpleNamespace(message=SimpleNamespace(content=json.dumps(results)), finish_reason="stop")
        ])

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.delenv("EPYON_AI_MAX_TOKENS", raising=False)
    assert len(assess.call_openai(client, "gemma4:12b", controls, "CODE")[0]) == 5
    assert calls[-1]["max_tokens"] == 5120
    monkeypatch.setenv("EPYON_AI_MAX_TOKENS", "1000")
    assess.call_openai(client, "gemma4:12b", controls, "CODE")
    assert calls[-1]["max_tokens"] == 1000
    assert "JSON array" not in calls[-1]["messages"][0]["content"]


@pytest.mark.parametrize("response", [
    '{}', '{"V-1":null}', '{"V-1":{},"V-2":{}}',
    json.dumps({"V-1": {**RESULT, "vuln_id": "V-2"}}),
    '{"V-1":' + json.dumps(RESULT) + ',"V-1":' + json.dumps(RESULT) + '}',
    json.dumps({"V-1": {**RESULT, "confidence": True}}),
    json.dumps([RESULT]),
])
def test_keyed_batch_rejects_missing_extra_mismatched_duplicate_or_invalid_controls(monkeypatch, response):
    monkeypatch.setenv("EPYON_AI_STRUCTURED_OUTPUT", "true")
    with pytest.raises(ValueError):
        assess._decode_assessments(response, [CONTROL])


@pytest.mark.parametrize("results", [
    {}, [], [RESULT, RESULT], [{**RESULT, "vuln_id": "V-2"}],
    [{**RESULT, "evidence": ""}], [{**RESULT, "confidence": True}],
    [{**RESULT, "confidence": 101}],
])
def test_rejects_incomplete_or_invalid_assessments(results):
    with pytest.raises(ValueError):
        assess._validate_batch(results, [CONTROL])


def test_valid_batch_preserves_evidence():
    assert assess._validate_batch([RESULT], [CONTROL]) == [RESULT]

def test_exhausted_stig_retries_preserve_diagnostics_and_fail(tmp_path, monkeypatch):
    control = {
        **CONTROL, "number": 1, "title": "Require logout", "severity": "medium",
        "check_content": "Review authentication.", "fix_text": "Implement logout.",
        "rule_id": "SV-1", "group_id": "V-1",
    }
    monkeypatch.setenv("EPYON_REQUIRE_COMPLETE", "true")
    monkeypatch.setenv("EPYON_STIG_FORMAT", "legacy")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=lambda **kwargs: object()))
    monkeypatch.setattr(assess, "check_stig_applicability", lambda *args: (True, "Applicable", 0, 0))

    def invalid(*args):
        raise ValueError("Empty model response")

    monkeypatch.setattr(assess, "call_openai", invalid)
    with pytest.raises(SystemExit, match="incomplete"):
        assess._assess_stig(
            stig_data={"controls": [control], "stig_name": "ASD"},
            stig_path="asd.xml", source_files=[], manual_docs=[], scan_dir=tmp_path,
            app_name="fixture", model="local", batch_size=1, delay=0, api_key="local",
            base_url="http://localhost:11434/v1", scan_date="2026-10-30",
            slug="asd", is_primary=True, target_dir=str(tmp_path),
        )
    output = json.loads((tmp_path / "stig-results-asd.json").read_text())
    assert output["assessment_complete"] is False
    assert output["failed_batches"] == [1]
    assert output["assessments"]["V-1"]["confidence"] == 0

def test_trivy_failure_is_nonzero_without_empty_success(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    trivy = tools / "trivy"
    trivy.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "*download-db-only*) exit 0;;\n"
        "version*) echo 'Version: test'; exit 0;;\n"
        "*) echo 'Maven dependency lookup HTTP 429' >&2; exit 1;;\n"
        "esac\n"
    )
    trivy.chmod(0o755)
    target = tmp_path / "target"
    target.mkdir()
    scan = tmp_path / "scan"
    result = subprocess.run([
        "bash", str(ROOT / "scripts/shell/run-trivy-scan.sh"),
        "--target", str(target), "--scan-mode", "filesystem",
    ], env=dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
                SCAN_DIR=str(scan), SCAN_ID="test", HOME=str(tmp_path)),
        text=True, capture_output=True)
    assert result.returncode != 0
    assert "Trivy target(s) failed" in result.stdout + result.stderr
    assert not list(scan.rglob("*results.json"))
    assert list(scan.rglob("*.failed-output"))


def make_archive(path, revision, corrupt=False):
    members = {}

    def blob(body):
        digest = hashlib.sha256(body).hexdigest()
        members["blobs/sha256/" + digest] = body
        return {"digest": "sha256:" + digest, "size": len(body)}

    config = blob(json.dumps({
        "config": {"Labels": {"org.opencontainers.image.revision": revision}}
    }).encode())
    layer = blob(b"container layer")
    manifest = blob(json.dumps({"config": config, "layers": [layer]}).encode())
    members["index.json"] = json.dumps({"manifests": [manifest]}).encode()
    if corrupt:
        members["blobs/sha256/" + layer["digest"].split(":")[1]] = b"tampered layer"
    with tarfile.open(path, "w") as archive:
        for name, data in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize("wrong_revision,corrupt", [(False, False), (True, False), (False, True)])
def test_external_archive_is_bound_to_source_and_content(tmp_path, wrong_revision, corrupt):
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", str(target)], check=True, capture_output=True)
    subprocess.run([
        "git", "-C", str(target), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--allow-empty", "-m", "fixture",
    ], check=True, capture_output=True)
    revision = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    archive = tmp_path / "image.tar"
    make_archive(archive, "wrong" if wrong_revision else revision, corrupt)
    output = tmp_path / "build"
    if wrong_revision or corrupt:
        with pytest.raises(ValueError):
            build.capture(archive, target, output)
        assert not (output / "build-summary.json").exists()
    else:
        build.capture(archive, target, output)
        summary = json.loads((output / "build-summary.json").read_text())
        assert summary["source_revision"] == revision
        assert summary["full_image"] == "oci-archive:" + str(archive)
        assert summary["digest"].startswith("sha256:")
