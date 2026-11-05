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
    assert options["response_format"]["json_schema"]["schema"]["minItems"] == 1


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
            build.capture(archive, target, output, tmp_path / "layout")
        assert not (output / "build-summary.json").exists()
        assert not (tmp_path / "layout").exists()
    else:
        layout = tmp_path / "layout"
        build.capture(archive, target, output, layout)
        summary = json.loads((output / "build-summary.json").read_text())
        assert summary["source_revision"] == revision
        assert summary["full_image"] == "oci-archive:" + str(archive)
        assert summary["digest"].startswith("sha256:")
        assert json.loads((layout / "oci-layout").read_text())["imageLayoutVersion"] == "1.0.0"
        assert len(list((layout / "blobs/sha256").iterdir())) == 3
        with pytest.raises(ValueError, match="must be empty"):
            build.capture(archive, target, tmp_path / "other-build", layout)


@pytest.mark.parametrize("scan_exit,temp_failure", [(0, False), (1, False), (0, True)])
def test_trivy_oci_uses_verified_directory_and_preserves_failure(tmp_path, scan_exit, temp_failure):
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", str(target)], check=True, capture_output=True)
    subprocess.run([
        "git", "-C", str(target), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "fixture",
    ], check=True, capture_output=True)
    revision = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    archive = tmp_path / "image.tar"
    make_archive(archive, revision)
    tools = tmp_path / "bin"
    tools.mkdir()
    trivy = tools / "trivy"
    trivy.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "*download-db-only*) exit 0;;\n"
        "version*) echo 'Version: test'; exit 0;;\n"
        "esac\n"
        "[ \"$1\" = image ] && [ \"$2\" = --input ] && "
        "[ -f \"$3/index.json\" ] && [ -f \"$3/oci-layout\" ] || exit 2\n"
        "printf '{\"Results\":[]}'\n"
        "exit \"$TRIVY_TEST_EXIT\"\n"
    )
    trivy.chmod(0o755)
    scan = tmp_path / "scan"
    env = dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
               SCAN_DIR=str(scan), SCAN_ID="test", HOME=str(tmp_path),
               TMPDIR=str(tmp_path / "missing" if temp_failure else tmp_path),
               PRIMARY_BASELINE_IMAGE="oci-archive:" + str(archive),
               TRIVY_TEST_EXIT=str(scan_exit))
    env.pop("TARGET_DIR", None)
    result = subprocess.run([
        "bash", str(ROOT / "scripts/shell/run-trivy-scan.sh"),
        "--target", str(target), "--scan-mode", "base",
    ], env=env, text=True, capture_output=True)
    assert (result.returncode == 0) == (scan_exit == 0 and not temp_failure), result.stdout + result.stderr
    assert bool(list(scan.rglob("*results.json"))) == (scan_exit == 0 and not temp_failure)
    assert bool(list(scan.rglob("*.failed-output"))) == (scan_exit != 0)
    if temp_failure:
        assert "Cannot create a temporary OCI layout" in result.stderr
    assert not list(tmp_path.glob("quartz-trivy-oci.*"))


@pytest.mark.parametrize("tool", ["modelcard", "inference-security"])
def test_report_only_preserves_findings_and_standalone_gate(tmp_path, tool):
    target = tmp_path / "source"
    target.mkdir()
    (target / "README.md").write_text("# Application\n")
    (target / "Dockerfile").write_text("FROM scratch\nUSER root\n")
    script = "run-modelcard-check.sh" if tool == "modelcard" else "run-inference-security-scan.sh"
    reports = []
    for report_only in (False, True):
        scan = tmp_path / str(report_only)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/shell" / script)] + (["--report-only"] if report_only else []),
            env=dict(os.environ, TARGET_DIR=str(target), SCAN_DIR=str(scan), SCAN_ID="fixture"),
            text=True, capture_output=True,
        )
        assert result.returncode == (0 if report_only else 1), result.stdout + result.stderr
        report = json.loads((scan / tool / f"{tool}-results.json").read_text())
        assert report["findings"]
        reports.append(report["findings"])
    assert reports[0] == reports[1]


@pytest.mark.parametrize("tool", ["modelcard", "inference-security"])
def test_report_only_still_fails_python_execution_errors(tmp_path, tool):
    target = tmp_path / "source"
    target.mkdir()
    (target / "README.md").write_text("# Application\n")
    (target / "Dockerfile").write_text("FROM scratch\nUSER root\n")
    tools = tmp_path / "bin"
    tools.mkdir()
    python = tools / "python3"
    python.write_text("#!/bin/sh\necho 'controlled Python execution failure' >&2\nexit 1\n")
    python.chmod(0o755)
    script = "run-modelcard-check.sh" if tool == "modelcard" else "run-inference-security-scan.sh"
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/shell" / script), "--report-only"],
        env=dict(os.environ, TARGET_DIR=str(target), SCAN_DIR=str(tmp_path / "scan"),
                 SCAN_ID="fixture", PATH=str(tools) + ":" + os.environ["PATH"]),
        text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "controlled Python execution failure" in result.stdout + result.stderr
