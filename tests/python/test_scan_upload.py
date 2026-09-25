"""Tests for POST /api/scans/upload — scanning a local project uploaded as
a .zip, the supported path for scanning not-yet-pushed code once Epyon is
deployed to a remote server (a typed absolute path is otherwise resolved
against the server's own filesystem, not the browser's machine)."""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


@pytest.fixture
def upload_client(tmp_path, monkeypatch):
    from web.api import main as api_main
    from web.api import jobs as job_store

    monkeypatch.setattr(api_main, "EPYON_ROOT", tmp_path)
    monkeypatch.setattr(api_main, "_audit", lambda *a, **k: None)

    calls: list[dict] = []

    async def _fake_run_scan_job(job_id, target, scan_type, script_path, epyon_root, **kwargs):
        calls.append({"job_id": job_id, "target": target, "scan_type": scan_type, **kwargs})

    monkeypatch.setattr(job_store, "run_scan_job", _fake_run_scan_job)

    client = TestClient(api_main.app)
    client.upload_calls = calls  # type: ignore[attr-defined]
    return client


def test_upload_rejects_non_zip_file(upload_client):
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("project.tar", b"not a zip", "application/octet-stream")},
        data={"scan_type": "full"},
    )
    assert r.status_code == 400
    assert "zip" in r.json()["detail"].lower()


def test_upload_rejects_invalid_zip_contents(upload_client):
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("project.zip", b"not actually a zip", "application/zip")},
        data={"scan_type": "full"},
    )
    assert r.status_code == 400


def test_upload_rejects_zip_slip_path_traversal(upload_client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", b"escape attempt")
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("project.zip", buf.getvalue(), "application/zip")},
        data={"scan_type": "full"},
    )
    assert r.status_code == 400


def test_upload_rejects_invalid_scan_type(upload_client):
    payload = _zip_bytes({"README.md": b"hello"})
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("project.zip", payload, "application/zip")},
        data={"scan_type": "not-a-real-type"},
    )
    assert r.status_code == 400


def test_upload_extracts_and_queues_a_local_path_scan(upload_client, tmp_path):
    payload = _zip_bytes({"project/README.md": b"hello", "project/app.py": b"print(1)"})
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("myproject.zip", payload, "application/zip")},
        data={"scan_type": "full"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "queued"
    assert "job_id" in body

    assert len(upload_client.upload_calls) == 1
    call = upload_client.upload_calls[0]
    assert call["scan_type"] == "full"
    # The single top-level "project/" wrapper folder is unwrapped so the
    # scan targets the project itself, not the upload wrapper directory.
    assert call["target"].endswith("/project")
    extracted = tmp_path / "tmp"
    assert (extracted.exists())
    assert any(p.name == "README.md" for p in extracted.rglob("README.md"))


def test_upload_without_wrapper_folder_scans_extraction_root(upload_client):
    payload = _zip_bytes({"README.md": b"hello", "app.py": b"print(1)"})
    r = upload_client.post(
        "/api/scans/upload",
        files={"file": ("flat-project.zip", payload, "application/zip")},
        data={"scan_type": "quick"},
    )
    assert r.status_code == 202
    call = upload_client.upload_calls[0]
    assert "flat-project" in call["target"]
