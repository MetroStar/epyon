"""Tests for the SQLite scan store (ingestion, archival, retention, restore)."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def scan_db_mod():
    import importlib.util
    import sys

    def _load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    # parsers must be importable as "web.api.parsers" for scan_store's relative import
    if "web" not in sys.modules:
        sys.path.insert(0, str(REPO_ROOT))
    from web.api import db as db_mod
    from web.api import scan_store as store_mod

    return db_mod, store_mod


@pytest.fixture
def sandbox(tmp_path, golden_scan_dir):
    """An isolated fake epyon_root with one copy of the golden scan under scans/."""
    root = tmp_path / "epyon_root"
    scans_dir = root / "scans"
    scans_dir.mkdir(parents=True)
    dest = scans_dir / golden_scan_dir.name
    shutil.copytree(golden_scan_dir, dest)
    return root, dest


def test_ingest_scan_dir_creates_row(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")

    assert store_mod.ingest_scan_dir(conn, scan_dir, root) is True

    row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_dir.name,)).fetchone()
    assert row is not None
    assert row["app_name"] == "goldenapp"
    assert row["archived"] == 0
    complete = json.loads(row["complete_json"])
    assert complete["scan_id"] == scan_dir.name


def test_ingest_is_idempotent_without_changes(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")

    assert store_mod.ingest_scan_dir(conn, scan_dir, root) is True
    # Second call with unchanged mtime should be a no-op.
    assert store_mod.ingest_scan_dir(conn, scan_dir, root) is False


def test_archive_and_prune_removes_folder_and_stores_blob(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")

    freed = store_mod.archive_and_prune(conn, scan_dir, root)
    assert freed > 0
    assert not scan_dir.exists()

    row = conn.execute("SELECT archived FROM scans WHERE scan_id = ?", (scan_dir.name,)).fetchone()
    assert row["archived"] == 1
    blob = conn.execute(
        "SELECT compressed_size_bytes FROM scan_archives WHERE scan_id = ?", (scan_dir.name,)
    ).fetchone()
    assert blob["compressed_size_bytes"] > 0
    # Compressed archive should be smaller than the raw folder it replaced.
    assert blob["compressed_size_bytes"] < freed


def test_restore_scan_extracts_files_back_to_disk(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")
    scan_id = scan_dir.name

    store_mod.archive_and_prune(conn, scan_dir, root)
    assert not scan_dir.exists()

    dest = store_mod.restore_scan(conn, scan_id, root, hours=1)
    assert dest is not None
    assert dest.exists()
    assert (dest / "scan-metadata.json").exists()

    row = conn.execute("SELECT archived, restored_until FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    assert row["archived"] == 0
    assert row["restored_until"] is not None


def test_get_scan_summary_reflects_archived_state(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")
    scan_id = scan_dir.name

    store_mod.ingest_scan_dir(conn, scan_dir, root)
    summary = store_mod.get_scan_summary(conn, scan_id)
    assert summary["archived"] is False

    store_mod.archive_and_prune(conn, scan_dir, root)
    summary = store_mod.get_scan_summary(conn, scan_id)
    assert summary["archived"] is True
    assert summary["scan_id"] == scan_id


def test_run_retention_sweep_archives_only_old_scans(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")

    # golden_scan_dir's name encodes a recent timestamp -> should NOT be archived
    # at the default 90-day retention window.
    result = store_mod.run_retention_sweep(conn, root, retention_days=90)
    assert result["ingested"] == 1
    assert result["archived"] == 0
    assert scan_dir.exists()

    # A retention window of 0 days means "anything is old enough" -> archived.
    result = store_mod.run_retention_sweep(conn, root, retention_days=0)
    assert result["archived"] == 1
    assert not scan_dir.exists()


def test_run_retention_sweep_respects_restore_grace_period(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")
    scan_id = scan_dir.name

    store_mod.run_retention_sweep(conn, root, retention_days=0)
    assert not scan_dir.exists()

    store_mod.restore_scan(conn, scan_id, root, hours=24)
    assert scan_dir.exists()

    # Even with a 0-day retention window, a scan restored moments ago should
    # not be immediately re-archived.
    result = store_mod.run_retention_sweep(conn, root, retention_days=0)
    assert result["archived"] == 0
    assert scan_dir.exists()


def test_is_archived_and_delete_cascade(scan_db_mod, sandbox):
    db_mod, store_mod = scan_db_mod
    root, scan_dir = sandbox
    conn = db_mod.connect(root / "epyon.db")
    scan_id = scan_dir.name

    store_mod.archive_and_prune(conn, scan_dir, root)
    assert store_mod.is_archived(conn, scan_id) is True

    conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()
    archive_row = conn.execute(
        "SELECT * FROM scan_archives WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    assert archive_row is None  # ON DELETE CASCADE via foreign key
