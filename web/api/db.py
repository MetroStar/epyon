"""
SQLite-backed persistent store for scan metadata/findings/STIG history.

Raw scan tool output continues to be written to ``scans/{app}_{ts}/`` by the
existing shell/Python scan scripts — nothing about that pipeline changes.
This module gives Epyon a durable, queryable database that survives even
after a raw scan folder has been archived and removed from disk by the
retention sweep (see ``scan_store.py``), so historical trend charts, STIG
history, and score cards keep working indefinitely while disk usage under
``scans/`` is bounded to the retention window (default 90 days).
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    app_name        TEXT NOT NULL,
    user_name       TEXT NOT NULL DEFAULT '',
    scan_type       TEXT NOT NULL DEFAULT '',
    scan_timestamp  TEXT NOT NULL DEFAULT '',
    location        TEXT NOT NULL DEFAULT '',
    critical        INTEGER NOT NULL DEFAULT 0,
    high            INTEGER NOT NULL DEFAULT 0,
    medium          INTEGER NOT NULL DEFAULT 0,
    low             INTEGER NOT NULL DEFAULT 0,
    ingested_at     TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    source_mtime    REAL NOT NULL DEFAULT 0,
    complete_json   TEXT NOT NULL,
    stig_json       TEXT,
    scorecard_json  TEXT,
    raw_size_bytes  INTEGER NOT NULL DEFAULT 0,
    archived        INTEGER NOT NULL DEFAULT 0,
    archived_at     TEXT,
    restored_until  TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_app       ON scans(app_name);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_archived  ON scans(archived);

CREATE TABLE IF NOT EXISTS scan_archives (
    scan_id               TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    archive_blob          BLOB NOT NULL,
    compressed_size_bytes INTEGER NOT NULL,
    created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retention_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    ingested_count INTEGER NOT NULL DEFAULT 0,
    archived_count INTEGER NOT NULL DEFAULT 0,
    bytes_freed    INTEGER NOT NULL DEFAULT 0,
    errors_json    TEXT
);
"""

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def default_db_path(epyon_root: Path) -> Path:
    return (epyon_root / "web" / "data" / "epyon.db").resolve()


def connect(db_path: Path) -> sqlite3.Connection:
    """Open (and if needed, create/migrate) the scan database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    with _lock:
        conn.executescript(_SCHEMA)
        conn.commit()
    return conn


def get_conn(epyon_root: Path) -> sqlite3.Connection:
    """Process-wide singleton connection (sqlite3 objects are safe to share
    across threads when check_same_thread=False and callers serialize writes)."""
    global _conn
    if _conn is None:
        _conn = connect(default_db_path(epyon_root))
    return _conn
