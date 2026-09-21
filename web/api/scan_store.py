"""
Scan ingestion, archival, and retention-sweep logic backing the SQLite scan
database (see ``db.py``).

Design:
  * Scan scripts are untouched — they keep writing raw tool output to
    ``scans/{app}_{ts}/`` exactly as before.
  * Whenever a scan folder is new or has changed (mtime bump), its parsed
    summary (``parsers.load_scan_complete``), STIG results, and score card
    are ingested into the ``scans`` table. This is cheap (a handful of JSON
    reads) compared to the raw tool output it summarises.
  * Once a scan folder is older than the retention window (default 90 days),
    it is compressed (tar + gzip) into the ``scan_archives`` BLOB table and
    removed from disk — reclaiming space while keeping the parsed summary
    (and the original raw bytes, on demand via ``restore_scan``) available
    indefinitely.
  * Endpoints that only need summary/trend data (stats, scan-history,
    applications, score cards, STIG history) keep working after archival
    because they read through ``_cached_load_scan``/``_cached_find_scan_dirs``
    in main.py, which fall back to the DB for archived scans. Endpoints that
    need the raw files (SBOM downloads, zip export, STIG md/cklb) return
    HTTP 410 with a hint to call the restore endpoint first.
"""
from __future__ import annotations

import io
import json
import logging
import shutil
import sqlite3
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import parsers

log = logging.getLogger("epyon.scan_store")

DEFAULT_RETENTION_DAYS = 90
DEFAULT_RESTORE_HOURS = 24


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir_mtime(scan_dir: Path) -> float:
    try:
        return scan_dir.stat().st_mtime
    except OSError:
        return 0.0


def _dir_size_bytes(scan_dir: Path) -> int:
    total = 0
    try:
        for p in scan_dir.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _read_json(path: Path) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _collect_stig_json(scan_dir: Path) -> dict | None:
    """Bundle every stig-results-*.json in the scan dir keyed by filename."""
    bundle: dict[str, Any] = {}
    for f in sorted(scan_dir.glob("stig-results-*.json")):
        data = _read_json(f)
        if data is not None:
            bundle[f.name] = data
    return bundle or None


def _scan_age_days(parsed_timestamp: str) -> float | None:
    if not parsed_timestamp:
        return None
    try:
        ts = datetime.fromisoformat(parsed_timestamp)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
    except ValueError:
        return None


class ArchivedScanRef:
    """Lightweight stand-in for a Path, representing a scan whose raw folder
    has been archived/pruned but whose summary lives on in the database.
    Only the small surface used by main.py's caching layer is implemented."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def exists(self) -> bool:
        return False

    def is_dir(self) -> bool:
        return False

    def __fspath__(self) -> str:  # pragma: no cover - defensive
        return self.name

    def __repr__(self) -> str:  # pragma: no cover
        return f"ArchivedScanRef({self.name!r})"


def ingest_scan_dir(conn: sqlite3.Connection, scan_dir: Path, epyon_root: Path) -> bool:
    """Parse a live scan folder and upsert its summary into the database.

    Returns True if the row was inserted/updated, False if it was already
    up to date (mtime unchanged) or the folder could not be parsed.
    """
    scan_id = scan_dir.name
    mtime = _dir_mtime(scan_dir)
    if mtime == 0.0:
        return False

    row = conn.execute(
        "SELECT source_mtime, archived FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if row and row["archived"]:
        return False  # archived scans are not re-ingested from disk
    if row and row["source_mtime"] >= mtime:
        return False  # unchanged since last ingest

    try:
        complete = parsers.load_scan_complete(scan_dir, epyon_root)
    except Exception:
        log.exception("failed to parse scan dir for ingestion: %s", scan_dir)
        return False

    stig_bundle = _collect_stig_json(scan_dir)
    scorecard = _read_json(scan_dir / "trl-assessment.json")
    now = _now_iso()

    conn.execute(
        """
        INSERT INTO scans (
            scan_id, app_name, user_name, scan_type, scan_timestamp, location,
            critical, high, medium, low,
            ingested_at, updated_at, source_mtime,
            complete_json, stig_json, scorecard_json, raw_size_bytes, archived
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(scan_id) DO UPDATE SET
            app_name       = excluded.app_name,
            user_name      = excluded.user_name,
            scan_type      = excluded.scan_type,
            scan_timestamp = excluded.scan_timestamp,
            location       = excluded.location,
            critical       = excluded.critical,
            high           = excluded.high,
            medium         = excluded.medium,
            low            = excluded.low,
            updated_at     = excluded.updated_at,
            source_mtime   = excluded.source_mtime,
            complete_json  = excluded.complete_json,
            stig_json      = excluded.stig_json,
            scorecard_json = excluded.scorecard_json
        """,
        (
            scan_id,
            complete.get("target", ""),
            complete.get("user", ""),
            complete.get("scan_type", ""),
            complete.get("timestamp", ""),
            complete.get("location", ""),
            complete.get("critical", 0),
            complete.get("high", 0),
            complete.get("medium", 0),
            complete.get("low", 0),
            now,
            now,
            mtime,
            json.dumps(complete),
            json.dumps(stig_bundle) if stig_bundle is not None else None,
            json.dumps(scorecard) if scorecard is not None else None,
            0,
        ),
    )
    conn.commit()
    return True


def archive_and_prune(conn: sqlite3.Connection, scan_dir: Path, epyon_root: Path) -> int:
    """Ensure the scan is ingested, then tar+gzip its folder into the DB and
    delete it from disk. Returns bytes freed on disk (0 on failure)."""
    scan_id = scan_dir.name
    ingest_scan_dir(conn, scan_dir, epyon_root)  # make sure summary is current

    raw_size = _dir_size_bytes(scan_dir)
    buf = io.BytesIO()
    try:
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
            tar.add(str(scan_dir), arcname=scan_id)
    except OSError:
        log.exception("failed to archive scan dir: %s", scan_dir)
        return 0

    blob = buf.getvalue()
    now = _now_iso()
    conn.execute(
        """
        INSERT INTO scan_archives (scan_id, archive_blob, compressed_size_bytes, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(scan_id) DO UPDATE SET
            archive_blob = excluded.archive_blob,
            compressed_size_bytes = excluded.compressed_size_bytes,
            created_at = excluded.created_at
        """,
        (scan_id, blob, len(blob), now),
    )
    conn.execute(
        """
        UPDATE scans SET archived = 1, archived_at = ?, raw_size_bytes = ?, restored_until = NULL
        WHERE scan_id = ?
        """,
        (now, raw_size, scan_id),
    )
    conn.commit()

    shutil.rmtree(scan_dir, ignore_errors=True)
    return raw_size


def restore_scan(
    conn: sqlite3.Connection, scan_id: str, epyon_root: Path, hours: int = DEFAULT_RESTORE_HOURS
) -> Path | None:
    """Extract an archived scan's raw folder back to disk for `hours`, after
    which the next retention sweep re-archives (and re-deletes) it."""
    row = conn.execute(
        "SELECT location FROM scans WHERE scan_id = ? AND archived = 1", (scan_id,)
    ).fetchone()
    if not row:
        return None
    blob_row = conn.execute(
        "SELECT archive_blob FROM scan_archives WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if not blob_row:
        return None

    dest_root = (epyon_root / row["location"]).resolve()
    try:
        dest_root.resolve().relative_to(epyon_root.resolve())
    except ValueError:
        return None
    dest_root.mkdir(parents=True, exist_ok=True)
    dest_dir = dest_root / scan_id
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)

    with tarfile.open(fileobj=io.BytesIO(blob_row["archive_blob"]), mode="r:gz") as tar:
        try:
            tar.extractall(str(dest_root), filter="data")  # PEP 706 (Python 3.12+)
        except TypeError:
            tar.extractall(str(dest_root))  # older Python without the filter kwarg

    restored_until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    conn.execute(
        "UPDATE scans SET archived = 0, restored_until = ? WHERE scan_id = ?",
        (restored_until, scan_id),
    )
    conn.commit()
    return dest_dir


def get_scan_summary(conn: sqlite3.Connection, scan_id: str) -> dict | None:
    row = conn.execute(
        "SELECT complete_json, archived, archived_at, raw_size_bytes FROM scans WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    if not row:
        return None
    data = json.loads(row["complete_json"])
    data["archived"] = bool(row["archived"])
    data["archived_at"] = row["archived_at"]
    return data


def is_archived(conn: sqlite3.Connection, scan_id: str) -> bool:
    row = conn.execute("SELECT archived FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return bool(row and row["archived"])


def list_archived_only_ids(conn: sqlite3.Connection, live_ids: set[str]) -> list[str]:
    """Scan ids that exist in the DB (archived) but not among live folders."""
    rows = conn.execute("SELECT scan_id FROM scans WHERE archived = 1").fetchall()
    return [r["scan_id"] for r in rows if r["scan_id"] not in live_ids]


def run_retention_sweep(
    conn: sqlite3.Connection,
    epyon_root: Path,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    dry_run: bool = False,
) -> dict:
    """Ingest any new/changed scan folders, then archive+prune folders older
    than `retention_days`. Safe to call repeatedly (idempotent)."""
    started = _now_iso()
    ingested = archived = 0
    bytes_freed = 0
    errors: list[str] = []

    live_dirs = parsers.find_scan_dirs(epyon_root, days=0)
    for scan_dir in live_dirs:
        try:
            if ingest_scan_dir(conn, scan_dir, epyon_root):
                ingested += 1
        except Exception as exc:  # noqa: BLE001 - never let one bad scan stop the sweep
            errors.append(f"ingest {scan_dir.name}: {exc}")

    for scan_dir in live_dirs:
        parsed = parsers.parse_dir_name(scan_dir.name)
        age = _scan_age_days(parsed.get("timestamp", ""))
        if age is None or age < retention_days:
            continue
        # Respect an active restore grace period.
        row = conn.execute(
            "SELECT restored_until FROM scans WHERE scan_id = ?", (scan_dir.name,)
        ).fetchone()
        if row and row["restored_until"]:
            try:
                if datetime.fromisoformat(row["restored_until"]) > datetime.now(timezone.utc):
                    continue
            except ValueError:
                pass
        if dry_run:
            archived += 1
            bytes_freed += _dir_size_bytes(scan_dir)
            continue
        try:
            freed = archive_and_prune(conn, scan_dir, epyon_root)
            if freed:
                archived += 1
                bytes_freed += freed
        except Exception as exc:  # noqa: BLE001
            errors.append(f"archive {scan_dir.name}: {exc}")

    conn.execute(
        """
        INSERT INTO retention_runs (started_at, finished_at, ingested_count, archived_count, bytes_freed, errors_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (started, _now_iso(), ingested, archived, bytes_freed, json.dumps(errors) if errors else None),
    )
    conn.commit()

    return {
        "started_at": started,
        "finished_at": _now_iso(),
        "ingested": ingested,
        "archived": archived,
        "bytes_freed": bytes_freed,
        "errors": errors,
    }
