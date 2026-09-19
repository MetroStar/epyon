#!/usr/bin/env python3
"""
scan-db-tool.py

Admin CLI for the SQLite scan database introduced to bound disk usage under
scans/ (see web/api/db.py and web/api/scan_store.py). The 55+ scan-tool
scripts are unchanged — they still write raw output to scans/{app}_{ts}/.
This tool ingests parsed summaries into the DB and (optionally) enforces the
retention window by compressing+removing raw folders older than N days.

Subcommands:
    backfill   One-time ingestion of every existing scans/ folder into the DB.
               Safe to re-run (idempotent, skips unchanged folders).
    sweep      Ingest new/changed folders, then archive+prune folders older
               than --retention-days (default 90). This is also run
               automatically once a day by the FastAPI backend; use this for
               manual/cron-driven operation or to run it immediately.
    status     Print retention configuration and recent sweep history.
    restore    Temporarily re-extract an archived scan's raw folder to disk.

Usage:
    scan-db-tool.py backfill [--apply-retention] [--retention-days 90]
    scan-db-tool.py sweep [--retention-days 90] [--dry-run]
    scan-db-tool.py status
    scan-db-tool.py restore --scan-id <scan_id> [--hours 24]

Exit codes:
    0 - Success
    1 - Error
"""
import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from web.api import db as scan_db  # noqa: E402
from web.api import parsers  # noqa: E402
from web.api import scan_store  # noqa: E402


def cmd_backfill(args: argparse.Namespace) -> int:
    conn = scan_db.connect(scan_db.default_db_path(_REPO_ROOT))
    dirs = parsers.find_scan_dirs(_REPO_ROOT, days=0)
    ingested = 0
    for scan_dir in dirs:
        try:
            if scan_store.ingest_scan_dir(conn, scan_dir, _REPO_ROOT):
                ingested += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  ! failed to ingest {scan_dir.name}: {exc}", file=sys.stderr)
    print(f"Backfilled {ingested}/{len(dirs)} scan folders into {scan_db.default_db_path(_REPO_ROOT)}")

    if args.apply_retention:
        result = scan_store.run_retention_sweep(conn, _REPO_ROOT, args.retention_days)
        print(
            f"Retention applied: archived={result['archived']} "
            f"bytes_freed={result['bytes_freed']:,} errors={len(result['errors'])}"
        )
        for err in result["errors"]:
            print(f"  ! {err}", file=sys.stderr)
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    conn = scan_db.connect(scan_db.default_db_path(_REPO_ROOT))
    result = scan_store.run_retention_sweep(
        conn, _REPO_ROOT, args.retention_days, dry_run=args.dry_run
    )
    print(json.dumps(result, indent=2))
    return 1 if result["errors"] else 0


def cmd_status(_args: argparse.Namespace) -> int:
    conn = scan_db.connect(scan_db.default_db_path(_REPO_ROOT))
    row = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(raw_size_bytes), 0) AS bytes FROM scans WHERE archived = 1"
    ).fetchone()
    total = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
    runs = conn.execute(
        "SELECT started_at, finished_at, ingested_count, archived_count, bytes_freed "
        "FROM retention_runs ORDER BY id DESC LIMIT 10"
    ).fetchall()
    print(f"DB path:          {scan_db.default_db_path(_REPO_ROOT)}")
    print(f"Total scans:      {total}")
    print(f"Archived scans:   {row['n']}")
    print(f"Bytes reclaimed:  {row['bytes']:,}")
    print("Recent sweeps:")
    for r in runs:
        print(
            f"  {r['started_at']}  ingested={r['ingested_count']} "
            f"archived={r['archived_count']} bytes_freed={r['bytes_freed']:,}"
        )
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    conn = scan_db.connect(scan_db.default_db_path(_REPO_ROOT))
    dest = scan_store.restore_scan(conn, args.scan_id, _REPO_ROOT, hours=args.hours)
    if dest is None:
        print(f"Scan '{args.scan_id}' not found in archive", file=sys.stderr)
        return 1
    print(f"Restored to {dest} for {args.hours}h")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_backfill = sub.add_parser("backfill", help="Ingest all existing scans/ folders into the DB")
    p_backfill.add_argument("--apply-retention", action="store_true",
                             help="Also archive+prune folders already older than --retention-days")
    p_backfill.add_argument("--retention-days", type=int, default=scan_store.DEFAULT_RETENTION_DAYS)
    p_backfill.set_defaults(func=cmd_backfill)

    p_sweep = sub.add_parser("sweep", help="Ingest + archive/prune folders older than the retention window")
    p_sweep.add_argument("--retention-days", type=int, default=scan_store.DEFAULT_RETENTION_DAYS)
    p_sweep.add_argument("--dry-run", action="store_true", help="Report what would be archived without doing it")
    p_sweep.set_defaults(func=cmd_sweep)

    p_status = sub.add_parser("status", help="Show retention configuration and sweep history")
    p_status.set_defaults(func=cmd_status)

    p_restore = sub.add_parser("restore", help="Temporarily restore an archived scan's raw folder")
    p_restore.add_argument("--scan-id", required=True)
    p_restore.add_argument("--hours", type=int, default=scan_store.DEFAULT_RESTORE_HOURS)
    p_restore.set_defaults(func=cmd_restore)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
