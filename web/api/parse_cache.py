"""Persistent memo for per-scan parse results.

Parsing a scan directory costs tens of milliseconds and the dashboard parses
~1,500 of them per request. Results are keyed by scan folder name and folder
mtime and stored in one JSON file so a server restart does not start cold.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("epyon.parse_cache")

# A scan that was touched recently may still be running; never persist it.
_SETTLE_SECONDS = 15 * 60
_MAX_ENTRIES = 6000

_lock = threading.Lock()
_entries: dict[str, list] = {}  # "kind:scan_name" -> [mtime_ns, value]
_dirty = False
_path: Path | None = None
_loaded = False


def configure(path: Path) -> None:
    """Set the cache file and load it. Safe to call more than once."""
    global _path, _loaded
    with _lock:
        _path = path
        _loaded = False
    _load()


def _load() -> None:
    global _loaded
    with _lock:
        if _loaded or _path is None:
            return
        _loaded = True
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                _entries.update(data)
        except FileNotFoundError:
            pass
        except Exception:
            log.warning("parse cache unreadable, starting empty", exc_info=True)


def get(kind: str, scan_dir: Path, compute: Callable[[], Any]) -> Any:
    """Return the cached result for scan_dir or compute and remember it."""
    global _dirty
    try:
        mtime_ns = scan_dir.stat().st_mtime_ns
    except OSError:
        return compute()
    key = f"{kind}:{scan_dir.name}"
    with _lock:
        hit = _entries.get(key)
        if hit and hit[0] == mtime_ns:
            return hit[1]
    value = compute()
    if time.time() - mtime_ns / 1e9 > _SETTLE_SECONDS:
        with _lock:
            if len(_entries) < _MAX_ENTRIES or key in _entries:
                _entries[key] = [mtime_ns, value]
                _dirty = True
    return value


def build_digest(scan_dir: Path) -> dict:
    """Compact per-scan summary for trend metrics: fingerprint -> severity and secret counts.

    Full findings run to hundreds of KB per scan, so only this digest is persisted.
    """
    import sys

    from . import parsers

    sf = parsers.parse_scan_findings(scan_dir)
    fps: dict[str, str] = {}
    secrets = verified = 0
    for sev in ("critical", "high", "medium", "low"):
        for f in sf.get(f"{sev}_findings", []):
            fp = f"{f.get('tool', '')}::{f.get('id', '')}::{f.get('package', '')}"
            fps[sys.intern(fp)] = sev
            if f.get("tool") == "TruffleHog":
                secrets += 1
                if f.get("severity") == "critical":
                    verified += 1
    return {"fps": fps, "secrets": secrets, "verified": verified}


def _warm_one(args: tuple[str, str]) -> tuple[str, int, dict, dict, list]:
    """Worker process: parse everything the dashboards need from one scan."""
    from . import parsers

    scan_dir, root = Path(args[0]), Path(args[1])
    mtime_ns = scan_dir.stat().st_mtime_ns
    return (
        scan_dir.name,
        mtime_ns,
        parsers.load_scan(scan_dir, root),
        build_digest(scan_dir),
        parsers.parse_suppressed_findings(scan_dir),
    )


def _is_cached(scan_dir: Path) -> bool:
    try:
        mtime_ns = scan_dir.stat().st_mtime_ns
    except OSError:
        return True
    with _lock:
        return all(
            (e := _entries.get(f"{k}:{scan_dir.name}")) and e[0] == mtime_ns
            for k in ("scan", "digest", "suppressed")
        )


def warm(scan_dirs: list[Path], root: Path, workers: int | None = None) -> int:
    """Fill the cache for scans not yet cached, in parallel worker processes.

    Returns the number of scans parsed. Scans modified in the last few minutes
    are skipped because they may still be written to.
    """
    global _dirty
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    now = time.time()
    todo = [
        d for d in scan_dirs
        if not _is_cached(d) and now - d.stat().st_mtime > _SETTLE_SECONDS
    ]
    if not todo:
        return 0
    workers = workers or max(1, min(os.cpu_count() or 1, 8))
    log.info("warming %d scans with %d workers", len(todo), workers)
    done = 0
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        for res in pool.map(_warm_one, [(str(d), str(root)) for d in todo], chunksize=4):
            name, mtime_ns, scan, digest, suppressed = res
            with _lock:
                _entries[f"scan:{name}"] = [mtime_ns, scan]
                _entries[f"digest:{name}"] = [mtime_ns, digest]
                _entries[f"suppressed:{name}"] = [mtime_ns, suppressed]
                _dirty = True
            done += 1
    flush()
    return done


def invalidate(scan_name: str | None = None) -> None:
    global _dirty
    with _lock:
        if scan_name is None:
            _entries.clear()
        else:
            for k in [k for k in _entries if k.split(":", 1)[1] == scan_name]:
                del _entries[k]
        _dirty = True


def flush() -> None:
    """Write the cache to disk if it changed. Never raises."""
    global _dirty
    with _lock:
        if not _dirty or _path is None:
            return
        try:
            payload = json.dumps(_entries, default=str)
        except Exception:
            log.warning("parse cache not serialisable", exc_info=True)
            return
        _dirty = False
        path = _path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".parse-cache-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, path)
    except Exception:
        log.warning("parse cache write failed", exc_info=True)
