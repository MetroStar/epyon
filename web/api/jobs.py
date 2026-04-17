"""
In-memory async job queue for running Epyon security scans.
"""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

JOB_TIMEOUT_SECONDS = 7200  # 2 hours
OUTPUT_BUFFER_MAX   = 1000

# Global stores
jobs:  dict[str, dict[str, Any]] = {}
procs: dict[str, asyncio.subprocess.Process] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_line(line: str) -> str:
    return _ANSI_RE.sub("", line).rstrip()


def _append_line(job: dict, line: str) -> None:
    clean = _clean_line(line)
    if not clean:
        return
    job["output"].append(clean)
    if len(job["output"]) > OUTPUT_BUFFER_MAX:
        job["output"] = job["output"][-OUTPUT_BUFFER_MAX:]


async def _read_stream(stream: asyncio.StreamReader, job: dict) -> None:
    while True:
        try:
            line = await stream.readline()
        except Exception:
            break
        if not line:
            break
        _append_line(job, line.decode("utf-8", errors="replace").rstrip("\n\r"))


async def run_scan_job(
    job_id: str,
    target: str,
    scan_type: str,
    script_path: Path,
    epyon_root: Path,
) -> None:
    job = jobs[job_id]
    job["status"] = "running"

    env = {**os.environ,
           "CI":               "true",
           "NONINTERACTIVE":   "1",
           "DEBIAN_FRONTEND":  "noninteractive",
           "TERM":             "dumb",
           "SKIP_GARAK":       "true"}

    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", str(script_path), target, scan_type,
            cwd=str(epyon_root),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        procs[job_id] = proc

        async def _timeout_kill() -> None:
            await asyncio.sleep(JOB_TIMEOUT_SECONDS)
            if job["status"] == "running":
                _append_line(job, f"[epyon] Job timed out after {JOB_TIMEOUT_SECONDS // 60} minutes")
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

        timeout_task = asyncio.create_task(_timeout_kill())

        await asyncio.gather(
            _read_stream(proc.stdout, job),
            _read_stream(proc.stderr, job),
        )

        return_code = await proc.wait()
        timeout_task.cancel()

        procs.pop(job_id, None)
        if job["status"] == "running":
            job["exit_code"]    = return_code
            job["status"]       = "completed" if return_code == 0 else "failed"
            job["completed_at"] = _now()

    except Exception as exc:
        procs.pop(job_id, None)
        job["status"]       = "error"
        job["error"]        = str(exc)
        job["completed_at"] = _now()


def create_job(job_id: str, target: str, scan_type: str) -> dict:
    job: dict = {
        "job_id":       job_id,
        "target":       target,
        "scan_type":    scan_type,
        "status":       "queued",
        "started_at":   _now(),
        "completed_at": None,
        "exit_code":    None,
        "output":       [],
        "error":        None,
    }
    jobs[job_id] = job
    return job


def cancel_job(job_id: str) -> bool:
    job = jobs.get(job_id)
    if not job:
        return False
    if job["status"] not in ("queued", "running"):
        return False
    proc = procs.get(job_id)
    if proc:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    job["status"]       = "cancelled"
    job["completed_at"] = _now()
    job["output"].append("[epyon] Job cancelled by user")
    return True
