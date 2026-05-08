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

from . import openai_summary

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
    hf_type: str | None = None,
) -> None:
    job = jobs[job_id]
    job["status"] = "running"

    # ── Derive target name and target dir ────────────────────────
    _git_re = re.compile(r"(?:https?://|git@)[^\s]+?/([^/\s]+?)(?:\.git)?$")
    _hf_re  = re.compile(r"huggingface\.co/(?:spaces/|datasets/)?([^/\s]+/[^/\s]+?)(?:\.git)?$")

    hf_match = _hf_re.search(target)
    git_match = _git_re.search(target)

    if hf_match:
        # Use last component (model-name) as display name
        target_name = hf_match.group(1).split("/")[-1]
    elif git_match:
        target_name = git_match.group(1)
    else:
        target_name = Path(target).name or "target"

    is_hf_url = bool(hf_match) or scan_type == "huggingface"

    # For local paths use as-is; for git URLs the script will clone
    if target.startswith("/") or target.startswith("./") or target.startswith("../"):
        target_dir = str(Path(target).resolve())
        is_remote  = False
    else:
        # Git/HF URL — will be cloned into a temp dir
        target_dir = str(epyon_root / "tmp" / f"clone-{job_id}")
        is_remote  = True

    timestamp    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_name    = f"{target_name}_{timestamp}"
    scan_dir     = epyon_root / "scans" / scan_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    # ── Write /tmp/epyon-env ─────────────────────────────────────
    epyon_version = "unknown"
    version_file = epyon_root / "VERSION"
    if version_file.exists():
        epyon_version = version_file.read_text().strip()

    env_lines = [
        f"TARGET_DIR={target_dir}",
        f"SCAN_MODE={scan_type}",
        f"TARGET_NAME={target_name}",
        f"GITHUB_ACTOR=web-ui",
        f"SUBDIR=",
        f"EPYON_VERSION={epyon_version}",
        f"GARAK_TARGET_TYPE=openai",
        f"GARAK_TARGET_NAME=gpt-4o-mini",
        f"GARAK_PROBES=promptinject,dan,knownbadsignatures,encoding,continuation",
        "SKIP_SBOM=false",
        "SKIP_TRUFFLEHOG=false",
        "SKIP_SONAR=true",
        "SKIP_CLAMAV=false",
        "SKIP_HELM=false",
        "SKIP_CHECKOV=false",
        "SKIP_TRIVY=false",
        "SKIP_GRYPE=false",
        "SKIP_XEOL=false",
        "SKIP_ANCHORE=false",
        "SKIP_API_DISCOVERY=false",
        "SKIP_STIG=false",
        f"SCAN_DIR={scan_dir}",
        f"SCAN_NAME={scan_name}",
        f"SCAN_ID={scan_name}",
    ]
    # HuggingFace-specific env vars
    if scan_type == "huggingface":
        _hf_type = hf_type or "model"
        env_lines.append(f"HF_REPO_TYPE={_hf_type}")
        env_lines.append("RUN_PICKLESCAN=true")
        env_lines.append("RUN_MODELCARD=true")
        # For model repos, enable Garak with huggingface target type
        if _hf_type == "model":
            env_lines.append("GARAK_TARGET_TYPE=huggingface")
    # Propagate API keys — prefer ai-config.json, fall back to environment
    openai_key = openai_summary.get_api_key() or os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        env_lines.append(f"OPENAI_API_KEY={openai_key}")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        env_lines.append(f"ANTHROPIC_API_KEY={anthropic_key}")

    Path("/tmp/epyon-env").write_text("\n".join(env_lines) + "\n")
    _append_line(job, f"[web-ui] Initialized scan: {scan_name}")

    # ── Write scan-metadata.json so the parser can read scan_type ────────────
    import json as _json
    scan_meta = {
        "scan_type":        scan_type,
        "target_name":      target_name,
        "scan_timestamp":   datetime.now().isoformat(),
        "target_directory": target_dir,
        "epyon_version":    epyon_version,
        "triggered_by":     "web-ui",
    }
    (scan_dir / "scan-metadata.json").write_text(_json.dumps(scan_meta, indent=2))

    # ── Clone git/HF target if needed ───────────────────────────
    if is_remote:
        _append_line(job, f"[web-ui] Cloning {target} …")
        Path(target_dir).mkdir(parents=True, exist_ok=True)

        if is_hf_url:
            # HuggingFace repos can have huge LFS weights — skip them
            clone_env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
            clone_cmd = ["git", "clone", "--depth=1", "--filter=blob:limit=10m", target, target_dir]
        else:
            clone_env = dict(os.environ)
            clone_cmd = ["git", "clone", "--depth=1", target, target_dir]

        clone_proc = await asyncio.create_subprocess_exec(
            *clone_cmd,
            env=clone_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        clone_out, clone_err = await clone_proc.communicate()
        for line in (clone_out + clone_err).decode("utf-8", errors="replace").splitlines():
            if line.strip():
                _append_line(job, f"[git] {line}")
        if clone_proc.returncode != 0:
            job["status"]       = "failed"
            job["exit_code"]    = clone_proc.returncode
            job["completed_at"] = _now()
            return

    env = {**os.environ,
           "CI":               "true",
           "NONINTERACTIVE":   "1",
           "DEBIAN_FRONTEND":  "noninteractive",
           "TERM":             "dumb",
           "SKIP_GARAK":       "true",
           "TARGET_DIR":       target_dir,
           "SCAN_DIR":         str(scan_dir),
           "SCAN_MODE":        scan_type,
           "TARGET_NAME":      target_name}
    if openai_key:
        env["OPENAI_API_KEY"] = openai_key

    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", str(script_path),
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


def cancel_job(job_id: str) -> None:
    job = jobs.get(job_id)
    if not job:
        return
    proc = procs.get(job_id)
    if proc:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        procs.pop(job_id, None)
    job["status"]       = "cancelled"
    job["completed_at"] = _now()
