"""
In-memory async job queue for running Epyon security scans.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import openai_summary
from . import github_config

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

JOB_TIMEOUT_SECONDS = 7200  # 2 hours
OUTPUT_BUFFER_MAX   = 10000

# Directory names excluded from file_statistics counts — mirrors the `find`
# exclusions in run-target-security-scan.sh / run-epyon-scan-ci.sh so all
# three scan-trigger paths (CLI, CI, Web UI) produce a comparable total_files
# signal for /api/metrics/scan-integrity.
_FILE_STATS_EXCLUDE_DIRS = {
    "node_modules", ".git", "venv", "__pycache__", "dist", "build",
    "vendor", ".next", ".venv",
}


def _compute_file_statistics(target_dir: str) -> dict:
    """Count source files under target_dir the same way the CLI/CI
    orchestrators do, so a Web UI-triggered scan's scan-metadata.json carries
    a real file_statistics.total_files for the Scan Integrity Check instead
    of permanently reading "unknown"."""
    stats = {
        "total_files": 0, "javascript_typescript": 0, "python": 0,
        "yaml_yml": 0, "json": 0, "terraform": 0, "dockerfiles": 0,
        "shell_scripts": 0,
    }
    root = Path(target_dir)
    if not root.is_dir():
        return stats
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _FILE_STATS_EXCLUDE_DIRS & set(path.relative_to(root).parts[:-1]):
            continue
        stats["total_files"] += 1
        name = path.name
        suffix = path.suffix.lower()
        if suffix in (".js", ".jsx", ".ts", ".tsx"):
            stats["javascript_typescript"] += 1
        elif suffix == ".py":
            stats["python"] += 1
        elif suffix in (".yaml", ".yml"):
            stats["yaml_yml"] += 1
        elif suffix == ".json":
            stats["json"] += 1
        elif suffix == ".tf":
            stats["terraform"] += 1
        elif "Dockerfile" in name:
            stats["dockerfiles"] += 1
        elif suffix in (".sh", ".bash"):
            stats["shell_scripts"] += 1
    return stats

# Maps each togglable scan layer number to the SKIP_<TOOL> environment
# variable run-epyon-scan-ci.sh checks to decide whether to run it, letting
# the Run Scan page's layer picker override scan-type defaults. Layer 3
# (Sonar, gated on SONAR_TOKEN), Layer 12 (Garak) and Layer 13 (STIG) are
# deliberately excluded — they already have their own dedicated opt-in
# controls — and Layer 20 (ML Runtime) is opt-in-only and not yet exposed
# as a picker option. Mirrors (minus 13) _SELF_ASSESSMENT_VALID_LAYERS in
# web/api/main.py, which validates the same layer numbers for the
# self-assessment harness.
LAYER_SKIP_ENV: dict[str, str] = {
    "1":    "SKIP_SBOM",
    "2":    "SKIP_TRUFFLEHOG",
    "4":    "SKIP_CLAMAV",
    "5":    "SKIP_HELM",
    "6":    "SKIP_CHECKOV",
    "7":    "SKIP_TRIVY",
    "8":    "SKIP_GRYPE",
    "8.5":  "SKIP_PIP_AUDIT",
    "9":    "SKIP_XEOL",
    "10":   "SKIP_ANCHORE",
    "11":   "SKIP_API_DISCOVERY",
    "14":   "SKIP_PICKLESCAN",
    "15":   "SKIP_MODELCARD",
    "16":   "SKIP_NETWORK_DISCOVERY",
    "18":   "SKIP_MODEL_PROVENANCE",
    "19":   "SKIP_INFERENCE_SECURITY",
    "21":   "SKIP_COMPROMISED_SOURCE",
}

# Global stores
jobs:  dict[str, dict[str, Any]] = {}
procs: dict[str, asyncio.subprocess.Process] = {}

# Optional callback invoked when a scan job reaches completed/failed/error.
# Set by main.py at startup to invalidate the scan data cache.
_on_scan_complete_cb = None


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


def _read_github_config() -> dict:
    """Read non-secret GitHub preferences with environment authentication."""
    config_file = Path(__file__).parent.parent / "github-config.json"
    return github_config.read_config(config_file)


class ContainerImageResolutionError(Exception):
    """Raised when a --scan-image-equivalent source can't be pulled/loaded."""


async def _run_cmd(*cmd: str) -> tuple[int, str]:
    """Run a command, returning (exit_code, combined stdout+stderr text)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    return proc.returncode, out.decode("utf-8", errors="replace")


async def resolve_container_image(image_source: str, scratch_dir: Path, job: dict) -> str:
    """Resolve a container-image scan source into a local image reference
    usable as PRIMARY_BASELINE_IMAGE, mirroring the CLI's --scan-image
    resolution in run-target-security-scan.sh. Supports:
      - A local image already loaded in Docker/Podman (name:tag or digest)
      - A path to a local image tarball (docker save/skopeo output)
      - A registry reference to pull (e.g. ghcr.io/org/app:tag)
      - An https:// URL to download an image tarball from
    Raises ContainerImageResolutionError with a user-facing message on failure.
    """
    tarball_path: str | None = None

    if image_source.startswith("http://") or image_source.startswith("https://"):
        _append_line(job, f"[image] Downloading image archive from: {image_source}")
        scratch_dir.mkdir(parents=True, exist_ok=True)
        tarball_path = str(scratch_dir / "downloaded-image.tar")
        rc, out = await _run_cmd("curl", "--fail", "--location", "--silent", "--show-error",
                                  "--output", tarball_path, image_source)
        for line in out.splitlines():
            _append_line(job, f"[image] {line}")
        if rc != 0:
            raise ContainerImageResolutionError(f"Failed to download image archive from: {image_source}")
    elif Path(image_source).is_file():
        tarball_path = image_source

    if tarball_path:
        _append_line(job, f"[image] Loading image tarball: {tarball_path}")
        rc, out = await _run_cmd("docker", "load", "--input", tarball_path)
        for line in out.splitlines():
            _append_line(job, f"[image] {line}")
        if rc != 0:
            raise ContainerImageResolutionError(f"Failed to load image tarball: {tarball_path}")
        match = re.search(r"Loaded image(?: ID)?:\s*(.+)", out)
        if not match:
            raise ContainerImageResolutionError(f"Could not parse loaded image reference from: {tarball_path}")
        resolved = match.group(1).strip()
        _append_line(job, f"[image] Resolved scan image: {resolved}")
        return resolved

    # Not a file/URL — treat as an image reference: use it directly if
    # already local, otherwise attempt to pull it from a registry.
    rc, _ = await _run_cmd("docker", "image", "inspect", image_source)
    if rc == 0:
        _append_line(job, f"[image] Found image already loaded locally: {image_source}")
        return image_source

    _append_line(job, f"[image] Pulling image from registry: {image_source}")
    rc, out = await _run_cmd("docker", "pull", image_source)
    for line in out.splitlines():
        _append_line(job, f"[image] {line}")
    if rc != 0:
        raise ContainerImageResolutionError(
            f"Image not found locally and could not be pulled: {image_source}"
        )
    _append_line(job, f"[image] Resolved scan image: {image_source}")
    return image_source


def _authenticated_clone_url(clone_url: str, github_token: str) -> str:
    """Inject GITHUB_TOKEN/GH_PAT credentials into an https://github.com URL.

    Without this, cloning any private GitHub repo fails with git's generic
    "could not read Username ... No such device or address" — there's no
    TTY in the container to prompt for credentials, and no credential
    helper is configured. Only github.com https URLs are rewritten (SSH
    URLs, HuggingFace, and other hosts already carry or don't need auth
    this way); the token is never logged (see the redaction in the clone
    output loop below).
    """
    if not github_token or not clone_url.startswith("https://github.com/"):
        return clone_url
    return clone_url.replace(
        "https://github.com/", f"https://x-access-token:{github_token}@github.com/", 1
    )


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
    run_garak: bool = False,
    run_stig:  bool = False,
    webhook_url: str = "",
    webhook_secret: str = "",
    selected_layers: list[str] | None = None,
) -> None:
    job = jobs[job_id]
    job["status"] = "running"

    # ── Container image scans bypass source derivation/clone entirely ────
    # The "target" field holds the image source (local ref, tarball path,
    # registry ref, or https:// tarball URL) instead of a path/Git URL.
    if scan_type == "container_image":
        image_source = target
        target_dir   = str(epyon_root / "tmp" / f"image-scan-{job_id}")
        Path(target_dir).mkdir(parents=True, exist_ok=True)
        is_remote    = False
        subdir       = ""
        _is_url      = False
        clone_url    = ""

        try:
            resolved_image = await resolve_container_image(image_source, Path(target_dir), job)
        except ContainerImageResolutionError as exc:
            _append_line(job, f"[image] ERROR: {exc}")
            job["status"]       = "failed"
            job["error"]        = str(exc)
            job["completed_at"] = _now()
            return

        # Name the scan after the resolved image (e.g. "hello-world-latest"),
        # not the raw image_source — otherwise every tarball upload or
        # digest-pinned pull would collapse onto the same generic
        # "uploaded-image.tar"/"sha256-xxxx" scan name.
        target_name = re.sub(r"[^A-Za-z0-9._-]+", "-", resolved_image).strip("-") or "scanned-image"

        timestamp    = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        scan_name    = f"{target_name}_{timestamp}"
        scan_dir     = epyon_root / "scans" / scan_name
        scan_dir.mkdir(parents=True, exist_ok=True)

        epyon_version = "unknown"
        version_file = epyon_root / "VERSION"
        if version_file.exists():
            epyon_version = version_file.read_text().strip()

        import json as _json
        scan_meta = {
            "scan_type":        scan_type,
            "target_name":      target_name,
            "scan_timestamp":   datetime.now(timezone.utc).isoformat(),
            "target_directory": target_dir,
            "source_url":       "",
            "image_source":     image_source,
            "resolved_image":   resolved_image,
            "epyon_version":    epyon_version,
            "triggered_by":     "web-ui",
        }
        (scan_dir / "scan-metadata.json").write_text(_json.dumps(scan_meta, indent=2))

        # Container-focused layers only — mirrors the CLI's --scan-image
        # default "images" scan type (TruffleHog, Trivy, Grype, Xeol).
        # SCAN_MODE itself is passed through as "container_image", which
        # run-epyon-scan-ci.sh doesn't recognize and falls back to "full"
        # internally (logging a warning) — harmless, since every layer
        # below is explicitly forced on/off via SKIP_* regardless of mode,
        # same pattern already used for scan_type="local_model".
        env_lines = [
            f"TARGET_DIR={target_dir}",
            f"SCAN_MODE={scan_type}",
            f"TARGET_NAME={target_name}",
            "GITHUB_ACTOR=web-ui",
            "SUBDIR=",
            f"EPYON_VERSION={epyon_version}",
            f"PRIMARY_BASELINE_IMAGE={resolved_image}",
            "BUILD_ENABLED=false",
            "SKIP_SBOM=true",
            "SKIP_TRUFFLEHOG=false",
            "SKIP_SONAR=true",
            "SKIP_CLAMAV=true",
            "SKIP_HELM=true",
            "SKIP_CHECKOV=true",
            "SKIP_TRIVY=false",
            "SKIP_GRYPE=false",
            "SKIP_XEOL=false",
            "SKIP_ANCHORE=true",
            "SKIP_API_DISCOVERY=true",
            "SKIP_NETWORK_DISCOVERY=true",
            "SKIP_PICKLESCAN=true",
            "SKIP_MODELCARD=true",
            "SKIP_MODEL_PROVENANCE=true",
            "SKIP_INFERENCE_SECURITY=true",
            "SKIP_COMPROMISED_SOURCE=true",
            "SKIP_STIG=true",
            "SKIP_GARAK=true",
            # No source checkout exists for an image-only scan, so the Python
            # dependency scanners (which walk the target directory for
            # requirements.txt/Pipfile/etc.) have nothing to find — matches
            # the CLI's --scan-image "images" layer set (TruffleHog, Trivy,
            # Grype, Xeol only), which never invokes these at all.
            "SKIP_PIP_AUDIT=true",
            "SKIP_SAFETY=true",
        ]
        _env_path = Path("/tmp/epyon-env")
        _env_path.write_text("\n".join(env_lines) + "\n")
        _env_path.chmod(0o600)
        _append_line(job, f"[web-ui] Initialized container image scan: {scan_name}")

        env = {**os.environ,
               "CI":               "true",
               "NONINTERACTIVE":   "1",
               "DEBIAN_FRONTEND":  "noninteractive",
               "TERM":             "dumb",
               "SKIP_GARAK":       "true",
               "TARGET_DIR":       target_dir,
               "SCAN_DIR":         str(scan_dir),
               "SCAN_MODE":        scan_type,
               "TARGET_NAME":      target_name,
               "PRIMARY_BASELINE_IMAGE": resolved_image,
               "BUILD_ENABLED":    "false"}
        current_path = env.get("PATH", "")
        homebrew_paths = "/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin"
        env["PATH"] = f"{homebrew_paths}:{current_path}" if current_path else f"{homebrew_paths}:/usr/bin:/bin"

        try:
            proc = await asyncio.create_subprocess_exec(
                str(script_path),
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
                if _on_scan_complete_cb:
                    _on_scan_complete_cb(target_name, scan_name)
        except Exception as exc:
            procs.pop(job_id, None)
            job["status"]       = "error"
            job["error"]        = str(exc)
            job["completed_at"] = _now()
        return

    # ── Derive target name and target dir ────────────────────────
    _git_re  = re.compile(r"(?:https?://|git@)[^\s]+?/([^/\s]+?)(?:\.git)?$")
    _hf_re   = re.compile(r"huggingface\.co/(?:spaces/|datasets/)?([^/\s]+/[^/\s]+?)(?:\.git)?$")
    # GitHub browser tree URL: https://github.com/org/repo/tree/<ref>[/subdir]
    _gh_tree = re.compile(
        r"^https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)(/.+)?$"
    )

    hf_match   = _hf_re.search(target)
    gh_match   = _gh_tree.match(target)
    git_match  = _git_re.search(target)

    subdir = ""  # subdirectory within the cloned repo to scan

    if hf_match:
        target_name = hf_match.group(1).split("/")[-1]
        clone_url   = target
    elif gh_match:
        # Convert browser URL → bare clone URL + subdir
        gh_org, gh_repo, gh_ref, gh_sub = gh_match.groups()
        clone_url   = f"https://github.com/{gh_org}/{gh_repo}.git"
        target_name = gh_repo
        subdir      = (gh_sub or "").lstrip("/")
        target      = clone_url  # use the bare URL going forward
    elif git_match:
        target_name = git_match.group(1)
        clone_url   = target
    else:
        target_name = Path(target).name or "target"
        clone_url   = target

    # URLs always require a clone regardless of scan_type.
    # Local paths are identified by filesystem prefixes.
    _is_url = target.startswith("http://") or target.startswith("https://") or target.startswith("git@")

    if not _is_url and (target.startswith("/") or target.startswith("./") or target.startswith("../") or scan_type == "local_model"):
        target_dir = str(Path(target).resolve())
        is_remote  = False
    else:
        # Git/HF URL — will be cloned into a temp dir
        clone_root = str(epyon_root / "tmp" / f"clone-{job_id}")
        # If there's a subdir, TARGET_DIR points inside the clone
        target_dir = str(Path(clone_root) / subdir) if subdir else clone_root
        is_remote  = True

    timestamp    = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    scan_name    = f"{target_name}_{timestamp}"
    scan_dir     = epyon_root / "scans" / scan_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    # ── Write non-secret scan state to /tmp/epyon-env ────────────
    epyon_version = "unknown"
    version_file = epyon_root / "VERSION"
    if version_file.exists():
        epyon_version = version_file.read_text().strip()

    env_lines = [
        f"TARGET_DIR={target_dir}",
        f"SCAN_MODE={scan_type}",
        f"TARGET_NAME={target_name}",
        f"GITHUB_ACTOR=web-ui",
        f"SUBDIR={subdir}",
        f"EPYON_VERSION={epyon_version}",
        f"GARAK_TARGET_TYPE=openai",
        f"GARAK_TARGET_NAME=gpt-4o-mini",
        f"GARAK_PROBES=promptinject,dan,knownbadsignatures,encoding,continuation",
    ]
    if selected_layers is not None and scan_type not in ("local_model", "stig"):
        # Layer picker override (Run Scan page): explicitly enable/skip
        # every togglable layer per the user's checkbox selection, taking
        # precedence over the scan-type defaults below. Layers outside
        # LAYER_SKIP_ENV (3/Sonar, 12/Garak, 13/STIG, 20/ML Runtime) keep
        # their own dedicated opt-in logic untouched. Not applied for
        # local_model/stig scan types — those already run a fixed, narrow
        # layer set via the overrides further down.
        selected_set = set(selected_layers)
        for layer_num, skip_var in LAYER_SKIP_ENV.items():
            env_lines.append(f"{skip_var}={'false' if layer_num in selected_set else 'true'}")
    else:
        env_lines += [
            "SKIP_SBOM=false",
            "SKIP_TRUFFLEHOG=false",
            "SKIP_CLAMAV=false",
            "SKIP_HELM=false",
            "SKIP_CHECKOV=false",
            "SKIP_TRIVY=false",
            "SKIP_GRYPE=false",
            "SKIP_XEOL=false",
            "SKIP_ANCHORE=false",
            "SKIP_API_DISCOVERY=false",
        ]
    env_lines += [
        f"SKIP_STIG={'false' if (run_stig or scan_type == 'stig') else 'true'}",
        f"SCAN_DIR={scan_dir}",
        f"SCAN_NAME={scan_name}",
        f"SCAN_ID={scan_name}",
    ]
    # Build-and-scan the target's own container image before the rest of the
    # scan (Phase 0), same default as the GitHub Actions reusable workflow —
    # this is what surfaces OS-package/dependency CVEs baked into the real
    # artifact rather than just a generic Dockerfile FROM-line baseline, and
    # was previously the single biggest source of Web UI vs. CI result
    # divergence (Web UI never set this, so it silently never built/scanned
    # the real image). Skipped for local_model (not a buildable repo target)
    # and stig (narrow, fast compliance-only scan type).
    env_lines.append(f"BUILD_ENABLED={'false' if scan_type in ('local_model', 'stig') else 'true'}")
    # Garak opt-in from UI checkbox
    if run_garak:
        env_lines.append("RUN_GARAK=true")
    # SonarQube — enable only when SONAR_TOKEN is available in environment
    sonar_token = os.environ.get("SONAR_TOKEN", "")
    if sonar_token:
        env_lines.append("SKIP_SONAR=false")
        sonar_host = os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io")
        env_lines.append(f"SONAR_HOST_URL={sonar_host}")
    else:
        env_lines.append("SKIP_SONAR=true")
    # Local model weight scan — picklescan + modelcard only, no remote clone
    if scan_type == "local_model":
        env_lines.append("RUN_PICKLESCAN=true")
        env_lines.append("RUN_MODELCARD=true")
        env_lines.append("SKIP_SBOM=true")
        env_lines.append("SKIP_TRUFFLEHOG=true")
        env_lines.append("SKIP_SONAR=true")
        env_lines.append("SKIP_HELM=true")
        env_lines.append("SKIP_CHECKOV=true")
        env_lines.append("SKIP_TRIVY=true")
        env_lines.append("SKIP_GRYPE=true")
        env_lines.append("SKIP_XEOL=true")
        env_lines.append("SKIP_ANCHORE=true")
        env_lines.append("SKIP_API_DISCOVERY=true")
        env_lines.append("SKIP_STIG=true")
    # Secrets are passed only through the subprocess environment, never this file.
    openai_key = openai_summary.get_api_key() or os.environ.get("OPENAI_API_KEY", "")
    openai_base_url = openai_summary.get_base_url() or os.environ.get("OPENAI_BASE_URL", "")
    if openai_base_url:
        env_lines.append(f"OPENAI_BASE_URL={openai_base_url}")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

    # GitHub authentication comes only from GITHUB_TOKEN/GH_PAT in the environment.
    github_config = _read_github_config()
    github_token = github_config.get("token", "")

    _env_path = Path("/tmp/epyon-env")
    _env_path.write_text("\n".join(env_lines) + "\n")
    _env_path.chmod(0o600)
    _append_line(job, f"[web-ui] Initialized scan: {scan_name}")

    # ── Write scan-metadata.json so the parser can read scan_type ────────────
    import json as _json
    scan_meta = {
        "scan_type":        scan_type,
        "target_name":      target_name,
        "scan_timestamp":   datetime.now(timezone.utc).isoformat(),
        "target_directory": target_dir,
        "source_url":       target if _is_url else "",
        "epyon_version":    epyon_version,
        "triggered_by":     "web-ui",
    }
    (scan_dir / "scan-metadata.json").write_text(_json.dumps(scan_meta, indent=2))

    # ── Clone git/HF target if needed ───────────────────────────
    if is_remote:
        _append_line(job, f"[web-ui] Cloning {clone_url} …")
        Path(clone_root).mkdir(parents=True, exist_ok=True)

        clone_env = dict(os.environ)
        auth_clone_url = _authenticated_clone_url(clone_url, github_token)

        # Mirror the reusable GitHub Actions workflow's clone strategy
        # (.github/workflows/epyon-scan.yml) so TruffleHog's historical
        # secret scan and Layer 21's git-log confidence scoring see the same
        # commit history here as they do in CI, instead of this path's
        # previous unconditional --depth=1 silently truncating history and
        # producing different findings for an identical target.
        if hf_match:
            # HuggingFace repos can carry huge LFS weight blobs — shallow
            # clone + blob-size limit, same as CI.
            clone_cmd = ["git", "clone", "--depth=1", "--filter=blob:limit=10m",
                         auth_clone_url, clone_root]
        else:
            clone_cmd = ["git", "clone", auth_clone_url, clone_root]

        clone_proc = await asyncio.create_subprocess_exec(
            *clone_cmd,
            env=clone_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        clone_out, clone_err = await clone_proc.communicate()
        for line in (clone_out + clone_err).decode("utf-8", errors="replace").splitlines():
            if line.strip():
                # Never let the injected token leak into job output/logs.
                if github_token:
                    line = line.replace(github_token, "***")
                _append_line(job, f"[git] {line}")
        if clone_proc.returncode != 0:
            job["status"]       = "failed"
            job["exit_code"]    = clone_proc.returncode
            job["completed_at"] = _now()
            return

    # Merge file_statistics into the scan-metadata.json written earlier
    # (before the clone, when target_dir was potentially still empty) now
    # that the final content is in place — unless this is a local_model or
    # container_image scan, which genuinely have no source checkout to
    # count and should stay "unknown" rather than a misleading 0.
    if scan_type not in ("local_model", "container_image"):
        scan_meta_path = scan_dir / "scan-metadata.json"
        try:
            scan_meta_on_disk = json.loads(scan_meta_path.read_text())
        except Exception:
            scan_meta_on_disk = {}
        scan_meta_on_disk["file_statistics"] = _compute_file_statistics(target_dir)
        scan_meta_path.write_text(json.dumps(scan_meta_on_disk, indent=2))

    env = {**os.environ,
           "CI":               "true",
           "NONINTERACTIVE":   "1",
           "DEBIAN_FRONTEND":  "noninteractive",
           "TERM":             "dumb",
           # Garak is opt-in only (layer 12). `/tmp/epyon-env` (written above
           # from env_lines) only ever *sets* RUN_GARAK=true when requested —
           # it never clears SKIP_GARAK. run_garak_layer() in
           # run-epyon-scan-ci.sh treats SKIP_GARAK as a hard stop that wins
           # over RUN_GARAK, so a stale "true" here previously made Garak
           # unrunnable from the Web UI even with the toggle enabled.
           "SKIP_GARAK":       "false" if run_garak else "true",
           "TARGET_DIR":       target_dir,
           "SCAN_DIR":         str(scan_dir),
           "SCAN_MODE":        scan_type,
           "TARGET_NAME":      target_name}
    if openai_key:
        env["OPENAI_API_KEY"] = openai_key
    if openai_base_url:
        env["OPENAI_BASE_URL"] = openai_base_url
    if github_token:
        env["GH_PAT"] = github_token
    # Webhook configuration (optional)
    if webhook_url:
        env["EPYON_CALLBACK_URL"] = webhook_url
        env["EPYON_JOB_ID"] = job_id
        _append_line(job, f"[web-ui] Webhook configured: {webhook_url}")
    if webhook_secret:
        env["EPYON_WEBHOOK_SECRET"] = webhook_secret
        _append_line(job, f"[web-ui] Webhook secret: configured")

    # Ensure PATH includes Homebrew locations so script can find bash 4+
    current_path = env.get("PATH", "")
    homebrew_paths = "/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin"
    if current_path:
        env["PATH"] = f"{homebrew_paths}:{current_path}"
    else:
        env["PATH"] = f"{homebrew_paths}:/usr/bin:/bin"

    # Let the script's shebang and shell auto-detection handle bash selection.
    # The script contains shell auto-detection logic that finds bash 4+ and re-execs.
    # Invoking as `bash script.sh` would bypass that logic, so we invoke directly.
    try:
        proc = await asyncio.create_subprocess_exec(
            str(script_path),
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
            if _on_scan_complete_cb:
                _on_scan_complete_cb(target_name, scan_name)

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


async def run_self_assessment_job(
    job_id: str,
    script_path: Path,
    epyon_root: Path,
    layers: list[str] | None = None,
) -> None:
    """Run scripts/shell/run-self-assessment.sh (the fixture-based, cross-
    layer scanner validation harness) as a background job, so the Performance
    page can trigger a self-diagnostic on demand and show live step-by-step
    progress instead of requiring someone to run it from a terminal.

    `layers`, if given, restricts validation to the listed manifest layer
    numbers (e.g. ["1", "2", "7", "8", "8.5"]) via the harness's --layers
    flag — every other layer's underlying scan step is skipped and it's
    reported with status "skipped" rather than pass/fail/not_validated.
    Omit (or pass None/empty) to run the full self-assessment, unchanged.

    The harness itself already writes the final structured per-layer
    pass/fail/environment_limited/not_validated/skipped verdict to
    web/data/self-assessment-latest.json (read by GET
    /api/metrics/self-assessment) — this job only needs to stream the raw
    console output live so the UI can show what's currently running, and
    flip to completed/failed based on the script's exit code.
    """
    job = jobs[job_id]
    job["status"] = "running"

    env = {**os.environ,
           "CI":              "true",
           "NONINTERACTIVE":  "1",
           "DEBIAN_FRONTEND": "noninteractive",
           "TERM":            "dumb"}
    # Ensure PATH includes Homebrew locations so the script can find bash 4+,
    # matching run_scan_job's convention.
    current_path = env.get("PATH", "")
    homebrew_paths = "/opt/homebrew/bin:/usr/local/bin:/home/linuxbrew/.linuxbrew/bin"
    env["PATH"] = f"{homebrew_paths}:{current_path}" if current_path else f"{homebrew_paths}:/usr/bin:/bin"

    cmd = ["bash", str(script_path)]
    if layers:
        cmd += ["--layers", ",".join(str(l) for l in layers)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
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
