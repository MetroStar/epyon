"""Epyon Web — scans routes."""
from __future__ import annotations

from pathlib import Path
import asyncio
import io
import json
import re
import shutil
import tarfile
import zipfile

from fastapi import APIRouter
from fastapi import File
from fastapi import Form
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi import UploadFile
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse

from .. import jobs as job_store
from .. import parsers
from .. import scan_store
from .. import main as api_main

router = APIRouter()

@router.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, request: Request, response: Response):
    """Permanently delete a single scan (raw folder and/or archived DB copy)."""
    api_main._sec_headers(response)
    api_main._audit(request, "delete_scan", f"scan_id={scan_id}")
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=0)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if matched:
        try:
            matched.resolve().relative_to(api_main.EPYON_ROOT.resolve())
        except ValueError:
            raise HTTPException(403, "Access denied")
        shutil.rmtree(matched)
    elif not scan_store.is_archived(api_main._scan_db_conn, scan_id):
        raise HTTPException(404, "Scan not found")
    api_main._scan_db_conn.execute("DELETE FROM scan_archives WHERE scan_id = ?", (scan_id,))
    api_main._scan_db_conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    api_main._scan_db_conn.commit()
    api_main._invalidate_scan_cache(reason="delete_scan", scan_id=scan_id)
    return {"deleted": scan_id}


@router.post("/api/scans/{scan_id}/restore")
def restore_scan(scan_id: str, request: Request, response: Response):
    """Temporarily restore an archived scan's raw files to disk (for
    _RESTORE_HOURS) so downloads/full-detail endpoints work again."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    api_main._audit(request, "restore_scan", f"scan_id={scan_id}")
    dest = scan_store.restore_scan(api_main._scan_db_conn, scan_id, api_main.EPYON_ROOT, hours=api_main._RESTORE_HOURS)
    if dest is None:
        raise HTTPException(404, "Archived scan not found")
    api_main._invalidate_scan_cache(reason="restore_scan", scan_id=scan_id)
    return {
        "scan_id": scan_id,
        "restored_path": str(dest),
        "restored_for_hours": api_main._RESTORE_HOURS,
    }


@router.get("/api/retention/status")
def retention_status(response: Response):
    """Retention/archival configuration and recent sweep history."""
    api_main._sec_headers(response)
    row = api_main._scan_db_conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(raw_size_bytes), 0) AS bytes FROM scans WHERE archived = 1"
    ).fetchone()
    last_runs = api_main._scan_db_conn.execute(
        "SELECT started_at, finished_at, ingested_count, archived_count, bytes_freed, errors_json "
        "FROM retention_runs ORDER BY id DESC LIMIT 10"
    ).fetchall()
    return {
        "retention_days": api_main._RETENTION_DAYS,
        "restore_hours": api_main._RESTORE_HOURS,
        "archived_scans": row["n"],
        "bytes_freed_total": row["bytes"],
        "recent_runs": [dict(r) for r in last_runs],
    }


@router.post("/api/retention/run")
def retention_run_now(response: Response):
    """Manually trigger an ingest + archive sweep (normally runs daily)."""
    api_main._sec_headers(response)
    result = scan_store.run_retention_sweep(api_main._scan_db_conn, api_main.EPYON_ROOT, api_main._RETENTION_DAYS)
    if result["ingested"] or result["archived"]:
        api_main._invalidate_scan_cache(reason="retention_sweep_manual")
    return result


# ── Scan detail ───────────────────────────────────────────────

@router.get("/api/scans/{scan_id}/dashboard")
def scan_dashboard(scan_id: str, response: Response):
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)
    dashboard = matched / "consolidated-reports" / "dashboards" / "security-dashboard.html"
    try:
        dashboard.resolve().relative_to(api_main.EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not dashboard.exists():
        raise HTTPException(404, "Dashboard not generated for this scan")
    return FileResponse(str(dashboard), media_type="text/html")


@router.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        summary = scan_store.get_scan_summary(api_main._scan_db_conn, scan_id)
        if summary is not None:
            return summary
        raise HTTPException(404, "Scan not found")
    return parsers.load_scan_complete(matched, api_main.EPYON_ROOT)


@router.get("/api/scans/{scan_id}/ssp-evidence")
def scan_ssp_evidence(scan_id: str, response: Response):
    """Return NIST SP 800-53 / FedRAMP control evidence & artifact mapping matrix."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    
    matrix = parsers.parse_ssp_evidence_matrix(matched)
    
    # Save package files asynchronously/on-demand
    try:
        json_out = matched / "ssp-ato-evidence-package.json"
        md_out = matched / "ssp-ato-evidence-matrix.md"
        if not json_out.exists():
            json_out.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        if not md_out.exists():
            md_out.write_text(parsers.generate_ssp_evidence_markdown(matrix), encoding="utf-8")
    except Exception:
        pass
        
    return matrix


@router.get("/api/scans/{scan_id}/ssp-evidence/md")
def scan_ssp_evidence_md(scan_id: str, response: Response):
    """Download Markdown matrix for NIST 800-53 control evidence."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    
    md_file = matched / "ssp-ato-evidence-matrix.md"
    if not md_file.exists():
        matrix = parsers.parse_ssp_evidence_matrix(matched)
        md_file.write_text(parsers.generate_ssp_evidence_markdown(matrix), encoding="utf-8")
        
    filename = f"ssp-ato-evidence-matrix-{scan_id}.md"
    return FileResponse(
        str(md_file),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/api/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str, response: Response):
    """Return SBOM package list for a scan (reads syft-json directly)."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)
    return parsers.load_sbom_packages(matched)


@router.get("/api/scans/{scan_id}/sbom/cyclonedx")
def scan_sbom_cyclonedx(scan_id: str, response: Response):
    """Download the CycloneDX SBOM JSON for a scan."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)
    sbom_dir = matched / "sbom"
    # Prefer the dedicated cyclonedx file, fall back to any *.cyclonedx.json
    candidates = [
        sbom_dir / "filesystem.cyclonedx.json",
        *sorted(sbom_dir.glob("*.cyclonedx.json")),
    ]
    cdx_file = next((f for f in candidates if f.exists()), None)
    if cdx_file is None:
        raise HTTPException(404, "CycloneDX SBOM not found for this scan")
    filename = f"sbom-{scan_id}.cyclonedx.json"
    return FileResponse(
        str(cdx_file),
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/scans/{scan_id}/download")
def scan_download_zip(scan_id: str, response: Response):
    """Stream the entire scan directory as a ZIP archive for ATO/IATT submissions."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)

    epyon_root_resolved = api_main.EPYON_ROOT.resolve()

    def _generate_zip():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in sorted(matched.rglob("*")):
                if not file_path.is_file():
                    continue
                # Skip large/noisy files that add no ATO value
                rel = file_path.relative_to(matched)
                rel_str = str(rel)
                if any(part.startswith(".") for part in rel.parts):
                    continue  # skip hidden dirs (.scannerwork etc)
                if file_path.suffix in (".tar", ".gz", ".db", ".zip"):
                    continue
                # Path traversal guard
                try:
                    file_path.resolve().relative_to(epyon_root_resolved)
                except ValueError:
                    continue
                zf.write(file_path, arcname=str(Path(scan_id) / rel))
        buf.seek(0)
        yield from buf

    filename = f"epyon-scan-{scan_id}.zip"
    return StreamingResponse(
        _generate_zip(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/scans/{scan_id}/download-json")
def scan_download_json(scan_id: str, response: Response):
    """Export the fully parsed scan result (findings, STIG, misconfig, ML/AI
    security, metadata) as a single downloadable JSON file — the same data
    model backing the scan detail page, for offline review or ingestion by
    other tooling without needing the full ZIP of raw scan artifacts."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)

    scan_data = parsers.load_scan_complete(matched, api_main.EPYON_ROOT)
    payload = json.dumps(scan_data, indent=2, default=str)
    filename = f"epyon-scan-{scan_id}.json"
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Trigger scan ──────────────────────────────────────────────

@router.post("/api/scans", status_code=202)
async def trigger_scan(request: Request, response: Response):
    api_main._sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    target    = (body.get("target") or "").strip()
    scan_type = body.get("scan_type", "full")
    run_garak = bool(body.get("run_garak", False))
    # run_stig is implicit when scan_type == "stig"; can also be set explicitly
    # for full/nightly scans that should include the STIG layer.
    run_stig  = bool(body.get("run_stig", False)) or scan_type == "stig"

    # Optional per-layer override from the Run Scan page's layer picker —
    # restricts the scan to exactly these layer numbers (see
    # job_store.LAYER_SKIP_ENV for the supported set). Omitted/None means
    # "use the scan type's default layer set", preserving prior behavior.
    layers = body.get("layers")
    if layers is not None:
        if not isinstance(layers, list) or not all(isinstance(l, str) for l in layers):
            raise HTTPException(400, "layers must be an array of layer number strings")
        invalid = [l for l in layers if l not in job_store.LAYER_SKIP_ENV]
        if invalid:
            raise HTTPException(400, f"Unknown scan layer(s): {', '.join(invalid)}")

    # Webhook configuration (optional)
    webhook_url    = (body.get("webhook_url") or "").strip()
    webhook_secret = (body.get("webhook_secret") or "").strip()
    
    # Log webhook config if present (for debugging)
    if webhook_url:
        print(f"[scan-trigger] Webhook URL: {webhook_url}", flush=True)

    if not target:
        raise HTTPException(400, "target is required")
    if scan_type == "container_image":
        # target holds an image source instead of a path/Git URL: a local
        # image ref (name:tag or digest), a local tarball path, a registry
        # reference to pull, or an https:// URL to an image tarball.
        if len(target) > 512:
            raise HTTPException(400, "target is too long for an image source")
    else:
        valid_prefixes = ["/", "./", "../", "https://", "http://", "git@"]
        if not any(target.startswith(p) for p in valid_prefixes):
            raise HTTPException(400, "target must be an absolute path, relative path, or Git URL")
    if re.search(r"[;&|`$\(\)\n\r<>]", target):
        raise HTTPException(400, "target contains invalid characters")
    if scan_type not in api_main._VALID_SCAN_TYPES:
        raise HTTPException(400, f"scan_type must be one of: {sorted(api_main._VALID_SCAN_TYPES)}")

    script_path = api_main.SCRIPTS_DIR / "run-epyon-scan-ci.sh"
    if not script_path.exists():
        raise HTTPException(500, "Scan script not found")

    job_id = job_store.new_job_id()
    api_main._audit(request, "scan_triggered", f"target={target} scan_type={scan_type}")
    job = job_store.create_job(job_id, target, scan_type)
    job_store._on_scan_complete_cb = api_main._on_scan_complete
    asyncio.create_task(
        job_store.run_scan_job(job_id, target, scan_type, script_path, api_main.EPYON_ROOT,
                               run_garak=run_garak, run_stig=run_stig,
                               webhook_url=webhook_url, webhook_secret=webhook_secret,
                               selected_layers=layers)
    )
    return {"job_id": job_id, "status": "queued"}


def _safe_extract_zip(zf: zipfile.ZipFile, extract_dir: Path) -> None:
    """Extract a zip archive defensively (zip-slip + zip-bomb protection).

    Rejects any entry whose resolved destination would fall outside
    extract_dir (path traversal / absolute paths / symlink-style names),
    and enforces a cap on total uncompressed size to guard against
    decompression bombs. Skips macOS '__MACOSX' metadata entries.
    """
    extract_root = extract_dir.resolve()
    total_uncompressed = 0
    for info in zf.infolist():
        name = info.filename
        if name.startswith("__MACOSX/") or name == "__MACOSX":
            continue
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValueError(f"unsafe path in archive: {name}")
        total_uncompressed += info.file_size
        if total_uncompressed > api_main.MAX_UPLOAD_UNZIPPED:
            raise ValueError("archive exceeds maximum uncompressed size")
        dest = (extract_root / name).resolve()
        if dest != extract_root and extract_root not in dest.parents:
            raise ValueError(f"unsafe path in archive: {name}")
        if info.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)


_PROJECT_TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def _safe_extract_tar(tf: tarfile.TarFile, extract_dir: Path) -> None:
    """Extract a tarball defensively, mirroring _safe_extract_zip.

    Rejects traversal/absolute paths and enforces the uncompressed-size cap.
    Only regular files and directories are written; symlinks, hardlinks and
    device nodes are skipped so an archive cannot point outside extract_dir.
    """
    extract_root = extract_dir.resolve()
    total_uncompressed = 0
    for member in tf:
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValueError(f"unsafe path in archive: {name}")
        if not (member.isfile() or member.isdir()):
            continue
        total_uncompressed += member.size
        if total_uncompressed > api_main.MAX_UPLOAD_UNZIPPED:
            raise ValueError("archive exceeds maximum uncompressed size")
        dest = (extract_root / name).resolve()
        if dest != extract_root and extract_root not in dest.parents:
            raise ValueError(f"unsafe path in archive: {name}")
        if member.isdir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(member)
        if src is None:
            continue
        with src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)


@router.post("/api/scans/upload", status_code=202)
async def trigger_scan_upload(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    scan_type: str = Form("full"),
    run_garak: bool = Form(False),
    run_stig: bool = Form(False),
    webhook_url: str = Form(""),
    webhook_secret: str = Form(""),
    layers: str = Form(""),
):
    """Scan a project the user uploads as a .zip or tarball, rather than a Git URL or
    a path that must already exist on the server's own filesystem. This is
    the supported way to scan a local, not-yet-pushed project once Epyon is
    deployed to a remote server (an absolute path typed into the standard
    "Target" field is resolved against the SERVER's filesystem, not the
    browser's machine, and won't find anything there)."""
    api_main._sec_headers(response)

    run_stig = run_stig or scan_type == "stig"
    if scan_type not in api_main._VALID_SCAN_TYPES:
        raise HTTPException(400, f"scan_type must be one of: {sorted(api_main._VALID_SCAN_TYPES)}")
    fname_lower = (file.filename or "").lower()
    is_tar = fname_lower.endswith(_PROJECT_TAR_EXTS)
    if not fname_lower.endswith(".zip") and not is_tar:
        raise HTTPException(400, "file must be a .zip or .tar/.tar.gz/.tgz archive")

    # Optional per-layer override from the Run Scan page's layer picker,
    # sent as a JSON-encoded array since multipart form fields are strings.
    selected_layers = None
    if layers:
        try:
            selected_layers = json.loads(layers)
        except (ValueError, TypeError):
            raise HTTPException(400, "layers must be a JSON array of layer number strings")
        if not isinstance(selected_layers, list) or not all(isinstance(l, str) for l in selected_layers):
            raise HTTPException(400, "layers must be an array of layer number strings")
        invalid = [l for l in selected_layers if l not in job_store.LAYER_SKIP_ENV]
        if invalid:
            raise HTTPException(400, f"Unknown scan layer(s): {', '.join(invalid)}")

    script_path = api_main.SCRIPTS_DIR / "run-epyon-scan-ci.sh"
    if not script_path.exists():
        raise HTTPException(500, "Scan script not found")

    # Spool the upload to disk with a hard size cap rather than buffering the
    # whole thing in memory (uploads can legitimately be tens/hundreds of MB).
    job_id  = job_store.new_job_id()
    tmp_dir = api_main.EPYON_ROOT / "tmp"
    zip_path = tmp_dir / f"upload-{job_id}.zip"
    written = 0
    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        with open(zip_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > api_main.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"upload exceeds {api_main.MAX_UPLOAD_BYTES // (1024*1024)}MB limit")
                out.write(chunk)

        if is_tar:
            if not tarfile.is_tarfile(zip_path):
                raise HTTPException(400, "uploaded file is not a valid tar archive")
        elif not zipfile.is_zipfile(zip_path):
            raise HTTPException(400, "uploaded file is not a valid zip archive")

        base_name = api_main._UPLOAD_NAME_RE.sub("-", Path(file.filename).stem).strip("-") or "upload"
        extract_dir = tmp_dir / f"upload-{base_name}-{job_id}"

        def _extract() -> None:
            if is_tar:
                with tarfile.open(zip_path) as tf:
                    _safe_extract_tar(tf, extract_dir)
            else:
                with zipfile.ZipFile(zip_path) as zf:
                    _safe_extract_zip(zf, extract_dir)

        try:
            # Extraction is pure CPU/disk work with no `await`s in it, so run
            # it in a worker thread rather than inline — otherwise a large
            # archive would block the single asyncio event loop (and every
            # other request the server is handling, including this same
            # upload's own job-status polling) for the whole extraction.
            await asyncio.to_thread(_extract)
        except (zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise HTTPException(400, f"could not extract archive: {e}")
    except BaseException:
        job_store.release_job_id(job_id)
        raise
    finally:
        try:
            zip_path.unlink(missing_ok=True)
        except OSError:
            job_store.release_job_id(job_id)
            raise

    try:
        # If the archive is a single wrapping folder (the common case when
        # zipping a project directory), scan that inner folder directly so the
        # scan name/target reflects the project, not the upload wrapper.
        entries = [e for e in extract_dir.iterdir() if e.name != "__MACOSX"]
        target_dir = entries[0] if (len(entries) == 1 and entries[0].is_dir()) else extract_dir
        target = str(target_dir.resolve())

        api_main._audit(request, "scan_upload_triggered", f"file={file.filename} scan_type={scan_type}")
        job = job_store.create_job(job_id, target, scan_type)
        job_store._on_scan_complete_cb = api_main._on_scan_complete
        asyncio.create_task(
            job_store.run_scan_job(job_id, target, scan_type, script_path, api_main.EPYON_ROOT,
                                   run_garak=run_garak, run_stig=run_stig,
                                   webhook_url=webhook_url, webhook_secret=webhook_secret,
                                   selected_layers=selected_layers)
        )
        return {"job_id": job_id, "status": "queued"}
    except BaseException:
        job_store.release_job_id(job_id)
        raise


_IMAGE_UPLOAD_EXTS = (".tar", ".tar.gz", ".tgz")


@router.post("/api/scans/upload-image", status_code=202)
async def trigger_scan_upload_image(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    webhook_url: str = Form(""),
    webhook_secret: str = Form(""),
):
    """Scan a container image the user uploads as a tarball (`docker save`
    or `skopeo` output), rather than a registry reference or https:// URL.
    This is the supported way to scan a local, not-yet-pushed image once
    Epyon is deployed to a remote server — a tarball path typed into the
    "Container Image Source" field is resolved on the SERVER's own
    filesystem, not the browser's machine, mirroring why the project
    "Upload .zip" option exists for directory/Git targets."""
    api_main._sec_headers(response)

    if not file.filename or not file.filename.lower().endswith(_IMAGE_UPLOAD_EXTS):
        raise HTTPException(400, f"file must be one of: {', '.join(_IMAGE_UPLOAD_EXTS)}")

    script_path = api_main.SCRIPTS_DIR / "run-epyon-scan-ci.sh"
    if not script_path.exists():
        raise HTTPException(500, "Scan script not found")

    # Save straight into this job's own scratch dir (the same
    # tmp/image-scan-{job_id}/ directory run_scan_job() creates for
    # container_image scans) so no extra copy/move step is needed —
    # resolve_container_image() picks it up via its "local file path"
    # branch exactly like a pre-existing path would be on local/dev use.
    job_id      = job_store.new_job_id()
    scratch_dir = api_main.EPYON_ROOT / "tmp" / f"image-scan-{job_id}"
    ext = ".tar.gz" if file.filename.lower().endswith(".tar.gz") else Path(file.filename).suffix
    tarball_path = scratch_dir / f"uploaded-image{ext}"
    written = 0
    try:
        scratch_dir.mkdir(parents=True, exist_ok=True)
        with open(tarball_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > api_main.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"upload exceeds {api_main.MAX_UPLOAD_BYTES // (1024*1024)}MB limit")
                out.write(chunk)
    except BaseException:
        shutil.rmtree(scratch_dir, ignore_errors=True)
        job_store.release_job_id(job_id)
        raise

    try:
        target = str(tarball_path)
        api_main._audit(request, "scan_upload_image_triggered", f"file={file.filename}")
        job = job_store.create_job(job_id, target, "container_image")
        job_store._on_scan_complete_cb = api_main._on_scan_complete
        asyncio.create_task(
            job_store.run_scan_job(job_id, target, "container_image", script_path, api_main.EPYON_ROOT,
                                   webhook_url=webhook_url, webhook_secret=webhook_secret)
        )
        return {"job_id": job_id, "status": "queued"}
    except BaseException:
        job_store.release_job_id(job_id)
        raise


# ── Jobs ──────────────────────────────────────────────────────

@router.get("/api/jobs")
def list_jobs(response: Response, summary: bool = False):
    api_main._sec_headers(response)
    items = sorted(job_store.jobs.values(), key=lambda j: j.get("started_at", ""), reverse=True)
    if summary:  # lightweight form for the global scan watcher: no log output
        return [{k: v for k, v in j.items() if k != "output"} for j in items]
    return items


@router.get("/api/jobs/{job_id}")
def get_job(job_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._JOB_ID_RE.match(job_id):
        raise HTTPException(400, "Invalid job_id")
    job = job_store.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._JOB_ID_RE.match(job_id):
        raise HTTPException(400, "Invalid job_id")
    if job_id not in job_store.jobs:
        raise HTTPException(404, "Job not found")
    if job_store.jobs[job_id]["status"] not in ("queued", "running"):
        raise HTTPException(409, "Job is not running")
    job_store.cancel_job(job_id)
    return {"job_id": job_id, "status": "cancelled"}
