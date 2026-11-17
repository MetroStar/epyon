"""Epyon Web — system routes."""
from __future__ import annotations

from typing import Optional
import asyncio
import json
import os
import re

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from pydantic import BaseModel

from .. import jobs as job_store
from .. import openai_summary
from .. import parsers
from .. import cache_state
import time
from .. import main as api_main

router = APIRouter()

# ── Health ────────────────────────────────────────────────────

@router.get("/api/health")
def health(response: Response):
    api_main._sec_headers(response)
    return {"status": "ok", "epyon_root": str(api_main.EPYON_ROOT), "version": api_main.EPYON_VERSION}


# ── Scan history ──────────────────────────────────────────────

@router.get("/api/scan-history")
def scan_history(response: Response):
    api_main._sec_headers(response)
    hidden  = api_main._load_hidden_apps()
    scans   = [api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs()
               if parsers.parse_dir_name(d.name)["target"] not in hidden]
    targets = sorted({s["target"] for s in scans})
    users   = sorted({s["user"] for s in scans if s.get("user")})
    return {
        "generated_at": api_main._now(),
        "total_scans":  len(scans),
        "targets":      targets,
        "users":        users,
    }


# ── Settings ──────────────────────────────────────────────────

@router.get("/api/settings/approved-images")
def approved_images(response: Response):
    api_main._sec_headers(response)
    try:
        content = api_main.APPROVED_IMAGES_FILE.read_text(encoding="utf-8")
    except OSError:
        content = ""
    return {"content": content}


# ── AI / OpenAI config ────────────────────────────────────────

@router.get("/api/ai/openai-models")
async def list_openai_models():
    """List chat models available to the server's OPENAI_API_KEY (public OpenAI API only)."""
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise HTTPException(400, "OPENAI_API_KEY is not set in the server environment")

    def _fetch() -> list:
        import http.client
        conn = http.client.HTTPSConnection("api.openai.com", timeout=15)
        try:
            conn.request("GET", "/v1/models", headers={"Authorization": f"Bearer {key}"})
            resp = conn.getresponse()
            if resp.status != 200:
                raise OSError(f"OpenAI models API returned {resp.status}")
            data = json.loads(resp.read())
        finally:
            conn.close()
        skip = ("audio", "realtime", "tts", "transcribe", "image", "search",
                "embedding", "moderation", "instruct", "codex", "live")
        ids = {m["id"] for m in data.get("data", [])
               if m["id"].startswith(("gpt-", "o1", "o3", "o4"))
               and not any(t in m["id"] for t in skip)
               and not re.search(r"-\d{4}-\d{2}-\d{2}$", m["id"])}
        return sorted(ids, reverse=True)

    try:
        models = await asyncio.get_running_loop().run_in_executor(None, _fetch)
    except Exception:
        raise HTTPException(502, "Could not list models from the OpenAI API")
    return {"models": models}


@router.get("/api/ai/local-models")
async def list_local_models(response: Response, base_url: str = ""):
    """List models served by a self-hosted OpenAI-compatible endpoint (Ollama, vLLM...).

    Calls ``{base_url}/models`` without credentials and without following redirects.
    The URL is validated with the same rules and SSRF guard as ``POST /api/ai/config``.
    """
    api_main._sec_headers(response)
    base_url = (base_url or openai_summary.get_base_url() or "").strip().rstrip("/")
    if not base_url:
        raise HTTPException(400, "No base URL configured")
    if not re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[\w./\-]*)?$", base_url):
        raise HTTPException(400, "base_url must be a valid http(s) URL")
    if not openai_summary.base_url_allowed(base_url):
        raise HTTPException(400, "base_url host is not allowed; add it to EPYON_AI_ALLOWED_HOSTS")

    def _fetch() -> list:
        import urllib.request
        import urllib.error

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(base_url + "/models", timeout=6) as resp:  # noqa: S310 - validated above
            data = json.loads(resp.read(2_000_000))
        return sorted({m["id"] for m in data.get("data", []) if isinstance(m.get("id"), str)})

    try:
        models = await asyncio.get_running_loop().run_in_executor(None, _fetch)
    except Exception as exc:
        raise HTTPException(502, f"Could not reach {base_url}/models ({type(exc).__name__})")
    return {"models": models, "base_url": base_url}


@router.get("/api/ai/config")
def ai_config_get(response: Response):
    api_main._sec_headers(response)
    cfg = openai_summary.read_ai_config()
    return {
        "key_set":  bool(os.environ.get("OPENAI_API_KEY", "").strip()),
        "from_env": bool(os.environ.get("OPENAI_API_KEY", "").strip()),
        # `model` reflects only the UI-managed value so the Settings dropdown
        # stays in sync with what was actually saved. Returning the resolved
        # effective model here would surface a non-allowlisted env value (e.g.
        # gemma4:26b) that the dropdown can't represent; the browser would then
        # fall back to its first <option> and a subsequent Save would persist
        # that, clobbering the env-configured model. `active_model` exposes the
        # resolved model (UI > OPENAI_MODEL > default) for display only.
        "provider":     openai_summary.get_provider(),
        "openai_model": cfg.get("openai_model") or openai_summary.DEFAULT_MODEL,
        "model":        cfg.get("model") or openai_summary.DEFAULT_MODEL,
        "active_model": openai_summary.get_model(),
        # The configured custom endpoint (UI value), plus the effective base URL
        # actually in use (UI > OPENAI_BASE_URL env > OpenAI default) for
        # display. Empty string means the public OpenAI API.
        "base_url":        cfg.get("base_url", ""),
        "active_base_url": openai_summary.get_base_url() or "",
        # Secondary (fallback) OpenAI provider — only takes effect when the
        # primary endpoint above is self-hosted (e.g. a local Ollama instance)
        # and OPENAI_API_KEY is present in the server environment.
        "fallback_enabled":   openai_summary.get_fallback_enabled(),
        "fallback_model":     cfg.get("fallback_model") or openai_summary.DEFAULT_MODEL,
        "fallback_available": openai_summary.fallback_available(),
    }


@router.post("/api/ai/config")
async def ai_config_post(request: Request, response: Response):
    api_main._sec_headers(response)
    api_main._audit(request, "ai_config_changed")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if "api_key" in body:
        raise HTTPException(
            400,
            "OpenAI API keys cannot be set in the UI; use OPENAI_API_KEY",
        )

    cfg = openai_summary.read_ai_config()

    if "provider" in body:
        provider = str(body["provider"] or "auto").lower()
        if provider not in openai_summary.PROVIDERS:
            raise HTTPException(400, "provider must be auto, local or openai")
        if provider == "openai" and not os.environ.get("OPENAI_API_KEY", "").strip():
            raise HTTPException(400, "OPENAI_API_KEY is not set in the server environment")
        cfg["provider"] = provider

    if body.get("openai_model"):
        openai_model = str(body["openai_model"]).strip()
        if not re.match(r"^[A-Za-z0-9._:\-/]{1,100}$", openai_model):
            raise HTTPException(400, "openai_model contains invalid characters")
        cfg["openai_model"] = openai_model

    if "base_url" in body:
        base_url = (body.get("base_url") or "").strip()
        if base_url:
            # Allow https:// for public providers and http:// for in-cluster /
            # self-hosted endpoints (e.g. http://ollama.ollama:11434/v1).
            if not re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/[\w./\-]*)?$", base_url):
                raise HTTPException(400, "base_url must be a valid http(s) URL")
            # SSRF / credential-exfil guard: only the public OpenAI API,
            # cluster-internal/private hosts, or an operator allowlist
            # (EPYON_AI_ALLOWED_HOSTS) may be targeted, so this endpoint cannot
            # be used to redirect a stored API key to an attacker host.
            if not openai_summary.base_url_allowed(base_url):
                raise HTTPException(
                    400,
                    "base_url host is not allowed; use the public OpenAI API, a "
                    "cluster-internal endpoint, or add it to EPYON_AI_ALLOWED_HOSTS",
                )
            cfg["base_url"] = base_url
        else:
            cfg.pop("base_url", None)  # explicit clear → fall back to env/default

    if body.get("model"):
        model = str(body["model"]).strip()
        # Accept curated OpenAI models and any self-hosted model id
        # (e.g. gemma4:26b, llama3.1:8b). Validate the character set so the
        # value is safe to use in request bodies and file paths.
        if not re.match(r"^[A-Za-z0-9._:\-/]{1,100}$", model):
            raise HTTPException(400, "model contains invalid characters")
        cfg["model"] = model

    if "fallback_enabled" in body:
        cfg["fallback_enabled"] = bool(body["fallback_enabled"])

    if "fallback_model" in body:
        fallback_model = str(body.get("fallback_model") or "").strip()
        if fallback_model:
            if not re.match(r"^[A-Za-z0-9._:\-/]{1,100}$", fallback_model):
                raise HTTPException(400, "fallback_model contains invalid characters")
            cfg["fallback_model"] = fallback_model
        else:
            cfg.pop("fallback_model", None)  # explicit clear → fall back to default

    openai_summary.write_ai_config(cfg)
    return {"ok": True}


def read_nvd_config() -> dict:
    """Remove legacy file keys; NVD authentication is environment-only."""
    if api_main.NVD_CONFIG_FILE.exists():
        try:
            with open(api_main.NVD_CONFIG_FILE) as f:
                config = json.load(f)
            if not isinstance(config, dict):
                return {}
            if "api_key" in config:
                config.pop("api_key", None)
                write_nvd_config(config)
            return config
        except Exception:
            return {}
    return {}


def write_nvd_config(cfg: dict):
    """Write non-secret NVD preferences only."""
    safe_config = {key: value for key, value in cfg.items() if key != "api_key"}
    api_main.NVD_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(api_main.NVD_CONFIG_FILE, "w") as f:
        json.dump(safe_config, f, indent=2)
    api_main.NVD_CONFIG_FILE.chmod(0o600)


@router.get("/api/nvd/config")
def nvd_config_get(response: Response):
    api_main._sec_headers(response)
    read_nvd_config()
    env_key = os.getenv("NVD_API_KEY", "")
    return {
        "key_set": bool(env_key),
        "from_env": bool(env_key),
    }


@router.post("/api/nvd/config")
async def nvd_config_post(request: Request, response: Response):
    api_main._sec_headers(response)
    api_main._audit(request, "nvd_config_changed")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if "api_key" in body:
        raise HTTPException(400, "NVD API keys cannot be set in the UI; use NVD_API_KEY")
    return {"ok": True}


# ── Scan concurrency ──────────────────────────────────────────

def _concurrency_payload() -> dict:
    active = [j for j in job_store.jobs.values()]
    return {
        "max_concurrent_scans": job_store._max_concurrent(),
        "source": job_store.concurrency_source(),
        "default": job_store.DEFAULT_MAX_CONCURRENT,
        "ceiling": job_store.MAX_CONCURRENT_CEILING,
        "running": sum(1 for j in active if j.get("status") == "running"),
        "queued": sum(1 for j in active if j.get("status") == "queued"),
    }


@router.get("/api/settings/scan-concurrency")
def scan_concurrency_get(response: Response):
    api_main._sec_headers(response)
    return _concurrency_payload()


@router.post("/api/settings/scan-concurrency")
async def scan_concurrency_post(request: Request, response: Response):
    api_main._sec_headers(response)
    api_main._audit(request, "scan_concurrency_changed")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    value = body.get("max_concurrent_scans") if isinstance(body, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= job_store.MAX_CONCURRENT_CEILING:
        raise HTTPException(400, f"max_concurrent_scans must be an integer from 1 to {job_store.MAX_CONCURRENT_CEILING}")
    job_store.save_max_concurrent(value)
    await job_store.wake_queue()
    return _concurrency_payload()


# Mirrors the togglable layer numbers in
# tests/fixtures/self-assessment/expected-findings.json (Layer 3/SonarQube
# and Layer 20/ML-Runtime are intentionally excluded — never run by the
# harness regardless of selection).
_SELF_ASSESSMENT_VALID_LAYERS = {
    "1", "2", "4", "5", "6", "7", "8", "8.5", "9", "10", "11",
    "13", "14", "15", "16", "18", "19", "21",
}


class SelfAssessmentRunRequest(BaseModel):
    layers: Optional[list[str]] = None


@router.post("/api/self-assessment/run", status_code=202)
async def trigger_self_assessment(body: SelfAssessmentRunRequest, request: Request, response: Response):
    """Kick off scripts/shell/run-self-assessment.sh as a background job so
    the Performance page's "Run Self-Diagnostic" button can show live
    step-by-step progress (via GET /api/jobs/{job_id}) and then refresh
    GET /api/metrics/self-assessment for the final per-layer verdict.

    `body.layers`, if given, restricts the run to only those manifest layer
    numbers (e.g. ["1", "2", "7", "8", "8.5"]) so a user can validate a
    subset of scanners instead of the full 21-layer run. Unknown values are
    rejected (400) rather than silently ignored."""
    api_main._sec_headers(response)
    layers = body.layers
    if layers:
        invalid = [l for l in layers if l not in _SELF_ASSESSMENT_VALID_LAYERS]
        if invalid:
            raise HTTPException(400, f"Unknown self-assessment layer(s): {', '.join(invalid)}")
    # Only one self-assessment run at a time — it drives a real full scan
    # plus pip-audit, so overlapping runs would race on the same scan
    # directory naming and Docker/tool locks.
    for existing in job_store.jobs.values():
        if existing.get("target") == "self-assessment" and existing["status"] in ("queued", "running"):
            return {"job_id": existing["job_id"], "status": existing["status"], "already_running": True}

    script_path = api_main.SCRIPTS_DIR / "run-self-assessment.sh"
    if not script_path.exists():
        raise HTTPException(500, "run-self-assessment.sh not found")

    job_id = job_store.new_job_id()
    api_main._audit(request, "self_assessment_triggered", ",".join(layers) if layers else "all")
    job = job_store.create_job(job_id, "self-assessment", "self-assessment")
    asyncio.create_task(job_store.run_self_assessment_job(job_id, script_path, api_main.EPYON_ROOT, layers))
    return {"job_id": job_id, "status": "queued"}


# ── Stats ─────────────────────────────────────────────────────

@router.get("/api/stats")
def stats(response: Response):
    now = time.monotonic()
    
    # Return cached stats if available
    if cache_state.stats and (now - cache_state.stats[1]) < api_main._STATS_CACHE_TTL:
        age = now - cache_state.stats[1]
        api_main._cache_metrics["hits"]["stats"] += 1
        api_main._cache_metrics_logger.debug(f"cache_read source=memory endpoint=stats hit=true age_seconds={age:.1f}")
        result = cache_state.stats[0]
        # Allow browser caching for 60s
        response.headers["Cache-Control"] = "public, max-age=60"
        response.headers["X-Cache-Version"] = str(cache_state.version)
        return result
    
    api_main._cache_metrics["misses"]["stats"] += 1
    api_main._cache_metrics_logger.debug("cache_read source=memory endpoint=stats hit=false")
    api_main._sec_headers(response)
    hidden = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    # Overview counts only continuously monitored apps; evaluation apps are excluded.
    scans = [s for s in (api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs())
             if s["target"] in monitored and s["target"] not in hidden]
    by_target: dict[str, dict] = {}
    for s in scans:
        t = s["target"]
        if t not in by_target or s.get("timestamp", "") > by_target[t].get("timestamp", ""):
            by_target[t] = s
    latest = list(by_target.values())
    result = {
        "total_applications": len(by_target),
        "total_scans":        len(scans),
        "critical": sum(s["critical"] for s in latest),
        "high":     sum(s["high"]     for s in latest),
        "medium":   sum(s["medium"]   for s in latest),
        "low":      sum(s["low"]      for s in latest),
    }
    
    cache_state.stats = (result, now)
    api_main._cache_metrics["writes"]["stats"] += 1
    api_main._cache_metrics_logger.debug("cache_write endpoint=stats success=true")
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Cache-Version"] = str(cache_state.version)
    return result
