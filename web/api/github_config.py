"""Non-secret GitHub settings with environment-only authentication."""
from __future__ import annotations

import json
import os
from pathlib import Path


def _environment_token() -> str:
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_PAT") or "").strip()


def read_config(path: Path) -> dict:
    """Read repository preferences and overlay an environment-provided token."""
    config: dict = {}
    had_legacy_secrets = False
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            config = loaded
            had_legacy_secrets = "token" in config or "extra_tokens" in config
    except Exception:
        pass

    config.pop("token", None)
    config.pop("extra_tokens", None)
    if had_legacy_secrets:
        write_config(path, config)
    token = _environment_token()
    config["token"] = token
    config["_from_env"] = bool(token)
    return config


def write_config(path: Path, config: dict) -> None:
    """Persist GitHub repository preferences without credential material."""
    safe_config = {
        key: value
        for key, value in config.items()
        if key not in {"token", "extra_tokens", "_from_env"}
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(safe_config, indent=2), encoding="utf-8")
    path.chmod(0o600)