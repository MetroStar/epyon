"""Mutable cache values shared by main.py and the routers.

Rebinding a module-level name in main.py (``global x; x = ...``) is invisible to
other modules that read it as ``api_main.x`` only by luck of attribute lookup,
and it forces every endpoint that writes a cache to stay in main.py. Keeping the
values here as attributes lets any module read and write them.
"""
from __future__ import annotations

metrics: dict = {}
metrics_ts: float = 0.0
gh_metrics: dict = {}
gh_metrics_ts: float = 0.0
stats: tuple[dict, float] | None = None
apps: tuple[list, float] | None = None
mobile_code_accuracy: tuple[dict, float] | None = None
version: int = 0  # Increment on scan completion to bust frontend caches
