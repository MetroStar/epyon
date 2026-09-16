"""Shared pytest fixtures for the Epyon Python test suite."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_SCAN_ROOT = REPO_ROOT / "tests" / "fixtures" / "golden-scan"
GOLDEN_SCAN_DIR = GOLDEN_SCAN_ROOT / "goldenapp_testuser_2026-09-16_12-00-00"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(autouse=True)
def isolated_ignore_cache(tmp_path, monkeypatch):
    """Keep tests off the machine-wide /tmp ignore cache so results are deterministic."""
    monkeypatch.setenv("IGNORE_CACHE", str(tmp_path / "epyon-ignore-cache.json"))


@pytest.fixture(scope="session")
def parsers():
    """The web API parsers module — the single source of truth for scan data."""
    return _load_module("epyon_parsers", REPO_ROOT / "web" / "api" / "parsers.py")


@pytest.fixture(scope="session")
def dashboard():
    """The offline dashboard generator module."""
    return _load_module(
        "epyon_generate_dashboard", REPO_ROOT / "scripts" / "shell" / "generate-dashboard.py"
    )


@pytest.fixture
def golden_scan_dir() -> Path:
    if not GOLDEN_SCAN_DIR.is_dir():
        pytest.skip(f"golden scan fixture missing: {GOLDEN_SCAN_DIR}")
    return GOLDEN_SCAN_DIR
