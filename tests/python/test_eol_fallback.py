import importlib.util
import json
from datetime import date
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "run_eol_fallback", Path(__file__).resolve().parents[2] / "scripts" / "shell" / "run-eol-fallback.py"
)
eol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(eol)

RELEASES = {
    "python": [
        {"name": "3.8", "eolFrom": "2024-10-07", "latest": {"name": "3.8.20"}},
        {"name": "3.12", "eolFrom": "2028-10-31", "latest": {"name": "3.12.9"}},
    ],
    "nodejs": [{"name": "16", "eolFrom": "2023-09-11", "latest": {"name": "16.20.2"}}],
}


def _run(tmp_path, dockerfile, scan_dir=None):
    (tmp_path / "Dockerfile").write_text(dockerfile)
    comps = list(eol.iter_components(tmp_path, scan_dir))
    return eol.build_matches(comps, fetch=RELEASES.get, today=date(2026, 11, 15))


def test_only_end_of_life_images_match(tmp_path):
    matches, failed = _run(tmp_path, "FROM python:3.8-slim AS a\nFROM docker.io/library/node:16.14-alpine\nFROM python:3.12\n")
    assert failed == 0
    assert {(m["artifact"]["name"], m["artifact"]["version"]) for m in matches} == {("python", "3.8"), ("node", "16.14")}
    assert matches[0]["cycle"] == {"eol": "2024-10-07", "latest": "3.8.20"}
    assert matches[0]["artifact"]["locations"] == [{"path": "Dockerfile"}]


def test_sbom_runtime_and_unreachable_lookups(tmp_path):
    sbom = tmp_path / "scan" / "sbom"
    sbom.mkdir(parents=True)
    (sbom / "x.cyclonedx.json").write_text(json.dumps({"components": [
        {"name": "python", "version": "3.8.10", "type": "application"},
        {"name": "requests", "version": "2.6.0", "type": "library"},
    ]}))
    (tmp_path / "t").mkdir()
    comps = list(eol.iter_components(tmp_path / "t", tmp_path / "scan"))
    assert [(c[0], c[1]) for c in comps] == [("python", "3.8.10")]
    matches, failed = eol.build_matches(comps, fetch=lambda p: None, today=date(2026, 11, 15))
    assert matches == [] and failed == 1
