"""Keep scanned ML dependency fixtures outside known vulnerable versions."""

from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/pip-audit"


def test_transformers_fixture_versions_are_outside_known_vulnerable_range():
    # CVE-2026-80047 affects Transformers through 5.16.1.
    for fixture in ("clean-ml", "typosquat-ml"):
        requirements = (FIXTURES / fixture / "requirements.txt").read_text().splitlines()
        pins = [
            line.partition("==")[2]
            for line in requirements
            if line.lower().startswith("transformers==")
        ]
        assert len(pins) == 1, f"{fixture} should pin Transformers exactly once"
        version = tuple(int(part) for part in pins[0].split("."))
        assert version >= (5, 17, 0), f"{fixture} has vulnerable Transformers {pins[0]}"
