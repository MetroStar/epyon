#!/usr/bin/env python3
"""End-of-life detection fallback that queries endoflife.date directly.

Used by run-xeol-scan.sh when the Xeol vulnerability database host is unreachable.
Checks runtimes and base images named in Dockerfiles / compose files and in the
CycloneDX SBOM, and writes results in the same shape Xeol uses (`matches[]` with
`artifact` and `cycle`) so the findings parser needs no changes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

API = "https://endoflife.date/api/v1/products/{product}/"
SKIP_DIRS = {".git", "node_modules", "scans", "tmp", "_archive", "tests", ".venv", "venv"}

# Docker image / SBOM component name -> endoflife.date product
PRODUCTS: Dict[str, str] = {
    "python": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "golang": "go",
    "go": "go",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "redis": "redis",
    "nginx": "nginx",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "ruby": "ruby",
    "php": "php",
    "tomcat": "tomcat",
    "alpine": "alpine-linux",
    "ubuntu": "ubuntu",
}

_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE)
_IMAGE_RE = re.compile(r"^\s*image:\s*['\"]?([^\s'\"#]+)")
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")


def fetch_product(product: str, timeout: int = 20) -> Optional[List[dict]]:
    """Return the release list for an endoflife.date product, or None on failure."""
    try:
        with urllib.request.urlopen(API.format(product=product), timeout=timeout) as resp:  # nosemgrep
            return json.load(resp).get("result", {}).get("releases", [])
    except Exception as exc:  # network, DNS, JSON
        print(f"  endoflife.date lookup failed for {product}: {exc}", file=sys.stderr)
        return None


def parse_image(ref: str) -> Optional[Tuple[str, str]]:
    """'registry/org/python:3.9-slim@sha256:..' -> ('python', '3.9')."""
    ref = ref.split("@", 1)[0]
    name, _, tag = ref.rpartition(":")
    if not name or "/" in tag:
        return None
    name = name.rsplit("/", 1)[-1].lower()
    m = _VERSION_RE.match(tag)
    if name not in PRODUCTS or not m:
        return None
    return name, m.group(1)


def iter_components(target: Path, scan_dir: Optional[Path]) -> Iterator[Tuple[str, str, str]]:
    """Yield (name, version, location) for every checkable component."""
    for path in target.rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(target).parts[:-1]):
            continue
        lowered = path.name.lower()
        if not (lowered.startswith("dockerfile") or lowered.endswith(("compose.yml", "compose.yaml"))):
            continue
        pattern = _FROM_RE if lowered.startswith("dockerfile") else _IMAGE_RE
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            m = pattern.match(line)
            parsed = parse_image(m.group(1)) if m else None
            if parsed:
                yield parsed[0], parsed[1], str(path.relative_to(target))

    if scan_dir and (scan_dir / "sbom").is_dir():
        for sbom in sorted((scan_dir / "sbom").glob("*.cyclonedx.json")):
            try:
                comps = json.loads(sbom.read_text()).get("components", [])
            except (OSError, ValueError):
                continue
            for comp in comps:
                name = (comp.get("name") or "").lower()
                m = _VERSION_RE.match(comp.get("version") or "")
                if name in PRODUCTS and m and comp.get("type") in ("application", "library"):
                    yield name, m.group(1), sbom.name


def find_release(releases: List[dict], version: str) -> Optional[dict]:
    parts = version.split(".")
    for n in range(min(len(parts), 3), 0, -1):
        cycle = ".".join(parts[:n])
        for rel in releases:
            if str(rel.get("name")) == cycle:
                return rel
    return None


def is_eol(release: dict, today: date) -> bool:
    eol_from = release.get("eolFrom")
    if eol_from:
        return eol_from <= today.isoformat()
    return bool(release.get("isEol"))


def build_matches(components, fetch=fetch_product, today: Optional[date] = None) -> Tuple[List[dict], int]:
    """Return (matches, products_that_failed_to_load)."""
    today = today or date.today()
    cache: Dict[str, Optional[List[dict]]] = {}
    matches: List[dict] = []
    seen = set()
    failed = 0
    for name, version, location in components:
        product = PRODUCTS[name]
        if product not in cache:
            cache[product] = fetch(product)
            failed += cache[product] is None
        releases = cache[product]
        release = find_release(releases, version) if releases else None
        if not release or not is_eol(release, today) or (name, version, location) in seen:
            continue
        seen.add((name, version, location))
        matches.append({
            "artifact": {"name": name, "version": version, "type": "eol-runtime",
                         "locations": [{"path": location}]},
            "cycle": {"eol": release.get("eolFrom") or "unknown",
                      "latest": (release.get("latest") or {}).get("name", "N/A")},
            "eolDate": release.get("eolFrom") or "unknown",
        })
    return matches, failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True)
    ap.add_argument("--scan-dir", default="")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    components = list(iter_components(Path(args.target), Path(args.scan_dir) if args.scan_dir else None))
    matches, failed = build_matches(components)
    Path(args.output).write_text(json.dumps({
        "matches": matches,
        "source": {"type": "endoflife.date-fallback", "target": args.target},
    }, indent=2))
    print(f"  checked {len(components)} components, {len(matches)} end-of-life, {failed} lookups failed")
    # Non-zero only when nothing could be checked at all, so the caller can report failure.
    return 1 if components and failed and failed == len({PRODUCTS[c[0]] for c in components}) else 0


if __name__ == "__main__":
    sys.exit(main())
