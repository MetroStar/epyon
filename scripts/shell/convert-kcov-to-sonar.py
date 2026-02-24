#!/usr/bin/env python3
"""
Convert kcov Cobertura XML to SonarCloud Generic Coverage XML format.

kcov produces a Cobertura-compatible cobertura.xml after instrumenting bash scripts.
SonarCloud's generic coverage format is simpler and is what sonar.coverageReportPaths
expects for shell/other language coverage.

Usage:
    python3 convert-kcov-to-sonar.py <cobertura.xml> <sonar-coverage.xml> [repo-root]

Arguments:
    cobertura.xml        Path to kcov's output cobertura.xml
    sonar-coverage.xml   Destination path for SonarCloud generic coverage XML
    repo-root            (Optional) Repo root to make file paths relative.
                         Auto-detected from <sources> or output path if omitted.
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def find_repo_root(cobertura_root: ET.Element, output_path: str) -> str | None:
    """
    Determine the repo root used to make file paths relative.

    Priority:
    1. <sources><source> element from kcov output.
       kcov sets this to the --include-path value (e.g. /repo/scripts/shell).
       Walk up until we find the repo root (parent of 'scripts').
    2. Derive from output_path: output is "$REPO_PATH/coverage/sonar-coverage.xml"
       so repo root = parent of parent of output_path.
    """
    sources_el = cobertura_root.find("sources/source")
    if sources_el is not None and sources_el.text and sources_el.text.strip():
        src = Path(sources_el.text.strip())
        # Walk up to find a directory that contains "scripts/" or known repo markers
        candidate = src
        for _ in range(5):
            if (candidate / "scripts").is_dir() or (candidate / ".git").is_dir():
                return str(candidate)
            candidate = candidate.parent
        # Fallback: assume include-path is scripts/shell, so go up two levels
        return str(src.parent.parent)

    # Derive from output path: coverage/sonar-coverage.xml → ../../
    if output_path:
        return str(Path(output_path).resolve().parent.parent)

    return None


def make_relative(filepath: str, repo_root: str | None) -> str:
    """Return filepath relative to repo_root, or stripped of leading slash."""
    if not repo_root:
        return filepath.lstrip("/")
    try:
        return str(Path(filepath).relative_to(repo_root))
    except ValueError:
        # Manual strip as a last resort
        norm_root = repo_root.rstrip("/") + "/"
        if filepath.startswith(norm_root):
            return filepath[len(norm_root):]
        return filepath.lstrip("/")


def convert(input_path: str, output_path: str, repo_root: str | None = None) -> int:
    """Parse cobertura.xml and write SonarCloud generic coverage XML."""
    try:
        tree = ET.parse(input_path)
    except ET.ParseError as exc:
        print(f"[ERROR] Cannot parse {input_path}: {exc}", file=sys.stderr)
        return 1

    cobertura = tree.getroot()

    if repo_root is None:
        repo_root = find_repo_root(cobertura, output_path)

    print(f"[INFO] Repo root resolved to: {repo_root}")

    # kcov sets <sources><source> to the --include-path value (e.g. /repo/scripts/shell).
    # When filenames in <class> elements are bare names (not absolute), they must be
    # resolved relative to this source directory before making them relative to repo_root.
    include_path: str | None = None
    sources_el = cobertura.find("sources/source")
    if sources_el is not None and sources_el.text and sources_el.text.strip():
        include_path = sources_el.text.strip()

    xml_lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<coverage version="1">',
    ]

    files_written = 0
    lines_total = 0

    for cls in cobertura.iter("class"):
        filename = (cls.get("filename") or "").strip()
        if not filename:
            continue

        # Resolve bare / relative filenames against the kcov include-path so that
        # make_relative can produce a proper repo-root-relative path
        # (e.g. "export-api-discovery.sh" → "scripts/shell/export-api-discovery.sh").
        if not Path(filename).is_absolute() and include_path:
            filename = str(Path(include_path) / filename)

        rel = make_relative(filename, repo_root)

        line_elems = cls.findall("lines/line")
        if not line_elems:
            continue

        xml_lines.append(f'  <file path="{rel}">')
        for line_el in line_elems:
            num = line_el.get("number", "0")
            hits = int(line_el.get("hits", "0"))
            covered = "true" if hits > 0 else "false"
            xml_lines.append(
                f'    <lineToCover lineNumber="{num}" covered="{covered}"/>'
            )
            lines_total += 1
        xml_lines.append("  </file>")
        files_written += 1

    xml_lines.append("</coverage>")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("\n".join(xml_lines) + "\n", encoding="utf-8")

    print(f"[OK] SonarCloud coverage XML written: {output_path}")
    print(f"[INFO] Files instrumented : {files_written}")
    print(f"[INFO] Line entries written: {lines_total}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <cobertura.xml> <sonar-coverage.xml> [repo-root]",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(
        convert(
            sys.argv[1],
            sys.argv[2],
            sys.argv[3] if len(sys.argv) > 3 else None,
        )
    )
