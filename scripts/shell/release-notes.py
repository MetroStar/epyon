#!/usr/bin/env python3
"""Release notes from pull request bodies (MID-4491).

Each pull request carries a "## Release notes" block with ### headings
(Added, Changed, Fixed, Removed, Security, Deprecated) and bullets, or the
`no-release-notes` label. Two subcommands:

  check-pr --event PATH          fail unless the PR has a valid block or the label
  body --repo OWNER/REPO --tag vX.Y.Z [--prev vX.Y.Y] [--head REF]
                                 print the release body for the PRs in the tag range

`body` reads the GitHub API with GITHUB_TOKEN. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

KINDS = ("Added", "Changed", "Fixed", "Removed", "Security", "Deprecated")
SKIP_LABEL = "no-release-notes"
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+Release notes\s*$", re.IGNORECASE | re.MULTILINE)
_NEXT_H2_RE = re.compile(r"^##\s+\S", re.MULTILINE)
_H3_RE = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)
_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")


def extract_notes(body: str | None) -> dict[str, list[str]]:
    """Return {kind: [bullet, ...]} from a PR body; empty when there is no valid block."""
    text = _COMMENT_RE.sub("", (body or "").replace("\r\n", "\n"))
    start = _SECTION_RE.search(text)
    if not start:
        return {}
    rest = text[start.end():]
    end = _NEXT_H2_RE.search(rest)
    block = rest[: end.start()] if end else rest
    notes: dict[str, list[str]] = {}
    headings = list(_H3_RE.finditer(block))
    for i, heading in enumerate(headings):
        kind = next((k for k in KINDS if k.lower() == heading.group(1).strip().lower()), None)
        if not kind:
            continue
        stop = headings[i + 1].start() if i + 1 < len(headings) else len(block)
        bullets = [
            line.strip()[2:].strip()
            for line in block[heading.end():stop].splitlines()
            if re.match(r"^\s*[-*]\s+\S", line)
        ]
        if bullets:
            notes.setdefault(kind, []).extend(bullets)
    return notes


def check_pr(body: str | None, labels: list[str]) -> str | None:
    """Return an error message when the PR records no release notes, else None."""
    if SKIP_LABEL in labels:
        return None
    if extract_notes(body):
        return None
    return (
        "This pull request has no release notes. Add a '## Release notes' section with at "
        f"least one bullet under a heading ({', '.join('### ' + k for k in KINDS)}), "
        f"or apply the '{SKIP_LABEL}' label if nothing ships to a release reader."
    )


def render_body(prs: list[dict], tag: str, prev: str | None) -> str:
    """Assemble the release body from PR dicts with number, title, body and labels."""
    merged: dict[str, list[str]] = {}
    for pr in sorted(prs, key=lambda p: p["number"]):
        for kind, bullets in extract_notes(pr.get("body")).items():
            for bullet in bullets:
                merged.setdefault(kind, []).append(f"{bullet} (#{pr['number']})")
    if not merged:
        return f"No release notes were recorded for {tag}.\n"
    lines = [f"## {tag}", ""]
    if prev:
        lines += [f"Changes since {prev}.", ""]
    for kind in KINDS:
        if kind in merged:
            lines += [f"### {kind}", ""] + [f"- {b}" for b in merged[kind]] + [""]
    return "\n".join(lines)


def _api(path: str, token: str) -> list | dict:
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        return json.load(resp)


def prs_in_range(repo: str, prev: str, tag: str, token: str) -> list[dict]:
    """Merged PRs whose commits are in prev..tag."""
    commits: list[dict] = []
    page = 1
    while True:
        batch = _api(
            f"repos/{repo}/compare/{prev}...{tag}?per_page=100&page={page}", token
        )["commits"]
        commits.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    prs: dict[int, dict] = {}
    for commit in commits:
        for pr in _api(f"repos/{repo}/commits/{commit['sha']}/pulls", token):
            if pr.get("merged_at"):
                prs[pr["number"]] = {
                    "number": pr["number"],
                    "title": pr["title"],
                    "body": pr.get("body") or "",
                    "labels": [label["name"] for label in pr.get("labels", [])],
                }
    return list(prs.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check-pr")
    chk.add_argument("--event", required=True, type=Path)
    bod = sub.add_parser("body")
    bod.add_argument("--repo", required=True)
    bod.add_argument("--tag", required=True)
    bod.add_argument("--prev", default="")
    bod.add_argument("--head", default="", help="git ref to compare to (default: the tag; use for dry runs)")
    args = parser.parse_args(argv)

    if args.cmd == "check-pr":
        pr = json.loads(args.event.read_text(encoding="utf-8"))["pull_request"]
        error = check_pr(pr.get("body"), [label["name"] for label in pr.get("labels", [])])
        if error:
            print(f"::error::{error}")
            return 1
        print("Release notes present.")
        return 0

    if not _TAG_RE.fullmatch(args.tag) or (args.prev and not _TAG_RE.fullmatch(args.prev)):
        print("Tags must look like vX.Y.Z", file=sys.stderr)
        return 2
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    if not args.prev:
        sys.stdout.write(f"## {args.tag}\n\nFirst tagged release. Earlier history is in CHANGELOG.md.\n")
        return 0
    sys.stdout.write(render_body(prs_in_range(args.repo, args.prev, args.head or args.tag, token), args.tag, args.prev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
