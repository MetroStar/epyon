# Release Checklist

Steps to publish an Epyon release. The model follows MIDAS: a release is a git
tag on `main` that publishes a GitHub Release with generated notes and
verifiable artifacts (MID-4491).

## Pre-release

1. Ensure `main` is green (CI passes).
2. Review the pull requests merged since the last tag:
   `git log --oneline vPREV..origin/main`.
3. Pick `X.Y.Z` from those pull requests: `PATCH` for fixes and docs, `MINOR` for
   backward-compatible features, `MAJOR` for breaking changes to the CLI, scan
   output schema or workflow contract.
4. Confirm the `VERSION` file on `main` already equals `X.Y.Z` (it is bumped in
   each pull request, together with `CHANGELOG.md` and `README.md`). The release
   workflow fails when the tag and `VERSION` disagree.
5. Optional dry run (builds and verifies, creates no release):
   ```
   gh workflow run release.yml -R MetroStar/epyon --ref main -f dry_run=true
   ```

## Tagging

A release is an annotated tag on `main`. There is no release branch or release
pull request.

```
git fetch origin
git tag -a vX.Y.Z -m vX.Y.Z origin/main
git push origin vX.Y.Z
```

## GitHub Release

The tag push runs `.github/workflows/release.yml`, which verifies the tag, builds
`epyon-X.Y.Z.tar.gz` (the repository at the tag), generates a CycloneDX SBOM
(`epyon-X.Y.Z.cdx.json`), writes a `.sha256` sidecar for each, and publishes the
release. Nothing is attached by hand.

The release body is assembled by `scripts/shell/release-notes.py` from the
`## Release notes` block of each pull request merged between the previous tag and
this one. The first tag has no previous tag, so its body points to `CHANGELOG.md`.

### Verify the release

1. Confirm the run succeeded and the assets are listed:
   ```
   gh release view vX.Y.Z -R MetroStar/epyon --json assets -q '.assets[].name'
   ```
2. Download the archive and its sidecar into a new directory and check the digest:
   ```bash
   TAG=vX.Y.Z
   ASSET=epyon-X.Y.Z.tar.gz
   VERIFY_DIR=$(mktemp -d)
   gh release download "$TAG" -R MetroStar/epyon \
       --pattern "$ASSET" --pattern "$ASSET.sha256" --dir "$VERIFY_DIR" &&
     (cd "$VERIFY_DIR" && shasum -a 256 --check "$ASSET.sha256")
   ```
   Stop on a mismatch.
3. Retain the tag, source commit, release run id and verified digest on the
   release ticket.

## Recovery

If the release run fails, fix the cause and re-run the same tagged run
(`gh run rerun <run id>`). Do not move a tag that has a published release. If the
tag and `VERSION` disagree and nothing was published, delete the tag
(`git push origin :refs/tags/vX.Y.Z`), correct `VERSION` through a pull request and
tag again.

## Pull request release notes

Every pull request needs a `## Release notes` block (the pull request template has
one) with a bullet under at least one of `### Added`, `### Changed`, `### Fixed`,
`### Removed`, `### Security` or `### Deprecated`, or the `no-release-notes` label.
The `Release notes` check reports a missing block. It is advisory for now: it is
not a required status check in branch protection.

## Pinning Epyon in a target repository

Pinning the reusable workflow to a release tag or commit SHA pins the workflow
definition, not necessarily the scanner implementation:

```yaml
jobs:
  security-scan:
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@vX.Y.Z
    # or: ...epyon-scan.yml@<full commit SHA> # vX.Y.Z
```

The current workflow separately checks out the scanner from `main` and reads
`VERSION` from that checkout. As a result, the scanner code and reported version
can change as `main` advances, regardless of the workflow ref above. A tag or
SHA pin alone therefore does not guarantee a fixed scanner version.
