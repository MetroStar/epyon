#!/usr/bin/env python3
"""Validate an external OCI build against the checked-out source and capture evidence."""

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path


def capture(archive: Path, target: Path, output: Path, oci_layout: Path | None = None) -> None:
    revision = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
    ).strip()
    with tarfile.open(archive) as bundle:
        def read(name: str) -> bytes:
            member = bundle.getmember(name)
            if not member.isfile():
                raise ValueError(f"OCI member is not a regular file: {name}")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError(f"Cannot read OCI member: {name}")
            return stream.read()

        def blob(descriptor: dict) -> bytes:
            digest = descriptor["digest"]
            algorithm, value = digest.split(":", 1)
            if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"Unsupported OCI digest: {digest}")
            body = read("blobs/sha256/" + value)
            if hashlib.sha256(body).hexdigest() != value or len(body) != descriptor["size"]:
                raise ValueError(f"OCI digest or size mismatch: {digest}")
            return body

        index = json.loads(read("index.json"))
        if len(index["manifests"]) != 1:
            raise ValueError("Supply exactly one OCI image for this platform")
        descriptor = index["manifests"][0]
        manifest_bytes = blob(descriptor)
        manifest = json.loads(manifest_bytes)
        config = json.loads(blob(manifest["config"]))
        if config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != revision:
            raise ValueError("OCI image source revision does not match the checked-out target")
        if not manifest.get("layers"):
            raise ValueError("OCI image contains no layers")
        for layer in manifest["layers"]:
            blob(layer)

        if oci_layout is not None:
            if oci_layout.exists() and any(oci_layout.iterdir()):
                raise ValueError("OCI layout destination must be empty")
            (oci_layout / "blobs" / "sha256").mkdir(parents=True)
            for item in [descriptor, manifest["config"], *manifest["layers"]]:
                (oci_layout / "blobs" / "sha256" / item["digest"].split(":")[1]).write_bytes(blob(item))
            (oci_layout / "index.json").write_text(json.dumps(index))
            (oci_layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')

    output.mkdir(parents=True, exist_ok=True)
    (output / "oci-manifest.json").write_bytes(manifest_bytes)
    (output / "image-digest.txt").write_text(descriptor["digest"] + "\n")
    (output / "build-summary.json").write_text(json.dumps({
        "status": "success",
        "mode": "container_build",
        "runtime": "external_oci_builder",
        "full_image": "oci-archive:" + str(archive.resolve()),
        "digest": descriptor["digest"],
        "source_revision": revision,
        "target_dir": str(target.resolve()),
    }, indent=2))
    print(f"Validated external OCI build {descriptor['digest']} for source {revision}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--oci-layout", type=Path, help="Materialize verified OCI blobs into an empty directory")
    args = parser.parse_args()
    try:
        capture(args.archive, args.target, args.output, args.oci_layout)
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"External OCI build validation failed: {error}") from error
