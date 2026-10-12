#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
"""Build and test the actual Zig package after applying manifest .paths."""

import argparse
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def extract_regular_archive(archive, destination):
    """Extract regular source files into a new empty private directory.

    Python 3.11.2 in the CI image predates tarfile's extraction filters. Do not
    fall back to unrestricted extractall: validate the complete namespace first,
    reject links/special entries, and create files exclusively without restoring
    archive ownership or privileged mode bits.
    """
    destination = Path(destination)
    if (
        destination.is_symlink()
        or not destination.is_dir()
        or any(destination.iterdir())
    ):
        raise ValueError("source destination must be an empty real directory")
    members = {}
    for member in archive.getmembers():
        name = member.name.rstrip("/") if member.isdir() else member.name
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or str(path) != name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or "\\" in name
            or ":" in name
            or "\x00" in name
            or name in members
            or not (member.isdir() or member.isfile())
        ):
            raise ValueError("source archive contains an unsafe member")
        members[name] = member
    for name in members:
        for parent in PurePosixPath(name).parents:
            previous = members.get(str(parent))
            if previous is not None and not previous.isdir():
                raise ValueError("source archive file is also a parent")
    for name, member in members.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if member.isdir():
            target.mkdir(exist_ok=True)
            continue
        with archive.extractfile(member) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(member.mode & 0o777)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    root = Path(__file__).resolve().parents[1]
    zig = os.environ.get("ZIG", "zig")
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    with tempfile.TemporaryDirectory(prefix="tls-source-package-") as directory:
        temporary = Path(directory)
        archive = temporary / "source.tar.gz"
        # Use tracked working-tree bytes so this also checks staged local fixes.
        # Generated files and ignored build products cannot hide missing inputs.
        with tarfile.open(archive, "w:gz") as source:
            for name in tracked:
                if name:
                    relative = os.fsdecode(name)
                    source.add(root / relative, arcname=relative, recursive=False)
        # Zig fetch installs a local zig-pkg directory beside a build file.
        # Give it a disposable checkout so validation leaves source untouched.
        checkout = temporary / "checkout"
        checkout.mkdir()
        with tarfile.open(archive) as source:
            extract_regular_archive(source, checkout)
        cache = temporary / "cache"
        package_hash = subprocess.check_output(
            [zig, "fetch", "--global-cache-dir", str(cache), str(archive)],
            cwd=checkout,
            text=True,
        ).strip()
        if not re.fullmatch(r"tls-[A-Za-z0-9_.-]+", package_hash):
            raise RuntimeError("unexpected Zig package identifier")
        package_archive = cache / "p" / (package_hash + ".tar.gz")
        extracted = temporary / "extracted"
        extracted.mkdir()
        with tarfile.open(package_archive) as package:
            extract_regular_archive(package, extracted)
        package_root = extracted / package_hash
        print(f"Checking filtered source package {package_hash}", flush=True)
        for target in [[], ["test"], ["test-vectors"], ["test-conformance"]]:
            subprocess.run(
                [zig, "build", *target, f"-j{args.jobs}", "--summary", "all"],
                cwd=package_root,
                check=True,
            )


if __name__ == "__main__":
    main()
