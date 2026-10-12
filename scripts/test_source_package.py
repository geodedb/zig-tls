#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Archive safety regressions, including the oldest CI Python runtime."""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from check_source_package import extract_regular_archive


def archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        for name, kind, mode in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = mode
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "../outside"
            if kind == tarfile.REGTYPE:
                member.size = 4
                output.addfile(member, io.BytesIO(b"test"))
            else:
                output.addfile(member)
    buffer.seek(0)
    return tarfile.open(fileobj=buffer, mode="r")


class SourceArchiveTest(unittest.TestCase):
    def test_regular_files_and_implicit_parents_preserve_execute_without_setid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with archive(
                [
                    ("pkg/bin/tool", tarfile.REGTYPE, 0o6755),
                    ("pkg/", tarfile.DIRTYPE, 0o777),
                    ("pkg/input", tarfile.REGTYPE, 0o644),
                ]
            ) as source:
                extract_regular_archive(source, root)
            self.assertEqual((root / "pkg/bin/tool").read_bytes(), b"test")
            self.assertEqual((root / "pkg/bin/tool").stat().st_mode & 0o7777, 0o755)
            self.assertEqual((root / "pkg/input").stat().st_mode & 0o777, 0o644)

    def test_unsafe_namespace_is_rejected_before_any_file_is_written(self):
        bad_entries = [
            ("../outside", tarfile.REGTYPE),
            ("/absolute", tarfile.REGTYPE),
            ("pkg/../../outside", tarfile.REGTYPE),
            ("pkg//file", tarfile.REGTYPE),
            ("pkg/./file", tarfile.REGTYPE),
            ("pkg\\file", tarfile.REGTYPE),
            ("C:/outside", tarfile.REGTYPE),
            ("C:outside", tarfile.REGTYPE),
            ("pkg/file:stream", tarfile.REGTYPE),
            (".", tarfile.DIRTYPE),
            ("pkg/link", tarfile.SYMTYPE),
            ("pkg/link", tarfile.LNKTYPE),
            ("pkg/pipe", tarfile.FIFOTYPE),
            ("pkg/device", tarfile.CHRTYPE),
        ]
        for name, kind in bad_entries:
            with (
                self.subTest(name=name, kind=kind),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                with (
                    archive(
                        [("good", tarfile.REGTYPE, 0o644), (name, kind, 0o644)]
                    ) as source,
                    self.assertRaises(ValueError),
                ):
                    extract_regular_archive(source, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_duplicate_and_file_parent_conflicts_are_rejected_before_writing(self):
        for names in [
            ("pkg/file", "pkg/file"),
            ("pkg", "pkg/file"),
            ("pkg/file", "pkg"),
        ]:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with (
                    archive(
                        [(name, tarfile.REGTYPE, 0o644) for name in names]
                    ) as source,
                    self.assertRaises(ValueError),
                ):
                    extract_regular_archive(source, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_preexisting_destination_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "existing").write_bytes(b"unchanged")
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            for destination in [root, link]:
                with (
                    archive([("existing", tarfile.REGTYPE, 0o644)]) as source,
                    self.assertRaises(ValueError),
                ):
                    extract_regular_archive(source, destination)
            self.assertEqual((root / "existing").read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
