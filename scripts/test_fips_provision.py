#!/usr/bin/env python3
"""Test the real Zig provisioning graph using an isolated installer fixture.

The provider package is fetched and hash-verified before copying it. Only its
installer is replaced to observe invocation, environment, and exit propagation;
cryptographic/provider acceptance is covered by the clean test-fips CI job.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
ZIG = os.environ.get("ZIG", "zig")
FIPS_ENTRY = re.compile(r"        \.fips = \.\{.*?\n        \},", re.DOTALL)


def tracked_files(root):
    # CI may mount a checkout owned by a different user. Trust only this
    # canonical checkout for this read; never persist or use wildcard trust.
    root = root.resolve()
    return (
        subprocess.check_output(
            ["git", "-c", f"safe.directory={root}", "ls-files", "-z"], cwd=root
        )
        .decode()
        .split("\0")[:-1]
    )


class CheckoutFilesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="tls-checkout-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.global_config = self.root / "gitconfig"
        self.global_config.write_text("# Must remain unchanged.\n")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        env.update(
            HOME=str(self.root),
            GIT_CONFIG_GLOBAL=str(self.global_config),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_TEST_ASSUME_DIFFERENT_OWNER="1",
        )
        patch = mock.patch.dict(os.environ, env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.repo = self.make_repo("runner checkout")
        self.sibling = self.make_repo("unrelated checkout")

    def make_repo(self, name):
        repo = self.root / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for filename in ["tracked fixture.txt", "line\nbreak.txt", "untracked.txt"]:
            (repo / filename).write_text("fixture\n")
        subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={repo.resolve()}",
                "add",
                "--",
                "tracked fixture.txt",
                "line\nbreak.txt",
            ],
            cwd=repo,
            check=True,
        )
        return repo

    def assert_untrusted(self, repo):
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"dubious ownership", result.stderr)

    def test_different_owner_checkout_lists_only_tracked_files(self):
        self.assert_untrusted(self.repo)
        self.assertCountEqual(
            tracked_files(self.repo), ["tracked fixture.txt", "line\nbreak.txt"]
        )

    def test_checkout_trust_does_not_persist_or_trust_siblings(self):
        before = (
            self.global_config.read_bytes(),
            (self.repo / ".git/config").read_bytes(),
        )
        self.assertTrue(tracked_files(self.repo))
        self.assert_untrusted(self.repo)
        self.assert_untrusted(self.sibling)
        self.assertEqual(
            before,
            (self.global_config.read_bytes(), (self.repo / ".git/config").read_bytes()),
        )

    def test_checkout_path_is_canonicalized(self):
        alias = self.root / "checkout alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        self.assertCountEqual(
            tracked_files(alias), ["tracked fixture.txt", "line\nbreak.txt"]
        )


class ProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="tls-fips-provision-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.manifest = (ROOT / "build.zig.zon").read_text()
        entry = FIPS_ENTRY.search(cls.manifest)
        if entry is None:
            raise AssertionError("published FIPS dependency is missing")
        url = re.search(r'\.url = "([^"]+)"', entry[0])[1]
        expected_hash = re.search(r'\.hash = "([^"]+)"', entry[0])[1]
        fetch_cache = cls.root / "fetch-cache"
        fetched = subprocess.run(
            [ZIG, "fetch", "--global-cache-dir", str(fetch_cache), url],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=True,
        ).stdout.strip()
        if fetched != expected_hash:
            raise AssertionError(f"FIPS package hash mismatch: {fetched}")
        # Zig 0.16 materializes packages in the build root's zig-pkg directory;
        # --global-cache-dir controls compilation/download metadata, not this.
        cls.package = ROOT / "zig-pkg" / expected_hash
        cls.files = tracked_files(ROOT)

    def setUp(self):
        self.case = self.root / self.id().rsplit(".", 1)[-1]
        self.repo = self.case / "tls"
        self.repo.mkdir(parents=True)
        for name in self.files:
            if not name or not (ROOT / name).is_file():
                continue
            destination = self.repo / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.fips = self.case / "resolved-provider"
        shutil.copytree(self.package, self.fips)
        self.installer = self.fips / "scripts/install-openssl-fips.sh"
        self.installer.write_text(
            "#!/bin/bash\nset -eu\n"
            'printf "%s\\n" "$OPENSSL_PREFIX" "$REQUIRE_GPG" >> "$PROVISION_TRACE"\n'
            'exit "${PROVISION_EXIT:-0}"\n'
        )
        self.trace = self.case / "installer.trace"
        self.prefix = self.case / "provider output"
        self.env = dict(os.environ, PROVISION_TRACE=str(self.trace), REQUIRE_GPG="0")
        self.set_entry('.path = "../resolved-provider", .lazy = true,')

    def set_entry(self, fields):
        replacement = (
            "" if fields is None else "        .fips = .{ " + fields + "\n        },"
        )
        changed, count = FIPS_ENTRY.subn(replacement, self.manifest)
        self.assertEqual(count, 1)
        (self.repo / "build.zig.zon").write_text(changed)

    def run_build(self, *args):
        return subprocess.run(
            [
                ZIG,
                "build",
                *args,
                "-Dfips=true",
                f"-Dopenssl_path={self.prefix}",
                "-j2",
            ],
            cwd=self.repo,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    def assert_stopped_before_installer(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.prefix.exists())

    def test_missing_dependency_stops_provisioning(self):
        self.set_entry(None)
        self.assert_stopped_before_installer(self.run_build("provision-fips"))

    def test_invalid_hash_stops_provisioning(self):
        self.set_entry(
            '.url = "git+https://gitlab.com/devnw/zig/fips.git", '
            '.hash = "invalid-package-hash", .lazy = true,'
        )
        self.assert_stopped_before_installer(self.run_build("provision-fips"))

    def test_missing_installer_stops_provisioning(self):
        self.installer.unlink()
        result = self.run_build("provision-fips")
        self.assert_stopped_before_installer(result)
        self.assertIn("install-openssl-fips.sh", result.stderr)

    def test_installer_failure_propagates_and_forces_signature_verification(self):
        self.env["PROVISION_EXIT"] = "73"
        result = self.run_build("provision-fips")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("73", result.stderr)
        self.assertEqual(self.trace.read_text().splitlines(), [str(self.prefix), "1"])
        self.assertFalse((self.case / "fips").exists(), "no sibling FIPS checkout")

    def test_successful_provisioning_runs_on_each_explicit_invocation(self):
        for _ in range(2):
            result = self.run_build("provision-fips")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.trace.read_text().splitlines(), [str(self.prefix), "1"] * 2
        )

    def test_inspecting_build_graph_does_not_run_installer(self):
        result = self.run_build("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("provision-fips", result.stdout)
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
