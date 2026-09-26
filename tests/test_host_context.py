"""Trusted host context: who owns the physical facts, and who never does."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from permission_slip.doctrine import load_doctrine
from permission_slip.host_context import (
    DEFAULT_TEST_PROFILES,
    HostContextError,
    TrustedHostContext,
    command_digest,
)
from tests.support import (
    CANONICAL_IDENTITY,
    EVIL_REMOTE_URL,
    add_remote,
    init_git_repo,
    set_remote_url,
)

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")


class TrustedContextCreationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-hostctx-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_create_validates_a_real_checkout_with_a_canonical_destination(self):
        repo = init_git_repo(self.root / "repo")
        context = TrustedHostContext.create(repo_root=repo, doctrine=DOCTRINE)
        self.assertTrue(context.verified_checkout)
        self.assertEqual(context.canonical_repository, CANONICAL_IDENTITY)
        self.assertEqual(context.repo_root, repo.resolve())

    def test_a_plain_directory_is_not_a_checkout(self):
        plain = self.root / "plain"
        plain.mkdir()
        with self.assertRaises(HostContextError) as caught:
            TrustedHostContext.create(repo_root=plain, doctrine=DOCTRINE)
        self.assertIn("not a Git checkout", str(caught.exception))

    def test_a_missing_root_is_refused(self):
        with self.assertRaises(HostContextError):
            TrustedHostContext.create(repo_root=self.root / "nope", doctrine=DOCTRINE)

    def test_a_non_canonical_remote_is_refused(self):
        repo = init_git_repo(self.root / "repo")
        set_remote_url(repo, "origin", EVIL_REMOTE_URL)
        with self.assertRaises(HostContextError) as caught:
            TrustedHostContext.create(repo_root=repo, doctrine=DOCTRINE)
        self.assertIn("not a recognised canonical GitHub repository", str(caught.exception))

    def test_a_second_remote_pointing_elsewhere_is_refused(self):
        repo = init_git_repo(self.root / "repo")
        add_remote(repo, "other", "https://github.com/someone-else/repo.git")
        with self.assertRaises(HostContextError):
            TrustedHostContext.create(repo_root=repo, doctrine=DOCTRINE)

    def test_a_repository_with_no_remote_is_refused(self):
        repo = self.root / "bare"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        with self.assertRaises(HostContextError):
            TrustedHostContext.create(repo_root=repo, doctrine=DOCTRINE)

    def test_normalisation_context_does_not_probe_git(self):
        plain = self.root / "plain"
        plain.mkdir()
        context = TrustedHostContext.for_normalisation(repo_root=plain, doctrine=DOCTRINE)
        self.assertFalse(context.verified_checkout)
        # ...and the real executor will not accept it.
        from permission_slip.host_executor import RealHostExecutor

        with self.assertRaises(HostContextError):
            RealHostExecutor(context, recorder=_WritableRecorder())


class ResourceMappingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-hostmap-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = init_git_repo(Path(self.tmp.name) / "repo")
        self.context = TrustedHostContext.create(repo_root=self.repo, doctrine=DOCTRINE)

    def test_prefix_sits_inside_the_doctrine_root_scope(self):
        self.assertTrue(self.context.resource_prefix.startswith(self.context.root_scope))
        self.assertEqual(
            self.context.resource_prefix,
            "runtime/spike-workspace/repos/permission-slip/",
        )

    def test_an_in_checkout_file_maps_to_the_scoped_identity(self):
        authority = self.context.authority_path(self.repo / "permission_slip" / "actions.py")
        self.assertEqual(
            authority, "runtime/spike-workspace/repos/permission-slip/permission_slip/actions.py"
        )
        self.assertEqual(self.context.physical_path(authority), (self.repo / "permission_slip" / "actions.py").resolve())

    def test_a_relative_request_is_relative_to_the_root_not_the_cwd(self):
        authority = self.context.authority_path("README.md")
        self.assertEqual(
            authority, "runtime/spike-workspace/repos/permission-slip/README.md"
        )

    def test_an_escaping_path_is_never_made_in_scope(self):
        authority = self.context.authority_path(self.root_escape)
        self.assertFalse(authority.startswith(self.context.resource_prefix))
        self.assertTrue(authority.startswith("..") or authority.startswith("/"))

    @property
    def root_escape(self) -> Path:
        return Path(self.tmp.name) / "outside.txt"

    def test_physical_path_refuses_a_foreign_prefix(self):
        with self.assertRaises(HostContextError):
            self.context.physical_path("runtime/spike-workspace/elsewhere/thing.txt")

    def test_physical_path_refuses_traversal(self):
        with self.assertRaises(HostContextError):
            self.context.physical_path(self.context.resource_prefix + "../../escape.txt")

    def test_physical_path_refuses_the_root_itself(self):
        with self.assertRaises(HostContextError):
            self.context.physical_path(self.context.resource_prefix)

    def test_mapping_is_immutable(self):
        with self.assertRaises(Exception):
            self.context.resource_prefix = "somewhere/else/"  # type: ignore[misc]

    def test_digest_covers_the_trusted_facts_and_is_stable(self):
        again = TrustedHostContext.create(repo_root=self.repo, doctrine=DOCTRINE)
        self.assertEqual(self.context.digest(), again.digest())
        self.assertRegex(self.context.digest(), r"^sha256:[0-9a-f]{64}$")
        moved = TrustedHostContext.create(
            repo_root=init_git_repo(Path(self.tmp.name) / "other"), doctrine=DOCTRINE
        )
        self.assertNotEqual(self.context.digest(), moved.digest())


class TestProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-hostprof-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = init_git_repo(Path(self.tmp.name) / "repo")
        self.context = TrustedHostContext.create(repo_root=self.repo, doctrine=DOCTRINE)

    def test_profiles_are_named_and_resolve_to_argv_vectors(self):
        for name in self.context.test_profile_names:
            argv = self.context.resolve_test_profile(name)
            self.assertIsInstance(argv, tuple)
            self.assertTrue(argv)
            self.assertEqual(argv[0], sys.executable)

    def test_an_unknown_profile_fails_closed(self):
        with self.assertRaises(HostContextError) as caught:
            self.context.resolve_test_profile("rm-rf-everything")
        self.assertIn("unknown trusted test profile", str(caught.exception))

    def test_a_non_string_profile_fails_closed(self):
        with self.assertRaises(HostContextError):
            self.context.resolve_test_profile(["/bin/sh", "-c", "whoami"])

    def test_command_digest_is_deterministic_and_typed(self):
        argv = self.context.resolve_test_profile("permission-slip-smoke")
        self.assertEqual(command_digest(argv), command_digest(tuple(argv)))
        self.assertRegex(command_digest(argv), r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(
            command_digest(argv), command_digest(argv + ("--extra",))
        )

    def test_empty_profile_sets_are_refused(self):
        with self.assertRaises(HostContextError):
            TrustedHostContext.for_normalisation(
                repo_root=self.repo, doctrine=DOCTRINE, test_profiles={}
            )

    def test_default_profiles_are_all_named_permission_slip(self):
        self.assertEqual(
            sorted(DEFAULT_TEST_PROFILES),
            ["permission-slip-doctrine", "permission-slip-full", "permission-slip-smoke"],
        )


class _WritableRecorder:
    writable = True


if __name__ == "__main__":
    unittest.main()
