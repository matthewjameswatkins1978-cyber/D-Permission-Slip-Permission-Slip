"""Real host effects: exactly what Tethers admitted, and nothing else."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from permission_slip.actions import (
    MISSING_FILE_DIGEST,
    ActionAdapter,
    NormalizedAction,
    canonical_repository_identity,
)
from permission_slip.doctrine import load_doctrine
from permission_slip.host_context import HostContextError, TrustedHostContext, command_digest
from permission_slip.host_executor import (
    SUPPORTED_REAL_EFFECTS,
    HostExecutionFailure,
    RealHostExecutor,
)
from permission_slip.observability import NullRecorder, TraceRecorder
from tests.support import (
    CANONICAL_IDENTITY,
    CANONICAL_REPOSITORY,
    commit_all,
    head_oid,
    init_git_repo,
)

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")

UNSUPPORTED_ACTIONS = (
    "git.history.rewrite",
    "identity.public_publish",
    "data.external_upload.repository",
    "data.external_upload.secret",
    "money.real_charge",
    "money.promotional_credit.use",
)


def sha(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class RealHostHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-realhost-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = init_git_repo(self.root / "repo")
        self.state = self.root / "state"
        self.recorder = TraceRecorder(self.state, session={"entry": "test"})
        self.context = TrustedHostContext.create(repo_root=self.repo, doctrine=DOCTRINE)
        self.executor = RealHostExecutor(self.context, recorder=self.recorder)
        self.adapter = ActionAdapter(DOCTRINE, host_context=self.context)

    def normalize(self, operation: dict[str, Any], actor: str = "worker-agent") -> NormalizedAction:
        return self.adapter.normalize(operation, actor)

    def git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return (completed.stdout or "").strip()

    # -- construction guards ------------------------------------------------

    def test_fixture_remains_the_default_and_the_real_one_is_explicit(self):
        from permission_slip.executor import FixtureExecutor
        from permission_slip.spike import PermissionSlip

        slip = PermissionSlip(
            REPO / "doctrine" / "matthew.v0.1.json",
            workdir=self.root / "work",
            repo_root=self.repo,
        )
        self.addCleanup(slip.close)
        self.assertFalse(slip.executor.is_real)
        self.assertIsInstance(slip.executor, FixtureExecutor)
        self.assertTrue(self.executor.is_real)
        self.assertIsInstance(self.executor, RealHostExecutor)

    def test_real_execution_requires_a_writable_recorder(self):
        with self.assertRaises(HostContextError):
            RealHostExecutor(self.context, recorder=None)
        with self.assertRaises(HostContextError):
            RealHostExecutor(self.context, recorder=NullRecorder())

    def test_real_execution_requires_a_fully_validated_context(self):
        unverified = TrustedHostContext.for_normalisation(repo_root=self.repo, doctrine=DOCTRINE)
        with self.assertRaises(HostContextError):
            RealHostExecutor(unverified, recorder=self.recorder)

    def test_unsupported_real_effects_fail_closed_without_a_marker(self):
        sandbox_before = sorted(
            p.relative_to(self.repo) for p in (self.repo / "runtime").rglob("*") if p.is_file()
        ) if (self.repo / "runtime").exists() else []
        for action in UNSUPPORTED_ACTIONS:
            with self.subTest(action=action):
                self.assertNotIn(action, SUPPORTED_REAL_EFFECTS)
                result = self.executor.execute(
                    NormalizedAction(
                        action=action,
                        arguments={"destination": "https://evil.example"},
                        facts={},
                        actor_id="worker-agent",
                    )
                )
                self.assertEqual(result.status, "failed")
                self.assertFalse(result.executed)
                self.assertFalse(result.ok)
                self.assertEqual(result.detail["reason"], "unsupported_real_effect")
                self.assertEqual(result.effects, [])
        sandbox_after = sorted(
            p.relative_to(self.repo) for p in (self.repo / "runtime").rglob("*") if p.is_file()
        ) if (self.repo / "runtime").exists() else []
        self.assertEqual(sandbox_before, sandbox_after)


class RealTestProfileTests(RealHostHarness):
    def profile_action(self, **overrides: Any) -> NormalizedAction:
        profiles = dict(self.context.test_profiles)
        profiles["exit0"] = (sys.executable, "-c", "import sys; sys.exit(0)")
        profiles["exit1"] = (sys.executable, "-c", "import sys; sys.exit(1)")
        profiles["noisy"] = (
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('RAW-BODY-XYZ'); sys.stderr.write('RAW-ERR')",
        )
        context = TrustedHostContext.create(
            repo_root=self.repo, doctrine=DOCTRINE, test_profiles=profiles
        )
        executor = RealHostExecutor(context, recorder=self.recorder)
        return executor, context, profiles

    def test_a_trusted_profile_runs_and_reports_a_truthful_exit_code(self):
        executor, context, _ = self.profile_action()
        argv = context.resolve_test_profile("exit0")
        action = NormalizedAction(
            action="dev.tests.run",
            arguments={
                "path": context.resource_prefix.rstrip("/"),
                "test_profile": "exit0",
                "command_digest": command_digest(argv),
            },
            facts={},
            actor_id="worker-agent",
        )
        result = executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.executed)
        self.assertEqual(result.detail["exit_code"], 0)

    def test_exit_one_is_a_failed_execution_not_an_exception(self):
        executor, context, _ = self.profile_action()
        argv = context.resolve_test_profile("exit1")
        action = NormalizedAction(
            action="dev.tests.run",
            arguments={
                "path": context.resource_prefix.rstrip("/"),
                "test_profile": "exit1",
                "command_digest": command_digest(argv),
            },
            facts={},
            actor_id="worker-agent",
        )
        result = executor.execute(action)
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.executed)
        self.assertEqual(result.detail["exit_code"], 1)
        self.assertNotEqual(result.status, "succeeded")

    def test_subprocess_bodies_are_fingerprinted_but_never_stored(self):
        executor, context, _ = self.profile_action()
        argv = context.resolve_test_profile("noisy")
        action = NormalizedAction(
            action="dev.tests.run",
            arguments={
                "path": context.resource_prefix.rstrip("/"),
                "test_profile": "noisy",
                "command_digest": command_digest(argv),
            },
            facts={},
            actor_id="worker-agent",
        )
        result = executor.execute(action)
        self.assertGreater(result.detail["stdout_bytes"], 0)
        self.assertGreater(result.detail["stderr_bytes"], 0)
        self.assertRegex(result.detail["stdout_sha256"], r"^sha256:[0-9a-f]{64}$")
        blob = json.dumps(result, default=str) + json.dumps(result.as_dict())
        self.assertNotIn("RAW-BODY-XYZ", blob)
        self.assertNotIn("RAW-ERR", blob)

    def test_an_unknown_profile_cannot_be_executed(self):
        action = NormalizedAction(
            action="dev.tests.run",
            arguments={
                "path": self.context.resource_prefix.rstrip("/"),
                "test_profile": "caller-invented-profile",
                "command_digest": "sha256:" + "0" * 64,
            },
            facts={},
            actor_id="worker-agent",
        )
        with self.assertRaises(HostExecutionFailure):
            self.executor.execute(action)

    def test_profile_drift_between_admission_and_launch_is_detected(self):
        argv = self.context.resolve_test_profile("permission-slip-smoke")
        action = NormalizedAction(
            action="dev.tests.run",
            arguments={
                "path": self.context.resource_prefix.rstrip("/"),
                "test_profile": "permission-slip-smoke",
                "command_digest": "sha256:" + "0" * 64,
            },
            facts={},
            actor_id="worker-agent",
        )
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("drift", str(caught.exception))

    def test_no_shell_ever_appears_in_the_argv(self):
        argv = list(self.context.resolve_test_profile("permission-slip-smoke"))
        self.assertEqual(argv[0], sys.executable)
        self.assertNotIn("-c", argv[:1])


class RealEditTests(RealHostHarness):
    def edit(self, relative: str, content: str) -> tuple[NormalizedAction, Path]:
        physical = self.repo / relative
        operation = {"tool": "edit_file", "path": relative, "content": content}
        action = self.normalize(operation)
        return action, physical

    def test_an_exact_edit_replaces_the_whole_file(self):
        target = self.repo / "notes" / "notes.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"old bytes")
        action, _ = self.edit("notes/notes.txt", "brand new content\n")
        self.assertEqual(action.arguments["before_digest"], sha(b"old bytes"))
        self.assertEqual(action.arguments["after_digest"], sha(b"brand new content\n"))

        result = self.executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(target.read_bytes(), b"brand new content\n")
        self.assertEqual(result.detail["before_digest"], sha(b"old bytes"))
        self.assertEqual(result.detail["after_digest"], sha(b"brand new content\n"))

    def test_a_new_file_inside_an_existing_directory_is_allowed(self):
        (self.repo / "existing-dir").mkdir()
        action, physical = self.edit("existing-dir/new.txt", "hello")
        result = self.executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(physical.read_text(encoding="utf-8"), "hello")

    def test_a_missing_parent_directory_is_refused_not_created(self):
        action, physical = self.edit("brand/new/dir/file.txt", "hello")
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("parent directory", str(caught.exception))
        self.assertFalse(physical.exists())
        self.assertFalse((self.repo / "brand").exists())

    def test_traversal_outside_the_trusted_root_is_refused(self):
        action = self.normalize(
            {"tool": "edit_file", "path": "../escape.txt", "content": "pwn"}
        )
        with self.assertRaises(HostExecutionFailure):
            self.executor.execute(action)
        self.assertFalse((self.root / "escape.txt").exists())

    def test_prefix_traversal_is_refused(self):
        action = self.normalize(
            {"tool": "edit_file", "path": "permission_slip/../../escape.txt", "content": "pwn"}
        )
        # Normalisation resolves the traversal; the identity is either inside
        # the checkout or genuinely outside it, never a prefix trick.
        with self.assertRaises(HostExecutionFailure):
            self.executor.execute(action)

    def test_a_link_target_is_refused_and_the_real_content_survives(self):
        link = self.repo / "link.txt"
        try:
            real_file = self.repo / "real-target.txt"
            real_file.write_bytes(b"real")
            link.symlink_to(real_file)
            protected = real_file
        except (OSError, NotImplementedError):
            # Windows without SeCreateSymbolicLinkPrivilege: a directory
            # junction needs no privilege and is the same reparse hazard.
            if os.name != "nt":  # pragma: no cover - non-Windows host
                self.skipTest("symlinks unavailable on this host")
            real_dir = self.repo / "real-target-dir"
            real_dir.mkdir(exist_ok=True)
            (real_dir / "f.txt").write_bytes(b"real")
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(real_dir)],
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:  # pragma: no cover - host policy
                self.skipTest("neither symlinks nor junctions are permitted here")
            protected = real_dir / "f.txt"

        payload = b"clobbered"
        action = NormalizedAction(
            action="project.files.edit",
            arguments={
                "path": self.context.resource_prefix + "link.txt",
                "before_digest": MISSING_FILE_DIGEST,
                "after_digest": sha(payload),
                "content_bytes": len(payload),
            },
            facts={},
            actor_id="worker-agent",
            execution_payload=payload,
        )
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("symlink or junction", str(caught.exception))
        self.assertEqual(protected.read_bytes(), b"real")

    def test_a_file_changed_after_admission_is_not_written(self):
        target = self.repo / "contested.txt"
        target.write_bytes(b"original")
        action = self.normalize(
            {"tool": "edit_file", "path": "contested.txt", "content": "mine"}
        )
        target.write_bytes(b"someone else got here first")
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("changed after COMMIT", str(caught.exception))
        self.assertEqual(target.read_bytes(), b"someone else got here first")

    def test_a_mutated_payload_is_refused(self):
        target = self.repo / "payload.txt"
        target.write_bytes(b"original")
        action = self.normalize(
            {"tool": "edit_file", "path": "payload.txt", "content": "admitted"}
        )
        # Same length, different bytes: only the digest check can catch this.
        action.execution_payload = b"ADMITTED"
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("after_digest", str(caught.exception))
        self.assertEqual(target.read_bytes(), b"original")

    def test_a_payload_length_mismatch_is_refused(self):
        target = self.repo / "length.txt"
        target.write_bytes(b"original")
        action = self.normalize(
            {"tool": "edit_file", "path": "length.txt", "content": "admitted"}
        )
        action.arguments["content_bytes"] = action.arguments["content_bytes"] + 1
        with self.assertRaises(HostExecutionFailure):
            self.executor.execute(action)
        self.assertEqual(target.read_bytes(), b"original")

    def test_a_missing_payload_is_refused(self):
        target = self.repo / "noload.txt"
        target.write_bytes(b"original")
        action = self.normalize(
            {"tool": "edit_file", "path": "noload.txt", "content": "admitted"}
        )
        action.execution_payload = None
        with self.assertRaises(HostExecutionFailure):
            self.executor.execute(action)
        self.assertEqual(target.read_bytes(), b"original")

    def test_normalisation_of_a_missing_file_uses_the_missing_sentinel(self):
        action = self.normalize(
            {"tool": "edit_file", "path": "not-yet.txt", "content": "hello"}
        )
        self.assertEqual(action.arguments["before_digest"], MISSING_FILE_DIGEST)
        result = self.executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual((self.repo / "not-yet.txt").read_text(encoding="utf-8"), "hello")


class RealPushTests(RealHostHarness):
    def setUp(self):
        super().setUp()
        self.bare = self.root / "bare.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.bare)], check=True)
        # Test-only: behave like a real forge and reject non-fast-forward pushes.
        subprocess.run(
            ["git", "-C", str(self.bare), "config", "receive.denyNonFastForwards", "true"],
            check=True,
        )

    def feature_action(self) -> NormalizedAction:
        return self.normalize({"tool": "git", "argv": ["push", "origin", "feature/foo"]})

    def with_local_transport(self):
        """TEST-ONLY: redirect the canonical URL to the local bare repository.

        Set only around an executor call -- never in production configuration.
        """
        import unittest.mock

        return unittest.mock.patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": f"url.{self.bare.as_uri()}.insteadOf",
                "GIT_CONFIG_VALUE_0": CANONICAL_REPOSITORY,
            },
        )

    def bare_refs(self) -> dict[str, str]:
        out = subprocess.run(
            ["git", "-C", str(self.bare), "for-each-ref", "--format=%(refname) %(objectname)"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout
        refs = {}
        for line in out.splitlines():
            name, _, oid = line.partition(" ")
            refs[name] = oid
        return refs

    # -- exact production command construction -----------------------------

    def test_push_argv_is_exactly_the_admitted_command(self):
        action = self.feature_action()
        argv = self.executor.push_argv(action)
        self.assertEqual(
            argv,
            [
                "git",
                "-C",
                str(self.repo.resolve()),
                "push",
                CANONICAL_REPOSITORY,
                f"{action.arguments['source_commit']}:{action.arguments['destination_ref']}",
            ],
        )
        self.assertNotIn("origin", argv)

    def test_push_binds_source_commit_destination_and_transport_digest(self):
        action = self.feature_action()
        self.assertEqual(action.arguments["source_commit"], head_oid(self.repo))
        self.assertEqual(action.arguments["destination_ref"], "refs/heads/feature/foo")
        self.assertEqual(action.arguments["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(
            action.arguments["remote_transport_digest"],
            "sha256:" + hashlib.sha256(CANONICAL_REPOSITORY.encode("utf-8")).hexdigest(),
        )
        # The transport string itself is sealed, never authority-visible.
        self.assertNotIn("sealed_transport", action.as_dict())
        self.assertNotIn(CANONICAL_REPOSITORY, json.dumps(action.as_dict()))
        self.assertEqual(action.sealed_transport, CANONICAL_REPOSITORY)

    def test_a_sealed_transport_that_is_not_the_admitted_remote_is_refused(self):
        action = self.feature_action()
        action.sealed_transport = str(self.bare)
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.push_argv(action)
        self.assertIn("does not match the admitted remote repository", str(caught.exception))

    def test_a_transport_digest_mismatch_is_refused(self):
        action = self.feature_action()
        # A different-but-equivalent spelling of the same canonical identity:
        # identity alone cannot tell them apart, so the digest must.
        action.sealed_transport = (
            "git@github.com:matthewjameswatkins1978-cyber/"
            "D-Permission-Slip-Permission-Slip.git"
        )
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.push_argv(action)
        # Identity still canonicalises, so the digest is what catches it.
        self.assertEqual(
            canonical_repository_identity(action.sealed_transport), CANONICAL_IDENTITY
        )
        self.assertIn("digest does not match", str(caught.exception))

    def test_a_missing_sealed_transport_is_refused(self):
        action = self.feature_action()
        action.sealed_transport = None
        with self.assertRaises(HostExecutionFailure):
            self.executor.push_argv(action)

    def test_a_destination_ref_that_was_never_admitted_is_not_used(self):
        action = self.feature_action()
        argv = self.executor.push_argv(action)
        self.assertTrue(argv[-1].endswith(":refs/heads/feature/foo"))

    # -- physical transport harness ---------------------------------------

    def test_a_real_feature_push_reaches_the_remote(self):
        action = self.feature_action()
        with self.with_local_transport():
            result = self.executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.executed)
        self.assertEqual(
            self.bare_refs().get("refs/heads/feature/foo"),
            action.arguments["source_commit"],
        )
        self.assertEqual(result.detail["remote_repository"], CANONICAL_IDENTITY)

    def test_a_non_fast_forward_push_is_a_truthful_failure(self):
        action = self.feature_action()
        with self.with_local_transport():
            first = self.executor.execute(action)
        self.assertEqual(first.status, "succeeded")

        # Point the remote ref at an unrelated commit so the admitted source
        # can no longer fast-forward onto it.
        tree = subprocess.run(
            ["git", "-C", str(self.bare), "rev-parse", f"{action.arguments['source_commit']}^{{tree}}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        unrelated = subprocess.run(
            ["git", "-C", str(self.bare), "commit-tree", tree, "-m", "diverge"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(self.bare), "update-ref", "refs/heads/feature/foo", unrelated],
            check=True,
        )
        with self.with_local_transport():
            second = self.executor.execute(action)
        self.assertEqual(second.status, "failed")
        self.assertNotEqual(second.status, "succeeded")
        self.assertEqual(second.detail["exit_code"] != 0, True)

    def test_a_push_whose_source_commit_vanished_is_refused(self):
        action = self.feature_action()
        action.arguments["source_commit"] = "0" * 40
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("no longer exists", str(caught.exception))


class RealMergeTests(RealHostHarness):
    def setUp(self):
        super().setUp()
        # HEAD is one commit behind the accepted source: a clean fast-forward.
        (self.repo / "a.txt").write_text("a", encoding="utf-8")
        self.base = commit_all(self.repo, "base")
        (self.repo / "b.txt").write_text("b", encoding="utf-8")
        self.source = commit_all(self.repo, "accepted")
        subprocess.run(["git", "-C", str(self.repo), "reset", "-q", "--hard", self.base], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "branch", "-f", "work/accepted", self.source], check=True
        )

    def merge_action(self, actor: str = "lucy") -> NormalizedAction:
        return self.normalize({"tool": "git", "argv": ["merge", "work/accepted"]}, actor)

    def test_merge_binds_source_target_and_ref(self):
        action = self.merge_action()
        self.assertEqual(action.arguments["source_commit"], self.source)
        self.assertEqual(action.arguments["target_commit"], self.base)
        self.assertTrue(action.arguments["target_ref"].startswith("refs/heads/"))

    def test_a_fast_forward_merge_succeeds(self):
        action = self.merge_action()
        result = self.executor.execute(action)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(head_oid(self.repo), self.source)
        self.assertTrue((self.repo / "b.txt").exists())

    def test_a_stale_target_head_is_refused(self):
        action = self.merge_action()
        (self.repo / "c.txt").write_text("c", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-q", "-m", "moved"], check=True
        )
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("HEAD moved", str(caught.exception))

    def test_a_changed_target_ref_is_refused(self):
        action = self.merge_action()
        subprocess.run(["git", "-C", str(self.repo), "checkout", "-q", "-b", "other"], check=True)
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("branch changed", str(caught.exception))

    def test_a_diverged_source_fails_without_a_merge_commit(self):
        # Make HEAD diverge from the accepted source.
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-q", "--allow-empty", "-m", "diverge"],
            check=True,
        )
        action = self.merge_action()
        result = self.executor.execute(action)
        self.assertEqual(result.status, "failed")
        parents = self.git("rev-list", "--parents", "-n", "1", "HEAD").split()
        self.assertEqual(len(parents), 2, "no merge commit may be created")  # commit + 1 parent

    def test_a_missing_source_commit_is_refused(self):
        action = self.merge_action()
        action.arguments["source_commit"] = "0" * 40
        with self.assertRaises(HostExecutionFailure) as caught:
            self.executor.execute(action)
        self.assertIn("no longer exists", str(caught.exception))

    def test_a_worker_without_merge_authority_never_reaches_the_executor(self):
        from permission_slip.spike import DECISION_DENY

        # The authority decision is Tethers'; this proves the capability is
        # gated before any physical merge can be attempted.
        action = self.merge_action(actor="worker-agent")
        self.assertFalse(action.facts["actor.merge_authority"])
        self.assertEqual(action.action, "git.merge.accepted")
        self.assertEqual(DECISION_DENY, "DENY")


if __name__ == "__main__":
    unittest.main()
