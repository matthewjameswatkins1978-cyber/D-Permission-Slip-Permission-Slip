"""Trusted action adapter tests.

These run without Tethers: they prove the trust boundary. Caller content
describes requested work; trusted harness context establishes who is acting;
trusted normalization establishes what the operation actually does.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from permission_slip.actions import (
    ActionAdapter,
    ActionAdapterError,
    UntrustedActorError,
    classify_push_refspec,
    parse_push,
)
from permission_slip.doctrine import load_doctrine

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")


def git(*args: str, **extra) -> dict:
    return {"tool": "git", "argv": list(args), **extra}


class ActorIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.tmp.name)

    def test_caller_actor_claim_cannot_select_lucy(self):
        operation = git("merge", "work/accepted", actor="lucy")
        result = self.adapter.normalize(operation, actor_id="worker-agent")
        self.assertEqual(result.action, "git.merge.accepted")
        self.assertEqual(result.actor_id, "worker-agent")
        self.assertFalse(result.facts["actor.merge_authority"])
        self.assertIn("actor", result.ignored_caller_claims)

    def test_trusted_lucy_context_obtains_merge_authority(self):
        result = self.adapter.normalize(git("merge", "work/accepted"), actor_id="lucy")
        self.assertEqual(result.actor_id, "lucy")
        self.assertTrue(result.facts["actor.merge_authority"])

    def test_untrusted_actor_context_is_rejected(self):
        with self.assertRaises(UntrustedActorError):
            self.adapter.normalize(git("push", "origin", "feature/x"), actor_id="stranger")

    def test_operation_actor_field_is_never_read(self):
        # Even an operation that claims a trusted actor yields the context actor.
        operation = git("merge", "work/accepted", actor="lucy", approved=True)
        result = self.adapter.normalize(operation, actor_id="worker-agent")
        self.assertEqual(result.actor_id, "worker-agent")
        self.assertFalse(result.facts["actor.merge_authority"])
        for claim in ("actor", "approved"):
            self.assertIn(claim, result.ignored_caller_claims)


class GitPushClassificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.tmp.name)

    def classify(self, *args: str) -> str:
        return self.adapter.normalize(git("push", *args), actor_id="worker-agent").action

    def test_ordinary_feature_push_is_feature(self):
        self.assertEqual(self.classify("origin", "feature/foo"), "git.push.feature")
        self.assertEqual(self.classify("origin", "refs/heads/feature/foo"), "git.push.feature")

    def test_shared_branch_push_is_history_rewrite(self):
        self.assertEqual(self.classify("origin", "main"), "git.history.rewrite")
        self.assertEqual(self.classify("origin", "master"), "git.history.rewrite")
        self.assertEqual(self.classify("origin", "trunk"), "git.history.rewrite")
        self.assertEqual(self.classify("origin", "release"), "git.history.rewrite")

    def test_explicit_destination_refspecs_are_history_rewrite(self):
        for refspec in (
            "HEAD:main",
            "feature/test:main",
            "HEAD:refs/heads/main",
            "feature/test:refs/heads/main",
        ):
            with self.subTest(refspec=refspec):
                self.assertEqual(self.classify("origin", refspec), "git.history.rewrite")

    def test_force_refspec_prefix_is_history_rewrite(self):
        for refspec in ("+feature/test", "+feature/test:main", "+HEAD:refs/heads/main"):
            with self.subTest(refspec=refspec):
                self.assertEqual(self.classify("origin", refspec), "git.history.rewrite")

    def test_force_option_variants_are_history_rewrite(self):
        self.assertEqual(self.classify("origin", "--force", "feature/foo"), "git.history.rewrite")
        self.assertEqual(self.classify("origin", "-f", "feature/foo"), "git.history.rewrite")
        self.assertEqual(
            self.classify("origin", "--force-with-lease", "feature/foo"), "git.history.rewrite"
        )
        self.assertEqual(
            self.classify("origin", "--force-with-lease=main", "feature/foo"),
            "git.history.rewrite",
        )
        self.assertEqual(
            self.classify("origin", "--force-if-includes", "feature/foo"),
            "git.history.rewrite",
        )

    def test_deletion_and_ambiguous_pushes_fail_closed(self):
        # No explicit refspec, multiple refspecs, deletions, tags and symbolic
        # refs must never become an ordinary feature push.
        for args in (
            ("origin",),
            ("origin", "feature/a", "feature/b"),
            ("origin", ":main"),
            ("origin", ":feature/foo"),
            ("origin", "refs/tags/v1.0"),
            ("origin", "HEAD"),
            ("origin", "feature/*"),
        ):
            with self.subTest(args=args):
                self.assertNotEqual(self.classify(*args), "git.push.feature")
                self.assertEqual(self.classify(*args), "git.history.rewrite")

    def test_parse_push_recognises_force_and_ambiguity(self):
        self.assertTrue(parse_push(["origin", "--force-with-lease=main", "feature/x"])["force"])
        self.assertTrue(parse_push(["origin"])["ambiguous"])
        self.assertFalse(parse_push(["origin", "feature/x"])["ambiguous"])

    def test_classify_refspec_helper_contract(self):
        self.assertEqual(classify_push_refspec("feature/foo"), (False, "feature/foo"))
        self.assertEqual(classify_push_refspec("HEAD:main"), (True, "main"))
        self.assertEqual(classify_push_refspec("+feature/foo"), (True, "feature/foo"))
        self.assertEqual(classify_push_refspec(":main"), (True, None))


class PathCanonicalisationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir(parents=True, exist_ok=True)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.repo)

    def canonical(self, path: str) -> str:
        return self.adapter.normalize(
            {"tool": "edit_file", "path": path}, actor_id="worker-agent"
        ).arguments["path"]

    def test_relative_in_project_path_is_canonical(self):
        self.assertEqual(
            self.canonical("runtime/spike-workspace/notes.txt"),
            "runtime/spike-workspace/notes.txt",
        )

    def test_absolute_in_project_path_matches_canonical_relative(self):
        absolute = str(self.repo / "runtime" / "spike-workspace" / "notes.txt")
        self.assertEqual(self.canonical(absolute), "runtime/spike-workspace/notes.txt")

    def test_parent_traversal_outside_project_is_not_made_in_scope(self):
        result = self.canonical("../runtime/spike-workspace/evil.txt")
        self.assertTrue(result.startswith(".."), result)
        self.assertNotEqual(result, "runtime/spike-workspace/evil.txt")

    def test_absolute_outside_project_is_not_made_in_scope(self):
        outside = str(Path(self.tmp.name) / "outside" / "evil.txt")
        result = self.canonical(outside)
        self.assertTrue(result.startswith("..") or os.path.isabs(result), result)
        self.assertNotEqual(result, "runtime/spike-workspace/evil.txt")

    def test_traversal_containing_workspace_substring_is_not_in_scope(self):
        result = self.canonical("../../runtime/spike-workspace/evil.txt")
        self.assertIn("runtime/spike-workspace", result)
        self.assertTrue(result.startswith(".."), result)

    def test_normalisation_never_strips_traversal(self):
        # The old ``lstrip("./")`` bug erased leading ``../``.
        result = self.canonical("../../secrets.txt")
        self.assertTrue(result.startswith(".."), result)
        self.assertNotEqual(result, "secrets.txt")


class OtherNormalisationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.tmp.name)

    def normalize(self, operation: dict, actor_id: str = "worker-agent"):
        return self.adapter.normalize(operation, actor_id=actor_id)

    def test_force_push_is_history_rewrite_from_argv_not_label(self):
        operation = git(
            "push", "--force", "origin", "main", action="git.push.feature", is_force_push=False
        )
        result = self.normalize(operation)
        self.assertEqual(result.action, "git.history.rewrite")
        self.assertIn("action", result.ignored_caller_claims)

    def test_secret_material_takes_precedence_over_repository_upload(self):
        result = self.normalize(
            {
                "tool": "external_upload",
                "destination": "https://new.example.com/drop",
                "secret_material": True,
                "secret_kind": "api_key",
            }
        )
        self.assertEqual(result.action, "data.external_upload.secret")

    def test_bounded_promotional_credit_fact_is_derived(self):
        within = self.normalize(
            {"tool": "payment", "amount_cents": 1000, "funding": "promotional", "vendor": "cloud-fixture"}
        )
        outside = self.normalize(
            {"tool": "payment", "amount_cents": 9000, "funding": "promotional", "vendor": "cloud-fixture"}
        )
        self.assertEqual(within.action, "money.promotional_credit.use")
        self.assertTrue(within.facts["promo.within_budget"])
        self.assertFalse(outside.facts["promo.within_budget"])

    def test_real_money_is_not_promotional(self):
        result = self.normalize(
            {"tool": "payment", "amount_cents": 100, "funding": "real", "vendor": "cloud-fixture"}
        )
        self.assertEqual(result.action, "money.real_charge")
        self.assertNotIn("promo.within_budget", result.facts)

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(ActionAdapterError):
            self.normalize({"tool": "shell", "argv": ["rm", "-rf", "/"]})


if __name__ == "__main__":
    unittest.main()
