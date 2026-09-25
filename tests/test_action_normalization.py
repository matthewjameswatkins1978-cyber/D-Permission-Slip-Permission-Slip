"""Trusted action adapter tests.

These run without Tethers: they prove the trust boundary. Caller content
describes requested work; trusted harness context establishes who is acting;
trusted normalization establishes what the operation actually does.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from permission_slip.actions import (
    ActionAdapter,
    ActionAdapterError,
    UntrustedActorError,
    classify_push_refspec,
    feature_branch_destination,
    parse_push,
)
from permission_slip.doctrine import load_doctrine

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")
PER_CALL_LIMIT = DOCTRINE["boundaries"]["promotional_credit"]["per_call_limit_cents"]
PROVIDER = DOCTRINE["boundaries"]["promotional_credit"]["provider"]


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

    def assert_unmappable(self, *args: str) -> None:
        """A push with no truthful v0.1 capability must fail closed, not ALLOW."""
        with self.assertRaises(ActionAdapterError):
            self.adapter.normalize(git("push", *args), actor_id="worker-agent")

    # -- positive feature authority ----------------------------------------

    def test_feature_namespace_destinations_receive_standing_authority(self):
        for args in (
            ("origin", "feature/foo"),
            ("origin", "refs/heads/feature/foo"),
            ("origin", "HEAD:feature/foo"),
            ("origin", "local-work:refs/heads/feature/foo"),
            ("origin", "worktree-source:refs/heads/feature/foo"),
            ("origin", "HEAD:refs/heads/feature/foo"),
            ("origin", "feature/a/b"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.classify(*args), "git.push.feature")

    def test_feature_branch_destination_is_an_allow_list(self):
        self.assertEqual(feature_branch_destination("feature/foo"), "feature/foo")
        self.assertEqual(feature_branch_destination("feature/a/b"), "feature/a/b")
        for hostile in (
            None,
            "",
            "production",
            "stable",
            "gh-pages",
            "shared",
            "customer-live",
            "arbitrary-name",
            "feature",  # bare name is not the feature/* namespace
            "feature/",
            "Feature/foo",
            "feature/../main",
            "feature//foo",
            "feature/foo/",
            "feature/.hidden",
            "feature/foo.lock",
            "feature/foo bar",
            "feature/foo~1",
            "feature/foo@{1}",
        ):
            with self.subTest(label=hostile):
                self.assertIsNone(feature_branch_destination(hostile))

    def test_non_feature_destinations_fail_closed(self):
        # Absence from the protected list is not positive evidence.
        for name in ("production", "stable", "gh-pages", "shared", "customer-live", "arbitrary-name"):
            with self.subTest(name=name):
                self.assert_unmappable("origin", name)

    def test_non_feature_explicit_destinations_fail_closed(self):
        # The destination governs, whatever the source is.
        for refspec in (
            "HEAD:production",
            "local-work:stable",
            "feature/foo:production",
            "refs/heads/shared",
        ):
            with self.subTest(refspec=refspec):
                self.assert_unmappable("origin", refspec)

    def test_hostile_feature_destination_shapes_fail_closed(self):
        for refspec in ("feature/../main", "feature//x", "feature/", "Feature/x"):
            with self.subTest(refspec=refspec):
                self.assert_unmappable("origin", refspec)

    # -- protected / destructive behaviour ---------------------------------

    def test_shared_branch_push_is_history_rewrite(self):
        for name in ("main", "master", "trunk", "release"):
            with self.subTest(name=name):
                self.assertEqual(self.classify("origin", name), "git.history.rewrite")
                self.assertEqual(
                    self.classify("origin", f"refs/heads/{name}"), "git.history.rewrite"
                )

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

    def test_force_variants_on_a_feature_branch_stay_consequential(self):
        for args in (
            ("--force", "origin", "feature/foo"),
            ("-f", "origin", "feature/foo"),
            ("--force-with-lease", "origin", "feature/foo"),
            ("--force-with-lease=feature/foo", "origin", "feature/foo"),
            ("--force-if-includes", "origin", "feature/foo"),
            ("origin", "+feature/foo"),
            ("origin", "+HEAD:feature/foo"),
            ("origin", "feature/foo", "--force"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.classify(*args), "git.history.rewrite")
                self.assertNotEqual(self.classify(*args), "git.push.feature")

    def test_alternate_force_syntax_never_reaches_feature_authority(self):
        # git accepts unambiguous abbreviations of long options, and combined
        # short flags. None of these may fall through to standing authority.
        for args in (
            ("--force-with-leas", "origin", "feature/foo"),
            ("--force-with-lease", "origin", "feature/foo"),
            ("--force-i", "origin", "feature/foo"),
            ("origin", "--force-with-lease=feature/foo", "feature/foo"),
            ("-fu", "origin", "feature/foo"),
            ("-uf", "origin", "feature/foo"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.classify(*args), "git.history.rewrite")

    def test_unrecognised_push_options_fail_closed(self):
        # Positive evidence means every token is recognised. An option we do
        # not understand (including one that retargets the push) is not ALLOW.
        for args in (
            ("--repo=https://evil.example/x", "origin", "feature/foo"),
            ("--exec=evil", "origin", "feature/foo"),
            ("--receive-pack=evil", "origin", "feature/foo"),
            ("--receive-pack", "evil", "origin", "feature/foo"),
            ("--signed", "origin", "feature/foo"),
            ("-x", "origin", "feature/foo"),
            ("origin", "--weird-flag", "feature/foo"),
        ):
            with self.subTest(args=args):
                self.assertNotEqual(self.classify(*args), "git.push.feature")
                self.assertEqual(self.classify(*args), "git.history.rewrite")

    def test_safe_local_options_keep_standing_authority(self):
        for args in (
            ("--set-upstream", "origin", "feature/foo"),
            ("-u", "origin", "feature/foo"),
            ("origin", "feature/foo", "--verbose"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.classify(*args), "git.push.feature")

    def test_deletion_and_ambiguous_pushes_fail_closed(self):
        # No explicit refspec, multiple refspecs, deletions, tags, wildcards and
        # symbolic refs must never become an ordinary feature push.
        for args in (
            ("origin",),
            ("origin", "feature/a", "feature/b"),
            ("origin", ":main"),
            ("origin", ":feature/foo"),
            ("origin", "refs/tags/v1.0"),
            ("origin", "HEAD"),
            ("origin", "feature/*"),
            ("origin", "*:feature/foo"),
            ("origin", "refs/heads/*"),
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
        self.assertEqual(classify_push_refspec("*:feature/foo"), (True, None))


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


class PromotionalCreditBoundTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.tmp.name)

    def charge(
        self,
        amount,
        *,
        funding: str = "promotional",
        vendor: str = PROVIDER,
        adapter: ActionAdapter | None = None,
    ):
        operation = {"tool": "payment", "amount_cents": amount, "funding": funding, "vendor": vendor}
        return (adapter or self.adapter).normalize(operation, actor_id="worker-agent")

    def test_positive_amount_at_approved_provider_is_within_bound(self):
        result = self.charge(1000)
        self.assertEqual(result.action, "money.promotional_credit.use")
        self.assertTrue(result.facts["promo.within_bound"])
        self.assertEqual(result.arguments["amount_cents"], 1000)

    def test_exact_per_call_limit_is_within_bound(self):
        result = self.charge(PER_CALL_LIMIT)
        self.assertTrue(result.facts["promo.within_bound"])

    def test_amount_above_per_call_limit_is_not_within_bound(self):
        result = self.charge(PER_CALL_LIMIT + 1)
        self.assertFalse(result.facts["promo.within_bound"])

    def test_wrong_provider_is_not_within_bound(self):
        result = self.charge(1000, vendor="other-vendor")
        self.assertEqual(result.action, "money.promotional_credit.use")
        self.assertFalse(result.facts["promo.within_bound"])

    def test_missing_provider_configuration_fails_closed(self):
        doctrine = json.loads(json.dumps(DOCTRINE))
        doctrine["boundaries"]["promotional_credit"].pop("provider", None)
        stripped = ActionAdapter(doctrine, repo_root=self.tmp.name)
        result = self.charge(1000, adapter=stripped)
        self.assertFalse(result.facts["promo.within_bound"])

    def test_zero_amount_is_not_within_bound(self):
        self.assertFalse(self.charge(0).facts["promo.within_bound"])

    def test_negative_amount_is_not_within_bound(self):
        self.assertFalse(self.charge(-100).facts["promo.within_bound"])

    def test_missing_amount_fails_closed(self):
        operation = {"tool": "payment", "funding": "promotional", "vendor": PROVIDER}
        with self.assertRaises(ActionAdapterError):
            self.adapter.normalize(operation, actor_id="worker-agent")

    def test_malformed_amounts_fail_closed(self):
        for raw in ("1000", 1000.5, True, False, None, [1000], {"cents": 1000}, 1e3, b"1000"):
            with self.subTest(raw=raw):
                with self.assertRaises(ActionAdapterError):
                    self.charge(raw)
                with self.assertRaises(ActionAdapterError):
                    self.charge(raw, funding="real")

    def test_real_funding_is_a_real_charge_without_promotional_fact(self):
        result = self.charge(1000, funding="real")
        self.assertEqual(result.action, "money.real_charge")
        self.assertNotIn("promo.within_bound", result.facts)
        self.assertTrue(result.supervision.real_money)

    def test_promotional_doctrine_field_is_explicitly_per_call(self):
        # The doctrine must not claim a cumulative budget it does not enforce.
        boundary = DOCTRINE["boundaries"]["promotional_credit"]
        self.assertIn("per_call_limit_cents", boundary)
        self.assertNotIn("budget_cents", boundary)
        capability = next(
            cap for cap in DOCTRINE["capabilities"] if cap["action"] == "money.promotional_credit.use"
        )
        self.assertEqual(capability["requires"], ["promo.within_bound"])


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

    def test_caller_action_label_cannot_manufacture_feature_authority(self):
        operation = git("push", "origin", "production", action="git.push.feature")
        with self.assertRaises(ActionAdapterError):
            self.normalize(operation)

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

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(ActionAdapterError):
            self.normalize({"tool": "shell", "argv": ["rm", "-rf", "/"]})


if __name__ == "__main__":
    unittest.main()
