"""Trusted action adapter tests.

These run without Tethers: they prove the trust boundary. Caller content
describes requested work; trusted harness context establishes who is acting;
trusted normalization establishes what the operation actually does.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from permission_slip.actions import (
    ActionAdapter,
    ActionAdapterError,
    UntrustedActorError,
    canonical_repository_identity,
    classify_push_refspec,
    feature_branch_destination,
    parse_push,
)
from permission_slip.doctrine import load_doctrine
from tests.support import (
    CANONICAL_IDENTITY,
    CANONICAL_REPOSITORY,
    EVIL_REMOTE_URL,
    OTHER_GITHUB_REMOTE_URL,
    add_remote,
    clear_push_urls,
    init_git_repo,
    push_urls,
    set_push_url,
    set_push_urls,
    set_remote_url,
)

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")
PER_CALL_LIMIT = DOCTRINE["boundaries"]["promotional_credit"]["per_call_limit_cents"]
PROVIDER = DOCTRINE["boundaries"]["promotional_credit"]["provider"]


def git(*args: str, **extra) -> dict:
    return {"tool": "git", "argv": list(args), **extra}


def action_digest(normalized) -> str:
    """Deterministic digest of the Tethers action input.

    ``event.data`` sent to PREPARE is exactly ``normalized.arguments``, so this
    is the identity Tethers binds an approval to.
    """
    payload = json.dumps(
        normalized.arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
        init_git_repo(self.tmp.name)
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


class PushRemoteBindingTests(unittest.TestCase):
    """The push destination must be proven from trusted repository state."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        init_git_repo(self.repo, remotes={"evil-remote": EVIL_REMOTE_URL})
        # A second remote on the correct host but a different repository.
        add_remote(self.repo, "other", OTHER_GITHUB_REMOTE_URL)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.repo)

    def push(self, *args: str, **extra):
        return self.adapter.normalize(
            {"tool": "git", "argv": ["push", *args], **extra}, actor_id="worker-agent"
        )

    def assert_unmappable(self, *args: str, **extra) -> None:
        with self.assertRaises(ActionAdapterError):
            self.push(*args, **extra)

    # -- canonical remote allow --------------------------------------------

    def test_canonical_remote_receives_standing_feature_authority(self):
        result = self.push("origin", "feature/foo")
        self.assertEqual(result.action, "git.push.feature")
        self.assertEqual(result.arguments["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(result.arguments["destination_ref"], "refs/heads/feature/foo")
        self.assertEqual(result.arguments["push_effect"], "push:refs/heads/feature/foo")
        self.assertEqual(result.arguments["repository"], "runtime/spike-workspace/repos/permission-slip")

    def test_equivalent_canonical_url_forms_normalise_identically(self):
        forms = (
            "https://github.com/matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip",
            "https://github.com/matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip.git",
            "https://github.com/matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip/",
            "git@github.com:matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip.git",
            "ssh://git@github.com/matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip.git",
            "HTTPS://GitHub.com/MatthewJamesWatkins1978-Cyber/D-Permission-Slip-Permission-Slip.GIT",
            "https://github.com/matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip.git/",
        )
        for form in forms:
            with self.subTest(form=form):
                self.assertEqual(canonical_repository_identity(form), CANONICAL_IDENTITY)

    def test_unrecognised_url_forms_do_not_normalise(self):
        for form in (
            None,
            "",
            "origin",
            "git://github.com/owner/repo.git",
            "http://github.com/owner/repo.git",
            "https://gitlab.com/owner/repo.git",
            "https://github.com/owner",
            "https://github.com/owner/repo/extra",
            "github.com/owner/repo",
            "someone-else:owner/repo.git",
            "https://github.com:8443/owner/repo.git",
            "ssh://git@github.com:2222/owner/repo.git",
            "https://github.com/owner/repo?tab=readme-ovh",
            "https://github.com/owner/repo#section",
            "/local/path/repo",
            "C:\\local\\repo",
        ):
            with self.subTest(form=form):
                self.assertIsNone(canonical_repository_identity(form))

    # -- wrong / unknown remote --------------------------------------------

    def test_wrong_remote_is_unmappable(self):
        self.assert_unmappable("evil-remote", "feature/foo")

    def test_other_github_repository_is_unmappable(self):
        self.assert_unmappable("other", "feature/foo")

    def test_missing_remote_is_unmappable(self):
        self.assert_unmappable("missing-alias", "feature/foo")

    def test_wrong_remote_is_unmappable_even_when_force_consequential(self):
        # An unfamiliar remote must not be re-described as a history rewrite
        # merely to obtain ASK.
        self.assert_unmappable("--force", "evil-remote", "main")
        self.assert_unmappable("--force", "other", "main")

    def test_non_repository_directory_cannot_establish_a_remote(self):
        plain = tempfile.TemporaryDirectory()
        self.addCleanup(plain.cleanup)
        adapter = ActionAdapter(DOCTRINE, repo_root=plain.name)
        with self.assertRaises(ActionAdapterError):
            adapter.normalize(
                {"tool": "git", "argv": ["push", "origin", "feature/foo"]},
                actor_id="worker-agent",
            )

    # -- direct URL targets -------------------------------------------------

    def test_direct_canonical_url_receives_standing_authority(self):
        for target in (
            CANONICAL_REPOSITORY,
            CANONICAL_REPOSITORY + ".git",
            "git@github.com:matthewjameswatkins1978-cyber/D-Permission-Slip-Permission-Slip.git",
        ):
            with self.subTest(target=target):
                result = self.push(target, "feature/foo")
                self.assertEqual(result.action, "git.push.feature")
                self.assertEqual(result.arguments["remote_repository"], CANONICAL_IDENTITY)

    def test_direct_unknown_url_is_unmappable(self):
        self.assert_unmappable("https://evil.example/x.git", "feature/foo")

    # -- the complete set of effective push URLs ---------------------------

    def test_single_explicit_canonical_push_url_allows(self):
        set_push_urls(self.repo, CANONICAL_REPOSITORY)
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

    def test_no_explicit_push_url_falls_back_to_the_fetch_url(self):
        clear_push_urls(self.repo)
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

    def test_canonical_first_plus_evil_second_push_url_is_unmappable(self):
        # Git physically pushes to BOTH. Seeing only the first must not grant
        # authority for the second.
        set_push_urls(self.repo, CANONICAL_REPOSITORY, EVIL_REMOTE_URL)
        self.assertEqual(len(push_urls(self.repo)), 2)
        self.assert_unmappable("origin", "feature/foo")
        self.assert_unmappable("--force", "origin", "main")

    def test_evil_first_plus_canonical_second_push_url_is_unmappable(self):
        set_push_urls(self.repo, EVIL_REMOTE_URL, CANONICAL_REPOSITORY)
        self.assertEqual(len(push_urls(self.repo)), 2)
        self.assert_unmappable("origin", "feature/foo")
        self.assert_unmappable("--force", "origin", "main")

    def test_two_canonical_equivalent_push_urls_fail_closed(self):
        # Two URLs that normalise to the same repository are still two
        # destinations. v0.1 does not reason that they are "probably" equal.
        set_push_urls(self.repo, CANONICAL_REPOSITORY, CANONICAL_REPOSITORY + ".git")
        self.assertEqual(len(push_urls(self.repo)), 2)
        self.assert_unmappable("origin", "feature/foo")

    def test_three_push_urls_fail_closed(self):
        set_push_urls(
            self.repo, CANONICAL_REPOSITORY, CANONICAL_REPOSITORY, EVIL_REMOTE_URL
        )
        self.assert_unmappable("origin", "feature/foo")

    def test_single_evil_push_url_is_unmappable(self):
        set_push_urls(self.repo, EVIL_REMOTE_URL)
        self.assert_unmappable("origin", "feature/foo")

    def test_exact_one_destination_rule_holds_after_restoring(self):
        set_push_urls(self.repo, CANONICAL_REPOSITORY, EVIL_REMOTE_URL)
        self.assert_unmappable("origin", "feature/foo")
        set_push_urls(self.repo, CANONICAL_REPOSITORY)
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

    # -- force / consequential binding -------------------------------------

    def test_force_canonical_remote_binds_remote_and_effect(self):
        result = self.push("--force", "origin", "main")
        self.assertEqual(result.action, "git.history.rewrite")
        self.assertEqual(result.arguments["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(result.arguments["destination_ref"], "refs/heads/main")
        self.assertEqual(result.arguments["push_effect"], "force:refs/heads/main")

    def test_distinct_destination_refs_produce_distinct_bound_inputs(self):
        main = self.push("--force", "origin", "main")
        release = self.push("--force", "origin", "release")
        self.assertEqual(main.action, "git.history.rewrite")
        self.assertEqual(release.action, "git.history.rewrite")
        self.assertNotEqual(main.arguments["push_effect"], release.arguments["push_effect"])
        self.assertNotEqual(main.arguments["destination_ref"], release.arguments["destination_ref"])
        self.assertNotEqual(action_digest(main), action_digest(release))

    def test_destructive_and_protected_effects_are_distinguished(self):
        protected = self.push("origin", "main")
        deletion = self.push("origin", ":main")
        wildcard = self.push("origin", "feature/*")
        self.assertEqual(protected.arguments["push_effect"], "push:refs/heads/main")
        self.assertEqual(deletion.arguments["push_effect"], "delete:refs/heads/main")
        self.assertEqual(wildcard.arguments["push_effect"], "push:feature/*")
        self.assertEqual(len({action_digest(protected), action_digest(deletion), action_digest(wildcard)}), 3)

    # -- caller spoofing ----------------------------------------------------

    def test_caller_remote_metadata_is_ignored(self):
        operation = {
            "tool": "git",
            "argv": ["push", "evil-remote", "feature/foo"],
            "remote_url": CANONICAL_REPOSITORY,
            "repository_url": CANONICAL_REPOSITORY,
            "canonical_remote": CANONICAL_IDENTITY,
            "approved_remote": CANONICAL_IDENTITY,
        }
        with self.assertRaises(ActionAdapterError):
            self.adapter.normalize(operation, actor_id="worker-agent")

    def test_origin_is_a_label_not_a_trusted_name(self):
        # Follows the *current* trusted Git configuration.
        result = self.push("origin", "feature/foo")
        self.assertEqual(result.action, "git.push.feature")

        set_remote_url(self.repo, "origin", OTHER_GITHUB_REMOTE_URL)
        self.assert_unmappable("origin", "feature/foo")
        self.assert_unmappable("--force", "origin", "main")

        set_remote_url(self.repo, "origin", CANONICAL_REPOSITORY)
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

    def test_push_url_is_followed_rather_than_the_fetch_url(self):
        # The push destination is what ``--push`` reports; retargeting only the
        # push URL must be enough to remove standing authority.
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

        set_push_url(self.repo, "origin", EVIL_REMOTE_URL)
        self.assert_unmappable("origin", "feature/foo")

        set_push_url(self.repo, "origin", CANONICAL_REPOSITORY)
        self.assertEqual(self.push("origin", "feature/foo").action, "git.push.feature")

    # -- doctrine fail-closed ----------------------------------------------

    def test_doctrine_without_canonical_repository_fails_closed(self):
        broken = json.loads(json.dumps(DOCTRINE))
        broken["project"]["canonical_repository"] = "not-a-repository"
        with self.assertRaises(ActionAdapterError):
            ActionAdapter(broken, repo_root=self.repo)

    # -- parser contract ----------------------------------------------------

    def test_parse_push_reports_remote_and_deletion(self):
        parsed = parse_push(["origin", "feature/foo"])
        self.assertEqual(parsed["remote"], "origin")
        self.assertFalse(parsed["delete"])
        self.assertTrue(parse_push(["origin", ":main"])["delete"])
        self.assertTrue(parse_push(["origin", "--delete", "main"])["delete"])
        self.assertTrue(parse_push(["-d", "origin", "main"])["delete"])
        self.assertIsNone(parse_push([])["remote"])


class OtherNormalisationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        init_git_repo(self.tmp.name)
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
