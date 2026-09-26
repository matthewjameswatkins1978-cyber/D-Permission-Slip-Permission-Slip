"""End-to-end vertical integration spike tests.

These exercise the real public ``tethers.authority/1`` seam over stdio against
the pinned Tethers R2 Authority Gate. Routine work must flow without approval;
consequential work must be intercepted, explained, and blocked until a fresh
COMMIT admits it.

Actor identity is always supplied as trusted harness context, never read from
the operation document.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from permission_slip.actions import ActionAdapterError
from permission_slip.doctrine import compile_doctrine, load_doctrine
from permission_slip.spike import (
    DECISION_ALLOW,
    DECISION_ASK,
    DECISION_DENY,
    PermissionSlip,
)
from permission_slip.tethers_client import discover_tethers
from permission_slip.tethers_install import AUTHORITY_PROTOCOL
from tests.support import (
    CANONICAL_IDENTITY,
    CANONICAL_REPOSITORY,
    EVIL_REMOTE_URL,
    add_remote,
    init_git_repo,
    set_push_urls,
    set_remote_url,
)

REPO = Path(__file__).resolve().parent.parent
DOCTRINE_PATH = REPO / "doctrine" / "matthew.v0.1.json"
COMMITTED_FIXTURE = REPO / "tethers-fixture"


def tests_op() -> dict:
    return {"tool": "tests", "argv": ["python", "-m", "unittest", "discover"]}


def edit_op(path: str = "runtime/spike-workspace/notes.txt") -> dict:
    return {"tool": "edit_file", "path": path}


def feature_push_op() -> dict:
    return {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]}


def merge_op() -> dict:
    return {"tool": "git", "argv": ["merge", "work/accepted"]}


def upload_op(destination: str = "https://new.example.com/drop", *, secret: bool = False) -> dict:
    operation = {"tool": "external_upload", "destination": destination}
    if secret:
        operation.update({"secret_material": True, "secret_kind": "api_key"})
    return operation


def force_push_op() -> dict:
    return {"tool": "git", "argv": ["push", "--force", "origin", "main"]}


def payment_op(amount_cents, funding: str, vendor: str = "cloud-fixture") -> dict:
    return {
        "tool": "payment",
        "amount_cents": amount_cents,
        "vendor": vendor,
        "funding": funding,
    }


def publish_op() -> dict:
    return {"tool": "publish", "channel": "public-blog", "as": "matthew"}


class VerticalSpikeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = discover_tethers()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-vertical-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        # A real temporary Git repository so push remotes resolve from trusted
        # local state. ``origin`` points at the canonical project repository.
        self.repo = init_git_repo(base / "repo")
        self.ps = PermissionSlip(
            DOCTRINE_PATH, workdir=base / "work", repo_root=self.repo, paths=self.paths
        )
        self.ps.start()
        self.addCleanup(self.ps.close)

    # -- helpers -----------------------------------------------------------

    def sandbox(self) -> Path:
        return self.repo / "runtime" / "spike-workspace"

    def upload_marker(self, destination: str) -> Path:
        return self.sandbox() / self.ps.executor.upload_marker_name(destination)

    # -- routine work ------------------------------------------------------

    def test_01_run_tests_allowed_without_approval_and_executes(self):
        def assert_not_yet(slip, prepared):
            self.assertFalse((self.sandbox() / "tests.log").exists())

        receipt = self.ps.run(
            tests_op(), "worker-agent", between_prepare_and_commit=assert_not_yet
        )
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertIsNone(receipt.approval_id)
        self.assertTrue(receipt.executed)
        self.assertEqual(receipt.outcome, "succeeded")
        self.assertTrue((self.sandbox() / "tests.log").exists())

    def test_02_edit_in_scope_allowed_and_only_after_commit(self):
        target = self.sandbox() / "notes.txt"

        def assert_not_yet(slip, prepared):
            self.assertFalse(target.exists())

        receipt = self.ps.run(
            edit_op(), "worker-agent", between_prepare_and_commit=assert_not_yet
        )
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertTrue(receipt.executed)
        self.assertTrue(target.exists())

    def test_03_feature_push_allowed_without_approval(self):
        receipt = self.ps.run(feature_push_op(), "worker-agent")
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertIsNone(receipt.approval_id)
        self.assertTrue(receipt.executed)
        self.assertTrue((self.sandbox() / "pushes.log").exists())

    def test_04_lucy_accepted_merge_allowed(self):
        receipt = self.ps.run(merge_op(), "lucy")
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertTrue(receipt.executed)
        self.assertIn("accepted-merge", receipt.effects)

    def test_05_worker_cannot_claim_lucy_merge_authority(self):
        receipt = self.ps.run(merge_op(), "worker-agent")
        self.assertIn(receipt.decision, (DECISION_DENY, DECISION_ASK))
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "merges.log").exists())

    def test_17_operation_actor_claim_cannot_spoof_lucy(self):
        # Trusted context is worker-agent; the operation lies that it is Lucy.
        operation = merge_op()
        operation["actor"] = "lucy"
        operation["approved"] = True
        receipt = self.ps.run(operation, "worker-agent")
        self.assertIn(receipt.decision, (DECISION_DENY, DECISION_ASK))
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.actor, "worker-agent")
        self.assertIn("actor", receipt.ignored_caller_claims)
        self.assertFalse((self.sandbox() / "merges.log").exists())

    # -- consequential work ------------------------------------------------

    def test_06_external_upload_asks_explains_and_requires_one_approval(self):
        destination = "https://new.example.com/drop"
        marker = self.upload_marker(destination)

        def assert_not_yet(slip, prepared):
            self.assertFalse(marker.exists())

        receipt = self.ps.run(
            upload_op(destination), "worker-agent", between_prepare_and_commit=assert_not_yet
        )
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertIsNotNone(receipt.approval_id)
        self.assertFalse(marker.exists())

        explanation = receipt.explanation["text"]
        self.assertIn(destination, explanation)
        self.assertIn("once", explanation)
        for question in ("what", "why", "changes"):
            self.assertTrue(receipt.explanation[question])

        approved = self.ps.approve(upload_op(destination), "worker-agent")
        self.assertEqual(approved.decision, DECISION_ALLOW)
        self.assertTrue(approved.executed)
        self.assertEqual(approved.outcome, "succeeded")
        self.assertTrue(marker.exists())

        # Approval is one-shot and not standing permission: a fresh attempt asks again.
        again = self.ps.run(upload_op(destination), "worker-agent")
        self.assertEqual(again.decision, DECISION_ASK)
        self.assertFalse(again.executed)

    def test_07_external_upload_without_approval_has_no_physical_effect(self):
        destination = "https://unapproved.example.com/drop"
        receipt = self.ps.run(upload_op(destination), "worker-agent")
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertFalse(self.upload_marker(destination).exists())

    def test_08_secret_upload_is_denied_with_no_effect(self):
        receipt = self.ps.run(
            upload_op("https://evil.example.com/drop", secret=True), "worker-agent"
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertFalse(receipt.executed)
        self.assertFalse(self.upload_marker("https://evil.example.com/drop").exists())

    def test_09_force_push_asks_and_does_not_execute_before_approval(self):
        log = self.sandbox() / "history-rewrite.log"
        receipt = self.ps.run(force_push_op(), "worker-agent")
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertFalse(log.exists())

        approved = self.ps.approve(force_push_op(), "worker-agent")
        self.assertEqual(approved.decision, DECISION_ALLOW)
        self.assertTrue(approved.executed)
        self.assertTrue(log.exists())

    def test_10_real_money_charge_asks(self):
        receipt = self.ps.run(payment_op(4200, "real"), "worker-agent")
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "charges.log").exists())

    def test_11_bounded_promotional_credit_allows_inside_and_not_outside(self):
        # Positive evidence for standing ALLOW: approved provider + promotional
        # source + strictly positive amount within the configured per-call limit.
        for amount in (1000, 5000):
            with self.subTest(amount=amount):
                allowed = self.ps.run(payment_op(amount, "promotional"), "worker-agent")
                self.assertEqual(allowed.decision, DECISION_ALLOW)
                self.assertTrue(allowed.executed)

        credit_log = self.sandbox() / "credit.log"
        admitted = credit_log.read_text(encoding="utf-8")

        denied_cases = (
            payment_op(5001, "promotional"),  # above per-call limit
            payment_op(1000, "promotional", vendor="other-vendor"),  # wrong provider
            payment_op(0, "promotional"),  # not a positive amount
            payment_op(-100, "promotional"),  # negative amount
        )
        for operation in denied_cases:
            with self.subTest(operation=operation):
                denied = self.ps.run(operation, "worker-agent")
                self.assertEqual(denied.decision, DECISION_DENY)
                self.assertFalse(denied.executed)
        self.assertEqual(credit_log.read_text(encoding="utf-8"), admitted)

    def test_18_non_feature_push_is_unmappable_and_denied(self):
        # Absence from the protected list is not positive feature authority.
        for name in ("production", "stable", "gh-pages", "shared", "arbitrary-name"):
            with self.subTest(name=name):
                receipt = self.ps.run(
                    {"tool": "git", "argv": ["push", "origin", name]}, "worker-agent"
                )
                self.assertEqual(receipt.decision, DECISION_DENY)
                self.assertEqual(receipt.reason, "unmappable_operation")
                self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())
        self.assertFalse((self.sandbox() / "history-rewrite.log").exists())

    def test_19_force_push_to_feature_branch_is_not_standing_allowed(self):
        receipt = self.ps.run(
            {"tool": "git", "argv": ["push", "--force", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())

    def test_20_malformed_payment_amount_fails_closed(self):
        for raw in ("1000", 1000.5, True, None, [1000]):
            with self.subTest(raw=raw):
                receipt = self.ps.run(payment_op(raw, "promotional"), "worker-agent")
                self.assertEqual(receipt.decision, DECISION_DENY)
                self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "credit.log").exists())

    # -- trusted remote resolution and exact action binding -----------------

    def _prepare_push(self, argv, evaluation_id: str):
        normalized = self.ps.adapter.normalize(
            {"tool": "git", "argv": argv}, actor_id="worker-agent"
        )
        payload = self.ps.prepare_payload(normalized, evaluation_id)
        response = self.ps.session.prepare(
            action_id=payload["action_id"],
            evaluation_id=payload["evaluation_id"],
            tether_id=payload["tether"]["id"],
            tether_version=payload["tether"]["version"],
            event_id=payload["event"]["id"],
            event_name=payload["event"]["name"],
            event_data=payload["event"]["data"],
            facts=payload["facts"],
        )
        return normalized, payload, response

    def test_21_canonical_remote_feature_push_is_allowed(self):
        receipt = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertIsNone(receipt.approval_id)
        self.assertTrue(receipt.executed)
        arguments = receipt.normalized["arguments"]
        self.assertEqual(arguments["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(
            arguments["destination_ref"], "refs/heads/feature/vertical-spike"
        )
        self.assertEqual(
            arguments["push_effect"], "push:refs/heads/feature/vertical-spike"
        )
        self.assertTrue((self.sandbox() / "pushes.log").exists())

    def test_22_wrong_remote_is_denied_without_execution(self):
        add_remote(self.repo, "evil-remote", EVIL_REMOTE_URL)
        receipt = self.ps.run(
            {"tool": "git", "argv": ["push", "evil-remote", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "unmappable_operation")
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())

    def test_23_origin_is_a_label_and_follows_current_configuration(self):
        # Hostile check: "origin" is a label, its resolved destination is the fact.
        allowed = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(allowed.decision, DECISION_ALLOW)

        set_remote_url(self.repo, "origin", EVIL_REMOTE_URL)
        denied = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(denied.decision, DECISION_DENY)
        self.assertEqual(denied.reason, "unmappable_operation")
        self.assertFalse(denied.executed)

        set_remote_url(self.repo, "origin", CANONICAL_REPOSITORY)
        restored = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(restored.decision, DECISION_ALLOW)

    def test_24_force_push_binds_remote_and_ref_into_tethers_input(self):
        receipt = self.ps.run(
            {"tool": "git", "argv": ["push", "--force", "origin", "main"]}, "worker-agent"
        )
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        arguments = receipt.normalized["arguments"]
        self.assertEqual(arguments["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(arguments["destination_ref"], "refs/heads/main")
        self.assertEqual(arguments["push_effect"], "force:refs/heads/main")

        # The bound fields are what Tethers actually receives, not just prose.
        normalized, payload, response = self._prepare_push(
            ["push", "--force", "origin", "main"], "eval-force-main"
        )
        self.assertEqual(response["decision"], "ask")
        event_data = payload["event"]["data"]
        self.assertEqual(event_data["remote_repository"], CANONICAL_IDENTITY)
        self.assertEqual(event_data["destination_ref"], "refs/heads/main")
        self.assertEqual(event_data["push_effect"], "force:refs/heads/main")
        self.assertTrue(response["approval"]["argument_digest"].startswith("sha256:"))
        self.assertIn("argument digest", response["approval"]["effect_summary"])

    def test_25_distinct_ref_effects_get_distinct_tethers_argument_digests(self):
        main_norm, main_payload, main_response = self._prepare_push(
            ["push", "--force", "origin", "main"], "eval-main"
        )
        release_norm, release_payload, release_response = self._prepare_push(
            ["push", "--force", "origin", "release"], "eval-release"
        )
        self.assertEqual(main_response["decision"], "ask")
        self.assertEqual(release_response["decision"], "ask")

        main_digest = main_response["approval"]["argument_digest"]
        release_digest = release_response["approval"]["argument_digest"]
        self.assertTrue(main_digest.startswith("sha256:"))
        self.assertNotEqual(main_digest, release_digest)
        # The prepared action identities differ too.
        self.assertNotEqual(main_response["prepared_id"], release_response["prepared_id"])
        # And Permission Slip's own view of the Tethers action input differs.
        self.assertNotEqual(main_payload["event"]["data"], release_payload["event"]["data"])
        self.assertNotEqual(
            main_norm.arguments["push_effect"], release_norm.arguments["push_effect"]
        )

    def test_26_wrong_remote_force_push_fails_closed_before_prepare(self):
        set_remote_url(self.repo, "origin", "https://github.com/someone-else/repo.git")
        with self.assertRaises(ActionAdapterError):
            self.ps.adapter.normalize(
                {"tool": "git", "argv": ["push", "--force", "origin", "main"]},
                actor_id="worker-agent",
            )
        receipt = self.ps.run(
            {"tool": "git", "argv": ["push", "--force", "origin", "main"]}, "worker-agent"
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "unmappable_operation")
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "history-rewrite.log").exists())

    # -- effect integrity: complete push URL set + COMMIT revalidation ------

    def test_27_multiple_push_urls_are_denied_without_execution(self):
        set_push_urls(self.repo, CANONICAL_REPOSITORY, EVIL_REMOTE_URL)
        first = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(first.decision, DECISION_DENY)
        self.assertEqual(first.reason, "unmappable_operation")
        self.assertFalse(first.executed)

        set_push_urls(self.repo, CANONICAL_REPOSITORY, CANONICAL_REPOSITORY + ".git")
        second = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(second.decision, DECISION_DENY)
        self.assertEqual(second.reason, "unmappable_operation")
        self.assertFalse(second.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())

        set_push_urls(self.repo, CANONICAL_REPOSITORY)
        restored = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(restored.decision, DECISION_ALLOW)
        self.assertTrue(restored.executed)

    def test_28_feature_push_remote_drift_rejected_at_commit_boundary(self):
        operation = {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]}

        def retarget(slip, prepared):
            set_remote_url(self.repo, "origin", EVIL_REMOTE_URL)

        receipt = self.ps.run(
            operation, "worker-agent", between_prepare_and_commit=retarget
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "trusted_context_changed")
        self.assertIn("trusted normalization failed", receipt.error)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())

    def test_29_force_push_remote_drift_is_not_rescued_by_approval(self):
        operation = {"tool": "git", "argv": ["push", "--force", "origin", "main"]}

        def retarget(slip, prepared):
            set_remote_url(self.repo, "origin", EVIL_REMOTE_URL)

        receipt = self.ps.approve(
            operation, "worker-agent", between_prepare_and_commit=retarget
        )
        # A human approval was granted for the prepared request...
        self.assertIsNotNone(receipt.approval_id)
        # ...but stale trusted context must not let it commit or execute.
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "trusted_context_changed")
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "history-rewrite.log").exists())

    def test_30_destination_ref_mutation_after_prepare_is_rejected(self):
        operation = {"tool": "git", "argv": ["push", "--force", "origin", "main"]}

        def mutate(slip, prepared):
            operation["argv"] = ["push", "--force", "origin", "release"]

        receipt = self.ps.approve(
            operation, "worker-agent", between_prepare_and_commit=mutate
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "trusted_context_changed")
        self.assertIn("trusted arguments changed", receipt.error)
        self.assertIn("refs/heads/main", receipt.error)
        self.assertIn("refs/heads/release", receipt.error)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "history-rewrite.log").exists())

    def test_31_authority_irrelevant_envelope_mutation_is_still_rejected(self):
        operation = {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]}

        def mutate(slip, prepared):
            operation["note"] = "unrelated caller field added after PREPARE"

        receipt = self.ps.run(
            operation, "worker-agent", between_prepare_and_commit=mutate
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertEqual(receipt.reason, "trusted_context_changed")
        self.assertIn("operation envelope changed", receipt.error)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "pushes.log").exists())

    def test_32_unchanged_trusted_context_still_commits(self):
        operation = {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]}

        def unchanged(slip, prepared):
            pass

        receipt = self.ps.run(
            operation, "worker-agent", between_prepare_and_commit=unchanged
        )
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertEqual(receipt.reason, "current_policy_allow")
        self.assertTrue(receipt.executed)
        self.assertEqual(receipt.outcome, "succeeded")
        self.assertTrue((self.sandbox() / "pushes.log").exists())

    def test_33_executor_records_the_bound_admitted_effect(self):
        # The executor consumes only the normalized action Tethers admitted; it
        # never re-reads the raw caller remote alias or ref labels.
        feature = self.ps.run(
            {"tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]},
            "worker-agent",
        )
        self.assertEqual(feature.decision, DECISION_ALLOW)
        feature_log = (self.sandbox() / "pushes.log").read_text(encoding="utf-8")
        self.assertIn(f"remote={CANONICAL_IDENTITY}", feature_log)
        self.assertIn("ref=refs/heads/feature/vertical-spike", feature_log)
        self.assertIn("effect=push:refs/heads/feature/vertical-spike", feature_log)
        self.assertNotIn("origin", feature_log)

        rewrite = self.ps.approve(
            {"tool": "git", "argv": ["push", "--force", "origin", "main"]},
            "worker-agent",
        )
        self.assertEqual(rewrite.decision, DECISION_ALLOW)
        self.assertTrue(rewrite.executed)
        rewrite_log = (self.sandbox() / "history-rewrite.log").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"remote={CANONICAL_IDENTITY}", rewrite_log)
        self.assertIn("ref=refs/heads/main", rewrite_log)
        self.assertIn("effect=force:refs/heads/main", rewrite_log)
        self.assertNotIn("origin", rewrite_log)

    def test_12_public_publication_asks(self):
        receipt = self.ps.run(publish_op(), "worker-agent")
        self.assertEqual(receipt.decision, DECISION_ASK)
        self.assertFalse(receipt.executed)
        self.assertFalse((self.sandbox() / "publications.log").exists())

    # -- last responsible moment and doctrine reuse ------------------------

    def test_13_authority_change_between_prepare_and_commit_blocks_dispatch(self):
        tests_log = self.sandbox() / "tests.log"

        def revoke(slip, prepared):
            self.assertEqual(prepared["decision"], "allow_prepared")
            slip.update_policy("dev.tests.run", "deny")

        receipt = self.ps.run(
            tests_op(), "worker-agent", between_prepare_and_commit=revoke
        )
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertFalse(receipt.executed)
        self.assertFalse(tests_log.exists())

    def test_14_second_agent_reuses_same_standing_doctrine(self):
        first = self.ps.run(tests_op(), "worker-agent")
        second = self.ps.run(tests_op(), "agent-two")
        edit = self.ps.run(edit_op(), "agent-two")
        for receipt in (first, second, edit):
            self.assertEqual(receipt.decision, DECISION_ALLOW)
            self.assertTrue(receipt.executed)

    # -- authority lies and truthful outcomes ------------------------------

    def test_15_caller_supplied_authority_cannot_manufacture_permission(self):
        lying = upload_op("https://evil.example.com/drop", secret=True)
        lying.update({"permission": True, "trusted": True, "approved": True, "decision": "ALLOW"})
        receipt = self.ps.run(lying, "worker-agent")
        self.assertEqual(receipt.decision, DECISION_DENY)
        self.assertFalse(receipt.executed)
        for claim in ("permission", "trusted", "approved", "decision"):
            self.assertIn(claim, receipt.ignored_caller_claims)

        # The Gate itself refuses forbidden authority keys on PREPARE.
        normalized = self.ps.adapter.normalize(tests_op(), "worker-agent")
        payload = self.ps.prepare_payload(normalized, "eval-forbidden-keys")
        payload["permission"] = True
        payload["authority_granted"] = True
        response = self.ps.session.request("prepare", payload)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"]["code"], "frame.forbidden_authority_key")

    def test_16_physical_failure_is_reported_as_failure_not_success(self):
        receipt = self.ps.run(tests_op(), "worker-agent", simulate_failure=True)
        self.assertEqual(receipt.decision, DECISION_ALLOW)
        self.assertTrue(receipt.executed)
        self.assertEqual(receipt.outcome, "failed")
        self.assertNotEqual(receipt.outcome, "succeeded")
        self.assertIsNotNone(receipt.error)


class FixtureAndPinningTests(unittest.TestCase):
    def test_committed_fixture_matches_doctrine(self):
        doctrine = load_doctrine(DOCTRINE_PATH)
        with tempfile.TemporaryDirectory(prefix="ps-fixture-") as tmp:
            compiled = compile_doctrine(doctrine, Path(tmp))
            self._assert_tree_equal(COMMITTED_FIXTURE, Path(tmp))
            self.assertTrue(compiled.config_path.exists())

    def _assert_tree_equal(self, left: Path, right: Path):
        left_files = sorted(p.relative_to(left) for p in left.rglob("*") if p.is_file())
        right_files = sorted(p.relative_to(right) for p in right.rglob("*") if p.is_file())
        self.assertEqual(left_files, right_files)
        for rel in left_files:
            self.assertEqual(
                (left / rel).read_text(encoding="utf-8"),
                (right / rel).read_text(encoding="utf-8"),
                f"fixture drift in {rel}",
            )

    def test_tethers_is_consumed_as_a_product_not_a_checkout(self):
        # Product identity, pairing and provenance -- never source lineage.
        installation = discover_tethers()
        self.assertTrue(installation.gate_bin.is_file())
        self.assertTrue(installation.engine_bin.is_file())
        self.assertEqual(installation.authority_protocol, AUTHORITY_PROTOCOL)
        self.assertRegex(installation.gate_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(installation.engine_sha256, r"^[0-9a-f]{64}$")
        self.assertIn(
            installation.verification, ("verified", "unverified", "dev_override")
        )
        # Normal operation must never route through a Tethers source checkout.
        self.assertNotEqual(installation.discovery_source, "dev_source_checkout")
        self.assertFalse(installation.is_dev)

        # No Git source lineage survives anywhere in the consumption boundary.
        import permission_slip.tethers_client as client_module
        import permission_slip.tethers_install as install_module

        for module in (install_module, client_module):
            source = Path(module.__file__).read_text(encoding="utf-8")
            with self.subTest(module=module.__name__):
                for retired in (
                    "REQUIRED_TETHERS_SHA",
                    "EXPECTED_ENGINE_SHA256",
                    "tree_equivalent",
                    "rev-parse",
                    "7e29110319c554a6586865ec6c47a45498696d16",
                ):
                    self.assertNotIn(retired, source)

    def test_git_capabilities_bind_remote_and_effect_in_the_fixture(self):
        # The remote/effect fields must reach the action Tethers sees, not just
        # Permission Slip's receipt or prose.
        for slug in ("git-push-feature", "git-history-rewrite"):
            with self.subTest(capability=slug):
                tether = (COMMITTED_FIXTURE / "tethers" / f"{slug}.tether").read_text(
                    encoding="utf-8"
                )
                for field in ("repository", "remote_repository", "destination_ref", "push_effect"):
                    self.assertIn(f"{field}: anchor.{field}", tether)

                manifest = json.loads(
                    (COMMITTED_FIXTURE / "manifests" / f"{slug}.json").read_text(
                        encoding="utf-8"
                    )
                )
                expected = {
                    "repository",
                    "remote_repository",
                    "destination_ref",
                    "push_effect",
                }
                self.assertEqual(set(manifest["input_schema"]["required"]), expected)
                self.assertEqual(manifest["input_schema"]["additionalProperties"], False)
                self.assertEqual(
                    manifest["permission_scope"],
                    {"kind": "path_prefix", "allowed_prefixes": ["runtime/spike-workspace/"]},
                )

    def test_path_scope_still_binds_the_local_repository_argument(self):
        runtime = json.loads(
            (COMMITTED_FIXTURE / "runtime.json").read_text(encoding="utf-8")
        )
        bindings = {
            cap["name"]: cap.get("scope_binding")
            for cap in runtime["providers"][0]["capabilities"]
        }
        pointer = {"kind": "path_prefix", "argument_json_pointer": "/repository"}
        self.assertEqual(bindings["git.push.feature"], pointer)
        self.assertEqual(bindings["git.history.rewrite"], pointer)
        # Merge is unchanged: it is not a remote/ref push effect.
        self.assertEqual(bindings["git.merge.accepted"], pointer)

    def test_merge_capability_arguments_are_unchanged(self):
        manifest = json.loads(
            (COMMITTED_FIXTURE / "manifests" / "git-merge-accepted.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["input_schema"]["required"], ["repository"])


if __name__ == "__main__":
    unittest.main()
