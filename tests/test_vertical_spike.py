"""End-to-end vertical integration spike tests.

These exercise the real public ``tethers.authority/1`` seam over stdio against
the pinned Tethers R2 Authority Gate. Routine work must flow without approval;
consequential work must be intercepted, explained, and blocked until a fresh
COMMIT admits it.

Actor identity is always supplied as trusted harness context, never read from
the operation document.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from permission_slip.doctrine import compile_doctrine, load_doctrine
from permission_slip.spike import (
    DECISION_ALLOW,
    DECISION_ASK,
    DECISION_DENY,
    PermissionSlip,
)
from permission_slip.tethers_client import (
    EXPECTED_ENGINE_SHA256,
    REQUIRED_TETHERS_SHA,
    discover_tethers,
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
        self.repo = base / "repo"
        self.repo.mkdir(parents=True, exist_ok=True)
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

    def test_tethers_lineage_and_engine_artifact_are_pinned(self):
        paths = discover_tethers()
        self.assertEqual(paths.required_sha, REQUIRED_TETHERS_SHA)
        self.assertIn(paths.verification, ("exact", "tree_equivalent"))
        self.assertEqual(paths.engine_sha256, EXPECTED_ENGINE_SHA256)
        self.assertTrue(paths.engine_matches_artifact)


if __name__ == "__main__":
    unittest.main()
