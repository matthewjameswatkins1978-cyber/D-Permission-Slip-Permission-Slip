"""Trusted action adapter tests.

These run without Tethers: they prove that the semantic normalisation boundary
derives authority-relevant facts from the actual operation and ignores anything
the caller claims about itself.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from permission_slip.actions import ActionAdapter, ActionAdapterError, UntrustedActorError
from permission_slip.doctrine import load_doctrine

REPO = Path(__file__).resolve().parent.parent
DOCTRINE = load_doctrine(REPO / "doctrine" / "matthew.v0.1.json")


class ActionNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.adapter = ActionAdapter(DOCTRINE, repo_root=self.repo)

    def test_force_push_is_history_rewrite_from_argv_not_label(self):
        operation = {
            "actor": "worker-agent",
            "tool": "git",
            "argv": ["push", "--force", "origin", "main"],
            # The caller tries to relabel a history rewrite as a safe feature push.
            "action": "git.push.feature",
            "is_force_push": False,
        }
        result = self.adapter.normalize(operation)
        self.assertEqual(result.action, "git.history.rewrite")
        self.assertIn("action", result.ignored_caller_claims)

    def test_plain_feature_push_is_feature(self):
        result = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "git", "argv": ["push", "origin", "feature/vertical-spike"]}
        )
        self.assertEqual(result.action, "git.push.feature")

    def test_non_force_push_to_shared_branch_is_still_consequential(self):
        result = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "git", "argv": ["push", "origin", "main"]}
        )
        self.assertEqual(result.action, "git.history.rewrite")

    def test_merge_authority_comes_from_trusted_profile(self):
        lucy = self.adapter.normalize(
            {"actor": "lucy", "tool": "git", "argv": ["merge", "work/accepted"]}
        )
        self.assertEqual(lucy.action, "git.merge.accepted")
        self.assertTrue(lucy.facts["actor.merge_authority"])

        worker = self.adapter.normalize(
            {
                "actor": "worker-agent",
                "tool": "git",
                "argv": ["merge", "work/accepted"],
                # A caller claim cannot manufacture merge authority.
                "merge_authority": True,
                "approved": True,
            }
        )
        self.assertFalse(worker.facts["actor.merge_authority"])
        self.assertIn("approved", worker.ignored_caller_claims)

    def test_secret_material_takes_precedence_over_repository_upload(self):
        result = self.adapter.normalize(
            {
                "actor": "worker-agent",
                "tool": "external_upload",
                "destination": "https://new.example.com/drop",
                "secret_material": True,
                "secret_kind": "api_key",
            }
        )
        self.assertEqual(result.action, "data.external_upload.secret")

    def test_bounded_promotional_credit_fact_is_derived(self):
        within = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "payment", "amount_cents": 1000, "funding": "promotional", "vendor": "cloud-fixture"}
        )
        outside = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "payment", "amount_cents": 9000, "funding": "promotional", "vendor": "cloud-fixture"}
        )
        self.assertEqual(within.action, "money.promotional_credit.use")
        self.assertTrue(within.facts["promo.within_budget"])
        self.assertFalse(outside.facts["promo.within_budget"])

    def test_real_money_is_not_promotional(self):
        result = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "payment", "amount_cents": 100, "funding": "real", "vendor": "cloud-fixture"}
        )
        self.assertEqual(result.action, "money.real_charge")
        self.assertNotIn("promo.within_budget", result.facts)

    def test_absolute_edit_path_is_normalised_relative(self):
        absolute = os.path.join(self.repo, "runtime", "spike-workspace", "notes.txt")
        result = self.adapter.normalize(
            {"actor": "worker-agent", "tool": "edit_file", "path": absolute, "cwd": str(self.repo)}
        )
        self.assertEqual(result.arguments["path"], "runtime/spike-workspace/notes.txt")

    def test_untrusted_actor_is_rejected(self):
        with self.assertRaises(UntrustedActorError):
            self.adapter.normalize({"actor": "stranger", "tool": "tests", "argv": []})

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(ActionAdapterError):
            self.adapter.normalize({"actor": "worker-agent", "tool": "shell", "argv": ["rm", "-rf", "/"]})


if __name__ == "__main__":
    unittest.main()
