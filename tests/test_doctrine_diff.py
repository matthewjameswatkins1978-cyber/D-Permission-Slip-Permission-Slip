"""Domain-aware doctrine diff: classification, naming, and order sensitivity."""

from __future__ import annotations

import unittest
from typing import Any, Callable

from permission_slip.doctrine_diff import (
    CONSEQUENTIAL,
    DIFF_SCHEMA,
    PRESENTATION,
    diff_doctrines,
    render_human,
)
from tests.support import matthew_doctrine

Change = Callable[[dict[str, Any]], None]


def diff(before: Change | None = None, after: Change | None = None) -> dict[str, Any]:
    left, right = matthew_doctrine(), matthew_doctrine()
    if before:
        before(left)
    if after:
        after(right)
    return diff_doctrines(left, right)


def consequences(envelope: dict[str, Any]) -> list[str]:
    return [item["consequence"] for item in envelope["changes"]]


def only(envelope: dict[str, Any]) -> dict[str, Any]:
    """Exactly one change, so a test cannot pass on an unrelated difference."""
    if len(envelope["changes"]) != 1:
        raise AssertionError(
            "expected exactly one change, got: "
            + " | ".join(consequences(envelope))
        )
    return envelope["changes"][0]


class DiffEnvelopeTests(unittest.TestCase):
    def test_identical_doctrines_report_no_changes(self):
        envelope = diff()
        self.assertEqual(envelope["schema"], DIFF_SCHEMA)
        self.assertFalse(envelope["changed"])
        self.assertEqual(envelope["changes"], [])
        self.assertIn("No changes.", render_human(envelope))

    def test_changed_digest_sets_changed_true(self):
        envelope = diff(after=lambda d: d["human"].update(display_name="M"))
        self.assertTrue(envelope["changed"])
        self.assertNotEqual(envelope["before_digest"], envelope["after_digest"])

    def test_human_rendering_never_scores_the_change(self):
        envelope = diff(after=lambda d: d["capabilities"][6].update(standing="allow"))
        text = render_human(envelope).lower()
        for forbidden in ("safer", "less safe", "therefore this action is authorised"):
            self.assertNotIn(forbidden, text)


class PresentationDiffTests(unittest.TestCase):
    def test_note_change_is_presentation(self):
        change = only(diff(after=lambda d: d["human"].update(note="Different.")))
        self.assertEqual(change["classification"], PRESENTATION)
        self.assertIn("human note changed", change["consequence"])

    def test_display_name_change_is_presentation(self):
        change = only(
            diff(after=lambda d: d["human"].update(display_name="Matt"))
        )
        self.assertEqual(change["classification"], PRESENTATION)
        self.assertIn("human display name changed", change["consequence"])

    def test_capability_purpose_change_is_presentation(self):
        change = only(
            diff(after=lambda d: d["capabilities"][0].update(purpose="Run tests."))
        )
        self.assertEqual(change["classification"], PRESENTATION)
        self.assertIn("dev.tests.run purpose changed", change["consequence"])

    def test_project_display_name_is_presentation(self):
        change = only(
            diff(after=lambda d: d["project"].update(display_name="Perm Slip"))
        )
        self.assertEqual(change["classification"], PRESENTATION)


class ConsequentialDiffTests(unittest.TestCase):
    def test_actor_trusted_false_to_true(self):
        change = only(
            diff(
                before=lambda d: d["actors"]["worker-agent"].update(trusted=False),
            )
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("actor worker-agent trusted changed false -> true", change["consequence"])

    def test_actor_merge_authority_false_to_true(self):
        change = only(
            diff(after=lambda d: d["actors"]["worker-agent"].update(merge_authority=True))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "actor worker-agent merge_authority changed false -> true",
            change["consequence"],
        )

    def test_standing_ask_to_allow(self):
        change = only(
            diff(after=lambda d: d["capabilities"][6].update(standing="allow"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "git.history.rewrite standing changed ASK -> ALLOW", change["consequence"]
        )

    def test_standing_allow_to_deny(self):
        change = only(
            diff(after=lambda d: d["capabilities"][0].update(standing="deny"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "dev.tests.run standing changed ALLOW -> DENY", change["consequence"]
        )

    def test_capability_added(self):
        def add_capability(document: dict[str, Any]) -> None:
            document["capabilities"].append(
                {
                    "action": "time.travel",
                    "purpose": "Move the clock.",
                    "standing": "ask",
                    "scope": {"kind": "unrestricted"},
                    "reversibility": "irreversible",
                    "effects": ["time.shift"],
                }
            )

        change = only(diff(after=add_capability))
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("capability time.travel added", change["consequence"])
        self.assertEqual(change["change"], "added")

    def test_capability_removed(self):
        def remove_capability(document: dict[str, Any]) -> None:
            document["capabilities"] = [
                item
                for item in document["capabilities"]
                if item["action"] != "money.real_charge"
            ]

        change = only(diff(after=remove_capability))
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("capability money.real_charge removed", change["consequence"])
        self.assertEqual(change["change"], "removed")

    def test_path_scope_widened(self):
        change = only(
            diff(
                after=lambda d: d["capabilities"][0]["scope"]["prefixes"].append(
                    "runtime/spike-workspace/nested/"
                )
            )
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("dev.tests.run path scope widened", change["consequence"])
        self.assertIn("added", change["consequence"])

    def test_path_scope_narrowed(self):
        change = only(
            diff(
                before=lambda d: d["capabilities"][0]["scope"]["prefixes"].append(
                    "runtime/spike-workspace/nested/"
                )
            )
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("dev.tests.run path scope narrowed", change["consequence"])
        self.assertIn("removed", change["consequence"])

    def test_scope_kind_change_is_consequential(self):
        change = only(
            diff(after=lambda d: d["capabilities"][4].update(scope={"kind": "path_prefix", "prefixes": ["runtime/spike-workspace/"]}))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("scope kind changed", change["consequence"])

    def test_required_fact_removed(self):
        change = only(
            diff(after=lambda d: d["capabilities"][3].pop("requires"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "git.merge.accepted required fact removed: actor.merge_authority",
            change["consequence"],
        )

    def test_effect_changed(self):
        envelope = diff(
            after=lambda d: d["capabilities"][0].update(effects=["compute.burst"])
        )
        self.assertEqual(
            consequences(envelope),
            [
                "dev.tests.run effect removed: compute.run",
                "dev.tests.run effect added: compute.burst",
            ],
        )
        for change in envelope["changes"]:
            self.assertEqual(change["classification"], CONSEQUENTIAL)

    def test_reversibility_changed(self):
        change = only(
            diff(after=lambda d: d["capabilities"][2].update(reversibility="irreversible"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "git.push.feature reversibility changed compensatable -> irreversible",
            change["consequence"],
        )

    def test_canonical_repository_changed(self):
        change = only(
            diff(
                after=lambda d: d["project"].update(
                    canonical_repository="https://github.com/someone-else/repo"
                )
            )
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("project canonical repository changed", change["consequence"])

    def test_root_scope_changed(self):
        change = only(
            diff(after=lambda d: d["project"].update(root_scope="runtime/other/"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("project root scope changed", change["consequence"])

    def test_promotional_limit_increased(self):
        change = only(
            diff(after=lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=9000))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "promotional credit per-call limit increased from 5000 to 9000 cents",
            change["consequence"],
        )

    def test_promotional_limit_decreased(self):
        change = only(
            diff(after=lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=100))
        )
        self.assertIn(
            "promotional credit per-call limit decreased from 5000 to 100 cents",
            change["consequence"],
        )

    def test_promotional_provider_changed(self):
        change = only(
            diff(after=lambda d: d["boundaries"]["promotional_credit"].update(provider="other-fixture"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("promotional credit provider changed", change["consequence"])

    def test_public_identity_subject_changed(self):
        change = only(
            diff(after=lambda d: d["boundaries"]["public_identity"].update(subject="lucy"))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("public identity subject changed", change["consequence"])

    def test_known_destination_set_changed(self):
        change = only(
            diff(after=lambda d: d["boundaries"]["external_upload"].update(known_destinations=["https://new.example/drop"]))
        )
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn(
            "external upload known destination added: https://new.example/drop",
            change["consequence"],
        )

    def test_actor_added_and_removed_are_consequential(self):
        def replace_actor(document: dict[str, Any]) -> None:
            document["actors"].pop("agent-two")
            document["actors"]["mallory"] = {
                "id": "mallory",
                "display_name": "Mallory",
                "trusted": True,
                "merge_authority": False,
            }

        envelope = diff(after=replace_actor)
        self.assertEqual(len(envelope["changes"]), 2)
        for change in envelope["changes"]:
            self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("actor agent-two removed", consequences(envelope)[0])
        self.assertIn("actor mallory added", consequences(envelope)[1])


class OrderSensitivityTests(unittest.TestCase):
    def test_capability_reorder_is_visible(self):
        change = only(diff(after=lambda d: d["capabilities"].reverse()))
        self.assertEqual(change["classification"], CONSEQUENTIAL)
        self.assertIn("capability order changed", change["consequence"])
        self.assertTrue(diff(after=lambda d: d["capabilities"].reverse())["changed"])

    def test_reorder_is_not_reported_as_no_changes(self):
        envelope = diff(after=lambda d: d["capabilities"].reverse())
        self.assertNotIn("No changes.", render_human(envelope))

    def test_effect_reorder_is_visible(self):
        def reorder_effects(document: dict[str, Any]) -> None:
            document["capabilities"][0]["effects"] = ["compute.run", "data.write"]

        def again(document: dict[str, Any]) -> None:
            document["capabilities"][0]["effects"] = ["data.write", "compute.run"]

        envelope = diff(before=reorder_effects, after=again)
        self.assertEqual(len(envelope["changes"]), 1)
        self.assertIn("effect order changed", consequences(envelope)[0])

    def test_requires_reorder_is_visible(self):
        def before(document: dict[str, Any]) -> None:
            document["capabilities"][3]["requires"] = ["actor.merge_authority", "promo.within_bound"]

        def after(document: dict[str, Any]) -> None:
            document["capabilities"][3]["requires"] = ["promo.within_bound", "actor.merge_authority"]

        envelope = diff(before, after)
        self.assertEqual(len(envelope["changes"]), 1)
        self.assertIn("required fact order changed", consequences(envelope)[0])


class HumanRenderingTests(unittest.TestCase):
    def test_rendering_names_the_concrete_semantic_item(self):
        envelope = diff(after=lambda d: d["capabilities"][6].update(standing="allow"))
        text = render_human(envelope)
        self.assertIn(
            "git.history.rewrite standing changed ASK -> ALLOW", text
        )
        self.assertIn("[CONSEQUENTIAL]", text)

    def test_rendering_states_counts(self):
        envelope = diff(
            after=lambda d: (
                d["capabilities"][6].update(standing="allow"),
                d["human"].update(note="Different."),
            )
        )
        text = render_human(envelope)
        self.assertIn("2 changes: 1 consequential, 1 presentation", text)

    def test_every_change_carries_path_subject_and_consequence(self):
        envelope = diff(
            after=lambda d: (
                d["capabilities"][6].update(standing="allow"),
                d["human"].update(note="Different."),
            )
        )
        for change in envelope["changes"]:
            self.assertTrue(change["path"].startswith("$"))
            self.assertTrue(change["subject"])
            self.assertTrue(change["consequence"])
            self.assertIn(change["classification"], (CONSEQUENTIAL, PRESENTATION))


if __name__ == "__main__":
    unittest.main()
