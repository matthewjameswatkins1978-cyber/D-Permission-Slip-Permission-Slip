"""Doctrine Contract v1: structure, canonicalisation, digest, compiler boundary.

The contract answers "is this a valid Permission Slip doctrine document?" and
nothing else. These tests pin that question, the deterministic identity it
produces, and the line where a *valid* document can still be unsupported by the
compiler.
"""

from __future__ import annotations

import copy
import json
import random
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from permission_slip.doctrine import DoctrineError, compile_doctrine, load_doctrine
from permission_slip.doctrine_contract import (
    SCHEMA_ID,
    DoctrineValidationError,
    canonical_digest,
    canonical_doctrine_bytes,
    parse_doctrine_json,
    validate_doctrine,
)

REPO = Path(__file__).resolve().parent.parent
DOCTRINE_PATH = REPO / "doctrine" / "matthew.v0.1.json"

# Pinned so a silent change to validation or canonicalisation cannot change
# the identity of the accepted Customer Zero doctrine unnoticed.
MATTHEW_DIGEST = "sha256:099ba9638dedbb0dc71e28222a0f971db38256a04dc270ea7523cc1eb002adfd"


def base() -> dict[str, Any]:
    """The current doctrine as an unvalidated, freely mutable document."""
    return json.loads(DOCTRINE_PATH.read_text(encoding="utf-8"))


def shuffled(value: Any, seed: int = 1234) -> Any:
    """Rebuild ``value`` with every object's keys visited in a fixed random order."""
    rng = random.Random(seed)

    def walk(item: Any) -> Any:
        if isinstance(item, dict):
            keys = list(item)
            rng.shuffle(keys)
            return {key: walk(item[key]) for key in keys}
        if isinstance(item, list):
            return [walk(entry) for entry in item]
        return item

    return walk(value)


class ContractValidityTests(unittest.TestCase):
    def test_current_matthew_doctrine_validates(self):
        document = validate_doctrine(base())
        self.assertEqual(document["schema"], SCHEMA_ID)

    def test_validation_returns_the_same_document(self):
        document = base()
        self.assertIs(validate_doctrine(document), document)

    def test_canonical_bytes_are_stable_across_presentation(self):
        document = base()
        pretty = json.loads(json.dumps(document, indent=4))
        reordered = shuffled(document)
        self.assertEqual(
            canonical_doctrine_bytes(document),
            canonical_doctrine_bytes(pretty),
        )
        self.assertEqual(
            canonical_doctrine_bytes(document),
            canonical_doctrine_bytes(reordered),
        )

    def test_canonical_bytes_round_trip_to_the_same_meaning(self):
        document = base()
        self.assertEqual(json.loads(canonical_doctrine_bytes(document)), document)

    def test_current_matthew_doctrine_digest_is_recorded(self):
        self.assertEqual(canonical_digest(base()), MATTHEW_DIGEST)

    def test_digest_is_sha256_lowercase_hex(self):
        self.assertRegex(
            canonical_digest(base()), r"^sha256:[0-9a-f]{64}$"
        )

    def test_load_doctrine_returns_a_valid_document(self):
        self.assertEqual(load_doctrine(DOCTRINE_PATH)["profile"], "matthew.v0.1")


class DigestSemanticsTests(unittest.TestCase):
    def digest(self, mutate: Callable[[dict[str, Any]], None]) -> str:
        document = base()
        mutate(document)
        return canonical_digest(document)

    def test_pretty_print_does_not_alter_digest(self):
        document = base()
        reparsed = json.loads(json.dumps(document, indent=8, sort_keys=False))
        self.assertEqual(canonical_digest(reparsed), canonical_digest(document))

    def test_object_key_order_does_not_alter_digest(self):
        document = base()
        reordered = shuffled(document)
        self.assertNotEqual(list(reordered), list(document))
        self.assertEqual(canonical_digest(reordered), canonical_digest(document))

    def test_actual_value_change_alters_digest(self):
        changed = self.digest(lambda d: d["human"].update(display_name="Not Matthew"))
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_actor_authority_change_alters_digest(self):
        changed = self.digest(lambda d: d["actors"]["lucy"].update(merge_authority=False))
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_standing_allow_to_ask_alters_digest(self):
        changed = self.digest(lambda d: d["capabilities"][0].update(standing="ask"))
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_scope_change_alters_digest(self):
        changed = self.digest(
            lambda d: d["capabilities"][0]["scope"].update(
                prefixes=["runtime/spike-workspace/nested/"]
            )
        )
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_effect_change_alters_digest(self):
        changed = self.digest(
            lambda d: d["capabilities"][0].update(effects=["compute.run", "data.write"])
        )
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_array_reordering_alters_digest_under_the_conservative_v1_rule(self):
        changed = self.digest(lambda d: d["capabilities"].reverse())
        self.assertNotEqual(changed, canonical_digest(base()))

    def test_digest_rejects_an_invalid_document(self):
        broken = base()
        broken["capabilities"][0].pop("purpose")
        with self.assertRaises(DoctrineValidationError):
            canonical_digest(broken)


class InvalidDoctrineTests(unittest.TestCase):
    def assert_invalid(
        self,
        mutate: Callable[[dict[str, Any]], None],
        *,
        path: str | None = None,
        contains: str | None = None,
    ) -> DoctrineValidationError:
        document = base()
        mutate(document)
        with self.assertRaises(DoctrineValidationError) as caught:
            validate_doctrine(document)
        error = caught.exception
        self.assertIsInstance(error, ValueError)
        if path is not None:
            self.assertEqual(error.path, path)
        if contains is not None:
            self.assertIn(contains, str(error))
        return error

    # -- top level --------------------------------------------------------

    def test_wrong_schema_fails_closed(self):
        self.assert_invalid(
            lambda d: d.update(schema="permission-slip.doctrine/99"),
            path="$.schema",
            contains="unsupported doctrine schema",
        )

    def test_missing_required_top_level_field(self):
        self.assert_invalid(lambda d: d.pop("profile"), path="$.profile")

    def test_unknown_dangerous_top_level_field(self):
        self.assert_invalid(
            lambda d: d.update(authority={"widen": True}), path="$.authority"
        )

    def test_primitive_type_must_be_a_string(self):
        self.assert_invalid(lambda d: d.update(profile=123), path="$.profile")

    def test_whitespace_only_profile_is_not_an_identifier(self):
        self.assert_invalid(lambda d: d.update(profile="   "), path="$.profile")

    def test_top_level_must_be_an_object(self):
        with self.assertRaises(DoctrineValidationError) as caught:
            validate_doctrine([])
        self.assertEqual(caught.exception.path, "$")

    # -- human ------------------------------------------------------------

    def test_malformed_human_is_not_an_object(self):
        self.assert_invalid(lambda d: d.update(human="matthew"), path="$.human")

    def test_human_missing_display_name(self):
        self.assert_invalid(lambda d: d["human"].pop("display_name"), path="$.human.display_name")

    def test_human_id_must_be_a_string(self):
        self.assert_invalid(lambda d: d["human"].update(id=7), path="$.human.id")

    def test_human_note_must_be_a_string(self):
        self.assert_invalid(lambda d: d["human"].update(note=42), path="$.human.note")

    def test_unknown_human_field(self):
        self.assert_invalid(lambda d: d["human"].update(title="Boss"), path="$.human.title")

    # -- project ----------------------------------------------------------

    def test_project_missing_root_scope(self):
        self.assert_invalid(lambda d: d["project"].pop("root_scope"), path="$.project.root_scope")

    def test_project_repository_must_be_canonical(self):
        self.assert_invalid(
            lambda d: d["project"].update(canonical_repository="https://example.com/any/repo"),
            path="$.project.canonical_repository",
        )

    # -- actors -----------------------------------------------------------

    def test_actor_map_key_and_id_must_agree(self):
        self.assert_invalid(lambda d: d["actors"]["lucy"].update(id="lucille"), path="$.actors.lucy.id")

    def test_actor_trust_must_be_boolean(self):
        self.assert_invalid(lambda d: d["actors"]["lucy"].update(trusted=1), path="$.actors.lucy.trusted")

    def test_actor_merge_authority_must_be_boolean_where_present(self):
        self.assert_invalid(
            lambda d: d["actors"]["lucy"].update(merge_authority="yes"),
            path="$.actors.lucy.merge_authority",
        )

    def test_actors_must_be_a_non_empty_object(self):
        self.assert_invalid(lambda d: d.update(actors={}), path="$.actors")
        self.assert_invalid(lambda d: d.update(actors=[]), path="$.actors")

    def test_unknown_actor_field(self):
        self.assert_invalid(
            lambda d: d["actors"]["lucy"].update(elevated=True), path="$.actors.lucy.elevated"
        )

    # -- capabilities -----------------------------------------------------

    def test_duplicate_capability_action_is_rejected(self):
        def mutate(document: dict[str, Any]) -> None:
            document["capabilities"].append(copy.deepcopy(document["capabilities"][0]))

        error = self.assert_invalid(mutate, path="$.capabilities[10]")
        self.assertIn('duplicate capability action "dev.tests.run"', str(error))

    def test_unsupported_standing_value(self):
        error = self.assert_invalid(
            lambda d: d["capabilities"][3].update(standing="maybe"),
            path="$.capabilities[3].standing",
        )
        self.assertIn('unsupported value "maybe"', str(error))

    def test_standing_must_be_a_string(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0].update(standing=1),
            path="$.capabilities[0].standing",
        )

    def test_malformed_path_prefix_is_not_a_list(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0]["scope"].update(prefixes="runtime/spike-workspace/"),
            path="$.capabilities[0].scope.prefixes",
        )

    def test_empty_prefixes(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0]["scope"].update(prefixes=[]),
            path="$.capabilities[0].scope.prefixes",
        )

    def test_empty_string_prefix(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0]["scope"].update(prefixes=[""]),
            path="$.capabilities[0].scope.prefixes[0]",
        )

    def test_unsupported_scope_kind_is_not_part_of_v1(self):
        def mutate(document: dict[str, Any]) -> None:
            document["capabilities"][0]["scope"] = {"kind": "repository"}

        error = self.assert_invalid(mutate, path="$.capabilities[0].scope.kind")
        self.assertIn('unsupported value "repository"', str(error))

    def test_prefixes_are_not_allowed_on_an_unrestricted_scope(self):
        def mutate(document: dict[str, Any]) -> None:
            document["capabilities"][4]["scope"]["prefixes"] = ["runtime/spike-workspace/"]

        self.assert_invalid(mutate, path="$.capabilities[4].scope.prefixes")

    def test_scope_is_required(self):
        self.assert_invalid(lambda d: d["capabilities"][0].pop("scope"), path="$.capabilities[0].scope")

    def test_invalid_reversibility(self):
        error = self.assert_invalid(
            lambda d: d["capabilities"][0].update(reversibility="undoable"),
            path="$.capabilities[0].reversibility",
        )
        self.assertIn('unsupported value "undoable"', str(error))

    def test_malformed_effects_is_not_a_list(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0].update(effects="compute.run"),
            path="$.capabilities[0].effects",
        )

    def test_empty_effects(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0].update(effects=[]),
            path="$.capabilities[0].effects",
        )

    def test_effect_must_be_a_non_empty_string(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0].update(effects=[" "]),
            path="$.capabilities[0].effects[0]",
        )

    def test_requires_must_be_a_list(self):
        self.assert_invalid(
            lambda d: d["capabilities"][3].update(requires="actor.merge_authority"),
            path="$.capabilities[3].requires",
        )

    def test_requires_must_be_unique(self):
        self.assert_invalid(
            lambda d: d["capabilities"][3].update(requires=["actor.merge_authority", "actor.merge_authority"]),
            path="$.capabilities[3].requires[1]",
        )

    def test_requires_element_must_be_a_string(self):
        self.assert_invalid(
            lambda d: d["capabilities"][3].update(requires=[True]),
            path="$.capabilities[3].requires[0]",
        )

    def test_unknown_capability_field(self):
        self.assert_invalid(
            lambda d: d["capabilities"][0].update(metadata={"widen": True}),
            path="$.capabilities[0].metadata",
        )

    def test_capabilities_must_be_a_non_empty_list(self):
        self.assert_invalid(lambda d: d.update(capabilities=[]), path="$.capabilities")
        self.assert_invalid(lambda d: d.update(capabilities={}), path="$.capabilities")

    def test_capability_purpose_is_required(self):
        self.assert_invalid(lambda d: d["capabilities"][0].pop("purpose"), path="$.capabilities[0].purpose")

    # -- boundaries -------------------------------------------------------

    def test_unknown_boundary_section(self):
        self.assert_invalid(
            lambda d: d["boundaries"].update(repository_scope={"kind": "path_prefix"}),
            path="$.boundaries.repository_scope",
        )

    def test_bad_promotional_credit_bound_is_zero(self):
        error = self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=0),
            path="$.boundaries.promotional_credit.per_call_limit_cents",
        )
        self.assertIn("must be > 0", str(error))

    def test_bad_promotional_credit_bound_is_negative(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=-1),
            path="$.boundaries.promotional_credit.per_call_limit_cents",
        )

    def test_promotional_credit_bound_must_be_an_integer(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=5000.5),
            path="$.boundaries.promotional_credit.per_call_limit_cents",
        )

    def test_promotional_credit_bound_must_not_be_a_boolean(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].update(per_call_limit_cents=True),
            path="$.boundaries.promotional_credit.per_call_limit_cents",
        )

    def test_promotional_credit_provider_is_required(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].pop("provider"),
            path="$.boundaries.promotional_credit.provider",
        )

    def test_promotional_credit_currency_is_required(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].pop("currency"),
            path="$.boundaries.promotional_credit.currency",
        )

    def test_promotional_credit_rejects_cumulative_spend_semantics(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["promotional_credit"].update(total_budget_cents=100000),
            path="$.boundaries.promotional_credit.total_budget_cents",
        )

    def test_known_destinations_may_start_empty(self):
        document = base()
        document["boundaries"]["external_upload"]["known_destinations"] = []
        validate_doctrine(document)

    def test_known_destination_must_be_a_non_empty_string(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["external_upload"].update(known_destinations=[None]),
            path="$.boundaries.external_upload.known_destinations[0]",
        )

    def test_public_identity_subject_is_required(self):
        self.assert_invalid(
            lambda d: d["boundaries"]["public_identity"].pop("subject"),
            path="$.boundaries.public_identity.subject",
        )


class ParsingTests(unittest.TestCase):
    def test_invalid_json_reports_a_contract_error_not_a_decoder_error(self):
        with self.assertRaises(DoctrineValidationError) as caught:
            parse_doctrine_json("{not json")
        self.assertEqual(caught.exception.path, "$")

    def test_duplicate_top_level_key_is_not_silently_collapsed(self):
        with self.assertRaises(DoctrineValidationError) as caught:
            parse_doctrine_json(
                '{"schema": "permission-slip.doctrine/1", '
                '"schema": "permission-slip.doctrine/1"}'
            )
        self.assertIn('duplicate object key "schema"', str(caught.exception))

    def test_duplicate_nested_key_is_rejected(self):
        with self.assertRaises(DoctrineValidationError) as caught:
            parse_doctrine_json('{"outer": {"k": 1, "k": 2}}')
        self.assertIn('duplicate object key "k"', str(caught.exception))

    def test_duplicate_actor_identity_cannot_be_hidden_in_the_source(self):
        document = base()
        compact = json.dumps(document)
        actor = json.dumps(document["actors"]["matthew"])
        needle = f'"matthew": {actor}'
        self.assertEqual(compact.count(needle), 1)
        with self.assertRaises(DoctrineValidationError) as caught:
            parse_doctrine_json(compact.replace(needle, f"{needle}, {needle}", 1))
        self.assertIn('duplicate object key "matthew"', str(caught.exception))

    def test_a_valid_document_parses(self):
        self.assertEqual(
            parse_doctrine_json(DOCTRINE_PATH.read_text(encoding="utf-8"))["profile"],
            "matthew.v0.1",
        )


class CompilerBoundaryTests(unittest.TestCase):
    def test_current_matthew_doctrine_still_compiles(self):
        with tempfile.TemporaryDirectory(prefix="ps-doctrine-") as tmp:
            compiled = compile_doctrine(load_doctrine(DOCTRINE_PATH), Path(tmp))
            self.assertTrue(compiled.config_path.is_file())
            self.assertEqual(len(compiled.capabilities), 10)

    def test_malformed_doctrine_is_rejected_before_anything_is_written(self):
        document = base()
        document["capabilities"][0].pop("standing")
        with tempfile.TemporaryDirectory(prefix="ps-doctrine-") as tmp:
            target = Path(tmp) / "fixture"
            with self.assertRaises(DoctrineValidationError):
                compile_doctrine(document, target)
            self.assertFalse(target.exists())

    def test_valid_but_compiler_unsupported_action_is_not_malformed(self):
        document = base()
        document["capabilities"].append(
            {
                "action": "time.travel",
                "purpose": "Move the clock without moving the work.",
                "standing": "ask",
                "scope": {"kind": "unrestricted"},
                "reversibility": "irreversible",
                "effects": ["time.shift"],
            }
        )
        validate_doctrine(document)
        with tempfile.TemporaryDirectory(prefix="ps-doctrine-") as tmp:
            with self.assertRaises(DoctrineError) as caught:
                compile_doctrine(document, Path(tmp) / "fixture")
        error = caught.exception
        self.assertNotIsInstance(error, DoctrineValidationError)
        self.assertIn("valid doctrine contract, unsupported by this compiler", str(error))

    def test_load_doctrine_reports_contract_errors_for_a_file(self):
        document = base()
        document.pop("actors")
        with tempfile.TemporaryDirectory(prefix="ps-doctrine-") as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(DoctrineValidationError) as caught:
                load_doctrine(path)
        self.assertEqual(caught.exception.path, "$.actors")


if __name__ == "__main__":
    unittest.main()
