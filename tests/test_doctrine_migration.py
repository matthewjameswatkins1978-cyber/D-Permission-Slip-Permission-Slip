"""Protected migration machinery: exact steps, fail-closed, never adoption."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

from permission_slip.doctrine_contract import (
    MIGRATIONS,
    SCHEMA_ID,
    DoctrineValidationError,
    Migration,
    canonical_digest,
    canonical_doctrine_bytes,
    migrate_to_current,
    validate_doctrine,
)
from tests.support import matthew_doctrine

#: A deliberately fake schema. It exists only inside these tests and is never
#: declared as a schema Permission Slip supports.
FAKE_SCHEMA = "permission-slip.doctrine-test/1"


def _promote(document: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(document)
    updated["schema"] = SCHEMA_ID
    return updated


class RegistryTests(unittest.TestCase):
    def test_production_registry_contains_no_migrations(self):
        # There has only ever been one real schema. An empty registry is the
        # honest answer, not a gap to be filled with invented history.
        self.assertEqual(MIGRATIONS, ())

    def test_migration_is_not_adoption(self):
        from permission_slip.doctrine_store import read_active_digest

        with tempfile.TemporaryDirectory(prefix="ps-migrate-") as tmp:
            state = Path(tmp) / "state"
            migrate_to_current(matthew_doctrine(), registry=())
            self.assertIsNone(read_active_digest(state))
            self.assertFalse((state / "doctrine" / "active.json").exists())


class CurrentSchemaTests(unittest.TestCase):
    def test_current_schema_returns_unchanged_and_applies_nothing(self):
        document = matthew_doctrine()
        outcome = migrate_to_current(document)
        self.assertIs(outcome.document, document)
        self.assertEqual(outcome.applied, ())

    def test_current_schema_still_validates(self):
        broken = matthew_doctrine()
        broken.pop("capabilities")
        with self.assertRaises(DoctrineValidationError):
            migrate_to_current(broken)


class FailClosedTests(unittest.TestCase):
    def test_unknown_schema_fails_closed(self):
        document = matthew_doctrine()
        document["schema"] = "permission-slip.doctrine/0"
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(document)
        self.assertEqual(caught.exception.path, "$.schema")
        self.assertIn("unsupported doctrine schema", str(caught.exception))

    def test_missing_schema_fails_closed(self):
        document = matthew_doctrine()
        document.pop("schema")
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(document)
        self.assertEqual(caught.exception.path, "$.schema")

    def test_non_string_schema_fails_closed(self):
        document = matthew_doctrine()
        document["schema"] = 1
        with self.assertRaises(DoctrineValidationError):
            migrate_to_current(document)

    def test_non_object_fails_closed(self):
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(["permission-slip.doctrine/1"])
        self.assertEqual(caught.exception.path, "$")

    def test_a_registered_step_is_not_used_for_a_different_source(self):
        registry = (Migration(FAKE_SCHEMA, SCHEMA_ID, _promote),)
        document = matthew_doctrine()
        document["schema"] = "permission-slip.doctrine-test/2"
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(document, registry=registry)
        self.assertIn("unsupported doctrine schema", str(caught.exception))

    def test_an_empty_registry_never_migrates_anything(self):
        document = matthew_doctrine()
        document["schema"] = FAKE_SCHEMA
        with self.assertRaises(DoctrineValidationError):
            migrate_to_current(document, registry=())


class RegisteredStepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = (Migration(FAKE_SCHEMA, SCHEMA_ID, _promote),)
        self.document = matthew_doctrine()
        self.document["schema"] = FAKE_SCHEMA

    def test_registered_step_reaches_the_current_schema(self):
        outcome = migrate_to_current(self.document, registry=self.registry)
        self.assertEqual(outcome.document["schema"], SCHEMA_ID)
        self.assertEqual(outcome.applied, ((FAKE_SCHEMA, SCHEMA_ID),))
        validate_doctrine(outcome.document)

    def test_migrated_document_digest_is_recomputed(self):
        outcome = migrate_to_current(self.document, registry=self.registry)
        self.assertEqual(
            canonical_digest(outcome.document), canonical_digest(matthew_doctrine())
        )

    def test_migration_is_deterministic(self):
        first = migrate_to_current(copy.deepcopy(self.document), registry=self.registry)
        second = migrate_to_current(copy.deepcopy(self.document), registry=self.registry)
        self.assertEqual(
            canonical_doctrine_bytes(first.document),
            canonical_doctrine_bytes(second.document),
        )
        self.assertEqual(
            canonical_digest(first.document), canonical_digest(second.document)
        )
        self.assertEqual(first.applied, second.applied)

    def test_step_output_must_validate(self):
        def broken(document: dict[str, Any]) -> dict[str, Any]:
            updated = copy.deepcopy(document)
            updated["schema"] = SCHEMA_ID
            updated.pop("profile")
            return updated

        registry = (Migration(FAKE_SCHEMA, SCHEMA_ID, broken),)
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(self.document, registry=registry)
        self.assertEqual(caught.exception.path, "$.profile")

    def test_step_must_declare_where_it_lands(self):
        def dishonest(document: dict[str, Any]) -> dict[str, Any]:
            return copy.deepcopy(document)  # schema unchanged

        registry = (Migration(FAKE_SCHEMA, SCHEMA_ID, dishonest),)
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(self.document, registry=registry)
        self.assertIn("did not reach", str(caught.exception))

    def test_step_must_return_an_object(self):
        registry = (Migration(FAKE_SCHEMA, SCHEMA_ID, lambda document: []),)
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(self.document, registry=registry)
        self.assertIn("did not return an object", str(caught.exception))


class CycleTests(unittest.TestCase):
    def test_a_cyclic_registry_fails_closed(self):
        def first(document: dict[str, Any]) -> dict[str, Any]:
            updated = copy.deepcopy(document)
            updated["schema"] = "permission-slip.doctrine-cycle/2"
            return updated

        def second(document: dict[str, Any]) -> dict[str, Any]:
            updated = copy.deepcopy(document)
            updated["schema"] = "permission-slip.doctrine-cycle/1"
            return updated

        registry = (
            Migration("permission-slip.doctrine-cycle/1", "permission-slip.doctrine-cycle/2", first),
            Migration("permission-slip.doctrine-cycle/2", "permission-slip.doctrine-cycle/1", second),
        )
        document = matthew_doctrine()
        document["schema"] = "permission-slip.doctrine-cycle/1"
        with self.assertRaises(DoctrineValidationError) as caught:
            migrate_to_current(document, registry=registry)
        self.assertIn("migration cycle", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
