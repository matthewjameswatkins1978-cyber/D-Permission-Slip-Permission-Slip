"""Portable export envelope: determinism, verification, and import-is-not-adoption."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from permission_slip.doctrine_contract import (
    DoctrineValidationError,
    canonical_digest,
    validate_doctrine,
)
from permission_slip.doctrine_export import (
    ENVELOPE_FIELDS,
    EXPORT_SCHEMA,
    decode_export,
    encode_export,
)
from permission_slip.doctrine_store import import_export, read_active_digest
from tests.support import matthew_doctrine


class ExportDeterminismTests(unittest.TestCase):
    def test_export_bytes_are_deterministic(self):
        document = validate_doctrine(matthew_doctrine())
        self.assertEqual(encode_export(document), encode_export(document))

    def test_export_bytes_ignore_key_order_and_pretty_printing(self):
        document = matthew_doctrine()
        reordered = json.loads(json.dumps(document, indent=6, sort_keys=True))
        # Rebuild with reversed key order at every level.
        def reverse(value):
            if isinstance(value, dict):
                return {key: reverse(value[key]) for key in reversed(list(value))}
            if isinstance(value, list):
                return [reverse(item) for item in value]
            return value

        self.assertEqual(
            encode_export(document),
            encode_export(reverse(reordered)),
        )

    def test_export_digest_is_the_recomputed_document_digest(self):
        document = validate_doctrine(matthew_doctrine())
        envelope = json.loads(encode_export(document))
        self.assertEqual(envelope["doctrine_digest"], canonical_digest(document))
        self.assertEqual(envelope["doctrine_digest"], canonical_digest(envelope["doctrine"]))

    def test_export_envelope_is_closed(self):
        envelope = json.loads(encode_export(matthew_doctrine()))
        self.assertEqual(set(envelope), set(ENVELOPE_FIELDS))
        self.assertEqual(envelope["schema"], EXPORT_SCHEMA)
        self.assertEqual(envelope["doctrine_schema"], "permission-slip.doctrine/1")

    def test_export_carries_no_machine_specific_content(self):
        text = encode_export(matthew_doctrine()).decode("utf-8")
        # No absolute paths: no drive-letter path and no POSIX root path.
        # (``https://`` in the canonical repository is a URL, not a path.)
        self.assertNotRegex(text, r"(?<![:\w])[A-Za-z]:[\\/]")
        self.assertNotRegex(text, r"(?<![\w])/(?:home|Users|tmp|var|etc|usr)/")
        # No timestamp-shaped value and no field that could hold one.
        self.assertNotRegex(text, r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
        for forbidden in ("timestamp", "generated_at", "created", "state_root", "signature"):
            self.assertNotIn(forbidden, text)

    def test_export_does_not_package_compiled_state(self):
        text = encode_export(matthew_doctrine()).decode("utf-8")
        for forbidden in ("runtime.json", "tethers-fixture", "manifests", "gate_bin"):
            self.assertNotIn(forbidden, text)

    def test_export_of_the_same_doctrine_twice_is_byte_identical(self):
        first = encode_export(matthew_doctrine())
        second = encode_export(matthew_doctrine())
        self.assertEqual(first, second)


class ImportVerificationTests(unittest.TestCase):
    def setUp(self):
        self.document = validate_doctrine(matthew_doctrine())
        self.text = encode_export(self.document).decode("utf-8")

    def test_import_returns_the_recomputed_digest(self):
        exported = decode_export(self.text)
        self.assertEqual(exported.digest, canonical_digest(self.document))
        self.assertEqual(exported.applied, ())

    def test_tampered_doctrine_is_rejected(self):
        envelope = json.loads(self.text)
        envelope["doctrine"]["human"]["display_name"] = "Someone Else"
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.doctrine_digest")

    def test_tampered_claimed_digest_is_rejected(self):
        envelope = json.loads(self.text)
        envelope["doctrine_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.doctrine_digest")

    def test_duplicate_keys_are_rejected(self):
        text = self.text.replace(
            '"schema": "permission-slip.doctrine-export/1"',
            '"schema": "permission-slip.doctrine-export/1",\n  '
            '"schema": "permission-slip.doctrine-export/1"',
            1,
        )
        self.assertNotEqual(text, self.text)
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(text)
        self.assertIn("duplicate object key", str(caught.exception))

    def test_unknown_export_schema_is_rejected(self):
        envelope = json.loads(self.text)
        envelope["schema"] = "permission-slip.doctrine-export/2"
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.schema")

    def test_unknown_envelope_field_is_rejected(self):
        envelope = json.loads(self.text)
        envelope["activated"] = True
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.activated")

    def test_missing_envelope_field_is_rejected(self):
        envelope = json.loads(self.text)
        envelope.pop("doctrine_digest")
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.doctrine_digest")

    def test_envelope_schema_and_document_must_agree(self):
        envelope = json.loads(self.text)
        envelope["doctrine_schema"] = "permission-slip.doctrine/0"
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.doctrine.schema")

    def test_unsupported_doctrine_schema_fails_closed(self):
        envelope = json.loads(self.text)
        envelope["doctrine_schema"] = "permission-slip.doctrine/0"
        envelope["doctrine"]["schema"] = "permission-slip.doctrine/0"
        with self.assertRaises(DoctrineValidationError) as caught:
            decode_export(json.dumps(envelope))
        self.assertEqual(caught.exception.path, "$.schema")
        self.assertIn("unsupported doctrine schema", str(caught.exception))

    def test_reexport_after_import_is_byte_identical(self):
        decoded = decode_export(self.text)
        self.assertEqual(encode_export(decoded.document), self.text.encode("utf-8"))


class ImportIsNotAdoptionTests(unittest.TestCase):
    def test_import_never_changes_the_active_doctrine(self):
        with tempfile.TemporaryDirectory(prefix="ps-export-") as tmp:
            state = Path(tmp) / "state"
            text = encode_export(matthew_doctrine()).decode("utf-8")

            # Before any adoption exists.
            self.assertIsNone(read_active_digest(state))
            import_export(text, state_root=state)
            self.assertIsNone(read_active_digest(state))

            # And again once something is already active.
            import_export(text, state_root=state)
            self.assertIsNone(read_active_digest(state))
            self.assertFalse((state / "doctrine" / "active.json").exists())

    def test_import_writes_only_a_candidate(self):
        with tempfile.TemporaryDirectory(prefix="ps-export-") as tmp:
            state = Path(tmp) / "state"
            imported = import_export(
                encode_export(matthew_doctrine()).decode("utf-8"), state_root=state
            )
            self.assertTrue(imported.path.is_file())
            self.assertEqual(imported.path.parent.name, "candidates")
            self.assertIsNone(read_active_digest(state))

    def test_import_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="ps-export-") as tmp:
            state = Path(tmp) / "state"
            text = encode_export(matthew_doctrine()).decode("utf-8")
            first = import_export(text, state_root=state)
            second = import_export(text, state_root=state)
            self.assertEqual(first.digest, second.digest)
            self.assertEqual(first.path, second.path)
            self.assertEqual(
                [p for p in (state / "doctrine").rglob("*") if p.is_file()],
                [first.path],
            )


if __name__ == "__main__":
    unittest.main()
