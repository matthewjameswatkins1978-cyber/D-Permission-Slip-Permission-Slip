"""The doctrine store: candidates, the active pointer, and explicit adoption.

The core law under test is ``import(candidate); active_before == active_after``.
Everything else here is the machinery that makes adoption the only operation
that can ever break that equality -- deliberately, explicitly, and with the
expected-current digest checked first.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable

from permission_slip.doctrine_contract import canonical_digest, validate_doctrine
from permission_slip.doctrine_export import encode_export
from permission_slip.doctrine_store import (
    ACTIVE_FILE,
    ACTIVE_SCHEMA,
    AdoptionConflict,
    CandidateUnavailable,
    DIGEST_PATTERN,
    DoctrineStateError,
    NoActiveDoctrine,
    active_pointer_path,
    adopt,
    candidate_name,
    candidate_path,
    candidates_dir,
    import_export,
    load_active_doctrine,
    read_active_digest,
    store_root,
)
from tests.support import matthew_doctrine

OTHER_DIGEST = "sha256:" + "0" * 64


def export_text(document: dict[str, Any]) -> str:
    return encode_export(document).decode("utf-8")


class StoreHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-store-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"

    def import_doctrine(self, document: dict[str, Any]):
        return import_export(export_text(document), state_root=self.state)

    def mutate(self, change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        document = matthew_doctrine()
        change(document)
        return document

    def tamper(self, path: Path, change: Callable[[dict[str, Any]], None]) -> None:
        document = json.loads(path.read_text(encoding="utf-8"))
        change(document)
        path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    def write_pointer(self, payload: Any) -> None:
        path = active_pointer_path(self.state)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, (dict, list)):
            text = json.dumps(payload, indent=2, sort_keys=True)
        else:
            text = str(payload)
        path.write_text(text, encoding="utf-8")


class StoreLayoutTests(StoreHarness):
    def test_layout_is_under_the_permission_slip_state_root(self):
        self.assertEqual(store_root(self.state), self.state / "doctrine")
        self.assertEqual(candidates_dir(self.state), self.state / "doctrine" / "candidates")
        self.assertEqual(
            active_pointer_path(self.state), self.state / "doctrine" / "active.json"
        )

    def test_candidate_identity_is_derived_not_chosen(self):
        digest = canonical_digest(matthew_doctrine())
        self.assertEqual(candidate_name(digest), f"sha256-{digest.split(':', 1)[1]}.json")
        self.assertEqual(
            candidate_path(digest, self.state), candidates_dir(self.state) / candidate_name(digest)
        )

    def test_a_non_digest_has_no_filename(self):
        for bad in (
            OTHER_DIGEST.replace("sha256:", "sha512:"),
            "../../etc/passwd",
            "sha256-0000.json",
            "",
            None,
            42,
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(DoctrineStateError):
                    candidate_name(bad)

    def test_well_formed_digests_match_the_pattern(self):
        self.assertRegex(canonical_digest(matthew_doctrine()), DIGEST_PATTERN.pattern)


class ImportIsNotAdoptionTests(StoreHarness):
    def test_import_does_not_activate(self):
        active_before = read_active_digest(self.state)
        self.import_doctrine(matthew_doctrine())
        self.assertEqual(read_active_digest(self.state), active_before)

    def test_import_does_not_create_an_active_pointer(self):
        self.import_doctrine(matthew_doctrine())
        self.assertFalse(active_pointer_path(self.state).exists())

    def test_no_best_available_candidate_fallback(self):
        # Two candidates, one of them newest by mtime, and no pointer.
        first = self.import_doctrine(matthew_doctrine())
        time.sleep(0.05)
        second = self.import_doctrine(
            self.mutate(lambda d: d["human"].update(note="newest."))
        )
        self.assertNotEqual(first.digest, second.digest)
        self.assertIsNone(read_active_digest(self.state))
        with self.assertRaises(NoActiveDoctrine):
            load_active_doctrine(self.state)

    def test_migration_result_is_never_adopted(self):
        from permission_slip.doctrine_contract import migrate_to_current

        migrate_to_current(matthew_doctrine())
        self.assertIsNone(read_active_digest(self.state))
        self.assertFalse(active_pointer_path(self.state).exists())


class AdoptionTests(StoreHarness):
    def test_adoption_from_none_works_exactly_once(self):
        candidate = self.import_doctrine(matthew_doctrine())
        self.assertIsNone(read_active_digest(self.state))
        adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), candidate.digest)

        with self.assertRaises(AdoptionConflict):
            adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), candidate.digest)

    def test_wrong_expected_current_refuses_adoption(self):
        first = self.import_doctrine(matthew_doctrine())
        second = self.import_doctrine(
            self.mutate(lambda d: d["human"].update(note="replacement."))
        )
        adopt(first.digest, expect_current=None, state_root=self.state)

        with self.assertRaises(AdoptionConflict) as caught:
            adopt(second.digest, expect_current=OTHER_DIGEST, state_root=self.state)
        self.assertIn("refusing to adopt", str(caught.exception))
        self.assertEqual(read_active_digest(self.state), first.digest)

    def test_stale_second_adoption_refuses(self):
        first = self.import_doctrine(matthew_doctrine())
        second = self.import_doctrine(
            self.mutate(lambda d: d["human"].update(note="replacement."))
        )
        adopt(first.digest, expect_current=None, state_root=self.state)
        # The caller still believes NONE is active.
        with self.assertRaises(AdoptionConflict):
            adopt(second.digest, expect_current=None, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), first.digest)

    def test_valid_replacement_with_correct_expected_current_succeeds(self):
        first = self.import_doctrine(matthew_doctrine())
        second = self.import_doctrine(
            self.mutate(lambda d: d["human"].update(note="replacement."))
        )
        adopt(first.digest, expect_current=None, state_root=self.state)
        adopt(second.digest, expect_current=first.digest, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), second.digest)

    def test_failed_replacement_preserves_the_previous_active_doctrine(self):
        first = self.import_doctrine(matthew_doctrine())
        adopt(first.digest, expect_current=None, state_root=self.state)
        before = read_active_digest(self.state)
        with self.assertRaises(AdoptionConflict):
            adopt(OTHER_DIGEST, expect_current=OTHER_DIGEST, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), before)

    def test_nonexistent_candidate_refuses_adoption(self):
        with self.assertRaises(CandidateUnavailable):
            adopt(OTHER_DIGEST, expect_current=None, state_root=self.state)
        self.assertIsNone(read_active_digest(self.state))

    def test_malformed_candidate_digest_refuses_adoption(self):
        with self.assertRaises(DoctrineStateError):
            adopt("../../active.json", expect_current=None, state_root=self.state)
        self.assertIsNone(read_active_digest(self.state))

    def test_malformed_expected_current_refuses_adoption(self):
        candidate = self.import_doctrine(matthew_doctrine())
        with self.assertRaises(DoctrineStateError):
            adopt(candidate.digest, expect_current="whatever", state_root=self.state)
        self.assertIsNone(read_active_digest(self.state))


class TamperTests(StoreHarness):
    def test_candidate_tamper_is_detected_before_adoption(self):
        candidate = self.import_doctrine(matthew_doctrine())
        self.tamper(candidate.path, lambda d: d["human"].update(display_name="Mallory"))
        with self.assertRaises(DoctrineStateError) as caught:
            adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.assertIn("does not verify", str(caught.exception))
        self.assertIsNone(read_active_digest(self.state))

    def test_candidate_tamper_that_makes_it_invalid_is_detected(self):
        candidate = self.import_doctrine(matthew_doctrine())
        self.tamper(candidate.path, lambda d: d["capabilities"][0].pop("standing"))
        with self.assertRaises(DoctrineStateError):
            adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.assertIsNone(read_active_digest(self.state))

    def test_active_candidate_tamper_is_detected_when_loaded(self):
        candidate = self.import_doctrine(matthew_doctrine())
        adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.tamper(candidate.path, lambda d: d["human"].update(display_name="Mallory"))
        with self.assertRaises(DoctrineStateError) as caught:
            load_active_doctrine(self.state)
        self.assertIn("does not verify", str(caught.exception))

    def test_active_candidate_removed_is_detected_when_loaded(self):
        candidate = self.import_doctrine(matthew_doctrine())
        adopt(candidate.digest, expect_current=None, state_root=self.state)
        candidate.path.unlink()
        with self.assertRaises(CandidateUnavailable):
            load_active_doctrine(self.state)

    def test_pointer_cannot_name_an_arbitrary_path(self):
        self.import_doctrine(matthew_doctrine())
        self.write_pointer(
            {"schema": ACTIVE_SCHEMA, "doctrine_digest": "../../etc/passwd"}
        )
        with self.assertRaises(DoctrineStateError):
            read_active_digest(self.state)
        with self.assertRaises(DoctrineStateError):
            load_active_doctrine(self.state)

    def test_pointer_well_formed_digest_must_name_a_real_candidate(self):
        self.write_pointer({"schema": ACTIVE_SCHEMA, "doctrine_digest": OTHER_DIGEST})
        with self.assertRaises(CandidateUnavailable):
            load_active_doctrine(self.state)


class MalformedPointerTests(StoreHarness):
    def test_active_pointer_must_be_json(self):
        active_pointer_path(self.state).parent.mkdir(parents=True, exist_ok=True)
        active_pointer_path(self.state).write_text("{not json", encoding="utf-8")
        with self.assertRaises(DoctrineStateError) as caught:
            read_active_digest(self.state)
        self.assertIn("malformed", str(caught.exception))

    def test_active_pointer_must_be_an_object(self):
        self.write_pointer(["sha256:" + "0" * 64])
        with self.assertRaises(DoctrineStateError):
            read_active_digest(self.state)

    def test_active_pointer_requires_both_fields(self):
        for payload in (
            {"schema": ACTIVE_SCHEMA},
            {"doctrine_digest": OTHER_DIGEST},
            {},
        ):
            with self.subTest(payload=payload):
                self.write_pointer(payload)
                with self.assertRaises(DoctrineStateError):
                    read_active_digest(self.state)

    def test_active_pointer_rejects_unknown_fields(self):
        self.write_pointer(
            {
                "schema": ACTIVE_SCHEMA,
                "doctrine_digest": OTHER_DIGEST,
                "fallback": OTHER_DIGEST,
            }
        )
        with self.assertRaises(DoctrineStateError) as caught:
            read_active_digest(self.state)
        self.assertIn("unknown field", str(caught.exception))

    def test_active_pointer_rejects_an_unknown_schema(self):
        self.write_pointer(
            {"schema": "permission-slip.active-doctrine/9", "doctrine_digest": OTHER_DIGEST}
        )
        with self.assertRaises(DoctrineStateError) as caught:
            read_active_digest(self.state)
        self.assertIn("unsupported active pointer schema", str(caught.exception))

    def test_active_pointer_rejects_duplicate_keys(self):
        path = active_pointer_path(self.state)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '{"schema": "%s", "doctrine_digest": "%s", "doctrine_digest": "%s"}'
            % (ACTIVE_SCHEMA, OTHER_DIGEST, OTHER_DIGEST),
            encoding="utf-8",
        )
        with self.assertRaises(DoctrineStateError):
            read_active_digest(self.state)


class LoadActiveTests(StoreHarness):
    def test_load_without_a_pointer_raises(self):
        with self.assertRaises(NoActiveDoctrine):
            load_active_doctrine(self.state)

    def test_load_returns_the_adopted_doctrine_and_its_digest(self):
        candidate = self.import_doctrine(matthew_doctrine())
        adopt(candidate.digest, expect_current=None, state_root=self.state)
        loaded = load_active_doctrine(self.state)
        self.assertEqual(loaded.digest, candidate.digest)
        self.assertEqual(
            loaded.digest,
            canonical_digest(validate_doctrine(matthew_doctrine())),
        )

    def test_active_file_exists_only_after_adoption(self):
        candidate = self.import_doctrine(matthew_doctrine())
        self.assertFalse(active_pointer_path(self.state).exists())
        adopt(candidate.digest, expect_current=None, state_root=self.state)
        self.assertTrue(active_pointer_path(self.state).is_file())
        self.assertEqual(active_pointer_path(self.state).name, ACTIVE_FILE)


if __name__ == "__main__":
    unittest.main()
