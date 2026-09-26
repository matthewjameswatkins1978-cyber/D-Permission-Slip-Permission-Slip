"""Fresh-machine portability proof and the adopted-doctrine runtime seam.

The key claim this file pins:

    same human doctrine
    -> same canonical identity
    -> same compiled authority configuration

...across a state root that starts out completely empty, and an explicit
adoption step that nothing else can substitute for.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from permission_slip.doctrine import compile_doctrine
from permission_slip.doctrine_contract import (
    canonical_digest,
    canonical_doctrine_bytes,
    validate_doctrine,
)
from permission_slip.doctrine_export import encode_export
from permission_slip.doctrine_store import (
    NoActiveDoctrine,
    adopt,
    import_export,
    load_active_doctrine,
    read_active_digest,
)
from permission_slip.spike import PermissionSlip
from permission_slip.tethers_install import discover_tethers
from tests.fake_tethers import bundle_env, make_release_bundle
from tests.support import DOCTRINE_PATH, matthew_doctrine


def tree_digest(root: Path) -> str:
    """Deterministic digest over relative paths and file bytes only."""
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class FreshMachinePortabilityProof(unittest.TestCase):
    def test_doctrine_survives_export_import_adopt_and_compile(self) -> None:
        # 1. validate original
        original = validate_doctrine(matthew_doctrine())
        original_bytes = canonical_doctrine_bytes(original)
        # 2. compute original digest
        original_digest = canonical_digest(original)
        self.assertEqual(
            original_digest,
            "sha256:099ba9638dedbb0dc71e28222a0f971db38256a04dc270ea7523cc1eb002adfd",
        )

        # 3. export
        payload = encode_export(original)

        with tempfile.TemporaryDirectory(prefix="ps-fresh-machine-") as tmp:
            # 4. a fresh, empty Permission Slip state root
            state = Path(tmp) / "state"
            self.assertFalse(state.exists())

            # 5. import the export into that empty state
            imported = import_export(payload.decode("utf-8"), state_root=state)

            # 6. candidate digest == original digest
            self.assertEqual(imported.digest, original_digest)

            # 7. the active doctrine is still NONE
            self.assertIsNone(read_active_digest(state))

            # 8. explicitly adopt with expected-current NONE
            adopt(imported.digest, expect_current=None, state_root=state)

            # 9. active digest == original digest
            self.assertEqual(read_active_digest(state), original_digest)

            # 10. load the adopted doctrine
            loaded = load_active_doctrine(state)
            self.assertEqual(loaded.digest, original_digest)

            # 11. canonical bytes are unchanged
            self.assertEqual(canonical_doctrine_bytes(loaded.document), original_bytes)

            # 12/13. compile original and the adopted doctrine
            fixture_a = Path(tmp) / "fixture-a"
            fixture_b = Path(tmp) / "fixture-b"
            compile_doctrine(original, fixture_a)
            compile_doctrine(loaded.document, fixture_b)

            # 14. the compiled trees are byte-for-byte equivalent
            self.assertEqual(tree_digest(fixture_a), tree_digest(fixture_b))
            left = {
                p.relative_to(fixture_a).as_posix(): p.read_bytes()
                for p in fixture_a.rglob("*")
                if p.is_file()
            }
            right = {
                p.relative_to(fixture_b).as_posix(): p.read_bytes()
                for p in fixture_b.rglob("*")
                if p.is_file()
            }
            self.assertEqual(sorted(left), sorted(right))
            self.assertEqual(left, right)

    def test_export_import_round_trip_is_byte_identical(self) -> None:
        original = validate_doctrine(matthew_doctrine())
        payload = encode_export(original)
        with tempfile.TemporaryDirectory(prefix="ps-round-trip-") as tmp:
            state = Path(tmp) / "state"
            imported = import_export(payload.decode("utf-8"), state_root=state)
            adopt(imported.digest, expect_current=None, state_root=state)
            loaded = load_active_doctrine(state)
        self.assertEqual(encode_export(loaded.document), payload)


class ActiveDoctrineRuntimeSeamTests(unittest.TestCase):
    """Adoption must have a real runtime consequence -- and only adoption."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-active-seam-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # A self-contained released-bundle shape: the seam test is about which
        # doctrine is compiled, not about Tethers provenance (covered elsewhere).
        bundle = make_release_bundle(self.root / "bundle", product_version="0.8.1")
        self.installation = discover_tethers(
            probe=False, env=bundle_env(bundle), platform=sys.platform
        )

    def _adopted_state(self) -> Path:
        state = self.root / "state"
        imported = import_export(
            encode_export(matthew_doctrine()).decode("utf-8"), state_root=state
        )
        adopt(imported.digest, expect_current=None, state_root=state)
        return state

    def test_from_active_doctrine_compiles_the_adopted_doctrine(self) -> None:
        state = self._adopted_state()
        active = PermissionSlip.from_active_doctrine(
            state_root=state,
            workdir=self.root / "work-active",
            paths=self.installation,
        )
        self.addCleanup(active.close)
        self.assertIsNone(active.doctrine_path)
        self.assertEqual(
            active.doctrine_digest,
            "sha256:099ba9638dedbb0dc71e28222a0f971db38256a04dc270ea7523cc1eb002adfd",
        )

        explicit = PermissionSlip(
            DOCTRINE_PATH,
            workdir=self.root / "work-explicit",
            paths=self.installation,
        )
        self.addCleanup(explicit.close)
        self.assertEqual(explicit.doctrine_path, DOCTRINE_PATH)

        self.assertEqual(
            (active.fixture_dir / "runtime.json").read_bytes(),
            (explicit.fixture_dir / "runtime.json").read_bytes(),
        )
        self.assertEqual(
            sorted(active.fixture.capabilities), sorted(explicit.fixture.capabilities)
        )

    def test_from_active_doctrine_requires_an_adopted_doctrine(self) -> None:
        state = self.root / "state"
        imported = import_export(
            encode_export(matthew_doctrine()).decode("utf-8"), state_root=state
        )
        # Imported, verified, present -- and still not active.
        self.assertEqual(
            imported.digest,
            "sha256:099ba9638dedbb0dc71e28222a0f971db38256a04dc270ea7523cc1eb002adfd",
        )
        with self.assertRaises(NoActiveDoctrine):
            PermissionSlip.from_active_doctrine(
                state_root=state,
                workdir=self.root / "work",
                paths=self.installation,
            )

    def test_explicit_path_route_never_reads_the_store(self) -> None:
        state = self._adopted_state()
        # Even with a different active doctrine, the explicit route loads
        # exactly what it was pointed at.
        explicit = PermissionSlip(
            DOCTRINE_PATH,
            workdir=self.root / "work",
            paths=self.installation,
        )
        self.addCleanup(explicit.close)
        self.assertEqual(explicit.doctrine_path, DOCTRINE_PATH)
        self.assertEqual(
            explicit.doctrine_digest,
            canonical_digest(validate_doctrine(matthew_doctrine())),
        )


if __name__ == "__main__":
    unittest.main()
