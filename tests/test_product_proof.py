"""Proof against a real, installed, released Tethers product.

These tests use whatever Tethers the ambient environment resolves -- never an
injected fake. They are skipped when no released product is installed, and
they are clearly separated from mock/fake coverage elsewhere in the suite.

Tethers 0.8.1 is **not** assumed anywhere: the assertions below record the
identity fields the currently released product actually reports.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from permission_slip.tethers_client import AUTHORITY_PROTOCOL, GateSession
from permission_slip.tethers_install import (
    describe_product,
    discover_tethers,
)

_MINIMAL_CONFIG = {
    "format_version": "0.1",
    "tether_set": {
        "id": "permission-slip.product-proof",
        "version": "1",
        "tethers": [],
        "capability_requirements": [],
    },
    "providers": [],
    "policy": {"default": "deny", "rules": []},
}


def _ambient_installation():
    """Resolve Tethers from the real environment, or ``None`` if absent/fake."""
    try:
        installation = discover_tethers(probe=False)
    except Exception:
        return None
    if (installation.gate_bin.parent / "_fake_tethers_gate.py").exists():
        return None  # a test fixture, not a released product
    if installation.discovery_source == "dev_source_checkout":
        return None  # a source build is not release proof
    return installation


INSTALLATION = _ambient_installation()
HAS_RELEASED_TETHERS = INSTALLATION is not None


@unittest.skipUnless(
    HAS_RELEASED_TETHERS,
    "no released Tethers product installed in this environment",
)
class ReleasedTethersProductProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installation = INSTALLATION

    def test_product_is_discovered_from_a_product_location(self):
        installation = self.installation
        self.assertTrue(installation.gate_bin.is_file())
        self.assertTrue(installation.engine_bin.is_file())
        self.assertIn(installation.discovery_source, ("path", "install_root", "explicit_config"))
        self.assertEqual(installation.engine_source, "bundle_sibling")
        self.assertNotEqual(installation.discovery_source, "dev_source_checkout")
        self.assertFalse(installation.is_dev)

    def test_release_provenance_verifies_without_a_git_checkout(self):
        installation = self.installation
        self.assertEqual(installation.verification, "verified")
        self.assertEqual(installation.provenance, "release_manifest")
        self.assertIsNotNone(installation.release_manifest)
        # No source .git is needed: the manifest and hashes are enough.
        self.assertFalse((installation.install_root / ".git").exists())  # type: ignore[union-attr]

    def test_release_manifest_hashes_match_the_installed_binaries(self):
        from permission_slip.tethers_install import (
            read_release_manifest,
            sha256_file,
        )

        installation = self.installation
        manifest = installation.release_manifest
        assert manifest is not None
        entries = read_release_manifest(manifest)
        for binary in (installation.gate_bin, installation.engine_bin):
            relative = binary.relative_to(manifest.parent).as_posix()
            self.assertEqual(entries[relative], sha256_file(binary), relative)

    def test_describe_reports_the_actual_product_surface(self):
        data = describe_product(self.installation.gate_bin)
        self.assertIsInstance(data, dict)
        # Actual schema/version fields the released product reports.
        self.assertEqual(data["schema"], "tethers.describe/1")
        self.assertEqual(data["cli_schema"], "tethers.cli/1")
        self.assertRegex(str(data["version"]), r"^\d+\.\d+\.\d+")
        self.assertEqual(data["supported_protocol_versions"], ["0.1"])
        self.assertEqual(data["supported_language_versions"], ["0.1"])
        self.assertIsInstance(data["features"], dict)

    def test_discovered_product_version_matches_describe(self):
        installation = discover_tethers(probe=True)
        self.assertEqual(installation.product_version, INSTALLATION.product_version)
        self.assertRegex(str(installation.product_version), r"^\d+\.\d+\.\d+")

    def test_authority_hello_against_the_released_product(self):
        installation = self.installation
        with tempfile.TemporaryDirectory(prefix="ps-product-hello-") as tmp:
            workdir = Path(tmp)
            config = workdir / "runtime.json"
            config.write_text(json.dumps(_MINIMAL_CONFIG, indent=2), encoding="utf-8")
            session = GateSession(
                config_path=config,
                trail_path=workdir / "trail.jsonl",
                host_data_root=workdir / "host-data",
                paths=installation,
                response_timeout=30.0,
            )
            session.start()
            try:
                result = session.hello()
            finally:
                session.close()

        self.assertEqual(result["protocol"], AUTHORITY_PROTOCOL)
        self.assertEqual(result["protocol_versions"], [AUTHORITY_PROTOCOL])
        self.assertEqual(result["provider_invocations"], 0)
        self.assertFalse(result["authority_granted"])
        self.assertRegex(str(result["product_version"]), r"^\d+\.\d+\.\d+")
        self.assertIsNone(result["git_sha"])  # a released product ships no git state
        self.assertRegex(str(result["gate_instance_id"]), r"^gate_")

    def test_released_product_reported_back(self):
        # Recorded so the packet's evidence names the exact artefacts used.
        import platform as platform_module

        installation = self.installation
        self.assertTrue(str(installation.gate_bin).lower().endswith("tethers.exe"))
        self.assertIn("Tethers", str(installation.install_root))  # type: ignore[union-attr]
        self.assertRegex(installation.gate_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(installation.engine_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(installation.platform, f"{platform_module.system()} x86_64")


if __name__ == "__main__":
    unittest.main()
