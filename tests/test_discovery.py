"""Tethers product discovery: installation modelling and provenance.

All of these run against fake released bundles or an explicitly named
development checkout. No real Tethers is required, and none of them can reach
a source checkout by accident.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import permission_slip.tethers_install as install_module
from permission_slip.tethers_install import (
    AUTHORITY_PROTOCOL,
    BUNDLE_ROOT_ENV,
    DEV_CHECKOUT_ENV,
    DEV_UNVERIFIED_ENV,
    ENGINE_ENV,
    GATE_ENV,
    TethersUnavailable,
    describe_product,
    discover_tethers,
    locate_tethers,
    read_release_manifest,
    verify_release_provenance,
)
from tests.fake_tethers import (
    FAKE_PRODUCT_VERSION,
    bundle_env,
    isolated_env,
    make_fake_gate,
    make_release_bundle,
)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-discovery-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    # -- explicit configuration --------------------------------------------

    def test_explicit_gate_and_engine_paths(self):
        bundle = make_release_bundle(self.root / "bundle")
        gate = bundle / "bin" / (Path("tethers.cmd" if sys_windows() else "tethers"))
        self.assertTrue(gate.is_file(), f"fake gate missing: {gate}")
        engine = next(p for p in (bundle / "bin").iterdir() if p.name.startswith("tethers-engine"))
        env = isolated_env({GATE_ENV: str(gate), ENGINE_ENV: str(engine)})

        installation = discover_tethers(probe=False, env=env, platform=plat())

        self.assertEqual(installation.discovery_source, "explicit_config")
        self.assertEqual(installation.engine_source, "explicit_config")
        self.assertEqual(installation.authority_protocol, AUTHORITY_PROTOCOL)
        self.assertEqual(installation.verification, "verified")
        self.assertEqual(installation.provenance, "release_manifest")

    def test_explicit_gate_path_must_exist(self):
        env = isolated_env({GATE_ENV: str(self.root / "nope" / "tethers.exe")})
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(caught.exception.code, "unreadable")

    def test_explicit_bundle_root_resolves_the_gate(self):
        bundle = make_release_bundle(self.root / "bundle")
        env = isolated_env({BUNDLE_ROOT_ENV: str(bundle)})
        installation = discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(installation.discovery_source, "explicit_config")
        self.assertEqual(installation.engine_source, "bundle_sibling")

    def test_bundle_root_without_a_gate_fails_closed(self):
        (self.root / "empty").mkdir(parents=True, exist_ok=True)
        env = isolated_env({BUNDLE_ROOT_ENV: str(self.root / "empty")})
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(caught.exception.code, "gate_missing")

    # -- missing pieces ----------------------------------------------------

    def test_missing_gate_fails_closed(self):
        empty = self.root / "nowhere"
        empty.mkdir(parents=True, exist_ok=True)
        env = isolated_env({"PATH": str(empty)})
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(caught.exception.code, "gate_missing")

    def test_missing_engine_fails_closed_and_names_the_remedy(self):
        bundle = self.root / "no-engine"
        bundle.mkdir(parents=True, exist_ok=True)
        make_fake_gate(bundle / "bin")
        env = bundle_env(bundle)
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(caught.exception.code, "engine_missing")
        self.assertIn(ENGINE_ENV, str(caught.exception))

    # -- discovery sources -------------------------------------------------

    def test_path_installed_tethers(self):
        bundle = make_release_bundle(self.root / "bundle")
        installation = discover_tethers(
            probe=False, env=bundle_env(bundle), platform=plat()
        )
        self.assertEqual(installation.discovery_source, "path")
        self.assertEqual(installation.engine_source, "bundle_sibling")

    def test_released_bundle_sibling_engine(self):
        bundle = make_release_bundle(self.root / "bundle")
        gate, engine, source, engine_source = locate_tethers(
            bundle_env(bundle), plat()
        )
        self.assertEqual(gate.parent, engine.parent)
        self.assertEqual(engine_source, "bundle_sibling")
        self.assertIn(source, ("path", "install_root"))

    def test_bundle_root_without_git_still_verifies(self):
        # A released product must not need its source .git directory.
        bundle = make_release_bundle(self.root / "bundle")
        git_dir = bundle / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        installation = discover_tethers(
            probe=False, env=bundle_env(bundle), platform=plat()
        )
        self.assertEqual(installation.verification, "verified")
        self.assertIsNone(installation.describe)  # probe disabled
        self.assertTrue((bundle / "SHA256SUMS").is_file())

    # -- no checkout in normal operation -----------------------------------

    def test_normal_discovery_never_mentions_a_source_checkout(self):
        for module in (install_module,):
            source = Path(module.__file__).read_text(encoding="utf-8")
            for retired in ("tethers-lang", ".deps", "rev-parse", "REQUIRED_TETHERS_SHA"):
                self.assertNotIn(retired, source, f"{module.__name__} still references it")

    def test_source_checkout_shape_is_not_discovered_by_default(self):
        checkout = self.root / "fake-checkout"
        target = checkout / "tethers-0.1" / "host-rust" / "target" / "release"
        target.mkdir(parents=True, exist_ok=True)
        make_fake_gate(target)
        engine_dir = checkout / "tethers-0.1" / "engine-ocaml" / "_build" / "default" / "bin"
        engine_dir.mkdir(parents=True, exist_ok=True)
        (engine_dir / ("tethers_mcp_main.exe" if sys_windows() else "tethers_mcp_main")).write_bytes(
            b"fake engine\n"
        )
        (checkout / ".git").mkdir()

        empty = self.root / "nowhere"
        empty.mkdir(parents=True, exist_ok=True)
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(
                probe=False,
                env=isolated_env({"PATH": str(empty)}),
                platform=plat(),
            )
        self.assertEqual(caught.exception.code, "gate_missing")

    def test_dev_source_checkout_is_explicit_and_marked(self):
        checkout = self.root / "fake-checkout"
        target = checkout / "tethers-0.1" / "host-rust" / "target" / "release"
        target.mkdir(parents=True, exist_ok=True)
        make_fake_gate(target)
        engine_dir = checkout / "tethers-0.1" / "engine-ocaml" / "_build" / "default" / "bin"
        engine_dir.mkdir(parents=True, exist_ok=True)
        (engine_dir / ("tethers_mcp_main.exe" if sys_windows() else "tethers_mcp_main")).write_bytes(
            b"fake engine\n"
        )

        env = isolated_env({DEV_CHECKOUT_ENV: str(checkout), "PATH": str(self.root / "nowhere")})
        installation = discover_tethers(probe=False, env=env, platform=plat())

        self.assertEqual(installation.discovery_source, "dev_source_checkout")
        self.assertEqual(installation.engine_source, "dev_source_checkout")
        self.assertTrue(installation.is_dev)
        self.assertTrue(any("development" in note for note in installation.notes))

    # -- release provenance -------------------------------------------------

    def test_release_manifest_is_parsed(self):
        bundle = make_release_bundle(self.root / "bundle")
        entries = read_release_manifest(bundle / "SHA256SUMS")
        self.assertEqual(set(entries), {"bin/" + gate_name(), "bin/" + engine_name()})
        for digest in entries.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_tampered_binary_fails_verification(self):
        bundle = make_release_bundle(self.root / "bundle", tamper=True)
        with self.assertRaises(TethersUnavailable) as caught:
            verify_release_provenance(
                bundle / "bin" / gate_name(),
                bundle / "bin" / engine_name(),
                isolated_env(),
            )
        self.assertEqual(caught.exception.code, "manifest_mismatch")

    def test_tamper_is_suppressed_only_by_a_named_dev_override(self):
        bundle = make_release_bundle(self.root / "bundle", tamper=True)
        env = isolated_env({DEV_UNVERIFIED_ENV: "1"})
        provenance, verification, dev_active, _notes = verify_release_provenance(
            bundle / "bin" / gate_name(), bundle / "bin" / engine_name(), env
        )
        self.assertEqual(provenance, "dev_override")
        self.assertEqual(verification, "dev_override")
        self.assertTrue(dev_active)

    def test_missing_manifest_is_unverified_not_a_silent_pass(self):
        bundle = make_release_bundle(self.root / "bundle", manifest=False)
        provenance, verification, dev_active, notes = verify_release_provenance(
            bundle / "bin" / gate_name(),
            bundle / "bin" / engine_name(),
            isolated_env(),
        )
        self.assertEqual(provenance, "absent")
        self.assertEqual(verification, "unverified")
        self.assertFalse(dev_active)
        self.assertTrue(any("no release SHA256SUMS" in note for note in notes))

    # -- product-owned identity surface ------------------------------------

    def test_describe_reports_the_product_identity_surface(self):
        bundle = make_release_bundle(self.root / "bundle")
        data = describe_product(bundle / "bin" / gate_name())
        self.assertIsInstance(data, dict)
        # Actual schema/version fields the released surface reports.
        self.assertEqual(data["schema"], "tethers.describe/1")
        self.assertEqual(data["version"], FAKE_PRODUCT_VERSION)
        self.assertEqual(data["supported_protocol_versions"], ["0.1"])
        self.assertEqual(data["cli_schema"], "tethers.cli/1")

    def test_product_version_is_recorded_from_the_product(self):
        bundle = make_release_bundle(self.root / "bundle")
        installation = discover_tethers(probe=True, env=bundle_env(bundle), platform=plat())
        self.assertEqual(installation.product_version, FAKE_PRODUCT_VERSION)
        self.assertEqual(installation.describe["schema"], "tethers.describe/1")


def sys_windows() -> bool:
    import sys

    return sys.platform == "win32"


def plat() -> str:
    import sys

    return sys.platform


def gate_name() -> str:
    return "tethers.cmd" if sys_windows() else "tethers"


def engine_name() -> str:
    return "tethers-engine.exe" if sys_windows() else "tethers-engine"


if __name__ == "__main__":
    unittest.main()
