"""Product trust: an unverified Tethers may never be Permission Slip's authority.

Diagnostic trust and execution trust are the same trust model. These tests
pin the invariant in both directions:

    doctor says the installation is not verified for authority
        ==> a default GateSession refuses to start it

They also pin that a development override or an explicitly named development
checkout only ever unlocks an *explicit* development-authority opt-in, never a
default production session.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from permission_slip.doctor import PASS, run_doctor
from permission_slip.tethers_client import GateSession, TethersUnverified
from permission_slip.tethers_install import (
    DEV_CHECKOUT_ENV,
    DEV_UNVERIFIED_ENV,
    TethersUnavailable,
    discover_tethers,
    validate_authority_installation,
)
from tests.fake_tethers import (
    bundle_env,
    isolated_env,
    make_fake_gate,
    make_release_bundle,
)

POPEN = "permission_slip.tethers_client.subprocess.Popen"

MINIMAL_CONFIG = {
    "format_version": "0.1",
    "tether_set": {
        "id": "permission-slip.product-trust",
        "version": "1",
        "tethers": [],
        "capability_requirements": [],
    },
    "providers": [],
    "policy": {"default": "deny", "rules": []},
}


def plat() -> str:
    import sys

    return sys.platform


def provision_state(state_root: Path) -> None:
    replay = state_root / "tethers-host" / "replay" / "v1"
    replay.mkdir(parents=True, exist_ok=True)
    (replay / "FORMAT.json").write_text('{"format": 1}\n', encoding="utf-8")


class ProductTrustHarness:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-trust-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_root = self.root / "state"
        provision_state(self.state_root)
        self.workdir = self.root / "work"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.config = self.workdir / "runtime.json"
        self.config.write_text(json.dumps(MINIMAL_CONFIG, indent=2), encoding="utf-8")

    # -- fixtures ----------------------------------------------------------

    def bundle(self, name: str, **kwargs) -> Path:
        return make_release_bundle(self.root / name, **kwargs)

    def dev_checkout(self) -> Path:
        checkout = self.root / "checkout"
        target = checkout / "tethers-0.1" / "host-rust" / "target" / "release"
        target.mkdir(parents=True, exist_ok=True)
        make_fake_gate(target)
        engine_dir = (
            checkout / "tethers-0.1" / "engine-ocaml" / "_build" / "default" / "bin"
        )
        engine_dir.mkdir(parents=True, exist_ok=True)
        engine_name = "tethers_mcp_main.exe" if plat() == "win32" else "tethers_mcp_main"
        (engine_dir / engine_name).write_bytes(b"fake dev engine\n")
        return checkout

    def doctor(self, env: dict[str, str]) -> dict:
        return run_doctor(
            env=env, platform=plat(), home=self.root / "home", state_root=self.state_root
        )

    @staticmethod
    def check(report: dict, check_id: str) -> dict:
        for item in report["checks"]:
            if item["id"] == check_id:
                return item
        raise AssertionError(f"check {check_id} missing")

    def session(self, installation, **kwargs) -> GateSession:
        return GateSession(
            config_path=self.config,
            trail_path=self.workdir / "trail.jsonl",
            host_data_root=self.workdir / "host-data",
            paths=installation,
            response_timeout=15.0,
            **kwargs,
        )

    def assert_refuses_before_startup(self, installation) -> None:
        with mock.patch(POPEN) as popen:
            with self.assertRaises(TethersUnverified) as caught:
                self.session(installation)
            popen.assert_not_called()
        self.assertEqual(caught.exception.code, "unverified_installation")


class VerifiedBundleTrustTests(ProductTrustHarness, unittest.TestCase):
    def test_verified_release_bundle_is_accepted_and_starts(self):
        bundle = self.bundle("verified")
        installation = discover_tethers(
            probe=True, env=bundle_env(bundle), platform=plat()
        )
        self.assertEqual(installation.verification, "verified")
        self.assertEqual(installation.provenance, "release_manifest")
        self.assertTrue(installation.acceptable_for_authority)
        self.assertIsNone(validate_authority_installation(installation))

        with self.session(installation) as session:
            result = session.hello()
        self.assertEqual(result["protocol"], "tethers.authority/1")
        self.assertFalse(session.development_authority)

    def test_verified_bundle_passes_doctor(self):
        env = bundle_env(self.bundle("verified"))
        report = self.doctor(env)
        self.assertEqual(report["overall"]["status"], PASS)
        self.assertIs(report["tethers"]["acceptable_for_authority"], True)
        self.assertEqual(self.check(report, "tethers.authority_ready")["status"], PASS)


class UnverifiedInstallationRefusalTests(ProductTrustHarness, unittest.TestCase):
    def test_manifest_absent_is_refused_before_gate_startup(self):
        bundle = self.bundle("no-manifest", manifest=False)
        installation = discover_tethers(
            probe=False, env=bundle_env(bundle), platform=plat()
        )
        self.assertEqual(installation.verification, "unverified")
        self.assertEqual(installation.provenance, "absent")
        self.assertFalse(installation.acceptable_for_authority)
        self.assert_refuses_before_startup(installation)

    def test_manifest_absent_fails_doctor(self):
        env = bundle_env(self.bundle("no-manifest", manifest=False))
        report = self.doctor(env)
        self.assertNotEqual(report["overall"]["status"], PASS)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        ready = self.check(report, "tethers.authority_ready")
        self.assertEqual(ready["status"], "FAIL")
        self.assertIn("no release manifest provenance", ready["detail"])

    def test_manifest_mismatch_fails_discovery_and_never_starts(self):
        env = bundle_env(self.bundle("tampered", tamper=True))
        with self.assertRaises(TethersUnavailable) as caught:
            discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(caught.exception.code, "manifest_mismatch")

        verified = discover_tethers(
            probe=False, env=bundle_env(self.bundle("verified")), platform=plat()
        )
        mismatched = dataclasses.replace(
            verified, provenance="mismatch", verification="unverified"
        )
        self.assertFalse(mismatched.acceptable_for_authority)
        self.assert_refuses_before_startup(mismatched)

    def test_manifest_mismatch_fails_doctor(self):
        env = bundle_env(self.bundle("tampered", tamper=True))
        report = self.doctor(env)
        self.assertNotEqual(report["overall"]["status"], PASS)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        self.assertEqual(self.check(report, "tethers.provenance")["status"], "FAIL")


class DevelopmentAuthorityTests(ProductTrustHarness, unittest.TestCase):
    def test_dev_override_never_becomes_default_authority(self):
        # The environment variable permits discovery/diagnosis only. It must
        # not silently upgrade the installation into a trusted authority.
        env = bundle_env(self.bundle("tampered", tamper=True)) | {
            DEV_UNVERIFIED_ENV: "1"
        }
        installation = discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(installation.verification, "dev_override")
        self.assertTrue(installation.dev_override_active)
        self.assertFalse(installation.acceptable_for_authority)
        self.assert_refuses_before_startup(installation)

        report = self.doctor(env)
        self.assertNotEqual(report["overall"]["status"], PASS)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        ready = self.check(report, "tethers.authority_ready")
        self.assertEqual(ready["status"], "FAIL")
        self.assertIn("unverified/dev", ready["detail"])

    def test_dev_override_starts_only_with_explicit_opt_in_and_stays_marked(self):
        env = bundle_env(self.bundle("tampered", tamper=True)) | {
            DEV_UNVERIFIED_ENV: "1"
        }
        installation = discover_tethers(probe=False, env=env, platform=plat())

        with self.session(
            installation, allow_unverified_for_development=True
        ) as session:
            self.assertTrue(session.development_authority)
            self.assertFalse(session.acceptable_for_authority)
            result = session.hello()
        # The Gate still works, but nothing about the session claims verification.
        self.assertEqual(result["protocol"], "tethers.authority/1")
        self.assertEqual(installation.verification, "dev_override")
        self.assertFalse(installation.acceptable_for_authority)

    def test_dev_source_checkout_never_becomes_default_authority(self):
        checkout = self.dev_checkout()
        env = isolated_env({DEV_CHECKOUT_ENV: str(checkout)})
        installation = discover_tethers(probe=False, env=env, platform=plat())
        self.assertEqual(installation.discovery_source, "dev_source_checkout")
        self.assertTrue(installation.is_dev)
        self.assertFalse(installation.acceptable_for_authority)
        self.assert_refuses_before_startup(installation)

        report = self.doctor(env)
        self.assertNotEqual(report["overall"]["status"], PASS)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        self.assertTrue(report["tethers"]["is_dev_checkout"])
        ready = self.check(report, "tethers.authority_ready")
        self.assertEqual(ready["status"], "FAIL")
        self.assertIn("development source checkout", ready["detail"])

    def test_dev_source_checkout_starts_only_with_explicit_opt_in(self):
        checkout = self.dev_checkout()
        env = isolated_env({DEV_CHECKOUT_ENV: str(checkout)})
        installation = discover_tethers(probe=False, env=env, platform=plat())

        with self.session(
            installation, allow_unverified_for_development=True
        ) as session:
            self.assertTrue(session.development_authority)
            session.hello()
        self.assertTrue(installation.is_dev)

    def test_permission_slip_refuses_unverified_installation(self):
        from permission_slip.spike import PermissionSlip

        doctrine = Path(__file__).resolve().parent.parent / "doctrine" / "matthew.v0.1.json"
        installation = discover_tethers(
            probe=False,
            env=bundle_env(self.bundle("no-manifest", manifest=False)),
            platform=plat(),
        )
        with self.assertRaises(TethersUnverified):
            PermissionSlip(doctrine, workdir=self.workdir, paths=installation)

    def test_dev_override_variable_neither_manufactures_nor_removes_trust(self):
        # A genuinely verified bundle stays verified whether or not the
        # development variable is present: the manifest is what grants trust.
        clean = discover_tethers(
            probe=False,
            env=bundle_env(self.bundle("verified")),
            platform=plat(),
        )
        with_variable = discover_tethers(
            probe=False,
            env=bundle_env(self.bundle("verified")) | {DEV_UNVERIFIED_ENV: "1"},
            platform=plat(),
        )
        for installation in (clean, with_variable):
            self.assertEqual(installation.verification, "verified")
            self.assertFalse(installation.dev_override_active)
            self.assertTrue(installation.acceptable_for_authority)


class ProductVersionSupportTests(ProductTrustHarness, unittest.TestCase):
    """Production authority accepts an explicit set of Tethers product versions.

    A genuinely verified bundle of the wrong version is a *product support*
    refusal, never a corruption report, and never a silent pass.
    """

    def bundle_version(self, name: str, version: str) -> Path:
        return make_release_bundle(self.root / name, product_version=version)

    def test_accepted_product_version_is_accepted(self):
        installation = discover_tethers(
            probe=True, env=bundle_env(self.bundle_version("v081", "0.8.1")),
            platform=plat(),
        )
        self.assertEqual(installation.product_version, "0.8.1")
        self.assertEqual(installation.verification, "verified")
        self.assertIsNone(validate_authority_installation(installation))
        self.assertTrue(installation.acceptable_for_authority)

    def test_verified_older_release_is_refused_as_unsupported(self):
        installation = discover_tethers(
            probe=True, env=bundle_env(self.bundle_version("v080", "0.8.0")),
            platform=plat(),
        )
        # The bytes are genuine; only the product support decision differs.
        self.assertEqual(installation.verification, "verified")
        self.assertEqual(installation.provenance, "release_manifest")
        self.assertFalse(installation.acceptable_for_authority)
        refusal = validate_authority_installation(installation)
        self.assertIsNotNone(refusal)
        self.assertIn("0.8.0", refusal)
        self.assertIn("0.8.1", refusal)
        self.assert_refuses_before_startup(installation)

    def test_verified_future_release_is_refused(self):
        installation = discover_tethers(
            probe=True, env=bundle_env(self.bundle_version("future", "9.9.9")),
            platform=plat(),
        )
        self.assertEqual(installation.verification, "verified")
        self.assertFalse(installation.acceptable_for_authority)
        self.assert_refuses_before_startup(installation)

    def test_missing_product_version_is_refused(self):
        installation = discover_tethers(
            probe=True, env=bundle_env(self.bundle_version("no-version", "")),
            platform=plat(),
        )
        self.assertIsNone(installation.product_version)
        self.assertEqual(installation.verification, "verified")
        self.assertFalse(installation.acceptable_for_authority)
        refusal = validate_authority_installation(installation)
        self.assertIn("missing or unknown", refusal)
        self.assert_refuses_before_startup(installation)

    def test_doctor_explains_an_unsupported_but_genuine_product(self):
        report = self.doctor(bundle_env(self.bundle_version("v080", "0.8.0")))
        # Genuine product: provenance and identity both pass...
        self.assertEqual(self.check(report, "tethers.provenance")["status"], PASS)
        self.assertEqual(self.check(report, "tethers.identity")["status"], PASS)
        self.assertEqual(report["tethers"]["verification"], "verified")
        self.assertEqual(report["tethers"]["product_version"], "0.8.0")
        self.assertEqual(report["tethers"]["supported_product_versions"], ["0.8.1"])
        self.assertIs(report["tethers"]["product_version_supported"], False)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        self.assertNotEqual(report["overall"]["status"], PASS)

        # ...but the product version is the reason authority is refused.
        ready = self.check(report, "tethers.authority_ready")
        self.assertEqual(ready["status"], "FAIL")
        self.assertIn("genuine verified release", ready["detail"])
        self.assertIn("0.8.0", ready["detail"])
        self.assertIn("0.8.1", ready["detail"])
        self.assertIn("0.8.1", ready["remediation"])
        for wording in ("missing", "corrupt", "not found", "engine missing"):
            self.assertNotIn(wording, ready["detail"].lower())

    def test_missing_version_is_reported_as_missing_not_corrupt(self):
        report = self.doctor(bundle_env(self.bundle_version("no-version", "")))
        ready = self.check(report, "tethers.authority_ready")
        self.assertEqual(ready["status"], "FAIL")
        self.assertIn("missing or unknown", ready["detail"])
        self.assertEqual(report["tethers"]["product_version"], None)
        self.assertIs(report["tethers"]["product_version_supported"], False)

    def test_dev_override_cannot_bypass_version_support(self):
        env = bundle_env(self.bundle_version("v080", "0.8.0")) | {
            DEV_UNVERIFIED_ENV: "1"
        }
        installation = discover_tethers(probe=False, env=env, platform=plat())
        self.assertFalse(installation.acceptable_for_authority)
        refusal = validate_authority_installation(installation)
        self.assertIn("0.8.0", refusal)
        self.assert_refuses_before_startup(installation)

        report = self.doctor(env)
        self.assertIs(report["tethers"]["acceptable_for_authority"], False)
        self.assertIs(report["tethers"]["product_version_supported"], False)
        self.assertIn("0.8.0", self.check(report, "tethers.authority_ready")["detail"])

    def test_development_opt_in_is_still_marked_and_never_production(self):
        # The explicit development boundary still works for an unsupported
        # version -- but it is permanently development authority, never trust.
        installation = discover_tethers(
            probe=False, env=bundle_env(self.bundle_version("v080", "0.8.0")),
            platform=plat(),
        )
        with self.session(
            installation, allow_unverified_for_development=True
        ) as session:
            self.assertTrue(session.development_authority)
            self.assertFalse(session.acceptable_for_authority)
            session.hello()
        self.assertFalse(installation.acceptable_for_authority)

    def test_version_support_is_one_explicit_set_not_a_semver_engine(self):
        from permission_slip.tethers_install import (
            SUPPORTED_AUTHORITY_PRODUCT_VERSIONS,
            product_version_refusal,
        )

        self.assertEqual(SUPPORTED_AUTHORITY_PRODUCT_VERSIONS, ("0.8.1",))
        self.assertIsNone(product_version_refusal("0.8.1"))
        for unsupported in ("0.8.0", "0.8.2", "0.9.0", "1.0.0", "", None):
            with self.subTest(version=unsupported):
                self.assertIsNotNone(product_version_refusal(unsupported))


class DoctorExecutionEquivalenceTests(ProductTrustHarness, unittest.TestCase):
    """The required invariant: doctor's verdict and execution must agree."""

    def _scenarios(self):
        yield "verified", bundle_env(self.bundle("verified"))
        yield "manifest absent", bundle_env(self.bundle("no-manifest", manifest=False))
        yield (
            "dev override",
            bundle_env(self.bundle("tampered", tamper=True))
            | {DEV_UNVERIFIED_ENV: "1"},
        )
        yield "dev source checkout", isolated_env(
            {DEV_CHECKOUT_ENV: str(self.dev_checkout())}
        )
        yield "unsupported product version", bundle_env(
            make_release_bundle(self.root / "v080", product_version="0.8.0")
        )
        yield "missing product version", bundle_env(
            make_release_bundle(self.root / "no-version", product_version="")
        )

    def test_doctor_and_execution_agree_on_every_installation_state(self):
        for label, env in self._scenarios():
            with self.subTest(label=label):
                report = self.doctor(env)
                acceptable = report["tethers"]["acceptable_for_authority"]
                ready_check = self.check(report, "tethers.authority_ready")
                # JSON field, check status and overall status all agree.
                self.assertEqual(acceptable, ready_check["status"] == PASS)
                self.assertEqual(
                    report["overall"]["status"] == PASS, acceptable is True
                )
                if report["tethers"]["product_version_supported"] is False:
                    self.assertFalse(
                        acceptable,
                        "an unsupported product version must never be acceptable authority",
                    )
                if acceptable is True:
                    self.assertIn("may act as Permission Slip authority", ready_check["detail"])
                else:
                    self.assertIn(
                        "may not act as Permission Slip authority", ready_check["detail"]
                    )

                try:
                    installation = discover_tethers(probe=False, env=env, platform=plat())
                except TethersUnavailable:
                    installation = None

                with mock.patch(POPEN) as popen:
                    started = False
                    if installation is not None:
                        try:
                            self.session(installation)
                        except TethersUnverified:
                            started = False
                        else:
                            started = True
                    # Invariant: doctor not-ready ==> no default authority session.
                    if acceptable is not True:
                        self.assertFalse(
                            started,
                            f"{label}: doctor said not ready but a default session was allowed",
                        )
                        popen.assert_not_called()
                    else:
                        self.assertTrue(started, f"{label}: ready but session refused")


if __name__ == "__main__":
    unittest.main()
