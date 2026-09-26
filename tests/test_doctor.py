"""``permission-slip doctor`` behaviour and its versioned JSON envelope."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from permission_slip import __version__
from permission_slip.doctor import (
    CHECK_ORDER,
    DOCTOR_SCHEMA,
    FAIL,
    PASS,
    UNAVAILABLE,
    UNSUPPORTED,
    exit_code_for,
    render_human,
    render_json,
    run_doctor,
)
from permission_slip.state import STATE_DIR_ENV
from permission_slip.tethers_install import DEV_UNVERIFIED_ENV, GATE_ENV
from tests.fake_tethers import bundle_env, isolated_env, make_release_bundle


def plat() -> str:
    import sys

    return sys.platform


def provision_state(state_root: Path) -> Path:
    host = state_root / "tethers-host"
    replay = host / "replay" / "v1"
    replay.mkdir(parents=True, exist_ok=True)
    (replay / "FORMAT.json").write_text('{"format": 1}\n', encoding="utf-8")
    return host


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-doctor-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state_root = self.root / "state"

    def healthy(self, **kwargs) -> dict:
        bundle = make_release_bundle(self.root / "bundle", **kwargs)
        provision_state(self.state_root)
        return run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
        )

    def check(self, report: dict, check_id: str) -> dict:
        for item in report["checks"]:
            if item["id"] == check_id:
                return item
        raise AssertionError(f"check {check_id} missing from report")

    # -- healthy ------------------------------------------------------------

    def test_healthy_installation_passes(self):
        report = self.healthy()
        self.assertEqual(report["overall"]["status"], PASS)
        self.assertEqual(report["overall"]["summary"], "ready")
        self.assertEqual(
            [item["id"] for item in report["checks"]], list(CHECK_ORDER)
        )
        for item in report["checks"]:
            self.assertEqual(item["status"], PASS, item)

    def test_human_output_shape(self):
        report = self.healthy()
        lines = render_human(report).splitlines()
        self.assertEqual(
            lines,
            [
                f"Permission Slip {__version__.rsplit('.', 1)[0]}",
                "Tethers: 9.9.9",
                f"Protocol: {report['tethers']['authority_protocol']}",
                f"Platform: {report['platform']['system']} {report['platform']['machine']}",
                "State: ready",
            ],
        )

    def test_json_envelope_is_versioned_and_deterministic(self):
        first = self.healthy()
        second = self.healthy()
        self.assertEqual(first["schema"], DOCTOR_SCHEMA)
        self.assertEqual(first["schema"], "permission-slip.doctor/1")
        self.assertEqual(first["permission_slip_version"], __version__)
        self.assertEqual(render_json(first), render_json(second))
        # Two independent parses must agree on every key.
        self.assertEqual(
            json.loads(render_json(first))["overall"], first["overall"]
        )

    def test_json_does_not_depend_on_the_human_prose(self):
        report = self.healthy()
        parsed = json.loads(render_json(report))
        self.assertNotIn("human", parsed)
        self.assertNotIn("summary_text", parsed)
        self.assertIn("checks", parsed)
        self.assertIn("overall", parsed)

    def test_json_prints_no_unrelated_environment(self):
        report = self.healthy()
        blob = render_json(report)
        self.assertNotIn("PATH=", blob)
        self.assertNotIn("PERMISSION_SLIP_DEV", blob)
        # Diagnostic paths are fine; raw environment dumps are not.
        self.assertNotIn('"environment"', blob)

    def test_exit_codes_are_distinct(self):
        self.assertEqual(exit_code_for(PASS), 0)
        self.assertEqual(exit_code_for(FAIL), 1)
        self.assertEqual(exit_code_for(UNAVAILABLE), 2)
        self.assertEqual(exit_code_for(UNSUPPORTED), 3)

    # -- failures -----------------------------------------------------------

    def test_missing_tethers_is_reported_as_not_ready(self):
        empty = self.root / "empty"
        empty.mkdir(parents=True, exist_ok=True)
        report = run_doctor(
            env=isolated_env({"PATH": str(empty)}),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        executable = self.check(report, "tethers.executable")
        self.assertEqual(executable["status"], FAIL)
        self.assertIn("Install a released Tethers bundle", executable["remediation"])
        self.assertEqual(self.check(report, "authority.protocol")["status"], UNAVAILABLE)

    def test_missing_engine_reports_a_specific_failure(self):
        bundle = self.root / "no-engine"
        from tests.fake_tethers import make_fake_gate

        make_fake_gate(bundle / "bin")
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        engine = self.check(report, "tethers.engine")
        self.assertEqual(engine["status"], FAIL)
        self.assertEqual(
            engine["detail"], "Tethers engine missing from installed bundle."
        )
        self.assertEqual(self.check(report, "tethers.executable")["status"], PASS)
        self.assertEqual(report["overall"]["counts"][FAIL], 1)

    def test_tampered_binary_fails_provenance(self):
        bundle = make_release_bundle(self.root / "tampered", tamper=True)
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        provenance = self.check(report, "tethers.provenance")
        self.assertEqual(provenance["status"], FAIL)
        self.assertIn("release manifest verification failed", provenance["detail"])

    def test_wrong_protocol_is_unsupported(self):
        bundle = make_release_bundle(self.root / "wrong-proto", gate_mode="wrong_protocol")
        provision_state(self.state_root)
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
        )
        self.assertEqual(report["overall"]["status"], UNSUPPORTED)
        protocol = self.check(report, "authority.protocol")
        self.assertEqual(protocol["status"], UNSUPPORTED)
        self.assertIn("tethers.authority/1", protocol["detail"])

    def test_gate_that_dies_during_startup_fails(self):
        bundle = make_release_bundle(self.root / "dies", gate_mode="exits")
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        protocol = self.check(report, "authority.protocol")
        self.assertEqual(protocol["status"], FAIL)
        self.assertIn("startup failed", protocol["detail"])

    def test_unwritable_state_root_fails(self):
        blocked = self.root / "blocked"
        blocked.write_text("a file, not a directory", encoding="utf-8")
        bundle = make_release_bundle(self.root / "bundle")
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=blocked,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        state = self.check(report, "state.root")
        self.assertEqual(state["status"], FAIL)
        self.assertIn(STATE_DIR_ENV, state["remediation"])
        self.assertEqual(self.check(report, "tethers.host_data")["status"], UNAVAILABLE)
        self.assertFalse(report["state"]["writable"])

    def test_unprovisioned_state_is_unavailable_with_remediation(self):
        bundle = make_release_bundle(self.root / "bundle")
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], UNAVAILABLE)
        self.assertFalse(report["state"]["provisioned"])
        for check_id in ("tethers.host_data", "provisioning.ready"):
            item = self.check(report, check_id)
            self.assertEqual(item["status"], UNAVAILABLE)
            self.assertEqual(item["remediation"], "Run: permission-slip setup")

    # -- development override ----------------------------------------------

    def test_dev_override_is_visible_and_never_counts_as_success(self):
        bundle = make_release_bundle(self.root / "tampered", tamper=True)
        provision_state(self.state_root)
        report = run_doctor(
            env=bundle_env(bundle) | {DEV_UNVERIFIED_ENV: "1"},
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
        )
        provenance = self.check(report, "tethers.provenance")
        self.assertEqual(provenance["status"], UNAVAILABLE)
        self.assertIn("development-only override active", provenance["detail"])
        self.assertIn(DEV_UNVERIFIED_ENV, provenance["detail"])
        self.assertTrue(report["tethers"]["dev_override"])
        self.assertIn(DEV_UNVERIFIED_ENV, report["tethers"]["dev_override_variables"])
        # A dev override must never be reported as a successful verification.
        self.assertNotEqual(report["overall"]["status"], PASS)
        self.assertNotIn("verified", report["tethers"]["verification"])
        self.assertIn("unverified/dev", render_human(report))

    def test_missing_manifest_is_reported_as_unverified(self):
        bundle = make_release_bundle(self.root / "no-manifest", manifest=False)
        provision_state(self.state_root)
        report = run_doctor(
            env=bundle_env(bundle),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        provenance = self.check(report, "tethers.provenance")
        self.assertEqual(provenance["status"], UNAVAILABLE)
        self.assertEqual(report["tethers"]["verification"], "unverified")
        self.assertNotEqual(report["overall"]["status"], PASS)

    def test_explicit_bad_gate_path_is_reported(self):
        report = run_doctor(
            env=isolated_env({GATE_ENV: str(self.root / "nope" / "tethers.exe")}),
            platform=plat(),
            home=self.root / "home",
            state_root=self.state_root,
            probe_protocol=False,
        )
        self.assertEqual(report["overall"]["status"], FAIL)
        executable = self.check(report, "tethers.executable")
        self.assertIn(GATE_ENV, executable["detail"])
        self.assertNotEqual(executable["status"], PASS)


if __name__ == "__main__":
    unittest.main()
