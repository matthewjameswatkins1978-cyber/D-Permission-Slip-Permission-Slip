"""``tethers.authority/1`` startup contract.

Every case here uses a fake Gate process so the failure modes can actually be
produced: unsupported protocol identity, malformed frames, a Gate that dies
during startup, and a Gate that never answers.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from permission_slip.tethers_client import (
    AUTHORITY_PROTOCOL,
    GateSession,
    TethersProtocolMismatch,
    TethersUnavailable,
)
from permission_slip.tethers_install import discover_tethers
from tests.fake_tethers import bundle_env, isolated_env, make_release_bundle

MINIMAL_CONFIG = {
    "format_version": "0.1",
    "tether_set": {
        "id": "permission-slip.protocol-tests",
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


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-protocol-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workdir = self.root / "work"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.config = self.workdir / "runtime.json"
        self.config.write_text(json.dumps(MINIMAL_CONFIG, indent=2), encoding="utf-8")

    def installation(self, mode: str = "ok"):
        bundle = make_release_bundle(self.root / f"bundle-{mode}", gate_mode=mode)
        return discover_tethers(
            probe=False, env=bundle_env(bundle), platform=plat()
        )

    def session(self, mode: str = "ok", *, response_timeout: float = 15.0) -> GateSession:
        return GateSession(
            config_path=self.config,
            trail_path=self.workdir / f"trail-{mode}.jsonl",
            host_data_root=self.workdir / f"host-data-{mode}",
            paths=self.installation(mode),
            response_timeout=response_timeout,
        )

    # -- success -----------------------------------------------------------

    def test_correct_authority_protocol_hello_succeeds(self):
        with self.session("ok") as session:
            result = session.hello()
        self.assertEqual(result["protocol"], AUTHORITY_PROTOCOL)
        self.assertIn(AUTHORITY_PROTOCOL, result["protocol_versions"])
        self.assertEqual(result["provider_invocations"], 0)
        self.assertEqual(result["product_version"], "9.9.9")

    def test_ndjson_process_boundary_is_preserved(self):
        session = self.session("ok")
        session.start()
        try:
            self.assertIsNotNone(session._process)  # external process, not an import
            result = session.hello()
        finally:
            session.close()
        self.assertIsInstance(result, dict)

    # -- unsupported protocol identity -------------------------------------

    def test_wrong_hello_protocol_identity_fails_closed(self):
        session = self.session("wrong_protocol")
        session.start()
        try:
            with self.assertRaises(TethersProtocolMismatch) as caught:
                session.hello()
        finally:
            session.close()
        self.assertIn("tethers.authority/1", str(caught.exception))

    def test_wrong_frame_schema_fails_closed(self):
        session = self.session("wrong_schema")
        session.start()
        try:
            with self.assertRaises(TethersProtocolMismatch):
                session.hello()
        finally:
            session.close()

    # -- malformed startup --------------------------------------------------

    def test_malformed_startup_response_fails_closed(self):
        session = self.session("malformed")
        session.start()
        try:
            with self.assertRaises(TethersUnavailable) as caught:
                session.hello()
            self.assertEqual(caught.exception.code, "malformed_response")
        finally:
            session.close()

    def test_gate_error_envelope_fails_closed(self):
        session = self.session("cli_error")
        session.start()
        try:
            with self.assertRaises(TethersUnavailable) as caught:
                session.hello()
            self.assertEqual(caught.exception.code, "startup_error")
        finally:
            session.close()

    def test_process_exiting_during_startup_fails_closed(self):
        session = self.session("exits")
        session.start()
        try:
            with self.assertRaises(TethersUnavailable) as caught:
                session.hello()
            self.assertEqual(caught.exception.code, "startup_failed")
        finally:
            session.close()

    def test_provider_calls_from_the_gate_are_rejected(self):
        session = self.session("provider_calls")
        session.start()
        try:
            with self.assertRaises(TethersUnavailable) as caught:
                session.hello()
            self.assertEqual(caught.exception.code, "malformed_response")
        finally:
            session.close()

    # -- bounded startup ---------------------------------------------------

    def test_startup_timeout_remains_bounded(self):
        session = self.session("silent", response_timeout=1.0)
        session.start()
        started = time.monotonic()
        try:
            with self.assertRaises(TethersUnavailable) as caught:
                session.hello()
            self.assertEqual(caught.exception.code, "timeout")
        finally:
            session.close()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 20.0, f"startup was not bounded: {elapsed}s")

    def test_missing_gate_binary_cannot_start(self):
        from permission_slip.tethers_install import TethersInstallation

        installation = TethersInstallation(
            gate_bin=self.root / "absent-gate.exe",
            engine_bin=self.root / "absent-engine.exe",
            install_root=None,
            product_version=None,
            authority_protocol=AUTHORITY_PROTOCOL,
            gate_sha256="0" * 64,
            engine_sha256="0" * 64,
            provenance="absent",
            verification="unverified",
            discovery_source="explicit_config",
            engine_source="explicit_config",
            platform="Windows x86_64",
            release_manifest=None,
            dev_override_active=False,
        )
        session = GateSession(
            config_path=self.config,
            trail_path=self.workdir / "trail-missing.jsonl",
            host_data_root=self.workdir / "host-data-missing",
            paths=installation,
            response_timeout=5.0,
        )
        with self.assertRaises(TethersUnavailable) as caught:
            session.start()
        self.assertEqual(caught.exception.code, "gate_unreadable")

    def test_isolated_environment_finds_no_tethers(self):
        with self.assertRaises(TethersUnavailable):
            discover_tethers(probe=False, env=isolated_env(), platform=plat())


if __name__ == "__main__":
    unittest.main()
