"""Prove Permission Slip consumes the published Tethers 0.8.1 product.

Run *after* ``scripts/tethers_release.py acquire`` has pinned and extracted the
release, with ``TETHERS_ROOT`` pointing at that clean extraction and with all
development override variables absent.

It walks the consumer path end to end and writes a machine-readable report:

    A  released package bytes were pinned against the release lock
    B  Permission Slip discovers the Gate + sibling engine from TETHERS_ROOT
    C  product_version == 0.8.1
    D  verification == verified
    E  provenance == release_manifest
    F  acceptable_for_authority == true
    G  development override == false
    H  setup/provisioning succeeds
    I  doctor reaches PASS / ready
    J  a real tethers.authority/1 hello succeeds
    K  the existing Permission Slip authority lifecycle (ALLOW / ASK / DENY /
       OUTCOME) runs against the packaged Tethers

K reuses ``tests.test_vertical_spike`` -- the accepted v0.1/0.2 integration
machinery -- rather than growing a second permission-engine suite.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from permission_slip.doctor import run_doctor  # noqa: E402
from permission_slip.state import TETHERS_HOST_STATE_DIR  # noqa: E402
from permission_slip.tethers_client import GateSession  # noqa: E402
from permission_slip.tethers_install import (  # noqa: E402
    AUTHORITY_PROTOCOL,
    discover_tethers,
    machine_label,
    provision_host_data_root,
    system_label,
)
from scripts.tethers_release import (  # noqa: E402
    FORBIDDEN_DEV_ENV_VARS,
    ReleaseProofError,
    load_release_lock,
    select_target,
)

PROOF_SCHEMA = "permission-slip.tethers-product-proof/1"

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


class Checks:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def record(self, check_id: str, ok: bool, detail: str) -> bool:
        self.items.append(
            {"id": check_id, "status": "PASS" if ok else "FAIL", "detail": detail}
        )
        return ok

    @property
    def failures(self) -> int:
        return sum(1 for item in self.items if item["status"] != "PASS")


def _run_lifecycle() -> dict[str, Any]:
    """Run the accepted vertical-spike lifecycle against the packaged product."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_vertical_spike")
    result = unittest.TestResult()
    suite.run(result)
    failures = len(result.failures) + len(result.errors)
    return {
        "tests_run": result.testsRun,
        "failures": failures,
        "failed_ids": [
            str(test) for test, _ in list(result.failures) + list(result.errors)
        ],
        "skipped": len(getattr(result, "skipped", [])),
    }


def run_proof(
    lock_path: Path,
    *,
    tethers_root: str | None,
    state_root: Path,
    evidence_dir: Path,
) -> dict[str, Any]:
    checks = Checks()
    report: dict[str, Any] = {"schema": PROOF_SCHEMA}

    if tethers_root:
        os.environ["TETHERS_ROOT"] = tethers_root
    present_overrides = [n for n in FORBIDDEN_DEV_ENV_VARS if os.environ.get(n, "")]
    checks.record(
        "dev_overrides_absent",
        not present_overrides,
        "no development override variable is set"
        if not present_overrides
        else "set: " + ", ".join(present_overrides),
    )

    # -- release lock -------------------------------------------------------
    lock = load_release_lock(lock_path)
    try:
        target = select_target(lock)
    except ReleaseProofError as exc:
        checks.record("release_lock_target", False, str(exc))
        return _finish(report, checks, state_root)
    checks.record(
        "release_lock_target",
        True,
        f"{target['target']} -> {target['release_asset']} "
        f"sha256={target['release_asset_sha256']}",
    )
    report["release_lock"] = {
        "schema": lock["schema"],
        "path": str(lock_path),
        "tag": lock["tag"],
        "source_commit": lock["source_commit"],
        "source_tree": lock["source_tree"],
        "product_version": lock["product_version"],
        "authority_protocol": lock["authority_protocol"],
        "target": target["target"],
        "release_asset": target["release_asset"],
        "release_asset_sha256": target["release_asset_sha256"],
        "manifest_asset": target["manifest_asset"],
        "manifest_asset_sha256": target["manifest_asset_sha256"],
        "bytes_pinned_before_extraction": True,
    }

    # -- B: discovery -------------------------------------------------------
    root_value = os.environ.get("TETHERS_ROOT", "")
    if not root_value:
        checks.record("discovery", False, "TETHERS_ROOT is not set")
        return _finish(report, checks, state_root)
    bundle_root = Path(root_value).resolve()
    try:
        installation = discover_tethers(probe=True)
    except Exception as exc:  # TethersUnavailable and friends
        checks.record("discovery", False, f"{type(exc).__name__}: {exc}")
        return _finish(report, checks, state_root)

    gate_inside = installation.gate_bin.is_relative_to(bundle_root)
    engine_inside = installation.engine_bin.is_relative_to(bundle_root)
    checks.record(
        "discovery",
        gate_inside and engine_inside,
        f"gate={installation.gate_bin} engine={installation.engine_bin} "
        f"(source={installation.discovery_source}/{installation.engine_source})",
    )
    checks.record(
        "engine_from_bundle",
        installation.engine_source == "bundle_sibling",
        f"engine_source={installation.engine_source}",
    )
    checks.record(
        "platform_matches_lock",
        system_label() == target["system"] and machine_label() == target["machine"],
        f"reported={system_label()} {machine_label()} "
        f"lock={target['system']} {target['machine']}",
    )

    # -- C: product version -------------------------------------------------
    checks.record(
        "product_version",
        installation.product_version == lock["product_version"],
        f"product_version={installation.product_version!r} "
        f"(expected {lock['product_version']!r})",
    )

    # -- D/E: verification + provenance -------------------------------------
    checks.record("verification", installation.verification == "verified",
                  f"verification={installation.verification}")
    checks.record("provenance", installation.provenance == "release_manifest",
                  f"provenance={installation.provenance}")

    # -- F: acceptable for authority ----------------------------------------
    acceptable = installation.acceptable_for_authority
    checks.record("acceptable_for_authority", acceptable is True,
                  f"acceptable_for_authority={acceptable}")

    # -- G: development override --------------------------------------------
    checks.record(
        "dev_override_false",
        installation.dev_override_active is False and not installation.is_dev,
        f"dev_override_active={installation.dev_override_active} "
        f"is_dev={installation.is_dev}",
    )

    report["tethers"] = {
        "gate_bin": str(installation.gate_bin),
        "engine_bin": str(installation.engine_bin),
        "install_root": str(installation.install_root),
        "discovery_source": installation.discovery_source,
        "engine_source": installation.engine_source,
        "product_version": installation.product_version,
        "authority_protocol": installation.authority_protocol,
        "verification": installation.verification,
        "provenance": installation.provenance,
        "gate_sha256": installation.gate_sha256,
        "engine_sha256": installation.engine_sha256,
        "release_manifest": str(installation.release_manifest),
        "acceptable_for_authority": acceptable,
        "dev_override_active": installation.dev_override_active,
        "is_dev": installation.is_dev,
        "platform": installation.platform,
    }

    if not acceptable:
        # Nothing below may run: an unacceptable installation is never started.
        checks.record(
            "setup", False, "installation is not acceptable for authority; refusing to start it"
        )
        return _finish(report, checks, state_root)

    # -- H: provisioning ----------------------------------------------------
    host_root = state_root / TETHERS_HOST_STATE_DIR
    try:
        setup_report = provision_host_data_root(installation, host_root)
    except Exception as exc:
        checks.record("setup", False, f"{type(exc).__name__}: {exc}")
        return _finish(report, checks, state_root)
    checks.record(
        "setup",
        bool(setup_report.get("provisioned")),
        f"host_data_root={setup_report.get('host_data_root')} "
        f"product_version={setup_report.get('product_version')}",
    )
    report["setup"] = setup_report

    # -- I: doctor ----------------------------------------------------------
    doctor = run_doctor(env=os.environ, platform=sys.platform, state_root=state_root)
    doctor_ok = doctor["overall"]["status"] == "PASS"
    ready = next(
        (
            item
            for item in doctor["checks"]
            if item["id"] == "tethers.authority_ready"
        ),
        {},
    )
    checks.record(
        "doctor",
        doctor_ok and ready.get("status") == "PASS",
        f"overall={doctor['overall']['status']} "
        f"authority_ready={ready.get('status')} ({ready.get('detail')})",
    )
    report["doctor"] = {
        "schema": doctor["schema"],
        "overall": doctor["overall"]["status"],
        "summary": doctor["overall"]["summary"],
        "acceptable_for_authority": doctor["tethers"]["acceptable_for_authority"],
        "product_version": doctor["tethers"]["product_version"],
        "supported_product_versions": doctor["tethers"]["supported_product_versions"],
        "product_version_supported": doctor["tethers"]["product_version_supported"],
        "verification": doctor["tethers"]["verification"],
        "provenance": doctor["tethers"]["provenance"],
        "checks": [
            {"id": item["id"], "status": item["status"]} for item in doctor["checks"]
        ],
    }
    if not doctor_ok:
        return _finish(report, checks, state_root)

    # -- J: real authority hello -------------------------------------------
    evidence_dir.mkdir(parents=True, exist_ok=True)
    config_path = evidence_dir / "runtime.json"
    config_path.write_text(json.dumps(_MINIMAL_CONFIG, indent=2), encoding="utf-8")
    try:
        session = GateSession(
            config_path=config_path,
            trail_path=evidence_dir / "trail.jsonl",
            host_data_root=evidence_dir / "host-data",
            paths=installation,
            response_timeout=60.0,
        )
        session.start()
        try:
            hello = session.hello()
        finally:
            session.close()
    except Exception as exc:
        checks.record("authority_hello", False, f"{type(exc).__name__}: {exc}")
        return _finish(report, checks, state_root)

    hello_ok = (
        hello.get("protocol") == AUTHORITY_PROTOCOL
        and hello.get("protocol_versions") == [AUTHORITY_PROTOCOL]
        and hello.get("provider_invocations") == 0
        and hello.get("authority_granted") is False
        and hello.get("product_version") == lock["product_version"]
    )
    checks.record(
        "authority_hello",
        hello_ok,
        f"protocol={hello.get('protocol')} "
        f"product_version={hello.get('product_version')} "
        f"authority_granted={hello.get('authority_granted')!r} "
        f"provider_invocations={hello.get('provider_invocations')}",
    )
    report["hello"] = {
        "protocol": hello.get("protocol"),
        "protocol_versions": hello.get("protocol_versions"),
        "product_version": hello.get("product_version"),
        "authority_granted": hello.get("authority_granted"),
        "provider_invocations": hello.get("provider_invocations"),
        "git_sha": hello.get("git_sha"),
        "gate_instance_id": hello.get("gate_instance_id"),
    }

    # -- K: existing authority lifecycle ------------------------------------
    try:
        lifecycle = _run_lifecycle()
    except Exception as exc:
        lifecycle = {"tests_run": 0, "failures": 1, "error": f"{type(exc).__name__}: {exc}"}
    checks.record(
        "authority_lifecycle",
        lifecycle.get("failures", 1) == 0 and lifecycle.get("tests_run", 0) > 0,
        f"{lifecycle.get('tests_run', 0)} tests, {lifecycle.get('failures', 0)} failed",
    )
    report["lifecycle"] = lifecycle

    return _finish(report, checks, state_root)


def _finish(report: dict[str, Any], checks: Checks, state_root: Path) -> dict[str, Any]:
    failures = checks.failures
    report["checks"] = checks.items
    report["state_root"] = str(state_root)
    report["overall"] = {
        "status": "PASS" if failures == 0 else "FAIL",
        "checks": len(checks.items),
        "failures": failures,
    }
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tethers_product_proof.py",
        description="Prove Permission Slip consumes the published Tethers product.",
    )
    parser.add_argument("--lock", required=True, help="Path to the release lock JSON.")
    parser.add_argument(
        "--tethers-root",
        help="Bundle root to prove (defaults to the TETHERS_ROOT environment variable).",
    )
    parser.add_argument(
        "--state-root",
        help="Isolated Permission Slip state root (defaults to a fresh temp directory).",
    )
    parser.add_argument(
        "--evidence-dir",
        help="Directory for the throwaway protocol evidence (defaults to a temp directory).",
    )
    parser.add_argument("--report", help="Write the JSON evidence report to this path.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    state_root = (
        Path(args.state_root)
        if args.state_root
        else Path(tempfile.mkdtemp(prefix="ps-product-proof-state-"))
    )
    state_root.mkdir(parents=True, exist_ok=True)
    os.environ["PERMISSION_SLIP_STATE_DIR"] = str(state_root)
    evidence_dir = (
        Path(args.evidence_dir)
        if args.evidence_dir
        else Path(tempfile.mkdtemp(prefix="ps-product-proof-evidence-"))
    )

    report = run_proof(
        Path(args.lock),
        tethers_root=args.tethers_root,
        state_root=state_root,
        evidence_dir=evidence_dir,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if report["overall"]["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
