"""``permission-slip doctor`` -- the first product front door.

Answers, quickly and honestly:

* which Permission Slip is this, and what platform is it on;
* where did Tethers come from, does it pair, and what does it report;
* does the ``tethers.authority/1`` protocol actually come up;
* is Permission Slip's own durable state root usable and provisioned.

Output is a Permission Slip-owned, versioned, deterministic JSON envelope
(``permission-slip.doctor/1``) plus a short human rendering. The JSON never
depends on the prose. Nothing secret and no unrelated environment value is
ever printed.
"""

from __future__ import annotations

import json
import os
import platform as platform_module
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .state import (
    STATE_DIR_ENV,
    TETHERS_HOST_STATE_DIR,
    permission_slip_state_root,
)
from .tethers_client import (
    AUTHORITY_PROTOCOL,
    GateSession,
    TethersProtocolMismatch,
    TethersUnavailable,
)
from .tethers_install import (
    DEV_CHECKOUT_ENV,
    DEV_UNVERIFIED_ENV,
    ENGINE_ENV,
    GATE_ENV,
    TethersInstallation,
    describe_product,
    dev_override_active,
    dev_override_names,
    find_release_manifest,
    host_data_provisioned,
    locate_tethers,
    machine_label,
    sha256_file,
    system_label,
    verify_release_provenance,
)

DOCTOR_SCHEMA = "permission-slip.doctor/1"
SETUP_SCHEMA = "permission-slip.setup/1"

PASS = "PASS"
FAIL = "FAIL"
UNAVAILABLE = "UNAVAILABLE"
UNSUPPORTED = "UNSUPPORTED"

#: Overall status is decided by this precedence: worst first.
_STATUS_PRECEDENCE = (FAIL, UNSUPPORTED, UNAVAILABLE, PASS)

#: Fixed check order. Determinism of the JSON depends on this being stable.
CHECK_ORDER = (
    "permission_slip.version",
    "platform",
    "tethers.executable",
    "tethers.engine",
    "tethers.discovery",
    "tethers.identity",
    "tethers.hashes",
    "tethers.provenance",
    "authority.protocol",
    "state.root",
    "tethers.host_data",
    "provisioning.ready",
)

_EXIT_CODES = {PASS: 0, FAIL: 1, UNAVAILABLE: 2, UNSUPPORTED: 3}

_SETUP_REMEDIATION = "Run: permission-slip setup"


def exit_code_for(status: str) -> int:
    return _EXIT_CODES.get(status, 1)


class _Checks:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def add(
        self,
        check_id: str,
        status: str,
        detail: str,
        remediation: str | None = None,
    ) -> None:
        item: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
        if remediation:
            item["remediation"] = remediation
        self._items[check_id] = item

    @property
    def ordered(self) -> list[dict[str, Any]]:
        return [self._items[key] for key in CHECK_ORDER if key in self._items]

    @property
    def statuses(self) -> dict[str, int]:
        counts = {status: 0 for status in _STATUS_PRECEDENCE}
        for item in self.ordered:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return counts

    @property
    def overall(self) -> str:
        present = {item["status"] for item in self.ordered}
        for status in _STATUS_PRECEDENCE:
            if status in present:
                return status
        return PASS


def _probe_protocol(
    installation: TethersInstallation, *, timeout: float = 20.0
) -> dict[str, Any]:
    """Perform a real ``tethers.authority/1`` hello against a throwaway workspace.

    The probe workspace is temporary and discarded: doctor must not leave
    durable state behind, and it must never run an authority request on
    Permission Slip's real host-data root.
    """
    config = {
        "format_version": "0.1",
        "tether_set": {
            "id": "permission-slip.doctor",
            "version": "1",
            "tethers": [],
            "capability_requirements": [],
        },
        "providers": [],
        "policy": {"default": "deny", "rules": []},
    }
    with tempfile.TemporaryDirectory(prefix="permission-slip-doctor-") as tmp:
        workdir = Path(tmp)
        config_path = workdir / "runtime.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        session = GateSession(
            config_path=config_path,
            trail_path=workdir / "trail.jsonl",
            host_data_root=workdir / "host-data",
            paths=installation,
            response_timeout=timeout,
        )
        session.start()
        try:
            result = session.hello()
        finally:
            session.close()
    return result


def run_doctor(
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
    probe_protocol: bool = True,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Build the ``permission-slip.doctor/1`` report."""
    environ: Mapping[str, str] = os.environ if env is None else env
    plat = sys_platform(platform)

    checks = _Checks()
    checks.add("permission_slip.version", PASS, __version__)
    checks.add(
        "platform",
        PASS,
        f"{system_label(environ_system(environ, platform))} {machine_label(environ_machine(environ))}",
    )

    gate_bin: Path | None = None
    engine_bin: Path | None = None
    discovery_source = ""
    engine_source = ""
    locate_error: TethersUnavailable | None = None
    try:
        gate_bin, engine_bin, discovery_source, engine_source = locate_tethers(
            environ, plat
        )
    except TethersUnavailable as exc:
        locate_error = exc

    install_root: Path | None = None
    product_version: str | None = None
    gate_sha: str | None = None
    engine_sha: str | None = None
    provenance = "unknown"
    verification = "unknown"
    dev_active = dev_override_active(environ)
    manifest: Path | None = None
    protocol_result: dict[str, Any] | None = None

    if locate_error is None:
        assert gate_bin is not None and engine_bin is not None
        install_root = (
            gate_bin.parent.parent
            if gate_bin.parent.name == "bin"
            else gate_bin.parent
        )
        if not install_root.is_dir():
            install_root = gate_bin.parent

        checks.add("tethers.executable", PASS, f"{gate_bin} ({discovery_source})")
        checks.add("tethers.engine", PASS, f"{engine_bin} ({engine_source})")
        checks.add(
            "tethers.discovery",
            PASS,
            f"gate from {discovery_source}, engine from {engine_source}",
            remediation=(
                f"Development-only source checkout selected with {DEV_CHECKOUT_ENV}."
                if discovery_source == "dev_source_checkout"
                else None
            ),
        )

        try:
            gate_sha = sha256_file(gate_bin)
            engine_sha = sha256_file(engine_bin)
        except OSError as exc:
            checks.add("tethers.hashes", FAIL, f"cannot hash installation: {exc}")
        else:
            checks.add(
                "tethers.hashes",
                PASS,
                f"gate sha256={gate_sha} engine sha256={engine_sha}",
            )

        manifest = find_release_manifest(gate_bin)
        try:
            provenance, verification, dev_active, _notes = verify_release_provenance(
                gate_bin, engine_bin, environ
            )
        except TethersUnavailable as exc:
            provenance = "mismatch"
            verification = "unverified"
            checks.add(
                "tethers.provenance",
                FAIL,
                str(exc),
                remediation=(
                    f"Reinstall the released Tethers bundle, or accept the mismatch "
                    f"visibly for development with {DEV_UNVERIFIED_ENV}=1."
                ),
            )
        else:
            if verification == "verified":
                checks.add(
                    "tethers.provenance",
                    PASS,
                    f"release manifest {manifest.name if manifest else ''} matches both binaries",
                )
            elif verification == "dev_override":
                checks.add(
                    "tethers.provenance",
                    UNAVAILABLE,
                    "development-only override active; installation is unverified/dev"
                    + (
                        " ("
                        + ", ".join(dev_override_names(environ))
                        + ")"
                        if dev_override_names(environ)
                        else ""
                    ),
                    remediation=f"Unset {DEV_UNVERIFIED_ENV} to verify the product normally.",
                )
            else:
                checks.add(
                    "tethers.provenance",
                    UNAVAILABLE,
                    "no release manifest beside the installation; package provenance "
                    "cannot be verified",
                    remediation="Install the released Tethers bundle (ships SHA256SUMS).",
                )

        describe = describe_product(gate_bin)
        describe_schema: str | None = None
        if isinstance(describe, dict):
            raw_schema = describe.get("schema")
            describe_schema = str(raw_schema) if raw_schema else None
            raw = describe.get("version")
            if isinstance(raw, (str, int, float)) and str(raw):
                product_version = str(raw)
        if product_version:
            detail = f"Tethers {product_version}"
            if describe_schema:
                detail += f" (describe schema {describe_schema})"
            checks.add("tethers.identity", PASS, detail)
        else:
            checks.add(
                "tethers.identity",
                UNAVAILABLE,
                "product identity unavailable from 'tethers describe --json'",
                remediation="Upgrade to a Tethers release that implements describe --json.",
            )

        if probe_protocol:
            try:
                protocol_result = _probe_protocol(
                    _installation_from(
                        gate_bin, engine_bin, product_version, provenance, verification,
                        discovery_source, engine_source, install_root, manifest, dev_active,
                    )
                )
            except TethersProtocolMismatch as exc:
                checks.add(
                    "authority.protocol",
                    UNSUPPORTED,
                    str(exc),
                    remediation="Install a Tethers release that speaks tethers.authority/1.",
                )
            except TethersUnavailable as exc:
                checks.add(
                    "authority.protocol",
                    FAIL,
                    f"authority protocol startup failed: {exc}",
                    remediation="Run 'tethers doctor' from the installed Tethers bundle.",
                )
            else:
                checks.add(
                    "authority.protocol",
                    PASS,
                    f"{protocol_result.get('protocol')} "
                    f"(product {protocol_result.get('product_version', 'unknown')})",
                )
        else:
            checks.add("authority.protocol", UNAVAILABLE, "protocol probe disabled")
    else:
        code = locate_error.code
        message = str(locate_error)
        if code == "engine_missing":
            checks.add("tethers.executable", PASS, f"{gate_bin} ({discovery_source})")
            checks.add(
                "tethers.engine",
                FAIL,
                "Tethers engine missing from installed bundle.",
                remediation=f"Set {ENGINE_ENV} to the engine shipped with the Gate.",
            )
        else:
            checks.add(
                "tethers.executable",
                FAIL,
                message,
                remediation=(
                    "Install a released Tethers bundle so 'tethers' is on PATH, or "
                    f"set {GATE_ENV}."
                ),
            )
            checks.add(
                "tethers.engine",
                UNAVAILABLE,
                f"not checked ({message})",
            )
        checks.add("tethers.discovery", UNAVAILABLE, f"not checked ({message})")
        checks.add("tethers.hashes", UNAVAILABLE, f"not checked ({message})")
        checks.add("tethers.provenance", UNAVAILABLE, f"not checked ({message})")
        checks.add("tethers.identity", UNAVAILABLE, f"not checked ({message})")
        checks.add("authority.protocol", UNAVAILABLE, f"not checked ({message})")

    # -- Permission Slip state --------------------------------------------
    root = state_root or permission_slip_state_root(
        environ, platform=plat, home=home
    )
    host_root = root / TETHERS_HOST_STATE_DIR
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".permission-slip-doctor-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        checks.add(
            "state.root",
            FAIL,
            f"state root {root} is not writable: {exc}",
            remediation=f"Set {STATE_DIR_ENV} to a writable directory.",
        )
        state_writable = False
    else:
        checks.add("state.root", PASS, str(root))
        state_writable = True

    if not state_writable:
        checks.add(
            "tethers.host_data",
            UNAVAILABLE,
            "not checked (state root unusable)",
        )
        checks.add(
            "provisioning.ready",
            UNAVAILABLE,
            "not checked (state root unusable)",
        )
        host_exists = False
        provisioned = False
    else:
        host_exists = host_root.exists()
        if host_exists:
            checks.add("tethers.host_data", PASS, str(host_root))
        else:
            checks.add(
                "tethers.host_data",
                UNAVAILABLE,
                f"Tethers host-data root {host_root} does not exist yet.",
                remediation=_SETUP_REMEDIATION,
            )
        provisioned = host_data_provisioned(host_root)
        if provisioned:
            checks.add(
                "provisioning.ready",
                PASS,
                f"replay store provisioned at {host_root}",
            )
        else:
            checks.add(
                "provisioning.ready",
                UNAVAILABLE,
                "replay store is not provisioned for this host-data root.",
                remediation=_SETUP_REMEDIATION,
            )

    overall = checks.overall
    report: dict[str, Any] = {
        "schema": DOCTOR_SCHEMA,
        "permission_slip_version": __version__,
        "platform": {
            "system": system_label(environ_system(environ, platform)),
            "machine": machine_label(environ_machine(environ)),
            "raw": plat,
        },
        "tethers": {
            "authority_protocol": AUTHORITY_PROTOCOL,
            "gate_bin": str(gate_bin) if gate_bin else None,
            "engine_bin": str(engine_bin) if engine_bin else None,
            "install_root": str(install_root) if install_root else None,
            "discovery_source": discovery_source or None,
            "engine_source": engine_source or None,
            "product_version": product_version,
            "gate_sha256": gate_sha,
            "engine_sha256": engine_sha,
            "release_manifest": str(manifest) if manifest else None,
            "provenance": provenance,
            "verification": verification,
            "dev_override": dev_active,
            "dev_override_variables": list(dev_override_names(environ)),
            "is_dev_checkout": discovery_source == "dev_source_checkout",
        },
        "state": {
            "root": str(root),
            "writable": state_writable,
            "tethers_host_data_root": str(host_root),
            "host_data_exists": host_exists,
            "provisioned": provisioned,
        },
        "protocol": (
            {
                "protocol": protocol_result.get("protocol"),
                "protocol_versions": protocol_result.get("protocol_versions"),
                "product_version": protocol_result.get("product_version"),
                "provider_invocations": protocol_result.get("provider_invocations"),
            }
            if protocol_result
            else None
        ),
        "checks": checks.ordered,
        "overall": {
            "status": overall,
            "summary": _summary_for(overall),
            "counts": checks.statuses,
        },
    }
    return report


def _summary_for(status: str) -> str:
    if status == PASS:
        return "ready"
    if status == UNSUPPORTED:
        return "unsupported authority protocol"
    if status == UNAVAILABLE:
        return "not ready"
    return "not ready"


def _installation_from(
    gate_bin: Path,
    engine_bin: Path,
    product_version: str | None,
    provenance: str,
    verification: str,
    discovery_source: str,
    engine_source: str,
    install_root: Path | None,
    manifest: Path | None,
    dev_active: bool,
) -> TethersInstallation:
    return TethersInstallation(
        gate_bin=gate_bin,
        engine_bin=engine_bin,
        install_root=install_root,
        product_version=product_version,
        authority_protocol=AUTHORITY_PROTOCOL,
        gate_sha256=sha256_file(gate_bin),
        engine_sha256=sha256_file(engine_bin),
        provenance=provenance,
        verification=verification,
        discovery_source=discovery_source,
        engine_source=engine_source,
        platform=f"{system_label()} {machine_label()}",
        release_manifest=manifest,
        dev_override_active=dev_active,
        describe=None,
    )


def render_human(report: dict[str, Any]) -> str:
    overall = report["overall"]["status"]
    if overall == PASS:
        tethers = report["tethers"]
        version = tethers.get("product_version") or "unknown"
        return "\n".join(
            [
                f"Permission Slip {__version__.rsplit('.', 1)[0]}",
                f"Tethers: {version}",
                f"Protocol: {tethers['authority_protocol']}",
                f"Platform: {report['platform']['system']} {report['platform']['machine']}",
                "State: ready",
            ]
        )

    # Failures first; readiness gaps only when nothing is outright wrong.
    blocking = [
        check
        for check in report["checks"]
        if check["status"] in (FAIL, UNSUPPORTED)
    ]
    if not blocking:
        blocking = [check for check in report["checks"] if check["status"] == UNAVAILABLE]

    lines = ["NOT READY"]
    seen: set[str] = set()
    for check in blocking:
        if check["detail"] in seen:
            continue
        seen.add(check["detail"])
        lines.append(f"{check['status']}: {check['detail']}")
        remediation = check.get("remediation")
        if remediation:
            lines.append(f"  -> {remediation}")
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


# -- helpers that keep platform inputs injectable ---------------------------


def sys_platform(platform: str | None) -> str:
    return sys.platform if platform is None else platform


def environ_system(environ: Mapping[str, str], platform: str | None) -> str:
    override = environ.get("PERMISSION_SLIP_DOCTOR_SYSTEM")
    if override:
        return override
    if platform is None:
        return platform_module.system()
    if platform == "win32":
        return "Windows"
    if platform == "darwin":
        return "Darwin"
    return "Linux"


def environ_machine(environ: Mapping[str, str]) -> str | None:
    override = environ.get("PERMISSION_SLIP_DOCTOR_MACHINE")
    return override
