"""Consume Tethers as an installed product, not as a source checkout.

Permission Slip depends on two things only:

* the ``tethers`` executable (the Gate host) plus its matching Core engine;
* the documented ``tethers.authority/1`` process protocol.

Everything else -- where the files came from, what they hash to, which
product version they report -- is *product identity and provenance*, which this
module gathers from Tethers' own machine-readable surfaces:

* ``tethers describe --json``   (product-owned discovery surface)
* ``tethers --version``          (fallback identity)
* a release ``SHA256SUMS`` manifest beside the bundle, when present
* the ``tethers.authority/1`` ``hello`` performed by :mod:`permission_slip.tethers_client`

There is deliberately no source-lineage check: a released product must not
need its source ``.git`` directory beside it. Development-only source-checkout
discovery exists only behind an explicitly named environment variable and is
never a production route.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as platform_module
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

AUTHORITY_PROTOCOL = "tethers.authority/1"

# -- explicit configuration -------------------------------------------------

GATE_ENV = "TETHERS_GATE_BIN"
ENGINE_ENV = "TETHERS_ENGINE_BIN"
BUNDLE_ROOT_ENV = "TETHERS_ROOT"
DEV_CHECKOUT_ENV = "PERMISSION_SLIP_DEV_TETHERS_CHECKOUT"

#: Development-only escape hatch. Both names are explicitly development
#: tooling: neither counts as successful product verification, and ``doctor``
#: reports the installation as unverified/dev whenever either is active.
DEV_UNVERIFIED_ENV = "PERMISSION_SLIP_DEV_TETHERS_UNVERIFIED"
LEGACY_DEV_UNVERIFIED_ENV = "TETHERS_ALLOW_SHA_MISMATCH"

RELEASE_MANIFEST_NAMES = ("SHA256SUMS",)
MANIFEST_SEARCH_LIMIT = 4
PROBE_TIMEOUT_SECONDS = 20.0

# Candidate file names. The engine is *not* assumed to be the v0.1 source-build
# name: a released bundle ships ``tethers-engine`` next to ``tethers``.
_GATE_STEMS = ("tethers",)
_ENGINE_STEMS = ("tethers-engine", "tethers_mcp_main")


class TethersUnavailable(RuntimeError):
    """The Tethers Gate or engine could not be located, verified or started.

    ``code`` lets ``doctor`` map the failure onto the right individual check
    instead of collapsing everything into one opaque error.
    """

    def __init__(self, message: str, *, code: str = "unavailable"):
        super().__init__(message)
        self.code = code


class TethersProtocolMismatch(TethersUnavailable):
    """The process speaks a protocol identity other than ``tethers.authority/1``."""

    def __init__(self, message: str):
        super().__init__(message, code="protocol_mismatch")


class TethersUnverified(TethersUnavailable):
    """The installation is not acceptable as Permission Slip's semantic authority.

    Raised *before* the Gate process is launched. Diagnostic trust and
    execution trust are the same trust model: an installation ``doctor`` would
    not call ready must never be started as the authority engine.
    """

    def __init__(self, message: str, *, code: str = "unverified_installation"):
        super().__init__(message, code=code)


#: The only verification state acceptable for production authority use.
ACCEPTED_AUTHORITY_VERIFICATION = "verified"
#: The only provenance form acceptable for production authority use.
ACCEPTED_AUTHORITY_PROVENANCE = "release_manifest"

#: Tethers product versions that production authority accepts. Deliberately an
#: explicit list, not a semver range: adopting another Tethers release is a
#: deliberate act recorded here, so an unknown future version fails closed
#: instead of being guessed compatible. Protocol compatibility is never
#: inferred from a product version -- ``tethers.authority/1`` is checked
#: separately at the ``hello``.
SUPPORTED_AUTHORITY_PRODUCT_VERSIONS: tuple[str, ...] = ("0.8.1",)


def supported_product_versions_text() -> str:
    return ", ".join(SUPPORTED_AUTHORITY_PRODUCT_VERSIONS)


def product_version_refusal(product_version: str | None) -> str | None:
    """The product-version half of the authority decision.

    Pure and stateless: it is called *by*
    :func:`validate_authority_installation`, never in place of it, so ``doctor``
    and execution can only ever differ in wording, never in verdict.
    """
    if not product_version:
        return (
            "product version is missing or unknown; production authority "
            "requires an accepted Tethers product version"
        )
    if product_version in SUPPORTED_AUTHORITY_PRODUCT_VERSIONS:
        return None
    return (
        f"product version {product_version} is not supported for production "
        f"authority (Permission Slip supports {supported_product_versions_text()})"
    )


def _executable_names(stem: str, plat: str) -> tuple[str, ...]:
    if plat == "win32":
        # ``.exe`` is the released form; ``.cmd``/``.bat`` are ordinary
        # Windows PATH shims and are executable by the same process boundary.
        return (f"{stem}.exe", f"{stem}.cmd", f"{stem}.bat", stem)
    return (stem, f"{stem}.exe")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    argv: Sequence[str],
    *,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    cwd: str | os.PathLike[str] | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        cwd=str(cwd) if cwd is not None else None,
    )


# -- installation model -----------------------------------------------------


@dataclass(frozen=True)
class TethersInstallation:
    """A verified, paired Tethers runtime that Permission Slip can consume."""

    gate_bin: Path
    engine_bin: Path
    install_root: Path | None
    product_version: str | None
    authority_protocol: str
    gate_sha256: str
    engine_sha256: str
    #: Release-manifest status: ``release_manifest`` | ``absent`` |
    #: ``mismatch`` | ``dev_override``.
    provenance: str
    #: Overall verification: ``verified`` | ``unverified`` | ``dev_override``.
    verification: str
    discovery_source: str
    engine_source: str
    platform: str
    release_manifest: Path | None
    dev_override_active: bool
    describe: dict[str, Any] | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def protocol(self) -> str:
        return self.authority_protocol

    @property
    def is_dev(self) -> bool:
        return self.dev_override_active or self.discovery_source == "dev_source_checkout"

    @property
    def acceptable_for_authority(self) -> bool:
        """May this installation act as Permission Slip's semantic authority?"""
        return validate_authority_installation(self) is None

    @property
    def describe_version(self) -> str | None:
        if not isinstance(self.describe, dict):
            return None
        value = self.describe.get("version")
        return str(value) if isinstance(value, (str, int, float)) else None


def validate_authority_installation(installation: TethersInstallation) -> str | None:
    """The single answer to: may this installation be Permission Slip's authority?

    Returns ``None`` when it may, otherwise the refusal reason. ``GateSession``,
    ``PermissionSlip`` and ``doctor`` all consult this one predicate, so a
    diagnostic verdict and an execution verdict can never disagree.

    The development override permits discovery and diagnosis. It never
    manufactures product trust: nothing here reads the environment, so an
    environment variable can upgrade *what is found*, but only this predicate
    decides *what may act as authority*.

    Production authority additionally requires an accepted product version
    (``SUPPORTED_AUTHORITY_PRODUCT_VERSIONS``). A genuinely verified but
    unsupported Tethers release is refused here -- this is a product-support
    decision, not a corruption report, and it is checked in exactly one place.
    """
    problems: list[str] = []

    verification = installation.verification
    if verification == ACCEPTED_AUTHORITY_VERIFICATION:
        pass
    elif verification == "dev_override":
        problems.append(
            "development-only override active: installation is unverified/dev"
        )
    else:
        problems.append(f"product verification is {verification!r}")

    version_problem = product_version_refusal(installation.product_version)
    if version_problem is not None:
        problems.append(version_problem)

    provenance = installation.provenance
    if provenance == ACCEPTED_AUTHORITY_PROVENANCE:
        pass
    elif provenance == "dev_override":
        pass  # already reported through the verification state
    elif provenance == "absent":
        problems.append("no release manifest provenance")
    elif provenance == "mismatch":
        problems.append("release manifest provenance mismatch")
    else:
        problems.append(f"provenance is {provenance!r}")

    if installation.discovery_source == "dev_source_checkout":
        problems.append("discovered as a development source checkout")
    if installation.dev_override_active and verification != "dev_override":
        problems.append("development override flag is set on the installation")

    if not problems:
        return None
    return "; ".join(problems)


def dev_override_active(env: Mapping[str, str]) -> bool:
    for name in (DEV_UNVERIFIED_ENV, LEGACY_DEV_UNVERIFIED_ENV):
        if env.get(name, "") == "1":
            return True
    return False


def dev_override_names(env: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        name
        for name in (DEV_UNVERIFIED_ENV, LEGACY_DEV_UNVERIFIED_ENV)
        if env.get(name, "") == "1"
    )


# -- release manifest -------------------------------------------------------


def find_release_manifest(gate_bin: Path) -> Path | None:
    """Locate the release ``SHA256SUMS`` shipped with the bundle, if any."""
    directory = gate_bin.parent
    for _ in range(MANIFEST_SEARCH_LIMIT):
        for name in RELEASE_MANIFEST_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        if directory.parent == directory:
            break
        directory = directory.parent
    return None


def read_release_manifest(path: Path) -> dict[str, str]:
    """Parse a ``SHA256SUMS`` file into ``{posix relative path: hex digest}``."""
    entries: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[-1]
        if name.startswith("*"):
            name = name[1:]
        if len(digest) != 64 or not all(ch in "0123456789abcdefABCDEF" for ch in digest):
            continue
        entries[name.replace("\\", "/").lstrip("./")] = digest.lower()
    return entries


def _manifest_digest_for(entries: dict[str, str], manifest_dir: Path, target: Path) -> str | None:
    try:
        relative = target.resolve().relative_to(manifest_dir.resolve())
    except ValueError:
        return None
    return entries.get(relative.as_posix())


# -- product identity surfaces ---------------------------------------------


def describe_product(
    gate_bin: Path, *, timeout: float = PROBE_TIMEOUT_SECONDS
) -> dict[str, Any] | None:
    """Run Tethers' own machine-readable discovery surface.

    Returns the ``data`` object of a successful ``tethers describe --json``,
    or ``None`` when the surface is unavailable or malformed. A failure here is
    a reporting gap, not a hard error: the authority ``hello`` remains the
    contract that matters.
    """
    try:
        completed = _run([str(gate_bin), "describe", "--json"], timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    payload = _first_json_object(completed.stdout)
    if payload is None:
        return None
    if payload.get("schema") != "tethers.cli/1" or payload.get("status") != "ok":
        return None
    data = payload.get("data")
    return data if isinstance(data, dict) else None


def product_version_from_cli(
    gate_bin: Path, *, timeout: float = PROBE_TIMEOUT_SECONDS
) -> str | None:
    """Fallback identity from ``tethers --version`` (``tethers 0.8.0``)."""
    try:
        completed = _run([str(gate_bin), "--version"], timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().split()
    if len(text) >= 2 and text[0].lower().startswith("tethers"):
        return text[1]
    return None


def _first_json_object(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


# -- discovery --------------------------------------------------------------


def _require_file(path: Path, *, env_name: str) -> Path:
    if not path.is_file():
        raise TethersUnavailable(
            f"{env_name} does not point to a file: {path}", code="unreadable"
        )
    if os.name == "posix" and not os.access(path, os.X_OK):
        raise TethersUnavailable(
            f"{env_name} is not executable: {path}", code="unreadable"
        )
    return path.resolve()


def _search_dirs(directories: Sequence[Path], stems: Sequence[str], plat: str) -> Path | None:
    for directory in directories:
        for stem in stems:
            for name in _executable_names(stem, plat):
                candidate = directory / name
                if candidate.is_file():
                    return candidate
    return None


def _known_install_roots(env: Mapping[str, str], plat: str) -> list[Path]:
    """Best-effort locations of an installed Tethers product.

    These are conventions, not a package manager: PATH is the primary route.
    Entries that have not been observed on a released platform are omitted
    rather than guessed at, so an unrecognised layout fails closed instead of
    silently matching something unrelated.
    """
    roots: list[Path] = []
    if plat == "win32":
        local_app_data = env.get("LOCALAPPDATA")
        if local_app_data:
            roots.append(Path(local_app_data) / "Programs" / "Tethers")
        program_files = env.get("ProgramFiles")
        if program_files:
            roots.append(Path(program_files) / "Tethers")
    elif plat == "darwin":
        roots.append(Path("/Applications/Tethers.app/Contents/MacOS"))
        home = _home_for(env)
        roots.append(home / "Applications" / "Tethers.app" / "Contents" / "MacOS")
    return roots


def _home_for(env: Mapping[str, str]) -> Path:
    override = env.get("HOME") or env.get("USERPROFILE")
    if override:
        return Path(override)
    return Path.home()


def _expand_install_root(root: Path, stems: Sequence[str], plat: str) -> list[Path]:
    """Candidate directories inside an install root, newest version first."""
    if not root.is_dir():
        return []
    direct = [root / "bin", root]
    try:
        children = sorted(
            (child for child in root.iterdir() if child.is_dir()),
            key=lambda child: child.name,
            reverse=True,
        )
    except OSError:
        children = []
    for child in children:
        direct.append(child / "bin")
        direct.append(child)
    for directory in direct:
        if _search_dirs([directory], stems, plat) is not None:
            return [directory]
    return []


def _dev_checkout_gate_and_engine(root: Path, plat: str) -> tuple[Path, Path] | None:
    """Development-only source-tree layout (v0.1 contributor builds)."""
    host_targets = (
        root / "tethers-0.1" / "host-rust" / "target" / "release",
        root / "tethers-0.1" / "host-rust" / "target" / "debug",
    )
    engine_dirs = (
        root / "tethers-0.1" / "engine-ocaml" / "_build" / "default" / "bin",
    )
    gate = _search_dirs(host_targets, _GATE_STEMS, plat)
    engine = _search_dirs(engine_dirs, _ENGINE_STEMS, plat)
    if gate is None or engine is None:
        return None
    return gate, engine


def _sibling_engine_dirs(gate_bin: Path) -> list[Path]:
    """Directories beside the Gate where a matching engine is shipped.

    The released bundle keeps both executables in the same ``bin`` directory;
    the two extra entries are conventional Unix bundle layouts.
    """
    directory = gate_bin.parent
    return [directory, directory.parent / "libexec", directory.parent / "lib"]


def discover_tethers(
    *,
    probe: bool = True,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> TethersInstallation:
    """Locate and verify a Tethers product installation.

    Discovery order:

    1. explicit configured executable paths (``TETHERS_GATE_BIN`` /
       ``TETHERS_ENGINE_BIN``, or a bundle root in ``TETHERS_ROOT``);
    2. an installed product on ``PATH`` or in a known install location;
    3. the engine as a sibling file of the discovered Gate executable.

    Development-only source-tree discovery sits behind
    ``PERMISSION_SLIP_DEV_TETHERS_CHECKOUT`` and is never the normal route.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    plat = sys.platform if platform is None else platform
    notes: list[str] = []

    gate_bin, engine_bin, discovery_source, engine_source = locate_tethers(environ, plat)

    install_root = gate_bin.parent.parent if gate_bin.parent.name == "bin" else gate_bin.parent
    if not install_root.is_dir():
        install_root = gate_bin.parent

    release_manifest = find_release_manifest(gate_bin)
    provenance, verification, dev_active, verify_notes = verify_release_provenance(
        gate_bin, engine_bin, environ
    )
    notes.extend(verify_notes)

    describe = describe_product(gate_bin, timeout=timeout) if probe else None
    product_version = None
    if describe is not None:
        raw = describe.get("version")
        if isinstance(raw, (str, int, float)) and str(raw):
            product_version = str(raw)
        supported = describe.get("supported_protocol_versions")
        if isinstance(supported, list) and supported:
            notes.append(
                "tethers describe reports supported_protocol_versions="
                + json.dumps(supported)
            )
    if product_version is None:
        product_version = product_version_from_cli(gate_bin, timeout=timeout)
        if product_version:
            notes.append("product identity taken from 'tethers --version'")

    if discovery_source == "dev_source_checkout":
        notes.append(
            f"development source checkout ({DEV_CHECKOUT_ENV}); not a released product"
        )
    if dev_active:
        notes.append(
            "development-only unverified-tether override active: "
            + ", ".join(dev_override_names(environ))
        )

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
        platform=_platform_label(plat),
        release_manifest=release_manifest,
        dev_override_active=dev_active,
        describe=describe,
        notes=tuple(notes),
    )


def locate_tethers(
    env: Mapping[str, str] | None = None, platform: str | None = None
) -> tuple[Path, Path, str, str]:
    """Locate the Gate and its engine without verifying them.

    Returns ``(gate_bin, engine_bin, discovery_source, engine_source)``.
    ``doctor`` uses this so it can report *which* part of the installation is
    wrong rather than collapsing a bad engine and a missing Gate into one
    error.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    plat = sys.platform if platform is None else platform

    dev_root = environ.get(DEV_CHECKOUT_ENV)

    gate_env = environ.get(GATE_ENV)
    engine_env = environ.get(ENGINE_ENV)

    if gate_env:
        gate_bin = _require_file(Path(gate_env).expanduser(), env_name=GATE_ENV)
        discovery_source = "explicit_config"
    else:
        gate_bin = None
        discovery_source = ""

    if gate_bin is None:
        bundle_root = environ.get(BUNDLE_ROOT_ENV)
        if bundle_root:
            root = Path(bundle_root).expanduser()
            found = _search_dirs([root / "bin", root], _GATE_STEMS, plat)
            if found is None:
                raise TethersUnavailable(
                    f"{BUNDLE_ROOT_ENV}={root} does not contain a Tethers "
                    f"executable (looked for {' / '.join(_executable_names('tethers', plat))} "
                    f"in <root>/bin and <root>). Source checkouts must be named "
                    f"explicitly with {DEV_CHECKOUT_ENV}.",
                    code="gate_missing",
                )
            gate_bin = found.resolve()
            discovery_source = "explicit_config"

    if gate_bin is None and dev_root:
        pair = _dev_checkout_gate_and_engine(Path(dev_root).expanduser(), plat)
        if pair is None:
            raise TethersUnavailable(
                f"{DEV_CHECKOUT_ENV}={dev_root} has no built Gate and engine.",
                code="gate_missing",
            )
        gate_bin, dev_engine = pair[0].resolve(), pair[1].resolve()
        discovery_source = "dev_source_checkout"
        if engine_env:
            dev_engine = _require_file(
                Path(engine_env).expanduser(), env_name=ENGINE_ENV
            )
        return gate_bin, dev_engine, discovery_source, "dev_source_checkout"

    if gate_bin is None:
        # Explicit PATH from the supplied environment, so discovery is
        # testable and never silently reads a different process environment.
        search_path = environ.get("PATH")
        for stem in _GATE_STEMS:
            found = shutil.which(stem, path=search_path)
            if found:
                gate_bin = Path(found).resolve()
                discovery_source = "path"
                break

    if gate_bin is None:
        for root in _known_install_roots(environ, plat):
            directories = _expand_install_root(root, _GATE_STEMS, plat)
            found = _search_dirs(directories, _GATE_STEMS, plat)
            if found is not None:
                gate_bin = found.resolve()
                discovery_source = "install_root"
                break

    if gate_bin is None:
        raise TethersUnavailable(
            "Tethers executable not found. Install a released Tethers bundle "
            f"and ensure 'tethers' is on PATH, or set {GATE_ENV}.",
            code="gate_missing",
        )

    if engine_env:
        engine_bin = _require_file(Path(engine_env).expanduser(), env_name=ENGINE_ENV)
        return gate_bin, engine_bin, discovery_source, "explicit_config"

    engine_bin = _search_dirs(_sibling_engine_dirs(gate_bin), _ENGINE_STEMS, plat)
    if engine_bin is None:
        raise TethersUnavailable(
            f"Tethers engine not found next to {gate_bin}. A released bundle "
            "ships the Gate and its matching engine together; set "
            f"{ENGINE_ENV} to point at the matching engine explicitly.",
            code="engine_missing",
        )
    return gate_bin, engine_bin.resolve(), discovery_source, "bundle_sibling"


def verify_release_provenance(
    gate_bin: Path,
    engine_bin: Path,
    env: Mapping[str, str],
) -> tuple[str, str, bool, list[str]]:
    """Apply the product verification hierarchy.

    ``released product identity`` + ``package provenance where available`` +
    ``executable hashes`` + ``protocol compatibility`` (the protocol half is
    performed by the Gate client at startup).

    Returns ``(provenance, verification, dev_override_active, notes)``. A
    manifest that exists but does not match raises rather than passing: that
    is a tamper/pairing failure, not a reporting gap. Absence of a manifest is
    a reporting gap (``unverified``), never a silent pass.
    """
    notes: list[str] = []
    dev_active = dev_override_active(env)
    release_manifest = find_release_manifest(gate_bin)

    if release_manifest is None:
        if dev_active:
            return "dev_override", "dev_override", True, notes
        notes.append(
            "no release SHA256SUMS manifest found beside the installation; "
            "binary hashes are recorded but package provenance cannot be verified"
        )
        return "absent", "unverified", False, notes

    entries = read_release_manifest(release_manifest)
    problems: list[str] = []
    for label, target in (("gate", gate_bin), ("engine", engine_bin)):
        expected = _manifest_digest_for(entries, release_manifest.parent, target)
        if expected is None:
            problems.append(f"{label} is not listed in {release_manifest.name}")
            continue
        actual = sha256_file(target)
        if actual != expected:
            problems.append(
                f"{label} sha256 {actual} does not match release manifest "
                f"{expected} for {target.name}"
            )

    if not problems:
        notes.append(
            f"release manifest {release_manifest.name} matches both binaries"
        )
        return "release_manifest", "verified", False, notes

    if dev_active:
        notes.append(
            "release manifest mismatch suppressed by development-only override: "
            + "; ".join(problems)
        )
        return "dev_override", "dev_override", True, notes

    raise TethersUnavailable(
        "Tethers release manifest verification failed: " + "; ".join(problems),
        code="manifest_mismatch",
    )


def _platform_label(plat: str | None = None) -> str:
    plat = plat or sys.platform
    if plat == "win32":
        system = "Windows"
    elif plat == "darwin":
        system = "macOS"
    else:
        system = "Linux"
    return f"{system} {_machine_label()}"


def _machine_label() -> str:
    machine = platform_module.machine()
    lowered = machine.lower()
    if lowered in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if lowered in ("arm64", "aarch64"):
        return "arm64"
    if lowered in ("x86", "i386", "i686"):
        return "x86"
    return lowered or "unknown"


def machine_label(machine: str | None = None) -> str:
    """Public so ``doctor`` can render a stable platform string in tests."""
    if machine is None:
        return _machine_label()
    lowered = machine.lower()
    if lowered in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if lowered in ("arm64", "aarch64"):
        return "arm64"
    if lowered in ("x86", "i386", "i686"):
        return "x86"
    return lowered or "unknown"


def system_label(system: str | None = None) -> str:
    value = (system or platform_module.system()).lower()
    if value.startswith("win"):
        return "Windows"
    if value in ("darwin", "mac"):
        return "macOS"
    return "Linux"


# -- provisioning -----------------------------------------------------------


def host_data_provisioned(root: str | os.PathLike[str]) -> bool:
    """True when ``tethers provision-replay`` has initialised this root."""
    replay_format = Path(root) / "replay" / "v1" / "FORMAT.json"
    return replay_format.is_file()


def provision_host_data_root(
    installation: TethersInstallation,
    root: str | os.PathLike[str],
    *,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Run Tethers' own ``provision-replay`` against an absolute root.

    This is deliberately a separate, explicitly invoked operation. Permission
    Slip never provisions durable authority state as a side effect of an
    ordinary authority request, and it does not reimplement Tethers'
    provisioning logic.
    """
    target = Path(root)
    try:
        resolved = target.expanduser().resolve()
    except OSError as exc:  # pragma: no cover - platform specific
        raise TethersUnavailable(
            f"host-data root {target} cannot be resolved: {exc}", code="state_unavailable"
        ) from exc

    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TethersUnavailable(
            f"host-data root {resolved} cannot be created: {exc}",
            code="state_unwritable",
        ) from exc

    try:
        completed = _run(
            [str(installation.gate_bin), "provision-replay", str(resolved)],
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TethersUnavailable(
            f"tethers provision-replay could not be run: {exc}",
            code="provisioning_unavailable",
        ) from exc

    if completed.returncode != 0 or not host_data_provisioned(resolved):
        detail = (completed.stdout or completed.stderr or "").strip()
        payload = _first_json_object(completed.stdout)
        if payload is None:
            payload = _first_json_object(completed.stderr)
        if payload is not None:
            error = payload.get("error") or {}
            detail = f"{error.get('code', 'PROVISION_FAILED')}: {error.get('message', '')}"
        raise TethersUnavailable(
            f"tethers provision-replay failed for {resolved}: {detail or 'no output'}",
            code="provisioning_failed",
        )

    return {
        "schema": "permission-slip.setup/1",
        "host_data_root": str(resolved),
        "provisioned": True,
        "engine": str(installation.engine_bin),
        "gate": str(installation.gate_bin),
        "product_version": installation.product_version,
    }
