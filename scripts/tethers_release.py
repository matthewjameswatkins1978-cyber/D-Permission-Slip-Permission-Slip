"""Acquire and verify the published Tethers release Permission Slip consumes.

This is **verification / setup machinery**, never normal runtime behaviour:
Permission Slip's runtime never downloads anything, and nothing in
``permission_slip/`` imports this module. CI and a human operator run it
explicitly, before ``permission-slip setup``.

What it establishes, in order and always in this order:

1. the release lock names a real target for this machine;
2. the *downloaded bytes* hash to the accepted release-lock SHA-256 **before**
   anything is extracted;
3. the ``tethers.release/1`` manifest agrees with the release lock (schema, tag,
   source commit, source tree, product version, platform, archive identity);
4. extraction refuses any archive member that would escape the destination;
5. the extracted bundle's ``SHA256SUMS`` verifies, with the single known
   0.8.1 self-referential entry recorded as the accepted release defect rather
   than silently ignored.

Everything is standard library. Checksums are bounded interim provenance:
the Tethers 0.8.1 release is not third-party signed and its macOS packages are
not notarized, so this pins *bytes*, not publisher identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as platform_module
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

RELEASE_LOCK_SCHEMA = "permission-slip.tethers-release-lock/1"
TETHERS_MANIFEST_SCHEMA = "tethers.release/1"
BUNDLE_CHECKSUM_NAME = "SHA256SUMS"

#: Environment variables that must be absent for a product proof. Any of them
#: means the run is about *development* trust, never published-product trust.
FORBIDDEN_DEV_ENV_VARS = (
    "PERMISSION_SLIP_DEV_TETHERS_CHECKOUT",
    "PERMISSION_SLIP_DEV_TETHERS_UNVERIFIED",
    "TETHERS_ALLOW_SHA_MISMATCH",
)

_RELEASE_LOCK_FIELDS = (
    "schema",
    "repository",
    "tag",
    "source_commit",
    "source_tree",
    "product_version",
    "authority_protocol",
)
_TARGET_FIELDS = (
    "target",
    "sys_platform",
    "machine",
    "release_asset",
    "release_asset_sha256",
    "manifest_asset",
    "manifest_asset_sha256",
    "tethers_release_platform",
)


class ReleaseProofError(RuntimeError):
    """A release-lock, download, manifest or extraction check failed."""

    def __init__(self, message: str, *, code: str = "release_proof_failed"):
        super().__init__(message)
        self.code = code


# -- release lock -----------------------------------------------------------


def load_release_lock(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and structurally validate the release lock."""
    lock_path = Path(path)
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseProofError(
            f"release lock not found: {lock_path}", code="lock_missing"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ReleaseProofError(
            f"release lock is not valid JSON: {lock_path}: {exc}",
            code="lock_malformed",
        ) from exc
    return validate_release_lock(lock)


def validate_release_lock(lock: Any) -> dict[str, Any]:
    if not isinstance(lock, dict):
        raise ReleaseProofError("release lock must be a JSON object", code="lock_malformed")
    if lock.get("schema") != RELEASE_LOCK_SCHEMA:
        raise ReleaseProofError(
            f"release lock schema must be {RELEASE_LOCK_SCHEMA!r}, got "
            f"{lock.get('schema')!r}",
            code="lock_schema",
        )
    missing = [field for field in _RELEASE_LOCK_FIELDS if field not in lock]
    if missing:
        raise ReleaseProofError(
            f"release lock is missing {', '.join(missing)}", code="lock_malformed"
        )
    targets = lock.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ReleaseProofError(
            "release lock must list at least one target", code="lock_malformed"
        )
    seen: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ReleaseProofError("release lock target must be an object", code="lock_malformed")
        absent = [field for field in _TARGET_FIELDS if field not in target]
        if absent:
            raise ReleaseProofError(
                f"release lock target is missing {', '.join(absent)}",
                code="lock_malformed",
            )
        key = f"{target['sys_platform']}/{target['machine']}"
        if key in seen:
            raise ReleaseProofError(
                f"release lock declares {key} twice", code="lock_malformed"
            )
        seen.add(key)
        _require_hex64(target["release_asset_sha256"], "release_asset_sha256")
        _require_hex64(target["manifest_asset_sha256"], "manifest_asset_sha256")
    return lock


def _require_hex64(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        ch not in "0123456789abcdefABCDEF" for ch in value
    ):
        raise ReleaseProofError(
            f"{label} must be a 64-character hex SHA-256, got {value!r}",
            code="lock_malformed",
        )


def machine_arch(machine: str | None = None) -> str:
    """Normalise a raw architecture name onto the release-lock vocabulary."""
    lowered = (machine or platform_module.machine()).lower()
    if lowered in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if lowered in ("arm64", "aarch64"):
        return "arm64"
    if lowered in ("x86", "i386", "i686"):
        return "x86"
    return lowered or "unknown"


def current_sys_platform(system: str | None = None) -> str:
    raw = (system or platform_module.system()).lower()
    if raw.startswith("win"):
        return "win32"
    if raw in ("darwin", "mac", "macos"):
        return "darwin"
    return "linux"


def select_target(
    lock: dict[str, Any],
    *,
    system: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    """Pick this machine's target from the lock, or fail closed.

    There is deliberately no fallback: an unlisted combination (for example
    macOS on Intel, which Permission Slip does not claim) is an error rather
    than a best guess.
    """
    sys_platform = current_sys_platform(system)
    arch = machine_arch(machine)
    for target in lock["targets"]:
        if target["sys_platform"] == sys_platform and target["machine"] == arch:
            return target
    available = ", ".join(
        f"{t['sys_platform']}/{t['machine']}" for t in lock["targets"]
    )
    raise ReleaseProofError(
        f"no release-lock target for {sys_platform}/{arch} (available: {available})",
        code="unsupported_target",
    )


def target_by_name(lock: dict[str, Any], name: str) -> dict[str, Any]:
    for target in lock["targets"]:
        if target["target"] == name:
            return target
    available = ", ".join(t["target"] for t in lock["targets"])
    raise ReleaseProofError(
        f"unknown target {name!r} (available: {available})", code="unsupported_target"
    )


def release_asset_url(lock: dict[str, Any], asset_name: str) -> str:
    return (
        f"{str(lock['repository']).rstrip('/')}/releases/download/"
        f"{lock['tag']}/{asset_name}"
    )


# -- bytes ------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, *, timeout: float = 120.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "permission-slip/0.2"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except OSError as exc:
        raise ReleaseProofError(
            f"could not download {url}: {exc}", code="download_failed"
        ) from exc


def check_archive_bytes(lock: dict[str, Any], target: dict[str, Any], data: bytes) -> str:
    """Hash the archive *before* extraction and require an exact lock match."""
    digest = sha256_bytes(data)
    expected = target["release_asset_sha256"].lower()
    if digest != expected:
        raise ReleaseProofError(
            f"{target['release_asset']} sha256 {digest} does not match the "
            f"accepted release lock {expected}; refusing to extract",
            code="archive_hash_mismatch",
        )
    return digest


def check_manifest_bytes(
    lock: dict[str, Any],
    target: dict[str, Any],
    manifest_bytes: bytes,
    archive_digest: str,
) -> dict[str, Any]:
    """Require the published ``tethers.release/1`` manifest to agree exactly."""
    manifest_digest = sha256_bytes(manifest_bytes)
    expected_manifest = target["manifest_asset_sha256"].lower()
    if manifest_digest != expected_manifest:
        raise ReleaseProofError(
            f"{target['manifest_asset']} sha256 {manifest_digest} does not match "
            f"the accepted release lock {expected_manifest}",
            code="manifest_hash_mismatch",
        )

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseProofError(
            f"{target['manifest_asset']} is not valid JSON: {exc}",
            code="manifest_malformed",
        ) from exc
    if not isinstance(manifest, dict):
        raise ReleaseProofError(
            f"{target['manifest_asset']} must be a JSON object",
            code="manifest_malformed",
        )

    expectations = (
        ("schema", TETHERS_MANIFEST_SCHEMA),
        ("tag", lock["tag"]),
        ("source_commit", lock["source_commit"]),
        ("source_tree", lock["source_tree"]),
        ("product_version", lock["product_version"]),
        ("platform", target["tethers_release_platform"]),
    )
    for field, expected in expectations:
        actual = manifest.get(field)
        if actual != expected:
            raise ReleaseProofError(
                f"{target['manifest_asset']} {field} is {actual!r}, expected "
                f"{expected!r}",
                code="manifest_identity_mismatch",
            )

    archive = manifest.get("archive")
    if not isinstance(archive, dict):
        raise ReleaseProofError(
            f"{target['manifest_asset']} has no archive identity",
            code="manifest_identity_mismatch",
        )
    if archive.get("name") != target["release_asset"]:
        raise ReleaseProofError(
            f"{target['manifest_asset']} archive name {archive.get('name')!r} does "
            f"not match {target['release_asset']!r}",
            code="manifest_identity_mismatch",
        )
    if str(archive.get("sha256", "")).lower() != target["release_asset_sha256"].lower():
        raise ReleaseProofError(
            f"{target['manifest_asset']} archive sha256 disagrees with the release lock",
            code="manifest_identity_mismatch",
        )
    if str(archive.get("sha256", "")).lower() != archive_digest:
        raise ReleaseProofError(
            f"{target['manifest_asset']} archive sha256 disagrees with the "
            f"downloaded bytes ({archive_digest})",
            code="manifest_identity_mismatch",
        )
    return manifest


# -- extraction -------------------------------------------------------------


def _unsafe_member(name: str) -> str | None:
    """Return a reason when ``name`` could escape the destination."""
    if not name or name in (".", "./"):
        return None
    normalised = name.replace("\\", "/")
    path = PurePosixPath(normalised)
    if path.is_absolute() or normalised.startswith("/"):
        return f"absolute path {name!r}"
    if len(normalised) >= 2 and normalised[1] == ":":
        return f"drive-qualified path {name!r}"
    if any(part == ".." for part in path.parts):
        return f"path traversal {name!r}"
    return None


def _tar_member_reason(member: tarfile.TarInfo) -> str | None:
    reason = _unsafe_member(member.name)
    if reason:
        return reason
    if member.issym() or member.islnk():
        reason = _unsafe_member(member.linkname)
        if reason:
            return f"link target {member.linkname!r} in {member.name!r}: {reason}"
    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return f"unsupported member type for {member.name!r}"
    return None


def safe_extract_archive(archive_path: Path, dest: Path) -> None:
    """Extract ``archive_path`` into ``dest``, refusing anything that escapes."""
    dest.mkdir(parents=True, exist_ok=True)
    if archive_path.name.endswith((".tar.gz", ".tgz", ".tar")):
        _safe_extract_tar(archive_path, dest)
    elif archive_path.name.endswith(".zip"):
        _safe_extract_zip(archive_path, dest)
    else:
        raise ReleaseProofError(
            f"unsupported archive format: {archive_path.name}",
            code="unsupported_archive",
        )


def _safe_extract_tar(archive_path: Path, dest: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            reasons = [
                reason
                for member in members
                for reason in [_tar_member_reason(member)]
                if reason is not None
            ]
            if reasons:
                raise ReleaseProofError(
                    "refusing to extract unsafe archive members: "
                    + "; ".join(sorted(set(reasons))[:5]),
                    code="unsafe_archive_member",
                )
            if hasattr(tarfile, "data_filter"):  # Python 3.12+
                archive.extractall(dest, members=members, filter="data")
            else:
                archive.extractall(dest, members=members)
    except tarfile.TarError as exc:
        raise ReleaseProofError(
            f"could not read archive {archive_path.name}: {exc}",
            code="archive_unreadable",
        ) from exc


def _safe_extract_zip(archive_path: Path, dest: Path) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            reasons = [
                reason
                for info in infos
                for reason in [_unsafe_member(info.filename)]
                if reason is not None
            ]
            if reasons:
                raise ReleaseProofError(
                    "refusing to extract unsafe archive members: "
                    + "; ".join(sorted(set(reasons))[:5]),
                    code="unsafe_archive_member",
                )
            archive.extractall(dest)
    except zipfile.BadZipFile as exc:
        raise ReleaseProofError(
            f"could not read archive {archive_path.name}: {exc}",
            code="archive_unreadable",
        ) from exc


def resolve_bundle_root(dest: Path) -> Path:
    """Find the directory that actually holds ``bin/`` and ``SHA256SUMS``."""
    if (dest / "bin").is_dir() and (dest / BUNDLE_CHECKSUM_NAME).is_file():
        return dest
    children = sorted(entry for entry in dest.iterdir() if not entry.name.startswith("."))
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest


# -- extracted bundle -------------------------------------------------------


def read_bundle_checksums(bundle_root: Path) -> dict[str, str]:
    manifest = bundle_root / BUNDLE_CHECKSUM_NAME
    if not manifest.is_file():
        raise ReleaseProofError(
            f"extracted bundle has no {BUNDLE_CHECKSUM_NAME} at {bundle_root}",
            code="bundle_checksums_missing",
        )
    entries: dict[str, str] = {}
    for raw in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[-1]
        if name.startswith("*"):
            name = name[1:]
        if len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
            continue
        entries[name.replace("\\", "/").lstrip("./")] = digest.lower()
    if not entries:
        raise ReleaseProofError(
            f"{BUNDLE_CHECKSUM_NAME} at {bundle_root} has no usable entries",
            code="bundle_checksums_malformed",
        )
    return entries


def verify_bundle_checksums(bundle_root: Path) -> dict[str, Any]:
    """Verify every extracted-file checksum.

    The known 0.8.1 defect -- one self-referential entry naming the
    ``SHA256SUMS`` file itself -- is *identified*, not swallowed: it must be
    exactly one entry and it must name the checksum file. Every other entry has
    to exist and hash correctly, and no other mismatch is tolerated.
    """
    manifest = bundle_root / BUNDLE_CHECKSUM_NAME
    entries = read_bundle_checksums(bundle_root)
    manifest_resolved = manifest.resolve()

    self_entries: list[str] = []
    verified = 0
    problems: list[str] = []
    for name, expected in sorted(entries.items()):
        reason = _unsafe_member(name)
        if reason is not None:
            problems.append(f"{BUNDLE_CHECKSUM_NAME} entry {reason}")
            continue
        target = (bundle_root / name)
        try:
            resolved = target.resolve()
        except OSError as exc:  # pragma: no cover - platform specific
            problems.append(f"{name}: cannot resolve ({exc})")
            continue
        if resolved == manifest_resolved:
            self_entries.append(name)
            continue
        if not target.is_file():
            problems.append(f"{name}: listed in {BUNDLE_CHECKSUM_NAME} but missing")
            continue
        actual = sha256_file(target)
        if actual != expected:
            problems.append(f"{name}: sha256 {actual} != {expected}")
            continue
        verified += 1

    if len(self_entries) > 1:
        problems.append(
            f"{BUNDLE_CHECKSUM_NAME} names itself {len(self_entries)} times"
        )
    if problems:
        raise ReleaseProofError(
            "extracted bundle checksum verification failed: " + "; ".join(problems[:5]),
            code="bundle_checksum_mismatch",
        )
    return {
        "entries": len(entries),
        "verified": verified,
        "known_self_reference": sorted(self_entries),
        "known_defect": (
            "tethers-0.8.1-self-referential-sha256sums" if self_entries else None
        ),
    }


# -- environment ------------------------------------------------------------


def assert_no_dev_override(env: Mapping[str, str] | None = None) -> None:
    environ = os.environ if env is None else env
    present = [name for name in FORBIDDEN_DEV_ENV_VARS if environ.get(name, "") not in ("", "0")]
    if present:
        raise ReleaseProofError(
            "development override variables are set; a published-product proof "
            "must not run with " + ", ".join(present),
            code="dev_override_present",
        )


# -- acquisition ------------------------------------------------------------


def acquire(
    lock: dict[str, Any],
    target: dict[str, Any],
    dest: str | os.PathLike[str],
    *,
    archive_path: str | os.PathLike[str] | None = None,
    manifest_path: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    fetch=download,
) -> Path:
    """Download, verify, extract and return the bundle root for ``target``."""
    assert_no_dev_override(env)

    if archive_path is None:
        archive_bytes = fetch(release_asset_url(lock, target["release_asset"]))
    else:
        archive_bytes = Path(archive_path).read_bytes()
    archive_digest = check_archive_bytes(lock, target, archive_bytes)

    if manifest_path is None:
        manifest_bytes = fetch(release_asset_url(lock, target["manifest_asset"]))
    else:
        manifest_bytes = Path(manifest_path).read_bytes()
    check_manifest_bytes(lock, target, manifest_bytes, archive_digest)

    workdir = Path(dest) / f"Tethers-{lock['product_version']}"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    staged = workdir / target["release_asset"]
    staged.write_bytes(archive_bytes)
    try:
        safe_extract_archive(staged, workdir)
    finally:
        if staged.exists():
            staged.unlink()

    bundle_root = resolve_bundle_root(workdir)
    verify_bundle_checksums(bundle_root)
    return bundle_root


# -- command line -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tethers_release.py",
        description="Acquire and verify the published Tethers release Permission Slip consumes.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    acquire_parser = subparsers.add_parser(
        "acquire", help="Download, verify, extract and print TETHERS_ROOT."
    )
    acquire_parser.add_argument("--lock", required=True, help="Path to the release lock JSON.")
    acquire_parser.add_argument("--target", help="Explicit target name; defaults to this machine.")
    acquire_parser.add_argument("--dest", help="Working directory; defaults to a temp directory.")
    acquire_parser.add_argument(
        "--archive", help="Use these already-downloaded archive bytes instead of fetching."
    )
    acquire_parser.add_argument(
        "--manifest", help="Use this already-downloaded manifest instead of fetching."
    )
    acquire_parser.add_argument(
        "--report", help="Write a machine-readable JSON report to this path."
    )
    acquire_parser.add_argument(
        "--github-env",
        help="Append TETHERS_ROOT=... to this file (used with $GITHUB_ENV).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if args.command != "acquire":  # pragma: no cover - argparse enforces this
        return 2

    try:
        lock = load_release_lock(args.lock)
        target = (
            target_by_name(lock, args.target) if args.target else select_target(lock)
        )
        # Never cleaned up here: the next step consumes TETHERS_ROOT, so the
        # extraction outlives this process by design.
        dest = args.dest or tempfile.mkdtemp(prefix="tethers-release-")
        bundle_root = acquire(
            lock,
            target,
            dest,
            archive_path=args.archive,
            manifest_path=args.manifest,
        )
    except ReleaseProofError as exc:
        sys.stderr.write(f"FAIL [{exc.code}] {exc}\n")
        return 1

    report = {
        "schema": "permission-slip.tethers-acquire/1",
        "lock_schema": lock["schema"],
        "target": target["target"],
        "tag": lock["tag"],
        "source_commit": lock["source_commit"],
        "source_tree": lock["source_tree"],
        "product_version": lock["product_version"],
        "authority_protocol": lock["authority_protocol"],
        "release_asset": target["release_asset"],
        "release_asset_sha256": target["release_asset_sha256"],
        "manifest_asset": target["manifest_asset"],
        "manifest_asset_sha256": target["manifest_asset_sha256"],
        "tethers_root": str(bundle_root),
        "dev_override_present": False,
        # Recorded so the report names the accepted 0.8.1 self-referential
        # SHA256SUMS entry rather than leaving it implicit.
        "bundle_checksums": verify_bundle_checksums(bundle_root),
    }
    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
    if args.github_env:
        with Path(args.github_env).open("a", encoding="utf-8") as handle:
            handle.write(f"TETHERS_ROOT={bundle_root}\n")
    sys.stdout.write(f"TETHERS_ROOT={bundle_root}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
