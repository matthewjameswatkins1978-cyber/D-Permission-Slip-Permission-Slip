"""Release-lock schema, platform selection and safe acquisition.

These cover the bounded provenance machinery in ``scripts/tethers_release.py``:
what the lock must say, which target a machine may claim, that a byte mismatch
fails *before* extraction, that a manifest contradicting the accepted release
identity fails, and that an archive which would escape the destination is
refused.

Nothing here touches the network: ``acquire`` is fed local bytes, exactly as a
tamper case would be.
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.tethers_release import (  # noqa: E402
    RELEASE_LOCK_SCHEMA,
    ReleaseProofError,
    acquire,
    check_archive_bytes,
    check_manifest_bytes,
    load_release_lock,
    release_asset_url,
    resolve_bundle_root,
    safe_extract_archive,
    select_target,
    sha256_bytes,
    sha256_file,
    validate_release_lock,
    verify_bundle_checksums,
)

LOCK_PATH = REPO_ROOT / "verification" / "tethers-v0.8.1.lock.json"

ACCEPTED_TAG = "v0.8.1"
ACCEPTED_COMMIT = "2710e867768f33be3e6bd1e722004c1c50e3f53b"
ACCEPTED_TREE = "ef1fe230bcf83498bd2b168a57f4570e02d3a046"


def synthetic_lock(**target_changes) -> dict:
    target = {
        "target": "linux-x86-64",
        "sys_platform": "linux",
        "machine": "x86_64",
        "release_asset": "Tethers-0.8.1-linux-x64.tar.gz",
        "release_asset_sha256": "0" * 64,
        "manifest_asset": "Tethers-0.8.1-linux-x64-manifest.json",
        "manifest_asset_sha256": "1" * 64,
        "tethers_release_platform": "linux-x64",
    }
    target.update(target_changes)
    return validate_release_lock(
        {
            "schema": RELEASE_LOCK_SCHEMA,
            "repository": "https://example.invalid/tethers-lang",
            "tag": ACCEPTED_TAG,
            "source_commit": ACCEPTED_COMMIT,
            "source_tree": ACCEPTED_TREE,
            "product_version": "0.8.1",
            "authority_protocol": "tethers.authority/1",
            "targets": [target],
        }
    )


def synthetic_manifest(**changes) -> bytes:
    manifest = {
        "schema": "tethers.release/1",
        "product_version": "0.8.1",
        "tag": ACCEPTED_TAG,
        "source_commit": ACCEPTED_COMMIT,
        "source_tree": ACCEPTED_TREE,
        "platform": "linux-x64",
        "archive": {"name": "Tethers-0.8.1-linux-x64.tar.gz", "sha256": "0" * 64},
    }
    manifest.update(changes)
    return json.dumps(manifest, indent=2).encode("utf-8")


class ReleaseLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-lock-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    # -- schema -------------------------------------------------------------

    def test_accepted_release_lock_declares_every_required_field(self):
        lock = load_release_lock(LOCK_PATH)
        self.assertEqual(lock["schema"], RELEASE_LOCK_SCHEMA)
        self.assertEqual(lock["tag"], ACCEPTED_TAG)
        self.assertEqual(lock["source_commit"], ACCEPTED_COMMIT)
        self.assertEqual(lock["source_tree"], ACCEPTED_TREE)
        self.assertEqual(lock["product_version"], "0.8.1")
        self.assertEqual(lock["authority_protocol"], "tethers.authority/1")
        self.assertEqual(len(lock["targets"]), 3)
        for target in lock["targets"]:
            self.assertRegex(target["release_asset_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(target["manifest_asset_sha256"], r"^[0-9a-f]{64}$")

    def test_accepted_release_lock_covers_exactly_the_three_official_targets(self):
        lock = load_release_lock(LOCK_PATH)
        self.assertEqual(
            {(t["sys_platform"], t["machine"]) for t in lock["targets"]},
            {("win32", "x86_64"), ("linux", "x86_64"), ("darwin", "arm64")},
        )
        self.assertEqual(
            {t["target"] for t in lock["targets"]},
            {"windows-x86-64", "linux-x86-64", "macos-arm64"},
        )

    def test_wrong_lock_schema_is_rejected(self):
        lock = synthetic_lock()
        lock["schema"] = "something.else/1"
        with self.assertRaises(ReleaseProofError) as caught:
            validate_release_lock(lock)
        self.assertEqual(caught.exception.code, "lock_schema")

    def test_lock_with_a_non_hex_digest_is_rejected(self):
        with self.assertRaises(ReleaseProofError) as caught:
            validate_release_lock(synthetic_lock(release_asset_sha256="nope"))
        self.assertEqual(caught.exception.code, "lock_malformed")

    def test_lock_is_deterministic_about_duplicate_targets(self):
        lock = synthetic_lock()
        lock["targets"].append(dict(lock["targets"][0]))
        with self.assertRaises(ReleaseProofError) as caught:
            validate_release_lock(lock)
        self.assertEqual(caught.exception.code, "lock_malformed")

    # -- platform selection -------------------------------------------------

    def test_target_selection_matches_the_official_matrix(self):
        lock = load_release_lock(LOCK_PATH)
        cases = (
            ({"system": "Windows", "machine": "AMD64"}, "windows-x86-64"),
            ({"system": "Linux", "machine": "x86_64"}, "linux-x86-64"),
            ({"system": "Darwin", "machine": "arm64"}, "macos-arm64"),
            ({"system": "Darwin", "machine": "aarch64"}, "macos-arm64"),
            ({"system": "Linux", "machine": "amd64"}, "linux-x86-64"),
        )
        for kwargs, expected in cases:
            with self.subTest(**kwargs):
                self.assertEqual(select_target(lock, **kwargs)["target"], expected)

    def test_unlisted_platforms_fail_closed(self):
        lock = load_release_lock(LOCK_PATH)
        for kwargs in (
            {"system": "Darwin", "machine": "x86_64"},  # macOS Intel, not claimed
            {"system": "Linux", "machine": "aarch64"},
            {"system": "Windows", "machine": "arm64"},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ReleaseProofError) as caught:
                    select_target(lock, **kwargs)
                self.assertEqual(caught.exception.code, "unsupported_target")

    def test_release_asset_url_is_derived_from_the_lock(self):
        lock = load_release_lock(LOCK_PATH)
        target = select_target(lock, system="Windows", machine="x86_64")
        self.assertEqual(
            release_asset_url(lock, target["release_asset"]),
            "https://github.com/matthewjameswatkins1978-cyber/tethers-lang/"
            f"releases/download/{ACCEPTED_TAG}/Tethers-0.8.1-windows-x64.zip",
        )


class AcquisitionGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-acquire-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_archive_hash_mismatch_fails_before_any_extraction(self):
        archive = self.root / "bundle.tar.gz"
        archive.write_bytes(b"not the accepted bytes")
        lock = synthetic_lock(release_asset_sha256=sha256_bytes(b"some other bytes"))
        dest = self.root / "dest"

        with self.assertRaises(ReleaseProofError) as caught:
            acquire(
                lock,
                lock["targets"][0],
                dest,
                archive_path=archive,
                manifest_path=self.root / "absent.json",
            )
        self.assertEqual(caught.exception.code, "archive_hash_mismatch")
        self.assertFalse((dest / "Tethers-0.8.1").exists())
        self.assertEqual(list(self.root.glob("dest/**")), [])

    def test_manifest_hash_mismatch_is_rejected(self):
        archive = self.root / "bundle.tar.gz"
        archive.write_bytes(b"payload")
        manifest = synthetic_manifest()
        lock = synthetic_lock(
            release_asset_sha256=sha256_bytes(b"payload"),
            manifest_asset_sha256="f" * 64,
        )
        with self.assertRaises(ReleaseProofError) as caught:
            check_manifest_bytes(lock, lock["targets"][0], manifest, sha256_bytes(b"payload"))
        self.assertEqual(caught.exception.code, "manifest_hash_mismatch")

    def test_manifest_contradicting_the_release_identity_is_rejected(self):
        archive_digest = sha256_bytes(b"payload")
        mutations = (
            ("tag", "v0.8.0", "manifest_identity_mismatch"),
            ("product_version", "0.8.0", "manifest_identity_mismatch"),
            ("source_commit", "0" * 40, "manifest_identity_mismatch"),
            ("source_tree", "1" * 40, "manifest_identity_mismatch"),
            ("platform", "macos-x64", "manifest_identity_mismatch"),
            ("schema", "tethers.release/2", "manifest_identity_mismatch"),
        )
        for field, value, code in mutations:
            with self.subTest(field=field):
                manifest = synthetic_manifest(**{field: value})
                lock = synthetic_lock(
                    release_asset_sha256="0" * 64,
                    manifest_asset_sha256=sha256_bytes(manifest),
                )
                with self.assertRaises(ReleaseProofError) as caught:
                    check_manifest_bytes(
                        lock, lock["targets"][0], manifest, archive_digest
                    )
                self.assertEqual(caught.exception.code, code)

    def test_manifest_archive_identity_must_match_the_lock(self):
        archive_digest = sha256_bytes(b"payload")
        manifest = synthetic_manifest(
            archive={"name": "Tethers-0.8.1-other.tar.gz", "sha256": "0" * 64}
        )
        lock = synthetic_lock(manifest_asset_sha256=sha256_bytes(manifest))
        with self.assertRaises(ReleaseProofError) as caught:
            check_manifest_bytes(lock, lock["targets"][0], manifest, archive_digest)
        self.assertEqual(caught.exception.code, "manifest_identity_mismatch")

    def test_check_archive_bytes_accepts_the_exact_bytes(self):
        data = b"accepted release bytes"
        lock = synthetic_lock(release_asset_sha256=sha256_bytes(data))
        self.assertEqual(
            check_archive_bytes(lock, lock["targets"][0], data),
            sha256_bytes(data),
        )

    def test_acquire_refuses_when_a_development_override_is_present(self):
        lock = synthetic_lock()
        with self.assertRaises(ReleaseProofError) as caught:
            acquire(
                lock,
                lock["targets"][0],
                self.root / "dest",
                env={"PERMISSION_SLIP_DEV_TETHERS_UNVERIFIED": "1"},
            )
        self.assertEqual(caught.exception.code, "dev_override_present")
        self.assertFalse((self.root / "dest").exists())


class SafeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-extract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _tar_with(self, name: str) -> Path:
        path = self.root / "bundle.tar.gz"
        payload = b"pwn"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return path

    def _zip_with(self, name: str) -> Path:
        path = self.root / "bundle.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name, "pwn")
        return path

    def test_path_traversal_in_a_tar_is_refused(self):
        dest = self.root / "out"
        with self.assertRaises(ReleaseProofError) as caught:
            safe_extract_archive(self._tar_with("../escape.txt"), dest)
        self.assertEqual(caught.exception.code, "unsafe_archive_member")
        self.assertFalse((self.root / "escape.txt").exists())
        self.assertEqual(list(dest.iterdir()) if dest.exists() else [], [])

    def test_absolute_path_in_a_tar_is_refused(self):
        with self.assertRaises(ReleaseProofError) as caught:
            safe_extract_archive(self._tar_with("/etc/passwd"), self.root / "out")
        self.assertEqual(caught.exception.code, "unsafe_archive_member")

    def test_path_traversal_in_a_zip_is_refused(self):
        dest = self.root / "out"
        with self.assertRaises(ReleaseProofError) as caught:
            safe_extract_archive(self._zip_with("../escape.txt"), dest)
        self.assertEqual(caught.exception.code, "unsafe_archive_member")
        self.assertFalse((self.root / "escape.txt").exists())

    def test_symlink_escaping_the_destination_is_refused(self):
        path = self.root / "link.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(name="bin/tethers")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        with self.assertRaises(ReleaseProofError) as caught:
            safe_extract_archive(path, self.root / "out")
        self.assertEqual(caught.exception.code, "unsafe_archive_member")

    def test_a_well_formed_archive_extracts(self):
        path = self.root / "good.tar.gz"
        payload = b"#!/bin/sh\n"
        with tarfile.open(path, "w:gz") as archive:
            for name in ("./bin/tethers", "./SHA256SUMS"):
                info = tarfile.TarInfo(name=name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        dest = self.root / "out"
        safe_extract_archive(path, dest)
        self.assertTrue((dest / "bin" / "tethers").is_file())
        self.assertTrue((dest / "SHA256SUMS").is_file())


class BundleChecksumTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-checksums-")
        self.addCleanup(self.tmp.cleanup)
        self.bundle = Path(self.tmp.name) / "bundle"
        (self.bundle / "bin").mkdir(parents=True)
        self.gate = self.bundle / "bin" / "tethers"
        self.gate.write_bytes(b"gate bytes\n")

    def _write_sums(self, lines) -> None:
        (self.bundle / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )

    def test_known_self_reference_is_identified_not_ignored(self):
        self._write_sums(
            [
                f"{sha256_file(self.gate)}  bin/tethers",
                # The accepted 0.8.1 release defect: a digest that can never
                # match the file it names.
                f"{'0' * 64}  SHA256SUMS",
            ]
        )
        result = verify_bundle_checksums(self.bundle)
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["known_self_reference"], ["SHA256SUMS"])
        self.assertEqual(
            result["known_defect"], "tethers-0.8.1-self-referential-sha256sums"
        )

    def test_without_a_self_reference_every_entry_is_verified(self):
        self._write_sums([f"{sha256_file(self.gate)}  bin/tethers"])
        result = verify_bundle_checksums(self.bundle)
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["known_self_reference"], [])
        self.assertIsNone(result["known_defect"])

    def test_any_other_checksum_mismatch_still_fails(self):
        self._write_sums([f"{'0' * 64}  bin/tethers", f"{'1' * 64}  SHA256SUMS"])
        with self.assertRaises(ReleaseProofError) as caught:
            verify_bundle_checksums(self.bundle)
        self.assertEqual(caught.exception.code, "bundle_checksum_mismatch")

    def test_a_listed_but_absent_file_fails(self):
        self._write_sums(
            [f"{sha256_file(self.gate)}  bin/tethers", f"{'1' * 64}  bin/tethers-engine"]
        )
        with self.assertRaises(ReleaseProofError) as caught:
            verify_bundle_checksums(self.bundle)
        self.assertEqual(caught.exception.code, "bundle_checksum_mismatch")

    def test_missing_checksum_file_fails(self):
        with self.assertRaises(ReleaseProofError) as caught:
            verify_bundle_checksums(self.bundle)
        self.assertEqual(caught.exception.code, "bundle_checksums_missing")

    def test_resolve_bundle_root_prefers_the_directory_holding_bin(self):
        nested = Path(self.tmp.name)
        direct = nested / "direct"
        (direct / "bin").mkdir(parents=True)
        (direct / "SHA256SUMS").write_text("x  y\n", encoding="utf-8")
        self.assertEqual(resolve_bundle_root(direct), direct)

        wrapped = nested / "wrapped"
        inner = wrapped / "Tethers-0.8.1-linux-x64"
        (inner / "bin").mkdir(parents=True)
        (inner / "SHA256SUMS").write_text("x  y\n", encoding="utf-8")
        self.assertEqual(resolve_bundle_root(wrapped), inner)


if __name__ == "__main__":
    unittest.main()
