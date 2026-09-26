"""The state-owned doctrine store: candidates, the active pointer, adoption.

Layout, under Permission Slip's existing state root::

    <permission-slip-state>/
        doctrine/
            candidates/
                sha256-<64 hex>.json     # verified canonical doctrine
            active.json                  # pointer to exactly one candidate

Three laws this module exists to enforce:

* **Writing or importing a doctrine never makes it active.** Import only ever
  creates (or re-verifies) a candidate file.
* **Adoption is the only operation that writes ``active.json``**, and it is an
  explicit compare-and-swap: the caller must state the digest it believes is
  currently active, and a stale statement is refused. The compare-and-swap is
  genuine across processes, not merely within one: the read, the comparison,
  the candidate verification and the replacement all run under
  :mod:`permission_slip.adoption_lock`, so two concurrent adopters from the
  same expected state yield exactly one winner.
* **Identity is the verified canonical digest, never a filename or an
  mtime.** Candidate filenames are derived from the digest, the active pointer
  stores a digest, and loading re-derives and re-checks the digest on every
  read. There is no "best available candidate" fallback and no
  newest-file-wins.

Limitation, stated honestly: adoption proves *that* an explicit adoption
operation happened against the correct expected state. It does **not** prove
*who* invoked it. Identity-backed proof of the adopting human belongs to later
trusted-identity work; there is deliberately no fake password, confirmation
phrase or "type YES" ceremony here.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

from .adoption_lock import adoption_lock
from .doctrine_contract import (
    DoctrineValidationError,
    canonical_digest,
    parse_json_duplicate_safe,
    parse_doctrine_json,
)
from .doctrine_export import decode_export
from .state import permission_slip_state_root

DOCTRINE_DIR = "doctrine"
CANDIDATES_DIR = "candidates"
ACTIVE_FILE = "active.json"
ACTIVE_SCHEMA = "permission-slip.active-doctrine/1"

#: ``sha256:<64 lowercase hex>`` -- the only accepted doctrine identity form.
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: ``sha256-<64 lowercase hex>.json`` -- the only accepted candidate filename.
#: Derived, never chosen: an active pointer cannot name an arbitrary path.
CANDIDATE_NAME_PATTERN = re.compile(r"^sha256-[0-9a-f]{64}\.json$")

POINTER_FIELDS = frozenset(("schema", "doctrine_digest"))


class DoctrineStateError(ValueError):
    """Doctrine state is missing, malformed or does not verify. Fail closed."""


class NoActiveDoctrine(DoctrineStateError):
    """No active pointer exists. Never a fallback to some candidate."""


class CandidateUnavailable(DoctrineStateError):
    """The named candidate does not exist, or cannot be read."""


class AdoptionConflict(DoctrineStateError):
    """The active doctrine is not what the caller expected. Refuse."""


class ImportedCandidate(NamedTuple):
    digest: str
    path: Path
    applied: tuple[tuple[str, str], ...]


class LoadedDoctrine(NamedTuple):
    document: dict[str, Any]
    digest: str


# -- paths and identity ----------------------------------------------------


def store_root(state_root: str | Path | None = None) -> Path:
    """``<permission-slip-state>/doctrine``."""
    root = permission_slip_state_root() if state_root is None else Path(state_root)
    return root / DOCTRINE_DIR


def candidates_dir(state_root: str | Path | None = None) -> Path:
    return store_root(state_root) / CANDIDATES_DIR


def active_pointer_path(state_root: str | Path | None = None) -> Path:
    return store_root(state_root) / ACTIVE_FILE


def candidate_name(digest: str) -> str:
    """The one filename a digest may occupy.

    A value that is not a well-formed doctrine digest has no filename at all,
    which is what stops a pointer from ever naming an arbitrary path.
    """
    if not isinstance(digest, str) or not DIGEST_PATTERN.match(digest):
        raise DoctrineStateError(f"not a doctrine digest: {digest!r}")
    return f"sha256-{digest.split(':', 1)[1]}.json"


def candidate_path(digest: str, state_root: str | Path | None = None) -> Path:
    return candidates_dir(state_root) / candidate_name(digest)


# -- atomic state writes ---------------------------------------------------


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write ``payload`` to ``path`` with temp-file + ``os.replace``.

    Readers see either the previous complete file or the new complete file --
    never a half-written pointer. If anything fails before the replace, the
    previous file is untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def _pointer_bytes(digest: str) -> bytes:
    pointer = {"schema": ACTIVE_SCHEMA, "doctrine_digest": digest}
    text = json.dumps(pointer, indent=2, sort_keys=True, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def _candidate_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


# -- candidates ------------------------------------------------------------


def _load_candidate_file(path: Path, expected: str) -> LoadedDoctrine:
    """Read one candidate and require its recomputed digest to match ``expected``."""
    if not path.is_file():
        raise CandidateUnavailable(f"candidate {expected} is not present at {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DoctrineStateError(
            f"candidate {expected} cannot be read: {exc}"
        ) from None
    try:
        document = parse_doctrine_json(raw)
    except DoctrineValidationError as exc:
        raise DoctrineStateError(
            f"candidate {expected} is not a valid doctrine: {exc}"
        ) from None
    digest = canonical_digest(document)
    if digest != expected:
        raise DoctrineStateError(
            f"candidate {path.name} does not verify: expected {expected}, "
            f"recomputed {digest}"
        )
    return LoadedDoctrine(document, digest)


def import_export(text: str, *, state_root: str | Path | None = None) -> ImportedCandidate:
    """Verify an export envelope and store it as a **candidate**.

    This is not adoption: the active pointer is not read, not compared and not
    written. The returned digest is recomputed, never taken from the input.
    """
    exported = decode_export(text)
    path = candidate_path(exported.digest, state_root)
    if path.is_file():
        # An existing candidate for this digest must already verify. Refuse
        # rather than quietly repairing corrupted state.
        _load_candidate_file(path, exported.digest)
    else:
        _atomic_write(path, _candidate_bytes(exported.document))
    return ImportedCandidate(exported.digest, path, exported.applied)


# -- the active pointer ----------------------------------------------------


def read_active_digest(state_root: str | Path | None = None) -> str | None:
    """The digest the active pointer names, or ``None`` if there is no pointer.

    A malformed, unknown-schema or badly-typed pointer fails closed rather
    than being ignored or falling back to a candidate.
    """
    path = active_pointer_path(state_root)
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DoctrineStateError(f"active pointer cannot be read: {exc}") from None

    try:
        pointer = parse_json_duplicate_safe(text)
    except DoctrineValidationError as exc:
        raise DoctrineStateError(f"active pointer is malformed: {exc}") from None
    if not isinstance(pointer, dict):
        raise DoctrineStateError("active pointer must be an object")
    for key in pointer:
        if key not in POINTER_FIELDS:
            raise DoctrineStateError(f"$.{key} unknown field in active pointer")
    for key in POINTER_FIELDS:
        if key not in pointer:
            raise DoctrineStateError(f"$.{key} missing from active pointer")
    if pointer["schema"] != ACTIVE_SCHEMA:
        raise DoctrineStateError(
            f"$.schema unsupported active pointer schema: {pointer['schema']!r}"
        )
    digest = pointer["doctrine_digest"]
    if not isinstance(digest, str) or not DIGEST_PATTERN.match(digest):
        raise DoctrineStateError("$.doctrine_digest is not a doctrine digest")
    return digest


def load_active_doctrine(state_root: str | Path | None = None) -> LoadedDoctrine:
    """Resolve the active pointer to a verified doctrine, or fail closed.

    Read pointer -> derive the candidate path from the digest -> parse and
    validate -> recompute the digest -> require exact agreement. No fallback,
    no newest-file-wins, no best-available-candidate.
    """
    digest = read_active_digest(state_root)
    if digest is None:
        raise NoActiveDoctrine("no active doctrine")
    return _load_candidate_file(candidate_path(digest, state_root), digest)


# -- explicit adoption -----------------------------------------------------


def _describe(digest: str | None) -> str:
    return "none" if digest is None else digest


def adopt(
    candidate_digest: str,
    *,
    expect_current: str | None,
    state_root: str | Path | None = None,
    lock_timeout: float | None = None,
) -> str:
    """Make ``candidate_digest`` active, but only if it is still ``expect_current``.

    ``expect_current=None`` means the caller expects *no* active doctrine --
    the first adoption. Any mismatch between the caller's expectation and the
    pointer actually on disk raises :class:`AdoptionConflict` instead of
    quietly adopting against a stale comparison.

    The candidate is fully verified before the pointer is touched, and the
    pointer is replaced atomically, so a failure leaves the previous active
    doctrine active.

    **The whole decision is one cross-process critical section.** ``os.replace``
    makes the pointer write atomic; it does not make read -> compare -> write
    atomic. So reading the current digest, comparing it with
    ``expect_current``, verifying the candidate and replacing the pointer all
    happen while holding the advisory lock described in
    :mod:`permission_slip.adoption_lock`. Concurrent adopters from the same
    expected state are therefore serialised: exactly one succeeds, and every
    other one -- holding a now-stale expectation -- gets
    :class:`AdoptionConflict` rather than a false success.

    Only adoption takes that lock. Import, export, diff and reading the active
    doctrine do not, and must not: they neither compare nor replace the pointer.
    """
    path = candidate_path(candidate_digest, state_root)  # validates digest format
    if expect_current is not None and not DIGEST_PATTERN.match(expect_current):
        raise DoctrineStateError(f"not a doctrine digest: {expect_current!r}")

    with adoption_lock(store_root(state_root), timeout=lock_timeout):
        # Everything below is inside the lock. Moving the comparison above it
        # would re-open the race this lock exists to close.
        current = read_active_digest(state_root)
        if expect_current != current:
            raise AdoptionConflict(
                f"expected active doctrine {_describe(expect_current)} but the "
                f"active doctrine is {_describe(current)}; refusing to adopt "
                f"{candidate_digest}"
            )

        if not path.is_file():
            raise CandidateUnavailable(
                f"candidate {candidate_digest} is not present at {path}"
            )
        # Verify before touching any state: a tampered candidate is never adopted.
        _load_candidate_file(path, candidate_digest)

        _atomic_write(active_pointer_path(state_root), _pointer_bytes(candidate_digest))
    return candidate_digest


__all__ = [
    "ACTIVE_FILE",
    "ACTIVE_SCHEMA",
    "CANDIDATES_DIR",
    "AdoptionConflict",
    "CandidateUnavailable",
    "DIGEST_PATTERN",
    "DoctrineStateError",
    "ImportedCandidate",
    "LoadedDoctrine",
    "NoActiveDoctrine",
    "active_pointer_path",
    "adopt",
    "candidate_name",
    "candidate_path",
    "candidates_dir",
    "import_export",
    "load_active_doctrine",
    "read_active_digest",
    "store_root",
]
