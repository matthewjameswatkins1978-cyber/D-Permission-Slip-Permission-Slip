"""Portable doctrine export/import envelope.

The envelope is deliberately small and machine-neutral. It carries a doctrine
and its identity -- nothing else. No state-root path, no Tethers binary path,
no Git checkout path, no timestamp, no secret material, no signature claim, and
no compiled fixture: **the doctrine is the portable human contract, and
compilation is derived state.**

    encode_export(valid_doctrine) -> deterministic bytes
    decode_export(bytes)          -> verified doctrine (still just a candidate)

Decoding an envelope never activates anything. See
:mod:`permission_slip.doctrine_store` for the candidate/active boundary.

``doctrine_digest`` meaning
---------------------------

The recorded digest is the canonical Doctrine Contract digest of the embedded
doctrine **after** it has been migrated to the current schema. Permission Slip
only ever embeds current-schema documents, so for every envelope this build can
produce, migration is the identity and the recorded digest is simply the digest
of the embedded document. If a legacy schema is ever registered for migration,
that equivalence stops holding and the envelope contract needs a deliberate
version decision rather than a quiet reinterpretation.
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple

from .doctrine_contract import (
    DoctrineValidationError,
    canonical_digest,
    migrate_to_current,
    parse_json_duplicate_safe,
    validate_doctrine,
)

EXPORT_SCHEMA = "permission-slip.doctrine-export/1"

#: The envelope is closed. An authority-bearing field cannot be smuggled in
#: beside the doctrine.
ENVELOPE_FIELDS = frozenset(
    ("schema", "doctrine_schema", "doctrine_digest", "doctrine")
)


def _fail(path: str, message: str) -> None:
    raise DoctrineValidationError(path, message)


class ExportedDoctrine(NamedTuple):
    """A decoded, migrated, digest-verified doctrine.

    ``applied`` records the exact ``source -> target`` schema steps the import
    performed, or an empty tuple when no migration was needed.
    """

    document: dict[str, Any]
    digest: str
    applied: tuple[tuple[str, str], ...]


def encode_export(doctrine: Any) -> bytes:
    """Serialise a *validated* doctrine into a deterministic export envelope.

    The digest is always recomputed from the document; a caller-supplied digest
    is never trusted. The output is sorted, indented JSON with a trailing
    newline, so the same doctrine always produces the same bytes on any host.
    """
    document = validate_doctrine(doctrine)
    envelope = {
        "schema": EXPORT_SCHEMA,
        "doctrine_schema": document["schema"],
        "doctrine_digest": canonical_digest(document),
        "doctrine": document,
    }
    text = json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def decode_export(text: str) -> ExportedDoctrine:
    """Parse, migrate and verify an export envelope.

    Every claim in the envelope is checked rather than believed: the envelope
    schema, the closed envelope field set, agreement between the recorded
    doctrine schema and the embedded document, the registered migration path,
    and finally the recomputed digest against the recorded one.
    """
    envelope = parse_json_duplicate_safe(text)
    if not isinstance(envelope, dict):
        _fail("$", "must be an object")
    for key in envelope:
        if key not in ENVELOPE_FIELDS:
            _fail(f"$.{key}", "unknown field")
    for key in ENVELOPE_FIELDS:
        if key not in envelope:
            _fail(f"$.{key}", "missing required field")

    if envelope["schema"] != EXPORT_SCHEMA:
        _fail("$.schema", f"unsupported doctrine export schema: {envelope['schema']!r}")

    doctrine_schema = envelope["doctrine_schema"]
    if not isinstance(doctrine_schema, str) or not doctrine_schema.strip():
        _fail("$.doctrine_schema", "must be a non-empty string")

    embedded = envelope["doctrine"]
    if not isinstance(embedded, dict):
        _fail("$.doctrine", "must be an object")
    if embedded.get("schema") != doctrine_schema:
        _fail(
            "$.doctrine.schema",
            "must agree with the envelope's doctrine_schema " f"({doctrine_schema!r})",
        )

    # Migration happens here and nowhere else, and it still cannot adopt.
    outcome = migrate_to_current(embedded)
    digest = canonical_digest(outcome.document)

    recorded = envelope["doctrine_digest"]
    if not isinstance(recorded, str):
        _fail("$.doctrine_digest", "must be a string")
    if recorded != digest:
        _fail("$.doctrine_digest", f"does not match the recomputed digest {digest}")

    return ExportedDoctrine(outcome.document, digest, outcome.applied)
