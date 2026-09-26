"""Permission Slip Doctrine Contract v1.

This module owns one question and one question only:

    "Is this a valid Permission Slip doctrine document?"

It deliberately does **not** answer "is this action authorised?" — that is
Tethers' answer and Tethers alone. This module never evaluates authority; it
checks structure, produces a deterministic canonical form, and computes a
deterministic identity for a document that has passed validation.

Layering::

    doctrine_contract  -- validates / canonicalises / identifies a doctrine
    doctrine compiler  -- translates a VALID doctrine into Tethers configuration
    Tethers            -- decides ALLOW / ASK / DENY

Validation is explicit standard-library checking against a small, closed v1
vocabulary. There is no JSON Schema engine and no third-party dependency: every
rule below is inspectable, deterministic and deliberately narrow.

Two invariants make the contract portable and safe:

* every section declares the exact set of fields it accepts, so an
  authority-bearing field can never be smuggled in as an unknown key;
* every scalar has an explicit type, so the canonical form can never contain a
  float and always round-trips byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, NoReturn

from .actions import canonical_repository_identity

SCHEMA_ID = "permission-slip.doctrine/1"

# The closed v1 vocabulary. Nothing outside these sets is part of the contract.
TOP_LEVEL_ORDER = (
    "schema",
    "profile",
    "human",
    "project",
    "actors",
    "boundaries",
    "capabilities",
)
TOP_LEVEL_FIELDS = frozenset(TOP_LEVEL_ORDER)

STANDINGS = ("allow", "ask", "deny")
REVERSIBILITIES = ("reversible", "compensatable", "irreversible")
SCOPE_KINDS = ("path_prefix", "unrestricted")

HUMAN_FIELDS = frozenset(("id", "display_name", "note", "presentation"))
HUMAN_REQUIRED = ("id", "display_name")

PROJECT_FIELDS_ORDER = ("id", "display_name", "root_scope", "canonical_repository")
PROJECT_FIELDS = frozenset(PROJECT_FIELDS_ORDER)

ACTOR_FIELDS = frozenset(
    ("id", "display_name", "trusted", "merge_authority", "role", "note", "presentation")
)
ACTOR_REQUIRED = ("id", "trusted")
ACTOR_PRESENTATION_FIELDS = ("display_name", "role", "note", "presentation")

BOUNDARY_SECTIONS = ("public_identity", "external_upload", "promotional_credit")

PUBLIC_IDENTITY_FIELDS = frozenset(("subject", "note"))
EXTERNAL_UPLOAD_FIELDS = frozenset(("known_destinations", "note"))
PROMOTIONAL_CREDIT_FIELDS = frozenset(
    ("provider", "currency", "per_call_limit_cents", "note")
)

CAPABILITY_FIELDS = frozenset(
    ("action", "purpose", "standing", "scope", "reversibility", "effects", "requires")
)
CAPABILITY_REQUIRED = ("action", "purpose", "standing", "scope", "reversibility", "effects")

SCOPE_FIELDS = {
    "path_prefix": frozenset(("kind", "prefixes")),
    "unrestricted": frozenset(("kind",)),
}


class DoctrineValidationError(ValueError):
    """A document that is not a valid Permission Slip doctrine.

    This is the public contract error. Structural problems are always reported
    as this type -- never as a raw ``KeyError`` or ``TypeError`` -- and carry
    the path to the offending value where practical::

        $.actors.lucy.merge_authority must be boolean
        $.capabilities[3].standing unsupported value "maybe"
    """

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path} {message}")


def _fail(path: str, message: str) -> NoReturn:
    raise DoctrineValidationError(path, message)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if not value.strip():
        _fail(path, "must be a non-empty string")
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        _fail(path, "must be boolean")
    return value


def _integer(value: Any, path: str) -> int:
    if type(value) is not int:
        _fail(path, "must be an integer")
    return value


def _list(value: Any, path: str, *, non_empty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "must be a list")
    if non_empty and not value:
        _fail(path, "must be a non-empty list")
    return value


def _text_list(value: Any, path: str, *, non_empty: bool) -> list[str]:
    items = _list(value, path, non_empty=non_empty)
    for index, item in enumerate(items):
        _text(item, f"{path}[{index}]")
    return items


def _check_fields(
    value: dict[str, Any],
    path: str,
    *,
    allowed: frozenset[str],
    required: tuple[str, ...],
) -> None:
    for key in value:
        if key not in allowed:
            _fail(f"{path}.{key}", "unknown field")
    for key in required:
        if key not in value:
            _fail(f"{path}.{key}", "missing required field")


def _choice(value: Any, path: str, vocabulary: tuple[str, ...]) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if value not in vocabulary:
        _fail(path, f"unsupported value {json.dumps(value)}")
    return value


# -- parsing ----------------------------------------------------------------


def _unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # json silently keeps the last of duplicate keys, which would make two
    # different documents look identical. Doctrine identity must not depend on
    # that silent collapse, so duplicates are a contract violation.
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            _fail("$", f"duplicate object key {json.dumps(key)}")
        seen[key] = value
    return seen


def parse_doctrine_json(text: str) -> dict[str, Any]:
    """Parse ``text`` and return a doctrine that satisfies the contract.

    Duplicate object keys anywhere in the document are rejected here rather
    than silently collapsed, which is what makes duplicate actor or capability
    identities impossible to hide.
    """
    try:
        document = json.loads(text, object_pairs_hook=_unique_object_pairs)
    except DoctrineValidationError:
        raise
    except json.JSONDecodeError as exc:
        _fail("$", f"not valid JSON ({exc.msg})")
    return validate_doctrine(document)


# -- validation ------------------------------------------------------------


def validate_doctrine(doctrine: Any) -> dict[str, Any]:
    """Validate ``doctrine`` against Doctrine Contract v1.

    Returns the document unchanged so callers can keep working with the same
    object. Raises :class:`DoctrineValidationError` for anything that is not a
    valid v1 doctrine, including an unknown schema version.
    """
    root = _object(doctrine, "$")
    _check_fields(root, "$", allowed=TOP_LEVEL_FIELDS, required=TOP_LEVEL_ORDER)

    if root["schema"] != SCHEMA_ID:
        _fail("$.schema", f"unsupported doctrine schema: {root['schema']!r}")

    _text(root["profile"], "$.profile")
    _validate_human(root["human"])
    _validate_project(root["project"])
    _validate_actors(root["actors"])
    _validate_boundaries(root["boundaries"])
    _validate_capabilities(root["capabilities"])
    return root


def _validate_human(human: Any) -> None:
    value = _object(human, "$.human")
    _check_fields(value, "$.human", allowed=HUMAN_FIELDS, required=HUMAN_REQUIRED)
    _text(value["id"], "$.human.id")
    _text(value["display_name"], "$.human.display_name")
    for key in ("note", "presentation"):
        if key in value:
            _text(value[key], f"$.human.{key}")


def _validate_project(project: Any) -> None:
    value = _object(project, "$.project")
    _check_fields(value, "$.project", allowed=PROJECT_FIELDS, required=PROJECT_FIELDS_ORDER)
    _text(value["id"], "$.project.id")
    _text(value["display_name"], "$.project.display_name")
    _text(value["root_scope"], "$.project.root_scope")
    repository = _text(value["canonical_repository"], "$.project.canonical_repository")
    if canonical_repository_identity(repository) is None:
        _fail(
            "$.project.canonical_repository",
            "must be a canonical GitHub repository URL",
        )


def _validate_actors(actors: Any) -> None:
    value = _object(actors, "$.actors")
    if not value:
        _fail("$.actors", "must be a non-empty object")
    for key in value:
        if not isinstance(key, str) or not key.strip():
            _fail("$.actors", "actor map keys must be non-empty strings")
        path = f"$.actors.{key}"
        actor = _object(value[key], path)
        _check_fields(actor, path, allowed=ACTOR_FIELDS, required=ACTOR_REQUIRED)
        actor_id = _text(actor["id"], f"{path}.id")
        # Map key and identity must agree: a doctrine can never describe the
        # same actor twice under two different labels.
        if actor_id != key:
            _fail(f"{path}.id", f"must equal its map key {json.dumps(key)}")
        _boolean(actor["trusted"], f"{path}.trusted")
        if "merge_authority" in actor:
            _boolean(actor["merge_authority"], f"{path}.merge_authority")
        for key_name in ACTOR_PRESENTATION_FIELDS:
            if key_name in actor:
                _text(actor[key_name], f"{path}.{key_name}")


def _validate_boundaries(boundaries: Any) -> None:
    value = _object(boundaries, "$.boundaries")
    _check_fields(
        value,
        "$.boundaries",
        allowed=frozenset(BOUNDARY_SECTIONS),
        required=BOUNDARY_SECTIONS,
    )

    public_identity = _object(value["public_identity"], "$.boundaries.public_identity")
    _check_fields(
        public_identity,
        "$.boundaries.public_identity",
        allowed=PUBLIC_IDENTITY_FIELDS,
        required=("subject",),
    )
    _text(public_identity["subject"], "$.boundaries.public_identity.subject")
    if "note" in public_identity:
        _text(public_identity["note"], "$.boundaries.public_identity.note")

    external_upload = _object(value["external_upload"], "$.boundaries.external_upload")
    _check_fields(
        external_upload,
        "$.boundaries.external_upload",
        allowed=EXTERNAL_UPLOAD_FIELDS,
        required=("known_destinations",),
    )
    # An empty list is valid: nothing is known yet, so every destination is
    # novel. Requiring a non-empty list here would invent destinations.
    _text_list(
        external_upload["known_destinations"],
        "$.boundaries.external_upload.known_destinations",
        non_empty=False,
    )
    if "note" in external_upload:
        _text(external_upload["note"], "$.boundaries.external_upload.note")

    credit = _object(value["promotional_credit"], "$.boundaries.promotional_credit")
    _check_fields(
        credit,
        "$.boundaries.promotional_credit",
        allowed=PROMOTIONAL_CREDIT_FIELDS,
        required=("provider", "currency", "per_call_limit_cents"),
    )
    _text(credit["provider"], "$.boundaries.promotional_credit.provider")
    _text(credit["currency"], "$.boundaries.promotional_credit.currency")
    limit_path = "$.boundaries.promotional_credit.per_call_limit_cents"
    # ``type(...) is int`` deliberately rejects ``True`` and rejects floats:
    # the v1 bound is a whole number of cents and nothing else.
    _integer(credit["per_call_limit_cents"], limit_path)
    if credit["per_call_limit_cents"] <= 0:
        _fail(limit_path, "must be > 0")
    if "note" in credit:
        _text(credit["note"], "$.boundaries.promotional_credit.note")


def _validate_capabilities(capabilities: Any) -> None:
    items = _list(capabilities, "$.capabilities", non_empty=True)
    seen: dict[str, int] = {}
    for index, raw in enumerate(items):
        path = f"$.capabilities[{index}]"
        capability = _object(raw, path)
        _check_fields(
            capability, path, allowed=CAPABILITY_FIELDS, required=CAPABILITY_REQUIRED
        )

        action = _text(capability["action"], f"{path}.action")
        # Duplicates are rejected outright: neither "first wins" nor "last
        # wins" is an acceptable reading of a doctrine.
        if action in seen:
            _fail(
                f"$.capabilities[{index}]",
                f"duplicate capability action {json.dumps(action)}",
            )
        seen[action] = index

        _text(capability["purpose"], f"{path}.purpose")
        _choice(capability["standing"], f"{path}.standing", STANDINGS)
        _validate_scope(capability["scope"], f"{path}.scope")
        _choice(capability["reversibility"], f"{path}.reversibility", REVERSIBILITIES)

        effects_path = f"{path}.effects"
        _text_list(capability["effects"], effects_path, non_empty=True)

        if "requires" in capability:
            requires_path = f"{path}.requires"
            facts = _text_list(capability["requires"], requires_path, non_empty=True)
            unique: set[str] = set()
            for position, fact in enumerate(facts):
                if fact in unique:
                    _fail(
                        f"{requires_path}[{position}]",
                        f"duplicate required fact {json.dumps(fact)}",
                    )
                unique.add(fact)


def _validate_scope(scope: Any, path: str) -> None:
    value = _object(scope, path)
    if "kind" not in value:
        _fail(f"{path}.kind", "missing required field")
    kind = _choice(value["kind"], f"{path}.kind", SCOPE_KINDS)
    allowed = SCOPE_FIELDS[kind]
    _check_fields(
        value,
        path,
        allowed=allowed,
        required=tuple(sorted(allowed)),
    )
    if kind == "path_prefix":
        # Only the scope kinds the product actually understands are part of v1.
        _text_list(value["prefixes"], f"{path}.prefixes", non_empty=True)


# -- canonical form and identity ------------------------------------------


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding for a value that is already known to be fine.

    Sorted object keys, no insignificant whitespace, UTF-8 without ASCII
    escaping. This is the one canonical-JSON encoder the repository uses --
    doctrine identity and compiled-manifest digests must not drift apart.
    Validation is the caller's job: the compiled manifests are artefacts, not
    doctrine documents.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_doctrine_bytes(doctrine: Any) -> bytes:
    """The deterministic UTF-8 encoding of a validated doctrine.

    Determinism rules for v1, deliberately conservative:

    * object key order is **non-semantic** -- keys are sorted;
    * array order is **preserved** -- the contract does not claim array
      ordering is irrelevant, so reordering is a different document;
    * no insignificant whitespace, no ASCII escaping of non-ASCII text.

    Because every v1 scalar is typed as string, integer, boolean, object or
    array, this encoding can never contain a float.
    """
    return canonical_json_bytes(validate_doctrine(doctrine))


def canonical_digest(doctrine: Any) -> str:
    """``sha256:<64 lowercase hex>`` over the canonical validated document.

    This is the whole document's identity, computed rather than stored, so a
    doctrine can never disagree with its own digest. Any value change --
    including a note or display name -- changes the digest, which is the
    conservative behaviour this version wants.
    """
    return "sha256:" + hashlib.sha256(canonical_doctrine_bytes(doctrine)).hexdigest()
