"""Deterministic, human-readable doctrine diff.

This is a *domain-aware* diff of two valid Doctrine Contract documents, not a
textual diff of two JSON files. It reports what changed, names the concrete
semantic item that changed, and classifies each change -- it never decides
whether the change is acceptable and never says an action is authorised.
Only Tethers decides a concrete action.

Two classifications, and only two:

``CONSEQUENTIAL``
    Anything that may affect authority, identity, scope, consequence binding,
    compiler output or a resource boundary -- and the fallback whenever the
    rule set does not recognise a field.

``PRESENTATION``
    Only an explicit allow-list of human-facing wording fields.

Array order is part of the contract's identity, so a reorder is reported as a
change even when the sets of values match. "No changes" is only ever printed
when the canonical digests are equal.
"""

from __future__ import annotations

import json
from typing import Any

from .doctrine_contract import canonical_digest, validate_doctrine

DIFF_SCHEMA = "permission-slip.doctrine-diff/1"

CONSEQUENTIAL = "CONSEQUENTIAL"
PRESENTATION = "PRESENTATION"

#: The entire presentation allow-list. Everything else, including anything
#: this module has never heard of, is consequential.
PRESENTATION_FIELDS = frozenset(
    ("display_name", "note", "presentation", "role", "purpose")
)


def classify(field: str) -> str:
    """Conservative: presentation only for a known human-wording field."""
    return PRESENTATION if field in PRESENTATION_FIELDS else CONSEQUENTIAL


def _j(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, (dict, list))


class _Changes:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def add(
        self,
        *,
        path: str,
        subject: str,
        field: str,
        change: str,
        before: Any,
        after: Any,
        consequence: str,
    ) -> None:
        self.items.append(
            {
                "path": path,
                "subject": subject,
                "change": change,
                "before": before,
                "after": after,
                "classification": classify(field),
                "consequence": consequence,
            }
        )


def _field(
    out: _Changes,
    *,
    path: str,
    subject: str,
    field: str,
    before: dict[str, Any],
    after: dict[str, Any],
    label: str,
) -> None:
    """Diff one named field of two objects, handling optional presence."""
    in_before, in_after = field in before, field in after
    if not in_before and not in_after:
        return
    if in_before and in_after:
        old, new = before[field], after[field]
        if old == new:
            return
        out.add(
            path=path,
            subject=subject,
            field=field,
            change="changed",
            before=old,
            after=new,
            consequence=f"{label} changed {_j(old)} -> {_j(new)}",
        )
    elif in_after:
        out.add(
            path=path,
            subject=subject,
            field=field,
            change="added",
            before=None,
            after=after[field],
            consequence=f"{label} added",
        )
    else:
        out.add(
            path=path,
            subject=subject,
            field=field,
            change="removed",
            before=before[field],
            after=None,
            consequence=f"{label} removed",
        )


def _ordered_strings(
    out: _Changes,
    *,
    path: str,
    subject: str,
    label: str,
    before: list[str],
    after: list[str],
) -> None:
    """Diff two ordered string lists without hiding a reorder."""
    if before == after:
        return
    removed = [item for item in before if item not in after]
    added = [item for item in after if item not in before]
    for item in removed:
        out.add(
            path=path,
            subject=subject,
            field=label.split()[-1],
            change="removed",
            before=item,
            after=None,
            consequence=f"{label} removed: {item}",
        )
    for item in added:
        out.add(
            path=path,
            subject=subject,
            field=label.split()[-1],
            change="added",
            before=None,
            after=item,
            consequence=f"{label} added: {item}",
        )
    if not removed and not added:
        out.add(
            path=path,
            subject=subject,
            field=label.split()[-1],
            change="changed",
            before=list(before),
            after=list(after),
            consequence=(
                f"{label} order changed: {', '.join(before)} -> {', '.join(after)}"
            ),
        )


# -- sections --------------------------------------------------------------


def _diff_profile(before: dict, after: dict, out: _Changes) -> None:
    if before["profile"] != after["profile"]:
        out.add(
            path="$.profile",
            subject="profile",
            field="profile",
            change="changed",
            before=before["profile"],
            after=after["profile"],
            consequence=(
                f"profile changed {before['profile']} -> {after['profile']}"
            ),
        )


def _diff_human(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["human"], after["human"]
    _field(
        out,
        path="$.human.id",
        subject=a["id"],
        field="id",
        before=b,
        after=a,
        label="human identity",
    )
    _field(
        out,
        path="$.human.display_name",
        subject=a["id"],
        field="display_name",
        before=b,
        after=a,
        label="human display name",
    )
    for field in ("note", "presentation"):
        _field(
            out,
            path=f"$.human.{field}",
            subject=a["id"],
            field=field,
            before=b,
            after=a,
            label=f"human {field}",
        )


def _diff_project(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["project"], after["project"]
    subject = a["id"]
    _field(
        out,
        path="$.project.id",
        subject=subject,
        field="id",
        before=b,
        after=a,
        label="project identity",
    )
    _field(
        out,
        path="$.project.display_name",
        subject=subject,
        field="display_name",
        before=b,
        after=a,
        label="project display name",
    )
    _field(
        out,
        path="$.project.root_scope",
        subject=subject,
        field="root_scope",
        before=b,
        after=a,
        label="project root scope",
    )
    _field(
        out,
        path="$.project.canonical_repository",
        subject=subject,
        field="canonical_repository",
        before=b,
        after=a,
        label="project canonical repository",
    )


def _diff_actors(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["actors"], after["actors"]
    for key in sorted(set(b) - set(a)):
        out.add(
            path=f"$.actors.{key}",
            subject=key,
            field="actor",
            change="removed",
            before=b[key],
            after=None,
            consequence=f"actor {key} removed",
        )
    for key in sorted(set(a) - set(b)):
        out.add(
            path=f"$.actors.{key}",
            subject=key,
            field="actor",
            change="added",
            before=None,
            after=a[key],
            consequence=f"actor {key} added",
        )
    for key in sorted(set(b) & set(a)):
        base = f"$.actors.{key}"
        _field(
            out,
            path=f"{base}.trusted",
            subject=key,
            field="trusted",
            before=b[key],
            after=a[key],
            label=f"actor {key} trusted",
        )
        for field in ("merge_authority", "display_name", "role", "note", "presentation"):
            _field(
                out,
                path=f"{base}.{field}",
                subject=key,
                field=field,
                before=b[key],
                after=a[key],
                label=f"actor {key} {field}",
            )


def _diff_public_identity(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["public_identity"], after["public_identity"]
    _field(
        out,
        path="$.boundaries.public_identity.subject",
        subject="public_identity",
        field="subject",
        before=b,
        after=a,
        label="public identity subject",
    )
    _field(
        out,
        path="$.boundaries.public_identity.note",
        subject="public_identity",
        field="note",
        before=b,
        after=a,
        label="public identity note",
    )


def _diff_external_upload(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["external_upload"], after["external_upload"]
    _ordered_strings(
        out,
        path="$.boundaries.external_upload.known_destinations",
        subject="external_upload",
        label="external upload known destination",
        before=b["known_destinations"],
        after=a["known_destinations"],
    )
    _field(
        out,
        path="$.boundaries.external_upload.note",
        subject="external_upload",
        field="note",
        before=b,
        after=a,
        label="external upload note",
    )


def _diff_promotional_credit(before: dict, after: dict, out: _Changes) -> None:
    b, a = before["promotional_credit"], after["promotional_credit"]
    base = "$.boundaries.promotional_credit"
    for field in ("provider", "currency", "note"):
        _field(
            out,
            path=f"{base}.{field}",
            subject="promotional_credit",
            field=field,
            before=b,
            after=a,
            label=f"promotional credit {field.replace('_', ' ')}",
        )
    old, new = b["per_call_limit_cents"], a["per_call_limit_cents"]
    if old != new:
        direction = "increased" if new > old else "decreased"
        out.add(
            path=f"{base}.per_call_limit_cents",
            subject="promotional_credit",
            field="per_call_limit_cents",
            change="changed",
            before=old,
            after=new,
            consequence=(
                f"promotional credit per-call limit {direction} from {old} "
                f"to {new} cents"
            ),
        )


def _diff_scope(action: str, before: dict, after: dict, out: _Changes) -> None:
    path = f"$.capabilities[{action}].scope"
    if before["kind"] != after["kind"]:
        direction = "narrowed" if before["kind"] == "unrestricted" else "widened"
        out.add(
            path=f"{path}.kind",
            subject=action,
            field="kind",
            change="changed",
            before=before["kind"],
            after=after["kind"],
            consequence=(
                f"{action} scope kind changed {before['kind']} -> "
                f"{after['kind']} ({direction})"
            ),
        )
        return
    if before["kind"] != "path_prefix":
        return
    old, new = before["prefixes"], after["prefixes"]
    if old == new:
        return
    removed = [item for item in old if item not in new]
    added = [item for item in new if item not in old]
    if removed:
        out.add(
            path=f"{path}.prefixes",
            subject=action,
            field="prefixes",
            change="removed",
            before=removed,
            after=None,
            consequence=(
                f"{action} path scope narrowed: {', '.join(removed)} removed"
            ),
        )
    if added:
        out.add(
            path=f"{path}.prefixes",
            subject=action,
            field="prefixes",
            change="added",
            before=None,
            after=added,
            consequence=f"{action} path scope widened: {', '.join(added)} added",
        )
    if not removed and not added:
        out.add(
            path=f"{path}.prefixes",
            subject=action,
            field="prefixes",
            change="changed",
            before=list(old),
            after=list(new),
            consequence=(
                f"{action} path prefix order changed: {', '.join(old)} -> "
                f"{', '.join(new)}"
            ),
        )


def _diff_capability(action: str, before: dict, after: dict, out: _Changes) -> None:
    base = f"$.capabilities[{action}]"
    _field(
        out,
        path=f"{base}.purpose",
        subject=action,
        field="purpose",
        before=before,
        after=after,
        label=f"{action} purpose",
    )
    if before["standing"] != after["standing"]:
        out.add(
            path=f"{base}.standing",
            subject=action,
            field="standing",
            change="changed",
            before=before["standing"],
            after=after["standing"],
            consequence=(
                f"{action} standing changed {before['standing'].upper()} -> "
                f"{after['standing'].upper()}"
            ),
        )
    if before["reversibility"] != after["reversibility"]:
        out.add(
            path=f"{base}.reversibility",
            subject=action,
            field="reversibility",
            change="changed",
            before=before["reversibility"],
            after=after["reversibility"],
            consequence=(
                f"{action} reversibility changed {before['reversibility']} -> "
                f"{after['reversibility']}"
            ),
        )
    _diff_scope(action, before["scope"], after["scope"], out)
    _ordered_strings(
        out,
        path=f"{base}.requires",
        subject=action,
        label=f"{action} required fact",
        before=before.get("requires", []),
        after=after.get("requires", []),
    )
    _ordered_strings(
        out,
        path=f"{base}.effects",
        subject=action,
        label=f"{action} effect",
        before=before["effects"],
        after=after["effects"],
    )


def _diff_capabilities(before: dict, after: dict, out: _Changes) -> None:
    b_list, a_list = before["capabilities"], after["capabilities"]
    b_by_action = {item["action"]: item for item in b_list}
    a_by_action = {item["action"]: item for item in a_list}

    for action in sorted(set(b_by_action) - set(a_by_action)):
        out.add(
            path=f"$.capabilities[{action}]",
            subject=action,
            field="capability",
            change="removed",
            before=b_by_action[action],
            after=None,
            consequence=f"capability {action} removed",
        )
    for action in sorted(set(a_by_action) - set(b_by_action)):
        out.add(
            path=f"$.capabilities[{action}]",
            subject=action,
            field="capability",
            change="added",
            before=None,
            after=a_by_action[action],
            consequence=f"capability {action} added",
        )
    for action in sorted(set(b_by_action) & set(a_by_action)):
        _diff_capability(action, b_by_action[action], a_by_action[action], out)

    # Array order is part of the contract's identity. Report a reorder even
    # though the members are identical.
    b_order = [item["action"] for item in b_list]
    a_order = [item["action"] for item in a_list]
    if b_order != a_order and set(b_order) == set(a_order):
        out.add(
            path="$.capabilities",
            subject="capabilities",
            field="capabilities",
            change="changed",
            before=b_order,
            after=a_order,
            consequence=(
                f"capability order changed: {', '.join(b_order)} -> "
                f"{', '.join(a_order)}"
            ),
        )


# -- public API ------------------------------------------------------------


def diff_doctrines(before: Any, after: Any) -> dict[str, Any]:
    """Compare two valid doctrines and return a ``doctrine-diff/1`` envelope."""
    left = validate_doctrine(before)
    right = validate_doctrine(after)

    out = _Changes()
    _diff_profile(left, right, out)
    _diff_human(left, right, out)
    _diff_project(left, right, out)
    _diff_actors(left, right, out)
    b_boundaries, a_boundaries = left["boundaries"], right["boundaries"]
    _diff_public_identity(b_boundaries, a_boundaries, out)
    _diff_external_upload(b_boundaries, a_boundaries, out)
    _diff_promotional_credit(b_boundaries, a_boundaries, out)
    _diff_capabilities(left, right, out)

    before_digest = canonical_digest(left)
    after_digest = canonical_digest(right)
    changes = out.items
    if before_digest != after_digest and not changes:
        # Defensive and conservative: if identity moved but no rule fired, say
        # so rather than reporting "No changes" for two different documents.
        changes.append(
            {
                "path": "$",
                "subject": "doctrine",
                "change": "changed",
                "before": before_digest,
                "after": after_digest,
                "classification": CONSEQUENTIAL,
                "consequence": (
                    "doctrine changed outside the classified field set; "
                    "review the full document"
                ),
            }
        )

    return {
        "schema": DIFF_SCHEMA,
        "before_digest": before_digest,
        "after_digest": after_digest,
        "changed": before_digest != after_digest,
        "changes": changes,
    }


def render_human(diff: dict[str, Any]) -> str:
    """Prose rendering. Every line names a concrete semantic item."""
    lines = [
        f"Doctrine diff ({diff['schema']})",
        f"  before {diff['before_digest']}",
        f"  after  {diff['after_digest']}",
        "",
    ]
    changes = diff["changes"]
    if not changes:
        lines.append("No changes.")
        return "\n".join(lines)

    for change in changes:
        lines.append(f"[{change['classification']}] {change['consequence']}")
        before, after = change["before"], change["after"]
        if change["change"] == "changed" and _is_scalar(before) and _is_scalar(after):
            lines.append(f"    {change['path']}: {_j(before)} -> {_j(after)}")
        else:
            lines.append(f"    {change['path']}")

    consequential = sum(
        1 for item in changes if item["classification"] == CONSEQUENTIAL
    )
    presentation = len(changes) - consequential
    lines.append("")
    lines.append(
        f"{len(changes)} change{'s' if len(changes) != 1 else ''}: "
        f"{consequential} consequential, {presentation} presentation"
    )
    return "\n".join(lines)
