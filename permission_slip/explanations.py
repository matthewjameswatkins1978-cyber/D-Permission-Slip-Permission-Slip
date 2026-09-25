"""Human consequence explanations for ASK decisions.

Answers exactly three questions, in order:

1. What is happening?
2. Why does it matter?
3. What changes if Matthew allows it?

Tethers' approval identity/proof stays authoritative underneath. Raw protocol
jargon and machine reason codes are not the primary user-facing explanation.
"""

from __future__ import annotations

from typing import Any

from .actions import NormalizedAction


def _money(cents: int) -> str:
    return f"${cents / 100:.2f} ({cents} cents)"


def explain(normalized: NormalizedAction) -> dict[str, Any]:
    action = normalized.action
    args = normalized.arguments
    supervision = normalized.supervision

    if action == "data.external_upload.repository":
        destination = args.get("destination", "an external service")
        known = supervision.destination_novelty == "known"
        what = (
            "This worker is about to upload the Permission Slip repository to "
            f"{'a previously authorised' if known else 'a new'} external service "
            f"({destination})."
        )
        why = (
            "That destination has not been authorised before, and disclosure "
            "cannot reliably be undone."
            if not known
            else "Disclosure to an external service cannot reliably be undone."
        )
        changes = "Allowing this permits this exact repository upload once."

    elif action == "data.external_upload.secret":
        destination = args.get("destination", "an external service")
        what = (
            "This worker is about to send secret material "
            f"({args.get('secret_kind', 'credential')}) to {destination}."
        )
        why = (
            "Secret material leaves its intended boundary and may grant access "
            "that cannot be withdrawn once disclosed."
        )
        changes = "This is prohibited by the standing doctrine and cannot be allowed here."

    elif action == "git.history.rewrite":
        what = (
            "This would rewrite public Git history for "
            f"{args.get('repository', 'the repository')}."
        )
        why = (
            "Existing commit references may disappear and other checkouts can "
            "diverge."
        )
        changes = "Allowing this permits this exact history rewrite once."

    elif action == "money.real_charge":
        what = (
            "This action would create a real-money charge of "
            f"{_money(int(args.get('amount_cents', 0)))} at "
            f"{args.get('vendor', 'a payment provider')} rather than use "
            "promotional credit."
        )
        why = "Allowing it creates the stated financial exposure."
        changes = "Approval applies to this exact charge only."

    elif action == "money.promotional_credit.use":
        what = (
            "This action would spend "
            f"{_money(int(args.get('amount_cents', 0)))} of promotional credit at "
            f"{args.get('vendor', 'a provider')}."
        )
        why = (
            "Promotional credit is limited to the approved provider and to a "
            "configured per-call limit; this charge is inside that limit."
        )
        changes = "Allowing this permits this exact bounded credit use once."

    elif action == "identity.public_publish":
        what = (
            "This will publish content publicly as Matthew on "
            f"{args.get('channel', 'a public channel')}."
        )
        why = (
            "Other people may reasonably treat the publication as Matthew's own "
            "action."
        )
        changes = "Allowing it permits this exact publication once."

    elif action == "dev.tests.run":
        what = "This worker is about to run the project test suite."
        why = "Test runs are routine and reversible."
        changes = "Allowing this runs the suite once."

    elif action == "project.files.edit":
        what = f"This worker is about to edit {args.get('path', 'a project file')}."
        why = "The edit is inside the Permission Slip project workspace and is reversible."
        changes = "Allowing this makes this exact edit once."

    elif action == "git.push.feature":
        what = "This worker is about to push an ordinary feature branch."
        why = (
            "The destination is positively inside the feature/* namespace and the "
            "push is non-force, so it does not rewrite shared history."
        )
        changes = "Allowing this pushes this feature branch once."

    elif action == "git.merge.accepted":
        what = "This worker is about to merge accepted work."
        why = "Only an actor with accepted-work merge authority may merge."
        changes = "Allowing this permits this exact merge once."

    else:  # pragma: no cover - defensive fallback
        what = f"This worker is about to perform {action}."
        why = "The action is consequential enough to require a decision."
        changes = "Allowing this permits this exact action once."

    text = f"{what}\n\n{why}\n\n{changes}"
    return {"action": action, "what": what, "why": why, "changes": changes, "text": text}
