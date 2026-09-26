"""Vertical orchestration: doctrine -> adapter -> Tethers -> executor -> outcome.

The lifecycle is the frozen ``tethers.authority/1`` lifecycle:

    hello
    prepare -> allow_prepared | ask | deny | unavailable
    (ask: explanation -> human decision -> approval_decision)
    commit
    external fixture execution
    outcome

Nothing is physically executed before a successful COMMIT. Human approval by
itself does not authorise execution. COMMIT remains the last-responsible-moment
admission step.

Supervision law preserved in code and docs here:

    supervision may narrow authority;
    supervision may never increase authority.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import doctrine as doctrine_module
from .actions import ActionAdapter, ActionAdapterError, NormalizedAction, UntrustedActorError
from .explanations import explain
from .executor import FixtureExecutor, FixtureFailure
from .tethers_client import GateSession

DECISION_ALLOW = "ALLOW"
DECISION_ASK = "ASK"
DECISION_DENY = "DENY"
DECISION_UNAVAILABLE = "UNAVAILABLE"


@dataclass
class Receipt:
    action: str
    actor: str
    decision: str
    reason: str
    executed: bool = False
    outcome: str | None = None
    approval_id: str | None = None
    explanation: dict[str, Any] | None = None
    execution_id: str | None = None
    effects: list[str] = field(default_factory=list)
    ignored_caller_claims: tuple[str, ...] = ()
    normalized: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "actor": self.actor,
            "decision": self.decision,
            "reason": self.reason,
            "executed": self.executed,
            "outcome": self.outcome,
            "approval_id": self.approval_id,
            "explanation": self.explanation,
            "execution_id": self.execution_id,
            "effects": list(self.effects),
            "ignored_caller_claims": list(self.ignored_caller_claims),
            "normalized": dict(self.normalized),
            "error": self.error,
        }


class UnknownOperationError(RuntimeError):
    pass


def operation_digest(operation: Any) -> str:
    """Canonical digest of an operation envelope.

    Used to freeze the caller-supplied request at the start of adjudication so
    that a later mutation of the same object is detectable at COMMIT.
    """
    try:
        payload = json.dumps(
            operation, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
    except (TypeError, ValueError):
        payload = repr(operation)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PermissionSlip:
    def __init__(
        self,
        doctrine_path: str | Path,
        *,
        workdir: str | Path | None = None,
        repo_root: str | Path | None = None,
        paths=None,
        allow_unverified_tethers_for_development: bool = False,
    ):
        self.doctrine_path = Path(doctrine_path).resolve()
        self.doctrine = doctrine_module.load_doctrine(self.doctrine_path)
        self.repo_root = Path(repo_root or Path(__file__).resolve().parent.parent).resolve()
        self.workdir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="permission-slip-"))
        self.workdir.mkdir(parents=True, exist_ok=True)

        self.fixture_dir = self.workdir / "tethers-fixture"
        self.fixture = doctrine_module.compile_doctrine(self.doctrine, self.fixture_dir)

        self.adapter = ActionAdapter(self.doctrine, repo_root=self.repo_root)
        self.executor = FixtureExecutor(self.repo_root)

        # Refuses unverified / development / provenance-mismatched installations
        # before any Gate process exists, unless explicitly opted in above.
        self._session = GateSession(
            config_path=self.fixture_dir / "runtime.json",
            trail_path=self.workdir / "trail.jsonl",
            host_data_root=self.workdir / "host-data",
            paths=paths,
            allow_unverified_for_development=allow_unverified_tethers_for_development,
        )
        self.hello_result: dict[str, Any] | None = None

    # -- session lifecycle -------------------------------------------------

    def __enter__(self) -> "PermissionSlip":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def start(self) -> None:
        self._session.start()
        self.hello_result = self._session.hello()

    def close(self) -> None:
        self._session.close()

    @property
    def session(self):
        return self._session

    # -- host-side policy mutation (for last-responsible-moment tests) -----

    def update_policy(self, action: str, decision: str) -> None:
        """Rewrite one capability's host-local policy decision in the fixture."""
        config_path = self.fixture_dir / "runtime.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for rule in config["policy"]["rules"]:
            if rule["name"] == action:
                rule["decision"] = decision
                break
        else:
            raise KeyError(action)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    # -- orchestration -----------------------------------------------------

    def run(
        self,
        operation: dict[str, Any],
        actor_id: str,
        *,
        approval: str | None = None,
        simulate_failure: bool = False,
        between_prepare_and_commit: Callable[["PermissionSlip", dict[str, Any]], None] | None = None,
    ) -> Receipt:
        # Freeze the caller request and trusted actor identity at the start of
        # adjudication. The actor binding is immutable (it must be a str key of
        # the harness profile); the operation envelope is frozen as a digest so
        # that a later mutation of the same object is detectable at COMMIT.
        frozen_operation_digest = operation_digest(operation)
        frozen_actor_id = actor_id

        try:
            normalized = self.adapter.normalize(operation, actor_id)
        except UntrustedActorError as exc:
            return Receipt(
                action=operation.get("tool", "unknown"),
                actor=str(actor_id),
                decision=DECISION_DENY,
                reason="untrusted_actor",
                error=str(exc),
                ignored_caller_claims=ActionAdapter._caller_claims(operation),
            )
        except ActionAdapterError as exc:
            return Receipt(
                action=operation.get("tool", "unknown"),
                actor=str(actor_id),
                decision=DECISION_DENY,
                reason="unmappable_operation",
                error=str(exc),
                ignored_caller_claims=ActionAdapter._caller_claims(operation),
            )

        return self._adjudicate(
            normalized,
            operation=operation,
            actor_id=frozen_actor_id,
            frozen_operation_digest=frozen_operation_digest,
            approval=approval,
            simulate_failure=simulate_failure,
            between_prepare_and_commit=between_prepare_and_commit,
        )

    def approve(
        self,
        operation: dict[str, Any],
        actor_id: str,
        *,
        simulate_failure: bool = False,
        between_prepare_and_commit: Callable[["PermissionSlip", dict[str, Any]], None] | None = None,
    ) -> Receipt:
        return self.run(
            operation,
            actor_id,
            approval="approve",
            simulate_failure=simulate_failure,
            between_prepare_and_commit=between_prepare_and_commit,
        )

    def _capability(self, action: str):
        return self.fixture.capability(action)

    def prepare_payload(self, normalized: NormalizedAction, evaluation_id: str) -> dict[str, Any]:
        capability = self._capability(normalized.action)
        declared_facts = {"actor.trusted", *capability.requires}
        facts = {
            key: value
            for key, value in normalized.facts.items()
            if key in declared_facts
        }
        return {
            "action_id": "action_1",
            "evaluation_id": evaluation_id,
            "tether": {"id": capability.tether_id, "version": capability.tether_version},
            "event": {
                "id": f"evt-{uuid.uuid4().hex[:12]}",
                "name": doctrine_module.EVENT_NAME,
                "data": dict(normalized.arguments),
            },
            "facts": facts,
        }

    def _adjudicate(
        self,
        normalized: NormalizedAction,
        *,
        operation: dict[str, Any],
        actor_id: str,
        frozen_operation_digest: str,
        approval: str | None,
        simulate_failure: bool,
        between_prepare_and_commit: Callable[["PermissionSlip", dict[str, Any]], None] | None,
    ) -> Receipt:
        evaluation_id = f"eval-{uuid.uuid4().hex}"
        payload = self.prepare_payload(normalized, evaluation_id)
        capability = self._capability(normalized.action)

        receipt = Receipt(
            action=normalized.action,
            actor=normalized.actor_id,
            decision=DECISION_UNAVAILABLE,
            reason="not_prepared",
            ignored_caller_claims=normalized.ignored_caller_claims,
            normalized=normalized.as_dict(),
        )

        try:
            prepared = self._session.prepare(
                action_id=payload["action_id"],
                evaluation_id=payload["evaluation_id"],
                tether_id=payload["tether"]["id"],
                tether_version=payload["tether"]["version"],
                event_id=payload["event"]["id"],
                event_name=payload["event"]["name"],
                event_data=payload["event"]["data"],
                facts=payload["facts"],
            )
        except Exception as exc:  # GateError or transport
            code = getattr(exc, "code", "prepare.failed")
            if code == "prepare.no_actions":
                receipt.decision = DECISION_DENY
                receipt.reason = "no_plan"
            else:
                receipt.decision = DECISION_UNAVAILABLE
                receipt.reason = code
            receipt.error = str(exc)
            return receipt

        receipt.reason = prepared.get("reason", "")
        decision = prepared["decision"]

        if between_prepare_and_commit is not None:
            between_prepare_and_commit(self, prepared)

        if decision == "deny":
            receipt.decision = DECISION_DENY
            return receipt
        if decision == "unavailable":
            receipt.decision = DECISION_UNAVAILABLE
            return receipt

        if decision == "ask":
            approval_info = prepared.get("approval", {})
            receipt.approval_id = approval_info.get("approval_id")
            receipt.explanation = explain(normalized)
            if approval == "approve":
                self._session.approval_decision(receipt.approval_id, "approve")
            elif approval == "deny":
                self._session.approval_decision(receipt.approval_id, "deny")
                receipt.decision = DECISION_DENY
                receipt.reason = "human_denied"
                return receipt
            else:
                receipt.decision = DECISION_ASK
                return receipt

        # allow_prepared, or an approved ask: the last-responsible-moment COMMIT.
        receipt.decision = DECISION_ALLOW
        return self._commit_and_execute(
            prepared,
            receipt,
            capability,
            normalized,
            operation=operation,
            actor_id=actor_id,
            frozen_operation_digest=frozen_operation_digest,
            simulate_failure=simulate_failure,
        )

    def revalidate_trusted_context(
        self,
        prepared_action: NormalizedAction,
        operation: dict[str, Any],
        actor_id: str,
        frozen_operation_digest: str,
    ) -> str | None:
        """Host invariant at the COMMIT boundary.

            prepared normalized action
            == freshly trusted-normalized action right now

        Trusted external state (such as Git remote configuration) may have
        changed since PREPARE. Tethers rechecks its own policy at COMMIT but it
        cannot observe host-supplied trusted state, so Permission Slip must.

        This is a monotonic safety check: it may only stop a stale execution.
        It never re-decides authority and can never turn DENY/ASK into ALLOW.
        """
        try:
            fresh = self.adapter.normalize(operation, actor_id)
        except ActionAdapterError as exc:
            return f"trusted normalization failed at COMMIT: {exc}"

        if fresh.action != prepared_action.action:
            return f"capability changed: {prepared_action.action} -> {fresh.action}"
        if fresh.actor_id != prepared_action.actor_id:
            return (
                f"actor identity changed: {prepared_action.actor_id} -> {fresh.actor_id}"
            )
        if fresh.arguments != prepared_action.arguments:
            return (
                "trusted arguments changed: "
                f"{prepared_action.arguments!r} -> {fresh.arguments!r}"
            )
        if fresh.facts != prepared_action.facts:
            return (
                f"trusted facts changed: {prepared_action.facts!r} -> {fresh.facts!r}"
            )
        # Authority is unchanged; the envelope itself must still be the one that
        # was frozen, so any mutation of the caller's request is noticed too.
        if operation_digest(operation) != frozen_operation_digest:
            return "operation envelope changed after PREPARE"
        return None

    def _commit_and_execute(
        self,
        prepared,
        receipt,
        capability,
        normalized,
        *,
        operation,
        actor_id,
        frozen_operation_digest,
        simulate_failure,
    ):
        stale = self.revalidate_trusted_context(
            normalized, operation, actor_id, frozen_operation_digest
        )
        if stale is not None:
            # Do not COMMIT the stale prepared action, and do not execute.
            receipt.decision = DECISION_DENY
            receipt.reason = "trusted_context_changed"
            receipt.error = stale
            return receipt

        try:
            dispatch = self._session.commit(prepared["prepared_id"])
        except Exception as exc:
            code = getattr(exc, "code", "commit.failed")
            if code.startswith("commit.deny") or code in (
                "commit.approval_required",
                "commit.approval_not_ready",
            ):
                receipt.decision = DECISION_DENY
            else:
                receipt.decision = DECISION_UNAVAILABLE
            receipt.reason = code
            receipt.error = str(exc)
            return receipt

        receipt.decision = DECISION_ALLOW
        receipt.execution_id = dispatch.get("execution_id")
        if prepared.get("approval", {}).get("approval_id"):
            receipt.reason = "approved_then_committed"
        else:
            receipt.reason = "current_policy_allow"

        try:
            result = self.executor.execute(normalized, simulate_failure=simulate_failure)
        except FixtureFailure as exc:
            receipt.executed = True
            receipt.outcome = "failed"
            receipt.error = str(exc)
            self._session.outcome(
                dispatch["execution_id"],
                "failed" if not exc.partial else "uncertain",
                error=str(exc),
                external_execution_identity=f"fixture-failed-{normalized.action}",
            )
            return receipt

        receipt.executed = True
        receipt.effects = list(result.effects)
        outcome = self._session.outcome(
            dispatch["execution_id"],
            "succeeded",
            result=result.output,
            external_execution_identity=result.external_execution_identity,
        )
        receipt.outcome = outcome.get("status", "succeeded")
        return receipt
