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
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import doctrine as doctrine_module
from . import doctrine_contract, doctrine_store
from .actions import ActionAdapter, ActionAdapterError, NormalizedAction, UntrustedActorError
from .explanations import explain
from .executor import FixtureExecutor, FixtureFailure, STATUS_SUCCEEDED
from .host_context import TrustedHostContext
from .observability import (
    AUTHORITY_COMMIT_RESULT,
    AUTHORITY_COMMIT_SENT,
    AUTHORITY_OUTCOME_RESULT,
    AUTHORITY_OUTCOME_SENT,
    AUTHORITY_PREPARE_RESULT,
    AUTHORITY_PREPARE_SENT,
    EXECUTION_RESULT,
    EXECUTION_STARTED,
    HUMAN_APPROVAL_RECORDED,
    HUMAN_APPROVAL_REQUESTED,
    NORMALIZATION_FAILED,
    NORMALIZATION_STARTED,
    NORMALIZATION_SUCCEEDED,
    RUN_STARTED,
    TRUSTED_CONTEXT_REVALIDATION_RESULT,
    TRUSTED_CONTEXT_REVALIDATION_STARTED,
    BaseRecorder,
    NullRecorder,
)
from .tethers_client import GateSession

DECISION_ALLOW = "ALLOW"
DECISION_ASK = "ASK"
DECISION_DENY = "DENY"
DECISION_UNAVAILABLE = "UNAVAILABLE"

#: Actor identity always comes from trusted harness context, never from the
#: operation document. Recorded so a trace can say *where* identity came from.
ACTOR_IDENTITY_SOURCE = "trusted_harness_context"


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
    #: Forensic identity so a receipt can be found again without reenacting it.
    run_id: str | None = None
    session_id: str | None = None
    doctrine_digest: str | None = None

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
            "run_id": self.run_id,
            "session_id": self.session_id,
            "doctrine_digest": self.doctrine_digest,
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
        executor=None,
        host_context: TrustedHostContext | None = None,
        recorder: BaseRecorder | None = None,
    ):
        self.doctrine_path = Path(doctrine_path).resolve()
        self._initialise(
            doctrine_module.load_doctrine(self.doctrine_path),
            workdir=workdir,
            repo_root=repo_root,
            paths=paths,
            allow_unverified_tethers_for_development=allow_unverified_tethers_for_development,
            executor=executor,
            host_context=host_context,
            recorder=recorder,
        )

    @classmethod
    def from_active_doctrine(
        cls,
        *,
        state_root: str | Path | None = None,
        workdir: str | Path | None = None,
        repo_root: str | Path | None = None,
        paths=None,
        allow_unverified_tethers_for_development: bool = False,
        executor=None,
        host_context: TrustedHostContext | None = None,
        recorder: BaseRecorder | None = None,
    ) -> "PermissionSlip":
        """Construct from the **adopted** doctrine in Permission Slip state.

        This is the only constructor that reads the store. It resolves the
        state root, loads the active pointer's candidate, re-validates it,
        re-derives the digest and requires exact agreement before anything is
        compiled. No candidate ever becomes active by being imported, and the
        existing ``PermissionSlip(doctrine_path=...)`` route keeps its exact
        meaning -- neither route implies the other.
        """
        loaded = doctrine_store.load_active_doctrine(state_root)
        instance = cls.__new__(cls)
        instance.doctrine_path = None
        instance.doctrine_digest = loaded.digest
        instance._initialise(
            loaded.document,
            workdir=workdir,
            repo_root=repo_root,
            paths=paths,
            allow_unverified_tethers_for_development=allow_unverified_tethers_for_development,
            executor=executor,
            host_context=host_context,
            recorder=recorder,
        )
        return instance

    def _initialise(
        self,
        doctrine: dict[str, Any],
        *,
        workdir: str | Path | None,
        repo_root: str | Path | None,
        paths,
        allow_unverified_tethers_for_development: bool,
        executor=None,
        host_context: TrustedHostContext | None = None,
        recorder: BaseRecorder | None = None,
    ) -> None:
        self.doctrine = doctrine
        if not hasattr(self, "doctrine_digest"):
            self.doctrine_digest = doctrine_contract.canonical_digest(doctrine)
        self.repo_root = Path(repo_root or Path(__file__).resolve().parent.parent).resolve()
        self.workdir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="permission-slip-"))
        self.workdir.mkdir(parents=True, exist_ok=True)

        self.fixture_dir = self.workdir / "tethers-fixture"
        self.fixture = doctrine_module.compile_doctrine(self.doctrine, self.fixture_dir)

        # Trusted host facts are established here, from trusted constructor
        # arguments -- never from an operation document.
        self.host_context = host_context or TrustedHostContext.for_normalisation(
            repo_root=self.repo_root, doctrine=self.doctrine
        )
        self.adapter = ActionAdapter(self.doctrine, host_context=self.host_context)

        # The fixture executor stays the default. Selecting the real host
        # executor is an explicit constructor decision, never a silent flip.
        self.executor = FixtureExecutor(self.repo_root, host_context=self.host_context) if executor is None else executor
        self.recorder: BaseRecorder = recorder if recorder is not None else NullRecorder()
        self._current_run_id: str | None = None

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

    # -- session facts for the trace --------------------------------------

    def session_facts(self) -> dict[str, Any]:
        """Safe identities only. Never a payload, credential or environment value."""
        from . import __version__
        from .tethers_install import AUTHORITY_PROTOCOL

        hello = self.hello_result or {}
        return {
            "permission_slip_version": str(__version__),
            "tethers_product_version": str(
                hello.get("product_version") or hello.get("version") or "unknown"
            ),
            "authority_protocol": str(hello.get("protocol") or AUTHORITY_PROTOCOL),
            "doctrine_digest": self.doctrine_digest,
            "trusted_host_context_digest": self.host_context.digest(),
            "executor_mode": "real-host" if getattr(self.executor, "is_real", False) else "fixture",
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
            "supported_executor_modes": ["fixture", "real-host"],
        }

    @property
    def is_real_execution(self) -> bool:
        return bool(getattr(self.executor, "is_real", False))

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

        run_id = self.recorder.start_run(
            operation_digest=frozen_operation_digest,
            actor=str(actor_id),
            actor_identity_source=ACTOR_IDENTITY_SOURCE,
            tool=str(operation.get("tool")) if isinstance(operation, dict) else None,
            doctrine_digest=self.doctrine_digest,
            host_context_digest=self.host_context.digest(),
            canonical_repository=self.host_context.canonical_repository,
            executor_mode="real-host" if self.is_real_execution else "fixture",
        )
        self._current_run_id = run_id
        self.recorder.emit(
            run_id,
            RUN_STARTED,
            tool=str(operation.get("tool")) if isinstance(operation, dict) else None,
            session=self.session_facts(),
        )

        receipt: Receipt | None = None
        try:
            if self.is_real_execution and not self.recorder.writable:
                # No recorder: no real effect. Refuse before the Gate is even
                # asked, so nothing consequential can be left unrecorded.
                receipt = Receipt(
                    action=str(operation.get("tool", "unknown")),
                    actor=str(actor_id),
                    decision=DECISION_DENY,
                    reason="no_trace_recorder",
                    error="real execution requires a writable trace/run record",
                    ignored_caller_claims=ActionAdapter._caller_claims(operation),
                    run_id=run_id,
                    session_id=self.recorder.session_id,
                    doctrine_digest=self.doctrine_digest,
                )
                return receipt

            receipt = self._normalize_and_adjudicate(
                operation,
                actor_id=frozen_actor_id,
                frozen_operation_digest=frozen_operation_digest,
                approval=approval,
                simulate_failure=simulate_failure,
                between_prepare_and_commit=between_prepare_and_commit,
            )
            return receipt
        finally:
            payload = receipt.as_dict() if receipt is not None else {
                "action": str(operation.get("tool", "unknown")) if isinstance(operation, dict) else "unknown",
                "actor": str(actor_id),
                "decision": DECISION_UNAVAILABLE,
                "reason": "internal_error",
                "executed": False,
            }
            payload.setdefault("run_id", run_id)
            payload.setdefault("session_id", self.recorder.session_id)
            payload.setdefault("doctrine_digest", self.doctrine_digest)
            self.recorder.finish(run_id, receipt=payload, session=self.session_facts())
            self._current_run_id = None

    def _normalize_and_adjudicate(
        self,
        operation: dict[str, Any],
        *,
        actor_id: str,
        frozen_operation_digest: str,
        approval: str | None,
        simulate_failure: bool,
        between_prepare_and_commit: Callable[["PermissionSlip", dict[str, Any]], None] | None,
    ) -> Receipt:
        run_id = self._current_run_id
        self.recorder.emit(run_id, NORMALIZATION_STARTED, actor=str(actor_id))
        self.recorder.stage(run_id, "normalization")
        try:
            normalized = self.adapter.normalize(operation, actor_id)
        except UntrustedActorError as exc:
            self.recorder.emit(
                run_id, NORMALIZATION_FAILED, reason="untrusted_actor", error=str(exc)
            )
            return Receipt(
                action=operation.get("tool", "unknown"),
                actor=str(actor_id),
                decision=DECISION_DENY,
                reason="untrusted_actor",
                error=str(exc),
                ignored_caller_claims=ActionAdapter._caller_claims(operation),
                run_id=run_id,
                session_id=self.recorder.session_id,
                doctrine_digest=self.doctrine_digest,
            )
        except ActionAdapterError as exc:
            self.recorder.emit(
                run_id, NORMALIZATION_FAILED, reason="unmappable_operation", error=str(exc)
            )
            return Receipt(
                action=operation.get("tool", "unknown"),
                actor=str(actor_id),
                decision=DECISION_DENY,
                reason="unmappable_operation",
                error=str(exc),
                ignored_caller_claims=ActionAdapter._caller_claims(operation),
                run_id=run_id,
                session_id=self.recorder.session_id,
                doctrine_digest=self.doctrine_digest,
            )
        self.recorder.stage(run_id, "normalization")
        self.recorder.emit(
            run_id,
            NORMALIZATION_SUCCEEDED,
            action=normalized.action,
            actor=normalized.actor_id,
            normalized_arguments=dict(normalized.arguments),
            facts=dict(normalized.facts),
            ignored_caller_claims=list(normalized.ignored_caller_claims),
            summary=normalized.summary,
        )

        return self._adjudicate(
            normalized,
            operation=operation,
            actor_id=actor_id,
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
        run_id = self._current_run_id

        receipt = Receipt(
            action=normalized.action,
            actor=normalized.actor_id,
            decision=DECISION_UNAVAILABLE,
            reason="not_prepared",
            ignored_caller_claims=normalized.ignored_caller_claims,
            normalized=normalized.as_dict(),
            run_id=run_id,
            session_id=self.recorder.session_id,
            doctrine_digest=self.doctrine_digest,
        )

        self.recorder.stage(run_id, "prepare")
        self.recorder.emit(
            run_id,
            AUTHORITY_PREPARE_SENT,
            evaluation_id=evaluation_id,
            tether_id=payload["tether"]["id"],
            tether_version=payload["tether"]["version"],
            action=normalized.action,
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
            self.recorder.emit(
                run_id, AUTHORITY_PREPARE_RESULT, status="error", code=code, error=str(exc)
            )
            self.recorder.stage(run_id, "prepare")
            if code == "prepare.no_actions":
                receipt.decision = DECISION_DENY
                receipt.reason = "no_plan"
            else:
                receipt.decision = DECISION_UNAVAILABLE
                receipt.reason = code
            receipt.error = str(exc)
            return receipt

        self.recorder.stage(run_id, "prepare")
        self.recorder.emit(
            run_id,
            AUTHORITY_PREPARE_RESULT,
            status="ok",
            decision=prepared.get("decision"),
            reason=prepared.get("reason", ""),
            prepared_id=prepared.get("prepared_id"),
        )

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
            self.recorder.emit(
                run_id,
                HUMAN_APPROVAL_REQUESTED,
                approval_id=receipt.approval_id,
                action=normalized.action,
            )
            if approval == "approve":
                self._session.approval_decision(receipt.approval_id, "approve")
                self.recorder.emit(
                    run_id,
                    HUMAN_APPROVAL_RECORDED,
                    approval_id=receipt.approval_id,
                    decision="approve",
                )
            elif approval == "deny":
                self._session.approval_decision(receipt.approval_id, "deny")
                self.recorder.emit(
                    run_id,
                    HUMAN_APPROVAL_RECORDED,
                    approval_id=receipt.approval_id,
                    decision="deny",
                )
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
        run_id = self._current_run_id
        self.recorder.emit(run_id, TRUSTED_CONTEXT_REVALIDATION_STARTED)
        self.recorder.stage(run_id, "revalidation")
        stale = self.revalidate_trusted_context(
            normalized, operation, actor_id, frozen_operation_digest
        )
        self.recorder.stage(run_id, "revalidation")
        if stale is not None:
            # Do not COMMIT the stale prepared action, and do not execute.
            self.recorder.emit(
                run_id, TRUSTED_CONTEXT_REVALIDATION_RESULT, ok=False, reason=stale
            )
            receipt.decision = DECISION_DENY
            receipt.reason = "trusted_context_changed"
            receipt.error = stale
            return receipt
        self.recorder.emit(run_id, TRUSTED_CONTEXT_REVALIDATION_RESULT, ok=True)

        self.recorder.stage(run_id, "commit")
        self.recorder.emit(run_id, AUTHORITY_COMMIT_SENT, prepared_id=prepared["prepared_id"])
        try:
            dispatch = self._session.commit(prepared["prepared_id"])
        except Exception as exc:
            code = getattr(exc, "code", "commit.failed")
            self.recorder.emit(
                run_id, AUTHORITY_COMMIT_RESULT, status="error", code=code, error=str(exc)
            )
            self.recorder.stage(run_id, "commit")
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

        self.recorder.stage(run_id, "commit")
        self.recorder.emit(
            run_id, AUTHORITY_COMMIT_RESULT, status="ok", execution_id=dispatch.get("execution_id")
        )
        receipt.decision = DECISION_ALLOW
        receipt.execution_id = dispatch.get("execution_id")
        if prepared.get("approval", {}).get("approval_id"):
            receipt.reason = "approved_then_committed"
        else:
            receipt.reason = "current_policy_allow"

        self.recorder.emit(
            run_id,
            EXECUTION_STARTED,
            executor_mode="real-host" if self.is_real_execution else "fixture",
            action=normalized.action,
            execution_id=receipt.execution_id,
        )
        self.recorder.stage(run_id, "execution")
        try:
            result = self.executor.execute(normalized, simulate_failure=simulate_failure)
        except FixtureFailure as exc:
            self.recorder.stage(run_id, "execution")
            status = "uncertain" if exc.partial else "failed"
            receipt.executed = True
            receipt.outcome = status
            receipt.error = str(exc)
            self.recorder.emit(
                run_id,
                EXECUTION_RESULT,
                status=status,
                executed=True,
                error=str(exc),
            )
            self._report_outcome(receipt, dispatch, status, error=str(exc))
            return receipt
        except Exception as exc:
            # A real executor refusing (unsupported effect, failed revalidation,
            # missing recorder) is a truthful failed execution, not a crash.
            self.recorder.stage(run_id, "execution")
            receipt.executed = False
            receipt.outcome = "failed"
            receipt.error = str(exc)
            self.recorder.emit(
                run_id, EXECUTION_RESULT, status="failed", executed=False, error=str(exc)
            )
            self._report_outcome(receipt, dispatch, "failed", error=str(exc))
            return receipt

        self.recorder.stage(run_id, "execution")
        status = result.status
        receipt.executed = result.executed
        receipt.effects = list(result.effects)
        self.recorder.emit(
            run_id,
            EXECUTION_RESULT,
            status=status,
            executed=result.executed,
            effects=list(result.effects),
            detail=dict(result.detail),
        )
        self._report_outcome(
            receipt,
            dispatch,
            status,
            result=result.output,
            external_identity=result.external_execution_identity,
        )
        return receipt

    def _report_outcome(
        self,
        receipt,
        dispatch,
        status: str,
        *,
        error: str | None = None,
        result=None,
        external_identity: str = "",
    ) -> None:
        """Tell Tethers exactly what happened in the physical world."""
        run_id = self._current_run_id
        self.recorder.stage(run_id, "outcome")
        self.recorder.emit(run_id, AUTHORITY_OUTCOME_SENT, status=status)
        try:
            response = self._session.outcome(
                dispatch["execution_id"],
                status,
                result=result,
                error=error,
                external_execution_identity=external_identity,
            )
        except Exception as exc:  # pragma: no cover - transport failure after effect
            receipt.error = receipt.error or str(exc)
            receipt.outcome = status
            return
        finally:
            self.recorder.stage(run_id, "outcome")
        self.recorder.emit(
            run_id, AUTHORITY_OUTCOME_RESULT, status=response.get("status", status)
        )
        receipt.outcome = response.get("status", status)
