"""Safe fixture external executor.

Permission Slip's external host physically executes the admitted effect. This
spike uses harmless fixtures: routine actions touch files only inside the
dedicated ``runtime/spike-workspace/`` sandbox, and consequential actions write
a marker instead of contacting any real service, charging money, or publishing.

No effect here is ever invoked before a successful Tethers COMMIT.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actions import NormalizedAction

SANDBOX = "runtime/spike-workspace"

#: The only three truthful physical outcomes. ``succeeded`` is never inferred
#: from "the process started"; it is what actually happened.
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_UNCERTAIN = "uncertain"

#: Statuses the orchestration layer is allowed to send to a Tethers OUTCOME.
EXECUTION_STATUSES = (STATUS_SUCCEEDED, STATUS_FAILED, STATUS_UNCERTAIN)


class FixtureFailure(RuntimeError):
    """The fixture effect failed physically."""

    def __init__(self, message: str, partial: bool = False):
        super().__init__(message)
        self.partial = partial


@dataclass
class ExecutorResult:
    """The shared contract every executor returns.

    Real and fixture executors answer with the same shape so the orchestration
    layer can stop assuming ``executor returned == succeeded``. ``status`` is
    the truth about the physical world; ``executed`` says whether an effect was
    actually attempted. ``detail`` carries safe structured evidence only --
    counts, digests and exit codes, never bodies or file content.
    """

    action: str
    ok: bool
    output: dict[str, Any]
    effects: list[str] = field(default_factory=list)
    external_execution_identity: str = ""
    status: str = STATUS_SUCCEEDED
    executed: bool = True
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ok": self.ok,
            "status": self.status,
            "executed": self.executed,
            "output": self.output,
            "effects": list(self.effects),
            "external_execution_identity": self.external_execution_identity,
            "detail": dict(self.detail),
        }


class FixtureExecutor:
    """The harmless deterministic executor. It stays the default.

    It is deliberately *not* turned into a production executor: real effects
    live in :mod:`permission_slip.host_executor` and must be selected
    explicitly. When a trusted host context is supplied, authority identities
    are mapped back to physical paths through it so the fixture exercises the
    same mapping the real executor uses.
    """

    #: Selecting a real executor is an explicit constructor decision, never a
    #: default flip. Tests may assert on this to prove the default never moved.
    is_real = False

    def __init__(
        self,
        repo_root: str | os.PathLike[str],
        host_context=None,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.sandbox = self.repo_root / SANDBOX
        self.host_context = host_context

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def bound_push_effect(action: str, args: dict[str, Any]) -> str:
        """The admitted effect, taken only from the normalized action.

        The executor never re-reads the raw operation, a caller remote alias,
        a caller ``remote_url`` or caller ref labels: it records exactly what
        Tethers admitted.
        """
        return (
            f"{action} remote={args.get('remote_repository')} "
            f"ref={args.get('destination_ref')} effect={args.get('push_effect')}"
        )

    def _sandbox_path(self, *parts: str) -> Path:
        path = self.sandbox.joinpath(*parts).resolve()
        if not str(path).startswith(str(self.sandbox)):
            raise FixtureFailure("fixture refused to write outside the sandbox")
        return path

    def _scoped_repo_path(self, relative: str) -> Path:
        """Resolve an authority identity to a physical path, confined to the sandbox.

        With a trusted host context the identity is mapped through
        ``resource_prefix -> physical`` exactly as the real executor does;
        without one, it is treated as repo-relative (legacy fixture behaviour).
        Either way the result must still land inside the fixture sandbox.
        """
        if self.host_context is not None:
            path = self.host_context.physical_path(relative)
        else:
            path = (self.repo_root / relative).resolve()
        if not str(path).startswith(str(self.sandbox)):
            raise FixtureFailure("fixture refused to write outside the sandbox")
        return path

    @staticmethod
    def upload_marker_name(destination: str) -> str:
        digest = hashlib.sha256(destination.encode("utf-8")).hexdigest()[:16]
        return f"uploads/{digest}.marker"

    def marker_path(self, normalized: NormalizedAction) -> Path:
        if normalized.action in (
            "data.external_upload.repository",
            "data.external_upload.secret",
        ):
            return self._sandbox_path(
                self.upload_marker_name(str(normalized.arguments.get("destination", "")))
            )
        return self._sandbox_path("markers", normalized.action.replace(".", "-") + ".marker")

    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def _append(self, name: str, text: str) -> None:
        self._write(self._sandbox_path(name), text)

    # -- execution ---------------------------------------------------------

    def execute(
        self, normalized: NormalizedAction, *, simulate_failure: bool = False
    ) -> ExecutorResult:
        action = normalized.action
        args = normalized.arguments
        external_id = f"fixture-exec-{hashlib.sha256((action + str(args)).encode()).hexdigest()[:12]}"

        if simulate_failure:
            raise FixtureFailure(f"fixture effect for {action} failed physically")

        output: dict[str, Any] = {"ok": True}
        effects: list[str] = []

        if action == "dev.tests.run":
            self._write(self._sandbox_path("tests.log"), "tests: ok")
            effects.append("tests-ran")

        elif action == "project.files.edit":
            rel = str(args.get("path", "")).replace("\\", "/")
            target = self._scoped_repo_path(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = normalized.execution_payload
            if payload is None:
                target.write_text("edited by permission slip fixture\n", encoding="utf-8")
            else:
                # The fixture writes exactly what was bound at normalisation:
                # the same bytes whose digest Tethers admitted.
                target.write_bytes(payload)
            effects.append(f"edited:{rel}")

        elif action == "git.push.feature":
            self._append("pushes.log", self.bound_push_effect(action, args))
            effects.append("feature-pushed")

        elif action == "git.merge.accepted":
            self._append("merges.log", f"merge accepted {args.get('repository')}")
            effects.append("accepted-merge")

        elif action == "git.history.rewrite":
            self._append("history-rewrite.log", self.bound_push_effect(action, args))
            effects.append("history-rewritten")

        elif action == "data.external_upload.repository":
            marker = self.marker_path(normalized)
            self._write(marker, f"would-upload {args.get('destination')}")
            effects.append("repository-upload-simulated")

        elif action == "data.external_upload.secret":
            marker = self.marker_path(normalized)
            self._write(marker, f"would-leak {args.get('secret_kind')}")
            effects.append("secret-upload-simulated")

        elif action == "money.real_charge":
            self._append("charges.log", f"charge {args.get('amount_cents')}c {args.get('vendor')}")
            effects.append("real-charge-simulated")

        elif action == "money.promotional_credit.use":
            self._append("credit.log", f"credit {args.get('amount_cents')}c {args.get('vendor')}")
            effects.append("promo-credit-simulated")

        elif action == "identity.public_publish":
            self._append("publications.log", f"publish {args.get('channel')}")
            effects.append("publication-simulated")

        else:  # pragma: no cover - defensive
            raise FixtureFailure(f"no fixture executor for {action}")

        return ExecutorResult(
            action=action,
            ok=True,
            output=output,
            effects=effects,
            external_execution_identity=external_id,
            status=STATUS_SUCCEEDED,
            executed=True,
            detail={"executor": "fixture"},
        )
