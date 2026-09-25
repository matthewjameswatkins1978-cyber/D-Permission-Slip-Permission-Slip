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


class FixtureFailure(RuntimeError):
    """The fixture effect failed physically."""

    def __init__(self, message: str, partial: bool = False):
        super().__init__(message)
        self.partial = partial


@dataclass
class ExecutorResult:
    action: str
    ok: bool
    output: dict[str, Any]
    effects: list[str] = field(default_factory=list)
    external_execution_identity: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ok": self.ok,
            "output": self.output,
            "effects": list(self.effects),
            "external_execution_identity": self.external_execution_identity,
        }


class FixtureExecutor:
    def __init__(self, repo_root: str | os.PathLike[str]):
        self.repo_root = Path(repo_root).resolve()
        self.sandbox = self.repo_root / SANDBOX

    # -- helpers -----------------------------------------------------------

    def _sandbox_path(self, *parts: str) -> Path:
        path = self.sandbox.joinpath(*parts).resolve()
        if not str(path).startswith(str(self.sandbox)):
            raise FixtureFailure("fixture refused to write outside the sandbox")
        return path

    def _scoped_repo_path(self, relative: str) -> Path:
        """Resolve a repo-relative path and confine it to the sandbox."""
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
            target.write_text(
                "edited by permission slip fixture\n", encoding="utf-8"
            )
            effects.append(f"edited:{rel}")

        elif action == "git.push.feature":
            self._append("pushes.log", f"push feature {args.get('repository')}")
            effects.append("feature-pushed")

        elif action == "git.merge.accepted":
            self._append("merges.log", f"merge accepted {args.get('repository')}")
            effects.append("accepted-merge")

        elif action == "git.history.rewrite":
            self._append("history-rewrite.log", f"rewrite {args.get('repository')}")
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
        )
