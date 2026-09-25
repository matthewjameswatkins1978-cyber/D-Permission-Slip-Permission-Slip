"""Trusted action adapter: the trust boundary.

This module is the only place where an agent's raw request becomes
authority-relevant facts. It is deliberately untrusting of the caller.

Law it enforces:

* authority-relevant facts are **derived from the actual operation**, never
  read from a model-supplied label;
* caller-supplied authority booleans (``permission``, ``trusted``,
  ``approved``, ``granted``, ...) are ignored, not honoured;
* actor identity comes from the trusted harness profile, not from content.

The output is a :class:`NormalizedAction`: a semantic capability plus resolved
arguments and trusted facts. Permission Slip does not decide ALLOW / ASK / DENY
here; it prepares the exact input Tethers will decide on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Keys a caller might use to try to manufacture authority. They are never read.
FORBIDDEN_CALLER_KEYS = (
    "permission",
    "within_scope",
    "trusted",
    "approved",
    "approved_by",
    "authority_granted",
    "granted",
    "authorised",
    "authorized",
    "declared_action",
    "claimed_action",
    "action",
    "capability",
    "decision",
)

_SHARED_BRANCHES = {"main", "master", "trunk", "release"}
_FORCE_FLAGS = {"--force", "-f", "--force-with-lease", "--force-if-includes"}


class ActionAdapterError(ValueError):
    """The operation could not be normalised into a trusted semantic action."""


class UntrustedActorError(ActionAdapterError):
    """The operation names an actor absent from the trusted harness profile."""


@dataclass(frozen=True)
class SupervisoryMetadata:
    """Explanation-only metadata. It never grants authority."""

    reversibility: str = "unknown"
    private_to_public: bool = False
    real_money: bool = False
    destination_novelty: str = "n/a"
    affected_parties: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "reversibility": self.reversibility,
            "private_to_public": self.private_to_public,
            "real_money": self.real_money,
            "destination_novelty": self.destination_novelty,
            "affected_parties": list(self.affected_parties),
        }


@dataclass
class NormalizedAction:
    action: str
    arguments: dict[str, Any]
    facts: dict[str, Any]
    actor_id: str
    ignored_caller_claims: tuple[str, ...] = ()
    supervision: SupervisoryMetadata = field(default_factory=SupervisoryMetadata)
    summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "arguments": dict(self.arguments),
            "facts": dict(self.facts),
            "actor": self.actor_id,
            "ignored_caller_claims": list(self.ignored_caller_claims),
            "supervision": self.supervision.as_dict(),
            "summary": self.summary,
        }


def _posix_relative(path: str, cwd: str) -> str:
    path = str(path)
    if os.path.isabs(path):
        try:
            path = os.path.relpath(path, cwd)
        except ValueError:
            return path.replace("\\", "/")
    return path.replace("\\", "/").lstrip("./")


class ActionAdapter:
    def __init__(self, doctrine: dict[str, Any], repo_root: str | os.PathLike[str] | None = None):
        self.doctrine = doctrine
        self.repo_root = os.path.abspath(repo_root or os.getcwd())
        project = doctrine.get("project", {})
        self.root_scope = project.get("root_scope", "runtime/spike-workspace/")
        credit = doctrine.get("boundaries", {}).get("promotional_credit", {})
        self.promo_budget_cents = int(credit.get("budget_cents", 0))
        self.promo_provider = credit.get("provider")
        self.known_destinations = set(
            doctrine.get("boundaries", {}).get("external_upload", {}).get("known_destinations", [])
        )
        self.actors: dict[str, dict[str, Any]] = {
            actor["id"]: actor for actor in doctrine.get("actors", {}).values()
        }

    # -- helpers -----------------------------------------------------------

    def _workspace_path(self, *parts: str) -> str:
        return self.root_scope.rstrip("/") + "/" + "/".join(parts)

    def _repo_path(self) -> str:
        return self._workspace_path("repos", "permission-slip")

    def _actor_facts(self, actor: dict[str, Any]) -> dict[str, Any]:
        return {
            "actor.trusted": bool(actor.get("trusted", False)),
            "actor.merge_authority": bool(actor.get("merge_authority", False)),
        }

    def _resolve_actor(self, operation: dict[str, Any]) -> dict[str, Any]:
        actor_id = operation.get("actor")
        if not isinstance(actor_id, str) or actor_id not in self.actors:
            raise UntrustedActorError(f"actor {actor_id!r} is not in the trusted harness profile")
        return self.actors[actor_id]

    @staticmethod
    def _caller_claims(operation: dict[str, Any]) -> tuple[str, ...]:
        return tuple(sorted(key for key in FORBIDDEN_CALLER_KEYS if key in operation))

    def _reversibility(self, action: str) -> str:
        for capability in self.doctrine.get("capabilities", []):
            if capability["action"] == action:
                return capability.get("reversibility", "unknown")
        return "unknown"

    # -- normalisation -----------------------------------------------------

    def normalize(self, operation: dict[str, Any]) -> NormalizedAction:
        if not isinstance(operation, dict):
            raise ActionAdapterError("operation envelope must be an object")
        actor = self._resolve_actor(operation)
        claims = self._caller_claims(operation)
        tool = operation.get("tool")
        cwd = str(operation.get("cwd", self.repo_root))
        facts = self._actor_facts(actor)

        if tool == "git":
            action, arguments, summary, supervision = self._normalize_git(operation, cwd)
        elif tool == "tests":
            action = "dev.tests.run"
            arguments = {"path": self._workspace_path("tests.log")}
            summary = "run the project test suite"
            supervision = SupervisoryMetadata(reversibility=self._reversibility(action))
        elif tool == "edit_file":
            action = "project.files.edit"
            arguments = {"path": _posix_relative(operation.get("path", ""), cwd)}
            summary = f"edit {arguments['path']}"
            supervision = SupervisoryMetadata(reversibility=self._reversibility(action))
        elif tool == "external_upload":
            action, arguments, summary, supervision = self._normalize_upload(operation)
        elif tool == "payment":
            action, arguments, facts, summary, supervision = self._normalize_payment(operation, facts)
        elif tool == "publish":
            action = "identity.public_publish"
            arguments = {"channel": str(operation.get("channel", ""))}
            summary = f"publish to {arguments['channel']} as {operation.get('as', actor['id'])}"
            supervision = SupervisoryMetadata(
                reversibility=self._reversibility(action),
                private_to_public=True,
                affected_parties=(str(operation.get("as", actor["id"])), "public"),
            )
        else:
            raise ActionAdapterError(f"unsupported trusted operation tool: {tool!r}")

        return NormalizedAction(
            action=action,
            arguments=arguments,
            facts=facts,
            actor_id=actor["id"],
            ignored_caller_claims=claims,
            supervision=supervision,
            summary=summary,
        )

    def _normalize_git(
        self, operation: dict[str, Any], cwd: str
    ) -> tuple[str, dict[str, Any], str, SupervisoryMetadata]:
        argv = operation.get("argv")
        if not isinstance(argv, list) or not argv:
            raise ActionAdapterError("git operation requires a non-empty argv list")
        argv = [str(item) for item in argv]
        subcommand = argv[0].lower()
        repo = self._repo_path()

        if subcommand == "push":
            force = any(flag in argv for flag in _FORCE_FLAGS)
            branch = self._push_branch(argv)
            shared = branch in _SHARED_BRANCHES
            if force or shared:
                action = "git.history.rewrite"
                summary = f"rewrite public history on {branch}"
                supervision = SupervisoryMetadata(
                    reversibility=self._reversibility(action),
                    private_to_public=True,
                    affected_parties=("repository collaborators", "public"),
                )
            else:
                action = "git.push.feature"
                summary = f"push feature branch {branch}"
                supervision = SupervisoryMetadata(reversibility=self._reversibility(action))
            return action, {"repository": repo}, summary, supervision

        if subcommand == "merge":
            action = "git.merge.accepted"
            source = next((item for item in argv[1:] if not item.startswith("-")), "")
            summary = f"merge accepted work ({source or 'unnamed source'})"
            supervision = SupervisoryMetadata(
                reversibility=self._reversibility(action),
                affected_parties=("accepted-work authority",),
            )
            return action, {"repository": repo}, summary, supervision

        raise ActionAdapterError(f"unsupported git subcommand: {subcommand!r}")

    @staticmethod
    def _push_branch(argv: list[str]) -> str:
        positional = [item for item in argv[1:] if not item.startswith("-")]
        if len(positional) >= 2:
            return positional[-1].replace("refs/heads/", "")
        if len(positional) == 1:
            # ``git push origin`` with no ref: treat conservatively as shared.
            return "main"
        return "main"

    def _normalize_upload(
        self, operation: dict[str, Any]
    ) -> tuple[str, dict[str, Any], str, SupervisoryMetadata]:
        destination = str(operation.get("destination", "")).strip()
        if not destination:
            raise ActionAdapterError("external_upload requires a destination")
        secret = bool(operation.get("secret_material", False))
        novelty = "known" if destination in self.known_destinations else "novel"
        supervision = SupervisoryMetadata(
            reversibility="irreversible",
            private_to_public=True,
            destination_novelty=novelty,
            affected_parties=("external destination", "data subjects"),
        )
        if secret:
            action = "data.external_upload.secret"
            arguments = {
                "destination": destination,
                "secret_kind": str(operation.get("secret_kind", "credential")),
            }
            summary = f"send secret material to {destination}"
        else:
            action = "data.external_upload.repository"
            arguments = {"destination": destination}
            summary = f"upload repository data to {destination}"
        return action, arguments, summary, supervision

    def _normalize_payment(
        self, operation: dict[str, Any], facts: dict[str, Any]
    ) -> tuple[str, dict[str, Any], dict[str, Any], str, SupervisoryMetadata]:
        amount = int(operation.get("amount_cents", 0))
        vendor = str(operation.get("vendor", operation.get("provider", "")))
        if operation.get("funding") == "promotional":
            within = amount <= self.promo_budget_cents
            action = "money.promotional_credit.use"
            arguments = {
                "amount_cents": amount,
                "vendor": vendor,
                "path": self._workspace_path("credit", "usage"),
            }
            facts = {**facts, "promo.within_budget": within}
            summary = f"spend {amount}c promotional credit at {vendor}"
            supervision = SupervisoryMetadata(
                reversibility=self._reversibility(action),
                real_money=False,
                affected_parties=("promotional credit provider",),
            )
        else:
            action = "money.real_charge"
            arguments = {"amount_cents": amount, "vendor": vendor}
            summary = f"create a real-money charge of {amount}c at {vendor}"
            supervision = SupervisoryMetadata(
                reversibility=self._reversibility(action),
                real_money=True,
                affected_parties=("Matthew", "payment provider"),
            )
        return action, arguments, facts, summary, supervision
