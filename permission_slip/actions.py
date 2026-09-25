"""Trusted action adapter: the trust boundary.

This module is the only place where an agent's raw request becomes
authority-relevant facts. It is deliberately untrusting of the caller.

Law it enforces:

    Caller content describes requested work.
    Trusted harness context establishes who is acting.
    Trusted normalization establishes what the operation actually does.
    Tethers alone establishes whether it is authorised.

Concretely:

* actor identity comes from a **trusted harness/session context** passed to
  ``normalize``, never from the operation document;
* authority-relevant facts are **derived from the actual operation**, never
  read from a model-supplied label;
* caller-supplied authority booleans (``permission``, ``trusted``,
  ``approved``, ``granted``, ``actor``, ...) are ignored, not honoured;
* when a consequential consequence cannot be safely established, the adapter
  fails closed rather than guessing.

The output is a :class:`NormalizedAction`: a semantic capability plus resolved
arguments and trusted facts. Permission Slip does not decide ALLOW / ASK / DENY
here; it prepares the exact input Tethers will decide on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Keys a caller might use to try to manufacture authority or identity. They are
# never read. ``actor`` is included: identity is not caller-selectable.
FORBIDDEN_CALLER_KEYS = (
    "actor",
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

PROTECTED_BRANCHES = {"main", "master", "trunk", "release"}

# Positive-evidence namespace for standing ``git.push.feature`` authority.
# A destination must be *inside* this namespace to be admitted at all; a
# destination that is merely absent from ``PROTECTED_BRANCHES`` is not enough.
FEATURE_NAMESPACE = "feature/"

# Characters git itself refuses in a ref name. Used so that a hostile-looking
# destination cannot be smuggled through the positive feature check.
_REF_FORBIDDEN = frozenset("~^:?*[\\ @{}")

# Push options that consume the following token as their value.
_PUSH_VALUE_OPTIONS = {"--repo", "--receive-pack", "--exec", "--push-option", "-o"}
# Push options that are inherently broad / destructive.
_BROAD_PUSH_FLAGS = {"--all", "--mirror", "--branches", "--tags", "--delete", "--prune", "-d"}
# Push options positively recognised as safe: non-force, non-deleting and
# non-retargeting. Everything else is unrecognised and fails closed.
_SAFE_PUSH_FLAGS = frozenset(
    {
        "--set-upstream",
        "--verbose",
        "--quiet",
        "--progress",
        "--no-thin",
        "--atomic",
        "--follow-tags",
        "--ipv4",
        "--ipv6",
    }
)
# Push options that change *where* the push lands or *what* runs on the far
# side, so the adapter's trusted ``repository`` argument would stop being
# truthful.
_RETARGET_PUSH_OPTIONS = frozenset({"--repo", "--exec", "--receive-pack"})
# Short single-dash options git push accepts. ``o`` is excluded: it takes a
# value and is handled separately.
_SAFE_SHORT_PUSH_FLAGS = frozenset("fduvqn")


class ActionAdapterError(ValueError):
    """The operation could not be normalised into a trusted semantic action."""


class UntrustedActorError(ActionAdapterError):
    """The trusted context names an actor absent from the harness profile."""


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


def _under_root(root: str, resolved: str) -> bool:
    """True when ``resolved`` is the same as or beneath ``root`` (ancestry)."""
    try:
        return os.path.commonpath([root, resolved]) == root
    except ValueError:
        # Different drives on Windows: unambiguously outside.
        return False


def _strip_heads(ref: str) -> str:
    prefix = "refs/heads/"
    return ref[len(prefix):] if ref.startswith(prefix) else ref


def classify_push_refspec(refspec: str) -> tuple[bool, str | None]:
    """Classify one push refspec.

    Returns ``(consequential, destination_label)``. ``destination_label`` is the
    branch name when it can be established, otherwise ``None``.

    The parser is intentionally small and conservative. It is not a full Git
    refspec grammar; anything it cannot safely establish is treated as
    consequential so it never silently becomes an ordinary feature push.
    """
    forced = False
    if refspec.startswith("+"):
        forced = True
        refspec = refspec[1:]

    if ":" in refspec:
        source, destination = refspec.split(":", 1)
        if source == "":
            # Remote ref deletion (``git push origin :branch``).
            return True, None
        if "*" in source:
            # Wildcard source: a wildcard push, never a single ordinary branch.
            return True, None
    else:
        destination = refspec

    if destination == "":
        # Remote ref deletion (``git push origin :branch``): consequential and
        # not a feature push.
        return True, None

    if destination in ("HEAD", "@") or "*" in destination:
        return True, None

    if destination.startswith("refs/heads/"):
        name = _strip_heads(destination)
    elif destination.startswith("refs/"):
        # Tags and other ref namespaces are not feature-branch pushes.
        return True, None
    else:
        name = destination

    if name == "":
        return True, None

    if forced or name in PROTECTED_BRANCHES:
        return True, name
    return False, name


def feature_branch_destination(label: str | None) -> str | None:
    """Positive evidence that a push destination sits inside ``feature/*``.

    Returns the destination label when the destination is *affirmatively* a
    feature-branch name, otherwise ``None``.

    This is an allow-list, not a deny-list: standing ``git.push.feature``
    authority exists only because the destination can be positively shown to be
    in the feature namespace. A destination that is merely unknown or absent
    from :data:`PROTECTED_BRANCHES` produces no evidence and therefore no
    standing authority.
    """
    if not isinstance(label, str) or not label.startswith(FEATURE_NAMESPACE):
        return None

    rest = label[len(FEATURE_NAMESPACE):]
    if not rest:
        return None
    # Refuse anything git would itself reject, so a hostile destination cannot
    # masquerade as a feature branch name.
    if ".." in rest or "//" in rest or "@{" in rest:
        return None
    if rest.startswith(("/", ".")) or rest.endswith(("/", ".")):
        return None
    if rest.endswith(".lock"):
        return None
    if any(ch in _REF_FORBIDDEN or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in rest):
        return None
    return label


def parse_push(args: list[str]) -> dict[str, Any]:
    """Parse ``git push`` arguments (excluding the subcommand).

    Returns ``{"force": bool, "broad": bool, "refspecs": [...], "ambiguous":
    bool}``.

    ``ambiguous`` is true when the push is not *positively* established as a
    single ordinary refspec with every token recognised. That includes an
    unrecognised push option: standing feature authority is granted only on
    positive evidence, never because nothing dangerous was spotted.
    """
    force = False
    broad = False
    unrecognised = False
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1:])
            break
        if token.startswith("-") and token != "-":
            if token.startswith("--"):
                name, separator, _inline = token.partition("=")
                # Every force form, including git's unambiguous abbreviations
                # such as ``--force-with-leas``.
                if name.startswith("--force"):
                    force = True
                elif name in _BROAD_PUSH_FLAGS:
                    broad = True
                elif name in _RETARGET_PUSH_OPTIONS:
                    if not separator:
                        index += 1  # consume the option's value
                    unrecognised = True
                elif name in _PUSH_VALUE_OPTIONS:
                    if not separator:
                        index += 1  # consume the option's value
                elif name in _SAFE_PUSH_FLAGS:
                    pass
                else:
                    unrecognised = True
            else:
                cluster = token[1:]
                if cluster[:1] == "o":
                    # ``-o`` / ``-ovalue`` (push-option) takes a value.
                    if cluster == "o":
                        index += 1
                else:
                    if set(cluster) - _SAFE_SHORT_PUSH_FLAGS:
                        unrecognised = True
                    if "f" in cluster:
                        force = True  # covers combined short flags such as ``-fu``
                    if "d" in cluster:
                        broad = True
            index += 1
            continue
        positionals.append(token)
        index += 1

    # First positional (when two or more exist) is the repository.
    refspecs = positionals[1:] if len(positionals) >= 2 else []
    ambiguous = len(refspecs) != 1 or unrecognised
    return {"force": force, "broad": broad, "refspecs": refspecs, "ambiguous": ambiguous}


class ActionAdapter:
    def __init__(self, doctrine: dict[str, Any], repo_root: str | os.PathLike[str] | None = None):
        self.doctrine = doctrine
        self.repo_root = os.path.realpath(repo_root or os.getcwd())
        project = doctrine.get("project", {})
        self.root_scope = project.get("root_scope", "runtime/spike-workspace/")
        credit = doctrine.get("boundaries", {}).get("promotional_credit", {})
        # v0.1 enforces a *per-call* limit only. There is no cumulative ledger
        # and this value must never be described as an overall budget.
        self.promo_per_call_limit_cents = int(credit.get("per_call_limit_cents", 0))
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

    def resolve_actor(self, actor_id: Any) -> dict[str, Any]:
        """Resolve a trusted actor from harness/session context only."""
        if not isinstance(actor_id, str) or actor_id not in self.actors:
            raise UntrustedActorError(
                f"trusted actor {actor_id!r} is not in the harness profile"
            )
        return self.actors[actor_id]

    @staticmethod
    def _caller_claims(operation: dict[str, Any]) -> tuple[str, ...]:
        return tuple(sorted(key for key in FORBIDDEN_CALLER_KEYS if key in operation))

    def _reversibility(self, action: str) -> str:
        for capability in self.doctrine.get("capabilities", []):
            if capability["action"] == action:
                return capability.get("reversibility", "unknown")
        return "unknown"

    def _canonical_project_path(self, requested: Any) -> str:
        """Canonicalise a requested path against the trusted project root.

        Traversal is resolved against the real root. A path that escapes the
        root is returned in its true out-of-scope relative form (leading
        ``..`` segments preserved) or as an absolute path; it is never rewritten
        into an apparently in-scope path.
        """
        requested = str(requested)
        root = os.path.realpath(self.repo_root)
        if os.path.isabs(requested):
            resolved = os.path.realpath(requested)
        else:
            resolved = os.path.realpath(os.path.join(root, requested))
        if _under_root(root, resolved):
            return os.path.relpath(resolved, root).replace("\\", "/")
        # Outside the trusted root: preserve the true out-of-scope identity,
        # with traversal segments intact so scope evaluation denies it.
        try:
            return os.path.relpath(resolved, root).replace("\\", "/")
        except ValueError:
            # Different drive on Windows: preserve the absolute form.
            return resolved.replace("\\", "/")

    # -- normalisation -----------------------------------------------------

    def normalize(self, operation: dict[str, Any], actor_id: Any) -> NormalizedAction:
        """Normalise an untrusted operation under a trusted actor context.

        ``actor_id`` must come from trusted harness/session code. Any ``actor``
        field inside ``operation`` is caller content and is ignored.
        """
        if not isinstance(operation, dict):
            raise ActionAdapterError("operation envelope must be an object")
        actor = self.resolve_actor(actor_id)
        claims = self._caller_claims(operation)
        tool = operation.get("tool")
        facts = self._actor_facts(actor)

        if tool == "git":
            action, arguments, summary, supervision = self._normalize_git(operation)
        elif tool == "tests":
            action = "dev.tests.run"
            arguments = {"path": self._workspace_path("tests.log")}
            summary = "run the project test suite"
            supervision = SupervisoryMetadata(reversibility=self._reversibility(action))
        elif tool == "edit_file":
            action = "project.files.edit"
            arguments = {"path": self._canonical_project_path(operation.get("path", ""))}
            summary = f"edit {arguments['path']}"
            supervision = SupervisoryMetadata(reversibility=self._reversibility(action))
        elif tool == "external_upload":
            action, arguments, summary, supervision = self._normalize_upload(operation)
        elif tool == "payment":
            action, arguments, facts, summary, supervision = self._normalize_payment(operation, facts)
        elif tool == "publish":
            action = "identity.public_publish"
            arguments = {"channel": str(operation.get("channel", ""))}
            summary = f"publish to {arguments['channel']} as {actor['id']}"
            supervision = SupervisoryMetadata(
                reversibility=self._reversibility(action),
                private_to_public=True,
                affected_parties=(actor["id"], "public"),
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
        self, operation: dict[str, Any]
    ) -> tuple[str, dict[str, Any], str, SupervisoryMetadata]:
        argv = operation.get("argv")
        if not isinstance(argv, list) or not argv:
            raise ActionAdapterError("git operation requires a non-empty argv list")
        argv = [str(item) for item in argv]
        subcommand = argv[0].lower()
        repo = self._repo_path()

        if subcommand == "push":
            parsed = parse_push(argv[1:])
            refspecs = parsed["refspecs"]
            forced = bool(parsed["force"])
            broad = bool(parsed["broad"])
            ambiguous = bool(parsed["ambiguous"])

            if not ambiguous:
                consequential, destination = classify_push_refspec(refspecs[0])
            else:
                consequential, destination = True, None

            if consequential or forced or broad or ambiguous:
                action = "git.history.rewrite"
                if destination:
                    summary = f"rewrite public history on {destination}"
                elif ambiguous or broad:
                    summary = "push with an ambiguous or broad refspec (failing closed)"
                else:
                    summary = "rewrite public history"
                supervision = SupervisoryMetadata(
                    reversibility=self._reversibility(action),
                    private_to_public=True,
                    affected_parties=("repository collaborators", "public"),
                )
            else:
                # Standing authority requires *positive* evidence that the
                # destination is inside feature/*. Anything else is unmappable
                # and fails closed rather than borrowing standing authority.
                feature = feature_branch_destination(destination)
                if feature is None:
                    raise ActionAdapterError(
                        "git push destination "
                        f"{destination!r} is not inside the {FEATURE_NAMESPACE!r} "
                        "namespace, so it is not mappable to git.push.feature"
                    )
                action = "git.push.feature"
                summary = f"push feature branch {feature}"
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

    @staticmethod
    def _parse_amount_cents(raw: Any) -> int:
        """Parse a caller-supplied amount strictly.

        A boolean, float, string, or missing amount is malformed for an
        integer-cents capability and fails closed instead of coercing into an
        amount that could sit inside a bound.
        """
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ActionAdapterError(
                "payment amount_cents must be an integer number of cents"
            )
        return raw

    def _promotional_within_bound(self, vendor: str, amount: int) -> bool:
        """Positive evidence that this exact charge may use promotional credit.

        v0.1 proves a **per-call** limit only. There is no cumulative ledger,
        so every clause must be independently true for this call:

        * the configured provider is present and the operation's vendor is it;
        * the amount is strictly positive;
        * the amount is within the configured per-call limit.

        Anything else is not evidence, and the fact stays false.
        """
        if not self.promo_provider or vendor != self.promo_provider:
            return False
        if amount <= 0:
            return False
        return amount <= self.promo_per_call_limit_cents

    def _normalize_payment(
        self, operation: dict[str, Any], facts: dict[str, Any]
    ) -> tuple[str, dict[str, Any], dict[str, Any], str, SupervisoryMetadata]:
        amount = self._parse_amount_cents(operation.get("amount_cents"))
        vendor = str(operation.get("vendor", operation.get("provider", "")))
        if operation.get("funding") == "promotional":
            action = "money.promotional_credit.use"
            arguments = {
                "amount_cents": amount,
                "vendor": vendor,
                "path": self._workspace_path("credit", "usage"),
            }
            facts = {**facts, "promo.within_bound": self._promotional_within_bound(vendor, amount)}
            summary = (
                f"spend {amount}c promotional credit at {vendor} "
                f"(per-call limit {self.promo_per_call_limit_cents}c)"
            )
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
