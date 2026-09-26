"""Trusted host context: the facts real execution needs, never caller content.

Real effects need physical facts that an agent's operation document must never
choose. This module owns exactly one small immutable object holding them:

* the **physical repository root**;
* the **canonical project repository identity**;
* the **synthetic Permission Slip resource prefix** used to turn a physical
  path into the scoped authority identity Tethers evaluates;
* **trusted named test profiles** (argv vectors -- never caller commands);
* boring host metadata useful for diagnostics.

Two constructors exist and they mean different things:

``TrustedHostContext.create()``
    Fully validated. Proves the root is a Git checkout, that its configured
    push destination resolves to the doctrine's canonical repository, and that
    the resource prefix sits inside the doctrine's allowed prefix. This is the
    only constructor :class:`~permission_slip.host_executor.RealHostExecutor`
    will accept.

``TrustedHostContext.for_normalisation()``
    Trusted, but deliberately does **not** probe Git. It exists so the
    :class:`~permission_slip.actions.ActionAdapter` can be unit-tested against
    a plain directory. A context built this way sets ``verified_checkout`` to
    ``False`` and the real executor refuses it.

The resource mapping is **temporary infrastructure** until 0.8 provides
truthful first-class repository resource scope. ``path_prefix`` is not
repository scope and must never be described as such. What it *is* here is
deterministic and trustworthy:

* the physical root comes only from this object;
* caller content cannot retarget it;
* it is immutable for the lifetime of a Permission Slip session;
* its digest is recorded in observability.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from . import __version__

#: Scoped authority identity of the Permission Slip dogfood checkout. Sits
#: inside the doctrine's ``root_scope`` so an in-checkout edit is in scope.
RESOURCE_PREFIX_NAME = ("repos", "permission-slip")

#: Trusted named test profiles. The caller may name one of these; the caller
#: may never supply the command. Resolution happens through the trusted host
#: context both at normalisation and again immediately before process launch.
DEFAULT_TEST_PROFILES: dict[str, tuple[str, ...]] = {
    "permission-slip-full": (sys.executable, "-m", "unittest", "discover", "-s", "tests"),
    "permission-slip-doctrine": (
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        "test_doctrine*.py",
    ),
    "permission-slip-smoke": (sys.executable, "-m", "unittest", "tests.test_state_root"),
}


class HostContextError(RuntimeError):
    """Trusted host context could not be established. Fail closed."""


def command_digest(argv: tuple[str, ...]) -> str:
    """Identity of a trusted resolved argv vector.

    Encoded with Permission Slip Canonical JSON v1 so two hosts that resolve
    the same argv always agree on the digest that Tethers admitted.
    """
    from . import doctrine_contract

    return "sha256:" + hashlib.sha256(
        doctrine_contract.canonical_json_bytes(list(argv))
    ).hexdigest()


def _under(root: Path, resolved: Path) -> bool:
    try:
        return os.path.commonpath([str(root), str(resolved)]) == str(root)
    except ValueError:
        return False  # different drives on Windows: unambiguously outside


def _canonical_identity(target: Any) -> str | None:
    # Imported lazily: ``actions`` depends on this module, so this module must
    # not depend on ``actions`` at import time.
    from .actions import canonical_repository_identity

    return canonical_repository_identity(target)


def _git(repo_root: Path, *args: str, timeout: float = 20.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostContextError(f"git is unavailable for trusted host checks: {exc}") from None


@dataclass(frozen=True)
class TrustedHostContext:
    """Immutable trusted host facts for one Permission Slip session."""

    repo_root: Path
    canonical_repository: str
    resource_prefix: str
    root_scope: str
    test_profiles: tuple[tuple[str, tuple[str, ...]], ...]
    verified_checkout: bool
    host: tuple[tuple[str, str], ...]

    # -- construction ------------------------------------------------------

    @classmethod
    def for_normalisation(
        cls,
        *,
        repo_root: str | os.PathLike[str] | None,
        doctrine: Mapping[str, Any],
        test_profiles: Mapping[str, tuple[str, ...]] | None = None,
    ) -> "TrustedHostContext":
        """Trusted facts for **normalisation only**.

        No Git probe: this is enough to derive scope and command identity, and
        it is explicitly not accepted by the real executor.
        """
        return cls._build(
            repo_root=Path(repo_root or os.getcwd()).resolve(),
            doctrine=doctrine,
            test_profiles=test_profiles,
            verified_checkout=False,
        )

    @classmethod
    def create(
        cls,
        *,
        repo_root: str | os.PathLike[str],
        doctrine: Mapping[str, Any],
        test_profiles: Mapping[str, tuple[str, ...]] | None = None,
    ) -> "TrustedHostContext":
        """Fully validated trusted host context for **real execution**."""
        root = Path(repo_root).expanduser().resolve()
        if not root.is_dir():
            raise HostContextError(f"trusted repository root {root} is not a directory")

        context = cls._build(
            repo_root=root,
            doctrine=doctrine,
            test_profiles=test_profiles,
            verified_checkout=False,
        )
        cls._verify_checkout(root, context.canonical_repository)
        return replace(context, verified_checkout=True)

    @classmethod
    def _build(
        cls,
        *,
        repo_root: Path,
        doctrine: Mapping[str, Any],
        test_profiles: Mapping[str, tuple[str, ...]] | None,
        verified_checkout: bool,
    ) -> "TrustedHostContext":
        project = doctrine.get("project", {})
        root_scope = str(project.get("root_scope", "runtime/spike-workspace/"))
        canonical = _canonical_identity(project.get("canonical_repository", ""))
        if not canonical:
            raise HostContextError(
                "doctrine project.canonical_repository is not a canonical GitHub repository"
            )

        derived_prefix = root_scope.rstrip("/") + "/" + "/".join(RESOURCE_PREFIX_NAME) + "/"
        if not derived_prefix.startswith(root_scope):
            raise HostContextError(
                f"resource prefix {derived_prefix!r} is outside the doctrine root scope "
                f"{root_scope!r}"
            )

        profiles = DEFAULT_TEST_PROFILES if test_profiles is None else test_profiles
        if not profiles:
            raise HostContextError("trusted host context requires at least one test profile")
        frozen_profiles = tuple(
            (str(name), tuple(str(part) for part in argv))
            for name, argv in sorted(profiles.items())
        )
        for name, argv in frozen_profiles:
            if not name or not argv:
                raise HostContextError(f"test profile {name!r} is empty")

        host = (
            ("permission_slip_version", str(__version__)),
            ("python_version", sys.version.split()[0]),
            ("platform", sys.platform),
        )
        return cls(
            repo_root=repo_root,
            canonical_repository=canonical,
            resource_prefix=derived_prefix,
            root_scope=root_scope,
            test_profiles=frozen_profiles,
            verified_checkout=verified_checkout,
            host=host,
        )

    @staticmethod
    def _verify_checkout(root: Path, canonical: str) -> None:
        probe = _git(root, "rev-parse", "--git-dir")
        if probe.returncode != 0:
            raise HostContextError(f"trusted repository root {root} is not a Git checkout")

        remotes = _git(root, "remote")
        if remotes.returncode != 0:
            raise HostContextError("trusted repository remotes could not be read")
        names = [line.strip() for line in (remotes.stdout or "").splitlines() if line.strip()]
        if not names:
            raise HostContextError("trusted repository has no configured remote")

        seen: set[str] = set()
        for name in names:
            urls = _git(root, "remote", "get-url", "--push", "--all", name)
            if urls.returncode != 0:
                raise HostContextError(f"push destination for remote {name!r} is unreadable")
            for line in (urls.stdout or "").splitlines():
                value = line.strip()
                if not value:
                    continue
                identity = _canonical_identity(value)
                if identity is None:
                    raise HostContextError(
                        f"push destination {value!r} for remote {name!r} is not a "
                        "recognised canonical GitHub repository"
                    )
                if identity != canonical:
                    raise HostContextError(
                        f"push destination {value!r} resolves to {identity}, which is not "
                        f"the canonical project repository {canonical}"
                    )
                seen.add(value)
        if not seen:
            raise HostContextError("trusted repository has no usable push destination")

    # -- lookup ------------------------------------------------------------

    def resolve_test_profile(self, name: Any) -> tuple[str, ...]:
        if not isinstance(name, str):
            raise HostContextError(f"unknown trusted test profile {name!r}")
        for candidate, argv in self.test_profiles:
            if candidate == name:
                return argv
        known = ", ".join(candidate for candidate, _ in self.test_profiles)
        raise HostContextError(f"unknown trusted test profile {name!r}; known: {known}")

    @property
    def test_profile_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.test_profiles)

    # -- resource mapping --------------------------------------------------

    def authority_path(self, physical: str | os.PathLike[str]) -> str:
        """Scoped authority identity of a physical path.

        Inside the trusted root this is ``resource_prefix + relative path``.
        Outside it, the true out-of-scope relative form is preserved (leading
        ``..`` intact) so scope evaluation denies it -- an out-of-root path is
        never rewritten into an apparently in-scope identity.
        """
        root = Path(os.path.realpath(str(self.repo_root)))
        candidate = os.fspath(physical)
        if not os.path.isabs(candidate):
            # A relative request is relative to the trusted root, never to the
            # process working directory.
            candidate = os.path.join(str(root), candidate)
        resolved = Path(os.path.realpath(candidate))
        if _under(root, resolved):
            relative = os.path.relpath(str(resolved), str(root)).replace("\\", "/")
            return self.resource_prefix + relative
        try:
            return os.path.relpath(str(resolved), str(root)).replace("\\", "/")
        except ValueError:  # pragma: no cover - different drive on Windows
            return str(resolved).replace("\\", "/")

    def physical_path(self, authority: Any) -> Path:
        """Inverse of :meth:`authority_path`, refusing anything that escapes."""
        if not isinstance(authority, str) or not authority.startswith(self.resource_prefix):
            raise HostContextError(
                f"{authority!r} is not inside the trusted resource prefix "
                f"{self.resource_prefix!r}"
            )
        relative = authority[len(self.resource_prefix):]
        if not relative or relative.startswith(("/", "\\")):
            raise HostContextError(f"{authority!r} does not name a file inside the checkout")
        if ".." in Path(relative).parts:
            raise HostContextError(f"{authority!r} contains a traversal segment")
        root = Path(os.path.realpath(str(self.repo_root)))
        resolved = Path(os.path.realpath(str(root / relative)))
        if not _under(root, resolved) or resolved == root:
            raise HostContextError(f"{authority!r} escapes the trusted repository root")
        return resolved

    # -- identity ----------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        """Safe structured facts. Local evidence only; never portable authority."""
        return {
            "repo_root": str(self.repo_root),
            "canonical_repository": self.canonical_repository,
            "resource_prefix": self.resource_prefix,
            "root_scope": self.root_scope,
            "test_profiles": {name: list(argv) for name, argv in self.test_profiles},
            "verified_checkout": self.verified_checkout,
            "host": dict(self.host),
        }

    def digest(self) -> str:
        payload = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "DEFAULT_TEST_PROFILES",
    "HostContextError",
    "TrustedHostContext",
    "command_digest",
]
