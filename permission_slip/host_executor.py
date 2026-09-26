"""The real host executor: narrow, explicit, and only what Tethers admitted.

This is the first Permission Slip executor that touches the physical world. It
is deliberately *not* a general host runner:

* no shell, ever -- every effect is an ``argv`` vector with ``shell=False``;
* no caller-supplied command -- test runs resolve a **trusted named profile**
  from :mod:`permission_slip.host_context` and re-derive its digest before the
  process starts;
* the executor consumes **only** the effect that was normalised and admitted.
  It never re-reads the raw caller request, a remote alias, a ref label or an
  absolute path after COMMIT;
* unsupported real effects fail closed instead of pretending.

``FixtureExecutor`` remains the default everywhere. Selecting this class is an
explicit constructor decision.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .actions import MISSING_FILE_DIGEST, NormalizedAction, canonical_repository_identity
from .executor import (
    STATUS_FAILED,
    STATUS_SUCCEEDED,
    ExecutorResult,
)
from .host_context import HostContextError, TrustedHostContext, command_digest

#: Effects 0.4A is willing to perform physically. Everything else -- history
#: rewrite, public publication, external upload, secret upload, money,
#: promotional credit -- fails closed with a clear unsupported-real-effect
#: result and never writes a marker pretending otherwise.
SUPPORTED_REAL_EFFECTS = frozenset(
    {
        "dev.tests.run",
        "project.files.edit",
        "git.push.feature",
        "git.merge.accepted",
    }
)

#: Default ceiling on one physical subprocess. A hanging test suite or a stuck
#: Git remote must produce a truthful ``uncertain`` outcome, not a wedged host.
DEFAULT_TIMEOUT_SECONDS = 900.0


class HostExecutionFailure(RuntimeError):
    """Real execution refused, or the physical effect did not succeed."""

    def __init__(self, message: str, *, uncertain: bool = False):
        super().__init__(message)
        self.uncertain = uncertain


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _body_evidence(prefix: str, payload: bytes) -> dict[str, Any]:
    """Fingerprint a subprocess body. The body itself is never persisted."""
    return {
        f"{prefix}_sha256": _sha256(payload),
        f"{prefix}_bytes": len(payload),
    }


class RealHostExecutor:
    """Performs exactly one of the four narrow 0.4A effects, truthfully."""

    #: Selection marker. ``FixtureExecutor.is_real`` is ``False``; the
    #: orchestration layer and the tests both assert on it.
    is_real = True

    def __init__(
        self,
        host_context: TrustedHostContext,
        *,
        recorder: Any = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        if not isinstance(host_context, TrustedHostContext):  # pragma: no cover
            raise HostContextError("real execution requires a trusted host context")
        if not host_context.verified_checkout:
            raise HostContextError(
                "real execution requires a fully validated trusted host context "
                "(Git checkout with a canonical push destination)"
            )
        if recorder is None or not getattr(recorder, "writable", False):
            # "No recorder: no real effect." Established before anything can
            # physically happen, not after.
            raise HostContextError(
                "real execution requires a writable trace/run recorder"
            )
        self.host_context = host_context
        self.recorder = recorder
        self.timeout_seconds = timeout_seconds

    # -- shared ------------------------------------------------------------

    def _run(self, argv: list[str], *, cwd: Path | None = None) -> tuple[int, bytes, bytes, float]:
        """Launch one argv vector with no shell and capture fingerprinted output."""
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HostExecutionFailure(
                f"{' '.join(argv[:3])} exceeded {self.timeout_seconds:g}s", uncertain=True
            ) from None
        except OSError as exc:
            raise HostExecutionFailure(f"could not launch process: {exc}", uncertain=True) from None
        duration_ms = int((time.monotonic() - started) * 1000)
        return completed.returncode, completed.stdout or b"", completed.stderr or b"", duration_ms

    @staticmethod
    def _git(root: Path, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            shell=False,
            timeout=timeout,
            check=False,
        )

    # -- dispatch ----------------------------------------------------------

    def execute(
        self, normalized: NormalizedAction, *, simulate_failure: bool = False
    ) -> ExecutorResult:
        action = normalized.action
        if action not in SUPPORTED_REAL_EFFECTS:
            # Fail closed and say so plainly. No marker, no simulation, no
            # claim that anything happened.
            return ExecutorResult(
                action=action,
                ok=False,
                output={"ok": False},
                effects=[],
                external_execution_identity=f"real-refused-{_sha256(action.encode())[:12]}",
                status=STATUS_FAILED,
                executed=False,
                detail={
                    "executor": "real-host",
                    "reason": "unsupported_real_effect",
                    "supported": sorted(SUPPORTED_REAL_EFFECTS),
                },
            )

        if simulate_failure:
            # Test seam: refuse *before* any physical effect, so the reported
            # failure is truthful rather than fabricated.
            raise HostExecutionFailure(f"simulated physical failure for {action}")

        if not getattr(self.recorder, "writable", False):
            raise HostContextError(
                "real execution requires a writable trace/run recorder"
            )

        if action == "dev.tests.run":
            result = self._run_tests(normalized)
        elif action == "project.files.edit":
            result = self._edit_file(normalized)
        elif action == "git.push.feature":
            result = self._push_feature(normalized)
        else:
            result = self._merge_accepted(normalized)

        self.recorder.note_physical_effect(
            action=action, status=result.status, detail=dict(result.detail)
        )
        return result

    # -- real effect 1: trusted test profiles ------------------------------

    def _run_tests(self, normalized: NormalizedAction) -> ExecutorResult:
        args = normalized.arguments
        profile = args["test_profile"]
        try:
            argv = self.host_context.resolve_test_profile(profile)
        except HostContextError as exc:
            raise HostExecutionFailure(str(exc)) from None

        # Re-resolve immediately before launch and require equality with what
        # Tethers admitted. Drift here means the admitted command is not the
        # command about to run, so we stop.
        rederived = command_digest(argv)
        if rederived != args["command_digest"]:
            raise HostExecutionFailure(
                f"trusted test profile {profile!r} drifted after admission"
            )

        exit_code, stdout, stderr, duration_ms = self._run(
            list(argv), cwd=self.host_context.repo_root
        )
        detail = {
            "executor": "real-host",
            "test_profile": profile,
            "command_digest": rederived,
            "cwd": str(self.host_context.repo_root),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            **_body_evidence("stdout", stdout),
            **_body_evidence("stderr", stderr),
        }
        status = STATUS_SUCCEEDED if exit_code == 0 else STATUS_FAILED
        return ExecutorResult(
            action=normalized.action,
            ok=status == STATUS_SUCCEEDED,
            output={"ok": status == STATUS_SUCCEEDED},
            effects=[f"tests-ran:{profile}"],
            external_execution_identity=f"real-tests-{rederived[7:19]}",
            status=status,
            executed=True,
            detail=detail,
        )

    # -- real effect 2: exact file replacement -----------------------------

    def _edit_file(self, normalized: NormalizedAction) -> ExecutorResult:
        args = normalized.arguments
        payload = normalized.execution_payload
        if payload is None:
            raise HostExecutionFailure("edit payload was not carried with the admitted action")
        if len(payload) != int(args["content_bytes"]):
            raise HostExecutionFailure("edit payload length does not match admitted content_bytes")
        if _sha256(payload) != args["after_digest"]:
            # The payload changed after COMMIT. Never write it.
            raise HostExecutionFailure("edit payload digest does not match admitted after_digest")

        target = self._resolve_target(args["path"])
        if self._is_link(target):
            raise HostExecutionFailure(
                f"refusing to replace a symlink or junction target {args['path']}"
            )

        before = self._digest_of(target)
        if before != args["before_digest"]:
            # The file moved under us between PREPARE and the write. Do not
            # merge, do not overwrite, do not helpfully reconcile.
            raise HostExecutionFailure(
                "file changed after COMMIT "
                f"(admitted {args['before_digest']}, found {before})"
            )

        if not target.parent.is_dir():
            raise HostExecutionFailure(
                f"parent directory of {args['path']} does not exist; 0.4A does not "
                "create directory trees"
            )

        self._atomic_write(target, payload)
        return ExecutorResult(
            action=normalized.action,
            ok=True,
            output={"ok": True},
            effects=[f"edited:{args['path']}"],
            external_execution_identity=f"real-edit-{args['after_digest'][7:19]}",
            status=STATUS_SUCCEEDED,
            executed=True,
            detail={
                "executor": "real-host",
                "path": args["path"],
                "before_digest": before,
                "after_digest": args["after_digest"],
                "content_bytes": args["content_bytes"],
            },
        )

    def _resolve_target(self, authority: str) -> Path:
        try:
            physical = self.host_context.physical_path(authority)
        except HostContextError as exc:
            raise HostExecutionFailure(str(exc)) from None
        # ``physical_path`` already confines after resolving symlinks; check the
        # un-resolved spelling too so a link is refused *as a link* rather than
        # silently followed. Junctions are reparse points with the same effect.
        prefix = self.host_context.resource_prefix
        if isinstance(authority, str) and authority.startswith(prefix):
            unresolved = self.host_context.repo_root / authority[len(prefix):]
            if self._is_link(unresolved):
                raise HostExecutionFailure(
                    f"refusing to replace a symlink or junction target {authority}"
                )
        return physical

    @staticmethod
    def _is_link(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction()) if callable(is_junction) else False

    @staticmethod
    def _digest_of(path: Path) -> str:
        try:
            return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        except (FileNotFoundError, NotADirectoryError):
            return MISSING_FILE_DIGEST
        except OSError as exc:  # pragma: no cover - defensive
            raise HostExecutionFailure(f"cannot read {path}: {exc}", uncertain=True) from None

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        """Temp file in the same directory, fsync, then ``os.replace``."""
        handle, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
        temp_path = Path(temp_name)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        except OSError as exc:
            try:
                temp_path.unlink()
            except OSError:
                pass
            raise HostExecutionFailure(f"atomic replace failed: {exc}") from None

    # -- real effect 3: ordinary feature push ------------------------------

    def push_argv(self, normalized: NormalizedAction) -> list[str]:
        """The exact production push command, derived only from admitted identity.

        Exposed so tests can assert command construction without a network.
        """
        args = normalized.arguments
        transport = normalized.sealed_transport
        if not isinstance(transport, str) or not transport:
            raise HostExecutionFailure("push transport was not carried with the admitted action")
        identity = canonical_repository_identity(transport)
        if identity is None or identity != args["remote_repository"]:
            # Sealed transport does not name the admitted repository: refuse
            # rather than push somewhere the Gate never evaluated.
            raise HostExecutionFailure(
                "sealed transport does not match the admitted remote repository"
            )
        if _sha256(transport.encode("utf-8")) != args["remote_transport_digest"]:
            raise HostExecutionFailure("sealed transport digest does not match admission")
        return [
            "git",
            "-C",
            str(self.host_context.repo_root),
            "push",
            transport,
            f"{args['source_commit']}:{args['destination_ref']}",
        ]

    def _push_feature(self, normalized: NormalizedAction) -> ExecutorResult:
        args = normalized.arguments
        root = self.host_context.repo_root
        argv = self.push_argv(normalized)

        # The source must still be the commit that was admitted.
        probe = self._git(root, "cat-file", "-e", f"{args['source_commit']}")
        if probe.returncode != 0:
            raise HostExecutionFailure("admitted source commit no longer exists")

        exit_code, stdout, stderr, duration_ms = self._run(argv, cwd=root)
        detail = {
            "executor": "real-host",
            "repository": args["repository"],
            "remote_repository": args["remote_repository"],
            "source_commit": args["source_commit"],
            "destination_ref": args["destination_ref"],
            "remote_transport_digest": args["remote_transport_digest"],
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            **_body_evidence("stdout", stdout),
            **_body_evidence("stderr", stderr),
        }
        status = STATUS_SUCCEEDED if exit_code == 0 else STATUS_FAILED
        return ExecutorResult(
            action=normalized.action,
            ok=status == STATUS_SUCCEEDED,
            output={"ok": status == STATUS_SUCCEEDED},
            effects=[f"pushed:{args['destination_ref']}"],
            external_execution_identity=f"real-push-{args['source_commit'][:12]}",
            status=status,
            executed=True,
            detail=detail,
        )

    # -- real effect 4: accepted fast-forward merge ------------------------

    def _merge_accepted(self, normalized: NormalizedAction) -> ExecutorResult:
        args = normalized.arguments
        root = self.host_context.repo_root

        head = self._git(root, "rev-parse", "HEAD")
        if head.returncode != 0 or (head.stdout or b"").strip().decode() != args["target_commit"]:
            raise HostExecutionFailure("HEAD moved since PREPARE; refusing to merge")
        ref = self._git(root, "symbolic-ref", "--quiet", "HEAD")
        if ref.returncode != 0 or (ref.stdout or b"").strip().decode() != args["target_ref"]:
            raise HostExecutionFailure("current branch changed since PREPARE; refusing to merge")
        if self._git(root, "cat-file", "-e", args["source_commit"]).returncode != 0:
            raise HostExecutionFailure("admitted source commit no longer exists")

        argv = ["git", "-C", str(root), "merge", "--ff-only", args["source_commit"]]
        exit_code, stdout, stderr, duration_ms = self._run(argv, cwd=root)
        detail = {
            "executor": "real-host",
            "repository": args["repository"],
            "source_commit": args["source_commit"],
            "target_commit": args["target_commit"],
            "target_ref": args["target_ref"],
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            **_body_evidence("stdout", stdout),
            **_body_evidence("stderr", stderr),
        }
        # A non-fast-forward, conflict or lock failure is a truthful failure.
        # There is no fallback to a merge commit and no editor.
        status = STATUS_SUCCEEDED if exit_code == 0 else STATUS_FAILED
        return ExecutorResult(
            action=normalized.action,
            ok=status == STATUS_SUCCEEDED,
            output={"ok": status == STATUS_SUCCEEDED},
            effects=[f"merged:{args['source_commit'][:12]}"],
            external_execution_identity=f"real-merge-{args['source_commit'][:12]}",
            status=status,
            executed=True,
            detail=detail,
        )


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "HostExecutionFailure",
    "RealHostExecutor",
    "SUPPORTED_REAL_EFFECTS",
]
