"""``tethers.authority/1`` stdio client.

Permission Slip interacts with the Tethers Authority Gate as an external
process over NDJSON on stdin/stdout. The real public seam is exercised; no
private Tethers Rust module is imported.

This module also verifies that the Tethers checkout/binary in use corresponds
to the expected R2 lineage. A mismatch is visible and fails closed unless the
developer sets ``TETHERS_ALLOW_SHA_MISMATCH=1``.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AUTHORITY_SCHEMA = "tethers.authority/1"
REQUIRED_TETHERS_SHA = "7e29110319c554a6586865ec6c47a45498696d16"
# From the frozen R2 gate artifact (verification/r2-gate-artifact.json).
EXPECTED_ENGINE_SHA256 = "6eef27224dd7def709a776837a5444826452125baa83dcfb31c59458749f437f"


class TethersUnavailable(RuntimeError):
    """The Tethers Gate or engine could not be located or started."""


class TethersVersionMismatch(TethersUnavailable):
    """The Tethers checkout does not match the required R2 lineage."""


class GateError(RuntimeError):
    """A structured ``tethers.authority/1`` error response."""

    def __init__(self, code: str, message: str, data: Any = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass
class TethersPaths:
    root: Path | None
    gate_bin: Path
    engine_bin: Path
    actual_sha: str | None
    required_sha: str
    verification: str
    gate_sha256: str
    engine_sha256: str
    engine_matches_artifact: bool


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    env = os.environ.get("TETHERS_ROOT")
    if env:
        roots.append(Path(env))
    roots.append(Path(".deps") / "tethers")
    roots.append(Path(r"D:\tethers-lang"))
    return roots


def _resolve_bin(env_var: str, candidates: list[Path]) -> Path | None:
    env = os.environ.get(env_var)
    if env:
        path = Path(env)
        if not path.is_file():
            raise TethersUnavailable(f"{env_var} does not point to a file: {path}")
        return path.resolve()
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def discover_tethers(required_sha: str = REQUIRED_TETHERS_SHA) -> TethersPaths:
    root: Path | None = None
    for candidate in _candidate_roots():
        if candidate.is_dir():
            root = candidate.resolve()
            if os.environ.get("TETHERS_ROOT") or candidate.is_dir():
                break

    gate_candidates: list[Path] = []
    engine_candidates: list[Path] = []
    if root is not None:
        gate_candidates += [
            root / "tethers-0.1" / "host-rust" / "target" / "release" / "tethers.exe",
            root / "tethers-0.1" / "host-rust" / "target" / "debug" / "tethers.exe",
            root / "tethers-0.1" / "host-rust" / "target" / "release" / "tethers",
            root / "tethers-0.1" / "host-rust" / "target" / "debug" / "tethers",
        ]
        engine_candidates += [
            root
            / "tethers-0.1"
            / "engine-ocaml"
            / "_build"
            / "default"
            / "bin"
            / "tethers_mcp_main.exe",
            root
            / "tethers-0.1"
            / "engine-ocaml"
            / "_build"
            / "default"
            / "bin"
            / "tethers_mcp_main",
        ]

    gate_bin = _resolve_bin("TETHERS_GATE_BIN", gate_candidates)
    engine_bin = _resolve_bin("TETHERS_ENGINE_BIN", engine_candidates)
    if gate_bin is None:
        raise TethersUnavailable(
            "Tethers Gate binary not found. Set TETHERS_GATE_BIN or build "
            "tethers-0.1/host-rust (see scripts/bootstrap-tethers.ps1)."
        )
    if engine_bin is None:
        raise TethersUnavailable(
            "Tethers Core engine not found. Set TETHERS_ENGINE_BIN (e.g. the "
            "engine-ocaml tethers_mcp_main build output)."
        )

    actual_sha: str | None = None
    verification = "unverified"
    override = os.environ.get("TETHERS_ALLOW_SHA_MISMATCH") == "1"
    if root is not None and (root / ".git").exists():
        head = _git(root, "rev-parse", "HEAD")
        if head.returncode == 0:
            actual_sha = head.stdout.strip()
        if actual_sha:
            if actual_sha == required_sha:
                verification = "exact"
            else:
                diff = _git(root, "diff", "--quiet", required_sha, actual_sha)
                if diff.returncode == 0:
                    verification = "tree_equivalent"
                elif override:
                    verification = "override"
                else:
                    raise TethersVersionMismatch(
                        "Tethers checkout "
                        f"{actual_sha} is not lineage-compatible with required R2 "
                        f"merge {required_sha}. Set TETHERS_ALLOW_SHA_MISMATCH=1 "
                        "to override visibly."
                    )

    engine_sha = _sha256_file(engine_bin)
    return TethersPaths(
        root=root,
        gate_bin=gate_bin,
        engine_bin=engine_bin,
        actual_sha=actual_sha,
        required_sha=required_sha,
        verification=verification,
        gate_sha256=_sha256_file(gate_bin),
        engine_sha256=engine_sha,
        engine_matches_artifact=engine_sha == EXPECTED_ENGINE_SHA256,
    )


class GateSession:
    """A single persistent ``tethers gate --stdio`` session."""

    def __init__(
        self,
        config_path: str | os.PathLike[str],
        trail_path: str | os.PathLike[str],
        host_data_root: str | os.PathLike[str],
        paths: TethersPaths | None = None,
    ):
        self.paths = paths or discover_tethers()
        self.config_path = Path(config_path).resolve()
        self.trail_path = Path(trail_path).resolve()
        self.host_data_root = Path(host_data_root).resolve()
        self._process: subprocess.Popen | None = None
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._reader: threading.Thread | None = None
        self._request_counter = 0
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("session already started")
        args = [
            str(self.paths.gate_bin),
            "gate",
            "--stdio",
            "--config",
            str(self.config_path),
            "--engine",
            str(self.paths.engine_bin),
            "--trail",
            str(self.trail_path),
            "--host-data-root",
            str(self.host_data_root),
        ]
        self._process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        for line in self._process.stdout:
            self._responses.put(line)
        self._responses.put(None)

    def close(self) -> None:
        if self._process is None:
            return
        process = self._process
        try:
            if process.poll() is None:
                try:
                    self.shutdown()
                except Exception:
                    pass
                try:
                    process.stdin.close()  # type: ignore[union-attr]
                except Exception:
                    pass
            process.wait(timeout=10)
        except Exception:
            process.kill()
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    stream.close()  # type: ignore[union-attr]
                except Exception:
                    pass
            self._process = None

    def __enter__(self) -> "GateSession":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- protocol ----------------------------------------------------------

    def _read_response(self, timeout: float = 60.0) -> dict[str, Any]:
        try:
            line = self._responses.get(timeout=timeout)
        except queue.Empty as exc:  # pragma: no cover - defensive
            raise TethersUnavailable("timed out waiting for a Tethers response") from exc
        if line is None:
            raise TethersUnavailable(self._startup_diagnostics())
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise TethersUnavailable(f"non-JSON response from Tethers: {line!r}") from exc
        if response.get("schema") == "tethers.cli/1":
            error = response.get("error", {})
            raise TethersUnavailable(
                f"Tethers gate failed to start: {error.get('code')}: {error.get('message')}"
            )
        if response.get("schema") != AUTHORITY_SCHEMA:
            raise TethersUnavailable(f"unexpected response schema: {response.get('schema')!r}")
        return response

    def _startup_diagnostics(self) -> str:
        stderr = ""
        if self._process is not None and self._process.stderr is not None:
            try:
                stderr = self._process.stderr.read()
            except Exception:
                stderr = ""
        return f"Tethers gate closed the session. stderr: {stderr.strip()!r}"

    def _next_request_id(self) -> str:
        with self._lock:
            self._request_counter += 1
            return f"ps-{self._request_counter}-{uuid.uuid4().hex[:12]}"

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("session not started")
        frame = {
            "schema": AUTHORITY_SCHEMA,
            "request_id": self._next_request_id(),
            "operation": operation,
            "payload": payload,
        }
        self._process.stdin.write(json.dumps(frame) + "\n")
        self._process.stdin.flush()
        return self._read_response()

    def expect(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.request(operation, payload)
        if response.get("status") != "ok":
            error = response.get("error", {})
            raise GateError(error.get("code", "error"), error.get("message", ""), error.get("data"))
        return response["result"]

    def hello(self) -> dict[str, Any]:
        return self.expect("hello", {})

    def prepare(
        self,
        *,
        action_id: str,
        evaluation_id: str,
        tether_id: str,
        tether_version: str,
        event_id: str,
        event_name: str,
        event_data: dict[str, Any],
        facts: dict[str, Any],
    ) -> dict[str, Any]:
        return self.expect(
            "prepare",
            {
                "action_id": action_id,
                "evaluation_id": evaluation_id,
                "tether": {"id": tether_id, "version": tether_version},
                "event": {"id": event_id, "name": event_name, "data": event_data},
                "facts": facts,
            },
        )

    def approval_decision(self, approval_id: str, decision: str) -> dict[str, Any]:
        return self.expect(
            "approval_decision", {"approval_id": approval_id, "decision": decision}
        )

    def commit(self, prepared_id: str) -> dict[str, Any]:
        return self.expect("commit", {"prepared_id": prepared_id})

    def outcome(
        self,
        execution_id: str,
        classification: str,
        *,
        result: Any = None,
        error: str | None = None,
        external_execution_identity: str | None = None,
        evidence: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "execution_id": execution_id,
            "classification": classification,
            "attempted": True,
        }
        if external_execution_identity is not None:
            payload["external_execution_identity"] = external_execution_identity
        if evidence is not None:
            payload["evidence"] = evidence
        if classification == "succeeded":
            payload["result"] = result
        else:
            payload["error"] = error or "unspecified"
        return self.expect("outcome", payload)

    def status(self) -> dict[str, Any]:
        return self.expect("status", {})

    def shutdown(self) -> dict[str, Any]:
        return self.expect("shutdown", {})
