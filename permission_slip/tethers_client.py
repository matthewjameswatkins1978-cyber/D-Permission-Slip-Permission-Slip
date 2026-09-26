"""``tethers.authority/1`` stdio client.

Permission Slip interacts with the Tethers Authority Gate as an external
process over NDJSON on stdin/stdout. The real public seam is exercised; no
private Tethers Rust or OCaml module is imported, and the NDJSON process
boundary is preserved.

The client depends on the *protocol*, never on a source checkout:

* the installation comes from :mod:`permission_slip.tethers_install`, which
  consumes Tethers as a released product;
* startup performs the documented ``hello`` and rejects any protocol identity
  other than ``tethers.authority/1``;
* every response frame is schema-checked, request-identity-checked where the
  Gate echoes it, and malformed startup output fails closed.

Startup is bounded: a Gate that never answers, dies mid-startup, or answers
with the wrong protocol all surface as :class:`TethersUnavailable` /
:class:`TethersProtocolMismatch` rather than hanging.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from .tethers_install import (
    AUTHORITY_PROTOCOL,
    TethersInstallation,
    TethersProtocolMismatch,
    TethersUnavailable,
    discover_tethers,
)

__all__ = [
    "AUTHORITY_PROTOCOL",
    "GateError",
    "GateSession",
    "TethersInstallation",
    "TethersProtocolMismatch",
    "TethersUnavailable",
    "discover_tethers",
]

DEFAULT_RESPONSE_TIMEOUT = 60.0

#: Alias kept for readability at the call sites; the contract is the protocol.
AUTHORITY_SCHEMA = AUTHORITY_PROTOCOL


class GateError(RuntimeError):
    """A structured ``tethers.authority/1`` error response."""

    def __init__(self, code: str, message: str, data: Any = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class GateSession:
    """A single persistent ``tethers gate --stdio`` session."""

    def __init__(
        self,
        config_path: str | os.PathLike[str],
        trail_path: str | os.PathLike[str],
        host_data_root: str | os.PathLike[str],
        paths: TethersInstallation | None = None,
        *,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
    ):
        self.paths = paths or discover_tethers()
        self.config_path = Path(config_path).resolve()
        self.trail_path = Path(trail_path).resolve()
        self.host_data_root = Path(host_data_root).resolve()
        self.response_timeout = response_timeout
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
        try:
            self._process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            self._process = None
            raise TethersUnavailable(
                f"Tethers Gate could not be started from {self.paths.gate_bin}: {exc}",
                code="gate_unreadable",
            ) from exc
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

    def _read_response(
        self, *, expected_request_id: str | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        try:
            line = self._responses.get(
                timeout=self.response_timeout if timeout is None else timeout
            )
        except queue.Empty as exc:
            raise TethersUnavailable(
                f"timed out after {self.response_timeout if timeout is None else timeout}s "
                "waiting for a Tethers response",
                code="timeout",
            ) from exc
        if line is None:
            raise TethersUnavailable(
                self._startup_diagnostics(), code="startup_failed"
            )
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TethersUnavailable(
                f"non-JSON response from Tethers: {line!r}", code="malformed_response"
            ) from exc
        if not isinstance(response, dict):
            raise TethersUnavailable(
                f"non-object response from Tethers: {line!r}", code="malformed_response"
            )
        schema = response.get("schema")
        if schema == "tethers.cli/1":
            error = response.get("error", {})
            raise TethersUnavailable(
                f"Tethers gate failed to start: {error.get('code')}: {error.get('message')}",
                code="startup_error",
            )
        if schema != AUTHORITY_SCHEMA:
            raise TethersProtocolMismatch(
                f"unsupported response schema: {schema!r}"
            )
        response_id = response.get("request_id")
        if isinstance(response_id, str) and expected_request_id is not None:
            if response_id != expected_request_id:
                raise TethersUnavailable(
                    "Tethers echoed a mismatched request identity: "
                    f"{response_id!r} != {expected_request_id!r}",
                    code="request_identity_mismatch",
                )
        if "status" not in response:
            raise TethersUnavailable(
                f"response is missing 'status': {line!r}", code="malformed_response"
            )
        return response

    def _startup_diagnostics(self) -> str:
        return (
            f"Tethers gate closed the session (exit code "
            f"{self._process.returncode if self._process is not None else 'unknown'}). "
            f"stderr: {self._read_stderr()!r}"
        )

    def _read_stderr(self) -> str:
        if self._process is None or self._process.stderr is None:
            return ""
        try:
            if self._process.poll() is None:
                return ""
            return (self._process.stderr.read() or "").strip()
        except Exception:  # pragma: no cover - defensive
            return ""

    def _next_request_id(self) -> str:
        with self._lock:
            self._request_counter += 1
            return f"ps-{self._request_counter}-{uuid.uuid4().hex[:12]}"

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("session not started")
        request_id = self._next_request_id()
        frame = {
            "schema": AUTHORITY_SCHEMA,
            "request_id": request_id,
            "operation": operation,
            "payload": payload,
        }
        self._process.stdin.write(json.dumps(frame) + "\n")
        self._process.stdin.flush()
        return self._read_response(expected_request_id=request_id)

    def expect(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.request(operation, payload)
        if response.get("status") != "ok":
            error = response.get("error", {})
            raise GateError(error.get("code", "error"), error.get("message", ""), error.get("data"))
        return response["result"]

    def hello(self) -> dict[str, Any]:
        """Negotiate the authority protocol and validate the startup response.

        Fails closed on unsupported protocol identity or on a Gate that
        reports provider activity (the Gate must emit no provider calls).
        """
        result = self.expect("hello", {})
        if not isinstance(result, dict):
            raise TethersProtocolMismatch("hello result is not an object")
        protocol = result.get("protocol")
        if protocol != AUTHORITY_SCHEMA:
            raise TethersProtocolMismatch(
                f"unsupported authority protocol: {protocol!r} "
                f"(expected {AUTHORITY_SCHEMA!r})"
            )
        versions = result.get("protocol_versions")
        if isinstance(versions, list) and AUTHORITY_SCHEMA not in versions:
            raise TethersProtocolMismatch(
                f"Gate does not advertise {AUTHORITY_SCHEMA}: {versions!r}"
            )
        if result.get("provider_invocations") != 0:
            raise TethersUnavailable(
                "hello reported provider_invocations != 0; the Authority Gate "
                "must not perform provider calls",
                code="malformed_response",
            )
        return result

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
