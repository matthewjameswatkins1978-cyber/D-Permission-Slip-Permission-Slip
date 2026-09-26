"""The forensic flight recorder: local, bounded, and never authoritative.

Before dogfooding real effects we want a black box. Every Permission Slip
session gets a ``session_id`` and every attempted action gets a ``run_id``;
every run is a directory under the Permission Slip state root holding an
ordered ``events.jsonl``, a ``summary.json`` and a ``receipt.json``.

Three laws this module exists to enforce:

* **Observability is not authority.** A missing, broken or unwritable trace
  never upgrades ASK or DENY into ALLOW, and never reports an effect as
  successful. For real physical execution the rule is stricter still: no
  writable record, no effect.
* **Payloads never enter the trace.** File contents, credentials, environment
  values and raw subprocess bodies are absent by construction; fingerprints,
  counts and safe identities are what get written.
* **The store is bounded.** A deterministic count policy keeps failures around
  longer than successes without creating an eternal forensics landfill.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .state import permission_slip_state_root

TRACE_SCHEMA = "permission-slip.trace-event/1"
SUMMARY_SCHEMA = "permission-slip.run-summary/1"
INSPECT_SCHEMA = "permission-slip.inspect/1"
BUNDLE_SCHEMA = "permission-slip.debug-bundle/1"

RUNS_DIR = "runs"

SESSION_ID_PREFIX = "pss_"
RUN_ID_PREFIX = "psr_"

#: Deterministic count retention. Soft cap trims successes first so failures
#: survive longer; hard cap is a hard bound regardless of outcome.
SOFT_RUN_CAP = 500
HARD_RUN_CAP = 1000

#: Deterministic attention thresholds. These are mechanical, not scores.
STAGE_ATTENTION_MS = 5000
REPEATED_DIGEST_WINDOW_SECONDS = 300
REPEATED_DIGEST_THRESHOLD = 3

# -- event names -----------------------------------------------------------

RUN_STARTED = "RUN_STARTED"
RUN_FINISHED = "RUN_FINISHED"
NORMALIZATION_STARTED = "NORMALIZATION_STARTED"
NORMALIZATION_SUCCEEDED = "NORMALIZATION_SUCCEEDED"
NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
AUTHORITY_PREPARE_SENT = "AUTHORITY_PREPARE_SENT"
AUTHORITY_PREPARE_RESULT = "AUTHORITY_PREPARE_RESULT"
HUMAN_APPROVAL_REQUESTED = "HUMAN_APPROVAL_REQUESTED"
HUMAN_APPROVAL_RECORDED = "HUMAN_APPROVAL_RECORDED"
TRUSTED_CONTEXT_REVALIDATION_STARTED = "TRUSTED_CONTEXT_REVALIDATION_STARTED"
TRUSTED_CONTEXT_REVALIDATION_RESULT = "TRUSTED_CONTEXT_REVALIDATION_RESULT"
AUTHORITY_COMMIT_SENT = "AUTHORITY_COMMIT_SENT"
AUTHORITY_COMMIT_RESULT = "AUTHORITY_COMMIT_RESULT"
EXECUTION_STARTED = "EXECUTION_STARTED"
EXECUTION_RESULT = "EXECUTION_RESULT"
AUTHORITY_OUTCOME_SENT = "AUTHORITY_OUTCOME_SENT"
AUTHORITY_OUTCOME_RESULT = "AUTHORITY_OUTCOME_RESULT"

REQUIRED_LIFECYCLE_EVENTS = (
    RUN_STARTED,
    NORMALIZATION_STARTED,
    AUTHORITY_PREPARE_SENT,
    AUTHORITY_COMMIT_SENT,
    EXECUTION_STARTED,
    AUTHORITY_OUTCOME_SENT,
    RUN_FINISHED,
)

#: Fields that must never appear in a trace event or a debug bundle,
#: whatever the caller passes. Checked by tests, not merely documented.
FORBIDDEN_TRACE_KEYS = frozenset(
    {
        "content",
        "payload",
        "execution_payload",
        "sealed_transport",
        "transport",
        "stdout",
        "stderr",
        "environment",
        "env",
        "secret",
        "secrets",
        "token",
        "password",
        "credential",
        "credentials",
        "private_key",
        "operation_body",
        "operation",
    }
)


def new_session_id() -> str:
    return SESSION_ID_PREFIX + uuid.uuid4().hex


def new_run_id() -> str:
    return RUN_ID_PREFIX + uuid.uuid4().hex


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# -- paths -----------------------------------------------------------------


def runs_root(state_root: str | os.PathLike[str] | None = None) -> Path:
    root = permission_slip_state_root() if state_root is None else Path(state_root)
    return root / RUNS_DIR


def run_dir(state_root: str | os.PathLike[str] | None, run_id: str) -> Path:
    if not isinstance(run_id, str) or not run_id.startswith(RUN_ID_PREFIX):
        raise ValueError(f"not a run id: {run_id!r}")
    return runs_root(state_root) / run_id


# -- recorders -------------------------------------------------------------


class BaseRecorder:
    """Everything the orchestration layer needs, with no storage behind it."""

    #: ``False`` means "no writable record". The real executor refuses to run.
    writable = False
    #: Set when a write failed: the record can no longer be trusted.
    broken = False

    def __init__(self) -> None:
        self.session_id = new_session_id()
        self.current_run_id: str | None = None

    @property
    def active_run_ids(self) -> tuple[str, ...]:
        return ()

    def start_run(self, **facts: Any) -> str:
        self.current_run_id = new_run_id()
        return self.current_run_id

    def emit(self, run_id: str | None, event: str, **fields: Any) -> None:
        return None

    def stage(self, run_id: str | None, name: str) -> None:
        return None

    def note_physical_effect(self, *, action: str, status: str, detail: dict) -> None:
        return None

    def finish(self, run_id: str | None, *, receipt: dict, session: dict) -> dict:
        self.current_run_id = None
        return {"schema": SUMMARY_SCHEMA, "run_id": run_id, "recorded": False}


class NullRecorder(BaseRecorder):
    """Explicitly injected no-op recorder for fixture tests.

    ``writable`` is ``False`` on purpose: this is the recorder that makes
    "no recorder, no real effect" observable rather than merely documented.
    """

    writable = False


@dataclass
class _RunState:
    run_id: str
    directory: Path
    started_monotonic: float
    started_utc: str
    session: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    stages: dict[str, int] = field(default_factory=dict)
    physical_effects: list[dict[str, Any]] = field(default_factory=list)


class TraceRecorder(BaseRecorder):
    """JSONL recorder backed by the Permission Slip state root.

    Never lives in the repository. Events are appended and flushed as they are
    written, so a crash still leaves an ordered prefix of the truth behind --
    which is exactly what makes a missing terminal event detectable.
    """

    writable = True

    def __init__(self, state_root: str | os.PathLike[str] | None = None, *, session: dict[str, Any] | None = None):
        super().__init__()
        self.state_root = permission_slip_state_root() if state_root is None else Path(state_root)
        self.session_facts = dict(session or {})
        self._runs: dict[str, _RunState] = {}
        self._stage_marks: dict[tuple[str, str], float] = {}

    @property
    def writable(self) -> bool:
        # A recorder that failed to write is no longer a recorder, so the real
        # executor must refuse rather than produce an unrecorded effect.
        return not self.broken

    @property
    def active_run_ids(self) -> tuple[str, ...]:
        return tuple(self._runs)

    # -- lifecycle ---------------------------------------------------------

    def start_run(self, **facts: Any) -> str:
        run_id = super().start_run(**facts)
        directory = run_dir(self.state_root, run_id)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Cannot establish the record: mark the recorder unusable so the
            # real executor refuses rather than producing an unrecorded effect.
            self.broken = True
            return run_id
        self._runs[run_id] = _RunState(
            run_id=run_id,
            directory=directory,
            started_monotonic=time.monotonic(),
            started_utc=utc_now(),
            session=dict(self.session_facts),
            facts=dict(facts),
        )
        return run_id

    @property
    def writable(self) -> bool:
        return not self.broken

    def emit(self, run_id: str | None, event: str, **fields: Any) -> None:
        if not run_id or run_id not in self._runs:
            return
        state = self._runs[run_id]
        record = {
            "schema": TRACE_SCHEMA,
            "session_id": self.session_id,
            "run_id": run_id,
            "event": event,
            "timestamp_utc": utc_now(),
            "monotonic_offset_ms": int((time.monotonic() - state.started_monotonic) * 1000),
        }
        for key, value in fields.items():
            if key in FORBIDDEN_TRACE_KEYS:
                continue
            # Scrub at every depth, not just the top level: a payload key
            # nested three levels down is still a payload key.
            record[key] = _safe(value)
        state.events.append(record)
        try:
            with (state.directory / "events.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
        except OSError:
            self.broken = True

    def stage(self, run_id: str | None, name: str) -> None:
        """Mark a stage boundary; duration is derived from paired marks."""
        if not run_id or run_id not in self._runs:
            return
        now = time.monotonic()
        key = (run_id, name)
        previous = self._stage_marks.get(key)
        if previous is None:
            self._stage_marks[key] = now
            return
        del self._stage_marks[key]
        state = self._runs[run_id]
        state.stages[name] = state.stages.get(name, 0) + int((now - previous) * 1000)

    def note_physical_effect(self, *, action: str, status: str, detail: dict) -> None:
        run_id = self.current_run_id
        if not run_id or run_id not in self._runs:
            return
        self._runs[run_id].physical_effects.append(
            {"action": action, "status": status, "detail": _safe(detail)}
        )

    def finish(self, run_id: str | None, *, receipt: dict, session: dict) -> dict:
        if not run_id or run_id not in self._runs:
            self.current_run_id = None
            return {"schema": SUMMARY_SCHEMA, "run_id": run_id, "recorded": False}
        state = self._runs[run_id]
        summary = build_summary(
            run_id=run_id,
            session_id=self.session_id,
            session={**session, **state.session},
            facts=state.facts,
            receipt=receipt,
            stages=state.stages,
            physical_effects=state.physical_effects,
            started_utc=state.started_utc,
            finished_utc=utc_now(),
        )
        try:
            with (state.directory / "events.jsonl").open("a", encoding="utf-8") as handle:
                record = {
                    "schema": TRACE_SCHEMA,
                    "session_id": self.session_id,
                    "run_id": run_id,
                    "event": RUN_FINISHED,
                    "timestamp_utc": summary["finished_utc"],
                    "monotonic_offset_ms": int(
                        (time.monotonic() - state.started_monotonic) * 1000
                    ),
                    "decision": receipt.get("decision"),
                    "outcome": receipt.get("outcome"),
                }
                handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
            _write_json(state.directory / "receipt.json", receipt)
            _write_json(state.directory / "summary.json", summary)
        except OSError:
            self.broken = True
            summary["recorded"] = False
        else:
            summary["recorded"] = True
        self._runs.pop(run_id, None)
        self.current_run_id = None
        # Bounded history: apply the deterministic count policy only after this
        # run is fully written, and never against a run still in flight.
        apply_retention(self.state_root, active_run_ids=self.active_run_ids)
        return summary


def _safe(value: Any) -> Any:
    """Drop forbidden keys at any depth; used for anything entering a trace."""
    if isinstance(value, dict):
        return {k: _safe(v) for k, v in value.items() if k not in FORBIDDEN_TRACE_KEYS}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, bytes):  # pragma: no cover - defensive
        return {"bytes": len(value)}
    return value


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


def build_summary(
    *,
    run_id: str,
    session_id: str,
    session: dict[str, Any],
    facts: dict[str, Any],
    receipt: dict[str, Any],
    stages: dict[str, int],
    physical_effects: list[dict[str, Any]],
    started_utc: str,
    finished_utc: str,
) -> dict[str, Any]:
    """The compact record ``inspect`` reads. Payload-free by construction."""
    duration_ms = None
    try:
        start = datetime.fromisoformat(started_utc.replace("Z", "+00:00"))
        end = datetime.fromisoformat(finished_utc.replace("Z", "+00:00"))
        duration_ms = int((end - start).total_seconds() * 1000)
    except ValueError:  # pragma: no cover - defensive
        pass
    normalized = receipt.get("normalized") or {}
    return {
        "schema": SUMMARY_SCHEMA,
        "run_id": run_id,
        "session_id": session_id,
        "terminal": True,
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "duration_ms": duration_ms,
        "decision": receipt.get("decision"),
        "reason": receipt.get("reason"),
        "outcome": receipt.get("outcome"),
        "executed": bool(receipt.get("executed")),
        "action": receipt.get("action"),
        "actor": receipt.get("actor"),
        "actor_identity_source": facts.get("actor_identity_source"),
        "operation_digest": facts.get("operation_digest"),
        "doctrine_digest": facts.get("doctrine_digest"),
        "host_context_digest": facts.get("host_context_digest"),
        "canonical_repository": facts.get("canonical_repository"),
        "executor_mode": facts.get("executor_mode"),
        "approval_id": receipt.get("approval_id"),
        "execution_id": receipt.get("execution_id"),
        "execution_ids": [receipt.get("execution_id")] if receipt.get("execution_id") else [],
        "error": receipt.get("error"),
        "normalized_action": normalized.get("action"),
        "normalized_arguments": _safe(normalized.get("arguments") or {}),
        "ignored_caller_claims": receipt.get("ignored_caller_claims") or [],
        "stage_ms": dict(stages),
        "physical_effects": _safe(physical_effects),
        "session": _safe(session),
    }


# -- reading ---------------------------------------------------------------


@dataclass
class RunRecord:
    run_id: str
    directory: Path
    summary: dict[str, Any] | None
    error: str | None = None

    @property
    def started_utc(self) -> str:
        if self.summary and isinstance(self.summary.get("started_utc"), str):
            return self.summary["started_utc"]
        try:
            return datetime.fromtimestamp(
                self.directory.stat().st_mtime, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except OSError:  # pragma: no cover - defensive
            return "1970-01-01T00:00:00.000000Z"


def list_runs(state_root: str | os.PathLike[str] | None = None) -> list[RunRecord]:
    root = runs_root(state_root)
    if not root.is_dir():
        return []
    records: list[RunRecord] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or not entry.name.startswith(RUN_ID_PREFIX):
            continue
        summary_path = entry / "summary.json"
        summary: dict[str, Any] | None = None
        error: str | None = None
        if summary_path.is_file():
            try:
                loaded = json.loads(summary_path.read_text(encoding="utf-8"))
                summary = loaded if isinstance(loaded, dict) else None
                if summary is None:
                    error = "malformed_summary"
            except (OSError, ValueError) as exc:
                error = f"malformed_summary: {exc}"
        records.append(RunRecord(entry.name, entry, summary, error))
    records.sort(key=lambda record: (record.started_utc, record.run_id))
    return records


# -- retention -------------------------------------------------------------


def apply_retention(
    state_root: str | os.PathLike[str] | None = None,
    *,
    soft_cap: int = SOFT_RUN_CAP,
    hard_cap: int = HARD_RUN_CAP,
    active_run_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Bounded count policy. Never deletes a run that is being written."""
    protected = set(active_run_ids)
    records = list_runs(state_root)
    deletions: list[str] = []

    def eligible(record: RunRecord) -> bool:
        return record.run_id not in protected

    survivors = [record for record in records if eligible(record)]
    # Above the soft cap, trim the oldest *successful* runs first: failures are
    # the records most worth keeping.
    if len(survivors) > soft_cap:
        successes = [
            r for r in survivors if (r.summary or {}).get("outcome") == "succeeded"
        ]
        excess = len(survivors) - soft_cap
        for record in successes:
            if excess <= 0:
                break
            deletions.append(record.run_id)
            excess -= 1
        survivors = [r for r in survivors if r.run_id not in set(deletions)]

    if len(survivors) > hard_cap:
        excess = len(survivors) - hard_cap
        for record in survivors:
            if excess <= 0:
                break
            deletions.append(record.run_id)
            excess -= 1

    for run_id in deletions:
        _delete_run_dir(runs_root(state_root) / run_id)
    return {
        "soft_cap": soft_cap,
        "hard_cap": hard_cap,
        "before": len(records),
        "deleted": deletions,
        "after": len(records) - len(deletions),
        "protected": sorted(protected),
    }


def _delete_run_dir(path: Path) -> None:
    try:
        for child in path.iterdir():
            if child.is_file():
                child.unlink()
        path.rmdir()
    except OSError:  # pragma: no cover - best effort
        pass


# -- 24-hour inspection ----------------------------------------------------


def _parse_when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def inspect_runs(
    state_root: str | os.PathLike[str] | None = None,
    *,
    since_hours: float = 24.0,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Deterministic burn-in report over local run summaries.

    No anomaly score, no model, no judgement -- only mechanical rules that are
    useful to read the morning after.
    """
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(hours=since_hours)
    records = [
        record
        for record in list_runs(state_root)
        if (_parse_when(record.started_utc) or cutoff) >= cutoff
    ]

    decisions: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    attention: list[dict[str, Any]] = []
    slowest: list[dict[str, Any]] = []
    digest_times: dict[str, list[datetime]] = {}
    execution_ids: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    errors: list[str] = []

    for record in records:
        summary = record.summary
        if summary is None or record.error or not summary.get("terminal"):
            attention.append(
                {
                    "kind": "malformed_or_missing_terminal_event",
                    "run_id": record.run_id,
                    "detail": record.error or "run has no terminal summary",
                }
            )
            continue

        decision = str(summary.get("decision") or "unknown")
        decisions[decision] = decisions.get(decision, 0) + 1
        outcome = summary.get("outcome")
        if outcome:
            outcomes[str(outcome)] = outcomes.get(str(outcome), 0) + 1

        if decision == "UNAVAILABLE":
            attention.append(
                {"kind": "unavailable", "run_id": record.run_id, "detail": summary.get("reason")}
            )
        if outcome in ("failed", "uncertain"):
            attention.append(
                {"kind": f"{outcome}_physical_outcome", "run_id": record.run_id, "detail": summary.get("action")}
            )
        if summary.get("reason") == "trusted_context_changed":
            attention.append(
                {"kind": "trusted_context_changed", "run_id": record.run_id, "detail": summary.get("error")}
            )
        if summary.get("reason") in ("host_binding_mismatch", "trusted_context_revalidation_failed"):
            attention.append(
                {"kind": "host_binding_mismatch", "run_id": record.run_id, "detail": summary.get("error")}
            )
        for effect in summary.get("physical_effects") or []:
            detail = effect.get("detail") or {}
            if detail.get("reason") == "unsupported_real_effect":
                attention.append(
                    {
                        "kind": "execution_unsupported_after_admission",
                        "run_id": record.run_id,
                        "detail": effect.get("action"),
                    }
                )
        if summary.get("error"):
            errors.append(f"{record.run_id}: {summary.get('error')}")

        for stage, duration in (summary.get("stage_ms") or {}).items():
            if isinstance(duration, int) and duration >= STAGE_ATTENTION_MS:
                slowest.append({"run_id": record.run_id, "stage": stage, "ms": duration})
                attention.append(
                    {
                        "kind": "stage_over_threshold",
                        "run_id": record.run_id,
                        "detail": f"{stage} {duration}ms",
                    }
                )
        if isinstance(summary.get("duration_ms"), int) and summary["duration_ms"] >= STAGE_ATTENTION_MS:
            slowest.append(
                {"run_id": record.run_id, "stage": "total", "ms": summary["duration_ms"]}
            )

        digest = summary.get("operation_digest")
        if digest:
            when = _parse_when(summary.get("started_utc"))
            digest_times.setdefault(digest, []).append(when or cutoff)
        for exec_id in summary.get("execution_ids") or []:
            if isinstance(exec_id, str) and exec_id:
                execution_ids.setdefault(exec_id, []).append(record.run_id)
        session = summary.get("session") or {}
        for key in ("permission_slip_version", "tethers_product_version", "authority_protocol"):
            if session.get(key):
                versions[key] = str(session[key])
        if summary.get("doctrine_digest"):
            versions["doctrine_digest"] = str(summary["doctrine_digest"])

    for exec_id, owners in sorted(execution_ids.items()):
        if len(owners) > 1:
            attention.append(
                {
                    "kind": "duplicate_execution_id",
                    "run_id": owners[0],
                    "detail": f"{exec_id} seen in {len(owners)} runs",
                }
            )

    for digest, times in sorted(digest_times.items()):
        times = sorted(times)
        window = timedelta(seconds=REPEATED_DIGEST_WINDOW_SECONDS)
        for index in range(len(times)):
            span = [t for t in times[index:] if t - times[index] <= window]
            if len(span) >= REPEATED_DIGEST_THRESHOLD:
                attention.append(
                    {
                        "kind": "repeated_operation_digest",
                        "run_id": "",
                        "detail": f"{digest} seen {len(span)} times in 5 minutes",
                    }
                )
                break

    slowest.sort(key=lambda item: item["ms"], reverse=True)
    attention.sort(key=lambda item: (item["kind"], item["run_id"] or ""))

    return {
        "schema": INSPECT_SCHEMA,
        "since_hours": since_hours,
        "generated_utc": current.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "runs": len(records),
        "decisions": dict(sorted(decisions.items())),
        "outcomes": dict(sorted(outcomes.items())),
        "attention": attention,
        "slowest": slowest[:10],
        "versions": dict(sorted(versions.items())),
        "errors": errors,
    }


def render_inspect_human(report: dict[str, Any]) -> str:
    decisions = report.get("decisions") or {}
    outcomes = report.get("outcomes") or {}
    versions = report.get("versions") or {}
    lines = [
        f"{int(report.get('since_hours', 24))}-HOUR INSPECTION",
        "",
        f"Runs: {report.get('runs', 0)}",
        f"ALLOW: {decisions.get('ALLOW', 0)}",
        f"ASK: {decisions.get('ASK', 0)}",
        f"DENY: {decisions.get('DENY', 0)}",
        f"UNAVAILABLE: {decisions.get('UNAVAILABLE', 0)}",
        "",
        f"Succeeded: {outcomes.get('succeeded', 0)}",
        f"Failed: {outcomes.get('failed', 0)}",
        f"Uncertain: {outcomes.get('uncertain', 0)}",
        "",
        "ATTENTION",
    ]
    attention = report.get("attention") or []
    if attention:
        for item in attention:
            suffix = f" -- {item['detail']}" if item.get("detail") else ""
            lines.append(f"- {item['kind']}{suffix}")
    else:
        lines.append("- none")

    lines.extend(["", "SLOWEST"])
    slowest = report.get("slowest") or []
    if slowest:
        for item in slowest:
            lines.append(f"- {item['stage']} {item['ms']}ms ({item['run_id']})")
    else:
        lines.append("- none")

    counts: dict[str, int] = {}
    for item in attention:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    lines.extend(["", "REPEATED"])
    if counts:
        for kind, count in sorted(counts.items()):
            lines.append(f"- {kind}: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "VERSIONS"])
    if versions:
        lines.append(f"Permission Slip {versions.get('permission_slip_version', 'unknown')}")
        lines.append(f"Tethers {versions.get('tethers_product_version', 'unknown')}")
        lines.append(f"Authority {versions.get('authority_protocol', 'unknown')}")
        lines.append(f"Doctrine {versions.get('doctrine_digest', 'unknown')}")
    else:
        lines.append("no recorded versions in window")
    return "\n".join(lines)


# -- debug bundle ----------------------------------------------------------

#: Exact allow-list. Anything not named here never reaches a bundle, because
#: the bundle is built by copying names -- not by walking a directory.
BUNDLE_FILES = ("events.jsonl", "summary.json", "receipt.json")


def build_debug_bundle(
    run_id: str,
    output: str | os.PathLike[str],
    *,
    state_root: str | os.PathLike[str] | None = None,
    session: dict[str, Any] | None = None,
) -> Path:
    """Sanitized evidence for "Lucy, this one did something weird."

    Only the three allow-listed run files plus a manifest of safe identities.
    No environment, no credentials, no file contents, no subprocess bodies, no
    home-directory spill.
    """
    directory = run_dir(state_root, run_id)
    if not directory.is_dir():
        raise FileNotFoundError(f"no run {run_id}")

    manifest: dict[str, Any] = {"schema": BUNDLE_SCHEMA, "run_id": run_id}
    summary_path = directory / "summary.json"
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            manifest["summary_present"] = True
            manifest["doctrine_digest"] = summary.get("doctrine_digest")
            manifest["host_context_digest"] = summary.get("host_context_digest")
            manifest["canonical_repository"] = summary.get("canonical_repository")
            manifest["decision"] = summary.get("decision")
            manifest["outcome"] = summary.get("outcome")
            manifest["session"] = _safe(summary.get("session") or {})
        except ValueError:
            manifest["summary_present"] = False
    else:
        manifest["summary_present"] = False

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        for name in BUNDLE_FILES:
            candidate = directory / name
            if candidate.is_file():
                bundle.write(str(candidate), arcname=name)
    return destination


__all__ = [
    "BUNDLE_FILES",
    "BUNDLE_SCHEMA",
    "BaseRecorder",
    "FORBIDDEN_TRACE_KEYS",
    "HARD_RUN_CAP",
    "INSPECT_SCHEMA",
    "NullRecorder",
    "REQUIRED_LIFECYCLE_EVENTS",
    "SOFT_RUN_CAP",
    "SUMMARY_SCHEMA",
    "STAGE_ATTENTION_MS",
    "TRACE_SCHEMA",
    "TraceRecorder",
    "apply_retention",
    "build_debug_bundle",
    "inspect_runs",
    "list_runs",
    "new_run_id",
    "new_session_id",
    "render_inspect_human",
    "run_dir",
    "runs_root",
]
