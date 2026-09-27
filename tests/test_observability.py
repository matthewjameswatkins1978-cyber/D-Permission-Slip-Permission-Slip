"""The flight recorder: what it writes, what it must never write."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from permission_slip import observability as obs
from permission_slip.observability import (
    FORBIDDEN_TRACE_KEYS,
    NullRecorder,
    RUN_FINISHED,
    RUN_STARTED,
    TRACE_SCHEMA,
    TraceRecorder,
    apply_retention,
    build_debug_bundle,
    inspect_runs,
    list_runs,
    new_run_id,
    new_session_id,
    render_inspect_human,
    run_dir,
    runs_root,
)

SYNTHETIC_SECRET = "sk-SYNTHETIC-TEST-SECRET-DO-NOT-BUNDLE"
SYNTHETIC_TOKEN = "ghp_SYNTHETIC_TEST_TOKEN"


def make_run(
    recorder: TraceRecorder,
    *,
    receipt: dict,
    facts: dict,
    events: tuple[str, ...] = (RUN_STARTED, "NORMALIZATION_SUCCEEDED"),
) -> tuple[str, dict]:
    run_id = recorder.start_run(**facts)
    for event in events:
        recorder.emit(run_id, event, action=receipt.get("action"))
    summary = recorder.finish(run_id, receipt=receipt, session={"entry": "test"})
    return run_id, summary


class IdentifierTests(unittest.TestCase):
    def test_session_and_run_ids_are_opaque_and_prefixed(self):
        session = new_session_id()
        run = new_run_id()
        self.assertTrue(session.startswith("pss_"))
        self.assertTrue(run.startswith("psr_"))
        self.assertEqual(len(session), 4 + 32)
        self.assertEqual(len(run), 4 + 32)
        self.assertRegex(session[4:], r"^[0-9a-f]{32}$")
        self.assertRegex(run[4:], r"^[0-9a-f]{32}$")
        # No timestamp is used as identity.
        self.assertNotRegex(session[4:], r"^20\d\d")
        self.assertNotEqual(session, new_session_id())

    def test_run_dir_requires_a_real_run_id(self):
        with self.assertRaises(ValueError):
            run_dir(None, "../escape")
        with self.assertRaises(ValueError):
            run_dir(None, "not-a-run")


class RecorderContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-obs-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.recorder = TraceRecorder(self.state, session={"entry": "unit"})

    def test_a_recorder_is_writable_and_a_null_one_is_not(self):
        self.assertTrue(TraceRecorder(self.state).writable)
        self.assertFalse(NullRecorder().writable)

    def test_events_carry_the_versioned_envelope(self):
        run_id = self.recorder.start_run(operation_digest="d" * 64, actor="worker-agent")
        self.recorder.emit(run_id, RUN_STARTED, tool="tests")
        line = (run_dir(self.state, run_id) / "events.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()[0]
        record = json.loads(line)
        self.assertEqual(record["schema"], TRACE_SCHEMA)
        self.assertEqual(record["session_id"], self.recorder.session_id)
        self.assertEqual(record["run_id"], run_id)
        self.assertEqual(record["event"], RUN_STARTED)
        self.assertRegex(record["timestamp_utc"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertIsInstance(record["monotonic_offset_ms"], int)

    def test_a_finished_run_has_summary_and_receipt(self):
        run_id, summary = make_run(
            self.recorder,
            receipt={"action": "dev.tests.run", "decision": "ALLOW", "outcome": "succeeded"},
            facts={"operation_digest": "a" * 64, "actor": "worker-agent"},
        )
        directory = run_dir(self.state, run_id)
        self.assertTrue((directory / "events.jsonl").is_file())
        self.assertTrue((directory / "summary.json").is_file())
        self.assertTrue((directory / "receipt.json").is_file())
        self.assertTrue(summary["terminal"])
        self.assertEqual(summary["schema"], obs.SUMMARY_SCHEMA)
        events = [
            json.loads(line)
            for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(events[-1]["event"], RUN_FINISHED)

    def test_forbidden_payload_keys_are_stripped_at_any_depth(self):
        run_id = self.recorder.start_run()
        self.recorder.emit(
            run_id,
            RUN_STARTED,
            content="FILE CONTENTS",
            nested={"payload": "x", "inner": {"stdout": "bodies", "ok": 1}},
            list_of_secrets=[{"token": SYNTHETIC_TOKEN}],
            keep="fine",
        )
        raw = (run_dir(self.state, run_id) / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("FILE CONTENTS", raw)
        self.assertNotIn(SYNTHETIC_TOKEN, raw)
        record = json.loads(raw.splitlines()[0])
        self.assertEqual(record["keep"], "fine")
        self.assertNotIn("content", record)
        self.assertEqual(record["nested"]["inner"]["ok"], 1)
        self.assertNotIn("stdout", record["nested"]["inner"])
        self.assertNotIn("token", record["list_of_secrets"][0])

    def test_every_documented_forbidden_key_is_actually_enforced(self):
        self.assertTrue(FORBIDDEN_TRACE_KEYS)
        for key in ("content", "stdout", "sealed_transport", "password", "env"):
            self.assertIn(key, FORBIDDEN_TRACE_KEYS)

    def test_a_broken_recorder_stops_reporting_itself_as_writable(self):
        run_id = self.recorder.start_run()
        self.recorder.broken = True
        self.assertFalse(self.recorder.writable)
        # Emitting while broken is a no-op rather than a crash.
        self.recorder.emit(run_id, RUN_STARTED)
        self.assertIsNotNone(run_id)

    def test_an_unwritable_state_root_makes_the_recorder_unusable(self):
        blocked = Path(self.tmp.name) / "blocked"
        blocked.write_text("a file, not a directory", encoding="utf-8")
        recorder = TraceRecorder(blocked)
        recorder.start_run()
        self.assertFalse(recorder.writable)


class RedactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-redact-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.recorder = TraceRecorder(self.state, session={"entry": "redaction"})

    def test_edit_content_never_reaches_the_trace(self):
        run_id = self.recorder.start_run()
        self.recorder.emit(
            run_id,
            "NORMALIZATION_SUCCEEDED",
            action="project.files.edit",
            normalized_arguments={
                "path": "runtime/spike-workspace/repos/permission-slip/x.py",
                "before_digest": "sha256:" + "0" * 64,
                "after_digest": "sha256:" + "1" * 64,
                "content_bytes": 11,
            },
            content="def secret_edit(): ...",
        )
        run_dir(self.state, run_id).mkdir(exist_ok=True)
        raw = (run_dir(self.state, run_id) / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("def secret_edit", raw)
        self.assertIn("content_bytes", raw)

    def test_synthetic_secrets_never_reach_a_bundle(self):
        run_id, _ = make_run(
            self.recorder,
            receipt={
                "action": "data.external_upload.secret",
                "decision": "DENY",
                "reason": "standing_deny",
            },
            facts={"operation_digest": "b" * 64},
        )
        # A caller that tries to smuggle secret material into the trace has it
        # dropped before a single byte is written.
        self.recorder.emit(
            run_id,
            "EXECUTION_RESULT",
            status="failed",
            content=SYNTHETIC_SECRET,
            stdout=SYNTHETIC_TOKEN,
            credential=SYNTHETIC_SECRET,
            detail={"reason": "standing_deny"},
        )
        output = Path(self.tmp.name) / "bundle.zip"
        build_debug_bundle(run_id, output, state_root=self.state)
        with zipfile.ZipFile(output) as bundle:
            names = sorted(bundle.namelist())
            self.assertEqual(
                names, ["events.jsonl", "manifest.json", "receipt.json", "summary.json"]
            )
            blob = b"".join(bundle.read(name) for name in names).decode("utf-8", "replace")
        self.assertNotIn(SYNTHETIC_SECRET, blob)
        self.assertNotIn(SYNTHETIC_TOKEN, blob)
        for key in FORBIDDEN_TRACE_KEYS:
            self.assertNotIn(f'"{key}"', blob)

    def test_bundle_includes_only_allow_listed_run_files(self):
        run_id, _ = make_run(
            self.recorder,
            receipt={"action": "dev.tests.run", "decision": "ALLOW", "outcome": "succeeded"},
            facts={"operation_digest": "c" * 64},
        )
        directory = run_dir(self.state, run_id)
        (directory / "extra-should-not-ship.txt").write_text("nope", encoding="utf-8")
        output = Path(self.tmp.name) / "bundle2.zip"
        build_debug_bundle(run_id, output, state_root=self.state)
        with zipfile.ZipFile(output) as bundle:
            self.assertNotIn("extra-should-not-ship.txt", bundle.namelist())
            self.assertEqual(
                sorted(bundle.namelist()),
                ["events.jsonl", "manifest.json", "receipt.json", "summary.json"],
            )
            manifest = json.loads(bundle.read("manifest.json"))
        self.assertEqual(manifest["schema"], obs.BUNDLE_SCHEMA)
        self.assertEqual(manifest["run_id"], run_id)

    def test_bundle_of_an_unknown_run_fails_loudly(self):
        with self.assertRaises(FileNotFoundError):
            build_debug_bundle("psr_" + "0" * 32, Path(self.tmp.name) / "x.zip", state_root=self.state)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-retention-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"

    def seed(self, count: int, *, outcome: str, base_minute: int = 0) -> list[str]:
        ids = []
        for index in range(count):
            run_id = new_run_id()
            directory = run_dir(self.state, run_id)
            directory.mkdir(parents=True, exist_ok=True)
            started = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=base_minute + index)
            (directory / "summary.json").write_text(
                json.dumps(
                    {
                        "schema": obs.SUMMARY_SCHEMA,
                        "run_id": run_id,
                        "terminal": True,
                        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        "finished_utc": started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                        "outcome": outcome,
                        "decision": "ALLOW",
                    }
                ),
                encoding="utf-8",
            )
            ids.append(run_id)
        return ids

    def test_soft_cap_trims_oldest_successes_and_keeps_failures(self):
        old_success = self.seed(6, outcome="succeeded", base_minute=0)
        failures = self.seed(3, outcome="failed", base_minute=100)
        report = apply_retention(self.state, soft_cap=5, hard_cap=100)
        self.assertEqual(len(report["deleted"]), 4)
        survivors = {record.run_id for record in list_runs(self.state)}
        for run_id in old_success[4:]:
            self.assertIn(run_id, survivors)
        self.assertNotIn(old_success[0], survivors)
        for run_id in failures:
            self.assertIn(run_id, survivors)

    def test_hard_cap_bounds_everything_regardless_of_outcome(self):
        failures = self.seed(6, outcome="failed")
        report = apply_retention(self.state, soft_cap=1, hard_cap=3)
        self.assertEqual(report["after"], 3)
        survivors = {record.run_id for record in list_runs(self.state)}
        self.assertEqual(len(survivors), 3)
        self.assertNotIn(failures[0], survivors)

    def test_a_run_being_written_is_never_deleted(self):
        self.seed(6, outcome="succeeded")
        active = self.seed(1, outcome="succeeded", base_minute=500)[0]
        apply_retention(self.state, soft_cap=2, hard_cap=2, active_run_ids=[active])
        survivors = {record.run_id for record in list_runs(self.state)}
        self.assertIn(active, survivors)

    def test_retention_is_a_no_op_below_the_caps(self):
        keep = self.seed(3, outcome="succeeded")
        report = apply_retention(self.state, soft_cap=500, hard_cap=1000)
        self.assertEqual(report["deleted"], [])
        self.assertEqual({r.run_id for r in list_runs(self.state)}, set(keep))

    def test_retention_runs_after_every_finished_trace(self):
        recorder = TraceRecorder(self.state)
        recorder.start_run()
        recorder.finish(
            recorder.current_run_id,
            receipt={"action": "dev.tests.run", "decision": "ALLOW", "outcome": "succeeded"},
            session={},
        )
        self.assertEqual(len(list_runs(self.state)), 1)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-inspect-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.now = datetime(2026, 9, 27, tzinfo=timezone.utc)

    def write_run(
        self,
        *,
        started_offset_hours: float = -1.0,
        summary: dict | None = None,
        terminal: bool = True,
        write_summary: bool = True,
        raw_summary: str | None = None,
    ) -> str:
        run_id = new_run_id()
        directory = run_dir(self.state, run_id)
        directory.mkdir(parents=True, exist_ok=True)
        started = self.now + timedelta(hours=started_offset_hours)
        (directory / "events.jsonl").write_text(
            json.dumps({"schema": TRACE_SCHEMA, "run_id": run_id, "event": RUN_STARTED}) + "\n",
            encoding="utf-8",
        )
        if not write_summary:
            return run_id
        payload = {
            "schema": obs.SUMMARY_SCHEMA,
            "run_id": run_id,
            "session_id": "pss_" + "a" * 32,
            "terminal": terminal,
            "started_utc": started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "finished_utc": started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "duration_ms": 10,
            "decision": "ALLOW",
            "outcome": "succeeded",
            "operation_digest": "d" * 64,
            "execution_ids": [],
            "stage_ms": {},
            "session": {
                "permission_slip_version": "0.4.0",
                "tethers_product_version": "0.8.1",
                "authority_protocol": "tethers.authority/1",
            },
        }
        payload.update(summary or {})
        text = raw_summary if raw_summary is not None else json.dumps(payload)
        (directory / "summary.json").write_text(text, encoding="utf-8")
        return run_id

    def test_a_clean_window_has_no_attention(self):
        self.write_run()
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["runs"], 1)
        self.assertEqual(report["attention"], [])
        self.assertEqual(report["decisions"]["ALLOW"], 1)
        self.assertEqual(report["versions"]["tethers_product_version"], "0.8.1")

    def test_runs_outside_the_window_are_excluded(self):
        self.write_run(started_offset_hours=-48)
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["runs"], 0)

    def test_missing_terminal_event_is_flagged(self):
        self.write_run(write_summary=False)
        self.write_run(terminal=False)
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        kinds = [item["kind"] for item in report["attention"]]
        self.assertEqual(kinds.count("malformed_or_missing_terminal_event"), 2)

    def test_a_malformed_summary_does_not_crash_inspection(self):
        self.write_run(raw_summary="{not json at all")
        self.write_run()
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["runs"], 2)
        self.assertIn("malformed_or_missing_terminal_event", [i["kind"] for i in report["attention"]])
        self.assertEqual(report["decisions"]["ALLOW"], 1)

    def test_deterministic_attention_rules(self):
        self.write_run(summary={"decision": "UNAVAILABLE", "reason": "prepare.failed", "outcome": None})
        self.write_run(summary={"decision": "ALLOW", "outcome": "failed"})
        self.write_run(summary={"decision": "ALLOW", "outcome": "uncertain"})
        self.write_run(summary={"decision": "DENY", "reason": "trusted_context_changed", "error": "stale"})
        self.write_run(
            summary={
                "decision": "ALLOW",
                "outcome": "failed",
                "physical_effects": [
                    {
                        "action": "money.real_charge",
                        "status": "failed",
                        "detail": {"reason": "unsupported_real_effect"},
                    }
                ],
            }
        )
        self.write_run(summary={"decision": "ALLOW", "stage_ms": {"execution": 12345}})
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        kinds = {item["kind"] for item in report["attention"]}
        self.assertIn("unavailable", kinds)
        self.assertIn("failed_physical_outcome", kinds)
        self.assertIn("uncertain_physical_outcome", kinds)
        self.assertIn("trusted_context_changed", kinds)
        self.assertIn("execution_unsupported_after_admission", kinds)
        self.assertIn("stage_over_threshold", kinds)
        self.assertGreaterEqual(report["slowest"][0]["ms"], 12345)

    def test_duplicate_execution_ids_across_runs_are_flagged(self):
        self.write_run(summary={"execution_ids": ["exec-same"]})
        self.write_run(summary={"execution_ids": ["exec-same"]})
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        kinds = [item["kind"] for item in report["attention"]]
        self.assertIn("duplicate_execution_id", kinds)

    def test_the_same_operation_three_times_in_five_minutes_is_flagged(self):
        for _ in range(3):
            self.write_run(summary={"operation_digest": "e" * 64})
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertIn(
            "repeated_operation_digest", [item["kind"] for item in report["attention"]]
        )

    def test_ask_and_deny_are_counted_but_not_treated_as_bugs(self):
        self.write_run(summary={"decision": "ASK", "outcome": None})
        self.write_run(summary={"decision": "DENY", "outcome": None})
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["decisions"]["ASK"], 1)
        self.assertEqual(report["decisions"]["DENY"], 1)
        self.assertEqual(report["attention"], [])

    def test_human_rendering_has_the_burn_in_shape(self):
        self.write_run(summary={"decision": "UNAVAILABLE", "outcome": None})
        self.write_run(summary={"decision": "ALLOW", "outcome": "failed"})
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        text = render_inspect_human(report)
        for heading in (
            "24-HOUR INSPECTION",
            "Runs:",
            "ALLOW:",
            "ASK:",
            "DENY:",
            "UNAVAILABLE:",
            "Succeeded:",
            "Failed:",
            "Uncertain:",
            "ATTENTION",
            "SLOWEST",
            "REPEATED",
            "VERSIONS",
            "Tethers 0.8.1",
        ):
            self.assertIn(heading, text)
        self.assertIn("unavailable", text)

    def test_the_json_envelope_is_versioned(self):
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["schema"], obs.INSPECT_SCHEMA)
        self.assertEqual(report["since_hours"], 24)

    def test_inspection_of_an_empty_state_root_is_benign(self):
        report = inspect_runs(self.state, since_hours=24, now=self.now)
        self.assertEqual(report["runs"], 0)
        self.assertEqual(report["attention"], [])
        self.assertIn("no recorded versions", render_inspect_human(report))


if __name__ == "__main__":
    unittest.main()
