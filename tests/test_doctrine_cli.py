"""``permission-slip doctrine`` CLI: bounded surface, prose failures, no tracebacks."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from permission_slip.__main__ import main
from tests.support import matthew_doctrine


def run_cli(*argv: str) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(list(argv))
    return code, buffer.getvalue()


class CliHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-cli-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        patcher = mock.patch.dict(
            os.environ, {"PERMISSION_SLIP_STATE_DIR": str(self.state)}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        self.original = self.root / "original.json"
        self.original.write_text(
            json.dumps(matthew_doctrine(), indent=2), encoding="utf-8"
        )
        self.envelope = self.root / "doctrine.ps.json"

    def export(self) -> Path:
        code, out = run_cli(
            "doctrine", "export", str(self.original), "--output", str(self.envelope)
        )
        self.assertEqual(code, 0, out)
        return self.envelope

    def imported_digest(self) -> str:
        code, out = run_cli(
            "doctrine", "import", str(self.export()), "--json"
        )
        self.assertEqual(code, 0, out)
        return json.loads(out)["candidate_digest"]


class ExportCommandTests(CliHarness):
    def test_export_writes_the_envelope_and_reports_the_digest(self):
        path = self.export()
        envelope = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(envelope["schema"], "permission-slip.doctrine-export/1")
        code, out = run_cli(
            "doctrine", "export", str(self.original), "--output", str(self.root / "b.json")
        )
        self.assertEqual(code, 0)
        self.assertIn("sha256:", out)
        self.assertEqual(
            (self.root / "b.json").read_bytes(), path.read_bytes()
        )

    def test_export_of_a_malformed_doctrine_is_invalid_doctrine(self):
        broken = self.root / "broken.json"
        document = matthew_doctrine()
        document.pop("profile")
        broken.write_text(json.dumps(document), encoding="utf-8")
        code, out = run_cli(
            "doctrine", "export", str(broken), "--output", str(self.root / "x.json")
        )
        self.assertEqual(code, 1)
        self.assertIn("INVALID DOCTRINE", out)
        self.assertIn("$.profile", out)
        self.assertNotIn("Traceback", out)
        self.assertFalse((self.root / "x.json").exists())


class ImportCommandTests(CliHarness):
    def test_import_reports_candidate_and_unchanged_active(self):
        envelope = self.export()
        code, out = run_cli("doctrine", "import", str(envelope))
        self.assertEqual(code, 0)
        self.assertIn("Candidate sha256:", out)
        self.assertIn("Active doctrine unchanged: none", out)
        self.assertFalse((self.state / "doctrine" / "active.json").exists())

    def test_import_json_marks_it_not_activated(self):
        envelope = self.export()
        code, out = run_cli("doctrine", "import", str(envelope), "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertFalse(payload["activated"])
        self.assertIsNone(payload["active_digest"])
        self.assertEqual(payload["schema"], "permission-slip.doctrine-import/1")

    def test_import_of_a_tampered_envelope_is_invalid_doctrine(self):
        envelope = json.loads(self.export().read_text(encoding="utf-8"))
        envelope["doctrine"]["human"]["display_name"] = "Mallory"
        path = self.root / "tampered.json"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        code, out = run_cli("doctrine", "import", str(path))
        self.assertEqual(code, 1)
        self.assertIn("INVALID DOCTRINE", out)
        self.assertIn("$.doctrine_digest", out)
        self.assertNotIn("Traceback", out)

    def test_import_of_a_missing_file_is_not_ready(self):
        code, out = run_cli("doctrine", "import", str(self.root / "absent.json"))
        self.assertEqual(code, 1)
        self.assertIn("NOT READY", out)
        self.assertNotIn("Traceback", out)


class ActiveCommandTests(CliHarness):
    def test_active_reports_none_before_adoption(self):
        code, out = run_cli("doctrine", "active")
        self.assertEqual(code, 0)
        self.assertIn("No active doctrine", out)

    def test_active_json_reports_none_before_adoption(self):
        code, out = run_cli("doctrine", "active", "--json")
        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(out)["active"])

    def test_active_reports_the_adopted_doctrine(self):
        digest = self.imported_digest()
        code, out = run_cli("doctrine", "adopt", "--candidate", digest, "--expect-current", "none")
        self.assertEqual(code, 0, out)
        code, out = run_cli("doctrine", "active", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["doctrine_digest"], digest)
        self.assertEqual(payload["profile"], "matthew.v0.1")
        self.assertEqual(payload["doctrine_schema"], "permission-slip.doctrine/1")


class AdoptCommandTests(CliHarness):
    def test_adopt_from_none_then_reports_active(self):
        digest = self.imported_digest()
        code, out = run_cli(
            "doctrine", "adopt", "--candidate", digest, "--expect-current", "none", "--json"
        )
        self.assertEqual(code, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["active_digest"], digest)
        self.assertIsNone(payload["previous_digest"])

    def test_stale_adoption_reports_conflict(self):
        digest = self.imported_digest()
        run_cli("doctrine", "adopt", "--candidate", digest, "--expect-current", "none")
        code, out = run_cli(
            "doctrine", "adopt", "--candidate", digest, "--expect-current", "none"
        )
        self.assertEqual(code, 1)
        self.assertIn("CONFLICT", out)
        self.assertIn("refusing to adopt", out)
        self.assertNotIn("Traceback", out)

    def test_adopting_an_absent_candidate_reports_not_ready(self):
        digest = "sha256:" + "0" * 64
        code, out = run_cli(
            "doctrine", "adopt", "--candidate", digest, "--expect-current", "none"
        )
        self.assertEqual(code, 1)
        self.assertIn("NOT READY", out)
        self.assertNotIn("Traceback", out)

    def test_adopt_never_imports(self):
        digest = "sha256:" + "0" * 64
        run_cli("doctrine", "adopt", "--candidate", digest, "--expect-current", "none")
        self.assertFalse((self.state / "doctrine" / "active.json").exists())


class DiffCommandTests(CliHarness):
    def _mutated(self, name: str) -> Path:
        document = matthew_doctrine()
        document["capabilities"][6]["standing"] = "allow"
        path = self.root / name
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return path

    def test_diff_two_files_renders_human_output(self):
        changed = self._mutated("changed.json")
        code, out = run_cli("doctrine", "diff", str(self.original), str(changed))
        self.assertEqual(code, 0)
        self.assertIn("Doctrine diff", out)
        self.assertIn(
            "git.history.rewrite standing changed ASK -> ALLOW", out
        )

    def test_diff_json_emits_the_versioned_envelope(self):
        changed = self._mutated("changed.json")
        code, out = run_cli("doctrine", "diff", str(changed), str(self.original), "--json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["schema"], "permission-slip.doctrine-diff/1")
        self.assertTrue(payload["changed"])

    def test_diff_against_the_active_doctrine(self):
        digest = self.imported_digest()
        run_cli("doctrine", "adopt", "--candidate", digest, "--expect-current", "none")
        changed = self._mutated("changed.json")
        code, out = run_cli("doctrine", "diff", str(changed), "active")
        self.assertEqual(code, 0)
        self.assertIn("git.history.rewrite standing changed ALLOW -> ASK", out)

    def test_diff_without_an_active_doctrine_reports_not_ready(self):
        code, out = run_cli("doctrine", "diff", "active", str(self.original))
        self.assertEqual(code, 1)
        self.assertIn("NOT READY", out)
        self.assertNotIn("Traceback", out)

    def test_diff_of_a_malformed_file_reports_invalid_doctrine(self):
        broken = self.root / "broken.json"
        document = matthew_doctrine()
        document.pop("capabilities")
        broken.write_text(json.dumps(document), encoding="utf-8")
        code, out = run_cli("doctrine", "diff", str(broken), str(self.original))
        self.assertEqual(code, 1)
        self.assertIn("INVALID DOCTRINE", out)
        self.assertNotIn("Traceback", out)

    def test_identical_documents_report_no_changes(self):
        code, out = run_cli("doctrine", "diff", str(self.original), str(self.original))
        self.assertEqual(code, 0)
        self.assertIn("No changes.", out)


if __name__ == "__main__":
    unittest.main()
