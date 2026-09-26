"""Adoption is a cross-process compare-and-swap, not just a same-process one.

``os.replace`` makes a *write* atomic. It does not make::

    read active -> compare against expected -> verify candidate -> write

atomic between two concurrent processes. Without a lock, two processes that
both believe ``X`` is active can both pass the comparison and both replace the
pointer, so both report success while the law they each claimed to honour --
"adopt only if the active doctrine is still X" -- holds for neither.

These tests therefore use **real separate processes**, synchronised onto the
same expected-current state at the same instant, and require exactly one
winner. The sequential cases are covered in ``test_doctrine_store.py`` and are
retained untouched there.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from permission_slip.adoption_lock import (
    AdoptionLockTimeout,
    adoption_lock,
    adoption_lock_path,
)
from permission_slip.doctrine_export import encode_export
from permission_slip.doctrine_store import (
    AdoptionConflict,
    adopt,
    import_export,
    load_active_doctrine,
    read_active_digest,
    store_root,
)
from tests.support import matthew_doctrine

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Two processes that signal they are parked at a shared barrier, wait for one
#: shared "go" file, and then call ``adopt`` together. Written as a real child
#: program: a thread or a second call in this process would not be contention.
ADOPT_CHILD = """
import json
import os
import sys
import time

from permission_slip.doctrine_store import AdoptionConflict, adopt

state, candidate, expected, go, result = sys.argv[1:6]
expected = None if expected == "none" else expected

with open(result + ".ready", "w", encoding="utf-8") as stream:
    stream.write("ready")
while not os.path.exists(go):
    time.sleep(0.0005)

try:
    adopt(candidate, expect_current=expected, state_root=state)
except AdoptionConflict as exc:
    payload = {"outcome": "conflict", "detail": str(exc)}
    code = 1
except BaseException as exc:
    payload = {"outcome": "error", "detail": "%s: %s" % (type(exc).__name__, exc)}
    code = 2
else:
    payload = {"outcome": "adopted", "detail": candidate}
    code = 0

with open(result, "w", encoding="utf-8") as stream:
    json.dump(payload, stream)
raise SystemExit(code)
"""

#: Holds the adoption lock until told to let go -- used to prove that the
#: expected-current comparison happens *while the lock is held*.
LOCK_HOLD_CHILD = """
import os
import sys
import time

from permission_slip.adoption_lock import adoption_lock

store, holding, release = sys.argv[1:4]
with adoption_lock(store):
    with open(holding, "w", encoding="utf-8") as stream:
        stream.write("holding")
    while not os.path.exists(release):
        time.sleep(0.005)
"""

#: Takes the lock and dies without running a single ``finally`` block: the
#: kernel, not our cleanup, has to be what releases it.
LOCK_CRASH_CHILD = """
import os
import sys

from permission_slip.adoption_lock import adoption_lock

store = sys.argv[1]
with adoption_lock(store):
    os._exit(7)
"""

OTHER_DIGEST = "sha256:" + "0" * 64


class LockHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ps-cas-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.store = store_root(self.state)
        self.last_child_stderr = ""

    def import_doctrine(self, document: dict[str, Any]):
        return import_export(
            encode_export(document).decode("utf-8"), state_root=self.state
        )

    def variant(self, note: str) -> dict[str, Any]:
        document = matthew_doctrine()
        document["human"]["note"] = note
        return document

    def child_env(self) -> dict[str, str]:
        env = dict(os.environ)
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(REPO_ROOT) + (
            os.pathsep + existing if existing else ""
        )
        return env

    def spawn(self, program: str, *args: object) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, "-c", program, *(str(arg) for arg in args)],
            cwd=str(REPO_ROOT),
            env=self.child_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def await_exit(
        self, process: subprocess.Popen[str], timeout: float = 30.0
    ) -> int:
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
            self.fail(f"child process did not exit within {timeout:g}s")
        self.last_child_stderr = (stderr or "").strip()
        return process.returncode

    def await_path(self, path: Path, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(f"timed out waiting for {path.name}")
            time.sleep(0.005)


class ConcurrentAdoptionTests(LockHarness):
    """Two processes, one expected state, exactly one winner."""

    def test_concurrent_adoption_from_one_expected_state_has_one_winner(self) -> None:
        x = self.import_doctrine(matthew_doctrine())
        candidate_a = self.import_doctrine(self.variant("adopted by process A"))
        candidate_b = self.import_doctrine(self.variant("adopted by process B"))
        self.assertNotEqual(candidate_a.digest, candidate_b.digest)

        # Start from a real, non-trivial expected state: active == X.
        adopt(x.digest, expect_current=None, state_root=self.state)
        self.assertEqual(read_active_digest(self.state), x.digest)

        go = self.root / "go"
        results = [self.root / "result-0", self.root / "result-1"]
        processes = [
            self.spawn(
                ADOPT_CHILD,
                self.state,
                candidate.digest,
                x.digest,
                go,
                result,
            )
            for candidate, result in (
                (candidate_a, results[0]),
                (candidate_b, results[1]),
            )
        ]

        # Both processes must be parked at the barrier before either is let go.
        for result in results:
            self.await_path(Path(str(result) + ".ready"))
        go.touch()

        codes = [self.await_exit(process) for process in processes]
        outcomes = [
            json.loads(result.read_text(encoding="utf-8"))["outcome"]
            for result in results
        ]

        # Exactly one success, exactly one AdoptionConflict, nothing else.
        detail = f"exit codes {codes}, outcomes {outcomes}, stderr={self.last_child_stderr!r}"
        self.assertEqual(codes.count(0), 1, detail)
        self.assertEqual(codes.count(1), 1, detail)
        self.assertEqual(outcomes.count("adopted"), 1, f"outcomes {outcomes}")
        self.assertEqual(outcomes.count("conflict"), 1, f"outcomes {outcomes}")
        self.assertNotIn("error", outcomes, f"outcomes {outcomes}")

        # The winner's exit code identifies which candidate actually won.
        expected = (
            candidate_a.digest if codes[0] == 0 else candidate_b.digest
        )
        self.assertIn(expected, (candidate_a.digest, candidate_b.digest))

        # The pointer names the winner, and the winner still verifies.
        final = read_active_digest(self.state)
        self.assertEqual(final, expected)
        loaded = load_active_doctrine(self.state)
        self.assertEqual(loaded.digest, final)
        self.assertIn(loaded.digest, (candidate_a.digest, candidate_b.digest))

        # The loser did not write anything of its own.
        self.assertNotEqual(
            final,
            candidate_b.digest if codes[0] == 0 else candidate_a.digest,
        )


class CriticalSectionTests(LockHarness):
    """The expected-current comparison must happen while the lock is held."""

    def test_comparison_and_verification_wait_for_the_lock(self) -> None:
        x = self.import_doctrine(matthew_doctrine())
        candidate = self.import_doctrine(self.variant("the replacement"))
        adopt(x.digest, expect_current=None, state_root=self.state)

        holding = self.root / "holding"
        release = self.root / "release"
        holder = self.spawn(LOCK_HOLD_CHILD, self.store, holding, release)
        try:
            self.await_path(holding)

            # A stale expectation must be reported as a *lock timeout*, not as
            # an AdoptionConflict: if the comparison ran before acquisition it
            # would raise Conflict straight away, and the CAS would not be
            # inside the lock at all.
            with self.assertRaises(AdoptionLockTimeout):
                adopt(
                    candidate.digest,
                    expect_current=OTHER_DIGEST,
                    state_root=self.state,
                    lock_timeout=0.3,
                )
            with self.assertRaises(AdoptionLockTimeout):
                adopt(
                    candidate.digest,
                    expect_current=None,
                    state_root=self.state,
                    lock_timeout=0.3,
                )

            # Nothing was touched while adoption was blocked.
            self.assertEqual(read_active_digest(self.state), x.digest)

            # Only adoption is serialised: readers and importers are free.
            self.assertEqual(load_active_doctrine(self.state).digest, x.digest)
            import_export(
                encode_export(self.variant("imported during contention")).decode(
                    "utf-8"
                ),
                state_root=self.state,
            )
            with self.assertRaises(AdoptionLockTimeout):
                adopt(
                    candidate.digest,
                    expect_current=x.digest,
                    state_root=self.state,
                    lock_timeout=0.3,
                )
        finally:
            release.touch()
            self.await_exit(holder)

        # Once the holder is gone, the same compare-and-swap succeeds.
        self.assertEqual(
            adopt(candidate.digest, expect_current=x.digest, state_root=self.state),
            candidate.digest,
        )
        self.assertEqual(read_active_digest(self.state), candidate.digest)

        # And a second adopter still holding the now-stale expectation loses.
        with self.assertRaises(AdoptionConflict):
            adopt(
                self.import_doctrine(self.variant("too late")).digest,
                expect_current=x.digest,
                state_root=self.state,
                lock_timeout=10.0,
            )
        self.assertEqual(read_active_digest(self.state), candidate.digest)


class CrashRecoveryTests(LockHarness):
    """A dying adopter must never strand the store."""

    def test_a_process_that_dies_holding_the_lock_does_not_poison_it(self) -> None:
        candidate = self.import_doctrine(matthew_doctrine())

        crashed = self.spawn(LOCK_CRASH_CHILD, self.store)
        # The holder exits without unlocking and without running any finally.
        code = self.await_exit(crashed)
        self.assertEqual(code, 7, f"crash child exited {code}: {self.last_child_stderr!r}")

        # The lock file is permanent and inert -- existence is never ownership.
        lock_path = adoption_lock_path(self.store)
        self.assertTrue(lock_path.is_file())
        self.assertEqual(lock_path.name, ".adoption.lock")

        # Ownership was returned to the kernel, so adoption still works.
        adopted = adopt(
            candidate.digest,
            expect_current=None,
            state_root=self.state,
            lock_timeout=10.0,
        )
        self.assertEqual(adopted, candidate.digest)
        self.assertEqual(read_active_digest(self.state), candidate.digest)

    def test_the_lock_lives_in_the_doctrine_store_and_nowhere_else(self) -> None:
        self.assertEqual(
            adoption_lock_path(self.store), self.store / ".adoption.lock"
        )
        self.assertEqual(
            adoption_lock_path(self.store),
            self.state / "doctrine" / ".adoption.lock",
        )

    def test_the_lock_is_advisory_and_released_on_a_normal_exit(self) -> None:
        with adoption_lock(self.store):
            self.assertTrue(adoption_lock_path(self.store).is_file())
        # Releasing is not a delete: the file outlives every acquisition.
        self.assertTrue(adoption_lock_path(self.store).is_file())
        with adoption_lock(self.store, timeout=5.0):
            pass


if __name__ == "__main__":
    unittest.main()
