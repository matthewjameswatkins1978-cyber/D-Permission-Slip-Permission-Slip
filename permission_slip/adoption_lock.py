"""One cross-process advisory lock around the doctrine adoption decision.

``os.replace`` makes a *write* atomic. It does **not** make this atomic between
two processes::

    read active -> compare against expected -> verify candidate -> write

Without a lock, two processes that both believe ``X`` is active can each read
``X``, each pass the comparison, each verify its own candidate, and each replace
the pointer. Both then report success while "adopt only if the active doctrine
is still X" holds for neither of them. The compare-and-swap was a claim, not a
guarantee.

This module closes exactly that gap, and nothing else. The whole adoption
decision runs while holding an OS advisory lock over one byte of one file:

* **POSIX** -- ``fcntl.flock(fd, LOCK_EX)`` on an open descriptor.
* **Windows** -- ``msvcrt.locking(fd, LK_NBLCK, 1)`` retried to the deadline.

Both are released by the kernel the instant the owning process exits, however
it exits -- including a crash or ``os._exit`` with no ``finally`` run at all.

**This is deliberately not a sentinel.** ``.adoption.lock`` is a permanent,
boring, one-byte file that means nothing on its own; only a *held* advisory
lock means anything. Nothing here is deleted, so nothing here can be stranded,
and no doctrine state form changes: the candidates directory and the active
pointer are exactly as they were.

Only adoption needs this. Import, export, diff and reading the active doctrine
are independent readers or non-pointer writers and must stay independent --
serialising them would buy nothing and cost a lock on every read.
"""

from __future__ import annotations

import errno
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

#: Inside ``<state>/doctrine``. Advisory only; never a "locked means locked"
#: marker, and never consulted for anything but acquiring the advisory lock.
ADOPTION_LOCK_NAME = ".adoption.lock"

#: Sleep between non-blocking acquisition attempts. Small enough that a
#: holder's millisecond-scale critical section is not a visible delay.
DEFAULT_POLL_SECONDS = 0.005

#: Errnos that mean "somebody else holds it", and nothing worse. Anything else
#: is a genuine failure and is re-raised rather than retried forever -- it is
#: better to fail loudly than to spin on a broken descriptor.
_CONTENTION_ERRNOS = frozenset(
    {
        errno.EACCES,
        errno.EAGAIN,
        errno.EDEADLOCK,
        errno.EWOULDBLOCK,
        errno.EINTR,
    }
)


class AdoptionLockTimeout(TimeoutError):
    """The adoption lock was not acquired before the caller's deadline.

    Subclasses ``TimeoutError`` (an ``OSError``), so the doctrine CLI renders
    it as ``NOT READY`` rather than as a traceback. It is never confused with
    :class:`~permission_slip.doctrine_store.AdoptionConflict`: a timeout says
    nothing about the state of the store, which is exactly why the
    expected-current comparison has to wait for the lock.
    """


# -- platform-specific primitives -------------------------------------------
#
# Deliberately the only platform-split code in the fix: two tiny functions,
# both non-blocking attempts so that one timeout policy serves both platforms.

if os.name == "nt":
    import msvcrt

    def _try_lock(fd: int) -> None:
        """One non-blocking ``LK_NBLCK`` attempt over byte zero.

        A contended lock raises ``PermissionError``/``OSError`` with
        ``errno == EACCES``; :func:`_acquire` decides whether to retry it.
        """
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> None:
        """One non-blocking ``flock(LOCK_EX | LOCK_NB)`` attempt."""
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


# -- paths ------------------------------------------------------------------


def adoption_lock_path(store_root: str | Path) -> Path:
    """``<state>/doctrine/.adoption.lock``.

    The file is permanent and inert. Its existence is never evidence of
    ownership, so a crash can never leave a lock file that still looks locked.
    """
    return Path(store_root) / ADOPTION_LOCK_NAME


def _open_lock_file(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o666)
    try:
        if os.fstat(fd).st_size == 0:
            # Lock a definite byte rather than a region past EOF. Two processes
            # may both take this branch; both write a NUL at offset zero, so the
            # file is one byte either way and everyone locks byte zero.
            os.write(fd, b"\0")
    except BaseException:
        os.close(fd)
        raise
    return fd


# -- acquisition ------------------------------------------------------------


def _is_contention(exc: OSError) -> bool:
    return exc.errno in _CONTENTION_ERRNOS


def _acquire(fd: int, path: Path, timeout: float | None, poll: float) -> None:
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        try:
            _try_lock(fd)
            return
        except OSError as exc:
            if not _is_contention(exc):
                raise
            if deadline is not None and time.monotonic() >= deadline:
                raise AdoptionLockTimeout(
                    f"adoption lock {path} not acquired within {timeout:g} seconds"
                ) from None
            time.sleep(poll)


@contextmanager
def adoption_lock(
    store_root: str | Path,
    *,
    timeout: float | None = None,
    poll: float = DEFAULT_POLL_SECONDS,
) -> Iterator[Path]:
    """Hold the doctrine adoption lock for the duration of the block.

    ``timeout=None`` (the default) waits as long as it takes; a live holder
    only ever holds this for the length of one read-verify-replace, and a dead
    one has already lost it to the kernel. ``timeout`` exists so a caller can
    fail closed instead of waiting forever.

    Not reentrant: one acquisition per process. Nothing in Permission Slip
    nests adoption.
    """
    path = adoption_lock_path(store_root)
    fd = _open_lock_file(path)
    try:
        _acquire(fd, path, timeout, poll)
        try:
            yield path
        finally:
            try:
                _unlock(fd)
            except OSError:
                # Closing the descriptor below releases the lock regardless;
                # failing to unlock explicitly must not mask the real error.
                pass
    finally:
        os.close(fd)


__all__ = [
    "ADOPTION_LOCK_NAME",
    "AdoptionLockTimeout",
    "DEFAULT_POLL_SECONDS",
    "adoption_lock",
    "adoption_lock_path",
]
