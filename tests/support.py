"""Shared test fixture: a real temporary Git repository with controlled remotes.

No network operation ever occurs. ``git init`` and ``git remote add`` are pure
local configuration writes, and ``git remote get-url --push`` only reads that
configuration back.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from permission_slip.doctrine import load_doctrine

DOCTRINE_PATH = Path(__file__).resolve().parent.parent / "doctrine" / "matthew.v0.1.json"
CANONICAL_REPOSITORY = load_doctrine(DOCTRINE_PATH)["project"]["canonical_repository"]
CANONICAL_IDENTITY = "github.com/matthewjameswatkins1978-cyber/d-permission-slip-permission-slip"

# A deliberately wrong remote: a non-GitHub host.
EVIL_REMOTE_URL = "https://evil.example/example.git"
# A different repository on the *right* host.
OTHER_GITHUB_REMOTE_URL = "https://github.com/someone-else/repo.git"


def _git(*args: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed ({completed.returncode}): "
            f"{(completed.stderr or '').strip()}"
        )
    return (completed.stdout or "").strip()


def init_git_repo(path: str | Path, remotes: dict[str, str] | None = None) -> Path:
    """Create a real temporary Git repository with the given remotes.

    ``origin`` always points at the doctrine's canonical repository so that
    ordinary test operations exercise the standing-ALLOW path.
    """
    repo = Path(path)
    repo.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", str(repo))
    configured = {"origin": CANONICAL_REPOSITORY}
    if remotes:
        configured.update(remotes)
    for name, url in configured.items():
        _git("remote", "add", name, url, cwd=repo)
    return repo


def set_remote_url(repo: str | Path, name: str, url: str) -> None:
    _git("remote", "set-url", name, url, cwd=Path(repo))


def add_remote(repo: str | Path, name: str, url: str) -> None:
    _git("remote", "add", name, url, cwd=Path(repo))


def set_push_url(repo: str | Path, name: str, url: str) -> None:
    """Retarget only the *push* URL, leaving the fetch URL untouched."""
    _git("remote", "set-url", "--push", name, url, cwd=Path(repo))
