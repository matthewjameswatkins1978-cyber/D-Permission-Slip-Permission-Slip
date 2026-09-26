"""Cross-platform Permission Slip state root.

Permission Slip owns a stable, user-owned location for its durable state --
notably the Tethers host-data root it drives. This must be private to
Permission Slip: it never shares an arbitrary global Tethers host-data root
with unrelated applications.

Resolution order:

1. ``PERMISSION_SLIP_STATE_DIR`` -- an explicit override, honoured verbatim;
2. the OS convention for user-owned application state.

The platform and environment are injectable so the rules can be tested on any
host without touching the real filesystem.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping

STATE_DIR_ENV = "PERMISSION_SLIP_STATE_DIR"

#: Application directory name used by the two platform families.
_WINDOWS_APP_DIR = "Permission Slip"
_UNIX_APP_DIR = "permission-slip"

#: Child directory holding the Tethers durable host state Permission Slip owns.
TETHERS_HOST_STATE_DIR = "tethers-host"


def _home(env: Mapping[str, str], home: Path | None) -> Path:
    if home is not None:
        return home
    override = env.get("HOME") or env.get("USERPROFILE")
    if override:
        return Path(override)
    return Path.home()


def permission_slip_state_root(
    env: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Return Permission Slip's state root for this platform.

    Defaults:

    * Windows: ``%LOCALAPPDATA%\\Permission Slip\\state``
    * macOS:   ``~/Library/Application Support/Permission Slip/State``
    * Linux:   ``$XDG_STATE_HOME/permission-slip``, else
      ``~/.local/state/permission-slip``
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    plat = sys.platform if platform is None else platform
    home_dir = _home(environ, home)

    override = environ.get(STATE_DIR_ENV)
    if override:
        return Path(override).expanduser()

    if plat == "win32":
        local_app_data = environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else home_dir / "AppData" / "Local"
        return base / _WINDOWS_APP_DIR / "state"

    if plat == "darwin":
        return home_dir / "Library" / "Application Support" / _WINDOWS_APP_DIR / "State"

    xdg_state = environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state).expanduser() / _UNIX_APP_DIR
    return home_dir / ".local" / "state" / _UNIX_APP_DIR


def tethers_host_data_root(
    env: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Permission Slip's own Tethers host-data root.

    A child of :func:`permission_slip_state_root`, stable across restarts and
    private to Permission Slip.
    """
    return permission_slip_state_root(env, platform=platform, home=home) / TETHERS_HOST_STATE_DIR
