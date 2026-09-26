"""Cross-platform Permission Slip state-root rules.

Platform and environment are injected, so every branch is exercised on any
host without touching the real filesystem.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from permission_slip.state import (
    STATE_DIR_ENV,
    permission_slip_state_root,
    tethers_host_data_root,
)

HOME = Path("/home/tester")


class StateRootTests(unittest.TestCase):
    def test_windows_default_uses_local_app_data(self):
        root = permission_slip_state_root(
            {"LOCALAPPDATA": r"C:\Users\tester\AppData\Local"},
            platform="win32",
            home=HOME,
        )
        self.assertEqual(
            root,
            Path(r"C:\Users\tester\AppData\Local") / "Permission Slip" / "state",
        )

    def test_windows_without_local_app_data_falls_back_to_profile(self):
        root = permission_slip_state_root({}, platform="win32", home=HOME)
        self.assertEqual(root, HOME / "AppData" / "Local" / "Permission Slip" / "state")

    def test_linux_uses_xdg_state_home(self):
        root = permission_slip_state_root(
            {"XDG_STATE_HOME": "/custom/state"}, platform="linux", home=HOME
        )
        self.assertEqual(root, Path("/custom/state/permission-slip"))

    def test_linux_falls_back_to_local_state(self):
        root = permission_slip_state_root({}, platform="linux", home=HOME)
        self.assertEqual(root, HOME / ".local" / "state" / "permission-slip")

    def test_macos_uses_application_support(self):
        root = permission_slip_state_root({}, platform="darwin", home=HOME)
        self.assertEqual(
            root, HOME / "Library" / "Application Support" / "Permission Slip" / "State"
        )

    def test_explicit_override_wins_on_every_platform(self):
        for platform in ("win32", "linux", "darwin"):
            with self.subTest(platform=platform):
                root = permission_slip_state_root(
                    {STATE_DIR_ENV: "/explicit/state", "XDG_STATE_HOME": "/xdg"},
                    platform=platform,
                    home=HOME,
                )
                self.assertEqual(root, Path("/explicit/state"))

    def test_tethers_host_state_is_a_private_child(self):
        for platform in ("win32", "linux", "darwin"):
            with self.subTest(platform=platform):
                host = tethers_host_data_root({}, platform=platform, home=HOME)
                self.assertEqual(host.name, "tethers-host")
                self.assertEqual(
                    host.parent, permission_slip_state_root({}, platform=platform, home=HOME)
                )

    def test_tethers_host_state_never_lands_in_a_shared_tethers_root(self):
        # Permission Slip must not share an arbitrary global Tethers
        # host-data root with unrelated applications.
        host = tethers_host_data_root({}, platform="win32", home=HOME)
        self.assertNotIn(Path("Tethers") / "data", host.parents)


if __name__ == "__main__":
    unittest.main()
