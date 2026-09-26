"""``permission-slip`` command line.

This is intentionally the first tiny product front door -- not the full 0.6
CLI. It owns two explicit, bounded commands:

``permission-slip doctor [--json]``
    Diagnose Permission Slip, the Tethers installation, the authority
    protocol, and Permission Slip's own state root.

``permission-slip setup [--json]``
    Explicitly provision Permission Slip's Tethers host-data root using
    Tethers' own ``provision-replay``. Deliberately separate from any
    authority request: durable authority state is never created as a side
    effect of ordinary operation.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .doctor import (
    DOCTOR_SCHEMA,
    SETUP_SCHEMA,
    exit_code_for,
    render_human,
    render_json,
    run_doctor,
)
from .state import tethers_host_data_root
from .tethers_client import TethersUnavailable
from .tethers_install import (
    GATE_ENV,
    host_data_provisioned,
    provision_host_data_root,
    discover_tethers,
)


def _print_setup(report: dict, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(render_json(report))
        return
    print(f"Provisioned {report['host_data_root']}")
    print(f"Tethers: {report.get('product_version') or 'unknown'}")
    print("Next: permission-slip doctor")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="permission-slip",
        description="Permission Slip -- human doctrine over Tethers authority.",
    )
    parser.add_argument(
        "--version", action="version", version=f"permission-slip {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser(
        "doctor", help="Diagnose Permission Slip and its Tethers installation."
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help=f"Emit the versioned {DOCTOR_SCHEMA} envelope instead of prose.",
    )
    doctor_parser.add_argument(
        "--no-protocol-probe",
        action="store_true",
        help="Skip launching the Gate to negotiate tethers.authority/1.",
    )

    setup_parser = subparsers.add_parser(
        "setup",
        help="Explicitly provision Permission Slip's Tethers host-data root."
    )
    setup_parser.add_argument(
        "--json", action="store_true", help="Emit the versioned setup envelope."
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "doctor":
        report = run_doctor(probe_protocol=not args.no_protocol_probe)
        sys.stdout.write(
            render_json(report) if args.json else render_human(report) + "\n"
        )
        return exit_code_for(report["overall"]["status"])

    if args.command == "setup":
        root = tethers_host_data_root()
        already_provisioned = host_data_provisioned(root)
        try:
            installation = discover_tethers()
        except TethersUnavailable as exc:
            payload = {
                "schema": SETUP_SCHEMA,
                "status": "FAIL",
                "host_data_root": str(root),
                "provisioned": already_provisioned,
                "error": {"code": exc.code, "message": str(exc)},
            }
            if args.json:
                sys.stdout.write(render_json(payload))
            else:
                print("NOT READY")
                print(f"FAIL: {exc}")
                print(f"  -> Set a released Tethers on PATH or {GATE_ENV}.")
            return 1
        report = provision_host_data_root(installation, root)
        report["status"] = "PASS"
        report["already_provisioned"] = already_provisioned
        _print_setup(report, args.json)
        return 0

    return 2  # pragma: no cover - argparse enforces a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
