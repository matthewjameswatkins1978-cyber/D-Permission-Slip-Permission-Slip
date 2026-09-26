"""``permission-slip`` command line.

This is intentionally the first tiny product front door -- not the full 0.6
CLI. It owns a small, explicit surface:

``permission-slip doctor [--json]``
    Diagnose Permission Slip, the Tethers installation, the authority
    protocol, and Permission Slip's own state root.

``permission-slip setup [--json]``
    Explicitly provision Permission Slip's Tethers host-data root using
    Tethers' own ``provision-replay``. Deliberately separate from any
    authority request: durable authority state is never created as a side
    effect of ordinary operation.

``permission-slip doctrine export|import|diff|active|adopt``
    Doctrine portability. Import stores a *candidate* and never activates it;
    only ``adopt`` -- with an explicit expected-current digest -- may change
    which doctrine is active.

Doctrine failures render ``INVALID DOCTRINE``, ``CONFLICT`` or ``NOT READY``
with the offending path and reason, and exit nonzero, instead of reaching the
human as a traceback.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
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
from . import doctrine as doctrine_module
from . import doctrine_export, doctrine_store
from .doctrine_contract import canonical_digest
from .doctrine_contract import DoctrineValidationError
from .doctrine_diff import DIFF_SCHEMA, diff_doctrines, render_human as render_diff
from .doctrine_store import AdoptionConflict, DoctrineStateError, NoActiveDoctrine
from .state import tethers_host_data_root
from .tethers_client import TethersUnavailable
from .tethers_install import (
    GATE_ENV,
    host_data_provisioned,
    provision_host_data_root,
    discover_tethers,
)

IMPORT_RESULT_SCHEMA = "permission-slip.doctrine-import/1"
ACTIVE_REPORT_SCHEMA = "permission-slip.doctrine-active/1"
ADOPT_RESULT_SCHEMA = "permission-slip.doctrine-adopt/1"

#: Diff arguments may name a file or the literal adopted doctrine.
ACTIVE_TOKEN = "active"


def _print_setup(report: dict, as_json: bool) -> None:
    if as_json:
        sys.stdout.write(render_json(report))
        return
    print(f"Provisioned {report['host_data_root']}")
    print(f"Tethers: {report.get('product_version') or 'unknown'}")
    print("Next: permission-slip doctor")


# -- doctrine portability --------------------------------------------------


def _doctrine_failure(kind: str, reason: str) -> int:
    """Render a doctrine failure as prose, never as a traceback."""
    print(kind)
    print(f"FAIL: {reason}")
    return 1


def _resolve_doctrine_argument(value: str) -> dict:
    """A diff operand is a file path, or the literal adopted doctrine."""
    if value == ACTIVE_TOKEN:
        return doctrine_store.load_active_doctrine().document
    return doctrine_module.load_doctrine(Path(value))


def _cmd_export(args: argparse.Namespace) -> int:
    document = doctrine_module.load_doctrine(Path(args.doctrine))
    payload = doctrine_export.encode_export(document)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(f"Exported {canonical_digest(document)}")
    print(f"  -> {output}")
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    text = Path(args.export_file).read_text(encoding="utf-8")
    imported = doctrine_store.import_export(text)
    active = doctrine_store.read_active_digest()
    payload = {
        "schema": IMPORT_RESULT_SCHEMA,
        "candidate_digest": imported.digest,
        "candidate_path": str(imported.path),
        "active_digest": active,
        "activated": False,
    }
    if args.json:
        sys.stdout.write(render_json(payload))
        return 0
    print(f"Candidate {imported.digest}")
    print(f"Stored at {imported.path}")
    print(f"Active doctrine unchanged: {active or 'none'}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    before = _resolve_doctrine_argument(args.before)
    after = _resolve_doctrine_argument(args.after)
    envelope = diff_doctrines(before, after)
    if args.json:
        sys.stdout.write(render_json(envelope))
    else:
        print(render_diff(envelope))
    return 0


def _cmd_active(args: argparse.Namespace) -> int:
    try:
        loaded = doctrine_store.load_active_doctrine()
    except NoActiveDoctrine:
        if args.json:
            sys.stdout.write(
                render_json({"schema": ACTIVE_REPORT_SCHEMA, "active": None})
            )
        else:
            print("No active doctrine")
        return 0
    payload = {
        "schema": ACTIVE_REPORT_SCHEMA,
        "doctrine_digest": loaded.digest,
        "doctrine_schema": loaded.document["schema"],
        "profile": loaded.document["profile"],
    }
    if args.json:
        sys.stdout.write(render_json(payload))
        return 0
    print(f"Active doctrine {loaded.digest}")
    print(f"  schema  {loaded.document['schema']}")
    print(f"  profile {loaded.document['profile']}")
    return 0


def _cmd_adopt(args: argparse.Namespace) -> int:
    expect = args.expect_current.strip()
    expected: str | None = None if expect.lower() == "none" else expect
    previous = doctrine_store.read_active_digest()
    digest = doctrine_store.adopt(args.candidate, expect_current=expected)
    payload = {
        "schema": ADOPT_RESULT_SCHEMA,
        "candidate_digest": digest,
        "previous_digest": previous,
        "active_digest": digest,
    }
    if args.json:
        sys.stdout.write(render_json(payload))
        return 0
    print(f"Adopted {digest}")
    print(f"  previous {previous or 'none'}")
    return 0


def _run_doctrine(args: argparse.Namespace) -> int:
    handlers = {
        "export": _cmd_export,
        "import": _cmd_import,
        "diff": _cmd_diff,
        "active": _cmd_active,
        "adopt": _cmd_adopt,
    }
    try:
        return handlers[args.doctrine_command](args)
    except DoctrineValidationError as exc:
        return _doctrine_failure("INVALID DOCTRINE", str(exc))
    except AdoptionConflict as exc:
        return _doctrine_failure("CONFLICT", str(exc))
    except (DoctrineStateError, OSError) as exc:
        return _doctrine_failure("NOT READY", str(exc))


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

    doctrine_parser = subparsers.add_parser(
        "doctrine",
        help="Export, import, diff, inspect and explicitly adopt doctrine.",
    )
    doctrine_commands = doctrine_parser.add_subparsers(
        dest="doctrine_command", required=True
    )

    export_parser = doctrine_commands.add_parser(
        "export", help="Write a portable, deterministic export envelope."
    )
    export_parser.add_argument("doctrine", help="path to a doctrine JSON document")
    export_parser.add_argument(
        "--output", "-o", required=True, help="file to write the envelope to"
    )

    import_parser = doctrine_commands.add_parser(
        "import",
        help="Verify an export envelope and store it as a CANDIDATE (never active).",
    )
    import_parser.add_argument("export_file", help="path to an export envelope")
    import_parser.add_argument(
        "--json", action="store_true", help=f"Emit the {IMPORT_RESULT_SCHEMA} envelope."
    )

    diff_parser = doctrine_commands.add_parser(
        "diff", help="Domain-aware diff of two doctrines."
    )
    diff_parser.add_argument(
        "before", help=f'a doctrine file, or the literal "{ACTIVE_TOKEN}"'
    )
    diff_parser.add_argument(
        "after", help=f'a doctrine file, or the literal "{ACTIVE_TOKEN}"'
    )
    diff_parser.add_argument(
        "--json", action="store_true", help=f"Emit the {DIFF_SCHEMA} envelope."
    )

    active_parser = doctrine_commands.add_parser(
        "active", help="Report the adopted (active) doctrine, if any."
    )
    active_parser.add_argument(
        "--json", action="store_true", help=f"Emit the {ACTIVE_REPORT_SCHEMA} envelope."
    )

    adopt_parser = doctrine_commands.add_parser(
        "adopt",
        help="Explicitly make an existing verified candidate the active doctrine.",
    )
    adopt_parser.add_argument(
        "--candidate",
        required=True,
        help="candidate digest to adopt; the candidate must already exist",
    )
    adopt_parser.add_argument(
        "--expect-current",
        required=True,
        help="digest believed to be active right now, or the literal 'none'",
    )
    adopt_parser.add_argument(
        "--json", action="store_true", help=f"Emit the {ADOPT_RESULT_SCHEMA} envelope."
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

    if args.command == "doctrine":
        return _run_doctrine(args)

    return 2  # pragma: no cover - argparse enforces a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
