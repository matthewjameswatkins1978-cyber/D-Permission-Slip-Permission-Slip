"""Customer Zero dogfood harness: the trusted launcher for real host effects.

This is deliberately **not** the 0.6 front door. It is the smallest trusted
Python entry point that can stand up everything the first real effects need:

* the **adopted** doctrine (import != adoption; this never adopts);
* a fully validated **trusted host context**;
* the **real host executor**;
* the **observability recorder**;
* the verified Tethers 0.8.1 product.

Trusted launcher facts, never operation payload:

* **actor identity** comes from ``--actor``;
* **physical repository root** comes from ``--repo``.

A ``--op`` document that carries an ``actor`` key, a ``command``, a ``remote_url``
or any other authority claim has that claim ignored by the adapter -- it can
describe requested work and nothing more.

    python scripts/permission_slip_dogfood.py \\
        --actor matthew --repo D:\\dogfood\\permission-slip \\
        --op '{"tool":"tests","profile":"permission-slip-smoke"}'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from permission_slip import doctrine_store  # noqa: E402
from permission_slip.host_context import HostContextError, TrustedHostContext  # noqa: E402
from permission_slip.host_executor import RealHostExecutor  # noqa: E402
from permission_slip.observability import TraceRecorder, runs_root  # noqa: E402
from permission_slip.spike import PermissionSlip  # noqa: E402
from permission_slip.tethers_client import discover_tethers  # noqa: E402

USAGE = """\
permission-slip dogfood harness (trusted launcher)

  --actor <id>      trusted actor from the harness profile (never from --op)
  --repo <path>     physical Git checkout of the Permission Slip repository
  --op <json>       the operation document
  --op-file <path>  ...or read it from a file
  --state <path>    Permission Slip state root (default: platform state root)
  --approval <a|d>  answer an ASK with "approve" or "deny"
  --json            print the receipt as JSON

No active doctrine:
    permission-slip doctrine import <export>
    permission-slip doctrine adopt --candidate <digest> --expect-current none
"""


def _load_operation(args: argparse.Namespace) -> dict[str, Any]:
    if args.op_file:
        return json.loads(Path(args.op_file).read_text(encoding="utf-8"))
    if not args.op:
        raise SystemExit("one of --op or --op-file is required\n\n" + USAGE)
    return json.loads(args.op)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="permission_slip_dogfood.py",
        description="Trusted launcher for Permission Slip real host effects.",
        usage=USAGE,
    )
    parser.add_argument("--actor", required=True, help="trusted actor id (launcher fact)")
    parser.add_argument("--repo", required=True, help="physical repository root (launcher fact)")
    parser.add_argument("--op", help="operation document as JSON")
    parser.add_argument("--op-file", help="path to a JSON operation document")
    parser.add_argument("--state", help="Permission Slip state root override")
    parser.add_argument("--approval", choices=("approve", "deny"), default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    operation = _load_operation(args)
    # The payload can never become identity or geography: those two fields are
    # launcher facts, and the adapter ignores any look-alike in the document.
    for key in ("actor", "repo_root", "repo", "repository_root", "root"):
        operation.pop(key, None)

    state_root = Path(args.state) if args.state else None

    try:
        paths = discover_tethers()
    except Exception as exc:  # TethersUnavailable and friends
        print(f"NOT READY\nFAIL: {exc}\n  -> Set TETHERS_ROOT or a released Tethers on PATH.")
        return 1

    try:
        slip = PermissionSlip.from_active_doctrine(
            state_root=state_root,
            repo_root=args.repo,
            paths=paths,
        )
    except Exception as exc:
        print("NOT READY")
        print(f"FAIL: {exc}")
        print(USAGE)
        return 1

    recorder = TraceRecorder(state_root, session={"entry": "dogfood-harness"})
    try:
        host_context = TrustedHostContext.create(repo_root=args.repo, doctrine=slip.doctrine)
        executor = RealHostExecutor(host_context, recorder=recorder)
    except HostContextError as exc:
        print("NOT READY")
        print(f"FAIL: {exc}")
        return 1

    slip.executor = executor
    slip.host_context = host_context
    slip.adapter = __import__(
        "permission_slip.actions", fromlist=["ActionAdapter"]
    ).ActionAdapter(slip.doctrine, host_context=host_context)
    slip.recorder = recorder

    slip.start()
    try:
        receipt = slip.run(
            operation,
            args.actor,
            approval=args.approval,
        )
    finally:
        slip.close()

    payload = receipt.as_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"decision  {receipt.decision}")
        print(f"reason    {receipt.reason}")
        print(f"executed  {receipt.executed}")
        print(f"outcome   {receipt.outcome}")
        if receipt.effects:
            print(f"effects   {', '.join(receipt.effects)}")
        if receipt.error:
            print(f"error     {receipt.error}")
        print(f"run_id    {receipt.run_id}")
        print(f"session   {receipt.session_id}")
        print(f"trace     {runs_root(state_root) / (receipt.run_id or '')}")
        print("inspect   permission-slip inspect --since 24h")

    # Success of the *harness* is "we learned the truth"; the physical outcome
    # is reported, never assumed.
    return 0 if receipt.decision != "UNAVAILABLE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
