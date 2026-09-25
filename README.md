# Permission Slip

> Tell one AI what it is allowed to do. Every AI knows.

Permission Slip is the **human-facing, portable authority and working-doctrine
layer**. It turns Matthew's doctrine into the exact action context a
consequential authority engine can decide on, explains that decision in human
terms, and coordinates the result. It is *not* the authority engine.

## Architecture

```
human doctrine
    ↓
Permission Slip trusted action adapter      (permission_slip/actions.py)
    ↓
Tethers Core + tethers.authority/1          (the pinned R2 Authority Gate)
    ↓
ALLOW / ASK / DENY
    ↓
external executor                           (permission_slip/executor.py)
    ↓
OUTCOME / receipt
```

- **Tethers is the deterministic consequential authority engine.** It is the
  single semantic authority that returns `ALLOW` / `ASK` / `DENY`. Permission
  Slip never decides that an action is authorised when Tethers has not
  authorised it.
- **Permission Slip does not execute policy independently.** It has no
  competing policy engine. It normalises trusted operations into semantic
  capabilities, holds supervisory/explanation metadata, coordinates the
  `tethers.authority/1` lifecycle, executes admitted fixtures, and reports
  outcomes.
- **AWS is optional future enforcement**, not required for local operation.
- The external Host/runtime physically executes actions. Tethers never does
  (`provider_invocations` is always `0`).

The vocabulary is about human consequences, not low-level primitives. A normal
feature push and a private-repository upload both use the network; they are not
the same human action, and Permission Slip does not collapse them.

## This repository

This is the **v0.1 vertical integration spike**. It proves that routine,
reversible, already-authorised work flows with no approval prompt while
genuinely consequential work is intercepted, explained, and mechanically
blocked until a fresh, exact admission.

The code is deliberately small and mostly standard-library Python. It talks to
the real public `tethers.authority/1` seam over NDJSON/stdin/stdout; it does not
import private Tethers modules, vendor Tethers, or duplicate its evaluator.

Layout:

| Path | Purpose |
| --- | --- |
| `doctrine/matthew.v0.1.json` | Customer Zero doctrine (human source) |
| `permission_slip/doctrine.py` | Compiles doctrine into Tethers fixtures |
| `permission_slip/actions.py` | Trusted action adapter / trust boundary |
| `permission_slip/tethers_client.py` | `tethers.authority/1` stdio client + pinning |
| `permission_slip/explanations.py` | Human consequence explanations |
| `permission_slip/executor.py` | Safe fixture external executor |
| `permission_slip/spike.py` | Vertical orchestration |
| `tethers-fixture/` | Compiled inspectable Tethers runtime/config fixtures |
| `tests/` | The 16-case end-to-end matrix + adapter/pinning tests |
| `scripts/` | Toolchain bootstrap and spike runner |

## Trust boundary

The worker/agent is not trusted to label its own consequences. The adapter
derives authority-relevant facts **from the actual operation**:

- `git push --force origin main` becomes `git.history.rewrite`, regardless of
  what the caller calls it;
- external destination comes from the actual target;
- actor identity comes from the trusted harness profile, not from content;
- secret material takes precedence over ordinary repository upload;
- monetary amount/source comes from the trusted payment fields;
- project file scope comes from resolved paths.

Caller-supplied authority booleans (`permission`, `trusted`, `approved`, ...)
are ignored by the adapter and refused by the Gate
(`frame.forbidden_authority_key`).

## Admission ordering

```
hello
prepare → allow_prepared | ask | deny | unavailable
(ask: explanation → human decision → approval_decision)
commit
external execution
outcome
```

PREPARE is informational; human approval alone does not authorise execution.
**COMMIT is the last-responsible-moment re-check**, and nothing is physically
executed before it succeeds. Approval is exact and one-shot.

Supervision law, preserved in code and docs:

> supervision may narrow authority;
> supervision may never increase authority.

A future supervisor may stop, hold, require fresh admission, or reduce scope. It
may not convert ASK/DENY into ALLOW. Anomaly detection is out of scope here.

## Running the spike

Prerequisites: Python 3 (3.11+), Git, PowerShell 7, and a built Tethers R2
Authority Gate plus its Core engine. Point at them with:

```
TETHERS_ROOT        # a tethers-lang checkout (lineage-verified)
TETHERS_GATE_BIN    # tethers gate --stdio binary
TETHERS_ENGINE_BIN  # Tethers Core engine (engine-ocaml tethers_mcp_main)
```

The spike verifies the checkout is lineage-compatible with the required R2
merge `7e29110319c554a6586865ec6c47a45498696d16` and that the engine binary
matches the frozen R2 artifact. A mismatch is visible and fails closed unless
`TETHERS_ALLOW_SHA_MISMATCH=1` is set.

```powershell
scripts\run-spike.ps1
```

This compiles the doctrine, runs the full suite, and reports the exact Tethers
SHA exercised. To provision a fresh pinned Tethers checkout into `.deps/`
(git-ignored), run `scripts\bootstrap-tethers.ps1`.

## Known v0.1 limitations

- Tethers' configured runtime scope resolver implements `PathPrefix` (and
  `Unrestricted`), not the declared `Repository`/`Calendar` scopes. The spike
  uses `PathPrefix` plus **distinct semantic capabilities** for history
  rewrite, upload, money, and publication rather than forcing those concepts
  into filesystem scope.
- Bounded numeric scope (promotional credit) is not a native Tethers runtime
  scope. The trusted adapter derives a `promo.within_budget` fact from the
  actual amount and the configured bound; the Tether condition and policy still
  make the decision. No Tethers change was required.

## Origin

> The rant was the requirements interview.
