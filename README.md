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
| `tests/` | The 33-case end-to-end matrix + adapter/pinning tests |
| `tests/support.py` | Temporary Git repositories with controlled remotes (no network) |
| `scripts/` | Toolchain bootstrap and spike runner |

## Trust boundary

The worker/agent is not trusted to label its own consequences. The adapter
derives authority-relevant facts **from the actual operation**:

- actor identity comes from the **trusted harness/session context** passed to
  `ActionAdapter.normalize(operation, actor_id)`, never from an `actor` field
  inside the operation;
- `git push --force origin main` becomes `git.history.rewrite`, regardless of
  what the caller calls it;
- equivalent consequential push forms (`HEAD:main`, `feature:main`,
  `+feature`, `--force-with-lease=...`, deletions) are recognised; an
  ambiguous push **fails closed** and never becomes `git.push.feature`;
- `git.push.feature` is granted on **positive evidence only**: the single
  unambiguous destination must sit inside the `feature/*` namespace, the push
  must carry no force semantics, **and the actual push remote must resolve —
  from trusted local Git configuration — to the doctrine's canonical
  repository**. A destination that is merely unknown (`production`, `stable`,
  `gh-pages`, `arbitrary-name`, ...) is *not* evidence, is not silently
  re-described as a history rewrite, and fails closed as unmappable → `DENY`;
- the remote *alias* is caller content and is never trusted by name. The
  adapter runs `git -C <repo> remote get-url --push --all <alias>` (local
  config only, no network) and compares the resolved URL against
  `project.canonical_repository`, normalising the small set of equivalent
  GitHub transport forms to `github.com/owner/repo`. Caller-supplied
  `remote_url` / `repository_url` / `canonical_remote` / `approved_remote`
  fields are forbidden keys and are never read;
- **the complete set of effective push URLs is proven, not just the first.**
  Git permits several `pushurl` entries and physically pushes to all of them,
  so v0.1 requires **exactly one** effective destination: zero URLs, two URLs
  (even two that normalise to the same repository), or a malformed URL all
  fail closed as unmappable → `DENY`. Two destinations are never reasoned
  about as "probably equivalent";
- Git push actions are bound **inside Tethers** to the exact remote/ref effect:
  `git.push.feature` and `git.history.rewrite` carry `remote_repository`,
  `destination_ref` and `push_effect` as Tether action arguments, so two
  materially different pushes (e.g. `force:refs/heads/main` vs
  `force:refs/heads/release`) receive different Tethers `argument_digest`s and
  cannot share one approval;
- the external executor consumes only the normalized action Tethers admitted.
  It never re-reads the raw caller operation, a remote alias or a `remote_url`
  to decide the physical target, and it records the admitted
  `remote_repository` / `destination_ref` / `push_effect` in its effect log;
- external destination comes from the actual target;
- secret material takes precedence over ordinary repository upload;
- monetary amount/source comes from the trusted payment fields, and a
  promotional-credit charge is admitted only on positive evidence of the
  configured provider **and** a strictly positive amount inside the
  configured **per-call** limit;
- project file scope comes from **canonicalised resolved paths**: traversal is
  resolved against the trusted project root and never rewritten into an
  apparently in-scope path.

Caller-supplied authority booleans and identity claims (`actor`, `permission`,
`trusted`, `approved`, ...) are ignored by the adapter and refused by the Gate
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

Immediately before COMMIT, Permission Slip applies a monotonic host invariant:

> prepared normalized action
> == freshly trusted-normalized action right now

The operation envelope and trusted actor identity are frozen at the start of
adjudication. If trusted external state (such as Git remote configuration) has
changed, if normalization now fails, or if the operation envelope itself was
mutated after PREPARE, the stale prepared action is **not** committed and
nothing executes — the receipt reports `trusted_context_changed` and a fresh
attempt is required. A human approval does not rescue stale context.

This check may only stop stale execution; it never re-decides authority and can
never turn DENY/ASK into ALLOW. Tethers remains the sole semantic authority.

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
  scope. The trusted adapter derives a `promo.within_bound` fact from the
  actual amount, the actual vendor, and the configured provider + per-call
  limit; the Tether condition and policy still make the decision. No Tethers
  change was required.
- The v0.1 promotional-credit proof is a **per-call** limit
  (`boundaries.promotional_credit.per_call_limit_cents`) at the approved
  provider, not cumulative cloud spend. There is no ledger, no running total
  and no remaining-credit accounting; a caller could in principle issue many
  individually-allowed calls. Cumulative quota accounting is later product
  work.
- `git.push.feature` recognises only the explicit `feature/*` namespace. A
  push to a branch outside it is unmappable in v0.1 and fails closed rather
  than being given standing authority or a mislabelled capability. A general
  branch taxonomy / `git.push.other` capability is deliberately not built.
- Remote identity normalisation is deliberately GitHub-only and covers just
  the four transport forms that are proven equivalent for this repository.
  Any other host, scheme, port, path shape or malformed URL fails closed as
  unmappable. There is no generic forge-URL framework and no remote policy
  language.
- v0.1 supports **exactly one effective push destination** per push. Git's
  multi-`pushurl` capability is not supported: two destinations always fail
  closed, even when both normalise to the same repository. A general
  multi-destination push policy is deliberately not built.
- COMMIT-time trusted-context revalidation compares the frozen operation
  envelope and the freshly normalized authority-relevant result. It is a
  safety net for host-supplied trusted state, not a substitute for Tethers'
  own COMMIT re-check.
- `git merge` still binds only the local `repository` argument: it is not a
  remote/ref push effect, so Packet 1C does not extend its action identity.

## Origin

> The rant was the requirements interview.
