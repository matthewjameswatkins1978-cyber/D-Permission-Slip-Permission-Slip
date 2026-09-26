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

This repository holds the **v0.1 vertical integration spike** (merged) and the
**0.2 Tethers product-consumption boundary**. Together they prove that routine,
reversible, already-authorised work flows with no approval prompt while
genuinely consequential work is intercepted, explained, and mechanically
blocked until a fresh, exact admission — consumed from an *installed* Tethers
product rather than a source checkout.

The code is deliberately small and mostly standard-library Python. It talks to
the real public `tethers.authority/1` seam over NDJSON/stdin/stdout; it does not
import private Tethers modules, vendor Tethers, or duplicate its evaluator.

Layout:

| Path | Purpose |
| --- | --- |
| `doctrine/matthew.v0.1.json` | Customer Zero doctrine (human source) |
| `permission_slip/doctrine_contract.py` | Doctrine Contract v1: validate, canonicalise, digest, migrate |
| `permission_slip/doctrine.py` | Compiles a contract-valid doctrine into Tethers fixtures |
| `permission_slip/doctrine_export.py` | Portable export/import envelope (a doctrine and its digest, nothing else) |
| `permission_slip/doctrine_store.py` | State-owned candidates, active pointer, explicit adoption |
| `permission_slip/adoption_lock.py` | One cross-process advisory lock around the adoption decision |
| `permission_slip/doctrine_diff.py` | Domain-aware doctrine diff: consequential vs presentation |
| `permission_slip/actions.py` | Trusted action adapter / trust boundary |
| `permission_slip/tethers_install.py` | Tethers product discovery, identity, provenance, provisioning |
| `permission_slip/tethers_client.py` | `tethers.authority/1` stdio client + startup contract |
| `permission_slip/state.py` | Cross-platform Permission Slip state root |
| `permission_slip/doctor.py` | `permission-slip doctor` checks and versioned envelope |
| `permission_slip/__main__.py` | `permission-slip` CLI (`doctor`, `setup`) |
| `permission_slip/explanations.py` | Human consequence explanations |
| `permission_slip/executor.py` | Safe fixture external executor |
| `permission_slip/spike.py` | Vertical orchestration |
| `tethers-fixture/` | Compiled inspectable Tethers runtime/config fixtures |
| `tests/` | Authority matrix, discovery, protocol, doctor, state, version support, release lock, doctrine contract and portability |
| `tests/fake_tethers.py` | Fake released-Tethers bundles (fakes, clearly separated) |
| `tests/support.py` | Temporary Git repositories with controlled remotes (no network) |
| `scripts/` | Spike runner, release acquisition and the product proof |
| `verification/tethers-v0.8.1.lock.json` | Accepted published Tethers 0.8.1 release lock (assets + SHA-256) |
| `scripts/tethers_release.py` | Acquire/verify/extract the published release (setup machinery, never runtime) |
| `scripts/tethers_product_proof.py` | Real packaged-Tethers consumer proof: discovery -> doctor -> hello -> lifecycle |

## Doctrine portability

The doctrine is portable, but portability never confers authority:

```text
candidate  ->  inspect  ->  diff  ->  explicit adopt
```

- `permission-slip doctrine export <file> --output <file>` writes a closed,
  deterministic envelope (`permission-slip.doctrine-export/1`) holding only the
  validated doctrine, its schema and its recomputed `sha256:` digest -- no
  paths, no timestamps, no secrets, no compiled fixtures. Same doctrine, same
  bytes.
- `permission-slip doctrine import <file>` verifies that envelope and stores it
  as a **candidate** under the Permission Slip state root, named by its own
  digest. Import does not activate. Migration does not activate. Diffing does
  not.
- `permission-slip doctrine diff <before> <after>` reports what changed, naming
  the concrete semantic item (`git.history.rewrite standing changed ASK ->
  ALLOW`) and classifying each change as `CONSEQUENTIAL` or `PRESENTATION`. It
  reports; it does not judge, and it is not an authority. Either operand may be
  the literal `active`.
- `permission-slip doctrine active` reports the adopted doctrine, and
  `permission-slip doctrine adopt --candidate <digest> --expect-current <digest|none>`
  is the **only** operation that can change it. Adoption is a compare-and-swap:
  if the active doctrine is not exactly what the caller expected, it refuses.

`os.replace` makes the pointer *write* atomic; it does not make
`read -> compare -> write` atomic. So the whole adoption decision -- read the
current digest, compare it, verify the candidate, replace the pointer -- runs
while holding one cross-process advisory lock on
`<state>/doctrine/.adoption.lock` (`fcntl.flock` on POSIX, `msvcrt.locking` on
Windows). Two processes adopting from the same expected state therefore produce
exactly one winner; every other one gets `CONFLICT`. The kernel releases that
lock if the holder dies, and the lock file itself is inert -- existence is never
ownership -- so no crash can strand the store. Import, export, diff and reads do
not take it; only adoption mutates the pointer, so only adoption needs it.

Adoption proves *that* an explicit operation happened against the expected
state. It does not yet prove *who* invoked it; identity-backed proof of the
adopting human belongs to later trusted-identity work and is deliberately not
simulated here.

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

## Consuming Tethers as a product

Permission Slip does not rummage through Tethers' workshop for an executable.
It consumes an installed/released Tethers runtime and depends only on the
`tethers.authority/1` process protocol.

Discovery order:

1. **explicit configured executable paths** — `TETHERS_GATE_BIN` and
   `TETHERS_ENGINE_BIN` (exact product files that are still validated), or a
   bundle root in `TETHERS_ROOT`;
2. **installed product location / `PATH`** — `tethers` on `PATH`, else a known
   install location;
3. **released-bundle sibling engine** — the matching engine shipped beside the
   Gate executable (`bin/tethers` + `bin/tethers-engine`).

Verification hierarchy, from Tethers' own surfaces:

| Source | What it establishes |
| --- | --- |
| `tethers describe --json` | product identity (`tethers.describe/1`, version) |
| release `SHA256SUMS` beside the bundle | package provenance + Gate/engine pairing |
| binary SHA-256 | exactly which files are being run |
| `tethers.authority/1` `hello` | protocol compatibility at startup |

A release manifest that exists but does not match fails closed. A manifest that
is absent is reported as `unverified`, never as a pass. **No `.git` directory
is required**, and normal operation never probes `.deps/tethers`,
`D:\tethers-lang`, or any Tethers checkout.

### Verified Tethers is the authority

`doctor` and the authority path share **one** predicate,
`validate_authority_installation`. A production `GateSession` /
`PermissionSlip` refuses to launch any installation that is not
`verified` with `release_manifest` provenance and not development-only:

| state | doctor | default authority session |
| --- | --- | --- |
| released bundle matching `SHA256SUMS` | `PASS` | starts |
| no release manifest | not `PASS` | **refuses before the Gate starts** |
| manifest mismatch | not `PASS` | **refuses** |
| verified but unsupported product version | not `PASS` (version) | **refuses** |
| dev override active | not `PASS` (`unverified/dev`) | **refuses** |
| explicit source checkout | not `PASS` (dev) | **refuses** |

The invariant is one-way but absolute: **if `doctor` says the installation is
not verified for authority, a default authority session does not proceed.**

### Supported production Tethers version

Production authority accepts one explicit set of Tethers product versions
(`SUPPORTED_AUTHORITY_PRODUCT_VERSIONS` in `permission_slip/tethers_install.py`):

| product version | production authority |
| --- | --- |
| `0.8.1` | accepted |
| `0.8.0` | refused - genuine, but unsupported |
| any other / future version | refused until deliberately adopted |
| missing or unknown | refused |

There is deliberately no semver compatibility engine: adopting a new Tethers
release is a one-line, reviewable change. This is a *product support* decision,
never a corruption report - a verified 0.8.0 bundle is still reported as
verified, and doctor says so. Protocol compatibility is never inferred from a
product version; it is negotiated at the `tethers.authority/1` `hello`.

`verification/tethers-v0.8.1.lock.json` pins the accepted published release
(assets and SHA-256) for the three official targets, and
`scripts/tethers_release.py` acquires and verifies those exact bytes before
anything is extracted. Checksums are bounded interim provenance: the release is
not third-party signed and its macOS packages are not notarized.


Development authority exists only through an explicit call-boundary opt-in —
`GateSession(..., allow_unverified_for_development=True)` or
`PermissionSlip(..., allow_unverified_tethers_for_development=True)` — and such
a session is permanently marked `development_authority`. The
`PERMISSION_SLIP_DEV_TETHERS_UNVERIFIED` variable may permit *discovery and
diagnosis*; it never upgrades an installation into a trusted production
authority engine.

> development override permits testing; it does not manufacture product trust.

Development-only source discovery exists behind one explicitly named switch:

```powershell
$env:PERMISSION_SLIP_DEV_TETHERS_CHECKOUT = <checkout path>
```

`permission-slip doctor` reports that route as an unverified development source
checkout. `PERMISSION_SLIP_DEV_TETHERS_UNVERIFIED=1` (legacy alias
`TETHERS_ALLOW_SHA_MISMATCH=1`) is development-only: it suppresses a manifest
mismatch, is always named in the report, and **never** counts as successful
product verification.

### State root

Permission Slip owns a stable, user-private location for its durable Tethers
host state. It never shares a global Tethers host-data root with unrelated
applications.

| Platform | Default |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Permission Slip\state` |
| Linux | `$XDG_STATE_HOME/permission-slip`, else `~/.local/state/permission-slip` |
| macOS | `~/Library/Application Support/Permission Slip/State` |

Override with `PERMISSION_SLIP_STATE_DIR`. The Tethers host-data root is the
`tethers-host` child of that state root.

### `permission-slip doctor`

```powershell
permission-slip doctor          # human
permission-slip doctor --json   # versioned permission-slip.doctor/1 envelope
```

```
Permission Slip 0.2
Tethers: 0.8.1
Protocol: tethers.authority/1
Platform: Windows x86_64
State: ready
```

The JSON is Permission Slip-owned, versioned, deterministic, and independent of
the prose. Check statuses are `PASS`, `FAIL`, `UNAVAILABLE`, `UNSUPPORTED`.
Exit codes: `0` PASS, `1` FAIL, `2` UNAVAILABLE, `3` UNSUPPORTED. The envelope
also carries `product_version`, `supported_product_versions` and
`product_version_supported`, so a verified-but-unsupported product is
distinguishable from a broken installation in machine-readable form.

### Provisioning

Tethers requires a provisioned host-data root for replay state. Permission Slip
never creates durable authority state as a side effect of an ordinary
authority request — provisioning is deliberately explicit:

```powershell
permission-slip setup           # runs Tethers' own 'provision-replay'
permission-slip doctor           # then reports ready / not ready
```

## Running the suite

Prerequisites: Python 3 (3.11+), Git, PowerShell 7, and an installed **Tethers
0.8.1** runtime (`TETHERS_ROOT` pointing at an extracted release, else `tethers`
on `PATH`, else `TETHERS_GATE_BIN` / `TETHERS_ENGINE_BIN`). Any other product
version is refused as production authority.

```powershell
scripts\run-spike.ps1
```

This compiles the doctrine, prints the Tethers product identity being consumed,
runs `permission-slip doctor`, and runs the full test matrix.

To acquire and verify the exact published release bytes before running
anything, on any of the three official targets:

```bash
python scripts/tethers_release.py acquire --lock verification/tethers-v0.8.1.lock.json
python scripts/tethers_product_proof.py --lock verification/tethers-v0.8.1.lock.json
```

The second command walks the whole consumer path (discovery, identity,
provenance, provisioning, doctor, a real `tethers.authority/1` hello, then the
existing ALLOW / ASK / DENY / OUTCOME lifecycle) against the packaged product
and writes a JSON report. `.github/workflows/permission-slip-tethers-product-proof.yml`
runs both plus the suite on Windows x86-64, Linux x86-64 and macOS ARM64.

`scripts\bootstrap-tethers.ps1` is **contributor/development tooling only**: it
builds a Tethers source checkout for people working on Tethers itself. It is
not the normal install path and is not how Permission Slip finds Tethers.

## Known limitations

- **Provenance is bounded and unsigned.** Tethers 0.8.1 is pinned by
  `verification/tethers-v0.8.1.lock.json` SHA-256 values plus the
  `tethers.release/1` manifest and the bundle `SHA256SUMS`. That pins *bytes*,
  not publisher identity: there is no PKI, no Sigstore and no third-party
  signature. macOS packages are not Apple Developer ID signed or notarized, so
  public Gatekeeper-trusted distribution is unavailable.
- **Known Tethers 0.8.1 release defect (accepted, not worked around).** The
  Linux and macOS package-internal `SHA256SUMS` contains one self-referential
  `./SHA256SUMS` entry that cannot verify itself. `scripts/tethers_release.py`
  *identifies* exactly that one entry as `tethers-0.8.1-self-referential-sha256sums`
  and requires every other entry to verify; it is not a general
  "ignore checksum failures" path. Windows packages have no such entry.
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
- Known install locations are only probed where a Tethers layout has actually
  been observed. Linux/macOS install locations are not guessed at: on those
  platforms the route is `PATH` or an explicit `TETHERS_ROOT`. Released 0.8.1
  packages for Windows x86-64, Linux x86-64 and macOS ARM64 are proven by the
  Tethers release and consumed by
  `.github/workflows/permission-slip-tethers-product-proof.yml`; macOS Intel is
  not claimed by Permission Slip.
- `tethers describe --json` is treated as best-effort reporting; the authority
  `hello` is the contract. Tethers 0.8.1 no longer reports
  `supported_protocol_versions` / `supported_language_versions` / `features`
  there (0.8.0 did); protocol compatibility is negotiated at the `hello`, and
  `product_version` still comes from `describe`. If a release stops shipping
  `describe --json`, doctor reports identity as `UNAVAILABLE` rather than
  guessing.
- Doctor's protocol probe uses a throwaway temporary workspace so it never
  writes to Permission Slip's real host-data root; consequently it proves
  `hello` negotiation, not a full authority evaluation.
- Tethers 0.8.x provisions its host-data store on first use if it is absent.
  Permission Slip does not invoke provisioning during an authority request and
  reports readiness through `doctor` / `setup`; whether the Gate should
  hard-require pre-provisioning is a Tethers contract question (dependency
  finding, not something to patch around here).
- The library `PermissionSlip` class still defaults its working directory to an
  ephemeral temp directory; the durable state root is owned by the `permission-slip`
  CLI. Moving the library default onto the state root belongs with the 0.6 CLI.

## Origin

> The rant was the requirements interview.
