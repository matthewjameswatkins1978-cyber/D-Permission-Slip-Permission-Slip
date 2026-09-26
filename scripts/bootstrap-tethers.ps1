<#
.SYNOPSIS
    CONTRIBUTOR / DEVELOPMENT TOOLING ONLY - build a Tethers source checkout.

.DESCRIPTION
    This is NOT how Permission Slip finds Tethers.

    Permission Slip consumes an installed/released Tethers product. Production
    discovery looks at explicit configured executable paths, then PATH / a known
    install location, then the engine shipped beside the Gate executable. It
    never probes .deps/tethers, never probes D:\tethers-lang, and never needs a
    Tethers .git directory.

    This script exists so a contributor working on the Tethers side can build a
    local source checkout for experimentation. The resulting checkout is only
    reachable through the EXPLICITLY named development switch:

        $env:PERMISSION_SLIP_DEV_TETHERS_CHECKOUT = <checkout path>

    Anything discovered that way is reported by `permission-slip doctor` as a
    development source checkout and is never treated as verified product
    provenance.

    It never modifies Tethers. The Core engine is built with dune when
    available; otherwise point TETHERS_ENGINE_BIN at an existing engine build.

    The checkout directory is git-ignored and is never committed into
    Permission Slip.
#>
[CmdletBinding()]
param(
    [string]$Repository = "https://github.com/matthewjameswatkins1978-cyber/tethers-lang.git",
    [string]$Ref = "7e29110319c554a6586865ec6c47a45498696d16",
    [string]$DepsDir
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $DepsDir) { $DepsDir = Join-Path $repoRoot ".deps/tethers" }

Write-Warning "DEVELOPMENT ONLY. This builds a Tethers source checkout for contributors."
Write-Warning "It is not the normal install path. Install the released Tethers bundle instead,"
Write-Warning "and use 'permission-slip doctor' to verify what you actually have."

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DepsDir) | Out-Null

if (-not (Test-Path (Join-Path $DepsDir ".git"))) {
    git clone $Repository $DepsDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
}

git -C $DepsDir fetch --all --tags
if ($LASTEXITCODE -ne 0) { throw "git fetch failed" }
git -C $DepsDir checkout --detach $Ref
if ($LASTEXITCODE -ne 0) { throw "git checkout $Ref failed" }

Write-Host "Tethers checkout: $(git -C $DepsDir rev-parse HEAD)"

$manifest = Join-Path $DepsDir "tethers-0.1/host-rust/Cargo.toml"
if (-not (Test-Path $manifest)) { throw "host-rust Cargo.toml not found in checkout" }

cargo build --manifest-path $manifest --bin tethers
if ($LASTEXITCODE -ne 0) { throw "cargo build of the Authority Gate failed" }

$engine = Join-Path $DepsDir "tethers-0.1/engine-ocaml/_build/default/bin/tethers_mcp_main.exe"
if (Test-Path $engine) {
    Write-Host "Core engine: $engine"
} elseif (Get-Command dune -ErrorAction SilentlyContinue) {
    Push-Location (Join-Path $DepsDir "tethers-0.1/engine-ocaml")
    try { dune build @install } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "dune build of the Core engine failed" }
} else {
    Write-Warning "Core engine not built and dune is unavailable. Set TETHERS_ENGINE_BIN to an existing engine build."
}

Write-Host ""
Write-Host "To point Permission Slip at this development checkout EXPLICITLY:"
Write-Host "  `$env:PERMISSION_SLIP_DEV_TETHERS_CHECKOUT = '$DepsDir'"
Write-Host "Then verify how it is classified:"
Write-Host "  permission-slip doctor"
Write-Warning "doctor will report this as an unverified development source checkout."
