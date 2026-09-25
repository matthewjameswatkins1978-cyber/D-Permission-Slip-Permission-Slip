<#
.SYNOPSIS
    Provision a pinned Tethers R2 checkout into .deps/tethers (git-ignored).

.DESCRIPTION
    Clones tethers-lang, checks out the required canonical R2 merge, and builds
    the Authority Gate binary. It never modifies Tethers. The Core engine is
    built with dune when available; otherwise an existing engine can be pointed
    at with TETHERS_ENGINE_BIN.

    This directory is git-ignored and is never committed into Permission Slip.
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

Write-Host "Done. TETHERS_ROOT=$DepsDir"
