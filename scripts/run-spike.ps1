<#
.SYNOPSIS
    Compile the doctrine and run the Permission Slip test matrix.

.DESCRIPTION
    Locates Python 3, compiles doctrine/matthew.v0.1.json into the committed
    tethers-fixture/, prints the exact Tethers product identity being consumed,
    and runs the full automated test matrix (v0.1 authority proofs plus the
    0.2 product-consumption boundary).

    This consumes an installed/released Tethers. It does not clone or build
    Tethers; see scripts/bootstrap-tethers.ps1 for contributor-only tooling.
#>
[CmdletBinding()]
param(
    [string]$Python
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    if (-not $Python) {
        $search = @()
        $search += Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Programs\Python") -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
        $search += (Get-Command python -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        $search += (Get-Command py -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        foreach ($candidate in $search) {
            if ($candidate -and (Test-Path $candidate)) {
                try {
                    & $candidate --version *> $null
                    if ($LASTEXITCODE -eq 0) { $Python = $candidate; break }
                }
                catch { }
            }
        }
        if (-not $Python) { throw "Python 3 not found. Pass -Python <path>." }
    }

    Write-Host "Using Python: $Python"
    & $Python --version

    Write-Host "`n== Compiling doctrine into tethers-fixture =="
    & $Python -m permission_slip.doctrine "doctrine/matthew.v0.1.json" "tethers-fixture"
    if ($LASTEXITCODE -ne 0) { throw "doctrine compilation failed" }

    Write-Host "`n== Tethers product identity =="
    & $Python -c "from permission_slip.tethers_install import discover_tethers; p = discover_tethers(); print('gate:         ', p.gate_bin); print('engine:       ', p.engine_bin); print('install root: ', p.install_root); print('product:      ', p.product_version); print('protocol:     ', p.authority_protocol); print('discovery:    ', p.discovery_source, '/', p.engine_source); print('provenance:   ', p.provenance, '(', p.verification, ')'); print('gate sha256:  ', p.gate_sha256); print('engine sha256:', p.engine_sha256); print('manifest:     ', p.release_manifest)"
    if ($LASTEXITCODE -ne 0) { throw "Tethers discovery failed" }

    Write-Host "`n== permission-slip doctor =="
    & $Python -m permission_slip doctor
    Write-Host "(informational; the test matrix below is the gate)"

    Write-Host "`n== Running automated tests =="
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }

    Write-Host "`nSpike complete."
}
finally {
    Pop-Location
}
