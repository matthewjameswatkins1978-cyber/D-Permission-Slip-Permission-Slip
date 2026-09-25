<#
.SYNOPSIS
    Compile the doctrine and run the Permission Slip v0.1 vertical spike tests.

.DESCRIPTION
    Locates Python 3, compiles doctrine/matthew.v0.1.json into the committed
    tethers-fixture/, prints the exact Tethers lineage being exercised, and runs
    the full automated test matrix.
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

    Write-Host "`n== Tethers lineage =="
    & $Python -c "from permission_slip.tethers_client import discover_tethers; p=discover_tethers(); print('root:', p.root); print('required SHA:', p.required_sha); print('actual SHA:  ', p.actual_sha); print('verification:', p.verification); print('engine sha256:', p.engine_sha256); print('engine matches frozen R2 artifact:', p.engine_matches_artifact)"

    Write-Host "`n== Running automated tests =="
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }

    Write-Host "`nSpike complete."
}
finally {
    Pop-Location
}
