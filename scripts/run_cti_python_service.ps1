[CmdletBinding()]
param(
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    & $PythonExe -m python.cti_service
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
