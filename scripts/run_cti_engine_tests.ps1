[CmdletBinding()]
param(
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    & $PythonExe -m unittest discover -s test\python -v
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
