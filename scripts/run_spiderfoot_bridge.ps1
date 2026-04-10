param(
    [Parameter(Mandatory = $true)]
    [string]$PayloadPath
)

$ErrorActionPreference = 'Stop'

function Convert-ToWslPath {
    param([string]$WindowsPath)

    $full = [System.IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    $tail = $full.Substring(2).Replace('\', '/')
    if (-not $tail.StartsWith('/')) {
        $tail = '/' + $tail
    }
    return "/mnt/$drive$tail"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$bridgePy = Join-Path $repoRoot 'python\spiderfoot_bridge\bridge.py'
if (-not (Test-Path -LiteralPath $bridgePy)) {
    throw "Bridge script not found: $bridgePy"
}

$payloadFull = [System.IO.Path]::GetFullPath($PayloadPath)
if (-not (Test-Path -LiteralPath $payloadFull)) {
    throw "Payload file not found: $payloadFull"
}

$bridgeWsl = Convert-ToWslPath $bridgePy
$payloadWsl = Convert-ToWslPath $payloadFull

$bashCommand = "python3 '$bridgeWsl' --payload-path '$payloadWsl'"

& wsl.exe -e bash -lc $bashCommand
exit $LASTEXITCODE
