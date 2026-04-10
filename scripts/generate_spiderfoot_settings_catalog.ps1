param(
    [string]$WorkbookPath = "C:\Users\John Lloyd T. Caban\Downloads\module settings spiderfoot.xlsx",
    [string]$RepoRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
} else {
    $RepoRoot = (Resolve-Path $RepoRoot).Path
}

if (-not (Test-Path -LiteralPath $WorkbookPath)) {
    throw "Workbook not found: $WorkbookPath"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Read-ZipEntryText {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive]$Zip,

        [Parameter(Mandatory = $true)]
        [string]$EntryName
    )

    $entry = $Zip.GetEntry($EntryName)
    if ($null -eq $entry) {
        return $null
    }

    $stream = $entry.Open()
    try {
        $reader = New-Object System.IO.StreamReader($stream)
        try {
            return $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-SharedStrings {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive]$Zip
    )

    $xmlText = Read-ZipEntryText -Zip $Zip -EntryName 'xl/sharedStrings.xml'
    if ([string]::IsNullOrEmpty($xmlText)) {
        return @()
    }

    [xml]$xml = $xmlText
    $values = @()
    foreach ($si in @($xml.sst.si)) {
        $parts = @()
        if ($si.PSObject.Properties['t'] -and $null -ne $si.t) {
            $parts += [string]$si.t
        }
        $sharedRuns = if ($si.PSObject.Properties['r']) { @($si.r) } else { @() }
        foreach ($run in $sharedRuns) {
            if ($run.PSObject.Properties['t'] -and $null -ne $run.t) {
                $parts += [string]$run.t
            }
        }
        $values += ($parts -join '')
    }

    return $values
}

function Get-WorksheetPath {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive]$Zip,

        [Parameter(Mandatory = $true)]
        [string]$SheetName
    )

    [xml]$workbook = Read-ZipEntryText -Zip $Zip -EntryName 'xl/workbook.xml'
    [xml]$rels = Read-ZipEntryText -Zip $Zip -EntryName 'xl/_rels/workbook.xml.rels'

    $relationshipId = $null
    foreach ($sheet in @($workbook.workbook.sheets.sheet)) {
        $sheetNameValue = $sheet.GetAttribute('name')
        if ($sheetNameValue -eq $SheetName) {
            $relationshipId = $sheet.GetAttribute('id', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships')
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($relationshipId)) {
        throw "Worksheet not found in workbook: $SheetName"
    }

    foreach ($rel in @($rels.Relationships.Relationship)) {
        $id = $rel.GetAttribute('Id')
        if ($id -eq $relationshipId) {
            $target = $rel.GetAttribute('Target')
            if ($target.StartsWith('/')) {
                return $target.TrimStart('/')
            }
            if ($target.StartsWith('xl/')) {
                return $target
            }
            return ('xl/' + $target.TrimStart('/'))
        }
    }

    throw "Worksheet relationship not found: $relationshipId"
}

function Get-CellValue {
    param(
        [Parameter(Mandatory = $true)]
        $Cell,

        [Parameter(Mandatory = $true)]
        [array]$SharedStrings
    )

    $type = ''
    if ($null -ne $Cell.Attributes['t']) {
        $type = [string]$Cell.Attributes['t'].Value
    }

    $valueNode = $Cell.SelectSingleNode('./*[local-name()="v"]')
    switch ($type) {
        's' {
            if ($null -eq $valueNode) {
                return ''
            }
            return [string]$SharedStrings[[int]$valueNode.InnerText]
        }
        'inlineStr' {
            $parts = @()
            $inlineString = $Cell.SelectSingleNode('./*[local-name()="is"]')
            if ($null -ne $inlineString) {
                $textNode = $inlineString.SelectSingleNode('./*[local-name()="t"]')
                if ($null -ne $textNode) {
                    $parts += [string]$textNode.InnerText
                }
                $inlineRuns = @($inlineString.SelectNodes('./*[local-name()="r"]'))
                foreach ($run in $inlineRuns) {
                    $runTextNode = $run.SelectSingleNode('./*[local-name()="t"]')
                    if ($null -ne $runTextNode) {
                        $parts += [string]$runTextNode.InnerText
                    }
                }
            }
            return ($parts -join '')
        }
        default {
            if ($null -eq $valueNode) {
                return ''
            }
            return [string]$valueNode.InnerText
        }
    }
}

function Import-XlsxRows {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$SheetName = 'Sheet1'
    )

    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $sharedStrings = Get-SharedStrings -Zip $zip
        $sheetPath = Get-WorksheetPath -Zip $zip -SheetName $SheetName
        [xml]$sheet = Read-ZipEntryText -Zip $zip -EntryName $sheetPath

        $rows = @()
        foreach ($row in @($sheet.worksheet.sheetData.row)) {
            $cells = @{}
            foreach ($cell in @($row.c)) {
                $ref = [string]$cell.r
                $col = ($ref -replace '\d', '')
                $cells[$col] = Get-CellValue -Cell $cell -SharedStrings $sharedStrings
            }

            $moduleValue = if ($cells.ContainsKey('A')) { $cells['A'] } else { '' }
            $optionValue = if ($cells.ContainsKey('B')) { $cells['B'] } else { '' }
            $valueValue = if ($cells.ContainsKey('C')) { $cells['C'] } else { $null }

            $rows += [pscustomobject]@{
                Module = [string]$moduleValue
                Option = [string]$optionValue
                Value  = $valueValue
            }
        }

        return $rows
    } finally {
        $zip.Dispose()
    }
}

function Normalize-LookupText {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $normalized = $Text.ToLowerInvariant()
    $normalized = $normalized -replace '[^a-z0-9]+', ' '
    $normalized = $normalized -replace '\s+', ' '
    return $normalized.Trim()
}

function Convert-ToSettingKey {
    param([AllowNull()][string]$Text)

    $normalized = Normalize-LookupText -Text $Text
    if ($normalized -eq '') {
        return 'setting'
    }

    $key = $normalized -replace ' ', '_'
    $key = $key -replace '^_+', ''
    $key = $key -replace '_+$', ''
    if ($key -eq '') {
        return 'setting'
    }

    return $key
}

function Normalize-KeyAlias {
    param([AllowNull()][string]$Key)

    if ([string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $normalized = $Key.ToLowerInvariant().Trim()
    $normalized = $normalized -replace '_size_', '_'
    $normalized = $normalized -replace '_size$', ''
    $normalized = $normalized -replace 'co_hosted', 'cohosts'
    $normalized = $normalized -replace 'co_host', 'cohost'
    return $normalized
}

function Get-TitleCaseLabel {
    param(
        [AllowNull()][string]$ExistingLabel,
        [AllowNull()][string]$Option,
        [AllowNull()][string]$Key
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingLabel)) {
        return $ExistingLabel
    }

    if (-not [string]::IsNullOrWhiteSpace($Option)) {
        return $Option.Trim()
    }

    $source = [string]$Key
    $source = $source -replace '_', ' '
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    return $culture.TextInfo.ToTitleCase($source)
}

function Looks-LikeBooleanOption {
    param(
        [AllowNull()][string]$Option,
        [AllowNull()][object]$Value
    )

    $text = [string]$Option
    if ($text.EndsWith('?')) {
        return $true
    }

    $prefixes = @(
        'Enable ', 'Apply ', 'Check ', 'Fetch ', 'Look ', 'Verify ', 'Use ',
        'Report ', 'Treat ', 'Extract ', 'Search ', 'Include ', 'Disable '
    )
    foreach ($prefix in $prefixes) {
        if ($text.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Infer-SettingType {
    param(
        [AllowNull()][string]$ExistingType,
        [AllowNull()][string]$Option,
        [AllowNull()][object]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingType)) {
        return $ExistingType
    }

    $valueText = if ($null -eq $Value) { '' } else { [string]$Value }
    if (Looks-LikeBooleanOption -Option $Option -Value $Value) {
        return 'boolean'
    }
    if ($valueText -match '^-?\d+$' -or $valueText -match '^-?\d+\.\d+$') {
        return 'number'
    }
    if (($Option -match '\bURL\b') -or ($valueText -match '^https?://')) {
        return 'url'
    }

    return 'text'
}

function Get-LevenshteinDistance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $sourceLength = $Source.Length
    $targetLength = $Target.Length

    if ($sourceLength -eq 0) {
        return $targetLength
    }
    if ($targetLength -eq 0) {
        return $sourceLength
    }

    $matrix = New-Object 'int[,]' ($sourceLength + 1), ($targetLength + 1)
    for ($i = 0; $i -le $sourceLength; $i++) {
        $matrix[$i, 0] = $i
    }
    for ($j = 0; $j -le $targetLength; $j++) {
        $matrix[0, $j] = $j
    }

    for ($i = 1; $i -le $sourceLength; $i++) {
        for ($j = 1; $j -le $targetLength; $j++) {
            $cost = if ($Source[$i - 1] -ceq $Target[$j - 1]) { 0 } else { 1 }
            $deletion = $matrix[($i - 1), $j] + 1
            $insertion = $matrix[$i, ($j - 1)] + 1
            $substitution = $matrix[($i - 1), ($j - 1)] + $cost
            $matrix[$i, $j] = [Math]::Min([Math]::Min($deletion, $insertion), $substitution)
        }
    }

    return $matrix[$sourceLength, $targetLength]
}

function Find-FuzzyMatchedSetting {
    param(
        [hashtable]$Index,
        [string]$Option
    )

    $normalizedOption = Normalize-LookupText -Text $Option
    if ($normalizedOption -eq '') {
        return $null
    }

    $seenKeys = @{}
    $bestSetting = $null
    $bestRatio = [double]::PositiveInfinity
    $bestDistance = [int]::MaxValue

    foreach ($entry in $Index.ByKey.GetEnumerator()) {
        $setting = $entry.Value
        $settingKey = [string]$setting.key
        if ($seenKeys.ContainsKey($settingKey)) {
            continue
        }
        $seenKeys[$settingKey] = $true

        foreach ($candidateText in @([string]$setting.description, [string]$setting.label)) {
            $normalizedCandidate = Normalize-LookupText -Text $candidateText
            if ($normalizedCandidate -eq '') {
                continue
            }

            $distance = Get-LevenshteinDistance -Source $normalizedOption -Target $normalizedCandidate
            $maxLength = [Math]::Max($normalizedOption.Length, $normalizedCandidate.Length)
            if ($maxLength -le 0) {
                continue
            }

            $ratio = [double]$distance / [double]$maxLength
            if ($ratio -lt $bestRatio -or ($ratio -eq $bestRatio -and $distance -lt $bestDistance)) {
                $bestSetting = $setting
                $bestRatio = $ratio
                $bestDistance = $distance
            }
        }
    }

    if ($null -ne $bestSetting -and ($bestDistance -le 3 -or $bestRatio -le 0.08)) {
        return $bestSetting
    }

    return $null
}

function Convert-WorkbookValue {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)]
        [string]$Type
    )

    if ($Type -eq 'boolean') {
        if ($null -eq $Value) {
            return $false
        }
        $text = ([string]$Value).Trim()
        return ($text -match '^(1|true|yes)$')
    }

    if ($Type -eq 'number') {
        if ($null -eq $Value -or ([string]$Value).Trim() -eq '') {
            return 0
        }
        $text = ([string]$Value).Trim()
        if ($text -match '^-?\d+$') {
            return [int]$text
        }
        if ($text -match '^-?\d+\.\d+$') {
            return [double]$text
        }
        return $text
    }

    if ($null -eq $Value) {
        return ''
    }

    return [string]$Value
}

function New-SettingIndex {
    param([array]$Settings)

    $index = @{
        ByKey = @{}
        ByCanonicalKey = @{}
        ByDescription = @{}
        ByLabel = @{}
        ByNormalizedDescription = @{}
        ByNormalizedLabel = @{}
    }

    foreach ($setting in @($Settings)) {
        if ($null -eq $setting -or -not $setting.PSObject.Properties['key']) {
            continue
        }
        $key = [string]$setting.key
        $description = [string]$setting.description
        $label = [string]$setting.label

        if ($key -ne '') {
            $index.ByKey[$key] = $setting
            $canonicalKey = Normalize-KeyAlias -Key $key
            if ($canonicalKey -ne '') {
                if (-not $index.ByCanonicalKey.ContainsKey($canonicalKey)) {
                    $index.ByCanonicalKey[$canonicalKey] = New-Object System.Collections.ArrayList
                }
                [void]$index.ByCanonicalKey[$canonicalKey].Add($setting)
            }
        }
        if ($description -ne '') {
            $index.ByDescription[$description] = $setting
            $normalizedDescription = Normalize-LookupText -Text $description
            if (-not $index.ByNormalizedDescription.ContainsKey($normalizedDescription)) {
                $index.ByNormalizedDescription[$normalizedDescription] = New-Object System.Collections.ArrayList
            }
            [void]$index.ByNormalizedDescription[$normalizedDescription].Add($setting)
        }
        if ($label -ne '') {
            $index.ByLabel[$label] = $setting
            $normalizedLabel = Normalize-LookupText -Text $label
            if (-not $index.ByNormalizedLabel.ContainsKey($normalizedLabel)) {
                $index.ByNormalizedLabel[$normalizedLabel] = New-Object System.Collections.ArrayList
            }
            [void]$index.ByNormalizedLabel[$normalizedLabel].Add($setting)
        }
    }

    return $index
}

function Find-MatchedSetting {
    param(
        [hashtable]$Index,
        [string]$Option,
        [AllowNull()][string]$MappedKey
    )

    if ($Index.ByDescription.ContainsKey($Option)) {
        return $Index.ByDescription[$Option]
    }

    $normalized = Normalize-LookupText -Text $Option
    if ($normalized -ne '' -and $Index.ByNormalizedDescription.ContainsKey($normalized)) {
        $matches = $Index.ByNormalizedDescription[$normalized]
        if ($matches.Count -eq 1) {
            return $matches[0]
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($MappedKey) -and $Index.ByKey.ContainsKey($MappedKey)) {
        return $Index.ByKey[$MappedKey]
    }

    if (-not [string]::IsNullOrWhiteSpace($MappedKey)) {
        $canonicalMappedKey = Normalize-KeyAlias -Key $MappedKey
        if ($canonicalMappedKey -ne '' -and $Index.ByCanonicalKey.ContainsKey($canonicalMappedKey)) {
            $matches = $Index.ByCanonicalKey[$canonicalMappedKey]
            if ($matches.Count -eq 1) {
                return $matches[0]
            }
        }
    }

    $fuzzyMatch = Find-FuzzyMatchedSetting -Index $Index -Option $Option
    if ($null -ne $fuzzyMatch) {
        return $fuzzyMatch
    }

    if ($Index.ByLabel.ContainsKey($Option)) {
        return $Index.ByLabel[$Option]
    }

    if ($normalized -ne '' -and $Index.ByNormalizedLabel.ContainsKey($normalized)) {
        $matches = $Index.ByNormalizedLabel[$normalized]
        if ($matches.Count -eq 1) {
            return $matches[0]
        }
    }

    return $null
}

function Resolve-SettingKey {
    param(
        [string]$Option,
        [AllowNull()]$MatchedSetting,
        [AllowNull()][string]$MappedKey,
        [hashtable]$UsedKeys
    )

    $candidate = $null

    if ($null -ne $MatchedSetting) {
        $candidate = [string]$MatchedSetting.key
    }

    if ([string]::IsNullOrWhiteSpace($candidate) -and -not [string]::IsNullOrWhiteSpace($MappedKey)) {
        $candidate = $MappedKey
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        if ($Option -match '\bAPI [Kk]ey\b') {
            $candidate = 'api_key'
        } elseif ($Option -match '\bAPI [Ss]ecret\b') {
            $candidate = 'api_secret'
        } elseif ($Option -match '\bAPI [Pp]assword\b') {
            $candidate = 'api_password'
        } elseif ($Option -match '\bAPI [Uu]sername\b') {
            $candidate = 'api_username'
        } else {
            $candidate = Convert-ToSettingKey -Text $Option
        }
    }

    $base = $candidate
    $resolved = $base
    $suffix = 2
    while ($UsedKeys.ContainsKey($resolved) -and $UsedKeys[$resolved] -ne $Option) {
        $resolved = '{0}_{1}' -f $base, $suffix
        $suffix++
    }

    $UsedKeys[$resolved] = $Option
    return $resolved
}

function Convert-ToOrderedModuleObject {
    param($Module, [array]$Settings)

    return [ordered]@{
        slug       = [string]$Module.slug
        name       = [string]$Module.name
        isPlatform = [bool]$Module.isPlatform
        info       = $Module.info
        apiConfig  = $Module.apiConfig
        settings   = $Settings
    }
}

function Convert-StaticJsToJson {
    param([string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw
    $prefix = 'window.CTI_STATIC_SETTINGS = '
    if (-not $raw.StartsWith($prefix)) {
        throw "Unexpected static settings format: $Path"
    }

    $json = $raw.Substring($prefix.Length)
    if ($json.TrimEnd().EndsWith(';')) {
        $json = $json.TrimEnd()
        $json = $json.Substring(0, $json.Length - 1)
    }

    return $json
}

$rows = Import-XlsxRows -Path $WorkbookPath
if ($rows.Count -lt 2) {
    throw "Workbook appears empty: $WorkbookPath"
}

$header = $rows[0]
if ($header.Module -ne 'Module' -or $header.Option -ne 'Option' -or $header.Value -ne 'Value') {
    throw "Unexpected workbook header row. Expected Module | Option | Value."
}

$dataRows = @($rows | Select-Object -Skip 1 | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Module) -and -not [string]::IsNullOrWhiteSpace($_.Option) })

$moduleMapJson = & php -r "require 'php/SpiderFootModuleMapper.php'; echo json_encode(SpiderFootModuleMapper::getModuleMap(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to load SpiderFoot module map from PHP."
}

$moduleMapObject = $moduleMapJson | ConvertFrom-Json
$moduleMap = @{}
foreach ($property in $moduleMapObject.PSObject.Properties) {
    $moduleMap[$property.Name] = [string]$property.Value
}

$schemaJson = & php -r "require 'php/ModuleSettingsSchema.php'; echo json_encode(ModuleSettingsSchema::getAllSchemas(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to load module settings schema from PHP."
}
$schemaObject = $schemaJson | ConvertFrom-Json
$schemaBySlug = @{}
foreach ($property in $schemaObject.PSObject.Properties) {
    $schemaBySlug[$property.Name] = @($property.Value)
}

$staticSettingsPath = Join-Path $RepoRoot 'assets/js/settings.static-data.js'
$staticJson = Convert-StaticJsToJson -Path $staticSettingsPath
$staticModules = $staticJson | ConvertFrom-Json

$moduleIndexes = @{}
foreach ($module in @($staticModules)) {
    $slug = [string]$module.slug
    $settings = if ($schemaBySlug.ContainsKey($slug)) { @($schemaBySlug[$slug]) } else { @() }
    $moduleIndexes[$slug] = @{
        Module = $module
        Index  = New-SettingIndex -Settings $settings
    }
}

$tmpRowsPath = Join-Path $RepoRoot 'tmp_spiderfoot_rows.json'
$tmpMapPath = Join-Path $RepoRoot 'tmp_spiderfoot_mapped_keys.json'
$tmpPhpPath = Join-Path $RepoRoot 'tmp_map_spiderfoot_option_keys.php'

try {
    Write-Utf8NoBom -Path $tmpRowsPath -Content ($dataRows | ConvertTo-Json -Depth 8)
    @'
<?php
require __DIR__ . '/php/SpiderFootModuleMapper.php';
$rows = json_decode(file_get_contents($argv[1]), true);
$keys = [];
foreach ($rows as $row) {
    $keys[] = SpiderFootModuleMapper::normaliseOptionKey((string)($row['Option'] ?? ''));
}
file_put_contents($argv[2], json_encode($keys, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
'@ | ForEach-Object { Write-Utf8NoBom -Path $tmpPhpPath -Content $_ }

    & php $tmpPhpPath $tmpRowsPath $tmpMapPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to map SpiderFoot option keys through PHP."
    }

    $mappedKeys = (Get-Content -LiteralPath $tmpMapPath -Raw | ConvertFrom-Json)
} finally {
    foreach ($tmpFile in @($tmpRowsPath, $tmpMapPath, $tmpPhpPath)) {
        if (Test-Path -LiteralPath $tmpFile) {
            Remove-Item -LiteralPath $tmpFile -Force
        }
    }
}

$catalogRows = New-Object System.Collections.ArrayList
$catalogBySlug = @{}
$usedKeysBySlug = @{}
$unmappedModules = New-Object System.Collections.ArrayList

for ($index = 0; $index -lt $dataRows.Count; $index++) {
    $row = $dataRows[$index]
    $moduleName = [string]$row.Module
    $option = [string]$row.Option
    $rawValue = $row.Value

    if (-not $moduleMap.ContainsKey($moduleName)) {
        [void]$unmappedModules.Add($moduleName)
        continue
    }

    $slug = [string]$moduleMap[$moduleName]
    if (-not $moduleIndexes.ContainsKey($slug)) {
        throw "Static settings module missing for slug: $slug (from $moduleName)"
    }

    if (-not $usedKeysBySlug.ContainsKey($slug)) {
        $usedKeysBySlug[$slug] = @{}
    }

    $mappedKey = $null
    if ($index -lt $mappedKeys.Count) {
        $mappedKey = [string]$mappedKeys[$index]
        if ($mappedKey -eq '') {
            $mappedKey = $null
        }
    }

    $matchedSetting = Find-MatchedSetting -Index $moduleIndexes[$slug].Index -Option $option -MappedKey $mappedKey
    $resolvedKey = Resolve-SettingKey -Option $option -MatchedSetting $matchedSetting -MappedKey $mappedKey -UsedKeys $usedKeysBySlug[$slug]
    $existingType = if ($null -ne $matchedSetting) { [string]$matchedSetting.type } else { $null }
    $type = Infer-SettingType -ExistingType $existingType -Option $option -Value $rawValue
    $defaultValue = Convert-WorkbookValue -Value $rawValue -Type $type
    $existingLabel = if ($null -ne $matchedSetting) { [string]$matchedSetting.label } else { $null }
    $label = Get-TitleCaseLabel -ExistingLabel $existingLabel -Option $option -Key $resolvedKey

    $catalogRow = [ordered]@{
        sfp_module  = $moduleName
        slug        = $slug
        key         = $resolvedKey
        label       = $label
        type        = $type
        default     = $defaultValue
        description = $option
        order       = $index
    }

    [void]$catalogRows.Add($catalogRow)

    if (-not $catalogBySlug.ContainsKey($slug)) {
        $catalogBySlug[$slug] = New-Object System.Collections.ArrayList
    }
    [void]$catalogBySlug[$slug].Add($catalogRow)
}

if ($unmappedModules.Count -gt 0) {
    $distinctUnmapped = $unmappedModules | Sort-Object -Unique
    throw "Found unmapped SpiderFoot module(s): $($distinctUnmapped -join ', ')"
}

$mergedModules = New-Object System.Collections.ArrayList
foreach ($module in @($staticModules)) {
    $slug = [string]$module.slug
    $existingByKey = @{}
    foreach ($setting in @($module.settings)) {
        $existingByKey[[string]$setting.key] = $setting
    }

    $mergedSettings = New-Object System.Collections.ArrayList
    if ($catalogBySlug.ContainsKey($slug)) {
        foreach ($catalogRow in @($catalogBySlug[$slug])) {
            $key = [string]$catalogRow.key
            $existingSetting = $null
            if ($existingByKey.ContainsKey($key)) {
                $existingSetting = $existingByKey[$key]
                $null = $existingByKey.Remove($key)
            }

            $settingObject = [ordered]@{
                key         = $key
                label       = [string]$catalogRow.label
                type        = [string]$catalogRow.type
                value       = Convert-WorkbookValue -Value $catalogRow.default -Type ([string]$catalogRow.type)
                description = [string]$catalogRow.description
            }
            [void]$mergedSettings.Add($settingObject)
        }
    }

    foreach ($setting in @($module.settings)) {
        $key = [string]$setting.key
        if ($existingByKey.ContainsKey($key)) {
            [void]$mergedSettings.Add([ordered]@{
                key         = $key
                label       = [string]$setting.label
                type        = [string]$setting.type
                value       = $setting.value
                description = [string]$setting.description
            })
            $null = $existingByKey.Remove($key)
        }
    }

    [void]$mergedModules.Add((Convert-ToOrderedModuleObject -Module $module -Settings @($mergedSettings)))
}

$staticPayload = $mergedModules | ConvertTo-Json -Depth 32 -Compress
$catalogJson = $catalogRows | ConvertTo-Json -Depth 16 -Compress

$catalogPhpPath = Join-Path $RepoRoot 'php/SpiderFootSettingsCatalog.php'
$catalogPhp = @'
<?php

class SpiderFootSettingsCatalog
{
    public static function rows(): array
    {
        static $rows = null;
        if ($rows !== null) {
            return $rows;
        }

        $rows = json_decode(<<<'JSON'
__CATALOG_JSON__
JSON, true, 512, JSON_THROW_ON_ERROR);

        return $rows;
    }

    public static function rowsBySlug(): array
    {
        $grouped = [];
        foreach (self::rows() as $row) {
            $slug = (string)($row['slug'] ?? '');
            if ($slug === '') {
                continue;
            }
            $grouped[$slug][] = $row;
        }
        return $grouped;
    }
}
'@
$catalogPhp = $catalogPhp.Replace('__CATALOG_JSON__', $catalogJson)

Write-Utf8NoBom -Path $catalogPhpPath -Content $catalogPhp
Write-Utf8NoBom -Path $staticSettingsPath -Content ("window.CTI_STATIC_SETTINGS = $staticPayload;")

Write-Output ("catalog_rows=" + $catalogRows.Count)
Write-Output ("catalog_modules=" + (@($catalogBySlug.Keys)).Count)
