<?php
// =============================================================================
//  CTI — Seed Baseline Module Settings from SpiderFoot MD Table
//  php/SeedBaselineSettings.php
//
//  CLI script that parses SPIDERFOOT_SCAN_SETTINGS_BASELINE_TABLE.md, maps
//  SpiderFoot module names and option descriptions to CTI slugs and normalised
//  setting keys, then INSERTs into `module_settings` with ON DUPLICATE KEY
//  UPDATE (preserves existing user overrides when $forceOverwrite is false).
//
//  Usage:
//    php php/SeedBaselineSettings.php              # seed defaults (skip existing)
//    php php/SeedBaselineSettings.php --force      # overwrite existing values
//    php php/SeedBaselineSettings.php --dry-run    # preview without writing
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/SpiderFootModuleMapper.php';

class SeedBaselineSettings
{
    private bool $forceOverwrite;
    private bool $dryRun;
    private int  $inserted  = 0;
    private int  $updated   = 0;
    private int  $skipped   = 0;
    private int  $unmapped  = 0;

    public function __construct(bool $forceOverwrite = false, bool $dryRun = false)
    {
        $this->forceOverwrite = $forceOverwrite;
        $this->dryRun         = $dryRun;
    }

    /**
     * Run the seeder. Returns summary stats.
     */
    public function run(): array
    {
        $mdPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.github'
                . DIRECTORY_SEPARATOR . 'SPIDERFOOT_SCAN_SETTINGS_BASELINE_TABLE.md';

        if (!is_readable($mdPath)) {
            throw new RuntimeException("Baseline MD file not found: {$mdPath}");
        }

        $lines = file($mdPath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuntimeException("Failed to read: {$mdPath}");
        }

        $rows = $this->parseMdTable($lines);
        $this->log("Parsed " . count($rows) . " setting rows from MD file.");

        // Group by (ctiSlug, settingKey) to handle duplicate option descriptions
        // within the same module — keep the last value.
        $grouped = [];
        $unmappedModules = [];
        $unmappedOptions = [];

        foreach ($rows as $row) {
            $sfpModule  = $row['module'];
            $optionDesc = $row['option'];
            $value      = $row['value'];

            // Map sfp_ module name → CTI slug
            $ctiSlug = SpiderFootModuleMapper::toCtiSlug($sfpModule);
            if ($ctiSlug === null) {
                $unmappedModules[$sfpModule] = true;
                $this->unmapped++;
                continue;
            }

            // Map option description → normalised setting key
            $settingKey = SpiderFootModuleMapper::normaliseOptionKey($optionDesc);
            if ($settingKey === null) {
                $unmappedOptions[] = "{$sfpModule} | {$optionDesc}";
                $this->unmapped++;
                continue;
            }

            $grouped["{$ctiSlug}|{$settingKey}"] = [
                'slug'  => $ctiSlug,
                'key'   => $settingKey,
                'value' => $value,
            ];
        }

        if (!empty($unmappedModules)) {
            $this->log("WARNING: " . count($unmappedModules) . " unmapped module(s): "
                . implode(', ', array_keys($unmappedModules)));
        }
        if (!empty($unmappedOptions)) {
            $this->log("WARNING: " . count($unmappedOptions) . " unmapped option(s).");
            foreach (array_slice($unmappedOptions, 0, 20) as $opt) {
                $this->log("  - {$opt}");
            }
            if (count($unmappedOptions) > 20) {
                $this->log("  ... and " . (count($unmappedOptions) - 20) . " more.");
            }
        }

        // Upsert into module_settings
        foreach ($grouped as $entry) {
            $this->upsertSetting($entry['slug'], $entry['key'], $entry['value']);
        }

        $summary = [
            'inserted'  => $this->inserted,
            'updated'   => $this->updated,
            'skipped'   => $this->skipped,
            'unmapped'  => $this->unmapped,
            'total_md'  => count($rows),
            'total_grouped' => count($grouped),
        ];

        $this->log("Done. Inserted={$this->inserted} Updated={$this->updated} "
            . "Skipped={$this->skipped} Unmapped={$this->unmapped}");

        return $summary;
    }

    /**
     * Parse the tab-separated (or pipe-delimited) MD table.
     */
    private function parseMdTable(array $lines): array
    {
        $rows = [];
        $headerFound = false;

        foreach ($lines as $line) {
            $trimmed = trim((string)$line);
            if ($trimmed === '') {
                continue;
            }

            // Detect format: tab-separated or pipe-delimited
            if (strpos($trimmed, "\t") !== false) {
                $cells = explode("\t", $trimmed);
                $cells = array_map('trim', $cells);
            } elseif ($trimmed[0] === '|') {
                $cells = preg_split('/(?<!\\\\)\|/', trim($trimmed, '|'));
                if (!is_array($cells) || count($cells) < 3) {
                    continue;
                }
                $cells = array_map(
                    static fn(string $c): string => trim(str_replace('\\|', '|', $c)),
                    $cells
                );
            } else {
                continue;
            }

            if (count($cells) < 3) {
                continue;
            }

            // Look for header row
            if (!$headerFound) {
                $header = array_map('strtolower', array_slice($cells, 0, 3));
                if ($header === ['module', 'option', 'value']) {
                    $headerFound = true;
                }
                continue;
            }

            // Skip separator rows (---|---|---)
            $isSep = true;
            foreach (array_slice($cells, 0, 3) as $c) {
                if (!preg_match('/^:?-{2,}:?$/', $c)) {
                    $isSep = false;
                    break;
                }
            }
            if ($isSep) {
                continue;
            }

            $module = trim((string)($cells[0] ?? ''));
            $option = trim((string)($cells[1] ?? ''));
            $value  = trim((string)implode('|', array_slice($cells, 2)));

            if ($module !== '' && $option !== '') {
                $rows[] = [
                    'module' => $module,
                    'option' => $option,
                    'value'  => $value,
                ];
            }
        }

        return $rows;
    }

    /**
     * Insert or update a single module setting.
     */
    private function upsertSetting(string $slug, string $key, string $value): void
    {
        if ($this->dryRun) {
            $this->log("  [dry-run] {$slug}.{$key} = {$value}");
            $this->inserted++;
            return;
        }

        try {
            // Check if row already exists
            $existing = DB::queryOne(
                'SELECT setting_value FROM module_settings WHERE module_slug = :slug AND setting_key = :key',
                [':slug' => $slug, ':key' => $key]
            );

            if ($existing !== null) {
                if ($this->forceOverwrite) {
                    DB::execute(
                        'UPDATE module_settings SET setting_value = :val WHERE module_slug = :slug AND setting_key = :key',
                        [':val' => $value, ':slug' => $slug, ':key' => $key]
                    );
                    $this->updated++;
                } else {
                    $this->skipped++;
                }
            } else {
                DB::execute(
                    'INSERT INTO module_settings (module_slug, setting_key, setting_value) VALUES (:slug, :key, :val)',
                    [':slug' => $slug, ':key' => $key, ':val' => $value]
                );
                $this->inserted++;
            }
        } catch (Throwable $e) {
            $this->log("  ERROR upserting {$slug}.{$key}: " . $e->getMessage());
        }
    }

    private function log(string $msg): void
    {
        if (PHP_SAPI === 'cli') {
            echo $msg . PHP_EOL;
        } else {
            error_log("[SeedBaseline] {$msg}");
        }
    }
}

// =============================================================================
//  CLI Entry Point
// =============================================================================

if (PHP_SAPI === 'cli' && realpath($argv[0] ?? '') === realpath(__FILE__)) {
    $force  = in_array('--force', $argv, true);
    $dryRun = in_array('--dry-run', $argv, true);

    echo "=== CTI Baseline Settings Seeder ===" . PHP_EOL;
    echo "Mode: " . ($dryRun ? 'DRY RUN' : ($force ? 'FORCE OVERWRITE' : 'SEED ONLY (skip existing)')) . PHP_EOL;
    echo PHP_EOL;

    try {
        $seeder = new SeedBaselineSettings($force, $dryRun);
        $stats  = $seeder->run();
        echo PHP_EOL . "Summary:" . PHP_EOL;
        echo json_encode($stats, JSON_PRETTY_PRINT) . PHP_EOL;
        exit(0);
    } catch (Throwable $e) {
        echo "FATAL: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
}
