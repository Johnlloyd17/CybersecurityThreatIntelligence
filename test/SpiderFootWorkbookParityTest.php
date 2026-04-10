<?php

declare(strict_types=1);

return static function (): void {
    require_once __DIR__ . '/../php/SpiderFootSettingsCatalog.php';
    require_once __DIR__ . '/../php/ModuleSettingsSchema.php';

    $catalogRows = SpiderFootSettingsCatalog::rows();
    if (count($catalogRows) !== 605) {
        throw new RuntimeException('Expected 605 SpiderFoot workbook rows, found ' . count($catalogRows));
    }

    $moduleCount = count(array_unique(array_map(
        static fn(array $row): string => (string)($row['slug'] ?? ''),
        $catalogRows
    )));
    if ($moduleCount !== 179) {
        throw new RuntimeException('Expected 179 SpiderFoot workbook modules, found ' . $moduleCount);
    }

    $schemas = ModuleSettingsSchema::getAllSchemas();
    $schemaBySlugAndKey = [];
    foreach ($schemas as $slug => $settings) {
        foreach ($settings as $setting) {
            $key = (string)($setting['key'] ?? '');
            if ($key === '') {
                continue;
            }
            $schemaBySlugAndKey[$slug . '|' . $key] = $setting;
        }
    }

    $staticRaw = file_get_contents(__DIR__ . '/../assets/js/settings.static-data.js');
    if ($staticRaw === false) {
        throw new RuntimeException('Unable to read settings.static-data.js');
    }

    $prefix = 'window.CTI_STATIC_SETTINGS = ';
    if (strpos($staticRaw, $prefix) !== 0) {
        throw new RuntimeException('Unexpected settings.static-data.js format');
    }

    $staticJson = substr($staticRaw, strlen($prefix));
    $staticJson = rtrim($staticJson);
    if (substr($staticJson, -1) === ';') {
        $staticJson = substr($staticJson, 0, -1);
    }

    $staticModules = json_decode($staticJson, true, 512, JSON_THROW_ON_ERROR);
    $staticBySlugAndKey = [];
    foreach ($staticModules as $module) {
        $slug = (string)($module['slug'] ?? '');
        foreach (($module['settings'] ?? []) as $setting) {
            $key = (string)($setting['key'] ?? '');
            if ($slug === '' || $key === '') {
                continue;
            }
            $staticBySlugAndKey[$slug . '|' . $key] = $setting;
        }
    }

    foreach ($catalogRows as $row) {
        $slug = (string)$row['slug'];
        $key = (string)$row['key'];
        $lookup = $slug . '|' . $key;

        if (!isset($schemaBySlugAndKey[$lookup])) {
            throw new RuntimeException("Schema missing workbook row: {$lookup}");
        }
        if (!isset($staticBySlugAndKey[$lookup])) {
            throw new RuntimeException("Static settings missing workbook row: {$lookup}");
        }

        $schemaSetting = $schemaBySlugAndKey[$lookup];
        if ((string)($schemaSetting['description'] ?? '') !== (string)$row['description']) {
            throw new RuntimeException("Schema description mismatch for {$lookup}");
        }
        if (json_encode($schemaSetting['default'] ?? null) !== json_encode($row['default'])) {
            throw new RuntimeException("Schema default mismatch for {$lookup}");
        }

        $staticSetting = $staticBySlugAndKey[$lookup];
        if ((string)($staticSetting['description'] ?? '') !== (string)$row['description']) {
            throw new RuntimeException("Static description mismatch for {$lookup}");
        }
        if (json_encode($staticSetting['value'] ?? null) !== json_encode($row['default'])) {
            throw new RuntimeException("Static value mismatch for {$lookup}");
        }
    }
};
