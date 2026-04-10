<?php
// =============================================================================
//  CTI — API KEY MANAGEMENT
//  php/api/api_keys.php
//
//  Endpoints:
//    GET   ?action=list    — List all API configs (keys are masked, never returned in full)
//    POST  ?action=save    — Save/update API key for a given slug
//    POST  ?action=clear   — Remove API key for a given slug
//    POST  ?action=toggle  — Enable or disable an API source
//
//  ⚠  Authentication required for all actions.
//     Only users with role 'admin' may save/clear/toggle keys.
//     Analysts may only list (masked) configs.
// =============================================================================

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../security-headers.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../InputSanitizer.php';
require_once __DIR__ . '/../ModuleSettingsSchema.php';
require_once __DIR__ . '/../GlobalSettings.php';

SecurityHeaders::init();
header('Content-Type: application/json; charset=utf-8');

// ── Auth gate — must be logged in for every action ────────────────────────────
if (session_status() !== PHP_SESSION_ACTIVE) {
    // SecurityHeaders::init() should have started the session already,
    // but guard just in case.
    session_start();
}

$userId   = $_SESSION['user_id']   ?? null;
$userRole = $_SESSION['user_role'] ?? null;

if (!$userId) {
    jsonApiResponse(401, ['error' => 'Authentication required.']);
}

// ── Route dispatcher ──────────────────────────────────────────────────────────
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'list':
        handleList();
        break;

    case 'settings_snapshot':
        handleSettingsSnapshot();
        break;

    case 'export_snapshot':
        requireAdmin($userRole);
        handleExportSnapshot();
        break;

    case 'import_snapshot':
        requireAdmin($userRole);
        handleImportSnapshot();
        break;

    case 'save':
        requireAdmin($userRole);
        handleSave();
        break;

    case 'save_settings':
        requireAdmin($userRole);
        handleSaveSettings();
        break;

    case 'clear':
        requireAdmin($userRole);
        handleClear();
        break;

    case 'toggle':
        requireAdmin($userRole);
        handleToggle();
        break;

    case 'health_check':
        requireAdmin($userRole);
        handleHealthCheck();
        break;

    default:
        jsonApiResponse(400, ['error' => 'Unknown action.']);
}

// =============================================================================
//  HANDLERS
// =============================================================================

/**
 * GET ?action=list
 * Returns all API config rows. API keys are NEVER returned in full — only a
 * masked representation is provided so the frontend can confirm a key exists.
 */
function handleList(): void
{
    try {
        $category = trim($_GET['category'] ?? '');

        $sql = 'SELECT id, name, slug, base_url, is_enabled, rate_limit, description,
                       category, auth_type, supported_types, docs_url, requires_key,
                       health_status, last_health_check,
                       (api_key IS NOT NULL AND api_key != "") AS has_key,
                       CASE
                         WHEN api_key IS NULL OR api_key = "" THEN ""
                         WHEN CHAR_LENGTH(api_key) <= 4 THEN REPEAT("*", CHAR_LENGTH(api_key))
                         ELSE CONCAT(REPEAT("*", LEAST(8, GREATEST(4, CHAR_LENGTH(api_key) - 4))), RIGHT(api_key, 4))
                       END AS api_key_masked,
                       created_at, updated_at
                  FROM api_configs';

        $params = [];
        if ($category !== '' && $category !== 'all') {
            $sql .= ' WHERE category = :cat';
            $params[':cat'] = $category;
        }

        $sql .= ' ORDER BY category ASC, name ASC';

        $rows = DB::query($sql, $params);

        // Parse supported_types JSON for each row
        foreach ($rows as &$row) {
            if (isset($row['supported_types']) && is_string($row['supported_types'])) {
                $row['supported_types'] = json_decode($row['supported_types'], true) ?? [];
            }
        }
        unset($row);

        // Never include the raw api_key column in the response
        jsonApiResponse(200, ['apis' => $rows]);
    } catch (Exception $e) {
        error_log('[api_keys] list error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to load API configurations.']);
    }
}

/**
 * GET ?action=settings_snapshot
 * Returns persisted platform/module setting overrides currently in DB.
 */
function handleSettingsSnapshot(): void
{
    try {
        $platformRows = DB::query(
            'SELECT setting_key, setting_value FROM platform_settings ORDER BY setting_key ASC'
        );

        $moduleRows = DB::query(
            'SELECT module_slug, setting_key, setting_value
               FROM module_settings
              ORDER BY module_slug ASC, setting_key ASC'
        );

        $platform = [];
        foreach ($platformRows as $row) {
            $key = (string)($row['setting_key'] ?? '');
            if ($key === '') {
                continue;
            }
            $platform[$key] = (string)($row['setting_value'] ?? '');
        }

        $modules = [];
        foreach ($moduleRows as $row) {
            $slug = (string)($row['module_slug'] ?? '');
            $key = (string)($row['setting_key'] ?? '');
            if ($slug === '' || $key === '') {
                continue;
            }
            if (!isset($modules[$slug])) {
                $modules[$slug] = [];
            }
            $modules[$slug][$key] = (string)($row['setting_value'] ?? '');
        }

        jsonApiResponse(200, [
            'platform_settings' => $platform,
            'module_settings' => $modules,
        ]);
    } catch (Throwable $e) {
        error_log('[api_keys] settings_snapshot error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to load settings snapshot.']);
    }
}

/**
 * POST ?action=export_snapshot
 * Returns the full admin configuration snapshot, including API keys.
 */
function handleExportSnapshot(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    try {
        $platformRows = DB::query(
            'SELECT setting_key, setting_value FROM platform_settings ORDER BY setting_key ASC'
        );
        $moduleRows = DB::query(
            'SELECT module_slug, setting_key, setting_value
               FROM module_settings
              ORDER BY module_slug ASC, setting_key ASC'
        );
        $apiRows = DB::query(
            'SELECT slug, name, api_key, base_url, rate_limit, is_enabled, auth_type, requires_key, category
               FROM api_configs
              ORDER BY slug ASC'
        );

        $snapshot = [
            'meta' => [
                'app' => APP_NAME,
                'version' => APP_VERSION,
                'exported_at' => gmdate('c'),
                'schema_version' => 1,
            ],
            'platform_settings' => [],
            'module_settings' => [],
            'api_configs' => [],
        ];

        foreach ($platformRows as $row) {
            $key = trim((string)($row['setting_key'] ?? ''));
            if ($key !== '') {
                $snapshot['platform_settings'][$key] = (string)($row['setting_value'] ?? '');
            }
        }

        foreach ($moduleRows as $row) {
            $slug = trim((string)($row['module_slug'] ?? ''));
            $key = trim((string)($row['setting_key'] ?? ''));
            if ($slug === '' || $key === '') {
                continue;
            }
            if (!isset($snapshot['module_settings'][$slug])) {
                $snapshot['module_settings'][$slug] = [];
            }
            $snapshot['module_settings'][$slug][$key] = (string)($row['setting_value'] ?? '');
        }

        foreach ($apiRows as $row) {
            $slug = trim((string)($row['slug'] ?? ''));
            if ($slug === '') {
                continue;
            }
            $snapshot['api_configs'][$slug] = [
                'name' => (string)($row['name'] ?? $slug),
                'category' => (string)($row['category'] ?? ''),
                'auth_type' => (string)($row['auth_type'] ?? 'none'),
                'requires_key' => !empty($row['requires_key']),
                'is_enabled' => !empty($row['is_enabled']),
                'rate_limit' => (int)($row['rate_limit'] ?? 0),
                'base_url' => (string)($row['base_url'] ?? ''),
                'api_key' => (string)($row['api_key'] ?? ''),
            ];
        }

        jsonApiResponse(200, ['snapshot' => $snapshot]);
    } catch (Throwable $e) {
        error_log('[api_keys] export_snapshot error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to export configuration snapshot.']);
    }
}

/**
 * POST ?action=import_snapshot
 * Body: { snapshot, _csrf_token }
 */
function handleImportSnapshot(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $snapshot = $input['snapshot'] ?? null;
    if (!is_array($snapshot)) {
        jsonApiResponse(422, ['error' => 'Snapshot payload is required.']);
    }

    $platformSettings = is_array($snapshot['platform_settings'] ?? null) ? $snapshot['platform_settings'] : [];
    $moduleSettings = is_array($snapshot['module_settings'] ?? null) ? $snapshot['module_settings'] : [];
    $apiConfigs = is_array($snapshot['api_configs'] ?? null) ? $snapshot['api_configs'] : [];

    $platformSchema = buildSchemaKeyMap('_global') + buildSchemaKeyMap('_storage');
    $importedPlatform = 0;
    $importedModuleSettings = 0;
    $updatedApis = 0;

    try {
        DB::transaction(function () use (
            $platformSettings,
            $moduleSettings,
            $apiConfigs,
            $platformSchema,
            &$importedPlatform,
            &$importedModuleSettings,
            &$updatedApis
        ) {
            foreach ($platformSettings as $key => $value) {
                $settingKey = trim((string)$key);
                if ($settingKey === '' || !isset($platformSchema[$settingKey])) {
                    continue;
                }

                $slug = array_key_exists($settingKey, buildSchemaKeyMap('_storage')) ? '_storage' : '_global';
                [$ok, $normalized, $err] = normalizeSettingForSave($slug, $settingKey, $value, $platformSchema[$settingKey]);
                if (!$ok) {
                    throw new InvalidArgumentException($err ?: "Invalid platform setting: {$settingKey}");
                }

                DB::execute(
                    "INSERT INTO platform_settings (setting_key, setting_value)
                     VALUES (:k, :v)
                     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
                    [':k' => $settingKey, ':v' => $normalized]
                );
                $importedPlatform++;
            }

            foreach ($moduleSettings as $slug => $settings) {
                $moduleSlug = trim((string)$slug);
                if ($moduleSlug === '' || !preg_match('/^[a-z0-9\\-]{1,50}$/i', $moduleSlug) || !is_array($settings)) {
                    continue;
                }

                $existing = DB::queryOne(
                    'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
                    [':slug' => $moduleSlug]
                );
                if (!$existing) {
                    continue;
                }

                $schemaMap = buildSchemaKeyMap($moduleSlug);
                foreach ($settings as $key => $value) {
                    $settingKey = trim((string)$key);
                    if ($settingKey === '' || !isset($schemaMap[$settingKey])) {
                        continue;
                    }

                    [$ok, $normalized, $err] = normalizeSettingForSave($moduleSlug, $settingKey, $value, $schemaMap[$settingKey]);
                    if (!$ok) {
                        throw new InvalidArgumentException($err ?: "Invalid module setting: {$moduleSlug}.{$settingKey}");
                    }

                    DB::execute(
                        "INSERT INTO module_settings (module_slug, setting_key, setting_value)
                         VALUES (:slug, :k, :v)
                         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
                        [':slug' => $moduleSlug, ':k' => $settingKey, ':v' => $normalized]
                    );
                    $importedModuleSettings++;
                }
            }

            foreach ($apiConfigs as $slug => $config) {
                $moduleSlug = trim((string)$slug);
                if ($moduleSlug === '' || !preg_match('/^[a-z0-9\\-]{1,50}$/i', $moduleSlug) || !is_array($config)) {
                    continue;
                }

                $existing = DB::queryOne(
                    'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
                    [':slug' => $moduleSlug]
                );
                if (!$existing) {
                    continue;
                }

                $params = [
                    ':slug' => $moduleSlug,
                    ':base' => trim((string)($config['base_url'] ?? '')),
                    ':rate' => max(0, (int)($config['rate_limit'] ?? 0)),
                    ':enabled' => !empty($config['is_enabled']) ? 1 : 0,
                ];

                $setSql = "base_url = :base, rate_limit = :rate, is_enabled = :enabled";
                if (array_key_exists('api_key', $config)) {
                    $apiKey = trim((string)($config['api_key'] ?? ''));
                    $params[':api_key'] = $apiKey !== '' ? $apiKey : null;
                    $setSql .= ", api_key = :api_key";
                }

                DB::execute(
                    "UPDATE api_configs
                        SET {$setSql},
                            updated_at = NOW()
                      WHERE slug = :slug",
                    $params
                );
                $updatedApis++;
            }
        });

        GlobalSettings::reload();
        jsonApiResponse(200, [
            'message' => 'Configuration snapshot imported successfully.',
            'platform_settings' => $importedPlatform,
            'module_settings' => $importedModuleSettings,
            'api_configs' => $updatedApis,
        ]);
    } catch (Throwable $e) {
        error_log('[api_keys] import_snapshot error: ' . $e->getMessage());
        jsonApiResponse(422, ['error' => $e->getMessage()]);
    }
}

/**
 * POST ?action=save
 * Body: { slug, api_key, _csrf_token }
 * Saves (AES-style trim + length-validated) API key to the database.
 * The raw key is stored server-side only; the frontend never receives it back.
 */
function handleSave(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    // CSRF validation
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $slug   = trim($input['slug']    ?? '');
    $apiKey = trim($input['api_key'] ?? '');

    // Validate slug (alphanumeric + hyphens only)
    if (!preg_match('/^[a-z0-9\-]{1,50}$/i', $slug)) {
        jsonApiResponse(422, ['error' => 'Invalid API slug.']);
    }

    // Validate key length (1–500 chars)
    if ($apiKey === '' || strlen($apiKey) > 500) {
        jsonApiResponse(422, ['error' => 'API key must be between 1 and 500 characters.']);
    }

    // Confirm the slug exists in the database
    $existing = DB::queryOne(
        'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
        [':slug' => $slug]
    );

    if (!$existing) {
        jsonApiResponse(404, ['error' => 'API source not found.']);
    }

    try {
        DB::execute(
            'UPDATE api_configs SET api_key = :key, updated_at = NOW() WHERE slug = :slug',
            [':key' => $apiKey, ':slug' => $slug]
        );

        jsonApiResponse(200, ['message' => 'API key saved successfully.']);
    } catch (Exception $e) {
        error_log('[api_keys] save error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to save API key.']);
    }
}

/**
 * POST ?action=save_settings
 * Body: { slug, settings: { key: value, ... }, _csrf_token }
 * Saves platform/module settings overrides.
 */
function handleSaveSettings(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $slug = trim((string)($input['slug'] ?? ''));
    $settings = $input['settings'] ?? null;

    if (!is_array($settings) || $settings === []) {
        jsonApiResponse(422, ['error' => 'At least one setting is required.']);
    }

    $platformSlug = in_array($slug, ['_global', '_storage'], true);
    if (!$platformSlug && !preg_match('/^[a-z0-9\-]{1,50}$/i', $slug)) {
        jsonApiResponse(422, ['error' => 'Invalid module slug.']);
    }

    if (!$platformSlug) {
        $existing = DB::queryOne(
            'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
            [':slug' => $slug]
        );
        if (!$existing) {
            jsonApiResponse(404, ['error' => 'API source not found.']);
        }
    }

    $schemaMap = buildSchemaKeyMap($slug);

    $normalized = [];
    foreach ($settings as $key => $value) {
        $settingKey = trim((string)$key);
        if ($settingKey === '' || !preg_match('/^[a-z0-9_\-]{1,100}$/i', $settingKey)) {
            jsonApiResponse(422, ['error' => "Invalid setting key: {$settingKey}"]);
        }

        if ($platformSlug && !isset($schemaMap[$settingKey])) {
            jsonApiResponse(422, ['error' => "Unknown platform setting: {$settingKey}"]);
        }

        [$ok, $settingValue, $err] = normalizeSettingForSave($slug, $settingKey, $value, $schemaMap[$settingKey] ?? null);
        if (!$ok) {
            jsonApiResponse(422, ['error' => $err ?: "Invalid value for setting: {$settingKey}"]);
        }

        if (strlen($settingValue) > 20000) {
            jsonApiResponse(422, ['error' => "Setting value is too long: {$settingKey}"]);
        }

        $normalized[$settingKey] = $settingValue;
    }

    try {
        DB::transaction(function () use ($platformSlug, $slug, $normalized) {
            foreach ($normalized as $settingKey => $settingValue) {
                if ($platformSlug) {
                    DB::execute(
                        "INSERT INTO platform_settings (setting_key, setting_value)
                         VALUES (:k, :v)
                         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
                        [':k' => $settingKey, ':v' => $settingValue]
                    );
                } else {
                    DB::execute(
                        "INSERT INTO module_settings (module_slug, setting_key, setting_value)
                         VALUES (:slug, :k, :v)
                         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
                        [':slug' => $slug, ':k' => $settingKey, ':v' => $settingValue]
                    );
                }
            }
        });

        if ($platformSlug) {
            GlobalSettings::reload();
        }

        jsonApiResponse(200, ['message' => 'Settings saved successfully.']);
    } catch (Throwable $e) {
        error_log('[api_keys] save_settings error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to save settings.']);
    }
}

/**
 * POST ?action=clear
 * Body: { slug, _csrf_token }
 * Removes the API key for a given slug.
 */
function handleClear(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $slug = trim($input['slug'] ?? '');
    if (!preg_match('/^[a-z0-9\-]{1,50}$/i', $slug)) {
        jsonApiResponse(422, ['error' => 'Invalid API slug.']);
    }

    $existing = DB::queryOne(
        'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
        [':slug' => $slug]
    );
    if (!$existing) {
        jsonApiResponse(404, ['error' => 'API source not found.']);
    }

    try {
        DB::execute(
            'UPDATE api_configs SET api_key = NULL, updated_at = NOW() WHERE slug = :slug',
            [':slug' => $slug]
        );
        jsonApiResponse(200, ['message' => 'API key cleared.']);
    } catch (Exception $e) {
        error_log('[api_keys] clear error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to clear API key.']);
    }
}

/**
 * POST ?action=toggle
 * Body: { slug, enabled (bool), _csrf_token }
 * Enables or disables an API source.
 */
function handleToggle(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $slug    = trim($input['slug'] ?? '');
    $enabled = isset($input['enabled']) ? (bool)$input['enabled'] : null;

    if (!preg_match('/^[a-z0-9\-]{1,50}$/i', $slug) || $enabled === null) {
        jsonApiResponse(422, ['error' => 'Invalid parameters.']);
    }

    $existing = DB::queryOne(
        'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
        [':slug' => $slug]
    );
    if (!$existing) {
        jsonApiResponse(404, ['error' => 'API source not found.']);
    }

    try {
        DB::execute(
            'UPDATE api_configs SET is_enabled = :enabled, updated_at = NOW() WHERE slug = :slug',
            [':enabled' => (int)$enabled, ':slug' => $slug]
        );
        jsonApiResponse(200, ['message' => 'API source ' . ($enabled ? 'enabled' : 'disabled') . '.']);
    } catch (Exception $e) {
        error_log('[api_keys] toggle error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Failed to update API status.']);
    }
}

/**
 * POST ?action=health_check
 * Body: { slug, _csrf_token }
 * Runs a lightweight health check against the API and updates status.
 */
function handleHealthCheck(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonApiResponse(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonApiResponse(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $slug = trim($input['slug'] ?? '');
    if (!preg_match('/^[a-z0-9\-]{1,50}$/i', $slug)) {
        jsonApiResponse(422, ['error' => 'Invalid API slug.']);
    }

    $existing = DB::queryOne(
        'SELECT id FROM api_configs WHERE slug = :slug LIMIT 1',
        [':slug' => $slug]
    );
    if (!$existing) {
        jsonApiResponse(404, ['error' => 'API source not found.']);
    }

    try {
        require_once __DIR__ . '/../OsintEngine.php';
        $result = OsintEngine::healthCheck($slug);
        jsonApiResponse(200, $result);
    } catch (Exception $e) {
        error_log('[api_keys] health_check error: ' . $e->getMessage());
        jsonApiResponse(500, ['error' => 'Health check failed.']);
    }
}

// =============================================================================
//  HELPERS
// =============================================================================

/**
 * Build key => setting-definition map for a schema slug.
 *
 * @return array<string,array<string,mixed>>
 */
function buildSchemaKeyMap(string $slug): array
{
    $schema = ModuleSettingsSchema::getSchema($slug);
    $map = [];
    foreach ($schema as $definition) {
        $key = (string)($definition['key'] ?? '');
        if ($key !== '') {
            $map[$key] = $definition;
        }
    }
    return $map;
}

/**
 * Normalize and validate a setting value before persistence.
 *
 * @param array<string,mixed>|null $schemaDef
 * @return array{0: bool, 1: string, 2: ?string}
 */
function normalizeSettingForSave(string $slug, string $key, mixed $value, ?array $schemaDef): array
{
    $type = (string)($schemaDef['type'] ?? 'text');
    [$ok, $normalized, $err] = normalizeByType($type, $value);
    if (!$ok) {
        return [false, '', $err];
    }

    if ($slug === '_global') {
        switch ($key) {
            case 'http_timeout':
                $n = (int)$normalized;
                if ($n < 1 || $n > 300) {
                    return [false, '', 'HTTP timeout must be between 1 and 300 seconds.'];
                }
                $normalized = (string)$n;
                break;
            case 'max_concurrent_modules':
                $n = (int)$normalized;
                if ($n < 1 || $n > 64) {
                    return [false, '', 'Max concurrent modules must be between 1 and 64.'];
                }
                $normalized = (string)$n;
                break;
            case 'tld_cache_hours':
                $n = (int)$normalized;
                if ($n < 1 || $n > 8760) {
                    return [false, '', 'TLD cache hours must be between 1 and 8760.'];
                }
                $normalized = (string)$n;
                break;
            case 'socks_type':
                $clean = GlobalSettings::sanitizeSocksType($normalized);
                if ($normalized !== '' && $clean === '') {
                    return [false, '', "SOCKS type must be one of: 4, 5, HTTP, TOR (or empty to disable)."];
                }
                $normalized = $clean;
                break;
            case 'socks_port':
                if ($normalized === '') {
                    break;
                }
                if (!preg_match('/^\d{1,5}$/', $normalized)) {
                    return [false, '', 'SOCKS port must be a number from 1 to 65535.'];
                }
                $port = (int)$normalized;
                if ($port < 1 || $port > 65535) {
                    return [false, '', 'SOCKS port must be a number from 1 to 65535.'];
                }
                $normalized = (string)$port;
                break;
            case 'dns_resolver':
                $validation = validateDnsResolverSetting($normalized);
                if ($validation !== null) {
                    return [false, '', $validation];
                }
                break;
            case 'tld_list_url':
                $validation = validateTldSourceSetting($normalized);
                if ($validation !== null) {
                    return [false, '', $validation];
                }
                break;
            case 'socks_username':
            case 'socks_password':
                if (strlen($normalized) > 255) {
                    return [false, '', ucfirst(str_replace('_', ' ', $key)) . ' is too long (max 255 chars).'];
                }
                break;
            case 'user_agent':
                if ($normalized !== '' && str_starts_with($normalized, '@') && trim(substr($normalized, 1)) === '') {
                    return [false, '', "User-Agent '@' prefix must be followed by a file path."];
                }
                break;
        }
    } elseif ($slug === '_storage' && $key === 'max_bytes_per_element') {
        $n = (int)$normalized;
        if ($n < 0 || $n > 10485760) {
            return [false, '', 'Max bytes per element must be between 0 and 10485760.'];
        }
        $normalized = (string)$n;
    }

    return [true, $normalized, null];
}

/**
 * Normalize raw setting values to the schema type.
 *
 * @return array{0: bool, 1: string, 2: ?string}
 */
function normalizeByType(string $type, mixed $value): array
{
    $type = strtolower(trim($type));

    if ($type === 'boolean') {
        if (is_bool($value)) {
            return [true, $value ? '1' : '0', null];
        }
        if (is_scalar($value) || $value === null) {
            $normalized = strtolower(trim((string)($value ?? '')));
            return [true, in_array($normalized, ['1', 'true', 'yes', 'on'], true) ? '1' : '0', null];
        }
        return [false, '', 'Boolean value is invalid.'];
    }

    if ($type === 'number') {
        if (is_bool($value) || is_array($value) || is_object($value)) {
            return [false, '', 'Numeric value is invalid.'];
        }
        $raw = trim((string)($value ?? ''));
        if ($raw === '' || !is_numeric($raw)) {
            return [false, '', 'Numeric value is invalid.'];
        }
        // Preserve integer representation where possible.
        if (preg_match('/^-?\d+$/', $raw)) {
            return [true, (string)((int)$raw), null];
        }
        return [true, (string)((float)$raw), null];
    }

    if (is_scalar($value) || $value === null) {
        return [true, trim((string)($value ?? '')), null];
    }

    return [false, '', 'Setting value type is invalid.'];
}

function validateDnsResolverSetting(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }

    $tokens = preg_split('/[\s,;]+/', $value) ?: [];
    foreach ($tokens as $token) {
        $token = trim($token);
        if ($token === '') {
            continue;
        }
        if (!isValidResolverToken($token)) {
            return 'DNS resolver must be a valid IP/host (comma-separated list allowed).';
        }
    }
    return null;
}

function isValidResolverToken(string $token): bool
{
    if (filter_var($token, FILTER_VALIDATE_IP)) {
        return true;
    }

    // IPv6 with explicit port: [2001:4860:4860::8888]:53
    if (preg_match('/^\[(.+)\]:(\d{1,5})$/', $token, $m)) {
        $port = (int)$m[2];
        return $port >= 1
            && $port <= 65535
            && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    // IPv4/hostname with explicit port.
    if (preg_match('/^([^:]+):(\d{1,5})$/', $token, $m)) {
        $port = (int)$m[2];
        if ($port < 1 || $port > 65535) {
            return false;
        }
        $host = $m[1];
        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || preg_match('/^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$/i', $host) === 1;
    }

    return preg_match('/^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$/i', $token) === 1;
}

function validateTldSourceSetting(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_URL)) {
        return null;
    }

    // Also allow inline comma/newline-separated lists.
    if (preg_match('/^[A-Za-z0-9,\s\.\-\r\n;]+$/', $value) === 1) {
        return null;
    }

    return 'Internet TLD list must be a valid URL or comma/newline-separated values.';
}

function requireAdmin(string $role): void
{
    if (strtolower($role) !== 'admin') {
        jsonApiResponse(403, ['error' => 'Administrator access required.']);
    }
}

function jsonApiResponse(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
