<?php
// =============================================================================
//  CTI — GLOBAL SETTINGS PROVIDER
//  php/GlobalSettings.php
//
//  Loads platform_settings from the database once per request (lazy, cached).
//  Provides typed accessors for all _global and _storage configuration keys.
//
//  These settings mirror SpiderFoot's global + storage configuration layer and
//  are consumed by OsintEngine (scan orchestration), HttpClient (all outbound
//  HTTP requests), and query.php (result storage).
//
//  Usage:
//    require_once __DIR__ . '/GlobalSettings.php';
//    $timeout = GlobalSettings::getInt('http_timeout', 15);
//    $debug   = GlobalSettings::getBool('debug');
//    $bytes   = GlobalSettings::getInt('max_bytes_per_element', 1024);
// =============================================================================

class GlobalSettings
{
    /** @var array<string,string>|null Per-request settings cache */
    private static ?array $cache = null;
    /** @var array<string,array<int,string>> Per-process TLD runtime cache */
    private static array $runtimeTldCache = [];

    private const DEFAULT_USER_AGENT =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0';

    /** @var array<int,string> Safe fallback TLD set when remote list load fails */
    private const FALLBACK_TLDS = [
        '.com', '.net', '.org', '.io', '.co', '.info', '.biz',
    ];

    /**
     * Compile-time defaults — identical to the migration seed in
     * sql/migration_003_module_settings.sql.  These are the fallback values
     * used when the platform_settings table is empty or the DB is unavailable.
     */
    private static array $defaults = [
        // ── _global settings ──────────────────────────────────────────────
        'debug'                  => 'false',
        'dns_resolver'           => '',
        'http_timeout'           => '15',
        'generic_usernames'      => 'abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,',
        'tld_list_url'           => 'https://publicsuffix.org/list/effective_tld_names.dat',
        'tld_cache_hours'        => '72',
        'max_concurrent_modules' => '3',
        'socks_type'             => '',
        'socks_host'             => '',
        'socks_port'             => '',
        'socks_username'         => '',
        'socks_password'         => '',
        'user_agent'             => self::DEFAULT_USER_AGENT,
        // ── _storage settings ─────────────────────────────────────────────
        'max_bytes_per_element'  => '1024',
    ];

    // =========================================================================
    //  LOAD / RELOAD
    // =========================================================================

    /**
     * Load settings from the database (once per request / process lifetime).
     * Falls back silently to $defaults if the DB is unavailable.
     */
    public static function load(): void
    {
        if (self::$cache !== null) {
            return;
        }

        // Start with compiled-in defaults so we always have a complete set.
        self::$cache = self::$defaults;

        try {
            $rows = DB::query('SELECT setting_key, setting_value FROM platform_settings');
            foreach ($rows as $row) {
                // Only accept non-null values so a NULL doesn't wipe a default.
                if ($row['setting_value'] !== null) {
                    self::$cache[(string)$row['setting_key']] = (string)$row['setting_value'];
                }
            }
        } catch (\Throwable $e) {
            // Log the issue but keep serving defaults.
            error_log('[GlobalSettings] Failed to load platform_settings: ' . $e->getMessage());
        }
    }

    /**
     * Force a reload from the database.
     * Call this after saving new settings via the Settings page so the
     * current request immediately picks up the updated values.
     */
    public static function reload(): void
    {
        self::$cache = null;
        self::$runtimeTldCache = [];
        self::load();
    }

    // =========================================================================
    //  TYPED ACCESSORS
    // =========================================================================

    /**
     * Get a raw string value.
     *
     * @param string $key      Setting key (e.g. 'http_timeout', 'user_agent')
     * @param string $fallback Value returned if the key is completely unknown
     */
    public static function get(string $key, string $fallback = ''): string
    {
        self::load();
        return self::$cache[$key] ?? self::$defaults[$key] ?? $fallback;
    }

    /**
     * Get an integer value cast from the stored string.
     */
    public static function getInt(string $key, int $fallback = 0): int
    {
        return (int)(self::get($key, (string)$fallback));
    }

    /**
     * Get a boolean value.
     * Truthy strings: 'true', '1', 'yes', 'on'.
     */
    public static function getBool(string $key, bool $fallback = false): bool
    {
        $val = strtolower(self::get($key, $fallback ? 'true' : 'false'));
        return in_array($val, ['true', '1', 'yes', 'on'], true);
    }

    /**
     * Get a comma-separated setting as a filtered array of trimmed strings.
     * Empty entries are removed.
     *
     * @return string[]
     */
    public static function getList(string $key): array
    {
        $val = self::get($key);
        if ($val === '') {
            return [];
        }
        $parts = preg_split('/[\r\n,;]+/', $val) ?: [];
        return array_values(
            array_filter(
                array_map('trim', $parts),
                fn($v) => $v !== ''
            )
        );
    }

    /**
     * Return all settings as a key/value map (for diagnostic purposes).
     *
     * @return array<string,string>
     */
    public static function all(): array
    {
        self::load();
        return self::$cache;
    }

    // =========================================================================
    //  CONVENIENCE SHORTCUTS
    // =========================================================================

    /** Whether debug mode is enabled. */
    public static function isDebug(): bool
    {
        return self::getBool('debug', false);
    }

    /** HTTP request timeout in seconds (minimum 1, falls back to 15). */
    public static function httpTimeout(): int
    {
        return max(1, self::getInt('http_timeout', 15));
    }

    /** User-Agent string for outbound HTTP requests. */
    public static function userAgent(): string
    {
        $ua = self::get('user_agent');
        return $ua !== '' ? $ua : self::DEFAULT_USER_AGENT;
    }

    /** Custom DNS resolver IP (empty = use system default). */
    public static function dnsResolver(): string
    {
        return self::get('dns_resolver');
    }

    /** SOCKS proxy type string: '4', '5', 'HTTP', 'TOR', or '' (disabled). */
    public static function socksType(): string
    {
        return self::sanitizeSocksType(self::get('socks_type'));
    }

    /** SOCKS/HTTP proxy host. */
    public static function socksHost(): string
    {
        return self::get('socks_host');
    }

    /** SOCKS/HTTP proxy port. */
    public static function socksPort(): int
    {
        return self::getInt('socks_port', 0);
    }

    /** Maximum number of modules to run concurrently (>= 1). */
    public static function maxConcurrentModules(): int
    {
        return max(1, self::getInt('max_concurrent_modules', 3));
    }

    /**
     * Maximum bytes to store per intelligence element.
     * Returns 0 when unlimited storage is requested.
     */
    public static function maxBytesPerElement(): int
    {
        return max(0, self::getInt('max_bytes_per_element', 1024));
    }

    /**
     * Truncate a string to maxBytesPerElement if needed.
     * Uses multibyte-safe operation and appends an ellipsis when truncated.
     */
    public static function truncate(string $value): string
    {
        $max = self::maxBytesPerElement();
        if ($max === 0 || mb_strlen($value, 'UTF-8') <= $max) {
            return $value;
        }
        return mb_substr($value, 0, $max - 1, 'UTF-8') . "\u{2026}";
    }

    /**
     * Return the configured list of generic usernames.
     *
     * @return array<int,string>
     */
    public static function genericUsernames(): array
    {
        $raw = strtolower(self::get('generic_usernames', self::$defaults['generic_usernames']));
        $parts = preg_split('/[\r\n,;]+/', $raw) ?: [];
        $values = [];
        foreach ($parts as $part) {
            $item = trim($part);
            if ($item !== '') {
                $values[$item] = true;
            }
        }
        return array_keys($values);
    }

    /**
     * Determine whether a username (or email local-part) is generic.
     */
    public static function isGenericUsername(string $value): bool
    {
        $candidate = strtolower(trim($value));
        if ($candidate === '') {
            return false;
        }

        if (str_contains($candidate, '@')) {
            $candidate = (string)strstr($candidate, '@', true);
        }

        if ($candidate === '') {
            return false;
        }

        $generic = array_fill_keys(self::genericUsernames(), true);
        if (isset($generic[$candidate])) {
            return true;
        }

        // Also treat segmented usernames like "admin-team" as generic when
        // one segment matches a configured generic name.
        $segments = preg_split('/[._+\-]+/', $candidate) ?: [];
        foreach ($segments as $segment) {
            $segment = trim($segment);
            if ($segment !== '' && isset($generic[$segment])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Source string for Internet TLD loading.
     * Can be a URL or an inline comma/newline-separated list.
     */
    public static function tldSource(): string
    {
        return trim(self::get('tld_list_url', self::$defaults['tld_list_url']));
    }

    /**
     * Hours to cache downloaded TLD lists.
     */
    public static function tldCacheHours(): int
    {
        return max(1, self::getInt('tld_cache_hours', 72));
    }

    /**
     * Load Internet TLDs as ".com" style suffixes.
     *
     * @return array<int,string>
     */
    public static function internetTlds(): array
    {
        $source = self::tldSource();
        $cacheHours = self::tldCacheHours();
        $cacheKey = hash('sha256', $source . '|' . $cacheHours);

        if (isset(self::$runtimeTldCache[$cacheKey])) {
            return self::$runtimeTldCache[$cacheKey];
        }

        $tlds = [];
        if ($source !== '') {
            if (filter_var($source, FILTER_VALIDATE_URL)) {
                $tlds = self::loadTldListFromSource($source, $cacheHours);
            } else {
                $tlds = self::parseTldListFromString($source);
            }
        }

        if (empty($tlds)) {
            $tlds = self::FALLBACK_TLDS;
        }

        self::$runtimeTldCache[$cacheKey] = $tlds;
        return $tlds;
    }

    /**
     * Normalize SOCKS type values to accepted values.
     */
    public static function sanitizeSocksType(string $type): string
    {
        $normalized = strtoupper(trim($type));
        if ($normalized === '') {
            return '';
        }
        if (in_array($normalized, ['4', '5', 'HTTP', 'TOR'], true)) {
            return $normalized;
        }
        return '';
    }

    /**
     * @return array<int,string>
     */
    private static function loadTldListFromSource(string $url, int $cacheHours): array
    {
        $cacheFile = rtrim(sys_get_temp_dir(), '\\/') . DIRECTORY_SEPARATOR
            . 'cti_tld_cache_' . md5($url) . '.json';
        $maxAgeSeconds = max(1, $cacheHours) * 3600;

        if (is_file($cacheFile) && (time() - (int)@filemtime($cacheFile)) < $maxAgeSeconds) {
            $cached = @file_get_contents($cacheFile);
            if ($cached !== false) {
                $decoded = json_decode($cached, true);
                if (is_array($decoded) && !empty($decoded)) {
                    return array_values(array_filter(array_map('strval', $decoded)));
                }
            }
        }

        $context = stream_context_create([
            'http' => [
                'timeout' => 12,
                'user_agent' => self::DEFAULT_USER_AGENT,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $raw = @file_get_contents($url, false, $context);
        if ($raw === false) {
            // Soft-fail to stale cache if available.
            if (is_file($cacheFile)) {
                $cached = @file_get_contents($cacheFile);
                if ($cached !== false) {
                    $decoded = json_decode($cached, true);
                    if (is_array($decoded) && !empty($decoded)) {
                        return array_values(array_filter(array_map('strval', $decoded)));
                    }
                }
            }
            return [];
        }

        $parsed = self::parseTldListFromString($raw);
        if (!empty($parsed)) {
            @file_put_contents(
                $cacheFile,
                json_encode($parsed, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
            );
        }

        return $parsed;
    }

    /**
     * Parse either PSL/plaintext content or comma/newline-delimited TLD values.
     *
     * @return array<int,string>
     */
    private static function parseTldListFromString(string $value): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $value) ?: [];
        if (count($lines) <= 1 && str_contains($value, ',')) {
            $lines = explode(',', $value);
        }

        $seen = [];
        $out = [];
        foreach ($lines as $line) {
            $candidate = trim((string)$line);
            if ($candidate === '') {
                continue;
            }

            if (str_starts_with($candidate, '#') || str_starts_with($candidate, '//')) {
                continue;
            }

            if (($spacePos = strpos($candidate, ' ')) !== false) {
                $candidate = substr($candidate, 0, $spacePos);
            }

            if (str_starts_with($candidate, '!')) {
                $candidate = substr($candidate, 1);
            }
            if (str_starts_with($candidate, '*.')) {
                $candidate = substr($candidate, 2);
            }

            $normalized = self::normalizeTldEntry($candidate);
            if ($normalized === null || isset($seen[$normalized])) {
                continue;
            }

            $seen[$normalized] = true;
            $out[] = $normalized;

            // Keep the list bounded for fast scan-time lookups.
            if (count($out) >= 1000) {
                break;
            }
        }

        return $out;
    }

    private static function normalizeTldEntry(string $entry): ?string
    {
        $entry = strtolower(trim($entry));
        $entry = ltrim($entry, '.');
        if ($entry === '') {
            return null;
        }

        if (!preg_match('/^[a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})*$/i', $entry)) {
            return null;
        }

        $labels = explode('.', $entry);
        $top = end($labels);
        if (!is_string($top) || $top === '') {
            return null;
        }

        return '.' . $top;
    }
}
