<?php
// =============================================================================
//  CTI — SHARED HTTP CLIENT
//  php/HttpClient.php
//
//  cURL wrapper with timeout, retry, and structured error handling.
//  Used by all OSINT module handlers for external API calls.
//
//  Global settings (timeout, User-Agent, proxy, DNS resolver) are injected
//  by OsintEngine via HttpClient::applyGlobalSettings() before any module
//  runs.  Individual module calls may still pass an explicit $timeout to
//  override the global value for that specific request.
// =============================================================================

class HttpClient
{
    // =========================================================================
    //  GLOBAL SETTINGS (pushed by OsintEngine via applyGlobalSettings())
    // =========================================================================

    /** Resolved HTTP timeout in seconds. 0 = use DEFAULT_TIMEOUT. */
    private static int    $globalTimeout   = 0;
    /** User-Agent for all outbound requests. */
    private static string $globalUserAgent = self::DEFAULT_USER_AGENT;
    /** Cached User-Agent pools for @file or URL list sources. */
    private static array  $userAgentPools  = [];
    /** Custom DNS resolver IP (empty = system default). */
    private static string $globalDnsServer = '';
    /** Proxy type: '4' | '5' | 'HTTP' | 'TOR' | '' */
    private static string $globalProxyType = '';
    /** Proxy host (IP or hostname). */
    private static string $globalProxyHost = '';
    /** Proxy port. */
    private static int    $globalProxyPort = 0;
    /** Proxy credentials — username. */
    private static string $globalProxyUser = '';
    /** Proxy credentials — password. */
    private static string $globalProxyPass = '';

    /** Default fallback timeout when no global setting has been applied. */
    private const DEFAULT_TIMEOUT = 15;
    /** Default fallback User-Agent when no setting is available. */
    private const DEFAULT_USER_AGENT =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0';

    // =========================================================================
    //  EVIDENCE COLLECTION (Parity System)
    // =========================================================================

    /**
     * Evidence callback — when set, every request/response pair is forwarded
     * to the RawEvidenceStore for audit and replay purposes.
     * Signature: function(string $method, string $url, array $headers,
     *            $body, int $status, string $responseBody, int $elapsedMs,
     *            ?string $error): ?int
     * @var callable|null
     */
    private static $evidenceCallback = null;

    /** Module slug context for evidence tagging (set before module execution). */
    private static string $currentModuleSlug = '';

    /** Enrichment pass context for evidence tagging. */
    private static int $currentEnrichmentPass = 0;

    /** Source reference context for evidence tagging. */
    private static string $currentSourceRef = 'ROOT';

    /**
     * Set the evidence collection callback.
     * Pass null to disable evidence collection.
     */
    public static function setEvidenceCallback(?callable $callback): void
    {
        self::$evidenceCallback = $callback;
    }

    /**
     * Set the current module context for evidence tagging.
     * Called by OsintEngine before dispatching each module.
     */
    public static function setModuleContext(string $slug, int $enrichmentPass = 0, string $sourceRef = 'ROOT'): void
    {
        self::$currentModuleSlug = $slug;
        self::$currentEnrichmentPass = $enrichmentPass;
        self::$currentSourceRef = $sourceRef;
    }

    /** Get the current DNS resolver being used. */
    public static function getDnsResolver(): string
    {
        return self::$globalDnsServer;
    }

    /**
     * Resolve the User-Agent that should be used for this request.
     * Exposed for modules that use native cURL multi handles.
     */
    public static function currentUserAgentForRequest(): string
    {
        return self::resolveUserAgentForRequest();
    }

    /**
     * Push GlobalSettings values into HttpClient's static config.
     * Called once per scan by OsintEngine before dispatching any module.
     * HttpClient itself does NOT depend on GlobalSettings to keep the
     * dependency direction clean.
     */
    public static function applyGlobalSettings(): void
    {
        if (!class_exists('GlobalSettings')) {
            return;
        }

        self::$globalTimeout   = GlobalSettings::httpTimeout();
        self::$globalUserAgent = trim(GlobalSettings::userAgent());
        if (self::$globalUserAgent === '') {
            self::$globalUserAgent = self::DEFAULT_USER_AGENT;
        }
        self::$globalDnsServer = GlobalSettings::dnsResolver();
        self::$globalProxyType = GlobalSettings::socksType();
        self::$globalProxyHost = GlobalSettings::socksHost();
        self::$globalProxyPort = GlobalSettings::socksPort();
        self::$globalProxyUser = class_exists('GlobalSettings') ? GlobalSettings::get('socks_username') : '';
        self::$globalProxyPass = class_exists('GlobalSettings') ? GlobalSettings::get('socks_password') : '';
    }

    // =========================================================================
    //  PUBLIC REQUEST API
    // =========================================================================

    /**
     * Perform a GET request.
     *
     * @param  string $url      Full URL to request
     * @param  array  $headers  Associative array of headers (e.g., ['X-Api-Key' => '...'])
     * @param  int    $timeout  Explicit timeout override (0 = use global / default)
     * @param  int    $retries  Number of retries on transient failure (default: 1)
     * @return array  ['status' => int, 'body' => string, 'json' => mixed|null, 'elapsed_ms' => int, 'error' => ?string]
     */
    public static function get(string $url, array $headers = [], int $timeout = 0, int $retries = 1): array
    {
        return self::request('GET', $url, $headers, null, $timeout, $retries);
    }

    /**
     * Perform a POST request.
     *
     * @param  string      $url
     * @param  array       $headers
     * @param  mixed       $body     String body or array (will be JSON-encoded)
     * @param  int         $timeout  Explicit timeout override (0 = use global / default)
     * @param  int         $retries
     * @return array
     */
    public static function post(string $url, array $headers = [], $body = null, int $timeout = 0, int $retries = 1): array
    {
        return self::request('POST', $url, $headers, $body, $timeout, $retries);
    }

    // =========================================================================
    //  CORE REQUEST
    // =========================================================================

    /**
     * Core request method.
     */
    private static function request(string $method, string $url, array $headers, $body, int $timeout, int $retries): array
    {
        // Resolve effective timeout: explicit > global > compile-time default
        if ($timeout <= 0) {
            $timeout = self::$globalTimeout > 0 ? self::$globalTimeout : self::DEFAULT_TIMEOUT;
        }

        $attempt = 0;
        $lastResult = null;

        while ($attempt <= $retries) {
            $attempt++;
            $startTime = microtime(true);
            $userAgent = self::resolveUserAgentForRequest();

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => $userAgent,
            ]);

            // ── CA bundle (XAMPP / environments without system CA) ─────────
            $caBundle = ini_get('curl.cainfo');
            if (!$caBundle) {
                // Common XAMPP locations for the CA bundle
                $candidates = [
                    dirname(PHP_BINARY) . '/../apache/bin/curl-ca-bundle.crt',
                    dirname(PHP_BINARY) . '/extras/ssl/cacert.pem',
                    'C:/xampp/apache/bin/curl-ca-bundle.crt',
                ];
                foreach ($candidates as $path) {
                    if (file_exists($path)) {
                        $caBundle = realpath($path);
                        break;
                    }
                }
            }
            if ($caBundle && file_exists($caBundle)) {
                curl_setopt($ch, CURLOPT_CAINFO, $caBundle);
            }

            // ── DNS resolver override (libcurl ≥ 7.24) ───────────────────
            if (self::$globalDnsServer !== '') {
                curl_setopt($ch, CURLOPT_DNS_SERVERS, self::$globalDnsServer);
            }

            // ── Proxy (SOCKS 4/5, HTTP, TOR) ─────────────────────────────
            if (self::$globalProxyHost !== '' && self::$globalProxyPort > 0) {
                $proxyUrl = self::$globalProxyHost . ':' . self::$globalProxyPort;
                curl_setopt($ch, CURLOPT_PROXY, $proxyUrl);

                $proxyType = self::$globalProxyType;

                if ($proxyType === 'TOR' || $proxyType === '5') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                } elseif ($proxyType === '4') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4);
                } elseif ($proxyType === 'HTTP') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                } else {
                    // Default to SOCKS5 for unrecognised types
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                }

                if (self::$globalProxyUser !== '') {
                    curl_setopt(
                        $ch,
                        CURLOPT_PROXYUSERPWD,
                        self::$globalProxyUser . ':' . self::$globalProxyPass
                    );
                }
            }

            // ── Build header array for cURL ───────────────────────────────
            $curlHeaders = [];
            foreach ($headers as $key => $val) {
                $curlHeaders[] = "{$key}: {$val}";
            }

            if ($method === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                if ($body !== null) {
                    if (is_array($body)) {
                        $body = json_encode($body);
                        $curlHeaders[] = 'Content-Type: application/json';
                    }
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                }
            }

            if (!empty($curlHeaders)) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaders);
            }

            $responseBody = curl_exec($ch);
            $elapsedMs    = (int)((microtime(true) - $startTime) * 1000);
            $httpCode     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError    = curl_error($ch);
            $curlErrno    = curl_errno($ch);
            curl_close($ch);

            // Build result
            $result = [
                'status'     => $httpCode,
                'body'       => $responseBody ?: '',
                'json'       => null,
                'elapsed_ms' => $elapsedMs,
                'error'      => null,
            ];

            // cURL-level error (timeout, DNS failure, connection refused)
            if ($curlErrno !== 0) {
                $result['error'] = "cURL error ({$curlErrno}): {$curlError}";
                $result['status'] = 0;
                $lastResult = $result;

                // Do NOT retry on timeout — an API that timed out once will almost
                // certainly time out again and would double the total wait per module.
                // Only retry on transient connection-level errors (DNS, TCP connect).
                if ($attempt <= $retries
                    && $curlErrno !== CURLE_OPERATION_TIMEDOUT
                    && in_array($curlErrno, [CURLE_COULDNT_CONNECT, CURLE_GOT_NOTHING], true)) {
                    usleep(250000); // 250ms backoff (was 500ms)
                    continue;
                }
                self::recordEvidence($method, $url, $headers, $body, $result);
                return $result;
            }

            // Try to parse JSON
            if ($responseBody) {
                $decoded = json_decode($responseBody, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $result['json'] = $decoded;
                }
            }

            // Retry on 429 (rate limited) or 5xx server errors
            if ($attempt <= $retries && ($httpCode === 429 || $httpCode >= 500)) {
                $lastResult = $result;
                usleep(1000000); // 1s backoff
                continue;
            }

            self::recordEvidence($method, $url, $headers, $body, $result);
            return $result;
        }

        $fallback = $lastResult ?? [
            'status' => 0,
            'body' => '',
            'json' => null,
            'elapsed_ms' => 0,
            'error' => 'Max retries exceeded.',
        ];
        self::recordEvidence($method, $url, $headers, $body, $fallback);
        return $fallback;
    }

    // =========================================================================
    //  USER-AGENT RESOLUTION
    // =========================================================================

    /**
     * Resolve User-Agent according to global setting:
     *   - "Mozilla/..."    => fixed User-Agent
     *   - "@C:\\agents.txt" => random line from local file per request
     *   - "https://..."    => random line from URL content per request
     */
    private static function resolveUserAgentForRequest(): string
    {
        $configured = trim(self::$globalUserAgent);
        if ($configured === '') {
            return self::DEFAULT_USER_AGENT;
        }

        $source = '';
        if (str_starts_with($configured, '@')) {
            $source = trim(substr($configured, 1));
        } elseif (filter_var($configured, FILTER_VALIDATE_URL)) {
            $source = $configured;
        }

        if ($source === '') {
            return $configured;
        }

        $pool = self::loadUserAgentPool($source);
        if (empty($pool)) {
            return self::DEFAULT_USER_AGENT;
        }

        try {
            $index = random_int(0, count($pool) - 1);
        } catch (\Throwable $e) {
            $index = array_rand($pool);
        }

        $selected = trim((string)($pool[$index] ?? ''));
        return $selected !== '' ? $selected : self::DEFAULT_USER_AGENT;
    }

    /**
     * Load and cache a User-Agent pool from a local file path or URL.
     *
     * @return array<int,string>
     */
    private static function loadUserAgentPool(string $source): array
    {
        $key = strtolower(trim($source));
        if ($key === '') {
            return [];
        }

        if (array_key_exists($key, self::$userAgentPools)) {
            return self::$userAgentPools[$key];
        }

        $content = self::readUserAgentSource($source);
        $pool = $content === null ? [] : self::parseUserAgentLines($content);
        self::$userAgentPools[$key] = $pool;

        return $pool;
    }

    private static function readUserAgentSource(string $source): ?string
    {
        $source = trim($source);
        if ($source === '') {
            return null;
        }

        if (filter_var($source, FILTER_VALIDATE_URL)) {
            $context = stream_context_create([
                'http' => [
                    'timeout' => max(3, min(20, self::$globalTimeout > 0 ? self::$globalTimeout : 12)),
                    'user_agent' => self::DEFAULT_USER_AGENT,
                ],
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                ],
            ]);
            $data = @file_get_contents($source, false, $context);
            if ($data === false) {
                error_log('[HttpClient] Failed to load User-Agent list from URL: ' . $source);
                return null;
            }
            return $data;
        }

        $path = self::resolveLocalPath($source);
        if ($path === null || !is_file($path)) {
            error_log('[HttpClient] User-Agent list file not found: ' . $source);
            return null;
        }

        $data = @file_get_contents($path);
        if ($data === false) {
            error_log('[HttpClient] Failed to read User-Agent list file: ' . $path);
            return null;
        }
        return $data;
    }

    /**
     * Resolve relative local paths against likely project roots.
     */
    private static function resolveLocalPath(string $path): ?string
    {
        if ($path === '') {
            return null;
        }

        // Absolute Windows path (e.g. C:\path\file.txt) or Unix absolute path.
        if (preg_match('/^[A-Za-z]:(?:\\\\|\\/)/', $path) || str_starts_with($path, '/') || str_starts_with($path, '\\\\')) {
            return $path;
        }

        $candidates = [
            $path,
            dirname(__DIR__) . DIRECTORY_SEPARATOR . $path,
            __DIR__ . DIRECTORY_SEPARATOR . $path,
        ];

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Parse a newline-delimited User-Agent list.
     *
     * @return array<int,string>
     */
    private static function parseUserAgentLines(string $content): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $content) ?: [];
        $pool = [];
        foreach ($lines as $line) {
            $ua = trim((string)$line);
            if ($ua === '') {
                continue;
            }

            // Ignore comment lines in shared lists.
            if (str_starts_with($ua, '#') || str_starts_with($ua, '//') || str_starts_with($ua, ';')) {
                continue;
            }

            $pool[] = $ua;
            if (count($pool) >= 10000) {
                break;
            }
        }

        return $pool;
    }

    // =========================================================================
    //  EVIDENCE RECORDING (Parity System)
    // =========================================================================

    /**
     * Forward the request/response pair to the evidence callback if set.
     */
    private static function recordEvidence(
        string $method,
        string $url,
        array  $headers,
        $body,
        array  $result
    ): void {
        if (self::$evidenceCallback === null) {
            return;
        }

        try {
            $params = null;
            if ($body !== null) {
                $params = is_array($body) ? $body : ['_raw' => $body];
            }

            (self::$evidenceCallback)(
                self::$currentModuleSlug,
                $method,
                $url,
                $params,
                $headers,
                $result['status'] ?? 0,
                $result['body'] ?? '',
                $result['elapsed_ms'] ?? 0,
                $result['error'] ?? null,
                null,  // pagination cursor
                null,  // page number
                self::$currentEnrichmentPass,
                self::$currentSourceRef,
                self::$globalDnsServer ?: null,
                null   // dns response
            );
        } catch (\Throwable $e) {
            error_log('[HttpClient] Evidence recording failed: ' . $e->getMessage());
        }
    }
}
