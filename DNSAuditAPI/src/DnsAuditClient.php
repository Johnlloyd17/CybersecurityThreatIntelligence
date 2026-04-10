<?php
/**
 * DNSAudit API Client
 *
 * Integrates with the real DNSAudit.io API (https://dnsaudit.io/docs/api).
 *
 * Endpoints:
 *   GET /v1/scan?domain=         - Run a full DNS security scan
 *   GET /export/json/:domain     - Export scan results as JSON
 *   GET /v1/scan-history?limit=  - Retrieve recent scan history
 *   GET /export/pdf/:domain      - Download PDF report (used in docs examples)
 *
 * Auth: X-API-Key header (early access, request at https://dnsaudit.io/api)
 * Rate limits: 20 scans/day, 10 req/min
 */
class DnsAuditClient
{
    private string $baseUrl;
    private string $apiKey;
    private int $timeout;
    private int $maxRetries;
    private string $encryptionMethod;
    private string $encryptionKey;
    private ?PDO $db;

    public function __construct(array $config, ?PDO $db = null)
    {
        $api = $config['api'] ?? [];
        $this->baseUrl = rtrim($api['base_url'] ?? 'https://dnsaudit.io/api', '/');
        $this->apiKey = $api['api_key'] ?? '';
        $this->timeout = (int) ($api['timeout'] ?? 30);
        $this->maxRetries = (int) ($api['max_retries'] ?? 2);
        $this->encryptionMethod = $config['encryption']['method'] ?? 'aes-256-cbc';
        $this->encryptionKey = $config['encryption']['key'] ?? '';
        $this->db = $db;
    }

    public function isConfigured(): bool
    {
        return !empty($this->apiKey) && $this->apiKey !== 'YOUR_DNSAUDIT_API_KEY';
    }

    // =====================================================================
    // API Endpoints
    // =====================================================================

    /**
     * GET /v1/scan?domain=example.com
     *
     * Runs a full DNS security scan (26+ checks: DNSSEC, SPF, DKIM, DMARC,
     * zone transfer, vulnerability detection). Returns security score, grade,
     * and detailed findings with severity.
     */
    public function scan(string $domain): array
    {
        $domain = $this->sanitizeDomain($domain);
        if ($domain === '') {
            throw new InvalidArgumentException('Invalid domain');
        }

        $startTime = microtime(true);
        $response = $this->request('GET', '/v1/scan', ['domain' => $domain]);
        $elapsedMs = (int) ((microtime(true) - $startTime) * 1000);

        $this->logApiCall('scan', $domain, $response['http_code'], $response['data'], $elapsedMs);

        if ($response['http_code'] === 429) {
            throw new RuntimeException('Rate limit exceeded. ' . $this->extractRateLimitMessage($response['data']));
        }
        if ($response['http_code'] >= 400) {
            throw new RuntimeException(
                "DNSAudit API error: HTTP {$response['http_code']}. " . $this->extractErrorMessage($response['data'])
            );
        }

        return $response['data'];
    }

    /**
     * GET /export/json/:domain
     *
     * Retrieves full scan results as structured JSON for integration
     * into dashboards or compliance reports.
     */
    public function export(string $domain): array
    {
        $domain = $this->sanitizeDomain($domain);
        if ($domain === '') {
            throw new InvalidArgumentException('Invalid domain');
        }

        $startTime = microtime(true);
        $response = $this->request('GET', '/export/json/' . urlencode($domain));
        $elapsedMs = (int) ((microtime(true) - $startTime) * 1000);

        $this->logApiCall('export', $domain, $response['http_code'], $response['data'], $elapsedMs);

        if ($response['http_code'] >= 400) {
            throw new RuntimeException(
                "DNSAudit export error: HTTP {$response['http_code']}. " . $this->extractErrorMessage($response['data'])
            );
        }

        return $response['data'];
    }

    /**
     * GET /export/pdf/:domain
     *
     * Retrieves a PDF report. The docs examples use format=detailed.
     *
     * @return array{content:string,content_type:string,filename:string}
     */
    public function exportPdf(string $domain, string $format = 'detailed'): array
    {
        $domain = $this->sanitizeDomain($domain);
        if ($domain === '') {
            throw new InvalidArgumentException('Invalid domain');
        }

        $params = [];
        $format = trim($format);
        if ($format !== '') {
            $params['format'] = $format;
        }

        $startTime = microtime(true);
        $response = $this->requestRaw('GET', '/export/pdf/' . urlencode($domain), $params, 'application/pdf');
        $elapsedMs = (int) ((microtime(true) - $startTime) * 1000);

        $this->logApiCall('export_pdf', $domain, $response['http_code'], [], $elapsedMs);

        if ($response['http_code'] >= 400) {
            $decoded = json_decode($response['body'], true);
            $message = is_array($decoded)
                ? $this->extractErrorMessage($decoded)
                : substr(trim($response['body']), 0, 200);

            throw new RuntimeException(
                "DNSAudit PDF export error: HTTP {$response['http_code']}. " . ($message !== '' ? $message : 'Unknown error')
            );
        }

        return [
            'content' => $response['body'],
            'content_type' => $response['content_type'] ?: 'application/pdf',
            'filename' => $domain . '-dns-report.pdf',
        ];
    }

    /**
     * GET /v1/scan-history?limit=N
     *
     * Returns recent scan history. Default limit 10, max 100.
     */
    public function scanHistory(int $limit = 10): array
    {
        $limit = max(1, min(100, $limit));

        $startTime = microtime(true);
        $response = $this->request('GET', '/v1/scan-history', ['limit' => $limit]);
        $elapsedMs = (int) ((microtime(true) - $startTime) * 1000);

        $this->logApiCall('history', null, $response['http_code'], $response['data'], $elapsedMs);

        if ($response['http_code'] >= 400) {
            throw new RuntimeException(
                "DNSAudit history error: HTTP {$response['http_code']}. " . $this->extractErrorMessage($response['data'])
            );
        }

        return $response['data'];
    }

    // =====================================================================
    // Response Normalization
    // =====================================================================

    /**
     * Extract scan summary data from a /v1/scan response.
     * Returns a row ready for the scan_summaries table.
     */
    public function extractSummary(array $scanResponse, ?int $assetId, string $domain): array
    {
        $findings = $this->extractFindings($scanResponse);
        $critical = 0;
        $warning = 0;
        $info = 0;

        foreach ($findings as $f) {
            $rowData = is_array($f) ? $f : ['value' => $f];
            $severity = $this->normalizeSeverity($rowData['severity'] ?? $rowData['type'] ?? 'info');
            if ($severity === 'critical') {
                $critical++;
            } elseif ($severity === 'warning') {
                $warning++;
            } else {
                $info++;
            }
        }

        return [
            'asset_id'        => $assetId,
            'domain'          => $domain,
            'grade'           => $this->extractGrade($scanResponse),
            'score'           => $this->extractScore($scanResponse),
            'subdomain_count' => $this->toNullableInt(
                $scanResponse['subdomain_count']
                    ?? $scanResponse['data']['subdomain_count']
                    ?? $scanResponse['subdomains']['total']
                    ?? $scanResponse['data']['subdomains']['total']
                    ?? null
            ),
            'total_findings'  => count($findings),
            'critical_count'  => $critical,
            'warning_count'   => $warning,
            'info_count'      => $info,
            'scanned_at'      => date('Y-m-d H:i:s'),
            'raw_response'    => $this->encryptPayload($scanResponse),
        ];
    }

    /**
     * Extract individual findings from a /v1/scan response.
     * Returns rows ready for the scan_findings table.
     */
    public function normalizeFindings(array $scanResponse, ?int $summaryId, ?int $assetId, string $domain): array
    {
        $findings = $this->extractFindings($scanResponse);
        $rows = [];
        $scannedAt = date('Y-m-d H:i:s');

        foreach ($findings as $finding) {
            $rowData = is_array($finding) ? $finding : ['value' => $finding];

            $severity = $this->normalizeSeverity($rowData['severity'] ?? $rowData['type'] ?? 'info');
            $title = $this->toNullableString($rowData['title'] ?? $rowData['name'] ?? $rowData['issue'] ?? null, 255);
            $description = $this->toNullableString($rowData['description'] ?? $rowData['details'] ?? $rowData['message'] ?? null);
            $category = $this->toNullableString($rowData['category'] ?? $rowData['group'] ?? null, 100);
            $recommendation = $this->toNullableString($rowData['recommendation'] ?? $rowData['fix'] ?? $rowData['solution'] ?? null);

            $hashInput = implode('|', [
                strtolower($domain),
                $severity,
                strtolower((string) ($title ?? '')),
                substr($scannedAt, 0, 10), // dedup per day
            ]);

            $rows[] = [
                'result_hash'    => hash('sha256', $hashInput),
                'summary_id'    => $summaryId,
                'asset_id'       => $assetId,
                'domain'         => $domain,
                'severity'       => $severity,
                'category'       => $category,
                'title'          => $title,
                'description'    => $description,
                'recommendation' => $recommendation,
                'status'         => 'open',
                'scanned_at'     => $scannedAt,
                'raw_payload'    => $this->encryptPayload($rowData),
            ];
        }

        return $rows;
    }

    // =====================================================================
    // Internal HTTP
    // =====================================================================

    private function request(string $method, string $path, array $params = []): array
    {
        $url = $this->baseUrl . $path;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $headers = [
            'Accept: application/json',
            'X-API-Key: ' . $this->apiKey,
        ];

        return $this->curlRequest($method, $url, $headers);
    }

    private function requestRaw(string $method, string $path, array $params = [], string $accept = 'application/octet-stream'): array
    {
        $url = $this->baseUrl . $path;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $headers = [
            'Accept: ' . $accept,
            'X-API-Key: ' . $this->apiKey,
        ];

        return $this->curlRequestRaw($method, $url, $headers);
    }

    private function curlRequest(string $method, string $url, array $headers): array
    {
        $attempt = 0;
        while ($attempt <= $this->maxRetries) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $this->timeout,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_CUSTOMREQUEST  => $method,
            ]);

            $body = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            if ($body === false || $httpCode === 0) {
                $attempt++;
                if ($attempt <= $this->maxRetries) {
                    sleep(min(2 ** $attempt, 8));
                    continue;
                }
                throw new RuntimeException("cURL error after retries: {$curlError}");
            }

            // Don't retry on rate limit - surface immediately.
            if ($httpCode === 429) {
                $data = json_decode($body, true);
                return ['http_code' => $httpCode, 'data' => is_array($data) ? $data : ['raw' => $body]];
            }

            // Retry on 5xx server errors
            if ($httpCode >= 500 && $attempt < $this->maxRetries) {
                $attempt++;
                sleep(min(2 ** $attempt, 8));
                continue;
            }

            $data = json_decode($body, true);
            if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
                $data = ['raw' => $body];
            }

            return ['http_code' => $httpCode, 'data' => $data];
        }

        throw new RuntimeException("Request failed after {$this->maxRetries} retries");
    }

    private function curlRequestRaw(string $method, string $url, array $headers): array
    {
        $attempt = 0;
        while ($attempt <= $this->maxRetries) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $this->timeout,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_CUSTOMREQUEST  => $method,
            ]);

            $body = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $contentType = (string) (curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: '');
            $curlError = curl_error($ch);
            curl_close($ch);

            if ($body === false || $httpCode === 0) {
                $attempt++;
                if ($attempt <= $this->maxRetries) {
                    sleep(min(2 ** $attempt, 8));
                    continue;
                }
                throw new RuntimeException("cURL error after retries: {$curlError}");
            }

            if ($httpCode >= 500 && $attempt < $this->maxRetries) {
                $attempt++;
                sleep(min(2 ** $attempt, 8));
                continue;
            }

            return [
                'http_code' => $httpCode,
                'body' => is_string($body) ? $body : '',
                'content_type' => $contentType,
            ];
        }

        throw new RuntimeException("Raw request failed after {$this->maxRetries} retries");
    }

    // =====================================================================
    // Response Parsing Helpers
    // =====================================================================

    /**
     * Extract the findings array from various possible response structures.
     * DNSAudit may wrap findings under different keys.
     */
    private function extractFindings(array $response): array
    {
        // Try common keys where findings might live
        foreach (['findings', 'issues', 'data.findings', 'data.issues'] as $key) {
            $value = $this->getNestedValue($response, $key);
            if (is_array($value) && !empty($value) && $this->isList($value)) {
                return $value;
            }
        }

        foreach (['results', 'data.results'] as $key) {
            $value = $this->getNestedValue($response, $key);
            if (!is_array($value) || $value === []) {
                continue;
            }

            if ($this->isList($value)) {
                return $value;
            }

            $mapped = $this->mapResultsObjectToFindings($value);
            if ($mapped !== []) {
                return $mapped;
            }
        }

        // If response.data is a list of findings directly
        if (isset($response['data']) && is_array($response['data']) && $this->isList($response['data'])) {
            return $response['data'];
        }

        return [];
    }

    private function extractScore(array $response): ?int
    {
        $score = $response['score']
            ?? $response['securityScore']
            ?? $response['data']['score']
            ?? $response['data']['securityScore']
            ?? null;
        return $this->toNullableInt($score);
    }

    private function extractGrade(array $response): ?string
    {
        $candidates = [
            $response['grade'] ?? null,
            $response['data']['grade'] ?? null,
            $response['summary']['grade'] ?? null,
            $response['summary']['overallGrade'] ?? null,
        ];

        foreach ($candidates as $candidate) {
            $grade = $this->toGradeString($candidate);
            if ($grade !== null) {
                return $grade;
            }
        }

        return null;
    }

    private function toGradeString(mixed $value): ?string
    {
        if (is_array($value)) {
            foreach (['grade', 'letter', 'value', 'current', 'overall', 'overallGrade'] as $key) {
                if (!array_key_exists($key, $value)) {
                    continue;
                }

                $fromKey = $this->toGradeString($value[$key]);
                if ($fromKey !== null) {
                    return $fromKey;
                }
            }
            return null;
        }

        $text = $this->toNullableString($value);
        if ($text === null) {
            return null;
        }

        $upper = strtoupper($text);
        if (preg_match('/\b([A-F][+-]?)\b/', $upper, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    private function normalizeSeverity(mixed $raw): string
    {
        $raw = strtolower(trim((string) $raw));
        return match ($raw) {
            'critical', 'high', 'danger', 'error', 'fail', 'failed' => 'critical',
            'warning', 'medium', 'warn'            => 'warning',
            default                                 => 'info',
        };
    }

    private function mapResultsObjectToFindings(array $results): array
    {
        $findings = [];

        foreach ($results as $checkName => $payload) {
            if (!is_string($checkName) || trim($checkName) === '') {
                continue;
            }

            if (!is_array($payload)) {
                $valueText = $this->toNullableString($payload);
                if ($valueText === null) {
                    continue;
                }

                $findings[] = [
                    'severity' => 'info',
                    'category' => $this->humanizeKey($checkName),
                    'title' => $this->humanizeKey($checkName),
                    'description' => $valueText,
                ];
                continue;
            }

            if ($this->isList($payload)) {
                foreach ($payload as $listItem) {
                    $item = is_array($listItem) ? $listItem : ['value' => $listItem];
                    $item['category'] = $item['category'] ?? $this->humanizeKey($checkName);
                    $item['title'] = $item['title'] ?? $item['check'] ?? $this->humanizeKey($checkName);
                    $findings[] = $item;
                }
                continue;
            }

            $findings[] = [
                'severity' => $payload['severity'] ?? $payload['status'] ?? 'info',
                'category' => $payload['category'] ?? $this->humanizeKey($checkName),
                'title' => $payload['title'] ?? $payload['check'] ?? $this->humanizeKey($checkName),
                'description' => $payload['description'] ?? $payload['details'] ?? $payload['message'] ?? $payload['record'] ?? null,
                'recommendation' => $payload['recommendation'] ?? $payload['fix'] ?? $payload['solution'] ?? null,
            ];
        }

        return $findings;
    }

    private function humanizeKey(string $key): string
    {
        $normalized = preg_replace('/(?<!^)[A-Z]/', ' $0', $key) ?? $key;
        $normalized = str_replace(['_', '-', '.'], ' ', $normalized);
        $normalized = preg_replace('/\s+/', ' ', $normalized) ?? $normalized;
        return ucwords(trim($normalized));
    }

    private function getNestedValue(array $data, string $dotPath): mixed
    {
        $keys = explode('.', $dotPath);
        $current = $data;
        foreach ($keys as $key) {
            if (!is_array($current) || !array_key_exists($key, $current)) {
                return null;
            }
            $current = $current[$key];
        }
        return $current;
    }

    private function extractErrorMessage(array $data): string
    {
        return $data['message'] ?? $data['error'] ?? $data['detail'] ?? json_encode($data);
    }

    private function extractRateLimitMessage(array $data): string
    {
        $msg = $data['message'] ?? 'Rate limit exceeded.';
        if (isset($data['retry_after'])) {
            $msg .= " Retry after {$data['retry_after']} seconds.";
        }
        return $msg;
    }

    private function isList(array $array): bool
    {
        if ($array === []) {
            return true;
        }
        return array_keys($array) === range(0, count($array) - 1);
    }

    // =====================================================================
    // Domain Sanitization
    // =====================================================================

    private function sanitizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('#^https?://#', '', $domain);
        $domain = rtrim($domain, '/.');
        $domain = preg_replace('#/.*$#', '', $domain);
        if (!preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/', $domain)) {
            return '';
        }
        return $domain;
    }

    // =====================================================================
    // Payload Encryption
    // =====================================================================

    public function encryptPayload(array $item): string
    {
        $json = json_encode($item) ?: '{}';

        $keyBin = $this->getEncryptionKeyBinary();
        if ($keyBin === null) {
            return base64_encode($json);
        }

        $ivLength = openssl_cipher_iv_length($this->encryptionMethod);
        if (!is_int($ivLength) || $ivLength <= 0) {
            return base64_encode($json);
        }

        $iv = openssl_random_pseudo_bytes($ivLength);
        if ($iv === false) {
            return base64_encode($json);
        }

        $cipher = openssl_encrypt($json, $this->encryptionMethod, $keyBin, 0, $iv);
        if ($cipher === false) {
            return base64_encode($json);
        }

        return base64_encode($iv . '::' . $cipher);
    }

    public function decryptPayload(string $encrypted): ?array
    {
        $decoded = base64_decode($encrypted, true);
        if ($decoded === false) {
            return null;
        }

        $keyBin = $this->getEncryptionKeyBinary();
        if ($keyBin === null) {
            $tmp = json_decode($decoded, true);
            return is_array($tmp) ? $tmp : null;
        }

        $parts = explode('::', $decoded, 2);
        if (count($parts) !== 2) {
            return null;
        }

        $plain = openssl_decrypt($parts[1], $this->encryptionMethod, $keyBin, 0, $parts[0]);
        if ($plain === false) {
            return null;
        }

        $tmp = json_decode($plain, true);
        return is_array($tmp) ? $tmp : null;
    }

    private function toNullableInt(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }
        if (is_array($value)) {
            foreach (['total', 'count', 'value', 'score', 'securityScore'] as $key) {
                if (array_key_exists($key, $value)) {
                    $nested = $this->toNullableInt($value[$key]);
                    if ($nested !== null) {
                        return $nested;
                    }
                }
            }
            return null;
        }
        if (is_float($value) || (is_string($value) && is_numeric($value))) {
            return (int) $value;
        }
        return null;
    }

    private function toNullableString(mixed $value, ?int $maxLength = null): ?string
    {
        if ($value === null) {
            return null;
        }

        if (is_string($value) || is_int($value) || is_float($value) || is_bool($value)) {
            $text = trim((string) $value);
        } else {
            $encoded = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($encoded === false) {
                $encoded = '[unserializable]';
            }
            $text = trim($encoded);
        }

        if ($text === '') {
            return null;
        }

        if (is_int($maxLength) && $maxLength > 0 && strlen($text) > $maxLength) {
            $text = substr($text, 0, $maxLength);
        }

        return $text;
    }

    private function getEncryptionKeyBinary(): ?string
    {
        $key = trim($this->encryptionKey);
        if ($key === '' || $key === 'CHANGE_THIS_TO_A_RANDOM_32_BYTE_HEX_STRING') {
            return null;
        }

        if (!preg_match('/^[a-f0-9]{64}$/i', $key)) {
            return null;
        }

        $decoded = hex2bin($key);
        return $decoded === false ? null : $decoded;
    }

    // =====================================================================
    // API Logging
    // =====================================================================

    private function logApiCall(string $endpoint, ?string $domain, int $httpCode, mixed $data, int $elapsedMs): void
    {
        if (!$this->db) {
            return;
        }

        try {
            Database::logApiCall($this->db, [
                'endpoint'         => $endpoint,
                'domain'           => $domain,
                'http_status'      => $httpCode,
                'finding_count'    => $this->countFindings($data),
                'response_time_ms' => $elapsedMs,
            ]);
        } catch (Throwable) {
            // Don't block responses if logging fails
        }
    }

    private function countFindings(mixed $data): int
    {
        if (!is_array($data)) {
            return 0;
        }
        $findings = $this->extractFindings($data);
        return count($findings);
    }
}

