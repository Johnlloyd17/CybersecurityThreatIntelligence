<?php
// =============================================================================
//  CTI — HAVE I BEEN PWNED MODULE HANDLER
//  php/modules/HaveIBeenPwnedModule.php
//
//  Checks email addresses against the Have I Been Pwned breach database.
//  API Docs: https://haveibeenpwned.com/API/v3
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HaveIBeenPwnedModule extends BaseApiModule
{
    private const API_ID   = 'hibp';
    private const API_NAME = 'Have I Been Pwned';

    /**
     * Execute a query against the HIBP API.
     *
     * @param  string $queryType  Must be "email"
     * @param  string $queryValue The email address to check
     * @param  string $apiKey     hibp-api-key
     * @param  string $baseUrl    Base URL (default: https://haveibeenpwned.com/api/v3)
     * @return OsintResult
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'email') {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. HIBP supports email lookups only.");
        }

        $headers = [
            'hibp-api-key' => $apiKey,
            'user-agent'   => 'CTI-Platform',
        ];

        $url = rtrim($baseUrl, '/') . '/breachedaccount/' . urlencode($queryValue) . '?truncateResponse=false';
        $response = HttpClient::get($url, $headers);

        // Handle HTTP-level errors
        if ($response['status'] === 0) {
            return OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms']);
        }
        if ($response['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }

        // 404 means the email was not found in any breaches — this is a clean result
        if ($response['status'] === 404) {
            return new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 90,
                responseMs: $response['elapsed_ms'],
                summary:    "Have I Been Pwned: {$queryValue} was not found in any known data breaches.",
                tags:       [self::API_ID, 'clean', 'no_breaches'],
                rawData:    null,
                success:    true,
                error:      null
            );
        }

        if ($response['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$response['status']}", $response['elapsed_ms']);
        }

        $breaches = $response['json'];
        if ($breaches === null || !is_array($breaches)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $breachCount = count($breaches);

        // Score based on number of breaches
        if ($breachCount === 0) {
            $score = 0;
        } elseif ($breachCount <= 2) {
            $score = 30;
        } elseif ($breachCount <= 5) {
            $score = 50;
        } elseif ($breachCount <= 10) {
            $score = 70;
        } else {
            $score = 90;
        }

        $severity = OsintResult::scoreToSeverity($score);

        // Build tags — include breach names (first 5)
        $tags = [self::API_ID, 'breached'];
        $breachNames = [];
        foreach (array_slice($breaches, 0, 5) as $breach) {
            $name = $breach['Name'] ?? $breach['name'] ?? '';
            if ($name !== '') {
                $breachNames[] = $name;
                $tags[] = $name;
            }
        }

        // Collect data classes across all breaches
        $dataClasses = [];
        foreach ($breaches as $breach) {
            foreach (($breach['DataClasses'] ?? []) as $dc) {
                $dataClasses[$dc] = true;
            }
        }
        $dataClassList = array_slice(array_keys($dataClasses), 0, 8);

        // Build summary
        $breachNamesStr = implode(', ', $breachNames);
        $summary = "Have I Been Pwned: {$queryValue} found in {$breachCount} breach(es).";
        if (!empty($breachNamesStr)) {
            $summary .= " Breaches: {$breachNamesStr}.";
            if ($breachCount > 5) {
                $summary .= " (and " . ($breachCount - 5) . " more)";
            }
        }
        if (!empty($dataClassList)) {
            $summary .= " Exposed data: " . implode(', ', $dataClassList) . ".";
        }

        $confidence = 95;

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $breaches,
            success:    true,
            error:      null
        );
    }

    /**
     * Health check: query a test email address. A 404 is acceptable (API is reachable).
     *
     * @param  string $apiKey
     * @param  string $baseUrl
     * @return array  ['status'=>'healthy'|'down', 'latency_ms'=>int, 'error'=>?string]
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = [
            'hibp-api-key' => $apiKey,
            'user-agent'   => 'CTI-Platform',
        ];

        $url = rtrim($baseUrl, '/') . '/breachedaccount/test@example.com?truncateResponse=false';
        $response = HttpClient::get($url, $headers);

        // 404 is fine — it means the API is reachable but the email is not breached
        if ($response['status'] === 200 || $response['status'] === 404) {
            return [
                'status'     => 'healthy',
                'latency_ms' => $response['elapsed_ms'],
                'error'      => null,
            ];
        }

        return [
            'status'     => 'down',
            'latency_ms' => $response['elapsed_ms'],
            'error'      => $response['error'] ?? "HTTP {$response['status']}",
        ];
    }
}
