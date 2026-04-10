<?php
// =============================================================================
//  CTI — Phonebook (IntelX) Module
//  Queries Intelligence X Phonebook API for email/domain/URL enumeration.
//  API Docs: https://intelx.io/developers (Phonebook endpoint)
//  Supports: email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PhonebookModule extends BaseApiModule
{
    private const API_ID   = 'phonebook';
    private const API_NAME = 'Phonebook (IntelX)';
    private const SUPPORTED = ['email', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://2.intelx.io', '/');
        $headers = [
            'x-key'        => $apiKey,
            'Content-Type' => 'application/json',
        ];

        // target: 1=emails, 2=domains, 3=URLs
        $target = ($queryType === 'email') ? 1 : 2;

        $body = json_encode([
            'term'       => $queryValue,
            'maxresults' => min(100, $this->maxResults()),
            'target'     => $target,
        ]);

        $resp = HttpClient::post("{$baseUrl}/phonebook/search", $body, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $searchId = $resp['json']['id'] ?? '';
        if (!$searchId) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'No search ID returned', $resp['elapsed_ms']);
        }

        usleep(500000);
        $resultResp = HttpClient::get("{$baseUrl}/phonebook/search/result?id=" . urlencode($searchId) . "&limit=100", $headers);
        $totalMs = $resp['elapsed_ms'] + ($resultResp['elapsed_ms'] ?? 0);

        $selectors = $resultResp['json']['selectors'] ?? [];

        if (empty($selectors)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $totalMs);
        }

        $totalFound = count($selectors);
        $emails  = [];
        $domains = [];
        $urls    = [];

        foreach ($selectors as $s) {
            $val  = $s['selectorvalue'] ?? '';
            $type = $s['selectortype'] ?? 0;
            if ($type === 1 || str_contains($val, '@')) $emails[] = $val;
            elseif ($type === 2) $domains[] = $val;
            elseif ($type === 3) $urls[] = $val;
        }

        $score      = min(35, (int)($totalFound / 5));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 60 + min(30, $totalFound));

        $parts = [];
        if (!empty($emails)) $parts[] = count($emails) . ' email(s)';
        if (!empty($domains)) $parts[] = count($domains) . ' domain(s)';
        if (!empty($urls)) $parts[] = count($urls) . ' URL(s)';

        $summary = "Phonebook: {$totalFound} result(s) for {$queryValue}. " . implode(', ', $parts) . '.';

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $totalMs,
            summary: $summary,
            tags: [self::API_ID, $queryType, 'osint', 'enumeration'],
            rawData: [
                'total'   => $totalFound,
                'emails'  => array_slice($emails, 0, 50),
                'domains' => array_slice($domains, 0, 50),
                'urls'    => array_slice($urls, 0, 20),
            ],
            success: true
        );

        foreach (array_slice($domains, 0, 10) as $d) $result->addDiscovery('Internet Name', $d);
        foreach (array_slice($emails, 0, 5) as $e) $result->addDiscovery('Email Address', $e);

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://2.intelx.io', '/');
        $resp = HttpClient::get("{$baseUrl}/authenticate/info", ['x-key' => $apiKey]);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
