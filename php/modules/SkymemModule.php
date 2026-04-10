<?php
// =============================================================================
//  CTI — Skymem Module
//  Queries Skymem for email address enumeration by domain.
//  Free, no API key required. Supports: domain, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SkymemModule extends BaseApiModule
{
    private const API_ID   = 'skymem';
    private const API_NAME = 'Skymem';
    private const SUPPORTED = ['domain', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://www.skymem.info', '/');

        // Extract domain from email if needed
        $domain = $queryValue;
        if ($queryType === 'email' && str_contains($queryValue, '@')) {
            $domain = substr($queryValue, strpos($queryValue, '@') + 1);
        }

        $url  = "{$baseUrl}/srch?q=" . urlencode($domain) . "&ss=home";
        $resp = HttpClient::get($url, [], $this->timeoutSeconds());

        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $body = $resp['body'] ?? '';

        // Extract emails from page
        $emails = [];
        if (preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $body, $matches)) {
            $emails = array_unique($matches[0]);
            // Filter to only domain-relevant emails
            $emails = array_values(array_filter($emails, function ($e) use ($domain) {
                return str_ends_with(strtolower($e), '@' . strtolower($domain));
            }));
        }

        $totalEmails = count($emails);

        if ($totalEmails === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $score      = min(25, (int)($totalEmails / 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(85, 55 + min(30, $totalEmails * 2));

        $sample = array_slice($emails, 0, 10);
        $summary = "Skymem: {$totalEmails} email(s) found for {$domain}.";
        if (!empty($sample)) $summary .= ' Sample: ' . implode(', ', $sample) . '.';

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, $queryType, 'email_enum'],
            rawData: [
                'domain'       => $domain,
                'total_emails' => $totalEmails,
                'emails'       => array_slice($emails, 0, 100),
            ],
            success: true
        );

        foreach (array_slice($emails, 0, 10) as $e) $result->addDiscovery('Email Address', $e);

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://www.skymem.info', '/');
        $resp = HttpClient::get("{$baseUrl}/srch?q=google.com&ss=home", [], 10);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
