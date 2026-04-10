<?php
// =============================================================================
//  CTI — crt.sh (Certificate Transparency) Module
//  API Docs: https://crt.sh (Comodo CT Log search)
//  Free, no key. Supports: domain
//  Endpoint: https://crt.sh/?q={domain}&output=json
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CrtShModule extends BaseApiModule
{
    private const API_ID   = 'crt-sh';
    private const API_NAME = 'Certificate Transparency (crt.sh)';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://crt.sh/?q=' . urlencode('%.' . $queryValue) . '&output=json';
        $resp = HttpClient::get($url, [], 30); // crt.sh can be slow

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalCerts = count($data);
        if ($totalCerts === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Extract unique common names (subdomains)
        $names = [];
        $issuers = [];
        foreach ($data as $cert) {
            $cn = $cert['common_name'] ?? '';
            if ($cn) $names[$cn] = true;
            $nameValue = $cert['name_value'] ?? '';
            if ($nameValue) {
                foreach (explode("\n", $nameValue) as $n) {
                    $n = trim($n);
                    if ($n) $names[$n] = true;
                }
            }
            $issuer = $cert['issuer_name'] ?? '';
            if ($issuer) $issuers[$issuer] = true;
        }

        $uniqueNames = array_keys($names);
        $uniqueCount = count($uniqueNames);

        // CT data is informational, not inherently dangerous
        $score = min(25, (int)($uniqueCount / 5));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 70 + min(25, $uniqueCount));

        $parts = ["Domain {$queryValue}: {$totalCerts} certificate(s) found, {$uniqueCount} unique name(s)"];

        // Show sample subdomains
        $sample = array_slice($uniqueNames, 0, 10);
        if (!empty($sample)) {
            $parts[] = "Names: " . implode(', ', $sample);
            if ($uniqueCount > 10) $parts[] = "... and " . ($uniqueCount - 10) . " more";
        }

        $issuerList = array_keys($issuers);
        if (!empty($issuerList)) {
            $parts[] = "Issuer(s): " . implode(', ', array_slice($issuerList, 0, 3));
        }

        $tags = [self::API_ID, 'domain', 'dns', 'certificates'];
        if ($uniqueCount > 50) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total_certs' => $totalCerts, 'unique_names' => array_slice($uniqueNames, 0, 50)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://crt.sh/?q=%.google.com&output=json', [], 15);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
