<?php
// =============================================================================
//  CTI — CertSpotter (SSLMate) Module
//  API Docs: https://sslmate.com/certspotter/api/
//  Auth: Bearer token or basic auth. Supports: domain
//  Endpoint: https://api.certspotter.com/v1/issuances?domain={domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CertSpotterModule extends BaseApiModule
{
    private const API_ID   = 'certspotter';
    private const API_NAME = 'CertSpotter';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'domain') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'https://api.certspotter.com/v1/issuances?domain=' . urlencode($queryValue) . '&include_subdomains=true&expand=dns_names';
        $headers = [];
        if ($apiKey) $headers['Authorization'] = 'Bearer ' . $apiKey;

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data) || empty($data))
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $certCount = count($data);
        $dnsNames = [];
        $issuers = [];
        foreach ($data as $cert) {
            foreach ($cert['dns_names'] ?? [] as $dn) $dnsNames[$dn] = true;
            $issuer = $cert['issuer'] ?? [];
            $org = $issuer['O'] ?? ($issuer['CN'] ?? '');
            if ($org) $issuers[$org] = true;
        }

        $uniqueNames = count($dnsNames);
        $parts = ["Domain {$queryValue}: {$certCount} certificate issuance(s) found, {$uniqueNames} unique DNS name(s)"];
        if (!empty($issuers)) $parts[] = "Issuers: " . implode(', ', array_slice(array_keys($issuers), 0, 5));
        $sample = array_slice(array_keys($dnsNames), 0, 10);
        if (!empty($sample)) $parts[] = "Names: " . implode(', ', $sample);

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: min(15, (int)($uniqueNames / 5)), severity: 'info', confidence: 90,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'certificates', 'dns', 'clean'],
            rawData: ['cert_count' => $certCount, 'unique_names' => $uniqueNames, 'dns_names' => array_slice(array_keys($dnsNames), 0, 50)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = $apiKey ? ['Authorization' => 'Bearer ' . $apiKey] : [];
        $resp = HttpClient::get('https://api.certspotter.com/v1/issuances?domain=google.com&include_subdomains=false', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
