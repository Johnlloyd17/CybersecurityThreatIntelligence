<?php
// =============================================================================
//  CTI — AlienVault OTX OSINT Module Handler
//  php/modules/AlienVaultModule.php
//
//  Queries the AlienVault OTX API v1 for threat intelligence on IPs, domains,
//  URLs, and file hashes.
//  API Docs: https://otx.alienvault.com/api
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';
require_once __DIR__ . '/BaseApiModule.php';

class AlienVaultModule extends BaseApiModule
{
    private const API_ID   = 'alienvault';
    private const API_NAME = 'AlienVault OTX';

    private const SUPPORTED_TYPES = ['ip', 'domain', 'url', 'hash'];

    /**
     * Execute a threat intelligence query against AlienVault OTX.
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://otx.alienvault.com/api/v1', '/');
        $headers = ['X-OTX-API-KEY' => $apiKey];

        $url = $this->buildEndpointUrl($baseUrl, $queryType, $queryValue);

        $response = HttpClient::get($url, $headers);

        // Handle error status codes
        if ($response['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms']);
        }
        if ($response['status'] === 0 || $response['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms']);
        }
        if ($response['status'] < 200 || $response['status'] >= 300) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$response['status']}", $response['elapsed_ms']);
        }

        $json = $response['json'];
        if (!$json) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms']);
        }

        return $this->parseResponse($json, $queryType, $queryValue, $response['elapsed_ms']);
    }

    /**
     * Run a health check against the AlienVault OTX API.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://otx.alienvault.com/api/v1', '/');
        $headers = ['X-OTX-API-KEY' => $apiKey];

        // Query a known safe IP (Google DNS) as a health check
        $url = "{$baseUrl}/indicators/IPv4/8.8.8.8/general";

        $response = HttpClient::get($url, $headers);

        if ($response['error'] || $response['status'] === 0) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => $response['error'] ?? 'Connection failed'];
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => 'Invalid API key'];
        }
        if ($response['status'] >= 200 && $response['status'] < 300) {
            return ['status' => 'healthy', 'latency_ms' => $response['elapsed_ms'], 'error' => null];
        }

        return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => "HTTP {$response['status']}"];
    }

    /**
     * Build the API endpoint URL based on query type.
     */
    private function buildEndpointUrl(string $baseUrl, string $queryType, string $queryValue): string
    {
        return match ($queryType) {
            'ip'     => "{$baseUrl}/indicators/IPv4/" . urlencode($queryValue) . "/general",
            'domain' => "{$baseUrl}/indicators/domain/" . urlencode($queryValue) . "/general",
            'url'    => "{$baseUrl}/indicators/url/" . urlencode($queryValue) . "/general",
            'hash'   => "{$baseUrl}/indicators/file/" . urlencode($queryValue) . "/general",
            default  => "{$baseUrl}/indicators/IPv4/" . urlencode($queryValue) . "/general",
        };
    }

    /**
     * Parse the AlienVault OTX response and compute risk metrics.
     */
    private function parseResponse(array $data, string $queryType, string $queryValue, int $elapsedMs): OsintResult
    {
        // Extract pulse info (threat intelligence pulses referencing this indicator)
        $pulseInfo  = $data['pulse_info'] ?? [];
        $pulseCount = $pulseInfo['count'] ?? 0;
        $pulses     = $pulseInfo['pulses'] ?? [];

        // Extract general indicator info
        $reputation = $data['reputation'] ?? null;
        $country    = $data['country_name'] ?? ($data['country_code'] ?? null);
        $asn        = $data['asn'] ?? null;
        $indicator  = $data['indicator'] ?? $queryValue;
        $sections   = $data['sections'] ?? [];
        $validation = $data['validation'] ?? [];
        $type       = $data['type'] ?? $queryType;

        // Score: based on pulse count
        // 0 pulses = 0, 1-2 = 15, 3-5 = 35, 6-10 = 55, 11-20 = 75, 20+ = 90
        if ($pulseCount === 0) {
            $score = 0;
        } elseif ($pulseCount <= 2) {
            $score = 15;
        } elseif ($pulseCount <= 5) {
            $score = 35;
        } elseif ($pulseCount <= 10) {
            $score = 55;
        } elseif ($pulseCount <= 20) {
            $score = 75;
        } else {
            $score = min(100, 85 + (int)(($pulseCount - 20) / 10));
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $pulseCount > 0 ? min(99, 55 + min(44, $pulseCount * 3)) : 40;

        // Build summary
        $summaryParts = [];

        $label = match ($queryType) {
            'ip'     => "IP {$queryValue}",
            'domain' => "Domain {$queryValue}",
            'url'    => "URL {$queryValue}",
            'hash'   => "File hash {$queryValue}",
            default  => $queryValue,
        };

        $summaryParts[] = "{$label}: Referenced in {$pulseCount} threat intelligence pulse(s)";

        if ($country) {
            $summaryParts[] = "Country: {$country}";
        }
        if ($asn) {
            $summaryParts[] = "ASN: {$asn}";
        }

        // Include top pulse names
        if ($pulseCount > 0 && !empty($pulses)) {
            $pulseNames = array_slice(array_map(fn($p) => $p['name'] ?? 'Unnamed', $pulses), 0, 3);
            $summaryParts[] = "Top pulses: " . implode('; ', $pulseNames);
        }

        $summary = implode('. ', $summaryParts) . '.';

        // Build tags
        $tags = [self::API_ID, $queryType];

        if ($pulseCount === 0) {
            $tags[] = 'clean';
        } elseif ($pulseCount <= 2) {
            $tags[] = 'low_risk';
        } elseif ($pulseCount <= 10) {
            $tags[] = 'suspicious';
        } else {
            $tags[] = 'malicious';
        }

        // Extract tags from pulses
        $pulseTags = [];
        foreach ($pulses as $pulse) {
            if (isset($pulse['tags']) && is_array($pulse['tags'])) {
                $pulseTags = array_merge($pulseTags, $pulse['tags']);
            }
        }
        // Take top 5 most common pulse tags
        if (!empty($pulseTags)) {
            $tagCounts = array_count_values(array_map('strtolower', $pulseTags));
            arsort($tagCounts);
            $topPulseTags = array_slice(array_keys($tagCounts), 0, 5);
            $tags = array_merge($tags, $topPulseTags);
        }

        // Extract adversary info from pulses
        foreach ($pulses as $pulse) {
            $adversary = $pulse['adversary'] ?? null;
            if ($adversary && $adversary !== '') {
                $tags[] = 'apt';
                break;
            }
        }

        $result = new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $elapsedMs,
            summary:    $summary,
            tags:       array_values(array_unique($tags)),
            rawData:    $data,
            success:    true
        );

        // Extract discoveries from pulse indicators for enrichment chaining
        foreach ($pulses as $pulse) {
            $indicators = $pulse['indicators'] ?? [];
            foreach ($indicators as $ind) {
                $indType  = $ind['type'] ?? '';
                $indValue = $ind['indicator'] ?? '';
                if ($indValue === '') continue;
                switch ($indType) {
                    case 'IPv4':
                    case 'IPv4 - Source':
                        $result->addDiscovery(EventTypes::IP_ADDRESS, $indValue);
                        break;
                    case 'IPv6':
                        $result->addDiscovery(EventTypes::IPV6_ADDRESS, $indValue);
                        break;
                    case 'domain':
                    case 'hostname':
                        $result->addDiscovery(EventTypes::INTERNET_NAME, $indValue);
                        break;
                    case 'email':
                        $result->addDiscovery(EventTypes::EMAILADDR, $indValue);
                        break;
                    case 'FileHash-SHA256':
                    case 'FileHash-MD5':
                    case 'FileHash-SHA1':
                        $result->addDiscovery(EventTypes::HASH, $indValue);
                        break;
                    case 'CVE':
                        $result->addDiscovery(EventTypes::VULNERABILITY, $indValue);
                        break;
                }
            }
        }

        return $result;
    }
}
