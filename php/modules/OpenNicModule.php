<?php
// =============================================================================
//  CTI — OpenNIC DNS Module
//  API Docs: https://www.opennicproject.org
//  Free, no key. Supports: domain
//  Endpoint: GET https://api.opennicproject.org/geoip/?json
//  Checks if domain uses OpenNIC TLDs and provides alternative DNS info
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OpenNicModule extends BaseApiModule
{
    private const API_ID   = 'opennic';
    private const API_NAME = 'OpenNIC DNS';
    private const SUPPORTED = ['domain'];

    // OpenNIC-specific TLDs
    private const OPENNIC_TLDS = [
        'bbs', 'chan', 'cyb', 'dyn', 'epic', 'geek', 'gopher', 'indy',
        'libre', 'neo', 'null', 'o', 'oss', 'oz', 'parody', 'pirate',
        'free', 'ku', 'te', 'ti', 'uu', 'opennic', 'glue', 'fur'
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);

        // Check if domain uses an OpenNIC TLD
        $domainParts = explode('.', $queryValue);
        $tld = end($domainParts);
        $isOpenNic = in_array(strtolower($tld), self::OPENNIC_TLDS, true);

        // Fetch OpenNIC DNS server info
        $url = 'https://api.opennicproject.org/geoip/?json';
        $resp = HttpClient::get($url, [], 15);

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);

        $servers = [];
        $serverError = null;

        if ($resp['error'] || $resp['status'] === 0) {
            $serverError = $resp['error'] ? $resp['error'] : 'Connection failed';
        } elseif ($resp['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        } elseif ($resp['status'] === 200 && $resp['json']) {
            $data = $resp['json'];
            if (is_array($data)) {
                // Could be array of server objects or a single object
                $serverList = isset($data[0]) ? $data : [$data];
                foreach ($serverList as $srv) {
                    $ip = isset($srv['host']) ? $srv['host'] : (isset($srv['ip']) ? $srv['ip'] : '');
                    if ($ip) {
                        $servers[] = [
                            'ip' => $ip,
                            'country' => isset($srv['stat']) ? $srv['stat'] : '',
                        ];
                    }
                }
            }
        }

        // Score: OpenNIC TLDs are unusual and may indicate non-standard infrastructure
        $score = $isOpenNic ? 35 : 5;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $isOpenNic ? 95 : 80;

        $parts = [];

        if ($isOpenNic) {
            $parts[] = "Domain {$queryValue} uses OpenNIC TLD '.{$tld}' — this is a non-standard TLD not resolvable via conventional DNS";
        } else {
            $parts[] = "Domain {$queryValue} does not use an OpenNIC TLD";
        }

        $serverCount = count($servers);
        if ($serverCount > 0) {
            $sampleIps = [];
            foreach (array_slice($servers, 0, 5) as $srv) {
                $sampleIps[] = $srv['ip'];
            }
            $parts[] = "{$serverCount} OpenNIC DNS server(s) available: " . implode(', ', $sampleIps);
        } elseif ($serverError) {
            $parts[] = "Could not retrieve OpenNIC server list: {$serverError}";
        }

        $tags = [self::API_ID, 'domain', 'dns', 'alternative_dns'];
        if ($isOpenNic) $tags[] = 'opennic_tld';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'] > 0 ? $resp['elapsed_ms'] : $elapsedMs,
            summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'is_opennic_tld' => $isOpenNic,
                'tld' => $tld,
                'opennic_servers' => array_slice($servers, 0, 20),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.opennicproject.org/geoip/?json', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
