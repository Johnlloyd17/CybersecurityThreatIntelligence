<?php
// =============================================================================
//  CTI — DigitalOcean Space Finder Module
//  Checks common DO Space name patterns for a domain across regions.
//  Uses curl_multi for parallel requests with a 30s time budget.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DoSpaceFinderModule extends BaseApiModule
{
    private const API_ID   = 'do-space-finder';
    private const API_NAME = 'DO Space Finder';
    private const SUPPORTED = ['domain'];

    // Only check the most common regions
    private const REGIONS = ['nyc3', 'sfo3', 'ams3', 'sgp1'];

    // Reduced suffix list — most common patterns only
    private const SUFFIXES = [
        '', '-backup', '-dev', '-staging', '-prod', '-assets', '-static', '-media',
    ];

    private const MAX_TIME_SECONDS = 25; // Time budget

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = strtolower(trim($queryValue));
        $baseName = preg_replace('/\.(com|net|org|io|co|dev|app|xyz|info|biz)$/i', '', $domain);
        $baseName = str_replace('.', '-', $baseName);

        // Build all URLs to check
        $urls = [];
        foreach (self::SUFFIXES as $suffix) {
            $spaceName = $baseName . $suffix;
            foreach (self::REGIONS as $region) {
                $urls[] = [
                    'url'   => "https://{$spaceName}.{$region}.digitaloceanspaces.com",
                    'space' => $spaceName,
                    'region' => $region,
                ];
            }
        }

        // Use curl_multi for parallel HEAD requests
        $mh = curl_multi_init();
        $handles = [];

        foreach ($urls as $i => $item) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $item['url'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_NOBODY         => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT      => 'CTI-Platform/1.0',
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$i] = $ch;
        }

        // Execute all in parallel with time budget
        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($status > 0) break;
            curl_multi_select($mh, 0.5);

            // Abort if time budget exceeded
            if ((microtime(true) - $start) > self::MAX_TIME_SECONDS) break;
        } while ($running > 0);

        // Collect results
        $found = [];
        $checked = 0;

        foreach ($handles as $i => $ch) {
            $checked++;
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlErrno = curl_errno($ch);
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);

            if ($curlErrno !== 0) continue;

            $item = $urls[$i];
            if ($httpCode === 200) {
                $found[] = ['space' => $item['space'], 'region' => $item['region'], 'url' => $item['url'], 'status' => 'public', 'http' => 200];
            } elseif ($httpCode === 403) {
                $found[] = ['space' => $item['space'], 'region' => $item['region'], 'url' => $item['url'], 'status' => 'exists_private', 'http' => 403];
            }
        }

        curl_multi_close($mh);
        $ms = (int)((microtime(true) - $start) * 1000);
        $foundCount = count($found);

        if ($foundCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 60,
                responseMs: $ms,
                summary: "Domain {$domain}: No DigitalOcean Spaces found among {$checked} checks.",
                tags: [self::API_ID, 'domain', 'digitalocean', 'clean'],
                rawData: ['found' => [], 'checked' => $checked],
                success: true
            );
        }

        $publicSpaces = array_filter($found, function($s) { return $s['status'] === 'public'; });
        $publicCount = count($publicSpaces);

        $parts = ["Domain {$domain}: {$foundCount} DigitalOcean Space(s) found"];
        $names = array_map(function($s) { return $s['space'] . '.' . $s['region'] . ' (' . $s['status'] . ')'; }, $found);
        $parts[] = "Spaces: " . implode(', ', $names);

        $score = $publicCount > 0 ? 70 : 15;
        $severity   = OsintResult::scoreToSeverity($score);
        $tags = [self::API_ID, 'domain', 'digitalocean', 'cloud'];
        if ($publicCount > 0) {
            $tags[] = 'public_storage';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'found' => $found,
                'found_count' => $foundCount,
                'public_count' => $publicCount,
                'checked' => $checked,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $ch = curl_init('https://nyc3.digitaloceanspaces.com');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_NOBODY => true, CURLOPT_SSL_VERIFYPEER => false]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($code > 0) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => 'DO Spaces endpoint unreachable'];
    }
}
