<?php
// =============================================================================
//  CTI — Azure Blob Storage Finder Module
//  Checks common Azure Blob Storage name patterns for a domain.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AzureBlobFinderModule extends BaseApiModule
{
    private const API_ID   = 'azure-blob-finder';
    private const API_NAME = 'Azure Blob Finder';
    private const SUPPORTED = ['domain'];

    private const SUFFIXES = [
        '', 'backup', 'bak', 'dev', 'staging', 'prod',
        'test', 'assets', 'static', 'media', 'uploads',
        'files', 'data', 'public', 'logs', 'www', 'cdn',
        'images', 'docs', 'content',
    ];

    /** @var int Maximum seconds the module may spend on network I/O. */
    private const TIME_BUDGET = 25;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = strtolower(trim($queryValue));
        $baseName = preg_replace('/\.(com|net|org|io|co|dev|app|xyz|info|biz)$/i', '', $domain);
        $baseName = str_replace(['.', '-'], '', $baseName);

        // --- Build the list of candidate account names / URLs ----------------
        $targets = []; // [ ['name' => …, 'url' => …], … ]
        foreach (self::SUFFIXES as $suffix) {
            $name = $suffix === '' ? $baseName : $baseName . $suffix;
            // Azure storage account names: 3-24 chars, lowercase letters and numbers only
            $name = preg_replace('/[^a-z0-9]/', '', $name);
            if (strlen($name) < 3 || strlen($name) > 24) continue;

            $targets[] = [
                'name' => $name,
                'url'  => "https://{$name}.blob.core.windows.net",
            ];
        }

        $checked = count($targets);
        $found   = [];

        // --- Fire all requests in parallel via curl_multi --------------------
        $mh         = curl_multi_init();
        $handleMap  = []; // (int)$ch => ['idx' => int, 'ch' => CurlHandle]
        $deadline   = $start + self::TIME_BUDGET;

        foreach ($targets as $idx => $target) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $target['url'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_NOBODY         => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT      => 'CTI-Platform/1.0',
            ]);
            curl_multi_add_handle($mh, $ch);
            $handleMap[(int)$ch] = ['idx' => $idx, 'ch' => $ch];
        }

        // Execute with a hard time budget so we never exceed max_execution_time
        $active = null;

        do {
            $mrc = curl_multi_exec($mh, $active);

            // Drain completed handles as they finish
            while ($info = curl_multi_info_read($mh)) {
                $ch  = $info['handle'];
                $entry = $handleMap[(int)$ch];
                $t   = $targets[$entry['idx']];

                $curlErrno = curl_errno($ch);
                $httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

                if ($curlErrno === 0) {
                    // Azure returns 400 for existing accounts (without container path), 404/DNS failure for non-existent
                    if ($httpCode === 400 || $httpCode === 200 || $httpCode === 403) {
                        $resultStatus = $httpCode === 200 ? 'public' : 'exists';
                        $found[] = ['account' => $t['name'], 'url' => $t['url'], 'status' => $resultStatus, 'http' => $httpCode];
                    }
                }

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($handleMap[(int)$ch]);
            }

            // Abort early if the time budget is exhausted
            if (microtime(true) >= $deadline) {
                break;
            }

            // Wait briefly for socket activity (max 100 ms) to avoid busy-looping
            if ($active > 0) {
                curl_multi_select($mh, 0.1);
            }
        } while ($active > 0 && $mrc === CURLM_OK);

        // Cleanup: remove and close any handles still in-flight (e.g. after time-budget break)
        foreach ($handleMap as $entry) {
            curl_multi_remove_handle($mh, $entry['ch']);
            curl_close($entry['ch']);
        }
        curl_multi_close($mh);

        $ms = (int)((microtime(true) - $start) * 1000);
        $foundCount = count($found);

        if ($foundCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 60,
                responseMs: $ms,
                summary: "Domain {$domain}: No Azure Blob Storage accounts found among {$checked} variations.",
                tags: [self::API_ID, 'domain', 'azure', 'clean'],
                rawData: ['found' => [], 'checked' => $checked],
                success: true
            );
        }

        $publicAccounts = array_filter($found, function($b) { return $b['status'] === 'public'; });
        $publicCount = count($publicAccounts);

        $parts = ["Domain {$domain}: {$foundCount} Azure Blob Storage account(s) found"];
        $names = array_map(function($b) { return $b['account'] . ' (' . $b['status'] . ')'; }, $found);
        $parts[] = "Accounts: " . implode(', ', $names);

        $score = $publicCount > 0 ? 70 : 15;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;
        $tags = [self::API_ID, 'domain', 'azure', 'cloud'];
        if ($publicCount > 0) {
            $tags[] = 'public_storage';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
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
        $ch = curl_init('https://microsoft.blob.core.windows.net');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_NOBODY => true, CURLOPT_SSL_VERIFYPEER => false]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($code > 0) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => 'Azure endpoint unreachable'];
    }
}
