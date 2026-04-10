<?php
// =============================================================================
//  CTI — Google Cloud Storage Finder Module
//  Checks common GCS bucket name patterns for a domain.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GcsFinderModule extends BaseApiModule
{
    private const API_ID   = 'gcs-finder';
    private const API_NAME = 'GCS Bucket Finder';
    private const SUPPORTED = ['domain'];

    private const SUFFIXES = [
        '', '-backup', '-bak', '-dev', '-staging', '-prod',
        '-test', '-assets', '-static', '-media', '-uploads',
        '-files', '-data', '-public', '-logs', '-www', '-cdn',
        '-images', '-docs', '-content',
    ];

    /** Maximum wall-clock seconds allowed for the entire batch of requests. */
    private const TIME_BUDGET = 25;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = strtolower(trim($queryValue));
        $baseName = preg_replace('/\.(com|net|org|io|co|dev|app|xyz|info|biz)$/i', '', $domain);
        $baseName = str_replace('.', '-', $baseName);

        $found = [];
        $checked = 0;

        // --- Build all curl handles and add to multi handle ---
        $mh = curl_multi_init();
        $handles = []; // Maps resource id => ['ch' => $ch, 'bucket' => $name, 'url' => $url]

        foreach (self::SUFFIXES as $suffix) {
            $bucketName = $baseName . $suffix;
            $url = "https://storage.googleapis.com/{$bucketName}";

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_NOBODY         => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT      => 'CTI-Platform/1.0',
            ]);

            curl_multi_add_handle($mh, $ch);
            $handles[(int)$ch] = [
                'ch'     => $ch,
                'bucket' => $bucketName,
                'url'    => $url,
            ];
        }

        // --- Execute all requests in parallel with a time budget ---
        $active = null;
        do {
            $status = curl_multi_exec($mh, $active);
            if ($status !== CURLM_OK) {
                break;
            }
            // Wait briefly for activity (max 200 ms) to avoid busy-looping
            if ($active > 0) {
                curl_multi_select($mh, 0.2);
            }
            // Enforce the overall time budget
            if ((microtime(true) - $start) >= self::TIME_BUDGET) {
                break;
            }
        } while ($active > 0);

        // --- Collect results from each handle ---
        foreach ($handles as $info) {
            $ch = $info['ch'];
            $checked++;
            $curlErrno = curl_errno($ch);
            $httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);

            if ($curlErrno !== 0) {
                continue;
            }

            if ($httpCode === 200) {
                $found[] = ['bucket' => $info['bucket'], 'url' => $info['url'], 'status' => 'public', 'http' => 200];
            } elseif ($httpCode === 403) {
                $found[] = ['bucket' => $info['bucket'], 'url' => $info['url'], 'status' => 'exists_private', 'http' => 403];
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
                summary: "Domain {$domain}: No GCS buckets found among {$checked} name variations.",
                tags: [self::API_ID, 'domain', 'gcs', 'clean'],
                rawData: ['found' => [], 'checked' => $checked],
                success: true
            );
        }

        $publicBuckets = array_filter($found, function($b) { return $b['status'] === 'public'; });
        $publicCount = count($publicBuckets);

        $parts = ["Domain {$domain}: {$foundCount} GCS bucket(s) found"];
        $names = array_map(function($b) { return $b['bucket'] . ' (' . $b['status'] . ')'; }, $found);
        $parts[] = "Buckets: " . implode(', ', $names);

        $score = $publicCount > 0 ? 70 : 15;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 75;
        $tags = [self::API_ID, 'domain', 'gcs', 'cloud'];
        if ($publicCount > 0) {
            $tags[] = 'public_bucket';
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
        $ch = curl_init('https://storage.googleapis.com');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_NOBODY => true, CURLOPT_SSL_VERIFYPEER => false]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($code > 0) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => 'GCS endpoint unreachable'];
    }
}
