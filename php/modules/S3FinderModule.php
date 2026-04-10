<?php
// =============================================================================
//  CTI — Amazon S3 Bucket Finder Module
//  Checks common S3 bucket name patterns for a domain.
//  Uses curl_multi for parallel requests with a 25s time budget.
//  403=exists but private, 200=public, 404=doesn't exist.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class S3FinderModule extends BaseApiModule
{
    private const API_ID   = 's3-finder';
    private const API_NAME = 'S3 Bucket Finder';
    private const SUPPORTED = ['domain'];

    /** Suffixes to append to domain name for bucket guesses */
    private const SUFFIXES = [
        '', '-backup', '-bak', '-dev', '-staging', '-stage', '-prod',
        '-production', '-test', '-testing', '-assets', '-static',
        '-media', '-uploads', '-files', '-data', '-public',
        '-private', '-logs', '-www', '-web', '-site', '-cdn',
        '-images', '-img', '-docs', '-content',
    ];

    private const MAX_TIME_SECONDS = 25; // Time budget

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = strtolower(trim($queryValue));

        // Strip TLD for base name
        $baseName = preg_replace('/\.(com|net|org|io|co|dev|app|xyz|info|biz)$/i', '', $domain);
        $baseName = str_replace('.', '-', $baseName);

        // Build all URLs to check
        $urls = [];
        foreach (self::SUFFIXES as $suffix) {
            $bucketName = $baseName . $suffix;
            $url = "https://{$bucketName}.s3.amazonaws.com";
            $urls[] = ['url' => $url, 'bucket' => $bucketName];
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
                $found[] = ['bucket' => $item['bucket'], 'url' => $item['url'], 'status' => 'public', 'http' => 200];
            } elseif ($httpCode === 403) {
                $found[] = ['bucket' => $item['bucket'], 'url' => $item['url'], 'status' => 'exists_private', 'http' => 403];
            }
            // 404 = doesn't exist, skip
        }

        curl_multi_close($mh);
        $ms = (int)((microtime(true) - $start) * 1000);

        $foundCount = count($found);
        if ($foundCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 60,
                responseMs: $ms,
                summary: "Domain {$domain}: No S3 buckets found among {$checked} name variations.",
                tags: [self::API_ID, 'domain', 's3', 'clean'],
                rawData: ['found' => [], 'checked' => $checked],
                success: true
            );
        }

        $publicBuckets = array_filter($found, function($b) { return $b['status'] === 'public'; });
        $privateBuckets = array_filter($found, function($b) { return $b['status'] === 'exists_private'; });
        $publicCount = count($publicBuckets);
        $privateCount = count($privateBuckets);

        $parts = ["Domain {$domain}: {$foundCount} S3 bucket(s) found"];
        if ($publicCount > 0) {
            $names = array_map(function($b) { return $b['bucket']; }, $publicBuckets);
            $parts[] = "PUBLIC ({$publicCount}): " . implode(', ', $names);
        }
        if ($privateCount > 0) {
            $names = array_map(function($b) { return $b['bucket']; }, $privateBuckets);
            $parts[] = "Private ({$privateCount}): " . implode(', ', $names);
        }

        $score = 0;
        if ($publicCount > 0) {
            $score = 70; // Public buckets are high risk
        } elseif ($privateCount > 0) {
            $score = 20; // Private buckets existing is informational
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 80;
        $tags = [self::API_ID, 'domain', 's3', 'cloud'];
        if ($publicCount > 0) {
            $tags[] = 'public_bucket';
            $tags[] = 'misconfigured';
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
                'private_count' => $privateCount,
                'checked' => $checked,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $ch = curl_init('https://s3.amazonaws.com');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_NOBODY => true, CURLOPT_SSL_VERIFYPEER => false]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($code > 0) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => 'S3 endpoint unreachable'];
    }
}
