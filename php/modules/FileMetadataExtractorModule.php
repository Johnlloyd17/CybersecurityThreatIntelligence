<?php
// =============================================================================
//  CTI — File Metadata Extractor Module
//  For URLs: fetch HTTP headers (Content-Type, Content-Length, etc.).
//  For hashes: query MalwareBazaar for file metadata.
//  Supports: url, hash, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FileMetadataExtractorModule extends BaseApiModule
{
    private const API_ID   = 'file-metadata-extractor';
    private const API_NAME = 'File Metadata Extractor';
    private const SUPPORTED = ['url', 'hash', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        try {
            if ($queryType === 'hash') {
                return $this->analyzeHash($value, $start);
            }
            return $this->analyzeUrl($queryType, $value, $start);
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    private function analyzeHash(string $hash, float $start): OsintResult
    {
        $resp = HttpClient::post(
            'https://mb-api.abuse.ch/api/v1/',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            http_build_query(['query' => 'get_info', 'hash' => $hash]),
            20
        );

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'], $ms);
        }

        $json = $resp['json'];
        $queryStatus = isset($json['query_status']) ? $json['query_status'] : 'unknown';

        if ($queryStatus !== 'ok' || empty($json['data'])) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $hash, $ms);
        }

        $data = $json['data'][0];
        $metadata = [
            'file_name'      => isset($data['file_name']) ? $data['file_name'] : 'unknown',
            'file_type'      => isset($data['file_type']) ? $data['file_type'] : 'unknown',
            'file_type_mime' => isset($data['file_type_mime']) ? $data['file_type_mime'] : 'unknown',
            'file_size'      => isset($data['file_size']) ? $data['file_size'] : 0,
            'sha256_hash'    => isset($data['sha256_hash']) ? $data['sha256_hash'] : '',
            'sha1_hash'      => isset($data['sha1_hash']) ? $data['sha1_hash'] : '',
            'md5_hash'       => isset($data['md5_hash']) ? $data['md5_hash'] : '',
            'first_seen'     => isset($data['first_seen']) ? $data['first_seen'] : '',
            'last_seen'      => isset($data['last_seen']) ? $data['last_seen'] : '',
            'signature'      => isset($data['signature']) ? $data['signature'] : 'none',
            'reporter'       => isset($data['reporter']) ? $data['reporter'] : '',
            'tags'           => isset($data['tags']) ? $data['tags'] : [],
        ];

        $fileName = $metadata['file_name'];
        $fileType = $metadata['file_type'];
        $fileSize = $metadata['file_size'];
        $signature = $metadata['signature'];

        $score = 65; // Known malware sample
        if ($signature && $signature !== 'none') {
            $score = 80;
        }
        $severity = OsintResult::scoreToSeverity($score);

        $summaryParts = [];
        $summaryParts[] = "File: {$fileName} ({$fileType}, {$fileSize} bytes)";
        if ($signature !== 'none') {
            $summaryParts[] = "Malware signature: {$signature}";
        }
        $firstSeen = $metadata['first_seen'];
        if ($firstSeen) {
            $summaryParts[] = "First seen: {$firstSeen}";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $ms,
            summary: implode('. ', $summaryParts) . '.',
            tags: array_values(array_unique(array_merge(
                [self::API_ID, 'hash', 'malware_bazaar', 'file_metadata'],
                is_array($metadata['tags']) ? $metadata['tags'] : []
            ))),
            rawData: $metadata,
            success: true
        );
    }

    private function analyzeUrl(string $queryType, string $value, float $start): OsintResult
    {
        $url = $value;
        if ($queryType === 'domain') {
            $url = 'https://' . $value;
        }
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }

        // Fetch with GET to capture headers (HttpClient follows redirects)
        $resp = HttpClient::get($url, [], 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'], $ms);
        }

        // Parse response headers from body using a secondary cURL call with HEADER option
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => 'CTI-Platform/1.0',
        ]);
        $headerResponse = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $headerLines = preg_split('/\r?\n/', $headerResponse);
        $headers = [];
        foreach ($headerLines as $line) {
            if (strpos($line, ':') !== false) {
                $parts = explode(':', $line, 2);
                $headerName = trim($parts[0]);
                $headerValue = trim($parts[1]);
                $headers[strtolower($headerName)] = $headerValue;
            }
        }

        $metadata = [
            'url'              => $url,
            'http_status'      => $httpCode,
            'content_type'     => isset($headers['content-type']) ? $headers['content-type'] : 'unknown',
            'content_length'   => isset($headers['content-length']) ? $headers['content-length'] : 'unknown',
            'server'           => isset($headers['server']) ? $headers['server'] : 'unknown',
            'last_modified'    => isset($headers['last-modified']) ? $headers['last-modified'] : 'unknown',
            'etag'             => isset($headers['etag']) ? $headers['etag'] : 'none',
            'x_powered_by'    => isset($headers['x-powered-by']) ? $headers['x-powered-by'] : 'none',
            'cache_control'    => isset($headers['cache-control']) ? $headers['cache-control'] : 'none',
        ];

        $score = 0;
        $findings = [];

        // Check for server version disclosure
        $server = $metadata['server'];
        if ($server !== 'unknown' && preg_match('/[\d]+\.[\d]+/', $server)) {
            $score = max($score, 20);
            $findings[] = 'Server version disclosed';
        }

        // Check for X-Powered-By disclosure
        $poweredBy = $metadata['x_powered_by'];
        if ($poweredBy !== 'none') {
            $score = max($score, 25);
            $findings[] = "X-Powered-By header exposed: {$poweredBy}";
        }

        $severity = OsintResult::scoreToSeverity($score);

        $contentType = $metadata['content_type'];
        $contentLength = $metadata['content_length'];
        $summaryParts = [];
        $summaryParts[] = "HTTP {$httpCode}, Content-Type: {$contentType}, Size: {$contentLength}";
        $summaryParts[] = "Server: {$server}";
        if (!empty($findings)) {
            $summaryParts[] = implode('; ', $findings);
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $ms,
            summary: implode('. ', $summaryParts) . '.',
            tags: array_values(array_unique([self::API_ID, $queryType, 'http_headers', 'file_metadata'])),
            rawData: $metadata,
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
