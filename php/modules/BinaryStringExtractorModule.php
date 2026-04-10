<?php
// =============================================================================
//  CTI — Binary String Extractor Module
//  For hash queries: fetch file from MalwareBazaar and extract printable strings.
//  For URLs/domains: fetch page content and extract embedded base64/hex strings.
//  Supports: hash, url, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BinaryStringExtractorModule extends BaseApiModule
{
    private const API_ID   = 'binary-string-extractor';
    private const API_NAME = 'Binary String Extractor';
    private const SUPPORTED = ['hash', 'url', 'domain'];

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
            return $this->analyzeWebContent($queryType, $value, $start);
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    private function analyzeHash(string $hash, float $start): OsintResult
    {
        // Query MalwareBazaar for file info
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
        $fileName = isset($data['file_name']) ? $data['file_name'] : 'unknown';
        $fileType = isset($data['file_type']) ? $data['file_type'] : 'unknown';
        $fileSize = isset($data['file_size']) ? $data['file_size'] : 0;
        $tags = isset($data['tags']) ? $data['tags'] : [];
        $signature = isset($data['signature']) ? $data['signature'] : 'none';

        // Extract interesting strings from available metadata
        $strings = [];
        $this->extractPrintableStrings($fileName, $strings);
        if ($signature && $signature !== 'none') {
            $this->extractPrintableStrings($signature, $strings);
        }
        if (is_array($tags)) {
            foreach ($tags as $tag) {
                $this->extractPrintableStrings($tag, $strings);
            }
        }

        $stringCount = count($strings);
        $score = 0;
        if ($queryStatus === 'ok') {
            $score = 60; // Known to MalwareBazaar = suspicious
        }
        foreach ($strings as $s) {
            $lower = strtolower($s);
            if (preg_match('/password|secret|key|token|admin|exec|eval|cmd|shell/i', $lower)) {
                $score = max($score, 75);
            }
        }

        $severity = OsintResult::scoreToSeverity($score);
        $summaryParts = [];
        $summaryParts[] = "File '{$fileName}' ({$fileType}, {$fileSize} bytes) found in MalwareBazaar";
        $summaryParts[] = "Signature: {$signature}";
        if ($stringCount > 0) {
            $summaryParts[] = "{$stringCount} interesting string(s) extracted";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 70,
            responseMs: $ms,
            summary: implode('. ', $summaryParts) . '.',
            tags: array_values(array_unique(array_merge(
                [self::API_ID, 'hash', 'malware_bazaar'],
                is_array($tags) ? $tags : []
            ))),
            rawData: [
                'file_name' => $fileName,
                'file_type' => $fileType,
                'file_size' => $fileSize,
                'signature' => $signature,
                'malware_tags' => $tags,
                'extracted_strings' => array_slice($strings, 0, 100),
            ],
            success: true
        );
    }

    private function analyzeWebContent(string $queryType, string $value, float $start): OsintResult
    {
        $url = $value;
        if ($queryType === 'domain') {
            $url = 'https://' . $value;
        }
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }

        $resp = HttpClient::get($url, [], 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'], $ms);
        }
        if ($resp['status'] >= 400) {
            $status = $resp['status'];
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$status} fetching target", $ms);
        }

        $body = $resp['body'];
        $findings = [];

        // Extract base64 strings (at least 16 chars)
        if (preg_match_all('/[A-Za-z0-9+\/]{16,}={0,2}/', $body, $matches)) {
            foreach ($matches[0] as $candidate) {
                $decoded = base64_decode($candidate, true);
                if ($decoded !== false && strlen($decoded) >= 4) {
                    $findings[] = [
                        'type' => 'base64',
                        'encoded' => mb_substr($candidate, 0, 80),
                        'decoded_preview' => mb_substr($decoded, 0, 80),
                    ];
                }
            }
        }

        // Extract hex-encoded strings (at least 16 hex chars)
        if (preg_match_all('/(?:0x)?([0-9a-fA-F]{16,})/', $body, $matches)) {
            foreach ($matches[1] as $hexStr) {
                $decoded = @hex2bin($hexStr);
                if ($decoded !== false && strlen($decoded) >= 4) {
                    $printable = preg_replace('/[^\x20-\x7E]/', '.', $decoded);
                    $findings[] = [
                        'type' => 'hex',
                        'hex' => mb_substr($hexStr, 0, 80),
                        'decoded_preview' => mb_substr($printable, 0, 80),
                    ];
                }
            }
        }

        // Extract printable strings from the body (unusual patterns)
        $printableStrings = [];
        $this->extractPrintableStrings($body, $printableStrings);

        $findingCount = count($findings);
        $uniqueStrings = count(array_unique($printableStrings));

        $score = 0;
        if ($findingCount > 0) {
            $score = min(10 + ($findingCount * 5), 60);
        }
        // Check for suspicious decoded content
        foreach ($findings as $f) {
            $preview = isset($f['decoded_preview']) ? strtolower($f['decoded_preview']) : '';
            if (preg_match('/password|secret|token|key|admin|exec|eval|shell/', $preview)) {
                $score = max($score, 70);
            }
        }

        $severity = OsintResult::scoreToSeverity($score);
        $summaryParts = [];
        $summaryParts[] = "{$findingCount} encoded string(s) found";
        $summaryParts[] = "{$uniqueStrings} unique printable string pattern(s) detected";

        $resultTags = [self::API_ID, $queryType, 'string_extraction'];
        if ($findingCount > 0) {
            $resultTags[] = 'encoded_content';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 60,
            responseMs: $ms,
            summary: implode('. ', $summaryParts) . '.',
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'encoded_findings' => array_slice($findings, 0, 50),
                'printable_strings_count' => $uniqueStrings,
                'printable_strings_sample' => array_slice($printableStrings, 0, 30),
            ],
            success: true
        );
    }

    private function extractPrintableStrings(string $data, array &$results): void
    {
        // Find sequences of printable ASCII chars >= 4 characters
        if (preg_match_all('/[\x20-\x7E]{4,}/', $data, $matches)) {
            foreach ($matches[0] as $str) {
                $trimmed = trim($str);
                if (strlen($trimmed) >= 4) {
                    $results[] = $trimmed;
                }
            }
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
