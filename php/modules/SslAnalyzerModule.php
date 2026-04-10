<?php
// =============================================================================
//  CTI — SSL Certificate Analyzer Module
//  Uses PHP's stream_socket_client + openssl to inspect certificates.
//  No external API. Supports: domain
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SslAnalyzerModule extends BaseApiModule
{
    private const API_ID   = 'ssl-analyzer';
    private const API_NAME = 'SSL Certificate Analyzer';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
            ]
        ]);

        $host = $queryValue;
        $errno = 0;
        $errstr = '';

        $client = @stream_socket_client(
            "ssl://{$host}:443",
            $errno, $errstr, 10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        $ms = (int)((microtime(true) - $start) * 1000);

        if (!$client) {
            return OsintResult::error(self::API_ID, self::API_NAME, "SSL connection failed: {$errstr}", $ms);
        }

        $params = stream_context_get_params($client);
        fclose($client);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'No certificate received', $ms);
        }

        $certData = openssl_x509_parse($cert);
        if (!$certData) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Failed to parse certificate', $ms);
        }

        $subject   = $certData['subject']['CN'] ?? 'Unknown';
        $issuer    = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Unknown');
        $validFrom = $certData['validFrom_time_t'] ?? 0;
        $validTo   = $certData['validTo_time_t'] ?? 0;
        $serial    = $certData['serialNumber'] ?? '';
        $sigAlgo   = $certData['signatureTypeSN'] ?? '';

        $now = time();
        $daysLeft = $validTo > 0 ? (int)(($validTo - $now) / 86400) : 0;
        $isExpired = $validTo < $now;
        $isExpiringSoon = $daysLeft < 30 && $daysLeft >= 0;

        // SAN (Subject Alternative Names)
        $san = [];
        if (isset($certData['extensions']['subjectAltName'])) {
            $sanStr = $certData['extensions']['subjectAltName'];
            preg_match_all('/DNS:([^,\s]+)/', $sanStr, $matches);
            $san = $matches[1] ?? [];
        }

        // Score
        $score = 0;
        $issues = [];
        if ($isExpired) {
            $score = 70;
            $issues[] = 'EXPIRED';
        } elseif ($isExpiringSoon) {
            $score = 40;
            $issues[] = "expires in {$daysLeft} days";
        }
        // Self-signed check
        if ($subject === ($certData['issuer']['CN'] ?? '')) {
            $score = max($score, 50);
            $issues[] = 'self-signed';
        }
        // Weak signature
        if (stripos($sigAlgo, 'sha1') !== false || stripos($sigAlgo, 'md5') !== false) {
            $score = max($score, 45);
            $issues[] = "weak signature ({$sigAlgo})";
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 95;

        $parts = ["Domain {$queryValue}: SSL cert for {$subject}"];
        $parts[] = "Issuer: {$issuer}";
        $parts[] = "Valid: " . date('Y-m-d', $validFrom) . " to " . date('Y-m-d', $validTo) . " ({$daysLeft} days remaining)";
        $parts[] = "Algorithm: {$sigAlgo}";
        if (count($san) > 0) $parts[] = count($san) . " SAN(s)";
        if (!empty($issues)) $parts[] = "Issues: " . implode(', ', $issues);

        $tags = [self::API_ID, 'domain', 'ssl', 'certificate'];
        if ($isExpired) $tags[] = 'expired_cert';
        if ($isExpiringSoon) $tags[] = 'expiring_soon';
        if (empty($issues)) $tags[] = 'clean';
        else $tags[] = 'misconfigured';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'subject' => $subject, 'issuer' => $issuer,
                'valid_from' => date('c', $validFrom), 'valid_to' => date('c', $validTo),
                'days_remaining' => $daysLeft, 'sig_algorithm' => $sigAlgo,
                'san_count' => count($san), 'san' => array_slice($san, 0, 20),
                'serial' => $serial, 'issues' => $issues
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false]]);
        $c = @stream_socket_client("ssl://google.com:443", $e, $es, 5, STREAM_CLIENT_CONNECT, $ctx);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($c) { fclose($c); return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null]; }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $es];
    }
}
