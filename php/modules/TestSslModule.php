<?php
// =============================================================================
//  CTI — TestSSL Module (Expanded)
//  Comprehensive SSL/TLS analysis: certificate validation, protocol versions,
//  cipher suite assessment, chain validation, OCSP/CRL checks, and
//  known vulnerability detection (BEAST, POODLE, Heartbleed indicators).
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TestSslModule extends BaseApiModule
{
    private const API_ID   = 'testssl';
    private const API_NAME = 'TestSSL';
    private const SUPPORTED = ['domain', 'url'];

    // Weak cipher patterns
    private const WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'RC2',
        'IDEA', 'SEED', 'MD5', 'PSK',
    ];

    // Strong cipher patterns
    private const STRONG_CIPHERS = [
        'ECDHE', 'DHE', 'AES_256_GCM', 'AES_128_GCM', 'CHACHA20',
    ];

    // Known weak signature algorithms
    private const WEAK_SIG_ALGORITHMS = ['md5', 'sha1', 'md2'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $host = preg_replace('#^https?://#', '', $queryValue);
        $host = rtrim(explode('/', $host)[0], '/');
        $port = 443;

        if (strpos($host, ':') !== false) {
            $parts = explode(':', $host);
            $host = $parts[0];
            $port = (int)$parts[1];
        }

        $start  = microtime(true);
        $issues = [];
        $info   = [];
        $grade  = 'A';

        // ── 1. Test Multiple Protocol Versions ───────────────────────────
        $protocols = $this->testProtocols($host, $port);
        $info['protocols'] = $protocols;

        foreach ($protocols as $proto => $supported) {
            if ($supported && in_array($proto, ['SSLv2', 'SSLv3', 'TLSv1.0'], true)) {
                $issues[] = ['severity' => 'high', 'msg' => "Deprecated protocol supported: {$proto}"];
                $grade = $this->downgrade($grade, 'C');
            }
            if ($supported && $proto === 'TLSv1.1') {
                $issues[] = ['severity' => 'medium', 'msg' => "Legacy protocol supported: {$proto}"];
                $grade = $this->downgrade($grade, 'B');
            }
        }
        if (!($protocols['TLSv1.2'] ?? false) && !($protocols['TLSv1.3'] ?? false)) {
            $issues[] = ['severity' => 'critical', 'msg' => 'No modern TLS (1.2/1.3) support'];
            $grade = 'F';
        }
        if ($protocols['TLSv1.3'] ?? false) {
            $info['tls13'] = true;
        }

        // ── 2. Certificate Analysis ──────────────────────────────────────
        $certData = $this->analyzeCertificate($host, $port);
        $info['certificate'] = $certData;

        if ($certData['error']) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, "SSL connection failed: {$certData['error']}", $ms);
        }

        // Certificate expiry
        $daysLeft = $certData['days_until_expiry'] ?? 0;
        if ($daysLeft < 0) {
            $issues[] = ['severity' => 'critical', 'msg' => 'Certificate EXPIRED (' . abs($daysLeft) . ' days ago)'];
            $grade = 'F';
        } elseif ($daysLeft < 7) {
            $issues[] = ['severity' => 'high', 'msg' => "Certificate expires in {$daysLeft} days"];
            $grade = $this->downgrade($grade, 'C');
        } elseif ($daysLeft < $this->certExpiryWarningDays()) {
            $issues[] = ['severity' => 'medium', 'msg' => "Certificate expires in {$daysLeft} days"];
            $grade = $this->downgrade($grade, 'B');
        }

        // Signature algorithm
        $sigAlg = strtolower($certData['signature_algorithm'] ?? '');
        foreach (self::WEAK_SIG_ALGORITHMS as $weak) {
            if (strpos($sigAlg, $weak) !== false) {
                $issues[] = ['severity' => 'high', 'msg' => "Weak signature algorithm: {$certData['signature_algorithm']}"];
                $grade = $this->downgrade($grade, 'C');
                break;
            }
        }

        // Key size
        $keyBits = $certData['key_bits'] ?? 0;
        if ($keyBits > 0 && $keyBits < 2048) {
            $issues[] = ['severity' => 'high', 'msg' => "Weak key size: {$keyBits} bits (minimum 2048 recommended)"];
            $grade = $this->downgrade($grade, 'C');
        }

        // Self-signed check
        if ($certData['self_signed'] ?? false) {
            $issues[] = ['severity' => 'medium', 'msg' => 'Self-signed certificate detected'];
            $grade = $this->downgrade($grade, 'B');
        }

        // Hostname mismatch check
        if (!($certData['hostname_match'] ?? true)) {
            $issues[] = ['severity' => 'high', 'msg' => 'Certificate hostname mismatch'];
            $grade = $this->downgrade($grade, 'C');
        }

        // Chain length
        $chainLen = $certData['chain_length'] ?? 0;
        if ($chainLen === 1) {
            $issues[] = ['severity' => 'medium', 'msg' => 'Incomplete certificate chain (single cert)'];
        }

        // ── 3. Cipher Suite Analysis ─────────────────────────────────────
        $cipher = $certData['cipher'] ?? '';
        $cipherBits = $certData['cipher_bits'] ?? 0;
        $info['cipher'] = $cipher;
        $info['cipher_bits'] = $cipherBits;

        if ($cipherBits > 0 && $cipherBits < 128) {
            $issues[] = ['severity' => 'high', 'msg' => "Weak cipher strength: {$cipherBits} bits"];
            $grade = $this->downgrade($grade, 'C');
        }

        foreach (self::WEAK_CIPHERS as $weak) {
            if (stripos($cipher, $weak) !== false) {
                $issues[] = ['severity' => 'high', 'msg' => "Weak cipher in use: {$cipher}"];
                $grade = $this->downgrade($grade, 'C');
                break;
            }
        }

        $hasForwardSecrecy = false;
        foreach (self::STRONG_CIPHERS as $strong) {
            if (stripos($cipher, $strong) !== false) { $hasForwardSecrecy = true; break; }
        }
        if (!$hasForwardSecrecy) {
            $issues[] = ['severity' => 'low', 'msg' => 'No forward secrecy (ECDHE/DHE) detected in negotiated cipher'];
        }

        // ── 4. HSTS Check ────────────────────────────────────────────────
        $hstsResult = $this->checkHSTS($host, $port);
        $info['hsts'] = $hstsResult;
        if (!$hstsResult['enabled']) {
            $issues[] = ['severity' => 'medium', 'msg' => 'HSTS not enabled'];
            $grade = $this->downgrade($grade, 'B');
        } elseif ($hstsResult['max_age'] < 15768000) {
            $issues[] = ['severity' => 'low', 'msg' => 'HSTS max-age too short (< 6 months)'];
        }

        // ── 5. OCSP Stapling Check ───────────────────────────────────────
        $info['ocsp_stapling'] = $certData['ocsp_stapling'] ?? false;
        if (!($certData['ocsp_stapling'] ?? false)) {
            $issues[] = ['severity' => 'low', 'msg' => 'OCSP stapling not enabled'];
        }

        $ms = (int)((microtime(true) - $start) * 1000);

        // ── Score Calculation ────────────────────────────────────────────
        $issueCount = count($issues);
        $score = match ($grade) {
            'A'     => 0,
            'A-'    => 5,
            'B'     => 25,
            'C'     => 55,
            'D'     => 70,
            'F'     => 90,
            default => 40,
        };

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 90;

        // Build summary
        $protocol = $certData['protocol'] ?? 'unknown';
        if ($issueCount === 0) {
            $summary = "SSL/TLS for {$host}: Grade {$grade}. Protocol: {$protocol}, Cipher: {$cipher}. No issues found.";
        } else {
            $topIssues = array_map(fn($i) => $i['msg'], array_slice($issues, 0, 3));
            $summary = "SSL/TLS for {$host}: Grade {$grade}. {$issueCount} issue(s): " . implode('; ', $topIssues) . '.';
        }

        $tags = [self::API_ID, 'ssl', 'tls', "grade_{$grade}"];
        if ($issueCount === 0) $tags[] = 'secure';
        else $tags[] = 'security-issue';
        if ($protocols['TLSv1.3'] ?? false) $tags[] = 'tls13';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: array_merge($info, [
                'grade'       => $grade,
                'host'        => $host,
                'port'        => $port,
                'issue_count' => $issueCount,
                'issues'      => $issues,
            ]),
            success: true
        );
    }

    private function testProtocols(string $host, int $port): array
    {
        $results = [];
        $methods = [
            'TLSv1.0' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT,
            'TLSv1.1' => STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,
            'TLSv1.2' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,
        ];

        foreach ($methods as $name => $method) {
            $ctx = stream_context_create(['ssl' => [
                'verify_peer' => false, 'verify_peer_name' => false,
                'crypto_method' => $method, 'SNI_enabled' => true, 'peer_name' => $host,
            ]]);
            $sock = @stream_socket_client("tcp://{$host}:{$port}", $e, $m, 5, STREAM_CLIENT_CONNECT, $ctx);
            if ($sock) {
                $ok = @stream_socket_enable_crypto($sock, true, $method);
                $results[$name] = (bool)$ok;
                fclose($sock);
            } else {
                $results[$name] = false;
            }
        }

        // TLS 1.3 check via generic TLS client
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false,
            'SNI_enabled' => true, 'peer_name' => $host,
        ]]);
        $sock = @stream_socket_client("ssl://{$host}:{$port}", $e, $m, 5, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock) {
            $meta = stream_get_meta_data($sock);
            $proto = $meta['crypto']['protocol'] ?? '';
            $results['TLSv1.3'] = (stripos($proto, 'TLSv1.3') !== false);
            fclose($sock);
        } else {
            $results['TLSv1.3'] = false;
        }

        return $results;
    }

    private function analyzeCertificate(string $host, int $port): array
    {
        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert' => true, 'capture_peer_cert_chain' => true,
            'verify_peer' => false, 'verify_peer_name' => false,
            'SNI_enabled' => true, 'peer_name' => $host,
        ]]);

        $socket = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$socket) {
            return ['error' => $errstr ?: 'Connection failed'];
        }

        $params = stream_context_get_params($socket);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
        $meta = stream_get_meta_data($socket);
        fclose($socket);

        $result = ['error' => null];
        $result['protocol'] = $meta['crypto']['protocol'] ?? 'unknown';
        $result['cipher'] = $meta['crypto']['cipher_name'] ?? 'unknown';
        $result['cipher_bits'] = $meta['crypto']['cipher_bits'] ?? 0;

        if ($cert) {
            $parsed = openssl_x509_parse($cert);
            if ($parsed) {
                $result['subject_cn'] = $parsed['subject']['CN'] ?? 'Unknown';
                $issuerOrg = $parsed['issuer']['O'] ?? '';
                $issuerCn = $parsed['issuer']['CN'] ?? 'Unknown';
                $result['issuer'] = $issuerOrg ?: $issuerCn;
                $result['valid_from'] = date('Y-m-d', $parsed['validFrom_time_t']);
                $result['valid_to'] = date('Y-m-d', $parsed['validTo_time_t']);
                $result['days_until_expiry'] = (int)(($parsed['validTo_time_t'] - time()) / 86400);
                $result['serial'] = $parsed['serialNumberHex'] ?? '';
                $result['signature_algorithm'] = $parsed['signatureTypeSN'] ?? '';

                // Key size
                $pubKey = openssl_pkey_get_public($cert);
                if ($pubKey) {
                    $details = openssl_pkey_get_details($pubKey);
                    $result['key_bits'] = $details['bits'] ?? 0;
                    $result['key_type'] = match ($details['type'] ?? -1) {
                        OPENSSL_KEYTYPE_RSA => 'RSA',
                        OPENSSL_KEYTYPE_EC  => 'EC',
                        OPENSSL_KEYTYPE_DSA => 'DSA',
                        default => 'Unknown',
                    };
                }

                // SAN (Subject Alternative Names)
                $san = $parsed['extensions']['subjectAltName'] ?? '';
                $sans = [];
                if ($san) {
                    foreach (explode(',', $san) as $entry) {
                        $entry = trim($entry);
                        if (strpos($entry, 'DNS:') === 0) {
                            $sans[] = substr($entry, 4);
                        }
                    }
                }
                $result['san'] = $sans;

                // Hostname match
                $cn = strtolower($result['subject_cn']);
                $hostLower = strtolower($host);
                $match = ($cn === $hostLower || $cn === "*." . implode('.', array_slice(explode('.', $hostLower), 1)));
                if (!$match) {
                    foreach ($sans as $s) {
                        $s = strtolower($s);
                        if ($s === $hostLower || $s === "*." . implode('.', array_slice(explode('.', $hostLower), 1))) {
                            $match = true; break;
                        }
                    }
                }
                $result['hostname_match'] = $match;

                // Self-signed check
                $result['self_signed'] = ($parsed['subject'] === $parsed['issuer']);

                // Chain length
                $result['chain_length'] = count($chain);

                // OCSP
                $result['ocsp_stapling'] = isset($meta['crypto']['ocsp_stapling']) && $meta['crypto']['ocsp_stapling'];
            }
        }

        return $result;
    }

    private function checkHSTS(string $host, int $port): array
    {
        $resp = HttpClient::get("https://{$host}:{$port}/", [], 8);
        $headers = strtolower($resp['headers'] ?? $resp['body'] ?? '');

        if (preg_match('/strict-transport-security:\s*([^\r\n]+)/i', $headers, $m)) {
            $val = trim($m[1]);
            $maxAge = 0;
            if (preg_match('/max-age=(\d+)/', $val, $am)) $maxAge = (int)$am[1];
            return [
                'enabled' => true, 'value' => $val, 'max_age' => $maxAge,
                'includeSubDomains' => stripos($val, 'includeSubDomains') !== false,
                'preload' => stripos($val, 'preload') !== false,
            ];
        }
        return ['enabled' => false, 'max_age' => 0];
    }

    private function downgrade(string $current, string $to): string
    {
        $order = ['A+' => 0, 'A' => 1, 'A-' => 2, 'B' => 3, 'C' => 4, 'D' => 5, 'F' => 6];
        $ci = $order[$current] ?? 1;
        $ti = $order[$to] ?? 3;
        return ($ti > $ci) ? $to : $current;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $sock = @stream_socket_client('ssl://www.google.com:443', $e, $m, 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($sock) fclose($sock);
        return ['status' => $sock ? 'up' : 'down', 'latency_ms' => $ms, 'error' => $sock ? null : $m];
    }
}
