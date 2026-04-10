<?php
// =============================================================================
//  CTI — DNS Look-aside Module
//  Internal tool (no external API). Supports: domain
//  Performs additional DNS lookups for security-related records:
//  DNSKEY, CAA, TLSA using dns_get_record()
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsLookasideModule extends BaseApiModule
{
    private const API_ID   = 'dns-lookaside';
    private const API_NAME = 'DNS Look-aside';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);
        $findings = [];
        $securityFeatures = [];

        // 1. Check CAA records (Certificate Authority Authorization)
        try {
            $caaRecords = @dns_get_record($queryValue, DNS_CAA);
            if ($caaRecords && count($caaRecords) > 0) {
                $caaEntries = [];
                foreach ($caaRecords as $rec) {
                    $tag   = isset($rec['tag']) ? $rec['tag'] : '';
                    $value = isset($rec['value']) ? $rec['value'] : '';
                    if ($tag && $value) {
                        $caaEntries[] = "{$tag}={$value}";
                    }
                }
                $findings['CAA'] = $caaRecords;
                $securityFeatures[] = 'CAA (' . implode(', ', $caaEntries) . ')';
            }
        } catch (\Exception $e) {
            // CAA lookup failed, continue
        }

        // 2. Check for DNSKEY records (DNSSEC)
        try {
            // dns_get_record does not directly support DNSKEY on all platforms,
            // try using DNS_ANY to catch it
            $anyRecords = @dns_get_record($queryValue, DNS_ANY);
            if ($anyRecords) {
                foreach ($anyRecords as $rec) {
                    $type = isset($rec['type']) ? $rec['type'] : '';
                    if ($type === 'DNSKEY' || $type === 'RRSIG' || $type === 'DS') {
                        if (!isset($findings['DNSSEC'])) {
                            $findings['DNSSEC'] = [];
                        }
                        $findings['DNSSEC'][] = $rec;
                        if (!in_array('DNSSEC', $securityFeatures, true)) {
                            $securityFeatures[] = 'DNSSEC';
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            // DNSKEY lookup failed, continue
        }

        // 3. Check for TLSA records (DANE - DNS-based Authentication of Named Entities)
        // TLSA records are at _port._proto.domain
        $tlsaPrefixes = ['_443._tcp', '_25._tcp', '_993._tcp'];
        foreach ($tlsaPrefixes as $prefix) {
            $tlsaDomain = $prefix . '.' . $queryValue;
            try {
                $tlsaRecords = @dns_get_record($tlsaDomain, DNS_ANY);
                if ($tlsaRecords && count($tlsaRecords) > 0) {
                    foreach ($tlsaRecords as $rec) {
                        $type = isset($rec['type']) ? $rec['type'] : '';
                        if ($type === 'TLSA') {
                            if (!isset($findings['TLSA'])) {
                                $findings['TLSA'] = [];
                            }
                            $findings['TLSA'][] = $rec;
                            if (!in_array('DANE/TLSA', $securityFeatures, true)) {
                                $securityFeatures[] = 'DANE/TLSA';
                            }
                        }
                    }
                }
            } catch (\Exception $e) {
                // TLSA lookup failed, continue
            }
        }

        // 4. Check TXT records for security policies (SPF, DMARC, DKIM hints)
        try {
            $txtRecords = @dns_get_record($queryValue, DNS_TXT);
            if ($txtRecords) {
                foreach ($txtRecords as $rec) {
                    $txt = isset($rec['txt']) ? $rec['txt'] : '';
                    if (stripos($txt, 'v=spf') === 0) {
                        $findings['SPF'] = $txt;
                        $securityFeatures[] = 'SPF';
                    }
                }
            }

            // Check _dmarc subdomain
            $dmarcRecords = @dns_get_record('_dmarc.' . $queryValue, DNS_TXT);
            if ($dmarcRecords) {
                foreach ($dmarcRecords as $rec) {
                    $txt = isset($rec['txt']) ? $rec['txt'] : '';
                    if (stripos($txt, 'v=DMARC') === 0) {
                        $findings['DMARC'] = $txt;
                        $securityFeatures[] = 'DMARC';
                    }
                }
            }
        } catch (\Exception $e) {
            // TXT lookup failed, continue
        }

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);

        $featureCount = count($securityFeatures);

        if ($featureCount === 0) {
            // No security records found — this is noteworthy
            $score = 15;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 70;

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: $confidence,
                responseMs: $elapsedMs,
                summary: "Domain {$queryValue}: No security-related DNS records found (no CAA, DNSSEC, DANE/TLSA, SPF, or DMARC).",
                tags: [self::API_ID, 'domain', 'dns', 'security', 'no_security_records'],
                rawData: ['findings' => $findings, 'security_features' => $securityFeatures],
                success: true
            );
        }

        // More security features = better security posture = lower threat score
        $score = max(0, 15 - ($featureCount * 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 70 + $featureCount * 5);

        $parts = ["Domain {$queryValue}: {$featureCount} security DNS feature(s) detected"];
        $parts[] = "Features: " . implode(', ', $securityFeatures);

        $tags = [self::API_ID, 'domain', 'dns', 'security'];
        foreach ($securityFeatures as $feat) {
            $tags[] = strtolower(str_replace(['/', ' '], '_', $feat));
        }
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['findings' => $findings, 'security_features' => $securityFeatures],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $startTime = microtime(true);
        try {
            $records = @dns_get_record('google.com', DNS_A);
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            if ($records && count($records) > 0) {
                return ['status' => 'healthy', 'latency_ms' => $elapsedMs, 'error' => null];
            }
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => 'DNS resolution failed'];
        } catch (\Exception $e) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => $e->getMessage()];
        }
    }
}
