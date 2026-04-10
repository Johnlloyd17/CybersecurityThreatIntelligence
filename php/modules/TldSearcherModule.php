<?php
// =============================================================================
//  CTI — TLD Searcher Module
//  Internal tool (no external API). Supports: domain
//  Extracts base domain name and checks availability across common TLDs
//  using dns_get_record()
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/BaseApiModule.php';

class TldSearcherModule extends BaseApiModule
{
    private const API_ID   = 'tld-searcher';
    private const API_NAME = 'TLD Searcher';
    private const SUPPORTED = ['domain'];

    private const DEFAULT_CHECK_TLDS = ['.com', '.net', '.org', '.io', '.co', '.info', '.biz'];
    private const PRIORITY_TLDS = ['.com', '.net', '.org', '.io', '.co', '.info', '.biz', '.app', '.dev', '.ai', '.xyz'];
    private const MAX_TLDS_TO_CHECK = 40;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);

        // Extract base domain name (strip TLD)
        $parts = explode('.', $queryValue);
        if (count($parts) < 2) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, "Invalid domain format: {$queryValue}", $elapsedMs);
        }

        // Get base name (everything before the TLD)
        // For "example.co.uk" we want "example", for "sub.example.com" we want "example"
        $baseName = $parts[0];
        if (count($parts) > 2) {
            // Use the second-to-last part as the probable domain name
            $baseName = $parts[count($parts) - 2];
        }

        $registered   = [];
        $unregistered = [];
        $originalTld  = '.' . strtolower((string)end($parts));
        $checkTlds    = $this->buildTldCandidates($originalTld);

        foreach ($checkTlds as $tld) {
            $testDomain = $baseName . $tld;
            try {
                $records = @dns_get_record($testDomain, DNS_A | DNS_AAAA);
                if ($records && count($records) > 0) {
                    $ips = [];
                    foreach ($records as $rec) {
                        if (isset($rec['ip'])) $ips[] = $rec['ip'];
                        if (isset($rec['ipv6'])) $ips[] = $rec['ipv6'];
                    }
                    $registered[$testDomain] = $ips;
                } else {
                    // Also try NS records — domain may exist but have no A record
                    $nsRecords = @dns_get_record($testDomain, DNS_NS);
                    if ($nsRecords && count($nsRecords) > 0) {
                        $registered[$testDomain] = ['NS record found'];
                    } else {
                        $unregistered[] = $testDomain;
                    }
                }
            } catch (\Exception $e) {
                $unregistered[] = $testDomain;
            }
        }

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);

        $registeredCount   = count($registered);
        $unregisteredCount = count($unregistered);
        $totalChecked      = count($checkTlds);

        // More registered TLDs = potential typosquatting or brand protection interest
        $score = min(30, $registeredCount * 4);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 70 + $totalChecked);

        $parts = ["Base name '{$baseName}': {$registeredCount} of {$totalChecked} TLD variations resolve"];

        if ($registeredCount > 0) {
            $regDomains = array_keys($registered);
            $parts[] = "Registered: " . implode(', ', $regDomains);
        }

        if ($unregisteredCount > 0) {
            $parts[] = "Not resolving: " . implode(', ', $unregistered);
        }

        $tags = [self::API_ID, 'domain', 'dns', 'tld_search'];
        if ($registeredCount >= 5) $tags[] = 'brand_protection';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'base_name' => $baseName,
                'checked_tlds' => $checkTlds,
                'tld_source' => GlobalSettings::tldSource(),
                'tld_cache_hours' => GlobalSettings::tldCacheHours(),
                'registered_count' => $registeredCount,
                'unregistered_count' => $unregisteredCount,
                'registered' => $registered,
                'unregistered' => $unregistered,
            ],
            success: true
        );
    }

    /**
     * Build a bounded, deterministic TLD candidate list.
     *
     * @return array<int,string>
     */
    private function buildTldCandidates(string $originalTld): array
    {
        $ordered = [];
        $seen = [];

        $add = static function (string $candidate) use (&$ordered, &$seen): void {
            $candidate = strtolower(trim($candidate));
            if ($candidate === '') {
                return;
            }
            if (!str_starts_with($candidate, '.')) {
                $candidate = '.' . $candidate;
            }
            if (!preg_match('/^\.[a-z0-9][a-z0-9\-]{0,62}$/i', $candidate)) {
                return;
            }
            if (isset($seen[$candidate])) {
                return;
            }
            $seen[$candidate] = true;
            $ordered[] = $candidate;
        };

        foreach (self::PRIORITY_TLDS as $tld) {
            $add($tld);
        }
        $add($originalTld);

        foreach (GlobalSettings::internetTlds() as $tld) {
            if (count($ordered) >= self::MAX_TLDS_TO_CHECK) {
                break;
            }
            $add($tld);
        }

        if (empty($ordered)) {
            foreach (self::DEFAULT_CHECK_TLDS as $tld) {
                $add($tld);
            }
        }

        return $ordered;
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
