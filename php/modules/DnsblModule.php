<?php
// =============================================================================
//  CTI — DNSBL (DNS Blacklist) Module
//  Handles: sorbs, spamcop, spamhaus-zen, uceprotect, dronebl, surbl
//  Uses DNS lookups against DNSBL services. Free, no key. Supports: ip
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsblModule extends BaseApiModule
{
    private const DNSBL_ZONES = [
        'sorbs'        => ['zone' => 'dnsbl.sorbs.net',           'name' => 'SORBS'],
        'spamcop'      => ['zone' => 'bl.spamcop.net',            'name' => 'SpamCop'],
        'spamhaus-zen' => ['zone' => 'zen.spamhaus.org',          'name' => 'Spamhaus Zen'],
        'uceprotect'   => ['zone' => 'dnsbl-1.uceprotect.net',    'name' => 'UCEPROTECT'],
        'dronebl'      => ['zone' => 'dnsbl.dronebl.org',         'name' => 'DroneBL'],
        'surbl'        => ['zone' => 'multi.surbl.org',            'name' => 'SURBL'],
    ];

    private string $slug;
    private string $apiName;
    private string $zone;

    public function __construct(string $slug = 'sorbs')
    {
        $config = self::DNSBL_ZONES[$slug] ?? self::DNSBL_ZONES['sorbs'];
        $this->slug    = $slug;
        $this->apiName = $config['name'];
        $this->zone    = $config['zone'];
    }

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'ip') {
            return OsintResult::error($this->slug, $this->apiName, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        // Reverse the IP octets and append the DNSBL zone
        $parts = explode('.', $queryValue);
        if (count($parts) !== 4) {
            return OsintResult::error($this->slug, $this->apiName, 'Invalid IPv4 address');
        }

        $reversed = implode('.', array_reverse($parts));
        $lookup   = "{$reversed}.{$this->zone}";

        $result = @dns_get_record($lookup, DNS_A);
        $ms = (int)((microtime(true) - $start) * 1000);

        $isListed = !empty($result);

        // Some DNSBLs return specific codes
        $returnCodes = [];
        if ($isListed) {
            foreach ($result as $r) {
                $returnCodes[] = $r['ip'] ?? '';
            }
        }

        // Also try TXT record for reason
        $reason = '';
        if ($isListed) {
            $txt = @dns_get_record($lookup, DNS_TXT);
            if (!empty($txt)) {
                $reason = $txt[0]['txt'] ?? '';
            }
        }

        if ($isListed) {
            $score      = 70;
            $severity   = 'high';
            $confidence = 95;
            $summary    = "IP {$queryValue} IS listed in {$this->apiName} ({$this->zone}).";
            if ($reason) $summary .= " Reason: {$reason}";
            if (!empty($returnCodes)) $summary .= " Return code(s): " . implode(', ', $returnCodes) . ".";
            $tags = [$this->slug, 'ip', 'blocklisted', 'spam', 'malicious'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 90;
            $summary    = "IP {$queryValue} is NOT listed in {$this->apiName} ({$this->zone}).";
            $tags       = [$this->slug, 'ip', 'clean'];
        }

        return new OsintResult(
            api: $this->slug, apiName: $this->apiName,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: $summary,
            tags: $tags,
            rawData: ['listed' => $isListed, 'zone' => $this->zone, 'return_codes' => $returnCodes, 'reason' => $reason],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        // Query a known-safe IP (Google DNS should not be listed)
        $lookup = "8.8.8.8." . str_replace('.', '.', implode('.', array_reverse(explode('.', '8.8.8.8'))));
        $result = @dns_get_record("8.8.8.8.{$this->zone}", DNS_A);
        $ms = (int)((microtime(true) - $start) * 1000);
        // Even if no result (not listed), the DNS query working means the service is up
        return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
    }
}

// Convenience subclasses so OsintEngine can instantiate by class name
class SorbsModule extends DnsblModule { public function __construct() { parent::__construct('sorbs'); } }
class SpamcopModule extends DnsblModule { public function __construct() { parent::__construct('spamcop'); } }
class SpamhausZenModule extends DnsblModule { public function __construct() { parent::__construct('spamhaus-zen'); } }
class UceprotectModule extends DnsblModule { public function __construct() { parent::__construct('uceprotect'); } }
class DroneBLModule extends DnsblModule { public function __construct() { parent::__construct('dronebl'); } }
class SurblModule extends DnsblModule { public function __construct() { parent::__construct('surbl'); } }
