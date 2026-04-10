<?php
// =============================================================================
//  CTI — Base API Module
//  php/modules/BaseApiModule.php
//
//  Abstract base class for all OSINT module handlers.
//  Provides:
//   - Settings injection via setSettings()
//   - Typed setting readers: bool(), int(), str(), float()
//   - SpiderFoot-compatible convenience accessors for common options
//
//  All module handlers should extend this class.
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';

abstract class BaseApiModule
{
    /** @var array<string, string> Module settings injected by OsintEngine */
    protected array $settings = [];

    /**
     * Inject module settings (called by OsintEngine before execute()).
     */
    public function setSettings(array $settings): void
    {
        $this->settings = $settings;
    }

    /**
     * Get all currently loaded settings.
     */
    public function getSettings(): array
    {
        return $this->settings;
    }

    // =========================================================================
    //  PRIMITIVE SETTING READERS
    // =========================================================================

    /**
     * Read a boolean setting.
     * Recognises '1', 'true', 'yes', 'on' as true; everything else as false.
     */
    protected function bool(string $key, bool $default = true): bool
    {
        if (!array_key_exists($key, $this->settings)) {
            return $default;
        }
        $v = $this->settings[$key];
        if (is_bool($v)) {
            return $v;
        }
        return in_array(strtolower(trim((string)$v)), ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * Read an integer setting.
     */
    protected function int(string $key, int $default = 0): int
    {
        if (!array_key_exists($key, $this->settings)) {
            return $default;
        }
        return (int)$this->settings[$key];
    }

    /**
     * Read a string setting.
     */
    protected function str(string $key, string $default = ''): string
    {
        if (!array_key_exists($key, $this->settings)) {
            return $default;
        }
        return (string)$this->settings[$key];
    }

    /**
     * Read a float setting.
     */
    protected function float(string $key, float $default = 0.0): float
    {
        if (!array_key_exists($key, $this->settings)) {
            return $default;
        }
        return (float)$this->settings[$key];
    }

    // =========================================================================
    //  SPIDERFOOT-COMPATIBLE CONVENIENCE ACCESSORS
    //
    //  These map to the normalised setting keys produced by
    //  SpiderFootModuleMapper::normaliseOptionKey().
    // =========================================================================

    // ── Affiliate / co-host / subnet toggles ─────────────────────────────

    /** Apply checks to affiliate IP addresses / domains? */
    protected function checkAffiliates(): bool
    {
        return $this->bool('check_affiliates', true);
    }

    /** Apply checks to co-hosted sites? */
    protected function checkCohosts(): bool
    {
        return $this->bool('check_cohosts', true);
    }

    /** Look up all IPs on netblocks owned by target? */
    protected function checkNetblocks(): bool
    {
        return $this->bool('check_netblocks', true);
    }

    /** Look up all IPs on subnets target is part of? */
    protected function checkSubnets(): bool
    {
        return $this->bool('check_subnets', false);
    }

    /** Treat co-hosted sites on the same target domain as co-hosting? */
    protected function cohostSameDomain(): bool
    {
        return $this->bool('cohost_same_domain', false);
    }

    // ── Netblock / subnet size limits ────────────────────────────────────

    /** Max IPv4 netblock CIDR to scan (default /24). */
    protected function maxNetblockIPv4(): int
    {
        return $this->int('max_netblock_ipv4', 24);
    }

    /** Max IPv4 subnet CIDR to scan (default /24). */
    protected function maxSubnetIPv4(): int
    {
        return $this->int('max_subnet_ipv4', 24);
    }

    /** Max IPv6 netblock CIDR to scan (default /120). */
    protected function maxNetblockIPv6(): int
    {
        return $this->int('max_netblock_ipv6', 120);
    }

    /** Max IPv6 subnet CIDR to scan (default /120). */
    protected function maxSubnetIPv6(): int
    {
        return $this->int('max_subnet_ipv6', 120);
    }

    // ── Verification ─────────────────────────────────────────────────────

    /** Verify discovered hostnames still resolve? */
    protected function verifyHostnames(): bool
    {
        return $this->bool('verify_hostnames', true);
    }

    /** Verify co-hosts still resolve to the shared IP? */
    protected function verifyCohosts(): bool
    {
        return $this->bool('verify_cohosts', true);
    }

    /** Verify certificate SAN entries resolve? */
    protected function verifySan(): bool
    {
        return $this->bool('verify_san', true);
    }

    /** Validate reverse-resolved hostnames resolve back? */
    protected function verifyReverseDns(): bool
    {
        return $this->bool('verify_reverse_dns', true);
    }

    // ── Co-host limits ───────────────────────────────────────────────────

    /** Stop reporting co-hosted sites after this many. */
    protected function maxCohosts(): int
    {
        return $this->int('max_cohosts', 100);
    }

    /** Ignore co-hosts older than N days (0 = unlimited). */
    protected function cohostMaxAgeDays(): int
    {
        return $this->int('cohost_max_age_days', 30);
    }

    // ── Cache / timing ───────────────────────────────────────────────────

    /** Hours to cache list data before re-fetching. */
    protected function cacheHours(): int
    {
        return $this->int('cache_hours', 18);
    }

    /** Delay in seconds between API requests. */
    protected function delaySeconds(): int
    {
        return $this->int('delay_seconds', 0);
    }

    /** Timeout in seconds for queries/connections. */
    protected function timeoutSeconds(): int
    {
        return $this->int('timeout_seconds', 30);
    }

    // ── Pagination / limits ──────────────────────────────────────────────

    /** Max number of pages of results to fetch. */
    protected function maxPages(): int
    {
        return $this->int('max_pages', 10);
    }

    /** Max number of results to retrieve. */
    protected function maxResults(): int
    {
        return $this->int('max_results', 10000);
    }

    /** Max results per page. */
    protected function maxResultsPerPage(): int
    {
        return $this->int('max_results_per_page', 100);
    }

    // ── Freshness / age ──────────────────────────────────────────────────

    /** Ignore records older than N days (0 = unlimited). */
    protected function ignoreOlderDays(): int
    {
        return $this->int('ignore_older_days', 0);
    }

    /** Max age of data in days to be considered valid (0 = unlimited). */
    protected function maxAgeDays(): int
    {
        return $this->int('max_age_days', 0);
    }

    /** Days before certificate expiry to raise a warning. */
    protected function certExpiryWarningDays(): int
    {
        return $this->int('cert_expiry_warning_days', 30);
    }

    // ── Thresholds ───────────────────────────────────────────────────────

    /** Minimum abuse score to consider malicious. */
    protected function minAbuseScore(): int
    {
        return $this->int('min_abuse_score', 85);
    }

    /** Minimum confidence level. */
    protected function minConfidence(): int
    {
        return $this->int('min_confidence', 90);
    }

    /** Minimum fraud score to flag. */
    protected function minFraudScore(): int
    {
        return $this->int('min_fraud_score', 80);
    }

    /** Minimum threat score. */
    protected function minThreatScore(): int
    {
        return $this->int('min_threat_score', 0);
    }

    // ── Port scanning ────────────────────────────────────────────────────

    /** Scan all IPs within identified owned netblocks? */
    protected function scanNetblockIps(): bool
    {
        return $this->bool('scan_netblock_ips', true);
    }

    /** TCP ports list to scan. */
    protected function tcpPorts(): string
    {
        return $this->str('tcp_ports', '21,22,23,25,53,80,443,8080,8443');
    }

    /** Randomize port scan order? */
    protected function randomizePorts(): bool
    {
        return $this->bool('randomize_ports', true);
    }

    /** Number of concurrent port scan threads. */
    protected function portScanThreads(): int
    {
        return $this->int('port_scan_threads', 10);
    }

    // ── Content / search toggles ─────────────────────────────────────────

    /** Search for human names? */
    protected function searchNames(): bool
    {
        return $this->bool('search_names', true);
    }

    /** Fetch darknet pages for verification? */
    protected function fetchDarknet(): bool
    {
        return $this->bool('fetch_darknet', true);
    }

    /** Using a public (free-tier) API key? */
    protected function isPublicKey(): bool
    {
        return $this->bool('public_key', true);
    }

    // ── Utility ──────────────────────────────────────────────────────────

    /**
     * Sleep for the configured delay between requests, if any.
     * Call this between paginated API requests.
     */
    protected function applyDelay(): void
    {
        $delay = $this->delaySeconds();
        if ($delay > 0) {
            sleep($delay);
        }
    }

    /**
     * Check if a record age in days exceeds the ignoreOlderDays threshold.
     * Returns true if the record should be skipped (too old).
     */
    protected function isTooOld(int $ageDays): bool
    {
        $max = $this->ignoreOlderDays();
        if ($max === 0) {
            return false; // 0 = unlimited, never too old
        }
        return $ageDays > $max;
    }

    // =========================================================================
    //  ABSTRACT CONTRACT
    // =========================================================================

    /**
     * Execute a threat intelligence query against this module's API.
     *
     * @param  string $queryType   One of: ip, domain, url, hash, email, etc.
     * @param  string $queryValue  The target to query.
     * @param  string $apiKey      API key (may be empty for free modules).
     * @param  string $baseUrl     API base URL.
     * @return OsintResult|OsintResult[]
     */
    abstract public function execute(
        string $queryType,
        string $queryValue,
        string $apiKey,
        string $baseUrl
    ): OsintResult|array;

    /**
     * Health check for module diagnostics.
     * Default implementation — modules may override.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'unknown', 'latency_ms' => 0, 'error' => 'No health check implemented'];
    }
}
