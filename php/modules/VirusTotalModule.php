<?php
// =============================================================================
//  CTI â€” VirusTotal OSINT Module Handler
//  php/modules/VirusTotalModule.php
//
//  Queries the VirusTotal API v3 for file hashes, domains, IPs, and URLs.
//  Supports SpiderFoot-compatible options: affiliate checks, co-hosted site
//  lookups, netblock/subnet enrichment, hostname verification, and throttling
//  for public API keys.
//
//  API Docs: https://developers.virustotal.com/reference
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';
require_once __DIR__ . '/../ApiQuotaTracker.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/BaseApiModule.php';

class VirusTotalModule extends BaseApiModule
{
    private const API_ID   = 'virustotal';
    private const API_NAME = 'VirusTotal';

    private const SUPPORTED_TYPES = ['ip', 'domain', 'url', 'hash'];

    /**
     * Set once a fatal API error (bad key, persistent throttle) occurs.
     * Mirrors SpiderFoot's errorState — prevents hammering a broken endpoint.
     */
    private bool $errorState = false;

    /**
     * Deduplication cache — mirrors SpiderFoot's self.results tempStorage.
     * Prevents querying the same value twice within a single scan run.
     * @var array<string, true>
     */
    private array $seen = [];

    /**
     * Hostname resolution cache for affiliate verification.
     * @var array<string, bool>
     */
    private array $hostnameResolutionCache = [];

    /**
     * Cache of VT v2 domain/report payloads by queried domain.
     * @var array<string, array<string, mixed>|null>
     */
    private array $domainReportV2Cache = [];

    // ── Public interface ──────────────────────────────────────────────────────

    /**
     * Execute a threat intelligence query against VirusTotal.
     */
    /**
     * Execute a VirusTotal query and return an array of SpiderFoot-style results.
     * The first element is always the primary result for the queried target.
     * Subsequent elements are one OsintResult per enrichment data element found
     * (sibling domains, co-hosted URLs, resolved IPs, netblock owners, etc.).
     *
     * @return OsintResult[]
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): array
    {
        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return [OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}")];
        }

        // errorState: abort if a previous call already confirmed the key is broken
        if ($this->errorState) {
            return [OsintResult::error(self::API_ID, self::API_NAME, 'Module in error state — previous fatal API error')];
        }

        // Deduplication: skip values already queried in this scan run
        $cacheKey = $queryType . ':' . $queryValue;
        if (isset($this->seen[$cacheKey])) {
            return [OsintResult::error(self::API_ID, self::API_NAME, "Duplicate query skipped: {$queryValue}")];
        }
        $this->seen[$cacheKey] = true;

        $baseUrl = rtrim($baseUrl ?: 'https://www.virustotal.com/api/v3', '/');
        $headers = ['x-apikey' => $apiKey];

        // Throttle for public API keys (VT free tier = 4 req/min → 15 s between calls).
        // Only enabled when the user explicitly sets public_key=true in module settings.
        // Default is false because most users with configured keys have premium/enterprise
        // access; enabling this on every scan by default adds 15 s per VT query.
        if ($this->bool('public_key', false)) {
            sleep(15);
        }

        // Daily quota enforcement (free tier = 500/day by default)
        $dailyLimit = $this->int('daily_limit', 500);
        if (!ApiQuotaTracker::check(self::API_ID, $dailyLimit)) {
            return [OsintResult::error(self::API_ID, self::API_NAME,
                'Daily API quota reached (' . $dailyLimit . ' calls). Resets tomorrow.')];
        }

        // Trim query value to avoid encoding issues
        $queryValue = trim($queryValue);

        // URL queries use a special POST-then-GET flow in VT v3
        if ($queryType === 'url') {
            return $this->queryUrl($baseUrl, $headers, $queryValue);
        }

        $url = $this->buildEndpointUrl($baseUrl, $queryType, $queryValue);
        $response = HttpClient::get($url, $headers);
        ApiQuotaTracker::increment(self::API_ID);

        $errorResult = $this->handleVtErrors($response);
        if ($errorResult !== null) return $errorResult;

        // 404 = not found in VT database
        if ($response['status'] === 404) {
            return [OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms'])];
        }

        $json = $response['json'];
        if (!$json || !isset($json['data'])) {
            return [OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms'])];
        }

        $domainReportV2 = null;
        if ($queryType === 'domain') {
            $domainReportV2 = $this->fetchDomainReportV2($apiKey, $queryValue);
        }

        // â”€â”€ Primary result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        $primary = $this->parseResponse($json['data'], $queryType, $queryValue, $response['elapsed_ms'], $domainReportV2);

        // â”€â”€ SpiderFoot-style enrichment elements (one per found entity) â”€â”€â”€â”€â”€â”€â”€
        $elements = $this->enrichToElements($baseUrl, $headers, $queryType, $queryValue, $json['data'], $domainReportV2);

        // Upgrade primary result score/tags based on what enrichment found
        if (!empty($elements)) {
            $primary = $this->upgradeFromElements($primary, $elements);
        }

        return array_merge([$primary], $elements);
    }

    /**
     * Run a health check against the VirusTotal API.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://www.virustotal.com/api/v3', '/');
        $headers = ['x-apikey' => $apiKey];

        $response = HttpClient::get("{$baseUrl}/users/me", $headers);

        if ($response['error'] || $response['status'] === 0) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => $response['error'] ?? 'Connection failed'];
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => 'Invalid API key'];
        }
        if ($response['status'] >= 200 && $response['status'] < 300) {
            return ['status' => 'healthy', 'latency_ms' => $response['elapsed_ms'], 'error' => null];
        }

        return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => "HTTP {$response['status']}"];
    }

    // ── Private: Core ─────────────────────────────────────────────────────────

    /**
     * Handle common VT API error responses. Returns an error result array or null if OK.
     */
    private function handleVtErrors(array $response): ?array
    {
        if ($response['status'] === 429) {
            $this->errorState = true;
            return [OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms'])];
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            $this->errorState = true;
            return [OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms'])];
        }
        if ($response['status'] === 404) {
            return null; // Caller handles 404 per context
        }
        if ($response['status'] === 0 || $response['error']) {
            return [OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms'])];
        }
        if ($response['status'] < 200 || $response['status'] >= 300) {
            $errMsg = "HTTP {$response['status']}";
            $errJson = $response['json'] ?? null;
            if ($errJson && isset($errJson['error']['message'])) {
                $errMsg .= ': ' . $errJson['error']['message'];
            } elseif ($errJson && isset($errJson['error']['code'])) {
                $errMsg .= ': ' . $errJson['error']['code'];
            }
            return [OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $response['elapsed_ms'])];
        }
        return null;
    }

    /**
     * URL query flow for VT v3:
     *  1. Try GET /urls/{base64url(url)} for existing report.
     *  2. If 404 or 400, POST /urls to submit for scanning.
     *  3. Poll GET /analyses/{id} until complete (max ~30s).
     *  4. Fetch final report from GET /urls/{base64url(url)}.
     *
     * @return OsintResult[]
     */
    private function queryUrl(string $baseUrl, array $headers, string $queryValue): array
    {
        $urlId = rtrim(strtr(base64_encode($queryValue), '+/', '-_'), '=');
        $reportUrl = "{$baseUrl}/urls/{$urlId}";

        // Step 1: Try fetching existing report
        $response = HttpClient::get($reportUrl, $headers);
        ApiQuotaTracker::increment(self::API_ID);

        $errorResult = $this->handleVtErrors($response);
        if ($errorResult !== null) return $errorResult;

        // If we got a valid report, use it
        if ($response['status'] === 200 && !empty($response['json']['data'])) {
            return $this->processUrlReport($response, $baseUrl, $headers, $queryValue);
        }

        // Step 2: Submit URL for scanning via POST
        if (!ApiQuotaTracker::check(self::API_ID, $this->int('daily_limit', 500))) {
            return [OsintResult::error(self::API_ID, self::API_NAME, 'Daily quota reached before URL submission.')];
        }

        $submitResp = HttpClient::post(
            "{$baseUrl}/urls",
            array_merge($headers, ['Content-Type' => 'application/x-www-form-urlencoded']),
            'url=' . urlencode($queryValue),
            30
        );
        ApiQuotaTracker::increment(self::API_ID);

        $submitError = $this->handleVtErrors($submitResp);
        if ($submitError !== null) return $submitError;

        if ($submitResp['status'] < 200 || $submitResp['status'] >= 300 || empty($submitResp['json']['data']['id'])) {
            $msg = 'URL submission failed';
            if (!empty($submitResp['json']['error']['message'])) {
                $msg .= ': ' . $submitResp['json']['error']['message'];
            }
            return [OsintResult::error(self::API_ID, self::API_NAME, $msg, $submitResp['elapsed_ms'])];
        }

        $analysisId = $submitResp['json']['data']['id'];

        // Step 3: Poll analysis status (max 30s, 5s intervals)
        $analysisUrl = "{$baseUrl}/analyses/{$analysisId}";
        $maxWait = 30;
        $waited  = 0;
        $analysisData = null;

        while ($waited < $maxWait) {
            sleep(5);
            $waited += 5;

            if (!ApiQuotaTracker::check(self::API_ID, $this->int('daily_limit', 500))) {
                break;
            }

            $pollResp = HttpClient::get($analysisUrl, $headers);
            ApiQuotaTracker::increment(self::API_ID);

            if ($pollResp['status'] !== 200 || empty($pollResp['json']['data'])) {
                continue;
            }

            $status = $pollResp['json']['data']['attributes']['status'] ?? '';
            if ($status === 'completed') {
                $analysisData = $pollResp['json']['data'];
                break;
            }
        }

        // Step 4: Fetch final URL report (analysis has enriched the URL record)
        $finalResp = HttpClient::get($reportUrl, $headers);
        ApiQuotaTracker::increment(self::API_ID);

        $finalError = $this->handleVtErrors($finalResp);
        if ($finalError !== null) return $finalError;

        if ($finalResp['status'] === 200 && !empty($finalResp['json']['data'])) {
            return $this->processUrlReport($finalResp, $baseUrl, $headers, $queryValue);
        }

        // Fallback: use the analysis data directly if the URL report is still not ready
        if ($analysisData) {
            $stats = $analysisData['attributes']['stats'] ?? [];
            $malicious = (int)($stats['malicious'] ?? 0);
            $total = array_sum(array_map('intval', $stats));
            $score = $total > 0 ? (int)round(($malicious / $total) * 100) : 0;

            return [new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      $score,
                severity:   OsintResult::scoreToSeverity($score),
                confidence: $total > 0 ? min(99, 50 + (int)($total / 2)) : 30,
                responseMs: $submitResp['elapsed_ms'],
                summary:    "URL analysis: {$malicious}/{$total} engines flagged as malicious.",
                tags:       array_values(array_unique(array_filter([self::API_ID, 'url', $malicious > 0 ? 'malicious' : 'clean']))),
                rawData:    $analysisData,
                success:    true,
                dataType:   $malicious > 0 ? 'Malicious URL' : 'Linked URL - Internal'
            )];
        }

        return [OsintResult::error(self::API_ID, self::API_NAME,
            'URL analysis timed out — VT may still be processing this URL.',
            $submitResp['elapsed_ms'])];
    }

    /**
     * Process a successful VT URL report response into results.
     * @return OsintResult[]
     */
    private function processUrlReport(array $response, string $baseUrl, array $headers, string $queryValue): array
    {
        $json = $response['json'];
        $primary = $this->parseResponse($json['data'], 'url', $queryValue, $response['elapsed_ms']);
        $elements = $this->enrichToElements($baseUrl, $headers, 'url', $queryValue, $json['data']);
        if (!empty($elements)) {
            $primary = $this->upgradeFromElements($primary, $elements);
        }
        return array_merge([$primary], $elements);
    }

    /**
     * Build the API endpoint URL based on query type.
     */
    private function buildEndpointUrl(string $baseUrl, string $queryType, string $queryValue): string
    {
        switch ($queryType) {
            case 'hash':   return "{$baseUrl}/files/" . urlencode($queryValue);
            case 'domain': return "{$baseUrl}/domains/" . urlencode($queryValue);
            case 'ip':     return "{$baseUrl}/ip_addresses/" . urlencode($queryValue);
            case 'url':    return "{$baseUrl}/urls/" . rtrim(strtr(base64_encode($queryValue), '+/', '-_'), '=');
            default:       return "{$baseUrl}/search?query=" . urlencode($queryValue);
        }
    }

    /**
     * Parse the VirusTotal response and compute risk metrics.
     */
    private function parseResponse(
        array $data,
        string $queryType,
        string $queryValue,
        int $elapsedMs,
        ?array $legacyDomainReport = null
    ): OsintResult
    {
        $attributes = $data['attributes'] ?? [];

        // Extract analysis stats (works for files, domains, IPs, URLs)
        $stats = $attributes['last_analysis_stats'] ?? [];
        $malicious  = $stats['malicious']  ?? 0;
        $suspicious = $stats['suspicious'] ?? 0;
        $undetected = $stats['undetected'] ?? 0;
        $harmless   = $stats['harmless']   ?? 0;
        $timeout    = $stats['timeout']    ?? 0;

        $total       = $malicious + $suspicious + $undetected + $harmless + $timeout;
        $threatCount = $malicious + $suspicious;

        // Score: (malicious / total) * 100
        $score = $total > 0 ? (int) round(($malicious / $total) * 100) : 0;
        $score = max(0, min(100, $score));

        $domainReportLooksMalicious = $queryType === 'domain'
            && $this->domainReportLooksMalicious($legacyDomainReport);
        $detectedUrlCount = $queryType === 'domain'
            ? $this->domainReportDetectedUrlCount($legacyDomainReport)
            : 0;
        if ($domainReportLooksMalicious) {
            $score = max($score, min(40, max(1, $detectedUrlCount) * 5));
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $total > 0 ? min(99, 50 + (int)($total / 2)) : 30;
        if ($domainReportLooksMalicious) {
            $confidence = max($confidence, 80);
        }

        // Build summary
        switch ($queryType) {
            case 'hash':   $summary = "File hash {$queryValue}: {$malicious}/{$total} engines flagged as malicious."; break;
            case 'domain': $summary = "Domain {$queryValue}: {$malicious}/{$total} engines flagged as malicious."; break;
            case 'ip':     $summary = "IP {$queryValue}: {$malicious}/{$total} engines flagged as malicious."; break;
            case 'url':    $summary = "URL analysis: {$malicious}/{$total} engines flagged as malicious."; break;
            default:       $summary = "{$queryValue}: {$malicious}/{$total} engines flagged as malicious."; break;
        }

        if ($suspicious > 0) {
            $summary .= " {$suspicious} marked suspicious.";
        }
        if ($domainReportLooksMalicious && $detectedUrlCount > 0) {
            $summary .= " VirusTotal domain report lists {$detectedUrlCount} detected URL(s).";
        }

        // Build tags
        $tags = [self::API_ID, $queryType];
        if ($malicious > 0)  $tags[] = 'malicious';
        if ($suspicious > 0) $tags[] = 'suspicious';
        if ($malicious === 0 && $suspicious === 0) $tags[] = 'clean';
        if ($domainReportLooksMalicious) {
            $tags[] = 'malicious';
            $tags[] = 'vt_v2_detected_urls';
        }

        if ($queryType === 'hash') {
            $fileType = $attributes['type_tag'] ?? $attributes['type_description'] ?? null;
            if ($fileType) $tags[] = strtolower($fileType);
        }

        $reputation = $attributes['reputation'] ?? null;
        if ($reputation !== null && $reputation < 0) {
            $tags[] = 'bad_reputation';
        }

        // Annotate network info (IP) â€” used later by enrichment
        if ($queryType === 'ip') {
            $network = $attributes['network'] ?? null;
            if ($network) $tags[] = 'network:' . $network;
            $asn = $attributes['asn'] ?? null;
            if ($asn) $tags[] = 'asn:' . $asn;
        }

        // Map query type to SpiderFoot-style primary data type
        $primaryType = $this->primaryDataType($queryType, $malicious, $domainReportLooksMalicious);

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $elapsedMs,
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true,
            dataType:   $primaryType
        );
    }

    /**
     * Map a query type to its SpiderFoot-style primary data type label.
     */
    private function primaryDataType(string $queryType, int $malicious = 0, bool $domainReportLooksMalicious = false): string
    {
        switch ($queryType) {
            case 'domain': return $domainReportLooksMalicious ? EventTypes::MALICIOUS_INTERNET_NAME : EventTypes::INTERNET_NAME;
            case 'ip':     return 'IP Address';
            case 'url':    return $malicious > 0 ? 'Malicious URL' : 'Linked URL - Internal';
            case 'hash':   return $malicious > 0 ? 'Malware' : 'File Hash';
            default:       return 'Raw Data';
        }
    }

    // ── Private: SpiderFoot-style enrichment elements ─────────────────────────

    /**
     * Produce one OsintResult per enrichment data entity found, using
     * SpiderFoot-compatible data type labels.
     *
     * @return OsintResult[]
     */
    private function enrichToElements(
        string $baseUrl,
        array $headers,
        string $queryType,
        string $queryValue,
        array $primaryData,
        ?array $legacyDomainReport = null
    ): array
    {
        $elements   = [];
        $attributes = $primaryData['attributes'] ?? [];

        // ── (1) check_affiliates ─────────────────────────────────────────────────────

        if ($queryType === 'domain') {
            $domainElements = $this->buildDomainElements(
                $baseUrl,
                $headers,
                $queryValue,
                $legacyDomainReport
            );
            if (!empty($domainElements)) {
                $elements = array_merge($elements, $domainElements);
            }
        }

        if ($this->bool('check_affiliates', true) && $queryType === 'ip') {
                // Historical SSL certs indicate shared infrastructure
                $certs = $this->fetchRelationship($baseUrl, $headers, 'ip_addresses', $queryValue, 'historical_ssl_certificates', 5);
                foreach ($certs as $cert) {
                    $certId = $cert['id'] ?? null;
                    if (!$certId) continue;
                    $elements[] = new OsintResult(
                        api:        self::API_ID,
                        apiName:    self::API_NAME,
                        score:      0,
                        severity:   'info',
                        confidence: 50,
                        responseMs: 0,
                        summary:    "SSL certificate associated with IP {$queryValue}: {$certId}",
                        tags:       [self::API_ID, 'ssl_certificate', 'infrastructure'],
                        rawData:    $cert,
                        success:    true,
                        dataType:   'SSL Certificate'
                    );
                }
        }

        // ── (2) check_co_hosted ─────────────────────────────────────────────────────

        if ($this->bool('check_co_hosted', true)) {
            if ($queryType === 'ip') {
                // URLs hosted on this IP
                $urls = $this->fetchRelationship($baseUrl, $headers, 'ip_addresses', $queryValue, 'urls', 10);
                foreach ($urls as $url) {
                    $urlId  = $url['id'] ?? null;
                    if (!$urlId) continue;
                    $stats    = $url['attributes']['last_analysis_stats'] ?? [];
                    $total    = array_sum($stats);
                    $malicious = (int)($stats['malicious'] ?? 0);
                    $dtStr    = $malicious > 0 ? 'Malicious URL' : 'Linked URL - Internal';
                    $score    = $total > 0 ? (int)round(($malicious / $total) * 100) : 0;
                    $cohostResult = new OsintResult(
                        api:        self::API_ID,
                        apiName:    self::API_NAME,
                        score:      $score,
                        severity:   OsintResult::scoreToSeverity($score),
                        confidence: $total > 0 ? 75 : 30,
                        responseMs: 0,
                        summary:    "Co-hosted URL on {$queryValue}: {$urlId}. {$malicious}/{$total} flagged.",
                        tags:       array_values(array_unique(array_filter([self::API_ID, 'co_hosted', $malicious > 0 ? 'malicious' : 'clean']))),
                        rawData:    $url,
                        success:    true,
                        dataType:   $dtStr
                    );

                    // Feed URL discoveries back into the enrichment queue when a
                    // canonical URL is available (SpiderFoot-like recursion).
                    $candidateUrl = trim((string)($url['attributes']['url'] ?? $url['attributes']['last_final_url'] ?? ''));
                    if ($candidateUrl !== '' && preg_match('#^https?://#i', $candidateUrl)) {
                        $cohostResult->addDiscovery(EventTypes::LINKED_URL_EXTERNAL, $candidateUrl);
                    }

                    $elements[] = $cohostResult;
                }
            }
        }

        // ── (3) lookup_netblock_ips ─────────────────────────────────────────────────────
        if ($this->bool('lookup_netblock_ips', true) && $queryType === 'ip') {
            $network  = $attributes['network'] ?? null;
            $asOwner  = $attributes['as_owner'] ?? null;
            $country  = $attributes['country'] ?? null;
            if ($network && $this->isNetblockWithinLimit($network, $this->int('netblock_size', 24))) {
                $label = $asOwner ? "{$network} ({$asOwner})" : $network;
                $elements[] = new OsintResult(
                    api:        self::API_ID,
                    apiName:    self::API_NAME,
                    score:      0,
                    severity:   'info',
                    confidence: 90,
                    responseMs: 0,
                    summary:    "IP {$queryValue} belongs to netblock {$label}" . ($country ? " [{$country}]" : '') . ".",
                    tags:       array_values(array_filter([self::API_ID, 'netblock', $asOwner ? 'asn_owner' : null])),
                    rawData:    ['network' => $network, 'as_owner' => $asOwner, 'country' => $country],
                    success:    true,
                    dataType:   'Netblock Owner'
                );
            }
        }

        // ── (4) lookup_subnet_ips ─────────────────────────────────────────────────────
        if ($this->bool('lookup_subnet_ips', true) && $queryType === 'ip') {
            $network = $attributes['network'] ?? null;
            if ($network && $this->isNetblockWithinLimit($network, $this->int('subnet_size', 24))) {
                // Only add a subnet element if we haven't already added a netblock for the same network
                $alreadyAdded = false;
                foreach ($elements as $el) {
                    if ($el->dataType === 'Netblock Owner') { $alreadyAdded = true; break; }
                }
                if (!$alreadyAdded) {
                    $elements[] = new OsintResult(
                        api:        self::API_ID,
                        apiName:    self::API_NAME,
                        score:      0,
                        severity:   'info',
                        confidence: 80,
                        responseMs: 0,
                        summary:    "IP {$queryValue} is in subnet {$network}.",
                        tags:       [self::API_ID, 'subnet'],
                        rawData:    ['network' => $network],
                        success:    true,
                        dataType:   'Netblock Member'
                    );
                }
            }
        }

        // ── (5) verify_hostnames ─────────────────────────────────────────────────────
        if ($this->bool('verify_hostnames', true) && $queryType === 'domain') {
            $resolutions = $this->fetchRelationship($baseUrl, $headers, 'domains', $queryValue, 'resolutions', 8);
            if (empty($resolutions)) {
                $elements[] = new OsintResult(
                    api:        self::API_ID,
                    apiName:    self::API_NAME,
                    score:      0,
                    severity:   'info',
                    confidence: 60,
                    responseMs: 0,
                    summary:    "Domain {$queryValue} does not appear to have current DNS resolutions in VirusTotal.",
                    tags:       [self::API_ID, 'unresolvable'],
                    rawData:    null,
                    success:    true,
                    dataType:   'Internet Name - Unresolved'
                );
            } else {
                $seenResolutionIps = [];
                foreach ($resolutions as $resolution) {
                    $ip = trim((string)($resolution['id'] ?? ''));
                    if ($ip === '' || isset($seenResolutionIps[$ip])) {
                        continue;
                    }
                    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                        continue;
                    }
                    $seenResolutionIps[$ip] = true;

                    $resolutionResult = new OsintResult(
                        api:        self::API_ID,
                        apiName:    self::API_NAME,
                        score:      0,
                        severity:   'info',
                        confidence: 80,
                        responseMs: 0,
                        summary:    "Domain {$queryValue} currently resolves to {$ip}.",
                        tags:       [self::API_ID, 'resolution', 'infrastructure'],
                        rawData:    $resolution,
                        success:    true,
                        dataType:   strpos($ip, ':') !== false ? 'IPv6 Address' : 'IP Address'
                    );
                    $resolutionResult->addDiscovery(
                        strpos($ip, ':') !== false ? EventTypes::IPV6_ADDRESS : EventTypes::IP_ADDRESS,
                        $ip
                    );

                    $elements[] = $resolutionResult;
                }
            }
        }

        return $elements;
    }

    /**
     * Upgrade the primary result's score/tags/summary based on what
     * enrichment elements revealed (threat uplift).
     */
    private function upgradeFromElements(OsintResult $primary, array $elements): OsintResult
    {
        $score   = $primary->score;
        $tags    = $primary->tags;
        $summary = $primary->summary;

        $affiliateMalicious = 0;
        $coHostedMalicious  = 0;

        foreach ($elements as $el) {
            if ($el->dataType === 'Affiliate - Internet Name' && $el->score > 0) {
                $affiliateMalicious++;
            }
            if ($el->dataType === 'Malicious URL') {
                $coHostedMalicious++;
            }
        }

        if ($affiliateMalicious > 0) {
            $tags[]  = 'affiliate_threat';
            $summary .= " {$affiliateMalicious} affiliated domain(s) also flagged as malicious.";
            $score   = min(100, $score + min(20, $affiliateMalicious * 5));
        }
        if ($coHostedMalicious > 0) {
            $tags[]  = 'co_hosted_threat';
            $summary .= " {$coHostedMalicious} co-hosted URL(s) flagged as malicious.";
            $score   = min(100, $score + min(15, $coHostedMalicious * 3));
        }
        if ($this->bool('public_key', true)) {
            $tags[] = 'public_key';
        }

        return new OsintResult(
            api:        $primary->api,
            apiName:    $primary->apiName,
            score:      $score,
            severity:   OsintResult::scoreToSeverity($score),
            confidence: $primary->confidence,
            responseMs: $primary->responseMs,
            summary:    $summary,
            tags:       array_values(array_unique($tags)),
            rawData:    $primary->rawData,
            success:    true,
            dataType:   $primary->dataType
        );
    }

    /**
     * Build SpiderFoot-style domain findings from VT legacy domain/report data.
     *
     * SpiderFoot's sfp_virustotal emits both domain_siblings and subdomains as
     * discrete events. Doing that here dramatically improves result parity for
     * domain scans without requiring a full event-bus rewrite.
     *
     * @return OsintResult[]
     */
    private function buildDomainElements(
        string $baseUrl,
        array $headers,
        string $queryValue,
        ?array $legacyDomainReport = null
    ): array {
        $elements = [];

        if (is_array($legacyDomainReport)) {
            $elements = $this->buildDomainElementsFromV2Report($legacyDomainReport, $queryValue);
        }

        if (!empty($elements)) {
            return $elements;
        }

        // Soft fallback when the legacy report is unavailable.
        $siblings = $this->fetchAffiliateDomainSiblings($baseUrl, $headers, $queryValue, 100);
        foreach ($siblings as $sibling) {
            $host = $this->normalizeDomainCandidate($sibling['id'] ?? null);
            if ($host === null) {
                continue;
            }

            $result = $this->buildLegacyDomainElement(
                $host,
                (string)($sibling['attributes']['_source'] ?? 'vt_v3_siblings'),
                $queryValue
            );
            if ($result !== null) {
                $elements[] = $result;
            }
        }

        return $elements;
    }

    /**
     * @return OsintResult[]
     */
    private function buildDomainElementsFromV2Report(array $legacyDomainReport, string $queryValue): array
    {
        $elements = [];
        $seenResultKeys = [];
        $domainSources = [
            'domain_siblings' => 'vt_v2_domain_siblings',
            'subdomains'      => 'vt_v2_subdomains',
        ];

        foreach ($domainSources as $field => $sourceTag) {
            $items = $legacyDomainReport[$field] ?? null;
            if (!is_array($items)) {
                continue;
            }

            foreach ($items as $item) {
                $host = $this->normalizeDomainCandidate($item);
                if ($host === null) {
                    continue;
                }

                $hostResult = $this->buildLegacyDomainElement($host, $sourceTag, $queryValue);
                if ($hostResult !== null) {
                    $key = $hostResult->dataType . '|' . strtolower($host);
                    if (!isset($seenResultKeys[$key])) {
                        $elements[] = $hostResult;
                        $seenResultKeys[$key] = true;
                    }
                }

                $domainType = $this->classifyDiscoveredDomainDataTypes($host)['domain'];
                if ($domainType === null) {
                    continue;
                }

                $registrable = $this->inferRegistrableDomain($host);
                if ($registrable === null || $registrable !== $host) {
                    continue;
                }

                $domainResult = new OsintResult(
                    api:        self::API_ID,
                    apiName:    self::API_NAME,
                    score:      0,
                    severity:   'info',
                    confidence: 70,
                    responseMs: 0,
                    summary:    "VirusTotal legacy domain report identified registrable domain {$host}.",
                    tags:       [self::API_ID, 'domain', $sourceTag, $this->matchesRootTarget($host) ? 'same_target' : 'affiliate'],
                    rawData:    ['host' => $host, 'source' => $sourceTag],
                    success:    true,
                    dataType:   $domainType
                );

                $domainKey = $domainResult->dataType . '|' . strtolower($host);
                if (!isset($seenResultKeys[$domainKey])) {
                    $elements[] = $domainResult;
                    $seenResultKeys[$domainKey] = true;
                }
            }
        }

        return $elements;
    }

    private function buildLegacyDomainElement(string $host, string $sourceTag, string $queryValue): ?OsintResult
    {
        $types = $this->classifyDiscoveredDomainDataTypes($host);
        $hostType = $types['host'];
        if ($hostType === null) {
            return null;
        }

        $resolved = true;
        if ($this->bool('verify_hostnames', true)) {
            $liveResolution = $this->hostResolvesNow($host);
            if ($liveResolution !== null) {
                $resolved = $liveResolution;
            }
        }

        if (!$resolved) {
            $hostType = $this->matchesRootTarget($host)
                ? 'Internet Name - Unresolved'
                : 'Affiliate - Internet Name - Unresolved';
        }

        $result = new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      0,
            severity:   'info',
            confidence: $resolved ? 75 : 45,
            responseMs: 0,
            summary:    "VirusTotal legacy domain report discovered {$host} while analyzing {$queryValue}.",
            tags:       [self::API_ID, 'domain', $sourceTag, $this->matchesRootTarget($host) ? 'same_target' : 'affiliate'],
            rawData:    ['host' => $host, 'source' => $sourceTag],
            success:    true,
            dataType:   $hostType
        );

        if ($resolved) {
            $result->addDiscovery(EventTypes::INTERNET_NAME, $host);
        }

        return $result;
    }

    /**
     * @return array{host:?string,domain:?string}
     */
    private function classifyDiscoveredDomainDataTypes(string $host): array
    {
        $sameTarget = $this->matchesRootTarget($host);
        $hostType = $sameTarget ? EventTypes::INTERNET_NAME : EventTypes::AFFILIATE_INTERNET_NAME;

        $registrable = $this->inferRegistrableDomain($host);
        $domainType = null;
        if ($registrable !== null && $registrable === $host) {
            $domainType = $sameTarget ? EventTypes::DOMAIN_NAME : EventTypes::AFFILIATE_DOMAIN_NAME;
        }

        return [
            'host' => $hostType,
            'domain' => $domainType,
        ];
    }

    private function domainReportLooksMalicious(?array $legacyDomainReport): bool
    {
        return $this->domainReportDetectedUrlCount($legacyDomainReport) > 0;
    }

    private function domainReportDetectedUrlCount(?array $legacyDomainReport): int
    {
        if (!is_array($legacyDomainReport)) {
            return 0;
        }

        $detectedUrls = $legacyDomainReport['detected_urls'] ?? null;
        return is_array($detectedUrls) ? count($detectedUrls) : 0;
    }

    /**
     * Fetch the VT v2 domain/report payload once and cache it for reuse.
     *
     * @return array<string, mixed>|null
     */
    private function fetchDomainReportV2(string $apiKey, string $domain): ?array
    {
        $apiKey = trim($apiKey);
        $domain = strtolower(trim(rtrim($domain, '.')));
        if ($apiKey === '' || $domain === '') {
            return null;
        }

        if (array_key_exists($domain, $this->domainReportV2Cache)) {
            return $this->domainReportV2Cache[$domain];
        }

        $dailyLimit = $this->int('daily_limit', 500);
        if (!ApiQuotaTracker::check(self::API_ID, $dailyLimit)) {
            $this->domainReportV2Cache[$domain] = null;
            return null;
        }

        $url = 'https://www.virustotal.com/vtapi/v2/domain/report?apikey='
            . urlencode($apiKey)
            . '&domain='
            . urlencode($domain);

        $response = HttpClient::get($url, []);
        ApiQuotaTracker::increment(self::API_ID);

        $status = (int)($response['status'] ?? 0);
        if ($status < 200 || $status >= 300 || !is_array($response['json'])) {
            $this->domainReportV2Cache[$domain] = null;
            return null;
        }

        $payload = $response['json'];
        $this->domainReportV2Cache[$domain] = $payload;
        return $payload;
    }

    /**
     * Fetch a VT relationships endpoint.
     * GET /v3/{resource_type}/{id}/{relationship}?limit={limit}
     */
    private function fetchRelationship(string $baseUrl, array $headers, string $resourceType, string $id, string $relationship, int $limit): array
    {
        $targetLimit = max(1, $limit);
        $pageSize = min(40, $targetLimit);
        $basePath = "{$baseUrl}/{$resourceType}/" . urlencode($id) . "/{$relationship}";
        $url = "{$basePath}?limit={$pageSize}";
        $results = [];
        $seenIds = [];

        while ($url !== '' && count($results) < $targetLimit) {
            $dailyLimit = $this->int('daily_limit', 500);
            if (!ApiQuotaTracker::check(self::API_ID, $dailyLimit)) {
                break;
            }

            $response = HttpClient::get($url, $headers);
            ApiQuotaTracker::increment(self::API_ID);
            if ($response['status'] < 200 || $response['status'] >= 300 || empty($response['json']['data'])) {
                break;
            }

            foreach ($response['json']['data'] as $item) {
                $itemId = (string)($item['id'] ?? '');
                $dedupeKey = $itemId !== '' ? $itemId : md5(json_encode($item));
                if (isset($seenIds[$dedupeKey])) {
                    continue;
                }
                $seenIds[$dedupeKey] = true;
                $results[] = $item;

                if (count($results) >= $targetLimit) {
                    break 2;
                }
            }

            $nextUrl = trim((string)($response['json']['links']['next'] ?? ''));
            if ($nextUrl !== '') {
                $url = $nextUrl;
                continue;
            }

            $cursor = trim((string)($response['json']['meta']['cursor'] ?? ''));
            if ($cursor === '') {
                break;
            }

            $remaining = $targetLimit - count($results);
            $nextLimit = min(40, $remaining);
            $url = "{$basePath}?limit={$nextLimit}&cursor=" . urlencode($cursor);
        }

        return $results;
    }

    /**
     * Fetch sibling domains for affiliate checks.
     * Uses VT v2 domain/report by default to mirror SpiderFoot's domain_siblings
     * output, then falls back to VT v3 relationships when unavailable.
     */
    private function fetchAffiliateDomainSiblings(string $baseUrl, array $headers, string $domain, int $limit): array
    {
        if ($this->bool('use_v2_domain_siblings', true)) {
            $apiKey = trim((string)($headers['x-apikey'] ?? ''));
            $v2Siblings = $this->fetchDomainSiblingsV2($apiKey, $domain, $limit);
            if (!empty($v2Siblings)) {
                return $v2Siblings;
            }
        }

        return $this->fetchRelationship($baseUrl, $headers, 'domains', $domain, 'siblings', $limit);
    }

    /**
     * Fetch domain siblings via VirusTotal v2 domain/report endpoint.
     *
     * @return array<int, array<string, mixed>>
     */
    private function fetchDomainSiblingsV2(string $apiKey, string $domain, int $limit): array
    {
        $payload = $this->fetchDomainReportV2($apiKey, $domain);
        if (!is_array($payload)) {
            return [];
        }

        $siblings = $payload['domain_siblings'] ?? null;
        if (!is_array($siblings) || empty($siblings)) {
            return [];
        }

        $results = [];
        $seen = [];
        foreach ($siblings as $item) {
            if (!is_string($item)) {
                continue;
            }

            $host = strtolower(trim(rtrim($item, '.')));
            if ($host === '' || !str_contains($host, '.')) {
                continue;
            }
            if (!preg_match('/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i', $host)) {
                continue;
            }
            if (isset($seen[$host])) {
                continue;
            }

            $seen[$host] = true;
            $results[] = [
                'id' => $host,
                'type' => 'domain',
                'attributes' => [
                    '_source' => 'vt_v2_domain_siblings',
                    'last_analysis_stats' => [],
                    'last_dns_records' => [],
                ],
            ];

            if (count($results) >= $limit) {
                break;
            }
        }

        return $results;
    }

    private function matchesRootTarget(string $host): bool
    {
        $rootType = strtolower($this->str('__root_query_type', $this->str('__query_type', '')));
        $rootValue = strtolower(trim(rtrim($this->str('__root_query_value', $this->str('__query_value', '')), '.')));
        $host = strtolower(trim(rtrim($host, '.')));

        if ($rootType !== 'domain' || $rootValue === '' || $host === '') {
            return $host === $rootValue;
        }

        return $host === $rootValue || str_ends_with($host, '.' . $rootValue);
    }

    private function inferRegistrableDomain(string $host): ?string
    {
        $host = strtolower(trim(rtrim($host, '.')));
        if ($host === '' || !str_contains($host, '.')) {
            return null;
        }

        $labels = array_values(array_filter(explode('.', $host), static fn($label): bool => $label !== ''));
        if (count($labels) < 2) {
            return null;
        }

        $tlds = GlobalSettings::internetTlds();
        $suffixes = [];
        foreach ($tlds as $tld) {
            $normalized = ltrim(strtolower(trim((string)$tld)), '.');
            if ($normalized !== '') {
                $suffixes[$normalized] = true;
            }
        }

        $labelCount = count($labels);
        $matchedSuffix = '';
        for ($i = 0; $i < $labelCount; $i++) {
            $candidateSuffix = implode('.', array_slice($labels, $i));
            if (isset($suffixes[$candidateSuffix]) && strlen($candidateSuffix) > strlen($matchedSuffix)) {
                $matchedSuffix = $candidateSuffix;
            }
        }

        if ($matchedSuffix !== '') {
            $suffixLabels = substr_count($matchedSuffix, '.') + 1;
            if ($labelCount <= $suffixLabels) {
                return null;
            }

            $registrableLabels = array_slice($labels, -($suffixLabels + 1));
            return implode('.', $registrableLabels);
        }

        return implode('.', array_slice($labels, -2));
    }

    private function normalizeDomainCandidate(mixed $candidate): ?string
    {
        if (!is_string($candidate)) {
            return null;
        }

        $host = strtolower(trim(rtrim($candidate, '.')));
        if ($host === '' || !str_contains($host, '.')) {
            return null;
        }
        if (!preg_match('/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/i', $host)) {
            return null;
        }

        return $host;
    }

    /**
     * Check if a CIDR network string (e.g. "1.2.3.0/24") fits within the
     * configured maximum CIDR prefix (prefix >= maxPrefix means /24 or smaller).
     */
    private function isNetblockWithinLimit(string $network, int $maxPrefix): bool
    {
        $parts = explode('/', $network, 2);
        if (count($parts) !== 2) return false;
        return (int)$parts[1] >= $maxPrefix;
    }

    /**
     * Resolve a hostname using local DNS resolvers.
     *
     * Returns:
     *  - true / false when a live resolution decision is possible
     *  - null when the runtime cannot perform a meaningful check
     */
    private function hostResolvesNow(string $hostname): ?bool
    {
        $host = strtolower(trim($hostname));
        $host = rtrim($host, '.');

        if ($host === '' || !str_contains($host, '.')) {
            return false;
        }

        if (!preg_match('/^[a-z0-9][a-z0-9\.-]*[a-z0-9]$/i', $host)) {
            return false;
        }

        if (isset($this->hostnameResolutionCache[$host])) {
            return $this->hostnameResolutionCache[$host];
        }

        $supported = false;
        $resolved = false;

        if (function_exists('dns_get_record')) {
            $supported = true;
            $recordsA = @dns_get_record($host, DNS_A);
            if (is_array($recordsA) && !empty($recordsA)) {
                $resolved = true;
            }
            if (!$resolved && defined('DNS_AAAA')) {
                $recordsAaaa = @dns_get_record($host, DNS_AAAA);
                if (is_array($recordsAaaa) && !empty($recordsAaaa)) {
                    $resolved = true;
                }
            }
            if (!$resolved && defined('DNS_CNAME')) {
                $recordsCname = @dns_get_record($host, DNS_CNAME);
                if (is_array($recordsCname) && !empty($recordsCname)) {
                    $resolved = true;
                }
            }
        }

        if (!$resolved && function_exists('gethostbynamel')) {
            $supported = true;
            $ips = @gethostbynamel($host);
            if (is_array($ips) && !empty($ips)) {
                $resolved = true;
            }
        }

        if (!$resolved && function_exists('gethostbyname')) {
            $supported = true;
            $ipv4 = @gethostbyname($host);
            if (is_string($ipv4) && $ipv4 !== $host && filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $resolved = true;
            }
        }

        if (!$supported) {
            return null;
        }

        $this->hostnameResolutionCache[$host] = $resolved;
        return $resolved;
    }
}
