<?php
// =============================================================================
//  CTI — OSINT RESULT DATA CLASS
//  php/OsintResult.php
//
//  Standardized result structure returned by all OSINT module handlers.
//  Maps directly to the response format expected by query.js.
// =============================================================================

class OsintResult
{
    public string  $api;
    public string  $apiName;
    public int     $score;
    public string  $severity;
    public int     $confidence;
    public int     $responseMs;
    public string  $summary;
    public array   $tags;
    public ?array  $rawData;
    public bool    $success;
    public ?string $error;
    /** SpiderFoot-style data type label (e.g. "Internet Name", "Affiliate - Internet Name") */
    public ?string $dataType;

    /**
     * Discovered sub-entities that can be used for enrichment cascading.
     * Each entry: ['type' => EventTypes::*, 'value' => string]
     * Example: a DNS module resolving example.com might add:
     *   [['type' => 'IP Address', 'value' => '93.184.216.34'], ...]
     *
     * The enrichment engine extracts these after each pass and feeds them
     * back as new query targets — mirroring SpiderFoot's event chaining.
     * @var array<int, array{type: string, value: string}>
     */
    public array $discoveries = [];

    /**
     * Source event hash — links this result to the parent event that triggered it.
     * For the initial scan pass this is 'ROOT'. For enrichment passes it references
     * the discovery that led to this module being invoked.
     * Mirrors SpiderFoot's source_event_hash in tbl_scan_results.
     */
    public string $sourceRef = 'ROOT';

    /** Enrichment pass number (0 = initial scan, 1+ = enrichment passes) */
    public int $enrichmentPass = 0;

    public function __construct(
        string  $api,
        string  $apiName,
        int     $score       = 0,
        string  $severity    = 'info',
        int     $confidence  = 0,
        int     $responseMs  = 0,
        string  $summary     = '',
        array   $tags        = [],
        ?array  $rawData     = null,
        bool    $success     = true,
        ?string $error       = null,
        ?string $dataType    = null,
        array   $discoveries = [],
        string  $sourceRef   = 'ROOT',
        int     $enrichmentPass = 0
    ) {
        $this->api            = $api;
        $this->apiName        = $apiName;
        $this->score          = $score;
        $this->severity       = $severity;
        $this->confidence     = $confidence;
        $this->responseMs     = $responseMs;
        $this->summary        = $summary;
        $this->tags           = $tags;
        $this->rawData        = $rawData;
        $this->success        = $success;
        $this->error          = $error;
        $this->dataType       = $dataType;
        $this->discoveries    = $discoveries;
        $this->sourceRef      = $sourceRef;
        $this->enrichmentPass = $enrichmentPass;
    }

    /**
     * Convert to the array format expected by query.php / query.js.
     */
    public function toArray(): array
    {
        $arr = [
            'api'              => $this->api,
            'api_name'         => $this->apiName,
            'score'            => $this->score,
            'severity'         => $this->severity,
            'confidence'       => $this->confidence,
            'response_ms'      => $this->responseMs,
            'summary'          => $this->summary,
            'tags'             => $this->tags,
            'success'          => $this->success,
            'enrichment_pass'  => $this->enrichmentPass,
            'source_ref'       => $this->sourceRef,
        ];
        if ($this->dataType !== null) {
            $arr['data_type'] = $this->dataType;
        }
        if ($this->error !== null) {
            $arr['error'] = $this->error;
        }
        if (!empty($this->discoveries)) {
            $arr['discoveries'] = $this->discoveries;
        }
        return $arr;
    }

    /**
     * Add a discovered sub-entity for enrichment cascading.
     */
    public function addDiscovery(string $eventType, string $value): self
    {
        $value = trim($value);
        if ($value === '') return $this;
        $this->discoveries[] = ['type' => $eventType, 'value' => $value];
        return $this;
    }

    /**
     * Create an error result.
     */
    public static function error(string $api, string $apiName, string $error, int $responseMs = 0): self
    {
        return new self(
            api:        $api,
            apiName:    $apiName,
            score:      0,
            severity:   'unknown',
            confidence: 0,
            responseMs: $responseMs,
            summary:    "Error querying {$apiName}: {$error}",
            tags:       [$api, 'error'],
            rawData:    null,
            success:    false,
            error:      $error
        );
    }

    /**
     * Create a rate-limited result.
     */
    public static function rateLimited(string $api, string $apiName, int $responseMs = 0): self
    {
        return new self(
            api:        $api,
            apiName:    $apiName,
            score:      0,
            severity:   'unknown',
            confidence: 0,
            responseMs: $responseMs,
            summary:    "{$apiName}: Rate limit exceeded. Try again later.",
            tags:       [$api, 'rate_limited'],
            rawData:    null,
            success:    false,
            error:      'Rate limit exceeded'
        );
    }

    /**
     * Create an unauthorized result.
     */
    public static function unauthorized(string $api, string $apiName, int $responseMs = 0): self
    {
        return new self(
            api:        $api,
            apiName:    $apiName,
            score:      0,
            severity:   'unknown',
            confidence: 0,
            responseMs: $responseMs,
            summary:    "{$apiName}: Invalid or expired API key.",
            tags:       [$api, 'unauthorized'],
            rawData:    null,
            success:    false,
            error:      'Invalid API key'
        );
    }

    /**
     * Create a not-found result.
     */
    public static function notFound(string $api, string $apiName, string $query, int $responseMs = 0): self
    {
        return new self(
            api:        $api,
            apiName:    $apiName,
            score:      0,
            severity:   'info',
            confidence: 90,
            responseMs: $responseMs,
            summary:    "{$apiName}: No records found for {$query}.",
            tags:       [$api, 'clean', 'not_found'],
            rawData:    null,
            success:    true,
            error:      null
        );
    }

    /**
     * Derive severity from a 0-100 score.
     */
    public static function scoreToSeverity(int $score): string
    {
        if ($score >= 90) return 'critical';
        if ($score >= 70) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 10) return 'low';
        return 'info';
    }
}
