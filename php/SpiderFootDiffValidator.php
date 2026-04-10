<?php
// =============================================================================
//  CTI — SPIDERFOOT DIFF VALIDATOR
//  php/SpiderFootDiffValidator.php
//
//  Imports SpiderFoot scan data (CSV export or JSON log) and compares it
//  against a CTI platform scan, producing a detailed diff report.
//
//  For each data Type:
//    - Shows SpiderFoot count vs CTI count
//    - Shows matched values, SpiderFoot-only, and CTI-only
//    - Attributes differences to: data_source, dns, time_window, or mapping
//
//  Output:
//    - Per-type breakdown with counts and values
//    - Overall parity score (0-100%)
//    - Diff reasons explaining where differences originate
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/ScanParity.php';
require_once __DIR__ . '/EventTypes.php';

class SpiderFootDiffValidator
{
    /** @var int CTI scan ID to compare against */
    private int $scanId;

    /** @var array Parsed SpiderFoot data: [{type, module, data, source}] */
    private array $sfData = [];

    /** @var string|null SpiderFoot scan ID from imported data */
    private ?string $sfScanId = null;

    /** @var string|null Imported filename */
    private ?string $sfFilename = null;

    // SpiderFoot CSV column indices (standard export format)
    private const SF_CSV_COL_UPDATED   = 0;
    private const SF_CSV_COL_TYPE      = 1;
    private const SF_CSV_COL_MODULE    = 2;
    private const SF_CSV_COL_SOURCE    = 3;
    private const SF_CSV_COL_F_P       = 4;
    private const SF_CSV_COL_DATA      = 5;

    // Type label mapping: SpiderFoot label → CTI EventTypes label
    // Most labels are identical; this handles known divergences.
    private static array $typeNormalization = [
        'Internet Name'                  => 'Internet Name',
        'IP Address'                     => 'IP Address',
        'IPv6 Address'                   => 'IPv6 Address',
        'Domain Name'                    => 'Domain Name',
        'Email Address'                  => 'Email Address',
        'Phone Number'                   => 'Phone Number',
        'Human Name'                     => 'Human Name',
        'Username'                       => 'Username',
        'Bitcoin Address'                => 'Bitcoin Address',
        'Hash'                           => 'Hash',
        'DNS TXT Record'                 => 'DNS TXT Record',
        'Email Gateway (DNS MX Records)' => 'Email Gateway (DNS MX Records)',
        'Name Server (DNS NS Records)'   => 'Name Server (DNS NS Records)',
        'DNS A Record'                   => 'DNS A Record',
        'DNS AAAA Record'                => 'DNS AAAA Record',
        'DNS CNAME Record'               => 'DNS CNAME Record',
        'DNS SOA Record'                 => 'DNS SOA Record',
        'Netblock Ownership'             => 'Netblock Ownership',
        'BGP AS Ownership'               => 'BGP AS Ownership',
        'Open TCP Port'                  => 'Open TCP Port',
        'Open TCP Port Banner'           => 'Open TCP Port Banner',
        'Operating System'               => 'Operating System',
        'Software Used'                  => 'Software Used',
        'Web Technology'                 => 'Web Technology',
        'SSL Certificate - Raw Data'     => 'SSL Certificate - Raw Data',
        'SSL Certificate - Issued to'    => 'SSL Certificate - Issued to',
        'SSL Certificate - Issued by'    => 'SSL Certificate - Issued by',
        'Co-Hosted Site'                 => 'Co-Hosted Site',
        'Co-Hosted Site - Domain Name'   => 'Co-Hosted Site - Domain Name',
        'Affiliate - Internet Name'      => 'Affiliate - Internet Name',
        'Affiliate - IP Address'         => 'Affiliate - IP Address',
        'Malicious IP Address'           => 'Malicious IP Address',
        'Malicious Internet Name'        => 'Malicious Internet Name',
        'Blacklisted IP Address'         => 'Blacklisted IP Address',
        'Blacklisted Internet Name'      => 'Blacklisted Internet Name',
        'Vulnerability'                  => 'Vulnerability',
        'Hacked Email Address'           => 'Hacked Email Address',
        'Social Media Presence'          => 'Social Media Presence',
        'Country Name'                   => 'Country Name',
        'Company Name'                   => 'Company Name',
        'Hosting Provider'               => 'Hosting Provider',
        'Domain Registrar'               => 'Domain Registrar',
        'Domain Whois'                   => 'Domain Whois',
        'TOR Exit Node'                  => 'TOR Exit Node',
        'Raw Data from RIRs/APIs'        => 'Raw Data from RIRs/APIs',
        'Leaked Data'                    => 'Leak Site Content',
        'Leak Site Content'              => 'Leak Site Content',
    ];

    public function __construct(int $scanId)
    {
        $this->scanId = $scanId;
    }

    // =========================================================================
    //  IMPORT SPIDERFOOT DATA
    // =========================================================================

    /**
     * Import SpiderFoot data from a CSV file (standard SF export format).
     *
     * SpiderFoot CSV columns: Updated, Type, Module, Source, F/P, Data
     *
     * @param string $csvContent Raw CSV content
     * @param string $filename   Original filename for reference
     * @return array{success: bool, count: int, error: ?string}
     */
    public function importCsv(string $csvContent, string $filename = ''): array
    {
        $this->sfFilename = $filename;
        $this->sfData = [];

        $lines = explode("\n", $csvContent);
        $headerSkipped = false;
        $count = 0;

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;

            // Skip header row
            if (!$headerSkipped) {
                if (stripos($line, 'Updated') !== false || stripos($line, 'Type') !== false) {
                    $headerSkipped = true;
                    continue;
                }
                $headerSkipped = true;
            }

            $fields = str_getcsv($line);
            if (count($fields) < 3) continue;

            $type   = trim($fields[self::SF_CSV_COL_TYPE] ?? '');
            $module = trim($fields[self::SF_CSV_COL_MODULE] ?? '');
            $source = trim($fields[self::SF_CSV_COL_SOURCE] ?? '');
            $fp     = trim($fields[self::SF_CSV_COL_F_P] ?? '0');
            $data   = trim($fields[self::SF_CSV_COL_DATA] ?? '');

            if ($type === '' || $type === 'ROOT') continue;

            // Normalize type label
            $normalizedType = self::$typeNormalization[$type] ?? $type;

            $this->sfData[] = [
                'type'           => $normalizedType,
                'original_type'  => $type,
                'module'         => $module,
                'source'         => $source,
                'false_positive' => $fp === '1',
                'data'           => $data,
            ];
            $count++;
        }

        return [
            'success' => $count > 0,
            'count'   => $count,
            'error'   => $count === 0 ? 'No valid data rows found in CSV.' : null,
        ];
    }

    /**
     * Import SpiderFoot data from JSON format (SF API export).
     *
     * @param string $jsonContent Raw JSON content
     * @param string $filename    Original filename
     * @return array{success: bool, count: int, error: ?string}
     */
    public function importJson(string $jsonContent, string $filename = ''): array
    {
        $this->sfFilename = $filename;
        $this->sfData = [];

        $data = json_decode($jsonContent, true);
        if (!is_array($data)) {
            return ['success' => false, 'count' => 0, 'error' => 'Invalid JSON format.'];
        }

        // Handle both array-of-events and {scan_id, events} formats
        $events = $data;
        if (isset($data['scan_id'])) {
            $this->sfScanId = (string)$data['scan_id'];
            $events = $data['events'] ?? $data['data'] ?? [];
        }

        $count = 0;
        foreach ($events as $event) {
            $type = $event['type'] ?? $event['event_type'] ?? '';
            if ($type === '' || $type === 'ROOT') continue;

            $normalizedType = self::$typeNormalization[$type] ?? $type;

            $this->sfData[] = [
                'type'           => $normalizedType,
                'original_type'  => $type,
                'module'         => $event['module'] ?? $event['source_module'] ?? '',
                'source'         => $event['source'] ?? '',
                'false_positive' => (bool)($event['false_positive'] ?? false),
                'data'           => $event['data'] ?? $event['value'] ?? '',
            ];
            $count++;
        }

        return [
            'success' => $count > 0,
            'count'   => $count,
            'error'   => $count === 0 ? 'No valid events found in JSON.' : null,
        ];
    }

    // =========================================================================
    //  COMPARE / DIFF
    // =========================================================================

    /**
     * Run the full diff comparison between SpiderFoot data and CTI scan results.
     *
     * @return array Complete diff report
     */
    public function compare(): array
    {
        if (empty($this->sfData)) {
            return ['success' => false, 'error' => 'No SpiderFoot data imported. Call importCsv() or importJson() first.'];
        }

        // Load CTI scan results
        $ctiResults = $this->loadCtiResults();
        if (empty($ctiResults)) {
            return ['success' => false, 'error' => 'No results found for CTI scan #' . $this->scanId];
        }

        // Build per-type buckets for SpiderFoot
        $sfByType = $this->bucketByType($this->sfData, 'data');

        // Build per-type buckets for CTI
        $ctiByType = $this->bucketCtiByType($ctiResults);

        // Compute per-type diff
        $allTypes = array_unique(array_merge(array_keys($sfByType), array_keys($ctiByType)));
        sort($allTypes);

        $typeDiffs = [];
        $totalMatched = 0;
        $totalSfOnly = 0;
        $totalCtiOnly = 0;

        foreach ($allTypes as $type) {
            $sfValues  = $sfByType[$type]  ?? [];
            $ctiValues = $ctiByType[$type] ?? [];

            // Normalize values for comparison
            $sfNorm  = array_map([self::class, 'normalizeValue'], $sfValues);
            $ctiNorm = array_map([self::class, 'normalizeValue'], $ctiValues);

            $sfUnique  = array_unique($sfNorm);
            $ctiUnique = array_unique($ctiNorm);

            $matched   = array_intersect($sfUnique, $ctiUnique);
            $sfOnly    = array_diff($sfUnique, $ctiUnique);
            $ctiOnly   = array_diff($ctiUnique, $sfUnique);

            $totalMatched += count($matched);
            $totalSfOnly  += count($sfOnly);
            $totalCtiOnly += count($ctiOnly);

            // Determine likely reason for differences
            $diffReason = $this->classifyDiffReason($type, $sfOnly, $ctiOnly);

            $typeDiffs[] = [
                'type'            => $type,
                'sf_count'        => count($sfValues),
                'cti_count'       => count($ctiValues),
                'sf_unique'       => count($sfUnique),
                'cti_unique'      => count($ctiUnique),
                'matched'         => count($matched),
                'sf_only_values'  => array_values(array_slice(array_values($sfOnly), 0, 50)),
                'cti_only_values' => array_values(array_slice(array_values($ctiOnly), 0, 50)),
                'diff_reason'     => $diffReason,
            ];
        }

        // Summary counts
        $sfTypeCount  = count(array_filter($allTypes, fn($t) => isset($sfByType[$t])));
        $ctiTypeCount = count(array_filter($allTypes, fn($t) => isset($ctiByType[$t])));
        $matchedTypes = count(array_filter($allTypes, fn($t) => isset($sfByType[$t]) && isset($ctiByType[$t])));
        $sfOnlyTypes  = count(array_filter($allTypes, fn($t) => isset($sfByType[$t]) && !isset($ctiByType[$t])));
        $ctiOnlyTypes = count(array_filter($allTypes, fn($t) => !isset($sfByType[$t]) && isset($ctiByType[$t])));

        // Overall parity score
        $totalValues = $totalMatched + $totalSfOnly + $totalCtiOnly;
        $parityScore = $totalValues > 0
            ? round(($totalMatched / $totalValues) * 100, 2)
            : 0;

        // Aggregate diff reasons
        $diffReasons = $this->aggregateDiffReasons($typeDiffs);

        // Build the full report
        $report = [
            'success'         => true,
            'scan_id'         => $this->scanId,
            'sf_scan_id'      => $this->sfScanId,
            'sf_filename'     => $this->sfFilename,
            'sf_total_types'  => $sfTypeCount,
            'cti_total_types' => $ctiTypeCount,
            'matched_types'   => $matchedTypes,
            'sf_only_types'   => $sfOnlyTypes,
            'cti_only_types'  => $ctiOnlyTypes,
            'total_matched'   => $totalMatched,
            'total_sf_only'   => $totalSfOnly,
            'total_cti_only'  => $totalCtiOnly,
            'parity_score'    => $parityScore,
            'diff_reasons'    => $diffReasons,
            'type_diffs'      => $typeDiffs,
        ];

        // Persist to database
        $this->persistDiffReport($report);

        return $report;
    }

    /**
     * Load previous diff reports for a scan.
     */
    public static function loadDiffReports(int $scanId): array
    {
        try {
            if (!function_exists('tableExists') || !tableExists('scan_sf_diff')) {
                return [];
            }
            return DB::query(
                "SELECT * FROM scan_sf_diff WHERE scan_id = :sid ORDER BY imported_at DESC",
                [':sid' => $scanId]
            );
        } catch (\Throwable $e) {
            return [];
        }
    }

    // =========================================================================
    //  INTERNAL: Data loading and bucketing
    // =========================================================================

    private function loadCtiResults(): array
    {
        try {
            $hasDataType = function_exists('columnExists') && columnExists('query_history', 'data_type');
            $hasEnrichmentPass = function_exists('columnExists') && columnExists('query_history', 'enrichment_pass');

            $cols = ['qh.api_source', 'qh.result_summary', 'qh.query_type', 'qh.query_value', 'qh.status'];
            if ($hasDataType) $cols[] = 'qh.data_type';
            if ($hasEnrichmentPass) $cols[] = 'qh.enrichment_pass';

            return DB::query(
                "SELECT " . implode(', ', $cols) . "
                 FROM query_history qh
                 WHERE qh.scan_id = :sid AND qh.status = 'completed'
                 ORDER BY qh.queried_at ASC",
                [':sid' => $this->scanId]
            );
        } catch (\Throwable $e) {
            error_log("[SpiderFootDiffValidator] Failed to load CTI results: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Bucket SpiderFoot data by normalized type.
     */
    private function bucketByType(array $data, string $valueField): array
    {
        $buckets = [];
        foreach ($data as $row) {
            $type = $row['type'] ?? 'Unknown';
            if ($row['false_positive'] ?? false) continue;
            $buckets[$type][] = $row[$valueField] ?? '';
        }
        return $buckets;
    }

    /**
     * Bucket CTI results by data_type (or query_type fallback).
     */
    private function bucketCtiByType(array $results): array
    {
        $buckets = [];
        foreach ($results as $r) {
            $type = $r['data_type'] ?? $r['query_type'] ?? 'Unknown';
            $value = $r['result_summary'] ?? '';
            $buckets[$type][] = $value;
        }
        return $buckets;
    }

    // =========================================================================
    //  INTERNAL: Diff classification
    // =========================================================================

    /**
     * Classify the most likely reason for differences in a specific type.
     */
    private function classifyDiffReason(string $type, array $sfOnly, array $ctiOnly): string
    {
        if (empty($sfOnly) && empty($ctiOnly)) {
            return 'exact_match';
        }

        // DNS-related types — likely DNS resolver/timing differences
        $dnsTypes = [
            'DNS A Record', 'DNS AAAA Record', 'DNS TXT Record', 'DNS MX Record',
            'DNS CNAME Record', 'DNS SOA Record', 'DNS NS Record',
            'Email Gateway (DNS MX Records)', 'Name Server (DNS NS Records)',
        ];
        if (in_array($type, $dnsTypes, true)) {
            return 'dns';
        }

        // If only counts differ but values overlap significantly, likely time_window
        $totalDiff = count($sfOnly) + count($ctiOnly);
        $totalValues = $totalDiff + count(array_intersect(
            array_unique(array_map([self::class, 'normalizeValue'], $sfOnly)),
            array_unique(array_map([self::class, 'normalizeValue'], $ctiOnly))
        ));

        if ($totalValues > 0 && ($totalDiff / max(1, $totalValues)) < 0.3) {
            return 'time_window';
        }

        // If one side has data and other doesn't, likely data_source difference
        if (empty($sfOnly) || empty($ctiOnly)) {
            return 'data_source';
        }

        // If type label doesn't match standard EventTypes, likely mapping
        $knownTypes = EventTypes::all();
        if (!in_array($type, $knownTypes, true)) {
            return 'mapping';
        }

        return 'data_source';
    }

    /**
     * Aggregate diff reasons across all types into a summary.
     */
    private function aggregateDiffReasons(array $typeDiffs): array
    {
        $reasons = [];
        foreach ($typeDiffs as $td) {
            $reason = $td['diff_reason'] ?? 'unknown';
            if ($reason === 'exact_match') continue;

            if (!isset($reasons[$reason])) {
                $reasons[$reason] = ['count' => 0, 'types' => []];
            }
            $reasons[$reason]['count']++;
            $reasons[$reason]['types'][] = $td['type'];
        }

        $result = [];
        foreach ($reasons as $reason => $info) {
            $result[] = [
                'reason'      => $reason,
                'description' => self::reasonDescription($reason),
                'type_count'  => $info['count'],
                'types'       => array_slice($info['types'], 0, 20),
            ];
        }

        return $result;
    }

    private static function reasonDescription(string $reason): string
    {
        return match ($reason) {
            'data_source'  => 'Different data returned by external API (version, coverage, or rate limits differ)',
            'dns'          => 'DNS resolver or TTL difference caused different resolution results',
            'time_window'  => 'Data changed between scan times (API data is dynamic)',
            'mapping'      => 'Type label mapping difference between SpiderFoot and CTI platform',
            default        => 'Unknown cause — manual review recommended',
        };
    }

    // =========================================================================
    //  INTERNAL: Value normalization
    // =========================================================================

    /**
     * Normalize a value for comparison purposes.
     */
    private static function normalizeValue(string $value): string
    {
        $v = strtolower(trim($value));
        // Remove trailing dots from domain names
        $v = rtrim($v, '.');
        // Collapse whitespace
        $v = preg_replace('/\s+/', ' ', $v) ?: $v;
        return $v;
    }

    // =========================================================================
    //  INTERNAL: Persist diff report
    // =========================================================================

    private function persistDiffReport(array $report): void
    {
        try {
            if (!function_exists('tableExists') || !tableExists('scan_sf_diff')) {
                return;
            }

            DB::execute(
                "INSERT INTO scan_sf_diff
                    (scan_id, sf_import_id, sf_filename,
                     sf_total_types, cti_total_types, matched_types,
                     sf_only_types, cti_only_types,
                     type_diff, parity_score, diff_reasons)
                 VALUES
                    (:sid, :sf_id, :fname,
                     :sf_types, :cti_types, :matched,
                     :sf_only, :cti_only,
                     :type_diff, :score, :reasons)",
                [
                    ':sid'       => $this->scanId,
                    ':sf_id'     => $this->sfScanId,
                    ':fname'     => $this->sfFilename,
                    ':sf_types'  => $report['sf_total_types'] ?? 0,
                    ':cti_types' => $report['cti_total_types'] ?? 0,
                    ':matched'   => $report['matched_types'] ?? 0,
                    ':sf_only'   => $report['sf_only_types'] ?? 0,
                    ':cti_only'  => $report['cti_only_types'] ?? 0,
                    ':type_diff' => json_encode($report['type_diffs'] ?? []),
                    ':score'     => $report['parity_score'] ?? 0,
                    ':reasons'   => json_encode($report['diff_reasons'] ?? []),
                ]
            );
        } catch (\Throwable $e) {
            error_log("[SpiderFootDiffValidator] Failed to persist diff report: " . $e->getMessage());
        }
    }
}
