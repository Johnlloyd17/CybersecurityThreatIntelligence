<?php
// =============================================================================
//  CTI - SCAN EXECUTOR
//  php/ScanExecutor.php
//
//  Shared execution logic consumed by:
//   - php/api/query.php       (HTTP entry point -> spawns background worker)
//   - php/background_scan.php (CLI background worker -> does the real work)
// =============================================================================

require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/ScanParity.php';
require_once __DIR__ . '/RawEvidenceStore.php';
require_once __DIR__ . '/CorrelationRuleEngine.php';
require_once __DIR__ . '/EventQueueRunner.php';
require_once __DIR__ . '/EventResultProjector.php';
require_once __DIR__ . '/CtiPythonServiceRunner.php';
require_once __DIR__ . '/SpiderFootBridgeRunner.php';

/**
 * Append a single log entry to scan_logs.
 */
function logScan(int $scanId, string $level, ?string $module, string $message): void
{
    try {
        DB::execute(
            "INSERT INTO scan_logs (scan_id, level, module, message) VALUES (:sid, :lvl, :mod, :msg)",
            [':sid' => $scanId, ':lvl' => $level, ':mod' => $module, ':msg' => $message]
        );
    } catch (Exception $e) {
        error_log('[scanlog] Failed: ' . $e->getMessage());
    }
}

/**
 * Lightweight schema checks used by the correlation persistence helpers.
 */
function scanExecutorTableExists(string $table): bool
{
    static $cache = [];
    if (array_key_exists($table, $cache)) {
        return $cache[$table];
    }

    $row = DB::queryOne(
        "SELECT 1
           FROM information_schema.tables
          WHERE table_schema = :schema
            AND table_name = :table
          LIMIT 1",
        [
            ':schema' => DB_NAME,
            ':table' => $table,
        ]
    );

    $cache[$table] = $row !== null;
    return $cache[$table];
}

function scanExecutorColumnExists(string $table, string $column): bool
{
    static $cache = [];
    $cacheKey = strtolower($table . '.' . $column);
    if (array_key_exists($cacheKey, $cache)) {
        return $cache[$cacheKey];
    }

    $row = DB::queryOne(
        "SELECT 1
           FROM information_schema.columns
          WHERE table_schema = :schema
            AND table_name = :table
            AND column_name = :column
          LIMIT 1",
        [
            ':schema' => DB_NAME,
            ':table' => $table,
            ':column' => $column,
        ]
    );

    $cache[$cacheKey] = $row !== null;
    return $cache[$cacheKey];
}

/**
 * @param array<int,int> $linkedResultIds
 */
function insertCorrelationFinding(
    int $scanId,
    string $ruleName,
    string $severity,
    string $title,
    string $detail,
    array $linkedResultIds = []
): void {
    $correlationId = (int)DB::insert(
        "INSERT INTO scan_correlations (scan_id, rule_name, severity, title, detail)
         VALUES (:sid, :rule, :severity, :title, :detail)",
        [
            ':sid' => $scanId,
            ':rule' => $ruleName,
            ':severity' => $severity,
            ':title' => $title,
            ':detail' => $detail,
        ]
    );

    if ($correlationId <= 0 || !scanExecutorTableExists('scan_correlation_events')) {
        return;
    }

    $linkedResultIds = array_values(array_unique(array_filter(
        array_map('intval', $linkedResultIds),
        fn(int $id): bool => $id > 0
    )));

    foreach ($linkedResultIds as $resultId) {
        DB::execute(
            "INSERT INTO scan_correlation_events (correlation_id, query_history_id)
             VALUES (:cid, :qid)
             ON DUPLICATE KEY UPDATE query_history_id = VALUES(query_history_id)",
            [
                ':cid' => $correlationId,
                ':qid' => $resultId,
            ]
        );
    }
}

/**
 * Evaluate correlation rules and write findings to scan_correlations.
 */
function runCorrelations(int $scanId, string $queryType, string $queryValue): void
{
    if (!scanExecutorTableExists('scan_correlations')) {
        return;
    }

    $hasFalsePositive = scanExecutorColumnExists('query_history', 'false_positive');
    $hasEnrichmentPass = scanExecutorColumnExists('query_history', 'enrichment_pass');
    $hasEnrichedFrom = scanExecutorColumnExists('query_history', 'enriched_from');
    $hasSourceRef = scanExecutorColumnExists('query_history', 'source_ref');

    $projection = implode(",\n                ", [
        'qh.id',
        'qh.query_type',
        'qh.query_value',
        'qh.api_source',
        'qh.result_summary',
        'qh.risk_score',
        'qh.status',
        $hasEnrichmentPass ? 'qh.enrichment_pass' : '0 AS enrichment_pass',
        $hasEnrichedFrom ? 'qh.enriched_from' : 'NULL AS enriched_from',
        $hasSourceRef ? "COALESCE(NULLIF(qh.source_ref, ''), 'ROOT') AS source_ref" : "'ROOT' AS source_ref",
        $hasFalsePositive ? 'qh.false_positive' : '0 AS false_positive',
        'ac.name AS api_name',
    ]);

    $whereParts = ['qh.scan_id = :sid', "qh.status = 'completed'"];
    if ($hasFalsePositive) {
        $whereParts[] = 'qh.false_positive = 0';
    }

    $rows = DB::query(
        "SELECT {$projection}
           FROM query_history qh
           LEFT JOIN api_configs ac ON ac.slug = qh.api_source
          WHERE " . implode(' AND ', $whereParts) . "
          ORDER BY qh.queried_at ASC, qh.id ASC",
        [':sid' => $scanId]
    );

    $engine = new CorrelationRuleEngine();
    $findings = $engine->evaluate($rows, $queryType, $queryValue);

    foreach ($findings as $finding) {
        insertCorrelationFinding(
            $scanId,
            (string)($finding['rule_name'] ?? 'UNKNOWN_RULE'),
            (string)($finding['severity'] ?? 'info'),
            trim((string)($finding['title'] ?? 'Untitled correlation')),
            trim((string)($finding['detail'] ?? '')),
            is_array($finding['linked_result_ids'] ?? null) ? $finding['linked_result_ids'] : []
        );
    }
}

class ScanExecutor
{
    /** Keep DNSAudit issue JSON mostly intact; TEXT columns are 64KB max. */
    private const DNSAUDIT_ISSUE_SUMMARY_MAX_BYTES = 60000;
    /** Modules where CTI's native PHP handler is the safer fallback than the SpiderFoot bridge. */
    private const PREFER_NATIVE_FALLBACK = [
        'wikipedia-edits',
    ];

    private static function findingSignature(
        string $apiSlug,
        string $queryType,
        string $queryValue,
        ?string $dataType,
        string $summary
    ): string {
        $normalizedSummary = preg_replace('/\s+/', ' ', strtolower(trim($summary))) ?: '';
        return hash('sha256', implode('|', [
            strtolower(trim($apiSlug)),
            strtolower(trim($queryType)),
            strtolower(trim($queryValue)),
            strtolower(trim((string)$dataType)),
            $normalizedSummary,
        ]));
    }

    private static function errorSignature(string $apiSlug, string $message): string
    {
        $normalizedMessage = preg_replace('/\s+/', ' ', strtolower(trim($message))) ?: '';
        return hash('sha256', strtolower(trim($apiSlug)) . '|' . $normalizedMessage);
    }

    private static function backendLabel(string $backendKey): string
    {
        return match ($backendKey) {
            'cti-python' => 'CTI Python Engine',
            'spiderfoot-bridge' => 'SpiderFoot Bridge',
            'cti-event-queue' => 'CTI Event Queue',
            'cti-legacy' => 'CTI Native Backend',
            default => ucwords(str_replace(['-', '_'], ' ', trim($backendKey))),
        };
    }

    /**
     * When the CTI Python service is unavailable, prefer the native CTI PHP
     * module over the SpiderFoot bridge for selected modules that already have
     * a stable first-party implementation.
     *
     * @param array<int,string> $selectedApis
     */
    private static function shouldPreferNativeFallback(array $selectedApis): bool
    {
        $selectedApis = array_values(array_unique(array_filter(array_map(
            static fn($slug): string => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn(string $slug): bool => $slug !== '')));

        if ($selectedApis === []) {
            return false;
        }

        foreach ($selectedApis as $slug) {
            if ($slug === 'abusech') {
                $slug = 'abuse-ch';
            }

            if (!in_array($slug, self::PREFER_NATIVE_FALLBACK, true)) {
                return false;
            }

            if (!OsintEngine::hasHandler($slug)) {
                return false;
            }
        }

        return true;
    }

    private static function persistBackendSelection(int $scanId, string $backendKey): void
    {
        if (!scanExecutorColumnExists('scans', 'config_snapshot')) {
            return;
        }

        try {
            $row = DB::queryOne(
                "SELECT config_snapshot FROM scans WHERE id = :id",
                [':id' => $scanId]
            );
            $snapshot = [];
            $rawSnapshot = $row['config_snapshot'] ?? null;
            if (is_string($rawSnapshot) && trim($rawSnapshot) !== '') {
                $decoded = json_decode($rawSnapshot, true);
                if (is_array($decoded)) {
                    $snapshot = $decoded;
                }
            } elseif (is_array($rawSnapshot)) {
                $snapshot = $rawSnapshot;
            }

            $snapshot['engine_backend'] = $backendKey;
            $snapshot['engine_backend_label'] = self::backendLabel($backendKey);
            $snapshot['engine_backend_recorded_at'] = gmdate('c');

            DB::execute(
                "UPDATE scans SET config_snapshot = :snapshot WHERE id = :id",
                [
                    ':snapshot' => json_encode($snapshot, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                    ':id' => $scanId,
                ]
            );
        } catch (Throwable $e) {
            logScan(
                $scanId,
                'warning',
                null,
                'Failed to persist backend selection (non-fatal): ' . $e->getMessage()
            );
        }
    }

    /**
     * @param array<string,int> $summary
     */
    private static function finaliseScan(
        int $scanId,
        string $queryType,
        string $queryValue,
        ScanParity $parity,
        array $summary,
        string $engineLabel = 'legacy'
    ): void {
        $currentStatus = DB::queryOne(
            "SELECT status FROM scans WHERE id = :id",
            [':id' => $scanId]
        )['status'] ?? 'unknown';

        if (in_array($currentStatus, ['aborted', 'failed'], true)) {
            logScan(
                $scanId,
                'warning',
                null,
                "Scan was {$currentStatus} externally. Collected "
                . (int)($summary['total_elements'] ?? 0)
                . ' elements, '
                . (int)($summary['error_count'] ?? 0)
                . ' errors before stop.'
            );
            self::cleanupParity($scanId, $parity);
            return;
        }

        DB::execute(
            "UPDATE scans SET status = 'finished', finished_at = NOW(),
                    total_elements = :te, unique_elements = :ue, error_count = :ec
             WHERE id = :id",
            [
                ':te' => (int)($summary['total_elements'] ?? 0),
                ':ue' => (int)($summary['unique_elements'] ?? 0),
                ':ec' => (int)($summary['error_count'] ?? 0),
                ':id' => $scanId,
            ]
        );

        $message = $engineLabel === 'legacy'
            ? 'Scan finished. '
            : 'Scan finished via ' . $engineLabel . '. ';

        $message .= (int)($summary['total_elements'] ?? 0)
            . ' elements, '
            . (int)($summary['error_count'] ?? 0)
            . ' errors.';

        if ((int)($summary['max_pass'] ?? 0) > 0) {
            $message .= ' Enrichment depth: ' . (int)$summary['max_pass'] . ' pass(es).';
        }

        logScan($scanId, 'info', null, $message);
        runCorrelations($scanId, $queryType, $queryValue);
        self::cleanupParity($scanId, $parity);
    }

    private static function cleanupParity(int $scanId, ScanParity $parity): void
    {
        try {
            $parity->closeCollectionWindow();
            $parity->disconnectEvidence();
            $evidenceStats = RawEvidenceStore::getScanStats($scanId);
            $evidenceCalls = (int)($evidenceStats['total_calls'] ?? 0);
            if ($evidenceCalls > 0) {
                logScan($scanId, 'info', null,
                    "Parity evidence collected: {$evidenceCalls} API call(s) recorded."
                );
            }
        } catch (Throwable $e) {
            logScan($scanId, 'warning', null,
                'Parity cleanup failed (non-fatal): ' . $e->getMessage()
            );
        }
    }

    public static function run(
        int $scanId,
        int $userId,
        string $queryType,
        string $queryValue,
        array $selectedApis
    ): void {
        $scanName = 'CTI SpiderFoot Scan';
        $scanSnapshot = [];
        $snapshotModuleSettings = null;

        try {
            $selectColumns = scanExecutorColumnExists('scans', 'config_snapshot')
                ? 'name, config_snapshot'
                : 'name';
            $scanRow = DB::queryOne(
                "SELECT {$selectColumns} FROM scans WHERE id = :id",
                [':id' => $scanId]
            );

            if (is_array($scanRow)) {
                $scanName = trim((string)($scanRow['name'] ?? $scanName)) ?: $scanName;
                if (!empty($scanRow['config_snapshot'])) {
                    $decodedSnapshot = json_decode((string)$scanRow['config_snapshot'], true);
                    if (is_array($decodedSnapshot)) {
                        $scanSnapshot = $decodedSnapshot;
                        if (isset($decodedSnapshot['module_settings']) && is_array($decodedSnapshot['module_settings'])) {
                            $snapshotModuleSettings = $decodedSnapshot['module_settings'];
                            logScan(
                                $scanId,
                                'info',
                                null,
                                'Using frozen module settings from config_snapshot ('
                                . count($snapshotModuleSettings)
                                . ' module(s)).'
                            );
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            logScan(
                $scanId,
                'warning',
                null,
                'Failed to load config_snapshot: ' . $e->getMessage() . ' - falling back to live DB settings.'
            );
        }

        if (CtiPythonServiceRunner::supportsScan($queryType, $selectedApis)) {
            try {
                self::persistBackendSelection($scanId, 'cti-python');
                logScan($scanId, 'info', 'cti-python', 'Own CTI Python engine selected for this scan.');
                $pythonRunner = new CtiPythonServiceRunner(
                    $scanId,
                    $userId,
                    $scanName,
                    $queryType,
                    $queryValue,
                    $selectedApis,
                    $scanSnapshot
                );
                $pythonRunner->run();
                return;
            } catch (CtiPythonServiceTerminated $e) {
                return;
            } catch (CtiPythonServiceSoftFailure $e) {
                logScan(
                    $scanId,
                    'warning',
                    'cti-python',
                    'CTI Python engine unavailable; falling back to existing backend: ' . $e->getMessage()
                );
            } catch (CtiPythonServiceHardFailure $e) {
                logScan(
                    $scanId,
                    'error',
                    'cti-python',
                    'CTI Python engine failed: ' . $e->getMessage()
                );
                return;
            } catch (Throwable $e) {
                logScan(
                    $scanId,
                    'warning',
                    'cti-python',
                    'CTI Python engine error; falling back to existing backend: ' . $e->getMessage()
                );
            }
        } else {
            logScan(
                $scanId,
                'info',
                'cti-python',
                CtiPythonServiceRunner::explainUnsupportedReason($queryType, $selectedApis)
            );
        }

        if (self::shouldPreferNativeFallback($selectedApis)) {
            logScan(
                $scanId,
                'info',
                'bridge',
                'SpiderFoot bridge skipped; using the native CTI backend for: '
                . implode(', ', array_values(array_unique($selectedApis))) . '.'
            );
        } elseif (SpiderFootBridgeRunner::supportsScan($queryType, $selectedApis)) {
            try {
                self::persistBackendSelection($scanId, 'spiderfoot-bridge');
                logScan($scanId, 'info', 'bridge', 'SpiderFoot Python backend selected for this scan.');
                $bridgeRunner = new SpiderFootBridgeRunner(
                    $scanId,
                    $userId,
                    $scanName,
                    $queryType,
                    $queryValue,
                    $selectedApis,
                    $scanSnapshot
                );
                $bridgeRunner->run();
                return;
            } catch (SpiderFootBridgeTerminated $e) {
                return;
            } catch (SpiderFootBridgeSoftFailure $e) {
                logScan(
                    $scanId,
                    'warning',
                    'bridge',
                    'SpiderFoot bridge unavailable; falling back to CTI backend: ' . $e->getMessage()
                );
            } catch (SpiderFootBridgeHardFailure $e) {
                logScan(
                    $scanId,
                    'error',
                    'bridge',
                    'SpiderFoot bridge failed: ' . $e->getMessage()
                );
                return;
            } catch (Throwable $e) {
                logScan(
                    $scanId,
                    'warning',
                    'bridge',
                    'SpiderFoot bridge error; falling back to CTI backend: ' . $e->getMessage()
                );
            }
        } else {
            $bridgeReason = SpiderFootBridgeRunner::supportsQueryType($queryType)
                ? 'SpiderFoot bridge does not support the selected module set; using CTI backend.'
                : 'SpiderFoot bridge does not support target type "' . $queryType . '"; using CTI backend.';
            logScan(
                $scanId,
                'info',
                'bridge',
                $bridgeReason
            );
        }

        GlobalSettings::load();
        HttpClient::applyGlobalSettings();

        $parity = new ScanParity($scanId);
        try {
            $apiConfigs = OsintEngine::loadApiConfigs($selectedApis);
            $parity->freezeConfiguration($selectedApis, $apiConfigs);
            logScan(
                $scanId,
                'info',
                null,
                'Parity system initialized: evidence collection active, '
                . count($selectedApis)
                . ' module(s) frozen in deterministic order.'
            );
        } catch (Throwable $e) {
            logScan($scanId, 'warning', null, 'Parity system init failed (non-fatal): ' . $e->getMessage());
        }

        if (GlobalSettings::isDebug()) {
            $concurrent = GlobalSettings::maxConcurrentModules();
            $timeout = GlobalSettings::httpTimeout();
            $maxBytes = GlobalSettings::maxBytesPerElement();
            $proxy = GlobalSettings::socksHost() !== ''
                ? (GlobalSettings::socksType() ?: 'SOCKS') . '://' . GlobalSettings::socksHost() . ':' . GlobalSettings::socksPort()
                : 'none';
            $dns = GlobalSettings::dnsResolver() ?: 'system default';
            logScan(
                $scanId,
                'debug',
                null,
                "[debug] Global settings - timeout={$timeout}s | concurrent={$concurrent}"
                . " | max_bytes={$maxBytes} | proxy={$proxy} | dns={$dns}"
            );
        }

        $eventRunner = new EventQueueRunner(
            $scanId,
            $userId,
            $queryType,
            $queryValue,
            $selectedApis,
            $snapshotModuleSettings
        );

        if ($eventRunner->isEnabled()) {
            self::persistBackendSelection($scanId, 'cti-event-queue');
            logScan($scanId, 'info', null, 'Event queue / watched-event routing enabled.');
            $summary = $eventRunner->run();
            self::finaliseScan($scanId, $queryType, $queryValue, $parity, $summary, 'event queue');
            return;
        }

        self::persistBackendSelection($scanId, 'cti-legacy');
        logScan(
            $scanId,
            'info',
            null,
            'Event queue tables not present; using legacy multi-pass enrichment engine.'
        );

        $apiResults = OsintEngine::queryWithEnrichment($queryType, $queryValue, $selectedApis, $scanId, $snapshotModuleSettings);
        $overallScore = 0;
        $errorCount = 0;
        $totalElements = 0;
        $uniqueFindingKeys = [];
        $maxPass = 0;
        $seenFindingSignatures = [];
        $seenErrorSignatures = [];

        foreach ($apiResults as $r) {
            $score = (int)($r['score'] ?? 0);
            $severity = (string)($r['severity'] ?? 'unknown');
            $conf = (int)($r['confidence'] ?? 0);
            $respMs = (int)($r['response_ms'] ?? 0);
            $summary = (string)($r['summary'] ?? '');
            $slug = (string)($r['api'] ?? '');
            $tags = is_array($r['tags'] ?? null) ? $r['tags'] : [];
            $isError = !($r['success'] ?? true) || isset($r['error']);

            $enrichPass = (int)($r['enrichment_pass'] ?? 0);
            $sourceRef = (string)($r['source_ref'] ?? 'ROOT');
            $enrichedFrom = $r['enriched_from'] ?? null;

            if ($enrichPass > $maxPass) {
                $maxPass = $enrichPass;
            }

            $isDnsAuditIssue = (
                strtolower((string)($r['api'] ?? '')) === 'dnsaudit'
                && strtolower((string)($r['data_type'] ?? '')) === 'dns security issue'
            );
            if ($isDnsAuditIssue) {
                if (strlen($summary) > self::DNSAUDIT_ISSUE_SUMMARY_MAX_BYTES) {
                    $summary = mb_strcut($summary, 0, self::DNSAUDIT_ISSUE_SUMMARY_MAX_BYTES - 3, 'UTF-8') . '...';
                }
            } else {
                $summary = GlobalSettings::truncate($summary);
            }

            $resultQueryValue = $enrichedFrom ?? $queryValue;
            $resultQueryType = (string)($r['query_type'] ?? $queryType);

            if ($isError) {
                $errorMessage = (string)($r['error'] ?? ($summary !== '' ? $summary : 'Module execution failed'));
                $errorSignature = self::errorSignature($slug, $errorMessage);
                if (isset($seenErrorSignatures[$errorSignature])) {
                    continue;
                }

                $seenErrorSignatures[$errorSignature] = true;
                $errorCount++;
                logScan($scanId, 'error', $slug, $errorMessage);
            } else {
                $dataType = $r['data_type'] ?? $resultQueryType;
                $findingSignature = self::findingSignature(
                    $slug,
                    $resultQueryType,
                    $resultQueryValue,
                    is_string($dataType) ? $dataType : null,
                    $summary
                );

                if (isset($seenFindingSignatures[$findingSignature])) {
                    continue;
                }

                $seenFindingSignatures[$findingSignature] = true;
                $totalElements++;
                $uniqueFindingKeys[$findingSignature] = true;
                $passLabel = $enrichPass > 0 ? " [enrichment pass {$enrichPass}]" : '';
                logScan($scanId, 'info', $slug, "Completed in {$respMs}ms - score: {$score}, severity: {$severity}{$passLabel}");
            }

            $rowStatus = $isError ? 'failed' : 'completed';
            $dataTypeVal = isset($r['data_type']) ? (string)$r['data_type'] : null;
            DB::execute(
                "INSERT INTO query_history
                    (user_id, scan_id, query_type, query_value, api_source, data_type,
                     result_summary, risk_score, status, response_time,
                     enrichment_pass, source_ref, enriched_from)
                 VALUES (:uid, :sid, :qt, :qv, :api, :dt,
                         :summary, :score, :status, :resp,
                         :epass, :sref, :efrom)",
                [
                    ':uid' => $userId,
                    ':sid' => $scanId,
                    ':qt' => $resultQueryType,
                    ':qv' => $resultQueryValue,
                    ':api' => $slug,
                    ':dt' => $dataTypeVal,
                    ':summary' => $summary,
                    ':score' => $score,
                    ':status' => $rowStatus,
                    ':resp' => $respMs,
                    ':epass' => $enrichPass,
                    ':sref' => $sourceRef,
                    ':efrom' => $enrichedFrom,
                ]
            );

            if (!$isError) {
                DB::execute(
                    "INSERT INTO threat_indicators
                        (indicator_type, indicator_value, source, severity, confidence, tags, first_seen, last_seen)
                     VALUES (:type, :val, :src, :sev, :conf, :tags, NOW(), NOW())
                     ON DUPLICATE KEY UPDATE
                        severity = IF(VALUES(severity) > severity, VALUES(severity), severity),
                        confidence = VALUES(confidence),
                        tags = VALUES(tags),
                        last_seen = NOW()",
                    [
                        ':type' => $resultQueryType,
                        ':val' => $resultQueryValue,
                        ':src' => $slug,
                        ':sev' => $severity,
                        ':conf' => $conf,
                        ':tags' => json_encode($tags, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    ]
                );
            }

            $overallScore = max($overallScore, $score);
        }

        self::finaliseScan($scanId, $queryType, $queryValue, $parity, [
            'overall_score' => $overallScore,
            'error_count' => $errorCount,
            'total_elements' => $totalElements,
            'unique_elements' => count($uniqueFindingKeys),
            'max_pass' => $maxPass,
        ], 'legacy');
    }
}
