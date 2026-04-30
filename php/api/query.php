<?php
// =============================================================================
//  CTI - QUERY / SCAN ENGINE API
// =============================================================================

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../security-headers.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../InputSanitizer.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/../ModuleSettingsSchema.php';
require_once __DIR__ . '/../SpiderFootModuleMapper.php';
require_once __DIR__ . '/../OsintEngine.php';
require_once __DIR__ . '/../ScanExecutor.php';
require_once __DIR__ . '/../EventResultProjector.php';
require_once __DIR__ . '/../ScanExportFormatter.php';

SecurityHeaders::init();
header('Content-Type: application/json; charset=utf-8');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$userId = $_SESSION['user_id'] ?? null;
$userRole = $_SESSION['user_role'] ?? null;
if (!$userId) {
    jsonQuery(401, ['error' => 'Authentication required.']);
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'execute': handleExecute((int)$userId); break;
    case 'history': handleHistory((int)$userId, $userRole); break;
    case 'list_scans': handleListScans((int)$userId, $userRole); break;
    case 'scan_detail': handleScanDetail((int)$userId, $userRole); break;
    case 'clone_scan': handleCloneScan((int)$userId, $userRole); break;
    case 'search_results': handleSearchResults((int)$userId, $userRole); break;
    case 'multi_export': handleMultiExport((int)$userId, $userRole); break;
    case 'delete_scan': handleDeleteScan((int)$userId, $userRole); break;
    case 'rerun_scan': handleRerunScan((int)$userId); break;
    case 'multi_rerun': handleMultiRerun((int)$userId, $userRole); break;
    case 'set_false_positive': handleSetFalsePositive((int)$userId, $userRole); break;
    case 'rerun_correlations': handleRerunCorrelations((int)$userId, $userRole); break;
    case 'abort_scan': handleAbortScan((int)$userId, $userRole); break;
    case 'multi_abort': handleMultiAbort((int)$userId, $userRole); break;
    case 'replay_scan': handleReplayScan((int)$userId, $userRole); break;
    case 'replay_info': handleReplayInfo((int)$userId, $userRole); break;
    case 'sf_diff_import': handleSfDiffImport((int)$userId, $userRole); break;
    case 'sf_diff_compare': handleSfDiffCompare((int)$userId, $userRole); break;
    case 'sf_diff_reports': handleSfDiffReports((int)$userId, $userRole); break;
    case 'evidence_stats': handleEvidenceStats((int)$userId, $userRole); break;
    case 'parity_config': handleParityConfig((int)$userId, $userRole); break;
    case 'db_maintenance':
        if (strtolower($userRole ?? '') !== 'admin') {
            jsonQuery(403, ['error' => 'Administrator access required.']);
        }
        handleDbMaintenance();
        break;
    case 'delete_history':
        if (strtolower($userRole ?? '') !== 'admin') {
            jsonQuery(403, ['error' => 'Administrator access required.']);
        }
        handleDeleteHistory();
        break;
    default:
        jsonQuery(400, ['error' => 'Unknown action.']);
}

function handleExecute(int $userId): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $allowedTypes = ['domain', 'ip', 'url', 'hash', 'email', 'cve', 'username', 'phone', 'bitcoin'];
    $queryType = strtolower(trim((string)($input['query_type'] ?? '')));
    if (!in_array($queryType, $allowedTypes, true)) {
        jsonQuery(422, ['error' => 'Invalid query type.']);
    }

    $scanName = trim((string)($input['scan_name'] ?? 'Untitled Scan'));
    if (strlen($scanName) > 200) {
        $scanName = substr($scanName, 0, 200);
    }

    $queryValue = normalizeQueryValue((string)($input['query_value'] ?? ''), $queryType);
    if ($queryValue === '' || strlen($queryValue) > 500) {
        jsonQuery(422, ['error' => 'Query value must be between 1 and 500 characters.']);
    }

    $useCase = trim((string)($input['use_case'] ?? ''));
    $knownSlugs = getEnabledApiSlugs();
    $selectedRaw = $input['apis'] ?? [];
    if (!is_array($selectedRaw)) {
        $selectedRaw = [];
    }
    $selectedApis = array_values(array_filter($selectedRaw, fn($slug) => in_array($slug, $knownSlugs, true)));

    if (empty($selectedApis)) {
        jsonQuery(422, ['error' => 'Select at least one API source.']);
    }

    $scanSnapshot = buildScanSnapshot(
        $scanName,
        $queryType,
        $queryValue,
        $useCase,
        $selectedApis,
        null,
        'execute'
    );
    $scanId = insertScanRecord(
        $userId,
        $scanName,
        $queryValue,
        $queryType,
        $useCase ?: null,
        $selectedApis,
        $scanSnapshot
    );

    logScan($scanId, 'info', null, "Scan started: '{$scanName}' targeting {$queryValue} ({$queryType})");
    logScan($scanId, 'info', null, count($selectedApis) . ' modules selected for execution.');

    $launched = spawnBackgroundScan($scanId, $userId);
    if (!$launched) {
        logScan($scanId, 'warning', null, 'Background spawn failed - running scan inline.');
        DB::execute("UPDATE scans SET status = 'running' WHERE id = :id", [':id' => $scanId]);
        set_time_limit(0);
        ignore_user_abort(true);
        ScanExecutor::run($scanId, $userId, $queryType, $queryValue, $selectedApis);
    }

    jsonQuery(200, ['scan_id' => $scanId]);
}

function spawnBackgroundScan(int $scanId, int $userId): bool
{
    $phpBinary = OsintEngine::resolvePhpBinary();
    $script = realpath(__DIR__ . '/../background_scan.php');

    if (!$script || !is_file($script)) {
        error_log('[query] background_scan.php not found');
        return false;
    }

    $cmd = escapeshellarg($phpBinary)
         . ' ' . escapeshellarg($script)
         . ' ' . (int)$scanId
         . ' ' . (int)$userId;

    if (PHP_OS_FAMILY === 'Windows') {
        $handle = @popen('start /B "" ' . $cmd, 'r');
        if (!$handle) {
            error_log('[query] popen failed for background_scan');
            return false;
        }
        pclose($handle);
    } else {
        $handle = @popen($cmd . ' > /dev/null 2>&1 &', 'r');
        if (!$handle) {
            error_log('[query] popen failed for background_scan');
            return false;
        }
        pclose($handle);
    }

    return true;
}

function handleListScans(int $userId, ?string $role): void
{
    $page = max(1, (int)($_GET['page'] ?? 1));
    $limit = min(100, max(1, (int)($_GET['limit'] ?? 20)));
    $offset = ($page - 1) * $limit;
    $status = trim((string)($_GET['status'] ?? ''));
    $isAdmin = strtolower($role ?? '') === 'admin';

    $where = [];
    $params = [];

    if (!$isAdmin) {
        $where[] = 's.user_id = :uid';
        $params[':uid'] = $userId;
    }

    if ($status === 'failed') {
        $where[] = "s.status IN ('failed','aborted')";
    } elseif ($status !== '' && in_array($status, ['starting', 'running', 'finished', 'aborted'], true)) {
        $where[] = 's.status = :status';
        $params[':status'] = $status;
    }

    $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
    $hasScanCorrelations = tableExists('scan_correlations');
    $correlationSelectSql = $hasScanCorrelations
        ? "(SELECT COUNT(*) FROM scan_correlations sc WHERE sc.scan_id = s.id AND sc.severity = 'high') AS corr_high,
           (SELECT COUNT(*) FROM scan_correlations sc WHERE sc.scan_id = s.id AND sc.severity = 'medium') AS corr_medium,
           (SELECT COUNT(*) FROM scan_correlations sc WHERE sc.scan_id = s.id AND sc.severity = 'low') AS corr_low,
           (SELECT COUNT(*) FROM scan_correlations sc WHERE sc.scan_id = s.id AND sc.severity = 'info') AS corr_info"
        : "0 AS corr_high,
           0 AS corr_medium,
           0 AS corr_low,
           0 AS corr_info";

    try {
        $total = (int)(DB::queryOne("SELECT COUNT(*) AS n FROM scans s {$whereClause}", $params)['n'] ?? 0);

        $sql = "SELECT s.id, s.name, s.target, s.target_type, s.status, s.use_case,
                       s.total_elements, s.unique_elements, s.error_count,
                       s.started_at, s.finished_at, u.full_name AS user_name,
                       {$correlationSelectSql}
                FROM scans s
                JOIN users u ON u.id = s.user_id
                {$whereClause}
                ORDER BY s.started_at DESC
                LIMIT :limit OFFSET :offset";

        $stmt = DB::connect()->prepare($sql);
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $scans = $stmt->fetchAll();

        foreach ($scans as &$scan) {
            $scanId = (int)($scan['id'] ?? 0);
            if ($scanId <= 0) {
                continue;
            }

            $statusLabel = strtolower(trim((string)($scan['status'] ?? '')));
            $shouldRefreshSummary = in_array($statusLabel, ['running', 'aborted', 'failed'], true)
                || (int)($scan['total_elements'] ?? 0) === 0;

            if (!$shouldRefreshSummary) {
                continue;
            }

            $summary = recalculateScanSummaryFromStorage(
                $scanId,
                in_array($statusLabel, ['aborted', 'failed'], true)
            );

            $scan['total_elements'] = $summary['total_elements'];
            $scan['unique_elements'] = $summary['unique_elements'];
            $scan['error_count'] = $summary['error_count'];
        }
        unset($scan);

        jsonQuery(200, [
            'scans' => $scans,
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ]);
    } catch (Exception $e) {
        error_log('[query/list_scans] ' . $e->getMessage());
        jsonQuery(500, ['error' => 'Failed to load scans.']);
    }
}

function handleScanDetail(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $hasEnrichmentPass = columnExists('query_history', 'enrichment_pass');
    $hasSourceRef = columnExists('query_history', 'source_ref');
    $hasEnrichedFrom = columnExists('query_history', 'enriched_from');
    $hasFalsePositive = columnExists('query_history', 'false_positive');
    $hasFpMarkedAt = columnExists('query_history', 'fp_marked_at');
    $hasConfigSnapshot = columnExists('scans', 'config_snapshot');

    try {
        $scan = DB::queryOne(
            "SELECT s.*, u.full_name AS user_name
             FROM scans s
             JOIN users u ON u.id = s.user_id
             WHERE s.id = :id" . ($isAdmin ? '' : ' AND s.user_id = :uid'),
            $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId]
        );

        if (!$scan) {
            jsonQuery(404, ['error' => 'Scan not found.']);
        }

        $resultsProjection = implode(",\n                    ", [
            'qh.id',
            'qh.query_type',
            'qh.query_value',
            'qh.api_source',
            'qh.data_type',
            'qh.result_summary',
            'qh.risk_score',
            'qh.status',
            'qh.response_time',
            'qh.queried_at',
            $hasEnrichmentPass ? 'qh.enrichment_pass' : '0 AS enrichment_pass',
            $hasSourceRef ? 'qh.source_ref' : 'NULL AS source_ref',
            $hasEnrichedFrom ? 'qh.enriched_from' : 'NULL AS enriched_from',
            $hasFalsePositive ? 'qh.false_positive' : '0 AS false_positive',
            $hasFpMarkedAt ? 'qh.fp_marked_at' : 'NULL AS fp_marked_at',
            $hasSourceRef ? "COALESCE(NULLIF(qh.source_ref, ''), 'ROOT') AS source_data" : "'ROOT' AS source_data",
            'ac.name AS api_name',
            'ac.category AS api_category',
        ]);

        $results = DB::query(
            "SELECT {$resultsProjection}
             FROM query_history qh
             LEFT JOIN api_configs ac ON ac.slug = qh.api_source
             WHERE qh.scan_id = :sid
             ORDER BY qh.queried_at ASC",
            [':sid' => $scanId]
        );

        if (tableExists('scan_correlations')) {
            if (tableExists('scan_correlation_events')) {
                $correlations = DB::query(
                    "SELECT sc.*,
                            COUNT(sce.query_history_id) AS linked_result_count,
                            GROUP_CONCAT(DISTINCT sce.query_history_id ORDER BY sce.query_history_id ASC SEPARATOR ',') AS linked_result_ids
                       FROM scan_correlations sc
                       LEFT JOIN scan_correlation_events sce ON sce.correlation_id = sc.id
                      WHERE sc.scan_id = :sid
                      GROUP BY sc.id
                      ORDER BY FIELD(sc.severity, 'high', 'medium', 'low', 'info'), sc.created_at DESC",
                    [':sid' => $scanId]
                );

                foreach ($correlations as &$correlation) {
                    $linkedIds = trim((string)($correlation['linked_result_ids'] ?? ''));
                    $correlation['linked_result_ids'] = $linkedIds === ''
                        ? []
                        : array_values(array_filter(array_map('intval', explode(',', $linkedIds)), fn($id) => $id > 0));
                    $correlation['linked_result_count'] = (int)($correlation['linked_result_count'] ?? 0);
                }
                unset($correlation);
            } else {
                $correlations = DB::query(
                    "SELECT * FROM scan_correlations
                     WHERE scan_id = :sid
                     ORDER BY FIELD(severity, 'high', 'medium', 'low', 'info'), created_at DESC",
                    [':sid' => $scanId]
                );
            }
        } else {
            $correlations = [];
        }

        $logs = tableExists('scan_logs')
            ? DB::query(
                "SELECT * FROM scan_logs WHERE scan_id = :sid ORDER BY logged_at ASC",
                [':sid' => $scanId]
            )
            : [];
        $summary = computeScanSummaryFromRows($results, $logs);
        $shouldRefreshStoredSummary = in_array((string)$scan['status'], ['aborted', 'failed'], true)
            || ((int)($scan['total_elements'] ?? 0) === 0 && $summary['total_elements'] > 0);
        if ($shouldRefreshStoredSummary) {
            $scan['total_elements'] = $summary['total_elements'];
            $scan['unique_elements'] = $summary['unique_elements'];
            $scan['error_count'] = $summary['error_count'];

            if (in_array((string)$scan['status'], ['aborted', 'failed'], true)) {
                persistScanSummaryCounts($scanId, $summary);
            }
        }

        $eventGraph = EventResultProjector::buildEventGraph($scanId);
        $eventStats = EventResultProjector::eventStats($scanId);

        $typeMap = [];
        foreach ($results as $result) {
            if (($result['status'] ?? '') === 'failed') {
                continue;
            }

            $rawType = $result['data_type'] ?? $result['api_category'] ?? $result['query_type'] ?? 'unknown';
            $displayType = $result['data_type'] ? $rawType : ucwords(str_replace(['_', '-'], ' ', $rawType));

            if (!isset($typeMap[$displayType])) {
                $typeMap[$displayType] = [
                    'type' => $displayType,
                    'unique_elements' => 0,
                    'total_elements' => 0,
                    'last_element_at' => null,
                    'seen_values' => [],
                ];
            }

            $typeMap[$displayType]['total_elements']++;
            $rawSummary = trim((string)($result['result_summary'] ?? ''));
            $valueKey = $rawSummary !== '' ? md5($rawSummary) : ('src:' . ($result['api_source'] ?? ''));
            if (!isset($typeMap[$displayType]['seen_values'][$valueKey])) {
                $typeMap[$displayType]['seen_values'][$valueKey] = true;
                $typeMap[$displayType]['unique_elements']++;
            }

            $ts = $result['queried_at'] ?? null;
            if ($ts && (!$typeMap[$displayType]['last_element_at'] || $ts > $typeMap[$displayType]['last_element_at'])) {
                $typeMap[$displayType]['last_element_at'] = $ts;
            }
        }

        foreach ($typeMap as &$item) {
            unset($item['seen_values']);
        }
        unset($item);

        $selectedModules = $scan['selected_modules'];
        if (is_string($selectedModules)) {
            $selectedModules = json_decode($selectedModules, true) ?? [];
        }

        $configSnapshot = $hasConfigSnapshot ? parseScanConfigSnapshotValue($scan) : null;
        $backendInfo = detectScanBackend($scan, $logs);

        $isLive = in_array($scan['status'], ['starting', 'running'], true);
        $stuck = false;
        if ($isLive && !empty($scan['started_at'])) {
            $startedTs = strtotime((string)$scan['started_at']);
            if ($startedTs !== false && (time() - $startedTs) > 600) {
                $stuck = true;
            }
        }

        jsonQuery(200, [
            'scan' => [
                'id' => (int)$scan['id'],
                'name' => $scan['name'],
                'target' => $scan['target'],
                'target_type' => $scan['target_type'],
                'status' => $scan['status'],
                'use_case' => $scan['use_case'],
                'selected_modules' => $selectedModules,
                'config_snapshot' => $configSnapshot,
                'backend_key' => $backendInfo['key'],
                'backend_used' => $backendInfo['label'],
                'total_elements' => $scan['total_elements'],
                'unique_elements' => $scan['unique_elements'],
                'error_count' => $scan['error_count'],
                'started_at' => $scan['started_at'],
                'finished_at' => $scan['finished_at'],
                'user_name' => $scan['user_name'],
                'stuck' => $stuck,
            ],
            'scan_settings' => buildScanSettingsView($scan, $backendInfo),
            'results' => $results,
            'correlations' => $correlations,
            'browse' => array_values($typeMap),
            'logs' => $logs,
            'event_graph' => $eventGraph,
            'event_stats' => $eventStats,
        ]);
    } catch (Exception $e) {
        error_log('[query/scan_detail] ' . $e->getMessage());
        jsonQuery(500, ['error' => 'Failed to load scan details.']);
    }
}

function handleCloneScan(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $scan = DB::queryOne(
        "SELECT * FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid'),
        $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId]
    );

    if (!$scan) {
        jsonQuery(404, ['error' => 'Scan not found.']);
    }

    $selectedModules = $scan['selected_modules'];
    if (is_string($selectedModules)) {
        $selectedModules = json_decode($selectedModules, true) ?? [];
    }

    $configSnapshot = columnExists('scans', 'config_snapshot') ? ($scan['config_snapshot'] ?? null) : null;
    if (is_string($configSnapshot)) {
        $configSnapshot = json_decode($configSnapshot, true) ?? null;
    }

    jsonQuery(200, [
        'scan' => [
            'id' => (int)$scan['id'],
            'name' => $scan['name'],
            'target' => $scan['target'],
            'target_type' => $scan['target_type'],
            'use_case' => $scan['use_case'],
            'selected_modules' => $selectedModules,
            'config_snapshot' => $configSnapshot,
        ],
    ]);
}

function handleSearchResults(int $userId, ?string $role): void
{
    $query = trim((string)($_GET['q'] ?? ''));
    if ($query === '') {
        jsonQuery(422, ['error' => 'Search query is required.']);
    }

    $mode = strtolower(trim((string)($_GET['mode'] ?? 'auto')));
    $scanId = (int)($_GET['scan_id'] ?? 0);
    $limit = min(200, max(1, (int)($_GET['limit'] ?? 50)));
    $isAdmin = strtolower($role ?? '') === 'admin';
    $hasSourceRef = columnExists('query_history', 'source_ref');
    $hasEnrichedFrom = columnExists('query_history', 'enriched_from');
    $hasFalsePositive = columnExists('query_history', 'false_positive');

    if ($mode === 'auto') {
        if (preg_match('/^\\/.+\\/[imsxuADSUXJ]*$/', $query)) {
            $mode = 'regex';
            $query = preg_replace('/^\\/(.+)\\/[imsxuADSUXJ]*$/', '$1', $query) ?? $query;
        } elseif (str_contains($query, '*') || str_contains($query, '?')) {
            $mode = 'wildcard';
        } else {
            $mode = 'substring';
        }
    }

    if (!in_array($mode, ['substring', 'regex', 'wildcard'], true)) {
        jsonQuery(422, ['error' => 'Invalid search mode.']);
    }

    $params = [];
    $where = [];

    if (!$isAdmin) {
        $where[] = 'qh.user_id = :uid';
        $params[':uid'] = $userId;
    }

    if ($scanId > 0) {
        $where[] = 'qh.scan_id = :sid';
        $params[':sid'] = $scanId;
    }

    $searchFields = ['qh.data_type', 'qh.query_value', 'qh.api_source', 'qh.result_summary'];
    if ($hasSourceRef) {
        $searchFields[] = 'qh.source_ref';
    }
    if ($hasEnrichedFrom) {
        $searchFields[] = 'qh.enriched_from';
    }

    if ($mode === 'substring') {
        $pattern = '%' . $query . '%';
        $matcherParts = [];
        foreach ($searchFields as $index => $field) {
            $paramKey = ':pattern_' . $index;
            $params[$paramKey] = $pattern;
            $matcherParts[] = "{$field} LIKE {$paramKey}";
        }
    } else {
        $pattern = $mode === 'wildcard' ? wildcardToRegex($query) : $query;
        $matcherParts = [];
        foreach ($searchFields as $index => $field) {
            $paramKey = ':pattern_' . $index;
            $params[$paramKey] = $pattern;
            $matcherParts[] = "{$field} REGEXP {$paramKey}";
        }
    }

    $matcher = '(' . implode(' OR ', $matcherParts) . ')';

    $where[] = $matcher;
    $whereClause = 'WHERE ' . implode(' AND ', $where);

    try {
        $searchProjection = implode(",\n                       ", [
            'qh.id',
            'qh.scan_id',
            'qh.query_type',
            'qh.query_value',
            'qh.api_source',
            'qh.data_type',
            'qh.result_summary',
            'qh.risk_score',
            'qh.status',
            'qh.queried_at',
            $hasFalsePositive ? 'qh.false_positive' : '0 AS false_positive',
            $hasSourceRef ? 'qh.source_ref' : 'NULL AS source_ref',
            $hasEnrichedFrom ? 'qh.enriched_from' : 'NULL AS enriched_from',
            's.name AS scan_name',
        ]);

        $sql = "SELECT {$searchProjection}
                FROM query_history qh
                LEFT JOIN scans s ON s.id = qh.scan_id
                {$whereClause}
                ORDER BY qh.queried_at DESC
                LIMIT :limit";

        $stmt = DB::connect()->prepare($sql);
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        jsonQuery(200, [
            'mode' => $mode,
            'query' => $query,
            'results' => $stmt->fetchAll(),
        ]);
    } catch (Exception $e) {
        error_log('[query/search_results] ' . $e->getMessage());
        jsonQuery(422, ['error' => 'Search pattern could not be evaluated.']);
    }
}

function handleDeleteScan(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanIds = $input['scan_ids'] ?? [];
    if (!is_array($scanIds) || empty($scanIds)) {
        jsonQuery(422, ['error' => 'No scans selected.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';

    $hasQueryHistory = tableExists('query_history');
    $hasScanLogs = tableExists('scan_logs');
    $hasScanCorrelations = tableExists('scan_correlations');
    $hasScanEvidence = tableExists('scan_evidence');
    $hasScanParityConfig = tableExists('scan_parity_config');
    $hasScanSfDiff = tableExists('scan_sf_diff');
    $hasScanEvents = tableExists('scan_events');
    $hasScanEventQueue = tableExists('scan_event_queue');
    $hasScanEventHandlers = tableExists('scan_event_handlers');
    $hasScanEventRelationships = tableExists('scan_event_relationships');
    $hasReplaySource = columnExists('scans', 'replay_source_scan_id');

    $deleted = 0;
    $deletedChildren = [
        'query_history' => 0,
        'scan_logs' => 0,
        'scan_correlations' => 0,
        'scan_evidence' => 0,
        'scan_parity_config' => 0,
        'scan_sf_diff' => 0,
        'scan_events' => 0,
        'scan_event_queue' => 0,
        'scan_event_handlers' => 0,
        'scan_event_relationships' => 0,
        'replay_links_cleared' => 0,
    ];
    $failed = [];

    foreach ($scanIds as $scanIdRaw) {
        $scanId = (int)$scanIdRaw;
        if ($scanId <= 0) {
            continue;
        }

        $scanCheckSql = "SELECT id FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid') . " LIMIT 1";
        $scanCheckParams = $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId];
        $scan = DB::queryOne($scanCheckSql, $scanCheckParams);
        if (!$scan) {
            continue;
        }

        try {
            DB::transaction(function () use (
                $scanId,
                $isAdmin,
                $userId,
                $hasQueryHistory,
                $hasScanLogs,
                $hasScanCorrelations,
                $hasScanEvidence,
                $hasScanParityConfig,
                $hasScanSfDiff,
                $hasScanEvents,
                $hasScanEventQueue,
                $hasScanEventHandlers,
                $hasScanEventRelationships,
                $hasReplaySource,
                &$deleted,
                &$deletedChildren
            ): void {
                if ($hasQueryHistory) {
                    $deletedChildren['query_history'] += DB::execute(
                        "DELETE FROM query_history WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanLogs) {
                    $deletedChildren['scan_logs'] += DB::execute(
                        "DELETE FROM scan_logs WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanCorrelations) {
                    $deletedChildren['scan_correlations'] += DB::execute(
                        "DELETE FROM scan_correlations WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanEvidence) {
                    $deletedChildren['scan_evidence'] += DB::execute(
                        "DELETE FROM scan_evidence WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanParityConfig) {
                    $deletedChildren['scan_parity_config'] += DB::execute(
                        "DELETE FROM scan_parity_config WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanSfDiff) {
                    $deletedChildren['scan_sf_diff'] += DB::execute(
                        "DELETE FROM scan_sf_diff WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanEventHandlers) {
                    $deletedChildren['scan_event_handlers'] += DB::execute(
                        "DELETE FROM scan_event_handlers WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanEventQueue) {
                    $deletedChildren['scan_event_queue'] += DB::execute(
                        "DELETE FROM scan_event_queue WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanEventRelationships) {
                    $deletedChildren['scan_event_relationships'] += DB::execute(
                        "DELETE FROM scan_event_relationships WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasScanEvents) {
                    $deletedChildren['scan_events'] += DB::execute(
                        "DELETE FROM scan_events WHERE scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }
                if ($hasReplaySource) {
                    $deletedChildren['replay_links_cleared'] += DB::execute(
                        "UPDATE scans SET replay_source_scan_id = NULL WHERE replay_source_scan_id = :sid",
                        [':sid' => $scanId]
                    );
                }

                $deleteScanSql = "DELETE FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid');
                $deleteScanParams = $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId];
                $deleted += DB::execute($deleteScanSql, $deleteScanParams);
            });
        } catch (Throwable $e) {
            $failed[] = $scanId;
            error_log('[query/delete_scan] failed for scan #' . $scanId . ': ' . $e->getMessage());
        }
    }

    jsonQuery(200, [
        'deleted' => $deleted,
        'deleted_children' => $deletedChildren,
        'failed_scan_ids' => $failed,
    ]);
}

function handleRerunScan(int $userId): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanId = (int)($input['scan_id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    $scan = DB::queryOne("SELECT * FROM scans WHERE id = :id", [':id' => $scanId]);
    if (!$scan) {
        jsonQuery(404, ['error' => 'Scan not found.']);
    }

    $newScanId = queueScanFromExisting($scan, $userId, ' (re-run)', $scanId, 'rerun');
    jsonQuery(200, ['scan_id' => $newScanId, 'message' => 'Scan queued.']);
}

function handleMultiRerun(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanIds = $input['scan_ids'] ?? [];
    if (!is_array($scanIds) || empty($scanIds)) {
        jsonQuery(422, ['error' => 'No scans selected.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $newScanIds = [];

    foreach ($scanIds as $scanId) {
        $scanId = (int)$scanId;
        if ($scanId <= 0) {
            continue;
        }

        $scan = DB::queryOne(
            "SELECT * FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid'),
            $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId]
        );

        if (!$scan) {
            continue;
        }

        $newScanIds[] = queueScanFromExisting($scan, $userId, ' (re-run)', $scanId, 'multi-rerun');
    }

    jsonQuery(200, [
        'scan_ids' => $newScanIds,
        'created' => count($newScanIds),
    ]);
}

function handleMultiExport(int $userId, ?string $role): void
{
    $rawIds = trim((string)($_GET['scan_ids'] ?? ''));
    if ($rawIds === '') {
        jsonQuery(422, ['error' => 'No scans selected.']);
    }

    $scanIds = array_values(array_filter(array_map('intval', explode(',', $rawIds)), fn($id) => $id > 0));
    if (empty($scanIds)) {
        jsonQuery(422, ['error' => 'No valid scan IDs supplied.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $format = strtolower(trim((string)($_GET['format'] ?? 'csv')));
    $download = !empty($_GET['download']);
    $jsonProfile = strtolower(trim((string)($_GET['json_profile'] ?? 'bundle')));
    if (!in_array($jsonProfile, ['bundle', 'spiderfoot'], true)) {
        $jsonProfile = 'bundle';
    }
    if (!in_array($format, ['csv', 'json', 'pdf'], true)) {
        $format = 'csv';
    }

    $hasSourceRef = columnExists('query_history', 'source_ref');
    $hasEnrichedFrom = columnExists('query_history', 'enriched_from');
    $hasFalsePositive = columnExists('query_history', 'false_positive');
    $hasConfigSnapshot = columnExists('scans', 'config_snapshot');
    $scanPlaceholders = implode(',', array_fill(0, count($scanIds), '?'));
    $scanSql = "SELECT s.id, s.name, s.target, s.target_type, s.status, s.use_case, s.started_at, s.finished_at"
            . ($hasConfigSnapshot ? ", s.config_snapshot" : '') . "
                FROM scans s
                WHERE s.id IN ({$scanPlaceholders})";
    $scanParams = $scanIds;

    if (!$isAdmin) {
        $scanSql .= " AND s.user_id = ?";
        $scanParams[] = $userId;
    }

    $scanSql .= " ORDER BY s.started_at DESC";
    $scanStmt = DB::connect()->prepare($scanSql);
    $scanStmt->execute($scanParams);
    $scans = $scanStmt->fetchAll();

    if (empty($scans)) {
        jsonQuery(404, ['error' => 'No matching scans found.']);
    }

    $exportScanIds = array_map(fn($scan) => (int)$scan['id'], $scans);
    $resultPlaceholders = implode(',', array_fill(0, count($exportScanIds), '?'));
    $resultProjection = implode(",\n                ", [
        'qh.id',
        'qh.scan_id',
        'qh.query_type',
        'qh.query_value',
        'qh.api_source',
        'qh.data_type',
        'qh.result_summary',
        'qh.risk_score',
        'qh.status',
        'qh.queried_at',
        $hasFalsePositive ? 'qh.false_positive' : '0 AS false_positive',
        $hasSourceRef ? 'qh.source_ref' : 'NULL AS source_ref',
        $hasEnrichedFrom ? 'qh.enriched_from' : 'NULL AS enriched_from',
    ]);
    $resultStmt = DB::connect()->prepare(
        "SELECT {$resultProjection}
         FROM query_history qh
         WHERE qh.scan_id IN ({$resultPlaceholders})
         ORDER BY qh.scan_id ASC, qh.queried_at ASC"
    );
    $resultStmt->execute($exportScanIds);
    $payload = [
        'format' => $format,
        'exported_at' => gmdate('c'),
        'scans' => $scans,
        'results' => $resultStmt->fetchAll(),
    ];

    if ($format === 'json') {
        if (tableExists('scan_correlations')) {
            $hasCorrelationLinks = tableExists('scan_correlation_events');
            $corrStmt = DB::connect()->prepare(
                $hasCorrelationLinks
                    ? "SELECT sc.*,
                              GROUP_CONCAT(DISTINCT sce.query_history_id ORDER BY sce.query_history_id ASC SEPARATOR ',') AS linked_result_ids
                         FROM scan_correlations sc
                         LEFT JOIN scan_correlation_events sce ON sce.correlation_id = sc.id
                        WHERE sc.scan_id IN ({$resultPlaceholders})
                        GROUP BY sc.id
                        ORDER BY sc.scan_id ASC, sc.created_at ASC"
                    : "SELECT sc.*, '' AS linked_result_ids
                         FROM scan_correlations sc
                        WHERE sc.scan_id IN ({$resultPlaceholders})
                        ORDER BY sc.scan_id ASC, sc.created_at ASC"
            );
            $corrStmt->execute($exportScanIds);
            $payload['correlations'] = array_map(static function (array $row): array {
                $linkedIds = trim((string)($row['linked_result_ids'] ?? ''));
                $row['linked_result_ids'] = $linkedIds === ''
                    ? []
                    : array_values(array_filter(array_map('intval', explode(',', $linkedIds)), fn($id) => $id > 0));
                return $row;
            }, $corrStmt->fetchAll());
        }

        if (tableExists('scan_logs')) {
            $logStmt = DB::connect()->prepare(
                "SELECT * FROM scan_logs
                  WHERE scan_id IN ({$resultPlaceholders})
                  ORDER BY scan_id ASC, logged_at ASC"
            );
            $logStmt->execute($exportScanIds);
            $payload['logs'] = $logStmt->fetchAll();
        }

        if (tableExists('scan_events')) {
            $eventStmt = DB::connect()->prepare(
                "SELECT scan_id, event_hash, event_type, event_data, module_slug, source_event_hash,
                        source_data, parent_event_hash, event_depth, confidence, risk_score,
                        visibility, false_positive, created_at
                   FROM scan_events
                  WHERE scan_id IN ({$resultPlaceholders})
                  ORDER BY scan_id ASC, created_at ASC"
            );
            $eventStmt->execute($exportScanIds);
            $payload['events'] = $eventStmt->fetchAll();
        }

        if (tableExists('scan_event_relationships')) {
            $relationshipStmt = DB::connect()->prepare(
                "SELECT scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type, created_at
                   FROM scan_event_relationships
                  WHERE scan_id IN ({$resultPlaceholders})
                  ORDER BY scan_id ASC, created_at ASC"
            );
            $relationshipStmt->execute($exportScanIds);
            $payload['event_relationships'] = $relationshipStmt->fetchAll();
        }

        if (tableExists('scan_event_handlers')) {
            $handlerStmt = DB::connect()->prepare(
                "SELECT scan_id, event_hash, module_slug, status, result_count, produced_count,
                        query_history_ids_json, produced_event_hashes_json, error_message,
                        started_at, finished_at
                   FROM scan_event_handlers
                  WHERE scan_id IN ({$resultPlaceholders})
                  ORDER BY scan_id ASC, started_at ASC"
            );
            $handlerStmt->execute($exportScanIds);
            $payload['event_handlers'] = $handlerStmt->fetchAll();
        }
    }

    $payload = ScanExportFormatter::sanitizePayload($payload);

    if ($download) {
        $filename = ScanExportFormatter::buildFilename($scans, $format);

        if ($format === 'csv') {
            $csv = ScanExportFormatter::buildCsv($scans, $payload['results']);
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
            header('Pragma: no-cache');
            header('Expires: 0');
            echo $csv;
            exit;
        }

        if ($format === 'pdf') {
            $pdf = ScanExportFormatter::buildPdf($scans, $payload['results'], (string)$payload['exported_at']);
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
            header('Content-Length: ' . strlen($pdf));
            header('Pragma: no-cache');
            header('Expires: 0');
            echo $pdf;
            exit;
        }

        if ($format === 'json') {
            if ($jsonProfile === 'spiderfoot') {
                $json = ScanExportFormatter::buildSpiderFootJson($scans, $payload['events'] ?? []);
                $filename = ScanExportFormatter::buildSpiderFootJsonFilename($scans);
                header('Content-Type: application/json; charset=utf-8');
                header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
                header('Pragma: no-cache');
                header('Expires: 0');
                echo $json;
                exit;
            }

            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . addslashes($filename) . '"');
            header('Pragma: no-cache');
            header('Expires: 0');
            echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            exit;
        }
    }

    jsonQuery(200, $payload);
}

function handleSetFalsePositive(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    if (!columnExists('query_history', 'false_positive')
        || !columnExists('query_history', 'fp_marked_by')
        || !columnExists('query_history', 'fp_marked_at')) {
        jsonQuery(503, [
            'error' => 'False-positive tracking is not available yet. Run sql/migration_008_scan_feature_gaps.sql.',
        ]);
    }

    $resultId = (int)($input['result_id'] ?? 0);
    $flag = !empty($input['false_positive']);
    if ($resultId <= 0) {
        jsonQuery(422, ['error' => 'Missing result ID.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $row = DB::queryOne(
        "SELECT qh.*, s.name AS scan_name
         FROM query_history qh
         LEFT JOIN scans s ON s.id = qh.scan_id
         WHERE qh.id = :id" . ($isAdmin ? '' : ' AND qh.user_id = :uid'),
        $isAdmin ? [':id' => $resultId] : [':id' => $resultId, ':uid' => $userId]
    );

    if (!$row) {
        jsonQuery(404, ['error' => 'Result not found.']);
    }

    if ($flag) {
        $descendantCount = countLiveDescendants(
            (int)($row['scan_id'] ?? 0),
            (int)$row['id'],
            (string)($row['query_value'] ?? ''),
            (string)($row['result_summary'] ?? '')
        );

        if ($descendantCount > 0) {
            jsonQuery(409, [
                'error' => 'Mark descendant findings as false positives first before tagging this parent result.',
            ]);
        }
    }

    DB::execute(
        "UPDATE query_history
         SET false_positive = :flag,
             fp_marked_by = :uid,
             fp_marked_at = NOW()
         WHERE id = :id",
        [
            ':flag' => $flag ? 1 : 0,
            ':uid' => $userId,
            ':id' => $resultId,
        ]
    );

    if (!empty($row['scan_id'])) {
        logScan(
            (int)$row['scan_id'],
            'info',
            $row['api_source'] ?? null,
            ($flag ? 'Marked' : 'Cleared') . " false positive for result #{$resultId}"
        );
    }

    jsonQuery(200, [
        'result_id' => $resultId,
        'false_positive' => $flag,
    ]);
}

function handleRerunCorrelations(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    if (!tableExists('scan_correlations')) {
        jsonQuery(503, [
            'error' => 'Correlation storage is not available yet. Run sql/migration_002_scans_table.sql.',
        ]);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanId = (int)($input['scan_id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(422, ['error' => 'Missing scan ID.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $scan = DB::queryOne(
        "SELECT id, target, target_type FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid'),
        $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId]
    );
    if (!$scan) {
        jsonQuery(404, ['error' => 'Scan not found.']);
    }

    DB::execute("DELETE FROM scan_correlations WHERE scan_id = :sid", [':sid' => $scanId]);
    runCorrelations($scanId, (string)($scan['target_type'] ?? 'domain'), (string)($scan['target'] ?? ''));

    $count = (int)(DB::queryOne(
        "SELECT COUNT(*) AS n FROM scan_correlations WHERE scan_id = :sid",
        [':sid' => $scanId]
    )['n'] ?? 0);

    logScan($scanId, 'info', null, "Correlation rules re-run on demand ({$count} finding(s)).");

    jsonQuery(200, [
        'scan_id' => $scanId,
        'processed_results' => (int)(DB::queryOne(
            "SELECT COUNT(*) AS n
               FROM query_history
              WHERE scan_id = :sid
                AND status = 'completed'"
                . (columnExists('query_history', 'false_positive') ? " AND false_positive = 0" : ''),
            [':sid' => $scanId]
        )['n'] ?? 0),
        'correlation_count' => $count,
    ]);
}

function handleDbMaintenance(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $task = strtolower(trim((string)($input['task'] ?? 'stats')));
    $tables = [
        'users',
        'api_configs',
        'platform_settings',
        'module_settings',
        'scans',
        'scan_logs',
        'scan_correlations',
        'scan_correlation_events',
        'scan_events',
        'scan_event_queue',
        'scan_event_handlers',
        'scan_event_relationships',
        'query_history',
        'threat_indicators',
        'raw_evidence',
        'scan_sf_diff',
        'login_attempts',
    ];
    $tables = array_values(array_filter($tables, 'tableExists'));
    if ($tables === []) {
        jsonQuery(200, [
            'task' => $task,
            'tables' => [],
            'results' => [],
        ]);
    }

    if ($task === 'stats') {
        $placeholders = implode(',', array_fill(0, count($tables), '?'));
        $stats = DB::query(
            "SELECT table_name,
                    table_rows,
                    data_length,
                    index_length,
                    update_time
               FROM information_schema.tables
              WHERE table_schema = ?
                AND table_name IN ({$placeholders})
              ORDER BY table_name ASC",
            array_merge([DB_NAME], $tables)
        );

        jsonQuery(200, [
            'task' => 'stats',
            'tables' => $stats,
        ]);
    }

    if (!in_array($task, ['optimize', 'analyze'], true)) {
        jsonQuery(422, ['error' => 'Unsupported maintenance task.']);
    }

    $results = [];
    foreach ($tables as $table) {
        try {
            $verb = strtoupper($task);
            $rows = DB::query("{$verb} TABLE `{$table}`");
            $results[] = [
                'table' => $table,
                'status' => 'ok',
                'result' => $rows,
            ];
        } catch (Throwable $e) {
            $results[] = [
                'table' => $table,
                'status' => 'error',
                'error' => $e->getMessage(),
            ];
        }
    }

    jsonQuery(200, [
        'task' => $task,
        'results' => $results,
    ]);
}

function handleAbortScan(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanId = (int)($input['scan_id'] ?? 0);
    $isAdmin = strtolower($role ?? '') === 'admin';

    $sql = "UPDATE scans SET status = 'aborted', finished_at = NOW() WHERE id = :id AND status IN ('starting','running')"
         . ($isAdmin ? '' : ' AND user_id = :uid');
    $params = $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId];

    $affected = DB::execute($sql, $params);
    if ($affected) {
        recalculateScanSummaryFromStorage($scanId, true);
        logScan($scanId, 'warning', null, 'Scan aborted by user.');
    }

    jsonQuery(200, ['aborted' => $affected > 0]);
}

function handleMultiAbort(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $scanIds = $input['scan_ids'] ?? [];
    if (!is_array($scanIds) || empty($scanIds)) {
        jsonQuery(422, ['error' => 'No scans selected.']);
    }

    $isAdmin = strtolower($role ?? '') === 'admin';
    $abortedIds = [];
    $skippedIds = [];

    foreach ($scanIds as $scanIdRaw) {
        $scanId = (int)$scanIdRaw;
        if ($scanId <= 0) {
            continue;
        }

        $sql = "UPDATE scans SET status = 'aborted', finished_at = NOW() WHERE id = :id AND status IN ('starting','running')"
             . ($isAdmin ? '' : ' AND user_id = :uid');
        $params = $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId];

        $affected = DB::execute($sql, $params);
        if ($affected > 0) {
            recalculateScanSummaryFromStorage($scanId, true);
            logScan($scanId, 'warning', null, 'Scan aborted by user.');
            $abortedIds[] = $scanId;
            continue;
        }

        $skippedIds[] = $scanId;
    }

    jsonQuery(200, [
        'aborted' => count($abortedIds) > 0,
        'aborted_count' => count($abortedIds),
        'aborted_ids' => $abortedIds,
        'skipped_ids' => $skippedIds,
    ]);
}

function handleDeleteHistory(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid CSRF token.']);
    }

    $ids = $input['ids'] ?? [];
    if (!is_array($ids) || empty($ids)) {
        jsonQuery(422, ['error' => 'No records selected.']);
    }

    $deleted = 0;
    foreach ($ids as $id) {
        $id = (int)$id;
        if ($id <= 0) {
            continue;
        }
        $deleted += DB::execute('DELETE FROM query_history WHERE id = :id', [':id' => $id]);
    }

    jsonQuery(200, ['deleted' => $deleted, 'message' => "{$deleted} record(s) deleted."]);
}

function handleHistory(int $userId, ?string $role): void
{
    $page = max(1, (int)($_GET['page'] ?? 1));
    $limit = min(500, max(1, (int)($_GET['limit'] ?? 500)));
    $offset = ($page - 1) * $limit;
    $isAdmin = strtolower($role ?? '') === 'admin';

    try {
        $countSql = $isAdmin
            ? "SELECT COUNT(*) AS n FROM query_history"
            : "SELECT COUNT(*) AS n FROM query_history WHERE user_id = :uid";
        $countParams = $isAdmin ? [] : [':uid' => $userId];
        $total = (int)(DB::queryOne($countSql, $countParams)['n'] ?? 0);

        $dataSql = $isAdmin
            ? "SELECT qh.id, qh.query_type, qh.query_value, qh.api_source,
                      qh.risk_score, qh.status, qh.response_time, qh.queried_at,
                      u.full_name AS user_name
                 FROM query_history qh
                 JOIN users u ON u.id = qh.user_id
                 ORDER BY qh.queried_at DESC
                 LIMIT :limit OFFSET :offset"
            : "SELECT qh.id, qh.query_type, qh.query_value, qh.api_source,
                      qh.risk_score, qh.status, qh.response_time, qh.queried_at,
                      u.full_name AS user_name
                 FROM query_history qh
                 JOIN users u ON u.id = qh.user_id
                 WHERE qh.user_id = :uid
                 ORDER BY qh.queried_at DESC
                 LIMIT :limit OFFSET :offset";

        $stmt = DB::connect()->prepare($dataSql);
        if (!$isAdmin) {
            $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        jsonQuery(200, [
            'history' => $stmt->fetchAll(),
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ]);
    } catch (Exception $e) {
        error_log('[query/history] ' . $e->getMessage());
        jsonQuery(500, ['error' => 'Failed to load query history.']);
    }
}

function getEnabledApiSlugs(): array
{
    $rows = DB::query("SELECT slug FROM api_configs");
    return array_column($rows, 'slug');
}

function slugToApiName(string $slug): string
{
    $row = DB::queryOne(
        'SELECT name FROM api_configs WHERE slug = :slug LIMIT 1',
        [':slug' => $slug]
    );
    return $row['name'] ?? ucfirst($slug);
}

function buildScanSnapshot(
    string $scanName,
    string $queryType,
    string $queryValue,
    string $useCase,
    array $selectedApis,
    ?int $sourceScanId,
    string $mode
): array {
    // ── Capture global settings at scan start ────────────────────────────
    $globalSettings = [];
    if (tableExists('platform_settings')) {
        $globalSettings = loadKeyValueMap('platform_settings', 'setting_key', 'setting_value');
    }

    // ── Capture module settings for selected modules ─────────────────────
    $moduleSettings = [];
    if (tableExists('module_settings')) {
        $allModuleSettings = loadNestedSettingsMap();
        foreach ($selectedApis as $slug) {
            $s = strtolower(trim($slug));
            if (isset($allModuleSettings[$s]) && !empty($allModuleSettings[$s])) {
                $moduleSettings[$s] = $allModuleSettings[$s];
            }
        }
    }

    $apiConfigsSnapshot = [];
    if (tableExists('api_configs')) {
        $allApiConfigs = loadSelectedApiConfigSnapshot($selectedApis);
        foreach ($selectedApis as $slug) {
            $s = strtolower(trim((string)$slug));
            if ($s !== '' && isset($allApiConfigs[$s])) {
                $apiConfigsSnapshot[$s] = $allApiConfigs[$s];
            }
        }
    }

    return [
        'scan_name' => $scanName,
        'query_type' => $queryType,
        'query_value' => $queryValue,
        'use_case' => $useCase ?: 'custom',
        'selected_modules' => array_values($selectedApis),
        'module_count' => count($selectedApis),
        'mode' => $mode,
        'source_scan_id' => $sourceScanId,
        'captured_at' => gmdate('c'),
        'global_settings' => $globalSettings,
        'module_settings' => $moduleSettings,
        'api_configs_snapshot' => $apiConfigsSnapshot,
    ];
}

function insertScanRecord(
    int $userId,
    string $scanName,
    string $queryValue,
    string $queryType,
    ?string $useCase,
    array $selectedApis,
    array $scanSnapshot
): int {
    $baseParams = [
        ':uid' => $userId,
        ':name' => $scanName,
        ':target' => $queryValue,
        ':ttype' => $queryType,
        ':uc' => $useCase,
        ':mods' => json_encode(array_values($selectedApis)),
    ];

    if (columnExists('scans', 'config_snapshot')) {
        return (int)DB::insert(
            "INSERT INTO scans (user_id, name, target, target_type, status, use_case, selected_modules, config_snapshot, started_at)
             VALUES (:uid, :name, :target, :ttype, 'starting', :uc, :mods, :snapshot, NOW())",
            $baseParams + [
                ':snapshot' => json_encode($scanSnapshot, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ]
        );
    }

    return (int)DB::insert(
        "INSERT INTO scans (user_id, name, target, target_type, status, use_case, selected_modules, started_at)
         VALUES (:uid, :name, :target, :ttype, 'starting', :uc, :mods, NOW())",
        $baseParams
    );
}

function queueScanFromExisting(array $scan, int $userId, string $nameSuffix, int $sourceScanId, string $mode): int
{
    $mods = $scan['selected_modules'];
    if (is_string($mods)) {
        $mods = json_decode($mods, true) ?? [];
    }
    if (!is_array($mods)) {
        $mods = [];
    }

    $newName = $scan['name'] . $nameSuffix;
    $snapshot = buildScanSnapshot(
        $newName,
        $scan['target_type'],
        $scan['target'],
        (string)($scan['use_case'] ?? ''),
        $mods,
        $sourceScanId,
        $mode
    );

    $newScanId = insertScanRecord(
        $userId,
        $newName,
        $scan['target'],
        $scan['target_type'],
        $scan['use_case'],
        $mods,
        $snapshot
    );

    logScan($newScanId, 'info', null, "Re-run of scan #{$sourceScanId}");

    $spawned = spawnBackgroundScan($newScanId, $userId);
    if (!$spawned) {
        error_log('[queueScanFromExisting] Background spawn unavailable, running inline for scan #' . $newScanId);
        DB::execute("UPDATE scans SET status = 'running' WHERE id = :id", [':id' => $newScanId]);
        ScanExecutor::run($newScanId, $userId, $scan['target_type'], $scan['target'], $mods);
    }

    return $newScanId;
}

function countLiveDescendants(int $scanId, int $rowId, string $queryValue, string $resultSummary): int
{
    if ($scanId <= 0) {
        return 0;
    }

    if (!columnExists('query_history', 'false_positive')
        || !columnExists('query_history', 'source_ref')
        || !columnExists('query_history', 'enriched_from')) {
        return 0;
    }

    $clauses = [];
    $params = [':sid' => $scanId, ':id' => $rowId];

    if ($queryValue !== '') {
        $clauses[] = 'source_ref = :qv';
        $clauses[] = 'enriched_from = :qv';
        $params[':qv'] = $queryValue;
    }

    if ($resultSummary !== '') {
        $clauses[] = 'source_ref = :summary';
        $params[':summary'] = $resultSummary;
    }

    if (empty($clauses)) {
        return 0;
    }

    $sql = "SELECT COUNT(*) AS n
            FROM query_history
            WHERE scan_id = :sid
              AND id <> :id
              AND false_positive = 0
              AND status <> 'failed'
              AND (" . implode(' OR ', $clauses) . ")";

    return (int)(DB::queryOne($sql, $params)['n'] ?? 0);
}

function wildcardToRegex(string $pattern): string
{
    $quoted = preg_quote($pattern, '/');
    $quoted = str_replace(['\\*', '\\?'], ['.*', '.'], $quoted);
    return '^' . $quoted . '$';
}

function parseScanConfigSnapshotValue(array $scan): ?array
{
    $configSnapshot = $scan['config_snapshot'] ?? null;
    if (is_string($configSnapshot)) {
        $decoded = json_decode($configSnapshot, true);
        return is_array($decoded) ? $decoded : null;
    }

    return is_array($configSnapshot) ? $configSnapshot : null;
}

function backendLabelFromKey(string $backendKey): string
{
    return match (strtolower(trim($backendKey))) {
        'cti-python' => 'CTI Python Engine',
        'spiderfoot-bridge' => 'SpiderFoot Bridge',
        'cti-event-queue' => 'CTI Event Queue',
        'cti-legacy' => 'CTI Native Backend',
        default => '',
    };
}

/**
 * @param array<int,array<string,mixed>>|null $logs
 * @return array{key:string,label:string}
 */
function detectScanBackend(array $scan, ?array $logs = null): array
{
    $snapshot = parseScanConfigSnapshotValue($scan);
    $snapshotKey = strtolower(trim((string)($snapshot['engine_backend'] ?? '')));
    $snapshotLabel = trim((string)($snapshot['engine_backend_label'] ?? ''));
    if ($snapshotKey !== '' || $snapshotLabel !== '') {
        return [
            'key' => $snapshotKey,
            'label' => $snapshotLabel !== '' ? $snapshotLabel : backendLabelFromKey($snapshotKey),
        ];
    }

    if ($logs === null && tableExists('scan_logs') && !empty($scan['id'])) {
        $logs = DB::query(
            "SELECT module, message
               FROM scan_logs
              WHERE scan_id = :sid
              ORDER BY logged_at DESC, id DESC
              LIMIT 60",
            [':sid' => (int)$scan['id']]
        );
    }

    foreach ($logs ?? [] as $log) {
        $module = strtolower(trim((string)($log['module'] ?? '')));
        $message = strtolower(trim((string)($log['message'] ?? '')));
        if ($module === 'cti-python' || str_contains($message, 'own cti python engine selected')) {
            return ['key' => 'cti-python', 'label' => backendLabelFromKey('cti-python')];
        }
        if ($module === 'bridge' || str_contains($message, 'spiderfoot python backend selected')) {
            return ['key' => 'spiderfoot-bridge', 'label' => backendLabelFromKey('spiderfoot-bridge')];
        }
        if (str_contains($message, 'event queue / watched-event routing enabled')
            || str_contains($message, 'event queue engine initialized')) {
            return ['key' => 'cti-event-queue', 'label' => backendLabelFromKey('cti-event-queue')];
        }
        if (str_contains($message, 'legacy multi-pass enrichment engine')
            || str_contains($message, 'using cti backend')) {
            return ['key' => 'cti-legacy', 'label' => backendLabelFromKey('cti-legacy')];
        }
    }

    return ['key' => '', 'label' => ''];
}

function buildScanSettingsView(array $scan, ?array $backendInfo = null): array
{
    $allSchemas = ModuleSettingsSchema::getAllSchemas();

    // ── Check for frozen config_snapshot (Phase 3/6 integration) ─────
    $snapshotGlobal  = null;
    $snapshotModules = null;
    $snapshotApiConfigs = null;
    $hasSnapshot     = false;

    $configSnapshot = parseScanConfigSnapshotValue($scan);
    if (is_array($configSnapshot)) {
        if (isset($configSnapshot['global_settings']) && is_array($configSnapshot['global_settings'])) {
            $snapshotGlobal = $configSnapshot['global_settings'];
        }
        if (isset($configSnapshot['module_settings']) && is_array($configSnapshot['module_settings'])) {
            $snapshotModules = $configSnapshot['module_settings'];
            $hasSnapshot = true;
        }
        if (isset($configSnapshot['api_configs_snapshot']) && is_array($configSnapshot['api_configs_snapshot'])) {
            $snapshotApiConfigs = $configSnapshot['api_configs_snapshot'];
        }
    }

    // Use snapshot values when available, fall back to live DB
    $platformValues = is_array($snapshotGlobal) && !empty($snapshotGlobal)
        ? $snapshotGlobal
        : (tableExists('platform_settings')
            ? loadKeyValueMap('platform_settings', 'setting_key', 'setting_value')
            : []);

    $moduleValues = is_array($snapshotModules) && !empty($snapshotModules)
        ? $snapshotModules
        : (tableExists('module_settings')
            ? loadNestedSettingsMap()
            : []);

    $apiConfigs = is_array($snapshotApiConfigs) && !empty($snapshotApiConfigs)
        ? $snapshotApiConfigs
        : (tableExists('api_configs')
            ? loadApiConfigMap()
            : []);

    $metaInformation = [
        ['option' => 'Name', 'value' => (string)($scan['name'] ?? '')],
        ['option' => 'Internal ID', 'value' => (string)($scan['id'] ?? '')],
        ['option' => 'Target', 'value' => (string)($scan['target'] ?? '')],
        ['option' => 'Started', 'value' => (string)($scan['started_at'] ?? '')],
        ['option' => 'Completed', 'value' => (string)($scan['finished_at'] ?? '')],
        ['option' => 'Status', 'value' => strtoupper((string)($scan['status'] ?? ''))],
    ];
    $backendInfo = is_array($backendInfo) ? $backendInfo : detectScanBackend($scan);
    if (!empty($backendInfo['label'])) {
        $metaInformation[] = ['option' => 'Backend Used', 'value' => (string)$backendInfo['label']];
    }

    $globalSettings = [];
    foreach (($allSchemas['_global'] ?? []) as $definition) {
        $key = (string)($definition['key'] ?? '');
        if ($key === '') {
            continue;
        }
        $value = array_key_exists($key, $platformValues)
            ? $platformValues[$key]
            : ($definition['default'] ?? '');
        $globalSettings[] = [
            'option' => (string)($definition['description'] ?? $definition['label'] ?? $key),
            'value' => normalizeSettingValue($value, (string)($definition['type'] ?? 'text')),
        ];
    }

    $moduleSettings = [];
    foreach (($allSchemas['_storage'] ?? []) as $definition) {
        $key = (string)($definition['key'] ?? '');
        if ($key === '') {
            continue;
        }
        $value = array_key_exists($key, $platformValues)
            ? $platformValues[$key]
            : ($definition['default'] ?? '');
        $moduleSettings[] = [
            'module' => 'sfp__stor_db',
            'option' => (string)($definition['description'] ?? $definition['label'] ?? $key),
            'value' => normalizeSettingValue($value, (string)($definition['type'] ?? 'text')),
        ];
    }

    $moduleSlugs = array_values(array_unique(array_merge(
        array_keys($allSchemas),
        array_keys($moduleValues),
        array_keys($apiConfigs)
    )));
    $moduleSlugs = SpiderFootModuleMapper::sortCtiSlugs($moduleSlugs);

    foreach ($moduleSlugs as $slug) {
        if ($slug === '_global' || $slug === '_storage') {
            continue;
        }

        $schema = $allSchemas[$slug] ?? [];
        $moduleSettingValues = $moduleValues[$slug] ?? [];
        $apiConfig = $apiConfigs[$slug] ?? null;
        $moduleLabel = mapToSpiderFootModuleLabel($slug);
        $schemaKeys = [];

        $hasApiKeyField = false;
        foreach ($schema as $definition) {
            $key = (string)($definition['key'] ?? '');
            if ($key !== '' && isApiKeyField($key)) {
                $hasApiKeyField = true;
            }
            if ($key !== '') {
                $schemaKeys[$key] = true;
            }
        }

        if ($apiConfig && !empty($apiConfig['requires_key']) && !$hasApiKeyField) {
            $apiName = trim((string)($apiConfig['name'] ?? ''));
            $moduleSettings[] = [
                'module' => $moduleLabel,
                'option' => ($apiName !== '' ? $apiName . ' API Key.' : 'API Key.'),
                'value' => maskApiKeyValue((string)($apiConfig['api_key'] ?? '')),
            ];
        }

        foreach ($schema as $definition) {
            $key = (string)($definition['key'] ?? '');
            if ($key === '') {
                continue;
            }

            $value = $moduleSettingValues[$key] ?? ($definition['default'] ?? '');
            if ($apiConfig && isApiKeyField($key) && (string)($apiConfig['api_key'] ?? '') !== '') {
                $value = maskApiKeyValue((string)$apiConfig['api_key']);
            } elseif (isApiKeyField($key)) {
                $value = maskApiKeyValue((string)$value);
            }

            $moduleSettings[] = [
                'module' => $moduleLabel,
                'option' => (string)($definition['description'] ?? $definition['label'] ?? $key),
                'value' => normalizeSettingValue($value, (string)($definition['type'] ?? 'text')),
            ];
        }

        foreach ($moduleSettingValues as $key => $value) {
            if (isset($schemaKeys[$key])) {
                continue;
            }
            if (isApiKeyField((string)$key)) {
                $value = maskApiKeyValue((string)$value);
            }
            $moduleSettings[] = [
                'module' => $moduleLabel,
                'option' => (string)$key,
                'value' => normalizeSettingValue($value, 'text'),
            ];
        }
    }

    return [
        'meta_information' => $metaInformation,
        'global_settings' => $globalSettings,
        'module_settings' => $moduleSettings,
        'has_snapshot' => $hasSnapshot,
    ];
}

function loadKeyValueMap(string $table, string $keyColumn, string $valueColumn): array
{
    $rows = DB::query("SELECT {$keyColumn} AS k, {$valueColumn} AS v FROM {$table}");
    $map = [];
    foreach ($rows as $row) {
        $map[(string)($row['k'] ?? '')] = (string)($row['v'] ?? '');
    }
    return $map;
}

function loadNestedSettingsMap(): array
{
    $rows = DB::query(
        "SELECT module_slug, setting_key, setting_value
         FROM module_settings"
    );

    $map = [];
    foreach ($rows as $row) {
        $module = (string)($row['module_slug'] ?? '');
        $key = (string)($row['setting_key'] ?? '');
        if ($module === '' || $key === '') {
            continue;
        }
        if (!isset($map[$module])) {
            $map[$module] = [];
        }
        $map[$module][$key] = (string)($row['setting_value'] ?? '');
    }
    return $map;
}

function loadApiConfigMap(): array
{
    $rows = DB::query(
        "SELECT slug, name, api_key, requires_key
         FROM api_configs"
    );

    $map = [];
    foreach ($rows as $row) {
        $slug = (string)($row['slug'] ?? '');
        if ($slug === '') {
            continue;
        }
        $map[$slug] = [
            'name' => (string)($row['name'] ?? ''),
            'api_key' => (string)($row['api_key'] ?? ''),
            'requires_key' => (int)($row['requires_key'] ?? 0),
        ];
    }
    return $map;
}

function loadSelectedApiConfigSnapshot(array $selectedApis): array
{
    $selectedApis = array_values(array_filter(array_map(
        static fn($slug) => strtolower(trim((string)$slug)),
        $selectedApis
    ), static fn($slug) => $slug !== ''));

    if (empty($selectedApis)) {
        return [];
    }

    $placeholders = [];
    $params = [];
    foreach ($selectedApis as $index => $slug) {
        $param = ':slug_' . $index;
        $placeholders[] = $param;
        $params[$param] = $slug;
    }

    $rows = DB::query(
        "SELECT slug, name, api_key, requires_key, is_enabled, base_url, rate_limit
           FROM api_configs
          WHERE slug IN (" . implode(', ', $placeholders) . ")",
        $params
    );

    $snapshot = [];
    foreach ($rows as $row) {
        $slug = strtolower(trim((string)($row['slug'] ?? '')));
        if ($slug === '') {
            continue;
        }
        $snapshot[$slug] = [
            'name' => (string)($row['name'] ?? ''),
            'api_key' => (string)($row['api_key'] ?? ''),
            'requires_key' => (int)($row['requires_key'] ?? 0),
            'is_enabled' => (int)($row['is_enabled'] ?? 0),
            'base_url' => (string)($row['base_url'] ?? ''),
            'rate_limit' => (int)($row['rate_limit'] ?? 0),
        ];
    }

    return $snapshot;
}

function normalizeQueryValue(string $value, string $queryType): string
{
    $normalized = trim($value);

    if ($queryType !== 'username') {
        return $normalized;
    }

    $hasDoubleQuotes = str_starts_with($normalized, '"') && str_ends_with($normalized, '"');
    $hasSingleQuotes = str_starts_with($normalized, "'") && str_ends_with($normalized, "'");
    if (($hasDoubleQuotes || $hasSingleQuotes) && strlen($normalized) >= 2) {
        $normalized = trim(substr($normalized, 1, -1));
    }

    return trim(ltrim($normalized, "@ \t\n\r\0\x0B"));
}

function normalizeSettingValue(mixed $value, string $type): string
{
    if ($type === 'boolean') {
        if (is_bool($value)) {
            return $value ? '1' : '0';
        }
        $normalized = strtolower(trim((string)$value));
        return in_array($normalized, ['1', 'true', 'yes', 'on'], true) ? '1' : '0';
    }

    if (is_array($value)) {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '';
    }

    if (is_object($value)) {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '';
    }

    return (string)$value;
}

function isApiKeyField(string $key): bool
{
    $normalized = strtolower($key);
    return $normalized === 'api_key'
        || str_starts_with($normalized, 'api_key_')
        || str_ends_with($normalized, '_api_key');
}

function maskApiKeyValue(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }

    $len = strlen($value);
    if ($len <= 4) {
        return str_repeat('*', $len);
    }

    $suffix = substr($value, -4);
    $stars = str_repeat('*', min(8, max(4, $len - 4)));
    return $stars . $suffix;
}

function mapToSpiderFootModuleLabel(string $slug): string
{
    $mapped = SpiderFootModuleMapper::toSfpName($slug);
    if ($mapped !== null) {
        return $mapped;
    }

    return 'sfp_' . str_replace('-', '', strtolower($slug));
}

function tableExists(string $table): bool
{
    static $cache = [];

    if (array_key_exists($table, $cache)) {
        return $cache[$table];
    }

    try {
        $row = DB::queryOne(
            "SELECT 1 AS present
             FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = :table
             LIMIT 1",
            [':table' => $table]
        );
        $cache[$table] = (bool)$row;
    } catch (Throwable $e) {
        error_log('[query/schema] tableExists check failed: ' . $e->getMessage());
        $cache[$table] = false;
    }

    return $cache[$table];
}

function columnExists(string $table, string $column): bool
{
    static $cache = [];
    $key = $table . '.' . $column;

    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }

    try {
        $row = DB::queryOne(
            "SELECT 1 AS present
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = :table
               AND COLUMN_NAME = :column
             LIMIT 1",
            [
                ':table' => $table,
                ':column' => $column,
            ]
        );
        $cache[$key] = (bool)$row;
    } catch (Throwable $e) {
        error_log('[query/schema] columnExists check failed: ' . $e->getMessage());
        $cache[$key] = false;
    }

    return $cache[$key];
}

/**
 * @param array<int,array<string,mixed>> $results
 * @param array<int,array<string,mixed>> $logs
 * @return array{total_elements:int,unique_elements:int,error_count:int}
 */
function computeScanSummaryFromRows(array $results, array $logs = []): array
{
    $totalElements = 0;
    $uniqueElements = [];
    $errorCount = 0;
    $sawStructuredLogs = !empty($logs);

    foreach ($logs as $log) {
        if (strtolower(trim((string)($log['level'] ?? ''))) === 'error') {
            $errorCount++;
        }
    }

    foreach ($results as $result) {
        $rowStatus = strtolower(trim((string)($result['status'] ?? 'completed')));
        if ($rowStatus === 'failed') {
            if (!$sawStructuredLogs) {
                $errorCount++;
            }
            continue;
        }

        $totalElements++;
        $uniqueElements[buildScanSummarySignature($result)] = true;
    }

    return [
        'total_elements' => $totalElements,
        'unique_elements' => count($uniqueElements),
        'error_count' => $errorCount,
    ];
}

/**
 * @param array<string,mixed> $row
 */
function buildScanSummarySignature(array $row): string
{
    $parts = [
        strtolower(trim((string)($row['api_source'] ?? ''))),
        strtolower(trim((string)($row['query_type'] ?? ''))),
        strtolower(trim((string)($row['query_value'] ?? ''))),
        strtolower(trim((string)($row['data_type'] ?? ''))),
        trim((string)($row['result_summary'] ?? '')),
    ];

    return hash('sha256', implode('|', $parts));
}

/**
 * @return array{total_elements:int,unique_elements:int,error_count:int}
 */
function recalculateScanSummaryFromStorage(int $scanId, bool $persist = false): array
{
    if ($scanId <= 0 || !tableExists('query_history')) {
        return [
            'total_elements' => 0,
            'unique_elements' => 0,
            'error_count' => 0,
        ];
    }

    $results = DB::query(
        "SELECT query_type, query_value, api_source, data_type, result_summary, status
         FROM query_history
         WHERE scan_id = :sid
         ORDER BY id ASC",
        [':sid' => $scanId]
    );

    $logs = tableExists('scan_logs')
        ? DB::query(
            "SELECT level
             FROM scan_logs
             WHERE scan_id = :sid
             ORDER BY id ASC",
            [':sid' => $scanId]
        )
        : [];

    $summary = computeScanSummaryFromRows($results, $logs);

    if ($persist) {
        persistScanSummaryCounts($scanId, $summary);
    }

    return $summary;
}

/**
 * @param array{total_elements:int,unique_elements:int,error_count:int} $summary
 */
function persistScanSummaryCounts(int $scanId, array $summary): void
{
    if ($scanId <= 0) {
        return;
    }

    DB::execute(
        "UPDATE scans
            SET total_elements = :te,
                unique_elements = :ue,
                error_count = :ec
          WHERE id = :id",
        [
            ':te' => (int)($summary['total_elements'] ?? 0),
            ':ue' => (int)($summary['unique_elements'] ?? 0),
            ':ec' => (int)($summary['error_count'] ?? 0),
            ':id' => $scanId,
        ]
    );
}

// =============================================================================
//  PARITY SYSTEM ENDPOINTS
// =============================================================================

/**
 * POST ?action=replay_scan  —  Replay a scan from stored evidence (100% reproducible).
 * Body: { scan_id: int, csrf_token: string }
 */
function handleReplayScan(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $sourceScanId = (int)($input['scan_id'] ?? 0);
    if ($sourceScanId <= 0) {
        jsonQuery(422, ['error' => 'Source scan ID is required.']);
    }

    require_once __DIR__ . '/../ReplayEngine.php';

    // Verify the source scan exists and user has access
    $isAdmin = strtolower($role ?? '') === 'admin';
    $scan = DB::queryOne(
        "SELECT * FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid'),
        $isAdmin ? [':id' => $sourceScanId] : [':id' => $sourceScanId, ':uid' => $userId]
    );
    if (!$scan) {
        jsonQuery(404, ['error' => 'Source scan not found.']);
    }

    // Check replay feasibility
    $replay = new ReplayEngine($sourceScanId);
    $check = $replay->canReplay();
    if (!$check['can_replay']) {
        jsonQuery(422, ['error' => 'Cannot replay scan.', 'issues' => $check['issues']]);
    }

    // Create a new scan record for the replay
    $selectedModules = $scan['selected_modules'];
    if (is_string($selectedModules)) {
        $selectedModules = json_decode($selectedModules, true) ?? [];
    }

    $replayName = ($scan['name'] ?? 'Scan') . ' (Replay)';
    $snapshot = buildScanSnapshot(
        $replayName,
        $scan['target_type'],
        $scan['target'],
        $scan['use_case'] ?? '',
        $selectedModules,
        $sourceScanId,
        'replay'
    );

    $newScanId = insertScanRecord(
        $userId,
        $replayName,
        $scan['target'],
        $scan['target_type'],
        $scan['use_case'] ?? null,
        $selectedModules,
        $snapshot
    );

    // Set parity mode and replay source
    try {
        if (columnExists('scans', 'parity_mode')) {
            DB::execute(
                "UPDATE scans SET parity_mode = 'replay', replay_source_scan_id = :src, status = 'running' WHERE id = :id",
                [':src' => $sourceScanId, ':id' => $newScanId]
            );
        } else {
            DB::execute("UPDATE scans SET status = 'running' WHERE id = :id", [':id' => $newScanId]);
        }
    } catch (\Throwable $e) {
        DB::execute("UPDATE scans SET status = 'running' WHERE id = :id", [':id' => $newScanId]);
    }

    logScan($newScanId, 'info', null, "Replay scan started from source scan #{$sourceScanId}");

    // Execute replay
    $result = $replay->replay($newScanId, $userId);

    // Finalize
    $status = $result['success'] ? 'finished' : 'failed';
    $totalElements = $result['counts']['total_elements'] ?? 0;
    $uniqueElements = $result['counts']['unique_elements'] ?? 0;

    DB::execute(
        "UPDATE scans SET status = :status, finished_at = NOW(),
                total_elements = :te, unique_elements = :ue, error_count = 0
         WHERE id = :id",
        [':status' => $status, ':te' => $totalElements, ':ue' => $uniqueElements, ':id' => $newScanId]
    );

    logScan($newScanId, 'info', null,
        "Replay finished: {$totalElements} elements, {$uniqueElements} unique."
    );

    // Run correlations on replay results
    if ($result['success'] && !empty($result['results'])) {
        runCorrelations($newScanId, $result['results'], $scan['target_type'], $scan['target']);
    }

    jsonQuery(200, [
        'scan_id'   => $newScanId,
        'source_id' => $sourceScanId,
        'mode'      => 'replay',
        'success'   => $result['success'],
        'counts'    => $result['counts'],
        'errors'    => $result['errors'],
    ]);
}

/**
 * GET ?action=replay_info&id={scanId}  —  Check replay feasibility for a scan.
 */
function handleReplayInfo(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    require_once __DIR__ . '/../ReplayEngine.php';

    $isAdmin = strtolower($role ?? '') === 'admin';
    $scan = DB::queryOne(
        "SELECT id FROM scans WHERE id = :id" . ($isAdmin ? '' : ' AND user_id = :uid'),
        $isAdmin ? [':id' => $scanId] : [':id' => $scanId, ':uid' => $userId]
    );
    if (!$scan) {
        jsonQuery(404, ['error' => 'Scan not found.']);
    }

    $replay = new ReplayEngine($scanId);
    $check = $replay->canReplay();
    $info = $replay->getReplayInfo();

    jsonQuery(200, array_merge($check, $info));
}

/**
 * POST ?action=sf_diff_import  —  Import SpiderFoot CSV/JSON for comparison.
 * Body: { scan_id: int, format: 'csv'|'json', data: string, filename: string }
 */
function handleSfDiffImport(int $userId, ?string $role): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonQuery(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonQuery(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $scanId = (int)($input['scan_id'] ?? 0);
    $format = strtolower(trim($input['format'] ?? 'csv'));
    $data = $input['data'] ?? '';
    $filename = trim($input['filename'] ?? '');

    if ($scanId <= 0 || $data === '') {
        jsonQuery(422, ['error' => 'scan_id and data are required.']);
    }

    if (!in_array($format, ['csv', 'json'], true)) {
        jsonQuery(422, ['error' => 'Format must be csv or json.']);
    }

    require_once __DIR__ . '/../SpiderFootDiffValidator.php';

    $validator = new SpiderFootDiffValidator($scanId);

    if ($format === 'csv') {
        $importResult = $validator->importCsv($data, $filename);
    } else {
        $importResult = $validator->importJson($data, $filename);
    }

    if (!$importResult['success']) {
        jsonQuery(422, ['error' => $importResult['error'] ?? 'Import failed.']);
    }

    // Run the comparison immediately
    $diffReport = $validator->compare();

    jsonQuery(200, $diffReport);
}

/**
 * POST ?action=sf_diff_compare  —  Compare a scan against previously imported SF data.
 * (Alternative: import + compare in one step via sf_diff_import)
 */
function handleSfDiffCompare(int $userId, ?string $role): void
{
    jsonQuery(200, ['message' => 'Use sf_diff_import to import and compare in one step.']);
}

/**
 * GET ?action=sf_diff_reports&id={scanId}  —  Load previous diff reports for a scan.
 */
function handleSfDiffReports(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    require_once __DIR__ . '/../SpiderFootDiffValidator.php';

    $reports = SpiderFootDiffValidator::loadDiffReports($scanId);

    // Decode JSON fields
    foreach ($reports as &$r) {
        if (isset($r['type_diff']) && is_string($r['type_diff'])) {
            $r['type_diff'] = json_decode($r['type_diff'], true) ?? [];
        }
        if (isset($r['diff_reasons']) && is_string($r['diff_reasons'])) {
            $r['diff_reasons'] = json_decode($r['diff_reasons'], true) ?? [];
        }
    }
    unset($r);

    jsonQuery(200, ['reports' => $reports]);
}

/**
 * GET ?action=evidence_stats&id={scanId}  —  Get evidence collection stats.
 */
function handleEvidenceStats(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    require_once __DIR__ . '/../RawEvidenceStore.php';

    $stats = RawEvidenceStore::getScanStats($scanId);

    jsonQuery(200, ['scan_id' => $scanId, 'evidence' => $stats]);
}

/**
 * GET ?action=parity_config&id={scanId}  —  Get frozen parity config for a scan.
 */
function handleParityConfig(int $userId, ?string $role): void
{
    $scanId = (int)($_GET['id'] ?? 0);
    if ($scanId <= 0) {
        jsonQuery(400, ['error' => 'Missing scan ID.']);
    }

    require_once __DIR__ . '/../ScanParity.php';

    $config = ScanParity::loadFrozenConfig($scanId);
    if (!$config) {
        jsonQuery(404, ['error' => 'No parity config found for scan #' . $scanId]);
    }

    // Redact api_configs_snapshot keys for safety
    if (isset($config['api_configs_snapshot'])) {
        foreach ($config['api_configs_snapshot'] as &$ac) {
            if (isset($ac['api_key'])) {
                $ac['api_key'] = '***REDACTED***';
            }
        }
        unset($ac);
    }

    jsonQuery(200, ['scan_id' => $scanId, 'parity_config' => $config]);
}

function jsonQuery(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
