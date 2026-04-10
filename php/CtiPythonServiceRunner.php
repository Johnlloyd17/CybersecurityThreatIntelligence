<?php
// =============================================================================
//  CTI - OWN PYTHON ENGINE SERVICE RUNNER
//
//  Incremental bridge from the existing PHP scan workflow into the new
//  first-party CTI Python service. Scans are routed here when every selected
//  module is already implemented in our own engine for the target type.
// =============================================================================

require_once __DIR__ . '/db.php';

class CtiPythonServiceSoftFailure extends RuntimeException {}
class CtiPythonServiceHardFailure extends RuntimeException {}
class CtiPythonServiceTerminated extends RuntimeException {}

class CtiPythonServiceRunner
{
    private const DEFAULT_SERVICE_URL = 'http://127.0.0.1:8765';
    private const CREATE_SCAN_PATH = '/api/v1/scans';
    private const TERMINATE_SCAN_PATH = '/api/v1/scans/%s/terminate';
    private const POLL_INTERVAL_US = 250000;
    private const MAX_WAIT_SECONDS = 180;

    /** @var array<string,string> */
    private const CTI_TO_SERVICE = [
        'apivoid' => 'apivoid',
        'abuse-ch' => 'abuse-ch',
        'abusech' => 'abuse-ch',
        'abuseipdb' => 'abuseipdb',
        'alienvault' => 'alienvault',
        'certspotter' => 'certspotter',
        'crt-sh' => 'crt-sh',
        'dns-resolver' => 'dnsresolve',
        'jsonwhois' => 'jsonwhois',
        'shodan' => 'shodan',
        'urlscan' => 'urlscan',
        'virustotal' => 'virustotal',
        'whoisology' => 'whoisology',
        'whoxy' => 'whoxy',
    ];

    /** @var array<string,array<int,string>> */
    private const MODULE_QUERY_SUPPORT = [
        'apivoid' => ['domain', 'ip', 'url', 'email'],
        'abuse-ch' => ['domain', 'ip', 'url', 'hash'],
        'abusech' => ['domain', 'ip', 'url', 'hash'],
        'abuseipdb' => ['ip'],
        'alienvault' => ['domain', 'ip', 'url', 'hash'],
        'certspotter' => ['domain'],
        'crt-sh' => ['domain'],
        'dns-resolver' => ['domain'],
        'jsonwhois' => ['domain'],
        'shodan' => ['domain', 'ip'],
        'urlscan' => ['domain', 'url'],
        'virustotal' => ['domain', 'ip'],
        'whoisology' => ['domain'],
        'whoxy' => ['domain'],
    ];

    /** @var array<string,string> */
    private const SERVICE_TO_CTI = [
        'dnsresolve' => 'dns-resolver',
        'engine' => 'cti-python',
        'seed' => 'cti-python',
    ];

    private int $scanId;
    private int $userId;
    private string $scanName;
    private string $queryType;
    private string $queryValue;
    /** @var array<int,string> */
    private array $selectedApis;
    /** @var array<string,mixed> */
    private array $configSnapshot;
    /** @var array<string,int> */
    private array $eventIdToQueryHistoryId = [];
    /** @var array<string,array<string,mixed>> */
    private array $eventById = [];
    /** @var array<string,int> */
    private array $depthByEventId = [];

    public function __construct(
        int $scanId,
        int $userId,
        string $scanName,
        string $queryType,
        string $queryValue,
        array $selectedApis,
        array $configSnapshot = []
    ) {
        $this->scanId = $scanId;
        $this->userId = $userId;
        $this->scanName = $scanName;
        $this->queryType = strtolower(trim($queryType));
        $this->queryValue = trim($queryValue);
        $this->selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));
        $this->configSnapshot = $configSnapshot;
    }

    public static function supportsScan(string $queryType, array $selectedApis): bool
    {
        $queryType = strtolower(trim($queryType));

        $selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));

        if (empty($selectedApis)) {
            return false;
        }

        foreach ($selectedApis as $slug) {
            if (!array_key_exists($slug, self::CTI_TO_SERVICE)) {
                return false;
            }

            $supportedQueryTypes = self::MODULE_QUERY_SUPPORT[$slug] ?? [];
            if (!in_array($queryType, $supportedQueryTypes, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Return canonical CTI module slugs already migrated to the own Python engine.
     *
     * @return array<int, string>
     */
    public static function getSupportedModuleSlugs(): array
    {
        $slugs = [];
        foreach (array_keys(self::CTI_TO_SERVICE) as $slug) {
            $canonicalSlug = $slug === 'abusech' ? 'abuse-ch' : $slug;
            $slugs[$canonicalSlug] = true;
        }

        $result = array_keys($slugs);
        sort($result, SORT_STRING);
        return $result;
    }

    /**
     * @return array<string,int>
     */
    public function run(): array
    {
        $payload = $this->buildPayload();
        $job = $this->requestJson('POST', self::CREATE_SCAN_PATH, $payload, 15);
        $jobId = trim((string)($job['job_id'] ?? $job['scan_id'] ?? ''));
        if ($jobId === '') {
            throw new CtiPythonServiceSoftFailure('CTI Python service did not return a job id.');
        }

        logScan(
            $this->scanId,
            'info',
            'cti-python',
            'CTI Python service job accepted. Job ID: ' . $jobId
        );

        $record = $this->pollForCompletion($jobId);
        $status = strtolower(trim((string)($record['status'] ?? 'unknown')));
        if ($status === 'aborted') {
            throw new CtiPythonServiceTerminated('CTI Python engine scan was terminated.');
        }
        if ($status === 'failed') {
            $message = trim((string)($record['error_message'] ?? 'Python engine job failed.'));
            throw new CtiPythonServiceSoftFailure($message !== '' ? $message : 'Python engine job failed.');
        }

        if ($status !== 'finished') {
            throw new CtiPythonServiceSoftFailure('Python engine job ended in unexpected state: ' . $status);
        }

        if ($this->wasScanTerminatedExternally()) {
            $this->requestTermination($jobId);
            throw new CtiPythonServiceTerminated('CTI Python engine scan terminated before results import.');
        }

        $projection = $this->requestJson('GET', '/api/v1/scans/' . rawurlencode($jobId) . '/results', null, 15);
        if (!is_array($projection)) {
            throw new CtiPythonServiceSoftFailure('Python engine results payload was invalid.');
        }

        return DB::transaction(function () use ($projection): array {
            if ($this->wasScanTerminatedExternally()) {
                throw new CtiPythonServiceTerminated('CTI Python engine scan terminated before persistence.');
            }

            $summary = $this->importProjection($projection);

            DB::execute(
                "UPDATE scans
                    SET status = 'finished',
                        finished_at = NOW(),
                        total_elements = :total,
                        unique_elements = :unique_count,
                        error_count = :errors
                  WHERE id = :id",
                [
                    ':total' => $summary['total_elements'],
                    ':unique_count' => $summary['unique_elements'],
                    ':errors' => $summary['error_count'],
                    ':id' => $this->scanId,
                ]
            );

            logScan(
                $this->scanId,
                'info',
                'cti-python',
                'CTI Python engine scan finished. '
                . $summary['total_elements']
                . ' result(s), '
                . $summary['error_count']
                . ' error log(s).'
            );

            runCorrelations($this->scanId, $this->queryType, $this->queryValue);
            return $summary;
        });
    }

    /**
     * @return array<string,mixed>
     */
    private function buildPayload(): array
    {
        $snapshot = $this->configSnapshot;
        $globalSettings = is_array($snapshot['global_settings'] ?? null)
            ? $snapshot['global_settings']
            : [];
        $moduleSettings = is_array($snapshot['module_settings'] ?? null)
            ? $snapshot['module_settings']
            : [];
        $apiConfigs = is_array($snapshot['api_configs_snapshot'] ?? null)
            ? $snapshot['api_configs_snapshot']
            : [];

        return [
            'scan_id' => $this->scanId,
            'user_id' => $this->userId,
            'scan_name' => $this->scanName,
            'query_type' => $this->queryType,
            'query_value' => $this->queryValue,
            'selected_modules' => $this->mapSelectedModulesToService(),
            'global_settings' => $globalSettings,
            'module_settings' => $moduleSettings,
            'api_configs_snapshot' => $apiConfigs,
        ];
    }

    /**
     * @return array<int,string>
     */
    private function mapSelectedModulesToService(): array
    {
        $mapped = [];
        foreach ($this->selectedApis as $slug) {
            if (!isset(self::CTI_TO_SERVICE[$slug])) {
                continue;
            }
            $mapped[] = self::CTI_TO_SERVICE[$slug];
        }
        return array_values(array_unique($mapped));
    }

    private function serviceBaseUrl(): string
    {
        $configured = trim((string)(getenv('CTI_PYTHON_ENGINE_URL') ?: ''));
        if ($configured === '') {
            $configured = self::DEFAULT_SERVICE_URL;
        }
        return rtrim($configured, '/');
    }

    /**
     * @return array<string,mixed>
     */
    private function requestJson(string $method, string $path, ?array $payload = null, int $timeout = 10): array
    {
        $url = $this->serviceBaseUrl() . $path;
        $jsonBody = $payload === null
            ? null
            : json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($jsonBody === false) {
            throw new CtiPythonServiceHardFailure('Failed to encode JSON payload for CTI Python service.');
        }

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                throw new CtiPythonServiceSoftFailure('Unable to initialize cURL for CTI Python service request.');
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => strtoupper($method),
                CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json'],
                CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
                CURLOPT_TIMEOUT => $timeout,
            ]);

            if ($jsonBody !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody);
            }

            $raw = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            if ($raw === false || $error !== '') {
                throw new CtiPythonServiceSoftFailure('Unable to reach CTI Python service at ' . $url . ': ' . $error);
            }
        } else {
            $context = stream_context_create([
                'http' => [
                    'method' => strtoupper($method),
                    'timeout' => $timeout,
                    'ignore_errors' => true,
                    'header' => "Accept: application/json\r\nContent-Type: application/json\r\n",
                    'content' => $jsonBody ?? '',
                ],
            ]);
            $raw = @file_get_contents($url, false, $context);
            $status = 0;
            if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
                $status = (int)$m[1];
            }

            if ($raw === false) {
                throw new CtiPythonServiceSoftFailure('Unable to reach CTI Python service at ' . $url . '.');
            }
        }

        $decoded = json_decode((string)$raw, true);
        if (!is_array($decoded)) {
            throw new CtiPythonServiceSoftFailure('CTI Python service returned invalid JSON from ' . $path . '.');
        }

        if ($status >= 400) {
            $message = trim((string)($decoded['error'] ?? 'HTTP ' . $status));
            throw new CtiPythonServiceSoftFailure('CTI Python service request failed: ' . $message);
        }

        return $decoded;
    }

    /**
     * @return array<string,mixed>
     */
    private function pollForCompletion(string $jobId): array
    {
        $started = microtime(true);
        do {
            if ($this->wasScanTerminatedExternally()) {
                $this->requestTermination($jobId);
                $status = $this->currentScanStatus();
                $message = $status === 'aborted'
                    ? 'CTI Python engine scan terminated by user.'
                    : 'CTI Python engine scan stopped because the scan status became "' . $status . '".';
                logScan($this->scanId, 'warning', 'cti-python', $message);
                throw new CtiPythonServiceTerminated($message);
            }

            $record = $this->requestJson('GET', '/api/v1/scans/' . rawurlencode($jobId), null, 10);
            $status = strtolower(trim((string)($record['status'] ?? 'unknown')));
            if (in_array($status, ['finished', 'failed', 'aborted'], true)) {
                return $record;
            }
            usleep(self::POLL_INTERVAL_US);
        } while ((microtime(true) - $started) < self::MAX_WAIT_SECONDS);

        throw new CtiPythonServiceSoftFailure('Timed out waiting for CTI Python service job ' . $jobId . '.');
    }

    private function currentScanStatus(): string
    {
        $row = DB::queryOne(
            "SELECT status FROM scans WHERE id = :id",
            [':id' => $this->scanId]
        );

        return strtolower(trim((string)($row['status'] ?? 'unknown')));
    }

    private function wasScanTerminatedExternally(): bool
    {
        return in_array($this->currentScanStatus(), ['aborted', 'failed'], true);
    }

    private function requestTermination(string $jobId): void
    {
        try {
            $this->requestJson(
                'POST',
                sprintf(self::TERMINATE_SCAN_PATH, rawurlencode($jobId)),
                ['reason' => 'terminated_from_cti_scan_status'],
                10
            );
        } catch (Throwable $e) {
            logScan(
                $this->scanId,
                'warning',
                'cti-python',
                'Failed to propagate terminate request to CTI Python service: ' . $e->getMessage()
            );
        }
    }

    /**
     * @param array<string,mixed> $projection
     * @return array<string,int>
     */
    private function importProjection(array $projection): array
    {
        $events = is_array($projection['events'] ?? null) ? $projection['events'] : [];
        $logs = is_array($projection['logs'] ?? null) ? $projection['logs'] : [];
        $correlations = is_array($projection['correlations'] ?? null) ? $projection['correlations'] : [];

        $this->cacheEvents($events);
        $this->importLogs($logs);
        $resultCount = $this->importEventsAsResults($events);
        $this->importCorrelations($correlations);

        $errorCount = 0;
        foreach ($logs as $log) {
            if (strtolower(trim((string)($log['level'] ?? ''))) === 'error') {
                $errorCount++;
            }
        }

        return [
            'overall_score' => $this->calculateOverallScore($events),
            'error_count' => $errorCount,
            'total_elements' => $resultCount,
            'unique_elements' => $resultCount,
            'max_pass' => $this->calculateMaxDepth(),
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function cacheEvents(array $events): void
    {
        foreach ($events as $event) {
            $eventId = trim((string)($event['event_id'] ?? ''));
            if ($eventId === '') {
                continue;
            }
            $this->eventById[$eventId] = $event;
        }
    }

    /**
     * @param array<int,array<string,mixed>> $logs
     */
    private function importLogs(array $logs): void
    {
        foreach ($logs as $log) {
            $message = trim((string)($log['message'] ?? ''));
            if ($message === '') {
                continue;
            }
            $level = strtolower(trim((string)($log['level'] ?? 'info')));
            if (!in_array($level, ['debug', 'info', 'warning', 'error'], true)) {
                $level = 'info';
            }

            logScan(
                $this->scanId,
                $level,
                $this->normalizeModuleSlug((string)($log['module'] ?? 'cti-python')),
                $message
            );
        }
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function importEventsAsResults(array $events): int
    {
        $count = 0;
        foreach ($events as $event) {
            $eventId = trim((string)($event['event_id'] ?? ''));
            $value = trim((string)($event['value'] ?? ''));
            $eventType = strtolower(trim((string)($event['event_type'] ?? '')));
            if ($eventId === '' || $value === '' || $eventType === '') {
                continue;
            }

            $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
            $depth = $this->depthForEvent($eventId);
            $sourceValue = $this->sourceValueForEvent($parentEventId);
            $moduleSlug = $this->normalizeModuleSlug((string)($event['source_module'] ?? 'cti-python'));
            $dataType = $this->displayTypeForEvent($eventType);
            $summary = $dataType . ': ' . $value;
            if ($sourceValue !== 'ROOT' && $sourceValue !== $value) {
                $summary .= ' (source: ' . $sourceValue . ')';
            }

            $insertedId = (int)DB::insert(
                "INSERT INTO query_history
                    (user_id, scan_id, query_type, query_value, api_source, data_type,
                     result_summary, risk_score, status, response_time,
                     enrichment_pass, source_ref, enriched_from)
                 VALUES
                    (:uid, :sid, :qt, :qv, :api, :dt,
                     :summary, :score, 'completed', :resp,
                     :pass, :source_ref, :enriched_from)",
                [
                    ':uid' => $this->userId,
                    ':sid' => $this->scanId,
                    ':qt' => $eventType,
                    ':qv' => $value,
                    ':api' => $moduleSlug,
                    ':dt' => $dataType,
                    ':summary' => $summary,
                    ':score' => max(0, min(100, (int)($event['risk_score'] ?? 0))),
                    ':resp' => 0,
                    ':pass' => $depth,
                    ':source_ref' => $sourceValue,
                    ':enriched_from' => $sourceValue === 'ROOT' ? null : $sourceValue,
                ]
            );

            $this->eventIdToQueryHistoryId[$eventId] = $insertedId;
            $count++;

            DB::execute(
                "INSERT INTO threat_indicators
                    (indicator_type, indicator_value, source, severity, confidence, tags, raw_data, first_seen, last_seen)
                 VALUES
                    (:type, :value, :source, :severity, :confidence, :tags, :raw, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE
                    severity = VALUES(severity),
                    confidence = VALUES(confidence),
                    tags = VALUES(tags),
                    raw_data = VALUES(raw_data),
                    last_seen = NOW()",
                [
                    ':type' => $eventType,
                    ':value' => $value,
                    ':source' => $moduleSlug,
                    ':severity' => $this->severityFromRisk((int)($event['risk_score'] ?? 0)),
                    ':confidence' => max(0, min(100, (int)($event['confidence'] ?? 0))),
                    ':tags' => json_encode([$moduleSlug, $eventType], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    ':raw' => json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ]
            );

            $this->upsertScanEvent($event, $moduleSlug, $sourceValue, $depth);
        }

        return $count;
    }

    /**
     * @param array<int,array<string,mixed>> $correlations
     */
    private function importCorrelations(array $correlations): void
    {
        if (empty($correlations) || !scanExecutorTableExists('scan_correlations')) {
            return;
        }

        foreach ($correlations as $correlation) {
            $ruleName = trim((string)($correlation['rule_name'] ?? 'cti_python_rule'));
            $severity = strtolower(trim((string)($correlation['severity'] ?? 'info')));
            if (!in_array($severity, ['critical', 'high', 'medium', 'low', 'info'], true)) {
                $severity = 'info';
            }
            $title = trim((string)($correlation['title'] ?? $ruleName));
            $detail = trim((string)($correlation['detail'] ?? ''));

            $correlationId = (int)DB::insert(
                "INSERT INTO scan_correlations (scan_id, rule_name, severity, title, detail)
                 VALUES (:sid, :rule, :severity, :title, :detail)",
                [
                    ':sid' => $this->scanId,
                    ':rule' => $ruleName,
                    ':severity' => $severity,
                    ':title' => $title,
                    ':detail' => $detail,
                ]
            );

            if ($correlationId <= 0 || !scanExecutorTableExists('scan_correlation_events')) {
                continue;
            }

            $linkedEventIds = is_array($correlation['linked_event_ids'] ?? null)
                ? $correlation['linked_event_ids']
                : [];

            foreach ($linkedEventIds as $eventId) {
                $queryHistoryId = $this->eventIdToQueryHistoryId[(string)$eventId] ?? null;
                if (!$queryHistoryId) {
                    continue;
                }
                DB::execute(
                    "INSERT INTO scan_correlation_events (correlation_id, query_history_id)
                     VALUES (:cid, :qid)
                     ON DUPLICATE KEY UPDATE query_history_id = VALUES(query_history_id)",
                    [
                        ':cid' => $correlationId,
                        ':qid' => $queryHistoryId,
                    ]
                );
            }
        }
    }

    /**
     * @param array<string,mixed> $event
     */
    private function upsertScanEvent(array $event, string $moduleSlug, string $sourceValue, int $depth): void
    {
        if (!scanExecutorTableExists('scan_events')) {
            return;
        }

        $eventId = (string)$event['event_id'];
        $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
        $eventType = $this->displayTypeForEvent((string)($event['event_type'] ?? ''));
        $eventValue = (string)($event['value'] ?? '');

        DB::execute(
            "INSERT INTO scan_events
                (scan_id, event_hash, event_type, event_data, module_slug,
                 source_event_hash, source_data, parent_event_hash, event_depth,
                 confidence, risk_score, visibility, false_positive, raw_payload_json)
             VALUES
                (:scan_id, :event_hash, :event_type, :event_data, :module_slug,
                 :source_event_hash, :source_data, :parent_event_hash, :event_depth,
                 :confidence, :risk_score, :visibility, :false_positive, :raw_payload_json)
             ON DUPLICATE KEY UPDATE
                event_type = VALUES(event_type),
                event_data = VALUES(event_data),
                module_slug = VALUES(module_slug),
                source_event_hash = VALUES(source_event_hash),
                source_data = VALUES(source_data),
                parent_event_hash = VALUES(parent_event_hash),
                event_depth = VALUES(event_depth),
                confidence = VALUES(confidence),
                risk_score = VALUES(risk_score),
                visibility = VALUES(visibility),
                false_positive = VALUES(false_positive),
                raw_payload_json = VALUES(raw_payload_json)",
            [
                ':scan_id' => $this->scanId,
                ':event_hash' => $eventId,
                ':event_type' => $eventType,
                ':event_data' => $eventValue,
                ':module_slug' => $moduleSlug,
                ':source_event_hash' => $parentEventId !== '' ? $parentEventId : 'ROOT',
                ':source_data' => $sourceValue,
                ':parent_event_hash' => $parentEventId !== '' ? $parentEventId : null,
                ':event_depth' => $depth,
                ':confidence' => max(0, min(100, (int)($event['confidence'] ?? 0))),
                ':risk_score' => max(0, min(100, (int)($event['risk_score'] ?? 0))),
                ':visibility' => 100,
                ':false_positive' => 0,
                ':raw_payload_json' => json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ]
        );

        if (scanExecutorTableExists('scan_event_relationships') && $parentEventId !== '') {
            DB::execute(
                "INSERT INTO scan_event_relationships
                    (scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type)
                 VALUES
                    (:sid, :parent_hash, :child_hash, :module, :type)
                 ON DUPLICATE KEY UPDATE relationship_type = VALUES(relationship_type)",
                [
                    ':sid' => $this->scanId,
                    ':parent_hash' => $parentEventId,
                    ':child_hash' => $eventId,
                    ':module' => $moduleSlug,
                    ':type' => 'discovered',
                ]
            );
        }
    }

    private function normalizeModuleSlug(string $module): string
    {
        $normalized = strtolower(trim($module));
        return self::SERVICE_TO_CTI[$normalized] ?? $normalized ?: 'cti-python';
    }

    private function displayTypeForEvent(string $eventType): string
    {
        $eventType = strtolower(trim($eventType));
        $eventType = str_replace('_', ' ', $eventType);
        return ucwords($eventType);
    }

    private function sourceValueForEvent(string $parentEventId): string
    {
        if ($parentEventId === '' || !isset($this->eventById[$parentEventId])) {
            return 'ROOT';
        }

        $parentValue = trim((string)($this->eventById[$parentEventId]['value'] ?? ''));
        return $parentValue !== '' ? $parentValue : 'ROOT';
    }

    private function depthForEvent(string $eventId): int
    {
        if (isset($this->depthByEventId[$eventId])) {
            return $this->depthByEventId[$eventId];
        }

        $event = $this->eventById[$eventId] ?? null;
        if (!is_array($event)) {
            return 1;
        }

        $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
        if ($parentEventId === '' || !isset($this->eventById[$parentEventId])) {
            $this->depthByEventId[$eventId] = 1;
            return 1;
        }

        $depth = $this->depthForEvent($parentEventId) + 1;
        $this->depthByEventId[$eventId] = $depth;
        return $depth;
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function calculateOverallScore(array $events): int
    {
        $max = 0;
        foreach ($events as $event) {
            $max = max($max, max(0, min(100, (int)($event['risk_score'] ?? 0))));
        }
        return $max;
    }

    private function calculateMaxDepth(): int
    {
        if (empty($this->eventById)) {
            return 0;
        }

        $max = 0;
        foreach (array_keys($this->eventById) as $eventId) {
            $max = max($max, $this->depthForEvent((string)$eventId));
        }
        return $max;
    }

    private function severityFromRisk(int $risk): string
    {
        if ($risk >= 90) {
            return 'critical';
        }
        if ($risk >= 70) {
            return 'high';
        }
        if ($risk >= 40) {
            return 'medium';
        }
        if ($risk > 0) {
            return 'low';
        }
        return 'info';
    }
}
