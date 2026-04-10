<?php
// =============================================================================
//  CTI - SPIDERFOOT BRIDGE RUNNER
//
//  Invokes the real SpiderFoot Python runtime through WSL and projects the
//  streamed SpiderFoot logs/results/correlations into the existing CTI MySQL
//  read-model tables.
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/SpiderFootModuleMapper.php';

class SpiderFootBridgeSoftFailure extends RuntimeException {}
class SpiderFootBridgeHardFailure extends RuntimeException {}
class SpiderFootBridgeTerminated extends RuntimeException {}

class SpiderFootBridgeRunner
{
    private const DEFAULT_WSL_INSTALL_PATH = '~/spiderfoot-4.0';
    private const WINDOWS_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

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
    private array $eventHashToQueryHistoryId = [];
    /** @var array<string,int> */
    private array $eventDepthByHash = [];
    /** @var array<int,array<string,mixed>> */
    private array $pendingCorrelations = [];
    /** @var array<string,true> */
    private array $seenEventHashes = [];

    private int $resultCount = 0;
    private int $errorCount = 0;
    private int $maxDepth = 0;
    private int $overallScore = 0;

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

    public static function supportsQueryType(string $queryType): bool
    {
        return in_array(strtolower(trim($queryType)), ['domain', 'ip', 'email', 'username', 'phone', 'bitcoin'], true);
    }

    public static function supportsScan(string $queryType, array $selectedApis): bool
    {
        if (!self::supportsQueryType($queryType)) {
            return false;
        }

        $selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));

        if (empty($selectedApis)) {
            return false;
        }

        foreach ($selectedApis as $slug) {
            $sfpName = SpiderFootModuleMapper::toSfpName($slug);
            if ($sfpName === null || $sfpName === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<string,int>
     */
    public function run(): array
    {
        $mapped = $this->buildModuleMap();
        if (empty($mapped['sfp_modules'])) {
            throw new SpiderFootBridgeSoftFailure('No selected CTI modules map to SpiderFoot modules.');
        }

        $payloadPath = $this->writePayloadFile($mapped);
        $stdoutLines = 0;
        $sawMeta = false;
        $stderrOutput = '';
        $stderrChunks = [];
        $process = null;
        $pipes = [];

        try {
            [$process, $pipes] = $this->openBridgeProcess($payloadPath);
        } catch (Throwable $e) {
            throw new SpiderFootBridgeSoftFailure('Unable to launch SpiderFoot bridge: ' . $e->getMessage(), 0, $e);
        }

        try {
            $stdout = $pipes[1];
            $stderr = $pipes[2];
            stream_set_blocking($stdout, false);
            stream_set_blocking($stderr, false);

            while (true) {
                if ($this->wasScanTerminatedExternally()) {
                    $this->terminateProcess($process, $pipes);
                    $this->flushPendingCorrelations();
                    $status = $this->currentScanStatus();
                    $message = $status === 'aborted'
                        ? 'SpiderFoot bridge scan terminated by user.'
                        : 'SpiderFoot bridge scan stopped because the scan status became "' . $status . '".';
                    logScan($this->scanId, 'warning', 'bridge', $message);
                    throw new SpiderFootBridgeTerminated($message);
                }

                $statusInfo = proc_get_status($process);
                $isRunning = (bool)($statusInfo['running'] ?? false);
                $read = [];

                if (is_resource($stdout) && !feof($stdout)) {
                    $read[] = $stdout;
                }
                if (is_resource($stderr) && !feof($stderr)) {
                    $read[] = $stderr;
                }

                if (!$isRunning && $read === []) {
                    break;
                }

                if ($read !== []) {
                    $write = null;
                    $except = null;
                    @stream_select($read, $write, $except, 0, 250000);
                } else {
                    usleep(250000);
                }

                if (in_array($stdout, $read, true)) {
                    while (($line = fgets($stdout)) !== false) {
                        $stdoutLines++;
                        $message = trim($line);
                        if ($message === '') {
                            continue;
                        }

                        $payload = json_decode($message, true);
                        if (!is_array($payload)) {
                            logScan($this->scanId, 'warning', 'bridge', 'Non-JSON bridge output: ' . $message);
                            continue;
                        }

                        if (($payload['kind'] ?? '') === 'meta') {
                            $sawMeta = true;
                        }

                        $this->handleBridgeMessage($payload);
                    }
                }

                if (in_array($stderr, $read, true)) {
                    $stderrChunk = stream_get_contents($stderr);
                    if ($stderrChunk !== false && $stderrChunk !== '') {
                        $stderrChunks[] = $stderrChunk;
                    }
                }
            }

            $trailingStderr = stream_get_contents($stderr);
            if ($trailingStderr !== false && $trailingStderr !== '') {
                $stderrChunks[] = $trailingStderr;
            }
            $stderrOutput = trim((string)implode('', $stderrChunks));
            fclose($stdout);
            fclose($stderr);
            $exitCode = proc_close($process);

            $this->flushPendingCorrelations();

            if ($stderrOutput !== '') {
                foreach (preg_split('/\r\n|\r|\n/', $stderrOutput) ?: [] as $line) {
                    $line = trim($line);
                    if ($line !== '') {
                        if (preg_match('/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?\s+\[(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\]\s+/', $line)) {
                            continue;
                        }
                        logScan($this->scanId, 'warning', 'bridge', 'SpiderFoot stderr: ' . $line);
                    }
                }
            }

            if ($this->wasScanTerminatedExternally()) {
                $status = $this->currentScanStatus();
                $message = $status === 'aborted'
                    ? 'SpiderFoot bridge scan terminated before final persistence.'
                    : 'SpiderFoot bridge scan stopped because the scan status became "' . $status . '" before final persistence.';
                logScan($this->scanId, 'warning', 'bridge', $message);
                throw new SpiderFootBridgeTerminated($message);
            }

            if ($exitCode !== 0) {
                $message = 'SpiderFoot bridge exited with code ' . $exitCode . '.';
                if (!$sawMeta && $stdoutLines === 0 && $this->resultCount === 0) {
                    throw new SpiderFootBridgeSoftFailure($message . ($stderrOutput !== '' ? ' ' . $stderrOutput : ''));
                }

                DB::execute(
                    "UPDATE scans SET status = 'failed', finished_at = NOW(), error_count = :errors WHERE id = :id",
                    [':errors' => max(1, $this->errorCount), ':id' => $this->scanId]
                );
                throw new SpiderFootBridgeHardFailure($message . ($stderrOutput !== '' ? ' ' . $stderrOutput : ''));
            }

            DB::execute(
                "UPDATE scans
                    SET status = 'finished',
                        finished_at = NOW(),
                        total_elements = :total,
                        unique_elements = :unique_count,
                        error_count = :errors
                  WHERE id = :id",
                [
                    ':total' => $this->resultCount,
                    ':unique_count' => $this->resultCount,
                    ':errors' => $this->errorCount,
                    ':id' => $this->scanId,
                ]
            );

            logScan(
                $this->scanId,
                'info',
                'bridge',
                'SpiderFoot bridge scan finished. ' . $this->resultCount . ' result(s), ' . $this->errorCount . ' error log(s).'
            );

            return [
                'overall_score' => $this->overallScore,
                'error_count' => $this->errorCount,
                'total_elements' => $this->resultCount,
                'unique_elements' => $this->resultCount,
                'max_pass' => $this->maxDepth,
            ];
        } finally {
            foreach ([1, 2] as $index) {
                if (isset($pipes[$index]) && is_resource($pipes[$index])) {
                    @fclose($pipes[$index]);
                }
            }
            if (is_resource($process)) {
                @proc_close($process);
            }
            @unlink($payloadPath);
        }
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

    /**
     * @param resource $process
     * @param array<int,resource> $pipes
     */
    private function terminateProcess($process, array $pipes): void
    {
        foreach ([1, 2] as $index) {
            if (isset($pipes[$index]) && is_resource($pipes[$index])) {
                @stream_set_blocking($pipes[$index], false);
            }
        }

        if (is_resource($process)) {
            @proc_terminate($process);
        }
    }

    /**
     * @return array<string,array<int,string>|array<string,string>>
     */
    private function buildModuleMap(): array
    {
        $sfpModules = [];
        $ctiBySfp = [];
        $missing = [];

        foreach ($this->selectedApis as $slug) {
            $sfpName = SpiderFootModuleMapper::toSfpName($slug);
            if ($sfpName === null || $sfpName === '') {
                $missing[] = $slug;
                continue;
            }
            $sfpModules[] = $sfpName;
            $ctiBySfp[$sfpName] = $slug;
        }

        if (!empty($missing)) {
            logScan(
                $this->scanId,
                'warning',
                'bridge',
                'Selected CTI module(s) have no SpiderFoot mapping and will be skipped: ' . implode(', ', $missing)
            );
        }

        return [
            'sfp_modules' => array_values(array_unique($sfpModules)),
            'cti_by_sfp' => $ctiBySfp,
        ];
    }

    private function writePayloadFile(array $mapped): string
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
            : $this->loadSelectedApiConfigSnapshot();

        $runtimeDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'runtime' . DIRECTORY_SEPARATOR . 'spiderfoot_bridge';
        if (!is_dir($runtimeDir) && !@mkdir($runtimeDir, 0777, true) && !is_dir($runtimeDir)) {
            throw new RuntimeException('Unable to create SpiderFoot runtime directory.');
        }

        $payloadPath = $runtimeDir . DIRECTORY_SEPARATOR . 'scan_' . $this->scanId . '_payload.json';
        $runtimeDbPath = $runtimeDir . DIRECTORY_SEPARATOR . 'scan_' . $this->scanId . '_spiderfoot.db';

        $payload = [
            'scan_id' => $this->scanId,
            'user_id' => $this->userId,
            'scan_name' => $this->scanName,
            'query_type' => $this->queryType,
            'query_value' => $this->queryValue,
            'selected_cti_modules' => $this->selectedApis,
            'selected_sfp_modules' => $mapped['sfp_modules'],
            'cti_by_sfp' => $mapped['cti_by_sfp'],
            'global_settings' => $globalSettings,
            'module_settings' => $moduleSettings,
            'api_configs_snapshot' => $apiConfigs,
            'runtime_db_path_windows' => $runtimeDbPath,
            'spiderfoot_install_wsl' => self::DEFAULT_WSL_INSTALL_PATH,
        ];

        file_put_contents(
            $payloadPath,
            json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
        );

        return $payloadPath;
    }

    /**
     * @return array<string,mixed>
     */
    private function loadSelectedApiConfigSnapshot(): array
    {
        if (empty($this->selectedApis) || !$this->tableExists('api_configs')) {
            return [];
        }

        $placeholders = [];
        $params = [];
        foreach ($this->selectedApis as $index => $slug) {
            $param = ':slug_' . $index;
            $placeholders[] = $param;
            $params[$param] = $slug;
        }

        $sql = "SELECT slug, name, api_key, requires_key, is_enabled, base_url, rate_limit
                  FROM api_configs
                 WHERE slug IN (" . implode(', ', $placeholders) . ")";
        $rows = DB::query($sql, $params);

        $snapshot = [];
        foreach ($rows as $row) {
            $slug = strtolower(trim((string)($row['slug'] ?? '')));
            if ($slug === '') {
                continue;
            }
            $snapshot[$slug] = [
                'name' => (string)($row['name'] ?? ''),
                'api_key' => (string)($row['api_key'] ?? ''),
                'requires_key' => !empty($row['requires_key']),
                'is_enabled' => !empty($row['is_enabled']),
                'base_url' => (string)($row['base_url'] ?? ''),
                'rate_limit' => (int)($row['rate_limit'] ?? 0),
            ];
        }

        return $snapshot;
    }

    /**
     * @return array{0: resource, 1: array<int,resource>}
     */
    private function openBridgeProcess(string $payloadPath): array
    {
        $repoRoot = dirname(__DIR__);
        $descriptorSpec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        if (PHP_OS_FAMILY === 'Windows') {
            $scriptPath = $repoRoot . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'run_spiderfoot_bridge.ps1';
            if (!is_file($scriptPath)) {
                throw new RuntimeException('PowerShell bridge launcher not found.');
            }

            $command = escapeshellarg(self::WINDOWS_POWERSHELL)
                . ' -ExecutionPolicy Bypass -File ' . escapeshellarg($scriptPath)
                . ' -PayloadPath ' . escapeshellarg($payloadPath);
        } else {
            $scriptPath = $repoRoot . DIRECTORY_SEPARATOR . 'python' . DIRECTORY_SEPARATOR . 'spiderfoot_bridge' . DIRECTORY_SEPARATOR . 'bridge.py';
            if (!is_file($scriptPath)) {
                throw new RuntimeException('Python bridge launcher not found.');
            }

            $command = 'python3 ' . escapeshellarg($scriptPath)
                . ' --payload-path ' . escapeshellarg($payloadPath);
        }

        $process = proc_open($command, $descriptorSpec, $pipes, $repoRoot);
        if (!is_resource($process)) {
            throw new RuntimeException('proc_open() failed for SpiderFoot bridge.');
        }

        fclose($pipes[0]);
        return [$process, $pipes];
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function handleBridgeMessage(array $payload): void
    {
        $kind = strtolower(trim((string)($payload['kind'] ?? '')));
        switch ($kind) {
            case 'meta':
                $moduleCount = is_array($payload['modules'] ?? null) ? count($payload['modules']) : 0;
                logScan(
                    $this->scanId,
                    'info',
                    'bridge',
                    'SpiderFoot bridge started. Scan GUID: ' . (string)($payload['scan_guid'] ?? '')
                    . ' | target type: ' . (string)($payload['target_type'] ?? '')
                    . ' | modules: ' . $moduleCount
                );
                break;

            case 'log':
                $level = strtolower(trim((string)($payload['level'] ?? 'info')));
                if ($level === 'error') {
                    $this->errorCount++;
                }
                logScan(
                    $this->scanId,
                    in_array($level, ['debug', 'info', 'warning', 'error'], true) ? $level : 'info',
                    $this->normalizeModuleSlug((string)($payload['module'] ?? 'bridge')),
                    (string)($payload['message'] ?? '')
                );
                break;

            case 'result':
                $this->importResult($payload);
                break;

            case 'correlation':
                $this->pendingCorrelations[] = $payload;
                break;

            case 'summary':
                logScan(
                    $this->scanId,
                    'info',
                    'bridge',
                    'SpiderFoot bridge reported final status: ' . (string)($payload['status'] ?? 'UNKNOWN')
                );
                break;

            default:
                logScan($this->scanId, 'debug', 'bridge', 'Unhandled bridge payload kind: ' . $kind);
                break;
        }
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function importResult(array $payload): void
    {
        $eventCode = strtoupper(trim((string)($payload['event_code'] ?? '')));
        if ($eventCode === 'ROOT') {
            $this->eventDepthByHash['ROOT'] = 0;
            return;
        }

        $eventHash = trim((string)($payload['event_hash'] ?? ''));
        if ($eventHash === '') {
            $eventHash = hash('sha256', implode('|', [
                $eventCode,
                (string)($payload['data'] ?? ''),
                (string)($payload['module'] ?? ''),
            ]));
        }

        if (isset($this->seenEventHashes[$eventHash])) {
            return;
        }

        $this->seenEventHashes[$eventHash] = true;
        $rawData = trim((string)($payload['data'] ?? ''));
        if ($rawData === '') {
            return;
        }

        $displayType = trim((string)($payload['event_descr'] ?? $eventCode));
        $moduleSlug = $this->normalizeModuleSlug((string)($payload['module'] ?? 'bridge'));
        $sourceData = trim((string)($payload['source_data'] ?? 'ROOT'));
        $sourceEventHash = trim((string)($payload['source_event_hash'] ?? 'ROOT')) ?: 'ROOT';
        $riskScore = max(0, (int)($payload['risk'] ?? 0));
        $this->overallScore = max($this->overallScore, $riskScore);
        $depth = $sourceEventHash === 'ROOT'
            ? 1
            : (($this->eventDepthByHash[$sourceEventHash] ?? 0) + 1);
        $this->eventDepthByHash[$eventHash] = $depth;
        $this->maxDepth = max($this->maxDepth, $depth);

        $queryType = $this->mapSpiderFootEventToQueryType($eventCode, $displayType, $rawData);
        $summary = $displayType . ': ' . $rawData;
        if ($sourceData !== '' && strtoupper($sourceData) !== 'ROOT' && $sourceData !== $rawData) {
            $summary .= ' (source: ' . $sourceData . ')';
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
                ':qt' => $queryType,
                ':qv' => $rawData,
                ':api' => $moduleSlug,
                ':dt' => $displayType,
                ':summary' => $summary,
                ':score' => $riskScore,
                ':resp' => 0,
                ':pass' => $depth,
                ':source_ref' => strtoupper($sourceData) === 'ROOT' ? 'ROOT' : $sourceData,
                ':enriched_from' => strtoupper($sourceData) === 'ROOT' ? null : $sourceData,
            ]
        );

        $this->eventHashToQueryHistoryId[$eventHash] = $insertedId;
        $this->resultCount++;

        $severity = $this->severityFromRisk($riskScore);
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
                ':type' => $queryType,
                ':value' => $rawData,
                ':source' => $moduleSlug,
                ':severity' => $severity,
                ':confidence' => max(0, min(100, (int)($payload['confidence'] ?? 0))),
                ':tags' => json_encode([$moduleSlug, $eventCode], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ':raw' => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ]
        );

        $this->upsertScanEvent($eventHash, $eventCode, $displayType, $payload, $moduleSlug, $sourceEventHash, $sourceData, $depth);
    }

    private function flushPendingCorrelations(): void
    {
        if (empty($this->pendingCorrelations) || !$this->tableExists('scan_correlations')) {
            return;
        }

        foreach ($this->pendingCorrelations as $correlation) {
            $ruleName = trim((string)($correlation['rule_name'] ?? $correlation['rule_id'] ?? 'spiderfoot_rule'));
            $severity = $this->normalizeCorrelationSeverity((string)($correlation['risk'] ?? 'info'));
            $title = trim((string)($correlation['title'] ?? $ruleName));
            $detailParts = [];
            $detail = trim((string)($correlation['detail'] ?? ''));
            $logic = trim((string)($correlation['logic'] ?? ''));
            if ($detail !== '') {
                $detailParts[] = $detail;
            }
            if ($logic !== '') {
                $detailParts[] = 'Logic: ' . $logic;
            }

            $correlationId = (int)DB::insert(
                "INSERT INTO scan_correlations (scan_id, rule_name, severity, title, detail)
                 VALUES (:sid, :rule, :severity, :title, :detail)",
                [
                    ':sid' => $this->scanId,
                    ':rule' => $ruleName,
                    ':severity' => $severity,
                    ':title' => $title,
                    ':detail' => implode("\n\n", $detailParts),
                ]
            );

            if ($correlationId <= 0 || !$this->tableExists('scan_correlation_events')) {
                continue;
            }

            $eventHashes = is_array($correlation['event_hashes'] ?? null) ? $correlation['event_hashes'] : [];
            foreach ($eventHashes as $eventHash) {
                $queryHistoryId = $this->eventHashToQueryHistoryId[(string)$eventHash] ?? null;
                if (!$queryHistoryId) {
                    continue;
                }
                DB::execute(
                    "INSERT INTO scan_correlation_events (correlation_id, query_history_id)
                     VALUES (:cid, :qid)
                     ON DUPLICATE KEY UPDATE query_history_id = VALUES(query_history_id)",
                    [':cid' => $correlationId, ':qid' => $queryHistoryId]
                );
            }
        }

        logScan($this->scanId, 'info', 'bridge', 'Imported ' . count($this->pendingCorrelations) . ' SpiderFoot correlation(s).');
        $this->pendingCorrelations = [];
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function upsertScanEvent(
        string $eventHash,
        string $eventCode,
        string $displayType,
        array $payload,
        string $moduleSlug,
        string $sourceEventHash,
        string $sourceData,
        int $depth
    ): void {
        if (!$this->tableExists('scan_events')) {
            return;
        }

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
                ':event_hash' => $eventHash,
                ':event_type' => $displayType !== '' ? $displayType : $eventCode,
                ':event_data' => (string)($payload['data'] ?? ''),
                ':module_slug' => $moduleSlug,
                ':source_event_hash' => $sourceEventHash,
                ':source_data' => strtoupper($sourceData) === 'ROOT' ? 'ROOT' : $sourceData,
                ':parent_event_hash' => $sourceEventHash === 'ROOT' ? null : $sourceEventHash,
                ':event_depth' => $depth,
                ':confidence' => max(0, min(100, (int)($payload['confidence'] ?? 0))),
                ':risk_score' => max(0, min(100, (int)($payload['risk'] ?? 0))),
                ':visibility' => max(0, min(100, (int)($payload['visibility'] ?? 100))),
                ':false_positive' => !empty($payload['false_positive']) ? 1 : 0,
                ':raw_payload_json' => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ]
        );

        if ($this->tableExists('scan_event_relationships')) {
            DB::execute(
                "INSERT INTO scan_event_relationships
                    (scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type)
                 VALUES
                    (:sid, :parent_hash, :child_hash, :module, :type)
                 ON DUPLICATE KEY UPDATE relationship_type = VALUES(relationship_type)",
                [
                    ':sid' => $this->scanId,
                    ':parent_hash' => $sourceEventHash,
                    ':child_hash' => $eventHash,
                    ':module' => $moduleSlug,
                    ':type' => $sourceEventHash === 'ROOT' ? 'seed' : 'discovered',
                ]
            );
        }

        if ($this->tableExists('scan_event_handlers')) {
            DB::execute(
                "INSERT INTO scan_event_handlers
                    (scan_id, event_hash, module_slug, status, result_count, produced_count, started_at, finished_at)
                 VALUES
                    (:sid, :hash, :module, 'done', 1, 0, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE
                    status = 'done',
                    result_count = result_count + 1,
                    finished_at = NOW()",
                [
                    ':sid' => $this->scanId,
                    ':hash' => $eventHash,
                    ':module' => $moduleSlug,
                ]
            );
        }
    }

    private function normalizeModuleSlug(string $moduleName): string
    {
        $normalized = strtolower(trim($moduleName));
        if ($normalized === '') {
            return 'bridge';
        }

        if (str_starts_with($normalized, 'sfp_')) {
            return SpiderFootModuleMapper::toCtiSlug($normalized) ?? $normalized;
        }

        return $normalized;
    }

    private function mapSpiderFootEventToQueryType(string $eventCode, string $displayType, string $data): string
    {
        $code = strtoupper(trim($eventCode));
        $display = strtoupper(trim($displayType));
        $data = trim($data);

        if ($code === '' && $display === '') {
            return $this->queryType;
        }

        $haystack = $code . ' ' . $display;
        if (str_contains($haystack, 'EMAIL')) {
            return 'email';
        }
        if (str_contains($haystack, 'PHONE')) {
            return 'phone';
        }
        if (str_contains($haystack, 'USERNAME') || str_contains($haystack, 'ACCOUNT_EXTERNAL')) {
            return 'username';
        }
        if (str_contains($haystack, 'BITCOIN') || str_contains($haystack, 'ETHEREUM')) {
            return 'bitcoin';
        }
        if (str_contains($haystack, 'HASH')) {
            return 'hash';
        }
        if (str_contains($haystack, 'URL') || str_contains($haystack, 'WEB CONTENT') || preg_match('#^https?://#i', $data)) {
            return 'url';
        }
        if (str_contains($haystack, 'CVE') || str_contains($haystack, 'VULNERABILITY')) {
            return 'cve';
        }
        if (str_contains($haystack, 'IP') || str_contains($haystack, 'NETBLOCK') || str_contains($haystack, 'BGP AS')) {
            return 'ip';
        }
        return 'domain';
    }

    private function severityFromRisk(int $riskScore): string
    {
        if ($riskScore >= 90) {
            return 'critical';
        }
        if ($riskScore >= 70) {
            return 'high';
        }
        if ($riskScore >= 40) {
            return 'medium';
        }
        if ($riskScore > 0) {
            return 'low';
        }
        return 'info';
    }

    private function normalizeCorrelationSeverity(string $severity): string
    {
        $normalized = strtolower(trim($severity));
        return match ($normalized) {
            'critical' => 'high',
            'high' => 'high',
            'medium' => 'medium',
            'low' => 'low',
            default => 'info',
        };
    }

    private function tableExists(string $table): bool
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
}
