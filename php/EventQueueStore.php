<?php
// =============================================================================
//  CTI - EVENT QUEUE STORE
//  php/EventQueueStore.php
//
//  Persists event-native scan state while remaining optional. If the new
//  tables are not present, the engine can gracefully fall back to the legacy
//  query_history-only flow.
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/ScanEvent.php';

class EventQueueStore
{
    /** @var array<string,bool> */
    private static array $tableExistsCache = [];

    /**
     * Event queue is enabled only when all required tables exist.
     */
    public function isEnabled(): bool
    {
        foreach (self::requiredTables() as $table) {
            if (!$this->tableExists($table)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return array<int,string>
     */
    public static function requiredTables(): array
    {
        return [
            'scan_events',
            'scan_event_queue',
            'scan_event_handlers',
            'scan_event_relationships',
        ];
    }

    /**
     * @return array{root: ScanEvent, seed: ScanEvent}
     */
    public function bootstrap(int $scanId, string $queryType, string $queryValue): array
    {
        $root = ScanEvent::root($scanId, $queryType, $queryValue);
        $seed = ScanEvent::seedTarget($scanId, $queryType, $queryValue, $root->eventHash);

        $this->ensureEvent($root);
        $seedInsert = $this->ensureEvent($seed);
        $this->linkEvents($scanId, $root->eventHash, $seed->eventHash, 'seed', 'seed');
        if ($seedInsert['inserted']) {
            $this->enqueue($scanId, $seed->eventHash, 0);
        }

        return ['root' => $root, 'seed' => $seed];
    }

    /**
     * @return array{inserted: bool, event: ScanEvent}
     */
    public function ensureEvent(ScanEvent $event): array
    {
        $existing = DB::queryOne(
            "SELECT *
               FROM scan_events
              WHERE scan_id = :sid
                AND event_hash = :hash
              LIMIT 1",
            [
                ':sid' => $event->scanId,
                ':hash' => $event->eventHash,
            ]
        );

        if ($existing) {
            return ['inserted' => false, 'event' => ScanEvent::fromRow($existing)];
        }

        DB::insert(
            "INSERT INTO scan_events
                (scan_id, event_hash, event_type, event_data, module_slug,
                 source_event_hash, source_data, parent_event_hash, event_depth,
                 confidence, risk_score, visibility, false_positive, raw_payload_json)
             VALUES
                (:scan_id, :event_hash, :event_type, :event_data, :module_slug,
                 :source_event_hash, :source_data, :parent_event_hash, :event_depth,
                 :confidence, :risk_score, :visibility, :false_positive, :raw_payload_json)",
            [
                ':scan_id' => $event->scanId,
                ':event_hash' => $event->eventHash,
                ':event_type' => $event->eventType,
                ':event_data' => $event->data,
                ':module_slug' => $event->moduleSlug,
                ':source_event_hash' => $event->sourceEventHash,
                ':source_data' => $event->sourceData,
                ':parent_event_hash' => $event->parentEventHash,
                ':event_depth' => $event->depth,
                ':confidence' => $event->confidence,
                ':risk_score' => $event->riskScore,
                ':visibility' => $event->visibility,
                ':false_positive' => $event->falsePositive ? 1 : 0,
                ':raw_payload_json' => $event->rawPayload !== null
                    ? json_encode($event->rawPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                    : null,
            ]
        );

        return ['inserted' => true, 'event' => $event];
    }

    public function enqueue(int $scanId, string $eventHash, int $priority = 100): void
    {
        $existing = DB::queryOne(
            "SELECT id
               FROM scan_event_queue
              WHERE scan_id = :sid
                AND event_hash = :hash
              LIMIT 1",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
            ]
        );

        if ($existing) {
            return;
        }

        DB::insert(
            "INSERT INTO scan_event_queue (scan_id, event_hash, status, priority)
             VALUES (:sid, :hash, 'queued', :priority)",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':priority' => $priority,
            ]
        );
    }

    public function claimNext(int $scanId): ?ScanEvent
    {
        return DB::transaction(function () use ($scanId): ?ScanEvent {
            $row = DB::queryOne(
                "SELECT id, event_hash
                   FROM scan_event_queue
                  WHERE scan_id = :sid
                    AND status = 'queued'
                  ORDER BY priority ASC, id ASC
                  LIMIT 1",
                [':sid' => $scanId]
            );

            if (!$row) {
                return null;
            }

            DB::execute(
                "UPDATE scan_event_queue
                    SET status = 'processing',
                        started_at = NOW(),
                        attempt_count = attempt_count + 1
                  WHERE id = :id",
                [':id' => (int)$row['id']]
            );

            $eventRow = DB::queryOne(
                "SELECT *
                   FROM scan_events
                  WHERE scan_id = :sid
                    AND event_hash = :hash
                  LIMIT 1",
                [
                    ':sid' => $scanId,
                    ':hash' => $row['event_hash'],
                ]
            );

            return $eventRow ? ScanEvent::fromRow($eventRow) : null;
        });
    }

    public function markQueueDone(int $scanId, string $eventHash): void
    {
        DB::execute(
            "UPDATE scan_event_queue
                SET status = 'done',
                    finished_at = NOW(),
                    last_error = NULL
              WHERE scan_id = :sid
                AND event_hash = :hash",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
            ]
        );
    }

    public function markQueueDropped(int $scanId, string $eventHash, string $reason = 'scan aborted'): void
    {
        DB::execute(
            "UPDATE scan_event_queue
                SET status = 'dropped',
                    finished_at = NOW(),
                    last_error = :reason
              WHERE scan_id = :sid
                AND event_hash = :hash",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':reason' => $reason,
            ]
        );
    }

    public function markQueueError(int $scanId, string $eventHash, string $error): void
    {
        DB::execute(
            "UPDATE scan_event_queue
                SET status = 'error',
                    finished_at = NOW(),
                    last_error = :error
              WHERE scan_id = :sid
                AND event_hash = :hash",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':error' => $error,
            ]
        );
    }

    public function startHandler(int $scanId, string $eventHash, string $moduleSlug): bool
    {
        $existing = DB::queryOne(
            "SELECT id, status
               FROM scan_event_handlers
              WHERE scan_id = :sid
                AND event_hash = :hash
                AND module_slug = :module
              LIMIT 1",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':module' => $moduleSlug,
            ]
        );

        if ($existing && strtolower((string)($existing['status'] ?? '')) === 'done') {
            return false;
        }

        if ($existing) {
            DB::execute(
                "UPDATE scan_event_handlers
                    SET status = 'processing',
                        started_at = NOW(),
                        finished_at = NULL,
                        error_message = NULL
                  WHERE id = :id",
                [':id' => (int)$existing['id']]
            );
            return true;
        }

        DB::insert(
            "INSERT INTO scan_event_handlers
                (scan_id, event_hash, module_slug, status, started_at)
             VALUES
                (:sid, :hash, :module, 'processing', NOW())",
            [
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':module' => $moduleSlug,
            ]
        );

        return true;
    }

    /**
     * @param array<int,int> $queryHistoryIds
     * @param array<int,string> $producedEventHashes
     */
    public function finishHandler(
        int $scanId,
        string $eventHash,
        string $moduleSlug,
        int $resultCount,
        int $producedCount,
        array $queryHistoryIds = [],
        array $producedEventHashes = [],
        ?string $errorMessage = null
    ): void {
        DB::execute(
            "UPDATE scan_event_handlers
                SET status = :status,
                    result_count = :result_count,
                    produced_count = :produced_count,
                    query_history_ids_json = :query_history_ids_json,
                    produced_event_hashes_json = :produced_event_hashes_json,
                    error_message = :error_message,
                    finished_at = NOW()
              WHERE scan_id = :sid
                AND event_hash = :hash
                AND module_slug = :module",
            [
                ':status' => $errorMessage === null ? 'done' : 'error',
                ':result_count' => $resultCount,
                ':produced_count' => $producedCount,
                ':query_history_ids_json' => json_encode(array_values($queryHistoryIds), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ':produced_event_hashes_json' => json_encode(array_values($producedEventHashes), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ':error_message' => $errorMessage,
                ':sid' => $scanId,
                ':hash' => $eventHash,
                ':module' => $moduleSlug,
            ]
        );
    }

    public function linkEvents(
        int $scanId,
        string $parentEventHash,
        string $childEventHash,
        string $moduleSlug,
        string $relationshipType = 'discovered'
    ): void {
        $existing = DB::queryOne(
            "SELECT id
               FROM scan_event_relationships
              WHERE scan_id = :sid
                AND parent_event_hash = :parent_hash
                AND child_event_hash = :child_hash
                AND module_slug = :module
                AND relationship_type = :type
              LIMIT 1",
            [
                ':sid' => $scanId,
                ':parent_hash' => $parentEventHash,
                ':child_hash' => $childEventHash,
                ':module' => $moduleSlug,
                ':type' => $relationshipType,
            ]
        );

        if ($existing) {
            return;
        }

        DB::insert(
            "INSERT INTO scan_event_relationships
                (scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type)
             VALUES
                (:sid, :parent_hash, :child_hash, :module, :type)",
            [
                ':sid' => $scanId,
                ':parent_hash' => $parentEventHash,
                ':child_hash' => $childEventHash,
                ':module' => $moduleSlug,
                ':type' => $relationshipType,
            ]
        );
    }

    /**
     * @return array<string,mixed>
     */
    public function eventGraphPayload(int $scanId): array
    {
        if (!$this->isEnabled()) {
            return ['enabled' => false, 'events' => [], 'relationships' => [], 'handlers' => []];
        }

        return [
            'enabled' => true,
            'events' => DB::query(
                "SELECT event_hash, event_type, event_data, module_slug, source_event_hash,
                        source_data, parent_event_hash, event_depth, confidence, risk_score,
                        visibility, false_positive, created_at
                   FROM scan_events
                  WHERE scan_id = :sid
                  ORDER BY created_at ASC, event_depth ASC, event_hash ASC",
                [':sid' => $scanId]
            ),
            'relationships' => DB::query(
                "SELECT parent_event_hash, child_event_hash, module_slug, relationship_type, created_at
                   FROM scan_event_relationships
                  WHERE scan_id = :sid
                  ORDER BY created_at ASC, id ASC",
                [':sid' => $scanId]
            ),
            'handlers' => DB::query(
                "SELECT event_hash, module_slug, status, result_count, produced_count, error_message,
                        started_at, finished_at
                   FROM scan_event_handlers
                  WHERE scan_id = :sid
                  ORDER BY started_at ASC, id ASC",
                [':sid' => $scanId]
            ),
        ];
    }

    /**
     * @return array<string,int>
     */
    public function stats(int $scanId): array
    {
        if (!$this->isEnabled()) {
            return [
                'events' => 0,
                'queued' => 0,
                'processing' => 0,
                'done' => 0,
                'dropped' => 0,
                'error' => 0,
                'handlers' => 0,
            ];
        }

        $eventCount = (int)(DB::queryOne(
            "SELECT COUNT(*) AS n FROM scan_events WHERE scan_id = :sid",
            [':sid' => $scanId]
        )['n'] ?? 0);

        $queueRows = DB::query(
            "SELECT status, COUNT(*) AS n
               FROM scan_event_queue
              WHERE scan_id = :sid
              GROUP BY status",
            [':sid' => $scanId]
        );

        $stats = [
            'events' => $eventCount,
            'queued' => 0,
            'processing' => 0,
            'done' => 0,
            'dropped' => 0,
            'error' => 0,
            'handlers' => (int)(DB::queryOne(
                "SELECT COUNT(*) AS n FROM scan_event_handlers WHERE scan_id = :sid",
                [':sid' => $scanId]
            )['n'] ?? 0),
        ];

        foreach ($queueRows as $row) {
            $status = strtolower((string)($row['status'] ?? ''));
            if (array_key_exists($status, $stats)) {
                $stats[$status] = (int)($row['n'] ?? 0);
            }
        }

        return $stats;
    }

    private function tableExists(string $table): bool
    {
        if (array_key_exists($table, self::$tableExistsCache)) {
            return self::$tableExistsCache[$table];
        }

        try {
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
            self::$tableExistsCache[$table] = $row !== null;
        } catch (Throwable $e) {
            self::$tableExistsCache[$table] = false;
        }

        return self::$tableExistsCache[$table];
    }
}
