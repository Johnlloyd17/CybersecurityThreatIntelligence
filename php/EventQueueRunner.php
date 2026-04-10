<?php
// =============================================================================
//  CTI - EVENT QUEUE RUNNER
//  php/EventQueueRunner.php
//
//  Executes selected modules against a SpiderFoot-style watched-event queue,
//  while projecting results back into the legacy read model for compatibility.
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/OsintEngine.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/ScanEvent.php';
require_once __DIR__ . '/EventQueueStore.php';
require_once __DIR__ . '/ModuleEventRegistry.php';
require_once __DIR__ . '/EventResultProjector.php';

class EventQueueRunner
{
    private int $scanId;
    private int $userId;
    private string $queryType;
    private string $queryValue;
    /** @var array<int,string> */
    private array $selectedApis;
    /** @var array<string,array<string,mixed>>|null */
    private ?array $snapshotModuleSettings;

    private EventQueueStore $store;
    private ModuleEventRegistry $registry;
    private EventResultProjector $projector;

    /**
     * @param array<int,string> $selectedApis
     * @param array<string,array<string,mixed>>|null $snapshotModuleSettings
     */
    public function __construct(
        int $scanId,
        int $userId,
        string $queryType,
        string $queryValue,
        array $selectedApis,
        ?array $snapshotModuleSettings = null
    ) {
        $this->scanId = $scanId;
        $this->userId = $userId;
        $this->queryType = $queryType;
        $this->queryValue = $queryValue;
        $this->selectedApis = $selectedApis;
        $this->snapshotModuleSettings = $snapshotModuleSettings;
        $this->store = new EventQueueStore();
        $this->registry = new ModuleEventRegistry($selectedApis);
        $this->projector = new EventResultProjector($scanId, $userId, $queryType, $queryValue);
    }

    public function isEnabled(): bool
    {
        return $this->store->isEnabled();
    }

    /**
     * @return array<string,int>
     */
    public function run(): array
    {
        $this->store->bootstrap($this->scanId, $this->queryType, $this->queryValue);
        if (function_exists('logScan')) {
            logScan(
                $this->scanId,
                'info',
                null,
                'Event queue engine initialized: root and seed events persisted.'
            );
        }

        while (($event = $this->store->claimNext($this->scanId)) instanceof ScanEvent) {
            if ($this->isScanStopped()) {
                $this->store->markQueueDropped($this->scanId, $event->eventHash);
                break;
            }

            $modules = $this->registry->modulesForEvent($event->eventType);
            if ($modules === []) {
                $this->store->markQueueDone($this->scanId, $event->eventHash);
                continue;
            }

            $eventFailed = false;
            foreach ($modules as $slug) {
                if ($this->isScanStopped()) {
                    $this->store->markQueueDropped($this->scanId, $event->eventHash);
                    return $this->projector->summary();
                }

                if (!$this->store->startHandler($this->scanId, $event->eventHash, $slug)) {
                    continue;
                }

                $config = $this->registry->configFor($slug);
                if (!$config) {
                    $this->store->finishHandler(
                        $this->scanId,
                        $event->eventHash,
                        $slug,
                        0,
                        0,
                        [],
                        [],
                        'Module configuration not found.'
                    );
                    continue;
                }

                if (!OsintEngine::hasHandler($slug)) {
                    $message = 'No module handler implemented';
                    $result = OsintResult::error($slug, (string)($config['name'] ?? $slug), $message)->toArray();
                    $normalized = $this->normalizeResults([$result], $event, $slug);
                    $projection = $this->projector->project($event, $slug, $normalized);
                    $this->store->finishHandler(
                        $this->scanId,
                        $event->eventHash,
                        $slug,
                        $projection['result_count'],
                        0,
                        $projection['inserted_ids'],
                        [],
                        $message
                    );
                    continue;
                }

                if (empty($config['api_key']) && !empty($config['requires_key'])) {
                    $message = 'API key not configured';
                    $result = OsintResult::error($slug, (string)($config['name'] ?? $slug), $message)->toArray();
                    $normalized = $this->normalizeResults([$result], $event, $slug);
                    $projection = $this->projector->project($event, $slug, $normalized);
                    $this->store->finishHandler(
                        $this->scanId,
                        $event->eventHash,
                        $slug,
                        $projection['result_count'],
                        0,
                        $projection['inserted_ids'],
                        [],
                        $message
                    );
                    continue;
                }

                try {
                    $moduleResults = OsintEngine::executeModule(
                        $slug,
                        $this->queryTypeForEvent($event),
                        $event->data,
                        (string)($config['api_key'] ?? ''),
                        (string)($config['base_url'] ?? ''),
                        (string)($config['name'] ?? $slug),
                        $this->snapshotModuleSettings[$slug] ?? null,
                        $this->queryType,
                        $this->queryValue
                    );

                    $normalized = $this->normalizeResults($moduleResults, $event, $slug);
                    $projection = $this->projector->project($event, $slug, $normalized);
                    $producedEventHashes = $this->materializeDiscoveries($event, $slug, $normalized);

                    $this->store->finishHandler(
                        $this->scanId,
                        $event->eventHash,
                        $slug,
                        $projection['result_count'],
                        count($producedEventHashes),
                        $projection['inserted_ids'],
                        $producedEventHashes,
                        null
                    );
                } catch (Throwable $e) {
                    $eventFailed = true;
                    $message = $e->getMessage();
                    if (function_exists('logScan')) {
                        logScan($this->scanId, 'error', $slug, $message);
                    }
                    $result = OsintResult::error($slug, (string)($config['name'] ?? $slug), $message)->toArray();
                    $normalized = $this->normalizeResults([$result], $event, $slug);
                    $projection = $this->projector->project($event, $slug, $normalized);
                    $this->store->finishHandler(
                        $this->scanId,
                        $event->eventHash,
                        $slug,
                        $projection['result_count'],
                        0,
                        $projection['inserted_ids'],
                        [],
                        $message
                    );
                }
            }

            if ($eventFailed) {
                $this->store->markQueueError($this->scanId, $event->eventHash, 'One or more handlers failed.');
                continue;
            }

            $this->store->markQueueDone($this->scanId, $event->eventHash);
        }

        $summary = $this->projector->summary();
        $queueStats = $this->store->stats($this->scanId);
        if (function_exists('logScan')) {
            logScan(
                $this->scanId,
                'info',
                null,
                'Event queue drained. '
                . ($queueStats['events'] ?? 0)
                . ' event(s), '
                . ($queueStats['handlers'] ?? 0)
                . ' handler execution(s).'
            );
        }

        return $summary;
    }

    private function queryTypeForEvent(ScanEvent $event): string
    {
        return EventTypes::toQueryType($event->eventType) ?? $this->queryType;
    }

    /**
     * @param array<int,OsintResult|array<string,mixed>> $moduleResults
     * @return array<int,array<string,mixed>>
     */
    private function normalizeResults(array $moduleResults, ScanEvent $event, string $moduleSlug): array
    {
        $normalized = [];
        foreach ($moduleResults as $result) {
            $row = $result instanceof OsintResult ? $result->toArray() : (is_array($result) ? $result : []);
            if ($row === []) {
                continue;
            }

            $row['api'] = (string)($row['api'] ?? $moduleSlug);
            $row['query_type'] = (string)($row['query_type'] ?? $this->queryTypeForEvent($event));
            $row['enrichment_pass'] = $event->depth;
            $row['source_ref'] = $event->depth > 0 ? $event->sourceRefForProjection() : 'ROOT';
            $row['enriched_from'] = $event->depth > 0 ? $event->data : null;
            $row['source_event_hash'] = $event->eventHash;
            $normalized[] = $row;
        }

        return $normalized;
    }

    /**
     * @param array<int,array<string,mixed>> $normalizedResults
     * @return array<int,string>
     */
    private function materializeDiscoveries(ScanEvent $event, string $moduleSlug, array $normalizedResults): array
    {
        $produced = [];

        foreach ($normalizedResults as $result) {
            if (!($result['success'] ?? true)) {
                continue;
            }

            $discoveries = is_array($result['discoveries'] ?? null) ? $result['discoveries'] : [];
            foreach ($discoveries as $discovery) {
                $eventType = trim((string)($discovery['type'] ?? ''));
                $value = trim((string)($discovery['value'] ?? ''));
                if ($eventType === '' || $value === '' || !EventTypes::isEnrichable($eventType)) {
                    continue;
                }

                $child = ScanEvent::discovery(
                    scanId: $this->scanId,
                    eventType: $eventType,
                    data: $value,
                    moduleSlug: $moduleSlug,
                    sourceEventHash: $event->eventHash,
                    sourceData: $event->data,
                    depth: $event->depth + 1,
                    rawPayload: [
                        'parent_event_type' => $event->eventType,
                        'parent_event_data' => $event->data,
                        'source_module' => $moduleSlug,
                    ],
                    confidence: (int)($result['confidence'] ?? 0),
                    riskScore: (int)($result['score'] ?? 0)
                );

                $insert = $this->store->ensureEvent($child);
                $actualChild = $insert['event'];
                $this->store->linkEvents($this->scanId, $event->eventHash, $actualChild->eventHash, $moduleSlug, 'discovered');
                if ($insert['inserted']) {
                    $this->store->enqueue($this->scanId, $actualChild->eventHash, 100 + $actualChild->depth);
                }
                if (!in_array($actualChild->eventHash, $produced, true)) {
                    $produced[] = $actualChild->eventHash;
                }
            }
        }

        return $produced;
    }

    private function isScanStopped(): bool
    {
        $row = DB::queryOne(
            "SELECT status FROM scans WHERE id = :id LIMIT 1",
            [':id' => $this->scanId]
        );

        return in_array(strtolower((string)($row['status'] ?? '')), ['aborted', 'failed'], true);
    }
}
