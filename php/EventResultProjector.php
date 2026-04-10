<?php
// =============================================================================
//  CTI - EVENT RESULT PROJECTOR
//  php/EventResultProjector.php
//
//  Projects event-native module execution back into the existing query_history
//  and threat_indicators read models so the current UI remains functional while
//  the event queue engine takes over scan orchestration.
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/GlobalSettings.php';
require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/EventQueueStore.php';
require_once __DIR__ . '/ScanEvent.php';

class EventResultProjector
{
    private int $scanId;
    private int $userId;
    private string $rootQueryType;
    private string $rootQueryValue;

    /** @var array<string,true> */
    private array $seenFindingSignatures = [];
    /** @var array<string,true> */
    private array $seenErrorSignatures = [];
    /** @var array<string,true> */
    private array $uniqueFindingKeys = [];

    private int $overallScore = 0;
    private int $errorCount = 0;
    private int $totalElements = 0;
    private int $maxPass = 0;

    public function __construct(int $scanId, int $userId, string $rootQueryType, string $rootQueryValue)
    {
        $this->scanId = $scanId;
        $this->userId = $userId;
        $this->rootQueryType = $rootQueryType;
        $this->rootQueryValue = $rootQueryValue;
    }

    /**
     * @param array<int,array<string,mixed>> $moduleResults
     * @return array{inserted_ids: array<int,int>, result_count: int}
     */
    public function project(ScanEvent $event, string $moduleSlug, array $moduleResults): array
    {
        $insertedIds = [];
        $resultCount = 0;

        foreach ($moduleResults as $result) {
            $resultCount++;

            $score = (int)($result['score'] ?? 0);
            $severity = (string)($result['severity'] ?? 'unknown');
            $confidence = (int)($result['confidence'] ?? 0);
            $responseMs = (int)($result['response_ms'] ?? 0);
            $summary = (string)($result['summary'] ?? '');
            $slug = (string)($result['api'] ?? $moduleSlug);
            $tags = is_array($result['tags'] ?? null) ? $result['tags'] : [];
            $isError = !($result['success'] ?? true) || isset($result['error']);
            $dataType = isset($result['data_type']) ? (string)$result['data_type'] : null;

            if ($event->depth > $this->maxPass) {
                $this->maxPass = $event->depth;
            }

            $summary = GlobalSettings::truncate($summary);
            $resultQueryType = (string)($result['query_type'] ?? EventTypes::toQueryType($event->eventType) ?? $this->rootQueryType);
            $resultQueryValue = $event->data;
            $sourceRef = $event->depth > 0 ? $event->sourceRefForProjection() : 'ROOT';
            $enrichedFrom = $event->depth > 0 ? $event->data : null;

            if ($isError) {
                $errorMessage = (string)($result['error'] ?? ($summary !== '' ? $summary : 'Module execution failed'));
                $errorSignature = self::errorSignature($slug, $errorMessage);
                if (isset($this->seenErrorSignatures[$errorSignature])) {
                    continue;
                }

                $this->seenErrorSignatures[$errorSignature] = true;
                $this->errorCount++;
                if (function_exists('logScan')) {
                    logScan($this->scanId, 'error', $slug, $errorMessage);
                }
            } else {
                $findingSignature = self::findingSignature(
                    $slug,
                    $resultQueryType,
                    $resultQueryValue,
                    $dataType,
                    $summary
                );

                if (isset($this->seenFindingSignatures[$findingSignature])) {
                    continue;
                }

                $this->seenFindingSignatures[$findingSignature] = true;
                $this->totalElements++;
                $this->uniqueFindingKeys[$findingSignature] = true;
                $passLabel = $event->depth > 0 ? " [event pass {$event->depth}]" : '';
                if (function_exists('logScan')) {
                    logScan(
                        $this->scanId,
                        'info',
                        $slug,
                        "Completed in {$responseMs}ms - score: {$score}, severity: {$severity}{$passLabel}"
                    );
                }
            }

            $rowStatus = $isError ? 'failed' : 'completed';
            $insertedIds[] = (int)DB::insert(
                "INSERT INTO query_history
                    (user_id, scan_id, query_type, query_value, api_source, data_type,
                     result_summary, risk_score, status, response_time,
                     enrichment_pass, source_ref, enriched_from)
                 VALUES
                    (:uid, :sid, :qt, :qv, :api, :dt,
                     :summary, :score, :status, :resp,
                     :epass, :sref, :efrom)",
                [
                    ':uid' => $this->userId,
                    ':sid' => $this->scanId,
                    ':qt' => $resultQueryType,
                    ':qv' => $resultQueryValue,
                    ':api' => $slug,
                    ':dt' => $dataType,
                    ':summary' => $summary,
                    ':score' => $score,
                    ':status' => $rowStatus,
                    ':resp' => $responseMs,
                    ':epass' => $event->depth,
                    ':sref' => $sourceRef,
                    ':efrom' => $enrichedFrom,
                ]
            );

            if (!$isError) {
                DB::execute(
                    "INSERT INTO threat_indicators
                        (indicator_type, indicator_value, source, severity, confidence, tags, first_seen, last_seen)
                     VALUES
                        (:type, :val, :src, :sev, :conf, :tags, NOW(), NOW())
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
                        ':conf' => $confidence,
                        ':tags' => json_encode($tags, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    ]
                );
            }

            $this->overallScore = max($this->overallScore, $score);
        }

        return [
            'inserted_ids' => $insertedIds,
            'result_count' => $resultCount,
        ];
    }

    /**
     * @return array<string,int>
     */
    public function summary(): array
    {
        return [
            'overall_score' => $this->overallScore,
            'error_count' => $this->errorCount,
            'total_elements' => $this->totalElements,
            'unique_elements' => count($this->uniqueFindingKeys),
            'max_pass' => $this->maxPass,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public static function buildEventGraph(int $scanId): array
    {
        $store = new EventQueueStore();
        return $store->eventGraphPayload($scanId);
    }

    /**
     * @return array<string,int>
     */
    public static function eventStats(int $scanId): array
    {
        $store = new EventQueueStore();
        return $store->stats($scanId);
    }

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
}
