<?php
// =============================================================================
//  CTI - SCAN EVENT VALUE OBJECT
//  php/ScanEvent.php
//
//  Represents one canonical data element in the event queue engine.
// =============================================================================

require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/EventHasher.php';

class ScanEvent
{
    public int $scanId;
    public string $eventHash;
    public string $eventType;
    public string $data;
    public string $moduleSlug;
    public string $sourceEventHash;
    public string $sourceData;
    public ?string $parentEventHash;
    public int $depth;
    public int $confidence;
    public int $riskScore;
    public int $visibility;
    public bool $falsePositive;
    /** @var array<string,mixed>|null */
    public ?array $rawPayload;
    public ?string $createdAt;

    /**
     * @param array<string,mixed>|null $rawPayload
     */
    public function __construct(
        int $scanId,
        string $eventType,
        string $data,
        string $moduleSlug,
        string $sourceEventHash = 'ROOT',
        string $sourceData = 'ROOT',
        ?string $parentEventHash = null,
        int $depth = 0,
        int $confidence = 0,
        int $riskScore = 0,
        int $visibility = 100,
        bool $falsePositive = false,
        ?array $rawPayload = null,
        ?string $createdAt = null
    ) {
        $this->scanId = $scanId;
        $this->eventType = trim($eventType);
        $this->data = trim($data);
        $this->moduleSlug = strtolower(trim($moduleSlug));
        $this->sourceEventHash = trim($sourceEventHash) !== '' ? trim($sourceEventHash) : 'ROOT';
        $this->sourceData = trim($sourceData) !== '' ? trim($sourceData) : 'ROOT';
        $this->parentEventHash = $parentEventHash !== null && trim($parentEventHash) !== '' ? trim($parentEventHash) : null;
        $this->depth = max(0, $depth);
        $this->confidence = max(0, min(100, $confidence));
        $this->riskScore = max(0, min(100, $riskScore));
        $this->visibility = max(0, min(100, $visibility));
        $this->falsePositive = $falsePositive;
        $this->rawPayload = $rawPayload;
        $this->createdAt = $createdAt;
        $this->eventHash = EventHasher::hash($this->eventType, $this->data);
    }

    public static function root(int $scanId, string $queryType, string $queryValue): self
    {
        return new self(
            scanId: $scanId,
            eventType: EventTypes::ROOT,
            data: strtolower(trim($queryType)) . ':' . trim($queryValue),
            moduleSlug: 'root',
            sourceEventHash: 'ROOT',
            sourceData: 'ROOT',
            parentEventHash: null,
            depth: 0,
            confidence: 100,
            riskScore: 0,
            visibility: 100,
            falsePositive: false,
            rawPayload: [
                'query_type' => $queryType,
                'query_value' => $queryValue,
            ]
        );
    }

    public static function seedTarget(int $scanId, string $queryType, string $queryValue, string $rootHash): self
    {
        $eventType = self::seedEventTypeForQueryType($queryType);
        return new self(
            scanId: $scanId,
            eventType: $eventType,
            data: $queryValue,
            moduleSlug: 'seed',
            sourceEventHash: $rootHash,
            sourceData: 'ROOT',
            parentEventHash: $rootHash,
            depth: 0,
            confidence: 100,
            riskScore: 0,
            visibility: 100,
            falsePositive: false,
            rawPayload: [
                'seed_query_type' => $queryType,
                'seed_query_value' => $queryValue,
            ]
        );
    }

    /**
     * @param array<string,mixed>|null $rawPayload
     */
    public static function discovery(
        int $scanId,
        string $eventType,
        string $data,
        string $moduleSlug,
        string $sourceEventHash,
        string $sourceData,
        int $depth,
        ?array $rawPayload = null,
        int $confidence = 0,
        int $riskScore = 0,
        int $visibility = 100
    ): self {
        return new self(
            scanId: $scanId,
            eventType: $eventType,
            data: $data,
            moduleSlug: $moduleSlug,
            sourceEventHash: $sourceEventHash,
            sourceData: $sourceData,
            parentEventHash: $sourceEventHash,
            depth: $depth,
            confidence: $confidence,
            riskScore: $riskScore,
            visibility: $visibility,
            falsePositive: false,
            rawPayload: $rawPayload
        );
    }

    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        $rawPayload = $row['raw_payload_json'] ?? null;
        if (is_string($rawPayload) && trim($rawPayload) !== '') {
            $decoded = json_decode($rawPayload, true);
            $rawPayload = is_array($decoded) ? $decoded : null;
        } elseif (!is_array($rawPayload)) {
            $rawPayload = null;
        }

        $event = new self(
            scanId: (int)($row['scan_id'] ?? 0),
            eventType: (string)($row['event_type'] ?? EventTypes::ROOT),
            data: (string)($row['event_data'] ?? ''),
            moduleSlug: (string)($row['module_slug'] ?? 'unknown'),
            sourceEventHash: (string)($row['source_event_hash'] ?? 'ROOT'),
            sourceData: (string)($row['source_data'] ?? 'ROOT'),
            parentEventHash: isset($row['parent_event_hash']) ? (string)$row['parent_event_hash'] : null,
            depth: (int)($row['event_depth'] ?? 0),
            confidence: (int)($row['confidence'] ?? 0),
            riskScore: (int)($row['risk_score'] ?? 0),
            visibility: (int)($row['visibility'] ?? 100),
            falsePositive: !empty($row['false_positive']),
            rawPayload: $rawPayload,
            createdAt: isset($row['created_at']) ? (string)$row['created_at'] : null
        );

        if (!empty($row['event_hash'])) {
            $event->eventHash = (string)$row['event_hash'];
        }

        return $event;
    }

    public function sourceRefForProjection(): string
    {
        if ($this->depth <= 0) {
            return 'ROOT';
        }

        return ($this->moduleSlug !== '' ? $this->moduleSlug : 'module') . ':' . $this->data;
    }

    public static function seedEventTypeForQueryType(string $queryType): string
    {
        return match (strtolower(trim($queryType))) {
            'ip' => EventTypes::IP_ADDRESS,
            'domain' => EventTypes::INTERNET_NAME,
            'email' => EventTypes::EMAILADDR,
            'hash' => EventTypes::HASH,
            'url' => EventTypes::LINKED_URL_EXTERNAL,
            'cve' => EventTypes::VULNERABILITY,
            'username' => EventTypes::USERNAME,
            'phone' => EventTypes::PHONE_NUMBER,
            'bitcoin' => EventTypes::BITCOIN_ADDRESS,
            default => EventTypes::ROOT,
        };
    }
}
