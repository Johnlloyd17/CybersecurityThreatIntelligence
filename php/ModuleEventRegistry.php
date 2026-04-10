<?php
// =============================================================================
//  CTI - MODULE EVENT REGISTRY
//  php/ModuleEventRegistry.php
//
//  Resolves watched-event routing for the selected modules by translating
//  api_configs.supported_types into routable event types.
// =============================================================================

require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/OsintEngine.php';

class ModuleEventRegistry
{
    /** @var array<int,string> */
    private array $slugs;
    /** @var array<string,array<string,mixed>> */
    private array $configs;
    /** @var array<string,array<int,string>> */
    private array $watchedEventMap = [];

    /**
     * @param array<int,string> $selectedSlugs
     */
    public function __construct(array $selectedSlugs)
    {
        $selectedSlugs = array_values(array_filter(array_map(
            static fn($slug): string => strtolower(trim((string)$slug)),
            $selectedSlugs
        ), static fn(string $slug): bool => $slug !== ''));

        $this->configs = OsintEngine::loadApiConfigs($selectedSlugs);
        $this->slugs = OsintEngine::sortSlugsByPriority($selectedSlugs, $this->configs);
        $this->buildWatchedEventMap();
    }

    /**
     * @return array<int,string>
     */
    public function slugs(): array
    {
        return $this->slugs;
    }

    /**
     * @return array<string,array<string,mixed>>
     */
    public function configs(): array
    {
        return $this->configs;
    }

    /**
     * @return array<string,mixed>|null
     */
    public function configFor(string $slug): ?array
    {
        return $this->configs[$slug] ?? null;
    }

    /**
     * @return array<int,string>
     */
    public function modulesForEvent(string $eventType): array
    {
        return $this->watchedEventMap[$eventType] ?? [];
    }

    private function buildWatchedEventMap(): void
    {
        foreach ($this->slugs as $slug) {
            $config = $this->configs[$slug] ?? null;
            if (!$config) {
                continue;
            }

            $supportedTypes = $config['supported_types'] ?? null;
            if (is_string($supportedTypes)) {
                $decoded = json_decode($supportedTypes, true);
                $supportedTypes = is_array($decoded) ? $decoded : [];
            }

            if (!is_array($supportedTypes) || $supportedTypes === []) {
                $supportedTypes = ['ip', 'domain', 'email', 'hash', 'url', 'cve', 'username', 'phone', 'bitcoin'];
            }

            $eventTypes = [];
            foreach ($supportedTypes as $queryType) {
                foreach (EventTypes::queryTypeToEventTypes((string)$queryType) as $eventType) {
                    $eventTypes[$eventType] = true;
                }
            }

            foreach (array_keys($eventTypes) as $eventType) {
                $this->watchedEventMap[$eventType] ??= [];
                if (!in_array($slug, $this->watchedEventMap[$eventType], true)) {
                    $this->watchedEventMap[$eventType][] = $slug;
                }
            }
        }
    }
}
