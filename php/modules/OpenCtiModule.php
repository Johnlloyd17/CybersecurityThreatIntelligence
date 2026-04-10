<?php
// =============================================================================
//  CTI — OpenCTI Module
//  Queries OpenCTI threat intelligence platform via GraphQL API.
//  API Docs: https://docs.opencti.io/latest/deployment/connectors/
//  Supports: ip, domain, url, hash, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OpenCtiModule extends BaseApiModule
{
    private const API_ID   = 'opencti';
    private const API_NAME = 'OpenCTI';
    private const SUPPORTED = ['ip', 'domain', 'url', 'hash', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://localhost:8080', '/');
        $headers = [
            'Authorization' => "Bearer {$apiKey}",
            'Content-Type'  => 'application/json',
        ];

        $graphql = json_encode([
            'query' => '
                query SearchIndicators($search: String!, $first: Int) {
                    stixCyberObservables(search: $search, first: $first) {
                        edges {
                            node {
                                id
                                entity_type
                                observable_value
                                x_opencti_score
                                x_opencti_description
                                created_at
                                objectLabel { edges { node { value color } } }
                                stixCoreRelationships(first: 20) {
                                    edges {
                                        node {
                                            relationship_type
                                            to { ... on StixDomainObject { id entity_type } }
                                        }
                                    }
                                }
                                indicators(first: 10) {
                                    edges {
                                        node {
                                            name
                                            pattern
                                            valid_from
                                            x_opencti_score
                                        }
                                    }
                                }
                            }
                        }
                    }
                }',
            'variables' => [
                'search' => $queryValue,
                'first'  => $this->maxResults(),
            ],
        ]);

        $resp = HttpClient::post("{$baseUrl}/graphql", $graphql, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json  = $resp['json'];
        $edges = $json['data']['stixCyberObservables']['edges'] ?? [];

        if (empty($edges)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalResults = count($edges);
        $maxScore     = 0;
        $labels       = [];
        $relTypes     = [];
        $indicators   = [];

        foreach ($edges as $edge) {
            $node = $edge['node'] ?? [];
            $nodeScore = (int)($node['x_opencti_score'] ?? 0);
            $maxScore  = max($maxScore, $nodeScore);

            foreach ($node['objectLabel']['edges'] ?? [] as $le) {
                $lbl = $le['node']['value'] ?? '';
                if ($lbl) $labels[$lbl] = true;
            }
            foreach ($node['stixCoreRelationships']['edges'] ?? [] as $re) {
                $rt = $re['node']['relationship_type'] ?? '';
                if ($rt) $relTypes[$rt] = ($relTypes[$rt] ?? 0) + 1;
            }
            foreach ($node['indicators']['edges'] ?? [] as $ie) {
                $iNode = $ie['node'] ?? [];
                if (!empty($iNode['name'])) {
                    $indicators[] = $iNode['name'];
                }
            }
        }

        $score      = min(100, $maxScore ?: min(60, $totalResults * 15));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + $totalResults * 5);

        $summary = "{$queryValue}: {$totalResults} observable(s) in OpenCTI (score: {$maxScore}).";
        if (!empty($labels)) {
            $summary .= ' Labels: ' . implode(', ', array_slice(array_keys($labels), 0, 5)) . '.';
        }
        if (!empty($indicators)) {
            $summary .= ' Linked to ' . count($indicators) . ' indicator(s).';
        }

        $resultTags = [self::API_ID, $queryType, 'threat_intel'];
        foreach (array_keys($labels) as $l) {
            $resultTags[] = strtolower($l);
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'total_observables' => $totalResults,
                'max_score'         => $maxScore,
                'labels'            => array_keys($labels),
                'relationship_types'=> $relTypes,
                'indicators'        => array_slice($indicators, 0, 20),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://localhost:8080', '/');
        $headers = ['Authorization' => "Bearer {$apiKey}", 'Content-Type' => 'application/json'];
        $body = json_encode(['query' => '{ about { version } }']);
        $resp = HttpClient::post("{$baseUrl}/graphql", $body, $headers);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
