<?php
// =============================================================================
//  CTI - CORRELATION RULE ENGINE
//  php/CorrelationRuleEngine.php
//
//  Loads correlation rules from correlations/*.yaml. The shipped rule files use
//  JSON syntax, which is also valid YAML, so we can parse them without pulling
//  in an additional YAML library.
// =============================================================================

class CorrelationRuleEngine
{
    private string $rulesDir;

    /** @var array<int,array<string,mixed>>|null */
    private ?array $cachedRules = null;

    public function __construct(?string $rulesDir = null)
    {
        $this->rulesDir = $rulesDir ?: dirname(__DIR__) . DIRECTORY_SEPARATOR . 'correlations';
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    public function loadRules(): array
    {
        if ($this->cachedRules !== null) {
            return $this->cachedRules;
        }

        $rules = [];
        $files = glob($this->rulesDir . DIRECTORY_SEPARATOR . '*.yaml') ?: [];
        sort($files, SORT_NATURAL | SORT_FLAG_CASE);

        foreach ($files as $file) {
            $rule = $this->parseRuleFile($file);
            if (!is_array($rule)) {
                continue;
            }

            $rule = $this->normalizeRuleDefinition($rule);

            $ruleName = trim((string)($rule['rule_name'] ?? ''));
            if ($ruleName === '') {
                error_log('[CorrelationRuleEngine] Skipping rule without rule_name: ' . basename($file));
                continue;
            }

            $rule['__file'] = basename($file);
            $rules[] = $rule;
        }

        $this->cachedRules = $rules;
        return $rules;
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,array<string,mixed>>
     */
    public function evaluate(array $rows, string $queryType, string $queryValue): array
    {
        $findings = [];

        foreach ($this->loadRules() as $rule) {
            $collections = $this->buildCollections($rows, $rule);
            $baseVars = $this->buildContextVariables(
                $rule['context'] ?? [],
                $collections,
                null,
                $queryType,
                $queryValue
            );

            if (!$this->conditionsMatch($rule['when'] ?? [], $collections, null)) {
                continue;
            }

            $emitMode = strtolower(trim((string)($rule['emit'] ?? 'single')));
            if ($emitMode === 'aggregated_legacy') {
                array_push($findings, ...$this->evaluateAggregatedLegacyRule($rule, $collections, $queryType, $queryValue));
                continue;
            }

            if ($emitMode === 'per_item') {
                $collectionName = (string)($rule['collection'] ?? '');
                $emitRows = $collections[$collectionName] ?? [];
                foreach ($emitRows as $row) {
                    if (!$this->conditionsMatch($rule['each_when'] ?? [], $collections, $row)) {
                        continue;
                    }

                    $vars = array_merge(
                        $baseVars,
                        $this->rowToVariables($row),
                        ['query_type' => $queryType, 'query_value' => $queryValue]
                    );

                    $findings[] = [
                        'rule_name' => (string)$rule['rule_name'],
                        'severity' => (string)($rule['severity'] ?? 'info'),
                        'title' => $this->applyTemplate((string)($rule['title'] ?? ''), $vars),
                        'detail' => $this->applyTemplate((string)($rule['detail'] ?? ''), $vars),
                        'linked_result_ids' => $this->resolveLinks($rule['links'] ?? ['collection' => 'item'], $collections, $row),
                    ];
                }
                continue;
            }

            $vars = array_merge($baseVars, ['query_type' => $queryType, 'query_value' => $queryValue]);
            $findings[] = [
                'rule_name' => (string)$rule['rule_name'],
                'severity' => (string)($rule['severity'] ?? 'info'),
                'title' => $this->applyTemplate((string)($rule['title'] ?? ''), $vars),
                'detail' => $this->applyTemplate((string)($rule['detail'] ?? ''), $vars),
                'linked_result_ids' => $this->resolveLinks($rule['links'] ?? [], $collections, null),
            ];
        }

        return $findings;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function parseRuleFile(string $file): ?array
    {
        $raw = trim((string)@file_get_contents($file));
        if ($raw === '') {
            return null;
        }

        $json = json_decode($raw, true);
        if (is_array($json)) {
            return $json;
        }

        if (function_exists('yaml_parse')) {
            $yaml = @yaml_parse($raw);
            if (is_array($yaml)) {
                return $yaml;
            }
        }

        error_log('[CorrelationRuleEngine] Could not parse rule file: ' . basename($file));
        return null;
    }

    /**
     * Supports the native CTI rule format and a SpiderFoot-inspired
     * meta/collections/aggregation/analysis structure.
     *
     * @param array<string,mixed> $rule
     * @return array<string,mixed>
     */
    private function normalizeRuleDefinition(array $rule): array
    {
        if (trim((string)($rule['rule_name'] ?? '')) !== '') {
            return $rule;
        }

        $meta = $rule['meta'] ?? null;
        $legacyCollections = $rule['collections'] ?? null;
        if (!is_array($meta) || !is_array($legacyCollections) || !$this->isListArray($legacyCollections)) {
            return $rule;
        }

        $normalized = [
            'rule_name' => trim((string)($meta['name'] ?? '')),
            'severity' => strtolower(trim((string)($meta['risk'] ?? 'info'))),
            'title' => trim((string)($rule['headline'] ?? $meta['name'] ?? '')),
            'detail' => trim((string)($meta['description'] ?? '')),
            'emit' => 'aggregated_legacy',
            'collection' => 'results',
            'collections' => [],
            '_aggregation' => is_array($rule['aggregation'] ?? null) ? $rule['aggregation'] : [],
            '_analysis' => is_array($rule['analysis'] ?? null) ? $rule['analysis'] : [],
        ];

        $idMap = [];
        foreach ($legacyCollections as $index => $definition) {
            if (!is_array($definition)) {
                continue;
            }
            $rawId = preg_replace('/[^a-z0-9]+/i', '', (string)($definition['id'] ?? ($index + 1)));
            $id = $rawId !== '' ? strtolower($rawId) : (string)($index + 1);
            $idMap[$id] = 'c' . $id;
        }

        $lastCollection = 'results';
        foreach ($legacyCollections as $index => $definition) {
            if (!is_array($definition)) {
                continue;
            }

            $rawId = preg_replace('/[^a-z0-9]+/i', '', (string)($definition['id'] ?? ($index + 1)));
            $id = $rawId !== '' ? strtolower($rawId) : (string)($index + 1);
            $name = $idMap[$id] ?? ('c' . ($index + 1));

            $collectFrom = preg_replace('/[^a-z0-9]+/i', '', (string)($definition['collect_from'] ?? ''));
            $from = $collectFrom !== '' && isset($idMap[strtolower($collectFrom)])
                ? $idMap[strtolower($collectFrom)]
                : 'results';

            $matcher = $this->normalizeLegacyCollectionMatcher($definition);
            $normalized['collections'][$name] = [
                'from' => $from,
                'where' => $matcher !== null ? [$matcher] : [],
            ];
            $lastCollection = $name;
        }

        $normalized['collection'] = $lastCollection;
        if (!isset($normalized['_aggregation']['field']) || trim((string)($normalized['_aggregation']['field'] ?? '')) === '') {
            $normalized['_aggregation']['field'] = 'query_value';
        }

        return $normalized;
    }

    /**
     * @param array<string,mixed> $definition
     * @return array<string,mixed>|null
     */
    private function normalizeLegacyCollectionMatcher(array $definition): ?array
    {
        $field = strtolower(trim((string)($definition['field'] ?? '')));
        if ($field === '') {
            return null;
        }

        $fieldMap = [
            'type' => 'data_type',
            'module' => 'api_source',
            'data' => 'result_summary',
            'entity' => 'query_value',
            'source' => 'source_ref',
        ];
        $method = strtolower(trim((string)($definition['method'] ?? 'exact')));
        $value = $definition['value'] ?? '';

        return [
            'field' => $fieldMap[$field] ?? $field,
            'method' => match ($method) {
                'exact' => 'equals',
                default => $method,
            },
            'value' => $value,
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @param array<string,mixed> $rule
     * @return array<string,array<int,array<string,mixed>>>
     */
    private function buildCollections(array $rows, array $rule): array
    {
        $collections = ['results' => array_values($rows)];
        $definitions = $rule['collections'] ?? [];
        if (!is_array($definitions)) {
            return $collections;
        }

        foreach ($definitions as $name => $definition) {
            if (!is_array($definition)) {
                continue;
            }

            $from = (string)($definition['from'] ?? 'results');
            $sourceRows = $collections[$from] ?? [];
            $filters = is_array($definition['filters'] ?? null) ? $definition['filters'] : [];
            $where = is_array($definition['where'] ?? null) ? $definition['where'] : [];
            $collections[(string)$name] = array_values(array_filter(
                $sourceRows,
                fn(array $row): bool => $this->rowMatchesFilters($row, $filters)
                    && $this->rowMatchesWhere($row, $where)
            ));
        }

        return $collections;
    }

    /**
     * @param array<string,mixed> $filters
     */
    private function rowMatchesFilters(array $row, array $filters): bool
    {
        foreach ($filters as $filter => $value) {
            switch ($filter) {
                case 'status':
                    if ($this->rowStatus($row) !== (string)$value) {
                        return false;
                    }
                    break;

                case 'status_not':
                    if ($this->rowStatus($row) === (string)$value) {
                        return false;
                    }
                    break;

                case 'success':
                    $expected = (bool)$value;
                    $actual = $this->rowSuccess($row);
                    if ($actual !== $expected) {
                        return false;
                    }
                    break;

                case 'score_gte':
                    if ($this->rowScore($row) < (float)$value) {
                        return false;
                    }
                    break;

                case 'score_lte':
                    if ($this->rowScore($row) > (float)$value) {
                        return false;
                    }
                    break;

                case 'enrichment_pass_gte':
                    if ($this->rowEnrichmentPass($row) < (int)$value) {
                        return false;
                    }
                    break;

                case 'enrichment_pass_eq':
                    if ($this->rowEnrichmentPass($row) !== (int)$value) {
                        return false;
                    }
                    break;

                case 'has_enriched_from':
                    $hasValue = trim($this->rowEnrichedFrom($row)) !== '';
                    if ($hasValue !== (bool)$value) {
                        return false;
                    }
                    break;

                case 'api_in':
                    $allowed = array_map('strval', is_array($value) ? $value : [$value]);
                    if (!in_array($this->rowApi($row), $allowed, true)) {
                        return false;
                    }
                    break;

                case 'query_type':
                    if ($this->rowQueryType($row) !== (string)$value) {
                        return false;
                    }
                    break;
            }
        }

        return true;
    }

    /**
     * @param array<int,array<string,mixed>> $where
     */
    private function rowMatchesWhere(array $row, array $where): bool
    {
        foreach ($where as $matcher) {
            if (!is_array($matcher)) {
                continue;
            }

            $field = trim((string)($matcher['field'] ?? ''));
            if ($field === '') {
                continue;
            }

            $actual = $this->valueForField($row, $field);
            $method = strtolower(trim((string)($matcher['method'] ?? 'equals')));
            $expected = $matcher['value'] ?? '';

            switch ($method) {
                case 'equals':
                case 'eq':
                    if ($actual !== (string)$expected) {
                        return false;
                    }
                    break;

                case 'contains':
                    if (stripos($actual, (string)$expected) === false) {
                        return false;
                    }
                    break;

                case 'regex':
                    $pattern = (string)$expected;
                    if ($pattern === '' || @preg_match($pattern, $actual) !== 1) {
                        return false;
                    }
                    break;

                case 'wildcard':
                    $quoted = preg_quote((string)$expected, '/');
                    $pattern = '/^' . str_replace(['\\*', '\\?'], ['.*', '.'], $quoted) . '$/i';
                    if (preg_match($pattern, $actual) !== 1) {
                        return false;
                    }
                    break;

                case 'present':
                    if (trim($actual) === '') {
                        return false;
                    }
                    break;

                case 'gte':
                case '>=':
                    if ((float)$actual < (float)$expected) {
                        return false;
                    }
                    break;

                case 'lte':
                case '<=':
                    if ((float)$actual > (float)$expected) {
                        return false;
                    }
                    break;
            }
        }

        return true;
    }

    /**
     * @param array<int,array<string,mixed>> $conditions
     */
    private function conditionsMatch(array $conditions, array $collections, ?array $item): bool
    {
        if ($conditions === []) {
            return true;
        }

        foreach ($conditions as $condition) {
            if (!is_array($condition)) {
                continue;
            }

            $left = $this->resolveAggregate(
                (string)($condition['collection'] ?? 'results'),
                (string)($condition['aggregate'] ?? 'count'),
                $collections,
                $condition,
                $item
            );

            $operator = (string)($condition['operator'] ?? '>=');
            $right = $condition['value'] ?? null;

            if (!$this->compareValues($left, $operator, $right)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string,mixed> $contextDefs
     * @return array<string,string|int|float>
     */
    private function buildContextVariables(array $contextDefs, array $collections, ?array $item, string $queryType, string $queryValue): array
    {
        $vars = [
            'query_type' => $queryType,
            'query_value' => $queryValue,
        ];

        foreach ($contextDefs as $name => $definition) {
            if (!is_array($definition)) {
                continue;
            }

            $aggregate = (string)($definition['aggregate'] ?? 'count');
            $collection = (string)($definition['collection'] ?? 'results');
            $vars[(string)$name] = $this->resolveAggregate($collection, $aggregate, $collections, $definition, $item);
        }

        return $vars;
    }

    /**
     * @param array<string,mixed> $definition
     * @return string|int|float
     */
    private function resolveAggregate(string $collectionName, string $aggregate, array $collections, array $definition, ?array $item)
    {
        if ($collectionName === 'item' && $item !== null) {
            $rows = [$item];
        } else {
            $rows = $collections[$collectionName] ?? [];
        }

        return match ($aggregate) {
            'count' => count($rows),
            'distinct_count' => count($this->distinctValues($rows, (string)($definition['field'] ?? 'id'))),
            'join_template' => implode(
                (string)($definition['separator'] ?? ', '),
                $this->buildTemplateList($rows, (string)($definition['template'] ?? '{{result_summary}}'), (int)($definition['limit'] ?? 0), false)
            ),
            'distinct_join_template' => implode(
                (string)($definition['separator'] ?? ', '),
                $this->buildTemplateList($rows, (string)($definition['template'] ?? '{{result_summary}}'), (int)($definition['limit'] ?? 0), true)
            ),
            'join_field' => implode(
                (string)($definition['separator'] ?? ', '),
                $this->buildFieldList($rows, (string)($definition['field'] ?? 'id'), (int)($definition['limit'] ?? 0), false)
            ),
            'distinct_join_field' => implode(
                (string)($definition['separator'] ?? ', '),
                $this->buildFieldList($rows, (string)($definition['field'] ?? 'id'), (int)($definition['limit'] ?? 0), true)
            ),
            default => count($rows),
        };
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,string>
     */
    private function buildTemplateList(array $rows, string $template, int $limit, bool $distinct): array
    {
        $items = [];
        foreach ($rows as $row) {
            $items[] = $this->applyTemplate($template, $this->rowToVariables($row));
        }

        if ($distinct) {
            $items = array_values(array_unique(array_filter($items, fn($value) => trim((string)$value) !== '')));
        }

        if ($limit > 0) {
            $items = array_slice($items, 0, $limit);
        }

        return $items;
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,string>
     */
    private function buildFieldList(array $rows, string $field, int $limit, bool $distinct): array
    {
        $items = $distinct
            ? $this->distinctValues($rows, $field)
            : array_map(fn(array $row): string => $this->valueForField($row, $field), $rows);

        $items = array_values(array_filter($items, fn($value) => trim((string)$value) !== ''));
        if ($limit > 0) {
            $items = array_slice($items, 0, $limit);
        }

        return $items;
    }

    /**
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,string>
     */
    private function distinctValues(array $rows, string $field): array
    {
        $values = array_map(fn(array $row): string => $this->valueForField($row, $field), $rows);
        $values = array_values(array_unique(array_filter($values, fn($value) => trim((string)$value) !== '')));
        return $values;
    }

    private function compareValues(mixed $left, string $operator, mixed $right): bool
    {
        return match ($operator) {
            '>', 'gt' => $left > $right,
            '>=', 'gte' => $left >= $right,
            '<', 'lt' => $left < $right,
            '<=', 'lte' => $left <= $right,
            '==', '=' => $left == $right,
            '===', 'eq' => $left === $right,
            '!=', '<>', 'neq' => $left != $right,
            default => false,
        };
    }

    /**
     * @param array<string,mixed>|string $links
     * @return array<int,int>
     */
    private function resolveLinks(array|string $links, array $collections, ?array $item): array
    {
        if (is_string($links) && $links !== '') {
            $links = ['collection' => $links];
        }

        if (!is_array($links)) {
            return [];
        }

        $collectionName = (string)($links['collection'] ?? '');
        $limit = max(0, (int)($links['limit'] ?? 0));

        if ($collectionName === 'item' && $item !== null) {
            $id = (int)($item['id'] ?? 0);
            return $id > 0 ? [$id] : [];
        }

        $rows = $collections[$collectionName] ?? [];
        $ids = [];
        foreach ($rows as $row) {
            $id = (int)($row['id'] ?? 0);
            if ($id > 0) {
                $ids[] = $id;
            }
        }

        $ids = array_values(array_unique($ids));
        if ($limit > 0) {
            $ids = array_slice($ids, 0, $limit);
        }

        return $ids;
    }

    /**
     * @return array<string,string|int|float>
     */
    private function rowToVariables(array $row): array
    {
        return [
            'id' => (int)($row['id'] ?? 0),
            'api' => $this->rowApi($row),
            'api_name' => $this->rowApiName($row),
            'risk_score' => $this->rowScore($row),
            'result_summary' => $this->rowSummary($row),
            'summary' => $this->rowSummary($row),
            'query_value' => $this->rowQueryValue($row),
            'query_type' => $this->rowQueryType($row),
            'enrichment_pass' => $this->rowEnrichmentPass($row),
            'enriched_from' => $this->rowEnrichedFrom($row),
            'source_ref' => $this->rowSourceRef($row),
            'status' => $this->rowStatus($row),
        ];
    }

    private function applyTemplate(string $template, array $vars): string
    {
        return (string)preg_replace_callback(
            '/\{\{\s*([a-z0-9_]+)\s*\}\}/i',
            static function (array $matches) use ($vars): string {
                $key = strtolower((string)($matches[1] ?? ''));
                $value = $vars[$key] ?? '';
                if (is_bool($value)) {
                    return $value ? '1' : '0';
                }
                if (is_scalar($value) || $value === null) {
                    return trim((string)($value ?? ''));
                }
                return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '';
            },
            $template
        );
    }

    /**
     * @param array<string,mixed> $rule
     * @param array<string,array<int,array<string,mixed>>> $collections
     * @return array<int,array<string,mixed>>
     */
    private function evaluateAggregatedLegacyRule(array $rule, array $collections, string $queryType, string $queryValue): array
    {
        $collectionName = (string)($rule['collection'] ?? 'results');
        $rows = $collections[$collectionName] ?? [];
        if ($rows === []) {
            return [];
        }

        $aggregation = is_array($rule['_aggregation'] ?? null) ? $rule['_aggregation'] : [];
        $analysis = is_array($rule['_analysis'] ?? null) ? $rule['_analysis'] : [];
        $groupField = trim((string)($aggregation['field'] ?? 'query_value'));
        $analysisMethod = strtolower(trim((string)($analysis['method'] ?? 'threshold')));
        $minimum = max(1, (int)($analysis['minimum'] ?? 1));

        $groups = [];
        foreach ($rows as $row) {
            $entity = $groupField !== '' ? $this->valueForField($row, $groupField) : $this->rowQueryValue($row);
            $entity = trim($entity) !== '' ? trim($entity) : $queryValue;
            if (!isset($groups[$entity])) {
                $groups[$entity] = [];
            }
            $groups[$entity][] = $row;
        }

        $findings = [];
        foreach ($groups as $entity => $groupRows) {
            $count = count($groupRows);
            $sourceCount = count(array_unique(array_map(fn(array $row): string => $this->rowApi($row), $groupRows)));
            $matches = match ($analysisMethod) {
                'first_collection_only' => true,
                'threshold', 'match_all_to_first_collection', 'outlier' => $count >= $minimum,
                default => $count >= $minimum,
            };

            if (!$matches) {
                continue;
            }

            $vars = [
                'query_type' => $queryType,
                'query_value' => $queryValue,
                'entity' => $entity,
                'count' => $count,
                'minimum' => $minimum,
                'source_count' => $sourceCount,
            ];

            $findings[] = [
                'rule_name' => (string)$rule['rule_name'],
                'severity' => (string)($rule['severity'] ?? 'info'),
                'title' => $this->applyTemplate((string)($rule['title'] ?? ''), $vars),
                'detail' => $this->applyTemplate((string)($rule['detail'] ?? ''), $vars),
                'linked_result_ids' => array_values(array_unique(array_filter(
                    array_map(static fn(array $row): int => (int)($row['id'] ?? 0), $groupRows),
                    static fn(int $id): bool => $id > 0
                ))),
            ];
        }

        return $findings;
    }

    private function valueForField(array $row, string $field): string
    {
        return match ($field) {
            'api', 'api_source' => $this->rowApi($row),
            'api_name' => $this->rowApiName($row),
            'risk_score', 'score' => (string)$this->rowScore($row),
            'result_summary', 'summary' => $this->rowSummary($row),
            'query_value' => $this->rowQueryValue($row),
            'query_type' => $this->rowQueryType($row),
            'enrichment_pass' => (string)$this->rowEnrichmentPass($row),
            'enriched_from' => $this->rowEnrichedFrom($row),
            'source_ref' => $this->rowSourceRef($row),
            'status' => $this->rowStatus($row),
            default => trim((string)($row[$field] ?? '')),
        };
    }

    private function rowApi(array $row): string
    {
        return trim((string)($row['api_source'] ?? $row['api'] ?? ''));
    }

    private function rowApiName(array $row): string
    {
        $name = trim((string)($row['api_name'] ?? ''));
        return $name !== '' ? $name : ($this->rowApi($row) ?: 'Unknown');
    }

    private function rowScore(array $row): float
    {
        return (float)($row['risk_score'] ?? $row['score'] ?? 0);
    }

    private function rowSummary(array $row): string
    {
        return trim((string)($row['result_summary'] ?? $row['summary'] ?? ''));
    }

    private function rowQueryValue(array $row): string
    {
        return trim((string)($row['query_value'] ?? ''));
    }

    private function rowQueryType(array $row): string
    {
        return trim((string)($row['query_type'] ?? ''));
    }

    private function rowEnrichmentPass(array $row): int
    {
        return (int)($row['enrichment_pass'] ?? 0);
    }

    private function rowEnrichedFrom(array $row): string
    {
        return trim((string)($row['enriched_from'] ?? ''));
    }

    private function rowSourceRef(array $row): string
    {
        return trim((string)($row['source_ref'] ?? ''));
    }

    /**
     * Backward-compatible replacement for PHP 8.1's array_is_list().
     */
    private function isListArray(array $array): bool
    {
        if (function_exists('array_is_list')) {
            return array_is_list($array);
        }

        $index = 0;
        foreach ($array as $key => $_value) {
            if ($key !== $index) {
                return false;
            }
            $index++;
        }

        return true;
    }

    private function rowStatus(array $row): string
    {
        $status = trim((string)($row['status'] ?? ''));
        if ($status !== '') {
            return $status;
        }
        return trim((string)($row['error'] ?? '')) !== '' ? 'failed' : 'completed';
    }

    private function rowSuccess(array $row): bool
    {
        if (array_key_exists('success', $row)) {
            return (bool)$row['success'];
        }
        return $this->rowStatus($row) !== 'failed';
    }
}
