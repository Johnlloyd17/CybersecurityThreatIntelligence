<?php
// =============================================================================
//  CTI - EVENT HASHER
//  php/EventHasher.php
//
//  Provides stable SpiderFoot-style event hashes so duplicate data elements
//  discovered through different paths can collapse into a single canonical
//  event while still keeping parent/child relationship records.
// =============================================================================

require_once __DIR__ . '/EventTypes.php';

class EventHasher
{
    /**
     * Produce a stable hash for an event type + data pair.
     */
    public static function hash(string $eventType, string $data): string
    {
        $normalizedType = strtolower(trim($eventType));
        $normalizedData = self::normalizeData($eventType, $data);
        return hash('sha256', $normalizedType . '|' . $normalizedData);
    }

    /**
     * Normalize event data according to the practical semantics of the type.
     */
    public static function normalizeData(string $eventType, string $data): string
    {
        $value = trim((string)$data);
        $value = preg_replace('/\s+/', ' ', $value) ?? $value;

        if ($value === '') {
            return '';
        }

        $lowercaseTypes = [
            EventTypes::ROOT,
            EventTypes::IP_ADDRESS,
            EventTypes::IPV6_ADDRESS,
            EventTypes::INTERNET_NAME,
            EventTypes::DOMAIN_NAME,
            EventTypes::EMAILADDR,
            EventTypes::USERNAME,
            EventTypes::HASH,
            EventTypes::CO_HOSTED_SITE,
            EventTypes::CO_HOSTED_SITE_DOMAIN,
            EventTypes::AFFILIATE_INTERNET_NAME,
            EventTypes::AFFILIATE_IPADDR,
            EventTypes::AFFILIATE_DOMAIN_NAME,
            EventTypes::MALICIOUS_IPADDR,
            EventTypes::MALICIOUS_INTERNET_NAME,
            EventTypes::MALICIOUS_AFFILIATE_IPADDR,
            EventTypes::BLACKLISTED_IPADDR,
            EventTypes::BLACKLISTED_INTERNET_NAME,
        ];

        if (in_array($eventType, $lowercaseTypes, true)) {
            return strtolower($value);
        }

        if ($eventType === EventTypes::LINKED_URL_EXTERNAL
            || $eventType === EventTypes::URL_FORM
            || $eventType === EventTypes::URL_PASSWORD) {
            return self::normalizeUrl($value);
        }

        return $value;
    }

    private static function normalizeUrl(string $value): string
    {
        $parts = @parse_url($value);
        if (!is_array($parts) || $parts === []) {
            return trim($value);
        }

        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = strtolower((string)($parts['host'] ?? ''));
        $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
        $path = (string)($parts['path'] ?? '');
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';
        $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';
        $user = (string)($parts['user'] ?? '');
        $pass = isset($parts['pass']) ? ':' . $parts['pass'] : '';
        $auth = $user !== '' ? $user . $pass . '@' : '';

        return ($scheme !== '' ? $scheme . '://' : '')
            . $auth
            . $host
            . $port
            . $path
            . $query
            . $fragment;
    }
}
