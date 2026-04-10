<?php
// =============================================================================
//  CTI — EVENT TYPES TAXONOMY
//  php/EventTypes.php
//
//  SpiderFoot-style data element type registry.
//  Each module result carries a data_type from this taxonomy, enabling:
//    - Event-driven enrichment routing (multi-pass scan loops)
//    - Consistent Browse-tab grouping in the UI
//    - Cross-module correlation by type
//
//  Based on SpiderFoot's tbl_event_types (200+ types).
//  We keep a practical subset that our modules actually produce/consume.
// =============================================================================

class EventTypes
{
    // ── Core Target Types (scan seeds) ──────────────────────────────────────
    const IP_ADDRESS          = 'IP Address';
    const IPV6_ADDRESS        = 'IPv6 Address';
    const INTERNET_NAME       = 'Internet Name';           // hostname / FQDN
    const DOMAIN_NAME         = 'Domain Name';             // registrable domain
    const EMAILADDR           = 'Email Address';
    const PHONE_NUMBER        = 'Phone Number';
    const HUMAN_NAME          = 'Human Name';
    const USERNAME            = 'Username';
    const BITCOIN_ADDRESS     = 'Bitcoin Address';
    const HASH                = 'Hash';                    // MD5 / SHA1 / SHA256

    // ── DNS / Network ──────────────────────────────────────────────────────
    const DNS_TEXT_RECORD     = 'DNS TXT Record';
    const DNS_MX_RECORD       = 'Email Gateway (DNS MX Records)';
    const DNS_NS_RECORD       = 'Name Server (DNS NS Records)';
    const DNS_A_RECORD        = 'DNS A Record';
    const DNS_AAAA_RECORD     = 'DNS AAAA Record';
    const DNS_CNAME_RECORD    = 'DNS CNAME Record';
    const DNS_SOA_RECORD      = 'DNS SOA Record';
    const RAW_DNS_RECORDS     = 'Raw DNS Records';
    const NETBLOCK_OWNER      = 'Netblock Ownership';
    const NETBLOCK_MEMBER     = 'Netblock Membership';
    const BGP_AS_OWNER        = 'BGP AS Ownership';

    // ── Infrastructure ─────────────────────────────────────────────────────
    const OPEN_TCP_PORT       = 'Open TCP Port';
    const OPEN_TCP_PORT_BANNER = 'Open TCP Port Banner';
    const OPERATING_SYSTEM    = 'Operating System';
    const DEVICE_TYPE         = 'Device Type';
    const SOFTWARE_USED       = 'Software Used';
    const HTTP_HEADERS        = 'HTTP Headers';
    const WEB_TECHNOLOGY      = 'Web Technology';

    // ── SSL / Certificates ─────────────────────────────────────────────────
    const SSL_CERTIFICATE_RAW      = 'SSL Certificate - Raw Data';
    const SSL_CERTIFICATE_ISSUED   = 'SSL Certificate - Issued to';
    const SSL_CERTIFICATE_ISSUER   = 'SSL Certificate - Issued by';
    const SSL_CERTIFICATE_EXPIRED  = 'SSL Certificate Expired';
    const SSL_CERTIFICATE_EXPIRING = 'SSL Certificate Expiring';
    const SSL_CERTIFICATE_MISMATCH = 'SSL Certificate Host Mismatch';

    // ── Co-Hosting / Affiliates ────────────────────────────────────────────
    const CO_HOSTED_SITE           = 'Co-Hosted Site';
    const CO_HOSTED_SITE_DOMAIN    = 'Co-Hosted Site - Domain Name';
    const AFFILIATE_INTERNET_NAME  = 'Affiliate - Internet Name';
    const AFFILIATE_IPADDR         = 'Affiliate - IP Address';
    const AFFILIATE_DOMAIN_NAME    = 'Affiliate - Domain Name';

    // ── Threat / Malicious ─────────────────────────────────────────────────
    const MALICIOUS_IPADDR             = 'Malicious IP Address';
    const MALICIOUS_INTERNET_NAME      = 'Malicious Internet Name';
    const MALICIOUS_AFFILIATE_IPADDR   = 'Malicious Affiliate IP Address';
    const MALICIOUS_COHOST             = 'Malicious Co-Hosted Site';
    const MALICIOUS_NETBLOCK           = 'Malicious Netblock';
    const MALICIOUS_SUBNET             = 'Malicious Subnet';
    const BLACKLISTED_IPADDR           = 'Blacklisted IP Address';
    const BLACKLISTED_INTERNET_NAME    = 'Blacklisted Internet Name';
    const BLACKLISTED_AFFILIATE_IPADDR = 'Blacklisted Affiliate IP Address';

    // ── Vulnerability / CVE ────────────────────────────────────────────────
    const VULNERABILITY        = 'Vulnerability';           // CVE reference
    const RAW_RIR_DATA         = 'Raw Data from RIRs/APIs';

    // ── Identity / Leaks ───────────────────────────────────────────────────
    const HACKED_EMAIL_ADDRESS = 'Hacked Email Address';
    const COMPROMISED_PASSWORD = 'Compromised Password';
    const SOCIAL_MEDIA         = 'Social Media Presence';
    const ACCOUNT_EXTERNAL     = 'Account on External Site';
    const LEAKED_DATA          = 'Leak Site Content';

    // ── Geolocation ────────────────────────────────────────────────────────
    const COUNTRY_NAME         = 'Country Name';
    const PHYSICAL_ADDRESS     = 'Physical Address';
    const GEOINFO              = 'Physical Coordinates';

    // ── Organization ───────────────────────────────────────────────────────
    const COMPANY_NAME         = 'Company Name';
    const PROVIDER_HOSTING     = 'Hosting Provider';
    const PROVIDER_TELECOM     = 'Telecommunications Provider';
    const DOMAIN_REGISTRAR     = 'Domain Registrar';
    const DOMAIN_WHOIS         = 'Domain Whois';

    // ── Misc / Search ──────────────────────────────────────────────────────
    const SEARCH_ENGINE_WEB_CONTENT = 'Search Engine Web Content';
    const LINKED_URL_EXTERNAL       = 'Linked URL - External';
    const INTERESTING_FILE          = 'Interesting File';
    const DARKNET_MENTION           = 'Darknet Mention URL';
    const TOR_EXIT_NODE             = 'TOR Exit Node';
    const URL_FORM                  = 'URL (Form)';
    const URL_PASSWORD              = 'URL (Accepts Passwords)';
    const BITCOIN_BALANCE           = 'Bitcoin Balance';
    const ETHEREUM_ADDRESS          = 'Ethereum Address';

    // ── Internal ───────────────────────────────────────────────────────────
    const ROOT                 = 'ROOT';                   // initial seed event

    // =========================================================================
    //  ENRICHMENT ROUTING MAP
    //
    //  Maps event types to the query_type string used by modules.
    //  When enrichment discovers an IP_ADDRESS element, we know to re-query
    //  modules with query_type='ip' to cascade discovery.
    // =========================================================================

    private static array $typeToQueryType = [
        self::IP_ADDRESS             => 'ip',
        self::IPV6_ADDRESS           => 'ip',
        self::INTERNET_NAME          => 'domain',
        self::DOMAIN_NAME            => 'domain',
        self::EMAILADDR              => 'email',
        self::HASH                   => 'hash',
        self::VULNERABILITY          => 'cve',
        self::USERNAME               => 'username',
        self::PHONE_NUMBER           => 'phone',
        self::BITCOIN_ADDRESS        => 'bitcoin',
        self::CO_HOSTED_SITE         => 'domain',
        self::CO_HOSTED_SITE_DOMAIN  => 'domain',
        self::AFFILIATE_INTERNET_NAME => 'domain',
        self::AFFILIATE_IPADDR       => 'ip',
        self::AFFILIATE_DOMAIN_NAME  => 'domain',
        self::MALICIOUS_IPADDR       => 'ip',
        self::MALICIOUS_INTERNET_NAME => 'domain',
    ];

    /**
     * Get the query_type for a given event type.
     * Returns null if the event type is not routable (e.g. informational).
     */
    public static function toQueryType(string $eventType): ?string
    {
        return self::$typeToQueryType[$eventType] ?? null;
    }

    /**
     * Check whether an event type is enrichable (can seed a new query pass).
     */
    public static function isEnrichable(string $eventType): bool
    {
        return isset(self::$typeToQueryType[$eventType]);
    }

    /**
     * Map of query_type → primary event types that match it.
     * Used by modules to declare which event types they can consume.
     */
    public static function queryTypeToEventTypes(string $queryType): array
    {
        return match ($queryType) {
            'ip'       => [self::IP_ADDRESS, self::IPV6_ADDRESS, self::AFFILIATE_IPADDR, self::MALICIOUS_IPADDR],
            'domain'   => [self::INTERNET_NAME, self::DOMAIN_NAME, self::CO_HOSTED_SITE, self::CO_HOSTED_SITE_DOMAIN, self::AFFILIATE_INTERNET_NAME, self::AFFILIATE_DOMAIN_NAME, self::MALICIOUS_INTERNET_NAME],
            'email'    => [self::EMAILADDR, self::HACKED_EMAIL_ADDRESS],
            'hash'     => [self::HASH],
            'url'      => [self::LINKED_URL_EXTERNAL, self::URL_FORM, self::URL_PASSWORD],
            'cve'      => [self::VULNERABILITY],
            'username' => [self::USERNAME],
            'phone'    => [self::PHONE_NUMBER],
            'bitcoin'  => [self::BITCOIN_ADDRESS],
            default    => [],
        };
    }

    /**
     * All defined event types for Browse tab grouping.
     */
    public static function all(): array
    {
        $ref = new \ReflectionClass(self::class);
        $types = [];
        foreach ($ref->getConstants() as $name => $value) {
            if ($name === 'ROOT') continue;
            if (is_string($value)) $types[] = $value;
        }
        return array_unique($types);
    }
}
