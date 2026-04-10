<?php
// =============================================================================
//  CTI — MODULE SETTINGS SCHEMA
//  php/ModuleSettingsSchema.php
//
//  Static class that defines the settings schema for each module/platform
//  component. Each setting has: key, label, type, default, description.
//
//  Supported types: text, number, boolean, url
// =============================================================================

require_once __DIR__ . '/SpiderFootSettingsCatalog.php';

class ModuleSettingsSchema
{
    // =========================================================================
    //  SCHEMA DEFINITIONS
    // =========================================================================

    private static array $schemas = [];
    private static bool  $initialized = false;

    /**
     * Lazy-initialize all schemas once.
     */
    private static function init(): void
    {
        if (self::$initialized) {
            return;
        }
        self::$initialized = true;

        // ── _global (Platform Global Settings) ──────────────────────────────
        self::$schemas['_global'] = [
            [
                'key'         => 'debug',
                'label'       => 'Debug',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Enable debugging?',
            ],
            [
                'key'         => 'dns_resolver',
                'label'       => 'DNS Resolver',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Override the default resolver with another DNS server. For example, 8.8.8.8 is Google\'s open DNS server.',
            ],
            [
                'key'         => 'http_timeout',
                'label'       => 'HTTP Timeout',
                'type'        => 'number',
                'default'     => 15,
                'description' => 'Number of seconds before giving up on a HTTP request.',
            ],
            [
                'key'         => 'generic_usernames',
                'label'       => 'Generic Usernames',
                'type'        => 'text',
                'default'     => 'abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,',
                'description' => 'List of usernames that if found as usernames or as part of e-mail addresses, should be treated differently to non-generics.',
            ],
            [
                'key'         => 'tld_list_url',
                'label'       => 'TLD List URL',
                'type'        => 'url',
                'default'     => 'https://publicsuffix.org/list/effective_tld_names.dat',
                'description' => 'List of Internet TLDs.',
            ],
            [
                'key'         => 'tld_cache_hours',
                'label'       => 'TLD Cache Hours',
                'type'        => 'number',
                'default'     => 72,
                'description' => 'Hours to cache the Internet TLD list. This can safely be quite a long time given that the list doesn\'t change too often.',
            ],
            [
                'key'         => 'max_concurrent_modules',
                'label'       => 'Max Concurrent Modules',
                'type'        => 'number',
                'default'     => 3,
                'description' => 'Max number of modules to run concurrently',
            ],
            [
                'key'         => 'socks_type',
                'label'       => 'SOCKS Type',
                'type'        => 'text',
                'default'     => '',
                'description' => 'SOCKS Server Type. Can be \'4\', \'5\', \'HTTP\' or \'TOR\'',
            ],
            [
                'key'         => 'socks_host',
                'label'       => 'SOCKS Host',
                'type'        => 'text',
                'default'     => '',
                'description' => 'SOCKS Server IP Address.',
            ],
            [
                'key'         => 'socks_port',
                'label'       => 'SOCKS Port',
                'type'        => 'text',
                'default'     => '',
                'description' => 'SOCKS Server TCP Port. Usually 1080 for 4/5, 8080 for HTTP and 9050 for TOR.',
            ],
            [
                'key'         => 'socks_username',
                'label'       => 'SOCKS Username',
                'type'        => 'text',
                'default'     => '',
                'description' => 'SOCKS Username. Valid only for SOCKS4 and SOCKS5 servers.',
            ],
            [
                'key'         => 'socks_password',
                'label'       => 'SOCKS Password',
                'type'        => 'text',
                'default'     => '',
                'description' => 'SOCKS Password. Valid only for SOCKS5 servers.',
            ],
            [
                'key'         => 'user_agent',
                'label'       => 'User-Agent',
                'type'        => 'text',
                'default'     => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
                'description' => 'User-Agent string to use for HTTP requests. Prefix with an \'@\' to randomly select the User Agent from a file containing user agent strings for each request, e.g. @C:\\useragents.txt or @/home/bob/useragents.txt. Or supply a URL to load the list from there.',
            ],
        ];

        // ── _storage (Platform Storage Settings) ────────────────────────────
        self::$schemas['_storage'] = [
            [
                'key'         => 'max_bytes_per_element',
                'label'       => 'Max Bytes Per Element',
                'type'        => 'number',
                'default'     => 1024,
                'description' => 'Maximum bytes to store for any piece of information retrieved (0 = unlimited).',
            ],
        ];

        // ── abstractapi ─────────────────────────────────────────────────────
        self::$schemas['abstractapi'] = [
            [
                'key'         => 'api_key_company',
                'label'       => 'Company Enrichment API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'AbstractAPI Company Enrichment API key.',
            ],
            [
                'key'         => 'api_key_ip_geolocation',
                'label'       => 'IP Geolocation API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'AbstractAPI IP Geolocation API key.',
            ],
            [
                'key'         => 'api_key_phone_validation',
                'label'       => 'Phone Validation API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'AbstractAPI Phone Validation API key.',
            ],
        ];

        // ── abuse-ch ────────────────────────────────────────────────────────
        self::$schemas['abuse-ch'] = [
            [
                'key'         => 'check_feodo_ip',
                'label'       => 'Check Feodo IP',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Enable abuse.ch Feodo IP check?',
            ],
            [
                'key'         => 'check_ssl_blacklist',
                'label'       => 'Check SSL Blacklist',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Enable abuse.ch SSL Blacklist IP check?',
            ],
            [
                'key'         => 'check_urlhaus',
                'label'       => 'Check URLhaus',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Enable abuse.ch URLhaus check?',
            ],
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
        ];

        // ── abuseipdb ───────────────────────────────────────────────────────
        self::$schemas['abuseipdb'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'min_confidence',
                'label'       => 'Minimum Confidence',
                'type'        => 'number',
                'default'     => 90,
                'description' => 'The minimum AbuseIPDB confidence level to require.',
            ],
            [
                'key'         => 'max_results',
                'label'       => 'Maximum Results',
                'type'        => 'number',
                'default'     => 10000,
                'description' => 'Maximum number of results to retrieve.',
            ],
        ];

        // ── abusix ──────────────────────────────────────────────────────────
        self::$schemas['abusix'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
            [
                'key'         => 'max_netblock_size_ipv4',
                'label'       => 'Max Netblock Size (IPv4)',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_size_ipv4',
                'label'       => 'Max Subnet Size (IPv4)',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum IPv4 subnet size to look up all IPs within.',
            ],
            [
                'key'         => 'max_netblock_size_ipv6',
                'label'       => 'Max Netblock Size (IPv6)',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up owned netblocks, the maximum IPv6 netblock size.',
            ],
            [
                'key'         => 'max_subnet_size_ipv6',
                'label'       => 'Max Subnet Size (IPv6)',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up subnets, the maximum IPv6 subnet size.',
            ],
            [
                'key'         => 'lookup_netblocks',
                'label'       => 'Lookup Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'lookup_subnets',
                'label'       => 'Lookup Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on subnets which your target is a part of for blacklisting?',
            ],
        ];

        // ── account-finder ──────────────────────────────────────────────────
        self::$schemas['account-finder'] = [
            [
                'key'         => 'skip_first_names',
                'label'       => 'Skip First Names',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Don\'t bother looking up names that are just stand-alone first names (too many false positives).',
            ],
            [
                'key'         => 'skip_dictionary',
                'label'       => 'Skip Dictionary Words',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Don\'t bother looking up names that appear in the dictionary.',
            ],
            [
                'key'         => 'require_username_mention',
                'label'       => 'Require Username Mention',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'The username must be mentioned on the social media page to consider it valid (helps avoid false positives).',
            ],
            [
                'key'         => 'check_permutations',
                'label'       => 'Check Permutations',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Look for the existence of account name permutations. Useful to identify fraudulent social media accounts or account squatting.',
            ],
            [
                'key'         => 'extract_emails',
                'label'       => 'Extract Emails',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Extract usernames from e-mail addresses at all? If disabled this can reduce false positives for common usernames but for highly unique usernames it would result in missed accounts.',
            ],
        ];

        // ── adblock-check ───────────────────────────────────────────────────
        self::$schemas['adblock-check'] = [
            [
                'key'         => 'blocklist_url',
                'label'       => 'Blocklist URL',
                'type'        => 'url',
                'default'     => 'https://easylist-downloads.adblockplus.org/easylist.txt',
                'description' => 'AdBlockPlus block list.',
            ],
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
        ];

        // ── ahmia ───────────────────────────────────────────────────────────
        self::$schemas['ahmia'] = [
            [
                'key'         => 'fetch_darknet_pages',
                'label'       => 'Fetch Darknet Pages',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.',
            ],
            [
                'key'         => 'search_human_names',
                'label'       => 'Search Human Names',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Search for human names?',
            ],
        ];

        // ── alienvault-ip-rep ──────────────────────────────────────────────
        self::$schemas['alienvault-ip-rep'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'report_netblocks',
                'label'       => 'Report Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Report if any malicious IPs are found within owned netblocks?',
            ],
            [
                'key'         => 'check_subnet',
                'label'       => 'Check Subnet',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check if any malicious IPs are found within the same subnet of the target?',
            ],
        ];

        // ── alienvault ──────────────────────────────────────────────────────
        self::$schemas['alienvault'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'cohost_age_limit',
                'label'       => 'Co-host Age Limit (days)',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Ignore any co-hosts older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'max_url_pages',
                'label'       => 'Max URL Pages',
                'type'        => 'number',
                'default'     => 50,
                'description' => 'Maximum number of pages of URL results to fetch.',
            ],
            [
                'key'         => 'cohost_stop_count',
                'label'       => 'Co-host Stop Count',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'max_netblock_size_ipv4',
                'label'       => 'Max Netblock Size (IPv4)',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_size_ipv4',
                'label'       => 'Max Subnet Size (IPv4)',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum IPv4 subnet size to look up all IPs within.',
            ],
            [
                'key'         => 'max_netblock_size_ipv6',
                'label'       => 'Max Netblock Size (IPv6)',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up owned netblocks, the maximum IPv6 netblock size.',
            ],
            [
                'key'         => 'max_subnet_size_ipv6',
                'label'       => 'Max Subnet Size (IPv6)',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up subnets, the maximum IPv6 subnet size.',
            ],
            [
                'key'         => 'lookup_netblocks',
                'label'       => 'Lookup Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts?',
            ],
            [
                'key'         => 'reputation_age_limit',
                'label'       => 'Reputation Age Limit (days)',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Ignore any reputation records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'min_threat_score',
                'label'       => 'Minimum Threat Score',
                'type'        => 'number',
                'default'     => 2,
                'description' => 'Minimum AlienVault threat score.',
            ],
            [
                'key'         => 'lookup_subnets',
                'label'       => 'Lookup Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on subnets which your target is a part of for blacklisting?',
            ],
            [
                'key'         => 'verify_cohosts',
                'label'       => 'Verify Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify co-hosts are valid by checking if they still resolve to the shared IP.',
            ],
        ];
        // ── apivoid ──────────────────────────────────────────────────────
        self::$schemas['apivoid'] = [
            [
                'key'         => 'check_ip_reputation',
                'label'       => 'Check IP Reputation',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Query the IP Reputation endpoint to check against 40+ blacklist engines.',
            ],
            [
                'key'         => 'check_domain_reputation',
                'label'       => 'Check Domain Reputation',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Query the Domain Reputation endpoint to check domains against blacklist engines.',
            ],
            [
                'key'         => 'check_url_reputation',
                'label'       => 'Check URL Reputation',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Query the URL Reputation endpoint for malware, phishing, and suspicious content detection.',
            ],
            [
                'key'         => 'check_email_verify',
                'label'       => 'Verify Email Addresses',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Validate email addresses and check for disposable/free providers.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates of the target?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
            [
                'key'         => 'min_blacklist_detections',
                'label'       => 'Min Blacklist Detections',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Minimum number of blacklist engine detections before considering a result as malicious.',
            ],
            [
                'key'         => 'request_timeout',
                'label'       => 'Request Timeout',
                'type'        => 'number',
                'default'     => 15,
                'description' => 'Timeout in seconds for each APIVoid API request.',
            ],
        ];
        // ── archive-org ────────────────────────────────────────────────────
        self::$schemas['archive-org'] = [
            [
                'key'         => 'days_back',
                'label'       => 'Days Back',
                'type'        => 'text',
                'default'     => '30,60,90',
                'description' => 'Number of days back to look for older versions of files/pages in the Wayback Machine snapshots. Comma-separate the values, so for example 30,60,90 means to look for snapshots 30 days, 60 days and 90 days back.',
            ],
            [
                'key'         => 'fetch_flash',
                'label'       => 'Fetch Flash URLs',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs containing Flash.',
            ],
            [
                'key'         => 'fetch_forms',
                'label'       => 'Fetch Form URLs',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs with forms.',
            ],
            [
                'key'         => 'fetch_interesting_files',
                'label'       => 'Fetch Interesting Files',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Query the Wayback Machine for historic versions of Interesting Files.',
            ],
            [
                'key'         => 'fetch_java_applets',
                'label'       => 'Fetch Java Applets',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs using Java Applets.',
            ],
            [
                'key'         => 'fetch_javascript',
                'label'       => 'Fetch Javascript',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs using Javascript.',
            ],
            [
                'key'         => 'fetch_passwords',
                'label'       => 'Fetch Password URLs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Query the Wayback Machine for historic versions of URLs with passwords.',
            ],
            [
                'key'         => 'fetch_static',
                'label'       => 'Fetch Static URLs',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of purely static URLs.',
            ],
            [
                'key'         => 'fetch_uploads',
                'label'       => 'Fetch Upload URLs',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs accepting uploads.',
            ],
            [
                'key'         => 'fetch_js_frameworks',
                'label'       => 'Fetch JS Framework URLs',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Query the Wayback Machine for historic versions of URLs using Javascript frameworks.',
            ],
        ];

        // ── azure-blob-finder ──────────────────────────────────────────────
        self::$schemas['azure-blob-finder'] = [
            [
                'key'         => 'suffixes',
                'label'       => 'Blob Name Suffixes',
                'type'        => 'text',
                'default'     => 'test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,storage,backup,site,assets,images,docs,public,private,archive,cdn,static,uploads,downloads',
                'description' => 'List of suffixes to append to domains tried as blob storage names.',
            ],
        ];

        // ── bad-packets ────────────────────────────────────────────────────
        self::$schemas['bad-packets'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Bad Packets API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Bad Packets API key.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check affiliates?',
            ],
            [
                'key'         => 'max_netblock_size',
                'label'       => 'Max Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_size',
                'label'       => 'Max Subnet Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblocks',
                'label'       => 'Lookup Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'lookup_subnets',
                'label'       => 'Lookup Subnets',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Look up all IPs on subnets which your target is a part of?',
            ],
        ];

        // ── base64-decoder ─────────────────────────────────────────────────
        self::$schemas['base64-decoder'] = [
            [
                'key'         => 'min_length',
                'label'       => 'Minimum Length',
                'type'        => 'number',
                'default'     => 10,
                'description' => 'The minimum length a string that looks like a base64-encoded string needs to be.',
            ],
        ];

        // ── binaryedge ────────────────────────────────────────────────────
        self::$schemas['binaryedge'] = [
            [
                'key'         => 'api_key',
                'label'       => 'BinaryEdge.io API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'BinaryEdge.io API Key.',
            ],
            [
                'key'         => 'vulnerability_age_limit',
                'label'       => 'Vulnerability Age Limit',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Ignore any vulnerability records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'cohost_stop_count',
                'label'       => 'Co-host Stop Count',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'max_netblock_size',
                'label'       => 'Max Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Max Pages',
                'type'        => 'number',
                'default'     => 10,
                'description' => 'Maximum number of pages to iterate through, to avoid exceeding BinaryEdge API usage limits. APIv2 has a maximum of 500 pages (10,000 results).',
            ],
            [
                'key'         => 'max_subnet_size',
                'label'       => 'Max Subnet Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblocks',
                'label'       => 'Lookup Netblocks',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'open_ports_age_limit',
                'label'       => 'Open Ports Age Limit',
                'type'        => 'number',
                'default'     => 90,
                'description' => 'Ignore any discovered open ports/banners older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'lookup_subnets',
                'label'       => 'Lookup Subnets',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Look up all IPs on subnets which your target is a part of?',
            ],
            [
                'key'         => 'torrent_age_limit',
                'label'       => 'Torrent Age Limit',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Ignore any torrent records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'verify_cohosts',
                'label'       => 'Verify Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify that any hostnames found on the target domain still resolve?',
            ],
        ];

        // ── bing ───────────────────────────────────────────────────────────
        self::$schemas['bing'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Bing API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Bing API Key for Bing search.',
            ],
            [
                'key'         => 'max_results',
                'label'       => 'Max Results',
                'type'        => 'number',
                'default'     => 20,
                'description' => 'Number of max bing results to request from the API.',
            ],
        ];

        // ── bing-shared-ips ────────────────────────────────────────────────
        self::$schemas['bing-shared-ips'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Bing API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Bing API Key for shared IP search.',
            ],
            [
                'key'         => 'cohosts_same_domain',
                'label'       => 'Co-hosts Same Domain',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Treat co-hosted sites on the same target domain as co-hosting?',
            ],
            [
                'key'         => 'cohost_stop_count',
                'label'       => 'Co-host Stop Count',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'max_results',
                'label'       => 'Max Results',
                'type'        => 'number',
                'default'     => 20,
                'description' => 'Number of max bing results to request from API.',
            ],
            [
                'key'         => 'verify_cohosts',
                'label'       => 'Verify Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify co-hosts are valid by checking if they still resolve to the shared IP.',
            ],
        ];

        // ── binary-string-extractor ────────────────────────────────────────
        self::$schemas['binary-string-extractor'] = [
            [
                'key'         => 'file_types',
                'label'       => 'File Types',
                'type'        => 'text',
                'default'     => 'png,gif,jpg,jpeg,tiff,tif,ico,flv,mp4,mp3,avi,mpg,mpeg,dat,mov,swf,exe,bin',
                'description' => 'File types to fetch and analyse.',
            ],
            [
                'key'         => 'ignore_characters',
                'label'       => 'Ignore Characters',
                'type'        => 'text',
                'default'     => '#}|{%^&*()=+,;[]~',
                'description' => 'Ignore strings with these characters, as they may just be garbage ASCII.',
            ],
            [
                'key'         => 'max_file_size',
                'label'       => 'Max File Size',
                'type'        => 'number',
                'default'     => 1000000,
                'description' => 'Maximum file size in bytes to download for analysis.',
            ],
            [
                'key'         => 'max_strings',
                'label'       => 'Max Strings',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting strings from a single binary after this many are found.',
            ],
            [
                'key'         => 'min_string_length',
                'label'       => 'Min String Length',
                'type'        => 'number',
                'default'     => 5,
                'description' => 'Upon finding a string in a binary, ensure it is at least this length. Helps weed out false positives.',
            ],
            [
                'key'         => 'use_dictionary',
                'label'       => 'Use Dictionary',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Use the dictionary to further reduce false positives - any string found must contain a word from the dictionary (can be very slow, especially for larger files).',
            ],
        ];

        // =================================================================
        //  PLACEHOLDER MODULES (161) — settings to be populated later
        // =================================================================
        // ── bitcoin-whos-who ───────────────────────────────────────────
        self::$schemas['bitcoin-whos-who'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Bitcoin Who\'s Who API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Bitcoin Who\'s Who API Key.',
            ],
        ];

        // ── bitcoinabuse ──────────────────────────────────────────────────
        self::$schemas['bitcoinabuse'] = [
            [
                'key'         => 'api_key',
                'label'       => 'BitcoinAbuse API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'BitcoinAbuse API Key.',
            ],
        ];

        // ── blocklist-de ──────────────────────────────────────────────────
        self::$schemas['blocklist-de'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_netblocks',
                'label'       => 'Check Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Report if any malicious IPs are found within owned netblocks?',
            ],
            [
                'key'         => 'check_subnets',
                'label'       => 'Check Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check if any malicious IPs are found within the same subnet of the target?',
            ],
        ];

        // ── botscout ──────────────────────────────────────────────────────
        self::$schemas['botscout'] = [
            [
                'key'         => 'api_key',
                'label'       => 'BotScout API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Botscout.com API key. Without this you will be limited to 100 look-ups per day.',
            ],
        ];

        // ── botvrij ───────────────────────────────────────────────────────
        self::$schemas['botvrij'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
        ];

        // ── builtwith ─────────────────────────────────────────────────────
        self::$schemas['builtwith'] = [
            [
                'key'         => 'api_key',
                'label'       => 'BuiltWith Domain API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Builtwith.com Domain API key.',
            ],
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'The maximum age of the data returned, in days, in order to be considered valid.',
            ],
        ];
        // ── c99 ───────────────────────────────────────────────────────────
        self::$schemas['c99'] = [
            [
                'key'         => 'api_key',
                'label'       => 'C99 API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'C99 API Key.',
            ],
            [
                'key'         => 'cohost_same_domain',
                'label'       => 'Co-host Same Domain',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Treat co-hosted sites on the same target domain as co-hosting?',
            ],
            [
                'key'         => 'max_cohosts',
                'label'       => 'Max Co-hosts',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'verify_domains_resolve',
                'label'       => 'Verify Domains Resolve',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify identified domains still resolve to the associated specified IP address.',
            ],
        ];

        // ── censys ────────────────────────────────────────────────────────
        self::$schemas['censys'] = [
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 90,
                'description' => 'Ignore any records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'api_secret',
                'label'       => 'Censys.io API Secret',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Censys.io API Secret.',
            ],
            [
                'key'         => 'api_uid',
                'label'       => 'Censys.io API UID',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Censys.io API UID.',
            ],
            [
                'key'         => 'request_delay',
                'label'       => 'Request Delay',
                'type'        => 'number',
                'default'     => 3,
                'description' => 'Delay between requests, in seconds.',
            ],
            [
                'key'         => 'max_netblock_size',
                'label'       => 'Max Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblocks',
                'label'       => 'Lookup Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
        ];

        // ── certspotter ───────────────────────────────────────────────────
        self::$schemas['certspotter'] = [
            [
                'key'         => 'api_key',
                'label'       => 'CertSpotter API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'CertSpotter API key.',
            ],
            [
                'key'         => 'cert_expiry_days',
                'label'       => 'Certificate Expiry Days',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Number of days in the future a certificate expires to consider it as expiring.',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Maximum Pages',
                'type'        => 'number',
                'default'     => 20,
                'description' => 'Maximum number of pages of results to fetch.',
            ],
            [
                'key'         => 'verify_alt_names',
                'label'       => 'Verify Alt Names',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify certificate subject alternative names resolve.',
            ],
        ];

        // ── chaos (ProjectDiscovery Chaos) ────────────────────────────────
        self::$schemas['chaos'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Chaos API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'ProjectDiscovery Chaos API key.',
            ],
        ];

        // ── cins-army ─────────────────────────────────────────────────────
        self::$schemas['cins-army'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_netblocks',
                'label'       => 'Check Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Report if any malicious IPs are found within owned netblocks?',
            ],
            [
                'key'         => 'check_subnets',
                'label'       => 'Check Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check if any malicious IPs are found within the same subnet of the target?',
            ],
        ];

        // ── circl-lu ──────────────────────────────────────────────────────
        self::$schemas['circl-lu'] = [
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 0,
                'description' => 'Ignore any Passive DNS records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'login',
                'label'       => 'CIRCL.LU Login',
                'type'        => 'text',
                'default'     => '',
                'description' => 'CIRCL.LU login.',
            ],
            [
                'key'         => 'password',
                'label'       => 'CIRCL.LU Password',
                'type'        => 'text',
                'default'     => '',
                'description' => 'CIRCL.LU password.',
            ],
            [
                'key'         => 'cohost_same_domain',
                'label'       => 'Co-host Same Domain',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Treat co-hosted sites on the same target domain as co-hosting?',
            ],
            [
                'key'         => 'max_cohosts',
                'label'       => 'Max Co-hosts',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'verify_cohosts_resolve',
                'label'       => 'Verify Co-hosts Resolve',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify co-hosts are valid by checking if they still resolve to the shared IP.',
            ],
        ];
        // ── cleantalk ─────────────────────────────────────────────────────
        self::$schemas['cleantalk'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliate IP addresses?',
            ],
            [
                'key'         => 'check_netblocks',
                'label'       => 'Check Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Report if any malicious IPs are found within owned netblocks?',
            ],
            [
                'key'         => 'check_subnets',
                'label'       => 'Check Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check if any malicious IPs are found within the same subnet of the target?',
            ],
        ];

        // ── clearbit ──────────────────────────────────────────────────────
        self::$schemas['clearbit'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Clearbit API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Clearbit.com API key.',
            ],
        ];

        // ── cmseek (Tool - CMSeeK) ────────────────────────────────────────
        self::$schemas['cmseek'] = [
            [
                'key'         => 'cmseek_path',
                'label'       => 'CMSeeK Path',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Path to the where the CMSeeK file lives. Optional.',
            ],
            [
                'key'         => 'python_path',
                'label'       => 'Python Path',
                'type'        => 'text',
                'default'     => 'python',
                'description' => 'Path to Python interpreter to use for CMSeeK. If just \'python\' then it must be in your PATH.',
            ],
        ];

        // ── coinblocker ───────────────────────────────────────────────────
        self::$schemas['coinblocker'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
        ];

        // ── commoncrawl ───────────────────────────────────────────────────
        self::$schemas['commoncrawl'] = [
            [
                'key'         => 'max_indexes',
                'label'       => 'Max Indexes',
                'type'        => 'number',
                'default'     => 6,
                'description' => 'Number of most recent indexes to attempt, because results tend to be occasionally patchy.',
            ],
        ];
        // ── company-name-extractor ────────────────────────────────────────
        self::$schemas['company-name-extractor'] = [
            [
                'key'         => 'filter_css_js',
                'label'       => 'Filter CSS/JS Content',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Filter out company names that originated from CSS/JS content. Enabling this avoids detection of popular Javascript and web framework author company names.',
            ],
        ];

        // ── country-name-extractor ────────────────────────────────────────
        self::$schemas['country-name-extractor'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Obtain country name from affiliate sites.',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Obtain country name from co-hosted sites.',
            ],
            [
                'key'         => 'parse_unassociated_tlds',
                'label'       => 'Parse Unassociated TLDs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Parse TLDs not associated with any country as default country domains.',
            ],
            [
                'key'         => 'check_similar_domains',
                'label'       => 'Check Similar Domains',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Obtain country name from similar domains.',
            ],
        ];

        // ── crobat ────────────────────────────────────────────────────────
        self::$schemas['crobat'] = [
            [
                'key'         => 'request_delay',
                'label'       => 'Request Delay',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Delay between requests, in seconds.',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Max Pages',
                'type'        => 'number',
                'default'     => 10,
                'description' => 'Maximum number of pages of results to fetch.',
            ],
            [
                'key'         => 'dns_resolve',
                'label'       => 'DNS Resolve',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'DNS resolve each identified subdomain.',
            ],
        ];

        // ── cross-referencer ──────────────────────────────────────────────
        self::$schemas['cross-referencer'] = [
            [
                'key'         => 'check_base_url',
                'label'       => 'Check Base URL',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check the base URL of the potential affiliate if no direct affiliation found?',
            ],
        ];

        // ── crt-sh (Certificate Transparency) ────────────────────────────
        self::$schemas['crt-sh'] = [
            [
                'key'         => 'fetch_certs',
                'label'       => 'Fetch Certificates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Fetch each certificate found, for processing by other modules.',
            ],
            [
                'key'         => 'verify_san',
                'label'       => 'Verify SAN Resolution',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify certificate subject alternative names resolve.',
            ],
        ];
        // ── crxcavator ────────────────────────────────────────────────────
        self::$schemas['crxcavator'] = [
            [
                'key'         => 'verify_hostnames',
                'label'       => 'Verify Hostnames',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify identified hostnames resolve.',
            ],
        ];

        // ── custom-threat-feed ────────────────────────────────────────────
        self::$schemas['custom-threat-feed'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 0,
                'description' => 'Maximum age of data in hours before re-downloading. 0 to always download.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
            [
                'key'         => 'feed_url',
                'label'       => 'Feed URL',
                'type'        => 'text',
                'default'     => '',
                'description' => 'The URL where the feed can be found. Exact matching is performed so the format must be a single line per host, ASN, domain, IP or netblock.',
            ],
        ];

        // ── cybercrime-tracker ────────────────────────────────────────────
        self::$schemas['cybercrime-tracker'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'check_cohosts',
                'label'       => 'Check Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP?',
            ],
        ];

        // ── darksearch ────────────────────────────────────────────────────
        self::$schemas['darksearch'] = [
            [
                'key'         => 'fetch_darknet_pages',
                'label'       => 'Fetch Darknet Pages',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.',
            ],
            [
                'key'         => 'search_human_names',
                'label'       => 'Search Human Names',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Search for human names?',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Max Pages',
                'type'        => 'number',
                'default'     => 20,
                'description' => 'Maximum number of pages of results to fetch.',
            ],
        ];

        // ── dehashed ──────────────────────────────────────────────────────
        self::$schemas['dehashed'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Dehashed API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Dehashed API key.',
            ],
            [
                'key'         => 'username',
                'label'       => 'Dehashed Username',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Dehashed username.',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Max Pages',
                'type'        => 'number',
                'default'     => 2,
                'description' => 'Maximum number of pages to fetch (Max: 10 pages).',
            ],
            [
                'key'         => 'request_delay',
                'label'       => 'Request Delay',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Number of seconds to wait between each API request.',
            ],
            [
                'key'         => 'max_results_per_page',
                'label'       => 'Max Results Per Page',
                'type'        => 'number',
                'default'     => 10000,
                'description' => 'Maximum number of results per page (Max: 10000).',
            ],
        ];
        // ── dns-bruteforce ────────────────────────────────────────────────
        self::$schemas['dns-bruteforce'] = [
            [
                'key'         => 'try_common_750',
                'label'       => 'Try Common 750',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Try a list of about 750 common hostnames/sub-domains.',
            ],
            [
                'key'         => 'only_domain_names',
                'label'       => 'Only Domain Names',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Only attempt to brute-force names on domain names, not hostnames (some hostnames are also sub-domains).',
            ],
            [
                'key'         => 'try_number_suffixes',
                'label'       => 'Try Number Suffixes',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'For any host found, try appending 1, 01, 001, -1, -01, -001, 2, 02, etc. (up to 10)',
            ],
            [
                'key'         => 'limit_number_suffixes',
                'label'       => 'Limit Number Suffixes',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Limit using the number suffixes for hosts that have already been resolved? If disabled this will significantly extend the duration of scans.',
            ],
            [
                'key'         => 'skip_wildcard_dns',
                'label'       => 'Skip Wildcard DNS',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'If wildcard DNS is detected, don\'t bother brute-forcing.',
            ],
            [
                'key'         => 'try_common_10000',
                'label'       => 'Try Common 10000',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Try a further 10,000 common hostnames/sub-domains. Will make the scan much slower.',
            ],
        ];

        // ── dns-lookaside ─────────────────────────────────────────────────
        self::$schemas['dns-lookaside'] = [
            [
                'key'         => 'netmask_size',
                'label'       => 'Netmask Size',
                'type'        => 'number',
                'default'     => 4,
                'description' => 'If look-aside is enabled, the netmask size (in CIDR notation) to check. Default is 4 bits (16 hosts).',
            ],
            [
                'key'         => 'validate_reverse',
                'label'       => 'Validate Reverse Resolution',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.',
            ],
        ];

        // ── dns-raw ───────────────────────────────────────────────────────
        self::$schemas['dns-raw'] = [
            [
                'key'         => 'verify_hostnames',
                'label'       => 'Verify Hostnames',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify identified hostnames resolve.',
            ],
        ];

        // ── dns-resolver ──────────────────────────────────────────────────
        self::$schemas['dns-resolver'] = [
            [
                'key'         => 'max_netblock_ipv4',
                'label'       => 'Max IPv4 Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'Maximum owned IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_netblock_ipv6',
                'label'       => 'Max IPv6 Netblock Size',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'Maximum owned IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblock_ips',
                'label'       => 'Lookup Netblock IPs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'wildcard_first_only',
                'label'       => 'Wildcard First Only',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.',
            ],
            [
                'key'         => 'validate_reverse',
                'label'       => 'Validate Reverse Resolution',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.',
            ],
        ];

        // ── dns-zone-transfer ─────────────────────────────────────────────
        self::$schemas['dns-zone-transfer'] = [
            [
                'key'         => 'timeout',
                'label'       => 'Timeout',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Timeout in seconds.',
            ],
        ];

        // ── dnsdb ─────────────────────────────────────────────────────────
        self::$schemas['dnsdb'] = [
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 0,
                'description' => 'Ignore any DNSDB records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'api_key',
                'label'       => 'DNSDB API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'DNSDB API Key.',
            ],
            [
                'key'         => 'same_target_cohosting',
                'label'       => 'Same Target Co-hosting',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Treat co-hosted sites on the same target domain as co-hosting?',
            ],
            [
                'key'         => 'max_cohosts',
                'label'       => 'Max Co-hosts',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
            ],
            [
                'key'         => 'verify_cohosts',
                'label'       => 'Verify Co-hosts',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify co-hosts are valid by checking if they still resolve to the shared IP.',
            ],
        ];

        // ── dnsgrep ───────────────────────────────────────────────────────
        self::$schemas['dnsgrep'] = [
            [
                'key'         => 'dns_resolve',
                'label'       => 'DNS Resolve',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'DNS resolve each identified domain.',
            ],
            [
                'key'         => 'query_timeout',
                'label'       => 'Query Timeout',
                'type'        => 'number',
                'default'     => 30,
                'description' => 'Query timeout, in seconds.',
            ],
        ];

        // ── dnstwist (Tool - DNSTwist) ────────────────────────────────────
        self::$schemas['dnstwist'] = [
            [
                'key'         => 'dnstwist_path',
                'label'       => 'DNSTwist Path',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Path to the where the dnstwist.py file lives. Optional.',
            ],
            [
                'key'         => 'python_path',
                'label'       => 'Python Path',
                'type'        => 'text',
                'default'     => 'python',
                'description' => 'Path to Python interpreter to use for DNSTwist. If just \'python\' then it must be in your PATH.',
            ],
        ];

        // ── do-space-finder ───────────────────────────────────────────────
        self::$schemas['dnsaudit'] = [
            [
                'key'         => 'timeout_seconds',
                'label'       => 'Timeout (Seconds)',
                'type'        => 'number',
                'default'     => 45,
                'description' => 'Timeout for DNSAudit API requests.',
            ],
            [
                'key'         => 'max_retries',
                'label'       => 'Max Retries',
                'type'        => 'number',
                'default'     => 2,
                'description' => 'Maximum retry attempts for transient DNSAudit API failures.',
            ],
            [
                'key'         => 'min_severity',
                'label'       => 'Minimum Severity',
                'type'        => 'text',
                'default'     => 'warning',
                'description' => 'Minimum finding severity to include (info, warning, critical).',
            ],
            [
                'key'         => 'max_results',
                'label'       => 'Maximum Results',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Maximum number of findings to include in module output.',
            ],
            [
                'key'         => 'include_history',
                'label'       => 'Include Scan History',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Fetch recent DNSAudit scan history as additional context.',
            ],
            [
                'key'         => 'history_limit',
                'label'       => 'History Limit',
                'type'        => 'number',
                'default'     => 10,
                'description' => 'Maximum DNSAudit history records to fetch when history is enabled.',
            ],
            [
                'key'         => 'emit_subdomain_discoveries',
                'label'       => 'Emit Subdomain Discoveries',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Emit discovered subdomains as enrichment events (can significantly increase scan time).',
            ],
            [
                'key'         => 'include_raw_payload',
                'label'       => 'Include Raw Payload',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Include raw DNSAudit API payload in the module result.',
            ],
            [
                'key'         => 'emit_issue_rows',
                'label'       => 'Emit Issue Rows',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Store one CTI result row per DNSAudit issue for category/severity drilldown.',
            ],
            [
                'key'         => 'include_docs_links',
                'label'       => 'Include Docs Links',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Attach DNSAudit documentation links to issue rows when the issue slug is recognized.',
            ],
        ];
        self::$schemas['do-space-finder'] = [
            [
                'key'         => 'locations',
                'label'       => 'DO Locations',
                'type'        => 'text',
                'default'     => 'nyc3.digitaloceanspaces.com,sgp1.digitaloceanspaces.com,ams3.digitaloceanspaces.com,sfo2.digitaloceanspaces.com,fra1.digitaloceanspaces.com,sfo3.digitaloceanspaces.com',
                'description' => 'Different Digital Ocean locations to check where spaces may exist.',
            ],
            [
                'key'         => 'suffixes',
                'label'       => 'Space Name Suffixes',
                'type'        => 'text',
                'default'     => 'test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,public,private,assets,backup,backups,logs,stag',
                'description' => 'List of suffixes to append to domains tried as space names.',
            ],
        ];
        // ── dronebl ───────────────────────────────────────────────────────
        self::$schemas['dronebl'] = [
            [
                'key'         => 'max_netblock_size',
                'label'       => 'Max Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_size',
                'label'       => 'Max Subnet Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblock_ips',
                'label'       => 'Lookup Netblock IPs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'lookup_subnet_ips',
                'label'       => 'Lookup Subnet IPs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on subnets which your target is a part of for blacklisting?',
            ],
        ];

        // ── duckduckgo ────────────────────────────────────────────────────
        self::$schemas['duckduckgo'] = [
            [
                'key'         => 'lookup_domain_name',
                'label'       => 'Lookup Domain Name',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'For affiliates, look up the domain name, not the hostname. This will usually return more meaningful information about the affiliate.',
            ],
        ];
        // ── emailcrawlr ───────────────────────────────────────────────────
        self::$schemas['emailcrawlr'] = [
            [
                'key'         => 'api_key',
                'label'       => 'EmailCrawlr API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'EmailCrawlr API key.',
            ],
            [
                'key'         => 'request_delay',
                'label'       => 'Request Delay',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Delay between requests, in seconds.',
            ],
        ];

        // ── emailrep ─────────────────────────────────────────────────────
        self::$schemas['emailrep'] = [
            [
                'key'         => 'api_key',
                'label'       => 'EmailRep API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'EmailRep API key.',
            ],
        ];

        // ── emerging-threats ──────────────────────────────────────────────
        self::$schemas['emerging-threats'] = [
            [
                'key'         => 'cache_hours',
                'label'       => 'Cache Hours',
                'type'        => 'number',
                'default'     => 18,
                'description' => 'Hours to cache list data before re-fetching.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliate IP addresses?',
            ],
            [
                'key'         => 'check_netblocks',
                'label'       => 'Check Netblocks',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Report if any malicious IPs are found within owned netblocks?',
            ],
            [
                'key'         => 'check_subnets',
                'label'       => 'Check Subnets',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Check if any malicious IPs are found within the same subnet of the target?',
            ],
        ];

        // ── etherscan ─────────────────────────────────────────────────────
        self::$schemas['etherscan'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Etherscan API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'API Key for etherscan.io.',
            ],
            [
                'key'         => 'request_delay',
                'label'       => 'Request Delay',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Number of seconds to wait between each API call.',
            ],
        ];

        // ── file-metadata-extractor ───────────────────────────────────────
        self::$schemas['file-metadata-extractor'] = [
            [
                'key'         => 'file_extensions',
                'label'       => 'File Extensions',
                'type'        => 'text',
                'default'     => 'docx,pptx,pdf,jpg,jpeg,tiff,tif',
                'description' => 'File extensions of files you want to analyze the meta data of (only PDF, DOCX, XLSX and PPTX are supported.)',
            ],
            [
                'key'         => 'download_timeout',
                'label'       => 'Download Timeout',
                'type'        => 'number',
                'default'     => 300,
                'description' => 'Download timeout for files, in seconds.',
            ],
        ];
        // ── flickr ─────────────────────────────────────────────────────────
        self::$schemas['flickr'] = [
            [
                'key'         => 'dns_resolve',
                'label'       => 'DNS Resolve',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'DNS resolve each identified domain.',
            ],
            [
                'key'         => 'max_pages',
                'label'       => 'Max Pages',
                'type'        => 'number',
                'default'     => 20,
                'description' => 'Maximum number of pages of results to fetch.',
            ],
            [
                'key'         => 'pause_seconds',
                'label'       => 'Pause Between Fetches',
                'type'        => 'number',
                'default'     => 1,
                'description' => 'Number of seconds to pause between fetches.',
            ],
            [
                'key'         => 'max_results_per_page',
                'label'       => 'Max Results Per Page',
                'type'        => 'number',
                'default'     => 100,
                'description' => 'Maximum number of results per page.',
            ],
        ];

        // ── focsec ────────────────────────────────────────────────────────
        self::$schemas['focsec'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Focsec API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Focsec API Key.',
            ],
        ];

        // ── fortiguard ────────────────────────────────────────────────────
        self::$schemas['fortiguard'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
        ];

        // ── fraudguard ────────────────────────────────────────────────────
        self::$schemas['fraudguard'] = [
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 90,
                'description' => 'Ignore any records older than this many days. 0 = unlimited.',
            ],
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates?',
            ],
            [
                'key'         => 'api_username',
                'label'       => 'Fraudguard Username',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Fraudguard.io API username.',
            ],
            [
                'key'         => 'api_password',
                'label'       => 'Fraudguard Password',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Fraudguard.io API password.',
            ],
            [
                'key'         => 'max_netblock_ipv4',
                'label'       => 'Max IPv4 Netblock Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_ipv4',
                'label'       => 'Max IPv4 Subnet Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum IPv4 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_netblock_ipv6',
                'label'       => 'Max IPv6 Netblock Size',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'max_subnet_ipv6',
                'label'       => 'Max IPv6 Subnet Size',
                'type'        => 'number',
                'default'     => 120,
                'description' => 'If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblock_ips',
                'label'       => 'Lookup Netblock IPs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'lookup_subnet_ips',
                'label'       => 'Lookup Subnet IPs',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on subnets which your target is a part of for blacklisting?',
            ],
        ];
        // ── fullcontact ───────────────────────────────────────────────────
        self::$schemas['fullcontact'] = [
            [
                'key'         => 'api_key',
                'label'       => 'FullContact API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'FullContact.com API key.',
            ],
            [
                'key'         => 'max_age_days',
                'label'       => 'Max Age (Days)',
                'type'        => 'number',
                'default'     => 365,
                'description' => 'Maximum number of age in days for a record before it\'s considered invalid and not reported.',
            ],
        ];

        // ── fullhunt ─────────────────────────────────────────────────────
        self::$schemas['fullhunt'] = [
            [
                'key'         => 'api_key',
                'label'       => 'FullHunt API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'FullHunt API key.',
            ],
        ];

        // ── gcs-finder (Google Object Storage Finder) ─────────────────────
        self::$schemas['gcs-finder'] = [
            [
                'key'         => 'suffixes',
                'label'       => 'Bucket Name Suffixes',
                'type'        => 'text',
                'default'     => 'test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,public,private,assets,backup,backups,logs,stag',
                'description' => 'List of suffixes to append to domains tried as bucket names.',
            ],
        ];

        // ── github ────────────────────────────────────────────────────────
        self::$schemas['github'] = [
            [
                'key'         => 'match_name_only',
                'label'       => 'Match Name Only',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Match repositories by name only, not by their descriptions. Helps reduce false positives.',
            ],
        ];

        // ── google ─────────────────────────────────────────────────────────
        self::$schemas['google'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Google API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Google API Key for Google search.',
            ],
            [
                'key'         => 'cse_id',
                'label'       => 'Custom Search Engine ID',
                'type'        => 'text',
                'default'     => '013611106330597893267:tfgl3wxdtbp',
                'description' => 'Google Custom Search Engine ID.',
            ],
        ];

        // ── google-maps ───────────────────────────────────────────────────
        self::$schemas['google-maps'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Google Geocoding API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Google Geocoding API Key.',
            ],
        ];

        // ── google-safebrowsing ───────────────────────────────────────────
        self::$schemas['google-safebrowsing'] = [
            [
                'key'         => 'api_key',
                'label'       => 'Google Safe Browsing API Key',
                'type'        => 'text',
                'default'     => '',
                'description' => 'Google Safe Browsing API key.',
            ],
        ];
        self::$schemas['grayhat-warfare'] = [];
        self::$schemas['greensnow'] = [];
        self::$schemas['grep-app'] = [];
        self::$schemas['greynoise'] = [];
        self::$schemas['hackertarget'] = [];
        self::$schemas['haveibeenpwned'] = [];
        self::$schemas['host-io'] = [];
        self::$schemas['human-name-extractor'] = [];
        self::$schemas['hunter'] = [];
        self::$schemas['hybrid-analysis'] = [];
        self::$schemas['iknowwhatyoudownload'] = [];
        self::$schemas['intelligencex'] = [];
        self::$schemas['interesting-file-finder'] = [];
        self::$schemas['ipapi'] = [];
        self::$schemas['ipinfo'] = [];
        self::$schemas['ipqualityscore'] = [];
        self::$schemas['ipregistry'] = [];
        self::$schemas['ipstack'] = [];
        self::$schemas['isc-sans'] = [];
        self::$schemas['jsonwhois'] = [];
        self::$schemas['junk-file-finder'] = [];
        self::$schemas['koodous'] = [];
        self::$schemas['leak-lookup'] = [];
        self::$schemas['leakix'] = [];
        self::$schemas['maltiverse'] = [];
        self::$schemas['malwarepatrol'] = [];
        self::$schemas['metadefender'] = [];
        self::$schemas['mnemonic-pdns'] = [];
        self::$schemas['multiproxy'] = [];
        self::$schemas['nameapi'] = [];
        self::$schemas['nbtscan'] = [];
        self::$schemas['networksdb'] = [];
        self::$schemas['neutrinoapi'] = [];
        self::$schemas['nmap'] = [];
        self::$schemas['nuclei'] = [];
        self::$schemas['numverify'] = [];
        self::$schemas['onesixtyone'] = [];
        self::$schemas['onion-link'] = [];
        self::$schemas['onionsearchengine'] = [];
        self::$schemas['onyphe'] = [];
        self::$schemas['open-pdns'] = [];
        self::$schemas['opencorporates'] = [];
        self::$schemas['opennic'] = [];
        self::$schemas['openphish'] = [];
        self::$schemas['pastebin'] = [];
        self::$schemas['pgp-keyservers'] = [];
        self::$schemas['phishstats'] = [];
        self::$schemas['phishtank'] = [];
        self::$schemas['port-scanner-tcp'] = [];
        self::$schemas['project-honeypot'] = [];
        self::$schemas['pulsedive'] = [];
        self::$schemas['recon-dev'] = [];
        self::$schemas['retire-js'] = [];
        // ── riddler (F-Secure Riddler.io) ─────────────────────────────────
        self::$schemas['riddler'] = [
            [
                'key'         => 'password',
                'label'       => 'Riddler.io Password',
                'type'        => 'text',
                'default'     => '',
                'description' => 'F-Secure Riddler.io password.',
            ],
            [
                'key'         => 'username',
                'label'       => 'Riddler.io Username',
                'type'        => 'text',
                'default'     => '',
                'description' => 'F-Secure Riddler.io username.',
            ],
            [
                'key'         => 'verify_hostnames',
                'label'       => 'Verify Hostnames',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify host names resolve.',
            ],
        ];
        self::$schemas['riskiq'] = [];
        self::$schemas['robtex'] = [];
        self::$schemas['s3-finder'] = [];
        self::$schemas['scylla'] = [];
        self::$schemas['searchcode'] = [];
        self::$schemas['securitytrails'] = [];
        self::$schemas['seon'] = [];
        self::$schemas['shodan'] = [];
        self::$schemas['snallygaster'] = [];
        self::$schemas['snov'] = [];
        self::$schemas['social-links'] = [];
        self::$schemas['social-media-finder'] = [];
        self::$schemas['sorbs'] = [];
        self::$schemas['spamcop'] = [];
        self::$schemas['spamhaus-zen'] = [];
        self::$schemas['spur'] = [];
        self::$schemas['spyonweb'] = [];
        self::$schemas['spyse'] = [];
        self::$schemas['ssl-analyzer'] = [];
        self::$schemas['stackoverflow'] = [];
        self::$schemas['steven-black-hosts'] = [];
        self::$schemas['surbl'] = [];
        self::$schemas['talos-intelligence'] = [];
        self::$schemas['testssl'] = [];
        self::$schemas['textmagic'] = [];
        self::$schemas['threatcrowd'] = [];
        self::$schemas['threatfox'] = [];
        self::$schemas['threatminer'] = [];
        self::$schemas['tld-searcher'] = [];
        self::$schemas['tor-exit-nodes'] = [];
        self::$schemas['torch'] = [];
        self::$schemas['trashpanda'] = [];
        self::$schemas['trufflehog'] = [];
        self::$schemas['twilio'] = [];
        self::$schemas['uceprotect'] = [];
        self::$schemas['urlscan'] = [];
        self::$schemas['viewdns'] = [];
        self::$schemas['virustotal'] = [
            [
                'key'         => 'check_affiliates',
                'label'       => 'Check Affiliates?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to affiliates of your target?',
            ],
            [
                'key'         => 'check_co_hosted',
                'label'       => 'Check Co-hosted Sites?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Apply checks to sites found to be co-hosted on the target\'s IP address?',
            ],
            [
                'key'         => 'netblock_size',
                'label'       => 'Max Netblock Size (Owned)',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'subnet_size',
                'label'       => 'Max Subnet Size',
                'type'        => 'number',
                'default'     => 24,
                'description' => 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
            ],
            [
                'key'         => 'lookup_netblock_ips',
                'label'       => 'Look Up IPs on Owned Netblocks?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?',
            ],
            [
                'key'         => 'public_key',
                'label'       => 'Using Public API Key?',
                'type'        => 'boolean',
                'default'     => false,
                'description' => 'Enable if you are using a free/public VirusTotal API key. Throttles requests to 4/min to avoid rate-limiting (adds 15 s delay per query). Leave disabled for premium keys.',
            ],
            [
                'key'         => 'daily_limit',
                'label'       => 'Daily API Quota',
                'type'        => 'number',
                'default'     => 500,
                'description' => 'Maximum VirusTotal API calls per day (free tier = 500). Set to 0 for unlimited (premium keys).',
            ],
            [
                'key'         => 'lookup_subnet_ips',
                'label'       => 'Look Up IPs on Subnets?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Look up all IPs on subnets which your target is a part of?',
            ],
            [
                'key'         => 'verify_hostnames',
                'label'       => 'Verify Hostnames Resolve?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Verify that any hostnames found on the target domain still resolve?',
            ],
            [
                'key'         => 'use_v2_domain_siblings',
                'label'       => 'Use VT v2 Domain Siblings?',
                'type'        => 'boolean',
                'default'     => true,
                'description' => 'Prefer VirusTotal v2 domain_siblings output for SpiderFoot-compatible affiliate counts. Falls back to v3 siblings when unavailable.',
            ],
        ];
        self::$schemas['voipbl'] = [];
        self::$schemas['vxvault'] = [];
        self::$schemas['wafw00f'] = [];
        self::$schemas['wappalyzer'] = [];
        self::$schemas['web-spider'] = [];
        self::$schemas['whatcms'] = [];
        self::$schemas['whatweb'] = [];
        self::$schemas['whoisology'] = [];
        self::$schemas['whoxy'] = [];
        self::$schemas['wigle'] = [];
        self::$schemas['wikileaks'] = [];
        self::$schemas['wikipedia-edits'] = [];
        self::$schemas['xforce-exchange'] = [];
        self::$schemas['zetalytics'] = [];
        self::$schemas['zone-h'] = [];

        self::applySpiderFootCatalog();
    }

    private static function applySpiderFootCatalog(): void
    {
        foreach (SpiderFootSettingsCatalog::rowsBySlug() as $slug => $rows) {
            $existing = self::$schemas[$slug] ?? [];
            $existingByKey = [];

            foreach ($existing as $setting) {
                $key = (string)($setting['key'] ?? '');
                if ($key !== '') {
                    $existingByKey[$key] = $setting;
                }
            }

            $merged = [];
            foreach ($rows as $row) {
                $key = (string)($row['key'] ?? '');
                if ($key === '') {
                    continue;
                }

                $catalogSetting = [
                    'key'         => $key,
                    'label'       => (string)($row['label'] ?? $key),
                    'type'        => (string)($row['type'] ?? 'text'),
                    'default'     => $row['default'] ?? '',
                    'description' => (string)($row['description'] ?? ''),
                ];

                if (isset($existingByKey[$key])) {
                    $merged[] = array_merge($existingByKey[$key], $catalogSetting);
                    unset($existingByKey[$key]);
                } else {
                    $merged[] = $catalogSetting;
                }
            }

            foreach ($existing as $setting) {
                $key = (string)($setting['key'] ?? '');
                if ($key !== '' && isset($existingByKey[$key])) {
                    $merged[] = $setting;
                }
            }

            self::$schemas[$slug] = $merged;
        }
    }

    // =========================================================================
    //  PUBLIC API
    // =========================================================================

    /**
     * Get the settings schema for a single module/platform slug.
     *
     * @param  string  $slug  Module slug (e.g. '_global', 'abuse-ch', 'alienvault')
     * @return array          Array of setting definitions, or empty array if unknown
     */
    public static function getSchema(string $slug): array
    {
        self::init();
        return self::$schemas[$slug] ?? [];
    }

    /**
     * Get all slug => schema pairs.
     *
     * @return array<string, array>
     */
    public static function getAllSchemas(): array
    {
        self::init();
        return self::$schemas;
    }

    /**
     * Get display info for platform pseudo-modules (_global, _storage).
     *
     * @param  string  $slug
     * @return array   {name, description}
     */
    public static function getModuleInfo(string $slug): array
    {
        $info = [
            '_global' => [
                'name'        => 'Global Settings',
                'description' => 'Platform-wide configuration for networking, proxies, and general behaviour.',
            ],
            '_storage' => [
                'name'        => 'Storage Settings',
                'description' => 'Controls how much data the platform stores per element.',
            ],
        ];

        return $info[$slug] ?? [];
    }

    /**
     * Get optional tags for a module (not stored in DB).
     *
     * @param  string  $slug
     * @return string  Comma-separated tags, or empty string
     */
    public static function getModuleTags(string $slug): string
    {
        $tags = [
            'apivoid'                 => 'apikey',
            'archive-org'             => 'slow',
            'bad-packets'             => 'apikey',
            'binaryedge'              => 'apikey',
            'bing'                    => 'apikey',
            'bing-shared-ips'         => 'apikey',
            'binary-string-extractor' => 'errorprone',
            'bitcoin-whos-who'        => 'apikey',
            'botscout'                => 'apikey',
            'builtwith'               => 'apikey',
            'c99'                     => 'apikey',
            'censys'                  => 'apikey',
            'certspotter'             => 'apikey',
            'bitcoinabuse'            => 'apikey',
            'circl-lu'                => 'apikey',
            'clearbit'                => 'apikey',
            'darksearch'              => 'tor',
            'dehashed'                => 'apikey',
            'dnsdb'                   => 'apikey',
            'dnsaudit'                => 'apikey',
            'emailcrawlr'             => 'apikey',
            'emailrep'                => 'apikey',
            'etherscan'               => 'apikey',
            'focsec'                  => 'apikey',
            'fraudguard'              => 'apikey',
            'chaos'                   => 'apikey',
            'cmseek'                  => 'tool',
            'dnstwist'                => 'tool',
            'fullcontact'             => 'apikey',
            'fullhunt'                => 'apikey',
            'google'                  => 'apikey',
            'google-maps'             => 'apikey',
            'google-safebrowsing'     => 'slow, apikey',
            'riddler'                 => 'apikey',
        ];

        return $tags[$slug] ?? '';
    }
}
