<?php
// =============================================================================
//  CTI — SpiderFoot Module Mapper
//  php/SpiderFootModuleMapper.php
//
//  Maps SpiderFoot module names (sfp_*) and long option descriptions to the
//  CTI platform's normalised slugs and setting keys.
// =============================================================================

class SpiderFootModuleMapper
{
    /**
     * Map SpiderFoot module names to CTI platform slugs.
     * Source: SPIDERFOOT_SCAN_SETTINGS_BASELINE_TABLE.md → OsintEngine $handlerMap
     */
    private static array $moduleMap = [
        'sfp__stor_db'                  => '_storage',
        'sfp_abstractapi'               => 'abstractapi',
        'sfp_abusech'                   => 'abuse-ch',
        'sfp_abuseipdb'                 => 'abuseipdb',
        'sfp_abusix'                    => 'abusix',
        'sfp_accounts'                  => 'account-finder',
        'sfp_adblock'                   => 'adblock-check',
        'sfp_ahmia'                     => 'ahmia',
        'sfp_alienvault'                => 'alienvault',
        'sfp_alienvaultiprep'           => 'alienvault-ip-rep',
        'sfp_archiveorg'                => 'archive-org',
        'sfp_azureblobstorage'          => 'azure-blob-finder',
        'sfp_badpackets'                => 'bad-packets',
        'sfp_base64'                    => 'base64-decoder',
        'sfp_binaryedge'                => 'binaryedge',
        'sfp_bingsearch'                => 'bing',
        'sfp_bingsharedip'              => 'bing-shared-ips',
        'sfp_binstring'                 => 'binary-string-extractor',
        'sfp_bitcoinabuse'              => 'bitcoinabuse',
        'sfp_bitcoinwhoswho'            => 'bitcoin-whos-who',
        'sfp_blocklistde'               => 'blocklist-de',
        'sfp_botscout'                  => 'botscout',
        'sfp_botvrij'                   => 'botvrij',
        'sfp_builtwith'                 => 'builtwith',
        'sfp_c99'                       => 'c99',
        'sfp_censys'                    => 'censys',
        'sfp_certspotter'               => 'certspotter',
        'sfp_cinsscore'                 => 'cins-army',
        'sfp_circllu'                   => 'circl-lu',
        'sfp_citadel'                   => 'leak-lookup',
        'sfp_cleantalk'                 => 'cleantalk',
        'sfp_clearbit'                  => 'clearbit',
        'sfp_coinblocker'               => 'coinblocker',
        'sfp_commoncrawl'               => 'commoncrawl',
        'sfp_company'                   => 'company-name-extractor',
        'sfp_countryname'               => 'country-name-extractor',
        'sfp_crobat_api'                => 'crobat',
        'sfp_crossref'                  => 'cross-referencer',
        'sfp_crt'                       => 'crt-sh',
        'sfp_crxcavator'                => 'crxcavator',
        'sfp_customfeed'                => 'custom-threat-feed',
        'sfp_cybercrimetracker'         => 'cybercrime-tracker',
        'sfp_darksearch'                => 'darksearch',
        'sfp_dehashed'                  => 'dehashed',
        'sfp_digitaloceanspace'         => 'do-space-finder',
        'sfp_dnsbrute'                  => 'dns-bruteforce',
        'sfp_dnsdb'                     => 'dnsdb',
        'sfp_dnsgrep'                   => 'dnsgrep',
        'sfp_dnsneighbor'               => 'dns-lookaside',
        'sfp_dnsraw'                    => 'dns-raw',
        'sfp_dnsresolve'                => 'dns-resolver',
        'sfp_dnszonexfer'               => 'dns-zone-transfer',
        'sfp_dronebl'                   => 'dronebl',
        'sfp_duckduckgo'                => 'duckduckgo',
        'sfp_emailcrawlr'               => 'emailcrawlr',
        'sfp_emailrep'                  => 'emailrep',
        'sfp_emergingthreats'           => 'emerging-threats',
        'sfp_etherscan'                 => 'etherscan',
        'sfp_filemeta'                  => 'file-metadata-extractor',
        'sfp_flickr'                    => 'flickr',
        'sfp_focsec'                    => 'focsec',
        'sfp_fortinet'                  => 'fortiguard',
        'sfp_fraudguard'                => 'fraudguard',
        'sfp_fsecure_riddler'           => 'riddler',
        'sfp_fullcontact'               => 'fullcontact',
        'sfp_fullhunt'                  => 'fullhunt',
        'sfp_github'                    => 'github',
        'sfp_googlemaps'                => 'google-maps',
        'sfp_googleobjectstorage'       => 'gcs-finder',
        'sfp_googlesafebrowsing'        => 'google-safebrowsing',
        'sfp_googlesearch'              => 'google',
        'sfp_grayhatwarfare'            => 'grayhat-warfare',
        'sfp_greensnow'                 => 'greensnow',
        'sfp_grep_app'                  => 'grep-app',
        'sfp_greynoise'                 => 'greynoise',
        'sfp_hackertarget'              => 'hackertarget',
        'sfp_haveibeenpwned'            => 'haveibeenpwned',
        'sfp_honeypot'                  => 'project-honeypot',
        'sfp_hostio'                    => 'host-io',
        'sfp_hunter'                    => 'hunter',
        'sfp_hybrid_analysis'           => 'hybrid-analysis',
        'sfp_iknowwhatyoudownload'      => 'iknowwhatyoudownload',
        'sfp_intelx'                    => 'intelligencex',
        'sfp_intfiles'                  => 'interesting-file-finder',
        'sfp_ipapicom'                  => 'ipapi',
        'sfp_ipinfo'                    => 'ipinfo',
        'sfp_ipqualityscore'            => 'ipqualityscore',
        'sfp_ipregistry'                => 'ipregistry',
        'sfp_ipstack'                   => 'ipstack',
        'sfp_isc'                       => 'isc-sans',
        'sfp_jsonwhoiscom'              => 'jsonwhois',
        'sfp_junkfiles'                 => 'junk-file-finder',
        'sfp_koodous'                   => 'koodous',
        'sfp_leakix'                    => 'leakix',
        'sfp_maltiverse'                => 'maltiverse',
        'sfp_malwarepatrol'             => 'malwarepatrol',
        'sfp_metadefender'              => 'metadefender',
        'sfp_mnemonic'                  => 'mnemonic-pdns',
        'sfp_multiproxy'                => 'multiproxy',
        'sfp_nameapi'                   => 'nameapi',
        'sfp_names'                     => 'human-name-extractor',
        'sfp_networksdb'                => 'networksdb',
        'sfp_neutrinoapi'               => 'neutrinoapi',
        'sfp_numverify'                 => 'numverify',
        'sfp_onioncity'                 => 'onion-link',
        'sfp_onionsearchengine'         => 'onionsearchengine',
        'sfp_onyphe'                    => 'onyphe',
        'sfp_open_passive_dns_database' => 'open-pdns',
        'sfp_opencorporates'            => 'opencorporates',
        'sfp_opennic'                   => 'opennic',
        'sfp_openphish'                 => 'openphish',
        'sfp_pastebin'                  => 'pastebin',
        'sfp_pgp'                       => 'pgp-keyservers',
        'sfp_phishstats'                => 'phishstats',
        'sfp_phishtank'                 => 'phishtank',
        'sfp_portscan_tcp'              => 'port-scanner-tcp',
        'sfp_projectdiscovery'          => 'chaos',
        'sfp_pulsedive'                 => 'pulsedive',
        'sfp_recondev'                  => 'recon-dev',
        'sfp_riskiq'                    => 'riskiq',
        'sfp_robtex'                    => 'robtex',
        'sfp_s3bucket'                  => 's3-finder',
        'sfp_scylla'                    => 'scylla',
        'sfp_searchcode'                => 'searchcode',
        'sfp_securitytrails'            => 'securitytrails',
        'sfp_seon'                      => 'seon',
        'sfp_shodan'                    => 'shodan',
        'sfp_snov'                      => 'snov',
        'sfp_sociallinks'               => 'social-links',
        'sfp_socialprofiles'            => 'social-media-finder',
        'sfp_sorbs'                     => 'sorbs',
        'sfp_spamcop'                   => 'spamcop',
        'sfp_spamhaus'                  => 'spamhaus-zen',
        'sfp_spider'                    => 'web-spider',
        'sfp_spur'                      => 'spur',
        'sfp_spyonweb'                  => 'spyonweb',
        'sfp_spyse'                     => 'spyse',
        'sfp_sslcert'                   => 'ssl-analyzer',
        'sfp_stackoverflow'             => 'stackoverflow',
        'sfp_stevenblack_hosts'         => 'steven-black-hosts',
        'sfp_surbl'                     => 'surbl',
        'sfp_talosintel'                => 'talos-intelligence',
        'sfp_textmagic'                 => 'textmagic',
        'sfp_threatcrowd'               => 'threatcrowd',
        'sfp_threatfox'                 => 'threatfox',
        'sfp_threatminer'               => 'threatminer',
        'sfp_tldsearch'                 => 'tld-searcher',
        'sfp_tool_cmseek'               => 'cmseek',
        'sfp_tool_dnstwist'             => 'dnstwist',
        'sfp_tool_nbtscan'              => 'nbtscan',
        'sfp_tool_nmap'                 => 'nmap',
        'sfp_tool_nuclei'               => 'nuclei',
        'sfp_tool_onesixtyone'          => 'onesixtyone',
        'sfp_tool_retirejs'             => 'retire-js',
        'sfp_tool_snallygaster'         => 'snallygaster',
        'sfp_tool_testsslsh'            => 'testssl',
        'sfp_tool_trufflehog'           => 'trufflehog',
        'sfp_tool_wafw00f'              => 'wafw00f',
        'sfp_tool_wappalyzer'           => 'wappalyzer',
        'sfp_tool_whatweb'              => 'whatweb',
        'sfp_torch'                     => 'torch',
        'sfp_torexits'                  => 'tor-exit-nodes',
        'sfp_trashpanda'                => 'trashpanda',
        'sfp_twilio'                    => 'twilio',
        'sfp_uceprotect'                => 'uceprotect',
        'sfp_urlscan'                   => 'urlscan',
        'sfp_viewdns'                   => 'viewdns',
        'sfp_virustotal'                => 'virustotal',
        'sfp_voipbl'                    => 'voipbl',
        'sfp_vxvault'                   => 'vxvault',
        'sfp_whatcms'                   => 'whatcms',
        'sfp_whoisology'                => 'whoisology',
        'sfp_whoxy'                     => 'whoxy',
        'sfp_wigle'                     => 'wigle',
        'sfp_wikileaks'                 => 'wikileaks',
        'sfp_wikipediaedits'            => 'wikipedia-edits',
        'sfp_xforce'                    => 'xforce-exchange',
        'sfp_zetalytics'                => 'zetalytics',
        'sfp_zoneh'                     => 'zone-h',
    ];

    /**
     * Common SpiderFoot option description patterns mapped to normalised setting keys.
     * Order matters — first match wins.
     */
    private static array $optionPatterns = [
        // API keys & credentials
        '/\bAPI [Kk]ey\b/'                                          => 'api_key',
        '/\bAPI [Ss]ecret\b/'                                       => 'api_secret',
        '/\bAPI [Pp]assword\b/'                                     => 'api_password',
        '/\bAPI [Uu]sername\b/'                                     => 'api_username',
        '/\bAPI [Uu]ser\s?[Ii][Dd]\b/'                              => 'api_uid',
        '/\bAPI [Cc]lient [Ii][Dd]\b/'                              => 'api_client_id',
        '/\bAPI [Cc]lient [Ss]ecret\b/'                             => 'api_client_secret',
        '/\blogin\b/i'                                               => 'api_login',
        '/\bpassword\b/i'                                            => 'api_password',
        '/\baccess token\b/i'                                        => 'api_token',
        '/\breceipt.*ID\b/i'                                        => 'api_receipt',
        '/\bbase64-encoded API name\/token\b/i'                      => 'api_token',

        // Affiliate / co-host / subnet checks
        '/Apply checks to affiliate/i'                               => 'check_affiliates',
        '/Check affiliate/i'                                         => 'check_affiliates',
        '/Check co-hosted/i'                                         => 'check_cohosts',
        '/Apply checks to sites found to be co-hosted/i'             => 'check_cohosts',
        '/Treat co-hosted sites on the same target domain/i'         => 'cohost_same_domain',
        '/Report if any malicious IPs are found within owned/i'      => 'check_netblocks',
        '/Look up all IPs on netblocks deemed/i'                     => 'check_netblocks',
        '/Check if any malicious IPs are found within the same subnet/i' => 'check_subnets',
        '/Look up all IPs on subnets/i'                              => 'check_subnets',

        // Netblock / subnet CIDR sizes
        '/maximum.*IPv6 netblock size/i'                             => 'max_netblock_ipv6',
        '/maximum.*IPv6 subnet size/i'                               => 'max_subnet_ipv6',
        '/maximum.*IPv4 netblock size/i'                             => 'max_netblock_ipv4',
        '/maximum.*IPv4 subnet size/i'                               => 'max_subnet_ipv4',
        '/maximum netblock size/i'                                   => 'max_netblock_ipv4',
        '/maximum subnet size/i'                                     => 'max_subnet_ipv4',
        '/Maximum netblock.*size to scan/i'                          => 'max_netblock_ipv4',

        // Verification
        '/Verify co-hosts are valid/i'                               => 'verify_cohosts',
        '/Verify.*hostnames?.*resolve/i'                             => 'verify_hostnames',
        '/Verify.*domains?.*resolve/i'                               => 'verify_hostnames',
        '/Verify certificate subject alternative names/i'            => 'verify_san',
        '/Verify identified domains still resolve/i'                 => 'verify_hostnames',
        '/Validate that reverse-resolved hostnames/i'                => 'verify_reverse_dns',
        '/DNS resolve each identified/i'                             => 'verify_hostnames',

        // Co-host limits
        '/Stop reporting co-hosted sites after/i'                    => 'max_cohosts',
        '/Ignore any co-hosts older than/i'                          => 'cohost_max_age_days',

        // Cache / timing
        '/Hours to cache list data/i'                                => 'cache_hours',
        '/Maximum age of data.*hours.*re-download/i'                 => 'cache_hours',
        '/Delay between requests/i'                                  => 'delay_seconds',
        '/Number of seconds to wait between/i'                       => 'delay_seconds',
        '/Number of seconds to pause between/i'                      => 'delay_seconds',
        '/Seconds before giving up/i'                                => 'timeout_seconds',
        '/Query timeout/i'                                           => 'timeout_seconds',
        '/Custom timeout/i'                                          => 'timeout_seconds',
        '/Download timeout/i'                                        => 'timeout_seconds',

        // Pagination / limits
        '/Maximum number of pages/i'                                 => 'max_pages',
        '/Number of results pages to iterate/i'                      => 'max_pages',
        '/Maximum number of results per page/i'                      => 'max_results_per_page',
        '/Maximum number of results/i'                               => 'max_results',
        '/Number of max.*results/i'                                  => 'max_results',
        '/Number of most recent indexes/i'                           => 'max_recent_indexes',

        // Age / freshness
        '/Ignore any.*records? older than.*days/i'                   => 'ignore_older_days',
        '/Ignore any.*older than.*days/i'                            => 'ignore_older_days',
        '/Ignore records older than/i'                               => 'ignore_older_days',
        '/maximum age.*data.*days/i'                                 => 'ignore_older_days',
        '/Maximum age of data/i'                                     => 'max_age_days',
        '/How far back.*days.*activity/i'                            => 'ignore_older_days',
        '/How many days back to consider/i'                          => 'ignore_older_days',
        '/Maximum days old/i'                                        => 'ignore_older_days',
        '/Maximum.*age.*days.*valid/i'                               => 'max_age_days',
        '/Number of days in the future a certificate expires/i'      => 'cert_expiry_warning_days',
        '/Number of days back to look for older versions/i'          => 'wayback_days',

        // Thresholds
        '/[Mm]inimum.*abuse.*score/i'                                => 'min_abuse_score',
        '/[Mm]inimum.*confidence/i'                                  => 'min_confidence',
        '/[Mm]inimum.*fraud score/i'                                 => 'min_fraud_score',
        '/[Mm]inimum.*threat score/i'                                => 'min_threat_score',
        '/[Mm]inimum AlienVault threat score/i'                      => 'min_threat_score',
        '/[Cc]onfidence that.*search result/i'                       => 'min_confidence',
        '/Threat score minimum/i'                                    => 'min_threat_score',
        '/Depth of the reputation checks/i'                          => 'reputation_depth',

        // Scan / discovery options
        '/Port scan all IPs/i'                                       => 'scan_netblock_ips',
        '/Scan all IPs within/i'                                     => 'scan_netblock_ips',
        '/Check all IPs within/i'                                    => 'scan_netblock_ips',
        '/The TCP ports to scan/i'                                   => 'tcp_ports',
        '/Randomize the order of ports/i'                            => 'randomize_ports',
        '/Number of ports to try.*simultaneously/i'                  => 'port_scan_threads',

        // DNS brute-force
        '/Try a list of about 750/i'                                 => 'brute_common',
        '/try appending 1, 01, 001/i'                                => 'brute_numbering',
        '/Only attempt to brute-force.*domain names/i'               => 'brute_domains_only',
        '/Limit using the number suffixes/i'                         => 'brute_limit_numbering',
        '/wildcard DNS is detected.*don.t bother/i'                  => 'skip_wildcard',
        '/further 10,000 common/i'                                   => 'brute_extended',

        // Content / file options
        '/File extensions.*ignore/i'                                 => 'ignore_extensions',
        '/File extensions.*fetch and analyse/i'                      => 'fetch_extensions',
        '/File extensions.*interesting/i'                             => 'interesting_extensions',
        '/File extensions.*analyze the meta/i'                       => 'metadata_extensions',
        '/File extensions to try/i'                                  => 'try_extensions',
        '/MIME types to ignore/i'                                    => 'ignore_mime',
        '/Maximum file size/i'                                       => 'max_file_bytes',
        '/Maximum bytes to store/i'                                  => 'max_bytes_per_element',

        // Search / discovery toggles
        '/Search for human names/i'                                  => 'search_names',
        '/Fetch the darknet pages/i'                                 => 'fetch_darknet',
        '/Fetch each certificate found/i'                            => 'fetch_certificates',
        '/Match repositories by name only/i'                         => 'match_repo_name_only',
        '/using.*public key/i'                                       => 'public_key',
        '/Are you using.*paid plan/i'                                => 'paid_plan',

        // Spider options
        '/Maximum levels to traverse/i'                              => 'max_depth',
        '/Maximum number of pages to fetch per/i'                    => 'max_pages_per_start',
        '/Skip spidering of subdomains/i'                            => 'skip_subdomains',
        '/Skip spidering of.*user directories/i'                     => 'skip_user_dirs',
        '/Only follow links specified by robots/i'                   => 'obey_robots',
        '/Report links every time/i'                                 => 'report_all_links',
        '/Accept and use cookies/i'                                  => 'use_cookies',
        '/Prepend targets with these/i'                              => 'url_prefixes',

        // Misc toggles
        '/Don.t bother looking up names.*first names/i'              => 'skip_standalone_firstnames',
        '/Don.t bother looking up names.*dictionary/i'               => 'skip_dictionary_names',
        '/username must be mentioned/i'                               => 'require_username_mention',
        '/Look for.*account name permutations/i'                     => 'check_permutations',
        '/Extract usernames from e-mail/i'                           => 'extract_email_usernames',
        '/Filter out company names.*CSS.*JS/i'                       => 'filter_css_js_companies',
        '/Filter out names that originated from CSS/i'               => 'filter_css_js_names',
        '/Obtain country name from affiliate/i'                      => 'country_affiliates',
        '/Obtain country name from co-hosted/i'                      => 'country_cohosts',
        '/Parse TLDs not associated.*default country/i'              => 'country_tld_default',
        '/Obtain country name from similar/i'                        => 'country_similar',
        '/Check the base URL.*affiliate/i'                           => 'check_affiliate_base',
        '/Only report domains that have content/i'                   => 'require_content',
        '/Skip TLDs.*wildcard DNS/i'                                 => 'skip_wildcard_tlds',
        '/Include entries considered search engines/i'               => 'include_search_engines',
        '/Include external leak sources/i'                           => 'include_external_leaks',
        '/wildcard DNS.*only attempt.*first common/i'                => 'wildcard_first_only',

        // Tool paths
        '/Path to.*where the.*file lives/i'                          => 'tool_path',
        '/Path to.*executable/i'                                     => 'tool_path',
        '/Path to.*binary/i'                                         => 'tool_path',
        '/Path to.*cli\.js/i'                                        => 'tool_path',
        '/Path to Python/i'                                          => 'python_path',
        '/Path to Ruby/i'                                            => 'ruby_path',
        '/Path to.*NodeJS/i'                                         => 'node_path',
        '/Path to your.*templates/i'                                 => 'templates_path',

        // Tool-specific
        '/Set WhatWeb aggression level/i'                            => 'aggression_level',
        '/Search all code repositories/i'                            => 'search_all_repos',
        '/Enable entropy checks/i'                                   => 'entropy_checks',
        '/SNMP communities to try/i'                                 => 'snmp_communities',

        // List URLs and configs
        '/block list\b/i'                                            => 'blocklist_url',
        '/AdBlockPlus block list/i'                                  => 'blocklist_url',
        '/The URL where the feed can be found/i'                     => 'feed_url',
        '/Different S3 endpoints/i'                                  => 's3_endpoints',
        '/Different Digital Ocean locations/i'                       => 'do_endpoints',
        '/List of suffixes to append/i'                              => 'bucket_suffixes',
        '/PGP public key server URL.*public key for/i'               => 'pgp_key_url',
        '/Backup PGP public key server URL.*public key for/i'        => 'pgp_key_url_backup',
        '/PGP public key server URL.*e-mail addresses/i'             => 'pgp_email_url',
        '/Backup PGP public key server URL.*e-mail addresses/i'      => 'pgp_email_url_backup',
        '/Google Custom Search Engine ID/i'                          => 'google_cse_id',
        '/API URL.*IntelligenceX/i'                                  => 'api_url',
        '/Search engine to use/i'                                    => 'search_engine',

        // String / binary analysis
        '/minimum length.*base64/i'                                  => 'min_base64_length',
        '/ensure it is at least this length/i'                       => 'min_string_length',
        '/Ignore strings with these characters/i'                    => 'ignore_chars',
        '/Stop reporting strings from a single binary/i'             => 'max_strings_per_binary',
        '/Use the dictionary to further reduce/i'                    => 'use_dictionary',
        '/Tighten results by expecting.*keyword/i'                   => 'require_domain_keyword',
        '/for affiliates.*look up the domain name/i'                 => 'affiliate_lookup_domain',

        // Name extraction sensitivity
        '/value between 0-100.*sensitivity.*name finder/i'           => 'name_sensitivity',
        '/Convert e-mail addresses.*firstname\.surname/i'            => 'convert_email_names',

        // Spider URL-related
        '/Try to fetch the containing folder/i'                      => 'folder_extensions',
        '/Try to fetch each of these files/i'                        => 'junk_filenames',
        '/Try those extensions against URLs/i'                       => 'target_extensions',

        // Netblock scan specifics
        '/If looking up owned netblocks.*maximum.*IPv4 netblock/i'   => 'max_netblock_ipv4',
        '/If looking up subnets.*maximum.*IPv4 subnet/i'             => 'max_subnet_ipv4',
        '/Maximum owned IPv4 netblock/i'                             => 'max_netblock_ipv4',
        '/Maximum owned IPv6 netblock/i'                             => 'max_netblock_ipv6',
        '/look-aside.*netmask size/i'                                => 'lookaside_bits',

        // Misc
        '/Exclude results from sites matching/i'                     => 'exclude_patterns',
        '/Retrieve IP HTTP headers/i'                                => 'retrieve_headers',
        '/How tightly to bound queries.*latitude/i'                  => 'geo_precision',
        '/Comma-separate the values/i'                               => 'wayback_days',
    ];

    /**
     * Get the CTI slug for a SpiderFoot module name.
     * Returns null if no mapping exists.
     */
    public static function toCtiSlug(string $sfpName): ?string
    {
        $key = strtolower(trim($sfpName));
        return self::$moduleMap[$key] ?? null;
    }

    /**
     * Get the SpiderFoot module name for a CTI slug.
     * Returns null if no mapping exists.
     */
    public static function toSfpName(string $ctiSlug): ?string
    {
        $slug = strtolower(trim($ctiSlug));
        $flipped = array_flip(self::$moduleMap);
        if (isset($flipped[$slug])) {
            return $flipped[$slug];
        }

        return null;
    }

    /**
     * Normalise a SpiderFoot option description into a snake_case setting key.
     * Returns null if no pattern matches.
     */
    public static function normaliseOptionKey(string $description): ?string
    {
        $desc = trim($description);
        foreach (self::$optionPatterns as $pattern => $key) {
            if (preg_match($pattern, $desc)) {
                return $key;
            }
        }
        return null;
    }

    /**
     * Get the full sfp_ → slug map.
     */
    public static function getModuleMap(): array
    {
        return self::$moduleMap;
    }

    /**
     * Get the CTI slugs in the same order as the SpiderFoot workbook rows.
     *
     * @return array<int,string>
     */
    public static function getOrderedCtiSlugs(): array
    {
        return array_values(self::$moduleMap);
    }

    /**
     * Get a slug => SpiderFoot display label map for frontend rendering.
     *
     * @return array<string,string>
     */
    public static function getDisplaySlugMap(): array
    {
        return array_flip(self::$moduleMap);
    }

    /**
     * Return a stable sort index map derived from the SpiderFoot workbook order.
     *
     * @return array<string,int>
     */
    public static function getOrderIndexMap(): array
    {
        $order = self::getOrderedCtiSlugs();
        $index = [];
        foreach ($order as $position => $slug) {
            $index[$slug] = $position;
        }
        return $index;
    }

    public static function compareCtiSlugs(string $left, string $right): int
    {
        $leftSlug = strtolower(trim($left));
        $rightSlug = strtolower(trim($right));

        if ($leftSlug === $rightSlug) {
            return 0;
        }

        if ($leftSlug === '_global') {
            return -1;
        }
        if ($rightSlug === '_global') {
            return 1;
        }

        $orderIndex = self::getOrderIndexMap();
        $leftIndex = $orderIndex[$leftSlug] ?? PHP_INT_MAX;
        $rightIndex = $orderIndex[$rightSlug] ?? PHP_INT_MAX;

        if ($leftIndex !== $rightIndex) {
            return $leftIndex <=> $rightIndex;
        }

        return strcasecmp($leftSlug, $rightSlug);
    }

    /**
     * @param array<int,string> $slugs
     * @return array<int,string>
     */
    public static function sortCtiSlugs(array $slugs): array
    {
        $sorted = array_values(array_unique(array_map(
            static fn($slug): string => strtolower(trim((string)$slug)),
            $slugs
        )));

        usort($sorted, [self::class, 'compareCtiSlugs']);
        return $sorted;
    }

    /**
     * Get the full option-pattern → key map.
     */
    public static function getOptionPatterns(): array
    {
        return self::$optionPatterns;
    }
}
