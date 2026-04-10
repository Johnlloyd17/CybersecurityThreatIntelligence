<?php
// =============================================================================
//  CTI — OSINT ENGINE (Orchestrator)
//  php/OsintEngine.php
//
//  Dispatches threat intelligence queries to individual module handlers.
//  Falls back to mock execution for modules without a real handler.
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/GlobalSettings.php';
require_once __DIR__ . '/EventTypes.php';

class OsintEngine
{
    /** Lower scores run earlier. */
    private static array $categoryPriority = [
        'threat'    => 10,
        'malware'   => 20,
        'network'   => 30,
        'blocklist' => 40,
        'dns'       => 50,
        'identity'  => 60,
        'infra'     => 70,
        'leaks'     => 80,
        'osint'     => 90,
        'tools'     => 100,
        'extract'   => 110,
        'search'    => 120,
        'crypto'    => 130,
    ];

    /** Fine-grained overrides for high-signal modules. */
    private static array $modulePriorityOverrides = [
        'virustotal'        => 5,
        'abuseipdb'         => 8,
        'abuse-ch'          => 10,
        'alienvault'        => 12,
        'shodan'            => 15,
        'dnsaudit'          => 20,
        'dns-zone-transfer' => 22,
        'dnstwist'          => 24,
        'nuclei'            => 26,
        'nmap'              => 28,
        'testssl'           => 30,
        'wafw00f'           => 32,
        'whatweb'           => 34,
        'trufflehog'        => 36,
    ];

    /**
     * Map of slug => module handler file path (relative to php/modules/).
     * Only modules with real API integrations are listed here.
     * All others fall back to mock execution.
     */
    private static array $handlerMap = [
        // ── Original 10 modules ──────────────────────────────────────────
        'virustotal'            => 'VirusTotalModule.php',
        'abuseipdb'             => 'AbuseIPDBModule.php',
        'shodan'                => 'ShodanModule.php',
        'alienvault'            => 'AlienVaultModule.php',
        'greynoise'             => 'GreyNoiseModule.php',
        'urlscan'               => 'UrlScanModule.php',
        'ipinfo'                => 'IPInfoModule.php',
        'securitytrails'        => 'SecurityTrailsModule.php',
        'haveibeenpwned'        => 'HaveIBeenPwnedModule.php',
        'abuse-ch'              => 'AbuseChModule.php',
        'apivoid'               => 'ApiVoidModule.php',

        // ── Free / No-Key modules ────────────────────────────────────────
        'threatcrowd'           => 'ThreatCrowdModule.php',
        'threatminer'           => 'ThreatMinerModule.php',
        'hackertarget'          => 'HackerTargetModule.php',
        'crt-sh'                => 'CrtShModule.php',
        'robtex'                => 'RobtexModule.php',
        'phishtank'             => 'PhishTankModule.php',
        'tor-exit-nodes'        => 'TorExitNodesModule.php',
        'isc-sans'              => 'IscSansModule.php',
        'blocklist-de'          => 'BlocklistDeModule.php',
        'greensnow'             => 'GreensnowModule.php',
        'threatfox'             => 'ThreatFoxModule.php',
        'phishstats'            => 'PhishStatsModule.php',
        'archive-org'           => 'ArchiveOrgModule.php',
        'dns-resolver'          => 'DnsResolverModule.php',
        'ssl-analyzer'          => 'SslAnalyzerModule.php',
        'cins-army'             => 'CinsArmyModule.php',
        'voipbl'                => 'VoipBlModule.php',
        'duckduckgo'            => 'DuckDuckGoModule.php',
        'openphish'             => 'OpenPhishModule.php',
        'wikipedia-edits'       => 'WikipediaEditsModule.php',
        'emerging-threats'      => 'EmergingThreatsModule.php',
        'vxvault'               => 'VxVaultModule.php',

        // ── DNSBL modules (all in DnsblModule.php) ───────────────────────
        'sorbs'                 => 'DnsblModule.php',
        'spamcop'               => 'DnsblModule.php',
        'spamhaus-zen'          => 'DnsblModule.php',
        'uceprotect'            => 'DnsblModule.php',
        'dronebl'               => 'DnsblModule.php',
        'surbl'                 => 'DnsblModule.php',

        // ── Key-Required modules (original batch) ────────────────────────
        'censys'                => 'CensysModule.php',
        'binaryedge'            => 'BinaryEdgeModule.php',
        'hybrid-analysis'       => 'HybridAnalysisModule.php',
        'xforce-exchange'       => 'XForceModule.php',
        'pulsedive'             => 'PulsediveModule.php',
        'host-io'               => 'HostIoModule.php',
        'hunter'                => 'HunterModule.php',
        'emailrep'              => 'EmailRepModule.php',
        'fullhunt'              => 'FullHuntModule.php',
        'onyphe'                => 'OnypheModule.php',
        'metadefender'          => 'MetaDefenderModule.php',
        'google-safebrowsing'   => 'GoogleSafeBrowsingModule.php',
        'ipqualityscore'        => 'IpQualityScoreModule.php',
        'leakix'                => 'LeakIxModule.php',
        'ipstack'               => 'IpStackModule.php',
        'ipapi'                 => 'IpApiModule.php',
        'viewdns'               => 'ViewDnsModule.php',
        'builtwith'             => 'BuiltWithModule.php',
        'whatcms'               => 'WhatCmsModule.php',
        'certspotter'           => 'CertSpotterModule.php',

        // ── Blocklist modules ────────────────────────────────────────────
        'botvrij'               => 'BotvrijModule.php',
        'coinblocker'           => 'CoinBlockerModule.php',
        'multiproxy'            => 'MultiproxyModule.php',
        'pgp-keyservers'        => 'PgpKeyserversModule.php',
        'steven-black-hosts'    => 'StevenBlackHostsModule.php',
        'zone-h'                => 'ZoneHModule.php',

        // ── DNS modules ─────────────────────────────────────────────────
        'crobat'                => 'CrobatModule.php',
        'dns-bruteforce'        => 'DnsBruteforceModule.php',
        'dns-raw'               => 'DnsRawModule.php',
        'dnsgrep'               => 'DnsGrepModule.php',
        'mnemonic-pdns'         => 'MnemonicPdnsModule.php',
        'open-pdns'             => 'OpenPdnsModule.php',
        'opennic'               => 'OpenNicModule.php',
        'tld-searcher'          => 'TldSearcherModule.php',
        'dns-lookaside'         => 'DnsLookasideModule.php',
        'dns-zone-transfer'     => 'DnsZoneTransferModule.php',
        'dnsdb'                 => 'DnsdbModule.php',
        'dnstwist'              => 'DnsTwistModule.php',
        'dnsaudit'              => 'DnsAuditModule.php',

        // ── OSINT / Threat modules ──────────────────────────────────────
        'ahmia'                 => 'AhmiaModule.php',
        'commoncrawl'           => 'CommonCrawlModule.php',
        'darksearch'            => 'DarksearchModule.php',
        'github'                => 'GithubOsintModule.php',
        'grep-app'              => 'GrepAppModule.php',
        'searchcode'            => 'SearchcodeModule.php',
        'stackoverflow'         => 'StackOverflowModule.php',
        'flickr'                => 'FlickrModule.php',
        'maltiverse'            => 'MaltiverseModule.php',
        'talos-intelligence'    => 'TalosIntelModule.php',
        'cybercrime-tracker'    => 'CybercrimeTrackerModule.php',
        'alienvault-ip-rep'     => 'AlienVaultIpRepModule.php',
        'onion-link'            => 'OnionLinkModule.php',
        'onionsearchengine'     => 'OnionSearchEngineModule.php',

        // ── Free tool / extract / infra modules ─────────────────────────
        'port-scanner-tcp'      => 'PortScannerModule.php',
        'wappalyzer'            => 'WappalyzerModule.php',
        'whatweb'               => 'WhatWebModule.php',
        'wafw00f'               => 'Wafw00fModule.php',
        'account-finder'        => 'AccountFinderModule.php',
        'retire-js'             => 'RetireJsModule.php',
        'scylla'                => 'ScyllaModule.php',
        'koodous'               => 'KoodousModule.php',
        'botscout'              => 'BotScoutModule.php',
        'cleantalk'             => 'CleanTalkModule.php',
        'fortiguard'            => 'FortiGuardModule.php',
        's3-finder'             => 'S3FinderModule.php',
        'azure-blob-finder'     => 'AzureBlobFinderModule.php',
        'gcs-finder'            => 'GcsFinderModule.php',
        'opencorporates'        => 'OpenCorporatesModule.php',
        'crxcavator'            => 'CrxcavatorModule.php',
        'cross-referencer'      => 'CrossReferencerModule.php',
        'do-space-finder'       => 'DoSpaceFinderModule.php',
        'base64-decoder'        => 'Base64DecoderModule.php',
        'company-name-extractor'=> 'CompanyNameExtractorModule.php',
        'country-name-extractor'=> 'CountryNameExtractorModule.php',
        'interesting-file-finder'=> 'InterestingFileFinderModule.php',
        'human-name-extractor'  => 'HumanNameExtractorModule.php',

        // ── Key-required modules (extended batch) ───────────────────────
        'chaos'                 => 'ChaosModule.php',
        'circl-lu'              => 'CirclLuModule.php',
        'jsonwhois'             => 'JsonWhoisModule.php',
        'riddler'               => 'RiddlerModule.php',
        'whoisology'            => 'WhoisologyModule.php',
        'whoxy'                 => 'WhoxyModule.php',
        'zetalytics'            => 'ZetalyticsModule.php',
        'abstractapi'           => 'AbstractApiModule.php',
        'clearbit'              => 'ClearbitModule.php',
        'emailcrawlr'           => 'EmailCrawlrModule.php',
        'fullcontact'           => 'FullContactModule.php',
        'nameapi'               => 'NameApiModule.php',
        'numverify'             => 'NumverifyModule.php',
        'project-honeypot'      => 'ProjectHoneypotModule.php',
        'seon'                  => 'SeonModule.php',
        'snov'                  => 'SnovModule.php',
        'social-links'          => 'SocialLinksModule.php',
        'social-media-finder'   => 'SocialMediaFinderModule.php',
        'textmagic'             => 'TextMagicModule.php',
        'twilio'                => 'TwilioModule.php',
        'c99'                   => 'C99Module.php',
        'etherscan'             => 'EtherscanModule.php',
        'grayhat-warfare'       => 'GrayhatWarfareModule.php',
        'networksdb'            => 'NetworksDbModule.php',
        'bitcoin-whos-who'      => 'BitcoinWhosWhoModule.php',
        'bitcoinabuse'          => 'BitcoinAbuseModule.php',
        'dehashed'              => 'DehashedModule.php',
        'iknowwhatyoudownload'  => 'IKnowWhatYouDownloadModule.php',
        'leak-lookup'           => 'LeakLookupModule.php',
        'trashpanda'            => 'TrashpandaModule.php',
        'abusix'                => 'AbusixModule.php',
        'bad-packets'           => 'BadPacketsModule.php',
        'focsec'                => 'FocsecModule.php',
        'fraudguard'            => 'FraudguardModule.php',
        'ipregistry'            => 'IpRegistryModule.php',
        'neutrinoapi'           => 'NeutrinoApiModule.php',

        // ── Search / Intel modules ──────────────────────────────────────
        'bing'                  => 'BingModule.php',
        'bing-shared-ips'       => 'BingSharedIpsModule.php',
        'google'                => 'GoogleSearchModule.php',
        'google-maps'           => 'GoogleMapsModule.php',
        'intelligencex'         => 'IntelligenceXModule.php',
        'pastebin'              => 'PastebinModule.php',
        'recon-dev'             => 'ReconDevModule.php',
        'riskiq'                => 'RiskIqModule.php',
        'spyonweb'              => 'SpyOnWebModule.php',
        'spyse'                 => 'SpyseModule.php',
        'wigle'                 => 'WigleModule.php',
        'spur'                  => 'SpurModule.php',

        // ── Security scanning modules ───────────────────────────────────
        'cmseek'                => 'CmseekModule.php',
        'nbtscan'               => 'NbtscanModule.php',
        'nmap'                  => 'NmapModule.php',
        'nuclei'                => 'NucleiModule.php',
        'onesixtyone'           => 'OneSixtyOneModule.php',
        'snallygaster'          => 'SnallygasterModule.php',
        'testssl'               => 'TestSslModule.php',
        'trufflehog'            => 'TruffleHogModule.php',
        'web-spider'            => 'WebSpiderModule.php',

        // ── Extract / Utility modules ───────────────────────────────────
        'binary-string-extractor'=> 'BinaryStringExtractorModule.php',
        'file-metadata-extractor'=> 'FileMetadataExtractorModule.php',
        'junk-file-finder'      => 'JunkFileFinderModule.php',
        'adblock-check'         => 'AdblockCheckModule.php',
        'custom-threat-feed'    => 'CustomThreatFeedModule.php',
        'malwarepatrol'         => 'MalwarePatrolModule.php',

        // ── Darknet / Special modules ───────────────────────────────────
        'torch'                 => 'TorchModule.php',
        'wikileaks'             => 'WikileaksModule.php',

        // ── NEW: Threat Intelligence Platforms ──────────────────────────
        'misp'                  => 'MispModule.php',
        'opencti'               => 'OpenCtiModule.php',
        'yara-scanner'          => 'YaraScannerModule.php',
        'intelx'                => 'IntelXModule.php',
        'zoomeye'               => 'ZoomEyeModule.php',

        // ── NEW: Infrastructure / Geolocation ──────────────────────────
        'bgpview'               => 'BgpViewModule.php',
        'ip2location'           => 'Ip2LocationModule.php',
        'maxmind'               => 'MaxMindModule.php',
        'domaintools'           => 'DomainToolsModule.php',
        'passivedns'            => 'PassiveDnsModule.php',
        'dnsdumpster'           => 'DnsDumpsterModule.php',

        // ── NEW: Breach / Leak / Dark Web ──────────────────────────────
        'leakcheck'             => 'LeakCheckModule.php',
        'snusbase'              => 'SnusbaseModule.php',
        'binaryedge-torrents'   => 'BinaryEdgeTorrentsModule.php',
        'phonebook'             => 'PhonebookModule.php',
        'skymem'                => 'SkymemModule.php',
        'onionoo'               => 'OnionooModule.php',
    ];

    /**
     * Query multiple APIs for a given target.
     *
     * @param  string $queryType   One of: domain, ip, url, hash, email, cve
     * @param  string $queryValue  The target to query
     * @param  array  $slugs       Array of API slugs to query
     * @return array  Array of result arrays (matching query.php response format)
     */
    /** Maximum total query time (seconds) before skipping remaining modules.
     *  In background mode PHP's execution time is unlimited; this constant
     *  acts as a safeguard against a single runaway scan consuming hours. */
    private const MAX_QUERY_TIME = 3600;

    /**
     * Query multiple APIs for a given target.
     *
     * Applies all Global Settings before dispatching:
     *  - http_timeout + user_agent + DNS resolver + proxy → HttpClient
     *  - max_concurrent_modules  → parallel proc_open workers (SpiderFoot-style)
     *  - debug                   → verbose error_log output
     *  - max_bytes_per_element   → truncate result summaries (Storage setting)
     *
     * @param  string $queryType   One of: domain, ip, url, hash, email, cve …
     * @param  string $queryValue  The target to query
     * @param  array  $slugs       Array of API slugs to query
     * @param  int    $scanId      Optional scan DB ID.  When provided, the engine
     *                             checks the scan status between module batches and
     *                             stops early if the scan has been aborted — mirroring
     *                             SpiderFoot's SpiderFootPlugin::checkForStop() pattern.
     * @return array  Array of result arrays (matching query.php response format)
     */
    public static function query(
        string $queryType,
        string $queryValue,
        array $slugs,
        int $scanId = 0,
        ?array $snapshotModuleSettings = null,
        ?string $rootQueryType = null,
        ?string $rootQueryValue = null
    ): array
    {
        if (empty($slugs)) return [];

        $rootQueryType = $rootQueryType ?: $queryType;
        $rootQueryValue = $rootQueryValue ?: $queryValue;

        // ── Load Global Settings and push to HTTP layer ─────────────────
        GlobalSettings::load();
        HttpClient::applyGlobalSettings();

        $maxConcurrent      = GlobalSettings::maxConcurrentModules();
        $maxBytesPerElement = GlobalSettings::maxBytesPerElement();
        $debugMode          = GlobalSettings::isDebug();

        if ($debugMode) {
            error_log('[OsintEngine|debug] query start — type=' . $queryType
                . ' target=' . $queryValue
                . ' modules=' . count($slugs)
                . ' concurrent=' . $maxConcurrent
                . ' timeout=' . GlobalSettings::httpTimeout() . 's'
                . ' max_bytes=' . $maxBytesPerElement);
        }

        $queryStart = microtime(true);

        // Load all API configs for the requested slugs in one query
        $configs = self::loadApiConfigs($slugs);
        $slugs = self::sortSlugsByPriority($slugs, $configs);

        // ── Choose execution strategy ────────────────────────────────────
        $canParallel = (
            $maxConcurrent > 1
            && function_exists('proc_open')
            && file_exists(__DIR__ . '/scan_worker.php')
        );

        if ($canParallel) {
            $results = self::executeParallel(
                $queryType, $queryValue, $slugs, $configs,
                $maxConcurrent, $debugMode, $queryStart, $scanId,
                $snapshotModuleSettings,
                $rootQueryType,
                $rootQueryValue
            );
        } else {
            $results = self::executeSequential(
                $queryType, $queryValue, $slugs, $configs,
                $debugMode, $queryStart, $scanId,
                $snapshotModuleSettings,
                $rootQueryType,
                $rootQueryValue
            );
        }

        // ── Storage setting: truncate summaries ──────────────────────────
        if ($maxBytesPerElement > 0) {
            foreach ($results as &$r) {
                if (isset($r['summary']) && mb_strlen($r['summary'], 'UTF-8') > $maxBytesPerElement) {
                    $r['summary'] = mb_substr($r['summary'], 0, $maxBytesPerElement - 1, 'UTF-8') . "\u{2026}";
                }
            }
            unset($r);
        }

        if ($debugMode) {
            $elapsed = round(microtime(true) - $queryStart, 2);
            error_log('[OsintEngine|debug] query finished — results=' . count($results) . ' elapsed=' . $elapsed . 's');
        }

        return $results;
    }

    // =========================================================================
    //  MULTI-PASS ENRICHMENT LOOP  (SpiderFoot-style event chaining)
    //
    //  After the initial query pass, the engine inspects every successful
    //  result for "discoveries" — sub-entities (IPs, domains, hostnames, etc.)
    //  extracted by the module from the raw API response.
    //
    //  Each unique discovery becomes a new query target for the next pass.
    //  The loop continues until:
    //    - No new discoveries are produced, OR
    //    - MAX_ENRICHMENT_PASSES is reached, OR
    //    - MAX_QUERY_TIME budget is exhausted, OR
    //    - The scan is aborted by the user.
    //
    //  A "visited" set prevents re-querying the same <type,value> pair.
    //  This mirrors SpiderFoot's self.results[eventData] = True dedup pattern.
    // =========================================================================

    /** Maximum number of enrichment passes beyond the initial query. */
    private const MAX_ENRICHMENT_PASSES = 25;

    /** Maximum total discoveries to enrich per scan (prevents explosion). */
    private const MAX_ENRICHMENT_TARGETS = 5000;

    /**
     * Run an initial query, then iteratively enrich discovered sub-entities.
     *
     * @param  string $queryType   Original target type
     * @param  string $queryValue  Original target value
     * @param  array  $slugs       Selected module slugs
     * @param  int    $scanId      Scan ID for abort checks
     * @return array  All result arrays (initial + enrichment passes)
     */
    public static function queryWithEnrichment(
        string $queryType,
        string $queryValue,
        array  $slugs,
        int    $scanId = 0,
        ?array $snapshotModuleSettings = null
    ): array {
        $allResults = [];
        $visited    = [];                       // "type:value" => true
        $queryStart = microtime(true);
        $debugMode  = GlobalSettings::isDebug();

        // Mark the original target as visited
        $visited["{$queryType}:{$queryValue}"] = true;

        // ── Pass 0: initial query ────────────────────────────────────────
        $passResults = self::query(
            $queryType,
            $queryValue,
            $slugs,
            $scanId,
            $snapshotModuleSettings,
            $queryType,
            $queryValue
        );

        // Tag each result with pass number
        foreach ($passResults as &$r) {
            $r['enrichment_pass'] = 0;
            $r['source_ref']      = 'ROOT';
        }
        unset($r);
        $allResults = array_merge($allResults, $passResults);

        // ── Enrichment passes 1..N ───────────────────────────────────────
        $totalEnriched = 0;

        for ($pass = 1; $pass <= self::MAX_ENRICHMENT_PASSES; $pass++) {
            // Abort check
            if ($scanId > 0 && self::isScanAborted($scanId)) {
                break;
            }

            // Time budget check
            if ((microtime(true) - $queryStart) > self::MAX_QUERY_TIME) {
                if ($debugMode) {
                    error_log("[OsintEngine|enrich] Time budget exceeded, stopping after pass " . ($pass - 1));
                }
                break;
            }

            // Extract new discoveries from previous pass results
            $newTargets = self::extractDiscoveries($passResults, $visited);

            if (empty($newTargets)) {
                if ($debugMode) {
                    error_log("[OsintEngine|enrich] No new discoveries at pass {$pass}, enrichment complete.");
                }
                break;
            }

            // Cap total enrichment targets
            $remaining  = self::MAX_ENRICHMENT_TARGETS - $totalEnriched;
            if ($remaining <= 0) break;
            $newTargets = array_slice($newTargets, 0, $remaining);
            $totalEnriched += count($newTargets);

            if ($debugMode) {
                error_log("[OsintEngine|enrich] Pass {$pass}: enriching "
                    . count($newTargets) . " new targets (total enriched: {$totalEnriched})");
            }

            $passResults = [];

            foreach ($newTargets as $target) {
                $tType  = $target['query_type'];
                $tValue = $target['value'];
                $tRef   = $target['source_ref'];
                $parentSlug = strtolower((string)($target['parent_slug'] ?? ''));

                // Pick modules that support this query type from the user's selection
                $eligibleSlugs = self::filterSlugsByQueryType($slugs, $tType);

                // DNSAudit discovers many subdomains; avoid recursively re-running
                // DNSAudit on each discovered host (causes very long scan runtimes).
                // Keep other eligible modules so cross-module enrichment still works.
                if ($parentSlug === 'dnsaudit') {
                    $eligibleSlugs = array_values(array_filter(
                        $eligibleSlugs,
                        static fn(string $slug): bool => strtolower($slug) !== 'dnsaudit'
                    ));
                }

                if (empty($eligibleSlugs)) continue;

                // Abort check per target
                if ($scanId > 0 && self::isScanAborted($scanId)) break;

                // Enforce global scan time budget inside target loop.
                if ((microtime(true) - $queryStart) > self::MAX_QUERY_TIME) {
                    if ($debugMode) {
                        error_log('[OsintEngine|enrich] Time budget exceeded inside target loop, stopping enrichment.');
                    }
                    break 2;
                }

                // Update enrichment context for evidence tagging (Parity System)
                HttpClient::setModuleContext('', $pass, $tRef);

                $targetResults = self::query(
                    $tType,
                    $tValue,
                    $eligibleSlugs,
                    $scanId,
                    $snapshotModuleSettings,
                    $queryType,
                    $queryValue
                );

                // Tag results with enrichment metadata
                foreach ($targetResults as &$r) {
                    $r['enrichment_pass'] = $pass;
                    $r['source_ref']      = $tRef;
                    $r['enriched_from']   = $tValue;
                }
                unset($r);

                $passResults  = array_merge($passResults, $targetResults);
                $allResults   = array_merge($allResults, $targetResults);
            }
        }

        if ($debugMode) {
            $elapsed = round(microtime(true) - $queryStart, 2);
            error_log("[OsintEngine|enrich] Total: " . count($allResults) . " results across "
                . min($pass, self::MAX_ENRICHMENT_PASSES + 1) . " passes, {$totalEnriched} enriched targets, {$elapsed}s");
        }

        return $allResults;
    }

    /**
     * Extract enrichable discoveries from a set of results, skipping visited.
     *
     * @return array<int, array{
     *   query_type: string,
     *   value: string,
     *   event_type: string,
     *   source_ref: string,
     *   parent_slug: string
     * }>
     */
    private static function extractDiscoveries(array $results, array &$visited): array
    {
        $targets = [];

        foreach ($results as $r) {
            if (!($r['success'] ?? true)) continue;

            $discoveries = $r['discoveries'] ?? [];
            $parentSlug  = $r['api'] ?? 'unknown';

            foreach ($discoveries as $disc) {
                $eventType = $disc['type']  ?? '';
                $value     = trim($disc['value'] ?? '');
                if ($value === '' || !$eventType) continue;

                $queryType = EventTypes::toQueryType($eventType);
                if (!$queryType) continue;

                $key = "{$queryType}:{$value}";
                if (isset($visited[$key])) continue;

                $visited[$key] = true;
                $targets[] = [
                    'query_type' => $queryType,
                    'value'      => $value,
                    'event_type' => $eventType,
                    'source_ref' => "{$parentSlug}:{$value}",
                    'parent_slug'=> $parentSlug,
                ];
            }
        }

        return $targets;
    }

    /**
     * Filter module slugs to only those that support the given query type.
     * Uses the api_configs.supported_types column.
     */
    private static function filterSlugsByQueryType(array $slugs, string $queryType): array
    {
        $configs = self::loadApiConfigs($slugs);
        $eligible = [];

        foreach ($slugs as $slug) {
            $config = $configs[$slug] ?? null;
            if (!$config) continue;

            $supported = $config['supported_types'] ?? null;
            if (is_string($supported)) {
                $supported = json_decode($supported, true);
            }
            // If no supported_types specified, module accepts all types
            if (!is_array($supported) || empty($supported) || in_array($queryType, $supported, true)) {
                $eligible[] = $slug;
            }
        }

        return $eligible;
    }

    // =========================================================================
    //  SEQUENTIAL EXECUTION (max_concurrent_modules = 1, or proc_open unavailable)
    // =========================================================================

    private static function executeSequential(
        string $queryType,
        string $queryValue,
        array  $slugs,
        array  $configs,
        bool   $debugMode,
        float  $queryStart,
        int    $scanId = 0,
        ?array $snapshotModuleSettings = null,
        ?string $rootQueryType = null,
        ?string $rootQueryValue = null
    ): array {
        $results = [];

        foreach ($slugs as $slug) {
            // ── SpiderFoot-style abort check (checkForStop equivalent) ──
            if ($scanId > 0 && self::isScanAborted($scanId)) {
                error_log('[OsintEngine] Scan #' . $scanId . ' aborted, stopping sequential execution at ' . $slug);
                break;
            }
            $config = $configs[$slug] ?? null;
            if (!$config) continue;

            $apiName = $config['name'];
            $apiKey  = $config['api_key'] ?? '';
            $baseUrl = $config['base_url'] ?? '';

            // ── Check if module supports this query type ────────────────
            $supportedTypes = $config['supported_types'] ?? null;
            if (is_string($supportedTypes)) {
                $supportedTypes = json_decode($supportedTypes, true);
            }
            if (is_array($supportedTypes) && !empty($supportedTypes) && !in_array($queryType, $supportedTypes, true)) {
                $results[] = OsintResult::error(
                    $slug, $apiName,
                    "Module does not support query type '{$queryType}'"
                )->toArray();
                continue;
            }

            // Check time budget — skip remaining modules if exceeded
            $elapsed = microtime(true) - $queryStart;
            if ($elapsed > self::MAX_QUERY_TIME) {
                error_log("[OsintEngine] Time budget exceeded ({$elapsed}s), skipping {$slug}");
                $results[] = OsintResult::error($slug, $apiName, 'Skipped: query time limit reached')->toArray();
                continue;
            }

            // Check if a real handler exists and has key (if required)
            $hasHandler = isset(self::$handlerMap[$slug]);
            $hasKey     = ($apiKey !== '' || !$config['requires_key']);

            if ($debugMode) {
                error_log("[OsintEngine|debug] executing {$slug} — handler={$hasHandler} key={$hasKey}");
            }

            // Set module context for evidence tagging (Parity System)
            HttpClient::setModuleContext($slug);

            if ($hasHandler && $hasKey) {
                try {
                    $moduleResults = self::executeModule(
                        $slug,
                        $queryType,
                        $queryValue,
                        $apiKey,
                        $baseUrl,
                        $apiName,
                        $snapshotModuleSettings[$slug] ?? null,
                        $rootQueryType,
                        $rootQueryValue
                    );
                } catch (\Throwable $e) {
                    error_log("[OsintEngine] Module {$slug} threw exception: " . $e->getMessage());
                    $moduleResults = [OsintResult::error($slug, $apiName, $e->getMessage())];
                }
            } elseif ($hasHandler && !$hasKey) {
                $moduleResults = [OsintResult::error($slug, $apiName, 'API key not configured')];
            } else {
                $moduleResults = [OsintResult::error($slug, $apiName, 'No module handler implemented')];
            }

            foreach ($moduleResults as $r) {
                $results[] = $r->toArray();
            }
        }

        return $results;
    }

    // =========================================================================
    //  PARALLEL EXECUTION (max_concurrent_modules > 1, proc_open available)
    // =========================================================================

    /**
     * Spawn up to $maxConcurrent child PHP workers simultaneously, each
     * running one OSINT module, and collect their JSON results when done.
     * This mirrors SpiderFoot's multi-threaded module runner behaviour.
     */
    private static function executeParallel(
        string $queryType,
        string $queryValue,
        array  $slugs,
        array  $configs,
        int    $maxConcurrent,
        bool   $debugMode,
        float  $queryStart,
        int    $scanId = 0,
        ?array $snapshotModuleSettings = null,
        ?string $rootQueryType = null,
        ?string $rootQueryValue = null
    ): array {
        $results      = [];
        $runnableTasks = [];

        // Classify slugs: pre-filter unsupported types and missing keys/handlers
        foreach ($slugs as $slug) {
            $config = $configs[$slug] ?? null;
            if (!$config) continue;

            $apiName = $config['name'];
            $apiKey  = $config['api_key'] ?? '';
            $baseUrl = $config['base_url'] ?? '';

            $supportedTypes = $config['supported_types'] ?? null;
            if (is_string($supportedTypes)) {
                $supportedTypes = json_decode($supportedTypes, true);
            }
            if (is_array($supportedTypes) && !empty($supportedTypes)
                && !in_array($queryType, $supportedTypes, true)) {
                $results[] = OsintResult::error(
                    $slug, $apiName,
                    "Module does not support query type '{$queryType}'"
                )->toArray();
                continue;
            }

            if (!isset(self::$handlerMap[$slug])) {
                $results[] = OsintResult::error($slug, $apiName, 'No module handler implemented')->toArray();
                continue;
            }

            if ($apiKey === '' && $config['requires_key']) {
                $results[] = OsintResult::error($slug, $apiName, 'API key not configured')->toArray();
                continue;
            }

            $runnableTasks[] = [
                'slug'    => $slug,
                'apiName' => $apiName,
                'apiKey'  => $apiKey,
                'baseUrl' => $baseUrl,
            ];
        }

        $workerScript = __DIR__ . '/scan_worker.php';
        $phpBinary    = self::resolvePhpBinary();

        // Process tasks in batches of $maxConcurrent
        foreach (array_chunk($runnableTasks, $maxConcurrent) as $batch) {
            // ── SpiderFoot-style abort check between batches ──────────────
            if ($scanId > 0 && self::isScanAborted($scanId)) {
                error_log('[OsintEngine] Scan #' . $scanId . ' aborted, stopping parallel execution before next batch');
                break;
            }

            $elapsed = microtime(true) - $queryStart;
            if ($elapsed > self::MAX_QUERY_TIME) {
                foreach ($batch as $task) {
                    $results[] = OsintResult::error(
                        $task['slug'], $task['apiName'],
                        'Skipped: query time limit reached'
                    )->toArray();
                }
                break;
            }

            $handles = [];

            // ── Spawn all workers in this batch simultaneously ───────────
            foreach ($batch as $task) {
                $workerSettings = $snapshotModuleSettings[$task['slug']] ?? null;
                $payload = json_encode([
                    'slug'            => $task['slug'],
                    'query_type'      => $queryType,
                    'query_value'     => $queryValue,
                    'root_query_type' => $rootQueryType ?: $queryType,
                    'root_query_value'=> $rootQueryValue ?: $queryValue,
                    'api_key'         => $task['apiKey'],
                    'base_url'        => $task['baseUrl'],
                    'api_name'        => $task['apiName'],
                    'debug'           => $debugMode,
                    'module_settings' => $workerSettings,
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

                $descriptors = [
                    0 => ['pipe', 'r'],   // stdin
                    1 => ['pipe', 'w'],   // stdout
                    2 => ['pipe', 'w'],   // stderr
                ];

                $pipes = [];
                $proc  = @proc_open(
                    escapeshellarg($phpBinary) . ' ' . escapeshellarg($workerScript),
                    $descriptors,
                    $pipes
                );

                if (is_resource($proc)) {
                    fwrite($pipes[0], $payload);
                    fclose($pipes[0]);

                    // Generous read timeout so a slow module doesn't block
                    $readTimeout = GlobalSettings::httpTimeout() + 30;
                    stream_set_timeout($pipes[1], $readTimeout);

                    $handles[$task['slug']] = [
                        'proc'     => $proc,
                        'stdout'   => $pipes[1],
                        'stderr'   => $pipes[2],
                        'api_name' => $task['apiName'],
                        'api_key'  => $task['apiKey'],
                        'base_url' => $task['baseUrl'],
                    ];

                    if ($debugMode) {
                        error_log('[OsintEngine|debug] spawned worker for ' . $task['slug']);
                    }
                } else {
                    // proc_open failed — fall back to inline sequential execution
                    error_log('[OsintEngine] proc_open failed for ' . $task['slug'] . ', falling back to inline');
                    try {
                        $moduleResults = self::executeModule(
                            $task['slug'], $queryType, $queryValue,
                            $task['apiKey'], $task['baseUrl'], $task['apiName'],
                            $workerSettings,
                            $rootQueryType,
                            $rootQueryValue
                        );
                    } catch (\Throwable $e) {
                        $moduleResults = [OsintResult::error($task['slug'], $task['apiName'], $e->getMessage())];
                    }
                    foreach ($moduleResults as $r) {
                        $results[] = $r->toArray();
                    }
                }
            }

            // ── Collect results once all batch workers finish ────────────
            foreach ($handles as $slug => $handle) {
                $output    = stream_get_contents($handle['stdout']);
                $errOutput = stream_get_contents($handle['stderr']);

                fclose($handle['stdout']);
                fclose($handle['stderr']);
                $exitCode = proc_close($handle['proc']);

                // Always log stderr when the worker produced non-JSON output
                $moduleResults = json_decode($output ?? '', true);
                if (is_array($moduleResults)) {
                    foreach ($moduleResults as $r) {
                        if (is_array($r)) {
                            $results[] = $r;
                        }
                    }
                } else {
                    // Log stderr unconditionally so the cause is always visible
                    if ($errOutput !== '') {
                        error_log("[OsintEngine] worker stderr [{$slug}]: " . trim($errOutput));
                    }
                    error_log('[OsintEngine] invalid worker output for '
                        . $slug . ' (exit=' . $exitCode . '): ' . substr($output ?? '', 0, 300));

                    // Fall back to inline execution rather than returning an error
                    try {
                        $fallbackResults = self::executeModule(
                            $slug, $queryType, $queryValue,
                            $handle['api_key'], $handle['base_url'], $handle['api_name'],
                            $snapshotModuleSettings[$slug] ?? null,
                            $rootQueryType,
                            $rootQueryValue
                        );
                        foreach ($fallbackResults as $r) {
                            $results[] = $r->toArray();
                        }
                    } catch (\Throwable $e) {
                        $results[] = OsintResult::error(
                            $slug, $handle['api_name'],
                            'Worker failed and inline fallback also failed: ' . $e->getMessage()
                        )->toArray();
                    }
                }
                if ($debugMode && $errOutput !== '') {
                    error_log("[OsintEngine|debug] worker stderr [{$slug}]: " . trim($errOutput));
                }
            }
        }

        return $results;
    }

    /**
     * Map DNSBL slugs to their specific subclass names (all in DnsblModule.php).
     */
    private static array $dnsblClassMap = [
        'sorbs'        => 'SorbsModule',
        'spamcop'      => 'SpamcopModule',
        'spamhaus-zen' => 'SpamhausZenModule',
        'uceprotect'   => 'UceprotectModule',
        'dronebl'      => 'DroneBLModule',
        'surbl'        => 'SurblModule',
    ];

    /**
     * Execute a real module handler.
     * Returns an array of OsintResult objects (most modules return one; modules
     * like VirusTotal can return multiple — one per discovered data element).
     *
     * @return OsintResult[]
     */
    /**
     * Execute a single module handler and return its OsintResult[]
     * Made public so scan_worker.php can call it directly in parallel workers.
     */
    public static function executeModule(
        string $slug,
        string $queryType,
        string $queryValue,
        string $apiKey,
        string $baseUrl,
        string $apiName,
        ?array $snapshotSettings = null,
        ?string $rootQueryType = null,
        ?string $rootQueryValue = null
    ): array
    {
        $handlerFile = __DIR__ . '/modules/' . self::$handlerMap[$slug];

        if (!file_exists($handlerFile)) {
            error_log("[OsintEngine] Handler file not found: {$handlerFile}");
            return [self::mockExecute($slug, $apiName, $queryType, $queryValue)];
        }

        require_once $handlerFile;

        // DNSBL modules share one file with subclasses per slug
        if (isset(self::$dnsblClassMap[$slug])) {
            $className = self::$dnsblClassMap[$slug];
        } else {
            $className = pathinfo(self::$handlerMap[$slug], PATHINFO_FILENAME);
        }

        if (!class_exists($className)) {
            error_log("[OsintEngine] Handler class not found: {$className}");
            return [self::mockExecute($slug, $apiName, $queryType, $queryValue)];
        }

        $handler = new $className();

        // Inject module settings — prefer frozen snapshot from config_snapshot,
        // fall back to live DB settings.  This ensures mid-scan setting changes
        // by the user do not affect a running scan.
        if (is_array($snapshotSettings)) {
            $settings = $snapshotSettings;
        } else {
            $settings = self::loadModuleSettings($slug);
        }
        $settings['__query_type'] = $queryType;
        $settings['__query_value'] = $queryValue;
        $settings['__root_query_type'] = $rootQueryType ?: $queryType;
        $settings['__root_query_value'] = $rootQueryValue ?: $queryValue;
        if (method_exists($handler, 'setSettings')) {
            $handler->setSettings($settings);
        }

        $result = $handler->execute($queryType, $queryValue, $apiKey, $baseUrl);

        // Normalize: modules may return a single OsintResult or OsintResult[]
        if ($result instanceof OsintResult) {
            return [$result];
        }
        return is_array($result) ? $result : [OsintResult::error($slug, $apiName, 'Invalid result from handler')];
    }

    /**
     * Check whether a real module handler exists for a slug.
     * This allows newer orchestration layers to avoid falling back to the
     * mock execution path used by legacy direct calls.
     */
    public static function hasHandler(string $slug): bool
    {
        return isset(self::$handlerMap[$slug]);
    }

    /**
     * Return all module slugs that already have a real CTI-native handler.
     *
     * @return array<int, string>
     */
    public static function getHandlerSlugs(): array
    {
        $slugs = array_keys(self::$handlerMap);
        sort($slugs, SORT_STRING);
        return $slugs;
    }

    /**
     * Load saved module settings from the database for a given slug.
     * Returns key => value map with string values (cast by module as needed).
     */
    private static function loadModuleSettings(string $slug): array
    {
        try {
            $rows = DB::query(
                'SELECT setting_key, setting_value FROM module_settings WHERE module_slug = :slug',
                [':slug' => $slug]
            );
            $settings = [];
            foreach ($rows as $row) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
            return $settings;
        } catch (\Throwable $e) {
            error_log("[OsintEngine] Failed to load settings for {$slug}: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Run a health check for a single module.
     */
    public static function healthCheck(string $slug): array
    {
        $config = self::loadApiConfig($slug);
        if (!$config) {
            return ['status' => 'down', 'error' => 'API not found', 'latency_ms' => 0];
        }

        $apiKey  = $config['api_key'] ?? '';
        $baseUrl = $config['base_url'] ?? '';

        if (!isset(self::$handlerMap[$slug])) {
            return ['status' => 'unknown', 'error' => 'No handler available', 'latency_ms' => 0];
        }

        if ($config['requires_key'] && $apiKey === '') {
            return ['status' => 'down', 'error' => 'API key not configured', 'latency_ms' => 0];
        }

        try {
            $handlerFile = __DIR__ . '/modules/' . self::$handlerMap[$slug];
            if (!file_exists($handlerFile)) {
                return ['status' => 'unknown', 'error' => 'Handler file missing', 'latency_ms' => 0];
            }

            require_once $handlerFile;
            $className = pathinfo(self::$handlerMap[$slug], PATHINFO_FILENAME);

            if (!class_exists($className) || !method_exists($className, 'healthCheck')) {
                return ['status' => 'unknown', 'error' => 'Health check not implemented', 'latency_ms' => 0];
            }

            $handler = new $className();
            $result  = $handler->healthCheck($apiKey, $baseUrl);

            // Update DB
            DB::execute(
                "UPDATE api_configs SET health_status = :status, last_health_check = NOW() WHERE slug = :slug",
                [':status' => $result['status'], ':slug' => $slug]
            );

            return $result;
        } catch (\Throwable $e) {
            error_log("[OsintEngine] Health check failed for {$slug}: " . $e->getMessage());
            DB::execute(
                "UPDATE api_configs SET health_status = 'down', last_health_check = NOW() WHERE slug = :slug",
                [':slug' => $slug]
            );
            return ['status' => 'down', 'error' => $e->getMessage(), 'latency_ms' => 0];
        }
    }

    /**
     * Load API configs for multiple slugs.
     */
    public static function loadApiConfigs(array $slugs): array
    {
        if (empty($slugs)) return [];

        $placeholders = implode(',', array_fill(0, count($slugs), '?'));
        $pdo  = DB::connect();
        $stmt = $pdo->prepare(
            "SELECT name, slug, category, base_url, api_key, is_enabled, rate_limit, requires_key, supported_types
             FROM api_configs WHERE slug IN ({$placeholders})"
        );
        $stmt->execute(array_values($slugs));
        $rows = $stmt->fetchAll();

        $map = [];
        foreach ($rows as $row) {
            $map[$row['slug']] = $row;
        }
        return $map;
    }

    /**
     * Load a single API config by slug.
     */
    private static function loadApiConfig(string $slug): ?array
    {
        return DB::queryOne(
            "SELECT name, slug, category, base_url, api_key, is_enabled, rate_limit, requires_key
             FROM api_configs WHERE slug = :slug LIMIT 1",
            [':slug' => $slug]
        );
    }

    /**
     * Sort module slugs by explicit override, then category, then slug.
     *
     * @param array<int,string> $slugs
     * @param array<string,array<string,mixed>> $configs
     * @return array<int,string>
     */
    public static function sortSlugsByPriority(array $slugs, array $configs = []): array
    {
        $ordered = array_values(array_unique(array_map(
            static fn($slug): string => strtolower(trim((string)$slug)),
            $slugs
        )));

        usort($ordered, function (string $left, string $right) use ($configs): int {
            $leftPriority = self::priorityForSlug($left, $configs[$left] ?? null);
            $rightPriority = self::priorityForSlug($right, $configs[$right] ?? null);

            if ($leftPriority !== $rightPriority) {
                return $leftPriority <=> $rightPriority;
            }

            $leftCategory = strtolower(trim((string)($configs[$left]['category'] ?? 'zzz')));
            $rightCategory = strtolower(trim((string)($configs[$right]['category'] ?? 'zzz')));
            if ($leftCategory !== $rightCategory) {
                return $leftCategory <=> $rightCategory;
            }

            return $left <=> $right;
        });

        return $ordered;
    }

    private static function priorityForSlug(string $slug, ?array $config = null): int
    {
        if (isset(self::$modulePriorityOverrides[$slug])) {
            return self::$modulePriorityOverrides[$slug];
        }

        $category = strtolower(trim((string)($config['category'] ?? '')));
        if ($category !== '' && isset(self::$categoryPriority[$category])) {
            return self::$categoryPriority[$category];
        }

        return 999;
    }

    /**
     * Check whether a scan has been aborted by the user.
     * Mirrors SpiderFoot's SpiderFootPlugin::checkForStop() pattern.
     * Returns true if the scan status is 'aborted' or 'failed'.
     */
    private static function isScanAborted(int $scanId): bool
    {
        try {
            $row = DB::queryOne(
                "SELECT status FROM scans WHERE id = :id LIMIT 1",
                [':id' => $scanId]
            );
            return in_array($row['status'] ?? '', ['aborted', 'failed'], true);
        } catch (\Throwable $e) {
            return false; // On DB error, let execution continue
        }
    }

    /**
     * Resolve the PHP CLI binary to use for spawning worker processes.
     *
     * PHP_BINARY is reliable in CLI and FPM contexts, but when PHP runs as
     * Apache mod_php on Windows (XAMPP), PHP_BINARY may point to the Apache
     * DLL rather than php.exe, making proc_open spawn nothing useful.
     * This method tries several candidates and returns the first valid one.
     */
    public static function resolvePhpBinary(): string
    {
        $candidate = PHP_BINARY;

        // On Windows/XAMPP, PHP_BINARY often resolves to httpd.exe (Apache) or
        // a DLL rather than php.exe.  We must find the actual CLI php.exe.
        if (PHP_OS_FAMILY === 'Windows') {
            $basename = strtolower(basename($candidate));

            // Only trust PHP_BINARY if it actually points to php.exe or php-cgi.exe
            $isPhpBinary = in_array($basename, ['php.exe', 'php-cgi.exe'], true);

            if (!$isPhpBinary) {
                // Look for php.exe beside the INI file
                $iniFile = php_ini_loaded_file();
                if ($iniFile) {
                    $guess = rtrim(dirname($iniFile), '\\/') . DIRECTORY_SEPARATOR . 'php.exe';
                    if (is_file($guess)) return $guess;
                }
                // Look beside the extension directory (e.g. C:\xampp\php\ext\.. => php.exe)
                $extDir = ini_get('extension_dir');
                if ($extDir) {
                    $guess = rtrim(dirname(rtrim($extDir, '\\/')), '\\/') . DIRECTORY_SEPARATOR . 'php.exe';
                    if (is_file($guess)) return $guess;
                }
                // Common XAMPP installation path
                if (is_file('C:\\xampp\\php\\php.exe')) return 'C:\\xampp\\php\\php.exe';
                // Fall back to PATH
                return 'php.exe';
            }
        }

        return $candidate;
    }

    // =========================================================================
    //  MOCK EXECUTION (fallback for modules without real handlers)
    // =========================================================================

    private static function mockExecute(string $slug, string $apiName, string $queryType, string $queryValue): OsintResult
    {
        $score      = rand(0, 100);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = rand(60, 99);
        $respMs     = rand(120, 900);
        $detail     = self::getMockDetail($queryType, $queryValue);
        $summary    = self::buildMockSummary($queryType, $queryValue, $apiName, $score, $detail);
        $tags       = self::buildMockTags($queryType, $slug, $score);

        return new OsintResult(
            api:        $slug,
            apiName:    $apiName,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $respMs,
            summary:    $summary,
            tags:       $tags,
            rawData:    null,
            success:    true
        );
    }

    private static function getMockDetail(string $type, string $value): array
    {
        return match ($type) {
            'ip'     => ['asn' => 'AS' . rand(1000, 65000), 'country' => ['US','CN','RU','DE','BR'][rand(0,4)], 'isp' => 'Unknown ISP'],
            'domain' => ['registrar' => 'GoDaddy / NameCheap', 'created' => date('Y-m-d', strtotime('-' . rand(1,3650) . ' days')), 'expires' => date('Y-m-d', strtotime('+' . rand(30,730) . ' days'))],
            'url'    => ['scheme' => parse_url($value, PHP_URL_SCHEME) ?: 'http', 'host' => parse_url($value, PHP_URL_HOST) ?: $value, 'path' => parse_url($value, PHP_URL_PATH) ?: '/'],
            'hash'   => ['algorithm' => strlen($value) === 32 ? 'MD5' : (strlen($value) === 40 ? 'SHA-1' : 'SHA-256'), 'file_type' => ['PE32','ELF','PDF','ZIP','DLL'][rand(0,4)]],
            'email'  => ['domain' => substr(strrchr($value, '@'), 1) ?: 'unknown.com', 'mx' => 'mx.' . (substr(strrchr($value, '@'), 1) ?: 'unknown.com')],
            'cve'    => ['cvss' => number_format(rand(20, 100) / 10, 1), 'vector' => ['Network','Adjacent','Local'][rand(0,2)]],
            default  => [],
        };
    }

    private static function buildMockSummary(string $type, string $value, string $apiName, int $score, array $detail): string
    {
        $severity = strtoupper(OsintResult::scoreToSeverity($score));
        $base = match ($type) {
            'ip'     => "IP {$value} — ASN: {$detail['asn']}, Country: {$detail['country']}, ISP: {$detail['isp']}.",
            'domain' => "Domain {$value} — Registrar: {$detail['registrar']}. Created: {$detail['created']}, Expires: {$detail['expires']}.",
            'url'    => "URL scanned: {$detail['scheme']}://{$detail['host']}{$detail['path']}.",
            'hash'   => "File hash {$value} — Type: {$detail['algorithm']}, Detected as: {$detail['file_type']}.",
            'email'  => "Email address {$value} — Domain: {$detail['domain']}, MX: {$detail['mx']}.",
            'cve'    => "Vulnerability {$value} — CVSS: {$detail['cvss']}, Attack vector: {$detail['vector']}.",
            default  => "Indicator: {$value}.",
        };
        return "{$base} Risk assessment: {$severity} ({$score}/100) via {$apiName}.";
    }

    private static function buildMockTags(string $type, string $slug, int $score): array
    {
        $tags = [$type, $slug];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if ($type === 'ip')     $tags[] = 'scanner';
        if ($type === 'domain') $tags[] = 'phishing';
        if ($type === 'hash')   $tags[] = 'malware';
        if ($type === 'cve')    $tags[] = 'vulnerability';
        return array_unique($tags);
    }
}
