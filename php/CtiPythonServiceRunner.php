<?php
// =============================================================================
//  CTI - OWN PYTHON ENGINE SERVICE RUNNER
//
//  Incremental bridge from the existing PHP scan workflow into the new
//  first-party CTI Python service. Scans are routed here when every selected
//  module is already implemented in our own engine for the target type.
// =============================================================================

require_once __DIR__ . '/db.php';

class CtiPythonServiceSoftFailure extends RuntimeException {}
class CtiPythonServiceHardFailure extends RuntimeException {}
class CtiPythonServiceTerminated extends RuntimeException {}

class CtiPythonServiceRunner
{
    private const DEFAULT_SERVICE_URL = 'http://127.0.0.1:8765';
    private const CREATE_SCAN_PATH = '/api/v1/scans';
    private const TERMINATE_SCAN_PATH = '/api/v1/scans/%s/terminate';
    private const POLL_INTERVAL_US = 250000;
    private const MAX_WAIT_SECONDS = 180;

    /** @var array<string,string> */
    private const CTI_TO_SERVICE = [
        'adblock-check' => 'adblock',
        'ahmia' => 'ahmia',
        'apivoid' => 'apivoid',
        'archive-org' => 'archive-org',
        'account-finder' => 'account-finder',
        'abuse-ch' => 'abuse-ch',
        'abusech' => 'abuse-ch',
        'abuseipdb' => 'abuseipdb',
        'alienvault' => 'alienvault',
        'alienvault-ip-rep' => 'alienvault-ip-rep',
        'azure-blob-finder' => 'azure-blob-finder',
        'base64-decoder' => 'base64',
        'binary-string-extractor' => 'binary-string-extractor',
        'bgpview' => 'bgpview',
        'blocklist-de' => 'blocklistde',
        'botvrij' => 'botvrij',
        'certspotter' => 'certspotter',
        'censys' => 'censys',
        'cins-army' => 'cinsscore',
        'cleantalk' => 'cleantalk',
        'coinblocker' => 'coinblocker',
        'commoncrawl' => 'commoncrawl',
        'company-name-extractor' => 'company-name-extractor',
        'country-name-extractor' => 'country-name-extractor',
        'crobat' => 'crobat',
        'crt-sh' => 'crt-sh',
        'cross-referencer' => 'cross-referencer',
        'custom-threat-feed' => 'custom-threat-feed',
        'cybercrime-tracker' => 'cybercrimetracker',
        'cmseek' => 'cmseek',
        'dns-bruteforce' => 'dns-bruteforce',
        'dns-lookaside' => 'dns-lookaside',
        'dnsgrep' => 'dnsgrep',
        'dnsdumpster' => 'dnsdumpster',
        'dns-raw' => 'dns-raw',
        'dns-resolver' => 'dnsresolve',
        'dns-zone-transfer' => 'dns-zone-transfer',
        'dnstwist' => 'dnstwist',
        'do-space-finder' => 'do-space-finder',
        'dronebl' => 'dronebl',
        'duckduckgo' => 'duckduckgo',
        'emailrep' => 'emailrep',
        'emerging-threats' => 'emergingthreats',
        'file-metadata-extractor' => 'file-metadata-extractor',
        'flickr' => 'flickr',
        'fortiguard' => 'fortiguard',
        'gcs-finder' => 'gcs-finder',
        'grep-app' => 'grep-app',
        'greynoise' => 'greynoise',
        'greensnow' => 'greensnow',
        'github' => 'github',
        'hackertarget' => 'hackertarget',
        'haveibeenpwned' => 'haveibeenpwned',
        'human-name-extractor' => 'human-name-extractor',
        'hunter' => 'hunter',
        'ipinfo' => 'ipinfo',
        'ipqualityscore' => 'ipqualityscore',
        'ipregistry' => 'ipregistry',
        'isc-sans' => 'isc-sans',
        'interesting-file-finder' => 'interesting-file-finder',
        'jsonwhois' => 'jsonwhois',
        'junk-file-finder' => 'junk-file-finder',
        'leakix' => 'leakix',
        'maltiverse' => 'maltiverse',
        'malwarepatrol' => 'malwarepatrol',
        'mnemonic-pdns' => 'mnemonic-pdns',
        'multiproxy' => 'multiproxy',
        'nbtscan' => 'nbtscan',
        'nmap' => 'nmap',
        'nuclei' => 'nuclei',
        'onionsearchengine' => 'onionsearchengine',
        'onesixtyone' => 'onesixtyone',
        'open-pdns' => 'open-pdns',
        'opennic' => 'opennic',
        'openphish' => 'openphish',
        'passivedns' => 'passivedns',
        'pgp-keyservers' => 'pgp-keyservers',
        'phishstats' => 'phishstats',
        'phishtank' => 'phishtank',
        'port-scanner-tcp' => 'port-scanner-tcp',
        'retire-js' => 'retire-js',
        'robtex' => 'robtex',
        'crxcavator' => 'crxcavator',
        's3-finder' => 's3-finder',
        'scylla' => 'scylla',
        'searchcode' => 'searchcode',
        'securitytrails' => 'securitytrails',
        'shodan' => 'shodan',
        'spamcop' => 'spamcop',
        'spamhaus-zen' => 'spamhaus',
        'snallygaster' => 'snallygaster',
        'sorbs' => 'sorbs',
        'steven-black-hosts' => 'stevenblackhosts',
        'surbl' => 'surbl',
        'ssl-analyzer' => 'ssl-analyzer',
        'tld-searcher' => 'tld-searcher',
        'talos-intelligence' => 'talos-intelligence',
        'threatcrowd' => 'threatcrowd',
        'threatfox' => 'threatfox',
        'threatminer' => 'threatminer',
        'torch' => 'torch',
        'tor-exit-nodes' => 'torexits',
        'testssl' => 'testssl',
        'trufflehog' => 'trufflehog',
        'uceprotect' => 'uceprotect',
        'urlscan' => 'urlscan',
        'virustotal' => 'virustotal',
        'voipbl' => 'voipbl',
        'vxvault' => 'vxvault',
        'web-spider' => 'web-spider',
        'viewdns' => 'viewdns',
        'wafw00f' => 'wafw00f',
        'wappalyzer' => 'wappalyzer',
        'wikipedia-edits' => 'wikipedia-edits',
        'whatweb' => 'whatweb',
        'whoisology' => 'whoisology',
        'whoxy' => 'whoxy',
        'wikileaks' => 'wikileaks',
        'zone-h' => 'zoneh',
    ];

    /** @var array<string,array<int,string>> */
    private const MODULE_QUERY_SUPPORT = [
        'adblock-check' => ['domain', 'url'],
        'ahmia' => ['domain'],
        'apivoid' => ['domain', 'ip', 'url', 'email'],
        'archive-org' => ['domain', 'url'],
        'account-finder' => ['domain', 'email', 'username'],
        'abuse-ch' => ['domain', 'ip', 'url', 'hash'],
        'abusech' => ['domain', 'ip', 'url', 'hash'],
        'abuseipdb' => ['ip'],
        'alienvault' => ['domain', 'ip', 'url', 'hash'],
        'alienvault-ip-rep' => ['ip'],
        'azure-blob-finder' => ['domain'],
        'base64-decoder' => ['domain', 'url'],
        'binary-string-extractor' => ['url'],
        'bgpview' => ['domain', 'ip'],
        'blocklist-de' => ['ip'],
        'botvrij' => ['domain'],
        'certspotter' => ['domain'],
        'censys' => ['domain', 'ip'],
        'cins-army' => ['ip'],
        'cleantalk' => ['domain', 'ip', 'email'],
        'coinblocker' => ['domain'],
        'commoncrawl' => ['domain', 'url'],
        'company-name-extractor' => ['domain', 'url'],
        'country-name-extractor' => ['domain', 'phone'],
        'crobat' => ['domain'],
        'crt-sh' => ['domain'],
        'cross-referencer' => ['domain', 'url'],
        'custom-threat-feed' => ['domain', 'ip', 'url', 'hash'],
        'cybercrime-tracker' => ['domain', 'ip'],
        'cmseek' => ['domain', 'url'],
        'dns-bruteforce' => ['domain'],
        'dns-lookaside' => ['domain', 'ip'],
        'dnsgrep' => ['domain'],
        'dnsdumpster' => ['domain'],
        'dns-raw' => ['domain'],
        'dns-resolver' => ['domain'],
        'dns-zone-transfer' => ['domain'],
        'dnstwist' => ['domain'],
        'do-space-finder' => ['domain'],
        'dronebl' => ['ip'],
        'duckduckgo' => ['domain'],
        'emailrep' => ['email'],
        'emerging-threats' => ['ip'],
        'file-metadata-extractor' => ['url'],
        'gcs-finder' => ['domain'],
        'fortiguard' => ['domain', 'ip', 'url'],
        'grep-app' => ['domain'],
        'greynoise' => ['ip'],
        'greensnow' => ['ip'],
        'github' => ['domain', 'username'],
        'hackertarget' => ['domain', 'ip'],
        'haveibeenpwned' => ['email'],
        'human-name-extractor' => ['domain', 'url', 'email'],
        'hunter' => ['domain', 'email'],
        'ipinfo' => ['ip'],
        'ipqualityscore' => ['ip', 'email', 'url', 'phone'],
        'ipregistry' => ['ip'],
        'isc-sans' => ['ip'],
        'interesting-file-finder' => ['domain', 'url'],
        'jsonwhois' => ['domain'],
        'junk-file-finder' => ['domain', 'url'],
        'leakix' => ['domain', 'ip', 'email'],
        'maltiverse' => ['domain', 'ip', 'url', 'hash'],
        'malwarepatrol' => ['domain', 'ip', 'url', 'hash'],
        'mnemonic-pdns' => ['domain', 'ip'],
        'multiproxy' => ['ip'],
        'nbtscan' => ['ip'],
        'nmap' => ['domain', 'ip'],
        'nuclei' => ['domain', 'url'],
        'onionsearchengine' => ['domain', 'email', 'username'],
        'onesixtyone' => ['ip'],
        'open-pdns' => ['domain', 'ip'],
        'opennic' => ['domain'],
        'openphish' => ['domain', 'url'],
        'passivedns' => ['domain', 'ip'],
        'pgp-keyservers' => ['domain', 'email'],
        'phishstats' => ['domain', 'ip', 'url'],
        'phishtank' => ['domain', 'url'],
        'port-scanner-tcp' => ['domain', 'ip'],
        'retire-js' => ['domain', 'url'],
        'robtex' => ['domain', 'ip'],
        'crxcavator' => ['domain'],
        's3-finder' => ['domain'],
        'scylla' => ['email', 'username'],
        'searchcode' => ['domain'],
        'securitytrails' => ['domain', 'ip', 'email'],
        'shodan' => ['domain', 'ip'],
        'spamcop' => ['ip'],
        'spamhaus-zen' => ['ip'],
        'snallygaster' => ['domain', 'url'],
        'sorbs' => ['ip'],
        'steven-black-hosts' => ['domain'],
        'surbl' => ['domain', 'ip'],
        'ssl-analyzer' => ['domain'],
        'tld-searcher' => ['domain'],
        'talos-intelligence' => ['domain', 'ip'],
        'threatcrowd' => ['domain', 'ip', 'email', 'hash'],
        'threatfox' => ['domain', 'ip', 'hash', 'url'],
        'threatminer' => ['domain', 'ip'],
        'torch' => ['domain', 'email', 'username'],
        'tor-exit-nodes' => ['ip'],
        'testssl' => ['domain', 'url'],
        'trufflehog' => ['domain', 'url'],
        'uceprotect' => ['ip'],
        'urlscan' => ['domain', 'url'],
        'virustotal' => ['domain', 'ip'],
        'voipbl' => ['ip'],
        'vxvault' => ['domain', 'ip'],
        'web-spider' => ['domain', 'url'],
        'viewdns' => ['domain', 'ip'],
        'wafw00f' => ['domain', 'url'],
        'wappalyzer' => ['domain', 'url'],
        'wikipedia-edits' => ['ip', 'username'],
        'whatweb' => ['domain', 'url'],
        'whoisology' => ['email'],
        'whoxy' => ['email'],
        'wikileaks' => ['domain', 'email', 'username'],
        'zone-h' => ['domain', 'ip'],
    ];

    /** @var array<string,array<int,string>> Canonical CTI slugs and target types that have passed parity verification. */
    private const PARITY_VERIFIED_SUPPORT = [
        'adblock-check' => ['domain', 'url'],
        'ahmia' => ['domain'],
        'abuseipdb' => ['ip'],
        'abuse-ch' => ['domain', 'ip'],
        'alienvault' => ['domain'],
        'alienvault-ip-rep' => ['ip'],
        'azure-blob-finder' => ['domain'],
        'archive-org' => ['domain', 'url'],
        'account-finder' => ['domain', 'email', 'username'],
        'base64-decoder' => ['domain', 'url'],
        'binary-string-extractor' => ['url'],
        'blocklist-de' => ['ip'],
        'botvrij' => ['domain'],
        'certspotter' => ['domain'],
        'cins-army' => ['ip'],
        'cleantalk' => ['domain', 'ip', 'email'],
        'coinblocker' => ['domain'],
        'commoncrawl' => ['domain', 'url'],
        'company-name-extractor' => ['domain', 'url'],
        'country-name-extractor' => ['domain', 'phone'],
        'crobat' => ['domain'],
        'crt-sh' => ['domain'],
        'cross-referencer' => ['domain', 'url'],
        'custom-threat-feed' => ['domain', 'ip', 'url', 'hash'],
        'cybercrime-tracker' => ['domain', 'ip'],
        'cmseek' => ['domain', 'url'],
        'dns-bruteforce' => ['domain'],
        'dns-lookaside' => ['domain', 'ip'],
        'dnsgrep' => ['domain'],
        'dns-raw' => ['domain'],
        'dns-resolver' => ['domain'],
        'dns-zone-transfer' => ['domain'],
        'dnstwist' => ['domain'],
        'do-space-finder' => ['domain'],
        'dronebl' => ['ip'],
        'duckduckgo' => ['domain'],
        'emerging-threats' => ['ip'],
        'file-metadata-extractor' => ['url'],
        'flickr' => ['domain'],
        'fortiguard' => ['domain', 'ip', 'url'],
        'gcs-finder' => ['domain'],
        'grep-app' => ['domain'],
        'greensnow' => ['ip'],
        'hackertarget' => ['domain', 'ip'],
        'human-name-extractor' => ['domain', 'url', 'email'],
        'jsonwhois' => ['domain'],
        'isc-sans' => ['ip'],
        'interesting-file-finder' => ['domain', 'url'],
        'maltiverse' => ['domain', 'ip', 'url', 'hash'],
        'malwarepatrol' => ['domain', 'ip', 'url', 'hash'],
        'mnemonic-pdns' => ['domain', 'ip'],
        'multiproxy' => ['ip'],
        'nbtscan' => ['ip'],
        'nmap' => ['domain', 'ip'],
        'nuclei' => ['domain', 'url'],
        'open-pdns' => ['domain', 'ip'],
        'opennic' => ['domain'],
        'onesixtyone' => ['ip'],
        'phishstats' => ['domain', 'ip', 'url'],
        'port-scanner-tcp' => ['domain', 'ip'],
        'retire-js' => ['domain', 'url'],
        'robtex' => ['domain', 'ip'],
        's3-finder' => ['domain'],
        'scylla' => ['email', 'username'],
        'searchcode' => ['domain'],
        'junk-file-finder' => ['domain', 'url'],
        'spamcop' => ['ip'],
        'spamhaus-zen' => ['ip'],
        'snallygaster' => ['domain', 'url'],
        'sorbs' => ['ip'],
        'steven-black-hosts' => ['domain'],
        'surbl' => ['domain', 'ip'],
        'ssl-analyzer' => ['domain'],
        'tld-searcher' => ['domain'],
        'talos-intelligence' => ['domain', 'ip'],
        'threatcrowd' => ['domain', 'ip', 'email', 'hash'],
        'threatminer' => ['domain', 'ip'],
        'tor-exit-nodes' => ['ip'],
        'testssl' => ['domain', 'url'],
        'trufflehog' => ['domain', 'url'],
        'uceprotect' => ['ip'],
        'urlscan' => ['domain'],
        'virustotal' => ['domain', 'ip'],
        'voipbl' => ['ip'],
        'vxvault' => ['domain', 'ip'],
        'web-spider' => ['domain', 'url'],
        'wafw00f' => ['domain', 'url'],
        'wappalyzer' => ['domain', 'url'],
        'wikipedia-edits' => ['ip', 'username'],
        'whatweb' => ['domain', 'url'],
        'zone-h' => ['domain', 'ip'],
        'shodan' => ['ip'],
        'whoisology' => ['email'],
        'whoxy' => ['email'],
    ];

    /** @var array<string,bool> Canonical migrated CTI Python modules and whether they require API credentials. */
    private const MODULE_REQUIRES_KEY = [
        'adblock-check' => false,
        'ahmia' => false,
        'abuse-ch' => false,
        'abuseipdb' => true,
        'alienvault' => true,
        'alienvault-ip-rep' => false,
        'azure-blob-finder' => false,
        'apivoid' => true,
        'archive-org' => false,
        'account-finder' => false,
        'base64-decoder' => false,
        'binary-string-extractor' => false,
        'bgpview' => false,
        'blocklist-de' => false,
        'botvrij' => false,
        'certspotter' => false,
        'censys' => true,
        'cins-army' => false,
        'cleantalk' => false,
        'coinblocker' => false,
        'commoncrawl' => false,
        'company-name-extractor' => false,
        'country-name-extractor' => false,
        'crobat' => false,
        'crt-sh' => false,
        'cross-referencer' => false,
        'custom-threat-feed' => false,
        'cybercrime-tracker' => false,
        'cmseek' => false,
        'dns-bruteforce' => false,
        'dns-lookaside' => false,
        'dnsgrep' => false,
        'dnsdumpster' => false,
        'dns-raw' => false,
        'dns-resolver' => false,
        'dns-zone-transfer' => false,
        'dnstwist' => false,
        'do-space-finder' => false,
        'dronebl' => false,
        'duckduckgo' => false,
        'emailrep' => false,
        'emerging-threats' => false,
        'file-metadata-extractor' => false,
        'flickr' => false,
        'fortiguard' => false,
        'gcs-finder' => false,
        'grep-app' => false,
        'greynoise' => true,
        'greensnow' => false,
        'github' => false,
        'hackertarget' => false,
        'haveibeenpwned' => true,
        'human-name-extractor' => false,
        'hunter' => true,
        'ipinfo' => true,
        'ipqualityscore' => true,
        'ipregistry' => true,
        'isc-sans' => false,
        'interesting-file-finder' => false,
        'jsonwhois' => true,
        'junk-file-finder' => false,
        'leakix' => false,
        'maltiverse' => false,
        'malwarepatrol' => false,
        'mnemonic-pdns' => false,
        'multiproxy' => false,
        'nbtscan' => false,
        'nmap' => false,
        'nuclei' => false,
        'onionsearchengine' => false,
        'onesixtyone' => false,
        'open-pdns' => false,
        'opennic' => false,
        'openphish' => false,
        'passivedns' => false,
        'pgp-keyservers' => false,
        'phishstats' => false,
        'phishtank' => false,
        'port-scanner-tcp' => false,
        'retire-js' => false,
        'robtex' => false,
        'crxcavator' => false,
        's3-finder' => false,
        'scylla' => false,
        'searchcode' => false,
        'securitytrails' => true,
        'shodan' => true,
        'spamcop' => false,
        'spamhaus-zen' => false,
        'snallygaster' => false,
        'sorbs' => false,
        'steven-black-hosts' => false,
        'surbl' => false,
        'ssl-analyzer' => false,
        'tld-searcher' => false,
        'talos-intelligence' => false,
        'threatcrowd' => false,
        'threatfox' => false,
        'threatminer' => false,
        'torch' => false,
        'tor-exit-nodes' => false,
        'testssl' => false,
        'trufflehog' => false,
        'uceprotect' => false,
        'urlscan' => false,
        'virustotal' => true,
        'voipbl' => false,
        'vxvault' => false,
        'web-spider' => false,
        'viewdns' => true,
        'wafw00f' => false,
        'wappalyzer' => false,
        'wikipedia-edits' => false,
        'whatweb' => false,
        'whoisology' => true,
        'whoxy' => true,
        'wikileaks' => false,
        'zone-h' => false,
    ];

    /** @var array<string,string> */
    private const SERVICE_TO_CTI = [
        'adblock' => 'adblock-check',
        'ahmia' => 'ahmia',
        'account-finder' => 'account-finder',
        'alienvault-ip-rep' => 'alienvault-ip-rep',
        'azure-blob-finder' => 'azure-blob-finder',
        'base64' => 'base64-decoder',
        'binary-string-extractor' => 'binary-string-extractor',
        'blocklistde' => 'blocklist-de',
        'cinsscore' => 'cins-army',
        'cleantalk' => 'cleantalk',
        'cybercrimetracker' => 'cybercrime-tracker',
        'company-name-extractor' => 'company-name-extractor',
        'country-name-extractor' => 'country-name-extractor',
        'cross-referencer' => 'cross-referencer',
        'custom-threat-feed' => 'custom-threat-feed',
        'cmseek' => 'cmseek',
        'dns-bruteforce' => 'dns-bruteforce',
        'dns-lookaside' => 'dns-lookaside',
        'dnsgrep' => 'dnsgrep',
        'dns-raw' => 'dns-raw',
        'dnsresolve' => 'dns-resolver',
        'dns-zone-transfer' => 'dns-zone-transfer',
        'dnstwist' => 'dnstwist',
        'do-space-finder' => 'do-space-finder',
        'duckduckgo' => 'duckduckgo',
        'engine' => 'cti-python',
        'file-metadata-extractor' => 'file-metadata-extractor',
        'flickr' => 'flickr',
        'fortiguard' => 'fortiguard',
        'gcs-finder' => 'gcs-finder',
        'grep-app' => 'grep-app',
        'github' => 'github',
        'human-name-extractor' => 'human-name-extractor',
        'seed' => 'cti-python',
        'crxcavator' => 'crxcavator',
        'interesting-file-finder' => 'interesting-file-finder',
        'junk-file-finder' => 'junk-file-finder',
        'malwarepatrol' => 'malwarepatrol',
        'nbtscan' => 'nbtscan',
        'nmap' => 'nmap',
        'nuclei' => 'nuclei',
        'onionsearchengine' => 'onionsearchengine',
        'onesixtyone' => 'onesixtyone',
        'open-pdns' => 'open-pdns',
        'opennic' => 'opennic',
        'pgp-keyservers' => 'pgp-keyservers',
        'port-scanner-tcp' => 'port-scanner-tcp',
        'retire-js' => 'retire-js',
        's3-finder' => 's3-finder',
        'scylla' => 'scylla',
        'searchcode' => 'searchcode',
        'snallygaster' => 'snallygaster',
        'sorbs' => 'sorbs',
        'spamhaus' => 'spamhaus-zen',
        'ssl-analyzer' => 'ssl-analyzer',
        'stevenblackhosts' => 'steven-black-hosts',
        'tld-searcher' => 'tld-searcher',
        'talos-intelligence' => 'talos-intelligence',
        'torch' => 'torch',
        'torexits' => 'tor-exit-nodes',
        'testssl' => 'testssl',
        'trufflehog' => 'trufflehog',
        'voipbl' => 'voipbl',
        'vxvault' => 'vxvault',
        'web-spider' => 'web-spider',
        'wafw00f' => 'wafw00f',
        'wappalyzer' => 'wappalyzer',
        'wikipedia-edits' => 'wikipedia-edits',
        'wikileaks' => 'wikileaks',
        'whatweb' => 'whatweb',
        'zoneh' => 'zone-h',
    ];

    private int $scanId;
    private int $userId;
    private string $scanName;
    private string $queryType;
    private string $queryValue;
    /** @var array<int,string> */
    private array $selectedApis;
    /** @var array<string,mixed> */
    private array $configSnapshot;
    /** @var array<string,int> */
    private array $eventIdToQueryHistoryId = [];
    /** @var array<string,array<string,mixed>> */
    private array $eventById = [];
    /** @var array<string,int> */
    private array $depthByEventId = [];

    public function __construct(
        int $scanId,
        int $userId,
        string $scanName,
        string $queryType,
        string $queryValue,
        array $selectedApis,
        array $configSnapshot = []
    ) {
        $this->scanId = $scanId;
        $this->userId = $userId;
        $this->scanName = $scanName;
        $this->queryType = strtolower(trim($queryType));
        $this->queryValue = trim($queryValue);
        $this->selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));
        $this->configSnapshot = $configSnapshot;
    }

    public static function supportsScan(string $queryType, array $selectedApis): bool
    {
        $queryType = strtolower(trim($queryType));

        $selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));

        if (empty($selectedApis)) {
            return false;
        }

        foreach ($selectedApis as $slug) {
            if (!array_key_exists($slug, self::CTI_TO_SERVICE)) {
                return false;
            }

            $canonicalSlug = $slug === 'abusech' ? 'abuse-ch' : $slug;
            $verifiedQueryTypes = self::PARITY_VERIFIED_SUPPORT[$canonicalSlug] ?? [];
            if (!$verifiedQueryTypes) {
                return false;
            }
            if (!in_array($queryType, $verifiedQueryTypes, true)) {
                return false;
            }

            $supportedQueryTypes = self::MODULE_QUERY_SUPPORT[$slug] ?? [];
            if (!in_array($queryType, $supportedQueryTypes, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Return canonical CTI module slugs already migrated to the own Python engine.
     *
     * @return array<int, string>
     */
    public static function getSupportedModuleSlugs(): array
    {
        $slugs = [];
        foreach (array_keys(self::CTI_TO_SERVICE) as $slug) {
            $canonicalSlug = $slug === 'abusech' ? 'abuse-ch' : $slug;
            $slugs[$canonicalSlug] = true;
        }

        $result = array_keys($slugs);
        sort($result, SORT_STRING);
        return $result;
    }

    /**
     * Return canonical migrated slugs that are safe to route by default because
     * their current CTI Python implementation has already passed parity review.
     *
     * @return array<int, string>
     */
    public static function getParityVerifiedModuleSlugs(): array
    {
        $slugs = array_keys(self::PARITY_VERIFIED_SUPPORT);
        sort($slugs, SORT_STRING);
        return $slugs;
    }

    /**
     * Return the parity-verified target types per canonical migrated module slug.
     *
     * @return array<string,array<int,string>>
     */
    public static function getParityVerifiedModuleTypes(): array
    {
        return self::PARITY_VERIFIED_SUPPORT;
    }

    /**
     * Return canonical migrated slugs mapped to whether the CTI Python module
     * requires an API key or credential to run its current implementation.
     *
     * @return array<string,bool>
     */
    public static function getModuleKeyRequirements(): array
    {
        return self::MODULE_REQUIRES_KEY;
    }

    /**
     * Return canonical migrated slugs mapped to the target types supported by
     * the current CTI Python implementation.
     *
     * @return array<string,array<int,string>>
     */
    public static function getModuleSupportedQueryTypes(): array
    {
        $result = [];

        foreach (self::MODULE_QUERY_SUPPORT as $slug => $queryTypes) {
            $canonicalSlug = $slug === 'abusech' ? 'abuse-ch' : $slug;
            if (!isset($result[$canonicalSlug])) {
                $result[$canonicalSlug] = [];
            }

            foreach ($queryTypes as $queryType) {
                if (!in_array($queryType, $result[$canonicalSlug], true)) {
                    $result[$canonicalSlug][] = $queryType;
                }
            }

            sort($result[$canonicalSlug], SORT_STRING);
        }

        ksort($result, SORT_STRING);
        return $result;
    }

    public static function explainUnsupportedReason(string $queryType, array $selectedApis): string
    {
        $queryType = strtolower(trim($queryType));
        $selectedApis = array_values(array_filter(array_map(
            static fn($slug) => strtolower(trim((string)$slug)),
            $selectedApis
        ), static fn($slug) => $slug !== ''));

        if (empty($selectedApis)) {
            return 'No modules were selected for CTI Python routing.';
        }

        $notMigrated = [];
        $notParityVerified = [];
        $unsupportedType = [];

        foreach ($selectedApis as $slug) {
            if (!array_key_exists($slug, self::CTI_TO_SERVICE)) {
                $notMigrated[] = $slug;
                continue;
            }

            $canonicalSlug = $slug === 'abusech' ? 'abuse-ch' : $slug;
            $verifiedQueryTypes = self::PARITY_VERIFIED_SUPPORT[$canonicalSlug] ?? [];
            if (!$verifiedQueryTypes) {
                $notParityVerified[] = $canonicalSlug;
                continue;
            }
            if (!in_array($queryType, $verifiedQueryTypes, true)) {
                $unsupportedType[] = $canonicalSlug;
                continue;
            }

            $supportedQueryTypes = self::MODULE_QUERY_SUPPORT[$slug] ?? [];
            if (!in_array($queryType, $supportedQueryTypes, true)) {
                $unsupportedType[] = $canonicalSlug;
            }
        }

        if ($notMigrated) {
            return 'Selected module(s) are not migrated to the CTI Python engine yet: ' . implode(', ', array_values(array_unique($notMigrated))) . '.';
        }

        if ($notParityVerified) {
            return 'Selected migrated module(s) are not parity-verified yet, so CTI keeps the proven backend: ' . implode(', ', array_values(array_unique($notParityVerified))) . '.';
        }

        if ($unsupportedType) {
            return 'Selected migrated module(s) are not parity-verified for target type "' . $queryType . '" yet, so CTI keeps the proven backend: ' . implode(', ', array_values(array_unique($unsupportedType))) . '.';
        }

        return 'CTI Python engine routing is not available for the selected scan.';
    }

    /**
     * @return array<string,int>
     */
    public function run(): array
    {
        $payload = $this->buildPayload();
        $job = $this->requestJson('POST', self::CREATE_SCAN_PATH, $payload, 15);
        $jobId = trim((string)($job['job_id'] ?? $job['scan_id'] ?? ''));
        if ($jobId === '') {
            throw new CtiPythonServiceSoftFailure('CTI Python service did not return a job id.');
        }

        logScan(
            $this->scanId,
            'info',
            'cti-python',
            'CTI Python service job accepted. Job ID: ' . $jobId
        );

        $record = $this->pollForCompletion($jobId);
        $status = strtolower(trim((string)($record['status'] ?? 'unknown')));
        if ($status === 'aborted') {
            throw new CtiPythonServiceTerminated('CTI Python engine scan was terminated.');
        }
        if ($status === 'failed') {
            $message = trim((string)($record['error_message'] ?? 'Python engine job failed.'));
            throw new CtiPythonServiceSoftFailure($message !== '' ? $message : 'Python engine job failed.');
        }

        if ($status !== 'finished') {
            throw new CtiPythonServiceSoftFailure('Python engine job ended in unexpected state: ' . $status);
        }

        if ($this->wasScanTerminatedExternally()) {
            $this->requestTermination($jobId);
            throw new CtiPythonServiceTerminated('CTI Python engine scan terminated before results import.');
        }

        $projection = $this->requestJson('GET', '/api/v1/scans/' . rawurlencode($jobId) . '/results', null, 15);
        if (!is_array($projection)) {
            throw new CtiPythonServiceSoftFailure('Python engine results payload was invalid.');
        }

        return DB::transaction(function () use ($projection): array {
            if ($this->wasScanTerminatedExternally()) {
                throw new CtiPythonServiceTerminated('CTI Python engine scan terminated before persistence.');
            }

            $summary = $this->importProjection($projection);

            DB::execute(
                "UPDATE scans
                    SET status = 'finished',
                        finished_at = NOW(),
                        total_elements = :total,
                        unique_elements = :unique_count,
                        error_count = :errors
                  WHERE id = :id",
                [
                    ':total' => $summary['total_elements'],
                    ':unique_count' => $summary['unique_elements'],
                    ':errors' => $summary['error_count'],
                    ':id' => $this->scanId,
                ]
            );

            logScan(
                $this->scanId,
                'info',
                'cti-python',
                'CTI Python engine scan finished. '
                . $summary['total_elements']
                . ' result(s), '
                . $summary['error_count']
                . ' error log(s).'
            );

            runCorrelations($this->scanId, $this->queryType, $this->queryValue);
            return $summary;
        });
    }

    /**
     * @return array<string,mixed>
     */
    private function buildPayload(): array
    {
        $snapshot = $this->configSnapshot;
        $globalSettings = is_array($snapshot['global_settings'] ?? null)
            ? $snapshot['global_settings']
            : [];
        $moduleSettings = is_array($snapshot['module_settings'] ?? null)
            ? $snapshot['module_settings']
            : [];
        $apiConfigs = is_array($snapshot['api_configs_snapshot'] ?? null)
            ? $snapshot['api_configs_snapshot']
            : [];

        return [
            'scan_id' => $this->scanId,
            'user_id' => $this->userId,
            'scan_name' => $this->scanName,
            'query_type' => $this->queryType,
            'query_value' => $this->queryValue,
            'selected_modules' => $this->mapSelectedModulesToService(),
            'global_settings' => $globalSettings,
            'module_settings' => $moduleSettings,
            'api_configs_snapshot' => $apiConfigs,
        ];
    }

    /**
     * @return array<int,string>
     */
    private function mapSelectedModulesToService(): array
    {
        $mapped = [];
        foreach ($this->selectedApis as $slug) {
            if (!isset(self::CTI_TO_SERVICE[$slug])) {
                continue;
            }
            $mapped[] = self::CTI_TO_SERVICE[$slug];
        }
        return array_values(array_unique($mapped));
    }

    private function serviceBaseUrl(): string
    {
        $configured = trim((string)(getenv('CTI_PYTHON_ENGINE_URL') ?: ''));
        if ($configured === '') {
            $configured = self::DEFAULT_SERVICE_URL;
        }
        return rtrim($configured, '/');
    }

    /**
     * @return array<string,mixed>
     */
    private function requestJson(string $method, string $path, ?array $payload = null, int $timeout = 10): array
    {
        $url = $this->serviceBaseUrl() . $path;
        $jsonBody = $payload === null
            ? null
            : json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($jsonBody === false) {
            throw new CtiPythonServiceHardFailure('Failed to encode JSON payload for CTI Python service.');
        }

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch === false) {
                throw new CtiPythonServiceSoftFailure('Unable to initialize cURL for CTI Python service request.');
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => strtoupper($method),
                CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json'],
                CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
                CURLOPT_TIMEOUT => $timeout,
            ]);

            if ($jsonBody !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody);
            }

            $raw = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            if ($raw === false || $error !== '') {
                throw new CtiPythonServiceSoftFailure('Unable to reach CTI Python service at ' . $url . ': ' . $error);
            }
        } else {
            $context = stream_context_create([
                'http' => [
                    'method' => strtoupper($method),
                    'timeout' => $timeout,
                    'ignore_errors' => true,
                    'header' => "Accept: application/json\r\nContent-Type: application/json\r\n",
                    'content' => $jsonBody ?? '',
                ],
            ]);
            $raw = @file_get_contents($url, false, $context);
            $status = 0;
            if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
                $status = (int)$m[1];
            }

            if ($raw === false) {
                throw new CtiPythonServiceSoftFailure('Unable to reach CTI Python service at ' . $url . '.');
            }
        }

        $decoded = json_decode((string)$raw, true);
        if (!is_array($decoded)) {
            throw new CtiPythonServiceSoftFailure('CTI Python service returned invalid JSON from ' . $path . '.');
        }

        if ($status >= 400) {
            $message = trim((string)($decoded['error'] ?? 'HTTP ' . $status));
            throw new CtiPythonServiceSoftFailure('CTI Python service request failed: ' . $message);
        }

        return $decoded;
    }

    /**
     * @return array<string,mixed>
     */
    private function pollForCompletion(string $jobId): array
    {
        $started = microtime(true);
        do {
            if ($this->wasScanTerminatedExternally()) {
                $this->requestTermination($jobId);
                $status = $this->currentScanStatus();
                $message = $status === 'aborted'
                    ? 'CTI Python engine scan terminated by user.'
                    : 'CTI Python engine scan stopped because the scan status became "' . $status . '".';
                logScan($this->scanId, 'warning', 'cti-python', $message);
                throw new CtiPythonServiceTerminated($message);
            }

            $record = $this->requestJson('GET', '/api/v1/scans/' . rawurlencode($jobId), null, 10);
            $status = strtolower(trim((string)($record['status'] ?? 'unknown')));
            if (in_array($status, ['finished', 'failed', 'aborted'], true)) {
                return $record;
            }
            usleep(self::POLL_INTERVAL_US);
        } while ((microtime(true) - $started) < self::MAX_WAIT_SECONDS);

        throw new CtiPythonServiceSoftFailure('Timed out waiting for CTI Python service job ' . $jobId . '.');
    }

    private function currentScanStatus(): string
    {
        $row = DB::queryOne(
            "SELECT status FROM scans WHERE id = :id",
            [':id' => $this->scanId]
        );

        return strtolower(trim((string)($row['status'] ?? 'unknown')));
    }

    private function wasScanTerminatedExternally(): bool
    {
        return in_array($this->currentScanStatus(), ['aborted', 'failed'], true);
    }

    private function requestTermination(string $jobId): void
    {
        try {
            $this->requestJson(
                'POST',
                sprintf(self::TERMINATE_SCAN_PATH, rawurlencode($jobId)),
                ['reason' => 'terminated_from_cti_scan_status'],
                10
            );
        } catch (Throwable $e) {
            logScan(
                $this->scanId,
                'warning',
                'cti-python',
                'Failed to propagate terminate request to CTI Python service: ' . $e->getMessage()
            );
        }
    }

    /**
     * @param array<string,mixed> $projection
     * @return array<string,int>
     */
    private function importProjection(array $projection): array
    {
        $events = is_array($projection['events'] ?? null) ? $projection['events'] : [];
        $logs = is_array($projection['logs'] ?? null) ? $projection['logs'] : [];
        $correlations = is_array($projection['correlations'] ?? null) ? $projection['correlations'] : [];

        $this->cacheEvents($events);
        $this->importLogs($logs);
        $resultCount = $this->importEventsAsResults($events);
        $this->importCorrelations($correlations);

        $errorCount = 0;
        foreach ($logs as $log) {
            if (strtolower(trim((string)($log['level'] ?? ''))) === 'error') {
                $errorCount++;
            }
        }

        return [
            'overall_score' => $this->calculateOverallScore($events),
            'error_count' => $errorCount,
            'total_elements' => $resultCount,
            'unique_elements' => $resultCount,
            'max_pass' => $this->calculateMaxDepth(),
        ];
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function cacheEvents(array $events): void
    {
        foreach ($events as $event) {
            $eventId = trim((string)($event['event_id'] ?? ''));
            if ($eventId === '') {
                continue;
            }
            $this->eventById[$eventId] = $event;
        }
    }

    /**
     * @param array<int,array<string,mixed>> $logs
     */
    private function importLogs(array $logs): void
    {
        foreach ($logs as $log) {
            $message = trim((string)($log['message'] ?? ''));
            if ($message === '') {
                continue;
            }
            $level = strtolower(trim((string)($log['level'] ?? 'info')));
            if (!in_array($level, ['debug', 'info', 'warning', 'error'], true)) {
                $level = 'info';
            }

            logScan(
                $this->scanId,
                $level,
                $this->normalizeModuleSlug((string)($log['module'] ?? 'cti-python')),
                $message
            );
        }
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function importEventsAsResults(array $events): int
    {
        $count = 0;
        foreach ($events as $event) {
            $eventId = trim((string)($event['event_id'] ?? ''));
            $value = trim((string)($event['value'] ?? ''));
            $eventType = strtolower(trim((string)($event['event_type'] ?? '')));
            if ($eventId === '' || $value === '' || $eventType === '') {
                continue;
            }

            $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
            $depth = $this->depthForEvent($eventId);
            $sourceValue = $this->sourceValueForEvent($parentEventId);
            $moduleSlug = $this->normalizeModuleSlug((string)($event['source_module'] ?? 'cti-python'));
            $dataType = $this->displayTypeForEvent($eventType);
            $summary = $dataType . ': ' . $value;
            if ($sourceValue !== 'ROOT' && $sourceValue !== $value) {
                $summary .= ' (source: ' . $sourceValue . ')';
            }

            $insertedId = (int)DB::insert(
                "INSERT INTO query_history
                    (user_id, scan_id, query_type, query_value, api_source, data_type,
                     result_summary, risk_score, status, response_time,
                     enrichment_pass, source_ref, enriched_from)
                 VALUES
                    (:uid, :sid, :qt, :qv, :api, :dt,
                     :summary, :score, 'completed', :resp,
                     :pass, :source_ref, :enriched_from)",
                [
                    ':uid' => $this->userId,
                    ':sid' => $this->scanId,
                    ':qt' => $eventType,
                    ':qv' => $value,
                    ':api' => $moduleSlug,
                    ':dt' => $dataType,
                    ':summary' => $summary,
                    ':score' => max(0, min(100, (int)($event['risk_score'] ?? 0))),
                    ':resp' => 0,
                    ':pass' => $depth,
                    ':source_ref' => $sourceValue,
                    ':enriched_from' => $sourceValue === 'ROOT' ? null : $sourceValue,
                ]
            );

            $this->eventIdToQueryHistoryId[$eventId] = $insertedId;
            $count++;

            DB::execute(
                "INSERT INTO threat_indicators
                    (indicator_type, indicator_value, source, severity, confidence, tags, raw_data, first_seen, last_seen)
                 VALUES
                    (:type, :value, :source, :severity, :confidence, :tags, :raw, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE
                    severity = VALUES(severity),
                    confidence = VALUES(confidence),
                    tags = VALUES(tags),
                    raw_data = VALUES(raw_data),
                    last_seen = NOW()",
                [
                    ':type' => $eventType,
                    ':value' => $value,
                    ':source' => $moduleSlug,
                    ':severity' => $this->severityFromRisk((int)($event['risk_score'] ?? 0)),
                    ':confidence' => max(0, min(100, (int)($event['confidence'] ?? 0))),
                    ':tags' => json_encode([$moduleSlug, $eventType], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    ':raw' => json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ]
            );

            $this->upsertScanEvent($event, $moduleSlug, $sourceValue, $depth);
        }

        return $count;
    }

    /**
     * @param array<int,array<string,mixed>> $correlations
     */
    private function importCorrelations(array $correlations): void
    {
        if (empty($correlations) || !scanExecutorTableExists('scan_correlations')) {
            return;
        }

        foreach ($correlations as $correlation) {
            $ruleName = trim((string)($correlation['rule_name'] ?? 'cti_python_rule'));
            $severity = strtolower(trim((string)($correlation['severity'] ?? 'info')));
            if (!in_array($severity, ['critical', 'high', 'medium', 'low', 'info'], true)) {
                $severity = 'info';
            }
            $title = trim((string)($correlation['title'] ?? $ruleName));
            $detail = trim((string)($correlation['detail'] ?? ''));

            $correlationId = (int)DB::insert(
                "INSERT INTO scan_correlations (scan_id, rule_name, severity, title, detail)
                 VALUES (:sid, :rule, :severity, :title, :detail)",
                [
                    ':sid' => $this->scanId,
                    ':rule' => $ruleName,
                    ':severity' => $severity,
                    ':title' => $title,
                    ':detail' => $detail,
                ]
            );

            if ($correlationId <= 0 || !scanExecutorTableExists('scan_correlation_events')) {
                continue;
            }

            $linkedEventIds = is_array($correlation['linked_event_ids'] ?? null)
                ? $correlation['linked_event_ids']
                : [];

            foreach ($linkedEventIds as $eventId) {
                $queryHistoryId = $this->eventIdToQueryHistoryId[(string)$eventId] ?? null;
                if (!$queryHistoryId) {
                    continue;
                }
                DB::execute(
                    "INSERT INTO scan_correlation_events (correlation_id, query_history_id)
                     VALUES (:cid, :qid)
                     ON DUPLICATE KEY UPDATE query_history_id = VALUES(query_history_id)",
                    [
                        ':cid' => $correlationId,
                        ':qid' => $queryHistoryId,
                    ]
                );
            }
        }
    }

    /**
     * @param array<string,mixed> $event
     */
    private function upsertScanEvent(array $event, string $moduleSlug, string $sourceValue, int $depth): void
    {
        if (!scanExecutorTableExists('scan_events')) {
            return;
        }

        $eventId = (string)$event['event_id'];
        $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
        $eventType = $this->displayTypeForEvent((string)($event['event_type'] ?? ''));
        $eventValue = (string)($event['value'] ?? '');

        DB::execute(
            "INSERT INTO scan_events
                (scan_id, event_hash, event_type, event_data, module_slug,
                 source_event_hash, source_data, parent_event_hash, event_depth,
                 confidence, risk_score, visibility, false_positive, raw_payload_json)
             VALUES
                (:scan_id, :event_hash, :event_type, :event_data, :module_slug,
                 :source_event_hash, :source_data, :parent_event_hash, :event_depth,
                 :confidence, :risk_score, :visibility, :false_positive, :raw_payload_json)
             ON DUPLICATE KEY UPDATE
                event_type = VALUES(event_type),
                event_data = VALUES(event_data),
                module_slug = VALUES(module_slug),
                source_event_hash = VALUES(source_event_hash),
                source_data = VALUES(source_data),
                parent_event_hash = VALUES(parent_event_hash),
                event_depth = VALUES(event_depth),
                confidence = VALUES(confidence),
                risk_score = VALUES(risk_score),
                visibility = VALUES(visibility),
                false_positive = VALUES(false_positive),
                raw_payload_json = VALUES(raw_payload_json)",
            [
                ':scan_id' => $this->scanId,
                ':event_hash' => $eventId,
                ':event_type' => $eventType,
                ':event_data' => $eventValue,
                ':module_slug' => $moduleSlug,
                ':source_event_hash' => $parentEventId !== '' ? $parentEventId : 'ROOT',
                ':source_data' => $sourceValue,
                ':parent_event_hash' => $parentEventId !== '' ? $parentEventId : null,
                ':event_depth' => $depth,
                ':confidence' => max(0, min(100, (int)($event['confidence'] ?? 0))),
                ':risk_score' => max(0, min(100, (int)($event['risk_score'] ?? 0))),
                ':visibility' => 100,
                ':false_positive' => 0,
                ':raw_payload_json' => json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ]
        );

        if (scanExecutorTableExists('scan_event_relationships') && $parentEventId !== '') {
            DB::execute(
                "INSERT INTO scan_event_relationships
                    (scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type)
                 VALUES
                    (:sid, :parent_hash, :child_hash, :module, :type)
                 ON DUPLICATE KEY UPDATE relationship_type = VALUES(relationship_type)",
                [
                    ':sid' => $this->scanId,
                    ':parent_hash' => $parentEventId,
                    ':child_hash' => $eventId,
                    ':module' => $moduleSlug,
                    ':type' => 'discovered',
                ]
            );
        }
    }

    private function normalizeModuleSlug(string $module): string
    {
        $normalized = strtolower(trim($module));
        return self::SERVICE_TO_CTI[$normalized] ?? $normalized ?: 'cti-python';
    }

    private function displayTypeForEvent(string $eventType): string
    {
        $eventType = strtolower(trim($eventType));
        $eventType = str_replace('_', ' ', $eventType);
        return ucwords($eventType);
    }

    private function sourceValueForEvent(string $parentEventId): string
    {
        if ($parentEventId === '' || !isset($this->eventById[$parentEventId])) {
            return 'ROOT';
        }

        $parentValue = trim((string)($this->eventById[$parentEventId]['value'] ?? ''));
        return $parentValue !== '' ? $parentValue : 'ROOT';
    }

    private function depthForEvent(string $eventId): int
    {
        if (isset($this->depthByEventId[$eventId])) {
            return $this->depthByEventId[$eventId];
        }

        $event = $this->eventById[$eventId] ?? null;
        if (!is_array($event)) {
            return 1;
        }

        $parentEventId = trim((string)($event['parent_event_id'] ?? ''));
        if ($parentEventId === '' || !isset($this->eventById[$parentEventId])) {
            $this->depthByEventId[$eventId] = 1;
            return 1;
        }

        $depth = $this->depthForEvent($parentEventId) + 1;
        $this->depthByEventId[$eventId] = $depth;
        return $depth;
    }

    /**
     * @param array<int,array<string,mixed>> $events
     */
    private function calculateOverallScore(array $events): int
    {
        $max = 0;
        foreach ($events as $event) {
            $max = max($max, max(0, min(100, (int)($event['risk_score'] ?? 0))));
        }
        return $max;
    }

    private function calculateMaxDepth(): int
    {
        if (empty($this->eventById)) {
            return 0;
        }

        $max = 0;
        foreach (array_keys($this->eventById) as $eventId) {
            $max = max($max, $this->depthForEvent((string)$eventId));
        }
        return $max;
    }

    private function severityFromRisk(int $risk): string
    {
        if ($risk >= 90) {
            return 'critical';
        }
        if ($risk >= 70) {
            return 'high';
        }
        if ($risk >= 40) {
            return 'medium';
        }
        if ($risk > 0) {
            return 'low';
        }
        return 'info';
    }
}
