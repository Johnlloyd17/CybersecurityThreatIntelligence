/**
 * CTI Platform - Settings UI
 * Renders settings and persists editable values via backend APIs.
 */
document.addEventListener('DOMContentLoaded', () => {
  const rawModules = Array.isArray(window.CTI_STATIC_SETTINGS) ? window.CTI_STATIC_SETTINGS : [];
  const SPIDERFOOT_MODULE_ORDER = Array.isArray(window.CTI_SPIDERFOOT_MODULE_ORDER)
    ? window.CTI_SPIDERFOOT_MODULE_ORDER.map((slug) => String(slug || '').toLowerCase())
    : [];
  const SPIDERFOOT_DISPLAY_SLUGS = window.CTI_SPIDERFOOT_DISPLAY_SLUGS && typeof window.CTI_SPIDERFOOT_DISPLAY_SLUGS === 'object'
    ? window.CTI_SPIDERFOOT_DISPLAY_SLUGS
    : {};
  const spiderFootOrderIndex = Object.fromEntries(SPIDERFOOT_MODULE_ORDER.map((slug, index) => [slug, index]));
  const STATIC_MODULES = normalizeModules(rawModules).map(applyModuleOverrides);
  const API_KEYS_ENDPOINT = 'php/api/api_keys.php';
  const API_QUERY_ENDPOINT = 'php/api/query.php';
  const AUTH_ENDPOINT = 'php/api/auth.php';

  const modList = document.getElementById('settingsModuleList');
  const panel = document.getElementById('settingsPanel');
  const toast = document.getElementById('settingsToast');
  const saveBtn = document.getElementById('saveChanges');
  const importBtn = document.getElementById('importKeys');
  const exportBtn = document.getElementById('exportKeys');
  const resetBtn = document.getElementById('resetFactory');
  const dbMaintStatsBtn = document.getElementById('dbMaintStats');
  const dbMaintAnalyzeBtn = document.getElementById('dbMaintAnalyze');
  const dbMaintOptimizeBtn = document.getElementById('dbMaintOptimize');
  const dbMaintOutput = document.getElementById('dbMaintOutput');

  const sidebar = document.getElementById('sidebar');
  const sidebarOpen = document.getElementById('sidebarToggle');
  const sidebarClose = document.getElementById('sidebarClose');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const logoutBtn = document.getElementById('logoutBtn');
  const clockEl = document.getElementById('currentTime');

  let activeSlug = STATIC_MODULES[0]?.slug || null;

  function isApiKeySetting(setting) {
    const key = String(setting?.key || '');
    return key === '_api_key_input' || /^api(?:[_-]?key)(?:[_-].+)?$/i.test(key);
  }

  function normalizeModules(modules) {
    return modules.map(module => ({
      slug: String(module?.slug || ''),
      name: String(module?.name || module?.slug || 'Module'),
      isPlatform: Boolean(module?.isPlatform),
      info: {
        description: String(module?.info?.description || ''),
        category: String(module?.info?.category || (module?.isPlatform ? 'platform' : 'module')),
        tags: String(module?.info?.tags || ''),
        website: String(module?.info?.website || ''),
      },
      apiConfig: module?.apiConfig
        ? {
            requiresKey: Boolean(module.apiConfig.requiresKey),
            hasKey: Boolean(module.apiConfig.hasKey),
            maskedKey: String(module.apiConfig.maskedKey || module.apiConfig.apiKeyMasked || ''),
            isEnabled: Boolean(module.apiConfig.isEnabled),
            healthStatus: String(module.apiConfig.healthStatus || 'unknown'),
            baseUrl: String(module.apiConfig.baseUrl || ''),
            rateLimit: Number(module.apiConfig.rateLimit || 0),
            authType: String(module.apiConfig.authType || 'none'),
            supportedTypes: Array.isArray(module.apiConfig.supportedTypes) ? module.apiConfig.supportedTypes.map(String) : [],
            updatedAt: String(module.apiConfig.updatedAt || 'Unknown'),
          }
        : null,
      settings: Array.isArray(module?.settings)
        ? module.settings.map(setting => ({
            key: String(setting?.key || ''),
            label: String(setting?.label || setting?.key || 'Setting'),
            type: String(setting?.type || 'text'),
            value: setting?.value ?? '',
            description: String(setting?.description || ''),
            placeholder: String(setting?.placeholder || ''),
            help: String(setting?.help || ''),
          }))
        : [],
    }));
  }

  function getSettingValue(module, key, fallback = '') {
    return module.settings.find(setting => setting.key === key)?.value ?? fallback;
  }

  function apiKeySetting(description, placeholder = 'Paste API key here...') {
    return {
      key: 'api_key',
      label: 'API Key',
      type: 'text',
      value: '',
      description,
      placeholder,
      help: 'API key field',
    };
  }

  function getModuleUiOverride(module) {
    switch (module.slug) {
      case '_global':
        return {
          displaySlug: '_global',
          settings: [
            {
              key: 'debug',
              label: 'Debug',
              type: 'boolean',
              value: getSettingValue(module, 'debug', false),
              description: 'Enable debugging?',
              placeholder: '',
              help: '',
            },
            {
              key: 'dns_resolver',
              label: 'DNS Resolver',
              type: 'text',
              value: getSettingValue(module, 'dns_resolver', ''),
              description: 'Override the default resolver with another DNS server. For example, 8.8.8.8 is Google\'s open DNS server.',
              placeholder: '',
              help: '',
            },
            {
              key: 'http_timeout',
              label: 'HTTP Timeout',
              type: 'number',
              value: getSettingValue(module, 'http_timeout', 15),
              description: 'Number of seconds before giving up on a HTTP request.',
              placeholder: '',
              help: '',
            },
            {
              key: 'generic_usernames',
              label: 'Generic Usernames',
              type: 'text',
              value: getSettingValue(module, 'generic_usernames', 'abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,'),
              description: 'List of usernames that if found as usernames or as part of e-mail addresses, should be treated differently to non-generics.',
              placeholder: '',
              help: '',
            },
            {
              key: 'tld_list_url',
              label: 'Internet TLD List',
              type: 'text',
              value: getSettingValue(module, 'tld_list_url', 'https://publicsuffix.org/list/effective_tld_names.dat'),
              description: 'List of Internet TLDs.',
              placeholder: '',
              help: '',
            },
            {
              key: 'tld_cache_hours',
              label: 'TLD Cache Hours',
              type: 'number',
              value: getSettingValue(module, 'tld_cache_hours', 72),
              description: 'Hours to cache the Internet TLD list. This can safely be quite a long time given that the list doesn\'t change too often.',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_concurrent_modules',
              label: 'Max Concurrent Modules',
              type: 'number',
              value: getSettingValue(module, 'max_concurrent_modules', 3),
              description: 'Max number of modules to run concurrently',
              placeholder: '',
              help: '',
            },
            {
              key: 'socks_type',
              label: 'SOCKS Type',
              type: 'text',
              value: getSettingValue(module, 'socks_type', ''),
              description: 'SOCKS Server Type. Can be \'4\', \'5\', \'HTTP\' or \'TOR\'',
              placeholder: '',
              help: '',
            },
            {
              key: 'socks_host',
              label: 'SOCKS Host',
              type: 'text',
              value: getSettingValue(module, 'socks_host', ''),
              description: 'SOCKS Server IP Address.',
              placeholder: '',
              help: '',
            },
            {
              key: 'socks_port',
              label: 'SOCKS Port',
              type: 'text',
              value: getSettingValue(module, 'socks_port', ''),
              description: 'SOCKS Server TCP Port. Usually 1080 for 4/5, 8080 for HTTP and 9050 for TOR.',
              placeholder: '',
              help: '',
            },
            {
              key: 'socks_username',
              label: 'SOCKS Username',
              type: 'text',
              value: getSettingValue(module, 'socks_username', ''),
              description: 'SOCKS Username. Valid only for SOCKS4 and SOCKS5 servers.',
              placeholder: '',
              help: '',
            },
            {
              key: 'socks_password',
              label: 'SOCKS Password',
              type: 'text',
              value: getSettingValue(module, 'socks_password', ''),
              description: 'SOCKS Password. Valid only for SOCKS5 servers.',
              placeholder: '',
              help: '',
            },
            {
              key: 'user_agent',
              label: 'User-Agent',
              type: 'text',
              value: getSettingValue(module, 'user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'),
              description: 'User-Agent string to use for HTTP requests. Prefix with an \'@\' to randomly select the User Agent from a file containing user agent strings for each request, e.g. @C:\\useragents.txt or @/home/bob/useragents.txt. Or supply a URL to load the list from there.',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'abuseipdb':
        return {
          displaySlug: 'sfp_abuseipdb',
          info: {
            description: 'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.',
            category: 'Reputation Systems',
            tags: 'apikey',
            website: 'https://www.abuseipdb.com',
          },
          settings: [
            apiKeySetting('AbuseIPDB.com API key.'),
            {
              key: 'check_affiliates',
              label: 'Apply checks to affiliates?',
              type: 'boolean',
              value: getSettingValue(module, 'check_affiliates', true),
              description: 'Apply checks to affiliates?',
              placeholder: '',
              help: '',
            },
            {
              key: 'min_confidence',
              label: 'Minimum confidence',
              type: 'number',
              value: getSettingValue(module, 'min_confidence', 90),
              description: 'The minimum AbuseIPDB confidence level to require.',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_results',
              label: 'Maximum results',
              type: 'number',
              value: getSettingValue(module, 'max_results', 10000),
              description: 'Maximum number of results to retrieve.',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'abuse-ch':
        return {
          displaySlug: 'sfp_abusech',
          info: {
            description: 'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.',
            category: 'Reputation Systems',
            tags: '',
            website: 'https://www.abuse.ch',
          },
          settings: [
            {
              key: 'check_feodo_ip',
              label: 'Enable abuse.ch Feodo IP check?',
              type: 'boolean',
              value: getSettingValue(module, 'check_feodo_ip', true),
              description: 'Enable abuse.ch Feodo IP check?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_ssl_blacklist',
              label: 'Enable abuse.ch SSL Blacklist IP check?',
              type: 'boolean',
              value: getSettingValue(module, 'check_ssl_blacklist', true),
              description: 'Enable abuse.ch SSL Blacklist IP check?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_urlhaus',
              label: 'Enable abuse.ch URLHaus check?',
              type: 'boolean',
              value: getSettingValue(module, 'check_urlhaus', true),
              description: 'Enable abuse.ch URLHaus check?',
              placeholder: '',
              help: '',
            },
            {
              key: 'cache_hours',
              label: 'Cache hours',
              type: 'number',
              value: getSettingValue(module, 'cache_hours', 18),
              description: 'Hours to cache list data before re-fetching.',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_affiliates',
              label: 'Apply checks to affiliates?',
              type: 'boolean',
              value: getSettingValue(module, 'check_affiliates', true),
              description: 'Apply checks to affiliates?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_cohosts',
              label: 'Apply checks to co-hosted sites?',
              type: 'boolean',
              value: getSettingValue(module, 'check_cohosts', true),
              description: 'Apply checks to sites found to be co-hosted on the target\'s IP?',
              placeholder: '',
              help: '',
            },
            {
              key: 'report_netblocks',
              label: 'Report malicious IPs on owned netblocks?',
              type: 'boolean',
              value: getSettingValue(module, 'report_netblocks', true),
              description: 'Report if any malicious IPs are found within owned netblocks?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_subnet',
              label: 'Check same subnet?',
              type: 'boolean',
              value: getSettingValue(module, 'check_subnet', true),
              description: 'Check if any malicious IPs are found within the same subnet of the target?',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'shodan':
        return {
          displaySlug: 'sfp_shodan',
          info: {
            description: 'Obtain information from SHODAN about identified IP addresses. Shodan is the world\'s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.',
            category: 'Search Engines',
            tags: 'apikey',
            website: 'https://www.shodan.io/',
          },
          settings: [
            apiKeySetting('SHODAN API Key.'),
            {
              key: 'netblock_size',
              label: 'Maximum netblock size',
              type: 'number',
              value: getSettingValue(module, 'netblock_size', 24),
              description: 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'lookup_netblocks',
              label: 'Look up owned netblocks?',
              type: 'boolean',
              value: getSettingValue(module, 'lookup_netblocks', true),
              description: 'Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'apivoid':
        return {
          displaySlug: 'sfp_apivoid',
          info: {
            description: 'Use APIVoid to check IP, domain, URL, and email reputation through multiple security and risk-analysis endpoints.',
            category: 'Reputation Systems',
            tags: 'apikey',
            website: 'https://docs.apivoid.com',
          },
          settings: [
            apiKeySetting('APIVoid API Key.'),
            {
              key: 'check_ip_reputation',
              label: 'Check IP reputation?',
              type: 'boolean',
              value: getSettingValue(module, 'check_ip_reputation', true),
              description: 'Query the IP Reputation endpoint to check whether the IP is risky or blacklisted.',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_domain_reputation',
              label: 'Check domain reputation?',
              type: 'boolean',
              value: getSettingValue(module, 'check_domain_reputation', true),
              description: 'Query the Domain Reputation endpoint to check domains against blacklist and risk signals.',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_url_reputation',
              label: 'Check URL reputation?',
              type: 'boolean',
              value: getSettingValue(module, 'check_url_reputation', true),
              description: 'Query the URL Reputation endpoint for phishing, malware, and suspicious URL patterns.',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_email_verify',
              label: 'Verify email addresses?',
              type: 'boolean',
              value: getSettingValue(module, 'check_email_verify', true),
              description: 'Validate email addresses and check for disposable or risky providers.',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_affiliates',
              label: 'Apply checks to affiliates?',
              type: 'boolean',
              value: getSettingValue(module, 'check_affiliates', true),
              description: 'Apply checks to affiliates of the target?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_cohosts',
              label: 'Apply checks to co-hosted sites?',
              type: 'boolean',
              value: getSettingValue(module, 'check_cohosts', true),
              description: 'Apply checks to sites found to be co-hosted on the target\'s IP?',
              placeholder: '',
              help: '',
            },
            {
              key: 'min_blacklist_detections',
              label: 'Minimum blacklist detections',
              type: 'number',
              value: getSettingValue(module, 'min_blacklist_detections', 1),
              description: 'Minimum number of blacklist detections before reporting a result.',
              placeholder: '',
              help: '',
            },
            {
              key: 'request_timeout',
              label: 'Request timeout',
              type: 'number',
              value: getSettingValue(module, 'request_timeout', 15),
              description: 'Timeout in seconds for each APIVoid request.',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'alienvault':
        return {
          displaySlug: 'sfp_alienvault',
          info: {
            description: 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.',
            category: 'Reputation Systems',
            tags: 'apikey',
            website: 'https://otx.alienvault.com/',
          },
          settings: [
            apiKeySetting('AlienVault OTX API Key.'),
            {
              key: 'check_affiliates',
              label: 'Apply checks to affiliates?',
              type: 'boolean',
              value: getSettingValue(module, 'check_affiliates', true),
              description: 'Apply checks to affiliates?',
              placeholder: '',
              help: '',
            },
            {
              key: 'cohost_age_limit',
              label: 'Co-host age limit',
              type: 'number',
              value: getSettingValue(module, 'cohost_age_limit', 30),
              description: 'Ignore any co-hosts older than this many days. 0 = unlimited.',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_url_pages',
              label: 'Maximum URL pages',
              type: 'number',
              value: getSettingValue(module, 'max_url_pages', 50),
              description: 'Maximum number of pages of URI results to fetch.',
              placeholder: '',
              help: '',
            },
            {
              key: 'cohost_stop_count',
              label: 'Co-host stop count',
              type: 'number',
              value: getSettingValue(module, 'cohost_stop_count', 100),
              description: 'Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_netblock_size_ipv4',
              label: 'Maximum IPv4 netblock size',
              type: 'number',
              value: getSettingValue(module, 'max_netblock_size_ipv4', 24),
              description: 'If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_subnet_size_ipv4',
              label: 'Maximum IPv4 subnet size',
              type: 'number',
              value: getSettingValue(module, 'max_subnet_size_ipv4', 24),
              description: 'If looking up subnets, the maximum IPv4 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_netblock_size_ipv6',
              label: 'Maximum IPv6 netblock size',
              type: 'number',
              value: getSettingValue(module, 'max_netblock_size_ipv6', 120),
              description: 'If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'max_subnet_size_ipv6',
              label: 'Maximum IPv6 subnet size',
              type: 'number',
              value: getSettingValue(module, 'max_subnet_size_ipv6', 120),
              description: 'If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'lookup_netblocks',
              label: 'Look up owned netblocks?',
              type: 'boolean',
              value: getSettingValue(module, 'lookup_netblocks', true),
              description: 'Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?',
              placeholder: '',
              help: '',
            },
            {
              key: 'reputation_age_limit',
              label: 'Reputation age limit',
              type: 'number',
              value: getSettingValue(module, 'reputation_age_limit', 30),
              description: 'Ignore any reputation records older than this many days. 0 = unlimited.',
              placeholder: '',
              help: '',
            },
            {
              key: 'lookup_subnets',
              label: 'Look up subnets?',
              type: 'boolean',
              value: getSettingValue(module, 'lookup_subnets', true),
              description: 'Look up all IPs on subnets which your target is a part of for blacklisting?',
              placeholder: '',
              help: '',
            },
            {
              key: 'min_threat_score',
              label: 'Minimum threat score',
              type: 'number',
              value: getSettingValue(module, 'min_threat_score', 2),
              description: 'Minimum AlienVault threat score.',
              placeholder: '',
              help: '',
            },
            {
              key: 'verify_cohosts',
              label: 'Verify co-hosts?',
              type: 'boolean',
              value: getSettingValue(module, 'verify_cohosts', true),
              description: 'Verify co-hosts are valid by checking if they still resolve to the shared IP.',
              placeholder: '',
              help: '',
            },
          ],
        };

      case 'virustotal':
        return {
          displaySlug: 'sfp_virustotal',
          info: {
            description: 'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.',
            category: 'Reputation Systems',
            tags: 'apikey',
            website: 'https://www.virustotal.com/',
          },
          settings: [
            apiKeySetting('VirusTotal API Key.'),
            {
              key: 'check_affiliates',
              label: 'Check affiliates?',
              type: 'boolean',
              value: getSettingValue(module, 'check_affiliates', true),
              description: 'Check affiliates?',
              placeholder: '',
              help: '',
            },
            {
              key: 'check_co_hosted',
              label: 'Check co-hosted sites?',
              type: 'boolean',
              value: getSettingValue(module, 'check_co_hosted', true),
              description: 'Check co-hosted sites?',
              placeholder: '',
              help: '',
            },
            {
              key: 'netblock_size',
              label: 'Maximum netblock size',
              type: 'number',
              value: getSettingValue(module, 'netblock_size', 24),
              description: 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'subnet_size',
              label: 'Maximum subnet size',
              type: 'number',
              value: getSettingValue(module, 'subnet_size', 24),
              description: 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
              placeholder: '',
              help: '',
            },
            {
              key: 'lookup_netblock_ips',
              label: 'Look up owned netblocks?',
              type: 'boolean',
              value: getSettingValue(module, 'lookup_netblock_ips', true),
              description: 'Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?',
              placeholder: '',
              help: '',
            },
            {
              key: 'public_key',
              label: 'Using a public key?',
              type: 'boolean',
              value: getSettingValue(module, 'public_key', true),
              description: 'Are you using a public key? If so SpiderFoot will pause for 15 seconds after each query to avoid VirusTotal dropping requests.',
              placeholder: '',
              help: '',
            },
            {
              key: 'lookup_subnet_ips',
              label: 'Look up subnets?',
              type: 'boolean',
              value: getSettingValue(module, 'lookup_subnet_ips', true),
              description: 'Look up all IPs on subnets which your target is a part of?',
              placeholder: '',
              help: '',
            },
            {
              key: 'verify_hostnames',
              label: 'Verify hostnames?',
              type: 'boolean',
              value: getSettingValue(module, 'verify_hostnames', true),
              description: 'Verify that any hostnames found on the target domain still resolve?',
              placeholder: '',
              help: '',
            },
          ],
        };

      default:
        return null;
    }
  }

  function applyModuleOverrides(module) {
    const override = getModuleUiOverride(module);
    const displaySlug = SPIDERFOOT_DISPLAY_SLUGS[module.slug] || module.slug;
    if (!override) {
      return { ...module, displaySlug };
    }

    return {
      ...module,
      displaySlug: override.displaySlug || displaySlug,
      info: { ...module.info, ...(override.info || {}) },
      settings: override.settings || module.settings,
    };
  }

  function compareModulesBySpiderFootOrder(left, right) {
    const leftSlug = String(left?.slug || '').toLowerCase();
    const rightSlug = String(right?.slug || '').toLowerCase();

    if (leftSlug === rightSlug) return 0;
    if (leftSlug === '_global') return -1;
    if (rightSlug === '_global') return 1;

    const leftIndex = Object.prototype.hasOwnProperty.call(spiderFootOrderIndex, leftSlug)
      ? spiderFootOrderIndex[leftSlug]
      : Number.MAX_SAFE_INTEGER;
    const rightIndex = Object.prototype.hasOwnProperty.call(spiderFootOrderIndex, rightSlug)
      ? spiderFootOrderIndex[rightSlug]
      : Number.MAX_SAFE_INTEGER;

    if (leftIndex !== rightIndex) {
      return leftIndex - rightIndex;
    }

    return String(left?.name || '').localeCompare(String(right?.name || ''));
  }

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escWithBreaks(value) {
    return esc(value).replace(/\n/g, '<br>');
  }

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'api-toast toast-success api-toast-success show';
    toast.classList.remove('hidden');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
      toast.classList.remove('show');
      toast.classList.add('hidden');
    }, 2800);
  }

  function showError(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.className = 'api-toast toast-error api-toast-error show';
    toast.classList.remove('hidden');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
      toast.classList.remove('show');
      toast.classList.add('hidden');
    }, 3200);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, { credentials: 'same-origin', ...options });
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }

    if (!response.ok) {
      const error = new Error(payload?.error || payload?.message || 'Request failed.');
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async function fetchCsrfToken() {
    const data = await fetchJson(`${AUTH_ENDPOINT}?action=csrf`);
    if (!data?.csrf_token) {
      throw new Error('Could not get CSRF token.');
    }
    return data.csrf_token;
  }

  function isCsrfError(error) {
    const message = String(error?.message || '');
    return Number(error?.status || 0) === 403 && /csrf/i.test(message);
  }

  async function postJsonWithFreshCsrf(url, payload, options = {}) {
    let lastError = null;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const csrfToken = await fetchCsrfToken();

      try {
        return await fetchJson(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
          ...options,
          body: JSON.stringify({
            ...(payload && typeof payload === 'object' ? payload : {}),
            _csrf_token: csrfToken,
          }),
        });
      } catch (error) {
        lastError = error;
        if (!isCsrfError(error) || attempt > 0) {
          throw error;
        }
      }
    }

    throw lastError || new Error('Request failed.');
  }

  function downloadBlob(content, filename, mime = 'application/json') {
    const blob = new Blob([content], { type: mime });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  function toBoolean(value) {
    if (typeof value === 'boolean') return value;
    const normalized = String(value ?? '').trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(normalized);
  }

  function maskApiKeyForDisplay(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    if (raw.length <= 4) return '*'.repeat(raw.length);
    const suffix = raw.slice(-4);
    const stars = '*'.repeat(Math.min(8, Math.max(4, raw.length - 4)));
    return `${stars}${suffix}`;
  }

  function coerceSettingValue(setting, rawValue) {
    if (!setting) return rawValue;
    if (setting.type === 'boolean') {
      return toBoolean(rawValue);
    }
    if (setting.type === 'number') {
      const n = Number(rawValue);
      return Number.isFinite(n) ? n : setting.value;
    }
    return String(rawValue ?? '');
  }

  async function hydrateApiConfigSnapshot() {
    const data = await fetchJson(`${API_KEYS_ENDPOINT}?action=list`);
    const apiList = Array.isArray(data?.apis) ? data.apis : [];
    const map = new Map(apiList.map((row) => [String(row.slug || ''), row]));

    STATIC_MODULES.forEach((module) => {
      if (module.isPlatform || !module.apiConfig) return;
      const live = map.get(module.slug);
      if (!live) return;

      module.apiConfig.requiresKey = Boolean(live.requires_key ?? module.apiConfig.requiresKey);
      module.apiConfig.hasKey = Boolean(live.has_key ?? module.apiConfig.hasKey);
      module.apiConfig.maskedKey = String((live.api_key_masked ?? module.apiConfig.maskedKey) || '');
      module.apiConfig.isEnabled = Boolean(live.is_enabled ?? module.apiConfig.isEnabled);
      module.apiConfig.healthStatus = String((live.health_status ?? module.apiConfig.healthStatus) || 'unknown');
      module.apiConfig.baseUrl = String((live.base_url ?? module.apiConfig.baseUrl) || '');
      module.apiConfig.rateLimit = Number((live.rate_limit ?? module.apiConfig.rateLimit) || 0);
      module.apiConfig.authType = String((live.auth_type ?? module.apiConfig.authType) || 'none');
      module.apiConfig.supportedTypes = Array.isArray(live.supported_types)
        ? live.supported_types.map(String)
        : module.apiConfig.supportedTypes;
      module.apiConfig.updatedAt = String((live.updated_at ?? module.apiConfig.updatedAt) || '');
    });
  }

  async function hydratePersistedSettings() {
    const snapshot = await fetchJson(`${API_KEYS_ENDPOINT}?action=settings_snapshot`);
    const platform = snapshot?.platform_settings && typeof snapshot.platform_settings === 'object'
      ? snapshot.platform_settings
      : {};
    const modules = snapshot?.module_settings && typeof snapshot.module_settings === 'object'
      ? snapshot.module_settings
      : {};

    STATIC_MODULES.forEach((module) => {
      const overrides = module.isPlatform
        ? platform
        : (modules[module.slug] && typeof modules[module.slug] === 'object' ? modules[module.slug] : null);

      if (!overrides) return;

      module.settings.forEach((setting) => {
        if (!Object.prototype.hasOwnProperty.call(overrides, setting.key)) return;
        setting.value = coerceSettingValue(setting, overrides[setting.key]);
      });
    });
  }

  async function refreshSettingsSnapshot() {
    await hydrateApiConfigSnapshot();
    await hydratePersistedSettings();
    renderModuleList();
    renderPanel();
  }

  function renderMaintenanceOutput(payload) {
    if (!dbMaintOutput) return;
    dbMaintOutput.textContent = JSON.stringify(payload, null, 2);
  }

  async function runDbMaintenance(task) {
    const data = await postJsonWithFreshCsrf(`${API_QUERY_ENDPOINT}?action=db_maintenance`, {
      task,
    });
    renderMaintenanceOutput(data);
    return data;
  }

  function getActiveModule() {
    return STATIC_MODULES.find(item => item.slug === activeSlug) || null;
  }

  function collectActiveSettings(module) {
    const payload = {};
    let apiKey = '';

    const inputs = panel?.querySelectorAll('.settings-input[data-setting-key]') || [];
    inputs.forEach((input) => {
      const key = String(input.dataset.settingKey || '').trim();
      if (!key) return;

      const type = String(input.dataset.settingType || 'text').toLowerCase();
      const isPrimaryApiKey = input.dataset.apiKeyInput === '1';
      const isSensitiveApi = input.dataset.sensitiveApi === '1';
      const raw = String(input.value ?? '');

      if (isPrimaryApiKey) {
        apiKey = raw.trim();
        return;
      }

      if (isSensitiveApi && raw.trim() === '') {
        // Keep existing stored secret unchanged when user leaves field empty.
        return;
      }

      const normalized = type === 'boolean'
        ? (toBoolean(raw) ? '1' : '0')
        : raw.trim();

      payload[key] = normalized;
    });

    module.settings.forEach((setting) => {
      if (!Object.prototype.hasOwnProperty.call(payload, setting.key)) return;
      setting.value = coerceSettingValue(setting, payload[setting.key]);
    });

    return { payload, apiKey };
  }

  async function saveActiveModuleChanges() {
    const module = getActiveModule();
    if (!module) {
      throw new Error('No active module selected.');
    }

    const { payload, apiKey } = collectActiveSettings(module);

    if (Object.keys(payload).length > 0) {
      await postJsonWithFreshCsrf(`${API_KEYS_ENDPOINT}?action=save_settings`, {
        slug: module.slug,
        settings: payload,
      });
    }

    if (!module.isPlatform && module.apiConfig?.requiresKey && apiKey !== '') {
      await postJsonWithFreshCsrf(`${API_KEYS_ENDPOINT}?action=save`, {
        slug: module.slug,
        api_key: apiKey,
      });

      module.apiConfig.hasKey = true;
      module.apiConfig.maskedKey = maskApiKeyForDisplay(apiKey);
      const apiKeyInput = panel?.querySelector('input.settings-input[data-api-key-input="1"]');
      if (apiKeyInput) {
        apiKeyInput.value = '';
        apiKeyInput.placeholder = getApiKeyPlaceholder(module);
      }
    }

    renderModuleList();
    return module.name;
  }

  async function exportConfigurationSnapshot() {
    const data = await postJsonWithFreshCsrf(`${API_KEYS_ENDPOINT}?action=export_snapshot`, {});

    const snapshot = data?.snapshot;
    if (!snapshot || typeof snapshot !== 'object') {
      throw new Error('Snapshot export returned an invalid payload.');
    }

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadBlob(
      JSON.stringify(snapshot, null, 2),
      `cti-settings-snapshot-${stamp}.json`
    );
  }

  async function importConfigurationSnapshot(snapshot) {
    await postJsonWithFreshCsrf(`${API_KEYS_ENDPOINT}?action=import_snapshot`, {
      snapshot,
    });

    await refreshSettingsSnapshot();
  }

  function promptSnapshotImport() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.addEventListener('change', async () => {
      const [file] = input.files || [];
      if (!file) return;

      try {
        const text = await file.text();
        const snapshot = JSON.parse(text);
        await importConfigurationSnapshot(snapshot);
        showToast('Configuration snapshot imported successfully.');
      } catch (err) {
        showError(err instanceof Error ? err.message : 'Failed to import configuration snapshot.');
      }
    }, { once: true });
    input.click();
  }

  function updateClock() {
    if (!clockEl) return;
    clockEl.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  }

  function openSidebar() {
    sidebar?.classList.add('open');
    sidebarOverlay?.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    sidebar?.classList.remove('open');
    sidebarOverlay?.classList.remove('active');
    document.body.style.overflow = '';
  }

  function getModuleAccessIcon(module) {
    if (module.isPlatform) return '';

    if (module.apiConfig?.requiresKey) {
      return `<span class="settings-mod-icon locked" title="Requires API key" aria-label="Requires API key">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="11" width="18" height="10" rx="2"></rect>
          <path d="M7 11V8a5 5 0 0 1 10 0v3"></path>
        </svg>
      </span>`;
    }

    return `<span class="settings-mod-icon unlocked" title="No API key required" aria-label="No API key required">
      <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="3" y="11" width="18" height="10" rx="2"></rect>
        <path d="M7 11V8a5 5 0 0 1 9.2-2.8"></path>
      </svg>
    </span>`;
  }

  function renderModuleList() {
    if (!modList) return;

    if (!STATIC_MODULES.length) {
      modList.innerHTML = '<div class="settings-panel-empty"><p class="label" style="color:var(--muted-fg);">No modules available.</p></div>';
      return;
    }

    const platformModules = STATIC_MODULES.filter(module => module.isPlatform);
    const regularModules = STATIC_MODULES
      .filter(module => !module.isPlatform)
      .sort(compareModulesBySpiderFootOrder);
    let html = '';

    platformModules.forEach(module => {
      html += `<button class="settings-mod-item is-platform${activeSlug === module.slug ? ' active' : ''}" data-slug="${esc(module.slug)}">
        <span class="settings-mod-name">${esc(module.name)}</span>
      </button>`;
    });

    if (platformModules.length && regularModules.length) {
      html += '<div class="settings-mod-divider"></div>';
    }

    regularModules.forEach(module => {
      html += `<button class="settings-mod-item${activeSlug === module.slug ? ' active' : ''}" data-slug="${esc(module.slug)}">
        <span class="settings-mod-name">${esc(module.name)}</span>
        <span class="settings-mod-meta">${getModuleAccessIcon(module)}</span>
      </button>`;
    });

    modList.innerHTML = html;
  }

  function renderInfoTable(info) {
    const rows = [];
    if (info.description) rows.push(`<tr><td class="settings-info-label">Summary</td><td>${escWithBreaks(info.description)}</td></tr>`);
    if (info.category) rows.push(`<tr><td class="settings-info-label">Category</td><td>${esc(info.category)}</td></tr>`);
    if (info.tags) rows.push(`<tr><td class="settings-info-label">Tags</td><td>${esc(info.tags)}</td></tr>`);
    if (info.website) rows.push(`<tr><td class="settings-info-label">Website</td><td><a href="${esc(info.website)}" target="_blank" rel="noopener" class="accent-text">${esc(info.website)}</a></td></tr>`);
    return rows.length ? `<table class="settings-info-table">${rows.join('')}</table>` : '';
  }

  function moduleHasApiKeyField(module) {
    return module.settings.some(setting => {
      const key = String(setting?.key || '');
      return key === '_api_key_input' || key === 'api_key';
    });
  }

  function getApiKeyPlaceholder(module) {
    if (module.apiConfig?.hasKey) {
      const masked = String(module.apiConfig?.maskedKey || '').trim();
      return masked ? `Configured: ${masked}` : 'API key already configured';
    }
    return 'Paste API key here...';
  }

  function buildModuleSettings(module) {
    const syntheticSettings = [];

    if (!module.isPlatform && module.apiConfig?.requiresKey && !moduleHasApiKeyField(module)) {
      syntheticSettings.push({
        key: '_api_key_input',
        label: 'API Key',
        type: 'text',
        value: '',
        description: 'API Key',
        placeholder: getApiKeyPlaceholder(module),
      });
    }

    return [...syntheticSettings, ...module.settings];
  }

  function renderSettingLabel(setting) {
    const text = esc(setting.description || setting.label);
    if (!setting.help) return text;
    return `${text}<span class="settings-inline-icon" title="${esc(setting.help)}" aria-hidden="true">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="9"></circle>
        <path d="M9.1 9a3 3 0 1 1 5.8 1c0 2-3 2-3 4"></path>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    </span>`;
  }

  function renderSettingsTable(module) {
    const visibleSettings = buildModuleSettings(module);

    if (!visibleSettings.length) {
      return `<section>
        <h3 class="settings-section-title">Module Settings</h3>
        <div class="settings-static-panel-note">No additional editable settings are configured for this module.</div>
      </section>`;
    }

    const rows = visibleSettings.map(setting => {
      const settingType = String(setting.type || 'text').toLowerCase();
      const value = setting.value ?? '';
      const isPrimaryApiKeyField = setting.key === '_api_key_input'
        || (setting.key === 'api_key' && module.apiConfig?.requiresKey);
      const isApiKeyField = isApiKeySetting(setting);
      const maskedSettingValue = maskApiKeyForDisplay(value);
      const sensitivePlaceholder = isPrimaryApiKeyField
        ? getApiKeyPlaceholder(module)
        : (maskedSettingValue ? `Configured: ${maskedSettingValue}` : (setting.placeholder || 'Paste API key here...'));
      const input = setting.type === 'boolean'
        ? `<select class="input input-sm settings-input" data-setting-key="${esc(setting.key)}" data-setting-type="boolean">
            <option value="1"${toBoolean(value) ? ' selected' : ''}>True</option>
            <option value="0"${toBoolean(value) ? '' : ' selected'}>False</option>
          </select>`
        : `<input
            type="${settingType === 'number' ? 'number' : 'text'}"
            class="input input-sm settings-input"
            data-setting-key="${esc(setting.key)}"
            data-setting-type="${esc(settingType)}"
            ${isPrimaryApiKeyField ? 'data-api-key-input="1" autocomplete="new-password" spellcheck="false"' : ''}
            ${isApiKeyField ? 'data-sensitive-api="1"' : ''}
            value="${esc(isApiKeyField ? '' : value)}"
            placeholder="${esc(isApiKeyField ? sensitivePlaceholder : (setting.placeholder || ''))}"
            ${settingType === 'number' ? 'step="any"' : ''}
            ${isApiKeyField ? 'autocomplete="new-password" spellcheck="false"' : ''}
          >`;

      return `<tr>
        <td class="settings-option-label">${renderSettingLabel(setting)}</td>
        <td class="settings-option-value">${input}</td>
      </tr>`;
    });

    return `<section>
      <h3 class="settings-section-title">Module Settings</h3>
      <div class="settings-static-panel-note">Edit values as needed, then click Save Changes to persist them.</div>
      <table class="settings-form-table">
        <thead><tr><th>Option</th><th>Value</th></tr></thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </section>`;
  }

  function renderEmptyPanel() {
    if (!panel) return;
    panel.innerHTML = '<div class="settings-panel-empty"><p class="label" style="color:var(--muted-fg);">No modules available.</p></div>';
  }

  function renderPanel() {
    if (!panel) return;
    if (!STATIC_MODULES.length) {
      renderEmptyPanel();
      return;
    }

    const module = STATIC_MODULES.find(item => item.slug === activeSlug) || STATIC_MODULES[0];
    if (!module) {
      renderEmptyPanel();
      return;
    }

    panel.innerHTML = `<div class="settings-panel-stack">
      <section>
        <div class="settings-section-head">
          <div>
            <h2 class="settings-heading">${esc(module.name)} <span class="settings-slug">(${esc(module.displaySlug || module.slug)})</span></h2>
          </div>
          <div class="settings-heading-badges">
            <span class="badge badge-info">${module.isPlatform ? 'Platform' : esc(module.info.category || 'module')}</span>
            <span class="badge badge-medium">Editable</span>
          </div>
        </div>
        ${renderInfoTable(module.info)}
      </section>

      ${renderSettingsTable(module)}
    </div>`;
  }

  modList?.addEventListener('click', event => {
    const item = event.target.closest('.settings-mod-item');
    if (!item) return;
    activeSlug = item.dataset.slug;
    renderModuleList();
    renderPanel();
  });

  saveBtn?.addEventListener('click', async () => {
    const original = saveBtn.innerHTML;
    try {
      saveBtn.disabled = true;
      saveBtn.innerHTML = 'Saving...';
      const moduleName = await saveActiveModuleChanges();
      showToast(`Saved settings for ${moduleName}.`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to save settings.');
    } finally {
      saveBtn.disabled = false;
      saveBtn.innerHTML = original;
    }
  });

  importBtn?.addEventListener('click', () => {
    promptSnapshotImport();
  });

  exportBtn?.addEventListener('click', async () => {
    try {
      await exportConfigurationSnapshot();
      showToast('Configuration snapshot exported.');
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to export configuration snapshot.');
    }
  });

  resetBtn?.addEventListener('click', () => {
    showToast('Factory reset is still not available from this page.');
  });

  dbMaintStatsBtn?.addEventListener('click', async () => {
    try {
      renderMaintenanceOutput({ status: 'running', task: 'stats' });
      const data = await runDbMaintenance('stats');
      showToast(`Loaded database stats for ${Array.isArray(data.tables) ? data.tables.length : 0} table(s).`);
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load database stats.');
    }
  });

  dbMaintAnalyzeBtn?.addEventListener('click', async () => {
    try {
      renderMaintenanceOutput({ status: 'running', task: 'analyze' });
      await runDbMaintenance('analyze');
      showToast('Analyze task completed.');
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to analyze database tables.');
    }
  });

  dbMaintOptimizeBtn?.addEventListener('click', async () => {
    try {
      renderMaintenanceOutput({ status: 'running', task: 'optimize' });
      await runDbMaintenance('optimize');
      showToast('Optimize task completed.');
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to optimize database tables.');
    }
  });

  sidebarOpen?.addEventListener('click', openSidebar);
  sidebarClose?.addEventListener('click', closeSidebar);
  sidebarOverlay?.addEventListener('click', closeSidebar);
  logoutBtn?.addEventListener('click', () => {
    window.location.href = 'index.php';
  });

  updateClock();
  setInterval(updateClock, 1000);

  (async () => {
    try {
      await refreshSettingsSnapshot();
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Failed to load live settings snapshot.');
    }
  })();
});
