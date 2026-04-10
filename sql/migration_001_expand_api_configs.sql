-- =============================================================================
--  CTI PLATFORM — MIGRATION 001: Expand api_configs + Seed All OSINT Modules
--  sql/migration_001_expand_api_configs.sql
--
--  Adds new columns for category, auth type, supported query types, docs URL,
--  env key, health check tracking. Then seeds all ~180 SpiderFoot-inspired
--  OSINT modules into the api_configs table.
--
--  Run:  mysql -u root -p cti_platform < sql/migration_001_expand_api_configs.sql
-- =============================================================================

USE `cti_platform`;

-- ─── SCHEMA CHANGES ─────────────────────────────────────────────────────────

ALTER TABLE `api_configs`
  ADD COLUMN IF NOT EXISTS `category`          VARCHAR(30)   NOT NULL DEFAULT 'uncategorized' AFTER `description`,
  ADD COLUMN IF NOT EXISTS `auth_type`         ENUM('api_key','basic_auth','oauth','none') NOT NULL DEFAULT 'none' AFTER `category`,
  ADD COLUMN IF NOT EXISTS `supported_types`   JSON          DEFAULT NULL AFTER `auth_type`,
  ADD COLUMN IF NOT EXISTS `docs_url`          VARCHAR(500)  DEFAULT NULL AFTER `supported_types`,
  ADD COLUMN IF NOT EXISTS `env_key`           VARCHAR(100)  DEFAULT NULL AFTER `docs_url`,
  ADD COLUMN IF NOT EXISTS `requires_key`      TINYINT(1)    NOT NULL DEFAULT 0 AFTER `env_key`,
  ADD COLUMN IF NOT EXISTS `last_health_check` TIMESTAMP     NULL DEFAULT NULL AFTER `requires_key`,
  ADD COLUMN IF NOT EXISTS `health_status`     ENUM('unknown','healthy','degraded','down') NOT NULL DEFAULT 'unknown' AFTER `last_health_check`;

-- Add index on category for filtering
CREATE INDEX IF NOT EXISTS `idx_api_category` ON `api_configs`(`category`);

-- ─── UPDATE EXISTING 6 ROWS ────────────────────────────────────────────────

UPDATE `api_configs` SET
  `category` = 'malware', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["ip","domain","url","hash"]',
  `description` = 'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.',
  `docs_url` = 'https://developers.virustotal.com/reference',
  `env_key` = 'VIRUSTOTAL_KEY'
WHERE `slug` = 'virustotal';

UPDATE `api_configs` SET
  `category` = 'network', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["ip"]',
  `description` = 'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.',
  `docs_url` = 'https://docs.abuseipdb.com',
  `env_key` = 'ABUSEIPDB_KEY'
WHERE `slug` = 'abuseipdb';

UPDATE `api_configs` SET
  `category` = 'infra', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["ip","domain"]',
  `description` = 'Obtain information from SHODAN about identified IP addresses. Shodan is the world''s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.',
  `docs_url` = 'https://developer.shodan.io/api',
  `env_key` = 'SHODAN_KEY'
WHERE `slug` = 'shodan';

UPDATE `api_configs` SET
  `category` = 'threat', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["ip","domain","url","hash","cve"]',
  `description` = 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.',
  `docs_url` = 'https://otx.alienvault.com/api',
  `env_key` = 'ALIENVAULT_OTX_KEY'
WHERE `slug` = 'alienvault';

UPDATE `api_configs` SET
  `category` = 'network', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["ip"]',
  `docs_url` = 'https://docs.greynoise.io',
  `env_key` = 'GREYNOISE_KEY'
WHERE `slug` = 'greynoise';

UPDATE `api_configs` SET
  `category` = 'malware', `auth_type` = 'api_key', `requires_key` = 1,
  `supported_types` = '["url","domain"]',
  `docs_url` = 'https://urlscan.io/docs/api/',
  `env_key` = 'URLSCAN_KEY'
WHERE `slug` = 'urlscan';

-- ─── SEED ALL REMAINING MODULES ─────────────────────────────────────────────
-- Using INSERT ... ON DUPLICATE KEY UPDATE keyed on uq_api_slug

-- ══════════════════════════════════════════════════════════════════════════════
--  THREAT INTEL
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('abuse.ch','abuse-ch','https://bazaar.abuse.ch/api/',60,'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.','threat','none','[\"hash\",\"domain\",\"ip\",\"url\"]','https://bazaar.abuse.ch/api/',NULL,0,1),
('AlienVault IP Reputation','alienvault-ip-rep','https://otx.alienvault.com/api/v1',100,'AlienVault OTX IP reputation lookups','threat','none','[\"ip\"]','https://otx.alienvault.com/api',NULL,0,1),
('Custom Threat Feed','custom-threat-feed','',10,'User-configured custom threat intelligence feed URL','threat','api_key','[\"ip\",\"domain\",\"url\",\"hash\"]',NULL,'CUSTOM_THREAT_FEED_URL',1,0),
('CyberCrime-Tracker.net','cybercrime-tracker','https://cybercrime-tracker.net',30,'C2 panel tracker — botnet and malware command-and-control infrastructure','threat','none','[\"domain\",\"ip\",\"url\"]','https://cybercrime-tracker.net',NULL,0,1),
('Emerging Threats','emerging-threats','https://rules.emergingthreats.net',30,'Proofpoint Emerging Threats open rulesets and IP/domain blocklists','threat','none','[\"ip\",\"domain\"]','https://rules.emergingthreats.net',NULL,0,1),
('Maltiverse','maltiverse','https://api.maltiverse.com',60,'IoC enrichment — IP, domain, URL, and file hash threat scoring','threat','none','[\"ip\",\"domain\",\"hash\",\"url\"]','https://app.swaggerhub.com/apis/maltiverse/api/',NULL,0,1),
('MalwarePatrol','malwarepatrol','https://lists.malwarepatrol.net',10,'Commercial malware URL/domain/IP blocklists','threat','api_key','[\"domain\",\"ip\",\"url\",\"hash\"]','https://www.malwarepatrol.net/api-documentation/','MALWAREPATROL_KEY',1,0),
('Talos Intelligence','talos-intelligence','https://talosintelligence.com',30,'Cisco Talos IP and domain reputation intelligence','threat','none','[\"ip\",\"domain\"]','https://talosintelligence.com',NULL,0,1),
('ThreatCrowd','threatcrowd','https://www.threatcrowd.org/searchApi/v2',30,'Community-driven threat intelligence — IP, domain, email, hash correlations','threat','none','[\"ip\",\"domain\",\"email\",\"hash\"]','https://www.threatcrowd.org/searchApi/v2/',NULL,0,1),
('ThreatFox','threatfox','https://threatfox-api.abuse.ch/api/v1',60,'abuse.ch ThreatFox — IoC sharing platform for malware C2 infrastructure','threat','none','[\"ip\",\"domain\",\"hash\",\"url\"]','https://threatfox.abuse.ch/api/',NULL,0,1),
('ThreatMiner','threatminer','https://api.threatminer.org/v2',30,'Free threat intelligence portal — passive DNS, WHOIS, malware samples','threat','none','[\"ip\",\"domain\",\"hash\"]','https://www.threatminer.org/api.php',NULL,0,1),
('VXVault.net','vxvault','http://vxvault.net',10,'Malware URL collection and sample repository','threat','none','[\"url\"]','http://vxvault.net',NULL,0,1),
('XForce Exchange','xforce-exchange','https://api.xforce.ibmcloud.com',30,'IBM X-Force Exchange — threat intelligence sharing platform','threat','api_key','[\"ip\",\"domain\",\"hash\",\"url\"]','https://api.xforce.ibmcloud.com/doc/','XFORCE_KEY',1,0)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

UPDATE `api_configs`
SET `description` = 'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.'
WHERE `slug` = 'abuse-ch';

-- ══════════════════════════════════════════════════════════════════════════════
--  IP & NETWORK
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Abusix Mail Intelligence','abusix','',30,'DNS-based mail abuse intelligence service','network','api_key','[\"ip\"]','https://abusix.com','ABUSIX_KEY',1,0),
('Bad Packets','bad-packets','https://api.badpackets.net/v1',30,'Monitors and reports on internet-wide vulnerability scanning activity','network','api_key','[\"ip\"]','https://docs.badpackets.net','BADPACKETS_KEY',1,0),
('blocklist.de','blocklist-de','https://api.blocklist.de/api.php',30,'Community-driven blocklist of attacking IP addresses','network','none','[\"ip\"]','https://www.blocklist.de/en/api.html',NULL,0,1),
('BotScout','botscout','https://botscout.com/test',30,'Detects automated bot registrations by IP, email, or username','network','none','[\"ip\",\"email\"]','https://botscout.com/api.htm',NULL,0,1),
('CINS Army List','cins-army','http://cinsscore.com/list/ci-badguys.txt',10,'Collective Intelligence Network Security — curated list of malicious IPs','network','none','[\"ip\"]','http://cinsscore.com',NULL,0,1),
('CleanTalk Spam List','cleantalk','https://api.cleantalk.org',30,'Anti-spam service checking IPs, emails, and domains for spam activity','network','none','[\"ip\",\"email\",\"domain\"]','https://cleantalk.org/help/api-check-spam',NULL,0,1),
('DroneBL','dronebl','https://dronebl.org/lookup',30,'DNS-based blocklist of abused IPs (open proxies, drones, etc.)','network','none','[\"ip\"]','https://dronebl.org/docs/api',NULL,0,1),
('Focsec','focsec','https://api.focsec.com/v1',30,'IP intelligence — VPN, proxy, tor, datacenter detection','network','api_key','[\"ip\"]','https://focsec.com/docs','FOCSEC_KEY',1,0),
('FortiGuard Antispam','fortiguard','https://www.fortiguard.com',10,'Fortinet antispam IP and email reputation lookups','network','none','[\"ip\",\"email\"]','https://www.fortiguard.com',NULL,0,1),
('Fraudguard','fraudguard','https://api.fraudguard.io',30,'IP risk scoring — geolocation, proxy detection, threat classification','network','basic_auth','[\"ip\"]','https://docs.fraudguard.io','FRAUDGUARD_USER',1,0),
('Greensnow','greensnow','https://blocklist.greensnow.co/greensnow.txt',10,'Aggregated list of IPs observed in online attacks','network','none','[\"ip\"]','https://greensnow.co',NULL,0,1),
('Internet Storm Center','isc-sans','https://isc.sans.edu/api',30,'SANS ISC — collaborative intrusion detection and analysis','network','none','[\"ip\"]','https://isc.sans.edu/api/',NULL,0,1),
('ipapi.com','ipapi','http://api.ipapi.com',30,'IP geolocation and threat detection API','network','api_key','[\"ip\"]','https://ipapi.com/documentation','IPAPI_KEY',1,0),
('IPInfo.io','ipinfo','https://ipinfo.io',100,'IP address geolocation, ASN, company, and privacy detection','network','api_key','[\"ip\"]','https://ipinfo.io/developers','IPINFO_KEY',1,0),
('IPQualityScore','ipqualityscore','https://www.ipqualityscore.com/api',30,'Fraud prevention — IP, email, URL, phone reputation scoring','network','api_key','[\"ip\",\"email\",\"url\",\"phone\"]','https://www.ipqualityscore.com/documentation','IPQUALITYSCORE_KEY',1,0),
('ipregistry','ipregistry','https://api.ipregistry.co',30,'IP geolocation, threat data, and connection type detection','network','api_key','[\"ip\"]','https://ipregistry.co/docs','IPREGISTRY_KEY',1,0),
('ipstack','ipstack','http://api.ipstack.com',30,'Real-time IP geolocation API','network','api_key','[\"ip\"]','https://ipstack.com/documentation','IPSTACK_KEY',1,0),
('NeutrinoAPI','neutrinoapi','https://neutrinoapi.net',30,'Multi-purpose API — IP info, email validation, phone lookup','network','api_key','[\"ip\",\"email\",\"phone\"]','https://www.neutrinoapi.com/api/api-basics/','NEUTRINOAPI_KEY',1,0),
('SORBS','sorbs','',10,'DNS-based spam and open relay blocking system','network','none','[\"ip\"]','http://www.sorbs.net',NULL,0,1),
('SpamCop','spamcop','',10,'DNS-based spam source blocklist','network','none','[\"ip\"]','https://www.spamcop.net',NULL,0,1),
('Spamhaus Zen','spamhaus-zen','',10,'Comprehensive DNS blocklist combining SBL, XBL, PBL, and CSS','network','none','[\"ip\"]','https://www.spamhaus.org/faq/section/DNSBL%20Usage',NULL,0,1),
('spur.us','spur','https://app.spur.us/api/v2',30,'VPN, residential proxy, and anonymous infrastructure detection','network','api_key','[\"ip\"]','https://spur.us/docs','SPUR_KEY',1,0),
('UCEPROTECT','uceprotect','',10,'DNS-based blocklist service with multiple threat levels','network','none','[\"ip\"]','http://www.uceprotect.net',NULL,0,1),
('VoIP Blacklist (VoIPBL)','voipbl','https://voipbl.org/update',10,'VoIP-specific IP blocklist for SIP/telephony abuse','network','none','[\"ip\"]','https://www.voipbl.org',NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  DOMAIN & DNS
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Censys','censys','https://search.censys.io/api/v2',120,'Internet-wide scanning — certificates, hosts, and services discovery','dns','api_key','[\"ip\",\"domain\"]','https://search.censys.io/api','CENSYS_API_ID',1,0),
('CertSpotter','certspotter','https://api.certspotter.com/v1',30,'Certificate Transparency log monitoring and alerting','dns','api_key','[\"domain\"]','https://sslmate.com/certspotter/api/','CERTSPOTTER_KEY',1,0),
('Certificate Transparency','crt-sh','https://crt.sh',30,'Free CT log search via crt.sh — discover subdomains from SSL certificates','dns','none','[\"domain\"]','https://crt.sh',NULL,0,1),
('CIRCL.LU','circl-lu','https://www.circl.lu/pdns/query',30,'Passive DNS database operated by CIRCL (Luxembourg CERT)','dns','basic_auth','[\"domain\",\"ip\"]','https://www.circl.lu/services/passive-dns/','CIRCL_USER',1,0),
('Crobat API','crobat','https://sonar.omnisint.io',30,'Rapid7 Project Sonar passive DNS data','dns','none','[\"domain\"]','https://sonar.omnisint.io',NULL,0,1),
('DNSDB','dnsdb','https://api.dnsdb.info',30,'Farsight DNSDB — the world''s largest passive DNS database','dns','api_key','[\"domain\",\"ip\"]','https://docs.dnsdb.info','DNSDB_KEY',1,0),
('DNS Brute-forcer','dns-bruteforce','',10,'Internal wordlist-based subdomain brute-force discovery','dns','none','[\"domain\"]',NULL,NULL,0,1),
('DNSGrep','dnsgrep','https://www.dnsgrep.cn',30,'Passive DNS search engine','dns','none','[\"domain\"]','https://www.dnsgrep.cn',NULL,0,1),
('DNS Look-aside','dns-lookaside','',10,'Internal DNS look-aside resolution for related domains','dns','none','[\"domain\"]',NULL,NULL,0,1),
('DNS Raw Records','dns-raw','',10,'Retrieve raw DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)','dns','none','[\"domain\"]',NULL,NULL,0,1),
('DNS Resolver','dns-resolver','',10,'Forward and reverse DNS resolution','dns','none','[\"domain\",\"ip\"]',NULL,NULL,0,1),
('DNS Zone Transfer','dns-zone-transfer','',10,'Attempt AXFR zone transfer to discover all DNS records','dns','none','[\"domain\"]',NULL,NULL,0,1),
('DNSAudit','dnsaudit','https://dnsaudit.io/api',10,'DNS security scan API (DNSSEC, SPF, DKIM, DMARC, zone transfer and related checks).','dns','api_key','[\"domain\",\"url\"]','https://dnsaudit.io/docs/api','DNSAUDIT_KEY',1,1),
('F-Secure Riddler.io','riddler','https://riddler.io/search',30,'F-Secure Riddler — internet-wide scanning data and DNS intelligence','dns','basic_auth','[\"domain\",\"ip\"]','https://riddler.io/help/api','RIDDLER_USER',1,0),
('HackerTarget','hackertarget','https://api.hackertarget.com',30,'Free online vulnerability scanners and network intelligence tools','dns','none','[\"domain\",\"ip\"]','https://hackertarget.com/api/',NULL,0,1),
('Host.io','host-io','https://host.io/api',30,'Domain data API — DNS, backlinks, redirects, and related domains','dns','api_key','[\"domain\",\"ip\"]','https://host.io/docs','HOSTIO_KEY',1,0),
('JsonWHOIS.com','jsonwhois','https://jsonwhois.com/api/v1',30,'WHOIS data in JSON format for domain registration details','dns','api_key','[\"domain\"]','https://jsonwhois.com/docs','JSONWHOIS_KEY',1,0),
('Mnemonic PassiveDNS','mnemonic-pdns','https://api.mnemonic.no/pdns/v3',30,'Mnemonic passive DNS database for historical DNS lookups','dns','none','[\"domain\",\"ip\"]','https://api.mnemonic.no/pdns/v3/',NULL,0,1),
('Open Passive DNS Database','open-pdns','https://www.circl.lu/pdns/query',30,'Open passive DNS database via CIRCL','dns','none','[\"domain\",\"ip\"]','https://www.circl.lu/services/passive-dns/',NULL,0,1),
('OpenNIC DNS','opennic','https://api.opennicproject.org',10,'OpenNIC alternative DNS root servers','dns','none','[\"domain\"]','https://www.opennicproject.org',NULL,0,1),
('ProjectDiscovery Chaos','chaos','https://dns.projectdiscovery.io',30,'ProjectDiscovery Chaos — internet-wide DNS data for bug bounty','dns','api_key','[\"domain\"]','https://chaos.projectdiscovery.io/#/','CHAOS_KEY',1,0),
('Robtex','robtex','https://freeapi.robtex.com',30,'Free DNS lookup, reverse DNS, and IP-to-ASN mapping','dns','none','[\"ip\",\"domain\"]','https://www.robtex.com/api/',NULL,0,1),
('SecurityTrails','securitytrails','https://api.securitytrails.com/v1',50,'Historical DNS data, WHOIS, subdomains, and associated domains','dns','api_key','[\"domain\",\"ip\"]','https://docs.securitytrails.com','SECURITYTRAILS_KEY',1,0),
('TLD Searcher','tld-searcher','',10,'Internal permutation-based TLD variant discovery','dns','none','[\"domain\"]',NULL,NULL,0,1),
('ViewDNS.info','viewdns','https://api.viewdns.info',30,'DNS tools — reverse IP, WHOIS, port scan, traceroute','dns','api_key','[\"domain\",\"ip\"]','https://viewdns.info/api/','VIEWDNS_KEY',1,0),
('Whoisology','whoisology','https://whoisology.com/api',30,'Reverse WHOIS lookups — find domains by registrant details','dns','api_key','[\"domain\"]','https://whoisology.com/api','WHOISOLOGY_KEY',1,0),
('Whoxy','whoxy','https://api.whoxy.com',30,'WHOIS history and reverse WHOIS lookup API','dns','api_key','[\"domain\"]','https://www.whoxy.com/whois-history/','WHOXY_KEY',1,0),
('Zetalytics','zetalytics','https://zonecruncher.com/api/v1',30,'Massive passive DNS and WHOIS database','dns','api_key','[\"domain\",\"ip\"]','https://zetalytics.com/api','ZETALYTICS_KEY',1,0)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  MALWARE & PHISHING
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Google SafeBrowsing','google-safebrowsing','https://safebrowsing.googleapis.com/v4',100,'Google Safe Browsing API — detect phishing, malware, and unwanted software URLs','malware','api_key','[\"url\"]','https://developers.google.com/safe-browsing/v4','GOOGLE_SAFEBROWSING_KEY',1,0),
('Hybrid Analysis','hybrid-analysis','https://www.hybrid-analysis.com/api/v2',30,'CrowdStrike Falcon Sandbox — malware analysis and file detonation','malware','api_key','[\"hash\",\"url\"]','https://www.hybrid-analysis.com/docs/api/v2','HYBRIDANALYSIS_KEY',1,0),
('Koodous','koodous','https://api.koodous.com',30,'Android malware analysis platform and APK intelligence','malware','none','[\"hash\"]','https://koodous.com/api-docs',NULL,0,1),
('MetaDefender','metadefender','https://api.metadefender.com/v4',30,'OPSWAT MetaDefender — multi-scanning engine for files, IPs, domains, URLs','malware','api_key','[\"hash\",\"ip\",\"domain\",\"url\"]','https://docs.opswat.com/mdcloud','METADEFENDER_KEY',1,0),
('OpenPhish','openphish','https://openphish.com/feed.txt',10,'Community phishing URL feed — free and commercial tiers','malware','none','[\"url\",\"domain\"]','https://openphish.com',NULL,0,1),
('PhishStats','phishstats','https://phishstats.info/apiv1',30,'Phishing URL and IP statistics database','malware','none','[\"url\",\"domain\",\"ip\"]','https://phishstats.info/api.php',NULL,0,1),
('PhishTank','phishtank','https://checkurl.phishtank.com/checkurl',30,'Community-driven phishing URL verification database','malware','none','[\"url\"]','https://phishtank.org/developer_info.php',NULL,0,1),
('SSL Certificate Analyzer','ssl-analyzer','',10,'Internal SSL/TLS certificate chain parsing and security analysis','malware','none','[\"domain\"]',NULL,NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  SEARCH & OSINT
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Ahmia','ahmia','https://ahmia.fi/api',10,'Tor hidden service search engine','osint','none','[\"domain\"]','https://ahmia.fi',NULL,0,1),
('Archive.org','archive-org','https://archive.org/wayback/available',30,'Wayback Machine — historical website snapshots and domain history','osint','none','[\"domain\",\"url\"]','https://archive.org/help/wayback_api.php',NULL,0,1),
('Bing','bing','https://api.bing.microsoft.com/v7.0/search',30,'Microsoft Bing Web Search API','osint','api_key','[\"domain\"]','https://docs.microsoft.com/en-us/bing/search-apis/','BING_API_KEY',1,0),
('Bing (Shared IPs)','bing-shared-ips','https://api.bing.microsoft.com/v7.0/search',30,'Bing reverse IP lookup — discover co-hosted domains','osint','api_key','[\"ip\"]','https://docs.microsoft.com/en-us/bing/search-apis/','BING_API_KEY',1,0),
('CommonCrawl','commoncrawl','https://index.commoncrawl.org',10,'CommonCrawl web archive — massive dataset of crawled web pages','osint','none','[\"domain\",\"url\"]','https://commoncrawl.org/the-data/get-started/',NULL,0,1),
('Darksearch','darksearch','https://darksearch.io/api',10,'Dark web search engine API','osint','none','[\"domain\"]','https://darksearch.io/apidoc',NULL,0,1),
('DuckDuckGo','duckduckgo','https://api.duckduckgo.com',30,'DuckDuckGo Instant Answer API','osint','none','[\"domain\"]','https://duckduckgo.com/api',NULL,0,1),
('Flickr','flickr','https://api.flickr.com/services/rest',30,'Flickr photo search — find accounts and photos by username or email','osint','none','[\"username\",\"email\"]','https://www.flickr.com/services/api/',NULL,0,1),
('Github','github','https://api.github.com',30,'GitHub API — user profiles, repositories, and code search','osint','none','[\"username\",\"email\"]','https://docs.github.com/en/rest',NULL,0,1),
('Google','google','https://www.googleapis.com/customsearch/v1',10,'Google Custom Search API','osint','api_key','[\"domain\"]','https://developers.google.com/custom-search/v1/overview','GOOGLE_API_KEY',1,0),
('Google Maps','google-maps','https://maps.googleapis.com/maps/api',30,'Google Maps Places and Geocoding API','osint','api_key','[\"domain\"]','https://developers.google.com/maps/documentation','GOOGLE_MAPS_KEY',1,0),
('grep.app','grep-app','https://grep.app/api',10,'Source code search engine — find code snippets and secrets','osint','none','[\"domain\",\"hash\"]','https://grep.app',NULL,0,1),
('IntelligenceX','intelligencex','https://2.intelx.io',30,'Intelligence X — search engine for leaked data, darknet, and OSINT','osint','api_key','[\"email\",\"domain\",\"ip\",\"url\"]','https://intelx.io/api','INTELX_KEY',1,0),
('Onion.link','onion-link','https://onion.link',10,'Tor2web proxy gateway for onion service access','osint','none','[\"domain\"]','https://onion.link',NULL,0,1),
('Onionsearchengine.com','onionsearchengine','https://onionsearchengine.com',10,'Dark web search engine','osint','none','[\"domain\"]','https://onionsearchengine.com',NULL,0,1),
('PasteBin','pastebin','https://scrape.pastebin.com/api_scraping.php',30,'Pastebin paste scraping API — search for leaked data','osint','api_key','[\"email\",\"username\"]','https://pastebin.com/doc_api','PASTEBIN_KEY',1,0),
('Pulsedive','pulsedive','https://pulsedive.com/api',30,'Community threat intelligence platform — IoC enrichment and correlation','osint','api_key','[\"ip\",\"domain\",\"url\",\"hash\"]','https://pulsedive.com/api/','PULSEDIVE_KEY',1,0),
('Recon.dev','recon-dev','https://recon.dev/api',30,'Attack surface management — subdomain and technology discovery','osint','api_key','[\"domain\"]','https://recon.dev/api/docs','RECONDEV_KEY',1,0),
('RiskIQ','riskiq','https://api.riskiq.net/pt/v2',30,'RiskIQ PassiveTotal — passive DNS, WHOIS, and host attributes','osint','api_key','[\"domain\",\"ip\"]','https://api.riskiq.net/api/pdns/','RISKIQ_KEY',1,0),
('searchcode','searchcode','https://searchcode.com/api',30,'Source code search engine across multiple repositories','osint','none','[\"domain\"]','https://searchcode.com/api/',NULL,0,1),
('Spyse','spyse','https://api.spyse.com/v4',30,'Internet assets search engine — domains, IPs, certificates, technologies','osint','api_key','[\"domain\",\"ip\"]','https://spyse.com/api','SPYSE_KEY',1,0),
('SpyOnWeb','spyonweb','https://api.spyonweb.com/v1',30,'Discover websites with shared analytics/AdSense IDs','osint','api_key','[\"domain\",\"ip\"]','https://api.spyonweb.com','SPYONWEB_KEY',1,0),
('StackOverflow','stackoverflow','https://api.stackexchange.com/2.3',30,'Stack Exchange API — developer profile and activity search','osint','none','[\"username\",\"email\"]','https://api.stackexchange.com/docs',NULL,0,1),
('TORCH','torch','https://torch.onionsearchengine.com',10,'Tor search engine','osint','none','[\"domain\"]','https://torch.onionsearchengine.com',NULL,0,1),
('Wikileaks','wikileaks','https://search.wikileaks.org/api',10,'WikiLeaks search API','osint','none','[\"domain\"]','https://wikileaks.org',NULL,0,1),
('Wikipedia Edits','wikipedia-edits','https://en.wikipedia.org/w/api.php',30,'Wikipedia user contribution and edit history API','osint','none','[\"username\"]','https://www.mediawiki.org/wiki/API:Main_page',NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  LEAKS & BREACHES
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('BitcoinAbuse','bitcoinabuse','https://www.bitcoinabuse.com/api',30,'Bitcoin address abuse reports — scam, ransomware, darknet marketplace','leaks','api_key','[\"bitcoin\"]','https://www.bitcoinabuse.com/api-docs','BITCOINABUSE_KEY',1,0),
('Bitcoin Who''s Who','bitcoin-whos-who','https://bitcoinwhoswho.com/api',30,'Bitcoin address ownership and transaction intelligence','leaks','api_key','[\"bitcoin\"]','https://bitcoinwhoswho.com/api','BITCOINWHOSEWHO_KEY',1,0),
('Dehashed','dehashed','https://api.dehashed.com/search',30,'Breach data search engine — email, username, IP, domain lookups','leaks','api_key','[\"email\",\"username\",\"ip\",\"domain\"]','https://www.dehashed.com/docs','DEHASHED_KEY',1,0),
('HaveIBeenPwned','haveibeenpwned','https://haveibeenpwned.com/api/v3',10,'Troy Hunt''s breach notification service — check if credentials were compromised','leaks','api_key','[\"email\"]','https://haveibeenpwned.com/API/v3','HIBP_KEY',1,0),
('Iknowwhatyoudownload.com','iknowwhatyoudownload','https://api.iknowwhatyoudownload.com/api',10,'Torrent download history by IP address','leaks','api_key','[\"ip\"]','https://iknowwhatyoudownload.com','IKNOWWHATYOUDOWNLOAD_KEY',1,0),
('Leak-Lookup','leak-lookup','https://leak-lookup.com/api',30,'Breach data search — email, username, hash lookups across leaked databases','leaks','api_key','[\"email\",\"hash\",\"username\"]','https://leak-lookup.com/api','LEAKLOOKUP_KEY',1,0),
('LeakIX','leakix','https://leakix.net/api',30,'Real-time indexing of internet-exposed data leaks and misconfigurations','leaks','api_key','[\"domain\",\"ip\"]','https://leakix.net/docs/api','LEAKIX_KEY',1,0),
('Scylla','scylla','https://scylla.sh/search',30,'Leaked credential search engine','leaks','none','[\"email\",\"username\"]','https://scylla.sh/docs',NULL,0,1),
('Trashpanda','trashpanda','https://trashpanda.cc/api',30,'Breach data aggregation and search service','leaks','api_key','[\"email\",\"username\"]','https://trashpanda.cc','TRASHPANDA_KEY',1,0)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  IDENTITY & EMAIL
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('AbstractAPI','abstractapi','https://emailvalidation.abstractapi.com/v1',30,'Email validation, geolocation, and company enrichment APIs','identity','api_key','[\"email\"]','https://www.abstractapi.com/api/email-verification-validation-api','ABSTRACTAPI_KEY',1,0),
('Account Finder','account-finder','',10,'Internal username permutation search across social platforms','identity','none','[\"username\"]',NULL,NULL,0,1),
('Clearbit','clearbit','https://person.clearbit.com/v2',30,'Business identity enrichment — person and company data from email/domain','identity','api_key','[\"email\",\"domain\"]','https://clearbit.com/docs','CLEARBIT_KEY',1,0),
('EmailCrawlr','emailcrawlr','https://api.emailcrawlr.com/v2',30,'Email intelligence — validation, domain emails, social profiles','identity','api_key','[\"email\",\"domain\"]','https://emailcrawlr.com/api','EMAILCRAWLR_KEY',1,0),
('EmailRep','emailrep','https://emailrep.io',30,'Email reputation and risk scoring','identity','api_key','[\"email\"]','https://emailrep.io/docs','EMAILREP_KEY',1,0),
('FullContact','fullcontact','https://api.fullcontact.com/v3',30,'Person and company enrichment from email, phone, or social profile','identity','api_key','[\"email\",\"username\"]','https://docs.fullcontact.com','FULLCONTACT_KEY',1,0),
('Hunter.io','hunter','https://api.hunter.io/v2',25,'Email finder and verifier — discover professional email addresses','identity','api_key','[\"email\",\"domain\"]','https://hunter.io/api-documentation/v2','HUNTER_KEY',1,0),
('NameAPI','nameapi','https://api.nameapi.org/rest/v5.3',30,'Name parsing, validation, and gender detection API','identity','api_key','[\"email\"]','https://www.nameapi.org/en/developer/api-docs/','NAMEAPI_KEY',1,0),
('numverify','numverify','http://apilayer.net/api/validate',30,'Phone number validation, carrier detection, and geolocation','identity','api_key','[\"phone\"]','https://numverify.com/documentation','NUMVERIFY_KEY',1,0),
('Project Honey Pot','project-honeypot','',30,'DNS-based IP threat check using Project Honey Pot''s http:BL API','identity','api_key','[\"ip\"]','https://www.projecthoneypot.org/httpbl_api.php','PROJECTHONEYPOT_KEY',1,0),
('Seon','seon','https://api.seon.io/SeonRestService/email-api/v2.2',30,'Digital footprint and fraud prevention — email, phone, IP scoring','identity','api_key','[\"email\",\"phone\",\"ip\"]','https://docs.seon.io','SEON_KEY',1,0),
('Snov','snov','https://api.snov.io/v1',30,'Email finder, verifier, and drip campaign tool','identity','api_key','[\"email\",\"domain\"]','https://snov.io/api','SNOV_CLIENT_ID',1,0),
('Social Links','social-links','https://api.sociallinks.io',30,'Social media intelligence and profile discovery','identity','api_key','[\"username\",\"email\"]','https://sociallinks.io/docs','SOCIALLINKS_KEY',1,0),
('Social Media Profile Finder','social-media-finder','',10,'Internal cross-platform social media username search','identity','api_key','[\"username\",\"email\"]',NULL,'SOCIALLINKS_KEY',1,0),
('TextMagic','textmagic','https://rest.textmagic.com/api/v2',30,'SMS API with phone number validation and carrier lookup','identity','api_key','[\"phone\"]','https://docs.textmagic.com','TEXTMAGIC_KEY',1,0),
('Twilio','twilio','https://lookups.twilio.com/v2/PhoneNumbers',30,'Phone number lookup — carrier, caller name, and line type detection','identity','api_key','[\"phone\"]','https://www.twilio.com/docs/lookup','TWILIO_ACCOUNT_SID',1,0)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  INFRASTRUCTURE
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('AdBlock Check','adblock-check','',10,'Check if a domain appears on popular adblock filter lists','infra','none','[\"domain\"]',NULL,NULL,0,1),
('Amazon S3 Bucket Finder','s3-finder','https://s3.amazonaws.com',10,'Discover open Amazon S3 buckets by domain name permutation','infra','none','[\"domain\"]','https://docs.aws.amazon.com/s3/index.html',NULL,0,1),
('Azure Blob Finder','azure-blob-finder','https://blob.core.windows.net',10,'Discover open Azure Blob Storage containers','infra','none','[\"domain\"]','https://docs.microsoft.com/en-us/azure/storage/',NULL,0,1),
('BinaryEdge','binaryedge','https://api.binaryedge.io/v2',30,'Internet-wide scanning — open ports, services, vulnerabilities','infra','api_key','[\"ip\",\"domain\"]','https://docs.binaryedge.io','BINARYEDGE_KEY',1,0),
('BuiltWith','builtwith','https://api.builtwith.com/v21',30,'Website technology profiling — CMS, frameworks, analytics, hosting','infra','api_key','[\"domain\"]','https://api.builtwith.com','BUILTWITH_KEY',1,0),
('C99','c99','https://api.c99.nl',30,'Multi-purpose OSINT API — subdomains, phone, IP, WAF detection','infra','api_key','[\"domain\",\"ip\"]','https://api.c99.nl','C99_KEY',1,0),
('CRXcavator','crxcavator','https://api.crxcavator.io/v1',30,'Chrome extension security analysis and risk scoring','infra','none','[\"domain\"]','https://crxcavator.io',NULL,0,1),
('Digital Ocean Space Finder','do-space-finder','',10,'Discover open DigitalOcean Spaces by domain name permutation','infra','none','[\"domain\"]','https://docs.digitalocean.com/products/spaces/',NULL,0,1),
('Etherscan','etherscan','https://api.etherscan.io/api',30,'Ethereum blockchain explorer — address, transaction, and token data','infra','api_key','[\"ip\",\"domain\"]','https://docs.etherscan.io','ETHERSCAN_KEY',1,0),
('FullHunt','fullhunt','https://fullhunt.io/api/v1',30,'Attack surface discovery — exposed hosts, services, and technologies','infra','api_key','[\"domain\"]','https://fullhunt.io/api/','FULLHUNT_KEY',1,0),
('Google Object Storage Finder','gcs-finder','https://storage.googleapis.com',10,'Discover open Google Cloud Storage buckets','infra','none','[\"domain\"]','https://cloud.google.com/storage/docs',NULL,0,1),
('Grayhat Warfare','grayhat-warfare','https://buckets.grayhatwarfare.com/api/v2',30,'Open S3 bucket and cloud storage search engine','infra','api_key','[\"domain\"]','https://grayhatwarfare.com','GRAYHAT_KEY',1,0),
('NetworksDB','networksdb','https://networksdb.io/api/v1',30,'IP and ASN intelligence — network ownership and geolocation','infra','api_key','[\"ip\"]','https://networksdb.io/api/docs','NETWORKSDB_KEY',1,0),
('Onyphe','onyphe','https://www.onyphe.io/api/v2',30,'Cyber defense search engine — open ports, vulns, threat data','infra','api_key','[\"ip\",\"domain\"]','https://www.onyphe.io/docs/onyphe-query-language','ONYPHE_KEY',1,0),
('OpenCorporates','opencorporates','https://api.opencorporates.com/v0.4',30,'Open database of companies worldwide','infra','none','[\"domain\"]','https://api.opencorporates.com',NULL,0,1),
('WhatCMS','whatcms','https://whatcms.org/API',30,'CMS detection API — identify content management systems','infra','api_key','[\"domain\"]','https://whatcms.org','WHATCMS_KEY',1,0),
('WiGLE','wigle','https://api.wigle.net/api/v2',30,'Wireless network mapping — WiFi, Bluetooth, cell tower data','infra','api_key','[\"ip\"]','https://api.wigle.net/swagger','WIGLE_API_NAME',1,0)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  BLOCKLISTS
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('botvrij.eu','botvrij','https://botvrij.eu',10,'Open source IoC feeds — IP addresses, domains, URLs, and file hashes','blocklist','none','[\"domain\",\"ip\",\"hash\"]','https://botvrij.eu',NULL,0,1),
('CoinBlocker Lists','coinblocker','https://zerodot1.gitlab.io/CoinBlockerLists',10,'Cryptocurrency mining blocklists — domains and IPs used for cryptojacking','blocklist','none','[\"domain\",\"ip\"]','https://zerodot1.gitlab.io/CoinBlockerLists/',NULL,0,1),
('multiproxy.org Open Proxies','multiproxy','https://multiproxy.org/txt_all/proxy.txt',10,'List of open proxy servers','blocklist','none','[\"ip\"]','https://multiproxy.org',NULL,0,1),
('PGP Key Servers','pgp-keyservers','https://keys.openpgp.org',10,'Search public PGP keyservers for email-associated cryptographic keys','blocklist','none','[\"email\"]','https://keys.openpgp.org',NULL,0,1),
('Steven Black Hosts','steven-black-hosts','https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',10,'Unified hosts file with base extensions for ad and malware blocking','blocklist','none','[\"domain\"]','https://github.com/StevenBlack/hosts',NULL,0,1),
('SURBL','surbl','',10,'DNS-based URI blocklist for spam and phishing domain detection','blocklist','none','[\"domain\"]','https://www.surbl.org/surbl-analysis',NULL,0,1),
('TOR Exit Nodes','tor-exit-nodes','https://check.torproject.org/exit-addresses',10,'List of current Tor network exit node IP addresses','blocklist','none','[\"ip\"]','https://check.torproject.org/exit-addresses',NULL,0,1),
('Zone-H Defacement Check','zone-h','https://zone-h.org',10,'Website defacement archive and monitoring','blocklist','none','[\"domain\"]','https://www.zone-h.org',NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  DATA EXTRACTORS
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Base64 Decoder','base64-decoder','',10,'Detect and decode Base64 encoded strings in content','extract','none','[\"url\",\"domain\"]',NULL,NULL,0,1),
('Binary String Extractor','binary-string-extractor','',10,'Extract printable ASCII strings from binary data','extract','none','[\"hash\"]',NULL,NULL,0,1),
('Company Name Extractor','company-name-extractor','',10,'NLP-based company and organization name extraction from text','extract','none','[\"domain\"]',NULL,NULL,0,1),
('Country Name Extractor','country-name-extractor','',10,'NLP-based country and geolocation extraction from text content','extract','none','[\"domain\",\"ip\"]',NULL,NULL,0,1),
('Cross-Referencer','cross-referencer','',10,'Cross-correlate and enrich results from multiple OSINT modules','extract','none','[\"ip\",\"domain\",\"email\",\"hash\"]',NULL,NULL,0,1),
('File Metadata Extractor','file-metadata-extractor','',10,'Extract EXIF, PDF, and document metadata from downloaded files','extract','none','[\"url\",\"hash\"]',NULL,NULL,0,1),
('Human Name Extractor','human-name-extractor','',10,'NLP-based human name detection and extraction from text','extract','none','[\"domain\",\"email\"]',NULL,NULL,0,1),
('Interesting File Finder','interesting-file-finder','',10,'Discover sensitive files (robots.txt, .env, backups) via web crawling','extract','none','[\"domain\",\"url\"]',NULL,NULL,0,1),
('Junk File Finder','junk-file-finder','',10,'Identify backup, temporary, and development files on web servers','extract','none','[\"domain\",\"url\"]',NULL,NULL,0,1),
('Web Spider','web-spider','',10,'Crawl web pages and extract links, emails, and metadata','extract','none','[\"domain\",\"url\"]',NULL,NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  TOOLS (CLI wrappers)
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO `api_configs` (`name`,`slug`,`base_url`,`rate_limit`,`description`,`category`,`auth_type`,`supported_types`,`docs_url`,`env_key`,`requires_key`,`is_enabled`) VALUES
('Port Scanner - TCP','port-scanner-tcp','',10,'TCP connect scan via raw sockets — discover open ports and services','tools','none','[\"ip\",\"domain\"]',NULL,NULL,0,1),
('Tool - CMSeeK','cmseek','',10,'CMS detection and exploitation tool — WordPress, Joomla, Drupal, etc.','tools','none','[\"domain\",\"url\"]','https://github.com/Tuhinshubhra/CMSeeK',NULL,0,1),
('Tool - DNSTwist','dnstwist','',10,'Domain name permutation engine — detect typosquatting and phishing','tools','none','[\"domain\"]','https://github.com/elceef/dnstwist',NULL,0,1),
('Tool - nbtscan','nbtscan','',10,'NetBIOS name service scanner for Windows network enumeration','tools','none','[\"ip\"]','http://www.unixwiz.net/tools/nbtscan.html',NULL,0,1),
('Tool - Nmap','nmap','',10,'Network mapper — port scanning, service detection, OS fingerprinting','tools','none','[\"ip\",\"domain\"]','https://nmap.org/book/man.html',NULL,0,1),
('Tool - Nuclei','nuclei','',10,'Fast vulnerability scanner using community-maintained templates','tools','none','[\"domain\",\"ip\",\"url\"]','https://docs.projectdiscovery.io/tools/nuclei',NULL,0,1),
('Tool - onesixtyone','onesixtyone','',10,'SNMP scanner — brute-force community strings on network devices','tools','none','[\"ip\"]','https://github.com/trailofbits/onesixtyone',NULL,0,1),
('Tool - Retire.js','retire-js','',10,'JavaScript library vulnerability scanner','tools','none','[\"url\",\"domain\"]','https://retirejs.github.io/retire.js/',NULL,0,1),
('Tool - snallygaster','snallygaster','',10,'Scan for secret files and misconfigurations on web servers','tools','none','[\"domain\"]','https://github.com/hannob/snallygaster',NULL,0,1),
('Tool - testssl.sh','testssl','',10,'SSL/TLS configuration analysis and vulnerability testing','tools','none','[\"domain\",\"ip\"]','https://testssl.sh',NULL,0,1),
('Tool - TruffleHog','trufflehog','',10,'Search for secrets and credentials in git repositories','tools','none','[\"domain\",\"url\"]','https://github.com/trufflesecurity/trufflehog',NULL,0,1),
('Tool - WAFW00F','wafw00f','',10,'Web Application Firewall detection and fingerprinting','tools','none','[\"domain\",\"url\"]','https://github.com/EnableSecurity/wafw00f',NULL,0,1),
('Tool - Wappalyzer','wappalyzer','',10,'Technology profiler — identify CMS, frameworks, analytics on websites','tools','none','[\"domain\",\"url\"]','https://www.wappalyzer.com/docs/api/',NULL,0,1),
('Tool - WhatWeb','whatweb','',10,'Web scanner — identify technologies, CMS, server software','tools','none','[\"domain\",\"url\"]','https://github.com/urbanadventurer/WhatWeb',NULL,0,1)
ON DUPLICATE KEY UPDATE `category`=VALUES(`category`), `auth_type`=VALUES(`auth_type`), `supported_types`=VALUES(`supported_types`), `docs_url`=VALUES(`docs_url`), `env_key`=VALUES(`env_key`), `requires_key`=VALUES(`requires_key`);

-- ══════════════════════════════════════════════════════════════════════════════
--  VERIFICATION
-- ══════════════════════════════════════════════════════════════════════════════

SELECT COUNT(*) AS total_modules FROM `api_configs`;
SELECT `category`, COUNT(*) AS cnt FROM `api_configs` GROUP BY `category` ORDER BY cnt DESC;
