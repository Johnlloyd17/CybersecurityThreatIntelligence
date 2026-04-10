-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:4306
-- Generation Time: Mar 18, 2026 at 07:39 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `cti_platform`
--

-- --------------------------------------------------------

--
-- Table structure for table `api_configs`
--

CREATE TABLE `api_configs` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(100) NOT NULL,
  `slug` varchar(50) NOT NULL,
  `base_url` varchar(500) NOT NULL,
  `api_key` varchar(500) DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `rate_limit` int(10) UNSIGNED DEFAULT NULL COMMENT 'Max requests per minute',
  `description` text DEFAULT NULL,
  `category` varchar(30) NOT NULL DEFAULT 'uncategorized',
  `auth_type` enum('api_key','basic_auth','oauth','none') NOT NULL DEFAULT 'none',
  `supported_types` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`supported_types`)),
  `docs_url` varchar(500) DEFAULT NULL,
  `env_key` varchar(100) DEFAULT NULL,
  `requires_key` tinyint(1) NOT NULL DEFAULT 0,
  `last_health_check` timestamp NULL DEFAULT NULL,
  `health_status` enum('unknown','healthy','degraded','down') NOT NULL DEFAULT 'unknown',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `api_configs`
--

INSERT INTO `api_configs` (`id`, `name`, `slug`, `base_url`, `api_key`, `is_enabled`, `rate_limit`, `description`, `category`, `auth_type`, `supported_types`, `docs_url`, `env_key`, `requires_key`, `last_health_check`, `health_status`, `created_at`, `updated_at`) VALUES
(1, 'VirusTotal', 'virustotal', 'https://www.virustotal.com/api/v3', 'adf973f8ac8da59800eb75f80b773e645cb26bf76f311d12a2ab9dd99750f8a9', 1, 4, 'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.', 'malware', 'api_key', '[\"ip\",\"domain\",\"url\",\"hash\"]', 'https://developers.virustotal.com/reference', 'VIRUSTOTAL_KEY', 1, '2026-03-14 16:21:12', 'healthy', '2026-03-11 07:30:04', '2026-03-18 03:16:19'),
(2, 'AbuseIPDB', 'abuseipdb', 'https://api.abuseipdb.com/api/v2', '4e6ad93add327aab1cdef86443752ddacdcc029fb397ede2bd4bb2cf95841eede847d410da753a38', 1, 60, 'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.', 'network', 'api_key', '[\"ip\"]', 'https://docs.abuseipdb.com', 'ABUSEIPDB_KEY', 1, '2026-03-18 03:46:07', 'healthy', '2026-03-11 07:30:04', '2026-03-18 03:46:07'),
(3, 'Shodan', 'shodan', 'https://api.shodan.io', 'k3X4R25F4PegUhF0eBD8XzTwbJtxKmvA', 1, 1, 'Obtain information from SHODAN about identified IP addresses. Shodan is the world''s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.', 'infra', 'api_key', '[\"ip\",\"domain\"]', 'https://developer.shodan.io/api', 'SHODAN_KEY', 1, NULL, 'unknown', '2026-03-11 07:30:04', '2026-03-18 03:16:32'),
(4, 'AlienVault OTX', 'alienvault', 'https://otx.alienvault.com/api/v1', 'k3X4R25F4PegUhF0eBD8XzTwbJtxKmvA', 1, 100, 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.', 'threat', 'api_key', '[\"ip\",\"domain\",\"url\",\"hash\",\"cve\"]', 'https://otx.alienvault.com/api', 'ALIENVAULT_OTX_KEY', 1, '2026-03-17 07:11:43', 'healthy', '2026-03-11 07:30:04', '2026-03-18 03:16:08'),
(5, 'GreyNoise', 'greynoise', 'https://api.greynoise.io/v3', NULL, 0, 30, 'Internet background noise and mass scanner detection', 'network', 'api_key', '[\"ip\"]', 'https://docs.greynoise.io', 'GREYNOISE_KEY', 1, NULL, 'unknown', '2026-03-11 07:30:04', '2026-03-14 16:58:32'),
(6, 'URLScan.io', 'urlscan', 'https://urlscan.io/api/v1', '019ce138-2145-75e8-8670-ae3e2b94f31c', 0, 60, 'Website screenshot, DOM, and resource analysis', 'malware', 'api_key', '[\"url\",\"domain\"]', 'https://urlscan.io/docs/api/', 'URLSCAN_KEY', 1, '2026-03-18 03:58:06', 'healthy', '2026-03-11 07:30:04', '2026-03-18 03:58:06'),
(7, 'abuse.ch', 'abuse-ch', 'https://bazaar.abuse.ch/api/', NULL, 0, 60, 'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.', 'threat', 'none', '[\"hash\",\"domain\",\"ip\",\"url\"]', 'https://bazaar.abuse.ch/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:06'),
(8, 'AlienVault IP Reputation', 'alienvault-ip-rep', 'https://otx.alienvault.com/api/v1', NULL, 0, 100, 'Check if an IP or netblock is malicious according to the AlienVault IP Reputation database.', 'threat', 'none', '[\"ip\"]', 'https://cybersecurity.att.com/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(9, 'Custom Threat Feed', 'custom-threat-feed', '', NULL, 0, 10, 'User-configured custom threat intelligence feed URL', 'threat', 'api_key', '[\"ip\",\"domain\",\"url\",\"hash\"]', NULL, 'CUSTOM_THREAT_FEED_URL', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(10, 'CyberCrime-Tracker.net', 'cybercrime-tracker', 'https://cybercrime-tracker.net', NULL, 0, 30, 'C2 panel tracker — botnet and malware command-and-control infrastructure', 'threat', 'none', '[\"domain\",\"ip\",\"url\"]', 'https://cybercrime-tracker.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:17'),
(11, 'Emerging Threats', 'emerging-threats', 'https://rules.emergingthreats.net', NULL, 0, 30, 'Proofpoint Emerging Threats open rulesets and IP/domain blocklists', 'threat', 'none', '[\"ip\",\"domain\"]', 'https://rules.emergingthreats.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:19'),
(12, 'Maltiverse', 'maltiverse', 'https://api.maltiverse.com', NULL, 0, 60, 'IoC enrichment — IP, domain, URL, and file hash threat scoring', 'threat', 'none', '[\"ip\",\"domain\",\"hash\",\"url\"]', 'https://app.swaggerhub.com/apis/maltiverse/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:20'),
(13, 'MalwarePatrol', 'malwarepatrol', 'https://lists.malwarepatrol.net', NULL, 0, 10, 'Commercial malware URL/domain/IP blocklists', 'threat', 'api_key', '[\"domain\",\"ip\",\"url\",\"hash\"]', 'https://www.malwarepatrol.net/api-documentation/', 'MALWAREPATROL_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:57:49'),
(14, 'Talos Intelligence', 'talos-intelligence', 'https://talosintelligence.com', NULL, 0, 30, 'Cisco Talos IP and domain reputation intelligence', 'threat', 'none', '[\"ip\",\"domain\"]', 'https://talosintelligence.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:24'),
(15, 'ThreatCrowd', 'threatcrowd', 'https://www.threatcrowd.org/searchApi/v2', NULL, 0, 30, 'Community-driven threat intelligence — IP, domain, email, hash correlations', 'threat', 'none', '[\"ip\",\"domain\",\"email\",\"hash\"]', 'https://www.threatcrowd.org/searchApi/v2/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:57:55'),
(16, 'ThreatFox', 'threatfox', 'https://threatfox-api.abuse.ch/api/v1', NULL, 0, 60, 'abuse.ch ThreatFox — IoC sharing platform for malware C2 infrastructure', 'threat', 'none', '[\"ip\",\"domain\",\"hash\",\"url\"]', 'https://threatfox.abuse.ch/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:28'),
(17, 'ThreatMiner', 'threatminer', 'https://api.threatminer.org/v2', NULL, 0, 30, 'Free threat intelligence portal — passive DNS, WHOIS, malware samples', 'threat', 'none', '[\"ip\",\"domain\",\"hash\"]', 'https://www.threatminer.org/api.php', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:30'),
(18, 'VXVault.net', 'vxvault', 'http://vxvault.net', NULL, 0, 10, 'Malware URL collection and sample repository', 'threat', 'none', '[\"url\"]', 'http://vxvault.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:35'),
(19, 'XForce Exchange', 'xforce-exchange', 'https://api.xforce.ibmcloud.com', NULL, 0, 30, 'IBM X-Force Exchange — threat intelligence sharing platform', 'threat', 'api_key', '[\"ip\",\"domain\",\"hash\",\"url\"]', 'https://api.xforce.ibmcloud.com/doc/', 'XFORCE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:57:30'),
(20, 'Abusix Mail Intelligence', 'abusix', '', NULL, 0, 30, 'DNS-based mail abuse intelligence service', 'network', 'api_key', '[\"ip\"]', 'https://abusix.com', 'ABUSIX_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(21, 'Bad Packets', 'bad-packets', 'https://api.badpackets.net/v1', NULL, 0, 30, 'Obtain information about any malicious activities involving IP addresses found.', 'network', 'api_key', '[\"ip\"]', 'https://badpackets.net', 'BADPACKETS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(22, 'blocklist.de', 'blocklist-de', 'https://api.blocklist.de/api.php', NULL, 0, 30, 'Community-driven blocklist of attacking IP addresses', 'network', 'none', '[\"ip\"]', 'https://www.blocklist.de/en/api.html', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:56:01'),
(23, 'BotScout', 'botscout', 'https://botscout.com/test', NULL, 0, 30, 'Detects automated bot registrations by IP, email, or username', 'network', 'none', '[\"ip\",\"email\"]', 'https://botscout.com/api.htm', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:55:58'),
(24, 'CINS Army List', 'cins-army', 'http://cinsscore.com/list/ci-badguys.txt', NULL, 0, 10, 'Collective Intelligence Network Security — curated list of malicious IPs', 'network', 'none', '[\"ip\"]', 'http://cinsscore.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:17'),
(25, 'CleanTalk Spam List', 'cleantalk', 'https://api.cleantalk.org', NULL, 0, 30, 'Anti-spam service checking IPs, emails, and domains for spam activity', 'network', 'none', '[\"ip\",\"email\",\"domain\"]', 'https://cleantalk.org/help/api-check-spam', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:19'),
(26, 'DroneBL', 'dronebl', 'https://dronebl.org/lookup', NULL, 0, 30, 'DNS-based blocklist of abused IPs (open proxies, drones, etc.)', 'network', 'none', '[\"ip\"]', 'https://dronebl.org/docs/api', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:21'),
(27, 'Focsec', 'focsec', 'https://api.focsec.com/v1', NULL, 1, 30, 'IP intelligence — VPN, proxy, tor, datacenter detection', 'network', 'api_key', '[\"ip\"]', 'https://focsec.com/docs', 'FOCSEC_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:23'),
(28, 'FortiGuard Antispam', 'fortiguard', 'https://www.fortiguard.com', NULL, 0, 10, 'Fortinet antispam IP and email reputation lookups', 'network', 'none', '[\"ip\",\"email\"]', 'https://www.fortiguard.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:25'),
(29, 'Fraudguard', 'fraudguard', 'https://api.fraudguard.io', NULL, 0, 30, 'IP risk scoring — geolocation, proxy detection, threat classification', 'network', 'basic_auth', '[\"ip\"]', 'https://docs.fraudguard.io', 'FRAUDGUARD_USER', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(30, 'Greensnow', 'greensnow', 'https://blocklist.greensnow.co/greensnow.txt', NULL, 0, 10, 'Aggregated list of IPs observed in online attacks', 'network', 'none', '[\"ip\"]', 'https://greensnow.co', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:30'),
(31, 'Internet Storm Center', 'isc-sans', 'https://isc.sans.edu/api', NULL, 0, 30, 'SANS ISC — collaborative intrusion detection and analysis', 'network', 'none', '[\"ip\"]', 'https://isc.sans.edu/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:41'),
(32, 'ipapi.com', 'ipapi', 'http://api.ipapi.com', NULL, 0, 30, 'IP geolocation and threat detection API', 'network', 'api_key', '[\"ip\"]', 'https://ipapi.com/documentation', 'IPAPI_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(33, 'IPInfo.io', 'ipinfo', 'https://ipinfo.io', NULL, 0, 100, 'IP address geolocation, ASN, company, and privacy detection', 'network', 'api_key', '[\"ip\"]', 'https://ipinfo.io/developers', 'IPINFO_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(34, 'IPQualityScore', 'ipqualityscore', 'https://www.ipqualityscore.com/api', NULL, 0, 30, 'Fraud prevention — IP, email, URL, phone reputation scoring', 'network', 'api_key', '[\"ip\",\"email\",\"url\",\"phone\"]', 'https://www.ipqualityscore.com/documentation', 'IPQUALITYSCORE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(35, 'ipregistry', 'ipregistry', 'https://api.ipregistry.co', NULL, 0, 30, 'IP geolocation, threat data, and connection type detection', 'network', 'api_key', '[\"ip\"]', 'https://ipregistry.co/docs', 'IPREGISTRY_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(36, 'ipstack', 'ipstack', 'http://api.ipstack.com', NULL, 0, 30, 'Real-time IP geolocation API', 'network', 'api_key', '[\"ip\"]', 'https://ipstack.com/documentation', 'IPSTACK_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(37, 'NeutrinoAPI', 'neutrinoapi', 'https://neutrinoapi.net', NULL, 0, 30, 'Multi-purpose API — IP info, email validation, phone lookup', 'network', 'api_key', '[\"ip\",\"email\",\"phone\"]', 'https://www.neutrinoapi.com/api/api-basics/', 'NEUTRINOAPI_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(38, 'SORBS', 'sorbs', '', NULL, 0, 10, 'DNS-based spam and open relay blocking system', 'network', 'none', '[\"ip\"]', 'http://www.sorbs.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:56'),
(39, 'SpamCop', 'spamcop', '', NULL, 0, 10, 'DNS-based spam source blocklist', 'network', 'none', '[\"ip\"]', 'https://www.spamcop.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:58:58'),
(40, 'Spamhaus Zen', 'spamhaus-zen', '', NULL, 0, 10, 'Comprehensive DNS blocklist combining SBL, XBL, PBL, and CSS', 'network', 'none', '[\"ip\"]', 'https://www.spamhaus.org/faq/section/DNSBL%20Usage', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:00'),
(41, 'spur.us', 'spur', 'https://app.spur.us/api/v2', NULL, 0, 30, 'VPN, residential proxy, and anonymous infrastructure detection', 'network', 'api_key', '[\"ip\"]', 'https://spur.us/docs', 'SPUR_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:14'),
(42, 'UCEPROTECT', 'uceprotect', '', NULL, 0, 10, 'DNS-based blocklist service with multiple threat levels', 'network', 'none', '[\"ip\"]', 'http://www.uceprotect.net', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:11'),
(43, 'VoIP Blacklist (VoIPBL)', 'voipbl', 'https://voipbl.org/update', NULL, 0, 10, 'VoIP-specific IP blocklist for SIP/telephony abuse', 'network', 'none', '[\"ip\"]', 'https://www.voipbl.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:09'),
(44, 'Censys', 'censys', 'https://search.censys.io/api/v2', NULL, 0, 120, 'Internet-wide scanning — certificates, hosts, and services discovery', 'dns', 'api_key', '[\"ip\",\"domain\"]', 'https://search.censys.io/api', 'CENSYS_API_ID', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:18'),
(45, 'CertSpotter', 'certspotter', 'https://api.certspotter.com/v1', NULL, 0, 30, 'Certificate Transparency log monitoring and alerting', 'dns', 'api_key', '[\"domain\"]', 'https://sslmate.com/certspotter/api/', 'CERTSPOTTER_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:24'),
(46, 'Certificate Transparency', 'crt-sh', 'https://crt.sh', NULL, 0, 30, 'Free CT log search via crt.sh — discover subdomains from SSL certificates', 'dns', 'none', '[\"domain\"]', 'https://crt.sh', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:21'),
(47, 'CIRCL.LU', 'circl-lu', 'https://www.circl.lu/pdns/query', NULL, 0, 30, 'Passive DNS database operated by CIRCL (Luxembourg CERT)', 'dns', 'basic_auth', '[\"domain\",\"ip\"]', 'https://www.circl.lu/services/passive-dns/', 'CIRCL_USER', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(48, 'Crobat API', 'crobat', 'https://sonar.omnisint.io', NULL, 0, 30, 'Rapid7 Project Sonar passive DNS data', 'dns', 'none', '[\"domain\"]', 'https://sonar.omnisint.io', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:29'),
(49, 'DNSDB', 'dnsdb', 'https://api.dnsdb.info', NULL, 0, 30, 'Farsight DNSDB — the world\'s largest passive DNS database', 'dns', 'api_key', '[\"domain\",\"ip\"]', 'https://docs.dnsdb.info', 'DNSDB_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(50, 'DNS Brute-forcer', 'dns-bruteforce', '', NULL, 0, 10, 'Internal wordlist-based subdomain brute-force discovery', 'dns', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:31'),
(51, 'DNSGrep', 'dnsgrep', 'https://www.dnsgrep.cn', NULL, 0, 30, 'Passive DNS search engine', 'dns', 'none', '[\"domain\"]', 'https://www.dnsgrep.cn', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:42'),
(52, 'DNS Look-aside', 'dns-lookaside', '', NULL, 0, 10, 'Internal DNS look-aside resolution for related domains', 'dns', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:33'),
(53, 'DNS Raw Records', 'dns-raw', '', NULL, 0, 10, 'Retrieve raw DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)', 'dns', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:35'),
(54, 'DNS Resolver', 'dns-resolver', '', NULL, 0, 10, 'Forward and reverse DNS resolution', 'dns', 'none', '[\"domain\",\"ip\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:37'),
(55, 'DNS Zone Transfer', 'dns-zone-transfer', '', NULL, 0, 10, 'Attempt AXFR zone transfer to discover all DNS records', 'dns', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:38'),
(56, 'F-Secure Riddler.io', 'riddler', 'https://riddler.io/search', NULL, 0, 30, 'F-Secure Riddler — internet-wide scanning data and DNS intelligence', 'dns', 'basic_auth', '[\"domain\",\"ip\"]', 'https://riddler.io/help/api', 'RIDDLER_USER', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(57, 'HackerTarget', 'hackertarget', 'https://api.hackertarget.com', NULL, 0, 30, 'Free online vulnerability scanners and network intelligence tools', 'dns', 'none', '[\"domain\",\"ip\"]', 'https://hackertarget.com/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:45'),
(58, 'Host.io', 'host-io', 'https://host.io/api', NULL, 0, 30, 'Domain data API — DNS, backlinks, redirects, and related domains', 'dns', 'api_key', '[\"domain\",\"ip\"]', 'https://host.io/docs', 'HOSTIO_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(59, 'JsonWHOIS.com', 'jsonwhois', 'https://jsonwhois.com/api/v1', NULL, 0, 30, 'WHOIS data in JSON format for domain registration details', 'dns', 'api_key', '[\"domain\"]', 'https://jsonwhois.com/docs', 'JSONWHOIS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(60, 'Mnemonic PassiveDNS', 'mnemonic-pdns', 'https://api.mnemonic.no/pdns/v3', NULL, 0, 30, 'Mnemonic passive DNS database for historical DNS lookups', 'dns', 'none', '[\"domain\",\"ip\"]', 'https://api.mnemonic.no/pdns/v3/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:52'),
(61, 'Open Passive DNS Database', 'open-pdns', 'https://www.circl.lu/pdns/query', NULL, 0, 30, 'Open passive DNS database via CIRCL', 'dns', 'none', '[\"domain\",\"ip\"]', 'https://www.circl.lu/services/passive-dns/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:54'),
(62, 'OpenNIC DNS', 'opennic', 'https://api.opennicproject.org', NULL, 0, 10, 'OpenNIC alternative DNS root servers', 'dns', 'none', '[\"domain\"]', 'https://www.opennicproject.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 16:59:56'),
(63, 'ProjectDiscovery Chaos', 'chaos', 'https://dns.projectdiscovery.io', NULL, 0, 30, 'ProjectDiscovery Chaos — internet-wide DNS data for bug bounty', 'dns', 'api_key', '[\"domain\"]', 'https://chaos.projectdiscovery.io/#/', 'CHAOS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(64, 'Robtex', 'robtex', 'https://freeapi.robtex.com', NULL, 0, 30, 'Free DNS lookup, reverse DNS, and IP-to-ASN mapping', 'dns', 'none', '[\"ip\",\"domain\"]', 'https://www.robtex.com/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:00:01'),
(65, 'SecurityTrails', 'securitytrails', 'https://api.securitytrails.com/v1', NULL, 0, 50, 'Historical DNS data, WHOIS, subdomains, and associated domains', 'dns', 'api_key', '[\"domain\",\"ip\"]', 'https://docs.securitytrails.com', 'SECURITYTRAILS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(66, 'TLD Searcher', 'tld-searcher', '', NULL, 0, 10, 'Internal permutation-based TLD variant discovery', 'dns', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:00:06'),
(67, 'ViewDNS.info', 'viewdns', 'https://api.viewdns.info', NULL, 0, 30, 'DNS tools — reverse IP, WHOIS, port scan, traceroute', 'dns', 'api_key', '[\"domain\",\"ip\"]', 'https://viewdns.info/api/', 'VIEWDNS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(68, 'Whoisology', 'whoisology', 'https://whoisology.com/api', NULL, 0, 30, 'Reverse WHOIS lookups — find domains by registrant details', 'dns', 'api_key', '[\"domain\"]', 'https://whoisology.com/api', 'WHOISOLOGY_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(69, 'Whoxy', 'whoxy', 'https://api.whoxy.com', NULL, 0, 30, 'WHOIS history and reverse WHOIS lookup API', 'dns', 'api_key', '[\"domain\"]', 'https://www.whoxy.com/whois-history/', 'WHOXY_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(70, 'Zetalytics', 'zetalytics', 'https://zonecruncher.com/api/v1', NULL, 0, 30, 'Massive passive DNS and WHOIS database', 'dns', 'api_key', '[\"domain\",\"ip\"]', 'https://zetalytics.com/api', 'ZETALYTICS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(71, 'Google SafeBrowsing', 'google-safebrowsing', 'https://safebrowsing.googleapis.com/v4', NULL, 0, 100, 'Google Safe Browsing API — detect phishing, malware, and unwanted software URLs', 'malware', 'api_key', '[\"url\"]', 'https://developers.google.com/safe-browsing/v4', 'GOOGLE_SAFEBROWSING_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(72, 'Hybrid Analysis', 'hybrid-analysis', 'https://www.hybrid-analysis.com/api/v2', NULL, 0, 30, 'CrowdStrike Falcon Sandbox — malware analysis and file detonation', 'malware', 'api_key', '[\"hash\",\"url\"]', 'https://www.hybrid-analysis.com/docs/api/v2', 'HYBRIDANALYSIS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(73, 'Koodous', 'koodous', 'https://api.koodous.com', NULL, 0, 30, 'Android malware analysis platform and APK intelligence', 'malware', 'none', '[\"hash\"]', 'https://koodous.com/api-docs', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:00:20'),
(74, 'MetaDefender', 'metadefender', 'https://api.metadefender.com/v4', NULL, 0, 30, 'OPSWAT MetaDefender — multi-scanning engine for files, IPs, domains, URLs', 'malware', 'api_key', '[\"hash\",\"ip\",\"domain\",\"url\"]', 'https://docs.opswat.com/mdcloud', 'METADEFENDER_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:00:23'),
(75, 'OpenPhish', 'openphish', 'https://openphish.com/feed.txt', NULL, 1, 10, 'Community phishing URL feed — free and commercial tiers', 'malware', 'none', '[\"url\",\"domain\"]', 'https://openphish.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(76, 'PhishStats', 'phishstats', 'https://phishstats.info/apiv1', NULL, 1, 30, 'Phishing URL and IP statistics database', 'malware', 'none', '[\"url\",\"domain\",\"ip\"]', 'https://phishstats.info/api.php', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(77, 'PhishTank', 'phishtank', 'https://checkurl.phishtank.com/checkurl', NULL, 1, 30, 'Community-driven phishing URL verification database', 'malware', 'none', '[\"url\"]', 'https://phishtank.org/developer_info.php', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(78, 'SSL Certificate Analyzer', 'ssl-analyzer', '', NULL, 1, 10, 'Internal SSL/TLS certificate chain parsing and security analysis', 'malware', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(79, 'Ahmia', 'ahmia', 'https://ahmia.fi/api', NULL, 1, 10, 'Tor hidden service search engine', 'osint', 'none', '[\"domain\"]', 'https://ahmia.fi', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(80, 'Archive.org', 'archive-org', 'https://archive.org/wayback/available', NULL, 1, 30, 'Identifies historic versions of interesting files/pages from the Wayback Machine.', 'osint', 'none', '[\"domain\",\"url\"]', 'https://archive.org/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(81, 'Bing', 'bing', 'https://api.bing.microsoft.com/v7.0/search', NULL, 0, 30, 'Obtain information from bing to identify sub-domains and links.', 'osint', 'api_key', '[\"domain\"]', 'https://www.bing.com/', 'BING_API_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(82, 'Bing (Shared IPs)', 'bing-shared-ips', 'https://api.bing.microsoft.com/v7.0/search', NULL, 0, 30, 'Search Bing for hosts sharing the same IP.', 'osint', 'api_key', '[\"ip\"]', 'https://www.bing.com/', 'BING_API_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(83, 'CommonCrawl', 'commoncrawl', 'https://index.commoncrawl.org', NULL, 1, 10, 'CommonCrawl web archive — massive dataset of crawled web pages', 'osint', 'none', '[\"domain\",\"url\"]', 'https://commoncrawl.org/the-data/get-started/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(84, 'Darksearch', 'darksearch', 'https://darksearch.io/api', NULL, 1, 10, 'Dark web search engine API', 'osint', 'none', '[\"domain\"]', 'https://darksearch.io/apidoc', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(85, 'DuckDuckGo', 'duckduckgo', 'https://api.duckduckgo.com', NULL, 1, 30, 'DuckDuckGo Instant Answer API', 'osint', 'none', '[\"domain\"]', 'https://duckduckgo.com/api', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(86, 'Flickr', 'flickr', 'https://api.flickr.com/services/rest', NULL, 1, 30, 'Flickr photo search — find accounts and photos by username or email', 'osint', 'none', '[\"username\",\"email\"]', 'https://www.flickr.com/services/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(87, 'Github', 'github', 'https://api.github.com', NULL, 1, 30, 'GitHub API — user profiles, repositories, and code search', 'osint', 'none', '[\"username\",\"email\"]', 'https://docs.github.com/en/rest', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(88, 'Google', 'google', 'https://www.googleapis.com/customsearch/v1', NULL, 0, 10, 'Google Custom Search API', 'osint', 'api_key', '[\"domain\"]', 'https://developers.google.com/custom-search/v1/overview', 'GOOGLE_API_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(89, 'Google Maps', 'google-maps', 'https://maps.googleapis.com/maps/api', NULL, 0, 30, 'Google Maps Places and Geocoding API', 'osint', 'api_key', '[\"domain\"]', 'https://developers.google.com/maps/documentation', 'GOOGLE_MAPS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(90, 'grep.app', 'grep-app', 'https://grep.app/api', NULL, 1, 10, 'Source code search engine — find code snippets and secrets', 'osint', 'none', '[\"domain\",\"hash\"]', 'https://grep.app', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(91, 'IntelligenceX', 'intelligencex', 'https://2.intelx.io', NULL, 0, 30, 'Intelligence X — search engine for leaked data, darknet, and OSINT', 'osint', 'api_key', '[\"email\",\"domain\",\"ip\",\"url\"]', 'https://intelx.io/api', 'INTELX_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(92, 'Onion.link', 'onion-link', 'https://onion.link', NULL, 1, 10, 'Tor2web proxy gateway for onion service access', 'osint', 'none', '[\"domain\"]', 'https://onion.link', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(93, 'Onionsearchengine.com', 'onionsearchengine', 'https://onionsearchengine.com', NULL, 1, 10, 'Dark web search engine', 'osint', 'none', '[\"domain\"]', 'https://onionsearchengine.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(94, 'PasteBin', 'pastebin', 'https://scrape.pastebin.com/api_scraping.php', NULL, 0, 30, 'Pastebin paste scraping API — search for leaked data', 'osint', 'api_key', '[\"email\",\"username\"]', 'https://pastebin.com/doc_api', 'PASTEBIN_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(95, 'Pulsedive', 'pulsedive', 'https://pulsedive.com/api', NULL, 0, 30, 'Community threat intelligence platform — IoC enrichment and correlation', 'osint', 'api_key', '[\"ip\",\"domain\",\"url\",\"hash\"]', 'https://pulsedive.com/api/', 'PULSEDIVE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(96, 'Recon.dev', 'recon-dev', 'https://recon.dev/api', NULL, 0, 30, 'Attack surface management — subdomain and technology discovery', 'osint', 'api_key', '[\"domain\"]', 'https://recon.dev/api/docs', 'RECONDEV_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(97, 'RiskIQ', 'riskiq', 'https://api.riskiq.net/pt/v2', NULL, 0, 30, 'RiskIQ PassiveTotal — passive DNS, WHOIS, and host attributes', 'osint', 'api_key', '[\"domain\",\"ip\"]', 'https://api.riskiq.net/api/pdns/', 'RISKIQ_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(98, 'searchcode', 'searchcode', 'https://searchcode.com/api', NULL, 1, 30, 'Source code search engine across multiple repositories', 'osint', 'none', '[\"domain\"]', 'https://searchcode.com/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(99, 'Spyse', 'spyse', 'https://api.spyse.com/v4', NULL, 0, 30, 'Internet assets search engine — domains, IPs, certificates, technologies', 'osint', 'api_key', '[\"domain\",\"ip\"]', 'https://spyse.com/api', 'SPYSE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(100, 'SpyOnWeb', 'spyonweb', 'https://api.spyonweb.com/v1', NULL, 0, 30, 'Discover websites with shared analytics/AdSense IDs', 'osint', 'api_key', '[\"domain\",\"ip\"]', 'https://api.spyonweb.com', 'SPYONWEB_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(101, 'StackOverflow', 'stackoverflow', 'https://api.stackexchange.com/2.3', NULL, 1, 30, 'Stack Exchange API — developer profile and activity search', 'osint', 'none', '[\"username\",\"email\"]', 'https://api.stackexchange.com/docs', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(102, 'TORCH', 'torch', 'https://torch.onionsearchengine.com', NULL, 1, 10, 'Tor search engine', 'osint', 'none', '[\"domain\"]', 'https://torch.onionsearchengine.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(103, 'Wikileaks', 'wikileaks', 'https://search.wikileaks.org/api', NULL, 1, 10, 'WikiLeaks search API', 'osint', 'none', '[\"domain\"]', 'https://wikileaks.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(104, 'Wikipedia Edits', 'wikipedia-edits', 'https://en.wikipedia.org/w/api.php', NULL, 1, 30, 'Wikipedia user contribution and edit history API', 'osint', 'none', '[\"username\"]', 'https://www.mediawiki.org/wiki/API:Main_page', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(105, 'BitcoinAbuse', 'bitcoinabuse', 'https://www.bitcoinabuse.com/api', NULL, 0, 30, 'Bitcoin address abuse reports — scam, ransomware, darknet marketplace', 'leaks', 'api_key', '[\"bitcoin\"]', 'https://www.bitcoinabuse.com/api-docs', 'BITCOINABUSE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(106, 'Bitcoin Who\'s Who', 'bitcoin-whos-who', 'https://bitcoinwhoswho.com/api', NULL, 0, 30, 'Bitcoin address ownership and transaction intelligence', 'leaks', 'api_key', '[\"bitcoin\"]', 'https://bitcoinwhoswho.com/api', 'BITCOINWHOSEWHO_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(107, 'Dehashed', 'dehashed', 'https://api.dehashed.com/search', NULL, 0, 30, 'Breach data search engine — email, username, IP, domain lookups', 'leaks', 'api_key', '[\"email\",\"username\",\"ip\",\"domain\"]', 'https://www.dehashed.com/docs', 'DEHASHED_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(108, 'HaveIBeenPwned', 'haveibeenpwned', 'https://haveibeenpwned.com/api/v3', NULL, 1, 10, 'Troy Hunt\'s breach notification service — check if credentials were compromised', 'leaks', 'api_key', '[\"email\"]', 'https://haveibeenpwned.com/API/v3', 'HIBP_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-18 03:33:51'),
(109, 'Iknowwhatyoudownload.com', 'iknowwhatyoudownload', 'https://api.iknowwhatyoudownload.com/api', NULL, 0, 10, 'Torrent download history by IP address', 'leaks', 'api_key', '[\"ip\"]', 'https://iknowwhatyoudownload.com', 'IKNOWWHATYOUDOWNLOAD_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(110, 'Leak-Lookup', 'leak-lookup', 'https://leak-lookup.com/api', NULL, 0, 30, 'Breach data search — email, username, hash lookups across leaked databases', 'leaks', 'api_key', '[\"email\",\"hash\",\"username\"]', 'https://leak-lookup.com/api', 'LEAKLOOKUP_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(111, 'LeakIX', 'leakix', 'https://leakix.net/api', NULL, 0, 30, 'Real-time indexing of internet-exposed data leaks and misconfigurations', 'leaks', 'api_key', '[\"domain\",\"ip\"]', 'https://leakix.net/docs/api', 'LEAKIX_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(112, 'Scylla', 'scylla', 'https://scylla.sh/search', NULL, 1, 30, 'Leaked credential search engine', 'leaks', 'none', '[\"email\",\"username\"]', 'https://scylla.sh/docs', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(113, 'Trashpanda', 'trashpanda', 'https://trashpanda.cc/api', NULL, 0, 30, 'Breach data aggregation and search service', 'leaks', 'api_key', '[\"email\",\"username\"]', 'https://trashpanda.cc', 'TRASHPANDA_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(114, 'AbstractAPI', 'abstractapi', 'https://emailvalidation.abstractapi.com/v1', NULL, 0, 30, 'Email validation, geolocation, and company enrichment APIs', 'identity', 'api_key', '[\"email\"]', 'https://www.abstractapi.com/api/email-verification-validation-api', 'ABSTRACTAPI_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(115, 'Account Finder', 'account-finder', '', NULL, 1, 10, 'Internal username permutation search across social platforms', 'identity', 'none', '[\"username\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(116, 'Clearbit', 'clearbit', 'https://person.clearbit.com/v2', NULL, 0, 30, 'Business identity enrichment — person and company data from email/domain', 'identity', 'api_key', '[\"email\",\"domain\"]', 'https://clearbit.com/docs', 'CLEARBIT_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(117, 'EmailCrawlr', 'emailcrawlr', 'https://api.emailcrawlr.com/v2', NULL, 0, 30, 'Email intelligence — validation, domain emails, social profiles', 'identity', 'api_key', '[\"email\",\"domain\"]', 'https://emailcrawlr.com/api', 'EMAILCRAWLR_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(118, 'EmailRep', 'emailrep', 'https://emailrep.io', NULL, 0, 30, 'Email reputation and risk scoring', 'identity', 'api_key', '[\"email\"]', 'https://emailrep.io/docs', 'EMAILREP_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(119, 'FullContact', 'fullcontact', 'https://api.fullcontact.com/v3', NULL, 0, 30, 'Person and company enrichment from email, phone, or social profile', 'identity', 'api_key', '[\"email\",\"username\"]', 'https://docs.fullcontact.com', 'FULLCONTACT_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(120, 'Hunter.io', 'hunter', 'https://api.hunter.io/v2', NULL, 0, 25, 'Email finder and verifier — discover professional email addresses', 'identity', 'api_key', '[\"email\",\"domain\"]', 'https://hunter.io/api-documentation/v2', 'HUNTER_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(121, 'NameAPI', 'nameapi', 'https://api.nameapi.org/rest/v5.3', NULL, 0, 30, 'Name parsing, validation, and gender detection API', 'identity', 'api_key', '[\"email\"]', 'https://www.nameapi.org/en/developer/api-docs/', 'NAMEAPI_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(122, 'numverify', 'numverify', 'http://apilayer.net/api/validate', NULL, 0, 30, 'Phone number validation, carrier detection, and geolocation', 'identity', 'api_key', '[\"phone\"]', 'https://numverify.com/documentation', 'NUMVERIFY_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(123, 'Project Honey Pot', 'project-honeypot', '', NULL, 0, 30, 'DNS-based IP threat check using Project Honey Pot\'s http:BL API', 'identity', 'api_key', '[\"ip\"]', 'https://www.projecthoneypot.org/httpbl_api.php', 'PROJECTHONEYPOT_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(124, 'Seon', 'seon', 'https://api.seon.io/SeonRestService/email-api/v2.2', NULL, 0, 30, 'Digital footprint and fraud prevention — email, phone, IP scoring', 'identity', 'api_key', '[\"email\",\"phone\",\"ip\"]', 'https://docs.seon.io', 'SEON_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(125, 'Snov', 'snov', 'https://api.snov.io/v1', NULL, 0, 30, 'Email finder, verifier, and drip campaign tool', 'identity', 'api_key', '[\"email\",\"domain\"]', 'https://snov.io/api', 'SNOV_CLIENT_ID', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(126, 'Social Links', 'social-links', 'https://api.sociallinks.io', NULL, 0, 30, 'Social media intelligence and profile discovery', 'identity', 'api_key', '[\"username\",\"email\"]', 'https://sociallinks.io/docs', 'SOCIALLINKS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(127, 'Social Media Profile Finder', 'social-media-finder', '', NULL, 0, 10, 'Internal cross-platform social media username search', 'identity', 'api_key', '[\"username\",\"email\"]', NULL, 'SOCIALLINKS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(128, 'TextMagic', 'textmagic', 'https://rest.textmagic.com/api/v2', NULL, 0, 30, 'SMS API with phone number validation and carrier lookup', 'identity', 'api_key', '[\"phone\"]', 'https://docs.textmagic.com', 'TEXTMAGIC_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(129, 'Twilio', 'twilio', 'https://lookups.twilio.com/v2/PhoneNumbers', NULL, 0, 30, 'Phone number lookup — carrier, caller name, and line type detection', 'identity', 'api_key', '[\"phone\"]', 'https://www.twilio.com/docs/lookup', 'TWILIO_ACCOUNT_SID', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(130, 'AdBlock Check', 'adblock-check', '', NULL, 1, 10, 'Check if a domain appears on popular adblock filter lists', 'infra', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(131, 'Amazon S3 Bucket Finder', 's3-finder', 'https://s3.amazonaws.com', NULL, 1, 10, 'Discover open Amazon S3 buckets by domain name permutation', 'infra', 'none', '[\"domain\"]', 'https://docs.aws.amazon.com/s3/index.html', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(132, 'Azure Blob Finder', 'azure-blob-finder', 'https://blob.core.windows.net', NULL, 1, 10, 'Search for potential Azure blobs associated with the target and attempt to list their contents.', 'infra', 'none', '[\"domain\"]', 'https://azure.microsoft.com/en-in/services/storage/blobs/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(133, 'BinaryEdge', 'binaryedge', 'https://api.binaryedge.io/v2', NULL, 0, 30, 'Obtain information from BinaryEdge.io Internet scanning systems, including breaches, vulnerabilities, torrents and passive DNS.', 'infra', 'api_key', '[\"ip\",\"domain\"]', 'https://www.binaryedge.io/', 'BINARYEDGE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(134, 'BuiltWith', 'builtwith', 'https://api.builtwith.com/v21', NULL, 0, 30, 'Website technology profiling — CMS, frameworks, analytics, hosting', 'infra', 'api_key', '[\"domain\"]', 'https://api.builtwith.com', 'BUILTWITH_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(135, 'C99', 'c99', 'https://api.c99.nl', NULL, 0, 30, 'Multi-purpose OSINT API — subdomains, phone, IP, WAF detection', 'infra', 'api_key', '[\"domain\",\"ip\"]', 'https://api.c99.nl', 'C99_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(136, 'CRXcavator', 'crxcavator', 'https://api.crxcavator.io/v1', NULL, 1, 30, 'Chrome extension security analysis and risk scoring', 'infra', 'none', '[\"domain\"]', 'https://crxcavator.io', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(137, 'Digital Ocean Space Finder', 'do-space-finder', '', NULL, 1, 10, 'Discover open DigitalOcean Spaces by domain name permutation', 'infra', 'none', '[\"domain\"]', 'https://docs.digitalocean.com/products/spaces/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(138, 'Etherscan', 'etherscan', 'https://api.etherscan.io/api', NULL, 0, 30, 'Ethereum blockchain explorer — address, transaction, and token data', 'infra', 'api_key', '[\"ip\",\"domain\"]', 'https://docs.etherscan.io', 'ETHERSCAN_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(139, 'FullHunt', 'fullhunt', 'https://fullhunt.io/api/v1', NULL, 0, 30, 'Attack surface discovery — exposed hosts, services, and technologies', 'infra', 'api_key', '[\"domain\"]', 'https://fullhunt.io/api/', 'FULLHUNT_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(140, 'Google Object Storage Finder', 'gcs-finder', 'https://storage.googleapis.com', NULL, 1, 10, 'Discover open Google Cloud Storage buckets', 'infra', 'none', '[\"domain\"]', 'https://cloud.google.com/storage/docs', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(141, 'Grayhat Warfare', 'grayhat-warfare', 'https://buckets.grayhatwarfare.com/api/v2', NULL, 0, 30, 'Open S3 bucket and cloud storage search engine', 'infra', 'api_key', '[\"domain\"]', 'https://grayhatwarfare.com', 'GRAYHAT_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(142, 'NetworksDB', 'networksdb', 'https://networksdb.io/api/v1', NULL, 0, 30, 'IP and ASN intelligence — network ownership and geolocation', 'infra', 'api_key', '[\"ip\"]', 'https://networksdb.io/api/docs', 'NETWORKSDB_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(143, 'Onyphe', 'onyphe', 'https://www.onyphe.io/api/v2', NULL, 0, 30, 'Cyber defense search engine — open ports, vulns, threat data', 'infra', 'api_key', '[\"ip\",\"domain\"]', 'https://www.onyphe.io/docs/onyphe-query-language', 'ONYPHE_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(144, 'OpenCorporates', 'opencorporates', 'https://api.opencorporates.com/v0.4', NULL, 1, 30, 'Open database of companies worldwide', 'infra', 'none', '[\"domain\"]', 'https://api.opencorporates.com', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(145, 'WhatCMS', 'whatcms', 'https://whatcms.org/API', NULL, 0, 30, 'CMS detection API — identify content management systems', 'infra', 'api_key', '[\"domain\"]', 'https://whatcms.org', 'WHATCMS_KEY', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(146, 'WiGLE', 'wigle', 'https://api.wigle.net/api/v2', NULL, 0, 30, 'Wireless network mapping — WiFi, Bluetooth, cell tower data', 'infra', 'api_key', '[\"ip\"]', 'https://api.wigle.net/swagger', 'WIGLE_API_NAME', 1, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(147, 'botvrij.eu', 'botvrij', 'https://botvrij.eu', NULL, 1, 10, 'Open source IoC feeds — IP addresses, domains, URLs, and file hashes', 'blocklist', 'none', '[\"domain\",\"ip\",\"hash\"]', 'https://botvrij.eu', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(148, 'CoinBlocker Lists', 'coinblocker', 'https://zerodot1.gitlab.io/CoinBlockerLists', NULL, 1, 10, 'Cryptocurrency mining blocklists — domains and IPs used for cryptojacking', 'blocklist', 'none', '[\"domain\",\"ip\"]', 'https://zerodot1.gitlab.io/CoinBlockerLists/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(149, 'multiproxy.org Open Proxies', 'multiproxy', 'https://multiproxy.org/txt_all/proxy.txt', NULL, 1, 10, 'List of open proxy servers', 'blocklist', 'none', '[\"ip\"]', 'https://multiproxy.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(150, 'PGP Key Servers', 'pgp-keyservers', 'https://keys.openpgp.org', NULL, 1, 10, 'Search public PGP keyservers for email-associated cryptographic keys', 'blocklist', 'none', '[\"email\"]', 'https://keys.openpgp.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(151, 'Steven Black Hosts', 'steven-black-hosts', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', NULL, 1, 10, 'Unified hosts file with base extensions for ad and malware blocking', 'blocklist', 'none', '[\"domain\"]', 'https://github.com/StevenBlack/hosts', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(152, 'SURBL', 'surbl', '', NULL, 1, 10, 'DNS-based URI blocklist for spam and phishing domain detection', 'blocklist', 'none', '[\"domain\"]', 'https://www.surbl.org/surbl-analysis', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(153, 'TOR Exit Nodes', 'tor-exit-nodes', 'https://check.torproject.org/exit-addresses', NULL, 1, 10, 'List of current Tor network exit node IP addresses', 'blocklist', 'none', '[\"ip\"]', 'https://check.torproject.org/exit-addresses', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(154, 'Zone-H Defacement Check', 'zone-h', 'https://zone-h.org', NULL, 1, 10, 'Website defacement archive and monitoring', 'blocklist', 'none', '[\"domain\"]', 'https://www.zone-h.org', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(155, 'Base64 Decoder', 'base64-decoder', '', NULL, 0, 10, 'Identify Base64-encoded strings in URLs, often revealing interesting hidden information.', 'extract', 'none', '[\"url\",\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(156, 'Binary String Extractor', 'binary-string-extractor', '', NULL, 0, 10, 'Attempt to identify strings in binary content.', 'extract', 'none', '[\"hash\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-17 07:09:39'),
(157, 'Company Name Extractor', 'company-name-extractor', '', NULL, 1, 10, 'NLP-based company and organization name extraction from text', 'extract', 'none', '[\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(158, 'Country Name Extractor', 'country-name-extractor', '', NULL, 1, 10, 'NLP-based country and geolocation extraction from text content', 'extract', 'none', '[\"domain\",\"ip\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(159, 'Cross-Referencer', 'cross-referencer', '', NULL, 1, 10, 'Cross-correlate and enrich results from multiple OSINT modules', 'extract', 'none', '[\"ip\",\"domain\",\"email\",\"hash\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(160, 'File Metadata Extractor', 'file-metadata-extractor', '', NULL, 0, 10, 'Extract EXIF, PDF, and document metadata from downloaded files', 'extract', 'none', '[\"url\",\"hash\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:39'),
(161, 'Human Name Extractor', 'human-name-extractor', '', NULL, 0, 10, 'NLP-based human name detection and extraction from text', 'extract', 'none', '[\"domain\",\"email\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:41'),
(162, 'Interesting File Finder', 'interesting-file-finder', '', NULL, 1, 10, 'Discover sensitive files (robots.txt, .env, backups) via web crawling', 'extract', 'none', '[\"domain\",\"url\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(163, 'Junk File Finder', 'junk-file-finder', '', NULL, 1, 10, 'Identify backup, temporary, and development files on web servers', 'extract', 'none', '[\"domain\",\"url\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(164, 'Web Spider', 'web-spider', '', NULL, 1, 10, 'Crawl web pages and extract links, emails, and metadata', 'extract', 'none', '[\"domain\",\"url\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(165, 'Port Scanner - TCP', 'port-scanner-tcp', '', NULL, 1, 10, 'TCP connect scan via raw sockets — discover open ports and services', 'tools', 'none', '[\"ip\",\"domain\"]', NULL, NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 11:19:45'),
(166, 'Tool - CMSeeK', 'cmseek', '', NULL, 0, 10, 'CMS detection and exploitation tool — WordPress, Joomla, Drupal, etc.', 'tools', 'none', '[\"domain\",\"url\"]', 'https://github.com/Tuhinshubhra/CMSeeK', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:09'),
(167, 'Tool - DNSTwist', 'dnstwist', '', NULL, 0, 10, 'Domain name permutation engine — detect typosquatting and phishing', 'tools', 'none', '[\"domain\"]', 'https://github.com/elceef/dnstwist', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:11'),
(168, 'Tool - nbtscan', 'nbtscan', '', NULL, 0, 10, 'NetBIOS name service scanner for Windows network enumeration', 'tools', 'none', '[\"ip\"]', 'http://www.unixwiz.net/tools/nbtscan.html', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:13'),
(169, 'Tool - Nmap', 'nmap', '', NULL, 0, 10, 'Network mapper — port scanning, service detection, OS fingerprinting', 'tools', 'none', '[\"ip\",\"domain\"]', 'https://nmap.org/book/man.html', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:04'),
(170, 'Tool - Nuclei', 'nuclei', '', NULL, 0, 10, 'Fast vulnerability scanner using community-maintained templates', 'tools', 'none', '[\"domain\",\"ip\",\"url\"]', 'https://docs.projectdiscovery.io/tools/nuclei', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:17'),
(171, 'Tool - onesixtyone', 'onesixtyone', '', NULL, 0, 10, 'SNMP scanner — brute-force community strings on network devices', 'tools', 'none', '[\"ip\"]', 'https://github.com/trailofbits/onesixtyone', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:19'),
(172, 'Tool - Retire.js', 'retire-js', '', NULL, 0, 10, 'JavaScript library vulnerability scanner', 'tools', 'none', '[\"url\",\"domain\"]', 'https://retirejs.github.io/retire.js/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:21'),
(173, 'Tool - snallygaster', 'snallygaster', '', NULL, 0, 10, 'Scan for secret files and misconfigurations on web servers', 'tools', 'none', '[\"domain\"]', 'https://github.com/hannob/snallygaster', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:23'),
(174, 'Tool - testssl.sh', 'testssl', '', NULL, 0, 10, 'SSL/TLS configuration analysis and vulnerability testing', 'tools', 'none', '[\"domain\",\"ip\"]', 'https://testssl.sh', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:25');
INSERT INTO `api_configs` (`id`, `name`, `slug`, `base_url`, `api_key`, `is_enabled`, `rate_limit`, `description`, `category`, `auth_type`, `supported_types`, `docs_url`, `env_key`, `requires_key`, `last_health_check`, `health_status`, `created_at`, `updated_at`) VALUES
(175, 'Tool - TruffleHog', 'trufflehog', '', NULL, 0, 10, 'Search for secrets and credentials in git repositories', 'tools', 'none', '[\"domain\",\"url\"]', 'https://github.com/trufflesecurity/trufflehog', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:26'),
(176, 'Tool - WAFW00F', 'wafw00f', '', NULL, 0, 10, 'Web Application Firewall detection and fingerprinting', 'tools', 'none', '[\"domain\",\"url\"]', 'https://github.com/EnableSecurity/wafw00f', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:28'),
(177, 'Tool - Wappalyzer', 'wappalyzer', '', NULL, 0, 10, 'Technology profiler — identify CMS, frameworks, analytics on websites', 'tools', 'none', '[\"domain\",\"url\"]', 'https://www.wappalyzer.com/docs/api/', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:29'),
(178, 'Tool - WhatWeb', 'whatweb', '', NULL, 0, 10, 'Web scanner — identify technologies, CMS, server software', 'tools', 'none', '[\"domain\",\"url\"]', 'https://github.com/urbanadventurer/WhatWeb', NULL, 0, NULL, 'unknown', '2026-03-14 11:19:45', '2026-03-14 17:01:31'),
(179, 'APIVoid', 'apivoid', 'https://endpoint.apivoid.com', 'zH9jOoZsvjan.tLWbEM6jlkoiqhxydmCtmp.CpOnxnsZtMtFuGfcYssh-fnd_heQ', 1, 30, 'Comprehensive threat analysis APIs ù IP reputation, domain reputation, URL reputation, email verification, DNS lookups, SSL certificate analysis, and site trustworthiness scoring powered by 40+ security engines.', 'threat', 'api_key', '[\"ip\",\"domain\",\"url\",\"email\"]', 'https://docs.apivoid.com', 'APIVOID_KEY', 1, '2026-03-18 03:44:42', 'healthy', '2026-03-18 03:25:44', '2026-03-18 03:44:42');

-- --------------------------------------------------------

--
-- Table structure for table `dashboards`
--

CREATE TABLE `dashboards` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `name` varchar(150) NOT NULL,
  `description` text DEFAULT NULL,
  `is_default` tinyint(1) NOT NULL DEFAULT 0,
  `layout` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Widget positions and sizes' CHECK (json_valid(`layout`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `dashboard_widgets`
--

CREATE TABLE `dashboard_widgets` (
  `id` int(10) UNSIGNED NOT NULL,
  `dashboard_id` int(10) UNSIGNED NOT NULL,
  `widget_type` enum('threat_map','recent_queries','severity_chart','top_indicators','api_status','stats_counter') NOT NULL,
  `title` varchar(150) NOT NULL,
  `config` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Widget-specific configuration' CHECK (json_valid(`config`)),
  `position_x` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `position_y` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `width` int(10) UNSIGNED NOT NULL DEFAULT 4,
  `height` int(10) UNSIGNED NOT NULL DEFAULT 3,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `attempt_key` varchar(64) NOT NULL,
  `attempts` int(10) UNSIGNED NOT NULL DEFAULT 1,
  `first_attempt_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_attempt_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `module_settings`
--

CREATE TABLE `module_settings` (
  `id` int(10) UNSIGNED NOT NULL,
  `module_slug` varchar(50) NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `platform_settings`
--

CREATE TABLE `platform_settings` (
  `id` int(10) UNSIGNED NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `platform_settings`
--

INSERT INTO `platform_settings` (`id`, `setting_key`, `setting_value`, `updated_at`) VALUES
(1, 'debug', 'false', '2026-03-16 09:13:14'),
(2, 'dns_resolver', '', '2026-03-16 09:13:14'),
(3, 'http_timeout', '30', '2026-03-16 10:10:32'),
(4, 'generic_usernames', 'abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,', '2026-03-16 09:13:14'),
(5, 'tld_list_url', 'https://publicsuffix.org/list/effective_tld_names.dat', '2026-03-16 09:13:14'),
(6, 'tld_cache_hours', '72', '2026-03-16 09:13:14'),
(7, 'max_concurrent_modules', '3', '2026-03-16 09:13:14'),
(8, 'socks_type', '', '2026-03-16 09:13:14'),
(9, 'socks_host', '', '2026-03-16 09:13:14'),
(10, 'socks_port', '', '2026-03-16 09:13:14'),
(11, 'socks_username', '', '2026-03-16 09:13:14'),
(12, 'socks_password', '', '2026-03-16 09:13:14'),
(13, 'user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0', '2026-03-16 09:13:14'),
(14, 'max_bytes_per_element', '1024', '2026-03-16 09:13:14');

-- --------------------------------------------------------

--
-- Table structure for table `query_history`
--

CREATE TABLE `query_history` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `scan_id` int(10) UNSIGNED DEFAULT NULL,
  `query_type` varchar(20) NOT NULL DEFAULT 'domain',
  `query_value` varchar(500) NOT NULL,
  `api_source` varchar(50) DEFAULT NULL COMMENT 'Which API was queried',
  `result_summary` text DEFAULT NULL COMMENT 'Truncated result for display',
  `risk_score` decimal(5,2) DEFAULT NULL COMMENT '0-100 risk score',
  `status` enum('pending','completed','failed','timeout') NOT NULL DEFAULT 'pending',
  `response_time` int(10) UNSIGNED DEFAULT NULL COMMENT 'Response time in ms',
  `queried_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `query_history`
--

INSERT INTO `query_history` (`id`, `user_id`, `scan_id`, `query_type`, `query_value`, `api_source`, `result_summary`, `risk_score`, `status`, `response_time`, `queried_at`) VALUES
(1030, 1, 17, 'domain', 'elms.sti.edu', 'virustotal', 'Domain elms.sti.edu: 0/94 engines flagged as malicious.', 0.00, 'completed', 716, '2026-03-18 06:32:44');

-- --------------------------------------------------------

--
-- Table structure for table `roles`
--

CREATE TABLE `roles` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `roles`
--

INSERT INTO `roles` (`id`, `name`, `description`, `created_at`) VALUES
(1, 'admin', 'Full access — manage users, APIs, and system settings', '2026-03-11 07:30:04'),
(2, 'analyst', 'Query threat intelligence sources and view dashboards', '2026-03-11 07:30:04');

-- --------------------------------------------------------

--
-- Table structure for table `scans`
--

CREATE TABLE `scans` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `name` varchar(200) NOT NULL DEFAULT 'Untitled Scan',
  `target` varchar(500) NOT NULL,
  `target_type` varchar(20) NOT NULL DEFAULT 'domain',
  `status` enum('starting','running','finished','failed','aborted') NOT NULL DEFAULT 'starting',
  `use_case` varchar(30) DEFAULT NULL COMMENT 'all, footprint, investigate, passive',
  `selected_modules` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Array of module slugs selected for this scan' CHECK (json_valid(`selected_modules`)),
  `total_elements` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `unique_elements` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `error_count` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `started_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `finished_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `scans`
--

INSERT INTO `scans` (`id`, `user_id`, `name`, `target`, `target_type`, `status`, `use_case`, `selected_modules`, `total_elements`, `unique_elements`, `error_count`, `started_at`, `finished_at`, `created_at`, `updated_at`) VALUES
(16, 1, 'Elms', 'elms.sti.edu', 'domain', 'finished', 'all', '[\"abuse-ch\",\"alienvault\",\"apivoid\",\"abuseipdb\",\"virustotal\",\"shodan\"]', 2, 1, 4, '2026-03-18 04:03:35', '2026-03-18 04:03:41', '2026-03-18 04:03:35', '2026-03-18 04:03:41'),
(17, 1, 'Elms', 'elms.sti.edu', 'domain', 'finished', 'all', '[\"virustotal\"]', 1, 1, 0, '2026-03-18 06:32:43', '2026-03-18 06:32:44', '2026-03-18 06:32:43', '2026-03-18 06:32:44');

-- --------------------------------------------------------

--
-- Table structure for table `scan_correlations`
--

CREATE TABLE `scan_correlations` (
  `id` int(10) UNSIGNED NOT NULL,
  `scan_id` int(10) UNSIGNED NOT NULL,
  `rule_name` varchar(200) NOT NULL,
  `severity` enum('high','medium','low','info') NOT NULL DEFAULT 'info',
  `title` varchar(500) NOT NULL,
  `detail` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `scan_correlations`
--

INSERT INTO `scan_correlations` (`id`, `scan_id`, `rule_name`, `severity`, `title`, `detail`, `created_at`) VALUES
(9, 16, 'ALL_CLEAR', 'info', 'No significant threats detected for elms.sti.edu', '2 out of 6 modules returned results — all with low risk scores.', '2026-03-18 04:03:41'),
(10, 17, 'ALL_CLEAR', 'info', 'No significant threats detected for elms.sti.edu', '1 out of 1 modules returned results — all with low risk scores.', '2026-03-18 06:32:44');

-- --------------------------------------------------------

--
-- Table structure for table `scan_logs`
--

CREATE TABLE `scan_logs` (
  `id` int(10) UNSIGNED NOT NULL,
  `scan_id` int(10) UNSIGNED NOT NULL,
  `level` enum('info','warning','error','debug') NOT NULL DEFAULT 'info',
  `module` varchar(100) DEFAULT NULL,
  `message` text NOT NULL,
  `logged_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `scan_logs`
--

INSERT INTO `scan_logs` (`id`, `scan_id`, `level`, `module`, `message`, `logged_at`) VALUES
(688, 16, 'info', NULL, 'Scan started: \'Elms\' targeting elms.sti.edu (domain)', '2026-03-18 04:03:35'),
(689, 16, 'info', NULL, '6 modules selected for execution.', '2026-03-18 04:03:35'),
(690, 16, 'error', 'abusech', 'Invalid API key', '2026-03-18 04:03:41'),
(691, 16, 'info', 'alienvault', 'Completed in 647ms — score: 0, severity: info', '2026-03-18 04:03:41'),
(692, 16, 'error', 'apivoid', 'API key is not valid', '2026-03-18 04:03:41'),
(693, 16, 'error', 'abuseipdb', 'Module does not support query type \'domain\'', '2026-03-18 04:03:41'),
(694, 16, 'info', 'virustotal', 'Completed in 2154ms — score: 0, severity: info', '2026-03-18 04:03:41'),
(695, 16, 'error', 'shodan', 'Invalid API key', '2026-03-18 04:03:41'),
(696, 16, 'info', NULL, 'Scan finished. 2 elements, 4 errors.', '2026-03-18 04:03:41'),
(697, 17, 'info', NULL, 'Scan started: \'Elms\' targeting elms.sti.edu (domain)', '2026-03-18 06:32:43'),
(698, 17, 'info', NULL, '1 modules selected for execution.', '2026-03-18 06:32:43'),
(699, 17, 'info', 'virustotal', 'Completed in 716ms — score: 0, severity: info', '2026-03-18 06:32:44'),
(700, 17, 'info', NULL, 'Scan finished. 1 elements, 0 errors.', '2026-03-18 06:32:44');

-- --------------------------------------------------------

--
-- Table structure for table `threat_indicators`
--

CREATE TABLE `threat_indicators` (
  `id` int(10) UNSIGNED NOT NULL,
  `indicator_type` varchar(20) NOT NULL DEFAULT 'domain',
  `indicator_value` varchar(500) NOT NULL,
  `source` varchar(50) NOT NULL COMMENT 'API source slug',
  `severity` enum('critical','high','medium','low','info','unknown') NOT NULL DEFAULT 'unknown',
  `confidence` decimal(5,2) DEFAULT NULL COMMENT '0-100 confidence score',
  `tags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Associated tags/categories' CHECK (json_valid(`tags`)),
  `raw_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Full API response (cached)' CHECK (json_valid(`raw_data`)),
  `first_seen` timestamp NULL DEFAULT NULL,
  `last_seen` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `threat_indicators`
--

INSERT INTO `threat_indicators` (`id`, `indicator_type`, `indicator_value`, `source`, `severity`, `confidence`, `tags`, `raw_data`, `first_seen`, `last_seen`, `created_at`, `updated_at`) VALUES
(522, 'domain', 'elms.sti.edu', 'virustotal', 'info', 97.00, '[\"virustotal\",\"domain\",\"clean\"]', NULL, '2026-03-18 06:32:44', '2026-03-18 06:32:44', '2026-03-18 06:32:44', '2026-03-18 06:32:44');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(10) UNSIGNED NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role_id` int(10) UNSIGNED NOT NULL,
  `organisation` varchar(150) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `last_login_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `full_name`, `email`, `password_hash`, `role_id`, `organisation`, `is_active`, `last_login_at`, `created_at`, `updated_at`) VALUES
(1, 'CTI Admin', 'admin@cti.local', '$2y$10$kUxI1jRUlq.aFs0/.gJBFOoEgiw3.l3ZKTLfLQLulQLtZn2dP/k.S', 1, 'CTI Platform', 1, '2026-03-18 06:30:59', '2026-03-11 07:30:04', '2026-03-18 06:30:59'),
(2, 'CTI Analyst', 'analyst@cti.local', '$2y$12$8G2sQeOYGgPGr/RNqnDRguWN385alfeErHr1kGaMmEgccWLDVZHWW', 2, 'CTI Platform', 1, '2026-03-11 07:49:25', '2026-03-11 07:30:04', '2026-03-11 07:49:25');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `api_configs`
--
ALTER TABLE `api_configs`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_api_slug` (`slug`),
  ADD KEY `idx_api_category` (`category`);

--
-- Indexes for table `dashboards`
--
ALTER TABLE `dashboards`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_dash_user` (`user_id`);

--
-- Indexes for table `dashboard_widgets`
--
ALTER TABLE `dashboard_widgets`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_dw_dashboard` (`dashboard_id`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`attempt_key`),
  ADD KEY `idx_login_first_attempt` (`first_attempt_at`);

--
-- Indexes for table `module_settings`
--
ALTER TABLE `module_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_module_setting` (`module_slug`,`setting_key`),
  ADD KEY `idx_module_slug` (`module_slug`);

--
-- Indexes for table `platform_settings`
--
ALTER TABLE `platform_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_platform_key` (`setting_key`);

--
-- Indexes for table `query_history`
--
ALTER TABLE `query_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_qh_user` (`user_id`),
  ADD KEY `idx_qh_type_value` (`query_type`,`query_value`(100)),
  ADD KEY `idx_qh_queried_at` (`queried_at`),
  ADD KEY `idx_qh_scan` (`scan_id`);

--
-- Indexes for table `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_roles_name` (`name`);

--
-- Indexes for table `scans`
--
ALTER TABLE `scans`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_scans_user` (`user_id`),
  ADD KEY `idx_scans_status` (`status`),
  ADD KEY `idx_scans_started` (`started_at`);

--
-- Indexes for table `scan_correlations`
--
ALTER TABLE `scan_correlations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sc_scan` (`scan_id`),
  ADD KEY `idx_sc_severity` (`severity`);

--
-- Indexes for table `scan_logs`
--
ALTER TABLE `scan_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sl_scan` (`scan_id`);

--
-- Indexes for table `threat_indicators`
--
ALTER TABLE `threat_indicators`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_ti_type_value` (`indicator_type`,`indicator_value`(100)),
  ADD KEY `idx_ti_severity` (`severity`),
  ADD KEY `idx_ti_source` (`source`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_users_email` (`email`),
  ADD KEY `idx_users_role` (`role_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `api_configs`
--
ALTER TABLE `api_configs`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=180;

--
-- AUTO_INCREMENT for table `dashboards`
--
ALTER TABLE `dashboards`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `dashboard_widgets`
--
ALTER TABLE `dashboard_widgets`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `module_settings`
--
ALTER TABLE `module_settings`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `platform_settings`
--
ALTER TABLE `platform_settings`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `query_history`
--
ALTER TABLE `query_history`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1031;

--
-- AUTO_INCREMENT for table `roles`
--
ALTER TABLE `roles`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `scans`
--
ALTER TABLE `scans`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `scan_correlations`
--
ALTER TABLE `scan_correlations`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `scan_logs`
--
ALTER TABLE `scan_logs`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=701;

--
-- AUTO_INCREMENT for table `threat_indicators`
--
ALTER TABLE `threat_indicators`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=523;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `dashboards`
--
ALTER TABLE `dashboards`
  ADD CONSTRAINT `fk_dash_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `dashboard_widgets`
--
ALTER TABLE `dashboard_widgets`
  ADD CONSTRAINT `fk_dw_dashboard` FOREIGN KEY (`dashboard_id`) REFERENCES `dashboards` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `query_history`
--
ALTER TABLE `query_history`
  ADD CONSTRAINT `fk_qh_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_qh_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `scans`
--
ALTER TABLE `scans`
  ADD CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `scan_correlations`
--
ALTER TABLE `scan_correlations`
  ADD CONSTRAINT `fk_sc_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `scan_logs`
--
ALTER TABLE `scan_logs`
  ADD CONSTRAINT `fk_sl_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `fk_users_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON UPDATE CASCADE;

--
-- Ensure DNSAudit module registration exists
--
INSERT INTO `api_configs`
  (`name`, `slug`, `base_url`, `rate_limit`, `description`, `category`, `auth_type`,
   `supported_types`, `docs_url`, `env_key`, `requires_key`, `is_enabled`)
VALUES
  ('DNSAudit', 'dnsaudit', 'https://dnsaudit.io/api', 10,
   'DNS security scan API (DNSSEC, SPF, DKIM, DMARC, zone transfer and related checks).',
   'dns', 'api_key', '[\"domain\",\"url\"]', 'https://dnsaudit.io/docs/api', 'DNSAUDIT_KEY', 1, 1)
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `base_url` = VALUES(`base_url`),
  `rate_limit` = VALUES(`rate_limit`),
  `description` = VALUES(`description`),
  `category` = VALUES(`category`),
  `auth_type` = VALUES(`auth_type`),
  `supported_types` = VALUES(`supported_types`),
  `docs_url` = VALUES(`docs_url`),
  `env_key` = VALUES(`env_key`),
  `requires_key` = VALUES(`requires_key`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
