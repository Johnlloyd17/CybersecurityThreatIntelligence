-- =============================================================================
--  CTI PLATFORM - MIGRATION 014: SpiderFoot-style module summaries
--  sql/migration_014_spiderfoot_summaries.sql
--
--  Updates description text for core modules to match SpiderFoot-style summaries.
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_014_spiderfoot_summaries.sql
-- =============================================================================

USE `cti_platform`;

UPDATE `api_configs`
SET `description` = 'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.'
WHERE `slug` = 'virustotal';

UPDATE `api_configs`
SET `description` = 'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.'
WHERE `slug` = 'abuseipdb';

UPDATE `api_configs`
SET `description` = 'Obtain information from SHODAN about identified IP addresses. Shodan is the world''s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.'
WHERE `slug` = 'shodan';

UPDATE `api_configs`
SET `description` = 'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.'
WHERE `slug` = 'abuse-ch';

UPDATE `api_configs`
SET `description` = 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.'
WHERE `slug` = 'alienvault';

