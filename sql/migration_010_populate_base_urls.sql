-- =============================================================================
--  Migration 010: Populate empty base_url values for all 43 modules
--  CTI Platform — Gap Closure Phase 1
--
--  This migration sets correct base_url values for:
--   - 6 DNS/Network modules (local PHP operations)
--   - 5 DNSBL/Blocklist modules (DNS-based lookups)
--   - 13 Web-based tool modules (PHP implementations)
--   - 10 Data extractor/utility modules (local processing)
--   - 9 External API / identity / scanner modules
-- =============================================================================

-- ── DNS & Network Modules (local PHP built-in functions) ─────────────────────
UPDATE api_configs SET base_url = 'local://dns'
WHERE slug IN ('dns-bruteforce','dns-lookaside','dns-raw','dns-resolver','dns-zone-transfer','tld-searcher')
  AND (base_url = '' OR base_url IS NULL);

-- ── Blocklist / DNSBL Modules (DNS TXT/A record lookups) ────────────────────
UPDATE api_configs SET base_url = 'https://lookup.abusix.com'       WHERE slug = 'abusix'        AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'http://dnsbl.sorbs.net'          WHERE slug = 'sorbs'         AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'https://bl.spamcop.net'          WHERE slug = 'spamcop'       AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'https://zen.spamhaus.org'        WHERE slug = 'spamhaus-zen'  AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'http://dnsbl-1.uceprotect.net'   WHERE slug = 'uceprotect'    AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'http://multi.surbl.org'          WHERE slug = 'surbl'         AND (base_url = '' OR base_url IS NULL);

-- ── Web-Based Tool Modules (PHP implementations, no CLI binary) ─────────────
UPDATE api_configs SET base_url = 'local://web-scanner'
WHERE slug IN ('cmseek','dnstwist','nbtscan','nmap','nuclei','onesixtyone','retire-js',
               'snallygaster','testssl','trufflehog','wafw00f','wappalyzer','whatweb')
  AND (base_url = '' OR base_url IS NULL);

-- ── Scanner Modules ─────────────────────────────────────────────────────────
UPDATE api_configs SET base_url = 'local://scanner'
WHERE slug IN ('port-scanner-tcp')
  AND (base_url = '' OR base_url IS NULL);

-- ── Data Extractor & Utility Modules (local processing) ─────────────────────
UPDATE api_configs SET base_url = 'local://extractor'
WHERE slug IN ('base64-decoder','binary-string-extractor','company-name-extractor',
               'country-name-extractor','cross-referencer','file-metadata-extractor',
               'human-name-extractor')
  AND (base_url = '' OR base_url IS NULL);

-- ── Web Crawling / File Discovery Modules ───────────────────────────────────
UPDATE api_configs SET base_url = 'local://web'
WHERE slug IN ('web-spider','interesting-file-finder','junk-file-finder')
  AND (base_url = '' OR base_url IS NULL);

-- ── Identity / Enumeration Modules ──────────────────────────────────────────
UPDATE api_configs SET base_url = 'local://identity'
WHERE slug IN ('account-finder','social-media-finder')
  AND (base_url = '' OR base_url IS NULL);

-- ── SSL Analysis Module ─────────────────────────────────────────────────────
UPDATE api_configs SET base_url = 'local://ssl'
WHERE slug = 'ssl-analyzer'
  AND (base_url = '' OR base_url IS NULL);

-- ── External API Modules with known endpoints ───────────────────────────────
UPDATE api_configs SET base_url = 'https://www.projecthoneypot.org'  WHERE slug = 'project-honeypot' AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'https://easylist.to'              WHERE slug = 'adblock-check'    AND (base_url = '' OR base_url IS NULL);
UPDATE api_configs SET base_url = 'https://api.digitalocean.com/v2'  WHERE slug = 'do-space-finder'  AND (base_url = '' OR base_url IS NULL);

-- ── Verify: count remaining modules with empty base_url ─────────────────────
-- SELECT slug, name FROM api_configs WHERE base_url = '' OR base_url IS NULL;
