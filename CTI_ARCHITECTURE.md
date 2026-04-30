# CTI Platform — Architecture Documentation

## Overview

The **Cybersecurity Threat Intelligence (CTI) Platform** is a web-based OSINT
(Open Source Intelligence) aggregator inspired by
[SpiderFoot](https://github.com/smicallef/spiderfoot). It queries 200+
external threat intelligence APIs, correlates results, and presents unified
risk assessments — all from a single scan.

| Layer | Stack |
|-------------|-----------------------------------------------|
| **Backend** | PHP 8.x (vanilla), MySQL 8 on XAMPP / Apache |
| **Frontend**| Vanilla HTML/CSS/JS, terminal/hacker aesthetic|
| **Auth** | Session-based (bcrypt passwords, JWT optional)|

---

## Directory Structure

```
CybersecurityThreatIntelligence/
├── index.html                  # Landing / login page
├── dashboard.html              # Post-login dashboard
├── newscan.html                # New scan form (select modules + target)
├── query.html                  # Live scan progress & results
├── scaninfo.html               # Historical scan detail view
├── indicators.html             # Threat indicator database
├── history.html                # Query history browser
├── settings.html               # Admin settings (API keys, globals)
├── apis.html                   # API configuration panel
│
├── assets/
│   ├── css/
│   │   ├── styles.css          # Global styles (terminal theme)
│   │   ├── dashboard.css       # Dashboard-specific styles
│   │   └── landing.css         # Landing page styles
│   └── js/
│       ├── api-config.js       # API base URL config
│       ├── api-keys.js         # API key management UI
│       ├── auth.js             # Login/session handling
│       ├── dashboard.js        # Dashboard widgets & charts
│       ├── dashboard-stats.js  # Dashboard statistics
│       ├── landing.js          # Landing page logic
│       ├── newscan.js          # New scan form logic
│       ├── query.js            # Scan results rendering
│       ├── scaninfo.js         # Scan detail page logic
│       ├── settings.js         # Settings page logic
│       └── theme.js            # Dark/light theme toggle
│
├── php/
│   ├── config.php              # Database connection config
│   ├── db.php                  # DB singleton (PDO wrapper)
│   ├── security-headers.php    # HTTP security headers
│   ├── InputSanitizer.php      # XSS/injection input sanitizer
│   ├── RateLimiter.php         # Per-endpoint rate limiting
│   ├── HttpClient.php          # cURL wrapper (proxy, timeouts)
│   ├── GlobalSettings.php      # Global settings manager
│   ├── EventTypes.php          # SpiderFoot-style event type taxonomy
│   ├── OsintResult.php         # Standardized result data class
│   ├── OsintEngine.php         # Core orchestrator (module dispatch + enrichment)
│   ├── ScanExecutor.php        # Scan lifecycle (execute → store → correlate)
│   ├── ModuleSettingsSchema.php# Per-module settings schema
│   ├── background_scan.php     # CLI scan worker (legacy)
│   ├── scan_worker.php         # Alternative scan worker
│   │
│   ├── api/                    # REST API endpoints
│   │   ├── auth.php            # POST /api/auth.php (login/logout)
│   │   ├── query.php           # POST /api/query.php (scan execution)
│   │   ├── stats.php           # GET  /api/stats.php (dashboard data)
│   │   ├── indicators.php      # CRUD /api/indicators.php
│   │   ├── api_keys.php        # CRUD /api/api_keys.php
│   │   └── module_settings.php # CRUD /api/module_settings.php
│   │
│   └── modules/                # 200+ OSINT module handlers
│       ├── VirusTotalModule.php
│       ├── ShodanModule.php
│       ├── AlienVaultModule.php
│       ├── AbuseIPDBModule.php
│       ├── DnsResolverModule.php
│       ├── GreyNoiseModule.php
│       └── ... (190+ more)
│
└── sql/
    ├── schema.sql              # Initial database schema
    ├── migration_001_*.sql     # Expand api_configs
    ├── migration_002_*.sql     # Scans table
    ├── migration_003_*.sql     # Module settings
    ├── migration_004_*.sql     # query_history data_type column
    └── migration_005_*.sql     # Enrichment tracking columns
```

---

## Core Architecture

### How a Scan Executes

```
User clicks "Start Scan"
        │
        ▼
┌────────────────┐
│  newscan.js    │  → POST /php/api/query.php
│  (frontend)    │     { query_type, query_value, selected_apis[] }
└────────────────┘
        │
        ▼
┌────────────────┐
│  query.php     │  1. Validates input (InputSanitizer)
│  (API endpoint)│  2. Creates scan row (status = 'running')
│                │  3. Calls ScanExecutor::run() inline
└────────────────┘
        │
        ▼
┌────────────────┐
│ ScanExecutor   │  1. Loads GlobalSettings
│ ::run()        │  2. Calls OsintEngine::queryWithEnrichment()
│                │  3. Iterates results → saves to query_history
│                │  4. Upserts threat_indicators
│                │  5. Marks scan finished
│                │  6. Runs runCorrelations()
└────────────────┘
        │
        ▼
┌────────────────────────────────────────────┐
│          OsintEngine::queryWithEnrichment() │
│                                             │
│  Pass 0 (initial):                          │
│    → OsintEngine::query()                   │
│    → Dispatches to each selected module     │
│    → Collects OsintResult[] arrays          │
│                                             │
│  Pass 1..N (enrichment):                    │
│    → Extracts discoveries from results      │
│    → Maps event types → query types         │
│    → Filters eligible modules per type      │
│    → Queries discovered sub-entities        │
│    → Tags results with enrichment metadata  │
│    → Repeats until no new discoveries       │
│      or limits reached                      │
└────────────────────────────────────────────┘
        │
        ▼
┌────────────────┐
│ Module Handler │  Each module implements:
│ (e.g. Shodan)  │    execute(type, value, key, url) → OsintResult
│                │    healthCheck(key, url) → array
│                │  Populates result->discoveries[] for chaining
└────────────────┘
```

### Module Interface (Duck-Typed)

Every module handler follows the same interface convention without inheriting
from a shared abstract class:

```php
class ExampleModule
{
    // Execute a query — returns OsintResult or OsintResult[]
    public function execute(
        string $queryType,   // 'ip', 'domain', 'url', 'hash', 'email', 'cve'
        string $queryValue,  // The actual target value
        string $apiKey,      // API key from api_configs table
        string $baseUrl      // API base URL from api_configs table
    ): OsintResult|array;

    // Health check — returns status array
    public function healthCheck(string $apiKey, string $baseUrl): array;
}
```

**Return types:**
- Most modules return a single `OsintResult`
- VirusTotal returns `OsintResult[]` (primary + enrichment elements)
- The engine normalizes both into flat arrays

---

## SpiderFoot-Style Enrichment System

### The Problem (Before)

The original CTI platform used **flat execution**: each module ran once with
the same query value. If you scanned a domain, VirusTotal checked that domain,
Shodan checked that domain, AbuseIPDB skipped it (IP only) — done. No
cascading discovery.

### SpiderFoot's Approach

SpiderFoot uses a **publish-subscribe event bus**:
1. Module A produces `IP_ADDRESS` event for a resolved IP
2. Modules B, C, D that "watch" `IP_ADDRESS` automatically receive it
3. Module B produces `VULNERABILITY` events for CVEs found on that IP
4. Modules that watch `VULNERABILITY` receive those events
5. This cascades until no new events are produced

### Our Implementation: Multi-Pass Enrichment

We implement a practical middle-ground that achieves similar results without
a full event bus rewrite:

```
┌──────────────────────────────────────────────────┐
│             queryWithEnrichment()                 │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │  PASS 0: Initial Query                      │  │
│  │  query("domain", "example.com", modules)    │  │
│  │                                              │  │
│  │  DNS Resolver → A:93.184.216.34             │  │
│  │  VirusTotal  → resolves to 93.184.216.34    │  │
│  │  Shodan      → domain lookup                │  │
│  │                                              │  │
│  │  Discoveries extracted:                      │  │
│  │    IP_ADDRESS: 93.184.216.34                 │  │
│  │    INTERNET_NAME: mail.example.com           │  │
│  └─────────────────────────────────────────────┘  │
│                     │                              │
│                     ▼                              │
│  ┌─────────────────────────────────────────────┐  │
│  │  PASS 1: Enrich discovered IPs              │  │
│  │  query("ip", "93.184.216.34", ip_modules)   │  │
│  │                                              │  │
│  │  Shodan     → 3 open ports, 2 CVEs          │  │
│  │  AbuseIPDB  → 12% abuse confidence          │  │
│  │  GreyNoise  → benign scanner                │  │
│  │                                              │  │
│  │  Discoveries extracted:                      │  │
│  │    VULNERABILITY: CVE-2023-1234              │  │
│  │    INTERNET_NAME: cdn.example.com            │  │
│  └─────────────────────────────────────────────┘  │
│                     │                              │
│                     ▼                              │
│  ┌─────────────────────────────────────────────┐  │
│  │  PASS 2: Enrich CVEs and new domains        │  │
│  │  query("domain", "cdn.example.com", ...)    │  │
│  │  query("cve", "CVE-2023-1234", ...)         │  │
│  │                                              │  │
│  │  No new discoveries → STOP                   │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│  Total: all results merged with enrichment_pass   │
│         and source_ref metadata                   │
└──────────────────────────────────────────────────┘
```

### Enrichment Safety Limits

| Constant | Value | Purpose |
|---|---|---|
| `MAX_ENRICHMENT_PASSES` | 3 | Max depth of enrichment recursion |
| `MAX_ENRICHMENT_TARGETS` | 50 | Max total sub-entities to enrich per scan |
| `MAX_QUERY_TIME` | 300s | Time budget for entire enrichment loop |
| Deduplication | visited set | Prevents re-querying same "type:value" pair |
| Abort check | per-pass | Stops if scan is aborted externally |

---

## Event Types Taxonomy (`EventTypes.php`)

Mirrors SpiderFoot's `tbl_event_types` — a practical subset of ~100 types
that our modules actually produce and consume.

### Key Categories

| Category | Examples |
|---|---|
| **Core Targets** | `IP Address`, `Domain Name`, `Email Address`, `Hash` |
| **DNS / Network** | `DNS A Record`, `DNS MX Record`, `Netblock Owner`, `BGP AS Ownership` |
| **Infrastructure** | `Open TCP Port`, `Operating System`, `Web Technology` |
| **SSL / Certs** | `SSL Certificate - Raw Data`, `SSL Certificate Expired` |
| **Co-Hosting** | `Co-Hosted Site`, `Affiliate - Internet Name` |
| **Threat** | `Malicious IP Address`, `Blacklisted Internet Name` |
| **Vulnerability** | `Vulnerability` (CVE) |
| **Identity** | `Hacked Email Address`, `Social Media Presence` |
| **Geo** | `Country Name`, `Physical Coordinates` |

### Enrichment Routing

`EventTypes::toQueryType()` maps discovered event types to query types:

```
IP_ADDRESS          → 'ip'     → runs IP-capable modules
INTERNET_NAME       → 'domain' → runs domain-capable modules
VULNERABILITY       → 'cve'    → runs CVE-capable modules
EMAILADDR           → 'email'  → runs email-capable modules
HASH                → 'hash'   → runs hash-capable modules
```

---

## OsintResult Data Class

Every module returns an `OsintResult` which standardizes:

| Field | Type | Description |
|---|---|---|
| `api` | string | Module slug (`virustotal`, `shodan`, etc.) |
| `apiName` | string | Human-readable module name |
| `score` | int | Risk score 0-100 |
| `severity` | string | `critical` / `high` / `medium` / `low` / `info` |
| `confidence` | int | Confidence score 0-100 |
| `responseMs` | int | API response time in milliseconds |
| `summary` | string | Human-readable result summary |
| `tags` | array | Categorization tags |
| `rawData` | ?array | Full API response (for drill-down) |
| `dataType` | ?string | SpiderFoot event type label |
| `discoveries` | array | Sub-entities for enrichment chaining |
| `sourceRef` | string | Parent event reference (`ROOT` for initial) |
| `enrichmentPass` | int | Which pass produced this (0 = initial) |

### Discovery Extraction

Modules populate `discoveries` to enable cascading:

```php
// In DnsResolverModule — after resolving A records:
$result->addDiscovery(EventTypes::IP_ADDRESS, '93.184.216.34');
$result->addDiscovery(EventTypes::INTERNET_NAME, 'mail.example.com');

// In ShodanModule — after finding vulnerabilities:
$result->addDiscovery(EventTypes::VULNERABILITY, 'CVE-2023-1234');
$result->addDiscovery(EventTypes::INTERNET_NAME, 'host.example.com');

// In AlienVaultModule — pulse indicators:
$result->addDiscovery(EventTypes::IP_ADDRESS, '10.0.0.1');
$result->addDiscovery(EventTypes::HASH, 'abc123...');
```

---

## Correlation Engine

After a scan finishes, `runCorrelations()` evaluates rules and writes
findings to the `scan_correlations` table.

### Correlation Rules

| Rule | Severity | Trigger |
|---|---|---|
| `MULTI_SOURCE_HIGH_RISK` | high | 3+ results with score >= 75 |
| `HIGH_RISK_SINGLE_SOURCE` | medium | Any single result with score >= 75 |
| `ENRICHMENT_CHAIN_RISK` | high | Enriched sub-entity has score >= 75 |
| `ENRICHMENT_DISCOVERY` | info | Enrichment found associated entities |
| `ALL_CLEAR` | info | All results have low risk scores |

### Enrichment Chain Risk

This is the key SpiderFoot-style correlation: if the initial target is
a domain, and enrichment discovers that its resolved IP has a high abuse
score, the correlation flags the original domain as associated with
malicious infrastructure — even if the domain itself looked clean.

---

## Database Schema

### Key Tables

| Table | Purpose |
|---|---|
| `users` | User accounts (admin/analyst roles) |
| `scans` | Scan lifecycle tracking |
| `scan_logs` | Per-scan log entries |
| `query_history` | All results from all scans |
| `threat_indicators` | Aggregated indicator database |
| `scan_correlations` | Correlation findings per scan |
| `api_configs` | External API keys and endpoints |
| `module_settings` | Per-module configuration |

### Enrichment Columns in `query_history`

Added by `migration_005_enrichment_columns.sql`:

| Column | Type | Description |
|---|---|---|
| `enrichment_pass` | TINYINT | 0 = initial, 1+ = enrichment pass |
| `source_ref` | VARCHAR(500) | Parent event that triggered this result |
| `enriched_from` | VARCHAR(500) | Actual sub-entity value queried |

---

## Module Categories

### Modules That Produce Discoveries

| Module | Discovers |
|---|---|
| **DNS Resolver** | IPs (A/AAAA), hostnames (MX/NS), reverse DNS |
| **Shodan** | Hostnames, CVEs from host info |
| **AlienVault OTX** | IPs, domains, emails, hashes, CVEs from pulses |
| **VirusTotal** | Resolved IPs, sibling domains, co-hosted URLs |
| **AbuseIPDB** | Associated domain from IP lookup |
| **CRT.sh** | Domains from certificate transparency logs |
| **SecurityTrails** | Subdomains, associated IPs |

### Query Type Support Matrix

| Module | ip | domain | url | hash | email | cve |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| VirusTotal | ✓ | ✓ | ✓ | ✓ | | |
| AbuseIPDB | ✓ | | | | | |
| Shodan | ✓ | ✓ | | | | |
| AlienVault | ✓ | ✓ | ✓ | ✓ | | |
| GreyNoise | ✓ | | | | | |
| DNS Resolver | ✓ | ✓ | | | | |
| URLScan.io | | ✓ | ✓ | | | |
| HaveIBeenPwned | | | | | ✓ | |

---

## Scan Lifecycle

```
   ┌───────────┐
   │  CREATED  │  User submits scan form
   └─────┬─────┘
         │
   ┌─────▼─────┐
   │  RUNNING  │  ScanExecutor::run() is executing
   └─────┬─────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼────┐
│FINISHED│ │ABORTED│  External abort or user cancellation
└───┬────┘ └───────┘
    │
    ▼
  Correlations computed
```

---

## Security

- **Input Sanitization**: `InputSanitizer.php` validates all user input
- **SQL Injection**: Parameterized queries via PDO throughout
- **XSS**: Output encoding + Content-Security-Policy headers
- **Rate Limiting**: `RateLimiter.php` per endpoint
- **Auth**: bcrypt password hashing, session-based authentication
- **Security Headers**: `security-headers.php` sets CSP, HSTS, X-Frame-Options
- **API Key Storage**: Keys stored server-side, never exposed to frontend

---

## How to Add a New Module

1. Create `php/modules/YourModule.php`:

```php
<?php
require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';

class YourModule
{
    private const API_ID   = 'your-module';
    private const API_NAME = 'Your Module';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue,
                            string $apiKey, string $baseUrl): OsintResult
    {
        // 1. Call external API via HttpClient
        $resp = HttpClient::get("https://api.example.com/lookup?q={$queryValue}");

        // 2. Parse response and compute score
        $score = /* ... */;

        // 3. Build result
        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: 80, responseMs: $resp['elapsed_ms'],
            summary: "Found ...", tags: [self::API_ID, $queryType],
            rawData: $resp['json'], success: true,
            dataType: 'IP Address'
        );

        // 4. Add discoveries for enrichment chaining
        $result->addDiscovery(EventTypes::INTERNET_NAME, 'found.example.com');
        $result->addDiscovery(EventTypes::IP_ADDRESS, '1.2.3.4');

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        // Quick API reachability check
        $resp = HttpClient::get("https://api.example.com/status");
        return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
    }
}
```

2. Register in `OsintEngine.php`'s `$handlerMap`:
```php
'your-module' => 'YourModule.php',
```

3. Add API config row to `api_configs` table (or `schema.sql`).

4. If the module needs per-module settings, register in `ModuleSettingsSchema.php`.

---

## Configuration

### Global Settings (`GlobalSettings.php`)

| Setting | Default | Description |
|---|---|---|
| `http_timeout` | 30s | Per-request timeout |
| `max_concurrent_modules` | 5 | Parallel module execution limit |
| `max_bytes_per_element` | 50KB | Truncation limit for summaries |
| `socks_host/port/type` | none | SOCKS/HTTP proxy for API calls |
| `dns_resolver` | system | Custom DNS resolver |
| `debug_mode` | false | Verbose logging |

### Module Settings (`ModuleSettingsSchema.php`)

Per-module toggles (e.g. VirusTotal):
- `public_key` — Use 15s throttle for public API keys
- `check_affiliates` — Fetch sibling domains
- `check_co_hosted` — Fetch co-hosted URLs/IPs
- `verify_hostnames` — Verify domain DNS resolution
- `netblock_size` — Max CIDR prefix for netblock lookups

---

## Running the Migration

After updating to the enrichment-enabled version, run:

```sql
mysql -u root -p cti_platform < sql/migration_005_enrichment_columns.sql
```

This adds `enrichment_pass`, `source_ref`, and `enriched_from` columns to
the `query_history` table and creates an index for efficient enrichment-chain
retrieval.

---

## Comparison: CTI Platform vs SpiderFoot

| Feature | SpiderFoot | CTI Platform |
|---|---|---|
| Language | Python | PHP |
| Event System | Pub-sub event bus | Multi-pass enrichment loop |
| Module Interface | `watchedEvents()`/`producedEvents()`/`handleEvent()` | `execute()`/`healthCheck()` + `discoveries[]` |
| Event Types | 200+ in `tbl_event_types` | ~100 in `EventTypes.php` |
| Enrichment Depth | Unlimited (until no new events) | Max 3 passes, 50 targets |
| Deduplication | `tempStorage + seen` dict | `visited` set (type:value) |
| Correlation | SpiderFootCorrelator | `runCorrelations()` with enrichment chain rules |
| Concurrency | Thread-per-module | Sequential or configurable parallel |
| UI | Python Flask + D3.js | Vanilla HTML/JS (terminal theme) |
| Deployment | Docker / pip | XAMPP / Apache |
