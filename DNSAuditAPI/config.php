<?php
/**
 * DNSAudit API Integration - Configuration
 *
 * Based on https://dnsaudit.io/docs/api
 * API is in early access — request access at https://dnsaudit.io/api
 */

return [
    // DNSAudit API settings
    'api' => [
        'base_url'    => 'https://dnsaudit.io/api',
        'api_key'     => 'dns_1hub4ftwfa9jm4j88x55jx', // from API Settings in your DNSAudit dashboard
        'timeout'     => 30, // seconds — scans can take time (26+ checks)
        'max_retries' => 2,
    ],

    // Rate limits (per DNSAudit docs)
    // 20 scans/day (resets midnight UTC), 10 requests/minute burst
    'rate_limits' => [
        'daily_scans'       => 20,
        'requests_per_min'  => 10,
    ],

    // API endpoints (from https://dnsaudit.io/docs/api)
    'endpoints' => [
        'scan' => [
            'method' => 'GET',
            'path'   => '/v1/scan',
            'label'  => 'DNS Security Scan',
            'description' => 'Runs a full DNS security scan (26+ checks including DNSSEC, SPF, DKIM, DMARC, zone transfer, vulnerability detection). Returns security score, grade, and detailed results.',
        ],
        'export' => [
            'method' => 'GET',
            'path'   => '/export/json', // append /:domain
            'label'  => 'Export Results',
            'description' => 'Retrieves full scan results as structured JSON for dashboards or compliance reports.',
        ],
        'history' => [
            'method' => 'GET',
            'path'   => '/v1/scan-history',
            'label'  => 'Scan History',
            'description' => 'Returns recent scan history. Supports limit parameter (default 10, max 100).',
        ],
    ],

    // MySQL database
    'db' => [
        'host'     => 'localhost',
        'port'     => 4306,
        'database' => 'dnsaudit_db',
        'username' => 'root',
        'password' => '',
        'charset'  => 'utf8mb4',
    ],

    // Optional payload encryption for stored raw API responses
    'encryption' => [
        'method' => 'aes-256-cbc',
        'key'    => 'CHANGE_THIS_TO_A_RANDOM_32_BYTE_HEX_STRING', // openssl rand -hex 32
    ],
];
