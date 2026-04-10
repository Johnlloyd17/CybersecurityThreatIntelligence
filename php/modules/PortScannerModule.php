<?php
// =============================================================================
//  CTI — TCP Port Scanner Module (Expanded)
//  100+ port coverage with banner grabbing, service fingerprinting,
//  risk categorization, and configurable port lists.
//  Supports: ip, domain
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PortScannerModule extends BaseApiModule
{
    private const API_ID   = 'port-scanner-tcp';
    private const API_NAME = 'TCP Port Scanner';
    private const SUPPORTED = ['ip', 'domain'];

    // 100+ ports organized by category
    private const PORT_MAP = [
        // ── Standard Services ─────────────────────────────────────────
        20   => 'FTP-Data',       21   => 'FTP',          22   => 'SSH',
        23   => 'Telnet',         25   => 'SMTP',         53   => 'DNS',
        67   => 'DHCP',           69   => 'TFTP',         80   => 'HTTP',
        110  => 'POP3',           111  => 'RPCbind',      119  => 'NNTP',
        123  => 'NTP',            135  => 'MSRPC',        137  => 'NetBIOS-NS',
        139  => 'NetBIOS-SSN',    143  => 'IMAP',         161  => 'SNMP',
        162  => 'SNMP-Trap',      179  => 'BGP',          389  => 'LDAP',
        443  => 'HTTPS',          445  => 'SMB',          465  => 'SMTPS',
        500  => 'IKE',            514  => 'Syslog',       515  => 'LPD',
        520  => 'RIP',            523  => 'DB2',          548  => 'AFP',
        554  => 'RTSP',           587  => 'SMTP-Sub',     593  => 'HTTP-RPC',
        631  => 'IPP/CUPS',       636  => 'LDAPS',        873  => 'rsync',
        902  => 'VMware',         993  => 'IMAPS',        995  => 'POP3S',
        // ── Database ──────────────────────────────────────────────────
        1433 => 'MSSQL',          1434 => 'MSSQL-UDP',    1521 => 'Oracle',
        1883 => 'MQTT',           2049 => 'NFS',          3306 => 'MySQL',
        5432 => 'PostgreSQL',     5984 => 'CouchDB',      6379 => 'Redis',
        7474 => 'Neo4j',          8529 => 'ArangoDB',     9042 => 'Cassandra',
        9200 => 'Elasticsearch',  11211 => 'Memcached',   27017 => 'MongoDB',
        28017 => 'MongoDB-Web',
        // ── Remote Access ─────────────────────────────────────────────
        3389 => 'RDP',            5900 => 'VNC',          5901 => 'VNC-1',
        5902 => 'VNC-2',          2222 => 'SSH-Alt',      4243 => 'Docker-API',
        // ── Web / Proxy ───────────────────────────────────────────────
        8080 => 'HTTP-Proxy',     8081 => 'HTTP-Alt',     8443 => 'HTTPS-Alt',
        8888 => 'HTTP-Alt-2',     3000 => 'Grafana/Dev',  3128 => 'Squid',
        4443 => 'Pharos',         5000 => 'Flask/Docker',
        8000 => 'Django/Alt',     8008 => 'HTTP-Alt-3',   9090 => 'Cockpit/Prometheus',
        9443 => 'HTTPS-Alt-2',    10000 => 'Webmin',
        // ── Messaging / Queue ─────────────────────────────────────────
        1883 => 'MQTT',           4369 => 'EPMD',         5044 => 'Logstash',
        5222 => 'XMPP',          5269 => 'XMPP-S2S',     5672 => 'AMQP',
        6660 => 'IRC',            6667 => 'IRC',          6697 => 'IRC-SSL',
        9092 => 'Kafka',          15672 => 'RabbitMQ-Mgmt',
        // ── Monitoring / Management ───────────────────────────────────
        161  => 'SNMP',           199  => 'SNMP-Mux',     1099 => 'Java-RMI',
        2181 => 'ZooKeeper',      2379 => 'etcd',         2380 => 'etcd-peer',
        4848 => 'GlassFish',      7077 => 'Spark',        8009 => 'AJP',
        8161 => 'ActiveMQ',       8500 => 'Consul',       9100 => 'JetDirect',
        9300 => 'ES-Transport',   50070 => 'HDFS',
        // ── IoT / Industrial ──────────────────────────────────────────
        502  => 'Modbus',         1911 => 'Niagara-Fox',  2404 => 'IEC-104',
        4840 => 'OPC-UA',         20000 => 'DNP3',        47808 => 'BACnet',
    ];

    // Risk classification
    private const RISK_MAP = [
        // Critical (publicly exposed = major risk)
        23    => ['risk' => 'critical', 'reason' => 'Telnet — cleartext credentials'],
        445   => ['risk' => 'critical', 'reason' => 'SMB — EternalBlue/ransomware vector'],
        3389  => ['risk' => 'high',     'reason' => 'RDP — BlueKeep/brute force target'],
        135   => ['risk' => 'high',     'reason' => 'MSRPC — remote exploitation'],
        139   => ['risk' => 'high',     'reason' => 'NetBIOS — information leak'],
        // Database (should never be public)
        1433  => ['risk' => 'high',     'reason' => 'MSSQL exposed to internet'],
        3306  => ['risk' => 'high',     'reason' => 'MySQL exposed to internet'],
        5432  => ['risk' => 'high',     'reason' => 'PostgreSQL exposed to internet'],
        1521  => ['risk' => 'high',     'reason' => 'Oracle DB exposed to internet'],
        6379  => ['risk' => 'critical', 'reason' => 'Redis — often unauthenticated'],
        27017 => ['risk' => 'critical', 'reason' => 'MongoDB — often unauthenticated'],
        9200  => ['risk' => 'high',     'reason' => 'Elasticsearch — data exposure'],
        11211 => ['risk' => 'high',     'reason' => 'Memcached — amplification/data leak'],
        5984  => ['risk' => 'high',     'reason' => 'CouchDB — REST API exposed'],
        // Management
        4243  => ['risk' => 'critical', 'reason' => 'Docker API — full host compromise'],
        2379  => ['risk' => 'high',     'reason' => 'etcd — secrets exposure'],
        8500  => ['risk' => 'high',     'reason' => 'Consul — service mesh control'],
        10000 => ['risk' => 'high',     'reason' => 'Webmin — admin interface'],
        1099  => ['risk' => 'high',     'reason' => 'Java RMI — deserialization attacks'],
        8009  => ['risk' => 'high',     'reason' => 'AJP — Ghostcat vulnerability'],
        5900  => ['risk' => 'high',     'reason' => 'VNC — remote desktop exposed'],
        // IoT / ICS
        502   => ['risk' => 'critical', 'reason' => 'Modbus — industrial control, no auth'],
        47808 => ['risk' => 'critical', 'reason' => 'BACnet — building automation exposed'],
        2404  => ['risk' => 'critical', 'reason' => 'IEC-104 — SCADA protocol exposed'],
        // Moderate
        25    => ['risk' => 'medium',   'reason' => 'SMTP — open relay check needed'],
        53    => ['risk' => 'medium',   'reason' => 'DNS — zone transfer/amplification'],
        111   => ['risk' => 'medium',   'reason' => 'RPCbind — service enumeration'],
        161   => ['risk' => 'medium',   'reason' => 'SNMP — community string exposure'],
        389   => ['risk' => 'medium',   'reason' => 'LDAP — directory information leak'],
        873   => ['risk' => 'medium',   'reason' => 'rsync — data exfiltration'],
        5672  => ['risk' => 'medium',   'reason' => 'AMQP — message queue exposed'],
        15672 => ['risk' => 'medium',   'reason' => 'RabbitMQ management console'],
    ];

    // Banner probes for service identification
    private const BANNER_PROBES = [
        22   => '',                                     // SSH sends banner first
        21   => '',                                     // FTP sends banner first
        25   => "EHLO scanner.local\r\n",
        80   => "HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
        110  => '',                                     // POP3 sends banner first
        143  => '',                                     // IMAP sends banner first
        443  => '',
        3306 => '',                                     // MySQL sends greeting
        6379 => "PING\r\n",                             // Redis PING
        11211 => "version\r\n",                         // Memcached
        27017 => '',                                    // MongoDB
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $host = trim($queryValue);

        // Configurable port list
        $customPorts = $this->tcpPorts();
        $portsToScan = !empty($customPorts) ? $customPorts : array_keys(self::PORT_MAP);
        $timeout = max(1, min(5, $this->int('connect_timeout', 2)));

        $openPorts     = [];
        $closedPorts   = [];
        $banners       = [];
        $riskFindings  = [];

        foreach ($portsToScan as $port) {
            $port = (int)$port;
            $conn = @fsockopen($host, $port, $errno, $errstr, $timeout);

            if ($conn) {
                $service = self::PORT_MAP[$port] ?? "port-{$port}";
                $openPorts[$port] = $service;

                // Banner grab
                $banner = $this->grabBanner($conn, $host, $port);
                if ($banner) {
                    $banners[$port] = $banner;
                    // Try to fingerprint
                    $fp = $this->fingerprint($banner, $port);
                    if ($fp) $openPorts[$port] = $fp;
                }

                fclose($conn);

                // Risk assessment
                if (isset(self::RISK_MAP[$port])) {
                    $riskFindings[] = array_merge(
                        self::RISK_MAP[$port],
                        ['port' => $port, 'service' => $openPorts[$port], 'banner' => $banners[$port] ?? null]
                    );
                }
            } else {
                $closedPorts[] = $port;
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);
        $openCount = count($openPorts);
        $totalScanned = count($portsToScan);

        if ($openCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 70,
                responseMs: $ms,
                summary: "Host {$host}: No open ports detected among {$totalScanned} ports scanned.",
                tags: [self::API_ID, $queryType, 'no_open_ports', 'clean'],
                rawData: ['open_ports' => [], 'closed_count' => count($closedPorts), 'total_scanned' => $totalScanned],
                success: true
            );
        }

        // ── Scoring ──────────────────────────────────────────────────────
        $score = 0;
        $riskScoreMap = ['critical' => 85, 'high' => 65, 'medium' => 40, 'low' => 15];

        foreach ($riskFindings as $rf) {
            $riskScore = $riskScoreMap[$rf['risk']] ?? 20;
            $score = max($score, $riskScore);
        }

        // Additional score for sheer number of open ports
        if ($openCount > 20) $score = max($score, 50);
        elseif ($openCount > 10) $score = max($score, 30);

        // Boost for multiple risky ports
        $score = min(95, $score + max(0, (count($riskFindings) - 1)) * 5);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 70 + count($riskFindings) * 3);

        // ── Summary ──────────────────────────────────────────────────────
        $portList = [];
        foreach ($openPorts as $p => $svc) {
            $portList[] = "{$p}/{$svc}";
        }

        $summaryParts = ["Host {$host}: {$openCount} open port(s) of {$totalScanned} scanned"];
        $summaryParts[] = "Open: " . implode(', ', array_slice($portList, 0, 15));

        if (!empty($riskFindings)) {
            $byCrit = array_filter($riskFindings, fn($r) => $r['risk'] === 'critical');
            $byHigh = array_filter($riskFindings, fn($r) => $r['risk'] === 'high');
            $byMed  = array_filter($riskFindings, fn($r) => $r['risk'] === 'medium');
            $riskSummary = [];
            if ($byCrit) $riskSummary[] = count($byCrit) . " critical";
            if ($byHigh) $riskSummary[] = count($byHigh) . " high";
            if ($byMed)  $riskSummary[] = count($byMed) . " medium";
            $summaryParts[] = "Risk findings: " . implode(', ', $riskSummary);

            // Top risk details
            foreach (array_slice($riskFindings, 0, 3) as $rf) {
                $summaryParts[] = "Port {$rf['port']}: {$rf['reason']}";
            }
        }

        // ── Categorize open ports ────────────────────────────────────────
        $categories = [];
        $catMap = [
            'web'        => [80, 443, 8080, 8081, 8443, 8888, 3000, 5000, 8000, 8008, 9090, 9443, 10000],
            'database'   => [1433, 1434, 1521, 3306, 5432, 5984, 6379, 7474, 8529, 9042, 9200, 11211, 27017, 28017],
            'mail'       => [25, 110, 143, 465, 587, 993, 995],
            'remote'     => [22, 23, 2222, 3389, 5900, 5901, 5902],
            'file'       => [20, 21, 69, 139, 445, 873, 2049],
            'directory'  => [389, 636],
            'messaging'  => [1883, 5222, 5269, 5672, 6660, 6667, 6697, 9092, 15672],
            'management' => [135, 161, 1099, 2181, 2379, 2380, 4243, 4848, 8009, 8161, 8500, 9100, 50070],
            'ics_iot'    => [502, 1911, 2404, 4840, 20000, 47808],
        ];
        foreach ($catMap as $cat => $ports) {
            $found = array_intersect(array_keys($openPorts), $ports);
            if (!empty($found)) $categories[$cat] = count($found);
        }

        $tags = [self::API_ID, $queryType, 'port_scan'];
        if (!empty($riskFindings)) $tags[] = 'risky_ports';
        if (isset($categories['database'])) $tags[] = 'exposed_database';
        if (isset($categories['ics_iot']))   $tags[] = 'exposed_ics';
        if ($score === 0) $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: implode('. ', array_slice($summaryParts, 0, 6)) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'open_ports'      => $openPorts,
                'open_count'      => $openCount,
                'closed_count'    => count($closedPorts),
                'total_scanned'   => $totalScanned,
                'banners'         => $banners,
                'risk_findings'   => $riskFindings,
                'categories'      => $categories,
            ],
            success: true
        );
    }

    private function grabBanner($conn, string $host, int $port): ?string
    {
        stream_set_timeout($conn, 3);

        // Send probe if needed
        $probe = self::BANNER_PROBES[$port] ?? null;
        if ($probe !== null && $probe !== '') {
            $probe = str_replace('{host}', $host, $probe);
            @fwrite($conn, $probe);
        }

        $banner = @fread($conn, 1024);
        if ($banner === false || $banner === '') return null;

        $banner = trim($banner);
        // Sanitize binary content
        if (preg_match('/[\x00-\x08\x0E-\x1F]/', $banner)) {
            $banner = preg_replace('/[\x00-\x08\x0E-\x1F]/', '.', $banner);
        }

        return substr($banner, 0, 256);
    }

    private function fingerprint(string $banner, int $port): ?string
    {
        $patterns = [
            '/^SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)/i'   => 'OpenSSH $1',
            '/^SSH-[\d.]+-dropbear/i'                   => 'Dropbear SSH',
            '/^220.*Microsoft.*FTP/i'                   => 'MS FTP',
            '/^220.*vsftpd\s*([\d.]+)/i'               => 'vsftpd $1',
            '/^220.*ProFTPD\s*([\d.]+)/i'              => 'ProFTPD $1',
            '/^220.*pure-ftpd/i'                        => 'Pure-FTPd',
            '/^220.*Postfix/i'                          => 'Postfix SMTP',
            '/^220.*Exim\s*([\d.]+)/i'                 => 'Exim $1',
            '/^220.*Microsoft.*ESMTP/i'                 => 'MS Exchange SMTP',
            '/^HTTP\/[\d.]+\s+(\d+).*\r?\nServer:\s*([^\r\n]+)/is' => 'HTTP ($2)',
            '/Server:\s*nginx\/([\d.]+)/i'             => 'nginx $1',
            '/Server:\s*Apache\/([\d.]+)/i'            => 'Apache $1',
            '/Server:\s*Microsoft-IIS\/([\d.]+)/i'     => 'IIS $1',
            '/Server:\s*LiteSpeed/i'                    => 'LiteSpeed',
            '/^.\x00\x00\x00\x0a([\d.]+)/s'           => 'MySQL $1',
            '/^\+OK.*Dovecot/i'                         => 'Dovecot POP3',
            '/^\* OK.*Dovecot/i'                        => 'Dovecot IMAP',
            '/^\+PONG/i'                                => 'Redis',
            '/^VERSION\s+([\d.]+)/i'                   => 'Memcached $1',
        ];

        foreach ($patterns as $pattern => $label) {
            if (preg_match($pattern, $banner, $m)) {
                $result = $label;
                for ($i = 1; $i <= 3; $i++) {
                    if (isset($m[$i])) $result = str_replace('$' . $i, $m[$i], $result);
                }
                return $result;
            }
        }
        return null;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $conn = @fsockopen('google.com', 80, $errno, $errstr, 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($conn) {
            fclose($conn);
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null,
                    'ports_in_db' => count(self::PORT_MAP)];
        }
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $errstr];
    }
}
