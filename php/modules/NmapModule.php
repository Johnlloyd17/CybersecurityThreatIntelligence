<?php
// =============================================================================
//  CTI — Nmap Module (Expanded)
//  Full TCP port scanner with banner grabbing, service fingerprinting,
//  and configurable port ranges. PHP-based using fsockopen().
//  Supports: ip, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class NmapModule extends BaseApiModule
{
    private const API_ID   = 'nmap';
    private const API_NAME = 'Nmap Port Scanner';
    private const SUPPORTED = ['ip', 'domain'];

    // Full service mapping: port => [service, protocol]
    private const PORT_MAP = [
        20 => 'FTP-Data', 21 => 'FTP', 22 => 'SSH', 23 => 'Telnet',
        25 => 'SMTP', 53 => 'DNS', 69 => 'TFTP', 80 => 'HTTP',
        81 => 'HTTP-Alt', 88 => 'Kerberos', 110 => 'POP3', 111 => 'RPCbind',
        119 => 'NNTP', 123 => 'NTP', 135 => 'MSRPC', 137 => 'NetBIOS-NS',
        138 => 'NetBIOS-DGM', 139 => 'NetBIOS-SSN', 143 => 'IMAP',
        161 => 'SNMP', 162 => 'SNMP-Trap', 179 => 'BGP', 389 => 'LDAP',
        443 => 'HTTPS', 445 => 'SMB', 465 => 'SMTPS', 500 => 'ISAKMP',
        514 => 'Syslog', 515 => 'LPD', 520 => 'RIP', 523 => 'IBM-DB2',
        554 => 'RTSP', 587 => 'Submission', 623 => 'IPMI', 636 => 'LDAPS',
        873 => 'Rsync', 902 => 'VMware', 993 => 'IMAPS', 995 => 'POP3S',
        1080 => 'SOCKS', 1099 => 'RMI', 1433 => 'MSSQL', 1434 => 'MSSQL-UDP',
        1521 => 'Oracle', 1723 => 'PPTP', 1883 => 'MQTT', 2049 => 'NFS',
        2181 => 'ZooKeeper', 2222 => 'SSH-Alt', 2375 => 'Docker',
        2376 => 'Docker-TLS', 3000 => 'Grafana/Dev', 3306 => 'MySQL',
        3389 => 'RDP', 3690 => 'SVN', 4443 => 'HTTPS-Alt', 4444 => 'Metasploit',
        4848 => 'GlassFish', 5000 => 'UPnP/Flask', 5432 => 'PostgreSQL',
        5555 => 'ADB', 5672 => 'AMQP', 5900 => 'VNC', 5901 => 'VNC-1',
        5984 => 'CouchDB', 5985 => 'WinRM-HTTP', 5986 => 'WinRM-HTTPS',
        6379 => 'Redis', 6443 => 'K8s-API', 6660 => 'IRC',
        6667 => 'IRC', 7001 => 'WebLogic', 7077 => 'Spark',
        8000 => 'HTTP-Alt', 8008 => 'HTTP-Alt', 8080 => 'HTTP-Proxy',
        8081 => 'HTTP-Alt', 8088 => 'HTTP-Alt', 8443 => 'HTTPS-Alt',
        8500 => 'Consul', 8834 => 'Nessus', 8888 => 'HTTP-Alt',
        9000 => 'SonarQube', 9090 => 'Prometheus', 9091 => 'Transmission',
        9092 => 'Kafka', 9200 => 'Elasticsearch', 9300 => 'Elasticsearch-Transport',
        9418 => 'Git', 9999 => 'Aastra', 10000 => 'Webmin',
        10250 => 'Kubelet', 10443 => 'HTTPS-Alt', 11211 => 'Memcached',
        11300 => 'Beanstalkd', 15672 => 'RabbitMQ-Mgmt', 17000 => 'Hashi-Consul',
        27017 => 'MongoDB', 27018 => 'MongoDB', 28017 => 'MongoDB-Web',
        50000 => 'SAP', 50070 => 'Hadoop', 61616 => 'ActiveMQ',
    ];

    // Risk classification
    private const HIGH_RISK_PORTS = [
        21, 23, 69, 111, 135, 137, 138, 139, 161, 445, 512, 513, 514,
        523, 623, 1099, 1434, 1723, 2049, 2375, 3306, 3389, 4444,
        5432, 5555, 5900, 5984, 6379, 6660, 6667, 9200, 10250,
        11211, 27017, 50000,
    ];

    private const MEDIUM_RISK_PORTS = [
        22, 25, 53, 80, 88, 110, 143, 389, 636, 873, 902, 1433,
        1521, 1883, 2181, 3000, 3690, 5672, 7001, 8080, 8443,
        8500, 8834, 9000, 9090, 9092, 9418, 10000, 15672,
    ];

    // Service fingerprint patterns: regex => service name
    private const BANNER_FINGERPRINTS = [
        '/^SSH-(\d+\.\d+)-(.+)/i'                  => 'SSH',
        '/^220.*FTP/i'                               => 'FTP',
        '/^220.*SMTP|^EHLO|^250/i'                   => 'SMTP',
        '/^\+OK.*POP3/i'                             => 'POP3',
        '/^\* OK.*IMAP/i'                            => 'IMAP',
        '/^HTTP\/[\d.]+\s+\d+/i'                     => 'HTTP',
        '/MySQL|MariaDB/i'                            => 'MySQL',
        '/PostgreSQL/i'                               => 'PostgreSQL',
        '/^Redis/i'                                   => 'Redis',
        '/MongoDB/i'                                  => 'MongoDB',
        '/^RFB\s+(\d+\.\d+)/i'                       => 'VNC',
        '/Microsoft.*Terminal Services/i'             => 'RDP',
        '/^AMQP/i'                                    => 'AMQP',
        '/Elasticsearch|lucene/i'                     => 'Elasticsearch',
        '/memcached/i'                                => 'Memcached',
        '/^-ERR.*Redis|NOAUTH/i'                      => 'Redis',
        '/Apache|nginx|IIS|LiteSpeed|Caddy/i'        => 'HTTP Server',
        '/OpenSSH/i'                                  => 'OpenSSH',
        '/ProFTPD|vsftpd|Pure-FTPd|FileZilla/i'      => 'FTP',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start  = microtime(true);
        $target = trim($queryValue);

        // Get port list from settings or use full map
        $portsToScan = $this->getPortList();
        $timeout = max(1, min(5, (int)($this->timeoutSeconds() / count($portsToScan) * 10)));

        try {
            $openPorts     = [];
            $closedPorts   = [];
            $filteredPorts = [];
            $services      = [];
            $banners       = [];

            foreach ($portsToScan as $port) {
                $sock = @fsockopen($target, $port, $errno, $errstr, $timeout);
                if ($sock) {
                    $serviceName = self::PORT_MAP[$port] ?? "unknown-{$port}";
                    stream_set_timeout($sock, 3);

                    // Banner grabbing with service-specific probes
                    $banner = $this->grabBanner($sock, $port);
                    $fingerprint = $this->fingerprint($banner, $port);

                    $portInfo = [
                        'port'    => $port,
                        'state'   => 'open',
                        'service' => $fingerprint['service'] ?: $serviceName,
                    ];
                    if ($fingerprint['version']) {
                        $portInfo['version'] = $fingerprint['version'];
                    }
                    if ($banner) {
                        $clean = trim(preg_replace('/[\x00-\x1F\x7F]/', '', substr($banner, 0, 120)));
                        if ($clean) {
                            $portInfo['banner'] = $clean;
                            $banners[$port] = $clean;
                        }
                    }

                    $openPorts[$port] = $portInfo;
                    $services[$fingerprint['service'] ?: $serviceName] = $fingerprint['version'] ?: '';

                    fclose($sock);
                } else {
                    if ($errno === 111 || $errno === 10061) {
                        $closedPorts[] = $port;
                    } else {
                        $filteredPorts[] = $port;
                    }
                }
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $openCount = count($openPorts);
            $totalScanned = count($portsToScan);

            // Risk scoring
            $score = 0;
            $highRiskOpen   = [];
            $mediumRiskOpen = [];

            foreach ($openPorts as $port => $info) {
                if (in_array($port, self::HIGH_RISK_PORTS, true)) {
                    $highRiskOpen[] = $port;
                } elseif (in_array($port, self::MEDIUM_RISK_PORTS, true)) {
                    $mediumRiskOpen[] = $port;
                }
            }

            // Scoring logic
            if (!empty($highRiskOpen)) {
                $score = max($score, 60 + count($highRiskOpen) * 5);
            }
            if (!empty($mediumRiskOpen)) {
                $score = max($score, 30 + count($mediumRiskOpen) * 3);
            }
            if ($openCount > 20) $score = max($score, 70);
            elseif ($openCount > 10) $score = max($score, 50);
            elseif ($openCount > 5) $score = max($score, 30);
            $score = min($score, 95);

            $severity = OsintResult::scoreToSeverity($score);

            // Build summary
            $summaryParts = [];
            $summaryParts[] = "{$openCount}/{$totalScanned} ports open on {$target}";

            if (!empty($highRiskOpen)) {
                $summaryParts[] = "High-risk: " . implode(', ', $highRiskOpen);
            }

            // Service summary
            if (!empty($services)) {
                $svcList = [];
                foreach (array_slice($services, 0, 8, true) as $svc => $ver) {
                    $svcList[] = $ver ? "{$svc}/{$ver}" : $svc;
                }
                $summaryParts[] = "Services: " . implode(', ', $svcList);
            }

            $resultTags = [self::API_ID, $queryType, 'port_scan'];
            if (!empty($highRiskOpen)) $resultTags[] = 'high_risk_ports';
            if ($openCount === 0) $resultTags[] = 'no_open_ports';
            if (!empty($banners)) $resultTags[] = 'banners_detected';

            $result = new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: 85,
                responseMs: $ms,
                summary: implode('. ', $summaryParts) . '.',
                tags: array_values(array_unique($resultTags)),
                rawData: [
                    'target'         => $target,
                    'total_scanned'  => $totalScanned,
                    'open_count'     => $openCount,
                    'closed_count'   => count($closedPorts),
                    'filtered_count' => count($filteredPorts),
                    'open_ports'     => array_values($openPorts),
                    'services'       => $services,
                    'high_risk_open' => $highRiskOpen,
                    'medium_risk_open' => $mediumRiskOpen,
                ],
                success: true
            );

            return $result;
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    private function getPortList(): array
    {
        $userPorts = $this->tcpPorts();
        if ($userPorts) {
            $parsed = array_filter(array_map('intval', explode(',', $userPorts)));
            if (!empty($parsed)) return $parsed;
        }
        return array_keys(self::PORT_MAP);
    }

    private function grabBanner($sock, int $port): string
    {
        // Some services need a probe to respond
        $probes = [
            80   => "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443  => "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8080 => "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8443 => "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            25   => '',  // SMTP sends banner on connect
            110  => '',  // POP3 sends banner
            143  => '',  // IMAP sends banner
            21   => '',  // FTP sends banner
        ];

        // First try passive read (services that send banners on connect)
        $banner = @fread($sock, 512);
        if ($banner && strlen(trim($banner)) > 2) {
            return $banner;
        }

        // If no passive banner, try active probe
        if (isset($probes[$port]) && $probes[$port] !== '') {
            @fwrite($sock, $probes[$port]);
            $banner = @fread($sock, 1024);
        }

        return $banner ?: '';
    }

    private function fingerprint(string $banner, int $port): array
    {
        $result = ['service' => '', 'version' => ''];
        if (!$banner) return $result;

        $banner = trim($banner);

        foreach (self::BANNER_FINGERPRINTS as $pattern => $service) {
            if (preg_match($pattern, $banner, $m)) {
                $result['service'] = $service;
                // Extract version if captured
                if (isset($m[2])) {
                    $result['version'] = trim($m[2]);
                } elseif (isset($m[1])) {
                    $result['version'] = trim($m[1]);
                }
                break;
            }
        }

        // Try to extract version from generic patterns
        if (!$result['version'] && preg_match('/(\d+\.\d+(?:\.\d+)?(?:[._-][\w.]+)?)/', $banner, $m)) {
            $result['version'] = $m[1];
        }

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null, 'ports_mapped' => count(self::PORT_MAP)];
    }
}
