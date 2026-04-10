<?php
// =============================================================================
//  CTI — Nbtscan Module
//  DNS-based NetBIOS detection. Resolves IP via reverse DNS, probes common
//  NetBIOS-related ports (137, 139, 445) using fsockopen.
//  Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class NbtscanModule extends BaseApiModule
{
    private const API_ID   = 'nbtscan';
    private const API_NAME = 'Nbtscan NetBIOS Scanner';
    private const SUPPORTED = ['ip'];

    private const NETBIOS_PORTS = [
        137 => 'NetBIOS Name Service',
        139 => 'NetBIOS Session Service',
        445 => 'SMB/CIFS',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $ip = trim($queryValue);

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Invalid IP address: {$ip}");
        }

        try {
            // Reverse DNS lookup
            $hostname = @gethostbyaddr($ip);
            $hasReverseDns = ($hostname !== false && $hostname !== $ip);

            // Probe NetBIOS-related ports
            $openPorts = [];
            $closedPorts = [];

            foreach (self::NETBIOS_PORTS as $port => $service) {
                $sock = @fsockopen($ip, $port, $errno, $errstr, 3);
                if ($sock) {
                    $openPorts[$port] = $service;
                    fclose($sock);
                } else {
                    $closedPorts[$port] = $service;
                }
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $openCount = count($openPorts);

            $score = 0;
            $findings = [];

            if ($hasReverseDns) {
                $findings[] = "Reverse DNS: {$hostname}";
            } else {
                $findings[] = 'No reverse DNS record';
            }

            if ($openCount > 0) {
                $portList = [];
                foreach ($openPorts as $port => $service) {
                    $portList[] = "{$port}/{$service}";
                }
                $portListStr = implode(', ', $portList);
                $findings[] = "Open NetBIOS ports: {$portListStr}";

                // SMB/NetBIOS exposure is significant
                if (isset($openPorts[445])) {
                    $score = max($score, 70); // SMB exposed
                }
                if (isset($openPorts[139])) {
                    $score = max($score, 60); // NetBIOS Session
                }
                if (isset($openPorts[137])) {
                    $score = max($score, 55); // NetBIOS Name
                }
            } else {
                $findings[] = 'No NetBIOS ports open';
            }

            $severity = OsintResult::scoreToSeverity($score);

            $resultTags = [self::API_ID, 'ip', 'netbios'];
            if ($openCount > 0) {
                $resultTags[] = 'smb_exposed';
            }
            if ($hasReverseDns) {
                $resultTags[] = 'reverse_dns';
            }

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: 75,
                responseMs: $ms,
                summary: implode('. ', $findings) . '.',
                tags: array_values(array_unique($resultTags)),
                rawData: [
                    'ip' => $ip,
                    'hostname' => $hasReverseDns ? $hostname : null,
                    'open_ports' => $openPorts,
                    'closed_ports' => $closedPorts,
                ],
                success: true
            );
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
