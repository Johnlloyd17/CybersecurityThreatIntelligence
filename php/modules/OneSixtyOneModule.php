<?php
// =============================================================================
//  CTI — OneSixtyOne Module
//  SNMP community string checker. Tries connecting to UDP port 161
//  with common community strings to detect open SNMP services.
//  Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OneSixtyOneModule extends BaseApiModule
{
    private const API_ID   = 'onesixtyone';
    private const API_NAME = 'OneSixtyOne SNMP Scanner';
    private const SUPPORTED = ['ip'];

    private const COMMUNITY_STRINGS = [
        'public',
        'private',
        'community',
        'manager',
        'admin',
        'default',
        'snmp',
        'monitor',
        'read',
        'write',
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
            $snmpPort = 161;
            $portOpen = false;
            $respondingStrings = [];
            $findings = [];

            // First, check if UDP port 161 is reachable
            // Use stream_socket_client for UDP
            $udpTarget = "udp://{$ip}:{$snmpPort}";
            $sock = @stream_socket_client($udpTarget, $errno, $errstr, 3);

            if ($sock) {
                $portOpen = true;
                stream_set_timeout($sock, 3);

                // Try each community string by sending SNMP v1 GetRequest
                foreach (self::COMMUNITY_STRINGS as $community) {
                    $packet = $this->buildSnmpGetRequest($community);
                    @fwrite($sock, $packet);

                    // Brief wait for response
                    $read = @fread($sock, 1024);
                    if ($read && strlen($read) > 0) {
                        $respondingStrings[] = $community;
                    }
                }

                fclose($sock);
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $respondCount = count($respondingStrings);

            if (!$portOpen) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 60,
                    responseMs: $ms,
                    summary: "SNMP port (UDP/161) appears closed or filtered on {$ip}.",
                    tags: [self::API_ID, 'ip', 'snmp', 'closed'],
                    rawData: [
                        'ip' => $ip,
                        'port' => $snmpPort,
                        'port_open' => false,
                        'responding_communities' => [],
                    ],
                    success: true
                );
            }

            $score = 30; // Port is open
            $findings[] = "SNMP port (UDP/161) is open on {$ip}";

            if ($respondCount > 0) {
                $score = 70; // SNMP responding with default community strings
                $stringList = implode(', ', $respondingStrings);
                $findings[] = "Responding community strings: {$stringList}";

                if (in_array('public', $respondingStrings, true) || in_array('private', $respondingStrings, true)) {
                    $score = 85; // Default community strings = critical
                    $findings[] = 'Default community strings accepted (critical risk)';
                }
            } else {
                $findings[] = 'SNMP port open but no default community strings accepted';
            }

            $severity = OsintResult::scoreToSeverity($score);
            $resultTags = [self::API_ID, 'ip', 'snmp'];
            if ($portOpen) {
                $resultTags[] = 'snmp_open';
            }
            if ($respondCount > 0) {
                $resultTags[] = 'default_community';
            }

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: 70,
                responseMs: $ms,
                summary: implode('. ', $findings) . '.',
                tags: array_values(array_unique($resultTags)),
                rawData: [
                    'ip' => $ip,
                    'port' => $snmpPort,
                    'port_open' => $portOpen,
                    'responding_communities' => $respondingStrings,
                    'tested_communities' => self::COMMUNITY_STRINGS,
                ],
                success: true
            );
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    /**
     * Build a minimal SNMP v1 GetRequest packet for a given community string.
     * This is a simplified BER/ASN.1 encoded SNMP GET for sysDescr.0 (1.3.6.1.2.1.1.1.0).
     */
    private function buildSnmpGetRequest(string $community): string
    {
        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        $oid = "\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00";
        // Null value
        $null = "\x05\x00";
        // VarBind
        $varBind = "\x30" . chr(strlen($oid) + strlen($null)) . $oid . $null;
        // VarBindList
        $varBindList = "\x30" . chr(strlen($varBind)) . $varBind;
        // Request ID
        $requestId = "\x02\x01\x01";
        // Error Status
        $errorStatus = "\x02\x01\x00";
        // Error Index
        $errorIndex = "\x02\x01\x00";
        // PDU (GetRequest = 0xA0)
        $pduContent = $requestId . $errorStatus . $errorIndex . $varBindList;
        $pdu = "\xa0" . chr(strlen($pduContent)) . $pduContent;
        // Version (SNMPv1 = 0)
        $version = "\x02\x01\x00";
        // Community string
        $communityEncoded = "\x04" . chr(strlen($community)) . $community;
        // Full SNMP message
        $messageContent = $version . $communityEncoded . $pdu;
        $message = "\x30" . chr(strlen($messageContent)) . $messageContent;

        return $message;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
