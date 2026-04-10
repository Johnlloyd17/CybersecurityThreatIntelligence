<?php
// =============================================================================
//  CTI — Etherscan Module
//  API Docs: https://docs.etherscan.io/
//  Auth: apikey query param. Supports: ip (ethereum address)
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class EtherscanModule extends BaseApiModule
{
    private const API_ID   = 'etherscan';
    private const API_NAME = 'Etherscan';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.etherscan.io/api?' . http_build_query([
            'module' => 'account',
            'action' => 'balance',
            'address' => $queryValue,
            'tag' => 'latest',
            'apikey' => $apiKey,
        ]);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $apiStatus = $data['status'] ?? '0';
        $message = $data['message'] ?? '';
        if ($apiStatus === '0' && stripos($message, 'NOTOK') !== false) {
            $errResult = $data['result'] ?? 'API error';
            return OsintResult::error(self::API_ID, self::API_NAME, $errResult, $resp['elapsed_ms']);
        }

        $balanceWei = $data['result'] ?? '0';
        $balanceEth = bcdiv($balanceWei, '1000000000000000000', 8);

        $score = 10;
        $ethFloat = (float)$balanceEth;
        if ($ethFloat > 100) $score = 30;
        elseif ($ethFloat > 10) $score = 20;

        $severity = OsintResult::scoreToSeverity($score);
        $summary = "Address {$queryValue}: Balance: {$balanceEth} ETH.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 90,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, 'blockchain', 'ethereum'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://api.etherscan.io/api?' . http_build_query(['module' => 'account', 'action' => 'balance', 'address' => '0x0000000000000000000000000000000000000000', 'tag' => 'latest', 'apikey' => $apiKey]);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
