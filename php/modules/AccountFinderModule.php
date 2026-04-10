<?php
// =============================================================================
//  CTI — Account Finder Module
//  Checks common platforms for username accounts by trying profile URLs.
//  Supports: username
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/BaseApiModule.php';

class AccountFinderModule extends BaseApiModule
{
    private const API_ID   = 'account-finder';
    private const API_NAME = 'Account Finder';
    private const SUPPORTED = ['username'];

    /** Platforms to check: name => URL template ({username} placeholder) */
    private const PLATFORMS = [
        'GitHub'    => 'https://github.com/{username}',
        'Twitter/X' => 'https://x.com/{username}',
        'Instagram' => 'https://www.instagram.com/{username}/',
        'Reddit'    => 'https://www.reddit.com/user/{username}',
        'TikTok'    => 'https://www.tiktok.com/@{username}',
        'LinkedIn'  => 'https://www.linkedin.com/in/{username}',
        'Pinterest' => 'https://www.pinterest.com/{username}/',
        'YouTube'   => 'https://www.youtube.com/@{username}',
        'Twitch'    => 'https://www.twitch.tv/{username}',
        'Medium'    => 'https://medium.com/@{username}',
        'GitLab'    => 'https://gitlab.com/{username}',
        'Keybase'   => 'https://keybase.io/{username}',
        'HackerOne' => 'https://hackerone.com/{username}',
        'Steam'     => 'https://steamcommunity.com/id/{username}',
        'Flickr'    => 'https://www.flickr.com/people/{username}/',
    ];

    /** Maximum wall-clock seconds for the entire batch of requests. */
    private const TIME_BUDGET = 25;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $username = trim($queryValue);
        $isGeneric = GlobalSettings::isGenericUsername($username);

        if (empty($username)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Empty username provided');
        }

        $found    = [];
        $notFound = [];
        $errors   = [];

        // --- Build all curl handles and add to multi handle ---
        $mh      = curl_multi_init();
        $handles = []; // platform => ['ch' => resource, 'url' => string]

        $requestTimeout = max(2, min(15, GlobalSettings::httpTimeout()));
        $connectTimeout = max(1, min(5, (int)floor($requestTimeout / 2)));
        $dnsResolver = trim(GlobalSettings::dnsResolver());
        $proxyType = GlobalSettings::socksType();
        $proxyHost = trim(GlobalSettings::socksHost());
        $proxyPort = GlobalSettings::socksPort();
        $proxyUser = trim(GlobalSettings::get('socks_username'));
        $proxyPass = GlobalSettings::get('socks_password');

        foreach (self::PLATFORMS as $platform => $urlTemplate) {
            $url = str_replace('{username}', urlencode($username), $urlTemplate);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $requestTimeout,
                CURLOPT_CONNECTTIMEOUT => $connectTimeout,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_NOBODY         => true,  // HEAD request only
                CURLOPT_USERAGENT      => HttpClient::currentUserAgentForRequest(),
            ]);

            if ($dnsResolver !== '') {
                @curl_setopt($ch, CURLOPT_DNS_SERVERS, $dnsResolver);
            }

            if ($proxyHost !== '' && $proxyPort > 0) {
                curl_setopt($ch, CURLOPT_PROXY, $proxyHost . ':' . $proxyPort);

                if ($proxyType === 'TOR' || $proxyType === '5') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                } elseif ($proxyType === '4') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4);
                } elseif ($proxyType === 'HTTP') {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
                } else {
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                }

                if ($proxyUser !== '') {
                    curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyUser . ':' . $proxyPass);
                }
            }

            curl_multi_add_handle($mh, $ch);
            $handles[$platform] = ['ch' => $ch, 'url' => $url];
        }

        // --- Execute all requests in parallel with a time budget ---
        $active = null;
        do {
            $status = curl_multi_exec($mh, $active);
            if ($active > 0) {
                // Wait up to 200 ms for network activity before polling again
                curl_multi_select($mh, 0.2);
            }
            // Abort if we have exceeded the time budget
            if ((microtime(true) - $start) >= self::TIME_BUDGET) {
                break;
            }
        } while ($active > 0 && $status === CURLM_OK);

        // --- Collect results ---
        foreach ($handles as $platform => $info) {
            $ch  = $info['ch'];
            $url = $info['url'];

            $curlErrno = curl_errno($ch);
            $httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);

            if ($curlErrno !== 0 || $httpCode === 0) {
                $errors[] = $platform;
                continue;
            }

            // 200 or 30x = likely exists, 404 = not found
            if ($httpCode >= 200 && $httpCode < 400) {
                $found[] = ['platform' => $platform, 'url' => $url, 'status' => $httpCode];
            } else {
                $notFound[] = $platform;
            }
        }

        curl_multi_close($mh);

        $ms = (int)((microtime(true) - $start) * 1000);

        $foundCount   = count($found);
        $totalChecked = count(self::PLATFORMS);

        if ($foundCount === 0) {
            $tags = [self::API_ID, 'username', 'not_found'];
            if ($isGeneric) {
                $tags[] = 'generic_username';
            }

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: $isGeneric ? 35 : 50,
                responseMs: $ms,
                summary: "Username '{$username}': No accounts found on {$totalChecked} platforms checked."
                    . ($isGeneric ? ' Note: username is classified as generic.' : ''),
                tags: $tags,
                rawData: ['found' => [], 'checked' => $totalChecked, 'errors' => $errors],
                success: true
            );
        }

        $platformNames = array_map(function($f) { return $f['platform']; }, $found);
        $parts = ["Username '{$username}': Found on {$foundCount}/{$totalChecked} platforms"];
        $parts[] = "Platforms: " . implode(', ', $platformNames);

        $score      = $isGeneric ? 2 : 5;
        $severity   = 'info';
        $confidence = $isGeneric ? 40 : 60; // HEAD requests can have false positives
        $tags = [self::API_ID, 'username', 'accounts_found'];
        if ($isGeneric) {
            $tags[] = 'generic_username';
            $parts[] = 'Generic username detected (confidence reduced)';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'found' => $found,
                'found_count' => $foundCount,
                'not_found' => $notFound,
                'errors' => $errors,
                'checked' => $totalChecked,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://github.com', [], 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
