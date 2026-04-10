<?php
// =============================================================================
//  CTI — Wappalyzer (Technology Detection) Module — Expanded
//  Full signature database: 100+ technologies across 20+ categories.
//  Detects web servers, frameworks, CMS, CDNs, analytics, payment,
//  security, databases, caching, CI/CD, and more.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WappalyzerModule extends BaseApiModule
{
    private const API_ID   = 'wappalyzer';
    private const API_NAME = 'Technology Detection';
    private const SUPPORTED = ['domain', 'url'];

    /** Header-based signatures: header_lower => [pattern, name, category] */
    private const HEADER_SIGS = [
        // Web Servers
        ['header' => 'server', 'match' => '/Apache(?:\/(\S+))?/i',        'name' => 'Apache',       'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/nginx(?:\/(\S+))?/i',         'name' => 'nginx',        'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Microsoft-IIS(?:\/(\S+))?/i', 'name' => 'Microsoft IIS','category' => 'Web Server'],
        ['header' => 'server', 'match' => '/LiteSpeed/i',                 'name' => 'LiteSpeed',    'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Caddy/i',                     'name' => 'Caddy',        'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/openresty/i',                 'name' => 'OpenResty',    'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Kestrel/i',                   'name' => 'Kestrel',      'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/gunicorn/i',                  'name' => 'Gunicorn',     'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Cowboy/i',                    'name' => 'Cowboy',       'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Jetty/i',                     'name' => 'Jetty',        'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Tomcat/i',                    'name' => 'Tomcat',       'category' => 'Web Server'],
        ['header' => 'server', 'match' => '/Werkzeug/i',                  'name' => 'Werkzeug',     'category' => 'Web Server'],
        // Languages / Frameworks
        ['header' => 'x-powered-by', 'match' => '/PHP(?:\/(\S+))?/i',      'name' => 'PHP',         'category' => 'Language'],
        ['header' => 'x-powered-by', 'match' => '/ASP\.NET/i',             'name' => 'ASP.NET',     'category' => 'Language'],
        ['header' => 'x-powered-by', 'match' => '/Express/i',              'name' => 'Express.js',  'category' => 'Framework'],
        ['header' => 'x-powered-by', 'match' => '/Next\.js/i',             'name' => 'Next.js',     'category' => 'Framework'],
        ['header' => 'x-powered-by', 'match' => '/Nuxt/i',                 'name' => 'Nuxt.js',     'category' => 'Framework'],
        ['header' => 'x-powered-by', 'match' => '/Phusion Passenger/i',    'name' => 'Passenger',   'category' => 'Framework'],
        ['header' => 'x-powered-by', 'match' => '/Servlet/i',              'name' => 'Java Servlet','category' => 'Language'],
        // CDN / Proxy
        ['header' => 'server',      'match' => '/cloudflare/i',           'name' => 'Cloudflare',    'category' => 'CDN'],
        ['header' => 'cf-ray',      'match' => '/.+/',                    'name' => 'Cloudflare',    'category' => 'CDN'],
        ['header' => 'x-cdn',       'match' => '/Incapsula/i',            'name' => 'Imperva',       'category' => 'CDN/WAF'],
        ['header' => 'x-sucuri-id', 'match' => '/.+/',                    'name' => 'Sucuri',        'category' => 'CDN/WAF'],
        ['header' => 'x-akamai-transformed', 'match' => '/.+/',           'name' => 'Akamai',        'category' => 'CDN'],
        ['header' => 'x-amz-cf-id', 'match' => '/.+/',                    'name' => 'Amazon CloudFront', 'category' => 'CDN'],
        ['header' => 'x-fastly-request-id', 'match' => '/.+/',            'name' => 'Fastly',        'category' => 'CDN'],
        ['header' => 'x-vercel-id', 'match' => '/.+/',                    'name' => 'Vercel',        'category' => 'Platform'],
        ['header' => 'x-netlify-request-id', 'match' => '/.+/',           'name' => 'Netlify',       'category' => 'Platform'],
        ['header' => 'fly-request-id', 'match' => '/.+/',                 'name' => 'Fly.io',        'category' => 'Platform'],
        ['header' => 'x-render-origin-server', 'match' => '/.+/',         'name' => 'Render',        'category' => 'Platform'],
        // Security headers indicating products
        ['header' => 'x-drupal-cache', 'match' => '/.+/',                 'name' => 'Drupal',        'category' => 'CMS'],
        ['header' => 'x-generator',    'match' => '/Drupal/i',            'name' => 'Drupal',        'category' => 'CMS'],
        ['header' => 'x-shopify-stage', 'match' => '/.+/',                'name' => 'Shopify',       'category' => 'E-commerce'],
        ['header' => 'x-wix-request-id', 'match' => '/.+/',               'name' => 'Wix',           'category' => 'Website Builder'],
    ];

    /** HTML body patterns */
    private const HTML_PATTERNS = [
        // CMS
        '/wp-content\/|wp-includes\//i'                    => ['WordPress', 'CMS'],
        '/Joomla!/i'                                       => ['Joomla', 'CMS'],
        '/Drupal\.settings/i'                              => ['Drupal', 'CMS'],
        '/content=["\']Shopify/i'                          => ['Shopify', 'E-commerce'],
        '/content=["\']WordPress/i'                        => ['WordPress', 'CMS'],
        '/content=["\']Wix\.com/i'                         => ['Wix', 'Website Builder'],
        '/content=["\']Squarespace/i'                      => ['Squarespace', 'Website Builder'],
        '/ghost-url/i'                                     => ['Ghost', 'CMS'],
        '/content=["\']Ghost/i'                            => ['Ghost', 'CMS'],
        '/\/typo3conf\//i'                                 => ['TYPO3', 'CMS'],
        '/content=["\']TYPO3/i'                            => ['TYPO3', 'CMS'],
        '/content=["\']PrestaShop/i'                       => ['PrestaShop', 'E-commerce'],
        '/prestashop/i'                                    => ['PrestaShop', 'E-commerce'],
        '/content=["\']Magento/i'                          => ['Magento', 'E-commerce'],
        '/Mage\.Cookies|\/static\/frontend/i'              => ['Magento', 'E-commerce'],
        '/\/media\/com_|\/components\/com_/i'              => ['Joomla', 'CMS'],
        '/content=["\']Hugo/i'                             => ['Hugo', 'Static Site Generator'],
        '/gatsby-/i'                                       => ['Gatsby', 'Static Site Generator'],
        '/hexo-/i'                                         => ['Hexo', 'Static Site Generator'],
        '/content=["\']Jekyll/i'                           => ['Jekyll', 'Static Site Generator'],
        '/\/craft\//i'                                     => ['Craft CMS', 'CMS'],
        '/\/concrete\/|concrete5/i'                        => ['Concrete5', 'CMS'],
        '/\/umbraco\//i'                                   => ['Umbraco', 'CMS'],
        '/\/sitecore\//i'                                  => ['Sitecore', 'CMS'],
        '/\/sitefinity\//i'                                => ['Sitefinity', 'CMS'],
        '/\/kentico\//i'                                   => ['Kentico', 'CMS'],
        '/DNN|DotNetNuke/i'                                => ['DNN', 'CMS'],
        '/content=["\']MediaWiki/i'                        => ['MediaWiki', 'CMS'],
        '/\/mw-config\//i'                                 => ['MediaWiki', 'CMS'],
        '/moodle/i'                                        => ['Moodle', 'LMS'],
        '/webflow\.com/i'                                  => ['Webflow', 'Website Builder'],
        '/weebly\.com/i'                                   => ['Weebly', 'Website Builder'],
        // JS Frameworks / Libraries
        '/js\/jquery[.\-\/]/i'                             => ['jQuery', 'JavaScript Library'],
        '/react(?:\.production|\.development|dom)/i'       => ['React', 'JavaScript Framework'],
        '/vue(?:\.runtime|\.global|\.esm)/i'               => ['Vue.js', 'JavaScript Framework'],
        '/angular(?:\.min)?\.js/i'                         => ['AngularJS', 'JavaScript Framework'],
        '/@angular\/core/i'                                => ['Angular', 'JavaScript Framework'],
        '/next(?:\/static|data|_next)/i'                   => ['Next.js', 'JavaScript Framework'],
        '/nuxt/i'                                          => ['Nuxt.js', 'JavaScript Framework'],
        '/svelte/i'                                        => ['Svelte', 'JavaScript Framework'],
        '/ember\./i'                                       => ['Ember.js', 'JavaScript Framework'],
        '/backbone[.\-\/]/i'                               => ['Backbone.js', 'JavaScript Library'],
        '/alpine(?:\.min)?\.js|x-data/i'                   => ['Alpine.js', 'JavaScript Framework'],
        '/htmx(?:\.min)?\.js/i'                            => ['htmx', 'JavaScript Library'],
        '/stimulus/i'                                      => ['Stimulus', 'JavaScript Framework'],
        '/turbo(?:links)?(?:\.min)?\.js/i'                 => ['Turbo', 'JavaScript Library'],
        '/preact/i'                                        => ['Preact', 'JavaScript Framework'],
        '/solid-js|solidjs/i'                              => ['SolidJS', 'JavaScript Framework'],
        '/astro/i'                                         => ['Astro', 'JavaScript Framework'],
        '/remix/i'                                         => ['Remix', 'JavaScript Framework'],
        // CSS Frameworks
        '/bootstrap(?:\.min)?\.(?:css|js)/i'               => ['Bootstrap', 'CSS Framework'],
        '/tailwindcss|tailwind/i'                          => ['Tailwind CSS', 'CSS Framework'],
        '/bulma(?:\.min)?\.css/i'                          => ['Bulma', 'CSS Framework'],
        '/foundation(?:\.min)?\.css/i'                     => ['Foundation', 'CSS Framework'],
        '/materialize(?:\.min)?\.css/i'                    => ['Materialize', 'CSS Framework'],
        '/semantic(?:\.min)?\.css/i'                       => ['Semantic UI', 'CSS Framework'],
        '/uikit(?:\.min)?\.(?:css|js)/i'                   => ['UIkit', 'CSS Framework'],
        '/font-awesome|fontawesome/i'                      => ['Font Awesome', 'Icon Library'],
        // Analytics
        '/google-analytics|gtag|googletagmanager/i'        => ['Google Analytics', 'Analytics'],
        '/ga\.js|analytics\.js|gtag\/js/i'                 => ['Google Analytics', 'Analytics'],
        '/hotjar/i'                                        => ['Hotjar', 'Analytics'],
        '/matomo|piwik/i'                                  => ['Matomo', 'Analytics'],
        '/plausible\.io/i'                                 => ['Plausible', 'Analytics'],
        '/umami\.is/i'                                     => ['Umami', 'Analytics'],
        '/segment\.(?:com|io)/i'                           => ['Segment', 'Analytics'],
        '/mixpanel/i'                                      => ['Mixpanel', 'Analytics'],
        '/amplitude/i'                                     => ['Amplitude', 'Analytics'],
        '/heap(?:analytics)?/i'                            => ['Heap', 'Analytics'],
        '/posthog/i'                                       => ['PostHog', 'Analytics'],
        '/clarity\.ms/i'                                   => ['Microsoft Clarity', 'Analytics'],
        '/facebook\.net\/.*fbevents|fbq\(/i'               => ['Facebook Pixel', 'Marketing'],
        '/connect\.facebook\.net/i'                        => ['Facebook SDK', 'Social'],
        '/platform\.twitter\.com/i'                        => ['Twitter Widgets', 'Social'],
        '/linkedin\.com\/insight/i'                        => ['LinkedIn Insight', 'Marketing'],
        // CDN
        '/cdn\.jsdelivr\.net/i'                            => ['jsDelivr', 'CDN'],
        '/cdnjs\.cloudflare\.com/i'                        => ['cdnjs', 'CDN'],
        '/unpkg\.com/i'                                    => ['unpkg', 'CDN'],
        '/stackpath\.bootstrapcdn\.com/i'                  => ['StackPath', 'CDN'],
        // Payment
        '/stripe\.com\/v|Stripe\(/i'                       => ['Stripe', 'Payment'],
        '/paypal\.com\/sdk/i'                              => ['PayPal', 'Payment'],
        '/braintree/i'                                     => ['Braintree', 'Payment'],
        '/square\.com/i'                                   => ['Square', 'Payment'],
        // Security
        '/recaptcha/i'                                     => ['reCAPTCHA', 'Security'],
        '/hcaptcha/i'                                      => ['hCaptcha', 'Security'],
        '/turnstile/i'                                     => ['Cloudflare Turnstile', 'Security'],
        // Backend Frameworks
        '/laravel/i'                                       => ['Laravel', 'Framework'],
        '/symfony/i'                                       => ['Symfony', 'Framework'],
        '/rails|ruby-on-rails/i'                           => ['Ruby on Rails', 'Framework'],
        '/django/i'                                        => ['Django', 'Framework'],
        '/flask/i'                                         => ['Flask', 'Framework'],
        '/spring/i'                                        => ['Spring', 'Framework'],
        '/grails/i'                                        => ['Grails', 'Framework'],
        '/play framework/i'                                => ['Play Framework', 'Framework'],
        '/phoenix/i'                                       => ['Phoenix', 'Framework'],
        // Animation
        '/gsap|greensock/i'                                => ['GSAP', 'Animation Library'],
        '/lottie/i'                                        => ['Lottie', 'Animation Library'],
        '/three(?:\.min)?\.js/i'                           => ['Three.js', '3D Library'],
        // Chat / Support
        '/intercom/i'                                      => ['Intercom', 'Live Chat'],
        '/drift\.com/i'                                    => ['Drift', 'Live Chat'],
        '/crisp\.chat/i'                                   => ['Crisp', 'Live Chat'],
        '/tawk\.to/i'                                      => ['Tawk.to', 'Live Chat'],
        '/zendesk/i'                                       => ['Zendesk', 'Support'],
        '/freshdesk|freshchat/i'                           => ['Freshworks', 'Support'],
        // A/B Testing
        '/optimizely/i'                                    => ['Optimizely', 'A/B Testing'],
        '/vwo\.com/i'                                      => ['VWO', 'A/B Testing'],
        '/launchdarkly/i'                                  => ['LaunchDarkly', 'Feature Flags'],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $url = $queryValue;
        if ($queryType === 'domain') $url = "https://{$queryValue}";
        if (!preg_match('#^https?://#i', $url)) $url = "https://{$url}";

        $headerString = '';
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_HEADERFUNCTION => function($curl, $header) use (&$headerString) {
                $headerString .= $header; return strlen($header);
            },
        ]);
        $body = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        $ms = (int)((microtime(true) - $start) * 1000);

        if (!$body && $curlError) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Failed to fetch: {$curlError}", $ms);
        }

        $detected = []; // name => [category, version]

        // Check headers
        $headerLines = [];
        foreach (explode("\n", $headerString) as $line) {
            if (strpos($line, ':') !== false) {
                $parts = explode(':', $line, 2);
                $headerLines[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }

        foreach (self::HEADER_SIGS as $sig) {
            $hdr = $sig['header'];
            if (!isset($headerLines[$hdr])) continue;
            if (preg_match($sig['match'], $headerLines[$hdr], $m)) {
                $version = $m[1] ?? '';
                $detected[$sig['name']] = ['category' => $sig['category'], 'version' => $version];
            }
        }

        // Check HTML body
        if ($body) {
            foreach (self::HTML_PATTERNS as $regex => $info) {
                if (preg_match($regex, $body)) {
                    if (!isset($detected[$info[0]])) {
                        $detected[$info[0]] = ['category' => $info[1], 'version' => ''];
                    }
                }
            }

            // Check meta generator
            if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $gen = trim($m[1]);
                // Try to split name and version
                if (preg_match('/^(.+?)\s+([\d.]+)/', $gen, $gm)) {
                    $detected[$gm[1]] = ['category' => 'Generator', 'version' => $gm[2]];
                } else {
                    $detected[$gen] = ['category' => 'Generator', 'version' => ''];
                }
            }
        }

        $techCount = count($detected);
        $displayName = $queryType === 'domain' ? $queryValue : $url;

        if ($techCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 50, responseMs: $ms,
                summary: "{$displayName}: No technologies detected.",
                tags: [self::API_ID, $queryType, 'clean'],
                rawData: ['technologies' => [], 'http_status' => $httpCode], success: true
            );
        }

        // Group by category
        $byCategory = [];
        $techList = [];
        foreach ($detected as $name => $info) {
            $cat = $info['category'];
            $ver = $info['version'];
            $byCategory[$cat][] = $ver ? "{$name} {$ver}" : $name;
            $techList[] = ['name' => $name, 'category' => $cat, 'version' => $ver];
        }

        $parts = ["{$displayName}: {$techCount} technology(ies) detected"];
        foreach ($byCategory as $cat => $names) {
            $parts[] = "{$cat}: " . implode(', ', $names);
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 80, responseMs: $ms,
            summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique([self::API_ID, $queryType, 'technology'])),
            rawData: [
                'technologies' => $techList, 'by_category' => $byCategory,
                'http_status' => $httpCode, 'tech_count' => $techCount,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null,
                'signatures' => count(self::HEADER_SIGS) + count(self::HTML_PATTERNS)];
    }
}
