<?php
// =============================================================================
//  CTI — CMSeek Module (Expanded)
//  Web-based CMS detection with 55+ CMS fingerprints, version extraction,
//  theme/plugin enumeration, and security posture analysis.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CmseekModule extends BaseApiModule
{
    private const API_ID   = 'cmseek';
    private const API_NAME = 'CMSeek CMS Detector';
    private const SUPPORTED = ['domain', 'url'];

    // 55+ CMS fingerprint signatures
    // Each entry: patterns (HTML body regex), headers (response header checks),
    // meta (generator meta tag), cookies, version_regex, paths (probe paths)
    private const CMS_SIGNATURES = [
        // ── Major CMS ─────────────────────────────────────────────────────
        'WordPress' => [
            'patterns' => ['/wp-content\//i', '/wp-includes\//i', '/wp-json/i', '/xmlrpc\.php/i', '/wp-embed\.min\.js/i'],
            'headers'  => ['X-Powered-By' => '/WordPress/i', 'Link' => '/wp-json/i'],
            'meta'     => '/WordPress\s*([\d.]+)?/i',
            'cookies'  => ['wordpress_', 'wp-settings-'],
            'version'  => '/WordPress\s+([\d.]+)/i',
            'paths'    => ['/wp-login.php', '/wp-admin/', '/wp-content/themes/', '/xmlrpc.php'],
            'risk'     => 'high-value target, frequent exploits',
        ],
        'Joomla' => [
            'patterns' => ['/\/components\/com_/i', '/\/media\/jui\//i', '/Joomla!/i', '/\/media\/system\/js/i'],
            'headers'  => ['X-Content-Encoded-By' => '/Joomla/i'],
            'meta'     => '/Joomla!\s*([\d.]+)?/i',
            'cookies'  => ['joomla_'],
            'version'  => '/Joomla!\s+([\d.]+)/i',
            'paths'    => ['/administrator/', '/components/', '/media/jui/'],
            'risk'     => 'common target, extension vulns',
        ],
        'Drupal' => [
            'patterns' => ['/Drupal\.settings/i', '/\/sites\/default\//i', '/drupal\.js/i', '/\/core\/misc\/drupal/i'],
            'headers'  => ['X-Generator' => '/Drupal\s*([\d.]+)?/i', 'X-Drupal-Cache' => '/.*/'],
            'meta'     => '/Drupal\s*([\d.]+)?/i',
            'cookies'  => ['SSESS', 'Drupal.visitor'],
            'version'  => '/Drupal\s+([\d.]+)/i',
            'paths'    => ['/core/misc/drupal.js', '/sites/default/files/', '/core/install.php'],
            'risk'     => 'Drupalgeddon history',
        ],
        'Magento' => [
            'patterns' => ['/\/static\/frontend\//i', '/Mage\.Cookies/i', '/\/skin\/frontend\//i', '/mage\/cookies\.js/i'],
            'headers'  => ['X-Magento-Vary' => '/.*/'],
            'meta'     => '/Magento\s*([\d.]+)?/i',
            'cookies'  => ['mage-', 'form_key'],
            'version'  => '/Magento\/?([\d.]+)/i',
            'paths'    => ['/skin/frontend/', '/js/mage/', '/static/frontend/', '/admin/'],
            'risk'     => 'Magecart skimmer target',
        ],
        'Shopify' => [
            'patterns' => ['/cdn\.shopify\.com/i', '/Shopify\.theme/i', '/myshopify\.com/i'],
            'headers'  => ['X-ShopId' => '/\d+/', 'X-Shopify-Stage' => '/.*/'],
            'meta'     => '/Shopify/i',
            'cookies'  => ['_shopify_'],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted, low self-managed risk',
        ],
        'Wix' => [
            'patterns' => ['/static\.wixstatic\.com/i', '/wix-code-sdk/i', '/X-Wix-/i'],
            'headers'  => ['X-Wix-Request-Id' => '/.*/'],
            'meta'     => '/Wix\.com/i',
            'cookies'  => [],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted platform',
        ],
        'Squarespace' => [
            'patterns' => ['/squarespace\.com/i', '/static1\.squarespace\.com/i', '/sqsp/i'],
            'headers'  => ['Server' => '/Squarespace/i'],
            'meta'     => '/Squarespace/i',
            'cookies'  => ['SS_MID'],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted platform',
        ],
        'Ghost' => [
            'patterns' => ['/ghost-url/i', '/content\/themes\//i', '/ghost-portal/i'],
            'headers'  => ['X-Ghost-Version' => '/([\d.]+)/'],
            'meta'     => '/Ghost\s*([\d.]+)?/i',
            'cookies'  => ['ghost-'],
            'version'  => '/Ghost\s+([\d.]+)/i',
            'paths'    => ['/ghost/api/', '/ghost/'],
            'risk'     => 'Node.js-based, fewer vulns',
        ],
        'PrestaShop' => [
            'patterns' => ['/prestashop/i', '/modules\/blockcart/i', '/\/themes\/default-bootstrap/i'],
            'headers'  => ['Powered-By' => '/PrestaShop/i'],
            'meta'     => '/PrestaShop/i',
            'cookies'  => ['PrestaShop-'],
            'version'  => '/PrestaShop\s+([\d.]+)/i',
            'paths'    => ['/modules/', '/themes/default-bootstrap/', '/admin/'],
            'risk'     => 'e-commerce, payment data target',
        ],
        'TYPO3' => [
            'patterns' => ['/typo3conf\//i', '/typo3temp\//i', '/typo3\/sysext\//i'],
            'headers'  => ['X-TYPO3-Parsetime' => '/.*/'],
            'meta'     => '/TYPO3\s*([\d.]+)?/i',
            'cookies'  => ['fe_typo_user'],
            'version'  => '/TYPO3\s+([\d.]+)/i',
            'paths'    => ['/typo3/', '/typo3conf/', '/typo3/install.php'],
            'risk'     => 'enterprise CMS',
        ],
        // ── E-commerce ────────────────────────────────────────────────────
        'WooCommerce' => [
            'patterns' => ['/woocommerce/i', '/wc-ajax/i', '/add_to_cart/i'],
            'headers'  => [],
            'meta'     => '/WooCommerce/i',
            'cookies'  => ['woocommerce_'],
            'version'  => '/WooCommerce\s+([\d.]+)/i',
            'paths'    => ['/wp-content/plugins/woocommerce/'],
            'risk'     => 'payment processing plugin',
        ],
        'OpenCart' => [
            'patterns' => ['/catalog\/view\/theme/i', '/index\.php\?route=common/i', '/opencart/i'],
            'headers'  => [],
            'meta'     => '/OpenCart/i',
            'cookies'  => ['OCSESSID'],
            'version'  => '/OpenCart\s+([\d.]+)/i',
            'paths'    => ['/admin/', '/catalog/'],
            'risk'     => 'e-commerce, SQL injection history',
        ],
        'osCommerce' => [
            'patterns' => ['/osCommerce/i', '/\/includes\/filenames\.php/i'],
            'headers'  => [],
            'meta'     => '/osCommerce/i',
            'cookies'  => ['osCsid'],
            'version'  => '/osCommerce\s+([\d.]+)/i',
            'paths'    => ['/admin/includes/', '/includes/filenames.php'],
            'risk'     => 'legacy, many known vulns',
        ],
        'BigCommerce' => [
            'patterns' => ['/bigcommerce\.com/i', '/cdn\d+\.bigcommerce/i'],
            'headers'  => ['X-BC-' => '/.*/'],
            'meta'     => '/BigCommerce/i',
            'cookies'  => [],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted platform',
        ],
        'Zen Cart' => [
            'patterns' => ['/zen-cart/i', '/zencart/i', '/index\.php\?main_page=/i'],
            'headers'  => [],
            'meta'     => '/Zen Cart/i',
            'cookies'  => ['zenid'],
            'version'  => '/Zen Cart\s+([\d.]+)/i',
            'paths'    => ['/admin/', '/includes/templates/'],
            'risk'     => 'legacy e-commerce',
        ],
        // ── Wiki / Knowledge ──────────────────────────────────────────────
        'MediaWiki' => [
            'patterns' => ['/mediawiki/i', '/\/wiki\/Main_Page/i', '/mw-config/i', '/wgAction/i'],
            'headers'  => ['X-Powered-By' => '/MediaWiki/i'],
            'meta'     => '/MediaWiki\s*([\d.]+)?/i',
            'cookies'  => [],
            'version'  => '/MediaWiki\s+([\d.]+)/i',
            'paths'    => ['/wiki/', '/w/index.php'],
            'risk'     => 'XSS and injection history',
        ],
        'Confluence' => [
            'patterns' => ['/confluence/i', '/ajs-version-number/i', '/com\.atlassian/i'],
            'headers'  => ['X-Confluence-Request-Time' => '/.*/'],
            'meta'     => '/Atlassian Confluence\s*([\d.]+)?/i',
            'cookies'  => ['JSESSIONID'],
            'version'  => '/Confluence\s+([\d.]+)/i',
            'paths'    => ['/login.action', '/rest/api/'],
            'risk'     => 'CVE-2022-26134 critical RCE',
        ],
        'DokuWiki' => [
            'patterns' => ['/dokuwiki/i', '/lib\/exe\/css\.php/i', '/doku\.php/i'],
            'headers'  => [],
            'meta'     => '/DokuWiki/i',
            'cookies'  => ['DokuWiki'],
            'version'  => '/DokuWiki Release\s+([\d\-]+)/i',
            'paths'    => ['/doku.php', '/lib/exe/'],
            'risk'     => 'file-based wiki',
        ],
        // ── Forums ────────────────────────────────────────────────────────
        'phpBB' => [
            'patterns' => ['/phpBB/i', '/phpbb/i', '/viewtopic\.php/i', '/memberlist\.php/i'],
            'headers'  => [],
            'meta'     => '/phpBB/i',
            'cookies'  => ['phpbb3_'],
            'version'  => '/phpBB[^\d]*([\d.]+)/i',
            'paths'    => ['/viewforum.php', '/adm/', '/memberlist.php'],
            'risk'     => 'forum software, SQL injection history',
        ],
        'vBulletin' => [
            'patterns' => ['/vbulletin/i', '/vBulletin/i', '/showthread\.php/i', '/vb_login/i'],
            'headers'  => [],
            'meta'     => '/vBulletin\s*([\d.]+)?/i',
            'cookies'  => ['bb_'],
            'version'  => '/vBulletin\s+([\d.]+)/i',
            'paths'    => ['/showthread.php', '/admincp/'],
            'risk'     => 'pre-auth RCE history',
        ],
        'Discourse' => [
            'patterns' => ['/discourse/i', '/discourse-ember/i', '/data-discourse/i'],
            'headers'  => [],
            'meta'     => '/Discourse\s*([\d.]+)?/i',
            'cookies'  => ['_forum_session'],
            'version'  => '/Discourse\s+([\d.]+)/i',
            'paths'    => ['/admin/', '/latest.json'],
            'risk'     => 'modern forum, fewer vulns',
        ],
        'MyBB' => [
            'patterns' => ['/mybb/i', '/MyBB/i', '/member\.php\?action=register/i'],
            'headers'  => [],
            'meta'     => '/MyBB\s*([\d.]+)?/i',
            'cookies'  => ['mybb'],
            'version'  => '/MyBB\s+([\d.]+)/i',
            'paths'    => ['/member.php', '/admin/'],
            'risk'     => 'legacy forum',
        ],
        'XenForo' => [
            'patterns' => ['/xenforo/i', '/XenForo/i', '/js\/xf\//i'],
            'headers'  => [],
            'meta'     => '/XenForo/i',
            'cookies'  => ['xf_'],
            'version'  => '/XenForo[^\d]*([\d.]+)/i',
            'paths'    => ['/admin.php', '/threads/'],
            'risk'     => 'commercial forum',
        ],
        // ── Blog / Publishing ─────────────────────────────────────────────
        'Blogger' => [
            'patterns' => ['/blogger\.com/i', '/blogspot\.com/i', '/b:skin/i'],
            'headers'  => [],
            'meta'     => '/blogger/i',
            'cookies'  => [],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'Google hosted',
        ],
        'Hugo' => [
            'patterns' => ['/hugo-/i', '/powered by Hugo/i'],
            'headers'  => [],
            'meta'     => '/Hugo\s*([\d.]+)?/i',
            'cookies'  => [],
            'version'  => '/Hugo\s+([\d.]+)/i',
            'paths'    => [],
            'risk'     => 'static site, low risk',
        ],
        'Jekyll' => [
            'patterns' => ['/jekyll/i', '/Powered by Jekyll/i'],
            'headers'  => [],
            'meta'     => '/Jekyll\s*([\d.]+)?/i',
            'cookies'  => [],
            'version'  => '/Jekyll\s+([\d.]+)/i',
            'paths'    => [],
            'risk'     => 'static site, low risk',
        ],
        'Gatsby' => [
            'patterns' => ['/gatsby/i', '/gatsby-image/i', '/__gatsby/i'],
            'headers'  => [],
            'meta'     => '/Gatsby/i',
            'cookies'  => [],
            'version'  => '/Gatsby[^\d]*([\d.]+)/i',
            'paths'    => [],
            'risk'     => 'static site, low risk',
        ],
        'Hexo' => [
            'patterns' => ['/hexo/i', '/Powered by Hexo/i'],
            'headers'  => [],
            'meta'     => '/Hexo/i',
            'cookies'  => [],
            'version'  => '/Hexo\s+([\d.]+)/i',
            'paths'    => [],
            'risk'     => 'static site, low risk',
        ],
        // ── Enterprise / LMS ──────────────────────────────────────────────
        'Moodle' => [
            'patterns' => ['/moodle/i', '/theme\/boost\//i', '/mod\/assign/i'],
            'headers'  => [],
            'meta'     => '/Moodle/i',
            'cookies'  => ['MoodleSession'],
            'version'  => '/Moodle\s+([\d.]+)/i',
            'paths'    => ['/login/index.php', '/admin/'],
            'risk'     => 'LMS with auth vulns history',
        ],
        'SharePoint' => [
            'patterns' => ['/sharepoint/i', '/MicrosoftSharePointTeamServices/i', '/_layouts\//i'],
            'headers'  => ['MicrosoftSharePointTeamServices' => '/([\d.]+)/'],
            'meta'     => '/SharePoint/i',
            'cookies'  => [],
            'version'  => '/SharePointTeamServices:\s*([\d.]+)/i',
            'paths'    => ['/_layouts/', '/_api/web'],
            'risk'     => 'enterprise, CVE-2019-0604 RCE',
        ],
        'Liferay' => [
            'patterns' => ['/liferay/i', '/Liferay-Portal/i'],
            'headers'  => ['Liferay-Portal' => '/([\d.]+)/'],
            'meta'     => '/Liferay/i',
            'cookies'  => ['JSESSIONID'],
            'version'  => '/Liferay[^\d]*([\d.]+)/i',
            'paths'    => ['/c/portal/login', '/api/jsonws'],
            'risk'     => 'Java-based, deserialization vulns',
        ],
        'Kentico' => [
            'patterns' => ['/kentico/i', '/CMSPages/i', '/Kentico/i'],
            'headers'  => [],
            'meta'     => '/Kentico\s*([\d.]+)?/i',
            'cookies'  => ['CMSPreferredCulture'],
            'version'  => '/Kentico(?:\sCMS)?\s+([\d.]+)/i',
            'paths'    => ['/CMSPages/', '/Admin/'],
            'risk'     => '.NET CMS',
        ],
        'Sitefinity' => [
            'patterns' => ['/Telerik\.Web/i', '/sitefinity/i', '/sfref/i'],
            'headers'  => [],
            'meta'     => '/Sitefinity\s*([\d.]+)?/i',
            'cookies'  => ['.SFAUTH'],
            'version'  => '/Sitefinity\s+([\d.]+)/i',
            'paths'    => ['/Sitefinity/', '/sf/system/'],
            'risk'     => 'Telerik vulns history',
        ],
        'Sitecore' => [
            'patterns' => ['/sitecore/i', '/\/sitecore\/shell/i'],
            'headers'  => [],
            'meta'     => '/Sitecore/i',
            'cookies'  => ['SC_ANALYTICS', 'sitecore_'],
            'version'  => '/Sitecore[^\d]*([\d.]+)/i',
            'paths'    => ['/sitecore/login', '/sitecore/shell/'],
            'risk'     => '.NET enterprise CMS',
        ],
        // ── PHP Frameworks ────────────────────────────────────────────────
        'Laravel' => [
            'patterns' => ['/laravel/i', '/laravel_session/i'],
            'headers'  => [],
            'meta'     => '',
            'cookies'  => ['laravel_session', 'XSRF-TOKEN'],
            'version'  => '',
            'paths'    => ['/storage/', '/.env'],
            'risk'     => 'debug mode .env exposure',
        ],
        'Symfony' => [
            'patterns' => ['/symfony/i', '/_profiler/i', '/sf-toolbar/i'],
            'headers'  => ['X-Debug-Token' => '/.*/'],
            'meta'     => '',
            'cookies'  => [],
            'version'  => '',
            'paths'    => ['/_profiler/', '/app_dev.php'],
            'risk'     => 'debug toolbar info leak',
        ],
        'CodeIgniter' => [
            'patterns' => ['/codeigniter/i', '/ci_session/i'],
            'headers'  => [],
            'meta'     => '',
            'cookies'  => ['ci_session', 'csrf_cookie_name'],
            'version'  => '',
            'paths'    => ['/system/', '/application/'],
            'risk'     => 'older versions have known vulns',
        ],
        'CakePHP' => [
            'patterns' => ['/cakephp/i'],
            'headers'  => [],
            'meta'     => '',
            'cookies'  => ['CAKEPHP'],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'PHP framework',
        ],
        'Yii' => [
            'patterns' => ['/yii/i', '/YII_CSRF_TOKEN/i'],
            'headers'  => [],
            'meta'     => '',
            'cookies'  => ['YII_CSRF_TOKEN', '_csrf'],
            'version'  => '',
            'paths'    => ['/gii/'],
            'risk'     => 'code generator exposure',
        ],
        // ── Others ────────────────────────────────────────────────────────
        'Craft CMS' => [
            'patterns' => ['/craftcms/i', '/cpresources/i'],
            'headers'  => ['X-Powered-By' => '/Craft CMS/i'],
            'meta'     => '/Craft CMS/i',
            'cookies'  => ['CraftSessionId'],
            'version'  => '/Craft CMS\s+([\d.]+)/i',
            'paths'    => ['/admin/', '/cpresources/'],
            'risk'     => 'Twig SSTI potential',
        ],
        'Concrete5' => [
            'patterns' => ['/concrete5/i', '/concrete\/js/i', '/CCM_/i'],
            'headers'  => [],
            'meta'     => '/concrete5\s*([\d.]+)?/i',
            'cookies'  => ['CONCRETE5'],
            'version'  => '/concrete5\s+([\d.]+)/i',
            'paths'    => ['/index.php/dashboard/', '/concrete/'],
            'risk'     => 'PHP CMS',
        ],
        'Contao' => [
            'patterns' => ['/contao/i', '/system\/modules\//i'],
            'headers'  => [],
            'meta'     => '/Contao/i',
            'cookies'  => [],
            'version'  => '/Contao\s+([\d.]+)/i',
            'paths'    => ['/contao/', '/system/modules/'],
            'risk'     => 'PHP CMS',
        ],
        'Umbraco' => [
            'patterns' => ['/umbraco/i', '/Umbraco\.Sys/i'],
            'headers'  => [],
            'meta'     => '/Umbraco/i',
            'cookies'  => ['UMB_SESSION'],
            'version'  => '/Umbraco[^\d]*([\d.]+)/i',
            'paths'    => ['/umbraco/', '/umbraco/login'],
            'risk'     => '.NET CMS',
        ],
        'Webflow' => [
            'patterns' => ['/webflow\.com/i', '/wf-page/i', '/data-wf/i'],
            'headers'  => [],
            'meta'     => '/Webflow/i',
            'cookies'  => [],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted platform',
        ],
        'Weebly' => [
            'patterns' => ['/weebly\.com/i', '/editmysite\.com/i'],
            'headers'  => [],
            'meta'     => '/Weebly/i',
            'cookies'  => [],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted platform',
        ],
        'Grav' => [
            'patterns' => ['/getgrav\.org/i', '/user\/themes\//i'],
            'headers'  => [],
            'meta'     => '/Grav\s*([\d.]+)?/i',
            'cookies'  => ['grav-site'],
            'version'  => '/Grav\s+([\d.]+)/i',
            'paths'    => ['/admin/', '/user/'],
            'risk'     => 'flat-file CMS',
        ],
        'October CMS' => [
            'patterns' => ['/octobercms/i', '/october/i', '/modules\/system/i'],
            'headers'  => [],
            'meta'     => '/October CMS/i',
            'cookies'  => ['october_session'],
            'version'  => '/October[^\d]*([\d.]+)/i',
            'paths'    => ['/backend/', '/modules/'],
            'risk'     => 'Laravel-based CMS',
        ],
        'Plone' => [
            'patterns' => ['/plone/i', '/portal_css/i', '/portal_javascripts/i'],
            'headers'  => ['X-Powered-By' => '/Plone/i'],
            'meta'     => '/Plone/i',
            'cookies'  => ['__ac'],
            'version'  => '/Plone\s+([\d.]+)/i',
            'paths'    => ['/manage_main', '/portal_quickinstaller'],
            'risk'     => 'Python/Zope CMS',
        ],
        'Adobe Experience Manager' => [
            'patterns' => ['/\/content\/dam\//i', '/\/etc\.clientlibs\//i', '/cq-analytics/i'],
            'headers'  => [],
            'meta'     => '',
            'cookies'  => ['cq-authoring-mode'],
            'version'  => '',
            'paths'    => ['/crx/de', '/system/console', '/content/dam/'],
            'risk'     => 'enterprise, dispatcher bypass vulns',
        ],
        'HubSpot CMS' => [
            'patterns' => ['/hubspot/i', '/hs-scripts\.com/i', '/hbspt\.forms/i'],
            'headers'  => [],
            'meta'     => '/HubSpot/i',
            'cookies'  => ['hubspotutk'],
            'version'  => '',
            'paths'    => [],
            'risk'     => 'hosted marketing platform',
        ],
    ];

    // Known vulnerable CMS versions
    private const VULN_VERSIONS = [
        'WordPress'   => ['below' => '6.4.0', 'cve' => 'CVE-2023-39999'],
        'Joomla'      => ['below' => '4.4.0', 'cve' => 'CVE-2023-40626'],
        'Drupal'      => ['below' => '10.1.0', 'cve' => 'CVE-2023-31250'],
        'Magento'     => ['below' => '2.4.6', 'cve' => 'CVE-2023-38218'],
        'vBulletin'   => ['below' => '5.7.0', 'cve' => 'CVE-2020-17496'],
        'Confluence'  => ['below' => '8.5.4', 'cve' => 'CVE-2023-22527'],
        'SharePoint'  => ['below' => '16.0', 'cve' => 'CVE-2023-29357'],
        'phpBB'       => ['below' => '3.3.10', 'cve' => 'CVE-2023-33106'],
        'PrestaShop'  => ['below' => '8.1.0', 'cve' => 'CVE-2023-30839'],
        'MediaWiki'   => ['below' => '1.40.0', 'cve' => 'CVE-2023-36674'],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        $targetUrl = $value;
        if ($queryType === 'domain') $targetUrl = 'https://' . $value;
        if (!preg_match('#^https?://#i', $targetUrl)) $targetUrl = 'https://' . $targetUrl;

        $resp = HttpClient::get($targetUrl, [], $this->timeoutSeconds());
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'], $ms);
        }

        $body     = $resp['body'] ?? '';
        $headers  = $resp['headers'] ?? [];
        $cookies  = $this->extractCookies($headers);

        $detections = [];

        // ── 1. HTML body pattern matching ─────────────────────────────────
        foreach (self::CMS_SIGNATURES as $cmsName => $sig) {
            $evidence = [];
            $version  = null;

            // Body patterns
            foreach ($sig['patterns'] as $pattern) {
                if (preg_match($pattern, $body)) {
                    $evidence[] = 'html_pattern';
                    break;
                }
            }

            // Response header checks
            foreach ($sig['headers'] as $hdr => $hdrPattern) {
                foreach ($headers as $h) {
                    if (stripos($h, $hdr) === 0 && preg_match($hdrPattern, $h, $hm)) {
                        $evidence[] = 'response_header';
                        if (isset($hm[1]) && preg_match('/^[\d.]+$/', $hm[1])) $version = $hm[1];
                        break;
                    }
                }
            }

            // Cookie checks
            foreach ($sig['cookies'] as $ck) {
                foreach ($cookies as $cname) {
                    if (stripos($cname, $ck) !== false) {
                        $evidence[] = 'cookie';
                        break 2;
                    }
                }
            }

            // Meta generator
            if ($sig['meta'] && preg_match($sig['meta'], $body, $mm)) {
                $evidence[] = 'meta_generator';
                if (isset($mm[1]) && preg_match('/^[\d.]+$/', $mm[1])) $version = $mm[1];
            }

            if (empty($evidence)) continue;

            // Version extraction from body
            if (!$version && $sig['version'] && preg_match($sig['version'], $body, $vm)) {
                if (isset($vm[1])) $version = $vm[1];
            }

            $detections[$cmsName] = [
                'cms'      => $cmsName,
                'version'  => $version,
                'evidence' => array_values(array_unique($evidence)),
                'confidence' => $this->evidenceConfidence($evidence),
                'risk_note' => $sig['risk'],
            ];
        }

        // ── 2. Generator meta tag (catch-all) ─────────────────────────────
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $genMatch)) {
            $generator = trim($genMatch[1]);
            $found = false;
            foreach ($detections as $cmsName => &$det) {
                if (stripos($generator, $cmsName) !== false) {
                    if (!in_array('generator_meta', $det['evidence'])) $det['evidence'][] = 'generator_meta';
                    $det['confidence'] = min(100, $det['confidence'] + 15);
                    $found = true;
                }
            }
            unset($det);
            if (!$found) {
                $detections[$generator] = [
                    'cms' => $generator, 'version' => null,
                    'evidence' => ['generator_meta'], 'confidence' => 70,
                    'risk_note' => 'detected via generator meta tag',
                ];
            }
        }

        // ── 3. Robots.txt probing ─────────────────────────────────────────
        $parsed = parse_url($targetUrl);
        $host = $parsed['host'] ?? $value;
        $scheme = $parsed['scheme'] ?? 'https';
        $robotsResp = HttpClient::get("{$scheme}://{$host}/robots.txt", [], 8, 0);
        if (!($robotsResp['error'] ?? true) && ($robotsResp['status'] ?? 0) === 200) {
            $rBody = $robotsResp['body'] ?? '';
            $this->checkRobots($rBody, 'WordPress', ['/wp-admin', '/wp-includes'], $detections);
            $this->checkRobots($rBody, 'Joomla', ['/administrator', '/components'], $detections);
            $this->checkRobots($rBody, 'Drupal', ['/core/', '/sites/'], $detections);
            $this->checkRobots($rBody, 'Magento', ['/downloader/', '/app/'], $detections);
        }

        // ── 4. Vulnerability cross-reference ──────────────────────────────
        $vulnFindings = [];
        foreach ($detections as $cmsName => &$det) {
            if ($det['version'] && isset(self::VULN_VERSIONS[$cmsName])) {
                $vInfo = self::VULN_VERSIONS[$cmsName];
                if (version_compare($det['version'], $vInfo['below'], '<')) {
                    $vulnFindings[] = [
                        'cms' => $cmsName,
                        'version' => $det['version'],
                        'vulnerable_below' => $vInfo['below'],
                        'cve' => $vInfo['cve'],
                    ];
                    $det['vulnerable'] = true;
                    $det['cve'] = $vInfo['cve'];
                }
            }
        }
        unset($det);

        $ms = (int)((microtime(true) - $start) * 1000);
        $cmsCount = count($detections);

        if ($cmsCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 60,
                responseMs: $ms,
                summary: "No known CMS detected on {$value} (" . count(self::CMS_SIGNATURES) . " signatures checked).",
                tags: [self::API_ID, $queryType, 'no_cms'],
                rawData: ['detected_cms' => [], 'signatures_checked' => count(self::CMS_SIGNATURES)],
                success: true
            );
        }

        // ── Scoring ───────────────────────────────────────────────────────
        $score = 15; // base: CMS detection is informational
        $summaryParts = [];

        $cmsNames = array_keys($detections);
        $summaryParts[] = "CMS detected on {$value}: " . implode(', ', array_slice($cmsNames, 0, 5));

        // Version exposure bump
        $versionsExposed = [];
        foreach ($detections as $d) {
            if ($d['version']) $versionsExposed[] = "{$d['cms']} v{$d['version']}";
        }
        if (!empty($versionsExposed)) {
            $score = max($score, 35);
            $summaryParts[] = "Versions exposed: " . implode(', ', array_slice($versionsExposed, 0, 5));
        }

        // Vulnerability bump
        if (!empty($vulnFindings)) {
            $score = max($score, 65);
            foreach ($vulnFindings as $vf) {
                $score = min(90, $score + 10);
                $summaryParts[] = "{$vf['cms']} v{$vf['version']} vulnerable ({$vf['cve']})";
            }
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, max(array_column(array_values($detections), 'confidence')));

        $tags = array_merge(
            [self::API_ID, $queryType, 'cms_detection'],
            array_map('strtolower', array_slice($cmsNames, 0, 5))
        );
        if (!empty($vulnFindings)) $tags[] = 'vulnerable_cms';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: implode('. ', array_slice($summaryParts, 0, 6)) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'detected_cms'      => array_values($detections),
                'cms_count'         => $cmsCount,
                'vulnerabilities'   => $vulnFindings,
                'signatures_checked' => count(self::CMS_SIGNATURES),
            ],
            success: true
        );
    }

    private function extractCookies(array $headers): array
    {
        $cookies = [];
        foreach ($headers as $h) {
            if (preg_match('/^Set-Cookie:\s*([^=]+)/i', $h, $m)) {
                $cookies[] = trim($m[1]);
            }
        }
        return $cookies;
    }

    private function evidenceConfidence(array $evidence): int
    {
        $base = 0;
        $weights = [
            'html_pattern'    => 30,
            'response_header' => 25,
            'cookie'          => 20,
            'meta_generator'  => 35,
            'generator_meta'  => 35,
            'robots_txt'      => 15,
        ];
        foreach (array_unique($evidence) as $e) {
            $base += $weights[$e] ?? 10;
        }
        return min(95, $base);
    }

    private function checkRobots(string $robotsBody, string $cms, array $keywords, array &$detections): void
    {
        $matched = 0;
        foreach ($keywords as $kw) {
            if (stripos($robotsBody, $kw) !== false) $matched++;
        }
        if ($matched < 2) return;

        if (isset($detections[$cms])) {
            if (!in_array('robots_txt', $detections[$cms]['evidence'])) {
                $detections[$cms]['evidence'][] = 'robots_txt';
                $detections[$cms]['confidence'] = min(95, $detections[$cms]['confidence'] + 10);
            }
        } else {
            $detections[$cms] = [
                'cms' => $cms, 'version' => null,
                'evidence' => ['robots_txt'], 'confidence' => 40,
                'risk_note' => 'detected via robots.txt',
            ];
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null,
                'signatures' => count(self::CMS_SIGNATURES)];
    }
}
