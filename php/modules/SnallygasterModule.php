<?php
// =============================================================================
//  CTI — Snallygaster Module (Expanded)
//  Probes for 100+ sensitive files and configurations that should not be
//  publicly accessible. Organized by category with content validation.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SnallygasterModule extends BaseApiModule
{
    private const API_ID   = 'snallygaster';
    private const API_NAME = 'Snallygaster Exposed File Scanner';
    private const SUPPORTED = ['domain', 'url'];

    // 100+ probe paths organized by category
    private const PROBE_FILES = [
        // ── Version Control ────────────────────────────────────────────
        '/.git/HEAD'           => ['risk' => 'critical', 'desc' => 'Git repository HEAD',         'confirm' => 'ref:',    'cat' => 'vcs'],
        '/.git/config'         => ['risk' => 'critical', 'desc' => 'Git config (may contain creds)', 'confirm' => '[core]', 'cat' => 'vcs'],
        '/.git/index'          => ['risk' => 'critical', 'desc' => 'Git index file',               'confirm' => null,     'cat' => 'vcs'],
        '/.gitignore'          => ['risk' => 'low',      'desc' => 'Git ignore rules',              'confirm' => null,     'cat' => 'vcs'],
        '/.svn/entries'        => ['risk' => 'critical', 'desc' => 'SVN repository entries',        'confirm' => null,     'cat' => 'vcs'],
        '/.svn/wc.db'          => ['risk' => 'critical', 'desc' => 'SVN working copy database',     'confirm' => null,     'cat' => 'vcs'],
        '/.hg/dirstate'        => ['risk' => 'critical', 'desc' => 'Mercurial repository state',    'confirm' => null,     'cat' => 'vcs'],
        '/.bzr/README'         => ['risk' => 'high',     'desc' => 'Bazaar repository',             'confirm' => null,     'cat' => 'vcs'],
        '/CVS/Root'            => ['risk' => 'high',     'desc' => 'CVS root file',                 'confirm' => null,     'cat' => 'vcs'],

        // ── Environment & Config Files ─────────────────────────────────
        '/.env'                => ['risk' => 'critical', 'desc' => 'Environment config with secrets', 'confirm' => '=',    'cat' => 'config'],
        '/.env.local'          => ['risk' => 'critical', 'desc' => 'Local environment config',        'confirm' => '=',    'cat' => 'config'],
        '/.env.production'     => ['risk' => 'critical', 'desc' => 'Production environment config',   'confirm' => '=',    'cat' => 'config'],
        '/.env.staging'        => ['risk' => 'critical', 'desc' => 'Staging environment config',      'confirm' => '=',    'cat' => 'config'],
        '/.env.backup'         => ['risk' => 'critical', 'desc' => 'Backup environment config',       'confirm' => '=',    'cat' => 'config'],
        '/.env.old'            => ['risk' => 'critical', 'desc' => 'Old environment config',          'confirm' => '=',    'cat' => 'config'],
        '/config.php'          => ['risk' => 'high',     'desc' => 'PHP config file',                 'confirm' => null,   'cat' => 'config'],
        '/config.yml'          => ['risk' => 'high',     'desc' => 'YAML config file',                'confirm' => null,   'cat' => 'config'],
        '/config.json'         => ['risk' => 'high',     'desc' => 'JSON config file',                'confirm' => null,   'cat' => 'config'],
        '/configuration.php'   => ['risk' => 'high',     'desc' => 'Configuration file',              'confirm' => null,   'cat' => 'config'],
        '/settings.php'        => ['risk' => 'high',     'desc' => 'Settings file (Drupal)',          'confirm' => null,   'cat' => 'config'],
        '/local_settings.py'   => ['risk' => 'high',     'desc' => 'Django local settings',           'confirm' => null,   'cat' => 'config'],
        '/application.yml'     => ['risk' => 'high',     'desc' => 'Spring application config',       'confirm' => null,   'cat' => 'config'],
        '/appsettings.json'    => ['risk' => 'high',     'desc' => '.NET app settings',               'confirm' => null,   'cat' => 'config'],

        // ── CMS-Specific Files ─────────────────────────────────────────
        '/wp-config.php'       => ['risk' => 'critical', 'desc' => 'WordPress config',                'confirm' => 'DB_',  'cat' => 'cms'],
        '/wp-config.php.bak'   => ['risk' => 'critical', 'desc' => 'WordPress config backup',         'confirm' => 'DB_',  'cat' => 'cms'],
        '/wp-config.php~'      => ['risk' => 'critical', 'desc' => 'WordPress config editor backup',  'confirm' => 'DB_',  'cat' => 'cms'],
        '/wp-config.php.save'  => ['risk' => 'critical', 'desc' => 'WordPress config save',           'confirm' => 'DB_',  'cat' => 'cms'],
        '/xmlrpc.php'          => ['risk' => 'medium',   'desc' => 'WordPress XML-RPC endpoint',      'confirm' => 'XML-RPC', 'cat' => 'cms'],
        '/wp-json/'            => ['risk' => 'low',      'desc' => 'WordPress REST API',              'confirm' => null,   'cat' => 'cms'],
        '/administrator/manifests/files/joomla.xml' => ['risk' => 'medium', 'desc' => 'Joomla version disclosure', 'confirm' => 'version', 'cat' => 'cms'],

        // ── Authentication Files ───────────────────────────────────────
        '/.htpasswd'           => ['risk' => 'critical', 'desc' => 'Apache password file',            'confirm' => ':',    'cat' => 'auth'],
        '/.htaccess'           => ['risk' => 'medium',   'desc' => 'Apache config file',              'confirm' => null,   'cat' => 'auth'],
        '/web.config'          => ['risk' => 'high',     'desc' => 'IIS web config',                  'confirm' => null,   'cat' => 'auth'],
        '/credentials.json'    => ['risk' => 'critical', 'desc' => 'Credentials JSON file',           'confirm' => null,   'cat' => 'auth'],
        '/secrets.json'        => ['risk' => 'critical', 'desc' => 'Secrets JSON file',               'confirm' => null,   'cat' => 'auth'],
        '/id_rsa'              => ['risk' => 'critical', 'desc' => 'SSH private key',                 'confirm' => 'PRIVATE KEY', 'cat' => 'auth'],
        '/id_rsa.pub'          => ['risk' => 'medium',   'desc' => 'SSH public key',                  'confirm' => 'ssh-rsa',    'cat' => 'auth'],

        // ── Server Status & Info ───────────────────────────────────────
        '/server-status'       => ['risk' => 'high',     'desc' => 'Apache server status',            'confirm' => 'Apache',     'cat' => 'server'],
        '/server-info'         => ['risk' => 'high',     'desc' => 'Apache server info',              'confirm' => 'Apache',     'cat' => 'server'],
        '/nginx_status'        => ['risk' => 'high',     'desc' => 'Nginx status page',               'confirm' => 'Active connections', 'cat' => 'server'],
        '/phpinfo.php'         => ['risk' => 'high',     'desc' => 'PHP info page',                   'confirm' => 'phpinfo',    'cat' => 'server'],
        '/info.php'            => ['risk' => 'high',     'desc' => 'PHP info page (alt)',              'confirm' => 'phpinfo',    'cat' => 'server'],
        '/test.php'            => ['risk' => 'medium',   'desc' => 'Test PHP file',                   'confirm' => null,         'cat' => 'server'],
        '/status'              => ['risk' => 'medium',   'desc' => 'Status endpoint',                 'confirm' => null,         'cat' => 'server'],
        '/_status'             => ['risk' => 'medium',   'desc' => 'Status endpoint (underscore)',     'confirm' => null,         'cat' => 'server'],

        // ── Database Files ─────────────────────────────────────────────
        '/dump.sql'            => ['risk' => 'critical', 'desc' => 'SQL dump file',                   'confirm' => null,         'cat' => 'database'],
        '/backup.sql'          => ['risk' => 'critical', 'desc' => 'SQL backup file',                 'confirm' => null,         'cat' => 'database'],
        '/database.sql'        => ['risk' => 'critical', 'desc' => 'Database SQL file',               'confirm' => null,         'cat' => 'database'],
        '/db.sql'              => ['risk' => 'critical', 'desc' => 'DB SQL file',                     'confirm' => null,         'cat' => 'database'],
        '/data.sql'            => ['risk' => 'critical', 'desc' => 'Data SQL file',                   'confirm' => null,         'cat' => 'database'],
        '/mysql.sql'           => ['risk' => 'critical', 'desc' => 'MySQL dump file',                 'confirm' => null,         'cat' => 'database'],
        '/db.sqlite'           => ['risk' => 'critical', 'desc' => 'SQLite database',                 'confirm' => null,         'cat' => 'database'],
        '/database.sqlite'     => ['risk' => 'critical', 'desc' => 'SQLite database',                 'confirm' => null,         'cat' => 'database'],
        '/phpmyadmin/'         => ['risk' => 'high',     'desc' => 'phpMyAdmin interface',             'confirm' => 'phpMyAdmin', 'cat' => 'database'],
        '/adminer.php'         => ['risk' => 'high',     'desc' => 'Adminer database manager',        'confirm' => 'Adminer',    'cat' => 'database'],

        // ── Backup Files ───────────────────────────────────────────────
        '/backup.zip'          => ['risk' => 'critical', 'desc' => 'Backup ZIP archive',              'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/backup.tar.gz'       => ['risk' => 'critical', 'desc' => 'Backup tar.gz archive',           'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/site.zip'            => ['risk' => 'critical', 'desc' => 'Site ZIP archive',                 'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/www.zip'             => ['risk' => 'critical', 'desc' => 'WWW ZIP archive',                  'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/public.zip'          => ['risk' => 'critical', 'desc' => 'Public ZIP archive',               'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/html.zip'            => ['risk' => 'critical', 'desc' => 'HTML ZIP archive',                 'confirm' => null, 'cat' => 'backup', 'binary' => true],
        '/backup.rar'          => ['risk' => 'critical', 'desc' => 'Backup RAR archive',               'confirm' => null, 'cat' => 'backup', 'binary' => true],

        // ── Package Manager Files ──────────────────────────────────────
        '/composer.json'       => ['risk' => 'medium',   'desc' => 'PHP Composer manifest',           'confirm' => 'require', 'cat' => 'package'],
        '/composer.lock'       => ['risk' => 'medium',   'desc' => 'PHP Composer lockfile',           'confirm' => 'packages','cat' => 'package'],
        '/package.json'        => ['risk' => 'medium',   'desc' => 'Node.js package manifest',        'confirm' => null,      'cat' => 'package'],
        '/package-lock.json'   => ['risk' => 'low',      'desc' => 'Node.js lockfile',                'confirm' => null,      'cat' => 'package'],
        '/yarn.lock'           => ['risk' => 'low',      'desc' => 'Yarn lockfile',                   'confirm' => null,      'cat' => 'package'],
        '/Gemfile'             => ['risk' => 'medium',   'desc' => 'Ruby Gemfile',                    'confirm' => 'gem',     'cat' => 'package'],
        '/Gemfile.lock'        => ['risk' => 'low',      'desc' => 'Ruby Gemfile lock',               'confirm' => null,      'cat' => 'package'],
        '/requirements.txt'    => ['risk' => 'medium',   'desc' => 'Python requirements',             'confirm' => null,      'cat' => 'package'],
        '/Pipfile'             => ['risk' => 'medium',   'desc' => 'Python Pipfile',                  'confirm' => null,      'cat' => 'package'],
        '/go.mod'              => ['risk' => 'low',      'desc' => 'Go module file',                  'confirm' => 'module',  'cat' => 'package'],
        '/Cargo.toml'          => ['risk' => 'low',      'desc' => 'Rust Cargo manifest',             'confirm' => null,      'cat' => 'package'],

        // ── CI/CD & DevOps ─────────────────────────────────────────────
        '/.github/workflows/'  => ['risk' => 'medium',   'desc' => 'GitHub Actions workflows',        'confirm' => null,      'cat' => 'cicd'],
        '/.gitlab-ci.yml'      => ['risk' => 'medium',   'desc' => 'GitLab CI config',                'confirm' => null,      'cat' => 'cicd'],
        '/Jenkinsfile'         => ['risk' => 'medium',   'desc' => 'Jenkins pipeline config',          'confirm' => null,      'cat' => 'cicd'],
        '/Dockerfile'          => ['risk' => 'medium',   'desc' => 'Docker build file',                'confirm' => 'FROM',   'cat' => 'cicd'],
        '/docker-compose.yml'  => ['risk' => 'high',     'desc' => 'Docker Compose config (may have secrets)', 'confirm' => null, 'cat' => 'cicd'],
        '/.dockerenv'          => ['risk' => 'medium',   'desc' => 'Docker environment indicator',     'confirm' => null,     'cat' => 'cicd'],
        '/Vagrantfile'         => ['risk' => 'medium',   'desc' => 'Vagrant configuration',            'confirm' => null,     'cat' => 'cicd'],
        '/.travis.yml'         => ['risk' => 'low',      'desc' => 'Travis CI config',                 'confirm' => null,     'cat' => 'cicd'],
        '/terraform.tfstate'   => ['risk' => 'critical', 'desc' => 'Terraform state (contains secrets)', 'confirm' => 'terraform', 'cat' => 'cicd'],
        '/ansible.cfg'         => ['risk' => 'medium',   'desc' => 'Ansible configuration',            'confirm' => null,     'cat' => 'cicd'],

        // ── Debug & Error Pages ────────────────────────────────────────
        '/elmah.axd'           => ['risk' => 'high',     'desc' => 'ASP.NET error log viewer',         'confirm' => 'Error',  'cat' => 'debug'],
        '/debug'               => ['risk' => 'high',     'desc' => 'Debug endpoint',                   'confirm' => null,     'cat' => 'debug'],
        '/trace.axd'           => ['risk' => 'high',     'desc' => 'ASP.NET trace viewer',             'confirm' => null,     'cat' => 'debug'],
        '/actuator'            => ['risk' => 'high',     'desc' => 'Spring Boot actuator',             'confirm' => null,     'cat' => 'debug'],
        '/actuator/env'        => ['risk' => 'critical', 'desc' => 'Spring actuator env (secrets)',     'confirm' => null,     'cat' => 'debug'],
        '/actuator/heapdump'   => ['risk' => 'critical', 'desc' => 'Spring heap dump',                 'confirm' => null,     'cat' => 'debug', 'binary' => true],
        '/_debugbar'           => ['risk' => 'high',     'desc' => 'Laravel debugbar',                  'confirm' => null,     'cat' => 'debug'],
        '/__debug__/'          => ['risk' => 'high',     'desc' => 'Django debug toolbar',              'confirm' => null,     'cat' => 'debug'],

        // ── API Documentation ──────────────────────────────────────────
        '/swagger-ui.html'     => ['risk' => 'medium',   'desc' => 'Swagger UI',                       'confirm' => 'swagger','cat' => 'api_docs'],
        '/swagger-ui/'         => ['risk' => 'medium',   'desc' => 'Swagger UI directory',              'confirm' => null,     'cat' => 'api_docs'],
        '/api-docs'            => ['risk' => 'medium',   'desc' => 'API documentation',                 'confirm' => null,     'cat' => 'api_docs'],
        '/v1/api-docs'         => ['risk' => 'medium',   'desc' => 'API docs (v1)',                     'confirm' => null,     'cat' => 'api_docs'],
        '/v2/api-docs'         => ['risk' => 'medium',   'desc' => 'API docs (v2)',                     'confirm' => null,     'cat' => 'api_docs'],
        '/openapi.json'        => ['risk' => 'medium',   'desc' => 'OpenAPI specification',             'confirm' => null,     'cat' => 'api_docs'],
        '/graphiql'            => ['risk' => 'medium',   'desc' => 'GraphiQL IDE',                      'confirm' => null,     'cat' => 'api_docs'],
        '/graphql/playground'  => ['risk' => 'medium',   'desc' => 'GraphQL Playground',                'confirm' => null,     'cat' => 'api_docs'],

        // ── Cross-Domain Policy ────────────────────────────────────────
        '/crossdomain.xml'     => ['risk' => 'medium',   'desc' => 'Flash cross-domain policy',         'confirm' => 'cross-domain', 'cat' => 'policy'],
        '/clientaccesspolicy.xml' => ['risk' => 'medium','desc' => 'Silverlight access policy',         'confirm' => null,          'cat' => 'policy'],
        '/.well-known/security.txt' => ['risk' => 'info','desc' => 'Security contact (good practice)',  'confirm' => 'Contact',     'cat' => 'policy'],
        '/robots.txt'          => ['risk' => 'info',     'desc' => 'Robots exclusion file',             'confirm' => null,          'cat' => 'policy'],
        '/sitemap.xml'         => ['risk' => 'info',     'desc' => 'Sitemap XML',                       'confirm' => 'urlset',      'cat' => 'policy'],

        // ── Log Files ──────────────────────────────────────────────────
        '/error.log'           => ['risk' => 'high',     'desc' => 'Error log file',                    'confirm' => null, 'cat' => 'logs'],
        '/access.log'          => ['risk' => 'high',     'desc' => 'Access log file',                   'confirm' => null, 'cat' => 'logs'],
        '/debug.log'           => ['risk' => 'high',     'desc' => 'Debug log file',                    'confirm' => null, 'cat' => 'logs'],
        '/app.log'             => ['risk' => 'high',     'desc' => 'Application log',                   'confirm' => null, 'cat' => 'logs'],
        '/laravel.log'         => ['risk' => 'high',     'desc' => 'Laravel log file',                  'confirm' => null, 'cat' => 'logs'],
        '/storage/logs/laravel.log' => ['risk' => 'high','desc' => 'Laravel storage log',               'confirm' => null, 'cat' => 'logs'],
        '/npm-debug.log'       => ['risk' => 'medium',   'desc' => 'NPM debug log',                    'confirm' => null, 'cat' => 'logs'],

        // ── Cloud Config ───────────────────────────────────────────────
        '/.aws/credentials'    => ['risk' => 'critical', 'desc' => 'AWS credentials file',              'confirm' => 'aws_', 'cat' => 'cloud'],
        '/.aws/config'         => ['risk' => 'high',     'desc' => 'AWS config file',                   'confirm' => null,   'cat' => 'cloud'],
        '/firebase.json'       => ['risk' => 'high',     'desc' => 'Firebase config',                   'confirm' => null,   'cat' => 'cloud'],
        '/.firebase'           => ['risk' => 'medium',   'desc' => 'Firebase directory',                'confirm' => null,   'cat' => 'cloud'],

        // ── Miscellaneous ──────────────────────────────────────────────
        '/.DS_Store'           => ['risk' => 'low',      'desc' => 'macOS directory metadata',           'confirm' => null, 'cat' => 'misc', 'binary' => true],
        '/Thumbs.db'           => ['risk' => 'low',      'desc' => 'Windows thumbnail cache',            'confirm' => null, 'cat' => 'misc', 'binary' => true],
        '/.vscode/settings.json' => ['risk' => 'medium', 'desc' => 'VS Code workspace settings',        'confirm' => null, 'cat' => 'misc'],
        '/.idea/workspace.xml' => ['risk' => 'medium',   'desc' => 'JetBrains workspace config',        'confirm' => null, 'cat' => 'misc'],
        '/TODO'                => ['risk' => 'low',      'desc' => 'TODO file (may contain internal info)', 'confirm' => null, 'cat' => 'misc'],
        '/CHANGELOG'           => ['risk' => 'info',     'desc' => 'Changelog file',                     'confirm' => null, 'cat' => 'misc'],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        $targetBase = $value;
        if ($queryType === 'domain') $targetBase = 'https://' . $value;
        if (!preg_match('#^https?://#i', $targetBase)) $targetBase = 'https://' . $targetBase;
        $targetBase = rtrim($targetBase, '/');

        try {
            $exposed = [];
            $checked = 0;
            $securityTxt = false;

            foreach (self::PROBE_FILES as $path => $info) {
                $probeUrl = $targetBase . $path;
                $resp = HttpClient::get($probeUrl, [], 5, 0);
                $checked++;

                if ($resp['status'] !== 200 || $resp['error']) continue;

                $body = $resp['body'] ?? '';
                $bodyLen = strlen($body);
                if ($bodyLen < 3) continue;

                // Skip custom 404 pages
                $bodyLower = strtolower($body);
                if (strpos($bodyLower, 'not found') !== false && strpos($bodyLower, '404') !== false) continue;
                if (strpos($bodyLower, '<title>404') !== false) continue;

                // For binary files, just check they exist and have content
                $isBinary = $info['binary'] ?? false;

                // Confirm content if confirmation string is set
                $confirmStr = $info['confirm'] ?? null;
                if (!$isBinary && $confirmStr !== null && stripos($body, $confirmStr) === false) continue;

                if ($path === '/.well-known/security.txt') $securityTxt = true;

                $exposed[] = [
                    'path'        => $path,
                    'size'        => $bodyLen,
                    'risk'        => $info['risk'],
                    'description' => $info['desc'],
                    'category'    => $info['cat'],
                    'preview'     => $isBinary ? '[binary data]' : mb_substr(trim($body), 0, 100),
                ];
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $exposedCount = count($exposed);

            if ($exposedCount === 0) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 80,
                    responseMs: $ms,
                    summary: "No exposed sensitive files found ({$checked} paths probed).",
                    tags: [self::API_ID, $queryType, 'clean'],
                    rawData: ['checked' => $checked, 'exposed' => []],
                    success: true
                );
            }

            // Score and categorize
            $maxScore = 0;
            $criticalFiles = [];
            $byCat = [];
            $byRisk = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];

            foreach ($exposed as $item) {
                $risk = $item['risk'];
                $byRisk[$risk] = ($byRisk[$risk] ?? 0) + 1;
                $byCat[$item['category']] = ($byCat[$item['category']] ?? 0) + 1;

                $itemScore = match ($risk) {
                    'critical' => 90,
                    'high'     => 70,
                    'medium'   => 45,
                    'low'      => 15,
                    default    => 0,
                };
                $maxScore = max($maxScore, $itemScore);
                if ($risk === 'critical') $criticalFiles[] = $item['path'];
            }

            // If only info/security.txt found, don't inflate score
            if ($exposedCount === 1 && $securityTxt) $maxScore = 0;
            if ($exposedCount === 1 && $exposed[0]['risk'] === 'info') $maxScore = 0;

            $severity = OsintResult::scoreToSeverity($maxScore);
            $confidence = min(90, 75 + $exposedCount);

            $summary = "{$exposedCount} exposed file(s) found ({$checked} probed).";
            if ($byRisk['critical'] > 0) $summary .= " CRITICAL: {$byRisk['critical']}.";
            if ($byRisk['high'] > 0) $summary .= " High: {$byRisk['high']}.";

            arsort($byCat);
            $catParts = [];
            foreach ($byCat as $c => $n) $catParts[] = "{$c}: {$n}";
            $summary .= ' Categories: ' . implode(', ', $catParts) . '.';

            if (!empty($criticalFiles)) {
                $summary .= ' Critical: ' . implode(', ', array_slice($criticalFiles, 0, 5)) . '.';
            }

            $resultTags = [self::API_ID, $queryType, 'exposed_files'];
            if (!empty($criticalFiles)) $resultTags[] = 'critical_exposure';
            if ($securityTxt) $resultTags[] = 'security_txt';
            foreach (array_keys($byCat) as $c) $resultTags[] = $c;

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $maxScore, severity: $severity, confidence: $confidence,
                responseMs: $ms,
                summary: $summary,
                tags: array_values(array_unique($resultTags)),
                rawData: [
                    'checked'       => $checked,
                    'exposed_count' => $exposedCount,
                    'by_risk'       => array_filter($byRisk),
                    'by_category'   => $byCat,
                    'exposed'       => $exposed,
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
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null, 'probe_count' => count(self::PROBE_FILES)];
    }
}
