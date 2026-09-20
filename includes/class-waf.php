<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_WAF {
    private ?AJS_AI $ai;

    private array $default_keywords = [
        'slot gacor', 'slot online', 'judi online', 'maxwin', 'pragmatic play',
        'toto togel', 'bandar togel', 'agen bola', 'sbobet', 'depo pulsa',
        'bocoran rtp', 'rtp live', 'scatter hitam', 'mahjong ways', 'gates of olympus',
        'kakek zeus', 'link alternatif', 'situs judi', 'daftar slot', 'taruhan bola',
        'casino online', 'poker online', 'jackpot paus', 'gampang menang'
    ];

    private array $dangerous_payloads = [
        // 1. RCE & Bahaya Eksekusi Perintah Sistem
        '/(?:eval|assert|passthru|shell_exec|system|popen|proc_open|pcntl_exec)\s*\(/i',
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/gzuncompress\s*\(/i',
        '/str_rot13\s*\(/i',
        '/hex2bin\s*\(/i',
        '/preg_replace\s*\(\s*["\'].*\/e["\']/i',
        '/create_function\s*\(/i',
        '/\b(?:call_user_func|call_user_func_array|array_map|array_filter|usort|uasort)\s*\(\s*[\'"]*(?:system|exec|passthru|shell_exec|assert|eval)/i',

        // 2. Dynamic Variable Function & Backtick Execution
        '/\$(?:_GET|_POST|_REQUEST|_COOKIE)\[[^\]]+\]\s*\(/i',
        '/`[^`]*\$(?:_GET|_POST|_REQUEST|_COOKIE)[^`]*`/i',

        // 3. PHP Protocol Wrappers (LFI/RFI/SSRF)
        '/php:\/\/(?:input|filter|memory)/i',
        '/data:\/\/(?:text\/plain|application)/i',
        '/phar:\/\//i',
        '/zip:\/\/.*#.*\.php/i',

        // 4. Injeksi Tag PHP Terbuka / Polyglot Webshell
        '/<\?php\s*(?:eval|base64_decode|assert|system|passthru|shell_exec|\$_)/is',
        '/<\?=\s*(?:eval|base64_decode|assert|system|passthru|shell_exec|\$_)/is',

        // 5. Pola SQL Injection Berbahaya
        '/\b(?:union\s+(?:all\s+)?select|into\s+(?:dump|out)file|load_file\s*\(|benchmark\s*\(|sleep\s*\()\b/i',

        // 6. Path Traversal & Directory Traversal
        '/(?:\.\.[\/\\\\]|%2e%2e[\/\\\\]|%252e%252e[\/\\\\])/i',

        // 7. Eksekusi File Skrip Berbahaya
        '/\b(?:phtml|php[34578]|phar)\b.*(?:upload|tmp)/i',
        '/\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:https?|ftp|php|data):/i'
    ];

    public function __construct(?AJS_AI $ai = null) {
        $this->ai = $ai;
        $this->bind_hooks();
    }

    private function bind_hooks(): void {
        // Jalankan inspeksi sedini mungkin (plugins_loaded & init prioritas tertinggi)
        add_action('plugins_loaded', [$this, 'inspect_request'], -9999);
        add_action('init', [$this, 'inspect_request'], -9999);

        // Filter proteksi upload berkas secara real-time
        add_filter('wp_handle_upload_prefilter', [$this, 'inspect_file_upload']);

        // Kunci akses editor berkas PHP bawaan dashboard WordPress
        add_action('admin_init', [$this, 'block_file_editor_access']);

        if ((int)get_option('ajs_block_xmlrpc', 1) === 1) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_action('init', [$this, 'block_xmlrpc_endpoint'], -9999);
        }

        if ((int)get_option('ajs_block_author_enum', 1) === 1) {
            add_action('request', [$this, 'block_author_scan']);
            add_filter('rest_endpoints', [$this, 'restrict_users_rest_endpoint']);
        }

        if ((int)get_option('ajs_rate_limit_login', 1) === 1) {
            add_action('wp_login_failed', [$this, 'record_login_failure']);
            add_filter('authenticate', [$this, 'check_login_lockout'], 25, 3);
        }

        if ((int)get_option('ajs_anti_spam_comments', 1) === 1) {
            add_filter('preprocess_comment', [$this, 'filter_spam_comment']);
        }

        if ((int)get_option('ajs_anti_spam_post_filter', 1) === 1) {
            add_filter('wp_insert_post_data', [$this, 'filter_post_content'], 10, 2);
        }

        // Proteksi intersepsi pembuatan & eskalasi role administrator ilegal
        add_action('user_register', [$this, 'guard_user_registration'], 1);
        add_action('set_user_role', [$this, 'guard_user_role_change'], 1, 3);

        // Cloaking & SEO Poisoning redirect protection
        add_filter('wp_redirect', [$this, 'guard_redirects'], 1, 2);
        add_action('template_redirect', [$this, 'start_output_cloaking_guard'], 1);
    }

    public function guard_redirects(string $location, int $status): string {
        $matched = $this->check_judol_keywords($location);
        if ($matched) {
            $this->block_request('Cloaked Judol Redirect', "Target: {$location}");
        }

        // Detect conditional redirection to external domains from search referrers
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $target_host = wp_parse_url($location, PHP_URL_HOST);

        if (!empty($target_host) && $target_host !== $home_host) {
            $search_engines = ['google.', 'bing.', 'yahoo.', 'yandex.'];
            foreach ($search_engines as $se) {
                if (stripos($referer, $se) !== false) {
                    $this->block_request('Suspicious Search Engine Referer Redirect', "To: {$location}");
                }
            }
        }

        return $location;
    }

    public function start_output_cloaking_guard(): void {
        if (!is_admin()) {
            ob_start([$this, 'filter_output_buffer']);
        }
    }

    public function filter_output_buffer(string $html): string {
        // Inspect rendered HTML for hidden doorway spam or obfuscated casino scripts
        if (strlen($html) > 100) {
            // Check for hidden spam doorway markers
            $has_hidden_spam = preg_match('/<(?:div|span|p)[^>]*(?:display\s*:\s*none|left\s*:\s*-\s*9999px|visibility\s*:\s*hidden)[^>]*>.*?(?:slot|gacor|maxwin|togel|judi)/is', $html);
            if ($has_hidden_spam) {
                $this->log_security_event($this->get_client_ip(), 'SEO Cloaked Spam Cleaned', 'Hidden doorway gambling HTML detected in page rendering');
                // Strip the hidden spam elements before rendering to users/search engine crawlers
                $html = preg_replace('/<(?:div|span|p)[^>]*(?:display\s*:\s*none|left\s*:\s*-\s*9999px|visibility\s*:\s*hidden)[^>]*>.*?(?:slot|gacor|maxwin|togel|judi).*?<\/(?:div|span|p)>/is', '', $html);
            }
        }
        return $html;
    }

    public function inspect_request(): void {
        if ((int)get_option('ajs_waf_enabled', 1) !== 1) {
            return;
        }

        // Jangan blokir admin yang sudah terautentikasi resmi
        if (function_exists('is_user_logged_in') && is_user_logged_in() && function_exists('current_user_can') && current_user_can('manage_options')) {
            return;
        }

        $uri          = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
        $query_string = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
        $user_agent   = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';

        // 1. Periksa URI & Query String (antisipasi double/nested encoding)
        $target = urldecode(urldecode($uri . ' ' . $query_string));
        $matched_keyword = $this->check_judol_keywords($target);
        if ($matched_keyword) {
            $this->block_request('Judol Keyword in URL', $matched_keyword);
        }

        $matched_uri_payload = $this->check_malicious_payload($target);
        if ($matched_uri_payload) {
            $this->block_request('Malicious Payload in URI', $matched_uri_payload);
        }

        // 2. Periksa User-Agent dari injeksi payload
        if (!empty($user_agent)) {
            $matched_ua = $this->check_malicious_payload($user_agent);
            if ($matched_ua) {
                $this->block_request('Malicious User-Agent Payload', $matched_ua);
            }
        }

        // 3. Inspeksi Rekursif Parameter GET, POST, COOKIE, dan REQUEST
        $sources = [
            'GET'    => $_GET,
            'POST'   => $_POST,
            'COOKIE' => $_COOKIE,
        ];

        foreach ($sources as $source_name => $data) {
            $this->inspect_array_recursively($data, $source_name);
        }

        // 4. Inspeksi Raw Request Body (php://input) untuk JSON/XML payload injeksi
        $raw_post = @file_get_contents('php://input');
        if (!empty($raw_post) && strlen($raw_post) < 200000) {
            $matched_raw = $this->check_malicious_payload($raw_post);
            if ($matched_raw) {
                $this->block_request('Raw Body Code Injection', $matched_raw);
            }
            $matched_raw_kw = $this->check_judol_keywords($raw_post);
            if ($matched_raw_kw) {
                $this->block_request('Judol Raw Payload Body', $matched_raw_kw);
            }
        }
    }

    private function inspect_array_recursively($data, string $prefix = '', int $depth = 0): void {
        if ($depth > 5 || empty($data) || !is_array($data)) {
            return;
        }

        foreach ($data as $key => $val) {
            $current_key = $prefix ? "{$prefix}[{$key}]" : (string)$key;

            if (is_array($val)) {
                $this->inspect_array_recursively($val, $current_key, $depth + 1);
                continue;
            }

            $str_val = (string)$val;
            if (strlen($str_val) < 2) {
                continue;
            }

            $matched_payload = $this->check_malicious_payload($str_val);
            if ($matched_payload) {
                $this->block_request("Malicious Code Injection in {$current_key}", $matched_payload);
            }

            $matched_kw = $this->check_judol_keywords($str_val);
            if ($matched_kw) {
                $this->block_request("Judol Payload in {$current_key}", $matched_kw);
            }
        }
    }

    public function inspect_file_upload(array $file): array {
        $name = $file['name'] ?? '';
        $tmp  = $file['tmp_name'] ?? '';

        // Blokir ekstensi berbahaya dan double-extension (contoh: shell.php.jpg)
        $dangerous_exts = [
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8',
            'phps', 'phar', 'shtml', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'htaccess'
        ];
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

        if (in_array($ext, $dangerous_exts, true) || preg_match('/\.(?:php[34578]?|phtml|phar)\./i', $name)) {
            $ip = $this->get_client_ip();
            $this->log_security_event($ip, 'Malicious File Upload Blocked', "Filename: {$name}");
            $this->block_request('Malicious Executable Upload Attempt', "File: {$name}");
        }

        // Inspeksi mendalam (deep inspection) isi file: cari tag eksekusi PHP pada upload gambar/dokumen
        if (!empty($tmp) && file_exists($tmp) && is_readable($tmp)) {
            $handle = @fopen($tmp, 'rb');
            if ($handle) {
                $bytes = (string)@fread($handle, 4096);
                @fclose($handle);
                if (preg_match('/<\?(?:php|=)/i', $bytes) || stripos($bytes, '<script language="php"') !== false) {
                    $ip = $this->get_client_ip();
                    $this->log_security_event($ip, 'Embedded PHP in Upload Blocked', "Filename: {$name}");
                    $this->block_request('Polyglot Webshell Upload Detected', "Embedded PHP in {$name}");
                }
            }
        }

        return $file;
    }

    public function block_file_editor_access(): void {
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        global $pagenow;
        if ($pagenow === 'theme-editor.php' || $pagenow === 'plugin-editor.php') {
            wp_die(
                esc_html__('Akses Ditolak: Editor berkas tema & plugin dinonaktifkan oleh Anti-Judol Shield demi keamanan situs.', 'anti-judol-shield'),
                'Access Denied',
                ['response' => 403]
            );
        }
    }

    public function guard_user_role_change(int $user_id, string $role, array $old_roles): void {
        if ($role === 'administrator') {
            if (!is_user_logged_in() || !current_user_can('manage_options')) {
                $user = get_userdata($user_id);
                if ($user) {
                    $user->set_role('subscriber');
                }
                $ip = $this->get_client_ip();
                $this->block_request('Unauthorized Administrator Escalation', "User #{$user_id} promoted to admin without valid authorization.");
            }
        }
    }

    private function check_judol_keywords(string $content): ?string {
        if (empty($content)) {
            return null;
        }

        $keywords = $this->get_all_keywords();
        $lower_content = strtolower($content);

        foreach ($keywords as $kw) {
            $trimmed = trim(strtolower($kw));
            if (!empty($trimmed) && strpos($lower_content, $trimmed) !== false) {
                return $kw;
            }
        }

        return null;
    }

    private function check_malicious_payload(string $content): ?string {
        foreach ($this->dangerous_payloads as $pattern) {
            if (preg_match($pattern, $content)) {
                return $pattern;
            }
        }
        return null;
    }

    public function get_all_keywords(): array {
        $custom = (string)get_option('ajs_custom_keywords', '');
        if (empty($custom)) {
            return $this->default_keywords;
        }

        $custom_list = array_filter(array_map('trim', explode("\n", $custom)));
        return array_unique(array_merge($this->default_keywords, $custom_list));
    }

    public function block_xmlrpc_endpoint(): void {
        $req = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (stripos($req, 'xmlrpc.php') !== false) {
            $this->block_request('XML-RPC Access Denied', 'xmlrpc.php blocked');
        }
    }

    public function block_author_scan(array $query_vars): array {
        if (!is_admin() && isset($_REQUEST['author']) && is_numeric($_REQUEST['author'])) {
            $this->block_request('Author Enumeration Attempt', 'author scan id ' . intval($_REQUEST['author']));
        }
        return $query_vars;
    }

    public function restrict_users_rest_endpoint(array $endpoints): array {
        if (!is_user_logged_in() && isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (!is_user_logged_in() && isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    }

    public function record_login_failure(string $username): void {
        $ip = $this->get_client_ip();
        $transient_key = 'ajs_fail_login_' . md5($ip);
        $attempts = (int)get_transient($transient_key) ?: 0;
        $attempts++;

        $lockout_duration = (int)get_option('ajs_lockout_duration', 900);
        set_transient($transient_key, $attempts, $lockout_duration);

        $max_attempts = (int)get_option('ajs_max_login_attempts', 5);
        if ($attempts >= $max_attempts) {
            $this->log_security_event($ip, 'Brute Force Lockout', "User: {$username}, Attempts: {$attempts}");
        }
    }

    public function check_login_lockout($user, string $username, string $password) {
        $ip = $this->get_client_ip();
        $transient_key = 'ajs_fail_login_' . md5($ip);
        $attempts = (int)get_transient($transient_key) ?: 0;
        $max_attempts = (int)get_option('ajs_max_login_attempts', 5);

        if ($attempts >= $max_attempts) {
            return new WP_Error(
                'ajs_lockout',
                __('<strong>Akses Diblokir:</strong> Terlalu banyak percobaan login gagal dari IP ini. Coba lagi dalam 15 menit.', 'anti-judol-shield')
            );
        }

        return $user;
    }

    public function guard_user_registration(int $user_id): void {
        $user = get_userdata($user_id);
        if (!$user) {
            return;
        }

        // Cegah backdoor/exploit yang mendaftarkan user baru dengan role administrator tanpa login admin sah
        if (in_array('administrator', (array)$user->roles, true) && !current_user_can('manage_options')) {
            $user->set_role('subscriber');
            $ip = $this->get_client_ip();
            $this->log_security_event(
                $ip,
                'Rogue Admin Creation Blocked',
                "User #{$user_id} ({$user->user_login}) terdaftar sebagai admin tanpa hak akses sah. Role otomatis diturunkan ke subscriber."
            );
            AJS_Notifications::send_alert(
                '🚨 Intersepsi Pembuatan User Admin Ilegal!',
                "Sistem Anti-Judol Shield mendeteksi dan menggagalkan injeksi akun baru dengan role Administrator tanpa sesi login admin resmi.\nUser: {$user->user_login} (ID: {$user_id}, Email: {$user->user_email})\nRole otomatis diturunkan ke Subscriber.",
                'CRITICAL'
            );
        }
    }

    public function filter_spam_comment(array $commentdata): array {
        $content = $commentdata['comment_content'] ?? '';
        $author_url = $commentdata['comment_author_url'] ?? '';

        $matched = $this->check_judol_keywords($content . ' ' . $author_url);
        if ($matched) {
            $ip = $this->get_client_ip();
            $this->log_security_event($ip, 'Spam Comment Judol', "Keyword: {$matched}");
            wp_die(
                esc_html__('Komentar ditolak: Terdeteksi kata kunci terlarang judi online.', 'anti-judol-shield'),
                'Spam Blocked',
                ['response' => 403]
            );
        }

        // AI Screening for subtle / obfuscated comment spam
        if ($this->ai && $this->ai->is_configured()) {
            $ai_result = $this->ai->inspect_content($content . ' ' . $author_url);
            if (!empty($ai_result['is_threat'])) {
                $ip = $this->get_client_ip();
                $this->log_security_event($ip, 'AI Shield: Spam Comment', $ai_result['reason']);
                wp_die(
                    esc_html__('Komentar ditolak oleh AI Shield: Terdeteksi indikasi promosi judi online.', 'anti-judol-shield'),
                    'AI Spam Blocked',
                    ['response' => 403]
                );
            }
        }

        return $commentdata;
    }

    public function filter_post_content(array $data, array $postarr): array {
        // Prevent post title/content poisoning with judol keywords
        if (!current_user_can('administrator')) {
            $title = $data['post_title'] ?? '';
            $content = $data['post_content'] ?? '';

            $matched = $this->check_judol_keywords($title . ' ' . $content);
            if ($matched) {
                $ip = $this->get_client_ip();
                $this->log_security_event($ip, 'Post Injection Judol', "Keyword: {$matched}");
                wp_die(
                    esc_html__('Ditolak: Konten memuat istilah terlarang judi online.', 'anti-judol-shield'),
                    'Post Blocked',
                    ['response' => 403]
                );
            }

            // AI Screening for backdoor/injected post content
            if ($this->ai && $this->ai->is_configured()) {
                $ai_result = $this->ai->inspect_content($title . "\n" . $content);
                if (!empty($ai_result['is_threat'])) {
                    $ip = $this->get_client_ip();
                    $this->log_security_event($ip, 'AI Shield: Post Injection', $ai_result['reason']);
                    wp_die(
                        esc_html__('Ditolak oleh AI Shield: Konten terdeteksi memuat materi judi online atau backdoor.', 'anti-judol-shield'),
                        'AI Post Blocked',
                        ['response' => 403]
                    );
                }
            }
        }

        return $data;
    }

    public function block_request(string $reason, string $payload): void {
        $ip = $this->get_client_ip();
        $this->log_security_event($ip, $reason, $payload);

        // Auto-ban IP penyerang langsung ke daftar hitam IPS (24 jam)
        if ($ip !== '127.0.0.1' && $ip !== '::1' && $ip !== '0.0.0.0') {
            $whitelist = (string)get_option('ajs_ip_whitelist', '');
            $whitelisted_ips = array_filter(array_map('trim', explode("\n", $whitelist)));
            if (!in_array($ip, $whitelisted_ips, true)) {
                $banned = (array)get_option('ajs_banned_ips_list', []);
                $duration = (int)get_option('ajs_ips_ban_duration', 86400);
                $banned[$ip] = [
                    'reason'     => 'Firewall Auto-Drop: ' . $reason,
                    'banned_at'  => current_time('mysql'),
                    'expires_at' => date('Y-m-d H:i:s', time() + $duration),
                ];
                update_option('ajs_banned_ips_list', $banned);
            }
        }

        // Send instant notification for critical intrusions
        if (stripos($reason, 'Injection') !== false || stripos($reason, 'Cloaked') !== false || stripos($reason, 'Lockout') !== false || stripos($reason, 'Upload') !== false || stripos($reason, 'Escalation') !== false) {
            AJS_Notifications::send_alert(
                "Firewall Dropped Threat: {$reason}",
                "IP Penyerang: {$ip} (Otomatis Diblokir)\nReason: {$reason}\nPayload: " . substr($payload, 0, 200),
                'CRITICAL'
            );
        }

        status_header(403);
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');

        $html = '<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden - Anti-Judol Shield</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 32px; border-radius: 12px; max-width: 500px; text-align: center; border: 1px solid #dc2626; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1 { color: #ef4444; font-size: 24px; margin-bottom: 8px; }
        p { color: #94a3b8; font-size: 14px; line-height: 1.5; }
        .badge { display: inline-block; background: #334155; color: #38bdf8; padding: 4px 10px; border-radius: 6px; font-size: 12px; margin-top: 10px; }
        .footer { margin-top: 24px; font-size: 11px; color: #64748b; }
    </style>
</head>
<body>
    <div class="card">
        <h1>403 Akses Ditolak oleh Firewall</h1>
        <p>Aktivitas jaringan Anda memicu sistem pertahanan <strong>Anti-Judol Shield WAF</strong>. Akses diblokir dan IP Anda telah dimasukkan ke daftar isolasi keamanan.</p>
        <div class="badge">IP: ' . esc_html($ip) . ' | Event: ' . esc_html($reason) . '</div>
        <div class="footer">Protected by Anti-Judol Shield &bull; BPTSI Active Defense</div>
    </div>
</body>
</html>';

        echo $html;
        exit;
    }

    public function log_security_event(string $ip, string $reason, string $payload): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';

        $wpdb->insert(
            $table_name,
            [
                'ip_address'     => substr($ip, 0, 45),
                'reason'         => substr($reason, 0, 100),
                'threat_payload' => substr($payload, 0, 1000),
                'request_uri'    => substr($_SERVER['REQUEST_URI'] ?? '', 0, 500),
                'user_agent'     => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
                'created_at'     => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    public function is_cloudflare_ip(string $ip): bool {
        $cf_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ];
        $ip_long = ip2long($ip);
        if ($ip_long === false) {
            return false;
        }
        foreach ($cf_ranges as $range) {
            list($net, $mask) = explode('/', $range);
            $net_long = ip2long($net);
            $mask_long = ~((1 << (32 - (int)$mask)) - 1);
            if (($ip_long & $mask_long) === ($net_long & $mask_long)) {
                return true;
            }
        }
        return false;
    }

    public function get_client_ip(): string {
        $remote_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Hanya percaya HTTP_CF_CONNECTING_IP jika request valid dari Cloudflare atau token disetel
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $cf_token = get_option('ajs_cf_api_token', '');
            if (!empty($cf_token) || $this->is_cloudflare_ip($remote_ip)) {
                $cf_ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
                if (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
                    return $cf_ip;
                }
            }
        }

        if (filter_var($remote_ip, FILTER_VALIDATE_IP)) {
            return $remote_ip;
        }

        return '0.0.0.0';
    }
}
