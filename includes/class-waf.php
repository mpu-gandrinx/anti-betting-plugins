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
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/str_rot13\s*\(/i',
        '/shell_exec\s*\(/i',
        '/passthru\s*\(/i',
        '/system\s*\(/i',
        '/assert\s*\(/i',
        '/\b(?:phtml|php[34578]|phar)\b.*(?:upload|tmp)/i',
        '/<\?php.*(eval|base64_decode|assert)/is'
    ];

    public function __construct(?AJS_AI $ai = null) {
        $this->ai = $ai;
        $this->bind_hooks();
    }

    private function bind_hooks(): void {
        add_action('init', [$this, 'inspect_request'], 1);

        if ((int)get_option('ajs_block_xmlrpc', 1) === 1) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_action('init', [$this, 'block_xmlrpc_endpoint'], 1);
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

        if (is_admin() && current_user_can('manage_options')) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $query_string = isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';

        // 1. Inspect URI & Query String
        $target = urldecode($uri . ' ' . $query_string);
        $matched_keyword = $this->check_judol_keywords($target);
        if ($matched_keyword) {
            $this->block_request('Judol Keyword in URL', $matched_keyword);
        }

        // 2. Inspect Payload patterns in GET & POST
        $raw_post = file_get_contents('php://input');
        $check_data = array_merge($_GET, $_POST);

        foreach ($check_data as $key => $val) {
            $str_val = is_array($val) ? json_encode($val) : (string)$val;
            $matched_payload = $this->check_malicious_payload($str_val);
            if ($matched_payload) {
                $this->block_request('Malicious Code Injection', $matched_payload);
            }

            $matched_kw = $this->check_judol_keywords($str_val);
            if ($matched_kw) {
                $this->block_request('Judol Payload Parameter', $matched_kw);
            }
        }

        if (!empty($raw_post)) {
            $matched_raw = $this->check_malicious_payload($raw_post);
            if ($matched_raw) {
                $this->block_request('Raw Body Code Injection', $matched_raw);
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

        // Send instant notification for critical intrusions
        if (stripos($reason, 'Injection') !== false || stripos($reason, 'Cloaked') !== false || stripos($reason, 'Lockout') !== false) {
            AJS_Notifications::send_alert(
                "Ancaman Diblokir: {$reason}",
                "IP: {$ip}\nReason: {$reason}\nPayload: " . substr($payload, 0, 200),
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
        <h1>403 Akses Ditolak</h1>
        <p>Aktivitas jaringan Anda memicu sistem pertahanan <strong>Anti-Judol Shield WAF</strong>. Permintaan diblokir demi keamanan integritas web.</p>
        <div class="badge">IP: ' . esc_html($ip) . ' | Event: ' . esc_html($reason) . '</div>
        <div class="footer">Protected by Anti-Judol Shield &bull; BPTSI</div>
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

    public function get_client_ip(): string {
        $ip_keys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}
