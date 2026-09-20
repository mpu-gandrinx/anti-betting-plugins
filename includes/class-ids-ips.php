<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_IDS_IPS {
    private int $ban_threshold = 100;
    private int $ban_duration = 86400; // 24 hours

    private array $probe_patterns = [
        'Webshell Probe' => '/\/(?:alfa|wso|c99|r57|b374k|shell|cmd|up|uploader|bypass|indoxploit|adminer|alfa_data|priv8|maro|madspot)\.(?:php|phtml|phar)/i',
        'Sensitive File Probe' => '/(?:\.env|\.git|\.aws|wp-config\.php(?:\.bak|\.old|\.swp|~|_old)|\.sql(?:\.gz)?)$/i',
        'Path Traversal' => '/(?:\.\.[\/\\\\]|%2e%2e[\/\\\\])/i',
        'SQL Injection Probe' => '/\b(?:union(?:\s+all)?\s+select|information_schema|load_file|into\s+(?:dump|out)file|benchmark\s*\(|sleep\s*\()\b/i',
        'XSS Vector Probe' => '/<script\b[^>]*>|javascript:\s*|on(?:error|load|click|mouseover)\s*=/i',
    ];

    public function __construct() {
        $this->ban_threshold = (int)get_option('ajs_ips_threshold', 100);
        $this->ban_duration  = (int)get_option('ajs_ips_ban_duration', 86400);

        add_action('init', [$this, 'inspect_and_enforce'], 0);
    }

    public function inspect_and_enforce(): void {
        $ip = $this->get_client_ip();

        if ($this->is_whitelisted($ip)) {
            return;
        }

        // 1. Enforce IPS Drop if IP is currently banned
        if ($this->is_banned($ip)) {
            $this->drop_connection($ip, 'IPS Active Ban');
        }

        if (is_admin() && current_user_can('manage_options')) {
            return;
        }

        // 2. IDS Behavioral & Signature Analysis
        $request_uri  = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $raw_post     = @file_get_contents('php://input');

        $check_target = urldecode(urldecode($request_uri . ' ' . $query_string . ' ' . substr((string)$raw_post, 0, 2000)));

        foreach ($this->probe_patterns as $rule_name => $pattern) {
            if (preg_match($pattern, $check_target)) {
                $is_critical = ($rule_name === 'Webshell Probe' || $rule_name === 'SQL Injection Probe');
                $score = $is_critical ? 100 : 50;
                $this->add_anomaly_score($ip, $score, $rule_name, $is_critical);
                break;
            }
        }
    }

    public function add_anomaly_score(string $ip, int $score, string $reason, bool $force_immediate_ban = false): void {
        $transient_key = 'ajs_score_' . md5($ip);
        $current_score = (int)get_transient($transient_key) ?: 0;
        $new_score = $current_score + $score;

        set_transient($transient_key, $new_score, 3600); // 1 hour score decay window

        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';

        $wpdb->insert(
            $table_name,
            [
                'ip_address'     => substr($ip, 0, 45),
                'reason'         => "IDS Anomaly (+{$score}): {$reason}",
                'threat_payload' => "Cumulative Score: {$new_score}/{$this->ban_threshold}",
                'request_uri'    => substr($_SERVER['REQUEST_URI'] ?? '', 0, 500),
                'user_agent'     => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
                'created_at'     => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );

        if ($force_immediate_ban || $new_score >= $this->ban_threshold) {
            $this->ban_ip($ip, $this->ban_duration, "Kritis/Batas Skor Terlampaui ({$reason})");
            $this->drop_connection($ip, "IPS Auto-Banned ({$reason})");
        }
    }

    public function ban_ip(string $ip, int $duration, string $reason = 'IPS Rule Violation'): void {
        $banned = get_option('ajs_banned_ips_list', []);
        $banned[$ip] = [
            'reason'     => $reason,
            'banned_at'  => current_time('mysql'),
            'expires_at' => date('Y-m-d H:i:s', time() + $duration),
        ];

        update_option('ajs_banned_ips_list', $banned);

        AJS_Notifications::send_alert(
            "IPS Auto-Ban Enforced: {$ip}",
            "IP {$ip} otomatis diblokir selama " . round($duration / 3600) . " jam.\nAlasan: {$reason}",
            'CRITICAL'
        );
    }

    public function unban_ip(string $ip): bool {
        $banned = get_option('ajs_banned_ips_list', []);
        if (isset($banned[$ip])) {
            unset($banned[$ip]);
            update_option('ajs_banned_ips_list', $banned);
            delete_transient('ajs_score_' . md5($ip));
            return true;
        }
        return false;
    }

    public function is_banned(string $ip): bool {
        $banned = get_option('ajs_banned_ips_list', []);
        if (!isset($banned[$ip])) {
            return false;
        }

        $meta = $banned[$ip];
        if (strtotime($meta['expires_at']) < time()) {
            $this->unban_ip($ip);
            return false;
        }

        return true;
    }

    public function is_whitelisted(string $ip): bool {
        $whitelist = get_option('ajs_ip_whitelist', []);
        if (!is_array($whitelist)) {
            $whitelist = array_filter(array_map('trim', explode("\n", (string)$whitelist)));
        }
        return in_array($ip, $whitelist, true) || $ip === '127.0.0.1' || $ip === '::1';
    }

    private function drop_connection(string $ip, string $reason): void {
        status_header(403);
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');

        echo '<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>403 Connection Dropped - Anti-Judol IPS</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .box { background: #111827; padding: 36px; border-radius: 12px; max-width: 520px; text-align: center; border: 1px solid #b91c1c; box-shadow: 0 10px 30px rgba(0,0,0,0.7); }
        h1 { color: #f87171; font-size: 24px; margin-top: 0; }
        p { color: #9ca3af; font-size: 14px; line-height: 1.6; }
        .ip-badge { background: #1f2937; color: #facc15; padding: 6px 12px; border-radius: 6px; font-size: 13px; display: inline-block; margin: 12px 0; font-family: monospace; }
        .foot { color: #4b5563; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="box">
        <h1>403 Akses Ditolak oleh IPS</h1>
        <p>Sistem <strong>Intrusion Prevention System (IPS)</strong> memutus sambungan IP Anda karena terdeteksi aktivitas pemindaian/serangan berulang.</p>
        <div class="ip-badge">IP: ' . esc_html($ip) . ' | Status: ' . esc_html($reason) . '</div>
        <div class="foot">Protected by Anti-Judol Shield &bull; Enterprise Defense</div>
    </div>
</body>
</html>';
        exit;
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
