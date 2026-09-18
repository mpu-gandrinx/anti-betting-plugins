<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Admin_Actions {
    private AJS_Scanner $scanner;
    private ?AJS_AI $ai;
    private ?AJS_IDS_IPS $ids_ips;
    private ?AJS_Auto_Heal $auto_heal;

    public function __construct(
        AJS_Scanner $scanner,
        ?AJS_AI $ai = null,
        ?AJS_IDS_IPS $ids_ips = null,
        ?AJS_Auto_Heal $auto_heal = null
    ) {
        $this->scanner   = $scanner;
        $this->ai        = $ai;
        $this->ids_ips   = $ids_ips;
        $this->auto_heal = $auto_heal;

        $this->bind_hooks();
    }

    private function bind_hooks(): void {
        add_action('admin_post_ajs_run_scan', [$this, 'handle_manual_scan']);
        add_action('wp_ajax_ajs_ajax_scan_step', [$this, 'handle_ajax_scan_step']);
        add_action('admin_post_ajs_clear_logs', [$this, 'handle_clear_logs']);
        add_action('admin_post_ajs_test_ai', [$this, 'handle_test_ai']);
        add_action('admin_post_ajs_create_baseline', [$this, 'handle_create_baseline']);
        add_action('admin_post_ajs_unban_ip', [$this, 'handle_unban_ip']);
        add_action('admin_post_ajs_manual_ban_ip', [$this, 'handle_manual_ban_ip']);
        add_action('admin_post_ajs_deploy_cf', [$this, 'handle_deploy_cf']);
        add_action('admin_post_ajs_test_alert', [$this, 'handle_test_alert']);
        add_action('admin_post_ajs_export_scan_report', [$this, 'handle_export_scan_report']);
    }

    public function handle_manual_scan(): void {
        check_admin_referer('ajs_scan_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        if (isset($_POST['scan_skip_nfs_present'])) {
            update_option('ajs_scan_skip_nfs', !empty($_POST['scan_skip_nfs']) ? 1 : 0);
        }
        if (isset($_POST['scan_skip_uploads_present'])) {
            update_option('ajs_scan_skip_uploads', !empty($_POST['scan_skip_uploads']) ? 1 : 0);
        }
        if (isset($_POST['scan_exclude_paths'])) {
            update_option('ajs_scan_exclude_paths', sanitize_textarea_field(wp_unslash($_POST['scan_exclude_paths'])));
        }

        if (isset($_POST['action_type']) && $_POST['action_type'] === 'save_only') {
            wp_safe_redirect(add_query_arg(['page' => 'anti-judol-scanner', 'settings_saved' => 1], admin_url('admin.php')));
            exit;
        }

        $auto_heal = !empty($_POST['auto_heal']);
        $ai_deep_scan = !empty($_POST['ai_deep_scan']);
        $this->scanner->run_full_scan($auto_heal, $ai_deep_scan);

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-scanner', 'scanned' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_ajax_scan_step(): void {
        check_ajax_referer('ajs_ajax_scan_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Akses ditolak.', 'anti-judol-shield')]);
        }

        $step    = sanitize_key($_POST['step'] ?? 'init');
        $scan_id = sanitize_key($_POST['scan_id'] ?? '');
        if (empty($scan_id)) {
            wp_send_json_error(['message' => 'Invalid scan session ID']);
        }

        $transient_key = 'ajs_scan_sess_' . $scan_id;
        $session_data  = get_transient($transient_key);
        if ($step === 'init' || !is_array($session_data)) {
            $session_data = [
                'findings'      => [],
                'skipped_paths' => [],
                'start_time'    => current_time('mysql'),
            ];
        }

        $raw_exclude = sanitize_textarea_field(wp_unslash($_POST['scan_exclude_paths'] ?? ''));
        $config = [
            'auto_heal'     => !empty($_POST['auto_heal']),
            'ai_deep_scan'  => !empty($_POST['ai_deep_scan']),
            'skip_nfs'      => !empty($_POST['scan_skip_nfs']),
            'skip_uploads'  => !empty($_POST['scan_skip_uploads']),
            'exclude_paths' => $this->parse_excluded_rules($raw_exclude),
        ];

        if (isset($_POST['scan_skip_nfs_present'])) {
            update_option('ajs_scan_skip_nfs', $config['skip_nfs'] ? 1 : 0);
        }
        if (isset($_POST['scan_skip_uploads_present'])) {
            update_option('ajs_scan_skip_uploads', $config['skip_uploads'] ? 1 : 0);
        }
        if (isset($_POST['scan_exclude_paths'])) {
            update_option('ajs_scan_exclude_paths', $raw_exclude);
        }

        $result = $this->scanner->run_scan_step($step, $config, $session_data);

        if ($step === 'finalize') {
            delete_transient($transient_key);
        } else {
            set_transient($transient_key, $session_data, 600);
        }

        wp_send_json_success($result);
    }

    private function parse_excluded_rules(string $raw): array {
        if (empty($raw)) {
            return $this->scanner->get_excluded_paths();
        }
        $lines = explode("\n", str_replace("\r", "", $raw));
        $rules = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed !== '' && $trimmed[0] !== '#') {
                $rules[] = $trimmed;
            }
        }
        return $rules;
    }

    public function handle_clear_logs(): void {
        check_admin_referer('ajs_clear_logs_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';
        $wpdb->query("TRUNCATE TABLE {$table_name}");

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-logs', 'cleared' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_test_ai(): void {
        check_admin_referer('ajs_test_ai_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        if (!$this->ai) {
            $result = ['success' => false, 'message' => 'Modul AI tidak terinisialisasi.'];
        } else {
            $result = $this->ai->test_connection();
        }

        set_transient('ajs_ai_test_notice', $result, 60);
        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-settings', 'ai_tested' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_create_baseline(): void {
        check_admin_referer('ajs_create_baseline_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        if ($this->auto_heal) {
            $this->auto_heal->create_integrity_baseline();
        } else {
            $this->scanner->create_integrity_baseline();
        }

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-scanner', 'baseline_created' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_unban_ip(): void {
        check_admin_referer('ajs_unban_ip_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
        if ($this->ids_ips && !empty($ip)) {
            $this->ids_ips->unban_ip($ip);
        }

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-ips', 'unbanned' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_manual_ban_ip(): void {
        check_admin_referer('ajs_manual_ban_ip_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        $target_ip = sanitize_text_field(wp_unslash($_POST['target_ip'] ?? ''));
        $duration  = (int)($_POST['duration'] ?? 86400);
        $reason    = sanitize_text_field(wp_unslash($_POST['reason'] ?? 'Manual Admin Ban'));

        if ($this->ids_ips && filter_var($target_ip, FILTER_VALIDATE_IP)) {
            $this->ids_ips->ban_ip($target_ip, $duration, $reason);
        }

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-ips', 'banned' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_deploy_cf(): void {
        check_admin_referer('ajs_deploy_cf_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        $token = sanitize_text_field(wp_unslash($_POST['ajs_cf_api_token'] ?? ''));
        $zone  = sanitize_text_field(wp_unslash($_POST['ajs_cf_zone_id'] ?? ''));

        if (!empty($token)) {
            update_option('ajs_cf_api_token', $token);
        }
        if (!empty($zone)) {
            update_option('ajs_cf_zone_id', $zone);
        }

        $token = get_option('ajs_cf_api_token', '');
        $zone  = get_option('ajs_cf_zone_id', '');

        $result = AJS_Cloudflare::deploy_to_cloudflare($token, $zone);
        set_transient('ajs_cf_notice', $result, 60);

        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-integrations', 'cf_deployed' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_test_alert(): void {
        check_admin_referer('ajs_test_alert_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        AJS_Notifications::send_alert(
            'Uji Coba Notifikasi Anti-Judol Shield',
            'Ini adalah pesan pengujian koneksi. Jalur komunikasi Telegram/Webhook/Email berfungsi normal.',
            'TEST'
        );

        set_transient('ajs_alert_test_notice', 1, 60);
        wp_safe_redirect(add_query_arg(['page' => 'anti-judol-integrations', 'alert_tested' => 1], admin_url('admin.php')));
        exit;
    }

    public function handle_export_scan_report(): void {
        check_admin_referer('ajs_export_scan_report_action');
        if (!current_user_can('manage_options')) {
            wp_die(__('Akses ditolak.', 'anti-judol-shield'));
        }

        $last_scan = get_option('ajs_last_scan_result', null);
        if (!$last_scan) {
            wp_die(__('Belum ada data laporan pemindaian untuk diekspor.', 'anti-judol-shield'));
        }

        $filename = 'ajs-security-scan-report-' . gmdate('Ymd-His') . '.json';
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Pragma: no-cache');
        header('Expires: 0');

        echo wp_json_encode($last_scan, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }
}
