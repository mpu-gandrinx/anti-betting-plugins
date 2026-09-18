<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Admin_Views {
    private AJS_Scanner $scanner;
    private ?AJS_AI $ai;
    private ?AJS_IDS_IPS $ids_ips;
    private ?AJS_Auto_Heal $auto_heal;
    private string $views_dir;

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
        $this->views_dir = plugin_dir_path(__FILE__) . 'admin/views/';
    }

    public function render_dashboard_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        global $wpdb;
        $table_name    = $wpdb->prefix . 'ajs_security_logs';
        $total_blocked = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$table_name}") ?: 0;
        $today_blocked = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} WHERE created_at >= %s",
            current_time('Y-m-d 00:00:00')
        )) ?: 0;

        $last_scan   = get_option('ajs_last_scan_result', null);
        $recent_logs = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 5");

        include $this->views_dir . 'dashboard.php';
    }

    public function render_logs_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';
        $logs = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 100");

        include $this->views_dir . 'logs.php';
    }

    public function render_ips_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $banned    = get_option('ajs_banned_ips_list', []);
        $whitelist = get_option('ajs_ip_whitelist', '');

        include $this->views_dir . 'ips.php';
    }

    public function render_scanner_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $last_scan      = get_option('ajs_last_scan_result', null);
        $baseline       = get_option('ajs_integrity_baseline', []);
        $last_healed    = get_option('ajs_last_auto_heal', null);
        $nginx_rules    = $this->scanner->get_nginx_rules();
        $network_mounts = $this->scanner->get_network_mounts();
        $has_ai         = $this->ai && $this->ai->is_configured();

        include $this->views_dir . 'scanner.php';
    }

    public function render_integrations_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $cf_expression = AJS_Cloudflare::get_waf_expression();
        $cf_notice     = get_transient('ajs_cf_notice');
        if ($cf_notice) {
            delete_transient('ajs_cf_notice');
        }

        $alert_notice = get_transient('ajs_alert_test_notice');
        if ($alert_notice) {
            delete_transient('ajs_alert_test_notice');
        }

        include $this->views_dir . 'integrations.php';
    }

    public function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $ai_notice = get_transient('ajs_ai_test_notice');
        if ($ai_notice) {
            delete_transient('ajs_ai_test_notice');
        }

        include $this->views_dir . 'settings.php';
    }
}
