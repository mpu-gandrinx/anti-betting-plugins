<?php
/**
 * Plugin Name: Anti-Judol Shield & Security WAF
 * Plugin URI:  https://github.com/bptsi/anti-betting-plugins
 * Description: Proteksi komprehensif WordPress dari serangan injeksi, backdoor, SEO spam, dan deface situs judi online.
 * Version:     1.0.0
 * Author:      BPTSI Security Team
 * License:     GPL-2.0+
 * Text Domain: anti-judol-shield
 */

if (!defined('ABSPATH')) {
    exit;
}

define('AJS_VERSION', '1.0.0');
define('AJS_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AJS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('AJS_DB_VERSION', '1.0');

require_once AJS_PLUGIN_DIR . 'includes/class-notifications.php';
require_once AJS_PLUGIN_DIR . 'includes/class-cloudflare.php';
require_once AJS_PLUGIN_DIR . 'includes/class-ids-ips.php';
require_once AJS_PLUGIN_DIR . 'includes/class-ai.php';
require_once AJS_PLUGIN_DIR . 'includes/class-waf.php';
require_once AJS_PLUGIN_DIR . 'includes/class-auto-heal.php';
require_once AJS_PLUGIN_DIR . 'includes/class-scanner.php';
require_once AJS_PLUGIN_DIR . 'includes/class-admin-actions.php';
require_once AJS_PLUGIN_DIR . 'includes/class-admin-views.php';
require_once AJS_PLUGIN_DIR . 'includes/class-admin.php';

final class Anti_Judol_Shield {
    private static ?Anti_Judol_Shield $instance = null;

    public AJS_AI $ai;
    public AJS_WAF $waf;
    public AJS_Auto_Heal $auto_heal;
    public AJS_Scanner $scanner;
    public AJS_IDS_IPS $ids_ips;
    public AJS_Admin $admin;

    public static function instance(): Anti_Judol_Shield {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init_components();
        $this->register_hooks();
    }

    private function init_components(): void {
        $this->ids_ips   = new AJS_IDS_IPS();
        $this->ai        = new AJS_AI();
        $this->waf       = new AJS_WAF($this->ai);
        $this->auto_heal = new AJS_Auto_Heal();
        $this->scanner   = new AJS_Scanner($this->ai, $this->auto_heal);
        $this->admin     = new AJS_Admin($this->waf, $this->scanner, $this->ai, $this->ids_ips, $this->auto_heal);
    }

    private function register_hooks(): void {
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        add_action('init', [$this, 'init_translations']);
    }

    public function init_translations(): void {
        load_plugin_textdomain('anti-judol-shield', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

    public function activate(): void {
        $this->create_log_table();
        $this->set_default_options();
        $this->scanner->protect_uploads_htaccess();
        $this->scanner->create_integrity_baseline();

        if (!wp_next_scheduled('ajs_daily_scan_cron')) {
            wp_schedule_event(time(), 'daily', 'ajs_daily_scan_cron');
        }

        if (!wp_next_scheduled('ajs_hourly_autoheal_cron')) {
            wp_schedule_event(time(), 'hourly', 'ajs_hourly_autoheal_cron');
        }
    }

    public function deactivate(): void {
        $daily = wp_next_scheduled('ajs_daily_scan_cron');
        if ($daily) {
            wp_unschedule_event($daily, 'ajs_daily_scan_cron');
        }

        $hourly = wp_next_scheduled('ajs_hourly_autoheal_cron');
        if ($hourly) {
            wp_unschedule_event($hourly, 'ajs_hourly_autoheal_cron');
        }
    }

    private function set_default_options(): void {
        $defaults = [
            'waf_enabled'           => 1,
            'auto_heal_enabled'     => 1,
            'block_xmlrpc'          => 1,
            'block_author_enum'     => 1,
            'block_uploads_php'     => 1,
            'anti_spam_comments'    => 1,
            'anti_spam_post_filter' => 1,
            'rate_limit_login'      => 1,
            'max_login_attempts'    => 5,
            'lockout_duration'      => 900,
            'custom_keywords'       => '',
            'scan_skip_uploads'     => 0,
            'scan_skip_nfs'         => 1,
            'scan_exclude_paths'    => '',
            'ai_enabled'            => 0,
            'ai_endpoint'           => 'https://api.openai.com/v1/chat/completions',
            'ai_api_key'            => '',
            'ai_model'              => 'gpt-4o-mini',
            'ips_threshold'         => 100,
            'ips_ban_duration'      => 86400,
            'ip_whitelist'          => '',
            'webhook_url'           => '',
            'telegram_bot_token'    => '',
            'telegram_chat_id'      => '',
            'email_notify'          => 0,
            'cf_api_token'          => '',
            'cf_zone_id'            => '',
        ];

        foreach ($defaults as $key => $val) {
            if (get_option('ajs_' . $key) === false) {
                add_option('ajs_' . $key, $val);
            }
        }
    }

    private function create_log_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(100) NOT NULL,
            threat_payload text NOT NULL,
            request_uri text NOT NULL,
            user_agent varchar(255) DEFAULT '',
            created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }
}

add_action('plugins_loaded', function() {
    Anti_Judol_Shield::instance();
}, 0);
