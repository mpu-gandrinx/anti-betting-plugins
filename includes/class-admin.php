<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Admin {
    private AJS_WAF $waf;
    private AJS_Scanner $scanner;
    private ?AJS_AI $ai;
    private ?AJS_IDS_IPS $ids_ips;
    private ?AJS_Auto_Heal $auto_heal;

    public AJS_Admin_Views $views;
    public AJS_Admin_Actions $actions;

    public function __construct(
        AJS_WAF $waf,
        AJS_Scanner $scanner,
        ?AJS_AI $ai = null,
        ?AJS_IDS_IPS $ids_ips = null,
        ?AJS_Auto_Heal $auto_heal = null
    ) {
        $this->waf       = $waf;
        $this->scanner   = $scanner;
        $this->ai        = $ai;
        $this->ids_ips   = $ids_ips;
        $this->auto_heal = $auto_heal;

        $this->views   = new AJS_Admin_Views($scanner, $ai, $ids_ips, $auto_heal);
        $this->actions = new AJS_Admin_Actions($scanner, $ai, $ids_ips, $auto_heal);

        add_action('admin_menu', [$this, 'add_menu_pages']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function add_menu_pages(): void {
        add_menu_page(
            __('Anti-Judol Shield', 'anti-judol-shield'),
            __('Anti-Judol Shield', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-shield',
            [$this, 'render_dashboard_page'],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'anti-judol-shield',
            __('Log Serangan', 'anti-judol-shield'),
            __('Log Serangan', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-logs',
            [$this, 'render_logs_page']
        );

        add_submenu_page(
            'anti-judol-shield',
            __('IDS / IPS & Banlist', 'anti-judol-shield'),
            __('IDS / IPS & Banlist', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-ips',
            [$this, 'render_ips_page']
        );

        add_submenu_page(
            'anti-judol-shield',
            __('Scanner & Auto-Heal', 'anti-judol-shield'),
            __('Scanner & Auto-Heal', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-scanner',
            [$this, 'render_scanner_page']
        );

        add_submenu_page(
            'anti-judol-shield',
            __('Cloudflare & Alert', 'anti-judol-shield'),
            __('Cloudflare & Alert', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-integrations',
            [$this, 'render_integrations_page']
        );

        add_submenu_page(
            'anti-judol-shield',
            __('Pengaturan WAF', 'anti-judol-shield'),
            __('Pengaturan WAF', 'anti-judol-shield'),
            'manage_options',
            'anti-judol-settings',
            [$this, 'render_settings_page']
        );
    }

    public function register_settings(): void {
        $options = [
            'ajs_waf_enabled',
            'ajs_auto_heal_enabled',
            'ajs_block_xmlrpc',
            'ajs_block_author_enum',
            'ajs_block_uploads_php',
            'ajs_anti_spam_comments',
            'ajs_anti_spam_post_filter',
            'ajs_rate_limit_login',
            'ajs_max_login_attempts',
            'ajs_lockout_duration',
            'ajs_custom_keywords',
            'ajs_scan_skip_uploads',
            'ajs_scan_skip_nfs',
            'ajs_scan_exclude_paths',
            'ajs_ai_enabled',
            'ajs_ai_endpoint',
            'ajs_ai_api_key',
            'ajs_ai_model',
            'ajs_ips_threshold',
            'ajs_ips_ban_duration',
            'ajs_ip_whitelist',
            'ajs_webhook_url',
            'ajs_telegram_bot_token',
            'ajs_telegram_chat_id',
            'ajs_email_notify',
            'ajs_cf_api_token',
            'ajs_cf_zone_id',
        ];

        foreach ($options as $opt) {
            register_setting('ajs_settings_group', $opt);
        }
    }

    public function render_dashboard_page(): void {
        $this->views->render_dashboard_page();
    }

    public function render_logs_page(): void {
        $this->views->render_logs_page();
    }

    public function render_ips_page(): void {
        $this->views->render_ips_page();
    }

    public function render_scanner_page(): void {
        $this->views->render_scanner_page();
    }

    public function render_integrations_page(): void {
        $this->views->render_integrations_page();
    }

    public function render_settings_page(): void {
        $this->views->render_settings_page();
    }

    public function handle_manual_scan(): void {
        $this->actions->handle_manual_scan();
    }

    public function handle_ajax_scan_step(): void {
        $this->actions->handle_ajax_scan_step();
    }

    public function handle_clear_logs(): void {
        $this->actions->handle_clear_logs();
    }

    public function handle_test_ai(): void {
        $this->actions->handle_test_ai();
    }

    public function handle_create_baseline(): void {
        $this->actions->handle_create_baseline();
    }

    public function handle_unban_ip(): void {
        $this->actions->handle_unban_ip();
    }

    public function handle_manual_ban_ip(): void {
        $this->actions->handle_manual_ban_ip();
    }

    public function handle_deploy_cf(): void {
        $this->actions->handle_deploy_cf();
    }

    public function handle_test_alert(): void {
        $this->actions->handle_test_alert();
    }
}
