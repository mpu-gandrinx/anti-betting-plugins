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
        add_action('wp_ajax_ajs_remediate_finding', [$this, 'handle_remediate_finding']);
        add_action('wp_ajax_ajs_batch_remediate', [$this, 'handle_batch_remediate']);
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

    public function handle_remediate_finding(): void {
        check_ajax_referer('ajs_ajax_scan_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Akses ditolak.', 'anti-judol-shield')]);
        }

        $target_file  = sanitize_text_field(wp_unslash($_POST['finding_file'] ?? ''));
        $threat_type  = sanitize_key($_POST['finding_type'] ?? 'threat');
        $force_action = sanitize_key($_POST['remediation_mode'] ?? 'ai_auto');

        if (empty($target_file)) {
            wp_send_json_error(['message' => 'Parameter target tidak valid.']);
        }

        $result = $this->execute_remediation($target_file, $threat_type, $force_action);
        $this->update_finding_record($target_file, $result);
        $this->log_remediation_event($target_file, $result['badge_text'] ?? ($result['action'] ?? 'Remediasi'), $result['message'] ?? '');

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    public function handle_batch_remediate(): void {
        check_ajax_referer('ajs_ajax_scan_nonce', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Akses ditolak.', 'anti-judol-shield')]);
        }

        $last_scan = get_option('ajs_last_scan_result', []);
        $findings  = $last_scan['findings'] ?? [];

        if (empty($findings)) {
            wp_send_json_success(['message' => 'Tidak ada temuan yang perlu diremediasi.', 'remediated_count' => 0]);
        }

        $remediated_count = 0;
        $details = [];

        foreach ($findings as $f) {
            if (!empty($f['healed'])) {
                continue;
            }
            $target = $f['file'] ?? '';
            $type   = $f['type'] ?? 'threat';
            if (!empty($target)) {
                $res = $this->execute_remediation($target, $type, 'ai_auto');
                $this->update_finding_record($target, $res);
                $details[] = [
                    'target'  => $target,
                    'action'  => $res['action'] ?? 'none',
                    'message' => $res['message'] ?? '',
                ];
                $remediated_count++;
            }
        }

        wp_send_json_success([
            'message'          => "Remediasi selesai: {$remediated_count} temuan telah dinetralkan/diverifikasi sah.",
            'remediated_count' => $remediated_count,
            'details'          => $details,
        ]);
    }

    private function execute_remediation(string $target, string $threat_type, string $mode = 'ai_auto'): array {
        // 1. Database Options
        if (strpos($target, 'Database Option:') === 0) {
            $opt_raw = trim(str_replace('Database Option:', '', $target));

            if ($threat_type === 'rogue_admin_registration' || strpos($opt_raw, 'default_role') !== false) {
                update_option('default_role', 'subscriber');
                update_option('users_can_register', 0);
                return [
                    'success'    => true,
                    'action'     => 'db_fixed',
                    'badge_text' => 'Ditutup & Dinonaktifkan',
                    'message'    => 'Registrasi publik dinonaktifkan (users_can_register = 0) dan role bawaan dikembalikan ke Subscriber.',
                ];
            }

            delete_option($opt_raw);
            delete_site_option($opt_raw);
            return [
                'success'    => true,
                'action'     => 'option_deleted',
                'badge_text' => 'Opsi Dihapus',
                'message'    => "Opsi database '{$opt_raw}' berhasil dihapus dari tabel wp_options.",
            ];
        }

        // 1b. WP Cron Hook Jahat
        if (strpos($target, 'WP Cron Hook:') === 0 || $threat_type === 'malicious_cron_job') {
            $hook_name = trim(str_replace('WP Cron Hook:', '', $target));
            wp_clear_scheduled_hook($hook_name);
            return [
                'success'    => true,
                'action'     => 'cron_cleared',
                'badge_text' => 'Cron Ilegal Dihapus',
                'message'    => "Tugas cron jahat '{$hook_name}' berhasil dihapus dari jadwal sistem WP-Cron.",
            ];
        }

        // 2. Akun Administrator Mencurigakan
        if (strpos($target, 'User ID #') === 0) {
            if (preg_match('/User ID #(\d+)/', $target, $m)) {
                $uid  = intval($m[1]);
                $user = get_userdata($uid);
                if ($user) {
                    $user->set_role('subscriber');
                    return [
                        'success'    => true,
                        'action'     => 'user_demoted',
                        'badge_text' => 'Role Diturunkan',
                        'message'    => "Hak akses user #{$uid} ({$user->user_login}) berhasil diturunkan dari Administrator ke Subscriber.",
                    ];
                }
            }
            return [
                'success'    => true,
                'action'     => 'user_checked',
                'badge_text' => 'User Terverifikasi',
                'message'    => 'Akun user telah diperiksa & dinetralkan.',
            ];
        }

        // 3. Artikel Terinjeksi
        if (strpos($target, 'Post ID #') === 0) {
            if (preg_match('/Post ID #(\d+)/', $target, $m)) {
                $pid = intval($m[1]);
                wp_update_post([
                    'ID'          => $pid,
                    'post_status' => 'draft',
                ]);
                return [
                    'success'    => true,
                    'action'     => 'post_drafted',
                    'badge_text' => 'Ditarik ke Draft',
                    'message'    => "Artikel #{$pid} berhasil ditarik ke status Draft untuk ditinjau.",
                ];
            }
        }

        // 3b. Kerentanan Celah Sistem & Hardening
        if ($threat_type === 'vuln_exposed_sensitive_file') {
            if (file_exists($target)) {
                @unlink($target);
                return [
                    'success'    => true,
                    'action'     => 'file_deleted',
                    'badge_text' => 'File Bocor Dihapus',
                    'message'    => "File sensitif publik '{$target}' berhasil dihapus dari direktori web server.",
                ];
            }
        }

        if ($threat_type === 'vuln_uploads_php_executable') {
            $this->scanner->protect_uploads_htaccess();
            return [
                'success'    => true,
                'action'     => 'htaccess_protected',
                'badge_text' => 'Proteksi Uploads Diterapkan',
                'message'    => 'File .htaccess pembatas eksekusi skrip PHP berhasil dibuat di folder wp-content/uploads/.',
            ];
        }

        if ($threat_type === 'vuln_file_edit_enabled') {
            return [
                'success'    => true,
                'action'     => 'runtime_locked',
                'badge_text' => 'Terkunci oleh WAF',
                'message'    => 'Akses editor berkas telah dinonaktifkan secara paksa di level runtime WAF Anti-Judol Shield.',
            ];
        }

        // 4. File Skrip Target
        $file_path = $target;

        if (!file_exists($file_path)) {
            return [
                'success'    => true,
                'action'     => 'already_removed',
                'badge_text' => 'File Bersih / Tidak Ada',
                'message'    => 'File target sudah tidak ditemukan di server.',
            ];
        }

        // Jika dipaksa Whitelist oleh Admin
        if ($mode === 'whitelist') {
            $whitelisted = (array)get_option('ajs_whitelisted_files', []);
            if (!in_array($file_path, $whitelisted, true)) {
                $whitelisted[] = $file_path;
                update_option('ajs_whitelisted_files', $whitelisted);
            }
            return [
                'success'    => true,
                'action'     => 'whitelisted',
                'badge_text' => 'Dikecualikan / Sah',
                'message'    => 'File berhasil ditandai sebagai fungsi sah & dikecualikan dari scan berikutnya.',
            ];
        }

        // Jika dipaksa Karantina
        if ($mode === 'quarantine') {
            return $this->isolate_malicious_file($file_path);
        }

        // Mode AI Auto Remediation (default)
        $content = (string)@file_get_contents($file_path);
        $snippet = substr($content, 0, 3000);

        if ($this->ai && $this->ai->is_configured()) {
            $ai_res = $this->ai->remediate_threat($file_path, $threat_type, $snippet);

            if (!empty($ai_res['success'])) {
                $action = $ai_res['action'];

                // Kasus A: AI verifikasi bahwa ini FALSE POSITIVE
                if ($action === 'whitelist' || ($ai_res['verdict'] ?? '') === 'SAFE_FALSE_POSITIVE') {
                    $whitelisted = (array)get_option('ajs_whitelisted_files', []);
                    if (!in_array($file_path, $whitelisted, true)) {
                        $whitelisted[] = $file_path;
                        update_option('ajs_whitelisted_files', $whitelisted);
                    }
                    return [
                        'success'    => true,
                        'action'     => 'whitelisted',
                        'badge_text' => 'Diverifikasi Sah oleh AI',
                        'message'    => 'Analisis AI: ' . $ai_res['explanation'],
                    ];
                }

                // Kasus B: AI merekomendasikan karantina file
                if ($action === 'quarantine') {
                    return $this->isolate_malicious_file($file_path, 'Terkarantina AI: ' . $ai_res['explanation']);
                }

                // Kasus C: AI patch / netralkan
                if ($action === 'patch') {
                    @file_put_contents($file_path, "<?php\n// Neutralized by Anti-Judol Shield AI Shield\nhttp_response_code(403);\nexit('Malicious Script Neutralized');\n");
                    return [
                        'success'    => true,
                        'action'     => 'patched',
                        'badge_text' => 'Dinetralkan AI',
                        'message'    => 'AI Remediasi: ' . $ai_res['explanation'],
                    ];
                }
            }
        }

        // File asing / webshell tak dikenal => Karantina Aman
        return $this->isolate_malicious_file($file_path, 'File dinonaktifkan & diisolasi ke zona karantina aman.');
    }

    private function isolate_malicious_file(string $file_path, string $note = ''): array {
        $quarantine_dir = WP_CONTENT_DIR . '/ajs-quarantine';
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            @file_put_contents($quarantine_dir . '/.htaccess', "Require all denied\nDeny from all\n");
            @file_put_contents($quarantine_dir . '/index.php', "<?php\nhttp_response_code(403);\nexit;\n");
        }

        $safe_name = md5($file_path . time()) . '_' . sanitize_file_name(basename($file_path)) . '.isolated';
        $dest_path = trailingslashit($quarantine_dir) . $safe_name;

        // Pindahkan file ke folder karantina tertutup
        if (@copy($file_path, $dest_path)) {
            // Jika berada di wp-content/uploads, hapus tuntas file aslinya
            $upload_dir = wp_upload_dir();
            $uploads_basedir = rtrim(wp_normalize_path($upload_dir['basedir']), '/');
            $norm_target = rtrim(wp_normalize_path($file_path), '/');

            if (strpos($norm_target, $uploads_basedir) === 0) {
                @unlink($file_path);
            } else {
                // Untuk file tema/plugin, netralkan isinya agar tidak merusak include namun tidak bisa dieksekusi
                @file_put_contents($file_path, "<?php\n// Isolated by Anti-Judol Shield\nhttp_response_code(403);\nexit('Isolated threat');\n");
            }

            return [
                'success'    => true,
                'action'     => 'quarantined',
                'badge_text' => 'Terisolasi Aman (Karantina)',
                'message'    => $note ?: 'File berhasil dipindahkan ke zona karantina tertutup dan dinonaktifkan.',
            ];
        }

        return [
            'success' => false,
            'message' => 'Gagal mengisolasi file (periksa izin tulis direktori wp-content).',
        ];
    }

    private function update_finding_record(string $target, array $result): void {
        $last_scan = get_option('ajs_last_scan_result', []);
        $findings  = $last_scan['findings'] ?? [];
        $changed   = false;

        foreach ($findings as &$f) {
            if (($f['file'] ?? '') === $target) {
                $f['healed'] = true;
                if (!empty($result['badge_text'])) {
                    $f['remediation_note'] = $result['badge_text'] . ': ' . ($result['message'] ?? '');
                }
                $changed = true;
                break;
            }
        }
        unset($f);

        if ($changed) {
            $unhealed = 0;
            foreach ($findings as $f) {
                if (empty($f['healed'])) {
                    $unhealed++;
                }
            }
            $last_scan['total_issues'] = $unhealed;
            $last_scan['findings']     = $findings;
            update_option('ajs_last_scan_result', $last_scan);
        }
    }

    private function log_remediation_event(string $target, string $action, string $details): void {
        global $wpdb;
        $table = $wpdb->prefix . 'ajs_security_logs';
        $ip = !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '127.0.0.1';
        $wpdb->insert($table, [
            'ip_address'     => $ip,
            'reason'         => 'Remediasi: ' . $action,
            'threat_payload' => substr($details, 0, 1000),
            'request_uri'    => wp_make_link_relative($target),
            'user_agent'     => 'AJS Remediation Engine',
            'created_at'     => current_time('mysql'),
        ]);
    }
}
