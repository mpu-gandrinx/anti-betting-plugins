<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Auto_Heal {
    public function __construct() {
        add_action('ajs_hourly_autoheal_cron', [$this, 'verify_and_auto_heal']);
        add_action('init', [$this, 'auto_heal_tick'], 5);
    }

    public function get_baseline_dir(): string {
        $upload_dir = wp_upload_dir();
        $dir = trailingslashit($upload_dir['basedir']) . 'ajs-baseline';
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
            file_put_contents($dir . '/index.php', "<?php\nexit;\n");
        }
        return $dir;
    }

    public function get_critical_files(): array {
        $theme_dir = get_stylesheet_directory();
        $files = [
            ABSPATH . 'index.php',
            ABSPATH . '.htaccess',
            $theme_dir . '/index.php',
            $theme_dir . '/header.php',
            $theme_dir . '/footer.php',
            $theme_dir . '/functions.php',
        ];
        return array_values(array_filter($files, 'file_exists'));
    }

    public function create_integrity_baseline(): int {
        $baseline_dir = $this->get_baseline_dir();
        $critical_files = $this->get_critical_files();
        $baseline_data = [];

        foreach ($critical_files as $file) {
            $hash = hash_file('sha256', $file);
            $backup_name = md5($file) . '.clean';
            $backup_path = trailingslashit($baseline_dir) . $backup_name;

            if (@copy($file, $backup_path)) {
                $baseline_data[$file] = [
                    'hash'       => $hash,
                    'backup'     => $backup_path,
                    'size'       => filesize($file),
                    'created_at' => current_time('mysql'),
                ];
            }
        }

        update_option('ajs_integrity_baseline', $baseline_data);
        return count($baseline_data);
    }

    public function verify_and_auto_heal(): array {
        if ((int)get_option('ajs_auto_heal_enabled', 1) !== 1) {
            return [];
        }

        $baseline = get_option('ajs_integrity_baseline', []);
        if (empty($baseline) || !is_array($baseline)) {
            return [];
        }

        $healed_files = [];
        global $wpdb;
        $table_name = $wpdb->prefix . 'ajs_security_logs';

        foreach ($baseline as $file => $meta) {
            if (!file_exists($file) || !isset($meta['hash'], $meta['backup'])) {
                continue;
            }

            $current_hash = hash_file('sha256', $file);
            if ($current_hash !== $meta['hash']) {
                if (file_exists($meta['backup'])) {
                    if (@copy($meta['backup'], $file)) {
                        $healed_files[] = $file;

                        $wpdb->insert(
                            $table_name,
                            [
                                'ip_address'     => '127.0.0.1',
                                'reason'         => 'Auto-Heal: Deface Reverted',
                                'threat_payload' => 'Perubahan ilegal pada ' . esc_html(basename($file)) . ' otomatis dipulihkan dari golden baseline.',
                                'request_uri'    => 'AUTO_HEAL_DAEMON',
                                'user_agent'     => 'Anti-Judol Shield Auto-Heal',
                                'created_at'     => current_time('mysql'),
                            ],
                            ['%s', '%s', '%s', '%s', '%s', '%s']
                        );
                    }
                }
            }
        }

        if (!empty($healed_files)) {
            update_option('ajs_last_auto_heal', [
                'timestamp' => current_time('mysql'),
                'files'     => $healed_files,
            ]);

            AJS_Notifications::send_alert(
                'Deface Berhasil Dipulihkan (Auto-Heal)',
                'Serangan deface dicegah. File otomatis dipulihkan ke kondisi bersih: ' . implode(', ', array_map('basename', $healed_files)),
                'CRITICAL'
            );
        }

        return $healed_files;
    }

    public function auto_heal_tick(): void {
        if (get_transient('ajs_auto_heal_tick_lock')) {
            return;
        }

        set_transient('ajs_auto_heal_tick_lock', 1, 60);
        $this->verify_and_auto_heal();
    }
}
