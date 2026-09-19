<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Scanner {
    private ?AJS_AI $ai;
    private AJS_Auto_Heal $auto_heal;

    private array $suspicious_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'suspected'];

    private array $backdoor_signatures = [
        // WebShell & Known Exploit Families
        'c99shell',
        'r57shell',
        'wso_version',
        'FilesMan',
        'ALFA_DATA',
        'IndoXploit',
        'b374k',
        'p0wny',
        'wp_vcd',
        'menuhdr',
        'wp-tmp.php',

        // Remote Execution & Dangerous Obfuscation
        'eval(base64_decode',
        'eval(gzinflate',
        'eval(gzuncompress',
        'eval(str_rot13',
        'eval(hex2bin',
        'eval($_POST',
        'eval($_GET',
        'eval($_REQUEST',
        'eval($_COOKIE',
        'assert($_POST',
        'assert($_REQUEST',
        'assert($_GET',
        'passthru($_',
        'shell_exec($_',
        'system($_POST',
        'system($_GET',
        'system($_REQUEST',
        'preg_replace("/.*/e"',
        'preg_replace(\'/.*/e\'',
        'create_function($_',
        'create_function(\'\', $_',
        'create_function("", $_',
        'call_user_func($_POST',
        'call_user_func($_GET',
        'call_user_func($_REQUEST',
        'include "data://',
        'include \'data://',
        'base64_decode("PD9waH',
        'base64_decode(\'PD9waH',
    ];

    private array $official_root_files = [
        'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
        'wp-config.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
        'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
        'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'
    ];

    public function __construct(?AJS_AI $ai = null, ?AJS_Auto_Heal $auto_heal = null) {
        $this->ai        = $ai;
        $this->auto_heal = $auto_heal ?: new AJS_Auto_Heal();
        add_action('ajs_daily_scan_cron', [$this, 'run_full_scan']);
    }

    public function protect_uploads_htaccess(): bool {
        $upload_dir = wp_upload_dir();
        $target_dir = $upload_dir['basedir'];

        if (!is_dir($target_dir) || !is_writable($target_dir)) {
            return false;
        }

        $htaccess_path = trailingslashit($target_dir) . '.htaccess';
        $rules = "# Anti-Judol Shield - Block PHP Execution in Uploads\n";
        $rules .= "<FilesMatch \"\.(?i:php|phtml|php3|php4|php5|php7|phps|phar)$\引>\n";
        $rules .= "    <IfModule mod_authz_core.c>\n";
        $rules .= "        Require all denied\n";
        $rules .= "    </IfModule>\n";
        $rules .= "    <IfModule !mod_authz_core.c>\n";
        $rules .= "        Order deny,allow\n";
        $rules .= "        Deny from all\n";
        $rules .= "    </IfModule>\n";
        $rules .= "</FilesMatch>\n";

        // Fix quote in regex
        $rules = str_replace('引', '', $rules);

        return file_put_contents($htaccess_path, $rules) !== false;
    }

    /**
     * Dapatkan daftar mount point jaringan / NFS pada sistem (Linux /proc/mounts atau /etc/mtab).
     */
    public function get_network_mounts(): array {
        $mounts = [];
        $mount_files = ['/proc/mounts', '/etc/mtab'];
        $network_fs_types = [
            'nfs', 'nfs4', 'cifs', 'smbfs', 'glusterfs', 'ceph',
            'sshfs', 'fuse.sshfs', 'fuse.glusterfs', 'nfsd',
            'panfs', 'lustre', 'gpfs', 's3fs', 'fuse.s3fs',
            'blobfuse', 'fuse.blobfuse', 'azurefile', 'davfs'
        ];

        foreach ($mount_files as $file) {
            if (!@is_readable($file)) {
                continue;
            }

            $content = @file_get_contents($file);
            if (!$content) {
                continue;
            }

            $lines = explode("\n", $content);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') {
                    continue;
                }

                $parts = preg_split('/\s+/', $line);
                if (count($parts) >= 3) {
                    $device     = $parts[0];
                    $mountpoint = $parts[1];
                    $fstype     = strtolower($parts[2]);

                    // Decode escape octal (contoh \040 untuk spasi)
                    $mountpoint = preg_replace_callback('/\\\\([0-7]{3})/', function($m) {
                        return chr(octdec($m[1]));
                    }, $mountpoint);

                    $is_network = in_array($fstype, $network_fs_types, true) ||
                                  strpos($fstype, 'nfs') !== false ||
                                  strpos($fstype, 'cifs') !== false ||
                                  strpos($fstype, 'smb') !== false;

                    if ($is_network) {
                        $norm_mount = rtrim(wp_normalize_path($mountpoint), '/');
                        $mounts[$norm_mount] = [
                            'path'   => $norm_mount,
                            'type'   => $fstype,
                            'device' => $device,
                        ];
                    }
                }
            }

            if (!empty($mounts)) {
                break;
            }
        }

        return array_values($mounts);
    }

    /**
     * Periksa apakah direktori tertentu adalah network mount (NFS/CIFS/SMB/UNC).
     */
    public function is_network_mount(string $path): bool {
        $norm_path = rtrim(wp_normalize_path($path), '/');

        // Deteksi Windows UNC path misal //nas/share atau \\nas\share
        if (substr($norm_path, 0, 2) === '//') {
            return true;
        }

        $mounts = $this->get_network_mounts();
        foreach ($mounts as $m) {
            $norm_mount = rtrim(wp_normalize_path($m['path']), '/');
            if ($norm_path === $norm_mount || strpos($norm_path . '/', $norm_mount . '/') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Ambil daftar path/folder yang dikecualikan dari opsi admin.
     */
    public function get_excluded_paths(): array {
        $raw = get_option('ajs_scan_exclude_paths', '');
        if (empty($raw)) {
            return [];
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

    /**
     * Cek apakah seluruh direktori uploads harus dilewati.
     */
    public function should_skip_uploads(): bool {
        return (int)get_option('ajs_scan_skip_uploads', 0) === 1;
    }

    /**
     * Periksa apakah path tertentu harus dikecualikan dari scanning.
     */
    public function is_path_excluded(
        string $path,
        array $excluded_rules = [],
        array $network_mounts = [],
        bool $skip_nfs = true,
        ?string &$reason = null
    ): bool {
        $norm_path = rtrim(wp_normalize_path($path), '/');

        // Selalu kecualikan direktori plugin Anti-Judol Shield itu sendiri agar scanner tidak mendeteksi signature miliknya sendiri
        if (defined('AJS_PLUGIN_DIR')) {
            $ajs_dir = rtrim(wp_normalize_path(AJS_PLUGIN_DIR), '/');
            if ($norm_path === $ajs_dir || strpos($norm_path . '/', $ajs_dir . '/') === 0) {
                $reason = 'Direktori plugin Anti-Judol Shield (self-exclude)';
                return true;
            }
        }

        // 1. Cek mount jaringan / NFS jika opsi aktif
        if ($skip_nfs) {
            if (substr($norm_path, 0, 2) === '//') {
                $reason = "Share jaringan UNC ({$norm_path})";
                return true;
            }

            foreach ($network_mounts as $m) {
                $norm_mount = rtrim(wp_normalize_path($m['path']), '/');
                if ($norm_path === $norm_mount || strpos($norm_path . '/', $norm_mount . '/') === 0) {
                    $type = strtoupper($m['type'] ?? 'NFS');
                    $reason = "Storage Jaringan {$type} ({$norm_mount})";
                    return true;
                }
            }
        }

        // 2. Cek aturan custom exclusion pengguna
        if (!empty($excluded_rules)) {
            $upload_dir = wp_upload_dir();
            $uploads_basedir = rtrim(wp_normalize_path($upload_dir['basedir']), '/');
            $base_name = basename($norm_path);

            foreach ($excluded_rules as $rule) {
                $clean_rule = trim($rule, " \t\n\r/\\");
                if ($clean_rule === '') {
                    continue;
                }

                // Cocokkan nama folder langsung (contoh: 'nfs', 'nas', 'arsip')
                if (strpos($clean_rule, '/') === false && strpos($clean_rule, '\\') === false) {
                    if (strcasecmp($base_name, $clean_rule) === 0 || fnmatch($clean_rule, $base_name)) {
                        $reason = "Folder dikecualikan: '{$clean_rule}'";
                        return true;
                    }
                }

                // Cocokkan path relatif uploads (contoh: 'uploads/nfs' atau '2024/dokumen')
                $norm_rule_path = rtrim(wp_normalize_path($clean_rule), '/');
                $target_relative = $uploads_basedir . '/' . $norm_rule_path;
                if ($norm_path === $target_relative || strpos($norm_path . '/', $target_relative . '/') === 0) {
                    $reason = "Path uploads dikecualikan: '{$clean_rule}'";
                    return true;
                }

                // Cocokkan path absolut
                $norm_abs_rule = rtrim(wp_normalize_path($rule), '/');
                if ($norm_path === $norm_abs_rule || strpos($norm_path . '/', $norm_abs_rule . '/') === 0) {
                    $reason = "Path absolut dikecualikan: '{$rule}'";
                    return true;
                }

                // Cocokkan segmen folder dalam path
                if (strpos($norm_path . '/', '/' . $clean_rule . '/') !== false) {
                    $reason = "Segmen direktori '{$clean_rule}' terdaftar dalam pengecualian";
                    return true;
                }
            }
        }

        return false;
    }

    public function run_full_scan(bool $auto_heal = false, bool $ai_deep_scan = false): array {
        @set_time_limit(300);
        $start_time    = current_time('mysql');
        $start_micro   = microtime(true);
        $findings      = [];
        $skipped_paths = [];
        $ai_audit      = [];
        $db_audit      = [];
        $core_audit    = [];
        $stats         = [
            'uploads_scanned'  => 0,
            'theme_scanned'    => 0,
            'ai_scanned'       => 0,
            'db_checked'       => 0,
            'core_checked'     => 0,
            'baseline_checked' => 0,
        ];

        $upload_dir     = wp_upload_dir();
        $uploads_path   = $upload_dir['basedir'];
        $theme_dir      = get_stylesheet_directory();

        $skip_uploads   = $this->should_skip_uploads();
        $skip_nfs       = (int)get_option('ajs_scan_skip_nfs', 1) === 1;
        $excluded_rules = $this->get_excluded_paths();
        $network_mounts = $skip_nfs ? $this->get_network_mounts() : [];
        $suspicious_files = [];

        // 1. Scan uploads directory for illegal script files (jika tidak di-skip dan bukan NFS)
        $skip_reason = '';
        if ($skip_uploads) {
            $skipped_paths[] = [
                'path'   => $uploads_path,
                'reason' => 'Dilewati seluruhnya (opsi Lewati Folder Uploads aktif).',
            ];
        } elseif ($this->is_path_excluded($uploads_path, $excluded_rules, $network_mounts, $skip_nfs, $skip_reason)) {
            $skipped_paths[] = [
                'path'   => $uploads_path,
                'reason' => 'Dilewati: ' . ($skip_reason ?: 'Terdeteksi sebagai NFS/Network Storage atau masuk daftar pengecualian.'),
            ];
        } elseif (is_dir($uploads_path)) {
            $this->scan_directory_for_scripts($uploads_path, $findings, $auto_heal, $skipped_paths, $stats['uploads_scanned']);
        }

        // 2. Scan tema aktif, tema induk, plugins, mu-plugins, dan root untuk backdoor & rogue user creation
        if (is_dir($theme_dir)) {
            $this->scan_directory_for_signatures($theme_dir, $findings, $skipped_paths, $stats['theme_scanned'], $suspicious_files);
        }
        $parent_theme = get_template_directory();
        if ($parent_theme !== $theme_dir && is_dir($parent_theme)) {
            $this->scan_directory_for_signatures($parent_theme, $findings, $skipped_paths, $stats['theme_scanned'], $suspicious_files);
        }
        $mu_plugins = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins');
        if (is_dir($mu_plugins)) {
            $this->scan_directory_for_signatures($mu_plugins, $findings, $skipped_paths, $stats['theme_scanned'], $suspicious_files);
        }
        if (defined('WP_PLUGIN_DIR') && is_dir(WP_PLUGIN_DIR)) {
            $this->scan_directory_for_signatures(WP_PLUGIN_DIR, $findings, $skipped_paths, $stats['theme_scanned'], $suspicious_files);
        }
        $this->scan_root_php_files($findings, $suspicious_files, $stats['theme_scanned']);

        // 3. AI Deep Scan: Analisis file skrip mencurigakan (backdoor/user creator) & postingan terbitan
        if ($ai_deep_scan && $this->ai && $this->ai->is_configured()) {
            if (!empty($suspicious_files)) {
                $this->scan_suspicious_files_with_ai($suspicious_files, $findings, $ai_audit);
            }
            $this->scan_posts_for_judol($findings, $auto_heal, $ai_audit);
            $stats['ai_scanned'] = count($ai_audit);
        }

        // 4. File Integrity & Deface check
        $healed_files = $this->verify_and_auto_heal();
        $stats['baseline_checked'] = count($this->get_critical_files());
        foreach ($healed_files as $hf) {
            $findings[] = [
                'type'     => 'deface_reverted',
                'severity' => 'CRITICAL',
                'file'     => $hf,
                'message'  => 'Deface terdeteksi dan berhasil dipulihkan secara otomatis (Auto-Healed).',
                'healed'   => true,
            ];
        }

        // 5. Database Options Scan (Detect injected scripts/casino spam in options)
        $this->scan_database_options($findings, $db_audit);
        $stats['db_checked'] = count($db_audit);

        // 6. WordPress.org Official Core Checksums Verification
        $this->scan_wordpress_core_checksums($findings, $core_audit);
        $stats['core_checked'] = count($core_audit);

        $duration = round(microtime(true) - $start_micro, 2);

        $scan_record = [
            'timestamp'     => current_time('mysql'),
            'start_time'    => $start_time,
            'duration_sec'  => $duration,
            'total_issues'  => count($findings),
            'findings'      => $findings,
            'ai_scanned'    => $ai_deep_scan,
            'skipped_paths' => $skipped_paths,
            'stats'         => $stats,
            'ai_audit'      => $ai_audit,
            'db_audit'      => $db_audit,
            'core_audit'    => $core_audit,
            'scope'         => [
                'uploads_path' => $uploads_path,
                'theme_path'   => $theme_dir,
                'wp_version'   => get_bloginfo('version'),
                'php_version'  => PHP_VERSION,
            ],
        ];

        update_option('ajs_last_scan_result', $scan_record);
        return $scan_record;
    }

    /**
     * Jalankan tahapan pemindaian secara bertahap (untuk visualisasi real-time progress di UI).
     */
    public function run_scan_step(string $step, array $config, array &$session_data): array {
        @set_time_limit(180);

        if (!isset($session_data['findings']) || !is_array($session_data['findings'])) {
            $session_data['findings'] = [];
        }
        if (!isset($session_data['skipped_paths']) || !is_array($session_data['skipped_paths'])) {
            $session_data['skipped_paths'] = [];
        }
        if (!isset($session_data['ai_audit']) || !is_array($session_data['ai_audit'])) {
            $session_data['ai_audit'] = [];
        }
        if (!isset($session_data['db_audit']) || !is_array($session_data['db_audit'])) {
            $session_data['db_audit'] = [];
        }
        if (!isset($session_data['core_audit']) || !is_array($session_data['core_audit'])) {
            $session_data['core_audit'] = [];
        }
        if (!isset($session_data['stats']) || !is_array($session_data['stats'])) {
            $session_data['stats'] = [
                'uploads_scanned'  => 0,
                'theme_scanned'    => 0,
                'ai_scanned'       => 0,
                'db_checked'       => 0,
                'core_checked'     => 0,
                'baseline_checked' => 0,
            ];
        }

        $auto_heal      = !empty($config['auto_heal']);
        $ai_deep_scan   = !empty($config['ai_deep_scan']);
        $skip_uploads   = !empty($config['skip_uploads']);
        $skip_nfs       = !empty($config['skip_nfs']);
        $excluded_rules = $config['exclude_paths'] ?? $this->get_excluded_paths();
        $network_mounts = $skip_nfs ? $this->get_network_mounts() : [];

        $upload_dir   = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        $theme_dir    = get_stylesheet_directory();

        $response = [
            'step'           => $step,
            'next_step'      => null,
            'progress'       => 0,
            'status_text'    => '',
            'logs'           => [],
            'total_findings' => count($session_data['findings']),
            'skipped_count'  => count($session_data['skipped_paths']),
            'scan_record'    => null,
        ];

        switch ($step) {
            case 'init':
                $session_data['findings']         = [];
                $session_data['skipped_paths']    = [];
                $session_data['ai_audit']         = [];
                $session_data['db_audit']         = [];
                $session_data['core_audit']       = [];
                $session_data['suspicious_files'] = [];
                $session_data['stats']            = [
                    'uploads_scanned'  => 0,
                    'theme_scanned'    => 0,
                    'ai_scanned'       => 0,
                    'db_checked'       => 0,
                    'core_checked'     => 0,
                    'baseline_checked' => 0,
                ];
                $session_data['start_time']    = current_time('mysql');
                $session_data['start_micro']   = microtime(true);

                $logs = [
                    'Memulai sesi pemindaian baru...',
                    'Konfigurasi: Auto-Heal (' . ($auto_heal ? 'Aktif' : 'Nonaktif') . ') | AI Deep Screening (' . ($ai_deep_scan ? 'Aktif' : 'Nonaktif') . ')',
                ];

                if ($skip_nfs && !empty($network_mounts)) {
                    $logs[] = 'Deteksi storage jaringan: Terdeteksi ' . count($network_mounts) . ' mount point NFS/CIFS (otomatis dilewati).';
                } else {
                    $logs[] = 'Storage server: Menggunakan filesystem lokal.';
                }

                $response['next_step']   = 'scan_uploads';
                $response['progress']    = 15;
                $response['status_text'] = 'Storage terverifikasi. Bersiap memindai direktori uploads...';
                $response['logs']        = $logs;
                break;

            case 'scan_uploads':
                $logs = [];
                $skip_reason = '';

                if ($skip_uploads) {
                    $session_data['skipped_paths'][] = [
                        'path'   => $uploads_path,
                        'reason' => 'Dilewati seluruhnya (Opsi lewati folder uploads aktif).',
                    ];
                    $logs[] = 'Lewati uploads: Direktori uploads diabaikan sesuai preferensi admin.';
                } elseif ($this->is_path_excluded($uploads_path, $excluded_rules, $network_mounts, $skip_nfs, $skip_reason)) {
                    $session_data['skipped_paths'][] = [
                        'path'   => $uploads_path,
                        'reason' => 'Dilewati: ' . $skip_reason,
                    ];
                    $logs[] = 'Lewati uploads: ' . $skip_reason;
                } elseif (is_dir($uploads_path)) {
                    $before_count   = count($session_data['findings']);
                    $before_skipped = count($session_data['skipped_paths']);

                    $this->scan_directory_for_scripts($uploads_path, $session_data['findings'], $auto_heal, $session_data['skipped_paths'], $session_data['stats']['uploads_scanned']);

                    $found_here   = count($session_data['findings']) - $before_count;
                    $skipped_here = count($session_data['skipped_paths']) - $before_skipped;

                    $logs[] = "Pemindaian uploads: {$session_data['stats']['uploads_scanned']} file diperiksa.";

                    if ($skipped_here > 0) {
                        $logs[] = "Proteksi storage: {$skipped_here} subfolder NFS/pengecualian di dalam uploads berhasil dilewati.";
                    }
                    if ($found_here > 0) {
                        $logs[] = "Peringatan: Terdeteksi {$found_here} file skrip mencurigakan di folder uploads!";
                    } else {
                        $logs[] = 'Direktori uploads lokal bersih dari skrip ilegal (.php/.phtml).';
                    }
                } else {
                    $logs[] = 'Direktori uploads tidak ditemukan di server.';
                }

                $response['next_step']   = 'scan_theme';
                $response['progress']    = 40;
                $response['status_text'] = 'Pemindaian direktori uploads selesai. Memindai tema aktif, plugins & backdoor...';
                $response['logs']        = $logs;
                break;

            case 'scan_theme':
                $logs = [];
                $before_count = count($session_data['findings']);
                if (!isset($session_data['suspicious_files']) || !is_array($session_data['suspicious_files'])) {
                    $session_data['suspicious_files'] = [];
                }

                // 1. Scan Tema Aktif
                if (is_dir($theme_dir)) {
                    $theme_name = basename($theme_dir);
                    $this->scan_directory_for_signatures($theme_dir, $session_data['findings'], $session_data['skipped_paths'], $session_data['stats']['theme_scanned'], $session_data['suspicious_files']);
                    $logs[] = "Pemindaian tema aktif ({$theme_name}): {$session_data['stats']['theme_scanned']} file PHP diperiksa.";
                }

                // 2. Scan Tema Induk jika ada
                $parent_theme = get_template_directory();
                if ($parent_theme !== $theme_dir && is_dir($parent_theme)) {
                    $this->scan_directory_for_signatures($parent_theme, $session_data['findings'], $session_data['skipped_paths'], $session_data['stats']['theme_scanned'], $session_data['suspicious_files']);
                    $logs[] = "Pemindaian tema induk (" . basename($parent_theme) . ") selesai.";
                }

                // 3. Scan Must-Use Plugins (vektor umum backdoor)
                $mu_plugins = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins');
                if (is_dir($mu_plugins)) {
                    $this->scan_directory_for_signatures($mu_plugins, $session_data['findings'], $session_data['skipped_paths'], $session_data['stats']['theme_scanned'], $session_data['suspicious_files']);
                    $logs[] = "Pemindaian must-use plugins (wp-content/mu-plugins) selesai.";
                }

                // 4. Scan Direktori Plugins
                if (defined('WP_PLUGIN_DIR') && is_dir(WP_PLUGIN_DIR)) {
                    $this->scan_directory_for_signatures(WP_PLUGIN_DIR, $session_data['findings'], $session_data['skipped_paths'], $session_data['stats']['theme_scanned'], $session_data['suspicious_files']);
                    $logs[] = "Pemindaian direktori plugins (wp-content/plugins) selesai.";
                }

                // 5. Scan File PHP Root WordPress (ABSPATH)
                $this->scan_root_php_files($session_data['findings'], $session_data['suspicious_files'], $session_data['stats']['theme_scanned']);
                $logs[] = "Verifikasi file skrip PHP di direktori root WordPress selesai.";

                $found_here = count($session_data['findings']) - $before_count;
                if ($found_here > 0) {
                    $logs[] = "Peringatan: Terdeteksi {$found_here} indikasi webshell/backdoor pembuat user ilegal!";
                } else {
                    $logs[] = "Tema, plugins, mu-plugins, dan file root bersih dari signature backdoor.";
                }

                $has_ai = $ai_deep_scan && $this->ai && $this->ai->is_configured();
                $response['next_step']   = $has_ai ? 'scan_ai' : 'verify_integrity';
                $response['progress']    = 60;
                $response['status_text'] = $has_ai ? 'Memulai AI Deep Screening pada file mencurigakan & artikel...' : 'Memeriksa integritas file Golden Baseline...';
                $response['logs']        = $logs;
                break;

            case 'scan_ai':
                $logs = [];
                if ($this->ai && $this->ai->is_configured()) {
                    $before_count = count($session_data['findings']);

                    // 1. Analisis AI pada file skrip mencurigakan / kandidat backdoor
                    $suspicious_files = $session_data['suspicious_files'] ?? [];
                    if (!empty($suspicious_files)) {
                        $logs[] = "AI Deep Screening: Mengirim " . count($suspicious_files) . " sampel potongan kode mencurigakan ke model " . esc_html($this->ai->get_model()) . " untuk deteksi backdoor/user injection...";
                        $this->scan_suspicious_files_with_ai($suspicious_files, $session_data['findings'], $session_data['ai_audit']);
                    }

                    // 2. Analisis AI pada artikel & postingan
                    $this->scan_posts_for_judol($session_data['findings'], $auto_heal, $session_data['ai_audit']);
                    $found_here = count($session_data['findings']) - $before_count;
                    $session_data['stats']['ai_scanned'] = count($session_data['ai_audit']);

                    $logs[] = "AI Screening Selesai: " . count($session_data['ai_audit']) . " item (skrip & artikel) diperiksa oleh model " . esc_html($this->ai->get_model()) . ".";

                    if ($found_here > 0) {
                        $logs[] = "Peringatan AI: Terkonfirmasi {$found_here} ancaman baru melalui penalaran AI!";
                    } else {
                        $logs[] = 'AI Screening: Seluruh sampel kode dan artikel yang diperiksa bersih/aman.';
                    }
                } else {
                    $logs[] = 'AI Screening dilewati (modul AI belum dikonfigurasi).';
                }

                $response['next_step']   = 'verify_integrity';
                $response['progress']    = 75;
                $response['status_text'] = 'Pemeriksaan AI selesai. Memeriksa integritas Golden Baseline...';
                $response['logs']        = $logs;
                break;

            case 'verify_integrity':
                $logs = [];
                $healed_files = $this->verify_and_auto_heal();
                $session_data['stats']['baseline_checked'] = count($this->get_critical_files());

                foreach ($healed_files as $hf) {
                    $session_data['findings'][] = [
                        'type'     => 'deface_reverted',
                        'severity' => 'CRITICAL',
                        'file'     => $hf,
                        'message'  => 'Deface terdeteksi dan berhasil dipulihkan secara otomatis (Auto-Healed).',
                        'healed'   => true,
                    ];
                }

                if (!empty($healed_files)) {
                    $logs[] = 'Auto-Heal: ' . count($healed_files) . ' file terdeface berhasil dipulihkan ke baseline bersih!';
                } else {
                    $logs[] = 'Golden Baseline utuh: File utama (index.php, .htaccess, header.php) identik dengan snapshot bersih.';
                }

                $response['next_step']   = 'scan_database';
                $response['progress']    = 85;
                $response['status_text'] = 'Integritas file terverifikasi. Memindai tabel database...';
                $response['logs']        = $logs;
                break;

            case 'scan_database':
                $logs = [];
                $before_count = count($session_data['findings']);
                $this->scan_database_options($session_data['findings'], $session_data['db_audit']);
                $found_here = count($session_data['findings']) - $before_count;
                $session_data['stats']['db_checked'] = count($session_data['db_audit']);

                $logs[] = "Database scan: " . count($session_data['db_audit']) . " pemeriksaan (options, registrasi publik, & akun administrator) dijalankan.";

                if ($found_here > 0) {
                    $logs[] = "Peringatan: Ditemukan {$found_here} anomali/opsi mencurigakan pada database!";
                } else {
                    $logs[] = 'Tabel opsi database & pengaturan registrasi pengguna bersih dari manipulasi.';
                }

                $response['next_step']   = 'scan_core';
                $response['progress']    = 92;
                $response['status_text'] = 'Database options bersih. Memvalidasi Checksums resmi WordPress.org...';
                $response['logs']        = $logs;
                break;

            case 'scan_core':
                $logs = [];
                $before_count = count($session_data['findings']);
                $this->scan_wordpress_core_checksums($session_data['findings'], $session_data['core_audit']);
                $found_here = count($session_data['findings']) - $before_count;
                $session_data['stats']['core_checked'] = count($session_data['core_audit']);

                $logs[] = "WordPress.org Checksums: " . count($session_data['core_audit']) . " file inti diverifikasi ke API resmi.";

                if ($found_here > 0) {
                    $logs[] = "Peringatan Kritis: {$found_here} file resmi WordPress Core gagal verifikasi MD5!";
                } else {
                    $logs[] = 'Official Core Checksums valid: Seluruh file inti WordPress cocok dengan rilis resmi WordPress.org.';
                }

                $response['next_step']   = 'finalize';
                $response['progress']    = 97;
                $response['status_text'] = 'Verifikasi core selesai. Menyusun laporan akhir...';
                $response['logs']        = $logs;
                break;

            case 'finalize':
                $duration = isset($session_data['start_micro']) ? round(microtime(true) - $session_data['start_micro'], 2) : 0;

                $scan_record = [
                    'timestamp'     => current_time('mysql'),
                    'start_time'    => $session_data['start_time'] ?? current_time('mysql'),
                    'duration_sec'  => $duration,
                    'total_issues'  => count($session_data['findings']),
                    'findings'      => $session_data['findings'],
                    'ai_scanned'    => $ai_deep_scan,
                    'skipped_paths' => $session_data['skipped_paths'],
                    'stats'         => $session_data['stats'],
                    'ai_audit'      => $session_data['ai_audit'],
                    'db_audit'      => $session_data['db_audit'],
                    'core_audit'    => $session_data['core_audit'],
                    'scope'         => [
                        'uploads_path' => $uploads_path,
                        'theme_path'   => $theme_dir,
                        'wp_version'   => get_bloginfo('version'),
                        'php_version'  => PHP_VERSION,
                    ],
                ];
                update_option('ajs_last_scan_result', $scan_record);

                $logs = [
                    'Pemindaian menyeluruh berhasil diselesaikan dalam ' . $duration . ' detik!',
                    'Hasil: ' . count($session_data['findings']) . ' masalah terdeteksi | ' . count($session_data['skipped_paths']) . ' path storage jaringan/dikecualikan dilewati.',
                ];

                $response['next_step']   = null;
                $response['progress']    = 100;
                $response['status_text'] = 'Pemindaian 100% Selesai!';
                $response['logs']        = $logs;
                $response['scan_record'] = $scan_record;
                break;
        }

        $response['total_findings'] = count($session_data['findings']);
        $response['skipped_count']  = count($session_data['skipped_paths']);

        return $response;
    }

    public function scan_database_options(array &$findings, array &$db_audit = []): void {
        global $wpdb;
        $patterns = [
            '%slot%gacor%', '%judi%online%', '%maxwin%', '%pragmatic%',
            '%base64_decode(%', '%eval(%', '%scatter%hitam%'
        ];

        $flagged_options = [];

        foreach ($patterns as $p) {
            $results = $wpdb->get_results($wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} 
                 WHERE option_value LIKE %s 
                   AND option_name NOT LIKE '%ajs_%' 
                   AND option_name NOT LIKE '_transient_%ajs_%'
                   AND option_name NOT LIKE '_transient_timeout_%ajs_%'
                 LIMIT 5",
                $p
            ));

            $matched_options = [];
            if (!empty($results)) {
                foreach ($results as $row) {
                    $opt_name = $row->option_name;
                    $matched_options[] = $opt_name;

                    // Cegah duplikasi finding jika opsi yang sama cocok di beberapa pattern
                    if (!isset($flagged_options[$opt_name])) {
                        $flagged_options[$opt_name] = true;
                        $findings[] = [
                            'type'     => 'db_option_tampered',
                            'severity' => 'CRITICAL',
                            'file'     => "Database Option: {$opt_name}",
                            'message'  => 'Ditemukan skrip mencurigakan/konten judi tersimpan di tabel opsi database WordPress.',
                            'healed'   => false,
                        ];
                    }
                }
            }

            $db_audit[] = [
                'pattern' => $p,
                'matched' => $matched_options,
            ];
        }

        // Audit Pengaturan Registrasi Pengguna Ilegal
        $this->audit_user_registration_settings($findings, $db_audit);

        // Audit Akun Administrator di wp_users
        $this->audit_administrator_accounts($findings, $db_audit);

        // Audit Tugas Cron Terjadwal (WP-Cron) untuk Persistensi Backdoor
        $this->audit_cron_jobs($findings, $db_audit);
    }

    public function audit_cron_jobs(array &$findings, array &$db_audit = []): void {
        $crons = _get_cron_array();
        if (empty($crons) || !is_array($crons)) {
            $db_audit[] = [
                'pattern' => 'Audit Tugas Cron Terjadwal (WP-Cron)',
                'matched' => [],
            ];
            return;
        }

        $suspicious_hooks = [];
        foreach ($crons as $timestamp => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }
            foreach ($hooks as $hook_name => $hook_events) {
                $h_lower = strtolower((string)$hook_name);
                if (preg_match('/^(wp_[a-z0-9]{12,}|eval_|shell_|backdoor_|update_user_role_|exec_)/i', (string)$hook_name) ||
                    strpos($h_lower, 'base64') !== false ||
                    strpos($h_lower, 'wp_vcd') !== false ||
                    strpos($h_lower, 'menuhdr') !== false) {
                    $suspicious_hooks[] = (string)$hook_name;
                    $findings[] = [
                        'type'     => 'malicious_cron_job',
                        'severity' => 'CRITICAL',
                        'file'     => "WP Cron Hook: {$hook_name}",
                        'message'  => "Terdeteksi tugas cron terjadwal mencurigakan ({$hook_name}). Peretas sering menggunakan cron untuk terus membuat ulang akun admin.",
                        'healed'   => false,
                    ];
                }
            }
        }

        $db_audit[] = [
            'pattern' => 'Audit Tugas Cron Terjadwal (WP-Cron)',
            'matched' => $suspicious_hooks ?: [],
        ];
    }

    public function audit_user_registration_settings(array &$findings, array &$db_audit = []): void {
        $users_can_register = (int)get_option('users_can_register', 0);
        $default_role       = (string)get_option('default_role', 'subscriber');

        if ($users_can_register === 1 && $default_role === 'administrator') {
            $findings[] = [
                'type'     => 'rogue_admin_registration',
                'severity' => 'CRITICAL',
                'file'     => 'Database Option: default_role (administrator) & users_can_register (1)',
                'message'  => 'BAHAYA KRITIS: Registrasi terbuka aktif dan Role Bawaan adalah Administrator! Penyerang dapat membuat akun admin tanpa batas dari form registrasi publik.',
                'healed'   => false,
            ];
            $db_audit[] = [
                'pattern' => 'Cek Registrasi Terbuka Administrator',
                'matched' => ['users_can_register = 1', 'default_role = administrator (Eksploitasi Aktif!)'],
            ];
        } else {
            $db_audit[] = [
                'pattern' => 'Cek Registrasi Terbuka Administrator',
                'matched' => [],
            ];
        }
    }

    public function audit_administrator_accounts(array &$findings, array &$db_audit = []): void {
        global $wpdb;
        $prefix  = $wpdb->get_blog_prefix();
        $cap_key = $prefix . 'capabilities';

        $admin_users = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered 
             FROM {$wpdb->users} u
             INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
             WHERE m.meta_key = %s AND m.meta_value LIKE %s
             ORDER BY u.user_registered DESC",
            $cap_key,
            '%administrator%'
        ));

        if (!empty($admin_users)) {
            $admin_list = [];
            $suspicious_names = ['admin1', 'admin2', 'wp_admin', 'system', 'root', 'backup', 'support', 'test', 'user', 'manager', 'updater', 'service'];

            foreach ($admin_users as $admin) {
                $login = (string)$admin->user_login;
                $email = (string)$admin->user_email;
                $admin_list[] = "{$login} ({$email}, #{$admin->ID})";

                $is_suspicious_name  = in_array(strtolower($login), $suspicious_names, true);
                $is_suspicious_email = (bool)preg_match('/@(temp|mailinator|guerrillamail|yopmail|disposable|ru|xyz|top|pw)\b/i', $email);

                if ($is_suspicious_name || $is_suspicious_email) {
                    $findings[] = [
                        'type'     => 'suspicious_admin_account',
                        'severity' => 'HIGH',
                        'file'     => "User ID #{$admin->ID}: {$login}",
                        'message'  => "Akun Administrator mencurigakan terdeteksi (Login: {$login}, Email: {$email}, Terdaftar: {$admin->user_registered}). Verifikasi apakah akun ini sah dibuat pemilik situs.",
                        'healed'   => false,
                    ];
                }
            }

            $db_audit[] = [
                'pattern' => 'Audit Akun Administrator (' . count($admin_users) . ' akun ditemukan)',
                'matched' => $admin_list,
            ];
        }
    }

    public function scan_wordpress_core_checksums(array &$findings, array &$core_audit = []): void {
        global $wp_version, $wp_local_package;
        $locale = $wp_local_package ?: 'en_US';
        $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";

        $cache_key = 'ajs_core_checksums_' . md5($wp_version);
        $checksums = get_transient($cache_key);

        if ($checksums === false) {
            $resp = wp_remote_get($api_url, ['timeout' => 8]);
            if (is_wp_error($resp) || wp_remote_retrieve_response_code($resp) !== 200) {
                return;
            }
            $body = json_decode(wp_remote_retrieve_body($resp), true);
            $checksums = $body['checksums'] ?? null;
            if ($checksums) {
                set_transient($cache_key, $checksums, 86400);
            }
        }

        if (empty($checksums) || !is_array($checksums)) {
            return;
        }

        $critical_core = [
            'wp-blog-header.php', 'wp-load.php', 'wp-settings.php',
            'wp-login.php', 'index.php', 'xmlrpc.php',
            'wp-includes/version.php', 'wp-includes/load.php', 'wp-includes/default-filters.php'
        ];

        foreach ($critical_core as $file) {
            if (!isset($checksums[$file])) {
                continue;
            }
            $abs_file = ABSPATH . $file;
            if (!file_exists($abs_file)) {
                $core_audit[] = [
                    'file'   => $file,
                    'status' => 'missing',
                    'md5'    => '-',
                ];
                continue;
            }

            $local_md5 = md5_file($abs_file);
            $is_valid  = ($local_md5 === $checksums[$file]);

            $core_audit[] = [
                'file'      => $file,
                'status'    => $is_valid ? 'valid' : 'tampered',
                'local_md5' => $local_md5,
                'wp_md5'    => $checksums[$file],
            ];

            if (!$is_valid) {
                $findings[] = [
                    'type'     => 'core_file_tampered',
                    'severity' => 'CRITICAL',
                    'file'     => esc_html($abs_file),
                    'message'  => 'Integritas file resmi WordPress gagal (Official MD5 mismatch: file core WordPress telah dimodifikasi oleh peretas).',
                    'healed'   => false,
                ];
            }
        }

        // Deteksi file .php liar/asing di direktori wp-includes/ yang tidak ada dalam checksums resmi
        $inc_dir = ABSPATH . (defined('WPINC') ? WPINC : 'wp-includes');
        if (is_dir($inc_dir)) {
            $extra_files = @glob($inc_dir . '/*.php');
            if ($extra_files) {
                foreach ($extra_files as $ef) {
                    $rel_path = 'wp-includes/' . basename($ef);
                    if (!isset($checksums[$rel_path])) {
                        $findings[] = [
                            'type'     => 'rogue_core_file',
                            'severity' => 'CRITICAL',
                            'file'     => $ef,
                            'message'  => 'Ditemukan file skrip asing di direktori wp-includes! File ini bukan bagian resmi WordPress (berpotensi kuat backdoor tersembunyi seperti wp-vcd/fake core).',
                            'healed'   => false,
                        ];
                        $core_audit[] = [
                            'file'      => $rel_path,
                            'status'    => 'rogue_file',
                            'local_md5' => md5_file($ef) ?: '-',
                            'wp_md5'    => 'TIDAK TERDAFTAR (ILEGAL)',
                        ];
                    }
                }
            }
        }
    }

    private function scan_posts_for_judol(array &$findings, bool $auto_heal = false, array &$ai_audit = []): void {
        $posts = get_posts([
            'post_type'      => ['post', 'page'],
            'post_status'    => 'publish',
            'posts_per_page' => 20,
            'orderby'        => 'post_modified',
            'order'          => 'DESC',
        ]);

        foreach ($posts as $p) {
            $text_sample = $p->post_title . "\n" . wp_strip_all_tags($p->post_content);
            $ai_check    = $this->ai ? $this->ai->inspect_content($text_sample) : ['is_threat' => false, 'reason' => 'AI nonaktif'];
            $is_threat   = !empty($ai_check['is_threat']);
            $healed      = false;

            if ($is_threat) {
                if ($auto_heal) {
                    // Pull post from public viewing to draft status immediately
                    wp_update_post([
                        'ID'          => $p->ID,
                        'post_status' => 'draft',
                    ]);
                    $healed = true;
                }

                $findings[] = [
                    'type'     => 'injected_post',
                    'severity' => 'CRITICAL',
                    'file'     => esc_html("Post ID #{$p->ID}: {$p->post_title}"),
                    'message'  => 'Konten disusupi materi judi online (Analisis AI: ' . ($ai_check['reason'] ?? '') . ')',
                    'healed'   => $healed,
                ];
            }

            $ai_audit[] = [
                'id'             => $p->ID,
                'title'          => $p->post_title,
                'type'           => $p->post_type,
                'modified'       => $p->post_modified,
                'word_count'     => str_word_count(wp_strip_all_tags($text_sample)),
                'char_length'    => strlen($text_sample),
                'sample_snippet' => mb_substr($text_sample, 0, 250) . (strlen($text_sample) > 250 ? '...' : ''),
                'system_prompt'  => $ai_check['system_prompt'] ?? ($this->ai ? $this->ai->get_system_prompt() : ''),
                'user_prompt'    => $ai_check['user_prompt'] ?? ("Periksa konten berikut:\n\n" . substr($text_sample, 0, 2500)),
                'model'          => $ai_check['model'] ?? ($this->ai ? $this->ai->get_model() : ''),
                'endpoint'       => $ai_check['endpoint'] ?? ($this->ai ? $this->ai->get_endpoint() : ''),
                'is_threat'      => $is_threat,
                'reason'         => $ai_check['reason'] ?? 'Aman',
                'raw_reply'      => $ai_check['raw_reply'] ?? '',
                'action'         => $healed ? 'Drafted (Auto-Healed)' : ($is_threat ? 'Terdeteksi (Perlu Tindakan)' : 'Aman (Dipublikasi)'),
            ];
        }
    }

    private function scan_directory_for_scripts(string $dir, array &$findings, bool $auto_heal, array &$skipped_paths = [], int &$scanned_count = 0): void {
        $excluded_rules = $this->get_excluded_paths();
        $skip_nfs       = (int)get_option('ajs_scan_skip_nfs', 1) === 1;
        $network_mounts = $skip_nfs ? $this->get_network_mounts() : [];

        try {
            $dir_iterator = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);

            // Filter mount NFS dan folder yang dikecualikan SEBELUM masuk ke dalamnya
            $filter = new RecursiveCallbackFilterIterator($dir_iterator, function ($current, $key, $iterator) use ($excluded_rules, $network_mounts, $skip_nfs, &$skipped_paths) {
                if ($current->isDir() || $current->isLink()) {
                    $path = $current->getPathname();
                    $reason = '';
                    if ($this->is_path_excluded($path, $excluded_rules, $network_mounts, $skip_nfs, $reason)) {
                        $skipped_paths[] = [
                            'path'   => $path,
                            'reason' => $reason ?: 'Dikecualikan dari pemindaian',
                        ];
                        return false; // Jangan masuki folder ini (menghemat I/O jaringan NFS)
                    }
                }
                return true;
            });

            $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);

            $file_count = 0;
            $max_files  = (int)apply_filters('ajs_scan_max_files', 30000);

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $file_count++;
                    $scanned_count++;
                    if ($file_count > $max_files) {
                        $skipped_paths[] = [
                            'path'   => $dir,
                            'reason' => "Batas keamanan jumlah file ({$max_files} file) tercapai.",
                        ];
                        break;
                    }

                    $ext = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
                    if (in_array($ext, $this->suspicious_extensions, true)) {
                        $file_path = $item->getPathname();
                        $healed = false;

                        if ($auto_heal) {
                            $quarantine_path = $file_path . '.quarantine_bak';
                            if (@rename($file_path, $quarantine_path)) {
                                $healed = true;
                            }
                        }

                        $findings[] = [
                            'type'     => 'uploads_executable',
                            'severity' => 'CRITICAL',
                            'file'     => $file_path,
                            'message'  => 'Ditemukan file skrip berbahaya di direktori uploads.',
                            'healed'   => $healed,
                        ];
                    }
                }
            }
        } catch (Throwable $e) {
            // Tangani error permission atau folder NFS unreadable/stale
        }
    }

    private function scan_directory_for_signatures(
        string $dir,
        array &$findings,
        array &$skipped_paths = [],
        int &$scanned_count = 0,
        array &$suspicious_files = []
    ): void {
        $excluded_rules = $this->get_excluded_paths();
        $skip_nfs       = (int)get_option('ajs_scan_skip_nfs', 1) === 1;
        $network_mounts = $skip_nfs ? $this->get_network_mounts() : [];

        try {
            $dir_iterator = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);

            $filter = new RecursiveCallbackFilterIterator($dir_iterator, function ($current, $key, $iterator) use ($excluded_rules, $network_mounts, $skip_nfs, &$skipped_paths) {
                if ($current->isDir() || $current->isLink()) {
                    $path = $current->getPathname();
                    $reason = '';
                    if ($this->is_path_excluded($path, $excluded_rules, $network_mounts, $skip_nfs, $reason)) {
                        $skipped_paths[] = [
                            'path'   => $path,
                            'reason' => $reason ?: 'Dikecualikan dari pemindaian',
                        ];
                        return false;
                    }
                }
                return true;
            });

            $iterator = new RecursiveIteratorIterator($filter);
            $max_size = 500 * 1024; // Batas 500KB per file untuk efisiensi scanner
            $max_files = 15000;
            $files_done = 0;

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $files_done++;
                    $scanned_count++;
                    if ($files_done > $max_files) {
                        break;
                    }

                    $ext = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
                    if ($ext === 'php' && $item->getSize() <= $max_size) {
                        $file_path = $item->getPathname();

                        // Abaikan file yang telah masuk daftar Whitelist oleh Admin/AI
                        $whitelisted_files = (array)get_option('ajs_whitelisted_files', []);
                        if (in_array($file_path, $whitelisted_files, true)) {
                            continue;
                        }

                        $content = @file_get_contents($file_path);
                        if ($content === false) {
                            continue;
                        }

                        $file_flagged = false;

                        // 1. Cek Signature Webshell & RCE Terkenal
                        foreach ($this->backdoor_signatures as $sig) {
                            $pos = stripos($content, $sig);
                            if ($pos !== false) {
                                $findings[] = [
                                    'type'     => 'backdoor_signature',
                                    'severity' => 'CRITICAL',
                                    'file'     => $file_path,
                                    'message'  => "Terdeteksi pola malware/webshell: '{$sig}'",
                                    'healed'   => false,
                                ];
                                $start = max(0, $pos - 300);
                                $suspicious_files[] = [
                                    'path'      => $file_path,
                                    'snippet'   => substr($content, $start, 2500),
                                    'signature' => $sig,
                                ];
                                $file_flagged = true;
                                break;
                            }
                        }

                        if ($file_flagged) {
                            continue;
                        }

                        // 2. Cek Vektor Pembuatan User Ilegal / Backdoor Administrator
                        $matched_vector = null;
                        $has_user_func  = stripos($content, 'wp_create_user') !== false || stripos($content, 'wp_insert_user') !== false;

                        if ($has_user_func) {
                            $has_admin_escalation = stripos($content, "'administrator'") !== false ||
                                                    stripos($content, '"administrator"') !== false ||
                                                    (stripos($content, 'administrator') !== false && stripos($content, 'set_role') !== false);
                            $has_backdoor_input   = stripos($content, '$_GET') !== false || stripos($content, '$_REQUEST') !== false;
                            $has_unauth_hook      = stripos($content, "'init'") !== false || stripos($content, '"init"') !== false ||
                                                    stripos($content, "'wp_loaded'") !== false || stripos($content, '"wp_loaded"') !== false;

                            // Abaikan registrasi customer/subscriber sah pada plugin e-commerce / LMS resmi
                            $is_legit_role = stripos($content, "'customer'") !== false || stripos($content, '"customer"') !== false ||
                                             stripos($content, "'subscriber'") !== false || stripos($content, '"subscriber"') !== false ||
                                             stripos($content, 'wc_create_new_customer') !== false || stripos($content, 'learnpress') !== false;

                            if (($has_admin_escalation && ($has_backdoor_input || $has_unauth_hook)) && !$is_legit_role) {
                                $matched_vector = 'wp_create_user/wp_insert_user (Injeksi User Admin Ilegal)';
                            }
                        } elseif ((stripos($content, 'set_role(\'administrator\')') !== false ||
                                   stripos($content, 'set_role("administrator")') !== false ||
                                   stripos($content, 'add_cap(\'administrator\')') !== false ||
                                   stripos($content, 'add_cap("administrator")') !== false) &&
                                  stripos($content, 'current_user_can') === false &&
                                  stripos($content, 'map_meta_cap') === false) {
                            $matched_vector = 'Eskalasi Role Administrator Tersembunyi (set_role/add_cap)';
                        } elseif (stripos($content, 'pre_option_default_role') !== false ||
                                  stripos($content, 'pre_option_users_can_register') !== false) {
                            $matched_vector = 'Pembajakan Filter Registrasi (pre_option_default_role)';
                        } elseif (stripos($content, 'update_option(\'default_role\', \'administrator\'') !== false ||
                                  stripos($content, 'update_option("default_role", "administrator"') !== false) {
                            $matched_vector = 'Injeksi Default Role Administrator di Database';
                        }

                        if ($matched_vector !== null) {
                            $pos   = stripos($content, 'wp_create_user') ?: stripos($content, 'administrator');
                            $start = max(0, ($pos ?: 0) - 300);
                            $findings[] = [
                                'type'     => 'rogue_user_backdoor',
                                'severity' => 'CRITICAL',
                                'file'     => $file_path,
                                'message'  => "Terdeteksi pola skrip pembuat user ilegal/backdoor admin: '{$matched_vector}'",
                                'healed'   => false,
                            ];
                            $suspicious_files[] = [
                                'path'      => $file_path,
                                'snippet'   => substr($content, $start, 2500),
                                'signature' => $matched_vector,
                            ];
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            // Tangani error permission atau file unreadable
        }
    }

    public function scan_root_php_files(array &$findings, array &$suspicious_files = [], int &$scanned_count = 0): void {
        $root_files = @glob(ABSPATH . '*.php');
        if (!$root_files) {
            return;
        }

        foreach ($root_files as $file_path) {
            $scanned_count++;
            $filename = basename($file_path);
            if (in_array(strtolower($filename), $this->official_root_files, true)) {
                continue;
            }

            $content = (string)@file_get_contents($file_path);
            $snippet = substr($content, 0, 2500);

            $findings[] = [
                'type'     => 'rogue_root_file',
                'severity' => 'CRITICAL',
                'file'     => $file_path,
                'message'  => "Ditemukan file skrip PHP tidak resmi di direktori root WordPress ({$filename}). Berpotensi kuat sebagai webshell/backdoor.",
                'healed'   => false,
            ];

            $suspicious_files[] = [
                'path'      => $file_path,
                'snippet'   => $snippet,
                'signature' => 'Rogue root PHP file (' . $filename . ')',
            ];
        }
    }

    private function scan_suspicious_files_with_ai(array $suspicious_files, array &$findings, array &$ai_audit = []): void {
        if (!$this->ai || !$this->ai->is_configured() || empty($suspicious_files)) {
            return;
        }

        // Batasi maksimal 25 file per scan agar tidak melebihi kuota/timeout API
        $files_to_check = array_slice($suspicious_files, 0, 25);

        foreach ($files_to_check as $item) {
            $file_path = $item['path'];
            $snippet   = $item['snippet'] ?? '';

            if (empty($snippet) && file_exists($file_path)) {
                $snippet = (string)@file_get_contents($file_path);
            }

            if (empty($snippet)) {
                continue;
            }

            $ai_check  = $this->ai->inspect_code($snippet, $file_path);
            $is_threat = !empty($ai_check['is_threat']);

            if ($is_threat) {
                // Perbarui pesan temuan yang ada dengan penjelasan detail AI
                $updated = false;
                foreach ($findings as &$f) {
                    if (($f['file'] ?? '') === $file_path) {
                        $f['message'] .= ' (Analisis AI: ' . ($ai_check['reason'] ?? 'Backdoor terverifikasi') . ')';
                        $f['severity'] = 'CRITICAL';
                        $updated = true;
                        break;
                    }
                }
                unset($f);

                if (!$updated) {
                    $findings[] = [
                        'type'     => 'ai_backdoor_detected',
                        'severity' => 'CRITICAL',
                        'file'     => $file_path,
                        'message'  => 'AI Screening mendeteksi backdoor: ' . ($ai_check['reason'] ?? 'Ancaman kode berbahaya'),
                        'healed'   => false,
                    ];
                }
            } else {
                // AI menyatakan file ini aman / false positive pada plugin resmi
                // Hapus dari temuan aktif agar website bersih dari laporan palsu
                foreach ($findings as $k => $f) {
                    if (($f['file'] ?? '') === $file_path && in_array($f['type'], ['rogue_user_backdoor', 'backdoor_signature', 'suspicious_code'], true)) {
                        unset($findings[$k]);
                    }
                }
                $findings = array_values($findings);
            }

            $ai_audit[] = [
                'id'             => 'FILE-' . substr(md5($file_path), 0, 5),
                'title'          => basename($file_path) . ' (' . wp_make_link_relative($file_path) . ')',
                'type'           => 'file_php',
                'modified'       => file_exists($file_path) ? date('Y-m-d H:i:s', filemtime($file_path)) : '-',
                'word_count'     => str_word_count($snippet),
                'char_length'    => strlen($snippet),
                'sample_snippet' => mb_substr($snippet, 0, 250) . (strlen($snippet) > 250 ? '...' : ''),
                'system_prompt'  => $ai_check['system_prompt'] ?? $this->ai->get_code_system_prompt(),
                'user_prompt'    => $ai_check['user_prompt'] ?? '',
                'model'          => $ai_check['model'] ?? $this->ai->get_model(),
                'endpoint'       => $ai_check['endpoint'] ?? $this->ai->get_endpoint(),
                'is_threat'      => $is_threat,
                'reason'         => $ai_check['reason'] ?? 'Aman',
                'raw_reply'      => $ai_check['raw_reply'] ?? '',
                'action'         => $is_threat ? 'Karantina / Hapus File' : 'Aman (Kode Normal)',
            ];
        }
    }

    public function get_baseline_dir(): string {
        return $this->auto_heal->get_baseline_dir();
    }

    public function get_critical_files(): array {
        return $this->auto_heal->get_critical_files();
    }

    public function create_integrity_baseline(): int {
        return $this->auto_heal->create_integrity_baseline();
    }

    public function verify_and_auto_heal(): array {
        return $this->auto_heal->verify_and_auto_heal();
    }

    public function auto_heal_tick(): void {
        $this->auto_heal->auto_heal_tick();
    }

    public function get_nginx_rules(): string {
        return "# Anti-Judol Shield - Nginx Security Rules\n" .
               "# 1. Blokir eksekusi file PHP di wp-content/uploads\n" .
               "location ~* ^/wp-content/uploads/.*\\.(php|phps|phtml|phar)$ {\n" .
               "    deny all;\n" .
               "    return 403;\n" .
               "}\n\n" .
               "# 2. Blokir akses xmlrpc.php\n" .
               "location = /xmlrpc.php {\n" .
               "    deny all;\n" .
               "    access_log off;\n" .
               "    log_not_found off;\n" .
               "    return 403;\n" .
               "}\n\n" .
               "# 3. Blokir author scan\n" .
               "if (\$query_string ~ \"author=\\d+\") {\n" .
               "    return 403;\n" .
               "}\n";
    }
}
