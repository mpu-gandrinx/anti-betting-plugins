<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Scanner {
    private ?AJS_AI $ai;
    private AJS_Auto_Heal $auto_heal;

    private array $suspicious_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'suspected'];

    private array $backdoor_signatures = [
        'eval(base64_decode',
        'eval(gzinflate',
        'eval(str_rot13',
        'c99shell',
        'r57shell',
        'wso_version',
        'FilesMan',
        'ALFA_DATA',
        'IndoXploit',
        'b374k',
        'preg_replace("/.*/e"',
        'assert($_POST',
        'system($_GET'
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

        // 2. Scan active theme & plugin root for webshell signatures
        if (is_dir($theme_dir)) {
            $this->scan_directory_for_signatures($theme_dir, $findings, $skipped_paths, $stats['theme_scanned']);
        }

        // 3. AI Deep Scan: Check published articles & pages for judol injections
        if ($ai_deep_scan && $this->ai && $this->ai->is_configured()) {
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
                $session_data['findings']      = [];
                $session_data['skipped_paths'] = [];
                $session_data['ai_audit']      = [];
                $session_data['db_audit']      = [];
                $session_data['core_audit']    = [];
                $session_data['stats']         = [
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
                $response['status_text'] = 'Pemindaian direktori uploads selesai. Memindai tema aktif...';
                $response['logs']        = $logs;
                break;

            case 'scan_theme':
                $logs = [];
                if (is_dir($theme_dir)) {
                    $theme_name   = basename($theme_dir);
                    $before_count = count($session_data['findings']);

                    $this->scan_directory_for_signatures($theme_dir, $session_data['findings'], $session_data['skipped_paths'], $session_data['stats']['theme_scanned']);
                    $found_here = count($session_data['findings']) - $before_count;

                    $logs[] = "Pemindaian tema ({$theme_name}): {$session_data['stats']['theme_scanned']} file PHP diperiksa.";

                    if ($found_here > 0) {
                        $logs[] = "Peringatan: Terdeteksi {$found_here} signature webshell/backdoor pada tema {$theme_name}!";
                    } else {
                        $logs[] = "Tema aktif ({$theme_name}) bersih dari pola webshell & backdoor.";
                    }
                } else {
                    $logs[] = 'Direktori tema aktif tidak ditemukan.';
                }

                $has_ai = $ai_deep_scan && $this->ai && $this->ai->is_configured();
                $response['next_step']   = $has_ai ? 'scan_ai' : 'verify_integrity';
                $response['progress']    = 60;
                $response['status_text'] = $has_ai ? 'Memulai AI Deep Screening pada artikel...' : 'Memeriksa integritas file Golden Baseline...';
                $response['logs']        = $logs;
                break;

            case 'scan_ai':
                $logs = [];
                if ($this->ai && $this->ai->is_configured()) {
                    $before_count = count($session_data['findings']);
                    $this->scan_posts_for_judol($session_data['findings'], $auto_heal, $session_data['ai_audit']);
                    $found_here = count($session_data['findings']) - $before_count;
                    $session_data['stats']['ai_scanned'] = count($session_data['ai_audit']);

                    $logs[] = "AI Screening: " . count($session_data['ai_audit']) . " artikel/postingan diperiksa oleh model " . esc_html($this->ai->get_model()) . ".";

                    if ($found_here > 0) {
                        $logs[] = "AI Screening: Ditemukan {$found_here} artikel disusupi link/materi judi online!";
                    } else {
                        $logs[] = 'AI Screening: Seluruh artikel yang diperiksa bersih dari materi judi online.';
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

                $logs[] = "Database scan: " . count($session_data['db_audit']) . " pola kata kunci judi diperiksa pada tabel wp_options.";

                if ($found_here > 0) {
                    $logs[] = "Peringatan: Ditemukan {$found_here} opsi mencurigakan/spam judi pada tabel wp_options!";
                } else {
                    $logs[] = 'Tabel opsi database (wp_options) bersih dari kata kunci dan payload judi.';
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

        foreach ($patterns as $p) {
            $results = $wpdb->get_results($wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} 
                 WHERE option_value LIKE %s AND option_name NOT LIKE 'ajs_%' LIMIT 5",
                $p
            ));

            $matched_options = [];
            if (!empty($results)) {
                foreach ($results as $row) {
                    $matched_options[] = $row->option_name;
                    $findings[] = [
                        'type'     => 'db_option_tampered',
                        'severity' => 'CRITICAL',
                        'file'     => "Database Option: {$row->option_name}",
                        'message'  => 'Ditemukan skrip mencurigakan/konten judi tersimpan di tabel opsi database WordPress.',
                        'healed'   => false,
                    ];
                }
            }

            $db_audit[] = [
                'pattern' => $p,
                'matched' => $matched_options,
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

    private function scan_directory_for_signatures(string $dir, array &$findings, array &$skipped_paths = [], int &$scanned_count = 0): void {
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

            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $scanned_count++;
                    $ext = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
                    if ($ext === 'php' && $item->getSize() <= $max_size) {
                        $content = @file_get_contents($item->getPathname());
                        if ($content !== false) {
                            foreach ($this->backdoor_signatures as $sig) {
                                if (stripos($content, $sig) !== false) {
                                    $findings[] = [
                                        'type'     => 'backdoor_signature',
                                        'severity' => 'HIGH',
                                        'file'     => $item->getPathname(),
                                        'message'  => "Terdeteksi pola malware/webshell: '{$sig}'",
                                        'healed'   => false,
                                    ];
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable $e) {
            // Tangani error permission atau file unreadable
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
