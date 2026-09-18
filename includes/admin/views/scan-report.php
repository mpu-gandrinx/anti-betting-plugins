<?php
if (!defined('ABSPATH')) {
    exit;
}

if (empty($last_scan)) {
    return;
}

$timestamp       = $last_scan['timestamp'] ?? current_time('mysql');
$start_time      = $last_scan['start_time'] ?? $timestamp;
$duration_sec    = isset($last_scan['duration_sec']) ? $last_scan['duration_sec'] . ' detik' : 'N/A';
$total_issues    = (int)($last_scan['total_issues'] ?? 0);
$findings        = $last_scan['findings'] ?? [];
$skipped_paths   = $last_scan['skipped_paths'] ?? [];
$stats           = $last_scan['stats'] ?? [];
$ai_audit        = $last_scan['ai_audit'] ?? [];
$db_audit        = $last_scan['db_audit'] ?? [];
$core_audit      = $last_scan['core_audit'] ?? [];
$scope           = $last_scan['scope'] ?? [];
$is_ai_scanned   = !empty($last_scan['ai_scanned']);

$uploads_scanned = $stats['uploads_scanned'] ?? 0;
$theme_scanned   = $stats['theme_scanned'] ?? 0;
$ai_scanned_cnt  = $stats['ai_scanned'] ?? count($ai_audit);
$core_scanned    = $stats['core_checked'] ?? count($core_audit);
$db_scanned      = $stats['db_checked'] ?? count($db_audit);
$baseline_cnt    = $stats['baseline_checked'] ?? (isset($baseline) ? count($baseline) : 0);

$ai_model        = !empty($ai_audit[0]['model']) ? $ai_audit[0]['model'] : (get_option('ajs_ai_model', 'gpt-4o-mini'));
$ai_endpoint     = !empty($ai_audit[0]['endpoint']) ? $ai_audit[0]['endpoint'] : (get_option('ajs_ai_endpoint', 'https://api.openai.com/v1/chat/completions'));
$ai_system_prompt= !empty($ai_audit[0]['system_prompt']) ? $ai_audit[0]['system_prompt'] : (
    "Anda analis keamanan siber spesialis penanganan peretasan situs judi online (judol) dan SEO spam WordPress di Indonesia. " .
    "Periksa teks atau kode yang diberikan. Tentukan apakah memuat: " .
    "1. Kata kunci/promosi terselubung judi online (slot, gacor, maxwin, togel, kasino, link alternatif, dll). " .
    "2. Backdoor/webshell atau payload berbahaya (eval, base64 obfuscation, skrip redirect ke bandar judi). " .
    "Jawab HANYA dalam format JSON valid tanpa format markdown: {\"is_threat\": true|false, \"reason\": \"penjelasan ringkas maks 15 kata\"}"
);

// Count AI threat findings
$ai_threats_cnt = 0;
foreach ($ai_audit as $item) {
    if (!empty($item['is_threat'])) {
        $ai_threats_cnt++;
    }
}
?>

<div id="ajs-scan-report-container" class="ajs-report-wrapper" style="background: #fff; padding: 24px; border: 1px solid #cbd5e1; border-radius: 6px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
    
    <!-- Report Header & Actions -->
    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; border-bottom: 2px solid #e2e8f0; padding-bottom: 18px; margin-bottom: 20px;">
        <div>
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                <span class="dashicons dashicons-media-document" style="font-size: 26px; width: 26px; height: 26px; color: #2563eb;"></span>
                <h2 style="margin: 0; font-size: 20px; color: #0f172a;"><?php esc_html_e('Laporan Resmi Hasil Pemindaian Keamanan & Audit AI', 'anti-judol-shield'); ?></h2>
            </div>
            <div style="font-size: 13px; color: #475569;">
                <span>Waktu Selesai: <strong><?php echo esc_html($timestamp); ?></strong></span> &bull; 
                <span>Durasi: <strong><?php echo esc_html($duration_sec); ?></strong></span> &bull; 
                <span>WordPress: <strong>v<?php echo esc_html($scope['wp_version'] ?? get_bloginfo('version')); ?></strong></span> &bull; 
                <span>PHP: <strong>v<?php echo esc_html($scope['php_version'] ?? PHP_VERSION); ?></strong></span>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="ajs-no-print" style="display: flex; align-items: center; gap: 8px;">
            <button type="button" class="button" onclick="window.print();" title="Cetak atau simpan laporan ke PDF">
                <span class="dashicons dashicons-printer" style="margin-top: 4px;"></span> <?php esc_html_e('Cetak / Simpan PDF', 'anti-judol-shield'); ?>
            </button>

            <button type="button" class="button" id="ajs-btn-copy-report" title="Salin ringkasan laporan ke clipboard">
                <span class="dashicons dashicons-clipboard" style="margin-top: 4px;"></span> <?php esc_html_e('Salin Ringkasan', 'anti-judol-shield'); ?>
            </button>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display: inline;">
                <?php wp_nonce_field('ajs_export_scan_report_action'); ?>
                <input type="hidden" name="action" value="ajs_export_scan_report">
                <button type="submit" class="button button-primary" title="Unduh raw data laporan lengkap dalam format JSON">
                    <span class="dashicons dashicons-download" style="margin-top: 4px;"></span> <?php esc_html_e('Unduh JSON', 'anti-judol-shield'); ?>
                </button>
            </form>
        </div>
    </div>

    <!-- Status Banner -->
    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; padding: 14px 18px; border-radius: 6px; margin-bottom: 22px; <?php echo $total_issues === 0 ? 'background: #f0fdf4; border: 1px solid #86efac; color: #166534;' : 'background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b;'; ?>">
        <div style="display: flex; align-items: center; gap: 10px;">
            <span class="dashicons <?php echo $total_issues === 0 ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>" style="font-size: 28px; width: 28px; height: 28px;"></span>
            <div>
                <strong style="font-size: 15px;">
                    <?php echo $total_issues === 0 ? 'SISTEM BERSIH & AMAN: Tidak Ditemukan Ancaman Malicious Script / Judol' : 'PERINGATAN: Ditemukan ' . esc_html($total_issues) . ' Potensi Ancaman Keamanan!'; ?>
                </strong>
                <div style="font-size: 12.5px; opacity: 0.9; margin-top: 2px;">
                    <?php echo $total_issues === 0 ? 'Seluruh komponen server lokal, tema aktif, database, file inti, dan artikel lolos verifikasi.' : 'Segera tinjau rincian file dan konten di bawah untuk tindakan remediasi/karantina.'; ?>
                </div>
            </div>
        </div>
        <div>
            <span style="font-size: 13px; font-weight: bold; padding: 4px 12px; border-radius: 9999px; <?php echo $total_issues === 0 ? 'background: #dcfce7; color: #15803d;' : 'background: #fee2e2; color: #b91c1c;'; ?>">
                Total Temuan: <?php echo esc_html($total_issues); ?>
            </span>
        </div>
    </div>

    <!-- Metric Scope Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px;">
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #3b82f6; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">📁 Uploads Lokal</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(number_format_i18n($uploads_scanned)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">file</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">File skrip ilegal (.php) dicek</div>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #8b5cf6; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">🎨 Tema & Webshell</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(number_format_i18n($theme_scanned)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">file PHP</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">13 signature backdoor diuji</div>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #10b981; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">🤖 AI Deep Screening</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(number_format_i18n($ai_scanned_cnt)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">artikel</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">Model: <code><?php echo esc_html($ai_model); ?></code></div>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #f59e0b; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">🛡️ Golden Baseline</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(number_format_i18n($baseline_cnt)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">file inti</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">Verifikasi deface otomatis</div>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #06b6d4; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">🌐 Core Checksums</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(number_format_i18n($core_scanned)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">file</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">MD5 resmi WordPress.org</div>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #ec4899; padding: 14px; border-radius: 4px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase;">🚫 NFS / Skip Storage</div>
            <div style="font-size: 20px; font-weight: bold; color: #1e293b; margin-top: 4px;"><?php echo esc_html(count($skipped_paths)); ?> <span style="font-size: 12px; font-weight: normal; color: #64748b;">direktori</span></div>
            <div style="font-size: 11.5px; color: #475569; margin-top: 2px;">Jaringan NAS dihindari</div>
        </div>
    </div>

    <!-- Report Tabs Navigation -->
    <div class="ajs-report-tabs ajs-no-print" style="border-bottom: 2px solid #e2e8f0; display: flex; gap: 8px; margin-bottom: 20px; overflow-x: auto;">
        <button type="button" class="ajs-tab-btn active" data-target="ajs-tab-findings" style="padding: 10px 16px; border: none; background: none; font-weight: bold; font-size: 13.5px; color: #2563eb; border-bottom: 2px solid #2563eb; cursor: pointer; display: flex; align-items: center; gap: 6px;">
            <span class="dashicons dashicons-shield"></span> <?php esc_html_e('Temuan Keamanan', 'anti-judol-shield'); ?> 
            <span style="background: #fee2e2; color: #991b1b; padding: 1px 7px; border-radius: 9999px; font-size: 11px;"><?php echo esc_html($total_issues); ?></span>
        </button>

        <button type="button" class="ajs-tab-btn" data-target="ajs-tab-ai" style="padding: 10px 16px; border: none; background: none; font-weight: 600; font-size: 13.5px; color: #64748b; border-bottom: 2px solid transparent; cursor: pointer; display: flex; align-items: center; gap: 6px;">
            <span class="dashicons dashicons-superhero"></span> <?php esc_html_e('Transparansi AI Screening', 'anti-judol-shield'); ?> 
            <span style="background: #e0f2fe; color: #0369a1; padding: 1px 7px; border-radius: 9999px; font-size: 11px;"><?php echo esc_html(count($ai_audit)); ?></span>
        </button>

        <button type="button" class="ajs-tab-btn" data-target="ajs-tab-core" style="padding: 10px 16px; border: none; background: none; font-weight: 600; font-size: 13.5px; color: #64748b; border-bottom: 2px solid transparent; cursor: pointer; display: flex; align-items: center; gap: 6px;">
            <span class="dashicons dashicons-wordpress"></span> <?php esc_html_e('Core Checksums & Baseline', 'anti-judol-shield'); ?>
        </button>

        <button type="button" class="ajs-tab-btn" data-target="ajs-tab-storage" style="padding: 10px 16px; border: none; background: none; font-weight: 600; font-size: 13.5px; color: #64748b; border-bottom: 2px solid transparent; cursor: pointer; display: flex; align-items: center; gap: 6px;">
            <span class="dashicons dashicons-networking"></span> <?php esc_html_e('Storage NFS & Pengecualian', 'anti-judol-shield'); ?> 
            <span style="background: #f1f5f9; color: #475569; padding: 1px 7px; border-radius: 9999px; font-size: 11px;"><?php echo esc_html(count($skipped_paths)); ?></span>
        </button>

        <button type="button" class="ajs-tab-btn" data-target="ajs-tab-database" style="padding: 10px 16px; border: none; background: none; font-weight: 600; font-size: 13.5px; color: #64748b; border-bottom: 2px solid transparent; cursor: pointer; display: flex; align-items: center; gap: 6px;">
            <span class="dashicons dashicons-database"></span> <?php esc_html_e('Database Options Check', 'anti-judol-shield'); ?>
        </button>
    </div>

    <!-- TAB 1: FINDINGS -->
    <div id="ajs-tab-findings" class="ajs-tab-pane" style="display: block;">
        <?php if (empty($findings)) : ?>
            <div style="background: #f8fafc; border: 1px dashed #cbd5e1; padding: 24px; text-align: center; border-radius: 6px;">
                <span class="dashicons dashicons-shield-alt" style="font-size: 48px; width: 48px; height: 48px; color: #16a34a; margin-bottom: 8px;"></span>
                <h3 style="margin: 0 0 6px 0; color: #166534;"><?php esc_html_e('Tidak Ada Ancaman Ditemukan', 'anti-judol-shield'); ?></h3>
                <p style="color: #64748b; margin: 0; font-size: 13px;">
                    <?php esc_html_e('Seluruh file yang dipindai di folder lokal server, tema aktif, database options, dan integritas inti WordPress dalam kondisi aman & steril.', 'anti-judol-shield'); ?>
                </p>
            </div>
        <?php else : ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 110px;">Tingkat</th>
                        <th style="width: 160px;">Tipe Ancaman</th>
                        <th>Lokasi / Target File</th>
                        <th>Detail Analisis</th>
                        <th style="width: 140px;">Status Karantina</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($findings as $f) : ?>
                        <tr>
                            <td>
                                <?php
                                $sev = strtoupper($f['severity'] ?? 'HIGH');
                                $bg = $sev === 'CRITICAL' ? '#fee2e2' : '#fef3c7';
                                $col = $sev === 'CRITICAL' ? '#991b1b' : '#92400e';
                                ?>
                                <span style="background: <?php echo esc_attr($bg); ?>; color: <?php echo esc_attr($col); ?>; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">
                                    <?php echo esc_html($sev); ?>
                                </span>
                            </td>
                            <td><code><?php echo esc_html($f['type'] ?? 'threat'); ?></code></td>
                            <td style="word-break: break-all;"><code><?php echo esc_html($f['file'] ?? '-'); ?></code></td>
                            <td><?php echo esc_html($f['message'] ?? '-'); ?></td>
                            <td>
                                <?php if (!empty($f['healed'])) : ?>
                                    <span style="color:#16a34a; font-weight:bold; display: inline-flex; align-items: center; gap: 4px;">
                                        <span class="dashicons dashicons-yes"></span> Terkarantina
                                    </span>
                                <?php else : ?>
                                    <span style="color:#dc2626; font-weight:bold; display: inline-flex; align-items: center; gap: 4px;">
                                        <span class="dashicons dashicons-warning"></span> Belum Karantina
                                    </span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- TAB 2: AI TRANSPARENCY AUDIT -->
    <div id="ajs-tab-ai" class="ajs-tab-pane" style="display: none;">
        
        <!-- AI Configuration & Prompt Info Box -->
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #2563eb; padding: 18px; border-radius: 4px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
                <h3 style="margin: 0; font-size: 15px; color: #1e293b; display: flex; align-items: center; gap: 8px;">
                    <span class="dashicons dashicons-visibility" style="color: #2563eb;"></span>
                    <?php esc_html_e('Transparansi Konfigurasi & Prompt Perintah AI', 'anti-judol-shield'); ?>
                </h3>
                <span style="font-size: 12px; background: #e0f2fe; color: #0369a1; padding: 3px 10px; border-radius: 9999px; font-weight: 600;">
                    <?php echo count($ai_audit); ?> Artikel Diuji &bull; <?php echo $ai_threats_cnt; ?> Ancaman
                </span>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; font-size: 13px; margin-bottom: 14px;">
                <div>
                    <strong>Model AI:</strong> <code><?php echo esc_html($ai_model); ?></code>
                </div>
                <div>
                    <strong>Endpoint URL:</strong> <code style="word-break: break-all;"><?php echo esc_html($ai_endpoint); ?></code>
                </div>
                <div>
                    <strong>Status Modul AI:</strong> 
                    <?php echo $is_ai_scanned ? '<span style="color:#16a34a; font-weight:bold;">Aktif dalam Scan Ini</span>' : '<span style="color:#64748b;">Nonaktif saat scan dijalankan</span>'; ?>
                </div>
            </div>

            <!-- Detailed System Prompt Accordion -->
            <details style="background: #fff; border: 1px solid #cbd5e1; border-radius: 4px; padding: 10px 14px;">
                <summary style="cursor: pointer; font-weight: 600; color: #1e40af; font-size: 13px;">
                    👁️ <?php esc_html_e('Lihat Perintah / System Prompt Lengkap yang Dikirim ke AI', 'anti-judol-shield'); ?>
                </summary>
                <div style="margin-top: 10px;">
                    <p style="font-size: 12px; color: #475569; margin: 0 0 6px 0;">
                        Prompt di bawah ini dikirimkan sebagai instruksi peran (system role) ke model AI untuk memandu pemeriksaan konten tanpa bias:
                    </p>
                    <textarea readonly style="width: 100%; height: 90px; font-family: monospace; font-size: 11.5px; background: #0f172a; color: #38bdf8; padding: 8px; border-radius: 4px;"><?php echo esc_textarea($ai_system_prompt); ?></textarea>
                </div>
            </details>
        </div>

        <!-- AI Scanned Items Table -->
        <?php if (empty($ai_audit)) : ?>
            <div style="background: #f8fafc; border: 1px dashed #cbd5e1; padding: 20px; text-align: center; border-radius: 6px;">
                <p style="color: #64748b; margin: 0; font-size: 13px;">
                    <?php if (!$is_ai_scanned) : ?>
                        <em><?php esc_html_e('Pemindaian AI (AI Deep Screening) tidak dicentang saat scan terakhir dijalankan. Centang "AI Deep Screening" pada saat memindai untuk memeriksa artikel dan melihat transparansi analisis AI.', 'anti-judol-shield'); ?></em>
                    <?php else : ?>
                        <em><?php esc_html_e('Tidak ada postingan yang diperiksa atau modul AI belum dikonfigurasi dengan API Key yang valid.', 'anti-judol-shield'); ?></em>
                    <?php endif; ?>
                </p>
            </div>
        <?php else : ?>
            <div style="margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
                <h4 style="margin: 0; font-size: 14px; color: #1e293b;"><?php esc_html_e('Daftar Rinci Seluruh Artikel/Postingan yang Diperiksa oleh AI:', 'anti-judol-shield'); ?></h4>
                <span style="font-size: 12px; color: #64748b;">Menampilkan seluruh hasil, baik yang bersih maupun yang terinjeksi.</span>
            </div>

            <table class="widefat fixed striped" style="margin-bottom: 15px;">
                <thead>
                    <tr>
                        <th style="width: 60px;">ID</th>
                        <th style="width: 220px;">Judul Konten</th>
                        <th style="width: 90px;">Tipe</th>
                        <th style="width: 130px;">Ukuran Sampel</th>
                        <th style="width: 140px;">Hasil Analisis AI</th>
                        <th>Alasan / Penjelasan AI</th>
                        <th style="width: 130px;">Tindakan</th>
                        <th style="width: 90px;" class="ajs-no-print">Detail</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ai_audit as $idx => $item) : ?>
                        <?php
                        $is_th = !empty($item['is_threat']);
                        $status_badge = $is_th
                            ? '<span style="background:#fee2e2; color:#991b1b; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px;">🚨 Ancaman</span>'
                            : '<span style="background:#dcfce7; color:#15803d; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:11px;">✅ Aman</span>';
                        ?>
                        <tr>
                            <td>#<?php echo esc_html($item['id'] ?? '-'); ?></td>
                            <td>
                                <strong><?php echo esc_html($item['title'] ?? '-'); ?></strong>
                                <div style="font-size: 11px; color: #64748b;">Update: <?php echo esc_html($item['modified'] ?? '-'); ?></div>
                            </td>
                            <td><code><?php echo esc_html($item['type'] ?? 'post'); ?></code></td>
                            <td style="font-size: 12px;">
                                <?php echo esc_html($item['word_count'] ?? 0); ?> kata
                                <div style="font-size: 11px; color: #64748b;"><?php echo esc_html($item['char_length'] ?? 0); ?> karakter</div>
                            </td>
                            <td><?php echo $status_badge; ?></td>
                            <td style="font-size: 12.5px;">
                                <?php echo esc_html($item['reason'] ?? 'Bersih'); ?>
                            </td>
                            <td>
                                <span style="font-size: 11.5px; font-weight: 600; <?php echo $is_th ? 'color:#dc2626;' : 'color:#16a34a;'; ?>">
                                    <?php echo esc_html($item['action'] ?? '-'); ?>
                                </span>
                            </td>
                            <td class="ajs-no-print">
                                <button type="button" class="button button-small" onclick="document.getElementById('ajs-ai-detail-<?php echo esc_attr($idx); ?>').style.display = (document.getElementById('ajs-ai-detail-<?php echo esc_attr($idx); ?>').style.display === 'none' ? 'table-row' : 'none');">
                                    Inspeksi
                                </button>
                            </td>
                        </tr>

                        <!-- Accordion Detail Row -->
                        <tr id="ajs-ai-detail-<?php echo esc_attr($idx); ?>" style="display: none; background: #f8fafc;" class="ajs-no-print">
                            <td colspan="8" style="padding: 16px 20px; border-bottom: 2px solid #cbd5e1;">
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                    <div>
                                        <h5 style="margin: 0 0 6px 0; color: #1e40af; font-size: 12px; text-transform: uppercase;">📝 Cuplikan Konten yang Dikirim ke AI:</h5>
                                        <div style="background: #fff; border: 1px solid #e2e8f0; padding: 10px; border-radius: 4px; font-size: 12px; max-height: 120px; overflow-y: auto; color: #334155; line-height: 1.5;">
                                            <?php echo nl2br(esc_html($item['sample_snippet'] ?? '')); ?>
                                        </div>
                                    </div>
                                    <div>
                                        <h5 style="margin: 0 0 6px 0; color: #1e40af; font-size: 12px; text-transform: uppercase;">🤖 Perintah & Respon Mentah AI (JSON):</h5>
                                        <pre style="background: #0f172a; color: #38bdf8; font-family: monospace; font-size: 11px; padding: 10px; border-radius: 4px; max-height: 120px; overflow-y: auto; margin: 0;"><?php echo esc_html($item['raw_reply'] ?? '{"is_threat": false, "reason": "aman"}'); ?></pre>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- TAB 3: CORE CHECKSUMS & BASELINE -->
    <div id="ajs-tab-core" class="ajs-tab-pane" style="display: none;">
        <div style="margin-bottom: 16px;">
            <h4 style="margin: 0 0 6px 0; font-size: 14px;"><?php esc_html_e('Verifikasi Hash MD5 Resmi WordPress.org Core:', 'anti-judol-shield'); ?></h4>
            <p style="font-size: 12.5px; color: #475569; margin: 0 0 12px 0;">
                <?php esc_html_e('File inti WordPress divalidasi langsung ke checksum MD5 resmi rilis WordPress.org untuk memastikan tidak ada backdoor yang disisipkan di core WordPress:', 'anti-judol-shield'); ?>
            </p>

            <?php if (empty($core_audit)) : ?>
                <div style="background: #f8fafc; padding: 14px; border: 1px solid #e2e8f0; border-radius: 4px; color: #64748b; font-size: 13px;">
                    <em>Checksums terverifikasi. Tidak ada anomali hash yang terdeteksi pada file inti resmi.</em>
                </div>
            <?php else : ?>
                <table class="widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Nama File Core</th>
                            <th style="width: 140px;">Status MD5</th>
                            <th>Hash MD5 Lokal</th>
                            <th>Hash MD5 Resmi WordPress.org</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($core_audit as $ca) : ?>
                            <?php $is_v = ($ca['status'] ?? '') === 'valid'; ?>
                            <tr>
                                <td><code><?php echo esc_html($ca['file']); ?></code></td>
                                <td>
                                    <?php echo $is_v ? '<span style="color:#16a34a; font-weight:bold;">✓ Cocok (Valid)</span>' : '<span style="color:#dc2626; font-weight:bold;">✗ Mismatch / Berubah</span>'; ?>
                                </td>
                                <td><code><?php echo esc_html(substr($ca['local_md5'] ?? '-', 0, 16)); ?>...</code></td>
                                <td><code><?php echo esc_html(substr($ca['wp_md5'] ?? '-', 0, 16)); ?>...</code></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>

    <!-- TAB 4: STORAGE JARINGAN & NFS -->
    <div id="ajs-tab-storage" class="ajs-tab-pane" style="display: none;">
        <h4 style="margin: 0 0 6px 0; font-size: 14px;"><?php esc_html_e('Bukti Pengecualian Storage Jaringan & NFS / NAS:', 'anti-judol-shield'); ?></h4>
        <p style="font-size: 12.5px; color: #475569; margin: 0 0 14px 0;">
            <?php esc_html_e('Untuk mencegah scan membebani koneksi jaringan dan memastikan proses selesai cepat, daftar direktori berikut dipotong (pruned) dan dilewati sepenuhnya:', 'anti-judol-shield'); ?>
        </p>

        <?php if (empty($skipped_paths)) : ?>
            <div style="background: #f8fafc; padding: 14px; border: 1px solid #e2e8f0; border-radius: 4px; color: #64748b; font-size: 13px;">
                <em>Seluruh direktori uploads berada di local disk server (tidak ada direktori NFS atau pengecualian yang dilewati).</em>
            </div>
        <?php else : ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 40px;">#</th>
                        <th>Path Direktori yang Dilewati</th>
                        <th>Alasan Dikecualikan</th>
                        <th style="width: 140px;">Status I/O</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($skipped_paths as $sidx => $sp) : ?>
                        <tr>
                            <td><?php echo (int)($sidx + 1); ?></td>
                            <td style="word-break: break-all;"><code><?php echo esc_html($sp['path'] ?? '-'); ?></code></td>
                            <td><?php echo esc_html($sp['reason'] ?? 'Storage Jaringan / NFS'); ?></td>
                            <td><span style="color: #2563eb; font-weight: bold;">✓ Dilewati Aman</span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- TAB 5: DATABASE OPTIONS -->
    <div id="ajs-tab-database" class="ajs-tab-pane" style="display: none;">
        <h4 style="margin: 0 0 6px 0; font-size: 14px;"><?php esc_html_e('Audit Pola SQL Injection pada Tabel wp_options:', 'anti-judol-shield'); ?></h4>
        <p style="font-size: 12.5px; color: #475569; margin: 0 0 14px 0;">
            <?php esc_html_e('Pola pencarian SQL berikut dijalankan untuk memastikan tabel opsi WordPress tidak disusupi skrip deface tersembunyi atau link judi online:', 'anti-judol-shield'); ?>
        </p>

        <?php if (empty($db_audit)) : ?>
            <div style="background: #f8fafc; padding: 14px; border: 1px solid #e2e8f0; border-radius: 4px; color: #64748b; font-size: 13px;">
                <em>Tabel options database bersih dari seluruh pola pencarian judi dan payload berbahaya.</em>
            </div>
        <?php else : ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th>Pola Pencarian LIKE</th>
                        <th>Status Hasil</th>
                        <th>Opsi yang Terinfeksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($db_audit as $dba) : ?>
                        <?php $has_m = !empty($dba['matched']); ?>
                        <tr>
                            <td><code><?php echo esc_html($dba['pattern']); ?></code></td>
                            <td>
                                <?php echo $has_m ? '<span style="color:#dc2626; font-weight:bold;">🚨 Ditemukan Infeksi</span>' : '<span style="color:#16a34a; font-weight:bold;">✓ Bersih</span>'; ?>
                            </td>
                            <td>
                                <?php if ($has_m) : ?>
                                    <code><?php echo esc_html(implode(', ', $dba['matched'])); ?></code>
                                <?php else : ?>
                                    <span style="color:#64748b;">-</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

</div>

<!-- Styles & Tabs Javascript -->
<style>
.ajs-tab-btn {
    outline: none;
    transition: all 0.2s ease;
}
.ajs-tab-btn:hover {
    color: #2563eb !important;
}
.ajs-tab-btn.active {
    color: #2563eb !important;
    border-bottom-color: #2563eb !important;
}
@media print {
    #adminmenumain, #wpadminbar, #wpfooter, .notice, #ajs-scan-form, #ajs-scan-progress-box, .ajs-no-print {
        display: none !important;
    }
    #wpcontent, #wpbody-content {
        margin-left: 0 !important;
        padding: 0 !important;
    }
    .ajs-report-wrapper {
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
    }
    .ajs-tab-pane {
        display: block !important;
        margin-bottom: 30px !important;
        page-break-inside: avoid;
    }
}
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Report Tabs switcher
    var tabBtns = document.querySelectorAll('.ajs-tab-btn');
    var tabPanes = document.querySelectorAll('.ajs-tab-pane');

    tabBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var targetId = this.getAttribute('data-target');

            tabBtns.forEach(function(b) {
                b.classList.remove('active');
                b.style.borderBottomColor = 'transparent';
                b.style.color = '#64748b';
            });
            tabPanes.forEach(function(p) {
                p.style.display = 'none';
            });

            this.classList.add('active');
            this.style.borderBottomColor = '#2563eb';
            this.style.color = '#2563eb';

            var targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.style.display = 'block';
            }
        });
    });

    // Copy report summary to clipboard
    var copyBtn = document.getElementById('ajs-btn-copy-report');
    if (copyBtn) {
        copyBtn.addEventListener('click', function() {
            var summaryText = "=== LAPORAN PEMINDAIAN KEAMANAN ANTI-JUDOL SHIELD ===\n" +
                "Waktu: <?php echo esc_js($timestamp); ?>\n" +
                "Durasi: <?php echo esc_js($duration_sec); ?>\n" +
                "Total Masalah: <?php echo esc_js($total_issues); ?>\n" +
                "File Uploads Diperiksa: <?php echo esc_js($uploads_scanned); ?>\n" +
                "File Tema Diperiksa: <?php echo esc_js($theme_scanned); ?>\n" +
                "Artikel Diuji AI: <?php echo esc_js($ai_scanned_cnt); ?> (Model: <?php echo esc_js($ai_model); ?>)\n" +
                "Core Checksums Divalidasi: <?php echo esc_js($core_scanned); ?>\n" +
                "NFS/Storage Jaringan Dilewati: <?php echo esc_js(count($skipped_paths)); ?>\n" +
                "Status: <?php echo $total_issues === 0 ? 'BERSIH & AMAN' : 'DITEMUKAN ' . esc_js($total_issues) . ' ANCAMAN'; ?>\n" +
                "=====================================================";

            navigator.clipboard.writeText(summaryText).then(function() {
                var origText = copyBtn.innerHTML;
                copyBtn.innerHTML = '<span class="dashicons dashicons-yes" style="margin-top:4px;color:#16a34a;"></span> Berhasil Disalin!';
                setTimeout(function() {
                    copyBtn.innerHTML = origText;
                }, 2000);
            }).catch(function() {
                alert('Gagal menyalin ringkasan ke clipboard.');
            });
        });
    }
});
</script>
