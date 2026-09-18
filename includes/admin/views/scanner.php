<?php
if (!defined('ABSPATH')) {
    exit;
}

if (isset($_GET['baseline_created'])) {
    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Golden Integrity Baseline berhasil dibuat & diperbarui.', 'anti-judol-shield') . '</p></div>';
}
if (isset($_GET['settings_saved'])) {
    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Pengaturan lingkup pemindaian & pengecualian NFS/NAS berhasil disimpan.', 'anti-judol-shield') . '</p></div>';
}
?>
<div class="wrap">
    <h1><?php esc_html_e('Scanner File & Auto-Heal Integrity', 'anti-judol-shield'); ?></h1>
    <p><?php esc_html_e('Pindai direktori wp-content/uploads dan tema untuk mendeteksi backdoor, webshell, atau file PHP tersembunyi yang disisipkan peretas judi online.', 'anti-judol-shield'); ?></p>

    <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1; border-left: 4px solid #16a34a; margin-bottom: 20px;">
        <h2 style="margin-top: 0;"><?php esc_html_e('🛡️ Golden Integrity Baseline & Auto-Heal Deface Engine', 'anti-judol-shield'); ?></h2>
        <p><?php esc_html_e('Menyimpan salinan bersih (golden snapshot) dari file inti dan tema (index.php, .htaccess, header.php, functions.php). Jika peretas mengubah file ini untuk deface atau menyisipkan link judol, sistem secara otomatis merestorasi file asli dalam hitungan detik.', 'anti-judol-shield'); ?></p>

        <p>Status Auto-Heal: <strong><?php echo (int)get_option('ajs_auto_heal_enabled', 1) === 1 ? '<span style="color:#16a34a;">AKTIF (Siaga Memulihkan)</span>' : '<span style="color:#dc2626;">NONAKTIF</span>'; ?></strong> | File Terproteksi: <strong><?php echo count($baseline); ?> file</strong></p>

        <?php if ($last_healed) : ?>
            <div style="background: #fef2f2; border: 1px solid #f87171; padding: 10px 14px; margin-bottom: 12px; border-radius: 4px; color: #991b1b;">
                <strong>🚨 Pemulihan Deface Terakhir Terjadi (<?php echo esc_html($last_healed['timestamp']); ?>):</strong>
                File yang otomatis disembuhkan: <code><?php echo esc_html(implode(', ', array_map('basename', $last_healed['files']))); ?></code>
            </div>
        <?php endif; ?>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('ajs_create_baseline_action'); ?>
            <input type="hidden" name="action" value="ajs_create_baseline">
            <button type="submit" class="button button-secondary"><?php esc_html_e('Buat / Perbarui Golden Baseline Bersih Sekarang', 'anti-judol-shield'); ?></button>
        </form>
    </div>

    <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1; margin-bottom: 20px;">
        <h2><?php esc_html_e('Jalankan Pemindaian Mandiri', 'anti-judol-shield'); ?></h2>

        <?php if (!empty($network_mounts)) : ?>
            <div style="background: #ecfdf5; border: 1px solid #6ee7b7; border-left: 4px solid #10b981; padding: 12px 16px; border-radius: 4px; margin-bottom: 16px; color: #065f46;">
                <strong>🟢 Storage Jaringan / NFS Terdeteksi di Server (Otomatis Dilewati):</strong>
                <ul style="margin: 6px 0 4px 18px; font-size: 13px;">
                    <?php foreach ($network_mounts as $dm) : ?>
                        <li><code><?php echo esc_html($dm['path']); ?></code> &mdash; Tipe: <strong><?php echo esc_html(strtoupper($dm['type'])); ?></strong> (Device: <?php echo esc_html($dm['device']); ?>)</li>
                    <?php endforeach; ?>
                </ul>
                <span style="font-size: 12px; color: #047857;">Scanner akan otomatis menghindari folder di atas agar scan tidak lambat dan tidak membebani bandwidth NAS.</span>
            </div>
        <?php else : ?>
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 13px; color: #475569;">
                ℹ️ <em>Tidak ada mount NFS sistem Linux yang terdeteksi via <code>/proc/mounts</code>. Jika subfolder di uploads Anda terhubung ke NAS/NFS, masukkan nama folder pada kolom pengecualian di bawah.</em>
            </div>
        <?php endif; ?>

        <form id="ajs-scan-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('ajs_scan_action'); ?>
            <input type="hidden" name="action" value="ajs_run_scan">
            <input type="hidden" name="scan_skip_nfs_present" value="1">
            <input type="hidden" name="scan_skip_uploads_present" value="1">

            <p>
                <label>
                    <input type="checkbox" name="auto_heal" id="ajs_field_auto_heal" value="1" checked>
                    <strong><?php esc_html_e('Mode Auto-Heal (Karantina Skrip & Tarik Draf Artikel Deface):', 'anti-judol-shield'); ?></strong>
                    <?php esc_html_e('Otomatis karantina file backdoor di uploads (.quarantine_bak) dan kembalikan artikel/post terinjeksi ke status draft.', 'anti-judol-shield'); ?>
                </label>
            </p>

            <p>
                <label>
                    <input type="checkbox" name="ai_deep_scan" id="ajs_field_ai_deep_scan" value="1" <?php disabled(!$has_ai); ?>>
                    <strong><?php esc_html_e('AI Deep Screening (Analisis Injeksi Artikel & Database):', 'anti-judol-shield'); ?></strong>
                    <?php esc_html_e('Kirim sampel artikel terbitan terbaru ke AI untuk memverifikasi apakah ada teks tersembunyi/link judi online yang disusupi.', 'anti-judol-shield'); ?>
                    <?php if (!$has_ai) : ?>
                        <em style="color: #dc2626;">(AI belum aktif/dikonfigurasi di menu Pengaturan WAF)</em>
                    <?php endif; ?>
                </label>
            </p>

            <hr style="margin: 16px 0; border: 0; border-top: 1px solid #e2e8f0;">
            <h3 style="margin-top: 0;"><?php esc_html_e('⚡ Optimasi Pemindaian Lokal Server (Hindari NFS/NAS)', 'anti-judol-shield'); ?></h3>

            <p>
                <label>
                    <input type="checkbox" name="scan_skip_nfs" id="ajs_field_skip_nfs" value="1" <?php checked(1, get_option('ajs_scan_skip_nfs', 1)); ?>>
                    <strong><?php esc_html_e('Otomatis Hindari / Lewati Mount NFS & Storage Jaringan (Rekomendasi):', 'anti-judol-shield'); ?></strong>
                    <?php esc_html_e('Mendeteksi direktori NFS/NAS dan melewatinya sehingga hanya file lokal di server yang dipindai.', 'anti-judol-shield'); ?>
                </label>
            </p>

            <p>
                <label>
                    <input type="checkbox" name="scan_skip_uploads" id="ajs_field_skip_uploads" value="1" <?php checked(1, get_option('ajs_scan_skip_uploads', 0)); ?>>
                    <strong><?php esc_html_e('Lewati Seluruh Folder Uploads (wp-content/uploads):', 'anti-judol-shield'); ?></strong>
                    <?php esc_html_e('Hanya pindai file tema, core, dan database (berguna jika seluruh folder uploads berada di NAS terpisah).', 'anti-judol-shield'); ?>
                </label>
            </p>

            <p>
                <label for="ajs_scan_exclude_paths">
                    <strong><?php esc_html_e('Folder / Path yang Dikecualikan dari Scan (1 per baris):', 'anti-judol-shield'); ?></strong>
                </label><br>
                <textarea name="scan_exclude_paths" id="ajs_scan_exclude_paths" rows="3" class="large-text code" style="max-width: 600px;" placeholder="Contoh:&#10;nfs&#10;nas&#10;shared&#10;uploads/dokumen_nfs&#10;2020"><?php echo esc_textarea(get_option('ajs_scan_exclude_paths', '')); ?></textarea>
                <span class="description" style="display: block; margin-top: 4px;">
                    <?php esc_html_e('Tuliskan nama subfolder atau path mount NFS di folder uploads yang ingin di-skip. Scanner akan memotong cabang direktori tersebut sehingga scan selesai cepat.', 'anti-judol-shield'); ?>
                </span>
            </p>

            <div style="margin-top: 20px;">
                <button type="submit" id="ajs-btn-start-scan" name="action_type" value="scan" class="button button-primary button-large"><?php esc_html_e('Mulai Pindai Sekarang', 'anti-judol-shield'); ?></button>
                <button type="submit" name="action_type" value="save_only" class="button button-secondary button-large" style="margin-left: 8px;"><?php esc_html_e('Simpan Pengaturan Pengecualian Saja', 'anti-judol-shield'); ?></button>
            </div>
        </form>

        <!-- Box Progress Pemindaian Real-Time -->
        <div id="ajs-scan-progress-box" style="display: none; margin-top: 24px; background: #f8fafc; border: 1px solid #cbd5e1; border-left: 4px solid #2563eb; padding: 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                <h3 style="margin: 0; display: flex; align-items: center; gap: 8px; color: #1e293b; font-size: 15px;">
                    <span class="dashicons dashicons-update ajs-spin" style="color: #2563eb; font-size: 20px; width: 20px; height: 20px;"></span>
                    <?php esc_html_e('Pemindaian Keamanan Sedang Berjalan...', 'anti-judol-shield'); ?>
                </h3>
                <span id="ajs-percent-badge" style="background: #dbeafe; color: #1e40af; padding: 3px 12px; border-radius: 9999px; font-weight: bold; font-size: 13px;">0%</span>
            </div>

            <!-- Progress Bar Container -->
            <div style="background: #e2e8f0; border-radius: 9999px; height: 24px; overflow: hidden; position: relative; margin-bottom: 12px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.08);">
                <div id="ajs-progress-bar" style="background: linear-gradient(90deg, #2563eb, #3b82f6); height: 100%; width: 0%; transition: width 0.35s ease; border-radius: 9999px; display: flex; align-items: center; justify-content: flex-end; padding-right: 12px; color: #fff; font-weight: bold; font-size: 12px; min-width: 24px;">0%</div>
            </div>

            <div id="ajs-progress-status" style="font-weight: 600; color: #334155; font-size: 13.5px; margin-bottom: 14px;">
                <?php esc_html_e('Menghubungkan ke scanner server...', 'anti-judol-shield'); ?>
            </div>

            <!-- Step Badges / Pills -->
            <div id="ajs-step-indicators" style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;">
                <span class="ajs-step-pill" data-step="init">1. Storage & NFS</span>
                <span class="ajs-step-pill" data-step="scan_uploads">2. Uploads Scan</span>
                <span class="ajs-step-pill" data-step="scan_theme">3. Tema & Webshell</span>
                <span class="ajs-step-pill" data-step="scan_ai">4. AI Screening</span>
                <span class="ajs-step-pill" data-step="verify_integrity">5. Golden Baseline</span>
                <span class="ajs-step-pill" data-step="scan_database">6. Database Options</span>
                <span class="ajs-step-pill" data-step="scan_core">7. WP Core Checksums</span>
            </div>

            <!-- Terminal Console Log -->
            <div style="margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                    <span style="font-size: 12px; font-weight: 600; color: #475569;">Log Aktivitas Pemindaian Real-Time:</span>
                    <span style="font-size: 11px; color: #64748b;">(Auto-scroll aktif)</span>
                </div>
                <div id="ajs-scan-console" style="background: #0f172a; color: #38bdf8; font-family: Consolas, Monaco, 'Courier New', monospace; font-size: 12px; padding: 12px 14px; border-radius: 6px; height: 160px; overflow-y: auto; line-height: 1.6; border: 1px solid #1e293b; box-shadow: inset 0 1px 3px rgba(0,0,0,0.3);">
                    <div>[<?php echo esc_html(current_time('H:i:s')); ?>] Menunggu sesi pemindaian diinisialisasi...</div>
                </div>
            </div>

            <!-- Live Metric Counters -->
            <div style="display: flex; flex-wrap: wrap; gap: 24px; font-size: 13px; color: #334155; padding-top: 10px; border-top: 1px solid #e2e8f0;">
                <div>Ancaman Terdeteksi: <strong id="ajs-live-findings" style="color: #16a34a; font-size: 14px;">0</strong></div>
                <div>Path NFS / Dikecualikan Dilewati: <strong id="ajs-live-skipped" style="color: #2563eb; font-size: 14px;">0</strong></div>
            </div>
        </div>

        <style>
        @keyframes ajs-spin-anim { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .ajs-spin { animation: ajs-spin-anim 1.2s infinite linear; }
        .ajs-step-pill {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 500;
            background: #e2e8f0;
            color: #475569;
            border: 1px solid #cbd5e1;
            transition: all 0.25s ease;
        }
        .ajs-step-pill.is-active {
            background: #dbeafe !important;
            color: #1d4ed8 !important;
            border-color: #93c5fd !important;
            font-weight: 700;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }
        .ajs-step-pill.is-done {
            background: #dcfce7 !important;
            color: #15803d !important;
            border-color: #86efac !important;
        }
        .ajs-step-pill.is-done::after {
            content: ' ✓';
        }
        </style>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var form = document.getElementById('ajs-scan-form');
            if (!form) return;

            var startBtn = document.getElementById('ajs-btn-start-scan');
            var progressBox = document.getElementById('ajs-scan-progress-box');
            var progressBar = document.getElementById('ajs-progress-bar');
            var percentBadge = document.getElementById('ajs-percent-badge');
            var statusText = document.getElementById('ajs-progress-status');
            var consoleBox = document.getElementById('ajs-scan-console');
            var liveFindings = document.getElementById('ajs-live-findings');
            var liveSkipped = document.getElementById('ajs-live-skipped');

            var ajaxUrl = <?php echo json_encode(admin_url('admin-ajax.php')); ?>;
            var ajaxNonce = <?php echo json_encode(wp_create_nonce('ajs_ajax_scan_nonce')); ?>;

            function getTimeStamp() {
                var now = new Date();
                return ('0' + now.getHours()).slice(-2) + ':' +
                       ('0' + now.getMinutes()).slice(-2) + ':' +
                       ('0' + now.getSeconds()).slice(-2);
            }

            function appendLog(msg, color) {
                var line = document.createElement('div');
                if (color) line.style.color = color;
                line.textContent = '[' + getTimeStamp() + '] ' + msg;
                consoleBox.appendChild(line);
                consoleBox.scrollTop = consoleBox.scrollHeight;
            }

            function updateStepPill(stepKey, status) {
                var pills = document.querySelectorAll('.ajs-step-pill');
                pills.forEach(function(pill) {
                    if (pill.getAttribute('data-step') === stepKey) {
                        if (status === 'active') {
                            pill.classList.add('is-active');
                            pill.classList.remove('is-done');
                        } else if (status === 'done') {
                            pill.classList.remove('is-active');
                            pill.classList.add('is-done');
                        }
                    }
                });
            }

            form.addEventListener('submit', function(e) {
                var clickedBtn = document.activeElement;
                if (clickedBtn && clickedBtn.getAttribute('name') === 'action_type' && clickedBtn.getAttribute('value') === 'save_only') {
                    return;
                }

                e.preventDefault();

                var autoHeal = document.getElementById('ajs_field_auto_heal') ? (document.getElementById('ajs_field_auto_heal').checked ? 1 : 0) : 1;
                var aiScan = document.getElementById('ajs_field_ai_deep_scan') ? (document.getElementById('ajs_field_ai_deep_scan').checked ? 1 : 0) : 0;
                var skipNfs = document.getElementById('ajs_field_skip_nfs') ? (document.getElementById('ajs_field_skip_nfs').checked ? 1 : 0) : 1;
                var skipUploads = document.getElementById('ajs_field_skip_uploads') ? (document.getElementById('ajs_field_skip_uploads').checked ? 1 : 0) : 0;
                var excludePaths = document.getElementById('ajs_scan_exclude_paths') ? document.getElementById('ajs_scan_exclude_paths').value : '';

                progressBox.style.display = 'block';
                progressBox.scrollIntoView({ behavior: 'smooth', block: 'center' });

                if (startBtn) {
                    startBtn.disabled = true;
                    startBtn.innerHTML = '<span class="dashicons dashicons-update ajs-spin" style="margin-top:4px;"></span> Sedang Memindai...';
                }

                consoleBox.innerHTML = '';
                appendLog('Inisialisasi pemindaian keamanan...');

                var scanId = 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);

                function runStep(step) {
                    updateStepPill(step, 'active');

                    var formData = new FormData();
                    formData.append('action', 'ajs_ajax_scan_step');
                    formData.append('nonce', ajaxNonce);
                    formData.append('scan_id', scanId);
                    formData.append('step', step);
                    formData.append('auto_heal', autoHeal);
                    formData.append('ai_deep_scan', aiScan);
                    formData.append('scan_skip_nfs', skipNfs);
                    formData.append('scan_skip_nfs_present', '1');
                    formData.append('scan_skip_uploads', skipUploads);
                    formData.append('scan_skip_uploads_present', '1');
                    formData.append('scan_exclude_paths', excludePaths);

                    fetch(ajaxUrl, {
                        method: 'POST',
                        body: formData
                    })
                    .then(function(res) { return res.json(); })
                    .then(function(res) {
                        if (!res.success) {
                            throw new Error(res.data && res.data.message ? res.data.message : 'Terjadi kegagalan komunikasi server.');
                        }

                        var data = res.data;

                        progressBar.style.width = data.progress + '%';
                        progressBar.textContent = data.progress + '%';
                        percentBadge.textContent = data.progress + '%';

                        if (data.status_text) {
                            statusText.textContent = data.status_text;
                        }

                        if (data.logs && data.logs.length) {
                            data.logs.forEach(function(l) {
                                appendLog(l);
                            });
                        }

                        if (typeof data.total_findings !== 'undefined') {
                            liveFindings.textContent = data.total_findings;
                            if (data.total_findings > 0) {
                                liveFindings.style.color = '#dc2626';
                            }
                        }
                        if (typeof data.skipped_count !== 'undefined') {
                            liveSkipped.textContent = data.skipped_count;
                        }

                        updateStepPill(step, 'done');

                        if (step === 'scan_theme' && data.next_step === 'verify_integrity') {
                            updateStepPill('scan_ai', 'done');
                        }

                        if (data.next_step) {
                            runStep(data.next_step);
                        } else {
                            progressBar.style.background = '#16a34a';
                            percentBadge.style.background = '#dcfce7';
                            percentBadge.style.color = '#15803d';
                            statusText.innerHTML = '<span style="color:#16a34a; font-weight:bold;">✅ Pemindaian Berhasil Selesai! Memperbarui ringkasan laporan...</span>';
                            appendLog('Laporan berhasil disimpan ke sistem. Memuat ulang halaman...');

                            setTimeout(function() {
                                window.location.href = window.location.pathname + '?page=anti-judol-scanner&scanned=1';
                            }, 1500);
                        }
                    })
                    .catch(function(err) {
                        appendLog('ERROR: ' + err.message, '#f87171');
                        statusText.innerHTML = '<span style="color:#dc2626; font-weight:bold;">Pemindaian terhenti: ' + err.message + '</span>';
                        if (startBtn) {
                            startBtn.disabled = false;
                            startBtn.textContent = 'Coba Pindai Ulang';
                        }
                    });
                }

                runStep('init');
            });
        });
        </script>
    </div>

    <?php if ($last_scan) : ?>
        <?php include __DIR__ . '/scan-report.php'; ?>
    <?php endif; ?>

    <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0;">
        <h3>🛡️ Rekomendasi Hardening Server (Nginx)</h3>
        <p><?php esc_html_e('Untuk website dengan web server Nginx, salin aturan blokir berikut ke konfigurasi block server Anda agar serangan tidak menyentuh PHP-FPM:', 'anti-judol-shield'); ?></p>
        <textarea readonly style="width: 100%; height: 180px; font-family: monospace; font-size: 12px; background: #0f172a; color: #38bdf8; padding: 10px;"><?php echo esc_textarea($nginx_rules); ?></textarea>
    </div>
</div>
