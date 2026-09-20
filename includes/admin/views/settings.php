<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1><?php esc_html_e('Pengaturan WAF & Anti-Judol Shield', 'anti-judol-shield'); ?></h1>
    <form method="post" action="options.php">
        <?php
        settings_fields('ajs_settings_group');
        do_settings_sections('ajs_settings_group');
        ?>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e('Aktifkan WAF Shield', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_waf_enabled" value="1" <?php checked(1, get_option('ajs_waf_enabled', 1)); ?>>
                        <?php esc_html_e('Filter seluruh traffic dari kata kunci judi online dan payload injeksi berbahaya.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Aktifkan Auto-Heal Deface Engine', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_auto_heal_enabled" value="1" <?php checked(1, get_option('ajs_auto_heal_enabled', 1)); ?>>
                        <?php esc_html_e('Otomatis pulihkan file inti/tema (index.php, .htaccess, header.php) ke kondisi bersih jika dirusak peretas.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Firewall Upload & Blokir PHP di Uploads', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_block_uploads_php" value="1" <?php checked(1, get_option('ajs_block_uploads_php', 1)); ?>>
                        <?php esc_html_e('Blokir upload file skrip berbahaya (.php, .phtml, polyglot) dan pasang proteksi eksekusi di direktori wp-content/uploads/.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Blokir XML-RPC', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_block_xmlrpc" value="1" <?php checked(1, get_option('ajs_block_xmlrpc', 1)); ?>>
                        <?php esc_html_e('Blokir akses xmlrpc.php untuk menghentikan serangan brute force dan DDoS amplifikasi.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Blokir Author Enumeration', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_block_author_enum" value="1" <?php checked(1, get_option('ajs_block_author_enum', 1)); ?>>
                        <?php esc_html_e('Cegah bot pemindai username admin melalui query ?author=1 atau WP REST API.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Filter Komentar & Injeksi Postingan', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_anti_spam_comments" value="1" <?php checked(1, get_option('ajs_anti_spam_comments', 1)); ?>>
                        <?php esc_html_e('Otomatis tolak komentar yang memuat link dan kata kunci judi.', 'anti-judol-shield'); ?>
                    </label><br>
                    <label>
                        <input type="checkbox" name="ajs_anti_spam_post_filter" value="1" <?php checked(1, get_option('ajs_anti_spam_post_filter', 1)); ?>>
                        <?php esc_html_e('Cegah peretas akun editor/kontributor menerbitkan postingan berisi kata kunci slot/judi.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Brute Force Shield (Rate Limiting)', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_rate_limit_login" value="1" <?php checked(1, get_option('ajs_rate_limit_login', 1)); ?>>
                        <?php esc_html_e('Kunci IP setelah gagal login berulang kali.', 'anti-judol-shield'); ?>
                    </label>
                    <p class="description">Maksimal percobaan gagal:
                        <input type="number" name="ajs_max_login_attempts" value="<?php echo esc_attr(get_option('ajs_max_login_attempts', 5)); ?>" style="width: 70px;"> kali.
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Kata Kunci Judol Tambahan (Custom)', 'anti-judol-shield'); ?></th>
                <td>
                    <textarea name="ajs_custom_keywords" rows="6" cols="50" class="large-text code"><?php echo esc_textarea(get_option('ajs_custom_keywords', '')); ?></textarea>
                    <p class="description"><?php esc_html_e('Tuliskan satu kata kunci per baris. Kata kunci ini akan otomatis diblokir jika muncul di parameter URL, payload, atau komentar.', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
        </table>

        <h2 style="margin-top: 30px;"><?php esc_html_e('Pengaturan Scanner & Pengecualian Storage (NFS / NAS)', 'anti-judol-shield'); ?></h2>
        <p><?php esc_html_e('Atur pembatasan scanner untuk menghindari direktori NFS, NAS, atau folder uploads berukuran sangat besar agar pemindaian hanya berfokus pada file lokal di server dan tidak membebani koneksi jaringan.', 'anti-judol-shield'); ?></p>

        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e('Otomatis Lewati Mount NFS / Jaringan', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_scan_skip_nfs" value="1" <?php checked(1, get_option('ajs_scan_skip_nfs', 1)); ?>>
                        <?php esc_html_e('Deteksi dan lewati direktori yang di-mount via NFS, CIFS, SMB, atau storage jaringan lain secara otomatis (Sangat disarankan).', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Lewati Seluruh Folder Uploads', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_scan_skip_uploads" value="1" <?php checked(1, get_option('ajs_scan_skip_uploads', 0)); ?>>
                        <?php esc_html_e('Jangan pindai direktori wp-content/uploads sama sekali (Hanya pindai tema, file inti, dan database).', 'anti-judol-shield'); ?>
                    </label>
                    <p class="description"><?php esc_html_e('Pilih opsi ini jika seluruh isi folder uploads berada di NAS / Object Storage terpisah.', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Daftar Path / Folder Dikecualikan', 'anti-judol-shield'); ?></th>
                <td>
                    <textarea name="ajs_scan_exclude_paths" rows="4" cols="50" class="large-text code"><?php echo esc_textarea(get_option('ajs_scan_exclude_paths', '')); ?></textarea>
                    <p class="description"><?php esc_html_e('Tuliskan nama folder, relative path di dalam uploads, atau path absolut yang ingin dihindari scanner (satu baris per entri). Contoh: nfs, nas, shared, 2020, uploads/dokumen-nfs', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
        </table>

        <h2 style="margin-top: 30px;"><?php esc_html_e('Integrasi AI Screening (OpenAI Compatible)', 'anti-judol-shield'); ?></h2>
        <p><?php esc_html_e('Gunakan model AI untuk menganalisis payload injeksi samar, komentar berselubung, dan verifikasi apakah artikel telah disusupi link/konten judi online.', 'anti-judol-shield'); ?></p>

        <?php
        if ($ai_notice) {
            $class = $ai_notice['success'] ? 'notice-success' : 'notice-error';
            echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . esc_html($ai_notice['message']) . '</p></div>';
        }
        ?>

        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e('Aktifkan AI Screening', 'anti-judol-shield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="ajs_ai_enabled" value="1" <?php checked(1, get_option('ajs_ai_enabled', 0)); ?>>
                        <?php esc_html_e('Aktifkan modul pendeteksi berbasis AI LLM.', 'anti-judol-shield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('AI Endpoint URL', 'anti-judol-shield'); ?></th>
                <td>
                    <input type="url" name="ajs_ai_endpoint" value="<?php echo esc_attr(get_option('ajs_ai_endpoint', 'https://api.openai.com/v1/chat/completions')); ?>" class="regular-text code">
                    <p class="description"><?php esc_html_e('Mendukung OpenAI atau reverse proxy / endpoint lokal yang kompatibel dengan format Chat Completions.', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('API Key', 'anti-judol-shield'); ?></th>
                <td>
                    <input type="password" name="ajs_ai_api_key" value="<?php echo esc_attr(get_option('ajs_ai_api_key', '')); ?>" class="regular-text code">
                    <p class="description"><?php esc_html_e('Kunci autentikasi Bearer API key untuk endpoint AI Anda.', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e('Model Name', 'anti-judol-shield'); ?></th>
                <td>
                    <input type="text" name="ajs_ai_model" value="<?php echo esc_attr(get_option('ajs_ai_model', 'gpt-4o-mini')); ?>" class="regular-text code">
                    <p class="description"><?php esc_html_e('Contoh: gpt-4o-mini, gpt-4o, gpt-3.5-turbo, claude-3-haiku, atau custom model ID.', 'anti-judol-shield'); ?></p>
                </td>
            </tr>
        </table>

        <?php submit_button(__('Simpan Konfigurasi', 'anti-judol-shield')); ?>
    </form>

    <hr style="margin: 30px 0;">
    <h3><?php esc_html_e('Uji Sambungan AI Endpoint', 'anti-judol-shield'); ?></h3>
    <p><?php esc_html_e('Kirim uji koneksi ringan ke endpoint AI yang tersimpan untuk memastikan API key dan endpoint berfungsi normal.', 'anti-judol-shield'); ?></p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <?php wp_nonce_field('ajs_test_ai_action'); ?>
        <input type="hidden" name="action" value="ajs_test_ai">
        <button type="submit" class="button button-secondary"><?php esc_html_e('Tes Koneksi AI Sekarang', 'anti-judol-shield'); ?></button>
    </form>
</div>
