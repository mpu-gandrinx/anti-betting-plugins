<?php
if (!defined('ABSPATH')) {
    exit;
}

if (isset($_GET['unbanned'])) {
    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP berhasil dicabut dari blokir IPS.', 'anti-judol-shield') . '</p></div>';
}
if (isset($_GET['banned'])) {
    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP berhasil ditambahkan ke daftar blokir IPS.', 'anti-judol-shield') . '</p></div>';
}
?>
<div class="wrap">
    <h1><?php esc_html_e('Intrusion Detection & Prevention System (IDS/IPS)', 'anti-judol-shield'); ?></h1>
    <p><?php esc_html_e('Sistem pendeteksi intrusi otomatis (IDS) yang mengakumulasikan skor anomali aktivitas pemindaian berbahaya dan memblokir (IPS) IP penyerang secara otomatis.', 'anti-judol-shield'); ?></p>

    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;">
        <div>
            <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1; margin-bottom: 20px;">
                <h2 style="margin-top: 0;"><?php esc_html_e('Daftar IP Terblokir Aktif (IPS Blacklist)', 'anti-judol-shield'); ?></h2>
                <table class="widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 140px;">IP Address</th>
                            <th>Alasan Pemblokiran</th>
                            <th style="width: 150px;">Waktu Diblokir</th>
                            <th style="width: 150px;">Berakhir Pada</th>
                            <th style="width: 90px;">Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($banned)) : ?>
                            <tr><td colspan="5"><?php esc_html_e('Tidak ada IP yang sedang diblokir oleh IPS saat ini.', 'anti-judol-shield'); ?></td></tr>
                        <?php else : ?>
                            <?php foreach ($banned as $ip => $meta) : ?>
                                <tr>
                                    <td><code><?php echo esc_html($ip); ?></code></td>
                                    <td><?php echo esc_html($meta['reason'] ?? 'IPS Rule'); ?></td>
                                    <td><?php echo esc_html($meta['banned_at'] ?? '-'); ?></td>
                                    <td><?php echo esc_html($meta['expires_at'] ?? '-'); ?></td>
                                    <td>
                                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                                            <?php wp_nonce_field('ajs_unban_ip_action'); ?>
                                            <input type="hidden" name="action" value="ajs_unban_ip">
                                            <input type="hidden" name="ip" value="<?php echo esc_attr($ip); ?>">
                                            <button type="submit" class="button button-small"><?php esc_html_e('Lepas', 'anti-judol-shield'); ?></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1;">
                <h2 style="margin-top: 0;"><?php esc_html_e('Whitelist IP Aman (Kecualikan dari IPS)', 'anti-judol-shield'); ?></h2>
                <p><?php esc_html_e('IP di daftar ini tidak akan pernah diblokir oleh IPS atau WAF (contoh: IP kantor, IP developer). Masukkan satu IP per baris.', 'anti-judol-shield'); ?></p>
                <form method="post" action="options.php">
                    <?php
                    settings_fields('ajs_settings_group');
                    ?>
                    <textarea name="ajs_ip_whitelist" rows="5" class="large-text code"><?php echo esc_textarea($whitelist); ?></textarea>
                    <p class="submit">
                        <button type="submit" class="button button-primary"><?php esc_html_e('Simpan Whitelist', 'anti-judol-shield'); ?></button>
                    </p>
                </form>
            </div>
        </div>

        <div>
            <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1;">
                <h3 style="margin-top: 0;"><?php esc_html_e('Blokir IP Manual', 'anti-judol-shield'); ?></h3>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <?php wp_nonce_field('ajs_manual_ban_ip_action'); ?>
                    <input type="hidden" name="action" value="ajs_manual_ban_ip">

                    <p>
                        <label><?php esc_html_e('Alamat IP Target:', 'anti-judol-shield'); ?><br>
                            <input type="text" name="target_ip" required class="widefat" placeholder="contoh: 198.51.100.4">
                        </label>
                    </p>
                    <p>
                        <label><?php esc_html_e('Durasi Pemblokiran:', 'anti-judol-shield'); ?><br>
                            <select name="duration" class="widefat">
                                <option value="3600">1 Jam</option>
                                <option value="86400" selected>24 Jam (1 Hari)</option>
                                <option value="604800">7 Hari</option>
                                <option value="2592000">30 Hari</option>
                            </select>
                        </label>
                    </p>
                    <p>
                        <label><?php esc_html_e('Alasan:', 'anti-judol-shield'); ?><br>
                            <input type="text" name="reason" class="widefat" value="Manual Admin Ban">
                        </label>
                    </p>
                    <button type="submit" class="button button-primary widefat"><?php esc_html_e('Terapkan Blokir IPS', 'anti-judol-shield'); ?></button>
                </form>
            </div>

            <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0; margin-top: 20px;">
                <h4 style="margin-top: 0;"><?php esc_html_e('Metrik Deteksi Heuristik IDS', 'anti-judol-shield'); ?></h4>
                <ul style="font-size: 13px; color: #475569; padding-left: 18px; margin: 0;">
                    <li><strong>Webshell / Backdoor probe</strong>: +60 pts</li>
                    <li><strong>SQL Injection probe</strong>: +60 pts</li>
                    <li><strong>Path Traversal (../)</strong>: +40 pts</li>
                    <li><strong>Sensitive file probe (.env/.git)</strong>: +40 pts</li>
                    <li><strong>Ambang Batas Blokir Otomatis</strong>: 100 pts</li>
                </ul>
            </div>
        </div>
    </div>
</div>
