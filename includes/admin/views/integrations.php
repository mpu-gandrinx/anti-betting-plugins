<?php
if (!defined('ABSPATH')) {
    exit;
}

if ($cf_notice) {
    $class = $cf_notice['success'] ? 'notice-success' : 'notice-error';
    echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . esc_html($cf_notice['message']) . '</p></div>';
}

if ($alert_notice) {
    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Uji notifikasi berhasil dikirim.', 'anti-judol-shield') . '</p></div>';
}
?>
<div class="wrap">
    <h1><?php esc_html_e('Integrasi Cloudflare Edge WAF & Notifikasi Alert', 'anti-judol-shield'); ?></h1>
    <p><?php esc_html_e('Konfigurasi blokir di level Edge Cloudflare (<10ms) dan notifikasi instan real-time jika terjadi deface atau serangan kritis.', 'anti-judol-shield'); ?></p>

    <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1; margin-bottom: 20px;">
        <h2 style="margin-top: 0;"><?php esc_html_e('⚡ Cloudflare Edge WAF (1-Click Deploy)', 'anti-judol-shield'); ?></h2>
        <p><?php esc_html_e('Blokir bot dan injeksi judi online di server CDN Cloudflare sebelum mencapai server hosting Anda, menghemat 100% beban CPU & bandwidth.', 'anti-judol-shield'); ?></p>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom: 20px;">
            <?php wp_nonce_field('ajs_deploy_cf_action'); ?>
            <input type="hidden" name="action" value="ajs_deploy_cf">

            <table class="form-table" style="margin-top: 0;">
                <tr>
                    <th scope="row"><?php esc_html_e('Cloudflare API Token', 'anti-judol-shield'); ?></th>
                    <td>
                        <input type="password" name="ajs_cf_api_token" value="<?php echo esc_attr(get_option('ajs_cf_api_token', '')); ?>" class="regular-text code" placeholder="Bearer API Token (Zone.WAF edit)">
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Cloudflare Zone ID', 'anti-judol-shield'); ?></th>
                    <td>
                        <input type="text" name="ajs_cf_zone_id" value="<?php echo esc_attr(get_option('ajs_cf_zone_id', '')); ?>" class="regular-text code" placeholder="32-character Zone ID">
                    </td>
                </tr>
            </table>

            <button type="submit" class="button button-primary"><?php esc_html_e('Deploy WAF Rule ke Cloudflare Edge Sekarang', 'anti-judol-shield'); ?></button>
        </form>

        <h4><?php esc_html_e('Ekspresi WAF Mandiri (Bisa disalin manual ke Cloudflare Dashboard > Security > WAF):', 'anti-judol-shield'); ?></h4>
        <textarea readonly style="width: 100%; height: 110px; font-family: monospace; font-size: 11px; background: #0f172a; color: #38bdf8; padding: 8px;"><?php echo esc_textarea($cf_expression); ?></textarea>
    </div>

    <div style="background: #fff; padding: 20px; border: 1px solid #cbd5e1;">
        <h2 style="margin-top: 0;"><?php esc_html_e('🔔 Notifikasi Peringatan Instan (Telegram & Webhook)', 'anti-judol-shield'); ?></h2>
        <p><?php esc_html_e('Kirim pemberitahuan langsung saat terdeteksi aktivitas deface yang dipulihkan (Auto-Heal) atau pemblokiran IP oleh IPS.', 'anti-judol-shield'); ?></p>

        <form method="post" action="options.php">
            <?php
            settings_fields('ajs_settings_group');
            ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e('Telegram Bot Token', 'anti-judol-shield'); ?></th>
                    <td>
                        <input type="text" name="ajs_telegram_bot_token" value="<?php echo esc_attr(get_option('ajs_telegram_bot_token', '')); ?>" class="regular-text code" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ">
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Telegram Chat ID', 'anti-judol-shield'); ?></th>
                    <td>
                        <input type="text" name="ajs_telegram_chat_id" value="<?php echo esc_attr(get_option('ajs_telegram_chat_id', '')); ?>" class="regular-text code" placeholder="-100xxxxxxxxxx atau Chat ID user">
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Webhook URL (Slack / Discord)', 'anti-judol-shield'); ?></th>
                    <td>
                        <input type="url" name="ajs_webhook_url" value="<?php echo esc_attr(get_option('ajs_webhook_url', '')); ?>" class="regular-text code" placeholder="https://discord.com/api/webhooks/... atau Slack URL">
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Kirim Alert ke Email Admin', 'anti-judol-shield'); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="ajs_email_notify" value="1" <?php checked(1, get_option('ajs_email_notify', 0)); ?>>
                            <?php esc_html_e('Kirim email ke admin_email setiap ada kejadian kritis.', 'anti-judol-shield'); ?>
                        </label>
                    </td>
                </tr>
            </table>

            <?php submit_button(__('Simpan Pengaturan Notifikasi', 'anti-judol-shield')); ?>
        </form>

        <hr style="margin: 20px 0;">
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('ajs_test_alert_action'); ?>
            <input type="hidden" name="action" value="ajs_test_alert">
            <button type="submit" class="button button-secondary"><?php esc_html_e('Kirim Uji Alert (Test Alert)', 'anti-judol-shield'); ?></button>
        </form>
    </div>
</div>
