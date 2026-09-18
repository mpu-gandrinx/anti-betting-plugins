<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1><?php esc_html_e('Log Serangan & Blokir WAF', 'anti-judol-shield'); ?></h1>
    <p><?php esc_html_e('Menampilkan 100 aktivitas serangan terakhir yang dicegah secara otomatis oleh WAF.', 'anti-judol-shield'); ?></p>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom: 15px;">
        <?php wp_nonce_field('ajs_clear_logs_action'); ?>
        <input type="hidden" name="action" value="ajs_clear_logs">
        <button type="submit" class="button" onclick="return confirm('Hapus seluruh riwayat log serangan?');"><?php esc_html_e('Bersihkan Semua Log', 'anti-judol-shield'); ?></button>
    </form>

    <table class="widefat fixed striped">
        <thead>
            <tr>
                <th style="width: 150px;">Waktu</th>
                <th style="width: 130px;">IP Address</th>
                <th style="width: 180px;">Alasan Blokir</th>
                <th>Target URI</th>
                <th>Payload Terdeteksi</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($logs)) : ?>
                <tr><td colspan="5"><?php esc_html_e('Tidak ada aktivitas ancaman.', 'anti-judol-shield'); ?></td></tr>
            <?php else : ?>
                <?php foreach ($logs as $log) : ?>
                    <tr>
                        <td><?php echo esc_html($log->created_at); ?></td>
                        <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                        <td><strong><?php echo esc_html($log->reason); ?></strong></td>
                        <td style="word-break: break-all;"><?php echo esc_html($log->request_uri); ?></td>
                        <td style="word-break: break-all;"><code><?php echo esc_html($log->threat_payload); ?></code></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>
