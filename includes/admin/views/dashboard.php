<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1><?php esc_html_e('🛡️ Anti-Judol Shield & WAF Dashboard', 'anti-judol-shield'); ?></h1>
    <p><?php esc_html_e('Sistem pertahanan berlapis untuk menangkal injeksi judi online, brute force, dan webshell.', 'anti-judol-shield'); ?></p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 20px 0;">
        <div style="background: #fff; border-left: 4px solid #2563eb; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="margin: 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Total Serangan Diblokir</h3>
            <p style="font-size: 28px; font-weight: bold; margin: 8px 0 0; color: #1e293b;"><?php echo esc_html(number_format_i18n($total_blocked)); ?></p>
        </div>
        <div style="background: #fff; border-left: 4px solid #dc2626; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="margin: 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Diblokir Hari Ini</h3>
            <p style="font-size: 28px; font-weight: bold; margin: 8px 0 0; color: #dc2626;"><?php echo esc_html(number_format_i18n($today_blocked)); ?></p>
        </div>
        <div style="background: #fff; border-left: 4px solid #16a34a; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="margin: 0; color: #64748b; font-size: 13px; text-transform: uppercase;">Status WAF & Guard</h3>
            <p style="font-size: 18px; font-weight: bold; margin: 12px 0 0; color: #16a34a;">
                <?php echo (int)get_option('ajs_waf_enabled', 1) === 1 ? 'AKTIF (Proteksi Maksimal)' : 'NONAKTIF'; ?>
            </p>
        </div>
        <div style="background: #fff; border-left: 4px solid #f59e0b; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="margin: 0; color: #64748b; font-size: 13px; text-transform: uppercase;">File Integrity Check</h3>
            <p style="font-size: 14px; margin: 12px 0 0; color: #475569;">
                <?php
                if ($last_scan) {
                    $issues = (int)$last_scan['total_issues'];
                    echo $issues === 0 ? 'Bersih (' . esc_html($last_scan['timestamp']) . ')' : '<span style="color:#dc2626;font-weight:bold;">' . esc_html($issues) . ' Ancaman Terdeteksi</span>';
                } else {
                    echo 'Belum pernah scan';
                }
                ?>
            </p>
        </div>
        <div style="background: #fff; border-left: 4px solid #7c3aed; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h3 style="margin: 0; color: #64748b; font-size: 13px; text-transform: uppercase;">IPS Active Banned IPs</h3>
            <p style="font-size: 28px; font-weight: bold; margin: 8px 0 0; color: #7c3aed;">
                <?php
                $banned_ips = get_option('ajs_banned_ips_list', []);
                echo esc_html(count($banned_ips));
                ?>
            </p>
        </div>
    </div>

    <div style="background: #fff; padding: 20px; border: 1px solid #e2e8f0; margin-top: 20px;">
        <h2><?php esc_html_e('Serangan Terbaru Ditolak', 'anti-judol-shield'); ?></h2>
        <?php if (empty($recent_logs)) : ?>
            <p><?php esc_html_e('Belum ada log serangan tercatat.', 'anti-judol-shield'); ?></p>
        <?php else : ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 160px;">Waktu</th>
                        <th style="width: 140px;">IP Pengirim</th>
                        <th style="width: 180px;">Jenis Deteksi</th>
                        <th>Payload / Kata Kunci Terdeteksi</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recent_logs as $log) : ?>
                        <tr>
                            <td><?php echo esc_html($log->created_at); ?></td>
                            <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                            <td><span class="badge" style="background:#fee2e2;color:#991b1b;padding:2px 8px;border-radius:4px;font-size:11px;"><?php echo esc_html($log->reason); ?></span></td>
                            <td><code><?php echo esc_html(wp_trim_words($log->threat_payload, 15)); ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
