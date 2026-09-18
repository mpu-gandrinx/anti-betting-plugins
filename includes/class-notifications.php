<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Notifications {
    public static function send_alert(string $title, string $details, string $severity = 'HIGH'): bool {
        $webhook_url = (string)get_option('ajs_webhook_url', '');
        $telegram_bot_token = (string)get_option('ajs_telegram_bot_token', '');
        $telegram_chat_id = (string)get_option('ajs_telegram_chat_id', '');
        $admin_email_notify = (bool)get_option('ajs_email_notify', 0);

        if (empty($webhook_url) && (empty($telegram_bot_token) || empty($telegram_chat_id)) && !$admin_email_notify) {
            return false;
        }

        // Throttle alerts per severity/event (max 1 alert per 5 minutes for same event title)
        $throttle_key = 'ajs_alert_throttle_' . md5($title);
        if (get_transient($throttle_key)) {
            return false;
        }
        set_transient($throttle_key, 1, 300);

        $site_name = get_bloginfo('name');
        $site_url  = home_url();
        $message   = "🚨 [{$severity}] {$title}\n" .
                     "Site: {$site_name} ({$site_url})\n" .
                     "Waktu: " . current_time('mysql') . "\n\n" .
                     "Detail:\n{$details}";

        // 1. Send to Telegram
        if (!empty($telegram_bot_token) && !empty($telegram_chat_id)) {
            wp_remote_post("https://api.telegram.org/bot{$telegram_bot_token}/sendMessage", [
                'body'    => [
                    'chat_id'    => $telegram_chat_id,
                    'text'       => $message,
                    'parse_mode' => 'HTML',
                ],
                'timeout' => 5,
            ]);
        }

        // 2. Send to Webhook (Slack / Discord / Custom API)
        if (!empty($webhook_url)) {
            wp_remote_post($webhook_url, [
                'headers' => ['Content-Type' => 'application/json'],
                'body'    => wp_json_encode([
                    'content' => $message,
                    'text'    => $message,
                    'title'   => "[{$severity}] {$title}",
                ]),
                'timeout' => 5,
            ]);
        }

        // 3. Send Email to Site Admin
        if ($admin_email_notify) {
            $to = get_option('admin_email');
            $subject = "[SECURITY ALERT] {$title} - {$site_name}";
            wp_mail($to, $subject, $message);
        }

        return true;
    }
}
