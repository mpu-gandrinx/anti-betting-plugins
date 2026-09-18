<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_Cloudflare {
    public static function get_waf_expression(): string {
        $keywords = [
            'slot', 'gacor', 'maxwin', 'zeus', 'pragmatic',
            'togel', 'sbobet', 'depo pulsa', 'scatter hitam',
            'mahjong ways', 'link alternatif'
        ];

        $kw_rules = [];
        foreach ($keywords as $kw) {
            $kw_rules[] = 'http.request.uri.path contains "' . esc_attr($kw) . '"';
            $kw_rules[] = 'http.request.uri.query contains "' . esc_attr($kw) . '"';
        }

        $kw_expression = '(' . implode(' or ', $kw_rules) . ')';

        $upload_rule = '(http.request.uri.path contains "/wp-content/uploads/" and ' .
                       '(http.request.uri.path endswith ".php" or ' .
                       'http.request.uri.path endswith ".phtml" or ' .
                       'http.request.uri.path endswith ".php5" or ' .
                       'http.request.uri.path endswith ".phar"))';

        $xmlrpc_rule = '(http.request.uri.path eq "/xmlrpc.php")';
        $author_rule = '(http.request.uri.query contains "author=" and not http.request.uri.path contains "/wp-admin")';

        return "{$upload_rule} or {$xmlrpc_rule} or {$author_rule} or {$kw_expression}";
    }

    public static function deploy_to_cloudflare(string $api_token, string $zone_id): array {
        if (empty($api_token) || empty($zone_id)) {
            return ['success' => false, 'message' => 'API Token dan Zone ID Cloudflare belum diisi.'];
        }

        $url = "https://api.cloudflare.com/client/v4/zones/{$zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint";
        $expression = self::get_waf_expression();

        $body = [
            'rules' => [
                [
                    'action'      => 'block',
                    'expression'  => $expression,
                    'description' => 'Anti-Judol Shield Edge Protection',
                    'enabled'     => true,
                ]
            ]
        ];

        $response = wp_remote_post($url, [
            'method'  => 'PUT',
            'headers' => [
                'Authorization' => 'Bearer ' . $api_token,
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($body),
            'timeout' => 15,
        ]);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => $response->get_error_message()];
        }

        $code = wp_remote_retrieve_response_code($response);
        $res_body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300 && !empty($res_body['success'])) {
            return ['success' => true, 'message' => 'Berhasil mendeploy WAF Ruleset ke Cloudflare Edge!'];
        }

        $err_msg = $res_body['errors'][0]['message'] ?? 'Gagal menghubungi API Cloudflare (HTTP ' . $code . ')';
        return ['success' => false, 'message' => $err_msg];
    }
}
