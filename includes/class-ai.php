<?php
if (!defined('ABSPATH')) {
    exit;
}

class AJS_AI {
    private string $endpoint;
    private string $api_key;
    private string $model;
    private bool $enabled;

    public function __construct() {
        $this->endpoint = (string)get_option('ajs_ai_endpoint', 'https://api.openai.com/v1/chat/completions');
        $this->api_key  = (string)get_option('ajs_ai_api_key', '');
        $this->model    = (string)get_option('ajs_ai_model', 'gpt-4o-mini');
        $this->enabled  = (bool)get_option('ajs_ai_enabled', 0);
    }

    public function is_configured(): bool {
        return $this->enabled && !empty($this->endpoint) && !empty($this->api_key);
    }

    public function get_endpoint(): string {
        return $this->endpoint;
    }

    public function get_model(): string {
        return $this->model;
    }

    public function is_enabled(): bool {
        return $this->enabled;
    }

    public function get_system_prompt(): string {
        return "Anda analis keamanan siber spesialis penanganan peretasan situs judi online (judol) dan SEO spam WordPress di Indonesia. " .
               "Periksa teks atau kode yang diberikan. Tentukan apakah memuat: " .
               "1. Kata kunci/promosi terselubung judi online (slot, gacor, maxwin, togel, kasino, link alternatif, dll). " .
               "2. Backdoor/webshell atau payload berbahaya (eval, base64 obfuscation, skrip redirect ke bandar judi). " .
               "Jawab HANYA dalam format JSON valid tanpa format markdown: {\"is_threat\": true|false, \"reason\": \"penjelasan ringkas maks 15 kata\"}";
    }

    public function get_vuln_system_prompt(): string {
        return "Anda adalah Chief Information Security Officer (CISO) dan pakar penetration testing WordPress di Indonesia. " .
               "Tugas Anda menganalisis konfigurasi keamanan server, berkas konfigurasi wp-config.php, izin berkas (file permissions), dan lingkungan hosting. " .
               "Identifikasi celah keamanan (vulnerabilities & hardening weaknesses) yang berpotensi menjadi pintu masuk bagi peretas untuk menyusupkan webshell, deface, atau spam judi online. " .
               "Jawab HANYA dalam format JSON valid tanpa markdown formatting: " .
               "{\"is_vulnerable\": true|false, \"risk_level\": \"CRITICAL\"|\"HIGH\"|\"MEDIUM\"|\"LOW\", \"summary\": \"ringkasan analisa risiko maks 30 kata\", \"loopholes\": [{\"issue\": \"nama celah\", \"severity\": \"CRITICAL\"|\"HIGH\"|\"MEDIUM\", \"recommendation\": \"solusi teknis perbaikan\"}]}";
    }

    public function get_code_system_prompt(): string {
        return "Anda analis keamanan siber & reverse engineer spesialis deteksi malware, webshell, dan backdoor WordPress. " .
               "Periksa potongan kode PHP berikut secara mendalam. Tentukan apakah memuat: " .
               "1. Pembuatan user ilegal / backdoor administrator (wp_create_user, wp_insert_user, eskalasi role administrator tersembunyi, manipulasi hook init/wp_loaded/admin_init tanpa izin). " .
               "2. Backdoor / webshell / eksekusi remote code (eval, assert, base64 obfuscation, system/exec/passthru dari input publik). " .
               "3. Manipulasi opsi registrasi (users_can_register, default_role administrator). " .
               "4. Potensi celah SQL Injection, LFI/RFI, atau Arbitrary File Write. " .
               "Jawab HANYA dalam format JSON valid tanpa format markdown: {\"is_threat\": true|false, \"threat_type\": \"backdoor\"|\"webshell\"|\"user_injection\"|\"rce\"|\"vulnerability\"|\"safe\", \"severity\": \"CRITICAL\"|\"HIGH\"|\"MEDIUM\"|\"LOW\", \"reason\": \"penjelasan ringkas maks 25 kata\", \"recommendation\": \"quarantine\"|\"patch\"|\"whitelist\"}";
    }

    public function inspect_content(string $content): array {
        $system_prompt = $this->get_system_prompt();

        if (!$this->is_configured() || empty(trim($content))) {
            return [
                'is_threat'     => false,
                'reason'        => 'AI nonaktif atau konten kosong',
                'system_prompt' => $system_prompt,
                'user_prompt'   => '',
                'model'         => $this->model,
                'endpoint'      => $this->endpoint,
                'raw_reply'     => '',
                'sample_length' => 0,
            ];
        }

        $sample      = substr($content, 0, 2500);
        $user_prompt = "Periksa konten berikut:\n\n" . $sample;

        $messages = [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_prompt]
        ];

        $result = $this->call_completion($messages);
        $result['system_prompt'] = $system_prompt;
        $result['user_prompt']   = $user_prompt;
        $result['model']         = $this->model;
        $result['endpoint']      = $this->endpoint;
        $result['sample_length'] = strlen($sample);

        return $result;
    }

    public function inspect_code(string $code, string $filepath = ''): array {
        $system_prompt = $this->get_code_system_prompt();

        if (!$this->is_configured() || empty(trim($code))) {
            return [
                'is_threat'     => false,
                'reason'        => 'AI nonaktif atau kode kosong',
                'system_prompt' => $system_prompt,
                'user_prompt'   => '',
                'model'         => $this->model,
                'endpoint'      => $this->endpoint,
                'raw_reply'     => '',
                'sample_length' => 0,
            ];
        }

        $sample    = substr($code, 0, 2500);
        $file_info = $filepath ? "Lokasi file: " . wp_make_link_relative($filepath) . "\n\n" : "";
        $user_prompt = "Periksa kode PHP berikut apakah memuat backdoor, webshell, atau skrip pembuatan user ilegal:\n\n{$file_info}" . $sample;

        $messages = [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_prompt]
        ];

        $result = $this->call_completion($messages);
        $result['system_prompt'] = $system_prompt;
        $result['user_prompt']   = $user_prompt;
        $result['model']         = $this->model;
        $result['endpoint']      = $this->endpoint;
        $result['sample_length'] = strlen($sample);

        return $result;
    }

    public function inspect_server_vulnerabilities(array $server_data): array {
        $system_prompt = $this->get_vuln_system_prompt();

        if (!$this->is_configured() || empty($server_data)) {
            return [
                'is_vulnerable' => false,
                'risk_level'    => 'LOW',
                'summary'       => 'Modul AI belum dikonfigurasi.',
                'loopholes'     => [],
                'raw_reply'     => '',
            ];
        }

        $formatted_data = wp_json_encode($server_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $user_prompt = "Berikut data audit konfigurasi server, lingkungan hosting, dan izin berkas WordPress saat ini:\n\n```json\n" . substr($formatted_data, 0, 4000) . "\n```\n\nAnalisis celah keamanan yang ada dan berikan rekomendasi perbaikan teknis.";

        $messages = [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_prompt]
        ];

        $response = $this->raw_request($messages, 600);
        if (is_wp_error($response)) {
            return [
                'is_vulnerable' => false,
                'risk_level'    => 'UNKNOWN',
                'summary'       => 'Gagal terhubung ke AI: ' . $response->get_error_message(),
                'loopholes'     => [],
                'raw_reply'     => '',
            ];
        }

        $body   = wp_remote_retrieve_body($response);
        $json   = json_decode($body, true);
        $reply  = $json['choices'][0]['message']['content'] ?? '';
        $parsed = $this->extract_json($reply);

        if (is_array($parsed)) {
            return [
                'is_vulnerable' => !empty($parsed['is_vulnerable']),
                'risk_level'    => (string)($parsed['risk_level'] ?? 'MEDIUM'),
                'summary'       => (string)($parsed['summary'] ?? 'Analisis selesai.'),
                'loopholes'     => (array)($parsed['loopholes'] ?? []),
                'raw_reply'     => $reply,
            ];
        }

        return [
            'is_vulnerable' => false,
            'risk_level'    => 'MEDIUM',
            'summary'       => 'Respon AI tidak dapat diurai.',
            'loopholes'     => [],
            'raw_reply'     => substr($reply, 0, 300),
        ];
    }

    public function inspect_source_code_deep(string $code, string $filepath = ''): array {
        $system_prompt = $this->get_code_system_prompt();

        if (!$this->is_configured() || empty(trim($code))) {
            return [
                'is_threat'      => false,
                'threat_type'    => 'safe',
                'severity'       => 'LOW',
                'reason'         => 'AI nonaktif atau kode kosong',
                'recommendation' => 'none',
                'raw_reply'      => '',
            ];
        }

        $sample    = substr($code, 0, 3500);
        $file_info = $filepath ? "Target File: " . wp_make_link_relative($filepath) . "\n\n" : "";
        $user_prompt = "Periksa source code PHP berikut secara mendalam:\n\n{$file_info}```php\n" . $sample . "\n```";

        $messages = [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_prompt]
        ];

        $response = $this->raw_request($messages, 400);
        if (is_wp_error($response)) {
            return [
                'is_threat'      => false,
                'threat_type'    => 'safe',
                'severity'       => 'LOW',
                'reason'         => 'AI Error: ' . $response->get_error_message(),
                'recommendation' => 'none',
                'raw_reply'      => '',
            ];
        }

        $body   = wp_remote_retrieve_body($response);
        $json   = json_decode($body, true);
        $reply  = $json['choices'][0]['message']['content'] ?? '';
        $parsed = $this->extract_json($reply);

        if (is_array($parsed) && isset($parsed['is_threat'])) {
            return [
                'is_threat'      => (bool)$parsed['is_threat'],
                'threat_type'    => (string)($parsed['threat_type'] ?? 'unknown'),
                'severity'       => strtoupper((string)($parsed['severity'] ?? 'HIGH')),
                'reason'         => (string)($parsed['reason'] ?? 'Ancaman terdeteksi AI'),
                'recommendation' => (string)($parsed['recommendation'] ?? 'quarantine'),
                'raw_reply'      => $reply,
            ];
        }

        return [
            'is_threat'      => false,
            'threat_type'    => 'safe',
            'severity'       => 'LOW',
            'reason'         => 'Respon AI tidak valid',
            'recommendation' => 'none',
            'raw_reply'      => substr($reply, 0, 300),
        ];
    }

    public function remediate_threat(string $file_or_target, string $threat_type, string $snippet): array {
        if (!$this->is_configured()) {
            return [
                'success'     => false,
                'action'      => 'none',
                'explanation' => 'Modul AI belum dikonfigurasi dengan API Key yang valid.',
            ];
        }

        $system_prompt = "Anda analis keamanan siber WordPress. " .
            "Tugas Anda memeriksa temuan keamanan pada file plugin/tema WordPress dan menentukan tindakan yang tepat: " .
            "1. 'whitelist' => Jika temuan adalah FALSE POSITIVE pada kode sah plugin (seperti WooCommerce customer registration, LearnPress student checkout, Elementor, Theme My Login) yang bukan backdoor peretas. " .
            "2. 'quarantine' => Jika file adalah file webshell/backdoor mandiri peretas yang harus dinonaktifkan (.quarantine_bak). " .
            "3. 'patch' => Jika file sah yang disisipi skrip jahat dan perlu dinetralkan. " .
            "Jawab HANYA format JSON valid tanpa markdown: {\"verdict\": \"SAFE_FALSE_POSITIVE\"|\"MALICIOUS_THREAT\", \"action\": \"whitelist\"|\"quarantine\"|\"patch\", \"explanation\": \"Penjelasan bahasa Indonesia maks 25 kata\"}";

        $file_info   = wp_make_link_relative($file_or_target);
        $user_prompt = "Target: {$file_info}\nTipe Ancaman: {$threat_type}\nCuplikan Kode:\n" . substr($snippet, 0, 2500);

        $messages = [
            ['role' => 'system', 'content' => $system_prompt],
            ['role' => 'user', 'content' => $user_prompt]
        ];

        $response = $this->raw_request($messages, 250);
        if (is_wp_error($response)) {
            return [
                'success'     => false,
                'action'      => 'none',
                'explanation' => 'Gagal terhubung ke AI: ' . $response->get_error_message(),
            ];
        }

        $body   = wp_remote_retrieve_body($response);
        $json   = json_decode($body, true);
        $reply  = $json['choices'][0]['message']['content'] ?? '';
        $parsed = $this->extract_json($reply);

        if (is_array($parsed) && isset($parsed['action'])) {
            return [
                'success'     => true,
                'verdict'     => (string)($parsed['verdict'] ?? 'MALICIOUS_THREAT'),
                'action'      => (string)($parsed['action'] ?? 'whitelist'),
                'explanation' => (string)($parsed['explanation'] ?? 'Tindakan remediasi diproses.'),
                'raw'         => $reply,
            ];
        }

        return [
            'success'     => false,
            'action'      => 'none',
            'explanation' => 'Respon AI tidak valid: ' . substr($reply, 0, 100),
        ];
    }

    public function test_connection(): array {
        if (empty($this->endpoint) || empty($this->api_key)) {
            return ['success' => false, 'message' => 'Endpoint dan API Key belum diisi.'];
        }

        $messages = [
            ['role' => 'user', 'content' => 'Ping. Jawab dengan JSON valid: {"status":"ok"}']
        ];

        $response = $this->raw_request($messages, 50);
        if (is_wp_error($response)) {
            return ['success' => false, 'message' => $response->get_error_message()];
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            $body = wp_remote_retrieve_body($response);
            return ['success' => false, 'message' => "HTTP {$code}: " . substr($body, 0, 150)];
        }

        return ['success' => true, 'message' => 'Koneksi ke AI Endpoint Berhasil.'];
    }

    public function extract_json(string $text): ?array {
        $clean = trim($text);
        $clean = preg_replace('/^```(?:json)?\s*/i', '', $clean);
        $clean = preg_replace('/\s*```$/i', '', $clean);
        $clean = trim($clean);

        $parsed = json_decode($clean, true);
        if (is_array($parsed)) {
            return $parsed;
        }

        if (preg_match('/\{[\s\S]*\}/', $text, $matches)) {
            $extracted = json_decode($matches[0], true);
            if (is_array($extracted)) {
                return $extracted;
            }
        }

        return null;
    }

    private function call_completion(array $messages): array {
        $response = $this->raw_request($messages, 250);
        if (is_wp_error($response)) {
            return [
                'is_threat' => false,
                'reason'    => 'AI Error: ' . $response->get_error_message(),
                'raw_reply' => '',
            ];
        }

        $body = wp_remote_retrieve_body($response);
        $json = json_decode($body, true);

        $reply  = $json['choices'][0]['message']['content'] ?? '';
        $parsed = $this->extract_json($reply);

        if (is_array($parsed) && isset($parsed['is_threat'])) {
            return [
                'is_threat' => (bool)$parsed['is_threat'],
                'reason'    => (string)($parsed['reason'] ?? 'AI Threat Detected'),
                'raw_reply' => $reply,
            ];
        }

        return [
            'is_threat' => false,
            'reason'    => 'Invalid AI Response',
            'raw_reply' => substr($reply, 0, 300),
        ];
    }

    private function raw_request(array $messages, int $max_tokens = 250) {
        $payload = [
            'model'       => $this->model,
            'messages'    => $messages,
            'max_tokens'  => $max_tokens,
            'temperature' => 0.0,
        ];

        return wp_remote_post($this->endpoint, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->api_key,
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode($payload),
            'timeout' => 25,
        ]);
    }
}
