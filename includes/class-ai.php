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

    public function get_code_system_prompt(): string {
        return "Anda analis keamanan siber spesialis deteksi malware, webshell, dan backdoor WordPress. " .
               "Periksa potongan kode PHP berikut. Tentukan apakah memuat: " .
               "1. Pembuatan user ilegal / backdoor administrator (wp_create_user, wp_insert_user, eskalasi role administrator tersembunyi, manipulasi hook init/wp_loaded/admin_init tanpa izin). " .
               "2. Backdoor / webshell / eksekusi remote code (eval, assert, base64 obfuscation, system/exec/passthru dari input publik). " .
               "3. Manipulasi opsi registrasi (users_can_register, default_role administrator). " .
               "Jawab HANYA dalam format JSON valid tanpa format markdown: {\"is_threat\": true|false, \"reason\": \"penjelasan ringkas maks 20 kata mengapa kode berbahaya atau aman\"}";
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

    private function call_completion(array $messages): array {
        $response = $this->raw_request($messages, 150);
        if (is_wp_error($response)) {
            return [
                'is_threat' => false,
                'reason'    => 'AI Error: ' . $response->get_error_message(),
                'raw_reply' => '',
            ];
        }

        $body = wp_remote_retrieve_body($response);
        $json = json_decode($body, true);

        $reply = $json['choices'][0]['message']['content'] ?? '';
        $clean_json = trim(preg_replace('/^```(?:json)?\s*|\s*```$/i', '', trim($reply)));
        $parsed = json_decode($clean_json, true);

        if (is_array($parsed) && isset($parsed['is_threat'])) {
            return [
                'is_threat' => (bool)$parsed['is_threat'],
                'reason'    => (string)($parsed['reason'] ?? 'AI Threat Detected'),
                'raw_reply' => $clean_json,
            ];
        }

        return [
            'is_threat' => false,
            'reason'    => 'Invalid AI Response',
            'raw_reply' => substr($reply, 0, 300),
        ];
    }

    private function raw_request(array $messages, int $max_tokens = 150) {
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
            'timeout' => 10,
        ]);
    }
}
