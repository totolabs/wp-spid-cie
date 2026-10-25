<?php

require_once __DIR__ . '/bootstrap.php';

error_reporting(E_ERROR | E_PARSE);

function trailingslashit($path) {
    return rtrim((string) $path, '/\\') . '/';
}

function untrailingslashit($path) {
    return rtrim((string) $path, '/\\');
}

function wp_mkdir_p($target) {
    return is_dir($target) || mkdir($target, 0777, true);
}

function sanitize_text_field($value) {
    return trim((string) $value);
}

function home_url($path = '/') {
    return 'https://example.gov.it' . $path;
}

function get_bloginfo($show = '') {
    return 'Comune di Test';
}

function is_wp_error($thing) {
    return $thing instanceof WP_Error;
}

class WP_Error {
    private $msg;
    public function __construct($code, $msg) {
        $this->msg = $msg;
    }
    public function get_error_message() {
        return $this->msg;
    }
}

require_once __DIR__ . '/../vendor/autoload.php';

class WP_SPID_CIE_OIDC_Factory {
    public static function resolve_spid_key_dir(bool $for_generation = false): string {
        return __DIR__ . '/tmp-keys';
    }
}

require_once __DIR__ . '/../includes/class-wp-spid-cie-spid-certificates.php';

function assert_true($condition, $message) {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$options = [
    'organization_name' => 'Comune di Test',
    'spid_saml_locality_name' => 'Salerno',
    'spid_saml_entity_id' => 'https://tsrmpstrpsalerno.it',
    'ipa_code' => 'cpdtsrs',
    'spid_saml_common_name' => 'Comune di Test',
    'sp_org_display_name' => 'Comune di Test',
];

function spid_certificates_test_remove_dir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $entry;
        is_dir($path) ? spid_certificates_test_remove_dir($path) : @unlink($path);
    }
    @rmdir($dir);
}

$dir = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(true);
// private.key, public.crt, csr.pem e la directory tests/tmp-keys vengono rimossi a fine processo
// dopo PASS, FAIL o eccezione.
register_shutdown_function(static function () use ($dir): void {
    spid_certificates_test_remove_dir($dir);
});
if (is_dir($dir)) {
    foreach (glob($dir . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dir);
}

$result = WP_SPID_CIE_OIDC_Spid_Certificates::generate($options, true);
assert_true($result['success'] === true, 'La generazione certificato deve riuscire.');
assert_true(file_exists($result['paths']['private']), 'private.key deve esistere.');
assert_true(file_exists($result['paths']['cert']), 'public.crt deve esistere.');

$validation = WP_SPID_CIE_OIDC_Spid_Certificates::validate($result['paths']['private'], $result['paths']['cert'], $options);
assert_true($validation['valid'] === true, 'Il certificato deve risultare valido.');

$status = WP_SPID_CIE_OIDC_Spid_Certificates::describe_status($options);
assert_true($status['present'] === true, 'Status present deve essere true.');
assert_true($status['valid'] === true, 'Status valid deve essere true.');

echo "OK\n";
wp_spid_cie_test_ok('spid-certificates-integration');
