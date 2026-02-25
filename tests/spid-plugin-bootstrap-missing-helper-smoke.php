<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$bootstrap = $root . '/wp-spid-cie.php';
if (!is_file($bootstrap)) {
    fwrite(STDERR, "Bootstrap file not found: {$bootstrap}\n");
    exit(1);
}

$source = (string) file_get_contents($bootstrap);
if ($source === '') {
    fwrite(STDERR, "Unable to read bootstrap source\n");
    exit(1);
}

$tmpBootstrap = tempnam(sys_get_temp_dir(), 'wp-spid-cie-bootstrap-');
if ($tmpBootstrap === false) {
    fwrite(STDERR, "Unable to create temporary bootstrap file\n");
    exit(1);
}

$patched = str_replace(
    [
        "'includes/Core/SpidSamlActivation.php'",
        "'includes/Core/SpidSamlMetadataProtection.php'",
        'run_wp_spid_cie();',
    ],
    [
        "'includes/Core/SpidSamlActivation.MISSING.php'",
        "'includes/Core/SpidSamlMetadataProtection.MISSING.php'",
        '// run_wp_spid_cie(); // disabled in smoke test',
    ],
    $source
);
file_put_contents($tmpBootstrap, $patched);

register_shutdown_function(static function () use ($tmpBootstrap): void {
    @unlink($tmpBootstrap);
});

if (!defined('WPINC')) {
    define('WPINC', 'wp-includes');
}
if (!defined('WP_DEBUG')) {
    define('WP_DEBUG', true);
}

if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file) {
        global $root;
        return rtrim((string) $root, '/\\') . '/';
    }
}
if (!function_exists('is_admin')) { function is_admin() { return false; } }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('register_activation_hook')) { function register_activation_hook(...$args) {} }
if (!function_exists('plugin_basename')) { function plugin_basename($file) { return basename((string) $file); } }
if (!function_exists('admin_url')) { function admin_url($path = '') { return 'http://example.test/wp-admin/' . ltrim((string) $path, '/'); } }
if (!function_exists('esc_url')) { function esc_url($url) { return (string) $url; } }
if (!function_exists('esc_html__')) { function esc_html__($text, $domain = null) { return (string) $text; } }
if (!function_exists('get_option')) { function get_option($name, $default = false) { return $default; } }
if (!function_exists('update_option')) { function update_option($name, $value, $autoload = null) { return true; } }

require $tmpBootstrap;

if (!defined('WP_SPID_CIE_OIDC_SAML_HELPERS_OK')) {
    fwrite(STDERR, "Missing health constant WP_SPID_CIE_OIDC_SAML_HELPERS_OK\n");
    exit(1);
}
if (WP_SPID_CIE_OIDC_SAML_HELPERS_OK !== false) {
    fwrite(STDERR, "Expected WP_SPID_CIE_OIDC_SAML_HELPERS_OK=false in missing-helper simulation\n");
    exit(1);
}

if (!defined('WP_SPID_CIE_OIDC_SAML_MISSING_HELPERS')) {
    fwrite(STDERR, "Missing diagnostic constant WP_SPID_CIE_OIDC_SAML_MISSING_HELPERS\n");
    exit(1);
}

$missing = (string) WP_SPID_CIE_OIDC_SAML_MISSING_HELPERS;
if (strpos($missing, 'includes/Core/SpidSamlActivation.MISSING.php') === false) {
    fwrite(STDERR, "Missing helper list does not contain activation helper\n");
    exit(1);
}
if (strpos($missing, 'includes/Core/SpidSamlMetadataProtection.MISSING.php') === false) {
    fwrite(STDERR, "Missing helper list does not contain metadata helper\n");
    exit(1);
}

echo "OK\n";
exit(0);
