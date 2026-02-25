<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('wp_unslash')) { function wp_unslash($value) { return $value; } }
if (!function_exists('sanitize_text_field')) { function sanitize_text_field($v) { return trim((string) $v); } }
if (!function_exists('status_header')) { function status_header($code) {} }
if (!function_exists('nocache_headers')) { function nocache_headers() {} }
if (!function_exists('home_url')) {
    function home_url($path = '/') {
        return 'https://example.test' . $path;
    }
}
if (!function_exists('get_option')) {
    function get_option($key, $default = null) {
        return $default;
    }
}
if (!function_exists('add_query_arg')) {
    function add_query_arg($key, $value = null, $url = null) {
        if (is_array($key)) {
            $base = (string) $value;
            $query = http_build_query($key);
        } else {
            $base = (string) $url;
            $query = http_build_query([$key => $value]);
        }
        $sep = strpos($base, '?') === false ? '?' : '&';
        return $base . $sep . $query;
    }
}
if (!function_exists('esc_html')) { function esc_html($v) { return (string) $v; } }
if (!function_exists('esc_url')) { function esc_url($v) { return (string) $v; } }
if (!function_exists('wp_nonce_url')) { function wp_nonce_url($url, $action = '') { return (string) $url; } }
if (!function_exists('admin_url')) { function admin_url($path = '') { return 'https://example.test/wp-admin/' . ltrim((string) $path, '/'); } }
if (!function_exists('sanitize_key')) { function sanitize_key($v) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $v)); } }
if (!function_exists('is_admin')) { function is_admin() { return true; } }
if (!function_exists('current_user_can')) { function current_user_can($capability) { return true; } }

require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';
require_once __DIR__ . '/../admin/class-wp-spid-cie-admin.php';

$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
$pathMethod = new ReflectionMethod($public, 'is_official_sp_metadata_request');
$pathMethod->setAccessible(true);

$_SERVER['REQUEST_URI'] = '/sp-metadata.xml';
if ($pathMethod->invoke($public) !== true) {
    fwrite(STDERR, "Expected /sp-metadata.xml to be official metadata path\n");
    exit(1);
}

$_SERVER['REQUEST_URI'] = '/sp-metadata.xml/';
if ($pathMethod->invoke($public) !== true) {
    fwrite(STDERR, "Expected /sp-metadata.xml/ to be official metadata path\n");
    exit(1);
}

$admin = new WP_SPID_CIE_OIDC_Admin('wp-spid-cie', 'test');
$renderMethod = new ReflectionMethod($admin, 'render_spid_saml_metadata_subtab');
$renderMethod->setAccessible(true);

ob_start();
$renderMethod->invoke($admin);
$output = (string) ob_get_clean();

if (strpos($output, 'sp-metadata.xml?aggregator=1') === false) {
    fwrite(STDERR, "Expected official Aggregator URL to use /sp-metadata.xml?aggregator=1\n");
    exit(1);
}

echo "Official metadata path normalization and aggregator URL: OK\n";
