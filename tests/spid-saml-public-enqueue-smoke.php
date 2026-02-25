<?php
declare(strict_types=1);

$enqueued_styles = [];
$enqueued_scripts = [];

if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('get_option')) {
    function get_option($key, $default = []) {
        if ($key === 'wp-spid-cie_options') {
            return [
                'spid_enabled' => '1',
                'spid_auth_method' => 'saml',
                'spid_saml_enabled' => '0', // sticky legacy value: must not break/fatal
            ];
        }
        return $default;
    }
}
if (!function_exists('plugin_dir_url')) { function plugin_dir_url($file) { return 'http://example.test/plugin/' . basename(dirname($file)) . '/'; } }
if (!function_exists('plugin_dir_path')) { function plugin_dir_path($file) { return rtrim(dirname($file), '/') . '/'; } }
if (!function_exists('wp_enqueue_style')) {
    function wp_enqueue_style($handle, $src = '', $deps = [], $ver = false, $media = 'all') {
        global $enqueued_styles;
        $enqueued_styles[] = $handle;
    }
}
if (!function_exists('wp_enqueue_script')) {
    function wp_enqueue_script($handle, $src = '', $deps = [], $ver = false, $in_footer = false) {
        global $enqueued_scripts;
        $enqueued_scripts[] = $handle;
    }
}
if (!function_exists('wp_register_script')) { function wp_register_script(...$args) {} }
if (!function_exists('wp_add_inline_script')) { function wp_add_inline_script(...$args) {} }

require_once __DIR__ . '/../includes/Core/SpidSamlActivation.php';
require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';

$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
$public->enqueue_styles();

if (!in_array('wp-spid-cie-spid-access-button', $enqueued_styles, true)) {
    fwrite(STDERR, "Expected SPID access button style to be enqueued without fatal\n");
    exit(1);
}
if (!in_array('wp-spid-cie', $enqueued_styles, true)) {
    fwrite(STDERR, "Expected main plugin public style to be enqueued\n");
    exit(1);
}

echo "public enqueue_styles smoke: OK\n";
