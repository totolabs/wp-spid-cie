<?php
declare(strict_types=1);

if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('wp_parse_url')) { function wp_parse_url($url, $component = -1) { return parse_url((string) $url, $component); } }
if (!function_exists('esc_url')) { function esc_url($url) { return (string) $url; } }
if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file) {
        if (strpos((string) $file, '/public/') !== false) {
            return 'http://example.test/wp-content/plugins/wp-spid-cie/public/';
        }
        return 'http://example.test/wp-content/plugins/wp-spid-cie/';
    }
}
if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file) {
        return rtrim(dirname((string) $file), '/') . '/';
    }
}

require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';

$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
$method = new ReflectionMethod($public, 'get_spid_idp_logo_by_entity');
$method->setAccessible(true);

$cases = [
    [
        'entity' => 'https://id.infocamere.it',
        'logo' => 'https://registry.spid.gov.it/assets/infocamere.png',
        'label' => 'InfoCamere should prefer registry logo URI',
    ],
    [
        'entity' => 'https://id.eht.eu',
        'logo' => 'https://registry.spid.gov.it/assets/etnaid.png',
        'label' => 'EtnaID should prefer registry logo URI',
    ],
];

foreach ($cases as $case) {
    $resolved = (string) $method->invoke($public, $case['entity'], $case['logo']);
    if ($resolved !== $case['logo']) {
        fwrite(STDERR, $case['label'] . "\nExpected: {$case['logo']}\nResolved: {$resolved}\n");
        exit(1);
    }
}

echo "SPID SAML IdP logo resolution: OK\n";
