<?php
declare(strict_types=1);

if (!function_exists('wp_generate_password')) {
    function wp_generate_password($length = 12, $special_chars = true, $extra_special_chars = false) {
        return str_repeat('T', max(1, (int) $length));
    }
}

require_once __DIR__ . '/../includes/Core/SpidSamlMetadataProtection.php';

function simulated_sanitize_options(array $input, array $existing): array {
    $allowed = ['spid_saml_metadata_token'];
    $new = $existing;
    foreach ($allowed as $key) {
        if (array_key_exists($key, $input)) {
            $new[$key] = (string) $input[$key];
        }
    }
    return $new;
}

function simulated_update_option_with_sanitize(array $db_value, array $new_value): array {
    return simulated_sanitize_options($new_value, $db_value);
}

function simulated_update_option_raw(array $new_value): array {
    return $new_value;
}

function toggle_metadata_token_fallback(array $options): array {
    $require_token = (string) ($options['spid_saml_metadata_require_token'] ?? '0') === '1';
    $options['spid_saml_metadata_require_token'] = $require_token ? '0' : '1';
    if ((string) ($options['spid_saml_metadata_require_token'] ?? '0') === '1' && empty($options['spid_saml_metadata_token'])) {
        $options['spid_saml_metadata_token'] = wp_generate_password(24, false, false);
    }
    return $options;
}

function simulated_metadata_http_status(string $route, array $options, string $request_path, string $provided_token = ''): int {
    if ($route !== 'metadata') {
        return 404;
    }

    $requires_token = (string) ($options['spid_saml_metadata_require_token'] ?? '0') === '1';
    $expected_token = (string) ($options['spid_saml_metadata_token'] ?? '');
    $normalized_path = '/' . ltrim($request_path, '/');
    $is_official = rtrim($normalized_path, '/') === '/sp-metadata.xml';

    if ($requires_token && !$is_official && ($expected_token === '' || $provided_token !== $expected_token)) {
        return 403;
    }

    return 200;
}

$options = [
    'spid_saml_metadata_require_token' => '0',
    'spid_saml_metadata_token' => '',
];

$toggled = WP_SPID_CIE_OIDC_Spid_Saml_Metadata_Protection::toggle($options);
if ((string) ($toggled['spid_saml_metadata_require_token'] ?? '0') !== '1') {
    fwrite(STDERR, "Expected spid_saml_metadata_require_token to become '1' after toggle\n");
    exit(1);
}
if (empty($toggled['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Expected non-empty metadata token after enabling protection\n");
    exit(1);
}

$toggled_back = WP_SPID_CIE_OIDC_Spid_Saml_Metadata_Protection::toggle($toggled);
if ((string) ($toggled_back['spid_saml_metadata_require_token'] ?? '0') !== '0') {
    fwrite(STDERR, "Expected spid_saml_metadata_require_token to become '0' after second toggle\n");
    exit(1);
}
if (empty($toggled_back['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Expected metadata token to remain non-empty after disabling protection\n");
    exit(1);
}

$fallback_options = [
    'spid_saml_metadata_require_token' => '0',
    'spid_saml_metadata_token' => '',
];
$fallback_on = toggle_metadata_token_fallback($fallback_options);
if ((string) ($fallback_on['spid_saml_metadata_require_token'] ?? '0') !== '1') {
    fwrite(STDERR, "Fallback expected require_token='1' after enable\n");
    exit(1);
}
if (empty($fallback_on['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Fallback expected token generation when enabling protection\n");
    exit(1);
}

$fallback_off = toggle_metadata_token_fallback($fallback_on);
if ((string) ($fallback_off['spid_saml_metadata_require_token'] ?? '0') !== '0') {
    fwrite(STDERR, "Fallback expected require_token='0' after disable\n");
    exit(1);
}
if (empty($fallback_off['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Fallback expected token to stay available after disabling protection\n");
    exit(1);
}

echo "metadata token toggle logic (helper + fallback): OK\n";

$admin_before = [
    'spid_saml_metadata_require_token' => '0',
    'spid_saml_metadata_token' => 'TOK-OLD',
];
$admin_target = $admin_before;
$admin_target['spid_saml_metadata_require_token'] = '1';
$admin_target['spid_saml_metadata_token'] = 'TOK-NEW';

$admin_after_sanitized = simulated_update_option_with_sanitize($admin_before, $admin_target);
if ((string) ($admin_after_sanitized['spid_saml_metadata_require_token'] ?? '0') !== '0') {
    fwrite(STDERR, "Expected sanitized admin update to drop require_token change without bypass\n");
    exit(1);
}

$admin_after_raw = simulated_update_option_raw($admin_target);
if ((string) ($admin_after_raw['spid_saml_metadata_require_token'] ?? '0') !== '1') {
    fwrite(STDERR, "Expected raw admin update to persist require_token with bypass\n");
    exit(1);
}
if (empty($admin_after_raw['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Expected raw admin update to keep metadata token\n");
    exit(1);
}

echo "admin persistence simulation (sanitize vs raw bypass): OK\n";

$secured_options = [
    'spid_saml_metadata_require_token' => '1',
    'spid_saml_metadata_token' => 'TOK-SECURE',
];
if (simulated_metadata_http_status('metadata', $secured_options, '/spid/saml/metadata') !== 403) {
    fwrite(STDERR, "Expected /spid/saml/metadata to return 403 without token when protection is active\n");
    exit(1);
}
if (simulated_metadata_http_status('metadata', $secured_options, '/spid/saml/metadata', 'TOK-SECURE') !== 200) {
    fwrite(STDERR, "Expected /spid/saml/metadata to return 200 with valid token when protection is active\n");
    exit(1);
}
if (simulated_metadata_http_status('metadata', $secured_options, '/sp-metadata.xml') !== 200) {
    fwrite(STDERR, "Expected /sp-metadata.xml to remain public (200) when protection is active\n");
    exit(1);
}
if (simulated_metadata_http_status('metadata', $secured_options, '/sp-metadata.xml/') !== 200) {
    fwrite(STDERR, "Expected /sp-metadata.xml/ to remain equivalent to /sp-metadata.xml (200)\n");
    exit(1);
}

echo "metadata endpoint policy enforcement simulation: OK\n";
