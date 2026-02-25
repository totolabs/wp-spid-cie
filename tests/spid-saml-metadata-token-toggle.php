<?php
declare(strict_types=1);

if (!function_exists('wp_generate_password')) {
    function wp_generate_password($length = 12, $special_chars = true, $extra_special_chars = false) {
        return str_repeat('T', max(1, (int) $length));
    }
}

require_once __DIR__ . '/../includes/Core/SpidSamlMetadataProtection.php';

$options = [
    'spid_saml_metadata_require_token' => '0',
    'spid_saml_metadata_token' => '',
];

$toggled = WP_SPID_CIE_OIDC_Spid_Saml_Metadata_Protection::toggle($options);
if (($toggled['spid_saml_metadata_require_token'] ?? '') !== '1') {
    fwrite(STDERR, "Expected spid_saml_metadata_require_token to become '1' after toggle\n");
    exit(1);
}
if (empty($toggled['spid_saml_metadata_token'])) {
    fwrite(STDERR, "Expected non-empty metadata token after enabling protection\n");
    exit(1);
}

echo "metadata token toggle logic: OK\n";
