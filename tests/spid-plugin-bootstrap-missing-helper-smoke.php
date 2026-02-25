<?php
declare(strict_types=1);

$bootstrap = __DIR__ . '/../wp-spid-cie.php';
$source = @file_get_contents($bootstrap);
if ($source === false) {
    fwrite(STDERR, "Unable to read bootstrap file: {$bootstrap}\n");
    exit(1);
}

$requiredSnippets = [
    '$activation_file = plugin_dir_path( __FILE__ ) . \'includes/Core/SpidSamlActivation.php\';',
    'if ( file_exists( $activation_file ) )',
    'require_once $activation_file;',
    '$metadata_protection_file = plugin_dir_path( __FILE__ ) . \'includes/Core/SpidSamlMetadataProtection.php\';',
    'if ( file_exists( $metadata_protection_file ) )',
    'require_once $metadata_protection_file;',
    'define( \'WP_SPID_CIE_OIDC_SAML_HELPERS_OK\', $spid_saml_helpers_ok );',
];

foreach ($requiredSnippets as $snippet) {
    if (strpos($source, $snippet) === false) {
        fwrite(STDERR, "Missing expected hardening snippet: {$snippet}\n");
        exit(1);
    }
}

if (preg_match("#require_once\\s+plugin_dir_path\\s*\\(\\s*__FILE__\\s*\\)\\s*\\.\\s*'includes/Core/SpidSamlActivation\\.php'#", $source)) {
    fwrite(STDERR, "Found direct require_once for SpidSamlActivation helper\n");
    exit(1);
}
if (preg_match("#require_once\\s+plugin_dir_path\\s*\\(\\s*__FILE__\\s*\\)\\s*\\.\\s*'includes/Core/SpidSamlMetadataProtection\\.php'#", $source)) {
    fwrite(STDERR, "Found direct require_once for SpidSamlMetadataProtection helper\n");
    exit(1);
}

echo "OK\n";
exit(0);
