<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/Core/SpidSamlActivation.php';

$options = [
    'spid_enabled' => '1',
    'spid_auth_method' => 'saml',
    'spid_saml_enabled' => '0', // legacy sticky value
];

$effective = WP_SPID_CIE_OIDC_Spid_Saml_Activation::is_effective_enabled($options);
if ($effective !== true) {
    fwrite(STDERR, "Expected effective_saml=true when spid_enabled=1 and spid_auth_method=saml, even if legacy spid_saml_enabled=0\n");
    exit(1);
}

$aligned = WP_SPID_CIE_OIDC_Spid_Saml_Activation::align_legacy_flag($options);
if (!isset($aligned['spid_saml_enabled']) || $aligned['spid_saml_enabled'] !== '1') {
    fwrite(STDERR, "Expected legacy spid_saml_enabled to align to '1'\n");
    exit(1);
}

echo "effective_saml=true with sticky legacy flag: OK\n";
echo "legacy alignment: OK\n";
