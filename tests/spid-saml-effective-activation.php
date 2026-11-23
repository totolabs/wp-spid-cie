<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

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

// SPID usa solo SAML: lo stato effettivo coincide con spid_enabled, qualunque sia il
// valore legacy di spid_auth_method o spid_saml_enabled.
$legacyCases = [
    'saml' => ['spid_auth_method' => 'saml'],
    'oidc' => ['spid_auth_method' => 'oidc'],
    'assente + flag legacy 1' => ['spid_saml_enabled' => '1'],
    'entrambi assenti' => [],
];
foreach ($legacyCases as $label => $legacy) {
    foreach (['1' => true, '0' => false] as $spidEnabled => $expected) {
        $caseOptions = $legacy + ['spid_enabled' => (string) $spidEnabled];
        $got = WP_SPID_CIE_OIDC_Spid_Saml_Activation::is_effective_enabled($caseOptions);
        if ($got !== $expected) {
            fwrite(STDERR, "Legacy case '{$label}' with spid_enabled={$spidEnabled}: expected " . var_export($expected, true) . ", got " . var_export($got, true) . "\n");
            exit(1);
        }
        $alignedCase = WP_SPID_CIE_OIDC_Spid_Saml_Activation::align_legacy_flag($caseOptions);
        if (($alignedCase['spid_saml_enabled'] ?? null) !== ($expected ? '1' : '0')) {
            fwrite(STDERR, "Legacy case '{$label}' with spid_enabled={$spidEnabled}: legacy flag not aligned\n");
            exit(1);
        }
    }
}

if (method_exists('WP_SPID_CIE_OIDC_Spid_Saml_Activation', 'sanitize_method')) {
    fwrite(STDERR, "sanitize_method must be removed (no callers left after SPID OIDC removal)\n");
    exit(1);
}

echo "effective_saml=true with sticky legacy flag: OK\n";
echo "legacy alignment: OK\n";
echo "legacy spid_auth_method cases follow spid_enabled: OK\n";
wp_spid_cie_test_ok('spid-saml-effective-activation');
