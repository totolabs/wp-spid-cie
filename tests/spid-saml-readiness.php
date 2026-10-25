<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// Policy pura di readiness SPID SAML: nessun filesystem, nessuna rete.

require_once __DIR__ . '/../includes/Core/SpidSamlActivation.php';

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function readiness(array $optionOverrides = [], array $factOverrides = []): array {
    $options = $optionOverrides + ['spid_enabled' => '1', 'user_provisioning_enabled' => '1'];
    $facts = $factOverrides + [
        'helpers_ok' => true,
        'private_key_readable' => true,
        'cert_readable' => true,
        'cert_valid' => true,
        'idp_registry_count' => 12,
        'sp_entity_source' => 'saml_entity_id',
        'clock_skew' => 120,
    ];
    return WP_SPID_CIE_OIDC_Spid_Saml_Activation::evaluate_readiness($options, $facts);
}

function codes(array $items): array {
    return array_map(static function (array $item): string { return (string) $item['code']; }, $items);
}

function assert_shape(array $result, string $label): void {
    foreach (['ready_local', 'blockers', 'warnings', 'external_checks'] as $key) {
        assert_true(array_key_exists($key, $result), "{$label}: chiave {$key} mancante.");
    }
    assert_true(is_bool($result['ready_local']), "{$label}: ready_local deve essere bool.");
    foreach (['blockers', 'warnings', 'external_checks'] as $list) {
        foreach ($result[$list] as $item) {
            assert_true(isset($item['code'], $item['message']) && $item['code'] !== '' && $item['message'] !== '', "{$label}: ogni voce di {$list} deve avere code e message.");
        }
    }
    assert_true(in_array('agid_metadata', codes($result['external_checks']), true), "{$label}: external_checks deve contenere sempre la verifica metadata AgID.");
}

// Configurazione completa.
$r = readiness();
assert_shape($r, 'completa');
assert_true($r['ready_local'] === true && $r['blockers'] === [] && $r['warnings'] === [], 'Configurazione completa: ready_local=true senza blocker ne warning.');

// Blocker.
$blockerCases = [
    'private key mancante' => [[], ['private_key_readable' => false], 'private_key_unreadable'],
    'cert mancante' => [[], ['cert_readable' => false], 'cert_unreadable'],
    'helper non caricati' => [[], ['helpers_ok' => false], 'saml_helpers_missing'],
    'spid_enabled=0' => [['spid_enabled' => '0'], [], 'spid_disabled'],
];
foreach ($blockerCases as $label => [$opts, $facts, $code]) {
    $r = readiness($opts, $facts);
    assert_shape($r, $label);
    assert_true($r['ready_local'] === false, "{$label}: ready_local deve essere false.");
    assert_true(codes($r['blockers']) === [$code], "{$label}: blocker atteso {$code}.");
}

// Provisioning spento: non blocca (un utente gia' associato entra comunque).
$r = readiness(['user_provisioning_enabled' => '0']);
assert_shape($r, 'provisioning spento');
assert_true($r['ready_local'] === true && $r['blockers'] === [], 'Provisioning spento non deve essere un blocker.');

// Warning: ready_local resta true.
$warningCases = [
    'entity da home_url' => [['sp_entity_source' => 'home_url'], 'sp_entity_home_url'],
    'clock_skew=0' => [['clock_skew' => 0], 'clock_skew_zero'],
    'Registry vuoto' => [['idp_registry_count' => 0], 'idp_registry_empty'],
    'certificato non valido' => [['cert_valid' => false], 'cert_invalid'],
];
foreach ($warningCases as $label => [$facts, $code]) {
    $r = readiness([], $facts);
    assert_shape($r, $label);
    assert_true($r['ready_local'] === true, "{$label}: ready_local deve restare true.");
    assert_true($r['blockers'] === [], "{$label}: nessun blocker atteso.");
    assert_true(codes($r['warnings']) === [$code], "{$label}: warning atteso {$code}.");
}

// Registry sconosciuto (null o assente): nessun warning "vuoto", nessun blocker.
$r = readiness([], ['idp_registry_count' => null]);
assert_shape($r, 'Registry sconosciuto (null)');
assert_true($r['ready_local'] === true && $r['blockers'] === [], 'Registry sconosciuto (null): ready_local=true senza blocker.');
assert_true(!in_array('idp_registry_empty', codes($r['warnings']), true), 'Registry sconosciuto (null) non deve emettere idp_registry_empty.');

$factsWithoutCount = [
    'helpers_ok' => true,
    'private_key_readable' => true,
    'cert_readable' => true,
    'cert_valid' => true,
    'sp_entity_source' => 'saml_entity_id',
    'clock_skew' => 120,
];
$r = WP_SPID_CIE_OIDC_Spid_Saml_Activation::evaluate_readiness(['spid_enabled' => '1'], $factsWithoutCount);
assert_shape($r, 'Registry sconosciuto (assente)');
assert_true($r['ready_local'] === true && $r['blockers'] === [], 'Registry sconosciuto (assente): ready_local=true senza blocker.');
assert_true(!in_array('idp_registry_empty', codes($r['warnings']), true), 'Registry sconosciuto (assente) non deve emettere idp_registry_empty.');

// provider_mode non e' un blocker della readiness.
$r = readiness(['provider_mode' => 'cie_only']);
assert_true($r['ready_local'] === true && $r['blockers'] === [], 'provider_mode non deve comparire tra i blocker.');

echo "readiness complete: OK\n";
echo "readiness blockers: OK\n";
echo "readiness warnings keep ready_local: OK\n";
echo "readiness registry unknown is not empty: OK\n";
echo "readiness external checks: OK\n";
wp_spid_cie_test_ok('spid-saml-readiness');
