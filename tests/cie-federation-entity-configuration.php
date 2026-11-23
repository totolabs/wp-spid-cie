<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

error_reporting(E_ERROR | E_PARSE);

function trailingslashit($path) {
    return rtrim((string) $path, '/\\') . '/';
}

function untrailingslashit($path) {
    return rtrim((string) $path, '/\\');
}

function wp_mkdir_p($target) {
    return is_dir($target) || mkdir($target, 0777, true);
}

function sanitize_text_field($value) {
    return trim((string) $value);
}

function plugin_dir_path($file) {
    return trailingslashit(dirname($file));
}

function remove_dir_recursive(string $path): void {
    if (is_file($path)) {
        @unlink($path);
        return;
    }

    if (!is_dir($path)) {
        return;
    }

    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        remove_dir_recursive($path . DIRECTORY_SEPARATOR . $entry);
    }

    @rmdir($path);
}

function home_url($path = '/') {
    $suffix = ltrim((string) $path, '/');
    if ($suffix === '') {
        return 'https://example.gov.it';
    }

    return 'https://example.gov.it/' . $suffix;
}

function set_url_scheme($url, $scheme = null) {
    $value = trim((string) $url);
    if ($value === '' || $scheme === null || $scheme === '') {
        return $value;
    }

    return (string) preg_replace('#^[a-z][a-z0-9+.-]*://#i', $scheme . '://', $value, 1);
}

function add_query_arg($args, $url) {
    $separator = strpos((string) $url, '?') === false ? '?' : '&';
    return (string) $url . $separator . http_build_query($args);
}

function wp_upload_dir() {
    $basedir = __DIR__ . '/tmp-cie-upload';
    if (!is_dir($basedir)) {
        mkdir($basedir, 0777, true);
    }

    return ['basedir' => $basedir];
}

function get_option($name, $default = false) {
    return $default;
}

// /resolve costruisce la trust chain via transient + HTTP (87839d2): shim OFFLINE, nessuna chiamata
// di rete. wp_remote_get fallisce sempre, quindi il runtime ricade su trust_chain = [self entity config].
function get_transient($key) {
    return false;
}

function set_transient($key, $value, $expiration = 0) {
    return true;
}

function wp_remote_get($url, $args = []) {
    return new WP_Error('offline', 'Rete disabilitata nei test.');
}

function get_bloginfo($show = '') {
    return 'Comune di Test';
}

function is_wp_error($thing) {
    return $thing instanceof WP_Error;
}

register_shutdown_function(static function (): void {
    remove_dir_recursive(__DIR__ . '/tmp-cie-upload');
    remove_dir_recursive(__DIR__ . '/tmp-keys');
});

class WP_Error {
    private $msg;

    public function __construct($code, $msg) {
        $this->msg = $msg;
    }

    public function get_error_message() {
        return $this->msg;
    }
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-factory.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-spid-certificates.php';

function assert_true($condition, $message) {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function decode_jwt_segment(string $jwt, int $index): array {
    $parts = explode('.', $jwt);
    if (!isset($parts[$index])) {
        throw new RuntimeException('JWT segment mancante.');
    }

    $segment = strtr($parts[$index], '-_', '+/');
    $segment .= str_repeat('=', (4 - strlen($segment) % 4) % 4);

    $json = base64_decode($segment, true);
    if ($json === false) {
        throw new RuntimeException('Base64url non valido.');
    }

    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('JSON JWT non valido.');
    }

    return $decoded;
}

function base64url_encode(string $value): string {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function build_test_jwt(array $payload): string {
    return base64url_encode((string) json_encode(['alg' => 'none', 'typ' => 'JWT'])) . '.'
        . base64url_encode((string) json_encode($payload))
        . '.';
}

$certificateOptions = [
    'organization_name' => 'Comune di Test',
    'spid_saml_locality_name' => 'Salerno',
    'issuer_override' => 'https://example.gov.it/',
    'ipa_code' => 'cpdtsrs',
    'spid_saml_common_name' => 'Comune di Test',
    'sp_org_display_name' => 'Comune di Test',
];

$keyDir = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(true);
if (is_dir($keyDir)) {
    foreach (glob($keyDir . '/*') ?: [] as $file) {
        @unlink($file);
    }
}

$generation = WP_SPID_CIE_OIDC_Spid_Certificates::generate($certificateOptions, true);
assert_true($generation['success'] === true, 'La generazione delle chiavi federative deve riuscire.');

$trustMark = build_test_jwt(['id' => 'https://example.gov.it/trust-mark/test']);

$wrapper = new WP_SPID_CIE_OIDC_Wrapper([
    'organization_name' => 'Comune di Test',
    'contacts_email' => 'servizi@example.gov.it',
    'ipa_code' => 'cpdtsrs',
    'fiscal_number' => '',
    'base_url' => 'https://example.gov.it',
    'entity_id' => 'https://example.gov.it/',
    'key_dir' => $keyDir,
    'cie_trust_mark_preprod' => $trustMark,
    'cie_trust_mark_prod' => '',
    'cie_trust_anchor_preprod' => '',
    'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it',
    'spid_trust_anchor' => '',
    'cie_enabled' => true,
    'spid_enabled' => true,
]);

$entityStatementJwt = $wrapper->getEntityStatement();
$entityStatementHeader = decode_jwt_segment($entityStatementJwt, 0);
$entityStatementPayload = decode_jwt_segment($entityStatementJwt, 1);
$entityRpMetadata = (array) ($entityStatementPayload['metadata']['openid_relying_party'] ?? []);
$entityFederationMetadata = (array) ($entityStatementPayload['metadata']['federation_entity'] ?? []);

assert_true(($entityStatementHeader['typ'] ?? '') === 'entity-statement+jwt', 'L\'entity configuration deve avere typ=entity-statement+jwt.');
assert_true(in_array('https://oidc.registry.servizicie.interno.gov.it', $entityStatementPayload['authority_hints'] ?? [], true), 'L\'entity configuration deve esporre authority_hints con il trust anchor CIE corretto.');
assert_true(isset($entityStatementPayload['jwks']['keys'][0]), 'L\'entity configuration iniziale deve includere jwks.');
assert_true(isset($entityStatementPayload['iss']) && $entityStatementPayload['iss'] === 'https://example.gov.it', 'iss deve essere presente e normalizzato senza trailing slash.');
assert_true(isset($entityStatementPayload['sub']) && $entityStatementPayload['sub'] === 'https://example.gov.it', 'sub deve essere presente e normalizzato senza trailing slash.');
assert_true($entityStatementPayload['iss'] === $entityStatementPayload['sub'], 'iss e sub devono restare coerenti.');
assert_true(isset($entityStatementPayload['iat']) && is_int($entityStatementPayload['iat']), 'L\'entity configuration iniziale deve includere iat.');
assert_true(isset($entityStatementPayload['exp']) && is_int($entityStatementPayload['exp']), 'L\'entity configuration iniziale deve includere exp.');
assert_true(isset($entityStatementPayload['metadata']['openid_relying_party']), 'L\'entity configuration iniziale deve includere metadata.openid_relying_party.');
assert_true(($entityRpMetadata['subject_type'] ?? '') === 'pairwise', 'L\'entity configuration iniziale CIE deve esporre subject_type=pairwise.');
assert_true(($entityRpMetadata['subject_type'] ?? '') !== 'public', 'L\'entity configuration iniziale CIE non deve esporre subject_type=public.');
assert_true(!array_key_exists('subject_types_supported', $entityRpMetadata), 'Il metadata RP non deve esporre subject_types_supported.');
assert_true(!array_key_exists('jwks_uri', $entityRpMetadata), 'L\'entity configuration iniziale non deve esporre jwks_uri.');
assert_true(isset($entityRpMetadata['jwks']['keys'][0]), 'La metadata RP deve continuare a includere jwks.');
assert_true(($entityRpMetadata['client_id'] ?? '') === $entityStatementPayload['sub'], 'client_id deve coincidere con l\'entity identifier normalizzato.');
assert_true(in_array('automatic', $entityRpMetadata['client_registration_types'] ?? [], true), 'client_registration_types deve contenere automatic.');
assert_true(in_array('authorization_code', $entityRpMetadata['grant_types'] ?? [], true), 'grant_types deve contenere authorization_code.');
assert_true(in_array('refresh_token', $entityRpMetadata['grant_types'] ?? [], true), 'grant_types deve contenere refresh_token (ammesso dalla metadata policy del Trust Anchor CIE, reinserito da f58dfa7).');
assert_true(in_array('code', $entityRpMetadata['response_types'] ?? [], true), 'response_types deve contenere code.');
assert_true(($entityRpMetadata['redirect_uris'] ?? null) === ['https://example.gov.it/?oidc_action=callback&provider=cie'], 'redirect_uris della EC deve contenere solo la callback CIE (HTTPS, slash prima della query da 5f21c10).');
assert_true(($entityFederationMetadata['organization_name'] ?? '') === 'Comune di Test', 'federation_entity RP deve includere organization_name.');
assert_true(($entityFederationMetadata['homepage_uri'] ?? '') === 'https://example.gov.it', 'federation_entity RP deve includere homepage_uri.');
assert_true(($entityFederationMetadata['policy_uri'] ?? '') === 'https://example.gov.it/privacy-policy', 'federation_entity RP deve includere policy_uri.');
assert_true(!array_key_exists('logo_uri', $entityFederationMetadata), 'federation_entity RP non deve esporre logo_uri se non configurato (nessun default hardcoded dal fix aca2590).');
assert_true(($entityFederationMetadata['contacts'][0] ?? '') === 'servizi@example.gov.it', 'federation_entity RP deve includere contacts.');
assert_true(($entityFederationMetadata['federation_resolve_endpoint'] ?? '') === 'https://example.gov.it/resolve', 'federation_entity RP deve includere federation_resolve_endpoint.');
assert_true(!array_key_exists('federation_api_endpoint', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre federation_api_endpoint.');
assert_true(!array_key_exists('federation_fetch_endpoint', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre federation_fetch_endpoint.');
assert_true(!array_key_exists('federation_list_endpoint', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre federation_list_endpoint.');
assert_true(!array_key_exists('federation_trust_mark_status_endpoint', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre federation_trust_mark_status_endpoint.');
assert_true(!array_key_exists('ipa_code', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre ipa_code.');
assert_true(!array_key_exists('organization_identifier', $entityFederationMetadata), 'federation_entity RP CIE iniziale non deve esporre organization_identifier.');
assert_true(($entityStatementPayload['trust_marks'][0]['id'] ?? '') === 'https://example.gov.it/trust-mark/test', 'I trust marks CIE validi devono restare presenti.');
assert_true(($entityStatementPayload['trust_marks'][0]['trust_mark'] ?? '') === $trustMark, 'Il trust mark CIE non deve essere alterato.');

$resolveJwt = $wrapper->getResolveResponse('', 'https://oidc.registry.servizicie.interno.gov.it');
$resolveHeader = decode_jwt_segment($resolveJwt, 0);
$resolvePayload = decode_jwt_segment($resolveJwt, 1);
$resolveRpMetadata = (array) ($resolvePayload['metadata']['openid_relying_party'] ?? []);
$resolveFederationMetadata = (array) ($resolvePayload['metadata']['federation_entity'] ?? []);

assert_true(($resolveHeader['typ'] ?? '') === 'resolve-response+jwt', 'La resolve response deve avere typ=resolve-response+jwt.');
assert_true(($resolvePayload['iss'] ?? '') === 'https://example.gov.it', 'Resolve deve mantenere iss coerente con l\'entity identifier normalizzato.');
assert_true(($resolvePayload['sub'] ?? '') === 'https://example.gov.it', 'Resolve deve mantenere sub coerente con l\'entity identifier normalizzato.');
assert_true(isset($resolvePayload['jwks']['keys'][0]), 'Resolve deve continuare a includere jwks.');
assert_true(isset($resolvePayload['metadata']['openid_relying_party']), 'Resolve deve includere metadata.openid_relying_party.');
assert_true(($resolveRpMetadata['subject_type'] ?? '') === 'pairwise', 'Resolve deve esporre subject_type=pairwise.');
assert_true(($resolveRpMetadata['subject_type'] ?? '') !== 'public', 'Resolve non deve esporre subject_type=public.');
assert_true(!array_key_exists('subject_types_supported', $resolveRpMetadata), 'Resolve RP non deve esporre subject_types_supported.');
assert_true(!array_key_exists('jwks_uri', $resolveRpMetadata), 'Resolve non deve esporre jwks_uri.');
assert_true(($resolveRpMetadata['redirect_uris'] ?? null) === ['https://example.gov.it/?oidc_action=callback&provider=cie'], 'redirect_uris in /resolve deve contenere solo la callback CIE.');
assert_true(($resolveFederationMetadata['federation_resolve_endpoint'] ?? '') === 'https://example.gov.it/resolve', 'Resolve deve continuare a pubblicare l\'endpoint /resolve corretto.');
assert_true(!array_key_exists('federation_fetch_endpoint', $resolveFederationMetadata), 'Resolve RP CIE non deve esporre federation_fetch_endpoint.');
assert_true(!array_key_exists('federation_list_endpoint', $resolveFederationMetadata), 'Resolve RP CIE non deve esporre federation_list_endpoint.');
assert_true(!array_key_exists('federation_trust_mark_status_endpoint', $resolveFederationMetadata), 'Resolve RP CIE non deve esporre federation_trust_mark_status_endpoint.');
assert_true(($resolvePayload['trust_anchor'] ?? '') === 'https://oidc.registry.servizicie.interno.gov.it', 'trust_anchor deve essere normalizzato senza trailing slash.');

$expectedRedirectUris = ['https://example.gov.it/?oidc_action=callback&provider=cie'];

// La self entity configuration dentro trust_chain (stub offline: catena a 1 elemento) segue la EC.
assert_true(isset($resolvePayload['trust_chain'][0]) && is_string($resolvePayload['trust_chain'][0]), 'Resolve deve includere la self entity configuration in trust_chain[0].');
$trustChainSelf = decode_jwt_segment($resolvePayload['trust_chain'][0], 1);
assert_true(($trustChainSelf['metadata']['openid_relying_party']['redirect_uris'] ?? null) === $expectedRedirectUris, 'La self EC in trust_chain[0] deve esporre la sola redirect_uri CIE.');

$baseWrapperConfig = [
    'organization_name' => 'Comune di Test',
    'contacts_email' => 'servizi@example.gov.it',
    'ipa_code' => 'cpdtsrs',
    'fiscal_number' => '',
    'base_url' => 'https://example.gov.it',
    'entity_id' => 'https://example.gov.it',
    'key_dir' => $keyDir,
    'cie_trust_mark_preprod' => $trustMark,
    'cie_trust_mark_prod' => '',
    'cie_trust_anchor_preprod' => '',
    'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it',
    'cie_enabled' => true,
    'spid_enabled' => true,
];

$rpInvariantKeys = ['client_id', 'jwks', 'grant_types', 'response_types', 'token_endpoint_auth_method', 'token_endpoint_auth_signing_alg', 'redirect_uris'];

// CIE disattivato dall'interfaccia: la EC resta in forma CIE.
$cieOffWrapper = new WP_SPID_CIE_OIDC_Wrapper(['cie_enabled' => false] + $baseWrapperConfig);
$cieOnWrapper = new WP_SPID_CIE_OIDC_Wrapper($baseWrapperConfig);
$cieOffEntityStatement = decode_jwt_segment($cieOffWrapper->getEntityStatement(), 1);
$cieOnEntityStatement = decode_jwt_segment($cieOnWrapper->getEntityStatement(), 1);
$cieOffRpMetadata = (array) ($cieOffEntityStatement['metadata']['openid_relying_party'] ?? []);
$cieOnRpMetadata = (array) ($cieOnEntityStatement['metadata']['openid_relying_party'] ?? []);
$cieOffFederationMetadata = (array) ($cieOffEntityStatement['metadata']['federation_entity'] ?? []);

assert_true(!array_key_exists('jwks_uri', $cieOffRpMetadata), 'Con CIE disattivato la EC non deve esporre jwks_uri.');
foreach (['federation_api_endpoint', 'federation_fetch_endpoint', 'federation_list_endpoint', 'federation_trust_mark_status_endpoint', 'ipa_code', 'organization_identifier'] as $legacyField) {
    assert_true(!array_key_exists($legacyField, $cieOffFederationMetadata), "Con CIE disattivato federation_entity non deve esporre {$legacyField}.");
}
assert_true(in_array('https://oidc.registry.servizicie.interno.gov.it', $cieOffEntityStatement['authority_hints'] ?? [], true), 'Con CIE disattivato authority_hints deve contenere il Trust Anchor CIE di produzione.');
foreach ($rpInvariantKeys as $key) {
    assert_true(array_key_exists($key, $cieOnRpMetadata) && ($cieOffRpMetadata[$key] ?? null) === $cieOnRpMetadata[$key], "Con CIE disattivato {$key} deve restare identico al wrapper con cie_enabled=true.");
}
assert_true(($cieOffRpMetadata['jwks']['keys'][0]['kid'] ?? '') !== '' && ($cieOffRpMetadata['jwks']['keys'][0]['n'] ?? '') !== '' && ($cieOffRpMetadata['jwks']['keys'][0]['e'] ?? '') !== '', 'La jwks deve contenere kid, n ed e.');
assert_true($cieOffRpMetadata['grant_types'] === ['authorization_code', 'refresh_token'], 'grant_types deve restare authorization_code + refresh_token.');
assert_true(($cieOffEntityStatement['trust_marks'] ?? null) === ($cieOnEntityStatement['trust_marks'] ?? null), 'Con CIE disattivato i trust_marks devono restare invariati.');
assert_true(array_keys($cieOffFederationMetadata) === array_keys((array) ($cieOnEntityStatement['metadata']['federation_entity'] ?? [])), 'federation_entity deve avere la stessa forma con CIE attivo o disattivato.');

// Nessun Trust Anchor configurato: authority_hints omesso.
$noTaEntityStatement = decode_jwt_segment((new WP_SPID_CIE_OIDC_Wrapper(['cie_trust_anchor_prod' => ''] + $baseWrapperConfig))->getEntityStatement(), 1);
assert_true(!array_key_exists('authority_hints', $noTaEntityStatement), 'Senza Trust Anchor CIE configurato la EC non deve esporre authority_hints.');

// spid_trust_anchor eventualmente ancora presente nel DB: ignorato.
$spidTaEntityStatement = decode_jwt_segment((new WP_SPID_CIE_OIDC_Wrapper(['spid_trust_anchor' => 'https://spid-ta.example.it'] + $baseWrapperConfig))->getEntityStatement(), 1);
assert_true(($spidTaEntityStatement['authority_hints'] ?? null) === ['https://oidc.registry.servizicie.interno.gov.it'], 'spid_trust_anchor non deve comparire in authority_hints.');

echo "entity configuration CIE initial claims: OK\n";
echo "entity identifier normalization: OK\n";
echo "resolve response compatibility: OK\n";
echo "cie disabled keeps CIE-shaped entity configuration: OK\n";
echo "authority_hints from CIE trust anchors only: OK\n";
wp_spid_cie_test_ok('cie-federation-entity-configuration');
