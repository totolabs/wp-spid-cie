<?php
declare(strict_types=1);

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
    'cie_trust_anchor_preprod' => 'https://registry.interno.gov.it/',
    'cie_trust_anchor_prod' => 'https://registry.interno.gov.it/',
    'spid_trust_anchor' => 'https://registry.agid.gov.it/',
    'cie_enabled' => true,
    'spid_enabled' => true,
]);

$entityStatementJwt = $wrapper->getEntityStatement();
$entityStatementHeader = decode_jwt_segment($entityStatementJwt, 0);
$entityStatementPayload = decode_jwt_segment($entityStatementJwt, 1);
$entityRpMetadata = (array) ($entityStatementPayload['metadata']['openid_relying_party'] ?? []);

assert_true(($entityStatementHeader['typ'] ?? '') === 'entity-statement+jwt', 'L\'entity configuration deve avere typ=entity-statement+jwt.');
assert_true(!array_key_exists('authority_hints', $entityStatementPayload), 'L\'entity configuration iniziale non deve esporre authority_hints.');
assert_true(isset($entityStatementPayload['jwks']['keys'][0]), 'L\'entity configuration iniziale deve includere jwks.');
assert_true(isset($entityStatementPayload['iss']) && $entityStatementPayload['iss'] === 'https://example.gov.it', 'iss deve essere presente e normalizzato senza trailing slash.');
assert_true(isset($entityStatementPayload['sub']) && $entityStatementPayload['sub'] === 'https://example.gov.it', 'sub deve essere presente e normalizzato senza trailing slash.');
assert_true($entityStatementPayload['iss'] === $entityStatementPayload['sub'], 'iss e sub devono restare coerenti.');
assert_true(($entityRpMetadata['subject_type'] ?? '') === 'pairwise', 'L\'entity configuration iniziale CIE deve esporre subject_type=pairwise.');
assert_true(($entityRpMetadata['subject_type'] ?? '') !== 'public', 'L\'entity configuration iniziale CIE non deve esporre subject_type=public.');
assert_true(!array_key_exists('jwks_uri', $entityRpMetadata), 'L\'entity configuration iniziale non deve esporre jwks_uri.');
assert_true(isset($entityRpMetadata['jwks']['keys'][0]), 'La metadata RP deve continuare a includere jwks.');
assert_true(($entityStatementPayload['trust_marks'][0]['id'] ?? '') === 'https://example.gov.it/trust-mark/test', 'I trust marks CIE validi devono restare presenti.');
assert_true(($entityStatementPayload['trust_marks'][0]['trust_mark'] ?? '') === $trustMark, 'Il trust mark CIE non deve essere alterato.');

$resolveJwt = $wrapper->getResolveResponse('', 'https://registry.interno.gov.it/');
$resolveHeader = decode_jwt_segment($resolveJwt, 0);
$resolvePayload = decode_jwt_segment($resolveJwt, 1);
$resolveRpMetadata = (array) ($resolvePayload['metadata']['openid_relying_party'] ?? []);
$resolveFederationMetadata = (array) ($resolvePayload['metadata']['federation_entity'] ?? []);

assert_true(($resolveHeader['typ'] ?? '') === 'resolve-response+jwt', 'La resolve response deve avere typ=resolve-response+jwt.');
assert_true(($resolvePayload['iss'] ?? '') === 'https://example.gov.it', 'Resolve deve mantenere iss coerente con l\'entity identifier normalizzato.');
assert_true(($resolvePayload['sub'] ?? '') === 'https://example.gov.it', 'Resolve deve mantenere sub coerente con l\'entity identifier normalizzato.');
assert_true(isset($resolvePayload['jwks']['keys'][0]), 'Resolve deve continuare a includere jwks.');
assert_true(($resolveRpMetadata['subject_type'] ?? '') === 'pairwise', 'Resolve deve esporre subject_type=pairwise.');
assert_true(($resolveRpMetadata['subject_type'] ?? '') !== 'public', 'Resolve non deve esporre subject_type=public.');
assert_true(($resolveRpMetadata['jwks_uri'] ?? '') === 'https://example.gov.it/jwks.json', 'Resolve non deve perdere jwks_uri.');
assert_true(($resolveFederationMetadata['federation_resolve_endpoint'] ?? '') === 'https://example.gov.it/resolve', 'Resolve deve continuare a pubblicare l\'endpoint /resolve corretto.');
assert_true(($resolvePayload['trust_anchor'] ?? '') === 'https://registry.interno.gov.it', 'trust_anchor deve essere normalizzato senza trailing slash.');

$spidOnlyWrapper = new WP_SPID_CIE_OIDC_Wrapper([
    'organization_name' => 'Comune di Test',
    'contacts_email' => 'servizi@example.gov.it',
    'ipa_code' => 'cpdtsrs',
    'fiscal_number' => '',
    'base_url' => 'https://example.gov.it',
    'entity_id' => 'https://example.gov.it',
    'key_dir' => $keyDir,
    'cie_trust_mark_preprod' => '',
    'cie_trust_mark_prod' => '',
    'cie_trust_anchor_preprod' => 'https://registry.interno.gov.it/',
    'cie_trust_anchor_prod' => 'https://registry.interno.gov.it/',
    'spid_trust_anchor' => 'https://registry.agid.gov.it/',
    'cie_enabled' => false,
    'spid_enabled' => true,
]);

$spidOnlyEntityStatement = decode_jwt_segment($spidOnlyWrapper->getEntityStatement(), 1);
$spidOnlyRpMetadata = (array) ($spidOnlyEntityStatement['metadata']['openid_relying_party'] ?? []);

assert_true(($spidOnlyRpMetadata['jwks_uri'] ?? '') === 'https://example.gov.it/jwks.json', 'La entity configuration senza CIE deve continuare a esporre jwks_uri.');
assert_true(($spidOnlyEntityStatement['authority_hints'][0] ?? '') === 'https://registry.agid.gov.it', 'La entity configuration SPID-only deve continuare a esporre authority_hints.');

echo "entity configuration CIE initial claims: OK\n";
echo "entity identifier normalization: OK\n";
echo "resolve response compatibility: OK\n";
echo "spid-only federation compatibility: OK\n";
