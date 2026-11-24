<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// H2 hardening chiavi:
// - la sola identita' runtime e' la PRIMARY uploads/wp-spid-cie-keys (nessun fallback, nemmeno con primary vuota);
// - una lettura dello stato chiavi non crea directory/file;
// - Factory, SAML service e helper SAML pubblico convergono sullo stesso resolver;
// - inspect_key_pair() classifica la coppia senza mai sollevare eccezioni;
// - generate(..., false) e' fail-closed (partial/invalid/mismatch/non conforme -> errore, nessuna sovrascrittura);
// - con PRIMARY sana kid/JWK/x5c/EC//resolve restano coerenti con la chiave.
// Solo materiale generato dal test in tests/tmp-key-integrity, rimosso a fine processo.

error_reporting(E_ERROR | E_PARSE);

$tmpRoot = __DIR__ . '/tmp-key-integrity';
$uploads = $tmpRoot . '/uploads';
$primaryDir = $uploads . '/wp-spid-cie-keys';
$fallbackDir = $uploads . '/spid-cie-oidc-keys';

function ki_rmdir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        is_dir($path) ? ki_rmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}
register_shutdown_function(static function () use ($tmpRoot): void { ki_rmdir($tmpRoot); });

// --- Stub WordPress ---
$GLOBALS['ki_upload_create_flags'] = [];
function wp_upload_dir($time = null, $create_dir = true, $refresh_cache = false) {
    $GLOBALS['ki_upload_create_flags'][] = (bool) $create_dir;
    return ['basedir' => __DIR__ . '/tmp-key-integrity/uploads'];
}
function trailingslashit($p) { return rtrim((string) $p, "/\\") . '/'; }
function untrailingslashit($p) { return rtrim((string) $p, "/\\"); }
function wp_mkdir_p($t) { return is_dir($t) || mkdir($t, 0777, true); }
function plugin_dir_path($f) { return trailingslashit(dirname((string) $f)); }
function plugin_dir_url($f) { return 'https://example.test/wp-content/plugins/wp-spid-cie/'; }
function sanitize_text_field($v) { return trim((string) $v); }
function esc_url_raw($v) { return (string) $v; }
function home_url($path = '/') { $s = ltrim((string) $path, '/'); return $s === '' ? 'https://sp.example.test' : 'https://sp.example.test/' . $s; }
function set_url_scheme($url, $scheme = null) { return (string) $url; }
function add_query_arg($args, $url) { return (string) $url . (strpos((string) $url, '?') === false ? '?' : '&') . http_build_query($args); }
function get_option($name, $default = false) { return $default; }
function get_bloginfo($show = '') { return 'Ente di Test'; }
function get_transient($key) { return false; }
function set_transient($key, $value, $expiration = 0) { return true; }
function wp_remote_get($url, $args = []) { return new WP_Error('offline', 'Rete disabilitata nei test.'); }
function is_wp_error($thing) { return $thing instanceof WP_Error; }
function add_action(...$a) {}
function add_filter(...$a) {}
function add_shortcode(...$a) {}
function __($t, $d = 'default') { return $t; }
class WP_Error {
    private $code;
    private $msg;
    public function __construct($code = '', $msg = '') { $this->code = $code; $this->msg = $msg; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->msg; }
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-factory.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-spid-certificates.php';
require_once __DIR__ . '/../includes/spid-saml-lib/class-wp-spid-cie-saml-service.php';
require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function b64url(string $d): string { return rtrim(strtr(base64_encode($d), '+/', '-_'), '='); }

function jwt_payload(string $jwt, int $i = 1): array {
    $parts = explode('.', $jwt);
    $seg = strtr($parts[$i] ?? '', '-_', '+/');
    $seg .= str_repeat('=', (4 - strlen($seg) % 4) % 4);
    return (array) json_decode((string) base64_decode($seg, true), true);
}

/** Coppia RSA + certificato self-signed semplice (NON conforme SPID), in memoria. */
function ki_simple_pair(): array {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $csr = openssl_csr_new(['commonName' => 'sp.example.test', 'countryName' => 'IT'], $key, ['digest_alg' => 'sha256']);
    $crt = openssl_csr_sign($csr, null, $key, 7, ['digest_alg' => 'sha256']);
    openssl_pkey_export($key, $privatePem);
    openssl_x509_export($crt, $certPem);
    return ['private' => $privatePem, 'cert' => $certPem];
}

function ki_reset(string $uploads): void {
    ki_rmdir($uploads);
}

function ki_write_pair(string $dir, ?string $private, ?string $cert): void {
    wp_mkdir_p($dir);
    if ($private !== null) { file_put_contents($dir . '/private.key', $private); }
    if ($cert !== null) { file_put_contents($dir . '/public.crt', $cert); }
}

function ki_hash_tree(string $dir): string {
    if (!is_dir($dir)) {
        return 'absent';
    }
    $out = [];
    foreach (scandir($dir) ?: [] as $e) {
        if ($e === '.' || $e === '..') { continue; }
        $out[] = $e . ':' . (is_file("$dir/$e") ? hash_file('sha256', "$dir/$e") : 'dir');
    }
    return implode('|', $out);
}

$pairA = ki_simple_pair();
$pairB = ki_simple_pair();

$saml = new WP_SPID_CIE_OIDC_Saml_Service();
$samlResolve = new ReflectionMethod($saml, 'resolve_active_key_dir');
$samlResolve->setAccessible(true);
$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
$publicResolve = new ReflectionMethod($public, 'resolve_spid_saml_active_key_dir');
$publicResolve->setAccessible(true);
$publicPrivatePath = new ReflectionMethod($public, 'get_saml_private_key_path');
$publicPrivatePath->setAccessible(true);
$norm = static function (string $p): string { return str_replace('\\', '/', untrailingslashit($p)); };
$P = $norm($primaryDir);

$assertAllPrimary = static function (string $label) use ($saml, $samlResolve, $public, $publicResolve, $norm, $P): void {
    assert_true($norm(WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(false)) === $P, "$label: Factory resolve(false) deve essere PRIMARY.");
    assert_true($norm((string) $samlResolve->invoke($saml)) === $P, "$label: SAML service deve risolvere PRIMARY.");
    assert_true($norm((string) $publicResolve->invoke($public)) === $P, "$label: helper SAML pubblico deve risolvere PRIMARY.");
    $sp = $saml->build_sp_config([]);
    assert_true($norm(dirname((string) $sp['private_key_path'])) === $P && $norm(dirname((string) $sp['cert_path'])) === $P, "$label: build_sp_config deve puntare alla PRIMARY.");
};

// ===================== Resolver =====================
// A. primary completa + fallback completa diversa -> PRIMARY.
ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], $pairA['cert']);
ki_write_pair($fallbackDir, $pairB['private'], $pairB['cert']);
$assertAllPrimary('A');

// B. primary inesistente + fallback completa -> PRIMARY; la lettura NON crea la primary.
ki_reset($uploads);
ki_write_pair($fallbackDir, $pairB['private'], $pairB['cert']);
$GLOBALS['ki_upload_create_flags'] = [];
$assertAllPrimary('B');
assert_true(!is_dir($primaryDir), 'B: una lettura non deve creare la directory primary.');
assert_true(!file_exists($primaryDir . '/.htaccess'), 'B: una lettura non deve creare .htaccess.');
assert_true(!in_array(true, $GLOBALS['ki_upload_create_flags'], true), 'B: le letture devono chiamare wp_upload_dir senza creazione directory.');
assert_true((string) $publicPrivatePath->invoke($public) === '', 'B: con primary assente il path della private SAML pubblica deve essere vuoto, non il fallback.');

// C. primary parziale + fallback completa -> PRIMARY.
ki_reset($uploads);
ki_write_pair($primaryDir, null, $pairA['cert']);
ki_write_pair($fallbackDir, $pairB['private'], $pairB['cert']);
$assertAllPrimary('C');
assert_true((string) $publicPrivatePath->invoke($public) === '', 'C: con primary parziale il path della private SAML pubblica deve essere vuoto, non il fallback.');

// D. resolve(true) -> PRIMARY, la crea con .htaccess, non tocca il fallback.
ki_reset($uploads);
ki_write_pair($fallbackDir, $pairB['private'], $pairB['cert']);
$fallbackBefore = ki_hash_tree($fallbackDir);
$generationDir = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(true);
assert_true($norm($generationDir) === $P, 'D: resolve(true) deve restituire la PRIMARY.');
assert_true(is_dir($primaryDir) && file_exists($primaryDir . '/.htaccess'), 'D: resolve(true) deve creare la PRIMARY e il suo .htaccess.');
assert_true(!file_exists($primaryDir . '/private.key') && !file_exists($primaryDir . '/public.crt'), 'D: resolve(true) non deve copiare chiavi nella PRIMARY.');
assert_true(ki_hash_tree($fallbackDir) === $fallbackBefore, 'D: il fallback deve restare intatto.');

// ===================== Integrita' =====================
$inspect = static function () use ($primaryDir): array {
    return WP_SPID_CIE_OIDC_Spid_Certificates::inspect_key_pair($primaryDir . '/private.key', $primaryDir . '/public.crt');
};

ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], $pairA['cert']);
$r = $inspect();
assert_true($r['state'] === 'valid' && $r['coherent'] === true, 'E: coppia coerente deve essere valid.');

ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], $pairB['cert']);
$r = $inspect();
assert_true($r['state'] === 'mismatch' && $r['coherent'] === false, 'F: private A + cert B deve essere mismatch.');

ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], null);
assert_true($inspect()['state'] === 'partial', 'G: solo private deve essere partial.');

ki_reset($uploads);
ki_write_pair($primaryDir, null, $pairA['cert']);
assert_true($inspect()['state'] === 'partial', 'H: solo cert deve essere partial.');

ki_reset($uploads);
wp_mkdir_p($primaryDir);
assert_true($inspect()['state'] === 'missing', 'I: entrambi assenti deve essere missing.');

ki_reset($uploads);
ki_write_pair($primaryDir, "non una chiave\n", "non un certificato\n");
$r = $inspect();
assert_true($r['state'] === 'invalid' && $r['coherent'] === null, 'J: contenuto spazzatura deve essere invalid, senza eccezioni.');
foreach ([$r] as $res) {
    foreach ($res['errors'] as $msg) {
        assert_true(strpos($msg, 'BEGIN') === false && strpos($msg, 'tmp-key-integrity') === false, 'I messaggi di inspect non devono contenere PEM o path.');
    }
}
ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
assert_true($inspect()['state'] === 'invalid', 'J: certificato PEM malformato deve essere invalid.');

// ===================== generate(false) =====================
$spidOptions = [
    'organization_name' => 'Ente di Test',
    'spid_saml_locality_name' => 'Roma',
    'spid_saml_entity_id' => 'https://sp.example.test',
    'ipa_code' => 'c_test',
    'spid_saml_common_name' => 'Ente di Test',
];
$fileHash = static function (string $f): string { return file_exists($f) ? hash_file('sha256', $f) : 'absent'; };

// K. coppia parziale -> errore, superstite byte-identico, mancante non creato.
ki_reset($uploads);
ki_write_pair($primaryDir, null, $pairA['cert']);
$before = $fileHash($primaryDir . '/public.crt');
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, false);
assert_true($res['success'] === false, 'K: generate(false) su coppia parziale deve fallire.');
assert_true($fileHash($primaryDir . '/public.crt') === $before, 'K: il file superstite deve restare byte-identico.');
assert_true(!file_exists($primaryDir . '/private.key'), 'K: il file mancante non deve essere creato.');

// L. mismatch -> errore, entrambi byte-identici.
ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], $pairB['cert']);
$beforeP = $fileHash($primaryDir . '/private.key');
$beforeC = $fileHash($primaryDir . '/public.crt');
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, false);
assert_true($res['success'] === false, 'L: generate(false) su mismatch deve fallire.');
assert_true($fileHash($primaryDir . '/private.key') === $beforeP && $fileHash($primaryDir . '/public.crt') === $beforeC, 'L: entrambi i file devono restare byte-identici.');

// M. coppia coerente ma certificato non conforme SPID -> errore, nessuna rigenerazione.
ki_reset($uploads);
ki_write_pair($primaryDir, $pairA['private'], $pairA['cert']);
$beforeP = $fileHash($primaryDir . '/private.key');
$beforeC = $fileHash($primaryDir . '/public.crt');
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, false);
assert_true($res['success'] === false, 'M: generate(false) su certificato non conforme deve fallire.');
assert_true($fileHash($primaryDir . '/private.key') === $beforeP && $fileHash($primaryDir . '/public.crt') === $beforeC, 'M: nessuna rigenerazione: file byte-identici.');

// N. directory vergine -> generate(false) crea una coppia valida.
ki_reset($uploads);
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, false);
assert_true($res['success'] === true, 'N: generate(false) su directory vergine deve riuscire: ' . implode(' ', $res['errors'] ?? []));
assert_true($inspect()['state'] === 'valid', 'N: la coppia generata deve essere valid.');
$validation = WP_SPID_CIE_OIDC_Spid_Certificates::validate($primaryDir . '/private.key', $primaryDir . '/public.crt', $spidOptions);
assert_true($validation['valid'] === true, 'N: la coppia generata deve passare validate().');
$firstGenerated = $fileHash($primaryDir . '/public.crt');

// Idempotenza: generate(false) su coppia valida e conforme -> success senza riscrivere.
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, false);
assert_true($res['success'] === true && $fileHash($primaryDir . '/public.crt') === $firstGenerated, 'N: generate(false) su coppia valida non deve rigenerare.');

// ===================== Invarianti metadata con PRIMARY sana =====================
$certPem = (string) file_get_contents($primaryDir . '/public.crt');
$pub = openssl_pkey_get_details(openssl_pkey_get_public($certPem));
$certModulus = ltrim($pub['rsa']['n'], "\0");
$certExponent = ltrim($pub['rsa']['e'], "\0");
// n/e del JWK si confrontano come BYTE: la codifica pubblicata da phpseclib include padding base64.
// E' il comportamento esistente (registrato presso CIE) e H2 non lo altera.
$jwkBytes = static function (string $v): string { return ltrim((string) base64_decode(strtr($v, '-_', '+/')), "\0"); };
$thumbprint = static function (array $jwk): string {
    $t = ['e' => $jwk['e'] ?? '', 'kty' => 'RSA', 'n' => $jwk['n'] ?? ''];
    ksort($t);
    return b64url(hash('sha256', (string) json_encode($t, JSON_UNESCAPED_SLASHES), true));
};
$expectedX5c = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certPem);

$wrapper = new WP_SPID_CIE_OIDC_Wrapper([
    'organization_name' => 'Ente di Test',
    'contacts_email' => 'servizi@example.test',
    'ipa_code' => 'c_test',
    'fiscal_number' => '',
    'base_url' => 'https://sp.example.test',
    'entity_id' => 'https://sp.example.test',
    'key_dir' => WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(false),
    'cie_trust_mark_preprod' => '',
    'cie_trust_mark_prod' => '',
    'cie_trust_anchor_preprod' => '',
    'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it',
    'cie_enabled' => true,
    'spid_enabled' => true,
]);
$ecJwt = $wrapper->getEntityStatement();
$ecHeader = jwt_payload($ecJwt, 0);
$ec = jwt_payload($ecJwt, 1);
$jwk = $ec['jwks']['keys'][0] ?? [];
$expectedKid = $thumbprint($jwk);
assert_true($jwkBytes((string) ($jwk['n'] ?? '')) === $certModulus && $jwkBytes((string) ($jwk['e'] ?? '')) === $certExponent, 'Metadata: n/e del JWK EC = modulus/esponente del certificato PRIMARY.');
assert_true(($jwk['kid'] ?? '') === $expectedKid, 'Metadata: kid del JWK EC = thumbprint {e,kty,n} del JWK pubblicato.');
assert_true(($ecHeader['kid'] ?? '') === $expectedKid, 'Metadata: kid dell\'header EC = kid del JWK pubblicato.');
assert_true(($jwk['x5c'][0] ?? '') === $expectedX5c, 'Metadata: x5c EC = certificato della PRIMARY.');
$rpJwk = $ec['metadata']['openid_relying_party']['jwks']['keys'][0] ?? [];
assert_true(($rpJwk['kid'] ?? '') === $expectedKid, 'Metadata: JWK del RP coerente con la chiave.');
$resolve = jwt_payload($wrapper->getResolveResponse('', 'https://oidc.registry.servizicie.interno.gov.it'), 1);
assert_true(($resolve['jwks']['keys'][0]['kid'] ?? '') === $expectedKid, '/resolve: kid coerente con la chiave.');
$jwks = json_decode((string) $wrapper->getJwks(), true);
assert_true(($jwks['keys'][0]['kid'] ?? '') === $expectedKid, '/jwks.json: kid coerente con la chiave.');
// Una seconda lettura con fallback completo presente non cambia la chiave pubblicata.
ki_write_pair($fallbackDir, $pairB['private'], $pairB['cert']);
$again = new WP_SPID_CIE_OIDC_Wrapper(['key_dir' => WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(false)] + ['organization_name' => 'Ente di Test', 'contacts_email' => 'servizi@example.test', 'base_url' => 'https://sp.example.test', 'entity_id' => 'https://sp.example.test', 'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it', 'cie_enabled' => true]);
assert_true((jwt_payload($again->getEntityStatement(), 0)['kid'] ?? '') === $expectedKid, 'Metadata: con un fallback completo presente il kid pubblicato non cambia.');

// ===================== O. force=true: rotazione esplicita =====================
$res = WP_SPID_CIE_OIDC_Spid_Certificates::generate($spidOptions, true);
assert_true($res['success'] === true, 'O: generate(true) deve riuscire.');
assert_true($fileHash($primaryDir . '/public.crt') !== $firstGenerated, 'O: la rotazione esplicita deve sostituire la coppia.');
assert_true($inspect()['state'] === 'valid', 'O: la coppia ruotata deve essere valid.');

ki_rmdir($tmpRoot);
assert_true(!is_dir($tmpRoot), 'La directory temporanea del test deve essere rimossa.');

echo "chiavi: PRIMARY-only, integrita' coppia, generate fail-closed, metadata coerenti: OK\n";
wp_spid_cie_test_ok('cie-key-resolution-integrity');
