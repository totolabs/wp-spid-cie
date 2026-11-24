<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// H3 hardening chiavi: con coppia PRIMARY non utilizzabile (missing/partial/invalid/mismatch) nessun fatal,
// nessuna firma/pubblicazione, endpoint con errore controllato e generico; con coppia sana nulla cambia.
// Gli scenari che terminano con exit (endpoint pubblici, pulsante admin) girano in un sottoprocesso
// (questo stesso file con --child). Solo materiale generato dal test in tests/tmp-key-failclosed.

$CHILD = ($argv[1] ?? '') === '--child';
$base = $CHILD ? (string) $argv[3] : __DIR__ . '/tmp-key-failclosed';
$uploads = $base . '/uploads';
$primaryDir = $uploads . '/wp-spid-cie-keys';
$legacyDir = $uploads . '/spid-cie-oidc-keys';

if ($CHILD) {
    ini_set('display_errors', '0');
    $GLOBALS['fc_status'] = 200;
    register_shutdown_function(static function (): void {
        $err = error_get_last();
        $fatal = $err !== null && in_array($err['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR], true);
        echo "\n@@STATUS=" . $GLOBALS['fc_status'] . "\n@@FATAL=" . ($fatal ? '1' : '0') . "\n";
    });
} else {
    error_reporting(E_ERROR | E_PARSE);
}

// --- Stub WordPress comuni ---
function wp_upload_dir($time = null, $create_dir = true, $refresh_cache = false) { return ['basedir' => $GLOBALS['uploads']]; }
function trailingslashit($p) { return rtrim((string) $p, "/\\") . '/'; }
function untrailingslashit($p) { return rtrim((string) $p, "/\\"); }
function wp_mkdir_p($t) { return is_dir($t) || mkdir($t, 0777, true); }
function plugin_dir_path($f) { return trailingslashit(dirname((string) $f)); }
function plugin_dir_url($f) { return 'https://sp.example.test/wp-content/plugins/wp-spid-cie/'; }
function sanitize_text_field($v) { return trim((string) $v); }
function sanitize_email($v) { return trim((string) $v); }
function sanitize_key($v) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $v)); }
function is_email($v) { return filter_var((string) $v, FILTER_VALIDATE_EMAIL) !== false; }
function esc_url_raw($v) { return (string) $v; }
function esc_attr($v) { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); }
function esc_html($v) { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); }
function wp_unslash($v) { return $v; }
function home_url($path = '/') { $s = ltrim((string) $path, '/'); return $s === '' ? 'https://sp.example.test' : 'https://sp.example.test/' . $s; }
function admin_url($p = '') { return 'https://sp.example.test/wp-admin/' . ltrim((string) $p, '/'); }
function set_url_scheme($url, $scheme = null) { return (string) $url; }
function add_query_arg($args, $url) { return (string) $url . (strpos((string) $url, '?') === false ? '?' : '&') . http_build_query($args); }
function get_bloginfo($show = '') { return 'Ente di Test'; }
function get_transient($key) { return false; }
function set_transient($key, $value, $expiration = 0) { return true; }
function delete_transient($key) { return true; }
function is_wp_error($thing) { return $thing instanceof WP_Error; }
function add_action(...$a) {}
function add_filter(...$a) {}
function add_shortcode(...$a) {}
function __($t, $d = 'default') { return $t; }
function nocache_headers() {}
function status_header($code) { $GLOBALS['fc_status'] = (int) $code; }
function wp_generate_uuid4() { return '00000000-0000-4000-8000-000000000000'; }
$GLOBALS['fc_remote_post_calls'] = 0;
$GLOBALS['fc_remote_get_body'] = '';
function wp_remote_post($url, $args = []) { $GLOBALS['fc_remote_post_calls']++; return new WP_Error('offline', 'offline'); }
function wp_remote_get($url, $args = []) {
    if ($GLOBALS['fc_remote_get_body'] === '') { return new WP_Error('offline', 'Rete disabilitata nei test.'); }
    return ['body' => $GLOBALS['fc_remote_get_body'], 'response' => ['code' => 200], 'headers' => ['content-type' => 'application/jwt']];
}
function wp_remote_retrieve_response_code($r) { return $r['response']['code'] ?? 0; }
function wp_remote_retrieve_body($r) { return $r['body'] ?? ''; }
function wp_remote_retrieve_header($r, $h) { return $r['headers'][strtolower((string) $h)] ?? ''; }
$GLOBALS['fc_options'] = [
    'organization_name' => 'Ente di Test', 'contacts_email' => 'servizi@example.test', 'ipa_code' => 'c_test',
    'issuer_override' => 'https://sp.example.test', 'entity_id' => 'https://sp.example.test',
    'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it', 'cie_enabled' => '1',
    'spid_enabled' => '0', 'spid_saml_entity_id' => 'https://sp.example.test',
];
function get_option($name, $default = false) {
    return in_array($name, ['wp-spid-cie_options'], true) ? $GLOBALS['fc_options'] : $default;
}
class WP_Error {
    private $code;
    private $msg;
    public function __construct($code = '', $msg = '') { $this->code = $code; $this->msg = $msg; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->msg; }
}

function fc_rmdir(string $dir): void {
    if (!is_dir($dir)) { return; }
    foreach (scandir($dir) ?: [] as $e) {
        if ($e === '.' || $e === '..') { continue; }
        $p = $dir . '/' . $e;
        is_dir($p) ? fc_rmdir($p) : @unlink($p);
    }
    @rmdir($dir);
}

// =====================================================================================
// CHILD: scenari che terminano con exit
// =====================================================================================
if ($CHILD) {
    [$_, $__, $scenario] = $argv;
    if ($scenario === 'admin_cap_denied' || $scenario === 'admin_cap_ok') {
        $GLOBALS['fc_cap'] = $scenario === 'admin_cap_ok';
        function wp_verify_nonce($n, $a) { return true; }
        function current_user_can($c) { return $GLOBALS['fc_cap']; }
        function wp_die($m = '') { echo 'WP_DIE'; exit; }
        function wp_redirect($u) { echo 'REDIRECT'; return true; }
        class WP_SPID_CIE_OIDC_Factory {
            public static function get_client() {
                return new class { public function generateKeys() { echo 'GENERATE_CALLED '; return true; } };
            }
        }
        require_once __DIR__ . '/../admin/class-wp-spid-cie-admin.php';
        $admin = new WP_SPID_CIE_OIDC_Admin('wp-spid-cie', 'test');
        $_GET = ['action' => 'generate_oidc_keys', '_wpnonce' => 'n'];
        $admin->handle_key_generation();
        exit;
    }

    function current_user_can($c) { return false; }
    function wp_redirect($u) { return true; }
    require_once __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/../includes/class-wp-spid-cie-factory.php';
    require_once __DIR__ . '/../includes/class-wp-spid-cie-spid-certificates.php';
    require_once __DIR__ . '/../includes/spid-saml-lib/class-wp-spid-cie-saml-service.php';
    require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';
    $GLOBALS['wp_query'] = new class { public function get($k) { return ''; } };
    $paths = [
        'ec' => '/.well-known/openid-federation',
        'jwks' => '/jwks.json',
        'resolve' => '/resolve',
        'saml_metadata' => '/sp-metadata.xml',
    ];
    $_SERVER['REQUEST_URI'] = $paths[$scenario];
    $_SERVER['REQUEST_METHOD'] = 'GET';
    if ($scenario === 'resolve') {
        $_GET = ['sub' => 'https://sp.example.test', 'trust_anchor' => 'https://oidc.registry.servizicie.interno.gov.it'];
    }
    $public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
    $public->serve_federation_endpoints();
    echo '@@NO_EXIT';
    exit;
}

// =====================================================================================
// PARENT
// =====================================================================================
register_shutdown_function(static function () use ($base): void { fc_rmdir($base); });
$GLOBALS['uploads'] = $uploads;

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../includes/Logging/Logger.php';
require_once __DIR__ . '/../includes/Core/PkceService.php';
require_once __DIR__ . '/../includes/Core/StateNonceStore.php';
require_once __DIR__ . '/../includes/Core/TokenValidator.php';
require_once __DIR__ . '/../includes/Core/OidcClient.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-factory.php';
require_once __DIR__ . '/../includes/class-wp-spid-cie-spid-certificates.php';
require_once __DIR__ . '/../includes/spid-saml-lib/class-wp-spid-cie-saml-service.php';

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function fc_pair(): array {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $crt = openssl_csr_sign(openssl_csr_new(['commonName' => 'sp.example.test', 'countryName' => 'IT'], $key, ['digest_alg' => 'sha256']), null, $key, 7, ['digest_alg' => 'sha256']);
    openssl_pkey_export($key, $p);
    openssl_x509_export($crt, $c);
    return ['private' => $p, 'cert' => $c];
}
$pairA = fc_pair();
$pairB = fc_pair();

/** Stati della PRIMARY: healthy | no_private (solo cert) | no_cert (solo private) | mismatch | garbage | empty */
function fc_state(string $state): void {
    global $uploads, $primaryDir, $pairA, $pairB;
    fc_rmdir($uploads);
    wp_mkdir_p($primaryDir);
    $files = [
        'healthy' => [$pairA['private'], $pairA['cert']],
        'no_private' => [null, $pairA['cert']],
        'no_cert' => [$pairA['private'], null],
        'mismatch' => [$pairA['private'], $pairB['cert']],
        'garbage' => ["non una chiave\n", "non un certificato\n"],
        'empty' => [null, null],
    ][$state];
    if ($files[0] !== null) { file_put_contents($primaryDir . '/private.key', $files[0]); }
    if ($files[1] !== null) { file_put_contents($primaryDir . '/public.crt', $files[1]); }
}

function fc_wrapper(): WP_SPID_CIE_OIDC_Wrapper {
    return new WP_SPID_CIE_OIDC_Wrapper([
        'organization_name' => 'Ente di Test', 'contacts_email' => 'servizi@example.test', 'ipa_code' => 'c_test',
        'fiscal_number' => '', 'base_url' => 'https://sp.example.test', 'entity_id' => 'https://sp.example.test',
        'key_dir' => WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(false),
        'cie_trust_anchor_prod' => 'https://oidc.registry.servizicie.interno.gov.it', 'cie_enabled' => true,
    ]);
}

/** Esegue $fn e restituisce la classe dell'eccezione sollevata ('' se nessuna). Un fatal termina il test. */
function fc_throws(callable $fn): string {
    try { $fn(); } catch (\Throwable $e) { return get_class($e); }
    return '';
}

$KEY_EX = 'WP_SPID_CIE_OIDC_Key_Unavailable_Exception';
$leak = ['private.key', 'public.crt', 'tmp-key-failclosed', 'uploads', 'Unable to read key', 'OpenSSL', 'openssl', 'phpseclib', 'BEGIN', 'NoKeyLoaded', 'Exception'];
$noLeak = static function (string $text, string $label) use ($leak): void {
    foreach ($leak as $needle) {
        assert_true(strpos($text, $needle) === false, "$label: il testo non deve contenere '$needle'.");
    }
};
// Nei log interni e' ammessa la classe dell'errore (es. ..._Key_Unavailable_Exception), mai path/PEM/testi crypto.
$noLeakLog = static function (string $text, string $label) use ($leak): void {
    foreach (array_diff($leak, ['Exception']) as $needle) {
        assert_true(strpos($text, $needle) === false, "$label: il log non deve contenere '$needle'.");
    }
};

// ===================== A. Wrapper / signing =====================
fc_state('healthy');
$jwt = fc_wrapper()->signRequestObject(['iss' => 'x']);
assert_true(count(explode('.', $jwt)) === 3, 'A1: con coppia sana signRequestObject() deve restituire un JWT.');
foreach (['no_private' => 'A2', 'no_cert' => 'A3', 'mismatch' => 'A4', 'garbage' => 'A5', 'empty' => 'A5b'] as $state => $id) {
    fc_state($state);
    $cls = fc_throws(static function () { fc_wrapper()->signRequestObject(['iss' => 'x']); });
    assert_true($cls === $KEY_EX, "$id ($state): signRequestObject deve sollevare l'eccezione di dominio, non '$cls'.");
    $cls = fc_throws(static function () { fc_wrapper()->signClientAssertion(['iss' => 'x']); });
    assert_true($cls === $KEY_EX, "$id ($state): signClientAssertion deve sollevare l'eccezione di dominio, non '$cls'.");
    $cls = fc_throws(static function () { fc_wrapper()->getEntityStatement(); });
    assert_true($cls === $KEY_EX, "$id ($state): getEntityStatement deve sollevare l'eccezione di dominio, non '$cls'.");
}
$ex = new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
assert_true($ex instanceof \RuntimeException, "L'eccezione di dominio deve estendere RuntimeException.");
$noLeak($ex->getMessage(), "Messaggio dell'eccezione di dominio");

// ===================== B. JWK =====================
fc_state('healthy');
$jwks = json_decode((string) fc_wrapper()->getJwks(), true);
assert_true(isset($jwks['keys'][0]['kid'], $jwks['keys'][0]['n']), 'B6: con coppia sana getJwks() deve restituire una JWKS.');
foreach (['no_private' => 'B7', 'mismatch' => 'B8'] as $state => $id) {
    fc_state($state);
    $cls = fc_throws(static function () { fc_wrapper()->getJwks(); });
    assert_true($cls === $KEY_EX, "$id ($state): getJwks() non deve pubblicare la chiave, attesa eccezione di dominio, non '$cls'.");
}

// ===================== C. OidcClient =====================
class FC_Logger extends WP_SPID_CIE_OIDC_Logger {
    public $lines = [];
    public function error(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function warn(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function info(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function debug(string $message, array $context = []): void {}
}
class FC_StateStore implements WP_SPID_CIE_OIDC_StateNonceStoreInterface {
    public function store(string $state, array $context, int $ttl): bool { return true; }
    public function consume(string $state): ?array { return null; }
}
$logger = new FC_Logger('TEST');
$oidc = new WP_SPID_CIE_OIDC_OidcClient(new WP_SPID_CIE_OIDC_PkceService(), new FC_StateStore(), new WP_SPID_CIE_OIDC_TokenValidator($logger), $logger);
$providerConfig = [
    'provider' => 'cie', 'client_id' => 'https://sp.example.test', 'redirect_uri' => 'https://sp.example.test/?oidc_action=callback&provider=cie',
    'issuer' => 'https://op.example.test', 'authorization_endpoint' => 'https://op.example.test/authz',
    'token_endpoint' => 'https://op.example.test/token', 'userinfo_endpoint' => 'https://op.example.test/userinfo', 'scope' => 'openid',
];
fc_state('no_private');
$wrapper = fc_wrapper();
$res = $oidc->buildAuthorizationUrl($providerConfig, 'https://sp.example.test/', 'corr-1', static function (array $p) use ($wrapper) { return $wrapper->signRequestObject($p); });
assert_true($res instanceof WP_Error && $res->get_error_code() === 'oidc_signing_key_unavailable', 'C9: Request Object con chiave non disponibile -> WP_Error oidc_signing_key_unavailable.');
$noLeak($res->get_error_message(), 'C9 messaggio utente');

$GLOBALS['fc_remote_post_calls'] = 0;
$exchange = new ReflectionMethod($oidc, 'exchangeCodeForTokens');
$exchange->setAccessible(true);
$res = $exchange->invoke($oidc, 'CODE-SEGRETO', 'VERIFIER-SEGRETO', $providerConfig, 'corr-2', static function (array $p) use ($wrapper) { return $wrapper->signClientAssertion($p); });
assert_true($res instanceof WP_Error && $res->get_error_code() === 'oidc_signing_key_unavailable', 'C10: client_assertion con chiave non disponibile -> WP_Error oidc_signing_key_unavailable.');
assert_true($GLOBALS['fc_remote_post_calls'] === 0, 'C10: con signer fallito il token endpoint NON deve essere contattato.');
foreach ($logger->lines as $line) {
    $noLeakLog($line, 'C log');
    assert_true(strpos($line, 'CODE-SEGRETO') === false && strpos($line, 'VERIFIER-SEGRETO') === false, 'C log: code e verifier non devono essere loggati.');
}

// ===================== D. JWE userinfo =====================
foreach (['no_private', 'mismatch'] as $state) {
    fc_state($state);
    $wrapper = fc_wrapper();
    $logger->lines = [];
    $GLOBALS['fc_remote_get_body'] = 'aaaa.bbbb.cccc.dddd.eeee';
    $fetch = new ReflectionMethod($oidc, 'fetchUserInfo');
    $fetch->setAccessible(true);
    $claims = $fetch->invoke($oidc, 'ACCESS-TOKEN', $providerConfig, 'corr-3', static function (string $jwe) use ($wrapper) { return $wrapper->decryptUserInfoJwe($jwe); });
    assert_true($claims === [], "D11 ($state): JWE con chiave non disponibile -> path controllato, nessun claim, nessun fatal.");
    foreach ($logger->lines as $line) { $noLeakLog($line, "D11 ($state) log"); }
    $cls = fc_throws(static function () use ($wrapper) { $wrapper->decryptUserInfoJwe('aaaa.bbbb.cccc.dddd.eeee'); });
    assert_true($cls === $KEY_EX, "D11 ($state): decryptUserInfoJwe deve sollevare l'eccezione di dominio, non '$cls'.");
}
$GLOBALS['fc_remote_get_body'] = '';

// ===================== E/F/G. Endpoint pubblici (sottoprocesso) =====================
function fc_child(string $scenario): array {
    global $base;
    $proc = proc_open([PHP_BINARY, __FILE__, '--child', $scenario, $base], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, __DIR__);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    preg_match('/@@STATUS=(\d+)/', $out, $m);
    preg_match('/@@FATAL=(\d)/', $out, $f);
    $body = trim((string) preg_replace('/@@STATUS=\d+|@@FATAL=\d|@@NO_EXIT/', '', $out));
    return ['status' => (int) ($m[1] ?? 0), 'fatal' => ($f[1] ?? '1') === '1', 'body' => $body, 'stderr' => $err, 'raw' => $out];
}

$expect503 = static function (string $scenario, string $state, string $id) use ($noLeak, $noLeakLog, $legacyDir): void {
    fc_state($state);
    $r = fc_child($scenario);
    assert_true(!$r['fatal'], "$id ($scenario/$state): nessun fatal.");
    assert_true($r['status'] === 503, "$id ($scenario/$state): atteso HTTP 503, ottenuto {$r['status']}.");
    assert_true($r['body'] === 'Servizio temporaneamente non disponibile.', "$id ($scenario/$state): body generico atteso, ottenuto: {$r['body']}");
    $noLeak($r['body'], "$id body");
    $noLeakLog($r['stderr'], "$id log");
    assert_true(!is_dir($legacyDir) && !file_exists($legacyDir . '/hits.log'), "F16 ($scenario/$state): l'endpoint non deve creare spid-cie-oidc-keys/ ne' hits.log.");
};

foreach (['empty', 'no_cert', 'mismatch', 'garbage'] as $state) { $expect503('ec', $state, 'E12'); }
$expect503('jwks', 'no_private', 'E13');   // solo public.crt: la JWKS NON viene piu' pubblicata
$expect503('jwks', 'mismatch', 'E13b');
foreach (['mismatch', 'no_private'] as $state) { $expect503('resolve', $state, 'E14'); }

// Coppia sana: endpoint OIDC 200 con JWT/JWKS, nessuna creazione legacy.
fc_state('healthy');
foreach (['ec' => 'entity', 'jwks' => 'jwks', 'resolve' => 'resolve'] as $scenario => $kind) {
    $r = fc_child($scenario);
    assert_true(!$r['fatal'] && $r['status'] === 200, "E sana ($scenario): atteso 200 senza fatal, ottenuto {$r['status']}.");
    if ($kind === 'jwks') {
        assert_true(isset(json_decode($r['body'], true)['keys'][0]['kid']), 'E sana: /jwks.json deve pubblicare la JWKS.');
    } else {
        assert_true(count(explode('.', $r['body'])) === 3, "E sana ($scenario): atteso un JWT.");
    }
    assert_true(!is_dir($legacyDir), "F16 sana ($scenario): nessuna spid-cie-oidc-keys/ creata.");
}

// G. Metadata SAML
foreach (['empty', 'no_private', 'mismatch', 'garbage'] as $state) { $expect503('saml_metadata', $state, 'G17'); }
fc_state('healthy');
$r = fc_child('saml_metadata');
assert_true(!$r['fatal'] && $r['status'] === 200, "G18: con coppia sana il metadata SAML deve rispondere 200, ottenuto {$r['status']}.");
assert_true(strpos($r['body'], 'EntityDescriptor') !== false && strpos($r['body'], 'SignatureValue') !== false, 'G18: metadata SAML firmato atteso.');

// ===================== H. SAML AuthnRequest =====================
$saml = new WP_SPID_CIE_OIDC_Saml_Service();
$idp = ['entity_id' => 'https://idp.example.test', 'sso_url' => 'https://idp.example.test/sso', 'x509_cert' => 'MIIB', 'slo_url' => ''];
foreach (['mismatch', 'no_private', 'no_cert', 'garbage'] as $state) {
    fc_state($state);
    $sp = $saml->build_sp_config($GLOBALS['fc_options']);
    $res = null;
    $cls = fc_throws(static function () use ($saml, $sp, $idp, &$res) { $res = $saml->build_authn_request_redirect($sp, $idp, 'https://sp.example.test/'); });
    assert_true($cls === '', "H19 ($state): AuthnRequest non deve sollevare eccezioni/TypeError, ottenuto '$cls'.");
    assert_true($res instanceof WP_Error && $res->get_error_code() === 'saml_sp_key_pair_invalid', "H19 ($state): atteso WP_Error saml_sp_key_pair_invalid.");
}
fc_state('healthy');
$sp = $saml->build_sp_config($GLOBALS['fc_options']);
$res = $saml->build_authn_request_redirect($sp, $idp, 'https://sp.example.test/');
assert_true(is_string($res) && strpos($res, 'Signature=') !== false && strpos($res, 'https://idp.example.test/sso') === 0, 'H20: con coppia sana l\'AuthnRequest firmato resta generato come prima.');

// ===================== I. Capability pulsante rigenerazione =====================
$r = fc_child('admin_cap_denied');
assert_true(strpos($r['raw'], 'WP_DIE') !== false && strpos($r['raw'], 'GENERATE_CALLED') === false, 'I21: senza manage_options la generazione NON deve essere chiamata.');
$r = fc_child('admin_cap_ok');
assert_true(strpos($r['raw'], 'GENERATE_CALLED') !== false, 'I22: con nonce e capability validi il path manuale deve restare raggiungibile.');

fc_rmdir($base);
assert_true(!is_dir($base), 'La directory temporanea del test deve essere rimossa.');

echo "chiavi non disponibili: nessun fatal, 503 generici, nessun leakage, nessuna firma incoerente: OK\n";
wp_spid_cie_test_ok('cie-key-runtime-failclosed');
