<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// H-UI-3: verifica crittografica e semantica del JWS interno della UserInfo CIE OIDC.
// Regole tecniche SPID/CIE OIDC e OpenID Connect Core 1.0 par. 5.3.2: la UserInfo e' un Nested JWT
// (JWS firmato dall'OP, cifrato in JWE verso il RP). Il RP DEVE verificarne la firma con la chiave
// dell'OP e i claim iss/aud/iat/exp; altrimenti i valori della UserInfo NON vanno usati.
//
// Livelli, da non confondere:
// - JWS REALMENTE firmato: coppie RSA sintetiche generate a runtime (phpseclib RSA::createKey), mai
//   committate; la verifica e' quella EREDITATA reale da WP_SPID_CIE_OIDC_TokenValidator (phpseclib).
// - JWE SIMULATO: busta compact a 5 parti aperta da un decrypter STUB. Esercita il percorso
//   applicativo di fetchUserInfo, NON la crittografia RSA-OAEP/AES (coperta da D11 come regressione).
// - Nessuna prova di compatibilita' con le risposte reali dell'OP CIE: serve la ricognizione live.
// Solo fixture sintetiche: nessuna rete, nessuna chiave reale o storica, nessun provider reale.
// I test passano da handleCallback/fetchUserInfo e NON chiamano direttamente il validatore: sul codice
// che non verifica la firma il rosso e' "payload non verificato accettato", non un fatal.

error_reporting(E_ALL);

// --- Stub WordPress minimi ---
function sanitize_key($v) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $v)); }
function sanitize_text_field($v) { return trim((string) $v); }
function wp_unslash($v) { return $v; }
function __($t, $d = 'default') { return $t; }
function wp_generate_uuid4() { return '00000000-0000-4000-8000-000000000000'; }
function wp_json_encode($v, $f = 0, $d = 512) { return json_encode($v, $f, $d); }
function is_wp_error($thing) { return $thing instanceof WP_Error; }
class WP_Error {
    private $code;
    private $msg;
    public function __construct($code = '', $msg = '', $data = '') { $this->code = $code; $this->msg = $msg; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->msg; }
}

const US_ACCESS_TOKEN = 'AT-SEGRETO-us-0001';
const US_ID_TOKEN = 'IDT-SEGRETO.us.0001';
const US_ISSUER = 'https://op.example.test';
const US_CLIENT_ID = 'https://sp.example.test';
const US_USERINFO_URL = 'https://op.example.test/userinfo';
const US_JWKS_URL = 'https://op.example.test/jwks';
const US_KID = 'us-kid-op-SEGRETO-4c1d9e7b';

$GLOBALS['us_access_token'] = US_ACCESS_TOKEN;
$GLOBALS['us_userinfo'] = ['body' => '', 'status' => 200, 'headers' => [], 'net_error' => false];
$GLOBALS['us_jwks'] = ['body' => '', 'status' => 200, 'net_error' => false];
$GLOBALS['us_userinfo_calls'] = 0;
$GLOBALS['us_get_urls'] = [];
function wp_remote_post($url, $args = []) {
    return ['response' => ['code' => 200], 'body' => json_encode(['access_token' => $GLOBALS['us_access_token'], 'id_token' => US_ID_TOKEN, 'token_type' => 'Bearer'])];
}
// Lo stub risponde per URL: UserInfo e jwks_uri sono distinti; qualunque altro URL e' registrato e fallisce.
function wp_remote_get($url, $args = []) {
    $url = (string) $url;
    $GLOBALS['us_get_urls'][] = $url;
    if ($url === US_USERINFO_URL) {
        $GLOBALS['us_userinfo_calls']++;
        $u = $GLOBALS['us_userinfo'];
        if ($u['net_error']) { return new WP_Error('offline', 'Rete disabilitata nei test.'); }
        return ['response' => ['code' => $u['status']], 'headers' => $u['headers'], 'body' => $u['body']];
    }
    if ($url === US_JWKS_URL) {
        $j = $GLOBALS['us_jwks'];
        if ($j['net_error']) { return new WP_Error('offline', 'Rete disabilitata nei test.'); }
        return ['response' => ['code' => $j['status']], 'headers' => [], 'body' => $j['body']];
    }
    return new WP_Error('unexpected_url', 'URL non previsto nei test.');
}
function wp_remote_retrieve_response_code($r) { return $r['response']['code'] ?? 0; }
function wp_remote_retrieve_body($r) { return $r['body'] ?? ''; }
function wp_remote_retrieve_header($r, $h) { return $r['headers'][strtolower((string) $h)] ?? ''; }

// Il vendor emette deprecation di terze parti su PHP recenti al caricamento: silenziate SOLO durante l'include.
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
require_once __DIR__ . '/../vendor/autoload.php';
error_reporting(E_ALL);
require_once __DIR__ . '/../includes/Logging/Logger.php';
require_once __DIR__ . '/../includes/Core/PkceService.php';
require_once __DIR__ . '/../includes/Core/StateNonceStore.php';
require_once __DIR__ . '/../includes/Core/TokenValidator.php';
require_once __DIR__ . '/../includes/Core/OidcClient.php';

use phpseclib3\Crypt\RSA;

class US_Logger extends WP_SPID_CIE_OIDC_Logger {
    public $lines = [];
    public function error(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function warn(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function info(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function debug(string $message, array $context = []): void {}
}
class US_StateStore implements WP_SPID_CIE_OIDC_StateNonceStoreInterface {
    public function store(string $state, array $context, int $ttl): bool { return true; }
    public function consume(string $state): ?array {
        return ['nonce' => 'NONCE-us', 'code_verifier' => 'VERIFIER-us', 'provider' => 'cie', 'target_url' => 'https://sp.example.test/'];
    }
}
// Solo l'ID Token e' fissato (gia' validato altrove). La verifica della UserInfo e' quella EREDITATA reale.
// L'orologio e' fissato per rendere deterministici i casi al bordo dello skew: e' tempo, non crittografia.
class US_TokenValidator extends WP_SPID_CIE_OIDC_TokenValidator {
    public $payload = [];
    public $now = 0;
    public function validateIdToken(string $idToken, array $providerConfig, string $expectedNonce, string $correlationId) {
        return $this->payload;
    }
    protected function currentTime(): int { return $this->now; }
}

// --- Raccolta esiti: tutti i casi vengono eseguiti, poi esito unico ---
$US_TOTAL = 0;
$US_FAILED = [];
function us_check(bool $condition, string $message): void {
    global $US_TOTAL, $US_FAILED;
    $US_TOTAL++;
    if (!$condition) { $US_FAILED[] = $message; }
}

function us_b64u(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function us_b64u_dec(string $s): string {
    $s = strtr($s, '-_', '+/');
    return (string) base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4));
}
function us_json($v): string { return (string) json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); }

// JWK pubblica costruita dai componenti Raw (n/e senza padding, indipendente da ext-sodium).
function us_jwk($priv, string $kid = US_KID, array $override = []): array {
    $raw = $priv->getPublicKey()->toString('Raw');
    $jwk = ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => us_b64u($raw['n']->toBytes()), 'e' => us_b64u($raw['e']->toBytes())];
    foreach ($override as $k => $v) {
        if ($v === null) { unset($jwk[$k]); } else { $jwk[$k] = $v; }
    }
    return $jwk;
}
function us_jwks(array $keys): string { return us_json(['keys' => $keys]); }
function us_sign(string $mode, $priv, string $input): string {
    if ($mode === 'PS256') {
        return $priv->withPadding(RSA::SIGNATURE_PSS)->withHash('sha256')->withMGFHash('sha256')->sign($input);
    }
    return $priv->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')->sign($input);
}
// JWS compact firmato davvero; $mode sceglie lo schema di firma, indipendente dall'alg dichiarato nell'header.
function us_jws(array $header, $payload, $priv, string $mode = 'RS256'): string {
    $input = us_b64u(us_json($header)) . '.' . us_b64u(is_string($payload) ? $payload : us_json($payload));
    return $input . '.' . us_b64u(us_sign($mode, $priv, $input));
}
function us_jwe(string $inner): string {
    return us_b64u('{"alg":"RSA-OAEP","enc":"A256CBC-HS512","cty":"JWT"}') . '.' . us_b64u('cek') . '.' . us_b64u('iv') . '.' . us_b64u($inner) . '.' . us_b64u('tag');
}
// Decrypter STUB: restituisce la parte "ciphertext" in chiaro. Nessuna crittografia.
$US_DECRYPTER = static function (string $jwe): string {
    $p = explode('.', $jwe);
    if (count($p) !== 5 || $p[3] === 'FAIL') { throw new RuntimeException('stub-decrypt-failure'); }
    return us_b64u_dec($p[3]);
};

// --- Chiavi sintetiche generate a runtime ---
$OP = RSA::createKey(2048);
$ALIEN = RSA::createKey(2048);
$WEAK = RSA::createKey(1024);
$OP_JWK = us_jwk($OP);
$DEFAULT_JWKS = us_jwks([$OP_JWK]);

$NOW = time();
$SUB = 'us-pairwise-5b7e2a91-6c4d-4f0e-9a3b-1d2c3e4f5a6b';
$OTHER_SUB = 'us-pairwise-ALTRO-9999-8888-7777-666655554444';
$SELF = [
    'given_name' => 'Ugo', 'family_name' => 'Binder',
    'https://attributes.eid.gov.it/fiscal_number' => 'TINIT-BNDUGO80A01H501Z',
    'phone_number' => '+390000000001',
];
$H = ['alg' => 'RS256', 'kid' => US_KID];
$C = ['iss' => US_ISSUER, 'sub' => $SUB, 'aud' => US_CLIENT_ID, 'iat' => $NOW, 'exp' => $NOW + 300] + $SELF;
// Variante di header/claim: null rimuove la chiave.
function us_with(array $base, array $changes): array {
    foreach ($changes as $k => $v) {
        if ($v === null) { unset($base[$k]); } else { $base[$k] = $v; }
    }
    return $base;
}
$FORBIDDEN_IN_LOG = [
    $SUB, $OTHER_SUB, US_ACCESS_TOKEN, US_ID_TOKEN, US_KID, substr($OP_JWK['n'], 0, 24),
    'BNDUGO80A01H501Z', 'Ugo', 'Binder', '+390000000001', 'eyJ',
];

$logger = new US_Logger('TEST');
$validator = new US_TokenValidator($logger);
$validator->now = $NOW;
$oidc = new WP_SPID_CIE_OIDC_OidcClient(new WP_SPID_CIE_OIDC_PkceService(), new US_StateStore(), $validator, $logger);
$PROVIDER = [
    'provider' => 'cie', 'client_id' => US_CLIENT_ID,
    'redirect_uri' => 'https://sp.example.test/?oidc_action=callback&provider=cie',
    'issuer' => US_ISSUER, 'token_endpoint' => 'https://op.example.test/token',
    'userinfo_endpoint' => US_USERINFO_URL, 'jwks_uri' => US_JWKS_URL,
];
$REQUEST = ['state' => 'STATE-us', 'code' => 'CODE-SEGRETO-us', 'correlation_id' => 'corr-us'];
$ID_PAYLOAD = ['iss' => US_ISSUER, 'sub' => $SUB, 'aud' => US_CLIENT_ID, 'nonce' => 'NONCE-us', 'acr' => 'https://www.spid.gov.it/SpidL2'];

// opzioni: jwks (body), jwks_status, jwks_net, ui_status, ui_headers, ui_net, access_token, provider, decrypter
$run = static function (string $body, array $o = []) use ($oidc, $validator, $logger, $PROVIDER, $REQUEST, $ID_PAYLOAD, $US_DECRYPTER, $DEFAULT_JWKS) {
    $validator->payload = $ID_PAYLOAD;
    $logger->lines = [];
    $GLOBALS['us_userinfo'] = ['body' => $body, 'status' => $o['ui_status'] ?? 200, 'headers' => $o['ui_headers'] ?? [], 'net_error' => $o['ui_net'] ?? false];
    $GLOBALS['us_jwks'] = ['body' => $o['jwks'] ?? $DEFAULT_JWKS, 'status' => $o['jwks_status'] ?? 200, 'net_error' => $o['jwks_net'] ?? false];
    $GLOBALS['us_access_token'] = $o['access_token'] ?? US_ACCESS_TOKEN;
    $GLOBALS['us_userinfo_calls'] = 0;
    $GLOBALS['us_get_urls'] = [];
    $decrypter = array_key_exists('decrypter', $o) ? $o['decrypter'] : $US_DECRYPTER;
    return $oidc->handleCallback($REQUEST, $o['provider'] ?? $PROVIDER, null, $decrypter);
};
$isCode = static function ($res, string $code): bool { return $res instanceof WP_Error && $res->get_error_code() === $code; };
$lastReason = static function () use ($logger): ?string {
    foreach (array_reverse($logger->lines) as $line) {
        if (preg_match('/"reason":"([a-z_]+)"/', $line, $m)) { return $m[1]; }
    }
    return null;
};
$noLeak = static function (string $label) use ($logger, $FORBIDDEN_IN_LOG): void {
    foreach ($logger->lines as $line) {
        foreach ($FORBIDDEN_IN_LOG as $needle) {
            us_check(strpos($line, $needle) === false, "$label: il log non deve contenere token, JWS, sub, kid, chiavi o dati personali (trovato un valore vietato).");
        }
    }
};
$accepted = static function ($res, string $label) use ($SUB): void {
    us_check(is_array($res) && ($res['claims']['sub'] ?? null) === $SUB, "$label: UserInfo valida deve essere accettata con sub dell'ID Token.");
    us_check(is_array($res) && ($res['claims']['given_name'] ?? null) === 'Ugo' && ($res['claims']['family_name'] ?? null) === 'Binder'
        && ($res['claims']['https://attributes.eid.gov.it/fiscal_number'] ?? null) === 'TINIT-BNDUGO80A01H501Z',
        "$label: i claim UserInfo verificati devono essere restituiti invariati.");
};
$expect = static function (string $id, $res, string $code, string $reason) use ($isCode, $lastReason, $noLeak): void {
    us_check($isCode($res, $code), "$id: atteso WP_Error $code (motivo $reason).");
    us_check(!is_array($res), "$id: nessun claim UserInfo deve uscire da handleCallback.");
    us_check($lastReason() === $reason, "$id: atteso motivo di log '$reason', ottenuto '" . (string) $lastReason() . "'.");
    $noLeak($id);
};

// ===================== P. Positivi =====================
$res = $run(us_jwe(us_jws($H, $C, $OP)));
$accepted($res, 'P1');
us_check($logger->lines === [], 'P1: nessun log sul percorso di successo.');
us_check($GLOBALS['us_get_urls'] === [US_USERINFO_URL, US_JWKS_URL], 'P1: solo GET UserInfo e jwks_uri configurato.');
$noLeak('P1');

$res = $run(us_jwe(us_jws($H, us_with($C, ['exp' => $NOW - 59, 'iat' => $NOW + 59, 'nbf' => $NOW + 59]), $OP)));
$accepted($res, 'P2');
us_check($logger->lines === [], 'P2: exp/iat/nbf al bordo dello skew (59 s) accettati senza log.');

$alienJwk = us_jwk($ALIEN, US_KID);
$h3 = $H + ['jwk' => $alienJwk, 'jku' => 'https://attaccante.example.test/jwks', 'x5u' => 'https://attaccante.example.test/x5u',
            'x5c' => ['TUlJQ0lHTkFUVVJBRklUVElaSUE='], 'x5t' => 'dGh1bWJwcmludC1maXR0aXppbw', 'x5t#S256' => 'dGh1bWJwcmludC1zMjU2'];
$res = $run(us_jwe(us_jws($h3, $C, $OP)));
$accepted($res, 'P3');
us_check($GLOBALS['us_get_urls'] === [US_USERINFO_URL, US_JWKS_URL], 'P3: jku/x5u dell\'header mai contattati: solo UserInfo e jwks_uri configurato.');
$noLeak('P3');

$res = $run(us_jwe(us_jws($H, $C, $OP)), ['jwks' => us_jwks([us_jwk($ALIEN, US_KID, ['use' => 'enc', 'alg' => 'RSA-OAEP']), $OP_JWK])]);
$accepted($res, 'P4');
us_check($logger->lines === [], 'P4: stesso kid su chiave sig ed enc: il filtro use seleziona la sig.');

// ===================== N. Negativi (un solo elemento alterato, rifirmato con la chiave OP) =====================
$sigOf = static function (string $jws): string { return explode('.', $jws)[2]; };
$base = us_jws($H, $C, $OP);
[$bh, $bp, $bs] = explode('.', $base);

// N1 firma alterata di un byte
$raw = us_b64u_dec($bs);
$raw[10] = chr(ord($raw[10]) ^ 0x01);
$expect('N1', $run(us_jwe("$bh.$bp." . us_b64u($raw))), 'oidc_userinfo_signature_invalid', 'bad_signature');
// N2 payload alterato dopo la firma
$expect('N2', $run(us_jwe($bh . '.' . us_b64u(us_json(us_with($C, ['family_name' => 'Binderr']))) . ".$bs")), 'oidc_userinfo_signature_invalid', 'bad_signature');
// N3 firmato dalla chiave estranea con il kid dell'OP
$expect('N3', $run(us_jwe(us_jws($H, $C, $ALIEN))), 'oidc_userinfo_signature_invalid', 'bad_signature');
// N4 header jwk con chiave attaccante e firma attaccante
$expect('N4', $run(us_jwe(us_jws($H + ['jwk' => $alienJwk], $C, $ALIEN))), 'oidc_userinfo_signature_invalid', 'bad_signature');
// N5 PS256 firmato validamente con la chiave OP: il rifiuto viene dall'allowlist, non dalla firma
$expect('N5', $run(us_jwe(us_jws(us_with($H, ['alg' => 'PS256']), $C, $OP, 'PS256'))), 'oidc_userinfo_signature_invalid', 'alg_not_allowed');
// N6 alg=none con segmento firma NON vuoto (garbage) e con segmento vuoto
$noneInput = us_b64u(us_json(us_with($H, ['alg' => 'none']))) . '.' . $bp;
$expect('N6a', $run(us_jwe($noneInput . '.' . us_b64u('garbage-signature'))), 'oidc_userinfo_signature_invalid', 'alg_not_allowed');
$expect('N6b', $run(us_jwe($noneInput . '.')), 'oidc_userinfo_signature_invalid', 'alg_not_allowed');
// N7 alg=HS256 con HMAC calcolato usando la n pubblica come segreto
$hsInput = us_b64u(us_json(us_with($H, ['alg' => 'HS256']))) . '.' . $bp;
$expect('N7', $run(us_jwe($hsInput . '.' . us_b64u(hash_hmac('sha256', $hsInput, us_b64u_dec($OP_JWK['n']), true)))), 'oidc_userinfo_signature_invalid', 'alg_not_allowed');
// N8 alg ES256 / assente / non stringa
foreach ([['ES256', 'ES256'], ['assente', null], ['intero', 256], ['array', ['RS256']]] as [$label, $alg]) {
    $hdr = $alg === null ? us_with($H, ['alg' => null]) : us_with($H, ['alg' => $alg]);
    $expect("N8 [$label]", $run(us_jwe(us_jws($hdr, $C, $OP))), 'oidc_userinfo_signature_invalid', 'alg_not_allowed');
}
// N9 crit presente
$expect('N9', $run(us_jwe(us_jws($H + ['crit' => ['exp']], $C, $OP))), 'oidc_userinfo_signature_invalid', 'crit_unsupported');
// N10 kid assente / vuoto / non stringa con JWKS a UNA chiave: nessun fallback alla prima chiave
foreach ([['assente', null], ['vuoto', ''], ['intero', 7]] as [$label, $kid]) {
    $hdr = $kid === null ? us_with($H, ['kid' => null]) : us_with($H, ['kid' => $kid]);
    $expect("N10 [$label]", $run(us_jwe(us_jws($hdr, $C, $OP))), 'oidc_userinfo_signature_invalid', 'kid_missing');
}
// N11 kid non presente nel JWKS
$expect('N11', $run(us_jwe(us_jws(us_with($H, ['kid' => 'us-kid-sconosciuto']), $C, $OP))), 'oidc_userinfo_signature_invalid', 'kid_not_found');
// N12 kid duplicato su DUE chiavi RSA di firma (con e senza use)
$expect('N12a', $run(us_jwe($base), ['jwks' => us_jwks([$OP_JWK, us_jwk($ALIEN, US_KID)])]), 'oidc_userinfo_signature_invalid', 'kid_ambiguous');
$expect('N12b', $run(us_jwe($base), ['jwks' => us_jwks([us_jwk($OP, US_KID, ['use' => null]), us_jwk($ALIEN, US_KID, ['use' => null])])]), 'oidc_userinfo_signature_invalid', 'kid_ambiguous');
// N13 JWK con il kid giusto ma non utilizzabile per RS256
$ecJwk = ['kty' => 'EC', 'kid' => US_KID, 'use' => 'sig', 'crv' => 'P-256', 'x' => us_b64u(str_repeat('x', 32)), 'y' => us_b64u(str_repeat('y', 32))];
foreach ([['kty_EC', $ecJwk], ['kty_EC_con_n_e', us_jwk($OP, US_KID, ['kty' => 'EC'])], ['use_enc', us_jwk($OP, US_KID, ['use' => 'enc'])],
          ['key_ops_encrypt', us_jwk($OP, US_KID, ['key_ops' => ['encrypt']])], ['key_ops_non_array', us_jwk($OP, US_KID, ['key_ops' => 'verify'])],
          ['alg_PS256', us_jwk($OP, US_KID, ['alg' => 'PS256'])], ['n_assente', us_jwk($OP, US_KID, ['n' => null])],
          ['n_non_base64url', us_jwk($OP, US_KID, ['n' => 'non base64url!'])]] as [$label, $jwk]) {
    $expect("N13 [$label]", $run(us_jwe($base), ['jwks' => us_jwks([$jwk])]), 'oidc_userinfo_signature_invalid', 'jwk_unusable');
}
// N14 JWK RSA a 1024 bit (firma valida con quella chiave)
$expect('N14', $run(us_jwe(us_jws($H, $C, $WEAK)), ['jwks' => us_jwks([us_jwk($WEAK)])]), 'oidc_userinfo_signature_invalid', 'jwk_unusable');
// N15 JWKS non disponibile
foreach ([['rete', ['jwks_net' => true]], ['http_500', ['jwks_status' => 500]], ['keys_vuoto', ['jwks' => '{"keys":[]}']],
          ['senza_keys', ['jwks' => '{"altro":1}']], ['non_json', ['jwks' => 'non-json']],
          ['jwks_uri_vuoto', ['provider' => ['jwks_uri' => ''] + $PROVIDER]]] as [$label, $opt]) {
    $expect("N15 [$label]", $run(us_jwe($base), $opt), 'oidc_userinfo_signature_invalid', 'jwks_unavailable');
}
// Claim: ogni variante e' rifirmata con la chiave OP, quindi scatta solo il controllo bersaglio.
$claimCase = static function (string $id, array $changes, string $reason) use ($run, $expect, $H, $C, $OP): void {
    $expect($id, $run(us_jwe(us_jws($H, us_with($C, $changes), $OP))), 'oidc_userinfo_claims_invalid', $reason);
};
// N16 iss
$claimCase('N16 [diverso]', ['iss' => 'https://altro-op.example.test'], 'iss_mismatch');
$claimCase('N16 [assente]', ['iss' => null], 'iss_mismatch');
$claimCase('N16 [slash finale]', ['iss' => US_ISSUER . '/'], 'iss_mismatch');
$claimCase('N16 [intero]', ['iss' => 1], 'invalid_claim_type');
$claimCase('N16 [array]', ['iss' => [US_ISSUER]], 'invalid_claim_type');
// N17 aud stringa diversa o assente
$claimCase('N17 [diversa]', ['aud' => 'https://altro-rp.example.test'], 'aud_mismatch');
$claimCase('N17 [assente]', ['aud' => null], 'aud_mismatch');
// N18 aud array senza client_id
$claimCase('N18 [altro]', ['aud' => ['https://altro-rp.example.test']], 'aud_mismatch');
$claimCase('N18 [vuoto]', ['aud' => []], 'aud_mismatch');
// N19 aud ne' stringa ne' array (un oggetto JSON non e' un elenco di audience)
$claimCase('N19 [intero]', ['aud' => 5], 'invalid_claim_type');
$claimCase('N19 [booleano]', ['aud' => true], 'invalid_claim_type');
$claimCase('N19 [oggetto]', ['aud' => ['x' => US_CLIENT_ID]], 'invalid_claim_type');
// N20 exp scaduto oltre lo skew
$claimCase('N20 [bordo 60 s]', ['exp' => $NOW - 60], 'expired');
$claimCase('N20 [1 ora]', ['exp' => $NOW - 3600], 'expired');
// N21 exp assente
$claimCase('N21', ['exp' => null], 'exp_missing');
// N22 iat nel futuro oltre lo skew
$claimCase('N22', ['iat' => $NOW + 61], 'iat_future');
// N23 iat assente
$claimCase('N23', ['iat' => null], 'iat_missing');
// N24 exp/iat di tipo non intero (restrizione dichiarata del profilo del plugin)
$claimCase('N24 [exp stringa]', ['exp' => (string) ($NOW + 300)], 'invalid_claim_type');
// Float non intero: json_encode scrive un float intero (es. 1.0) come intero, che non sarebbe un caso float.
$claimCase('N24 [exp float]', ['exp' => $NOW + 300.5], 'invalid_claim_type');
$claimCase('N24 [iat stringa]', ['iat' => (string) $NOW], 'invalid_claim_type');
$claimCase('N24 [iat float]', ['iat' => $NOW + 0.5], 'invalid_claim_type');
$claimCase('N24 [exp booleano]', ['exp' => true], 'invalid_claim_type');
// N25 nbf futuro oltre lo skew (R1)
$claimCase('N25', ['nbf' => $NOW + 61], 'nbf_future');
// N26 nbf non intero (R1)
$claimCase('N26 [stringa]', ['nbf' => 'x'], 'invalid_claim_type');
$claimCase('N26 [float]', ['nbf' => $NOW - 9.5], 'invalid_claim_type');
// N27 firma e claim validi, sub non coincidente: blocco H-UI-1, raggiunto solo dietro la firma
foreach ([['diverso', $OTHER_SUB, 'mismatch'], ['assente', null, 'missing'], ['vuoto', '', 'empty']] as [$label, $value, $reason]) {
    $claims = $value === null ? us_with($C, ['sub' => null]) : us_with($C, ['sub' => $value]);
    $expect("N27 [$label]", $run(us_jwe(us_jws($H, $claims, $OP))), 'oidc_userinfo_subject_invalid', $reason);
}
// N28 JWE -> JSON non firmato (anche con punti nei valori)
$expect('N28a', $run(us_jwe(us_json($C))), 'oidc_userinfo_format_invalid', 'unsigned_payload');
$expect('N28b', $run(us_jwe(us_json(us_with($C, ['given_name' => 'U.g.o'])))), 'oidc_userinfo_format_invalid', 'unsigned_payload');
// N29 JSON in chiaro
$expect('N29', $run(us_json($C)), 'oidc_userinfo_format_invalid', 'plain_json');
// N30 JWS a 3 parti non cifrato ma firmato correttamente
$expect('N30', $run($base), 'oidc_userinfo_format_invalid', 'unencrypted_jws');
// N31 JWS interno malformato
foreach ([['2 segmenti', "$bh.$bp"], ['4 segmenti', "$bh.$bp.$bs.$bs"], ['header con +', '+' . substr($bh, 1) . ".$bp.$bs"],
          ['payload con =', "$bh.$bp=.$bs"], ['header vuoto', ".$bp.$bs"], ['header array JSON', us_b64u('[1]') . ".$bp.$bs"],
          ['payload stringa JSON', "$bh." . us_b64u('"x"') . ".$bs"], ['header non JSON', us_b64u('non-json') . ".$bp.$bs"],
          ['payload array JSON', "$bh." . us_b64u(us_json([$C])) . ".$bs"]] as [$label, $inner]) {
    $expect("N31 [$label]", $run(us_jwe($inner)), 'oidc_userinfo_format_invalid', 'malformed_jws');
}
// N32 corpo 2xx non riconosciuto
foreach ([['testo', 'non-json'], ['2 segmenti', 'aaaa.bbbb'], ['4 segmenti', 'a.b.c.d'], ['6 segmenti', 'a.b.c.d.e.f']] as [$label, $body]) {
    $expect("N32 [$label]", $run($body), 'oidc_userinfo_format_invalid', 'unknown_format');
}

// ===================== O. Osservabili: accettati, nessun log in produzione =====================
foreach ([['cty JWT interno', us_jws($H + ['cty' => 'JWT'], $C, $OP), []], ['typ JWT interno', us_jws($H + ['typ' => 'JWT'], $C, $OP), []],
          ['aud array con client_id', us_jws($H, us_with($C, ['aud' => ['https://altro-rp.example.test', US_CLIENT_ID]]), $OP), []],
          ['nbf valido', us_jws($H, us_with($C, ['nbf' => $NOW - 10]), $OP), []],
          ['exp <= iat', us_jws($H, us_with($C, ['iat' => $NOW, 'exp' => $NOW - 10]), $OP), []],
          ['Content-Type jose', $base, ['content-type' => 'application/jose']],
          ['Content-Type jwt', $base, ['content-type' => 'application/jwt']],
          ['Content-Type altro', $base, ['content-type' => 'text/plain']]] as [$label, $inner, $headers]) {
    $res = $run(us_jwe($inner), ['ui_headers' => $headers]);
    $accepted($res, "O [$label]");
    us_check($logger->lines === [], "O [$label]: osservabile accettato SENZA log nella build ordinaria.");
}

// ===================== E. Rami "non ottenuta": [] invariato (limite preesistente, R5) =====================
$notObtained = static function ($res, string $label) use ($SUB): void {
    us_check(is_array($res) && ($res['claims']['sub'] ?? null) === $SUB && !isset($res['claims']['given_name']),
        "$label: UserInfo non ottenuta -> [] come oggi, claim solo dall'ID Token.");
};
$res = $run(us_jwe($base), ['access_token' => '']);
$notObtained($res, 'E1 [access token vuoto]');
us_check($GLOBALS['us_userinfo_calls'] === 0, 'E1: con access token vuoto la UserInfo non e\' richiesta.');
$res = $run(us_jwe($base), ['provider' => ['userinfo_endpoint' => ''] + $PROVIDER]);
$notObtained($res, 'E2 [endpoint vuoto]');
us_check($GLOBALS['us_userinfo_calls'] === 0, 'E2: con endpoint vuoto la UserInfo non e\' richiesta.');
$notObtained($run(us_jwe($base), ['ui_net' => true]), 'E3 [errore HTTP]');
$notObtained($run(us_jwe($base), ['ui_status' => 500]), 'E4 [non 2xx]');
$notObtained($run(''), 'E5 [body vuoto]');
$notObtained($run(us_jwe($base), ['decrypter' => null]), 'E6 [nessun decrypter]');
$notObtained($run('aaaa.bbbb.cccc.FAIL.eeee'), 'E7 [decifratura fallita]');
$noLeak('E7');

// ===================== C. Traccia statica: un WP_Error della UserInfo ferma il flusso prima del merge =====================
$src = (string) file_get_contents(__DIR__ . '/../includes/Core/OidcClient.php');
$pFetch = strpos($src, '$userInfoClaims = $this->fetchUserInfo(');
$pIsErr = $pFetch === false ? false : strpos($src, 'if (is_wp_error($userInfoClaims)) {', $pFetch);
$pReturn = $pIsErr === false ? false : strpos($src, 'return $userInfoClaims;', $pIsErr);
$pMerge = $pFetch === false ? false : strpos($src, 'array_merge($payload, $userInfoClaims)', $pFetch);
us_check($pFetch !== false && $pIsErr !== false && $pReturn !== false && $pMerge !== false && $pIsErr < $pReturn && $pReturn < $pMerge,
    'C1: in handleCallback il WP_Error della UserInfo deve essere restituito PRIMA di array_merge (la traccia in public e\' S1-S3).');

// ===================== Esito =====================
fwrite(STDOUT, "cie-userinfo-signature: $US_TOTAL verifiche, " . count($US_FAILED) . " fallite\n");
if ($US_FAILED !== []) {
    $shown = array_slice(array_values(array_unique($US_FAILED)), 0, 400);
    foreach ($shown as $msg) { fwrite(STDERR, 'FAIL ' . $msg . "\n"); }
    exit(1);
}
wp_spid_cie_test_ok('cie-userinfo-signature');
