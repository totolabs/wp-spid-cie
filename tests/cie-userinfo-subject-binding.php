<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// H-UI-1: binding del claim sub tra ID Token validato e UserInfo CIE OIDC.
// OpenID Connect Core 1.0 §5.3.2 e regole tecniche SPID/CIE OIDC: il JWS interno della UserInfo DEVE
// contenere sub e il RP DEVE verificare che coincida ESATTAMENTE con quello dell'ID Token; altrimenti i
// valori della UserInfo NON vanno usati.
// Solo fixture sintetiche e stub: nessuna rete, nessuna chiave reale o storica, nessun provider reale.
// La "JWE" usata qui e' una busta compact a 5 parti aperta da un decrypter STUB: esercita il PERCORSO
// applicativo di fetchUserInfo, NON la crittografia RSA-OAEP/AES.
// Con H-UI-3 l'unica forma accettata e' JWE -> JWS firmato dall'OP: il JWS interno qui e' firmato DAVVERO
// con una coppia RSA sintetica generata a runtime e verificato dal TokenValidator reale (ereditato), cosi'
// il controllo del sub e' esercitato DIETRO una firma valida. La matrice completa di firma e claim
// (iss/aud/exp/iat/nbf, alg, kid, JWKS) e' in cie-userinfo-signature.php.

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
    public function __construct($code = '', $msg = '') { $this->code = $code; $this->msg = $msg; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->msg; }
}

const UB_ACCESS_TOKEN = 'AT-SEGRETO-ub-0001';
const UB_ID_TOKEN = 'IDT-SEGRETO.ub.0001';
$GLOBALS['ub_access_token'] = UB_ACCESS_TOKEN;
$GLOBALS['ub_userinfo_body'] = '';
$GLOBALS['ub_userinfo_net_error'] = false;
$GLOBALS['ub_userinfo_calls'] = 0;
function wp_remote_post($url, $args = []) {
    return ['response' => ['code' => 200], 'body' => json_encode(['access_token' => $GLOBALS['ub_access_token'], 'id_token' => UB_ID_TOKEN, 'token_type' => 'Bearer'])];
}
const UB_USERINFO_URL = 'https://op.example.test/userinfo';
const UB_JWKS_URL = 'https://op.example.test/jwks';
const UB_KID = 'ub-kid-op-SEGRETO-0a1b2c3d';
$GLOBALS['ub_jwks_body'] = '';
// Lo stub risponde per URL: ub_userinfo_calls conta SOLO le richieste all'endpoint UserInfo.
function wp_remote_get($url, $args = []) {
    if ((string) $url === UB_JWKS_URL) {
        return ['response' => ['code' => 200], 'body' => $GLOBALS['ub_jwks_body']];
    }
    if ((string) $url !== UB_USERINFO_URL) { return new WP_Error('unexpected_url', 'URL non previsto nei test.'); }
    $GLOBALS['ub_userinfo_calls']++;
    if ($GLOBALS['ub_userinfo_net_error']) { return new WP_Error('offline', 'Rete disabilitata nei test.'); }
    return ['response' => ['code' => 200], 'body' => $GLOBALS['ub_userinfo_body']];
}
function wp_remote_retrieve_response_code($r) { return $r['response']['code'] ?? 0; }
function wp_remote_retrieve_body($r) { return $r['body'] ?? ''; }

// Il vendor emette deprecation di terze parti su PHP recenti al caricamento: silenziate SOLO durante l'include.
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
require_once __DIR__ . '/../vendor/autoload.php';
error_reporting(E_ALL);
require_once __DIR__ . '/../includes/Logging/Logger.php';
require_once __DIR__ . '/../includes/Core/PkceService.php';
require_once __DIR__ . '/../includes/Core/StateNonceStore.php';
require_once __DIR__ . '/../includes/Core/TokenValidator.php';
require_once __DIR__ . '/../includes/Core/OidcClient.php';

class UB_Logger extends WP_SPID_CIE_OIDC_Logger {
    public $lines = [];
    public function error(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function warn(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function info(string $message, array $context = []): void { $this->lines[] = $message . ' ' . json_encode($context); }
    public function debug(string $message, array $context = []): void {}
}
class UB_StateStore implements WP_SPID_CIE_OIDC_StateNonceStoreInterface {
    public function store(string $state, array $context, int $ttl): bool { return true; }
    public function consume(string $state): ?array {
        return ['nonce' => 'NONCE-ub', 'code_verifier' => 'VERIFIER-ub', 'provider' => 'cie', 'target_url' => 'https://sp.example.test/'];
    }
}
// L'ID Token e' gia' validato (firma, iss, aud, exp, iat, nonce, acr) dal TokenValidator reale: qui si fissa il payload.
class UB_TokenValidator extends WP_SPID_CIE_OIDC_TokenValidator {
    public $payload = [];
    public function validateIdToken(string $idToken, array $providerConfig, string $expectedNonce, string $correlationId) {
        return $this->payload;
    }
}

// --- Raccolta esiti: tutti i casi vengono eseguiti, poi esito unico ---
$UB_TOTAL = 0;
$UB_FAILED = [];
function ub_check(bool $condition, string $message): void {
    global $UB_TOTAL, $UB_FAILED;
    $UB_TOTAL++;
    if (!$condition) { $UB_FAILED[] = $message; }
}

function ub_b64u(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function ub_b64u_dec(string $s): string {
    $s = strtr($s, '-_', '+/');
    return (string) base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4));
}
function ub_json(array $claims): string { return (string) json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); }
// Coppia OP sintetica generata a runtime (mai committata); JWKS con n/e dai componenti Raw.
$UB_OP_KEY = \phpseclib3\Crypt\RSA::createKey(2048);
$ubRaw = $UB_OP_KEY->getPublicKey()->toString('Raw');
$GLOBALS['ub_jwks_body'] = (string) json_encode(['keys' => [['kty' => 'RSA', 'kid' => UB_KID, 'use' => 'sig', 'alg' => 'RS256',
    'n' => ub_b64u($ubRaw['n']->toBytes()), 'e' => ub_b64u($ubRaw['e']->toBytes())]]]);
// JWS firmato DAVVERO (RS256) con la chiave OP sintetica.
function ub_jws(string $json): string {
    global $UB_OP_KEY;
    $input = ub_b64u('{"alg":"RS256","kid":"' . UB_KID . '"}') . '.' . ub_b64u($json);
    return $input . '.' . ub_b64u($UB_OP_KEY->withPadding(\phpseclib3\Crypt\RSA::SIGNATURE_PKCS1)->withHash('sha256')->sign($input));
}
function ub_jwe(string $inner): string {
    return ub_b64u('{"alg":"RSA-OAEP","enc":"A256CBC-HS512"}') . '.' . ub_b64u('cek') . '.' . ub_b64u('iv') . '.' . ub_b64u($inner) . '.' . ub_b64u('tag');
}
// Decrypter STUB: restituisce la parte "ciphertext" in chiaro. Nessuna crittografia.
$UB_DECRYPTER = static function (string $jwe): string {
    $p = explode('.', $jwe);
    if (count($p) !== 5 || $p[3] === 'FAIL') { throw new RuntimeException('stub-decrypt-failure'); }
    return ub_b64u_dec($p[3]);
};
function ub_body(string $format, string $json): string {
    switch ($format) {
        case 'json': return $json;
        case 'jws': return ub_jws($json);
        case 'jwe_jws': return ub_jwe(ub_jws($json));
        case 'jwe_json': return ub_jwe($json);
    }
    throw new InvalidArgumentException($format);
}

$SUB = 'ub-pairwise-9f2c1e7a-0b3d-4c5e-8a61-2f4d6b8c0e13';
$OTHER_SUB = 'ub-pairwise-ALTRO-0000-1111-2222-333344445555';
$SUB_NFC = "ub-pairwise-caf\u{00E9}";
$SUB_NFD = "ub-pairwise-cafe\u{0301}";
$SELF = [
    'given_name' => 'Ugo', 'family_name' => 'Binder',
    'https://attributes.eid.gov.it/fiscal_number' => 'TINIT-BNDUGO80A01H501Z',
    'phone_number' => '+390000000001',
];
$OTHER = [
    'given_name' => 'Alba', 'family_name' => 'Altrove',
    'https://attributes.eid.gov.it/fiscal_number' => 'TINIT-LTRLBA85B41F205X',
    'email' => 'altro.soggetto@example.test', 'phone_number' => '+390000000002',
];
// Claim di protocollo validi del JWS interno (H-UI-3): il sub e' controllato solo dopo firma e claim.
$PROTO = ['iss' => 'https://op.example.test', 'aud' => 'https://sp.example.test', 'iat' => time(), 'exp' => time() + 300];
$SELF += $PROTO;
$OTHER += $PROTO;
$FORBIDDEN_IN_LOG = [
    $SUB, $OTHER_SUB, $SUB_NFC, $SUB_NFD, UB_ACCESS_TOKEN, UB_ID_TOKEN, UB_KID,
    'BNDUGO80A01H501Z', 'LTRLBA85B41F205X', 'Ugo', 'Binder', 'Alba', 'Altrove',
    'altro.soggetto@example.test', '+390000000001', '+390000000002', 'eyJ',
];

$logger = new UB_Logger('TEST');
$validator = new UB_TokenValidator($logger);
$oidc = new WP_SPID_CIE_OIDC_OidcClient(new WP_SPID_CIE_OIDC_PkceService(), new UB_StateStore(), $validator, $logger);
$providerConfig = [
    'provider' => 'cie', 'client_id' => 'https://sp.example.test',
    'redirect_uri' => 'https://sp.example.test/?oidc_action=callback&provider=cie',
    'issuer' => 'https://op.example.test', 'token_endpoint' => 'https://op.example.test/token',
    'userinfo_endpoint' => 'https://op.example.test/userinfo', 'jwks_uri' => 'https://op.example.test/jwks',
];
$request = ['state' => 'STATE-ub', 'code' => 'CODE-SEGRETO-ub', 'correlation_id' => 'corr-ub'];

$run = static function (array $idPayload, string $body, bool $netError = false, string $accessToken = UB_ACCESS_TOKEN) use ($oidc, $validator, $logger, $providerConfig, $request, $UB_DECRYPTER) {
    $validator->payload = $idPayload;
    $logger->lines = [];
    $GLOBALS['ub_userinfo_body'] = $body;
    $GLOBALS['ub_userinfo_net_error'] = $netError;
    $GLOBALS['ub_access_token'] = $accessToken;
    $GLOBALS['ub_userinfo_calls'] = 0;
    return $oidc->handleCallback($request, $providerConfig, null, $UB_DECRYPTER);
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
            ub_check(strpos($line, $needle) === false, "$label: il log non deve contenere dati personali/token/payload (trovato un valore vietato).");
        }
    }
};
$idPayload = static function ($sub, bool $present = true): array {
    $p = ['iss' => 'https://op.example.test', 'aud' => 'https://sp.example.test', 'nonce' => 'NONCE-ub', 'acr' => 'https://www.spid.gov.it/SpidL2'];
    if ($present) { $p['sub'] = $sub; }
    return $p;
};

// H-UI-3: l'unico formato positivo e' jwe_jws firmato; gli altri sono rifiuti di formato (motivo atteso).
$FORMATS = ['jwe_jws'];
$REJECTED_FORMATS = ['json' => 'plain_json', 'jws' => 'unencrypted_jws', 'jwe_json' => 'unsigned_payload'];
$ABSENT = new stdClass();
// [etichetta, valore del sub UserInfo (ABSENT = chiave assente), motivo atteso nel log]
$NEGATIVES = [
    ['diverso', $OTHER_SUB, 'mismatch'],
    ['assente', $ABSENT, 'missing'],
    ['vuoto', '', 'empty'],
    ['intero', 123, 'invalid_type'],
    ['decimale', 1.5, 'invalid_type'],
    ['true', true, 'invalid_type'],
    ['false', false, 'invalid_type'],
    ['null', null, 'invalid_type'],
    ['array', [$SUB], 'invalid_type'],
    ['oggetto', ['value' => $SUB], 'invalid_type'],
    ['maiuscole', strtoupper($SUB), 'mismatch'],
    ['spazio_iniziale', ' ' . $SUB, 'mismatch'],
    ['spazio_finale', $SUB . ' ', 'mismatch'],
    ['a_capo', $SUB . "\n", 'mismatch'],
    ['tab', "\t" . $SUB, 'mismatch'],
];

// ===================== M. Matrice formati x sub =====================
foreach ($FORMATS as $f) {
    // M1 positivo: sub identico -> claim restituiti come prima, sub autoritativo dall'ID Token
    $res = $run($idPayload($SUB), ub_body($f, ub_json(['sub' => $SUB] + $SELF)));
    ub_check(is_array($res) && ($res['claims']['sub'] ?? null) === $SUB, "M1 [$f]: sub identico deve essere accettato.");
    ub_check(is_array($res) && ($res['claims']['https://attributes.eid.gov.it/fiscal_number'] ?? null) === 'TINIT-BNDUGO80A01H501Z'
        && ($res['claims']['given_name'] ?? null) === 'Ugo' && ($res['claims']['family_name'] ?? null) === 'Binder',
        "M1 [$f]: con sub identico i claim UserInfo (anagrafica, codice fiscale con TINIT-) devono essere restituiti invariati.");
    $noLeak("M1 [$f]");

    foreach ($NEGATIVES as [$label, $value, $reason]) {
        $claims = $SELF;
        if ($value !== $ABSENT) { $claims = ['sub' => $value] + $SELF; }
        $res = $run($idPayload($SUB), ub_body($f, ub_json($claims)));
        ub_check($isCode($res, 'oidc_userinfo_subject_invalid'), "M2 [$f/$label]: atteso WP_Error oidc_userinfo_subject_invalid.");
        ub_check(!is_array($res), "M2 [$f/$label]: nessun claim UserInfo utilizzabile deve uscire da handleCallback.");
        ub_check($lastReason() === $reason, "M2 [$f/$label]: atteso motivo di log '$reason'.");
        $noLeak("M2 [$f/$label]");
    }

    // M3 Unicode equivalente (NFC vs NFD): nessuna normalizzazione, rifiuto
    $res = $run($idPayload($SUB_NFC), ub_body($f, ub_json(['sub' => $SUB_NFD] + $SELF)));
    ub_check($isCode($res, 'oidc_userinfo_subject_invalid'), "M3 [$f]: sub Unicode equivalente ma non identico (NFC/NFD) va rifiutato.");
    ub_check($lastReason() === 'mismatch', "M3 [$f]: atteso motivo di log 'mismatch'.");
    $noLeak("M3 [$f]");
    $res = $run($idPayload($SUB_NFC), ub_body($f, ub_json(['sub' => $SUB_NFC] + $SELF)));
    ub_check(is_array($res) && ($res['claims']['sub'] ?? null) === $SUB_NFC, "M3 [$f]: sub Unicode identico byte per byte va accettato.");

    // M4 UserInfo senza sub ma con firma e claim di protocollo validi: rifiutata (sub mancante), non trattata come
    // "non ottenuta". La distinzione da [] e' posizionale (i rami di fallimento ritornano [] prima del controllo).
    $res = $run($idPayload($SUB), ub_body($f, ub_json($PROTO)));
    ub_check($isCode($res, 'oidc_userinfo_subject_invalid'), "M4 [$f]: UserInfo firmata senza sub va rifiutata (sub mancante), non trattata come 'non ottenuta'.");
    ub_check($lastReason() === 'missing', "M4 [$f]: atteso motivo di log 'missing'.");
    // M4b '{}' firmato: con H-UI-3 i claim obbligatori sono verificati prima del sub -> rifiuto, mai [].
    $res = $run($idPayload($SUB), ub_body($f, '{}'));
    ub_check($isCode($res, 'oidc_userinfo_claims_invalid') && !is_array($res), "M4b [$f]: UserInfo '{}' firmata va rifiutata (claim obbligatori), non trattata come 'non ottenuta'.");
}

// M5 formati non piu' ammessi (H-UI-3): rifiutati PRIMA del controllo del sub, anche con sub identico.
foreach ($REJECTED_FORMATS as $f => $reason) {
    $res = $run($idPayload($SUB), ub_body($f, ub_json(['sub' => $SUB] + $SELF)));
    ub_check($isCode($res, 'oidc_userinfo_format_invalid'), "M5 [$f]: formato non ammesso -> atteso WP_Error oidc_userinfo_format_invalid.");
    ub_check(!is_array($res), "M5 [$f]: nessun claim UserInfo utilizzabile deve uscire da handleCallback.");
    ub_check($lastReason() === $reason, "M5 [$f]: atteso motivo di log '$reason'.");
    $noLeak("M5 [$f]");
}

// ===================== I. sub dell'ID Token non valido =====================
foreach ([['assente', null, false, 'missing'], ['vuoto', '', true, 'empty'], ['intero', 42, true, 'invalid_type'],
          ['null', null, true, 'invalid_type'], ['array', [$SUB], true, 'invalid_type'], ['true', true, true, 'invalid_type']] as [$label, $value, $present, $reason]) {
    $res = $run($idPayload($value, $present), ub_body('json', ub_json(['sub' => $SUB] + $SELF)));
    ub_check($isCode($res, 'oidc_id_token_sub_invalid'), "I1 [$label]: sub ID Token non valido -> atteso WP_Error oidc_id_token_sub_invalid.");
    ub_check($GLOBALS['ub_userinfo_calls'] === 0, "I1 [$label]: con sub ID Token non valido la UserInfo NON deve essere richiesta.");
    ub_check($lastReason() === $reason, "I1 [$label]: atteso motivo di log '$reason'.");
    $noLeak("I1 [$label]");
}

// ===================== X. Altro soggetto: contaminazione =====================
foreach ($FORMATS as $f) {
    $res = $run($idPayload($SUB), ub_body($f, ub_json(['sub' => $OTHER_SUB] + $OTHER)));
    ub_check($isCode($res, 'oidc_userinfo_subject_invalid'), "X1 [$f]: UserInfo di un altro soggetto deve produrre oidc_userinfo_subject_invalid.");
    ub_check(!is_array($res), "X1 [$f]: nessun codice fiscale/anagrafica/email dell'altro soggetto deve essere restituito.");
    $noLeak("X1 [$f]");
}
foreach ($REJECTED_FORMATS as $f => $reason) {
    $res = $run($idPayload($SUB), ub_body($f, ub_json(['sub' => $OTHER_SUB] + $OTHER)));
    ub_check($isCode($res, 'oidc_userinfo_format_invalid') && !is_array($res), "X1 [$f]: formato non ammesso: nessun dato dell'altro soggetto deve essere restituito.");
    $noLeak("X1 [$f]");
}

// ===================== E. Comportamento esistente invariato (UserInfo non ottenuta -> []) =====================
$res = $run($idPayload($SUB), ub_body('json', ub_json(['sub' => $SUB] + $SELF)), false, '');
ub_check(is_array($res) && ($res['claims']['sub'] ?? null) === $SUB && !isset($res['claims']['given_name']) && $GLOBALS['ub_userinfo_calls'] === 0,
    'E1: access token assente -> UserInfo non richiesta, claim solo dall\'ID Token (comportamento esistente).');
$res = $run($idPayload($SUB), '', true);
ub_check(is_array($res) && !isset($res['claims']['given_name']), 'E2: errore di rete UserInfo -> [] come oggi (rischio residuo: gestito da validateMandatoryClaims).');
$res = $run($idPayload($SUB), 'aaaa.bbbb.cccc.FAIL.eeee');
ub_check(is_array($res) && !isset($res['claims']['given_name']), 'E3: decrittazione fallita -> [] come oggi.');
// E4 (cambiato da H-UI-3): un corpo 2xx ottenuto ma non riconosciuto non e' piu' [] ma un rifiuto di formato.
$res = $run($idPayload($SUB), 'non-json');
ub_check($isCode($res, 'oidc_userinfo_format_invalid') && $lastReason() === 'unknown_format', 'E4: body 2xx non riconosciuto -> oidc_userinfo_format_invalid / unknown_format.');

$fetch = new ReflectionMethod($oidc, 'fetchUserInfo');
$fetch->setAccessible(true);
$GLOBALS['ub_userinfo_calls'] = 0;
$GLOBALS['ub_userinfo_net_error'] = false;
$GLOBALS['ub_userinfo_body'] = ub_body('jwe_jws', ub_json(['sub' => $SUB] + $SELF));
$r = $fetch->invoke($oidc, '', $providerConfig, 'corr-ub', $UB_DECRYPTER, $SUB);
ub_check($r === [] && $GLOBALS['ub_userinfo_calls'] === 0, 'E5: fetchUserInfo con access token vuoto -> [] senza richiesta (invariato).');
$r = $fetch->invoke($oidc, UB_ACCESS_TOKEN, ['userinfo_endpoint' => ''] + $providerConfig, 'corr-ub', $UB_DECRYPTER, $SUB);
ub_check($r === [] && $GLOBALS['ub_userinfo_calls'] === 0, 'E6: fetchUserInfo con endpoint vuoto -> [] senza richiesta (invariato).');
$r = $fetch->invoke($oidc, UB_ACCESS_TOKEN, $providerConfig, 'corr-ub', $UB_DECRYPTER, $SUB);
ub_check(is_array($r) && ($r['sub'] ?? null) === $SUB && ($r['given_name'] ?? null) === 'Ugo', 'E7: fetchUserInfo con sub identico restituisce i claim.');
$GLOBALS['ub_userinfo_body'] = ub_body('jwe_jws', ub_json(['sub' => $OTHER_SUB] + $OTHER));
$r = $fetch->invoke($oidc, UB_ACCESS_TOKEN, $providerConfig, 'corr-ub', $UB_DECRYPTER, $SUB);
ub_check($isCode($r, 'oidc_userinfo_subject_invalid'), 'E8: fetchUserInfo con sub diverso restituisce WP_Error, non un array silenzioso.');

// ===================== S. Traccia statica del flusso in public =====================
// handleCallback non apre sessioni: e' public a farlo. Si verifica che un WP_Error di handleCallback termini il
// callback (redirect_to_login_error -> exit) PRIMA di normalizeClaims/validateMandatoryClaims/resolveOrProvisionUser.
$pub = (string) file_get_contents(__DIR__ . '/../public/class-wp-spid-cie-public.php');
$pos = static function (string $re, int $from = 0) use ($pub): int {
    return preg_match($re, $pub, $m, PREG_OFFSET_CAPTURE, $from) ? (int) $m[0][1] : -1;
};
$pCall = $pos('/\$result\s*=\s*\$oidc->handleCallback\(/');
$pIf = $pCall >= 0 ? $pos('/if\s*\(\s*is_wp_error\(\s*\$result\s*\)\s*\)\s*\{/', $pCall) : -1;
$pRedirect = $pIf >= 0 ? $pos('/\$this->redirect_to_login_error\(/', $pIf) : -1;
$pNormalize = $pCall >= 0 ? $pos('/->normalizeClaims\(/', $pCall) : -1;
$pMandatory = $pCall >= 0 ? $pos('/->validateMandatoryClaims\(/', $pCall) : -1;
$pResolve = $pCall >= 0 ? $pos('/->resolveOrProvisionUser\(/', $pCall) : -1;
$pCookie = $pCall >= 0 ? $pos('/wp_set_auth_cookie\(/', $pCall) : -1;
ub_check($pCall >= 0 && $pIf > $pCall && $pRedirect > $pIf, 'S1: in public il risultato di handleCallback deve essere seguito da is_wp_error -> redirect_to_login_error.');
ub_check($pRedirect > 0 && $pNormalize > $pRedirect && $pMandatory > $pNormalize && $pResolve > $pMandatory && $pCookie > $pResolve,
    'S2: il redirect di errore deve precedere normalizeClaims, validateMandatoryClaims, resolveOrProvisionUser e wp_set_auth_cookie.');
$pDef = $pos('/private function redirect_to_login_error\(/');
$pDefEnd = $pDef >= 0 ? $pos('/\n    \}/', $pDef) : -1;
$pExit = $pDef >= 0 ? $pos('/\bexit\s*;/', $pDef) : -1;
ub_check($pDef >= 0 && $pExit > $pDef && $pExit < $pDefEnd, 'S3: redirect_to_login_error deve terminare con exit (nessuna prosecuzione verso il mapping).');

// ===================== Esito =====================
fwrite(STDOUT, "cie-userinfo-subject-binding: $UB_TOTAL verifiche, " . count($UB_FAILED) . " fallite\n");
if ($UB_FAILED !== []) {
    $shown = array_slice(array_values(array_unique($UB_FAILED)), 0, 400);
    foreach ($shown as $msg) { fwrite(STDERR, 'FAIL ' . $msg . "\n"); }
    exit(1);
}
wp_spid_cie_test_ok('cie-userinfo-subject-binding');
