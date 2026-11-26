<?php
defined( 'ABSPATH' ) || exit;

/**
 * Validates OIDC id_tokens received from SPID and CIE providers.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_TokenValidator {
    /**
     * Algoritmi ammessi per il JWS interno della UserInfo: solo quello registrato dal RP nella
     * Entity Configuration (userinfo_signed_response_alg = RS256). Da allargare solo se i metadata
     * registrati lo prevedono.
     */
    const USERINFO_ALLOWED_ALGS = ['RS256'];

    /** Dimensione minima in bit del modulo RSA della chiave di firma dell'OP per la UserInfo. */
    const USERINFO_MIN_RSA_BITS = 2048;

    /** Tolleranza di orologio in secondi per exp/iat/nbf della UserInfo: la stessa dell'ID Token. */
    const USERINFO_CLOCK_SKEW = 60;

    private $logger;

    /**
     * @since 1.0.0
     * @param WP_SPID_CIE_OIDC_Logger $logger
     */
    public function __construct(WP_SPID_CIE_OIDC_Logger $logger) {
        $this->logger = $logger;
    }

    /**
     * Validates an id_token JWT: structure, claims, nonce, ACR, and signature.
     *
     * @since  1.0.0
     * @param  string $idToken        Compact JWT string.
     * @param  array  $providerConfig Resolved provider configuration (includes jwks_uri, issuer, client_id).
     * @param  string $expectedNonce  Nonce stored during the authorization request.
     * @param  string $correlationId  Unique request identifier for logging.
     * @return array|WP_Error Validated payload claims, or error.
     */
    public function validateIdToken(string $idToken, array $providerConfig, string $expectedNonce, string $correlationId) {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return new WP_Error('oidc_invalid_token', __('Token di identità non valido.', 'wp-spid-cie'));
        }

        $header = $this->decodePart($parts[0]);
        $payload = $this->decodePart($parts[1]);
        $signature = $this->base64urlDecode($parts[2]);

        if (!is_array($header) || !is_array($payload) || $signature === false) {
            return new WP_Error('oidc_invalid_token_format', __('Token di identità malformato.', 'wp-spid-cie'));
        }

        $allowedAlgs = ['RS256', 'PS256'];
        $alg = $header['alg'] ?? '';
        if (!in_array($alg, $allowedAlgs, true)) {
            return new WP_Error('oidc_alg_not_allowed', __('Algoritmo token non consentito.', 'wp-spid-cie'));
        }

        $now = time();
        $skew = 60;

        if (($payload['iss'] ?? '') !== ($providerConfig['issuer'] ?? '')) {
            return new WP_Error('oidc_iss_mismatch', __('Issuer non valido.', 'wp-spid-cie'));
        }

        $aud = $payload['aud'] ?? null;
        $clientId = (string) ($providerConfig['client_id'] ?? '');
        if (is_array($aud)) {
            if (!in_array($clientId, $aud, true)) {
                return new WP_Error('oidc_aud_mismatch', __('Audience non valida.', 'wp-spid-cie'));
            }
        } elseif ((string) $aud !== $clientId) {
            return new WP_Error('oidc_aud_mismatch', __('Audience non valida.', 'wp-spid-cie'));
        }

        if (empty($payload['exp']) || ($now - $skew) >= intval($payload['exp'])) {
            return new WP_Error('oidc_expired', __('Token scaduto.', 'wp-spid-cie'));
        }

        if (empty($payload['iat']) || intval($payload['iat']) > ($now + $skew)) {
            return new WP_Error('oidc_iat_invalid', __('Token con timestamp non valido.', 'wp-spid-cie'));
        }

        if (($payload['nonce'] ?? '') !== $expectedNonce) {
            return new WP_Error('oidc_nonce_mismatch', __('Nonce non valido.', 'wp-spid-cie'));
        }

        $acrCheck = $this->validateAcrPolicy($payload, $providerConfig);
        if (is_wp_error($acrCheck)) {
            return $acrCheck;
        }

        $jwksUri = $providerConfig['jwks_uri'] ?? '';
        if (empty($jwksUri)) {
            return new WP_Error('oidc_no_jwks', __('Impossibile verificare la firma del token.', 'wp-spid-cie'));
        }

        $jwks = $this->fetchJwks($jwksUri, $correlationId);
        if (is_wp_error($jwks)) {
            return $jwks;
        }

        $kid = $header['kid'] ?? '';
        $jwk = $this->findJwk($jwks, $kid);
        if (!$jwk) {
            return new WP_Error('oidc_kid_not_found', __('Chiave di firma non trovata.', 'wp-spid-cie'));
        }

        $verify = $this->verifySignature($parts[0] . '.' . $parts[1], $signature, $jwk, $alg);
        if (!$verify) {
            return new WP_Error('oidc_bad_signature', __('Firma token non valida.', 'wp-spid-cie'));
        }

        return $payload;
    }

    /**
     * Verifica il JWS interno (compact) della UserInfo CIE, gia' decifrato dalla JWE.
     *
     * Ordine vincolante: struttura, header (alg, crit, kid), chiave dal JWKS di
     * providerConfig['jwks_uri'], firma sui byte originali, poi iss/aud/exp/iat/nbf.
     * La chiave dell'OP proviene dalla configurazione del provider ed e' protetta da TLS/WebPKI,
     * come per l'ID Token (non dalla trust chain della federazione). Le chiavi e gli URL presenti
     * nell'header del token (jku, jwk, x5u, x5c, x5t) non vengono mai letti.
     * Il sub NON e' verificato qui: resta il controllo H-UI-1 in OidcClient, dopo questo metodo.
     *
     * @since  1.4.2
     * @param  string $jws            JWS compact interno alla JWE.
     * @param  array  $providerConfig Configurazione risolta (jwks_uri, issuer, client_id).
     * @param  string $correlationId  Identificativo della richiesta per il log.
     * @return array|WP_Error Payload verificato, oppure WP_Error con codice dedicato.
     */
    public function validateUserInfoJws(string $jws, array $providerConfig, string $correlationId) {
        // 1. Struttura: 3 segmenti; header e payload base64url stretti e JSON oggetto.
        $parts = explode('.', $jws);
        if (count($parts) !== 3) {
            return $this->rejectUserInfo('oidc_userinfo_format_invalid', 'malformed_jws', $correlationId);
        }
        $header = $this->decodeUserInfoSegment($parts[0]);
        $decodedPayload = $this->decodeUserInfoSegment($parts[1]);
        if ($header === null || $decodedPayload === null) {
            return $this->rejectUserInfo('oidc_userinfo_format_invalid', 'malformed_jws', $correlationId);
        }
        $header = $header['array'];
        $payloadObject = $decodedPayload['object'];
        $payload = $decodedPayload['array'];

        // 2. alg in allowlist, prima di toccare il segmento firma.
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !in_array($alg, self::USERINFO_ALLOWED_ALGS, true)) {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'alg_not_allowed', $correlationId);
        }

        // 3. Nessuna estensione critica supportata.
        if (array_key_exists('crit', $header)) {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'crit_unsupported', $correlationId);
        }

        // 4. kid obbligatorio: nessun fallback alla prima chiave del JWKS.
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'kid_missing', $correlationId);
        }

        // 6. JWKS solo dal jwks_uri configurato (stessa fonte dell'ID Token).
        $jwksUri = (string) ($providerConfig['jwks_uri'] ?? '');
        if ($jwksUri === '') {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'jwks_unavailable', $correlationId);
        }
        $jwks = $this->fetchJwks($jwksUri, $correlationId);
        if (is_wp_error($jwks)) {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'jwks_unavailable', $correlationId);
        }

        // 7. Selezione univoca della chiave per kid esatto.
        $jwk = $this->selectUserInfoJwk($jwks, $kid, $alg);
        if (is_string($jwk)) {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', $jwk, $correlationId);
        }

        // 8. Firma sui byte originali header.payload, con JWK minimale {kty, n, e}.
        $signature = $this->base64urlDecodeStrict($parts[2]);
        if ($signature === null || !$this->verifySignature($parts[0] . '.' . $parts[1], $signature, $jwk, $alg)) {
            return $this->rejectUserInfo('oidc_userinfo_signature_invalid', 'bad_signature', $correlationId);
        }

        // 9. iss === issuer configurato.
        $issuer = (string) ($providerConfig['issuer'] ?? '');
        if (!array_key_exists('iss', $payload)) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'iss_mismatch', $correlationId);
        }
        if (!is_string($payload['iss'])) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'invalid_claim_type', $correlationId);
        }
        if ($issuer === '' || $payload['iss'] !== $issuer) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'iss_mismatch', $correlationId);
        }

        // 10. aud: stringa === client_id, oppure array JSON che lo contiene. Il tipo si valuta sulla
        // decodifica a oggetti: un oggetto JSON non e' un elenco di audience.
        $clientId = (string) ($providerConfig['client_id'] ?? '');
        if (!property_exists($payloadObject, 'aud')) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'aud_mismatch', $correlationId);
        }
        $aud = $payloadObject->aud;
        if (is_string($aud)) {
            if ($clientId === '' || $aud !== $clientId) {
                return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'aud_mismatch', $correlationId);
            }
        } elseif (is_array($aud)) {
            if ($clientId === '' || !in_array($clientId, $aud, true)) {
                return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'aud_mismatch', $correlationId);
            }
        } else {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'invalid_claim_type', $correlationId);
        }

        // 11-13. exp/iat obbligatori, nbf se presente. is_int e' una restrizione del profilo del plugin.
        $now = $this->currentTime();
        $skew = self::USERINFO_CLOCK_SKEW;
        if (!array_key_exists('exp', $payload)) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'exp_missing', $correlationId);
        }
        if (!is_int($payload['exp'])) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'invalid_claim_type', $correlationId);
        }
        if (($now - $skew) >= $payload['exp']) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'expired', $correlationId);
        }
        if (!array_key_exists('iat', $payload)) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'iat_missing', $correlationId);
        }
        if (!is_int($payload['iat'])) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'invalid_claim_type', $correlationId);
        }
        if ($payload['iat'] > ($now + $skew)) {
            return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'iat_future', $correlationId);
        }
        if (array_key_exists('nbf', $payload)) {
            if (!is_int($payload['nbf'])) {
                return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'invalid_claim_type', $correlationId);
            }
            if ($payload['nbf'] > ($now + $skew)) {
                return $this->rejectUserInfo('oidc_userinfo_claims_invalid', 'nbf_future', $correlationId);
            }
        }

        return $payload;
    }

    /**
     * Orologio della verifica UserInfo (sovrascrivibile nei test).
     */
    protected function currentTime(): int {
        return time();
    }

    private function rejectUserInfo(string $code, string $reason, string $correlationId): WP_Error {
        // Solo correlazione e motivo enumerato: mai token, JWS, kid, sub, claim o dati personali.
        $this->logger->error('OIDC userinfo JWS rejected', [
            'correlation_id' => $correlationId,
            'reason'         => $reason,
        ]);
        return new WP_Error($code, __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
    }

    /**
     * Seleziona l'unica chiave di firma utilizzabile per il kid dato.
     *
     * @return array|string JWK minimale {kty, n, e}, oppure il motivo di rifiuto
     *                      ('kid_not_found', 'jwk_unusable', 'kid_ambiguous').
     */
    private function selectUserInfoJwk(array $jwks, string $kid, string $alg) {
        $candidates = 0;
        $usable = [];
        foreach ($jwks['keys'] as $key) {
            if (!is_array($key) || !array_key_exists('kid', $key) || $key['kid'] !== $kid) {
                continue;
            }
            $candidates++;
            $jwk = $this->usableUserInfoJwk($key, $alg);
            if ($jwk !== null) {
                $usable[] = $jwk;
            }
        }

        if ($candidates === 0) {
            return 'kid_not_found';
        }
        if ($usable === []) {
            return 'jwk_unusable';
        }
        if (count($usable) > 1) {
            return 'kid_ambiguous';
        }
        return $usable[0];
    }

    private function usableUserInfoJwk(array $key, string $alg): ?array {
        if (($key['kty'] ?? null) !== 'RSA') {
            return null;
        }
        $n = $key['n'] ?? null;
        $e = $key['e'] ?? null;
        if (!is_string($n) || $n === '' || !is_string($e) || $e === '') {
            return null;
        }
        if (array_key_exists('use', $key) && $key['use'] !== 'sig') {
            return null;
        }
        if (array_key_exists('key_ops', $key) && (!is_array($key['key_ops']) || !in_array('verify', $key['key_ops'], true))) {
            return null;
        }
        if (array_key_exists('alg', $key) && $key['alg'] !== $alg) {
            return null;
        }

        // n/e: base64url, padding finale tollerato (sono metadati di chiave, non il token firmato).
        $n = rtrim($n, '=');
        $e = rtrim($e, '=');
        $modulus = $this->base64urlDecodeStrict($n);
        if ($modulus === null || $this->base64urlDecodeStrict($e) === null) {
            return null;
        }
        $modulus = ltrim($modulus, "\0");
        if ($modulus === '' || ((strlen($modulus) - 1) * 8 + strlen(decbin(ord($modulus[0])))) < self::USERINFO_MIN_RSA_BITS) {
            return null;
        }

        return ['kty' => 'RSA', 'n' => $n, 'e' => $e];
    }

    /**
     * Decodifica un segmento header/payload: base64url stretto e JSON oggetto.
     *
     * @return array|null ['object' => stdClass, 'array' => array], oppure null se non valido.
     */
    private function decodeUserInfoSegment(string $segment): ?array {
        $raw = $this->base64urlDecodeStrict($segment);
        if ($raw === null) {
            return null;
        }
        $object = json_decode($raw, false);
        if (!($object instanceof \stdClass)) {
            return null;
        }
        $array = json_decode($raw, true);
        if (!is_array($array)) {
            return null;
        }
        return ['object' => $object, 'array' => $array];
    }

    /**
     * base64url senza padding e senza caratteri fuori alfabeto; null se non valido.
     */
    private function base64urlDecodeStrict(string $data): ?string {
        if ($data === '' || preg_match('/^[A-Za-z0-9_-]+$/', $data) !== 1 || strlen($data) % 4 === 1) {
            return null;
        }
        $decoded = base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4), true);
        return $decoded === false ? null : $decoded;
    }

    private function fetchJwks(string $jwksUri, string $correlationId) {
        $response = wp_remote_get($jwksUri, ['timeout' => 10, 'redirection' => 2]);
        if (is_wp_error($response)) {
            $this->logger->error('JWKS fetch failed', ['correlation_id' => $correlationId, 'error' => $response->get_error_message()]);
            return new WP_Error('oidc_jwks_fetch_fail', __('Errore rete durante verifica token.', 'wp-spid-cie'));
        }

        $status = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        if ($status !== 200 || empty($body)) {
            return new WP_Error('oidc_jwks_http_fail', __('JWKS non disponibile.', 'wp-spid-cie'));
        }

        $json = json_decode($body, true);
        if (!is_array($json) || empty($json['keys']) || !is_array($json['keys'])) {
            return new WP_Error('oidc_jwks_invalid', __('JWKS non valido.', 'wp-spid-cie'));
        }

        return $json;
    }

    private function findJwk(array $jwks, string $kid): ?array {
        foreach ($jwks['keys'] as $key) {
            if (!is_array($key)) {
                continue;
            }
            if (!empty($kid) && ($key['kid'] ?? '') !== $kid) {
                continue;
            }
            if (($key['kty'] ?? '') === 'RSA' && !empty($key['n']) && !empty($key['e'])) {
                return $key;
            }
        }

        return null;
    }

    private function verifySignature(string $signedData, string $signature, array $jwk, string $alg): bool {
        try {
            $key = \phpseclib3\Crypt\PublicKeyLoader::load(wp_json_encode($jwk));
            $rsa = $key->withHash('sha256');

            if ($alg === 'PS256') {
                $rsa = $rsa->withPadding(\phpseclib3\Crypt\RSA::SIGNATURE_PSS);
            } else {
                $rsa = $rsa->withPadding(\phpseclib3\Crypt\RSA::SIGNATURE_PKCS1);
            }

            return $rsa->verify($signedData, $signature);
        } catch (\Throwable $e) {
            $this->logger->error('ID token signature verification error', ['error' => $e->getMessage()]);
            return false;
        }
    }

    private function decodePart(string $part): ?array {
        $decoded = $this->base64urlDecode($part);
        if ($decoded === false) {
            return null;
        }

        $json = json_decode($decoded, true);
        return is_array($json) ? $json : null;
    }

    private function base64urlDecode(string $data) {
        $data = strtr($data, '-_', '+/');
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }
        return base64_decode($data);
    }

    private function validateAcrPolicy(array $payload, array $providerConfig) {
        $minAcr = isset($providerConfig['min_acr']) ? trim((string) $providerConfig['min_acr']) : '';
        if ($minAcr === '') {
            return true;
        }

        $allowMissing = !empty($providerConfig['allow_missing_acr']);
        $actualAcr = isset($payload['acr']) ? (string) $payload['acr'] : '';

        if ($actualAcr === '') {
            if ($allowMissing) {
                return true;
            }
            return new WP_Error('oidc_missing_acr', __('Livello di autenticazione non presente.', 'wp-spid-cie'));
        }

        if (!$this->isAcrAtLeast($actualAcr, $minAcr)) {
            return new WP_Error('oidc_acr_too_low', __('Livello di autenticazione insufficiente.', 'wp-spid-cie'));
        }

        return true;
    }

    private function isAcrAtLeast(string $actual, string $min): bool {
        $actualLevel = $this->extractLoaLevel($actual);
        $minLevel = $this->extractLoaLevel($min);

        if ($actualLevel !== null && $minLevel !== null) {
            return $actualLevel >= $minLevel;
        }

        return strtolower($actual) === strtolower($min);
    }

    private function extractLoaLevel(string $acr): ?int {
        if (preg_match('/(?:spidl?|loa)\s*([1-3])$/i', $acr, $m)) {
            return intval($m[1]);
        }
        if (preg_match('/\/SpidL([1-3])$/i', $acr, $m)) {
            return intval($m[1]);
        }
        return null;
    }

}
