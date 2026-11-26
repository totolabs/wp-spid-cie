<?php
defined( 'ABSPATH' ) || exit;

/**
 * Handles the OIDC authorization code flow with PKCE.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_OidcClient {
    private $pkce;
    private $stateStore;
    private $tokenValidator;
    private $logger;

    /**
     * @since 1.0.0
     * @param WP_SPID_CIE_OIDC_PkceService              $pkce
     * @param WP_SPID_CIE_OIDC_StateNonceStoreInterface $stateStore
     * @param WP_SPID_CIE_OIDC_TokenValidator           $tokenValidator
     * @param WP_SPID_CIE_OIDC_Logger                   $logger
     */
    public function __construct(
        WP_SPID_CIE_OIDC_PkceService $pkce,
        WP_SPID_CIE_OIDC_StateNonceStoreInterface $stateStore,
        WP_SPID_CIE_OIDC_TokenValidator $tokenValidator,
        WP_SPID_CIE_OIDC_Logger $logger
    ) {
        $this->pkce = $pkce;
        $this->stateStore = $stateStore;
        $this->tokenValidator = $tokenValidator;
        $this->logger = $logger;
    }

    /**
     * Builds the OIDC authorization URL with PKCE and stores the state context.
     *
     * @since  1.0.0
     * @param  array  $providerConfig Resolved provider configuration.
     * @param  string $targetUrl      URL to redirect to after successful login.
     * @param  string $correlationId  Unique request identifier for logging.
     * @return string|WP_Error Authorization URL, or error.
     */
    public function buildAuthorizationUrl(array $providerConfig, string $targetUrl, string $correlationId, ?callable $requestObjectSigner = null) {
        // Il provider deve arrivare esplicito dal profilo: nessun fallback implicito.
        if (empty($providerConfig['provider']) || !is_string($providerConfig['provider'])) {
            return new WP_Error('oidc_provider_not_configured', __('Provider non configurato.', 'wp-spid-cie'));
        }

        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $verifier = $this->pkce->generateVerifier();
        $challenge = $this->pkce->generateChallenge($verifier);

        $ctx = [
            'created_at' => time(),
            'nonce' => $nonce,
            'code_verifier' => $verifier,
            'provider' => $providerConfig['provider'],
            'target_url' => $targetUrl,
            'issuer' => $providerConfig['issuer'] ?? '',
            'correlation_id' => $correlationId,
        ];

        if (!$this->stateStore->store($state, $ctx, 600)) {
            return new WP_Error('oidc_state_store_fail', __('Errore temporaneo di sicurezza.', 'wp-spid-cie'));
        }

        $params = [
            'client_id' => $providerConfig['client_id'],
            'response_type' => 'code',
            'redirect_uri' => $providerConfig['redirect_uri'],
            'scope' => $providerConfig['scope'] ?? 'openid',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => $this->pkce->getChallengeMethod(),
        ];

        if (!empty($providerConfig['acr_values'])) {
            $params['acr_values'] = $providerConfig['acr_values'];
        }

        $authorizationEndpoint = $providerConfig['authorization_endpoint'] ?? '';
        if (!$authorizationEndpoint) {
            return new WP_Error('oidc_no_auth_endpoint', __('Endpoint di autorizzazione non configurato.', 'wp-spid-cie'));
        }

        if ($requestObjectSigner !== null) {
            $provider   = $providerConfig['provider'] ?? '';
            // Per spec SPID/CIE OIDC (Authorization Endpoint, tabella claim del request object)
            // il payload non prevede il claim "sub". Includendolo, e per di piu' con valore
            // uguale a client_id, il CIE OP rifiuta la richiesta. Riferimento:
            // https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/authorization_endpoint.html
            $ro_payload = array_merge($params, [
                'iss'    => $providerConfig['client_id'],
                'aud'    => [$providerConfig['issuer'] ?? $authorizationEndpoint],
                'iat'    => time(),
                'exp'    => time() + 300,
                'prompt' => 'consent login',
            ]);

            if ($provider === 'cie') {
                $userinfoClaims = [
                    'given_name'                                   => ['essential' => true],
                    'family_name'                                  => ['essential' => true],
                    'https://attributes.eid.gov.it/fiscal_number' => ['essential' => true],
                ];
                // CIE: phone_number best-effort. email NON richiesta nemmeno come
                // non-essential perche' la sua presenza nel set di claim della authz
                // request fa rispondere al CIE OP "unauthorized_client" al code
                // exchange (riprodotto in produzione).
                $userinfoClaims['phone_number'] = ['essential' => false];
                $ro_payload['claims'] = ['userinfo' => $userinfoClaims];
            }

            try {
                $request_jwt = $requestObjectSigner($ro_payload);
            } catch (\Throwable $e) {
                // Nessun payload/JWT/path/materiale di chiave nel log: solo correlazione e classe errore.
                $this->logger->error('OIDC request object signing failed', [
                    'correlation_id' => $correlationId,
                    'error_class' => get_class($e),
                ]);
                return new WP_Error('oidc_signing_key_unavailable', __('Servizio di autenticazione temporaneamente non disponibile.', 'wp-spid-cie'));
            }
            $outer = [
                'client_id'             => $providerConfig['client_id'],
                'response_type'         => 'code',
                'scope'                 => $providerConfig['scope'] ?? 'openid',
                'code_challenge'        => $params['code_challenge'],
                'code_challenge_method' => $params['code_challenge_method'],
                'request'               => $request_jwt,
            ];
            return $authorizationEndpoint . '?' . http_build_query($outer);
        }

        return $authorizationEndpoint . '?' . http_build_query($params);
    }

    /**
     * Handles the OIDC callback: validates state, exchanges code, validates id_token.
     *
     * @since  1.0.0
     * @param  array $request        Callback query parameters (state, code, error).
     * @param  array $providerConfig Resolved provider configuration.
     * @return array|WP_Error Validated claims and state context, or error.
     */
    public function handleCallback(array $request, array $providerConfig, ?callable $clientAssertionSigner = null, ?callable $userInfoJweDecrypter = null) {
        $correlationId = $request['correlation_id'] ?? $this->logger->generateCorrelationId();

        if (!empty($request['error'])) {
            $code = sanitize_key($request['error']);
            $this->logger->warn('OIDC callback provider error', ['correlation_id' => $correlationId, 'code' => $code]);
            return new WP_Error('oidc_provider_error', __('Accesso annullato o non autorizzato.', 'wp-spid-cie'));
        }

        $state = isset($request['state']) ? sanitize_text_field(wp_unslash($request['state'])) : '';
        $code = isset($request['code']) ? sanitize_text_field(wp_unslash($request['code'])) : '';

        if (empty($state) || empty($code)) {
            return new WP_Error('oidc_missing_callback_params', __('Risposta di autenticazione non valida.', 'wp-spid-cie'));
        }

        $stateCtx = $this->stateStore->consume($state);
        if (!$stateCtx || !is_array($stateCtx)) {
            $this->logger->error('OIDC state mismatch/expired', ['correlation_id' => $correlationId]);
            return new WP_Error('oidc_state_mismatch', __('Sessione di autenticazione non valida o scaduta.', 'wp-spid-cie'));
        }

        $tokenResponse = $this->exchangeCodeForTokens($code, $stateCtx['code_verifier'], $providerConfig, $correlationId, $clientAssertionSigner);
        if (is_wp_error($tokenResponse)) {
            return $tokenResponse;
        }

        $idToken = $tokenResponse['id_token'] ?? '';
        if (empty($idToken)) {
            return new WP_Error('oidc_no_id_token', __('Token di identità assente nella risposta.', 'wp-spid-cie'));
        }

        $payload = $this->tokenValidator->validateIdToken($idToken, $providerConfig, $stateCtx['nonce'], $correlationId);
        if (is_wp_error($payload)) {
            $this->logger->error('OIDC id_token validation failed', [
                'correlation_id' => $correlationId,
                'error_code' => $payload->get_error_code(),
            ]);
            return $payload;
        }

        // OIDC Core 1.0 par. 5.3.2 e regole tecniche SPID/CIE OIDC: il sub della UserInfo DEVE
        // coincidere con quello dell'ID Token validato. Serve quindi un sub dell'ID Token valido
        // (valore originale, stringa non vuota) PRIMA di richiedere la UserInfo.
        $idTokenSubIssue = $this->getSubjectIssue($payload);
        if ($idTokenSubIssue !== null) {
            $this->logger->error('OIDC id_token subject invalid', [
                'correlation_id' => $correlationId,
                'reason'         => $idTokenSubIssue,
            ]);
            return new WP_Error('oidc_id_token_sub_invalid', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        // L'id_token CIE contiene solo sub + claim JWT standard. Gli attributi utente
        // (given_name, family_name, fiscal_number, email, phone_number) sono nella
        // userinfo, che CIE restituisce come JWE cifrato con la chiave pubblica del SP.
        $accessToken    = (string) ($tokenResponse['access_token'] ?? '');
        $userInfoClaims = $this->fetchUserInfo($accessToken, $providerConfig, $correlationId, $userInfoJweDecrypter, $payload['sub']);
        if (is_wp_error($userInfoClaims)) {
            // UserInfo ottenuta ma di un soggetto diverso o senza sub valido: nessun claim va usato.
            return $userInfoClaims;
        }

        $claims = array_merge($payload, $userInfoClaims);
        if (!empty($payload['sub'])) {
            // sub autoritativo dall'id_token, non sovrascrivibile dalla userinfo
            $claims['sub'] = $payload['sub'];
        }

        return [
            'claims' => $claims,
            'state_context' => $stateCtx,
            'correlation_id' => $correlationId,
        ];
    }

    /**
     * Recupera i claim utente dal /userinfo endpoint.
     *
     * Regole tecniche SPID/CIE OIDC: la UserInfo e' un Nested JWT, JWS firmato dall'OP e cifrato in
     * JWE verso la chiave pubblica del RP. E' l'unica forma accettata: JSON in chiaro, JWE con JSON
     * non firmato e JWS non cifrato vengono rifiutati (la JWE da sola non autentica l'OP). Il JWE e'
     * aperto dal decrypter del SP; il JWS interno e' verificato da TokenValidator::validateUserInfoJws
     * (firma con la chiave del jwks_uri configurato, iss/aud/exp/iat/nbf). Solo dopo, il sub deve
     * coincidere esattamente con $expectedSub (sub dell'ID Token validato).
     *
     * Limite preesistente, invariato: i rami in cui la UserInfo non e' ottenuta (token o endpoint
     * vuoti, errore HTTP, stato non 2xx, corpo vuoto, nessun decrypter, decifratura fallita)
     * restituiscono [] e non un WP_Error; il rifiuto resta affidato ai claim obbligatori a valle.
     *
     * @return array|WP_Error Claim UserInfo verificati, [] se non ottenuta, WP_Error se rifiutata.
     */
    private function fetchUserInfo(string $accessToken, array $providerConfig, string $correlationId, ?callable $userInfoJweDecrypter, string $expectedSub) {
        if ($accessToken === '') {
            return [];
        }
        $endpoint = (string) ($providerConfig['userinfo_endpoint'] ?? '');
        if ($endpoint === '') {
            return [];
        }

        $response = wp_remote_get($endpoint, [
            'timeout'     => 15,
            'redirection' => 2,
            'headers'     => [
                'Authorization' => 'Bearer ' . $accessToken,
                'Accept'        => 'application/jwt, application/json',
            ],
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('OIDC userinfo http error', [
                'correlation_id' => $correlationId,
                'error'          => $response->get_error_message(),
            ]);
            return [];
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $body   = trim((string) wp_remote_retrieve_body($response));

        if ($status < 200 || $status >= 300 || $body === '') {
            return [];
        }

        // Solo JWE -> JWS: ogni altra forma ottenuta e' rifiutata, senza fallback.
        if ($body[0] === '{') {
            return $this->rejectUserInfoFormat('plain_json', $correlationId);
        }
        $parts = explode('.', $body);
        if (count($parts) === 3) {
            return $this->rejectUserInfoFormat('unencrypted_jws', $correlationId);
        }
        if (count($parts) !== 5) {
            return $this->rejectUserInfoFormat('unknown_format', $correlationId);
        }

        if ($userInfoJweDecrypter === null) {
            $this->logger->error('OIDC userinfo received JWE but no decrypter configured', [
                'correlation_id' => $correlationId,
            ]);
            return [];
        }
        try {
            $inner = (string) $userInfoJweDecrypter($body);
        } catch (\Throwable $e) {
            $this->logger->error('OIDC userinfo JWE decrypt failed', [
                'correlation_id' => $correlationId,
                'error'          => $e->getMessage(),
            ]);
            return [];
        }

        // JSON cifrato ma non firmato: chiunque conosca la chiave pubblica del RP puo' produrlo.
        $inner = trim($inner);
        if ($inner !== '' && $inner[0] === '{') {
            return $this->rejectUserInfoFormat('unsigned_payload', $correlationId);
        }

        $json = $this->tokenValidator->validateUserInfoJws($inner, $providerConfig, $correlationId);
        if (is_wp_error($json)) {
            return $json;
        }

        // Raggiunto solo con JWS interno verificato (firma e claim):
        // confronto esatto (===) sul valore originale, senza trim/sanitize/normalizzazioni.
        $subjectIssue = $this->getSubjectIssue($json);
        if ($subjectIssue === null && $json['sub'] !== $expectedSub) {
            $subjectIssue = 'mismatch';
        }
        if ($subjectIssue !== null) {
            // Nessun sub, claim, codice fiscale, token o contenuto della UserInfo nel log.
            $this->logger->error('OIDC userinfo subject rejected', [
                'correlation_id' => $correlationId,
                'reason'         => $subjectIssue,
            ]);
            return new WP_Error('oidc_userinfo_subject_invalid', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        return $json;
    }

    /**
     * Motivo per cui il claim sub non e' utilizzabile, oppure null se e' una stringa non vuota.
     *
     * @return string|null 'missing', 'invalid_type', 'empty' oppure null.
     */
    private function getSubjectIssue(array $claims): ?string {
        if (!array_key_exists('sub', $claims)) {
            return 'missing';
        }
        if (!is_string($claims['sub'])) {
            return 'invalid_type';
        }
        if ($claims['sub'] === '') {
            return 'empty';
        }
        return null;
    }

    private function rejectUserInfoFormat(string $reason, string $correlationId): WP_Error {
        // Nessun token, JWS, claim o contenuto della UserInfo nel log: solo correlazione e motivo.
        $this->logger->error('OIDC userinfo format rejected', [
            'correlation_id' => $correlationId,
            'reason'         => $reason,
        ]);
        return new WP_Error('oidc_userinfo_format_invalid', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
    }

    private function exchangeCodeForTokens(string $code, string $codeVerifier, array $providerConfig, string $correlationId, ?callable $clientAssertionSigner = null) {
        $tokenEndpoint = $providerConfig['token_endpoint'] ?? '';
        if (empty($tokenEndpoint)) {
            return new WP_Error('oidc_no_token_endpoint', __('Endpoint token non configurato.', 'wp-spid-cie'));
        }

        // redirect_uri ripristinato: e' prescritto da RFC 6749 §4.1.3 e non e' la
        // causa di unauthorized_client (test del 2026-05-29 14:46 con body privo di
        // redirect_uri ha riprodotto lo stesso errore). La tabella della spec AgID
        // (token_endpoint.html) lo omette, ma e' un'omissione del documento: il
        // redirect_uri al code exchange e' standard OAuth2 e va incluso.
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $providerConfig['redirect_uri'],
            'client_id' => $providerConfig['client_id'],
            'code_verifier' => $codeVerifier,
        ];

        // CIE/SPID OIDC: token endpoint auth method = private_key_jwt (spec token_endpoint).
        // client_assertion JWT con sub == iss == client_id (qui obbligatorio,
        // a differenza del request object dell'authorization request).
        if ($clientAssertionSigner !== null) {
            $now = time();
            $ca_payload = [
                'iss' => $providerConfig['client_id'],
                'sub' => $providerConfig['client_id'],
                'aud' => $tokenEndpoint,
                'iat' => $now,
                'exp' => $now + 300,
                'jti' => wp_generate_uuid4(),
            ];
            try {
                $client_assertion = $clientAssertionSigner($ca_payload);
            } catch (\Throwable $e) {
                // Il token endpoint NON viene contattato. Nessun code/verifier/assertion/token nel log.
                $this->logger->error('OIDC client assertion signing failed', [
                    'correlation_id' => $correlationId,
                    'error_class' => get_class($e),
                ]);
                return new WP_Error('oidc_signing_key_unavailable', __('Servizio di autenticazione temporaneamente non disponibile.', 'wp-spid-cie'));
            }
            $body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $body['client_assertion']      = $client_assertion;
        }

        $response = wp_remote_post($tokenEndpoint, [
            'timeout' => 15,
            'redirection' => 2,
            'headers' => ['Accept' => 'application/json'],
            'body' => $body,
        ]);

        if (is_wp_error($response)) {
            $this->logger->error('OIDC token request failed', [
                'correlation_id' => $correlationId,
                'error' => $response->get_error_message(),
            ]);
            return new WP_Error('oidc_token_http_error', __('Errore di rete durante autenticazione.', 'wp-spid-cie'));
        }

        $status = wp_remote_retrieve_response_code($response);
        $rawBody = wp_remote_retrieve_body($response);
        $json = json_decode($rawBody, true);

        if ($status < 200 || $status >= 300 || !is_array($json)) {
            $this->logger->error('OIDC token endpoint invalid response', [
                'correlation_id' => $correlationId,
                'http_status'    => $status,
            ]);
            return new WP_Error('oidc_token_bad_response', __('Risposta non valida dal servizio di autenticazione.', 'wp-spid-cie'));
        }

        return $json;
    }
}
