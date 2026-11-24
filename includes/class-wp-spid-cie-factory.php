<?php
defined( 'ABSPATH' ) || exit;

/**
 * Factory for creating and configuring the OIDC client instance.
 * Wrapper for the SPID_CIE_OIDC_PHP library.
 *
 * @package    WP_SPID_CIE_OIDC
 * @subpackage WP_SPID_CIE_OIDC/includes
 */

// Path relativo al file (equivalente a plugin_dir_path(dirname(__FILE__))): la Factory deve poter essere
// caricata on demand dai consumer SAML anche prima che le funzioni WordPress siano disponibili.
if ( file_exists( dirname( __DIR__ ) . '/vendor/autoload.php' ) ) {
    require_once dirname( __DIR__ ) . '/vendor/autoload.php';
}

use SPID_CIE_OIDC_PHP\Core\Util;

/**
 * Factory for creating and configuring the OIDC client instance.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_Factory {

    private static $runtime_services = null;
    private static $provider_registry = null;

    /**
     * Builds and returns a configured WP_SPID_CIE_OIDC_Wrapper instance.
     *
     * @since  1.0.0
     * @return WP_SPID_CIE_OIDC_Wrapper
     */
    public static function get_client() {
        $options = get_option('wp-spid-cie_options');
        
        $issuer_override = isset($options['issuer_override']) ? trim((string) $options['issuer_override']) : '';
        $base_source = $issuer_override !== '' ? $issuer_override : home_url();
        $base_url = untrailingslashit(set_url_scheme((string) $base_source, 'https'));

        $entity_id_override = isset($options['entity_id']) ? trim((string) $options['entity_id']) : '';
        $entity_id_source = $entity_id_override !== '' ? $entity_id_override : ($issuer_override !== '' ? $issuer_override : home_url('/'));
        $entity_id = untrailingslashit(set_url_scheme((string) $entity_id_source, 'https'));

        $config = [
            'organization_name' => $options['organization_name'] ?? get_bloginfo('name'),
            'ipa_code'          => $options['ipa_code'] ?? '',
            'fiscal_number'     => $options['fiscal_number'] ?? '',
            'contacts_email'    => $options['contacts_email'] ?? get_option('admin_email'),
            'logo_uri'          => isset($options['logo_uri']) ? esc_url_raw((string) $options['logo_uri']) : '',
            'spid_saml_locality_name' => $options['spid_saml_locality_name'] ?? '',
            'base_url'          => $base_url,
            'entity_id'         => $entity_id,
			'cie_trust_anchor_preprod' => $options['cie_trust_anchor_preprod'] ?? '',
			'cie_trust_anchor_prod'    => $options['cie_trust_anchor_prod'] ?? '',
			'cie_trust_mark_preprod' => $options['cie_trust_mark_preprod'] ?? '',
			'cie_trust_mark_prod'    => $options['cie_trust_mark_prod'] ?? '',
			'spid_enabled' => !empty($options['spid_enabled']) && $options['spid_enabled'] === '1',
			'cie_enabled'  => !empty($options['cie_enabled']) && $options['cie_enabled'] === '1'
        ];

        $config['key_dir'] = self::resolve_spid_key_dir();

        return new WP_SPID_CIE_OIDC_Wrapper($config);
    }

    /**
     * Resolves the filesystem path to the plugin key directory.
     *
     * The ONLY runtime key identity is the primary directory uploads/wp-spid-cie-keys: the legacy
     * uploads/spid-cie-oidc-keys is never used as a key source (no automatic fallback), so a damaged
     * or missing primary pair can never silently switch the published identity (kid/certificate).
     *
     * @since  1.0.0
     * @param  bool $for_generation false = pure read: no directory or file is created.
     *                              true  = generation path: creates the primary dir and its .htaccess if missing.
     * @return string Absolute path to the primary key directory (always the same identity).
     */
    public static function resolve_spid_key_dir(bool $for_generation = false): string {
        $upload_dir = wp_upload_dir(null, $for_generation);
        $primary_dir = trailingslashit($upload_dir['basedir']) . 'wp-spid-cie-keys';

        if (!$for_generation) {
            return $primary_dir;
        }

        if (!is_dir($primary_dir)) {
            wp_mkdir_p($primary_dir);
        }

        $htaccess_file = trailingslashit($primary_dir) . '.htaccess';
        if (!file_exists($htaccess_file)) {
            @file_put_contents($htaccess_file, "Deny from all\n");
        }

        return $primary_dir;
    }

    /**
     * Returns (and lazily initialises) the shared OIDC runtime services.
     *
     * @since  1.0.0
     * @return array Associative map: logger, oidc_client, user_mapper, auth_service.
     */
    public static function get_runtime_services() {
        if (is_array(self::$runtime_services)) {
            return self::$runtime_services;
        }

        $logger = new WP_SPID_CIE_OIDC_Logger('OIDC');
        $pkce = new WP_SPID_CIE_OIDC_PkceService();
        $store = new WP_SPID_CIE_OIDC_TransientStateNonceStore();
        $validator = new WP_SPID_CIE_OIDC_TokenValidator($logger);
        $client = new WP_SPID_CIE_OIDC_OidcClient($pkce, $store, $validator, $logger);
        $userMapper = new WP_SPID_CIE_OIDC_WpUserMapper($logger);
        $authService = new WP_SPID_CIE_OIDC_WpAuthService($logger);

        self::$runtime_services = [
            'logger' => $logger,
            'oidc_client' => $client,
            'user_mapper' => $userMapper,
            'auth_service' => $authService,
        ];

        return self::$runtime_services;
    }

    /**
     * Returns (and lazily initialises) the shared provider registry.
     *
     * @since  1.0.0
     * @return WP_SPID_CIE_OIDC_ProviderRegistry
     */
    public static function get_provider_registry() {
        if (self::$provider_registry instanceof WP_SPID_CIE_OIDC_ProviderRegistry) {
            return self::$provider_registry;
        }

        $runtime = self::get_runtime_services();
        $logger = $runtime['logger'];
        $wrapper = self::get_client();
        $resolver = new WP_SPID_CIE_OIDC_DiscoveryResolver($logger);

        self::$provider_registry = new WP_SPID_CIE_OIDC_ProviderRegistry($resolver, $wrapper);
        return self::$provider_registry;
    }
}

/**
 * Coppia chiave privata/certificato del plugin non utilizzabile (assente, parziale, invalida o incoerente).
 * Il messaggio e' fisso e generico: non contiene mai path, PEM o dettagli OpenSSL/phpseclib e non va
 * usato come body HTTP.
 *
 * @since 1.4.2
 */
class WP_SPID_CIE_OIDC_Key_Unavailable_Exception extends \RuntimeException {
    public function __construct() {
        parent::__construct('Coppia chiave/certificato del plugin non disponibile.');
    }
}

/**
 * Wraps SPID/CIE provider configuration and JWT-signing operations.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_Wrapper {

    private $config;

    /**
     * @since 1.0.0
     * @param array $config Configuration map (base_url, entity_id, key_dir, etc.).
     */
    public function __construct($config) {
        $this->config = $config;
    }

    /**
     * Generates SPID-compliant key/certificate pair and updates the key_dir config.
     *
     * @since  1.0.0
     * @return true
     * @throws Exception On generation failure.
     */
	public function generateKeys() {
		$result = WP_SPID_CIE_OIDC_Spid_Certificates::generate($this->config, true);
		if (!$result['success']) {
			throw new Exception(implode(' ', $result['errors']));
		}

		$this->config['key_dir'] = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(true);
		return true;
	}

    /**
     * Returns the JWK Set JSON string for the entity's signing key.
     *
     * @since  1.0.0
     * @return string JSON-encoded JWK Set.
     */
    public function getJwks() {
        $this->assert_usable_key_pair();
        $jwk_item = $this->buildJwkItem();
        $jwks = ['keys' => [$jwk_item]];
        return json_encode($jwks);
    }

    /**
     * Builds and signs the OpenID Federation entity statement JWT.
     *
     * @since  1.0.0
     * @return string Compact entity-statement+jwt.
     * @throws Exception On signing or key-loading failure.
     */
    public function getEntityStatement() {
        $this->assert_usable_key_pair();
        $now = time();
        $exp = $now + 21600; // 6 hours
        $sub = $this->getEntityId();
        if ($sub === '') {
            throw new Exception('Issuer base_url non configurato');
        }

        $jwk_item = $this->buildJwkItem();
        $jwks_structure = ['keys' => [$jwk_item]];

        $endpoint_base = untrailingslashit((string) ($this->config['base_url'] ?? $sub));
        $rp_metadata = [
            "application_type" => "web",
            "client_id" => $sub,
            "client_registration_types" => ["automatic"],
            "jwks" => $jwks_structure,
            "client_name" => $this->config['organization_name'],
            "contacts" => [$this->config['contacts_email']],
            "grant_types" => ["authorization_code", "refresh_token"],
            "redirect_uris" => [
                add_query_arg(['oidc_action' => 'callback', 'provider' => 'cie'], trailingslashit($endpoint_base))
            ],
            "response_types" => ["code"],
            "subject_type" => "pairwise",
            "id_token_signed_response_alg" => "RS256",
            "userinfo_signed_response_alg" => "RS256",
            "userinfo_encrypted_response_alg" => "RSA-OAEP",
            "userinfo_encrypted_response_enc" => "A256CBC-HS512",
            "token_endpoint_auth_method" => "private_key_jwt",
            "token_endpoint_auth_signing_alg" => "RS256"
        ];

        $payload = [
            "iss" => $sub,
            "sub" => $sub,
            "iat" => $now,
            "exp" => $exp,
            "jwks" => $jwks_structure,
            "metadata" => [
                "openid_relying_party" => $rp_metadata,
                "federation_entity" => $this->buildFederationEntityMetadata($endpoint_base)
            ]
        ];

        $authority_hints = $this->buildAuthorityHints();
        if (!empty($authority_hints)) {
            $payload['authority_hints'] = $authority_hints;
        }

        $trust_marks = $this->buildTrustMarks();
        if (!empty($trust_marks)) {
            $payload['trust_marks'] = $trust_marks;
        }

        return $this->signJwt($payload);
    }

    /**
     * Builds and signs the OpenID Federation /resolve response JWT.
     *
     * @since  1.0.0
     * @param  string $sub          Entity identifier to resolve (defaults to own entity ID).
     * @param  string $trust_anchor Trust anchor URI included in the payload.
     * @return string Compact resolve-response+jwt.
     * @throws Exception On signing or key-loading failure.
     */
    public function getResolveResponse($sub = '', $trust_anchor = '') {
        $this->assert_usable_key_pair();
        $base_sub = $this->getEntityId();
        if ($base_sub === '') {
            throw new Exception('Issuer base_url non configurato');
        }

        $resolved_sub = $this->normalizeEntityIdentifier((string) $sub);
        if ($resolved_sub === '') {
            $resolved_sub = $base_sub;
        }

        $now = time();
        $exp = $now + 21600;
        $jwk_item = $this->buildJwkItem();
        $jwks_structure = ['keys' => [$jwk_item]];

        $endpoint_base = untrailingslashit((string) ($this->config['base_url'] ?? $base_sub));

        $payload = [
            'iss' => $base_sub,
            'sub' => $resolved_sub,
            'iat' => $now,
            'exp' => $exp,
            'jwks' => $jwks_structure,
            'metadata' => [
                'openid_relying_party' => [
                    'application_type' => 'web',
                    'client_id' => $base_sub,
                    'client_registration_types' => ['automatic'],
                    'jwks' => $jwks_structure,
                    'client_name' => $this->config['organization_name'],
                    'contacts' => [$this->config['contacts_email']],
                    'grant_types' => ['authorization_code', 'refresh_token'],
                    'redirect_uris' => [
                        add_query_arg(['oidc_action' => 'callback', 'provider' => 'cie'], trailingslashit($endpoint_base))
                    ],
                    'response_types' => ['code'],
                    'subject_type' => 'pairwise',
                    'id_token_signed_response_alg' => 'RS256',
                    'userinfo_signed_response_alg' => 'RS256',
                    'userinfo_encrypted_response_alg' => 'RSA-OAEP',
                    'userinfo_encrypted_response_enc' => 'A256CBC-HS512',
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'token_endpoint_auth_signing_alg' => 'RS256'
                ],
                'federation_entity' => $this->buildFederationEntityMetadata($endpoint_base)
            ]
        ];

        $ta = trim((string) $trust_anchor);
        if ($ta !== '') {
            $payload['trust_anchor'] = untrailingslashit($ta);
        }

        $trust_marks = $this->buildTrustMarks();
        if (!empty($trust_marks)) {
            $payload['trust_marks'] = $trust_marks;
        }

        $trust_chain = $this->buildTrustChain();
        if (!empty($trust_chain)) {
            $payload['trust_chain'] = $trust_chain;
        }

        return $this->signGenericJwt($payload, 'resolve-response+jwt');
    }


    /**
     * Returns the normalized entity identifier (iss/sub/client_id).
     *
     * @since  1.0.0
     * @return string Entity ID without trailing slash, or empty string if not configured.
     */
    public function getEntityId() {
        $entity_id = $this->normalizeEntityIdentifier((string) ($this->config['entity_id'] ?? ''));
        if ($entity_id !== '') {
            return $entity_id;
        }
        return $this->normalizeEntityIdentifier((string) ($this->config['base_url'] ?? ''));
    }

    /**
     * Stub for UserInfo endpoint support (not currently used).
     *
     * @since  1.0.0
     * @param  array $get_params Request parameters.
     * @return array Empty array (placeholder).
     */
    public function getUserInfo($get_params) {
        return [];
    }

    // --- Private Helpers ---

    private function buildJwkItem() {
        $crt_content = @file_get_contents($this->config['key_dir'] . '/public.crt');
        if (!is_string($crt_content) || $crt_content === '') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }
        $key = \phpseclib3\Crypt\PublicKeyLoader::load($crt_content);
        $jwk_native = json_decode($key->toString('JWK'), true);
        if (isset($jwk_native['keys'][0])) $jwk_native = $jwk_native['keys'][0];
        $jwk = [
            'kty' => 'RSA', 'n' => $jwk_native['n'], 'e' => $jwk_native['e'], 
            'alg' => 'RS256', 'use' => 'sig', 'kid' => $this->getKid()
        ];

        $x5c = $this->buildX5cFromCertificate();
        if (!empty($x5c)) {
            $jwk['x5c'] = [$x5c];
            $der = base64_decode($x5c);
            if ($der !== false) {
                $jwk['x5t#S256'] = $this->base64url_encode(hash('sha256', $der, true));
            }
        }

        return $jwk;
    }

    // Sign Metadata (entity-statement+jwt)
    private function signJwt($payload) {
        return $this->signGenericJwt($payload, 'entity-statement+jwt');
    }

    // Sign Request Object — typ "oauth-authz-req+jwt" per RFC 9101 (JAR).
    // Il precedente cambio a "entity-statement+jwt" (commit 833a8ad) era basato su
    // un'interpretazione errata: la causa di "La sessione non e' piu' valida" del
    // CIE OP era il claim "sub" nel payload (rimosso in 4141bb1), non il typ. Lasciare
    // entity-statement+jwt qui causa unauthorized_client al code exchange (riprodotto
    // in produzione).
    public function signRequestObject(array $payload): string {
        $this->assert_usable_key_pair();
        return $this->signGenericJwt($payload, 'oauth-authz-req+jwt');
    }

    // Sign client_assertion (private_key_jwt) per token endpoint CIE/SPID OIDC
    public function signClientAssertion(array $payload): string {
        $this->assert_usable_key_pair();
        return $this->signGenericJwt($payload, 'JWT');
    }

    /**
     * Decifra una userinfo JWE inviata dal CIE OP usando la chiave privata RSA del SP.
     * CIE pubblica entity config con userinfo_encrypted_response_alg=RSA-OAEP e
     * userinfo_encrypted_response_enc=A256CBC-HS512 (policy registry consente anche
     * RSA-OAEP-256 / A128CBC-HS256). Ritorna il payload del JWS interno (compact form).
     *
     * @throws WP_SPID_CIE_OIDC_Key_Unavailable_Exception se la coppia di chiavi non e' utilizzabile.
     * @throws \Exception su decryption fallita.
     */
    public function decryptUserInfoJwe(string $jwe): string {
        $this->assert_usable_key_pair();
        $privateKeyPem = @file_get_contents($this->config['key_dir'] . '/private.key');
        if (!is_string($privateKeyPem) || $privateKeyPem === '') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }

        $jwk = \Jose\Component\KeyManagement\JWKFactory::createFromKey($privateKeyPem);

        $keyEncAlgorithms = new \Jose\Component\Core\AlgorithmManager([
            new \Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP(),
            new \Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256(),
        ]);
        $contentEncAlgorithms = new \Jose\Component\Core\AlgorithmManager([
            new \Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512(),
            new \Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256(),
        ]);
        $compressionManager = new \Jose\Component\Encryption\Compression\CompressionMethodManager([]);

        $jweDecrypter = new \Jose\Component\Encryption\JWEDecrypter(
            $keyEncAlgorithms,
            $contentEncAlgorithms,
            $compressionManager
        );

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();
        $jweObject  = $serializer->unserialize($jwe);

        if (!$jweDecrypter->decryptUsingKey($jweObject, $jwk, 0)) {
            throw new \Exception('JWE decryption failed');
        }

        return (string) $jweObject->getPayload();
    }

    private function signGenericJwt($payload, $typ) {
        $privateKeyContent = @file_get_contents($this->config['key_dir'] . '/private.key');
        if (!is_string($privateKeyContent) || $privateKeyContent === '') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }
        $rsa = \phpseclib3\Crypt\RSA::load($privateKeyContent);
        $rsa = $rsa->withHash('sha256')->withPadding(\phpseclib3\Crypt\RSA::SIGNATURE_PKCS1);

        $header = ['typ' => $typ, 'alg' => 'RS256', 'kid' => $this->getKid()];
        
        $jsonHeader = json_encode($header, JSON_UNESCAPED_SLASHES);
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);

        $base64UrlHeader = $this->base64url_encode($jsonHeader);
        $base64UrlPayload = $this->base64url_encode($jsonPayload);
        
        $signature = $rsa->sign($base64UrlHeader . "." . $base64UrlPayload);
        
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $this->base64url_encode($signature);
    }

    private function buildX5cFromCertificate() {
        $crt = file_get_contents($this->config['key_dir'] . '/public.crt');
        if (!$crt) {
            return null;
        }

        $clean = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', (string) $crt);
        return $clean !== '' ? $clean : null;
    }

    private function getKid() {
        $crt = @file_get_contents($this->config['key_dir'] . '/public.crt');
        if (!is_string($crt) || $crt === '') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }
        $key = \phpseclib3\Crypt\PublicKeyLoader::load($crt);
        $jwk_native = json_decode($key->toString('JWK'), true);
        if (isset($jwk_native['keys'][0])) $jwk_native = $jwk_native['keys'][0];
        $jwk = ['e' => $jwk_native['e'], 'kty' => 'RSA', 'n' => $jwk_native['n']];
        ksort($jwk);
        $json = json_encode($jwk, JSON_UNESCAPED_SLASHES);
        return $this->base64url_encode(hash('sha256', $json, true));
    }

    /**
     * Preflight della coppia PRIMARY: prosegue solo se inspect_key_pair() la classifica 'valid'.
     * Non modifica il calcolo di kid/JWK/x5c (e' solo una guardia) e non scrive nulla.
     *
     * @throws WP_SPID_CIE_OIDC_Key_Unavailable_Exception se la coppia non e' utilizzabile.
     */
    private function assert_usable_key_pair(): void {
        if (!class_exists('WP_SPID_CIE_OIDC_Spid_Certificates')) {
            require_once __DIR__ . '/class-wp-spid-cie-spid-certificates.php';
        }
        $key_dir = rtrim((string) ($this->config['key_dir'] ?? ''), '/\\');
        if ($key_dir === '') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }
        $pair = WP_SPID_CIE_OIDC_Spid_Certificates::inspect_key_pair($key_dir . '/private.key', $key_dir . '/public.crt');
        if (($pair['state'] ?? '') !== 'valid') {
            throw new WP_SPID_CIE_OIDC_Key_Unavailable_Exception();
        }
    }

    private function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function generateCodeVerifier() {
        return $this->base64url_encode(random_bytes(64));
    }
    private function generateCodeChallenge($verifier) {
        return $this->base64url_encode(hash('sha256', $verifier, true));
    }

    private function buildFederationEntityMetadata(string $endpoint_base): array {
        $metadata = [
            'organization_name' => $this->config['organization_name'],
            'homepage_uri' => $endpoint_base,
            'policy_uri' => $endpoint_base . '/privacy-policy',
            'contacts' => [$this->config['contacts_email']],
            'federation_resolve_endpoint' => $endpoint_base . '/resolve',
        ];

        if (!empty($this->config['logo_uri'])) {
            $metadata['logo_uri'] = $this->config['logo_uri'];
        }

        return $metadata;
    }

	private function extract_trust_mark_id(string $jwt): ?string {
    $parts = explode('.', $jwt);
    if (count($parts) < 2) return null;

    $payload_b64 = strtr($parts[1], '-_', '+/');
    $payload_b64 .= str_repeat('=', (4 - strlen($payload_b64) % 4) % 4);

    $json = base64_decode($payload_b64);
    if (!$json) return null;

    $data = json_decode($json, true);
    if (!is_array($data)) return null;

    return isset($data['id']) && is_string($data['id']) ? $data['id'] : null;
	}

    private function normalizeEntityIdentifier(string $value): string {
        return untrailingslashit(trim($value));
    }

    private function buildAuthorityHints(): array {
        $authority_hints = [];

        // Dipende solo dai Trust Anchor CIE configurati, non dal flag cie_enabled dell'interfaccia.
        if (!empty($this->config['cie_trust_anchor_preprod'])) {
            $authority_hints[] = untrailingslashit((string) $this->config['cie_trust_anchor_preprod']);
        }

        if (!empty($this->config['cie_trust_anchor_prod'])) {
            $authority_hints[] = untrailingslashit((string) $this->config['cie_trust_anchor_prod']);
        }

        return array_values(array_unique(array_filter($authority_hints)));
    }

    private function buildTrustMarks(): array {
        $trust_marks = [];
        $tm_pre  = trim((string) ($this->config['cie_trust_mark_preprod'] ?? ''));
        $tm_prod = trim((string) ($this->config['cie_trust_mark_prod'] ?? ''));

        foreach ([$tm_pre, $tm_prod] as $tm) {
            if ($tm === '') {
                continue;
            }

            $id = $this->extract_trust_mark_id($tm);
            if ($id) {
                $trust_marks[] = [
                    'id' => $id,
                    'trust_mark' => $tm,
                ];
            }
        }

        return $trust_marks;
    }

    private function buildTrustChain(): array {
        try {
            $self_es = $this->getEntityStatement();
        } catch (\Exception $e) {
            return [];
        }

        $sub = $this->getEntityId();
        $trust_anchor = untrailingslashit((string) ($this->config['cie_trust_anchor_prod'] ?? ''));

        if ($sub === '' || $trust_anchor === '') {
            return [$self_es];
        }

        // Per OpenID Federation 1.0 il trust_chain restituito da /resolve va dall'entity
        // soggetto fino al trust anchor: [self entity config, subordinate ES, anchor entity config].
        $subordinate = $this->fetchFederationJwt(
            $trust_anchor . '/fetch?sub=' . rawurlencode($sub),
            'wp_spid_cie_tc_sub_' . md5($trust_anchor . '|' . $sub)
        );
        $anchor_ec = $this->fetchFederationJwt(
            $trust_anchor . '/.well-known/openid-federation',
            'wp_spid_cie_tc_anchor_' . md5($trust_anchor)
        );

        if ($subordinate !== '' && $anchor_ec !== '') {
            return [$self_es, $subordinate, $anchor_ec];
        }

        return [$self_es];
    }

    private function fetchFederationJwt(string $url, string $cache_key): string {
        $cached = get_transient($cache_key);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $response = wp_remote_get($url, [
            'timeout' => 10,
            'redirection' => 3,
            'headers' => ['Accept' => 'application/entity-statement+jwt'],
        ]);

        if (is_wp_error($response)) {
            return '';
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code < 200 || $code >= 300) {
            return '';
        }

        $body = trim((string) wp_remote_retrieve_body($response));
        if ($body === '' || substr_count($body, '.') !== 2) {
            return '';
        }

        // Le subordinate statement del registry CIE hanno exp ~6h; refresh ogni 4h evita scadenze.
        set_transient($cache_key, $body, HOUR_IN_SECONDS * 4);
        return $body;
    }
}
