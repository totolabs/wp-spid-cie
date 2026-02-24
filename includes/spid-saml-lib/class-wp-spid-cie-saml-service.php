<?php

class WP_SPID_CIE_OIDC_Saml_Service {
    const REQ_TTL = 600;
    const RESP_TTL = 600;

    private function resolve_active_key_dir(): string {
        $upload_dir = wp_upload_dir();
        $base_dir = trailingslashit($upload_dir['basedir']);

        $primary_dir = $base_dir . 'wp-spid-cie-keys';
        $fallback_dir = $base_dir . 'spid-cie-oidc-keys';

        $primary_private = trailingslashit($primary_dir) . 'private.key';
        $primary_cert = trailingslashit($primary_dir) . 'public.crt';
        if (file_exists($primary_private) && is_readable($primary_private) && file_exists($primary_cert) && is_readable($primary_cert)) {
            return $primary_dir;
        }

        $fallback_private = trailingslashit($fallback_dir) . 'private.key';
        $fallback_cert = trailingslashit($fallback_dir) . 'public.crt';
        if (file_exists($fallback_private) && is_readable($fallback_private) && file_exists($fallback_cert) && is_readable($fallback_cert)) {
            return $fallback_dir;
        }

        return $primary_dir;
    }

    public function build_sp_config(array $options): array {
        $entityId = !empty($options['spid_saml_entity_id']) ? (string) $options['spid_saml_entity_id'] : (!empty($options['issuer_override']) ? (string) $options['issuer_override'] : home_url('/'));
        $keys_dir = $this->resolve_active_key_dir();

        return [
            'entity_id' => esc_url_raw($entityId),
            'acs_url' => home_url('/spid/saml/acs'),
            'sls_url' => home_url('/spid/saml/sls'),
            'login_url' => home_url('/spid/saml/login'),
            'metadata_url' => home_url('/spid/saml/metadata'),
            'private_key_path' => $keys_dir . '/private.key',
            'cert_path' => $keys_dir . '/public.crt',
            'clock_skew' => isset($options['spid_saml_clock_skew']) ? max(0, (int) $options['spid_saml_clock_skew']) : 120,
            'binding' => isset($options['spid_saml_binding']) && in_array($options['spid_saml_binding'], ['redirect', 'post'], true) ? $options['spid_saml_binding'] : 'post',
            'loa' => isset($options['spid_saml_level']) && in_array($options['spid_saml_level'], ['SpidL1', 'SpidL2', 'SpidL3'], true) ? $options['spid_saml_level'] : 'SpidL2',
        ];
    }

    public function read_idp_config(array $options): array {
        $legacyCert = isset($options['spid_saml_idp_cert']) ? (string) $options['spid_saml_idp_cert'] : '';
        $cert = isset($options['spid_saml_idp_x509_cert']) ? (string) $options['spid_saml_idp_x509_cert'] : $legacyCert;

        $cfg = [
            'entity_id' => isset($options['spid_saml_idp_entity_id']) ? esc_url_raw((string) $options['spid_saml_idp_entity_id']) : '',
            'sso_url' => isset($options['spid_saml_idp_sso_url']) ? esc_url_raw((string) $options['spid_saml_idp_sso_url']) : '',
            'slo_url' => isset($options['spid_saml_idp_slo_url']) ? esc_url_raw((string) $options['spid_saml_idp_slo_url']) : '',
            'x509_cert' => $this->normalize_cert($cert),
            'alias' => isset($options['spid_saml_default_idp']) ? sanitize_key((string) $options['spid_saml_default_idp']) : 'default',
        ];

        $metadataXml = isset($options['spid_saml_idp_metadata_xml']) ? (string) $options['spid_saml_idp_metadata_xml'] : '';
        if ($metadataXml !== '') {
            $fromMetadata = $this->extract_idp_from_metadata($metadataXml);
            if (!is_wp_error($fromMetadata)) {
                $cfg = array_merge($cfg, array_filter($fromMetadata, function ($v) {
                    return $v !== '';
                }));
            }
        }

        return $cfg;
    }

    public function is_idp_config_complete(array $idp): bool {
        return !empty($idp['entity_id']) && !empty($idp['sso_url']) && !empty($idp['x509_cert']);
    }

    public function build_authn_request_redirect(array $sp, array $idp, string $relayState, array $requestContext = []): string {
        if (strlen($relayState) > 512) {
            $relayState = home_url('/');
        }
        $id = '_' . bin2hex(random_bytes(16));
        $issueInstant = gmdate('Y-m-d\TH:i:s\Z');

        $binding = $sp['binding'] === 'post' ? 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' : 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
        $loa = isset($sp['loa']) ? (string) $sp['loa'] : 'SpidL2';
        $xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . esc_attr($id) . '" Version="2.0" IssueInstant="' . esc_attr($issueInstant) . '" Destination="' . esc_attr($idp['sso_url']) . '" ProtocolBinding="' . esc_attr($binding) . '" AssertionConsumerServiceURL="' . esc_attr($sp['acs_url']) . '"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">' . esc_html($sp['entity_id']) . '</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>https://www.spid.gov.it/' . esc_html($loa) . '</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>';

        $this->store_request_context($id, array_merge([
            'idp' => $idp['entity_id'],
            'idp_x509_cert' => isset($idp['x509_cert']) ? (string) $idp['x509_cert'] : '',
            'idp_slo_url' => isset($idp['slo_url']) ? (string) $idp['slo_url'] : '',
            'relay_state' => $relayState,
            'created_at' => time(),
        ], $requestContext));

        $samlRequest = base64_encode(gzdeflate($xml));
        $params = [
            'SAMLRequest' => $samlRequest,
            'RelayState' => $relayState,
            'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        ];

        $privateKey = @file_get_contents($sp['private_key_path']);
        if (!$privateKey) {
            return new WP_Error('saml_missing_sp_private_key', __('Configurazione SPID SAML incompleta.', 'wp-spid-cie'));
        }

        $signedQuery = 'SAMLRequest=' . rawurlencode($params['SAMLRequest']) . '&RelayState=' . rawurlencode($params['RelayState']) . '&SigAlg=' . rawurlencode($params['SigAlg']);
        $ok = openssl_sign($signedQuery, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        if (!$ok) {
            return new WP_Error('saml_authn_sign_failed', __('Configurazione SPID SAML incompleta.', 'wp-spid-cie'));
        }

        $params['Signature'] = base64_encode($signature);

        // Per HTTP-Redirect la stringa firmata deve combaciare byte-per-byte
        // con la query inviata (ordine/encoding RFC3986), altrimenti alcuni IdP
        // SPID rispondono con errori di formato richiesta (es. codice 10).
        $redirectQuery = $signedQuery . '&Signature=' . rawurlencode($params['Signature']);
        return $idp['sso_url'] . '?' . $redirectQuery;
    }

    public function extract_response_issuer(string $samlResponseB64): string {
        if (strlen($samlResponseB64) > 900000) {
            return '';
        }

        $decoded = base64_decode($samlResponseB64, true);
        if ($decoded === false || trim($decoded) === '' || strlen($decoded) > 600000) {
            return '';
        }

        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        if (!@$dom->loadXML($decoded, LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOCDATA)) {
            return '';
        }

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xp->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $issuer = trim((string) $xp->evaluate('string(/samlp:Response/saml:Issuer)'));
        if ($issuer !== '') {
            return $issuer;
        }

        return trim((string) $xp->evaluate('string(//saml:Assertion/saml:Issuer)'));
    }

    public function parse_and_validate_response(string $samlResponseB64, array $sp, array $idp) {
        $xmlRaw = base64_decode($samlResponseB64, true);
        if ($xmlRaw === false || $xmlRaw === '') {
            return new WP_Error('saml_invalid_payload', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        if (strlen($xmlRaw) > 600000) {
            return new WP_Error('saml_payload_too_large', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $ok = $dom->loadXML($xmlRaw, LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOCDATA);
        if (!$ok) {
            return new WP_Error('saml_invalid_xml', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xp->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $root = $dom->documentElement;
        if (!$root || $root->localName !== 'Response') {
            return new WP_Error('saml_invalid_root', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $responseId = (string) $root->getAttribute('ID');
        if ($responseId === '' || get_transient('spid_saml_resp_' . md5($responseId))) {
            return new WP_Error('saml_replay_detected', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $destination = (string) $root->getAttribute('Destination');
        if ($destination !== '' && untrailingslashit($destination) !== untrailingslashit($sp['acs_url'])) {
            return new WP_Error('saml_invalid_destination', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $issuer = trim((string) $xp->evaluate('string(/samlp:Response/saml:Issuer)'));
        if ($issuer === '') {
            $issuer = trim((string) $xp->evaluate('string(//saml:Assertion/saml:Issuer)'));
        }

        $statusCode = trim((string) $xp->evaluate('string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)'));
        if ($statusCode !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            return new WP_Error('saml_status_not_success', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $inResponseTo = (string) $root->getAttribute('InResponseTo');
        $ctx = $this->consume_request_context($inResponseTo);
        if (is_wp_error($ctx)) {
            return $ctx;
        }

        $expectedIssuer = '';
        if (!empty($ctx['idp'])) {
            $expectedIssuer = (string) $ctx['idp'];
        } elseif (!empty($idp['entity_id'])) {
            $expectedIssuer = (string) $idp['entity_id'];
        }
        if ($issuer === '' || ($expectedIssuer !== '' && !hash_equals($expectedIssuer, $issuer))) {
            return new WP_Error('saml_invalid_issuer', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $audience = trim((string) $xp->evaluate('string(//saml:AudienceRestriction/saml:Audience)'));
        if ($audience !== '' && untrailingslashit($audience) !== untrailingslashit($sp['entity_id'])) {
            return new WP_Error('saml_invalid_audience', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $recipient = trim((string) $xp->evaluate('string(//saml:SubjectConfirmationData/@Recipient)'));
        if ($recipient !== '' && untrailingslashit($recipient) !== untrailingslashit($sp['acs_url'])) {
            return new WP_Error('saml_invalid_recipient', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $subjectInResponseTo = trim((string) $xp->evaluate('string(//saml:SubjectConfirmationData/@InResponseTo)'));
        if ($subjectInResponseTo !== '' && !hash_equals($inResponseTo, $subjectInResponseTo)) {
            return new WP_Error('saml_invalid_subject_inresponseto', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $this->validate_time_window((string) $xp->evaluate('string(//saml:Conditions/@NotBefore)'), (string) $xp->evaluate('string(//saml:Conditions/@NotOnOrAfter)'), (int) $sp['clock_skew']);
        $this->validate_not_on_or_after((string) $xp->evaluate('string(//saml:SubjectConfirmationData/@NotOnOrAfter)'), (int) $sp['clock_skew']);

        $signatureNodes = $xp->query('//ds:Signature');
        if (!$signatureNodes || $signatureNodes->length !== 1) {
            return new WP_Error('saml_signature_ambiguous', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }
        $sigNode = $signatureNodes->item(0);
        if (!$sigNode instanceof DOMElement) {
            return new WP_Error('saml_missing_signature', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        $certForValidation = !empty($ctx['idp_x509_cert']) ? (string) $ctx['idp_x509_cert'] : '';
        if ($certForValidation === '' && !empty($idp['x509_cert'])) {
            $certForValidation = (string) $idp['x509_cert'];
        }
        $sigValid = $this->verify_signature_strict($dom, $sigNode, $certForValidation);
        if (!$sigValid) {
            return new WP_Error('saml_signature_invalid', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        set_transient('spid_saml_resp_' . md5($responseId), 1, self::RESP_TTL);

        $attrs = [];
        foreach ($xp->query('//saml:AttributeStatement/saml:Attribute') as $attrNode) {
            if (!$attrNode instanceof DOMElement) {
                continue;
            }
            $name = $attrNode->getAttribute('Name');
            if ($name === '') {
                continue;
            }
            $valueNode = $xp->query('saml:AttributeValue', $attrNode)->item(0);
            $attrs[$name] = $valueNode ? trim((string) $valueNode->textContent) : '';
        }

        $nameId = trim((string) $xp->evaluate('string(//saml:Subject/saml:NameID)'));
        $fiscal = $this->normalize_fiscal_code($this->pick_first($attrs, ['fiscalNumber', 'fiscal_code', 'fiscalCode', 'cf']));

        return [
            'request_context' => $ctx,
            'claims' => [
                'sub' => $nameId !== '' ? $nameId : $fiscal,
                'fiscal_code' => $fiscal,
                'email' => sanitize_email($this->pick_first($attrs, ['email', 'mail'])),
                'given_name' => sanitize_text_field($this->pick_first($attrs, ['name', 'givenName', 'given_name'])),
                'family_name' => sanitize_text_field($this->pick_first($attrs, ['familyName', 'family_name', 'surname'])),
                'mobile' => sanitize_text_field($this->pick_first($attrs, ['mobilePhone', 'mobile', 'phoneNumber'])),
                'acr' => sanitize_text_field(trim((string) $xp->evaluate('string(//saml:AuthnContextClassRef)'))),
                'issuer' => $issuer,
            ],
        ];
    }

    private function verify_signature_strict(DOMDocument $dom, DOMElement $signatureNode, string $x509Cert): bool {
        $xp = new DOMXPath($signatureNode->ownerDocument);
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $signedInfo = $xp->query('ds:SignedInfo', $signatureNode)->item(0);
        $signatureValueNode = $xp->query('ds:SignatureValue', $signatureNode)->item(0);
        $sigAlgNode = $xp->query('ds:SignedInfo/ds:SignatureMethod', $signatureNode)->item(0);
        if (!$signedInfo instanceof DOMElement || !$signatureValueNode instanceof DOMElement) {
            return false;
        }

        $signatureValue = base64_decode(trim((string) $signatureValueNode->textContent), true);
        if ($signatureValue === false) {
            return false;
        }

        $canonical = $signedInfo->C14N(true, false);
        $algo = $this->resolve_signature_openssl_algo($sigAlgNode instanceof DOMElement ? (string) $sigAlgNode->getAttribute('Algorithm') : '');

        $certCandidates = $this->extract_cert_candidates($x509Cert);
        if (empty($certCandidates)) {
            return false;
        }

        $verified = false;
        foreach ($certCandidates as $candidate) {
            $publicKey = openssl_pkey_get_public($candidate);
            if (!$publicKey) {
                continue;
            }
            $check = openssl_verify($canonical, $signatureValue, $publicKey, $algo);
            if ($check === 1) {
                $verified = true;
                break;
            }
        }

        if (!$verified) {
            return false;
        }

        return $this->validate_reference_digest($dom, $signatureNode);
    }

    private function validate_reference_digest(DOMDocument $dom, DOMElement $signatureNode): bool {
        $xp = new DOMXPath($dom);
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $refNode = $xp->query('ds:SignedInfo/ds:Reference', $signatureNode)->item(0);
        $digestNode = $xp->query('ds:SignedInfo/ds:Reference/ds:DigestValue', $signatureNode)->item(0);
        $digestMethodNode = $xp->query('ds:SignedInfo/ds:Reference/ds:DigestMethod', $signatureNode)->item(0);
        if (!$refNode instanceof DOMElement || !$digestNode instanceof DOMElement) {
            return false;
        }

        $uri = ltrim((string) $refNode->getAttribute('URI'), '#');
        if ($uri === '') {
            return false;
        }

        $targetNodes = $xp->query('//*[@ID="' . $uri . '"]');
        if (!$targetNodes || $targetNodes->length !== 1) {
            return false;
        }

        $target = $targetNodes->item(0);
        if (!$target instanceof DOMElement) {
            return false;
        }

        $clone = $target->cloneNode(true);
        $sigInside = $clone->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
        while ($sigInside->length > 0) {
            $sigInside->item(0)->parentNode->removeChild($sigInside->item(0));
        }

        $canon = $clone->C14N(true, false);
        $digestAlgo = $this->resolve_digest_algo($digestMethodNode instanceof DOMElement ? (string) $digestMethodNode->getAttribute('Algorithm') : '');
        $computed = base64_encode(hash($digestAlgo, $canon, true));
        $expected = trim((string) $digestNode->textContent);
        return hash_equals($expected, $computed);
    }

    private function resolve_signature_openssl_algo(string $algorithmUri): int {
        $uri = strtolower(trim($algorithmUri));
        if ($uri === 'http://www.w3.org/2000/09/xmldsig#rsa-sha1') {
            return OPENSSL_ALGO_SHA1;
        }
        if ($uri === 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') {
            return OPENSSL_ALGO_SHA512;
        }
        return OPENSSL_ALGO_SHA256;
    }

    private function resolve_digest_algo(string $algorithmUri): string {
        $uri = strtolower(trim($algorithmUri));
        if ($uri === 'http://www.w3.org/2000/09/xmldsig#sha1') {
            return 'sha1';
        }
        if ($uri === 'http://www.w3.org/2001/04/xmlenc#sha512') {
            return 'sha512';
        }
        return 'sha256';
    }

    private function extract_cert_candidates(string $x509Cert): array {
        $raw = trim($x509Cert);
        if ($raw === '') {
            return [];
        }

        $blocks = preg_split('/-----END CERTIFICATE-----/i', $raw) ?: [];
        $out = [];
        foreach ($blocks as $block) {
            $clean = trim(str_replace('-----BEGIN CERTIFICATE-----', '', $block));
            if ($clean === '') {
                continue;
            }
            $clean = preg_replace('/\s+/', '', $clean);
            if (!is_string($clean) || $clean === '') {
                continue;
            }
            $out[] = "-----BEGIN CERTIFICATE-----\n" . $clean . "\n-----END CERTIFICATE-----";
        }

        if (empty($out)) {
            $clean = preg_replace('/\s+/', '', $raw);
            if (is_string($clean) && $clean !== '') {
                $out[] = "-----BEGIN CERTIFICATE-----\n" . $clean . "\n-----END CERTIFICATE-----";
            }
        }

        return array_values(array_unique($out));
    }

    private function validate_time_window(string $notBefore, string $notOnOrAfter, int $skew): void {
        $now = time();
        if ($notBefore !== '' && strtotime($notBefore) > ($now + $skew)) {
            throw new RuntimeException('saml_not_yet_valid');
        }
        if ($notOnOrAfter !== '' && strtotime($notOnOrAfter) <= ($now - $skew)) {
            throw new RuntimeException('saml_expired');
        }
    }

    private function validate_not_on_or_after(string $value, int $skew): void {
        if ($value === '') {
            return;
        }
        if (strtotime($value) <= (time() - $skew)) {
            throw new RuntimeException('saml_subject_expired');
        }
    }

    public function extract_idp_from_metadata(string $xml) {
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        if (!$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOCDATA)) {
            return new WP_Error('saml_metadata_invalid', __('Configurazione SPID SAML incompleta.', 'wp-spid-cie'));
        }

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        return [
            'entity_id' => trim((string) $xp->evaluate('string(/md:EntityDescriptor/@entityID)')),
            'sso_url' => trim((string) $xp->evaluate('string(//md:IDPSSODescriptor/md:SingleSignOnService[1]/@Location)')),
            'slo_url' => trim((string) $xp->evaluate('string(//md:IDPSSODescriptor/md:SingleLogoutService[1]/@Location)')),
            'x509_cert' => $this->normalize_cert(trim((string) $xp->evaluate('string(//md:IDPSSODescriptor//ds:X509Certificate[1])'))),
        ];
    }

    public function normalize_cert(string $cert): string {
        $cert = str_replace(["\r", "\n", '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $cert);
        return trim($cert);
    }

    public function pick_first(array $source, array $keys): string {
        foreach ($keys as $key) {
            if (!isset($source[$key])) {
                continue;
            }
            $v = trim((string) $source[$key]);
            if ($v !== '') {
                return $v;
            }
        }
        return '';
    }

    public function normalize_fiscal_code(string $value): string {
        $value = strtoupper(trim($value));
        if (strpos($value, 'TINIT-') === 0) {
            $value = substr($value, 6);
        }
        return preg_replace('/[^A-Z0-9]/', '', $value);
    }

    public function store_request_context(string $requestId, array $payload): void {
        set_transient('spid_saml_req_' . md5($requestId), $payload, self::REQ_TTL);
    }

    public function consume_request_context(string $requestId) {
        if ($requestId === '') {
            return new WP_Error('saml_missing_inresponseto', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }
        $key = 'spid_saml_req_' . md5($requestId);
        $ctx = get_transient($key);
        delete_transient($key);
        if (!is_array($ctx)) {
            return new WP_Error('saml_request_context_not_found', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }
        return $ctx;
    }
}
