<?php

class WP_SPID_CIE_OIDC_Spid_Certificates {
    public static function generate(array $options = [], bool $force = false): array {
        $key_dir = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir(true);
        $private_path = trailingslashit($key_dir) . 'private.key';
        $cert_path = trailingslashit($key_dir) . 'public.crt';
        $csr_path = trailingslashit($key_dir) . 'csr.pem';

        if (!$force && file_exists($private_path) && file_exists($cert_path)) {
            $status = self::validate($private_path, $cert_path, $options);
            if ($status['valid']) {
                return ['success' => true, 'paths' => ['private' => $private_path, 'cert' => $cert_path, 'csr' => $csr_path], 'errors' => []];
            }
        }

        if (!extension_loaded('openssl')) {
            return ['success' => false, 'errors' => ['Estensione OpenSSL non disponibile in PHP.']];
        }

        if (!is_dir($key_dir) && !wp_mkdir_p($key_dir)) {
            return ['success' => false, 'errors' => ['Impossibile creare la cartella certificati in uploads/wp-spid-cie-keys.']];
        }

        $org = trim((string) ($options['organization_name'] ?? get_bloginfo('name')));
        $org = $org !== '' ? $org : 'Service Provider';
        $locality = trim((string) ($options['spid_saml_locality_name'] ?? ''));
        if ($locality === '') {
            return ['success' => false, 'errors' => ['Compila "Locality Name" (L) in SPID SAML prima di generare il certificato.']];
        }

        $entity_id = trim((string) ($options['spid_saml_entity_id'] ?? ($options['issuer_override'] ?? home_url('/'))));
        $entity_id = untrailingslashit($entity_id);
        if ($entity_id === '') {
            return ['success' => false, 'errors' => ['EntityID SPID SAML mancante: impossibile valorizzare OID URI (2.5.4.83).']];
        }

        $ipa_code = sanitize_text_field((string) ($options['ipa_code'] ?? ($options['sp_contact_ipa_code'] ?? '')));
        if ($ipa_code === '') {
            return ['success' => false, 'errors' => ['Codice IPA mancante: impossibile valorizzare organizationIdentifier (2.5.4.97).']];
        }

        $cn_default = trim((string) ($options['sp_org_display_name'] ?? $org));
        $common_name = trim((string) ($options['spid_saml_common_name'] ?? $cn_default));
        if ($common_name === '') {
            $common_name = $cn_default;
        }

        $dn = [
            'countryName' => 'IT',
            'localityName' => $locality,
            'organizationName' => $org,
            'commonName' => $common_name,
            'organizationIdentifier' => 'PA:IT-' . $ipa_code,
            'URI' => $entity_id,
            '2.5.4.83' => $entity_id,
        ];

        $bits = max(2048, (int) ($options['spid_saml_key_bits'] ?? 2048));
        $digest = !empty($options['spid_saml_digest_alg']) ? (string) $options['spid_saml_digest_alg'] : 'sha256';

        $config_path = self::write_openssl_config($key_dir, $bits, $digest, $dn, $entity_id);
        if (is_wp_error($config_path)) {
            return ['success' => false, 'errors' => [$config_path->get_error_message()]];
        }

        $priv_key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
            'digest_alg' => $digest,
            'config' => $config_path,
        ]);
        if ($priv_key === false) {
            @unlink($config_path);
            return ['success' => false, 'errors' => [self::collect_openssl_errors('Generazione chiave privata fallita')]];
        }

        if (!openssl_pkey_export($priv_key, $private_pem, null, ['config' => $config_path, 'digest_alg' => $digest])) {
            @unlink($config_path);
            return ['success' => false, 'errors' => [self::collect_openssl_errors('Export chiave privata fallito')]];
        }

        $csr = openssl_csr_new($dn, $priv_key, ['digest_alg' => $digest, 'config' => $config_path, 'req_extensions' => 'v3_spid']);
        if ($csr === false) {
            @unlink($config_path);
            return ['success' => false, 'errors' => [self::collect_openssl_errors('Generazione CSR fallita')]];
        }

        $x509 = openssl_csr_sign($csr, null, $priv_key, 3650, ['digest_alg' => $digest, 'config' => $config_path, 'x509_extensions' => 'v3_spid']);
        if ($x509 === false) {
            @unlink($config_path);
            return ['success' => false, 'errors' => [self::collect_openssl_errors('Firma certificato self-signed fallita')]];
        }

        $cert_pem = '';
        if (!openssl_x509_export($x509, $cert_pem)) {
            @unlink($config_path);
            return ['success' => false, 'errors' => [self::collect_openssl_errors('Export certificato X509 fallito')]];
        }

        $csr_pem = '';
        openssl_csr_export($csr, $csr_pem);

        if (file_put_contents($private_path, $private_pem) === false || file_put_contents($cert_path, $cert_pem) === false) {
            @unlink($config_path);
            return ['success' => false, 'errors' => ['Impossibile scrivere i file certificato/chiave. Verificare i permessi di uploads/wp-spid-cie-keys.']];
        }
        if ($csr_pem !== '') {
            @file_put_contents($csr_path, $csr_pem);
        }

        @chmod($private_path, 0600);
        @chmod($cert_path, 0644);
        if (file_exists($csr_path)) {
            @chmod($csr_path, 0644);
        }
        @unlink($config_path);

        $status = self::validate($private_path, $cert_path, $options);
        if (!$status['valid']) {
            return ['success' => false, 'errors' => $status['errors']];
        }

        return ['success' => true, 'paths' => ['private' => $private_path, 'cert' => $cert_path, 'csr' => $csr_path], 'errors' => []];
    }

    public static function validate(string $private_path, string $cert_path, array $options = []): array {
        $errors = [];
        if (!file_exists($private_path) || !is_readable($private_path)) {
            $errors[] = 'Chiave privata non trovata o non leggibile.';
        }
        if (!file_exists($cert_path) || !is_readable($cert_path)) {
            $errors[] = 'Certificato pubblico non trovato o non leggibile.';
        }
        if (!empty($errors)) {
            return ['valid' => false, 'errors' => $errors];
        }

        $private_pem = (string) file_get_contents($private_path);
        $cert_pem = (string) file_get_contents($cert_path);
        $cert_data = openssl_x509_parse($cert_pem, false);
        if ($cert_data === false) {
            return ['valid' => false, 'errors' => ['Certificato X509 non parsabile.']];
        }

        $subject = isset($cert_data['subject']) && is_array($cert_data['subject']) ? $cert_data['subject'] : [];
        $extensions = isset($cert_data['extensions']) && is_array($cert_data['extensions']) ? $cert_data['extensions'] : [];
        $subject_country = (string) ($subject['C'] ?? ($subject['countryName'] ?? ''));
        if ($subject_country !== 'IT') {
            $errors[] = 'Subject C deve essere IT.';
        }
        $subject_locality = (string) ($subject['L'] ?? ($subject['localityName'] ?? ''));
        if ($subject_locality === '') {
            $errors[] = 'Subject L (localityName) mancante.';
        }
        $subject_org = (string) ($subject['O'] ?? ($subject['organizationName'] ?? ''));
        if ($subject_org === '') {
            $errors[] = 'Subject O (organizationName) mancante.';
        }
        $subject_cn = (string) ($subject['CN'] ?? ($subject['commonName'] ?? ''));
        if ($subject_cn === '') {
            $errors[] = 'Subject CN mancante.';
        }

        $entity_id = untrailingslashit(trim((string) ($options['spid_saml_entity_id'] ?? ($options['issuer_override'] ?? ''))));
        $subject_uri = trim((string) ($subject['URI'] ?? ($subject['2.5.4.83'] ?? '')));
        $subject_alt_name = (string) ($extensions['subjectAltName'] ?? '');
        $san_uri = '';
        if (preg_match('/URI:([^,]+)/', $subject_alt_name, $matches)) {
            $san_uri = trim((string) $matches[1]);
        }
        $resolved_uri = $subject_uri !== '' ? $subject_uri : $san_uri;
        if ($resolved_uri === '') {
            $errors[] = 'OID URI (2.5.4.83) mancante nel Subject.';
        } elseif ($entity_id !== '' && !hash_equals($entity_id, untrailingslashit($resolved_uri))) {
            $errors[] = 'OID URI (2.5.4.83) non coerente con EntityID configurato.';
        }

        $expected_org_id = '';
        if (!empty($options['ipa_code'])) {
            $expected_org_id = 'PA:IT-' . sanitize_text_field((string) $options['ipa_code']);
        } elseif (!empty($options['sp_contact_ipa_code'])) {
            $expected_org_id = 'PA:IT-' . sanitize_text_field((string) $options['sp_contact_ipa_code']);
        }
        $subject_org_id = trim((string) ($subject['organizationIdentifier'] ?? ($subject['2.5.4.97'] ?? ($subject['serialNumber'] ?? ''))));
        if ($subject_org_id === '') {
            $errors[] = 'OID organizationIdentifier (2.5.4.97) mancante nel Subject.';
        } elseif ($expected_org_id !== '' && !hash_equals($expected_org_id, $subject_org_id)) {
            $errors[] = 'OID organizationIdentifier (2.5.4.97) non coerente con codice IPA.';
        }

        $key_usage = (string) ($extensions['keyUsage'] ?? '');
        if (stripos($key_usage, 'Digital Signature') === false) {
            $errors[] = 'Estensione keyUsage senza digitalSignature.';
        }
        if (stripos($key_usage, 'Non Repudiation') === false && stripos($key_usage, 'Content Commitment') === false) {
            $errors[] = 'Estensione keyUsage senza contentCommitment/nonRepudiation.';
        }
        $basic_constraints = (string) ($extensions['basicConstraints'] ?? '');
        if (stripos($basic_constraints, 'CA:FALSE') === false) {
            $errors[] = 'Estensione basicConstraints deve essere CA:FALSE.';
        }
        $policies = (string) ($extensions['certificatePolicies'] ?? '');
        if (stripos($policies, '1.3.76.16.6') === false || stripos($policies, '1.3.76.16.4.2.1') === false) {
            $errors[] = 'certificatePolicies non contiene gli OID SPID richiesti.';
        }

        $private_key = openssl_pkey_get_private($private_pem);
        $public_key = openssl_pkey_get_public($cert_pem);
        if ($private_key === false || $public_key === false) {
            $errors[] = 'Impossibile caricare chiave privata/pubblica per verifica modulus.';
        } else {
            $private_details = openssl_pkey_get_details($private_key);
            $public_details = openssl_pkey_get_details($public_key);
            $private_modulus = isset($private_details['rsa']['n']) ? bin2hex($private_details['rsa']['n']) : '';
            $public_modulus = isset($public_details['rsa']['n']) ? bin2hex($public_details['rsa']['n']) : '';
            if ($private_modulus === '' || $public_modulus === '' || !hash_equals($private_modulus, $public_modulus)) {
                $errors[] = 'La chiave privata non combacia con il certificato (modulus mismatch).';
            }
        }

        return ['valid' => empty($errors), 'errors' => $errors, 'cert' => $cert_data];
    }

    public static function describe_status(array $options = []): array {
        $key_dir = WP_SPID_CIE_OIDC_Factory::resolve_spid_key_dir();
        $private_path = trailingslashit($key_dir) . 'private.key';
        $cert_path = trailingslashit($key_dir) . 'public.crt';
        $validation = self::validate($private_path, $cert_path, $options);

        $result = [
            'key_dir' => $key_dir,
            'private_path' => $private_path,
            'cert_path' => $cert_path,
            'present' => file_exists($private_path) && file_exists($cert_path),
            'valid' => $validation['valid'],
            'errors' => $validation['errors'],
            'subject' => '',
            'expiry' => '',
            'modulus_match' => $validation['valid'] || !in_array('La chiave privata non combacia con il certificato (modulus mismatch).', $validation['errors'], true),
        ];

        if (!empty($validation['cert']) && is_array($validation['cert'])) {
            $subject = isset($validation['cert']['subject']) && is_array($validation['cert']['subject']) ? $validation['cert']['subject'] : [];
            $result['subject'] = implode(', ', array_filter([
                isset($subject['CN']) ? 'CN=' . $subject['CN'] : (isset($subject['commonName']) ? 'CN=' . $subject['commonName'] : ''),
                isset($subject['O']) ? 'O=' . $subject['O'] : (isset($subject['organizationName']) ? 'O=' . $subject['organizationName'] : ''),
                isset($subject['L']) ? 'L=' . $subject['L'] : (isset($subject['localityName']) ? 'L=' . $subject['localityName'] : ''),
                isset($subject['C']) ? 'C=' . $subject['C'] : (isset($subject['countryName']) ? 'C=' . $subject['countryName'] : ''),
            ]));
            if (!empty($validation['cert']['validTo_time_t'])) {
                $result['expiry'] = gmdate('Y-m-d H:i:s', (int) $validation['cert']['validTo_time_t']) . ' UTC';
            }
        }

        return $result;
    }

    private static function write_openssl_config(string $key_dir, int $bits, string $digest_alg, array $dn, string $entity_id) {
        $config_path = tempnam($key_dir, 'spid-openssl-');
        if ($config_path === false) {
            return new WP_Error('spid_tmp_config', 'Impossibile creare file temporaneo OpenSSL nella cartella chiavi.');
        }

        $config = "[ req ]\n"
            . "default_bits = {$bits}\n"
            . "prompt = no\n"
            . "default_md = {$digest_alg}\n"
            . "distinguished_name = req_dn\n"
            . "x509_extensions = v3_spid\n"
            . "oid_section = custom_oids\n\n"
            . "[ custom_oids ]\n"
            . "organizationIdentifier = 2.5.4.97\n"
            . "URI = 2.5.4.83\n\n"
            . "[ req_dn ]\n"
            . "C = IT\n"
            . "L = " . self::escape_config_value((string) ($dn['localityName'] ?? '')) . "\n"
            . "O = " . self::escape_config_value((string) ($dn['organizationName'] ?? '')) . "\n"
            . "CN = " . self::escape_config_value((string) ($dn['commonName'] ?? '')) . "\n"
            . "organizationIdentifier = " . self::escape_config_value((string) ($dn['organizationIdentifier'] ?? '')) . "\n"
            . "URI = " . self::escape_config_value($entity_id) . "\n"
            . "2.5.4.83 = " . self::escape_config_value($entity_id) . "\n\n"
            . "[ v3_spid ]\n"
            . "keyUsage = critical, digitalSignature, nonRepudiation\n"
            . "basicConstraints = CA:FALSE\n"
            . "certificatePolicies = @agidcert, @spidsp\n"
            . "subjectAltName = URI:" . self::escape_config_value($entity_id) . "\n\n"
            . "[ agidcert ]\n"
            . "policyIdentifier = 1.3.76.16.6\n"
            . "userNotice.1 = @notice_agid\n\n"
            . "[ notice_agid ]\n"
            . "explicitText = UTF8:agIDcert\n\n"
            . "[ spidsp ]\n"
            . "policyIdentifier = 1.3.76.16.4.2.1\n"
            . "userNotice.1 = @notice_sp\n\n"
            . "[ notice_sp ]\n"
            . "explicitText = UTF8:cert_SP_Pub\n";

        if (@file_put_contents($config_path, $config) === false) {
            return new WP_Error('spid_tmp_config_write', 'Impossibile scrivere il file OpenSSL config temporaneo.');
        }

        return $config_path;
    }


    private static function escape_config_value(string $value): string {
        return str_replace(["\r", "\n"], '', trim($value));
    }

    private static function collect_openssl_errors(string $prefix): string {
        $messages = [];
        while ($error = openssl_error_string()) {
            $messages[] = $error;
        }
        if (empty($messages)) {
            return $prefix . '.';
        }
        return $prefix . ': ' . implode(' | ', $messages);
    }
}
