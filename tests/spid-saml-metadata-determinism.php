<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// Minimal WordPress function shims for offline regression execution.
if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('get_option')) { function get_option($key, $default = null) { return $default; } }
if (!function_exists('sanitize_key')) { function sanitize_key($v) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $v)); } }
if (!function_exists('sanitize_text_field')) { function sanitize_text_field($v) { return trim((string) $v); } }
if (!function_exists('sanitize_email')) { function sanitize_email($v) { return trim((string) $v); } }
if (!function_exists('is_email')) { function is_email($v) { return filter_var((string) $v, FILTER_VALIDATE_EMAIL) !== false; } }
if (!function_exists('esc_url_raw')) { function esc_url_raw($v) { return (string) $v; } }
if (!function_exists('home_url')) { function home_url($path = '/') { return 'https://example.test' . $path; } }
if (!function_exists('get_bloginfo')) { function get_bloginfo($show = '') { return 'Example PA'; } }
if (!function_exists('__')) { function __($text, $domain = null) { return $text; } }
if (!function_exists('trailingslashit')) { function trailingslashit($value) { return rtrim((string) $value, '/') . '/'; } }
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir() {
        return ['basedir' => __DIR__ . '/artifacts/uploads'];
    }
}

require_once __DIR__ . '/../includes/spid-saml-lib/class-wp-spid-cie-saml-service.php';
require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';

$uploads = wp_upload_dir();
$keyDir = trailingslashit($uploads['basedir']) . 'wp-spid-cie-keys';
if (!is_dir($keyDir) && !mkdir($keyDir, 0775, true) && !is_dir($keyDir)) {
    fwrite(STDERR, "Cannot create key dir: {$keyDir}\n");
    exit(1);
}

$privateKeyPath = $keyDir . '/private.key';
$certPath = $keyDir . '/public.crt';

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
$dn = [
    'countryName' => 'IT',
    'stateOrProvinceName' => 'Roma',
    'localityName' => 'Roma',
    'organizationName' => 'Example PA',
    'commonName' => 'example.test',
    'emailAddress' => 'admin@example.test',
];
$csr = openssl_csr_new($dn, $key, ['digest_alg' => 'sha256']);
$cert = openssl_csr_sign($csr, null, $key, 7, ['digest_alg' => 'sha256']);
openssl_pkey_export($key, $privatePem);
openssl_x509_export($cert, $certPem);
file_put_contents($privateKeyPath, $privatePem);
file_put_contents($certPath, $certPem);

$options = [
    'spid_saml_entity_id' => 'https://example.test',
    'organization_name' => 'Example PA',
    'contacts_email' => 'admin@example.test',
    'ipa_code' => 'ipa123',
    'fiscal_number' => 'fisc123',
    'spid_saml_requested_attributes' => ['name', 'familyName', 'fiscalNumber', 'email'],
];

$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');
$xml1 = $public->build_spid_saml_metadata_xml($options);
$xml2 = $public->build_spid_saml_metadata_xml($options);

$hash1 = hash('sha256', $xml1);
$hash2 = hash('sha256', $xml2);
if ($hash1 !== $hash2) {
    fwrite(STDERR, "Metadata hash mismatch on consecutive generation\n");
    exit(1);
}

$doc = new DOMDocument();
$doc->loadXML($xml1);
$xp = new DOMXPath($doc);
$xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
$xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$entity = $xp->query('/md:EntityDescriptor')->item(0);
$signatureNode = $xp->query('/md:EntityDescriptor/ds:Signature')->item(0);
if (!$entity instanceof DOMElement || !$signatureNode instanceof DOMElement) {
    fwrite(STDERR, "Missing EntityDescriptor or Signature in metadata\n");
    exit(1);
}

$signedInfoNode = $xp->query('/md:EntityDescriptor/ds:Signature/ds:SignedInfo')->item(0);
$signatureValueNode = $xp->query('/md:EntityDescriptor/ds:Signature/ds:SignatureValue')->item(0);
$keyInfoCertNode = $xp->query('/md:EntityDescriptor/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')->item(0);
if (!$signedInfoNode || !$signatureValueNode || !$keyInfoCertNode) {
    fwrite(STDERR, "Missing SignedInfo/SignatureValue/KeyInfo certificate\n");
    exit(1);
}

$signedInfo = $signedInfoNode->C14N(true, false);
$signatureRaw = base64_decode((string) preg_replace('/\s+/', '', $signatureValueNode->textContent), true);
$certB64 = (string) preg_replace('/\s+/', '', $keyInfoCertNode->textContent);
$certPemFromXml = "-----BEGIN CERTIFICATE-----\n" . chunk_split($certB64, 64, "\n") . "-----END CERTIFICATE-----\n";
$publicKey = openssl_pkey_get_public($certPemFromXml);
$verify = ($publicKey !== false && is_string($signedInfo) && is_string($signatureRaw))
    ? openssl_verify($signedInfo, $signatureRaw, $publicKey, OPENSSL_ALGO_SHA256)
    : 0;
if ($verify !== 1) {
    fwrite(STDERR, "Signature verification failed\n");
    exit(1);
}

echo "SHA256#1 {$hash1}\n";
echo "SHA256#2 {$hash2}\n";
echo "Deterministic metadata generation: OK\n";
echo "Signature verification: OK\n";
