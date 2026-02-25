<?php

declare(strict_types=1);

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

require_once __DIR__ . '/../vendor/autoload.php';

$outDir = __DIR__ . '/artifacts';
if (!is_dir($outDir) && !mkdir($outDir, 0775, true) && !is_dir($outDir)) {
    fwrite(STDERR, "Cannot create artifacts directory: {$outDir}\n");
    exit(1);
}

$privateKeyPath = $outDir . '/spid-metadata-test.key';
$certPath = $outDir . '/spid-metadata-test.crt';
$metadataPath = $outDir . '/sp-metadata.xml';

$dn = [
    'countryName' => 'IT',
    'stateOrProvinceName' => 'Campania',
    'localityName' => 'Salerno',
    'organizationName' => 'Totolabs',
    'commonName' => 'tsrmpstrpsalerno.it',
    'emailAddress' => 'info@tsrmpstrpsalerno.it',
];

$keyResource = openssl_pkey_new([
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
if ($keyResource === false) {
    fwrite(STDERR, "openssl_pkey_new failed\n");
    exit(1);
}

$csr = openssl_csr_new($dn, $keyResource, ['digest_alg' => 'sha256']);
if ($csr === false) {
    fwrite(STDERR, "openssl_csr_new failed\n");
    exit(1);
}

$certResource = openssl_csr_sign($csr, null, $keyResource, 7, ['digest_alg' => 'sha256']);
if ($certResource === false) {
    fwrite(STDERR, "openssl_csr_sign failed\n");
    exit(1);
}

$privatePem = '';
$certPem = '';
openssl_pkey_export($keyResource, $privatePem);
openssl_x509_export($certResource, $certPem);
file_put_contents($privateKeyPath, $privatePem);
file_put_contents($certPath, $certPem);

$doc = new DOMDocument('1.0', 'UTF-8');
$doc->preserveWhiteSpace = true;
$doc->formatOutput = false;

$entity = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'md:EntityDescriptor');
$entity->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
$entity->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:spid', 'https://spid.gov.it/saml-extensions');
$entity->setAttribute('entityID', 'https://tsrmpstrpsalerno.it');
$entity->setAttribute('ID', 'spid-metadata');
$entity->setIdAttribute('ID', true);
$doc->appendChild($entity);

$spSso = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'md:SPSSODescriptor');
$spSso->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
$spSso->setAttribute('AuthnRequestsSigned', 'true');
$spSso->setAttribute('WantAssertionsSigned', 'true');
$entity->appendChild($spSso);

$dsig = new XMLSecurityDSig();
$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$dsig->addReference(
    $entity,
    XMLSecurityDSig::SHA256,
    [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
    ]
);

$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
$key->loadKey($privateKeyPath, true);
$dsig->sign($key);
$dsig->add509Cert($certPem);
$dsig->appendSignature($entity);

file_put_contents($metadataPath, $doc->saveXML());

$xp = new DOMXPath($doc);
$xp->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
$xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$signedInfoNode = $xp->query('/md:EntityDescriptor/ds:Signature/ds:SignedInfo')->item(0);
$signatureValueNode = $xp->query('/md:EntityDescriptor/ds:Signature/ds:SignatureValue')->item(0);

if (!$signedInfoNode || !$signatureValueNode) {
    fwrite(STDERR, "Missing Signature nodes\n");
    exit(1);
}

$signedInfo = $signedInfoNode->C14N(true, false);
$signatureRaw = base64_decode((string) preg_replace('/\s+/', '', $signatureValueNode->textContent), true);
$publicKey = openssl_pkey_get_public($certPem);
$verify = ($publicKey !== false && is_string($signedInfo) && is_string($signatureRaw))
    ? openssl_verify($signedInfo, $signatureRaw, $publicKey, OPENSSL_ALGO_SHA256)
    : 0;
if ($verify !== 1) {
    fwrite(STDERR, "OpenSSL verify failed\n");
    exit(1);
}

echo "Generated metadata: {$metadataPath}\n";
echo "OpenSSL SignedInfo verification: OK\n";

$xmlsecBinary = trim((string) shell_exec('command -v xmlsec1 2>/dev/null'));
if ($xmlsecBinary !== '') {
    $cmd = sprintf(
        '%s --verify --id-attr:ID EntityDescriptor --pubkey-cert-pem %s %s 2>&1',
        escapeshellcmd($xmlsecBinary),
        escapeshellarg($certPath),
        escapeshellarg($metadataPath)
    );
    exec($cmd, $xmlsecOutput, $xmlsecCode);
    if ($xmlsecCode !== 0) {
        fwrite(STDERR, "xmlsec1 verification failed\n" . implode("\n", $xmlsecOutput) . "\n");
        exit(1);
    }
    echo "xmlsec1 verification: OK\n";
} else {
    echo "xmlsec1 not available: skipped offline xmlsec check\n";
}

$checkerBin = trim((string) shell_exec('command -v spid-saml-check 2>/dev/null'));
if ($checkerBin !== '') {
    $cmd = sprintf(
        '%s --input-file %s --profile spid-sp-public --strict 2>&1',
        escapeshellcmd($checkerBin),
        escapeshellarg($metadataPath)
    );
    exec($cmd, $checkerOutput, $checkerCode);
    if ($checkerCode !== 0) {
        fwrite(STDERR, "spid-saml-check failed\n" . implode("\n", $checkerOutput) . "\n");
        exit(1);
    }
    echo "spid-saml-check strict profile: OK\n";
} else {
    echo "spid-saml-check not available: skipped strict profile check\n";
}
