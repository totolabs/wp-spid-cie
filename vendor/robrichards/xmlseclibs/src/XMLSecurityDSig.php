<?php

namespace RobRichards\XMLSecLibs;

use DOMDocument;
use DOMElement;

class XMLSecurityDSig {
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    private $sigNode;
    private $signedInfoNode;
    private $canonicalMethod = self::EXC_C14N;
    private $referenceNode;

    public function setCanonicalMethod($method): void {
        $this->canonicalMethod = (string) $method;
    }

    public function addReference(DOMElement $node, $digestAlgorithm, array $transforms = [], array $options = []): void {
        $doc = $node->ownerDocument;
        if (!$doc instanceof DOMDocument) {
            return;
        }

        $this->sigNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:Signature');
        $this->signedInfoNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:SignedInfo');

        $canonNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:CanonicalizationMethod');
        $canonNode->setAttribute('Algorithm', $this->canonicalMethod);
        $this->signedInfoNode->appendChild($canonNode);

        $sigMethod = $doc->createElementNS(self::XMLDSIGNS, 'ds:SignatureMethod');
        $sigMethod->setAttribute('Algorithm', XMLSecurityKey::RSA_SHA256);
        $this->signedInfoNode->appendChild($sigMethod);

        $reference = $doc->createElementNS(self::XMLDSIGNS, 'ds:Reference');
        $idName = isset($options['id_name']) ? (string) $options['id_name'] : 'ID';
        $id = trim((string) $node->getAttribute($idName));
        if ($id !== '') {
            $reference->setAttribute('URI', '#' . $id);
        }

        $transformsNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:Transforms');
        foreach ($transforms as $transform) {
            $transformNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:Transform');
            $transformNode->setAttribute('Algorithm', (string) $transform);
            $transformsNode->appendChild($transformNode);
        }
        $reference->appendChild($transformsNode);

        $digestMethod = $doc->createElementNS(self::XMLDSIGNS, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', (string) $digestAlgorithm);
        $reference->appendChild($digestMethod);

        $digestValue = $this->calculateDigest($node);
        $reference->appendChild($doc->createElementNS(self::XMLDSIGNS, 'ds:DigestValue', $digestValue));

        $this->signedInfoNode->appendChild($reference);
        $this->sigNode->appendChild($this->signedInfoNode);
        $this->referenceNode = $node;
    }

    public function sign(XMLSecurityKey $objKey): void {
        if (!$this->signedInfoNode instanceof DOMElement || !$this->sigNode instanceof DOMElement) {
            return;
        }

        // Canonicalize SignedInfo in the final document context.
        // If Signature is detached here, inherited namespace nodes may differ
        // from the served XML and break signature verification.
        if (!$this->sigNode->parentNode && $this->referenceNode instanceof DOMElement) {
            $this->referenceNode->insertBefore($this->sigNode, $this->referenceNode->firstChild);
        }

        $signedInfoC14n = $this->signedInfoNode->C14N(true, false);
        if ($signedInfoC14n === false) {
            return;
        }
        $signature = $objKey->signData($signedInfoC14n);
        if ($signature === '') {
            return;
        }
        $doc = $this->signedInfoNode->ownerDocument;
        if (!$doc instanceof DOMDocument) {
            return;
        }
        $sigValueNode = $doc->createElementNS(self::XMLDSIGNS, 'ds:SignatureValue', base64_encode($signature));
        $this->sigNode->appendChild($sigValueNode);
    }

    public function add509Cert($cert, $isPEMFormat = true, $isURL = false, array $options = []): void {
        if (!$this->sigNode instanceof DOMElement) {
            return;
        }
        $doc = $this->sigNode->ownerDocument;
        if (!$doc instanceof DOMDocument) {
            return;
        }

        $certValue = (string) $cert;
        $certValue = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certValue);

        $keyInfo = $doc->createElementNS(self::XMLDSIGNS, 'ds:KeyInfo');
        $x509Data = $doc->createElementNS(self::XMLDSIGNS, 'ds:X509Data');
        $x509Cert = $doc->createElementNS(self::XMLDSIGNS, 'ds:X509Certificate', trim((string) $certValue));
        $x509Data->appendChild($x509Cert);
        $keyInfo->appendChild($x509Data);
        $this->sigNode->appendChild($keyInfo);
    }

    public function appendSignature(DOMElement $node): void {
        if (!$this->sigNode instanceof DOMElement) {
            return;
        }
        if ($this->sigNode->parentNode === $node) {
            return;
        }
        $node->insertBefore($this->sigNode, $node->firstChild);
    }

    private function calculateDigest(DOMElement $node): string {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->preserveWhiteSpace = true;
        $doc->formatOutput = false;
        $imported = $doc->importNode($node, true);
        $doc->appendChild($imported);

        $xp = new \DOMXPath($doc);
        $xp->registerNamespace('ds', self::XMLDSIGNS);
        foreach ($xp->query('//ds:Signature') as $sig) {
            if ($sig->parentNode) {
                $sig->parentNode->removeChild($sig);
            }
        }

        $c14n = $doc->documentElement->C14N(true, false);
        if ($c14n === false) {
            return '';
        }

        return base64_encode(hash('sha256', $c14n, true));
    }
}
