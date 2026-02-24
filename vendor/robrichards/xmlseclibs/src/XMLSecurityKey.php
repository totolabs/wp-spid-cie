<?php

namespace RobRichards\XMLSecLibs;

class XMLSecurityKey {
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    private $type;
    private $key = '';

    public function __construct($type, $params = null) {
        $this->type = (string) $type;
    }

    public function loadKey($key, $isFile = false, $isCert = false): void {
        if ($isFile) {
            $contents = @file_get_contents((string) $key);
            $this->key = is_string($contents) ? $contents : '';
            return;
        }
        $this->key = (string) $key;
    }

    public function signData(string $data): string {
        $algorithm = OPENSSL_ALGO_SHA256;
        $ok = openssl_sign($data, $signature, $this->key, $algorithm);
        if (!$ok) {
            return '';
        }
        return (string) $signature;
    }
}
