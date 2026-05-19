<?php

/**
 * PKCE (Proof Key for Code Exchange) helper for OIDC authorization flows.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_PkceService {

    /**
     * Generates a cryptographically random PKCE code verifier.
     *
     * @since  1.0.0
     * @return string Base64url-encoded 64-byte random verifier.
     */
    public function generateVerifier(): string {
        return $this->base64urlEncode(random_bytes(64));
    }

    /**
     * Computes the PKCE code challenge from a verifier.
     *
     * @since  1.0.0
     * @param  string $verifier The PKCE code verifier.
     * @return string Base64url-encoded SHA-256 hash of the verifier.
     */
    public function generateChallenge(string $verifier): string {
        return $this->base64urlEncode(hash('sha256', $verifier, true));
    }

    /**
     * Returns the PKCE challenge method identifier.
     *
     * @since  1.0.0
     * @return string Always 'S256'.
     */
    public function getChallengeMethod(): string {
        return 'S256';
    }

    private function base64urlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
