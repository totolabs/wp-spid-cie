<?php

/**
 * Contract for storing and consuming OIDC state/nonce pairs.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
interface WP_SPID_CIE_OIDC_StateNonceStoreInterface {
    /**
     * Persists an OIDC state context for later retrieval.
     *
     * @since  1.0.0
     * @param  string $state   Opaque state token.
     * @param  array  $context Associated flow context (nonce, verifier, etc.).
     * @param  int    $ttl     TTL in seconds.
     * @return bool   True on success.
     */
    public function store(string $state, array $context, int $ttl): bool;

    /**
     * Retrieves and deletes the context for a state token (one-time use).
     *
     * @since  1.0.0
     * @param  string $state Opaque state token.
     * @return array|null Flow context, or null if not found or expired.
     */
    public function consume(string $state): ?array;
}

/**
 * WordPress-transient-backed implementation of the state/nonce store.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_TransientStateNonceStore implements WP_SPID_CIE_OIDC_StateNonceStoreInterface {
    const PREFIX = 'spidcie_oidc_state_';

    /**
     * @since  1.0.0
     * @param  string $state   Opaque state token.
     * @param  array  $context Associated flow context.
     * @param  int    $ttl     TTL in seconds.
     * @return bool
     */
    public function store(string $state, array $context, int $ttl): bool {
        $key = $this->buildKey($state);
        return set_transient($key, $context, $ttl);
    }

    /**
     * @since  1.0.0
     * @param  string $state Opaque state token.
     * @return array|null Flow context, or null if not found or expired.
     */
    public function consume(string $state): ?array {
        $key = $this->buildKey($state);
        $value = get_transient($key);
        delete_transient($key);

        if (!is_array($value)) {
            return null;
        }

        return $value;
    }

    private function buildKey(string $state): string {
        return self::PREFIX . md5($state);
    }
}
