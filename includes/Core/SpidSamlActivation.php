<?php

/**
 * Determines the effective SPID SAML activation state from plugin options.
 *
 * @since   1.3.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_Spid_Saml_Activation {
    /**
     * Returns true when SPID is enabled and the auth method is 'saml'.
     *
     * @since  1.3.0
     * @param  array $options Plugin options.
     * @return bool
     */
    public static function is_effective_enabled(array $options): bool {
        $spid_enabled = isset($options['spid_enabled']) && (string) $options['spid_enabled'] === '1';
        $method = isset($options['spid_auth_method']) ? self::sanitize_method((string) $options['spid_auth_method']) : self::infer_method_from_legacy($options);
        return $spid_enabled && $method === 'saml';
    }

    /**
     * Syncs the legacy spid_saml_enabled flag with the current effective state.
     *
     * @since  1.3.0
     * @param  array $options Plugin options.
     * @return array Updated options array.
     */
    public static function align_legacy_flag(array $options): array {
        $options['spid_saml_enabled'] = self::is_effective_enabled($options) ? '1' : '0';
        return $options;
    }

    /**
     * Sanitizes and normalizes a spid_auth_method value.
     *
     * @since  1.3.0
     * @param  string $method Raw method string ('saml' or 'oidc').
     * @return string Sanitized method; defaults to 'saml' for unrecognized values.
     */
    public static function sanitize_method(string $method): string {
        $method = strtolower(trim($method));
        return in_array($method, ['saml', 'oidc'], true) ? $method : 'saml';
    }

    private static function infer_method_from_legacy(array $options): string {
        $legacy = isset($options['spid_saml_enabled']) && (string) $options['spid_saml_enabled'] === '1';
        return $legacy ? 'saml' : 'oidc';
    }
}
