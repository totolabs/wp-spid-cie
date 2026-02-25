<?php

class WP_SPID_CIE_OIDC_Spid_Saml_Activation {
    public static function is_effective_enabled(array $options): bool {
        $spid_enabled = isset($options['spid_enabled']) && (string) $options['spid_enabled'] === '1';
        $method = isset($options['spid_auth_method']) ? self::sanitize_method((string) $options['spid_auth_method']) : self::infer_method_from_legacy($options);
        return $spid_enabled && $method === 'saml';
    }

    public static function align_legacy_flag(array $options): array {
        $options['spid_saml_enabled'] = self::is_effective_enabled($options) ? '1' : '0';
        return $options;
    }

    public static function sanitize_method(string $method): string {
        $method = strtolower(trim($method));
        return in_array($method, ['saml', 'oidc'], true) ? $method : 'saml';
    }

    private static function infer_method_from_legacy(array $options): string {
        $legacy = isset($options['spid_saml_enabled']) && (string) $options['spid_saml_enabled'] === '1';
        return $legacy ? 'saml' : 'oidc';
    }
}
