<?php
defined( 'ABSPATH' ) || exit;

/**
 * CIE OIDC provider profile.
 *
 * @since   1.3.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_CieProviderProfile implements WP_SPID_CIE_OIDC_ProviderProfileInterface {
    /**
     * @since  1.3.0
     * @return string Always 'cie'.
     */
    public function getProviderKey(): string {
        return 'cie';
    }

    /**
     * @since  1.3.0
     * @param  array                     $options Plugin options.
     * @param  string|null               $idp     Unused for CIE.
     * @param  WP_SPID_CIE_OIDC_Wrapper  $wrapper Provider wrapper.
     * @return array Baseline configuration.
     */
    public function buildBaseConfig(array $options, ?string $idp, WP_SPID_CIE_OIDC_Wrapper $wrapper): array {
        return [
            'provider' => 'cie',
            'provider_id' => 'cie',
            'issuer' => untrailingslashit(!empty($options['cie_issuer']) ? (string) $options['cie_issuer'] : 'https://oidc.idserver.servizicie.interno.gov.it'),
            'authorization_endpoint' => !empty($options['cie_authorization_endpoint']) ? (string) $options['cie_authorization_endpoint'] : 'https://oidc.idserver.servizicie.interno.gov.it/idp/profile/oidc/authorize',
            'token_endpoint' => !empty($options['cie_token_endpoint']) ? (string) $options['cie_token_endpoint'] : 'https://oidc.idserver.servizicie.interno.gov.it/idp/profile/oidc/token',
            'jwks_uri' => !empty($options['cie_jwks_uri']) ? (string) $options['cie_jwks_uri'] : 'https://oidc.idserver.servizicie.interno.gov.it/idp/profile/oidc/keyset',
            'userinfo_endpoint' => !empty($options['cie_userinfo_endpoint']) ? (string) $options['cie_userinfo_endpoint'] : 'https://oidc.idserver.servizicie.interno.gov.it/idp/profile/oidc/userinfo',
            'end_session_endpoint' => (string) ($options['cie_end_session_endpoint'] ?? ''),
        ];
    }

    /**
     * @since  1.3.0
     * @param  array                              $options           Plugin options.
     * @param  string|null                        $idp               Unused for CIE.
     * @param  WP_SPID_CIE_OIDC_Wrapper           $wrapper           Provider wrapper.
     * @param  WP_SPID_CIE_OIDC_DiscoveryResolver $discoveryResolver Discovery service.
     * @return array|WP_Error Resolved configuration, or error.
     */
    public function resolveConfig(array $options, ?string $idp, WP_SPID_CIE_OIDC_Wrapper $wrapper, WP_SPID_CIE_OIDC_DiscoveryResolver $discoveryResolver) {
        $base = $this->buildBaseConfig($options, $idp, $wrapper);
        $mode = $options['discovery_mode'] ?? 'auto';

        if ($mode === 'auto') {
            $resolved = $discoveryResolver->resolveFromIssuer((string) $base['issuer'], 'cie-' . bin2hex(random_bytes(4)));
            if (!is_wp_error($resolved)) {
                $base = array_merge($base, $resolved);
            }
            // If discovery fails, fall back to static endpoints already set in buildBaseConfig.
        }

        $base['scope'] = $this->buildScope($options['cie_scope'] ?? 'openid profile email');
        $base['acr_values'] = $this->resolveAcrValues($options, 'cie');
        $base['min_acr'] = $options['min_loa'] ?? 'SpidL2';
        $base['allow_missing_acr'] = false;

        return $base;
    }

    private function buildScope(string $scope): string {
        $scope = trim(preg_replace('/\s+/', ' ', $scope));
        return $scope === '' ? 'openid profile email' : $scope;
    }

    private function resolveAcrValues(array $options, string $provider): string {
        if (!empty($options[$provider . '_acr_values'])) {
            return (string) $options[$provider . '_acr_values'];
        }

        $map = [
            'SpidL1' => 'https://www.cie.gov.it/IAL1',
            'SpidL2' => 'https://www.cie.gov.it/IAL2',
            'SpidL3' => 'https://www.cie.gov.it/IAL3',
        ];

        $min = $options['min_loa'] ?? 'SpidL2';
        return $map[$min] ?? $map['SpidL2'];
    }
}
