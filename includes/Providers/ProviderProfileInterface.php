<?php

/**
 * Contract for SPID and CIE provider configuration profiles.
 *
 * @since   1.3.0
 * @package WP_SPID_CIE_OIDC
 */
interface WP_SPID_CIE_OIDC_ProviderProfileInterface {
    /**
     * Returns the unique provider key for this profile.
     *
     * @since  1.3.0
     * @return string Provider key (e.g. 'spid' or 'cie').
     */
    public function getProviderKey(): string;

    /**
     * Build provider-specific baseline config (pre-discovery/manual override).
     */
    public function buildBaseConfig(array $options, ?string $idp, WP_SPID_CIE_OIDC_Wrapper $wrapper): array;

    /**
     * Returns normalized config by applying discovery/manual endpoint strategy.
     */
    public function resolveConfig(
        array $options,
        ?string $idp,
        WP_SPID_CIE_OIDC_Wrapper $wrapper,
        WP_SPID_CIE_OIDC_DiscoveryResolver $discoveryResolver
    );
}
