<?php

/**
 * Manages token-based protection for the SPID SAML SP metadata endpoint.
 *
 * @since   1.3.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_Spid_Saml_Metadata_Protection {
    /**
     * Toggles token protection on/off and auto-generates a token when enabling.
     *
     * @since  1.3.0
     * @param  array $options Plugin options.
     * @return array Updated options array.
     */
    public static function toggle(array $options): array {
        $enabled = !empty($options['spid_saml_metadata_require_token']) && (string) $options['spid_saml_metadata_require_token'] === '1';
        $options['spid_saml_metadata_require_token'] = $enabled ? '0' : '1';
        if ($options['spid_saml_metadata_require_token'] === '1' && empty($options['spid_saml_metadata_token'])) {
            $options['spid_saml_metadata_token'] = wp_generate_password(24, false, false);
        }
        return $options;
    }
}
