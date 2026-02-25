<?php

class WP_SPID_CIE_OIDC_Spid_Saml_Metadata_Protection {
    public static function toggle(array $options): array {
        $enabled = !empty($options['spid_saml_metadata_require_token']) && (string) $options['spid_saml_metadata_require_token'] === '1';
        $options['spid_saml_metadata_require_token'] = $enabled ? '0' : '1';
        if ($options['spid_saml_metadata_require_token'] === '1' && empty($options['spid_saml_metadata_token'])) {
            $options['spid_saml_metadata_token'] = wp_generate_password(24, false, false);
        }
        return $options;
    }
}
