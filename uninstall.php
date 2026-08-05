<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Opt-in esplicito via costante in wp-config.php (pattern WooCommerce WC_REMOVE_ALL_DATA).
// Senza la costante, o se falsa, NON si cancella nulla: default sicuro.
if ( ! defined( 'WP_SPID_CIE_DELETE_DATA_ON_UNINSTALL' ) || ! WP_SPID_CIE_DELETE_DATA_ON_UNINSTALL ) {
    return;
}

global $wpdb;

// Remove plugin options
delete_option( 'wp-spid-cie_options' );

// Transient registry IdP: 4 nomi fissi
// (idp_list_v3, idp_list_lkg_v3, status_v3, registry_list_v1 legacy)
// e 3 famiglie dinamiche per-IdP
// (idp_detail_v3_<md5>, idp_detail_lkg_v3_<md5>, registry_detail_<md5>).
// Il LIKE '_transient_spid_saml_registry_%' li copre tutti.
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '_transient_spid\_saml\_registry\_%'
        OR option_name LIKE '_transient\_timeout\_spid\_saml\_registry\_%'"
);

// Remove user meta added by the plugin
$meta_keys = [
    '_spidcie_provider',
    '_spidcie_sub_spid',
    '_spidcie_sub_cie',
    '_spidcie_fiscal_code',
    '_spidcie_mobile',
    '_spidcie_last_login_ts',
    '_spidcie_last_acr',
];

foreach ( $meta_keys as $key ) {
    $wpdb->delete( $wpdb->usermeta, [ 'meta_key' => $key ], [ '%s' ] );
}
