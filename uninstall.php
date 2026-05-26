<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

// Remove plugin options
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wp-spid-cie\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'spid\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'cie\_%'" );

// Remove all registry transients (list, LKG, per-IdP detail)
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
