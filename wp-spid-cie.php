<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              https://totolabs.it
 * @since             0.1.0
 * @package           WP_SPID_CIE_OIDC
 *
 * @wordpress-plugin
 * Plugin Name:       SPID & CIE Login per WordPress
 * Plugin URI:        https://github.com/totolabs/wp-spid-cie
 * Description:       Abilita l'autenticazione tramite SPID e CIE con protocollo OpenID Connect per le Pubbliche Amministrazioni italiane. Conforme PNRR 1.4.4. Sviluppato da Totolabs Srl.
 * Version:           1.3.1
 * Author:            Totolabs Srl
 * Author URI:        https://totolabs.it
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-spid-cie
 * Domain Path:       /languages
 * Requires at least: 6.0
 * Requires PHP:      7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

if ( ! defined( 'WP_SPID_CIE_OIDC_VERSION' ) ) {
	define( 'WP_SPID_CIE_OIDC_VERSION', '1.3.1' );
}

// 1. Load Composer autoloader (external libraries)
if ( file_exists( plugin_dir_path( __FILE__ ) . 'vendor/autoload.php' ) ) {
    require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';
}

// 2. Load our Factory (configuration and key management)
require_once plugin_dir_path( __FILE__ ) . 'includes/class-wp-spid-cie-factory.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-wp-spid-cie-spid-certificates.php';

// 2.b Core OIDC runtime services (Milestone 1)
require_once plugin_dir_path( __FILE__ ) . 'includes/Logging/Logger.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Core/PkceService.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Core/StateNonceStore.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Core/TokenValidator.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Core/OidcClient.php';

$spid_saml_helpers_ok = true;
$spid_saml_missing_helpers = [];

$activation_relative_file = 'includes/Core/SpidSamlActivation.php';
$activation_file = plugin_dir_path( __FILE__ ) . $activation_relative_file;
if ( file_exists( $activation_file ) ) {
    require_once $activation_file;
} else {
    $spid_saml_helpers_ok = false;
    $spid_saml_missing_helpers[] = $activation_relative_file;
    if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
        error_log( '[wp-spid-cie] Missing file: ' . $activation_file );
    }
}

$metadata_protection_relative_file = 'includes/Core/SpidSamlMetadataProtection.php';
$metadata_protection_file = plugin_dir_path( __FILE__ ) . $metadata_protection_relative_file;
if ( file_exists( $metadata_protection_file ) ) {
    require_once $metadata_protection_file;
} else {
    $spid_saml_helpers_ok = false;
    $spid_saml_missing_helpers[] = $metadata_protection_relative_file;
    if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
        error_log( '[wp-spid-cie] Missing file: ' . $metadata_protection_file );
    }
}

if ( ! defined( 'WP_SPID_CIE_OIDC_SAML_HELPERS_OK' ) ) {
    define( 'WP_SPID_CIE_OIDC_SAML_HELPERS_OK', $spid_saml_helpers_ok );
}

if ( ! defined( 'WP_SPID_CIE_OIDC_SAML_MISSING_HELPERS' ) ) {
    define( 'WP_SPID_CIE_OIDC_SAML_MISSING_HELPERS', implode( ',', $spid_saml_missing_helpers ) );
}

require_once plugin_dir_path( __FILE__ ) . 'includes/Providers/ProviderProfileInterface.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Providers/DiscoveryResolver.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Providers/SpidProviderProfile.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Providers/CieProviderProfile.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Providers/ProviderRegistry.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/WP/WpUserMapper.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/WP/WpAuthService.php';

// 3. Load Admin and Public classes
require_once plugin_dir_path( __FILE__ ) . 'admin/class-wp-spid-cie-admin.php';
require_once plugin_dir_path( __FILE__ ) . 'public/class-wp-spid-cie-public.php';


/**
 * Runs the plugin.
 * Initializes the Admin class (when in wp-admin) and the Public class (always).
 */
function run_wp_spid_cie() {

    $plugin_name = 'wp-spid-cie';
    $version = WP_SPID_CIE_OIDC_VERSION;

    // Start Admin side (only when loading /wp-admin/)
    if ( is_admin() ) {
        $plugin_admin = new WP_SPID_CIE_OIDC_Admin( $plugin_name, $version );
    }

    // Bootstrap runtime services once (OIDC client, mapper, auth, provider registry)
    WP_SPID_CIE_OIDC_Factory::get_runtime_services();
    WP_SPID_CIE_OIDC_Factory::get_provider_registry();

    // Start Public side (login, callbacks, shortcodes, federation endpoints)
    $plugin_public = new WP_SPID_CIE_OIDC_Public( $plugin_name, $version );

}

/**
 * Sets default option values on first activation.
 */
function wp_spid_cie_activate() {
    $option_name = 'wp-spid-cie_options';
    $options = get_option($option_name, []);

    // Set each default only if the field is empty or missing
    $defaults = [
        'cie_trust_anchor_preprod' => '',
        'cie_trust_anchor_prod'    => 'https://oidc.registry.servizicie.interno.gov.it',
        'spid_trust_anchor'        => '',
    ];

    $updated = false;
    foreach ($defaults as $k => $v) {
        if (empty($options[$k])) {
            $options[$k] = $v;
            $updated = true;
        }
    }

    if ($updated) {
        update_option($option_name, $options);
    }

    // Sync W3TC exclusion list at most once per day to avoid a DB query on every page load.
    if ( ! get_transient( 'wp_spid_cie_w3tc_synced' ) ) {
        wp_spid_cie_sync_w3tc_exclusion();
        set_transient( 'wp_spid_cie_w3tc_synced', 1, DAY_IN_SECONDS );
    }
}

/**
 * Adds paths of pages containing [spid_cie_login] to W3 Total Cache's
 * pgcache.reject.uri list, so they are excluded before advanced-cache.php
 * even decides to serve a cached copy.
 */
function wp_spid_cie_sync_w3tc_exclusion(): void {
    if ( ! defined( 'W3TC' ) || ! class_exists( 'W3TC\\Config' ) ) {
        return;
    }

    global $wpdb;
    $ids = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT ID FROM {$wpdb->posts}
             WHERE post_status = 'publish'
               AND post_type   = 'page'
               AND post_content LIKE %s",
            '%[spid_cie_login%'
        )
    );

    if ( empty( $ids ) ) {
        return;
    }

    $paths = [];
    foreach ( $ids as $id ) {
        $link = get_permalink( (int) $id );
        if ( $link ) {
            $path = rtrim( (string) parse_url( $link, PHP_URL_PATH ), '/' );
            if ( $path !== '' ) {
                $paths[] = $path;
            }
        }
    }

    if ( empty( $paths ) ) {
        return;
    }

    try {
        $cfg   = new W3TC\Config();
        $uris  = (array) $cfg->get_array( 'pgcache.reject.uri' );
        $dirty = false;
        foreach ( $paths as $p ) {
            if ( ! in_array( $p, $uris, true ) ) {
                $uris[] = $p;
                $dirty  = true;
            }
        }
        if ( $dirty ) {
            $cfg->set( 'pgcache.reject.uri', array_values( $uris ) );
            $cfg->save();
        }
    } catch ( \Throwable $e ) {
        // W3TC not configured or unavailable — skip silently.
    }

    // Delete existing cached files for the login page(s) so the next GET
    // request is handled by PHP (where DONOTCACHEPAGE prevents re-caching).
    if ( function_exists( 'w3tc_pgcache_flush_url' ) ) {
        foreach ( $paths as $p ) {
            w3tc_pgcache_flush_url( home_url( $p ) );
            w3tc_pgcache_flush_url( home_url( $p . '/' ) );
        }
    }
}

/**
 * Re-syncs W3TC exclusion when a page containing the login shortcode is saved.
 */
function wp_spid_cie_on_page_save( int $post_id ): void {
    if ( wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) ) {
        return;
    }
    $post = get_post( $post_id );
    if ( $post instanceof WP_Post && has_shortcode( $post->post_content, 'spid_cie_login' ) ) {
        delete_transient( 'wp_spid_cie_w3tc_synced' );
        wp_spid_cie_sync_w3tc_exclusion();
        set_transient( 'wp_spid_cie_w3tc_synced', 1, DAY_IN_SECONDS );
    }
}

register_activation_hook(__FILE__, 'wp_spid_cie_activate');

/**
 * Adds the "Settings" link to the WordPress plugin action links.
 *
 * @param array $links Current action links.
 * @return array
 */
function wp_spid_cie_plugin_action_links( $links ) {
	$settings_url = admin_url( 'admin.php?page=wp-spid-cie' );
	$settings_link = '<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'wp-spid-cie' ) . '</a>';

	array_unshift( $links, $settings_link );

	return $links;
}

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'wp_spid_cie_plugin_action_links' );

add_action('plugins_loaded', function () {
    // Set defaults also on already-active installs (upgrade-safe)
    wp_spid_cie_activate();
});

add_action( 'save_post_page', 'wp_spid_cie_on_page_save' );
add_action( 'update_option_wp-spid-cie_options', function () {
    delete_transient( 'wp_spid_cie_w3tc_synced' );
    wp_spid_cie_sync_w3tc_exclusion();
    set_transient( 'wp_spid_cie_w3tc_synced', 1, DAY_IN_SECONDS );
} );

// Bootstrap everything
run_wp_spid_cie();
