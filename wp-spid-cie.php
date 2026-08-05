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
 * Version:           1.4.1
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
	define( 'WP_SPID_CIE_OIDC_VERSION', '1.4.1' );
}

/**
 * Mostra l'interfaccia di configurazione SPID OIDC nel pannello.
 *
 * Il profilo SPID OIDC non e' ancora stabile lato AgID: i relativi campi restano
 * nascosti per non offrire scelte non utilizzabili. Option e codice restano intatti,
 * l'interfaccia riemerge alzando questa costante (anche da wp-config.php).
 *
 * @since 1.4.1
 */
if ( ! defined( 'WP_SPID_CIE_ENABLE_SPID_OIDC' ) ) {
	define( 'WP_SPID_CIE_ENABLE_SPID_OIDC', false );
}

// 1. Load Composer autoloader (external libraries)
if ( file_exists( plugin_dir_path( __FILE__ ) . 'vendor/autoload.php' ) ) {
    require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';
}

// 2. Load our Factory (configuration and key management)
// FiscalCode first: both the SAML service and the OIDC mapper depend on it.
require_once plugin_dir_path( __FILE__ ) . 'includes/Core/FiscalCode.php';
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
require_once plugin_dir_path( __FILE__ ) . 'includes/WP/FiscalCodeMigration.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/Integrations/GayadeedBridge.php';

// 3. Load Admin and Public classes
require_once plugin_dir_path( __FILE__ ) . 'admin/class-wp-spid-cie-admin.php';
require_once plugin_dir_path( __FILE__ ) . 'admin/class-wp-spid-cie-user-profile.php';
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
        $plugin_user_profile = new WP_SPID_CIE_OIDC_User_Profile();
        $plugin_fc_migration = new WP_SPID_CIE_OIDC_FiscalCodeMigration();
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

// Bootstrap everything
run_wp_spid_cie();
