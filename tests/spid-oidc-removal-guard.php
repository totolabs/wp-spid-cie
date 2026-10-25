<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// Guardia della rimozione SPID OIDC: provider=spid non entra nel flusso OIDC, il registry
// rifiuta 'spid' e il frontend mostra solo il menu SPID SAML e il link CIE.

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$test_options = [
    'spid_enabled' => '1',
    'cie_enabled' => '1',
    'spid_auth_method' => 'oidc', // valore legacy: deve essere ignorato
    'spid_saml_enabled' => '0',
];
$inline_scripts = [];

if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('get_option')) {
    function get_option($key, $default = []) {
        global $test_options;
        return $key === 'wp-spid-cie_options' ? $test_options : $default;
    }
}
if (!function_exists('plugin_dir_url')) { function plugin_dir_url($file) { return 'http://example.test/plugin/' . basename(dirname($file)) . '/'; } }
if (!function_exists('plugin_dir_path')) { function plugin_dir_path($file) { return rtrim(dirname($file), '/\\') . '/'; } }
if (!function_exists('wp_enqueue_style')) { function wp_enqueue_style(...$args) {} }
if (!function_exists('wp_enqueue_script')) { function wp_enqueue_script(...$args) {} }
if (!function_exists('wp_register_script')) { function wp_register_script(...$args) {} }
if (!function_exists('wp_add_inline_script')) {
    function wp_add_inline_script($handle, $data, $position = 'after') {
        global $inline_scripts;
        $inline_scripts[] = (string) $data;
    }
}
if (!function_exists('sanitize_key')) { function sanitize_key($key) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $key)); } }
if (!function_exists('wp_unslash')) { function wp_unslash($value) { return $value; } }
if (!function_exists('get_query_var')) { function get_query_var($var, $default = '') { return $default; } }
if (!function_exists('home_url')) { function home_url($path = '') { return 'https://example.gov.it' . ($path === '' ? '' : '/' . ltrim((string) $path, '/')); } }
if (!function_exists('add_query_arg')) {
    function add_query_arg(array $args, string $url): string {
        return $url . (strpos($url, '?') === false ? '?' : '&') . http_build_query($args);
    }
}
if (!function_exists('esc_url')) { function esc_url($url) { return (string) $url; } }
if (!function_exists('esc_attr')) { function esc_attr($text) { return htmlspecialchars((string) $text, ENT_QUOTES); } }
if (!function_exists('esc_html')) { function esc_html($text) { return htmlspecialchars((string) $text, ENT_QUOTES); } }
if (!function_exists('wp_kses_post')) { function wp_kses_post($text) { return (string) $text; } }
if (!function_exists('is_wp_error')) { function is_wp_error($thing) { return $thing instanceof WP_Error; } }
if (!function_exists('__')) { function __($text, $domain = 'default') { return $text; } }
if (!function_exists('wp_parse_url')) { function wp_parse_url($url, $component = -1) { return parse_url((string) $url, $component); } }

if (!class_exists('WP_Error')) {
    class WP_Error {
        private $code;
        public function __construct($code = '', $message = '') { $this->code = $code; }
        public function get_error_code() { return $this->code; }
    }
}

final class FactoryCalled extends RuntimeException {}

// Stub Factory: qualsiasi accesso significa che il flusso OIDC e' stato avviato.
class WP_SPID_CIE_OIDC_Factory {
    public static function get_runtime_services() { throw new FactoryCalled('get_runtime_services'); }
    public static function get_client() { throw new FactoryCalled('get_client'); }
    public static function get_provider_registry() { throw new FactoryCalled('get_provider_registry'); }
}

// Stub dei servizi SAML: readiness pronta, lista Registry contata per verificare il singolo accesso.
class WP_SPID_CIE_OIDC_Saml_Service {
    public static $private_key_readable = true;
    public function collect_readiness_facts(array $options): array {
        return [
            'private_key_readable' => self::$private_key_readable,
            'cert_readable' => true,
            'cert_valid' => true,
            'sp_entity_source' => 'saml_entity_id',
            'clock_skew' => 120,
        ];
    }
}
class WP_SPID_CIE_OIDC_Spid_Registry_Service {
    public static $list_calls = 0;
    public static $use_override = false;
    public static $override = null;
    public function get_idp_list(bool $force = false) {
        self::$list_calls++;
        if (self::$use_override) {
            return self::$override;
        }
        return [
            ['entity_id' => 'https://idp-one.example.it', 'name' => 'IdP Uno', 'logo' => ''],
            ['entity_id' => 'https://idp-two.example.it', 'name' => 'IdP Due', 'logo' => ''],
        ];
    }
}
class WP_SPID_CIE_OIDC_DiscoveryResolver {}
class WP_SPID_CIE_OIDC_Wrapper {}

if (!defined('WP_SPID_CIE_OIDC_SAML_HELPERS_OK')) {
    define('WP_SPID_CIE_OIDC_SAML_HELPERS_OK', true);
}

require_once __DIR__ . '/../includes/Core/SpidSamlActivation.php';
require_once __DIR__ . '/../includes/Providers/ProviderProfileInterface.php';
require_once __DIR__ . '/../includes/Providers/CieProviderProfile.php';
require_once __DIR__ . '/../includes/Providers/ProviderRegistry.php';
require_once __DIR__ . '/../public/class-wp-spid-cie-public.php';

$public = new WP_SPID_CIE_OIDC_Public('wp-spid-cie', 'test');

// 1. provider=spid: no-op immediato, Factory mai toccata.
foreach (['login', 'callback'] as $action) {
    $_GET = ['oidc_action' => $action, 'provider' => 'spid', 'idp' => 'poste'];
    try {
        $public->handle_login_flow();
    } catch (FactoryCalled $e) {
        assert_true(false, "oidc_action={$action}&provider=spid non deve raggiungere la Factory ({$e->getMessage()}).");
    }
}

// 2. provider=cie: il flusso OIDC parte e raggiunge la Factory.
$_GET = ['oidc_action' => 'login', 'provider' => 'cie'];
$cieReachedFactory = false;
try {
    $public->handle_login_flow();
} catch (FactoryCalled $e) {
    $cieReachedFactory = true;
}
assert_true($cieReachedFactory, 'oidc_action=login&provider=cie deve raggiungere la Factory.');
$_GET = [];

// 3. Il registry non conosce piu' il provider spid.
$registry = new WP_SPID_CIE_OIDC_ProviderRegistry(new WP_SPID_CIE_OIDC_DiscoveryResolver(), new WP_SPID_CIE_OIDC_Wrapper());
$spidConfig = $registry->resolveConfig('spid');
assert_true($spidConfig instanceof WP_Error && $spidConfig->get_error_code() === 'oidc_provider_not_supported', "resolveConfig('spid') deve restituire WP_Error oidc_provider_not_supported.");

// 4. Frontend: menu SPID SAML e link CIE, nessuna traccia del menu SPID OIDC.
$html = $public->render_login_buttons();
assert_true(is_string($html) && $html !== '', 'render_login_buttons deve produrre HTML con SPID e CIE abilitati.');
assert_true(strpos($html, 'provider=spid') === false, "L'HTML non deve contenere provider=spid.");
assert_true(strpos($html, 'spid-dropdown') === false, "L'HTML non deve contenere spid-dropdown.");
assert_true(strpos($html, 'toggleSpidDropdown') === false, "L'HTML non deve contenere toggleSpidDropdown.");
assert_true(strpos($html, 'spid_saml_route=login') !== false, "L'HTML deve contenere il login SPID SAML (spid_saml_route=login).");
assert_true(strpos($html, 'idp-one.example.it') !== false, "L'HTML deve contenere gli IdP del Registry nel menu SAML.");
assert_true(strpos($html, 'oidc_action=login&provider=cie') !== false || strpos($html, 'oidc_action=login&amp;provider=cie') !== false, "L'HTML deve contenere il link CIE con provider=cie.");
assert_true(WP_SPID_CIE_OIDC_Spid_Registry_Service::$list_calls === 1, 'La lista Registry deve essere letta una sola volta per readiness e menu SAML.');

// 5. Readiness non pronta (chiave privata assente): nessun pulsante SPID, CIE resta.
WP_SPID_CIE_OIDC_Saml_Service::$private_key_readable = false;
$notReadyHtml = $public->render_login_buttons();
assert_true(strpos($notReadyHtml, 'spid_saml_route=login') === false, 'Con readiness non pronta il pulsante SPID non deve comparire.');
assert_true(strpos($notReadyHtml, 'provider=cie') !== false, 'Con readiness SPID non pronta il link CIE deve restare.');
WP_SPID_CIE_OIDC_Saml_Service::$private_key_readable = true;

// 5b. Registry vuoto ([] o WP_Error spid_registry_empty) = conteggio 0 noto; altri WP_Error = sconosciuto.
// In entrambi i casi SPID resta visibile (il menu mostra l'avviso) e la readiness non blocca.
$readinessMethod = new ReflectionMethod(WP_SPID_CIE_OIDC_Public::class, 'get_spid_saml_readiness');
$readinessMethod->setAccessible(true);
$registryCases = [
    'Registry vuoto []' => [[], true],
    'Registry vuoto (spid_registry_empty)' => [new WP_Error('spid_registry_empty', 'vuoto'), true],
    'Registry non disponibile (spid_registry_http_error)' => [new WP_Error('spid_registry_http_error', 'offline'), false],
];
foreach ($registryCases as $label => [$list, $expectEmptyWarning]) {
    $readiness = $readinessMethod->invoke($public, $test_options, $list);
    $warningCodes = array_column($readiness['warnings'], 'code');
    assert_true($readiness['ready_local'] === true && $readiness['blockers'] === [], "{$label}: la readiness non deve bloccare SPID.");
    assert_true(in_array('idp_registry_empty', $warningCodes, true) === $expectEmptyWarning, "{$label}: idp_registry_empty atteso solo per lista vuota nota.");

    WP_SPID_CIE_OIDC_Spid_Registry_Service::$use_override = true;
    WP_SPID_CIE_OIDC_Spid_Registry_Service::$override = $list;
    $registryHtml = $public->render_login_buttons();
    WP_SPID_CIE_OIDC_Spid_Registry_Service::$use_override = false;
    assert_true(strpos($registryHtml, 'Elenco IdP non disponibile') !== false, "{$label}: il menu SPID deve mostrare l'avviso.");
    assert_true(strpos($registryHtml, 'spid-idp-button-menu') !== false, "{$label}: il pulsante SPID deve restare visibile.");
}

$test_options['cie_enabled'] = '0';
$test_options['spid_enabled'] = '0';
assert_true($public->render_login_buttons() === '', 'Con SPID e CIE disabilitati render_login_buttons deve restituire stringa vuota.');

// 6. Nessuno script inline del menu OIDC.
$test_options['spid_enabled'] = '1';
$public->enqueue_styles();
foreach ($inline_scripts as $script) {
    assert_true(strpos($script, 'toggleSpidDropdown') === false, 'Nessuno script inline deve definire toggleSpidDropdown.');
}

echo "provider=spid ignored by OIDC flow: OK\n";
echo "provider=cie reaches OIDC flow: OK\n";
echo "registry rejects spid: OK\n";
echo "login buttons: SPID SAML + CIE only: OK\n";
echo "registry empty vs unavailable mapping: OK\n";
wp_spid_cie_test_ok('spid-oidc-removal-guard');
