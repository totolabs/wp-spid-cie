<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// H1 hardening chiavi: il normale salvataggio admin non deve mai rigenerare/sovrascrivere
// un'identita' crittografica esistente o degradata. L'autogenerazione resta consentita SOLO al
// bootstrap realmente vergine: directory attiva == primaria e primaria senza ENTRAMBI i file.
// Il materiale usato e' fittizio (contenuti segnaposto, nessuna chiave reale) e vive solo in
// tests/tmp-keygen-guard, rimossa a fine processo.

$tmpRoot = __DIR__ . '/tmp-keygen-guard';
$primaryDir = $tmpRoot . '/uploads/wp-spid-cie-keys';
$fallbackDir = $tmpRoot . '/uploads/spid-cie-oidc-keys';

function keygen_guard_rmdir(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        is_dir($path) ? keygen_guard_rmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}
register_shutdown_function(static function () use ($tmpRoot): void { keygen_guard_rmdir($tmpRoot); });

/** Prepara le due directory: $primary/$fallback = lista dei file da creare (contenuto fittizio). */
function keygen_guard_setup(string $primaryDir, string $fallbackDir, array $primary, array $fallback): void {
    keygen_guard_rmdir(dirname($primaryDir));
    @mkdir($primaryDir, 0777, true);
    @mkdir($fallbackDir, 0777, true);
    foreach ($primary as $f) { file_put_contents($primaryDir . '/' . $f, "placeholder-primary-{$f}\n"); }
    foreach ($fallback as $f) { file_put_contents($fallbackDir . '/' . $f, "placeholder-fallback-{$f}\n"); }
}

// --- Stub WordPress minimi ---
if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('trailingslashit')) { function trailingslashit($s) { return rtrim((string) $s, "/\\") . '/'; } }
if (!function_exists('untrailingslashit')) { function untrailingslashit($s) { return rtrim((string) $s, "/\\"); } }
if (!function_exists('plugin_dir_path')) { function plugin_dir_path($f) { return rtrim(dirname((string) $f), "/\\") . '/'; } }
if (!function_exists('get_option')) { function get_option($k, $d = []) { return $k === 'wp-spid-cie_options' ? [] : $d; } }
if (!function_exists('sanitize_key')) { function sanitize_key($v) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $v)); } }
if (!function_exists('sanitize_text_field')) { function sanitize_text_field($v) { return trim((string) $v); } }
if (!function_exists('sanitize_textarea_field')) { function sanitize_textarea_field($v) { return trim((string) $v); } }
if (!function_exists('esc_url_raw')) { function esc_url_raw($v) { return (string) $v; } }
if (!function_exists('wp_kses_post')) { function wp_kses_post($v) { return (string) $v; } }
if (!function_exists('wp_unslash')) { function wp_unslash($v) { return $v; } }
if (!function_exists('get_role')) { function get_role($r) { return null; } }
$GLOBALS['keygen_guard_settings_errors'] = [];
if (!function_exists('add_settings_error')) {
    function add_settings_error($setting, $code, $message, $type = 'error') {
        $GLOBALS['keygen_guard_settings_errors'][] = ['code' => $code, 'message' => $message, 'type' => $type];
    }
}

// --- Stub Factory (resolver) e Certificates (conteggio chiamate a generate) ---
class WP_SPID_CIE_OIDC_Factory {
    public static $active = '';
    public static $primary = '';
    public static function resolve_spid_key_dir(bool $for_generation = false): string {
        return $for_generation ? self::$primary : self::$active;
    }
}
class WP_SPID_CIE_OIDC_Spid_Certificates {
    public static $generate_calls = 0;
    public static function generate(array $options = [], bool $force = false): array {
        self::$generate_calls++;
        return ['success' => true, 'paths' => [], 'errors' => []];
    }
}

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$adminFile = __DIR__ . '/../admin/class-wp-spid-cie-admin.php';
require_once $adminFile;
$admin = new WP_SPID_CIE_OIDC_Admin('wp-spid-cie', 'test');
$classify = new ReflectionMethod($admin, 'classify_initial_key_generation');
$classify->setAccessible(true);
$decide = static function (string $active) use ($admin, $classify, $primaryDir): string {
    return (string) $classify->invoke($admin, $active, $primaryDir);
};

// --- Casi A-F sulla decisione reale ---
$both = ['private.key', 'public.crt'];

keygen_guard_setup($primaryDir, $fallbackDir, [], []);
assert_true($decide($primaryDir) === 'generate', 'A: primaria vergine con ACTIVE=PRIMARY deve consentire la generazione iniziale.');
assert_true($decide($primaryDir . '/') === 'generate', 'A: il trailing slash non deve cambiare la decisione.');

keygen_guard_setup($primaryDir, $fallbackDir, $both, []);
assert_true($decide($primaryDir) === 'complete', 'B: primaria completa non deve generare.');

keygen_guard_setup($primaryDir, $fallbackDir, ['private.key'], []);
assert_true($decide($primaryDir) === 'partial', 'C: primaria con solo private.key non deve generare.');

keygen_guard_setup($primaryDir, $fallbackDir, ['public.crt'], []);
assert_true($decide($primaryDir) === 'partial', 'D: primaria con solo public.crt non deve generare.');

keygen_guard_setup($primaryDir, $fallbackDir, [], $both);
assert_true($decide($fallbackDir) === 'active_not_primary', 'E: primaria vuota con ACTIVE=FALLBACK non deve generare.');

keygen_guard_setup($primaryDir, $fallbackDir, ['public.crt'], $both);
assert_true($decide($fallbackDir) === 'partial', 'F: primaria parziale con ACTIVE=FALLBACK non deve generare.');

keygen_guard_setup($primaryDir, $fallbackDir, $both, $both);
assert_true($decide($primaryDir) === 'complete', 'Primaria completa + fallback completo non deve generare.');

// --- Salvataggio completo (tab ente) ---
$save = static function () use ($admin): void {
    $GLOBALS['keygen_guard_settings_errors'] = [];
    WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls = 0;
    $admin->sanitize_options(['_current_tab' => 'ente', 'organization_name' => 'Ente di Test']);
};

// Stato parziale: nessuna generate(), file superstite byte-identico, errore admin senza path.
keygen_guard_setup($primaryDir, $fallbackDir, ['public.crt'], []);
WP_SPID_CIE_OIDC_Factory::$active = $primaryDir;
WP_SPID_CIE_OIDC_Factory::$primary = $primaryDir;
$before = (string) file_get_contents($primaryDir . '/public.crt');
$save();
assert_true(WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls === 0, 'Save con coppia parziale: generate() non deve essere chiamato.');
assert_true(is_file($primaryDir . '/public.crt') && (string) file_get_contents($primaryDir . '/public.crt') === $before, 'Save con coppia parziale: il file superstite deve restare byte-identico.');
assert_true(!is_file($primaryDir . '/private.key'), 'Save con coppia parziale: nessuna private.key deve comparire.');
$codes = array_column($GLOBALS['keygen_guard_settings_errors'], 'code');
assert_true(in_array('spid_cie_key_pair_incomplete', $codes, true), 'Save con coppia parziale: atteso avviso spid_cie_key_pair_incomplete.');
foreach ($GLOBALS['keygen_guard_settings_errors'] as $err) {
    assert_true(strpos($err['message'], 'tmp-keygen-guard') === false && strpos($err['message'], 'uploads') === false, "L'avviso non deve contenere path.");
}

// Stato parziale opposto (solo private.key): idem.
keygen_guard_setup($primaryDir, $fallbackDir, ['private.key'], []);
$before = (string) file_get_contents($primaryDir . '/private.key');
$save();
assert_true(WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls === 0, 'Save con solo private.key: generate() non deve essere chiamato.');
assert_true((string) file_get_contents($primaryDir . '/private.key') === $before, 'Save con solo private.key: il file superstite deve restare byte-identico.');

// ACTIVE=FALLBACK con primaria vuota: nessuna generate().
keygen_guard_setup($primaryDir, $fallbackDir, [], $both);
WP_SPID_CIE_OIDC_Factory::$active = $fallbackDir;
$save();
assert_true(WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls === 0, 'Save con ACTIVE=FALLBACK: generate() non deve essere chiamato.');

// Coppia completa: nessuna generate(), nessun avviso di coppia incompleta.
keygen_guard_setup($primaryDir, $fallbackDir, $both, []);
WP_SPID_CIE_OIDC_Factory::$active = $primaryDir;
$save();
assert_true(WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls === 0, 'Save con coppia completa: generate() non deve essere chiamato.');
assert_true(!in_array('spid_cie_key_pair_incomplete', array_column($GLOBALS['keygen_guard_settings_errors'], 'code'), true), 'Save con coppia completa: nessun avviso di coppia incompleta.');

// Bootstrap vergine: la generazione iniziale resta raggiungibile (una sola chiamata, non forzata).
keygen_guard_setup($primaryDir, $fallbackDir, [], []);
$save();
assert_true(WP_SPID_CIE_OIDC_Spid_Certificates::$generate_calls === 1, 'Save al bootstrap vergine: generate() deve essere chiamato esattamente una volta.');

// --- G. Guardia strutturale: la vecchia semantica "manca almeno un file -> genera" non esiste piu' ---
$source = (string) file_get_contents($adminFile);
assert_true(preg_match('/!\s*file_exists\(\s*\$private_path\s*\)\s*\|\|\s*!\s*file_exists\(\s*\$cert_path\s*\)/', $source) === 0, "La condizione '!file_exists(private) || !file_exists(cert)' non deve piu' esistere nell'admin.");
assert_true(strpos($source, '$must_generate') === false, "La variabile \$must_generate non deve piu' esistere nell'admin.");
assert_true(substr_count($source, 'WP_SPID_CIE_OIDC_Spid_Certificates::generate(') === 1, 'Nel save deve restare una sola chiamata a Spid_Certificates::generate().');
assert_true(preg_match("/if \\(\\\$key_state === 'generate'\\) \\{\\s*\\\$generation = WP_SPID_CIE_OIDC_Spid_Certificates::generate\\(/", $source) === 1, "generate() nel save deve essere comandato SOLO da \$key_state === 'generate'.");

keygen_guard_rmdir($tmpRoot);
assert_true(!is_dir($tmpRoot), 'La directory temporanea del test deve essere rimossa.');

echo "autogenerazione chiavi: solo bootstrap vergine, nessuna rotazione implicita: OK\n";
wp_spid_cie_test_ok('cie-key-autogeneration-guard');
