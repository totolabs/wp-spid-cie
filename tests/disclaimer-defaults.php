<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

// Default del disclaimer: nessun testo site-specific (messaggio operativo OFI) come default di prodotto.
// - il campo registrato non porta piu' 'default': su installazione nuova la textarea resta vuota
//   (e il primo salvataggio non persiste piu' il testo OFI);
// - un testo gia' salvato dall'ente e' riproposto identico (preservazione, nessuna migrazione);
// - l'anteprima admin a opzione vuota non stampa nulla.
// Solo letture: nessun file scritto su disco, niente cleanup.

if (!function_exists('add_action')) { function add_action(...$args) {} }
if (!function_exists('add_filter')) { function add_filter(...$args) {} }
if (!function_exists('add_shortcode')) { function add_shortcode(...$args) {} }

$GLOBALS['test_options'] = [];
if (!function_exists('get_option')) {
    function get_option($key, $default = []) {
        if ($key === 'wp-spid-cie_options') {
            return $GLOBALS['test_options'];
        }
        return $default;
    }
}
if (!function_exists('esc_attr')) { function esc_attr($v) { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); } }
if (!function_exists('esc_textarea')) { function esc_textarea($v) { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); } }
if (!function_exists('esc_html')) { function esc_html($v) { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); } }
if (!function_exists('wp_kses_post')) { function wp_kses_post($v) { return (string) $v; } }
if (!function_exists('__')) { function __($text, $domain = 'default') { return $text; } }
if (!function_exists('esc_html__')) { function esc_html__($text, $domain = 'default') { return $text; } }
if (!function_exists('plugin_dir_path')) { function plugin_dir_path($file) { return rtrim(dirname((string) $file . '/x'), '/\\') . '/'; } }
if (!function_exists('plugin_dir_url')) { function plugin_dir_url($file) { return 'https://example.test/wp-content/plugins/wp-spid-cie/'; } }

function assert_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function capture_output(callable $fn): string {
    ob_start();
    $fn();
    return (string) ob_get_clean();
}

$adminFile = __DIR__ . '/../admin/class-wp-spid-cie-admin.php';
require_once $adminFile;

$admin = new WP_SPID_CIE_OIDC_Admin('wp-spid-cie', 'test');
$ofiPhrase = 'temporaneamente non disponibile per aggiornamento tecnico';
// Il campo come e' registrato ora: senza chiave 'default'.
$field = ['id' => 'disclaimer_text', 'label_for' => 'disclaimer_text', 'desc' => 'x'];
$renderField = static function () use ($admin, $field): void { $admin->render_textarea_field($field); };

// A. Il sorgente dell'admin non contiene piu' il testo operativo OFI.
$source = (string) file_get_contents($adminFile);
assert_true(strpos($source, $ofiPhrase) === false, "Il sorgente dell'admin non deve contenere il testo OFI.");

// A2. Guardia strutturale: disclaimer_text e' registrato SENZA alcuna chiave 'default' (non solo senza testo OFI).
// Segmento = da add_settings_field('disclaimer_text' al primo ');' successivo, che chiude quella chiamata.
$fieldCall = "add_settings_field('disclaimer_text'";
assert_true(substr_count($source, $fieldCall) === 1, "add_settings_field('disclaimer_text' deve comparire esattamente 1 volta nell'admin.");
$segStart = (int) strpos($source, $fieldCall);
$segEnd = strpos($source, ');', $segStart);
assert_true($segEnd !== false, "Chiusura ');' della registrazione disclaimer_text non trovata.");
$fieldSegment = substr($source, $segStart, $segEnd - $segStart + 2);
assert_true(strpos($fieldSegment, "'default' =>") === false, "La registrazione di disclaimer_text non deve contenere alcuna chiave 'default'.");
assert_true(strpos($fieldSegment, "'id' => 'disclaimer_text'") !== false, "La registrazione di disclaimer_text deve contenere 'id' => 'disclaimer_text'.");
assert_true(strpos($fieldSegment, "'label_for' => 'disclaimer_text'") !== false, "La registrazione di disclaimer_text deve contenere 'label_for' => 'disclaimer_text'.");
assert_true(strpos($fieldSegment, "'desc' =>") !== false, "La registrazione di disclaimer_text deve contenere 'desc' =>.");

// B. Opzioni assenti: textarea vuota, nessun testo OFI.
$GLOBALS['test_options'] = [];
$html = capture_output($renderField);
assert_true(preg_match("~<textarea id='disclaimer_text'[^>]*></textarea>~", $html) === 1, 'Con opzioni assenti la textarea disclaimer deve essere vuota.');
assert_true(strpos($html, $ofiPhrase) === false, 'Con opzioni assenti la textarea non deve contenere il testo OFI.');

// C. disclaimer_text salvato vuoto: textarea vuota (niente risalvataggio del testo OFI).
$GLOBALS['test_options'] = ['disclaimer_text' => ''];
$html = capture_output($renderField);
assert_true(preg_match("~<textarea id='disclaimer_text'[^>]*></textarea>~", $html) === 1, 'Con disclaimer_text vuoto la textarea deve restare vuota.');
assert_true(strpos($html, $ofiPhrase) === false, 'Con disclaimer_text vuoto la textarea non deve contenere il testo OFI.');

// D. Testo gia' salvato dall'ente: riproposto identico (preservazione).
$saved = '<strong>Avviso ente</strong>';
$GLOBALS['test_options'] = ['disclaimer_text' => $saved];
$html = capture_output($renderField);
assert_true(strpos($html, '>' . esc_textarea($saved) . '</textarea>') !== false, 'Il testo salvato dall\'ente deve essere riproposto identico nella textarea.');

// E. Anteprima a opzione assente o vuota: nessun output.
$preview = new ReflectionMethod($admin, 'render_disclaimer_preview');
$preview->setAccessible(true);
$renderPreview = static function () use ($preview, $admin): void { $preview->invoke($admin); };

$GLOBALS['test_options'] = [];
$out = capture_output($renderPreview);
assert_true($out === '', 'Con disclaimer_text assente l\'anteprima non deve stampare nulla.');

$GLOBALS['test_options'] = ['disclaimer_text' => ''];
$out = capture_output($renderPreview);
assert_true($out === '', 'Con disclaimer_text vuoto l\'anteprima non deve stampare nulla.');

// F. Anteprima con testo salvato: titolo e contenuto dell'ente.
$GLOBALS['test_options'] = ['disclaimer_text' => $saved];
$out = capture_output($renderPreview);
assert_true(strpos($out, '<h4>Anteprima disclaimer</h4>') !== false, "Con testo salvato l'anteprima deve mostrare il titolo.");
assert_true(strpos($out, $saved) !== false, "Con testo salvato l'anteprima deve mostrare il testo dell'ente.");
assert_true(strpos($out, $ofiPhrase) === false, "L'anteprima non deve mai mostrare il testo OFI.");

echo "disclaimer default neutro, preservazione e anteprima: OK\n";
wp_spid_cie_test_ok('disclaimer-defaults');
