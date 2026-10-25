<?php
declare(strict_types=1);

// Bootstrap comune della suite: va incluso da ogni test subito dopo declare(strict_types=1).
// Definisce SOLO ABSPATH e l'helper del marker finale; gli shim WordPress restano nei singoli test.

// Nel plugin ABSPATH e' usato solo come guardia (defined('ABSPATH') || exit;), mai per costruire path:
// basta una directory esistente, qui la root del plugin.
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__) . DIRECTORY_SEPARATOR);
}

if (!function_exists('wp_spid_cie_test_ok')) {
    /**
     * Stampa il marker finale TEST_OK:<nome>. Va chiamato SOLO dopo l'ultimo assert:
     * il runner considera PASS un test solo con exit code 0 E questo marker presente.
     */
    function wp_spid_cie_test_ok(string $name): void {
        echo 'TEST_OK:' . $name . "\n";
    }
}
