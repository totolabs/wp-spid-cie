<?php
declare(strict_types=1);

// Runner della suite: esegue ogni test tracciato in un processo PHP separato.
// PASS solo con exit code 0 E marker finale TEST_OK:<nome>; exit 0 senza marker = FAIL.
// Uso: php tests/run-tests.php

// Lista ESPLICITA: niente discovery di tests/*.php, che includerebbe bootstrap, runner
// e file non della suite.
$tests = [
    'cie-federation-entity-configuration',
    'cie-key-autogeneration-guard',
    'disclaimer-defaults',
    'spid-certificates-integration',
    'spid-oidc-removal-guard',
    'spid-plugin-bootstrap-missing-helper-smoke',
    'spid-saml-effective-activation',
    'spid-saml-idp-logo-resolution',
    'spid-saml-metadata-determinism',
    'spid-saml-metadata-official-path-and-aggregator',
    'spid-saml-metadata-token-toggle',
    'spid-saml-public-enqueue-smoke',
    'spid-saml-readiness',
];

$root = dirname(__DIR__);
$results = [];

foreach ($tests as $name) {
    $path = __DIR__ . DIRECTORY_SEPARATOR . $name . '.php';
    echo "=== {$name}\n";

    if (!is_file($path)) {
        echo "file non trovato: {$path}\n";
        $results[$name] = ['exit' => null, 'marker' => false, 'pass' => false];
        continue;
    }

    // stderr rediretto su stdout: output, fatal e assert restano visibili e nell'ordine originale.
    $process = proc_open(
        [PHP_BINARY, $path],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
        $pipes,
        $root
    );
    if (!is_resource($process)) {
        echo "impossibile avviare il processo PHP\n";
        $results[$name] = ['exit' => null, 'marker' => false, 'pass' => false];
        continue;
    }

    fclose($pipes[0]);
    $output = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $exitCode = proc_close($process);

    echo $output;
    if ($output !== '' && substr($output, -1) !== "\n") {
        echo "\n";
    }

    $marker = preg_match('/^TEST_OK:' . preg_quote($name, '/') . '\r?$/m', $output) === 1;
    $pass = $exitCode === 0 && $marker;
    $results[$name] = ['exit' => $exitCode, 'marker' => $marker, 'pass' => $pass];

    echo '--- ' . ($pass ? 'PASS' : 'FAIL') . " (exit={$exitCode}, marker=" . ($marker ? 'si' : 'no') . ")\n\n";
}

echo "=== Riepilogo\n";
$failed = 0;
foreach ($results as $name => $result) {
    if (!$result['pass']) {
        $failed++;
    }
    $exit = $result['exit'] === null ? '-' : (string) $result['exit'];
    printf("%-4s  exit=%-4s marker=%-2s  %s\n", $result['pass'] ? 'PASS' : 'FAIL', $exit, $result['marker'] ? 'si' : 'no', $name);
}
printf("%d/%d PASS\n", count($results) - $failed, count($results));

exit($failed === 0 ? 0 : 1);
