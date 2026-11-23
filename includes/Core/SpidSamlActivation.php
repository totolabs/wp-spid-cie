<?php
defined( 'ABSPATH' ) || exit;

/**
 * Determines the effective SPID SAML activation state from plugin options.
 *
 * @since   1.3.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_Spid_Saml_Activation {
    /**
     * Returns true when SPID is enabled. SPID uses SAML only: a legacy
     * spid_auth_method value stored in the database is ignored.
     *
     * @since  1.3.0
     * @param  array $options Plugin options.
     * @return bool
     */
    public static function is_effective_enabled(array $options): bool {
        return isset($options['spid_enabled']) && (string) $options['spid_enabled'] === '1';
    }

    /**
     * Syncs the legacy spid_saml_enabled flag with the current effective state.
     *
     * @since  1.3.0
     * @param  array $options Plugin options.
     * @return array Updated options array.
     */
    public static function align_legacy_flag(array $options): array {
        $options['spid_saml_enabled'] = self::is_effective_enabled($options) ? '1' : '0';
        return $options;
    }

    /**
     * Local SPID SAML readiness policy. Pure: no filesystem, no network.
     *
     * Facts are gathered by the caller: helpers_ok, private_key_readable, cert_readable,
     * cert_valid, idp_registry_count, sp_entity_source ('saml_entity_id', 'issuer_override'
     * or 'home_url') and clock_skew (effective value in seconds).
     *
     * idp_registry_count is ?int: > 0 known and populated, 0 known and empty, null or
     * missing unknown (Registry status not available). Only a known empty Registry warns.
     *
     * IdP completeness (entity_id, sso_url, x509) is not a local blocker: in registry mode
     * IdP details are fetched at login time, where saml_config_incomplete still applies.
     *
     * @since  1.4.2
     * @param  array $options Plugin options.
     * @param  array $facts   Local facts.
     * @return array {ready_local: bool, blockers: array, warnings: array, external_checks: array}
     *               Each list item is ['code' => string, 'message' => string].
     */
    public static function evaluate_readiness(array $options, array $facts): array {
        $blockers = [];
        $warnings = [];

        if (empty($facts['helpers_ok'])) {
            $blockers[] = ['code' => 'saml_helpers_missing', 'message' => 'Helper SAML del plugin non caricati.'];
        }
        if (!self::is_effective_enabled($options)) {
            $blockers[] = ['code' => 'spid_disabled', 'message' => 'SPID non è abilitato nelle Impostazioni.'];
        }
        if (empty($facts['private_key_readable'])) {
            $blockers[] = ['code' => 'private_key_unreadable', 'message' => 'Chiave privata SP (private.key) assente o non leggibile.'];
        }
        if (empty($facts['cert_readable'])) {
            $blockers[] = ['code' => 'cert_unreadable', 'message' => 'Certificato SP (public.crt) assente o non leggibile.'];
        }

        if (array_key_exists('cert_valid', $facts) && $facts['cert_valid'] === false) {
            $warnings[] = ['code' => 'cert_invalid', 'message' => 'Certificato SP non valido o scaduto: AgID e gli IdP possono rifiutarlo.'];
        }
        $registry_count = $facts['idp_registry_count'] ?? null;
        if ($registry_count === 0) {
            $warnings[] = ['code' => 'idp_registry_empty', 'message' => 'Elenco IdP del Registry vuoto: il menu SPID mostra un avviso.'];
        }
        if (($facts['sp_entity_source'] ?? '') === 'home_url') {
            $warnings[] = ['code' => 'sp_entity_home_url', 'message' => 'Entity ID SP ricavato da home_url(): deve coincidere con quello registrato presso AgID.'];
        }
        if (array_key_exists('clock_skew', $facts) && (int) $facts['clock_skew'] === 0) {
            $warnings[] = ['code' => 'clock_skew_zero', 'message' => 'Tolleranza orologio SAML a 0 secondi: i login possono essere rifiutati con saml_not_yet_valid.'];
        }

        return [
            'ready_local' => empty($blockers),
            'blockers' => $blockers,
            'warnings' => $warnings,
            'external_checks' => [
                ['code' => 'agid_metadata', 'message' => 'Accettazione/propagazione dei metadata SP presso AgID (non verificabile localmente).'],
            ],
        ];
    }
}
