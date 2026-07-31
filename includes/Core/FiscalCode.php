<?php
defined( 'ABSPATH' ) || exit;

/**
 * Single normalization point for the fiscal code across every authentication flow.
 *
 * SPID SAML delivers the fiscal code bare, while CIE OIDC delivers it prefixed with
 * "TINIT-" (eIDAS uniqueness identifier). Before this class the two flows normalized
 * differently, so the same person produced two distinct WordPress accounts and the
 * fiscal-code lookup in WP_SPID_CIE_OIDC_WpAuthService never matched across protocols.
 *
 * Every flow must call normalize() so the stored value is protocol-independent.
 *
 * @since   1.4.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_FiscalCode {

    /**
     * Prefixes carried by eIDAS/SPID/CIE identifiers, stripped before storage.
     *
     * @since 1.4.0
     * @var   string[]
     */
    const PREFIXES = ['TINIT-', 'TIN-IT-', 'TINIT'];

    /**
     * Normalizes a fiscal code to its bare, uppercase, alphanumeric form.
     *
     * @since  1.4.0
     * @param  string $value Raw fiscal code as delivered by the provider.
     * @return string Normalized fiscal code, or empty string when nothing usable remains.
     */
    public static function normalize($value): string {
        $value = strtoupper(trim((string) $value));
        if ($value === '') {
            return '';
        }

        foreach (self::PREFIXES as $prefix) {
            if (strpos($value, $prefix) === 0) {
                $value = substr($value, strlen($prefix));
                break;
            }
        }

        return preg_replace('/[^A-Z0-9]/', '', $value);
    }

    /**
     * Checks whether a normalized value has the shape of an Italian fiscal code.
     *
     * Used for heuristics only (e.g. deciding whether a search term looks like a
     * fiscal code). Never use it to reject an identity: foreign-issued codes and
     * temporary codes are legitimate and would not match.
     *
     * @since  1.4.0
     * @param  string $value Normalized fiscal code.
     * @return bool True when the value is 16 alphanumeric characters.
     */
    public static function looksLikeFiscalCode($value): bool {
        return (bool) preg_match('/^[A-Z0-9]{16}$/', strtoupper(trim((string) $value)));
    }
}
