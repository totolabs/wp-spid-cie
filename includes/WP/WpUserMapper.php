<?php
defined( 'ABSPATH' ) || exit;

/**
 * Maps raw OIDC provider claims to the normalized internal identity schema.
 *
 * @since   1.0.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_WpUserMapper {
    private $logger;

    /**
     * @since 1.0.0
     * @param WP_SPID_CIE_OIDC_Logger $logger
     */
    public function __construct(WP_SPID_CIE_OIDC_Logger $logger) {
        $this->logger = $logger;
    }

    /**
     * Normalize provider claims into stable internal schema.
     */
    public function normalizeClaims(array $claims, string $provider): array {
        $email = $this->pickFirst($claims, ['email', 'mail']);
        $givenName = $this->pickFirst($claims, ['given_name', 'name']);
        $familyName = $this->pickFirst($claims, ['family_name', 'familyName', 'surname']);
        // CIE userinfo restituisce il codice fiscale con la chiave URI piena.
        $fiscalCode = $this->pickFirst($claims, [
            'fiscal_code', 'fiscalCode', 'fiscalNumber', 'fiscal_number', 'cf', 'tax_id',
            'https://attributes.eid.gov.it/fiscal_number',
        ]);
        $mobile = $this->pickFirst($claims, [
            'phone_number', 'phoneNumber',
            'mobilePhone', 'mobile', 'mobile_phone', 'cellulare',
            'https://attributes.eid.gov.it/phone_number',
        ]);

        return [
            'provider' => $provider,
            'sub' => $this->sanitizeText($claims['sub'] ?? ''),
            'email' => sanitize_email((string) $email),
            'given_name' => $this->sanitizeText($givenName),
            'family_name' => $this->sanitizeText($familyName),
            // CIE consegna il codice fiscale con prefisso TINIT-, SPID SAML nudo: senza
            // normalizzazione condivisa la stessa persona produce due account distinti.
            'fiscal_code' => WP_SPID_CIE_OIDC_FiscalCode::normalize($this->sanitizeText($fiscalCode)),
            'mobile' => $this->normalizeMobile($mobile),
        ];
    }

    /**
     * Mandatory PA-grade validation.
     */
    public function validateMandatoryClaims(array $normalized, string $correlationId) {
        $missing = [];
        $provider = (string) ($normalized['provider'] ?? '');

        if (empty($normalized['sub'])) {
            $missing[] = 'sub';
        }
        if (empty($normalized['given_name'])) {
            $missing[] = 'given_name';
        }
        if (empty($normalized['family_name'])) {
            $missing[] = 'family_name';
        }
        if (empty($normalized['fiscal_code'])) {
            $missing[] = 'fiscal_code';
        }
        // Email obbligatoria per SPID (sempre garantita), opzionale per CIE (non sempre
        // memorizzata sulla carta). Per CIE manca -> WpAuthService genera email sintetica.
        if ($provider === 'spid' && (empty($normalized['email']) || !is_email($normalized['email']))) {
            $missing[] = 'email';
        }
        // Mobile non piu' obbligatoria: phone_number per CIE e' best-effort,
        // mobilePhone per SPID dipende dal profilo del provider.

        if (!empty($missing)) {
            $this->logger->error('OIDC mandatory claims missing', [
                'correlation_id' => $correlationId,
                'provider' => $normalized['provider'] ?? 'unknown',
                'missing' => implode(',', $missing),
            ]);
            return new WP_Error('oidc_missing_required_claims', __('Autenticazione SPID/CIE non completata.', 'wp-spid-cie'));
        }

        return true;
    }

    private function pickFirst(array $claims, array $keys): string {
        foreach ($keys as $key) {
            if (isset($claims[$key]) && $claims[$key] !== null && $claims[$key] !== '') {
                return (string) $claims[$key];
            }
        }
        return '';
    }

    private function sanitizeText(string $value): string {
        return sanitize_text_field(trim($value));
    }

    private function normalizeMobile(string $value): string {
        $v = preg_replace('/\s+/', '', (string) $value);
        $v = preg_replace('/[^0-9\+]/', '', $v);
        return sanitize_text_field($v ?? '');
    }
}
