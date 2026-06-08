<?php
defined( 'ABSPATH' ) || exit;

add_action('wp_spid_cie_user_identity_updated', function (int $userId, array $identity, string $provider): void {
    if (!defined('GAYADEED_PLUGIN_VERSION')) {
        return;
    }

    $fiscalCode = strtoupper((string) ($identity['fiscal_code'] ?? ''));
    $mobile     = (string) ($identity['mobile'] ?? '');
    $prefix     = (strncmp($mobile, '+39', 3) === 0) ? '+39' : '';

    update_user_meta($userId, 'gayadeed_fiscal_code',  $fiscalCode);
    update_user_meta($userId, 'gayadeed_mobile_phone', $mobile);
    update_user_meta($userId, 'gayadeed_phone_prefix', $prefix);
}, 10, 3);
