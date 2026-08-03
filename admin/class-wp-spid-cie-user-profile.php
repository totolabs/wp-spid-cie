<?php
defined( 'ABSPATH' ) || exit;

/**
 * Surfaces the SPID/CIE fiscal code inside the WordPress users UI.
 *
 * The fiscal code is the only stable identifier across SPID and CIE: the email can
 * change and CIE often does not carry one at all. WP_SPID_CIE_OIDC_WpAuthService
 * already reconciles identities on it, but the value lived in a protected meta with
 * no interface, so an administrator could neither inspect nor repair a link.
 *
 * This class adds: a profile field, a users-list column, and fiscal-code search.
 *
 * @since   1.4.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_User_Profile {

    /**
     * Meta key holding the normalized fiscal code.
     *
     * @since 1.4.0
     * @var   string
     */
    const META_KEY = '_spidcie_fiscal_code';

    /**
     * Transient prefix used to carry a save error across the post-update redirect.
     *
     * @since 1.4.0
     * @var   string
     */
    const NOTICE_TRANSIENT = 'spidcie_fc_notice_';

    /**
     * @since 1.4.0
     */
    public function __construct() {
        add_action('show_user_profile', array($this, 'render_field'));
        add_action('edit_user_profile', array($this, 'render_field'));
        add_action('personal_options_update', array($this, 'save_field'));
        add_action('edit_user_profile_update', array($this, 'save_field'));

        add_filter('manage_users_columns', array($this, 'add_column'));
        add_filter('manage_users_custom_column', array($this, 'render_column'), 10, 3);

        add_action('pre_get_users', array($this, 'search_by_fiscal_code'));
        add_action('admin_notices', array($this, 'render_notice'));
    }

    /**
     * Renders the fiscal code row in the user profile screen.
     *
     * Editable only by users who can edit_users: the fiscal code is the identity
     * reconciliation key, so letting people edit their own would let them attach
     * their WordPress account to somebody else's SPID/CIE identity at next login.
     *
     * @since  1.4.0
     * @param  WP_User $user User being displayed.
     * @return void
     */
    public function render_field($user): void {
        if (!($user instanceof WP_User)) {
            return;
        }

        $value = (string) get_user_meta($user->ID, self::META_KEY, true);
        $can_edit = current_user_can('edit_users');
        $legacy = $value !== '' && $value !== WP_SPID_CIE_OIDC_FiscalCode::normalize($value);
        ?>
        <h2><?php esc_html_e('Identità SPID / CIE', 'wp-spid-cie'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th><label for="spidcie_fiscal_code"><?php esc_html_e('Codice fiscale', 'wp-spid-cie'); ?></label></th>
                <td>
                    <?php if ($can_edit) : ?>
                        <?php wp_nonce_field('spidcie_save_fiscal_code', 'spidcie_fiscal_code_nonce'); ?>
                        <input type="text"
                               name="spidcie_fiscal_code"
                               id="spidcie_fiscal_code"
                               value="<?php echo esc_attr($value); ?>"
                               class="regular-text"
                               maxlength="20"
                               autocapitalize="characters" />
                        <p class="description">
                            <?php esc_html_e('Identificatore stabile usato per collegare questo utente alla sua identità SPID o CIE. Viene normalizzato al salvataggio (maiuscolo, senza prefisso TINIT-). Lasciare vuoto per scollegare l\'identità.', 'wp-spid-cie'); ?>
                        </p>
                    <?php else : ?>
                        <span><?php echo $value !== '' ? esc_html($value) : '<em>' . esc_html__('non impostato', 'wp-spid-cie') . '</em>'; ?></span>
                        <p class="description"><?php esc_html_e('Solo un amministratore può modificare questo campo.', 'wp-spid-cie'); ?></p>
                    <?php endif; ?>

                    <?php if ($legacy) : ?>
                        <p class="description" style="color:#b32d2e">
                            <strong><?php esc_html_e('Valore non normalizzato.', 'wp-spid-cie'); ?></strong>
                            <?php
                            printf(
                                /* translators: %s: normalized fiscal code */
                                esc_html__('Il collegamento fra SPID e CIE non funziona finché resta in questa forma. Valore atteso: %s', 'wp-spid-cie'),
                                '<code>' . esc_html(WP_SPID_CIE_OIDC_FiscalCode::normalize($value)) . '</code>'
                            );
                            ?>
                        </p>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Persists the fiscal code, refusing values already bound to another account.
     *
     * A duplicate would make WP_SPID_CIE_OIDC_WpAuthService find two users for one
     * identity and return oidc_identity_conflict, locking both of them out.
     *
     * @since  1.4.0
     * @param  int $user_id User being saved.
     * @return void
     */
    public function save_field($user_id): void {
        $user_id = (int) $user_id;

        if (!current_user_can('edit_users')) {
            return;
        }
        if (!isset($_POST['spidcie_fiscal_code_nonce'])
            || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['spidcie_fiscal_code_nonce'])), 'spidcie_save_fiscal_code')) {
            return;
        }
        if (!isset($_POST['spidcie_fiscal_code'])) {
            return;
        }

        $raw = sanitize_text_field(wp_unslash($_POST['spidcie_fiscal_code']));
        $value = WP_SPID_CIE_OIDC_FiscalCode::normalize($raw);
        $current = (string) get_user_meta($user_id, self::META_KEY, true);

        if ($value === $current) {
            return;
        }

        if ($value === '') {
            delete_user_meta($user_id, self::META_KEY);
            $this->set_notice($user_id, 'success', __('Codice fiscale rimosso: l\'utente non è più collegato a un\'identità SPID/CIE.', 'wp-spid-cie'));
            return;
        }

        $owners = get_users(array(
            'meta_key'   => self::META_KEY,
            'meta_value' => $value,
            'fields'     => 'ID',
            'number'     => 2,
            'exclude'    => array($user_id),
        ));

        if (!empty($owners)) {
            $other = get_user_by('id', (int) $owners[0]);
            $this->set_notice(
                $user_id,
                'error',
                sprintf(
                    /* translators: 1: fiscal code, 2: existing username */
                    __('Codice fiscale %1$s non salvato: è già assegnato all\'utente %2$s. Due account con lo stesso codice fiscale bloccherebbero il login di entrambi.', 'wp-spid-cie'),
                    $value,
                    $other instanceof WP_User ? $other->user_login : ('#' . (int) $owners[0])
                )
            );
            return;
        }

        update_user_meta($user_id, self::META_KEY, $value);
        $this->set_notice($user_id, 'success', sprintf(
            /* translators: %s: fiscal code */
            __('Codice fiscale salvato: %s', 'wp-spid-cie'),
            $value
        ));
    }

    /**
     * Adds the fiscal code column to the users list table.
     *
     * @since  1.4.0
     * @param  array $columns Existing columns.
     * @return array Columns with the fiscal code appended.
     */
    public function add_column($columns): array {
        if (!is_array($columns)) {
            return $columns;
        }
        $columns['spidcie_fiscal_code'] = __('Codice fiscale', 'wp-spid-cie');
        return $columns;
    }

    /**
     * Renders the fiscal code cell, flagging values still carrying a prefix.
     *
     * @since  1.4.0
     * @param  string $output      Current cell output.
     * @param  string $column_name Column being rendered.
     * @param  int    $user_id     User for this row.
     * @return string Cell markup.
     */
    public function render_column($output, $column_name, $user_id): string {
        if ($column_name !== 'spidcie_fiscal_code') {
            return (string) $output;
        }

        $value = (string) get_user_meta((int) $user_id, self::META_KEY, true);
        if ($value === '') {
            return '<span aria-hidden="true">—</span><span class="screen-reader-text">'
                . esc_html__('nessun codice fiscale', 'wp-spid-cie') . '</span>';
        }

        $normalized = WP_SPID_CIE_OIDC_FiscalCode::normalize($value);
        if ($value !== $normalized) {
            return '<code>' . esc_html($value) . '</code><br />'
                . '<span style="color:#b32d2e">' . esc_html__('da normalizzare', 'wp-spid-cie') . '</span>';
        }

        return '<code>' . esc_html($value) . '</code>';
    }

    /**
     * Makes the users list searchable by fiscal code.
     *
     * WP_User_Query cannot OR a search term against a meta query, so when the term
     * resolves to a known fiscal code the search is replaced by an explicit include.
     * Both the normalized value and the legacy TINIT- form are looked up, so accounts
     * not yet migrated remain findable.
     *
     * @since  1.4.0
     * @param  WP_User_Query $query Query being prepared.
     * @return void
     */
    public function search_by_fiscal_code($query): void {
        if (!is_admin() || !($query instanceof WP_User_Query)) {
            return;
        }

        $screen_ok = function_exists('get_current_screen') ? true : false;
        if ($screen_ok) {
            $screen = get_current_screen();
            if ($screen && $screen->id !== 'users') {
                return;
            }
        }

        $search = (string) $query->get('search');
        if ($search === '') {
            return;
        }

        $term = trim($search, '*');
        $normalized = WP_SPID_CIE_OIDC_FiscalCode::normalize($term);
        if ($normalized === '') {
            return;
        }

        $ids = get_users(array(
            'meta_key'     => self::META_KEY,
            'meta_value'   => array($normalized, 'TINIT-' . $normalized),
            'meta_compare' => 'IN',
            'fields'       => 'ID',
            'number'       => 100,
        ));

        if (empty($ids)) {
            return;
        }

        $query->set('search', '');
        $query->set('include', array_map('intval', $ids));
    }

    /**
     * Stores a one-shot admin notice for the current administrator.
     *
     * @since  1.4.0
     * @param  int    $user_id Edited user, used only in the message context.
     * @param  string $type    'success' or 'error'.
     * @param  string $message Human-readable message.
     * @return void
     */
    private function set_notice(int $user_id, string $type, string $message): void {
        set_transient(
            self::NOTICE_TRANSIENT . get_current_user_id(),
            array('type' => $type, 'message' => $message),
            60
        );
    }

    /**
     * Prints and clears the pending notice, if any.
     *
     * @since  1.4.0
     * @return void
     */
    public function render_notice(): void {
        $key = self::NOTICE_TRANSIENT . get_current_user_id();
        $notice = get_transient($key);
        if (!is_array($notice) || empty($notice['message'])) {
            return;
        }
        delete_transient($key);

        printf(
            '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
            esc_attr($notice['type'] === 'error' ? 'error' : 'success'),
            esc_html($notice['message'])
        );
    }
}
