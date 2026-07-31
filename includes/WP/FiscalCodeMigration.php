<?php
defined( 'ABSPATH' ) || exit;

/**
 * Repairs fiscal codes stored before normalization was centralized.
 *
 * Accounts created by CIE logins before 1.4.0 hold "TINIT-XXXXX" in the fiscal code
 * meta, while SPID accounts hold the bare form. WP_SPID_CIE_OIDC_WpAuthService matches
 * that meta exactly, so the two never reconcile.
 *
 * Normalizing is safe for a user who owns a single account: the provider "sub" still
 * matches, so the login succeeds and the meta is rewritten on the way through. It is
 * NOT safe when the same person already owns two accounts (one per protocol): there
 * the sub points at one and the fiscal code at the other, which raises
 * oidc_identity_conflict and locks the user out. Those pairs are reported and skipped.
 *
 * @since   1.4.0
 * @package WP_SPID_CIE_OIDC
 */
class WP_SPID_CIE_OIDC_FiscalCodeMigration {

    /**
     * @since 1.4.0
     * @var   string
     */
    const META_KEY = '_spidcie_fiscal_code';

    /**
     * @since 1.4.0
     */
    public function __construct() {
        add_action('admin_init', array($this, 'handle_actions'));
    }

    /**
     * Reads every stored fiscal code and classifies what needs doing.
     *
     * @since  1.4.0
     * @return array{total:int,to_normalize:array,conflicts:array,legacy_usernames:array}
     */
    public static function scan(): array {
        global $wpdb;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
                self::META_KEY
            )
        );

        $report = array(
            'total'            => 0,
            'to_normalize'     => array(),
            'conflicts'        => array(),
            'legacy_usernames' => array(),
        );

        if (empty($rows)) {
            return $report;
        }

        $by_normalized = array();

        foreach ($rows as $row) {
            $user_id = (int) $row->user_id;
            $stored = (string) $row->meta_value;
            $normalized = WP_SPID_CIE_OIDC_FiscalCode::normalize($stored);

            if ($normalized === '') {
                continue;
            }

            $report['total']++;
            $by_normalized[$normalized][] = $user_id;

            $user = get_user_by('id', $user_id);
            $login = $user instanceof WP_User ? $user->user_login : ('#' . $user_id);

            if ($stored !== $normalized) {
                $report['to_normalize'][] = array(
                    'user_id'    => $user_id,
                    'login'      => $login,
                    'stored'     => $stored,
                    'normalized' => $normalized,
                );
            }

            if ($user instanceof WP_User
                && $user->user_login !== WP_SPID_CIE_OIDC_FiscalCode::normalize($user->user_login)
                && stripos($user->user_login, 'TINIT') === 0) {
                $report['legacy_usernames'][] = array(
                    'user_id'  => $user_id,
                    'login'    => $user->user_login,
                    'proposed' => $normalized,
                );
            }
        }

        foreach ($by_normalized as $normalized => $user_ids) {
            if (count($user_ids) > 1) {
                $report['conflicts'][$normalized] = $user_ids;
            }
        }

        return $report;
    }

    /**
     * Rewrites non-normalized fiscal codes, skipping accounts involved in a conflict.
     *
     * @since  1.4.0
     * @return array{updated:int,skipped:int}
     */
    public static function normalize_all(): array {
        $report = self::scan();
        $updated = 0;
        $skipped = 0;

        foreach ($report['to_normalize'] as $entry) {
            if (isset($report['conflicts'][$entry['normalized']])) {
                $skipped++;
                continue;
            }
            update_user_meta($entry['user_id'], self::META_KEY, $entry['normalized']);
            $updated++;
        }

        return array('updated' => $updated, 'skipped' => $skipped);
    }

    /**
     * Renames legacy TINIT- usernames to the bare fiscal code.
     *
     * Purely cosmetic: identity reconciliation uses the meta, not user_login. Users
     * authenticate through SPID/CIE and never type a username, so the rename is not
     * disruptive. WordPress exposes no API for this, hence the direct write plus a
     * cache flush. Names already taken are left alone.
     *
     * @since  1.4.0
     * @return array{renamed:int,skipped:int}
     */
    public static function rename_legacy_usernames(): array {
        global $wpdb;

        $report = self::scan();
        $renamed = 0;
        $skipped = 0;

        foreach ($report['legacy_usernames'] as $entry) {
            $proposed = sanitize_user($entry['proposed'], true);
            if ($proposed === '' || username_exists($proposed)) {
                $skipped++;
                continue;
            }

            $ok = $wpdb->update(
                $wpdb->users,
                array('user_login' => $proposed),
                array('ID' => (int) $entry['user_id']),
                array('%s'),
                array('%d')
            );

            if ($ok) {
                clean_user_cache((int) $entry['user_id']);
                $renamed++;
            } else {
                $skipped++;
            }
        }

        return array('renamed' => $renamed, 'skipped' => $skipped);
    }

    /**
     * Executes the admin actions triggered from the Stato tab.
     *
     * @since  1.4.0
     * @return void
     */
    public function handle_actions(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        $redirect = add_query_arg(
            array('page' => 'wp-spid-cie', 'tab' => 'stato'),
            admin_url('admin.php')
        );

        if (isset($_GET['spidcie_fc_normalize']) && check_admin_referer('spidcie_fc_normalize')) {
            $result = self::normalize_all();
            wp_safe_redirect(add_query_arg(
                array('fc_updated' => (int) $result['updated'], 'fc_skipped' => (int) $result['skipped']),
                $redirect
            ));
            exit;
        }

        if (isset($_GET['spidcie_fc_rename']) && check_admin_referer('spidcie_fc_rename')) {
            $result = self::rename_legacy_usernames();
            wp_safe_redirect(add_query_arg(
                array('fc_renamed' => (int) $result['renamed'], 'fc_rename_skipped' => (int) $result['skipped']),
                $redirect
            ));
            exit;
        }
    }

    /**
     * Renders the migration panel inside the Stato tab.
     *
     * @since  1.4.0
     * @return void
     */
    public static function render_panel(): void {
        $report = self::scan();

        echo '<h3>Codici fiscali SPID / CIE</h3>';

        if (isset($_GET['fc_updated'])) {
            printf(
                '<div class="notice notice-success inline"><p>Normalizzati %d codici fiscali, %d saltati per conflitto.</p></div>',
                (int) $_GET['fc_updated'],
                isset($_GET['fc_skipped']) ? (int) $_GET['fc_skipped'] : 0
            );
        }
        if (isset($_GET['fc_renamed'])) {
            printf(
                '<div class="notice notice-success inline"><p>Rinominati %d username, %d saltati.</p></div>',
                (int) $_GET['fc_renamed'],
                isset($_GET['fc_rename_skipped']) ? (int) $_GET['fc_rename_skipped'] : 0
            );
        }

        if ($report['total'] === 0) {
            echo '<p>Nessun utente con identità SPID/CIE registrata.</p>';
            return;
        }

        printf(
            '<p>Utenti con identità SPID/CIE: <strong>%d</strong>. Da normalizzare: <strong>%d</strong>. Conflitti: <strong>%d</strong>.</p>',
            (int) $report['total'],
            count($report['to_normalize']),
            count($report['conflicts'])
        );

        if (!empty($report['conflicts'])) {
            echo '<div class="notice notice-error inline"><p><strong>Conflitti da risolvere a mano.</strong> ';
            echo 'Lo stesso codice fiscale risulta su più account: finché resta così, quegli utenti ';
            echo 'non riescono ad autenticarsi (errore <code>oidc_identity_conflict</code>). ';
            echo 'Tenere l\'account corretto e rimuovere il codice fiscale dall\'altro dal suo profilo.</p></div>';
            echo '<table class="widefat striped"><thead><tr><th>Codice fiscale</th><th>Account coinvolti</th></tr></thead><tbody>';
            foreach ($report['conflicts'] as $fc => $user_ids) {
                $links = array();
                foreach ($user_ids as $uid) {
                    $u = get_user_by('id', $uid);
                    $links[] = sprintf(
                        '<a href="%s">%s</a>',
                        esc_url(get_edit_user_link($uid)),
                        esc_html($u instanceof WP_User ? $u->user_login : ('#' . $uid))
                    );
                }
                printf(
                    '<tr><td><code>%s</code></td><td>%s</td></tr>',
                    esc_html($fc),
                    implode(' &middot; ', $links)
                );
            }
            echo '</tbody></table>';
        }

        if (!empty($report['to_normalize'])) {
            echo '<table class="widefat striped" style="margin-top:12px"><thead><tr>';
            echo '<th>Utente</th><th>Valore attuale</th><th>Dopo la normalizzazione</th></tr></thead><tbody>';
            foreach ($report['to_normalize'] as $entry) {
                printf(
                    '<tr><td><a href="%s">%s</a></td><td><code>%s</code></td><td><code>%s</code></td></tr>',
                    esc_url(get_edit_user_link($entry['user_id'])),
                    esc_html($entry['login']),
                    esc_html($entry['stored']),
                    esc_html($entry['normalized'])
                );
            }
            echo '</tbody></table>';

            $url = wp_nonce_url(
                add_query_arg(
                    array('page' => 'wp-spid-cie', 'tab' => 'stato', 'spidcie_fc_normalize' => '1'),
                    admin_url('admin.php')
                ),
                'spidcie_fc_normalize'
            );
            printf(
                '<p><a class="button button-primary" href="%s">Normalizza %d codici fiscali</a></p>',
                esc_url($url),
                count($report['to_normalize'])
            );
        } else {
            echo '<p>Tutti i codici fiscali sono già normalizzati.</p>';
        }

        if (!empty($report['legacy_usernames'])) {
            printf(
                '<p style="margin-top:12px">%d username conservano il prefisso <code>TINIT-</code>. È solo estetica: '
                . 'il collegamento fra le identità usa il codice fiscale, non lo username, e gli utenti accedono '
                . 'via SPID/CIE senza digitarlo.</p>',
                count($report['legacy_usernames'])
            );
            $url = wp_nonce_url(
                add_query_arg(
                    array('page' => 'wp-spid-cie', 'tab' => 'stato', 'spidcie_fc_rename' => '1'),
                    admin_url('admin.php')
                ),
                'spidcie_fc_rename'
            );
            printf(
                '<p><a class="button button-secondary" onclick="return confirm(\'Rinominare gli username? Operazione non reversibile automaticamente.\');" href="%s">Rinomina %d username</a></p>',
                esc_url($url),
                count($report['legacy_usernames'])
            );
        }
    }
}
