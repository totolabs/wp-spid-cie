<?php

/**
 * La funzionalità specifica dell'area di amministrazione del plugin.
 *
 * @since      1.0.0
 * @package    WP_SPID_CIE_OIDC
 * @subpackage WP_SPID_CIE_OIDC/admin
 * @author     Totolabs Srl <info@totolabs.it>
 */

class WP_SPID_CIE_OIDC_Admin {

    private $plugin_name;
    private $version;

    public function __construct( $plugin_name, $version ) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        add_action( 'admin_menu', array( $this, 'add_options_page' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_init', array( $this, 'handle_key_generation' ) );
        add_action( 'admin_init', array( $this, 'normalize_spid_saml_options' ) );
        add_action( 'admin_init', array( $this, 'handle_spid_saml_registry_refresh' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_styles' ) );
    }

    /**
     * Carica gli stili CSS per il pannello di amministrazione.
     */
    public function enqueue_admin_styles($hook) {
        if (strpos($hook, $this->plugin_name) === false) {
            return;
        }

        wp_enqueue_style(
            $this->plugin_name . '-admin',
            plugin_dir_url( __FILE__ ) . 'css/wp-spid-cie-admin.css',
            array(),
            $this->version,
            'all'
        );
    }

    public function add_options_page() {
        add_options_page(
            'Configurazione SPID & CIE', // Titolo pagina browser
            'SPID & CIE Login',          // Titolo menu (Più user friendly)
            'manage_options', 
            $this->plugin_name, 
            array( $this, 'create_admin_page' )
        );
    }

    public function create_admin_page() {
        $current_tab = $this->get_current_tab();
        $tabs = $this->get_admin_tabs();
        ?>
        <div class="wrap">
            <h1 class="wp-heading-inline">SPID & CIE Login (PNRR 1.4.4)</h1>
            <hr class="wp-header-end">
            
            <?php settings_errors(); ?>

            <nav class="nav-tab-wrapper spid-tabs" aria-label="Sezioni configurazione SPID CIE OIDC">
                <?php foreach ($tabs as $tab_key => $tab): ?>
                    <?php $url = add_query_arg(['page' => $this->plugin_name, 'tab' => $tab_key], admin_url('options-general.php')); ?>
                    <a href="<?php echo esc_url($url); ?>" class="nav-tab <?php echo $current_tab === $tab_key ? 'nav-tab-active' : ''; ?>">
                        <?php echo esc_html($tab['label']); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <p class="description spid-tab-help"><?php echo esc_html($tabs[$current_tab]['help']); ?></p>

            <form method="post" action="options.php">
                <?php settings_fields( $this->plugin_name . '_options_group' ); ?>
                <input type="hidden" name="<?php echo esc_attr($this->plugin_name . '_options[_current_tab]'); ?>" value="<?php echo esc_attr($current_tab); ?>" />
                
                <div class="spid-admin-wrap">
                    <div class="spid-main-col">

                        <?php if ($current_tab === 'ente'): ?>
                            <div class="spid-card">
                                <?php do_settings_sections($this->plugin_name . '_ente'); ?>
                            </div>
                        <?php elseif ($current_tab === 'impostazioni'): ?>
                            <div class="spid-card">
                                <?php $this->render_impostazioni_tab(); ?>
                            </div>
                        <?php elseif ($current_tab === 'spid_oidc'): ?>
                            <div class="spid-card">
                                <?php $this->render_spid_oidc_tab(); ?>
                            </div>
                        <?php elseif ($current_tab === 'spid_saml'): ?>
                            <div class="spid-card">
                                <?php $this->render_spid_saml_module(); ?>
                            </div>
                        <?php elseif ($current_tab === 'cie'): ?>
                            <div class="spid-card">
                                <?php $this->render_cie_tab(); ?>
                            </div>
                        <?php elseif ($current_tab === 'stato'): ?>
                            <div class="spid-card">
                                <?php $this->render_stato_tab(); ?>
                            </div>
                        <?php else: ?>
                            <div class="spid-card">
                                <?php $this->render_impostazioni_tab(); ?>
                            </div>
                        <?php endif; ?>

                        <?php submit_button('Salva Impostazioni Tab Corrente', 'primary large'); ?>
                    </div>

                    <div class="spid-side-col">
                        
                        <div class="spid-side-box">
                            <div class="spid-side-header">Progetto Open Source</div>
                            <div class="spid-side-content">
                                <p>Questo plugin è sviluppato con filosofia <strong>Open Source</strong> per supportare la digitalizzazione della PA Italiana.</p>
                                <ul>
                                    <li><a href="https://github.com/totolabs/wp-spid-cie" target="_blank">Repository GitHub</a></li>
                                    <li><a href="https://github.com/totolabs/wp-spid-cie/wiki" target="_blank">Manuale & Wiki</a></li>
                                    <li><a href="https://wordpress.org/plugins/" target="_blank">Pagina Plugin WordPress</a></li>
                                </ul>
                                <p>Hai trovato un bug? Vuoi contribuire? Apri una Issue su GitHub!</p>
                            </div>
                        </div>

                        <div class="spid-side-box">
                            <div class="spid-side-header">Sviluppo & Supporto</div>
                            <div class="spid-side-content">
                                <img src="<?php echo plugin_dir_url(dirname(__FILE__)) . 'public/img/logo-totolabs.png'; ?>" alt="Totolabs" style="max-width: 100%; height: auto; margin-bottom: 10px; display:none;"> 
                                
                                <p>Sviluppato con ❤️ da <strong>Totolabs Srl</strong>.</p>
                                <p>Offriamo servizi specialistici per le PA:</p>
                                <ul>
                                    <li>Supporto all'installazione</li>
                                    <li>Consulenza accreditamento AgID/CIE</li>
                                    <li>Sviluppo personalizzato</li>
                                </ul>
                                <a href="https://www.totolabs.it" target="_blank" class="button button-secondary button-full">Visita Totolabs.it</a>
                            </div>
                        </div>

                    </div>
                </div>
            </form>
        </div>
        <?php
    }

    public function register_settings() {
        register_setting(
            $this->plugin_name . '_options_group', 
            $this->plugin_name . '_options', 
            array( $this, 'sanitize_options' )
        );

        // --- 1. DATI ANAGRAFICI ---
        add_settings_section('ente_section', '1. Dati Anagrafici Ente', null, $this->plugin_name . '_ente');
        add_settings_field('organization_name', 'Denominazione Ente', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section', 
            ['id' => 'organization_name', 'desc' => 'Es. Comune di Roma', 'placeholder' => 'Es. Comune di Roma']
        );
        add_settings_field('ipa_code', 'Codice IPA', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section', 
            ['id' => 'ipa_code', 'desc' => 'Codice univoco IPA (es. c_h501)', 'placeholder' => 'c_h501']
        );
        add_settings_field('fiscal_number', 'Codice Fiscale Ente', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section', 
            ['id' => 'fiscal_number', 'desc' => 'Codice Fiscale numerico (es. 80012345678)', 'placeholder' => '01234567890']
        );
        add_settings_field('contacts_email', 'Email Contatto Tecnico', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section', 
            ['id' => 'contacts_email', 'type' => 'email', 'desc' => 'Email per comunicazioni tecniche.', 'placeholder' => 'ced@ente.it']
        );
        add_settings_field('issuer_override', 'Issuer / Identificativo componente', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section',
            ['id' => 'issuer_override', 'desc' => 'URL base HTTPS usato per endpoint e fallback metadata OIDC Federation.', 'placeholder' => 'https://demo.ente.it']
        );
        add_settings_field('entity_id', 'Entity ID Federation (iss/sub)', array($this, 'render_text_field'), $this->plugin_name . '_ente', 'ente_section',
            ['id' => 'entity_id', 'desc' => 'Identificativo entità usato come iss/sub/client_id. Mantiene lo slash finale se presente (es. https://demo.ente.it/).', 'placeholder' => 'https://demo.ente.it/']
        );

        // --- 2. CRITTOGRAFIA ---
        add_settings_section('keys_section', '2. Crittografia e Federazione', array($this, 'print_keys_section_info'), $this->plugin_name . '_keys');
        add_settings_field('oidc_keys_manager', 'Stato Chiavi', array($this, 'render_keys_manager'), $this->plugin_name . '_keys', 'keys_section');
		add_settings_field(
		  'cie_trust_anchor_preprod',
		  'Trust Anchor CIE (Pre-produzione)',
		  array($this, 'render_text_field'),
		  $this->plugin_name . '_keys',
		  'keys_section',
		  ['id' => 'cie_trust_anchor_preprod', 'desc' => 'URL Trust Anchor CIE pre-produzione', 'placeholder' => 'https://...']
		);
		add_settings_field(
		  'cie_trust_anchor_prod',
		  'Trust Anchor CIE (Produzione)',
		  array($this, 'render_text_field'),
		  $this->plugin_name . '_keys',
		  'keys_section',
		  ['id' => 'cie_trust_anchor_prod', 'desc' => 'URL Trust Anchor CIE produzione', 'placeholder' => 'https://...']
		);
		add_settings_field(
		  'spid_trust_anchor',
		  'Trust Anchor SPID (futuro)',
		  array($this, 'render_text_field'),
		  $this->plugin_name . '_keys',
		  'keys_section',
		  ['id' => 'spid_trust_anchor', 'desc' => 'URL Trust Anchor SPID (quando OIDC sarà operativo)', 'placeholder' => 'https://...']
		);
		add_settings_field(
		  'trust_anchor_preview',
		  'Trust anchor configurati (read-only)',
		  array($this, 'render_trust_anchor_preview_field'),
		  $this->plugin_name . '_keys',
		  'keys_section'
		);
		add_settings_field(
		  'cie_trust_mark_preprod',
		  'Trust Mark CIE (Pre-produzione)',
		  array($this, 'render_textarea_field'),
		  $this->plugin_name . '_keys',
		  'keys_section',
		  ['id' => 'cie_trust_mark_preprod', 'desc' => 'Incolla qui il JWT Trust Mark rilasciato dal portale CIE pre-prod.']
		);
		add_settings_field(
		  'cie_trust_mark_prod',
		  'Trust Mark CIE (Produzione)',
		  array($this, 'render_textarea_field'),
		  $this->plugin_name . '_keys',
		  'keys_section',
		  ['id' => 'cie_trust_mark_prod', 'desc' => 'Incolla qui il JWT Trust Mark rilasciato dal portale CIE prod.']
		);
		add_settings_field(
		  'public_key_pem',
		  'Chiave pubblica di federazione (PEM)',
		  array($this, 'render_public_key_field'),
		  $this->plugin_name . '_keys',
		  'keys_section'
		);
		add_settings_field(
		  'cie_certificate_pem',
		  'Certificato pubblico (X.509) per portale CIE',
		  array($this, 'render_cie_certificate_field'),
		  $this->plugin_name . '_keys',
		  'keys_section'
		);

		add_settings_field(
		  'public_key_raw_pem',
		  'Chiave pubblica (PEM) – raw',
		  array($this, 'render_public_key_raw_field'),
		  $this->plugin_name . '_keys',
		  'keys_section'
		);
        // --- 3. ATTIVAZIONE SERVIZI ---
        add_settings_section('providers_section', '3. Attivazione Servizi', null, $this->plugin_name . '_providers');
        
        // SPID e relativo test
        add_settings_field('spid_enabled', 'Abilita SPID', array($this, 'render_checkbox_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_enabled', 'desc' => 'Mostra il pulsante "Entra con SPID".']);
        
        // Spostiamo qui sotto il Test Environment (logicamente collegato a SPID)
        add_settings_field('spid_test_env', 'Ambiente di Test (Validator)', array($this, 'render_checkbox_field'), $this->plugin_name . '_providers', 'providers_section', 
            ['id' => 'spid_test_env', 'desc' => 'Abilita il provider "SPID Validator" (solo per collaudo tecnico AgID).']
        );

        // CIE
        add_settings_field('cie_enabled', 'Abilita CIE', array($this, 'render_checkbox_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_enabled', 'desc' => 'Mostra il pulsante "Entra con CIE".']);

        // Milestone 2: Provider profiles + discovery + LoA/ACR policy
        add_settings_field('provider_mode', 'Modalità Provider', array($this, 'render_select_field'), $this->plugin_name . '_providers', 'providers_section', [
            'id' => 'provider_mode',
            'options' => ['both' => 'SPID + CIE', 'spid_only' => 'Solo SPID', 'cie_only' => 'Solo CIE'],
            'default' => 'both',
            'desc' => 'Definisce quali provider sono autorizzati al login OIDC.'
        ]);
        add_settings_field('discovery_mode', 'Modalità Discovery', array($this, 'render_select_field'), $this->plugin_name . '_providers', 'providers_section', [
            'id' => 'discovery_mode',
            'options' => ['auto' => 'Auto (.well-known)', 'manual' => 'Manual endpoints'],
            'default' => 'auto',
            'desc' => 'Auto: usa issuer/.well-known/openid-configuration. Manual: usa endpoint configurati sotto.'
        ]);

        add_settings_field('min_loa', 'Livello minimo LoA/ACR', array($this, 'render_select_field'), $this->plugin_name . '_providers', 'providers_section', [
            'id' => 'min_loa',
            'options' => ['SpidL1' => 'SpidL1', 'SpidL2' => 'SpidL2 (consigliato)', 'SpidL3' => 'SpidL3'],
            'default' => 'SpidL2',
            'desc' => 'Valore minimo accettato nel claim acr.'
        ]);
        add_settings_field('spid_issuer', 'SPID Issuer', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_issuer', 'placeholder' => 'https://...', 'desc' => 'Issuer SPID (usato per discovery auto e validazione iss).']);
        add_settings_field('cie_issuer', 'CIE Issuer', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_issuer', 'placeholder' => 'https://...', 'desc' => 'Issuer CIE (usato per discovery auto e validazione iss).']);

        add_settings_field('spid_scope', 'SPID Scope', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_scope', 'placeholder' => 'openid profile', 'desc' => 'Scope base SPID.']);
        add_settings_field('cie_scope', 'CIE Scope', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_scope', 'placeholder' => 'openid profile email', 'desc' => 'Scope base CIE.']);
        add_settings_field('spid_acr_values', 'SPID acr_values', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_acr_values', 'placeholder' => 'https://www.spid.gov.it/SpidL2', 'desc' => 'Override opzionale acr_values SPID.']);
        add_settings_field('cie_acr_values', 'CIE acr_values', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_acr_values', 'placeholder' => 'https://www.spid.gov.it/SpidL2', 'desc' => 'Override opzionale acr_values CIE.']);

        // Manual endpoints (discovery_mode=manual)
        add_settings_field('spid_authorization_endpoint', 'SPID Authorization endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_authorization_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('spid_token_endpoint', 'SPID Token endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_token_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('spid_jwks_uri', 'SPID JWKS URI', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_jwks_uri', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('spid_userinfo_endpoint', 'SPID UserInfo endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_userinfo_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        add_settings_field('spid_end_session_endpoint', 'SPID End Session endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'spid_end_session_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);

        add_settings_field('cie_authorization_endpoint', 'CIE Authorization endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_authorization_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('cie_token_endpoint', 'CIE Token endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_token_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('cie_jwks_uri', 'CIE JWKS URI', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_jwks_uri', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        add_settings_field('cie_userinfo_endpoint', 'CIE UserInfo endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_userinfo_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        add_settings_field('cie_end_session_endpoint', 'CIE End Session endpoint', array($this, 'render_text_field'), $this->plugin_name . '_providers', 'providers_section', ['id' => 'cie_end_session_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);

        // --- 4. DISCLAIMER ---
        add_settings_section('disclaimer_section', '4. Gestione Avvisi (Disclaimer)', null, $this->plugin_name . '_disclaimer');
        add_settings_field('disclaimer_enabled', 'Attiva Messaggio Avviso', array($this, 'render_checkbox_field'), $this->plugin_name . '_disclaimer', 'disclaimer_section', 
            ['id' => 'disclaimer_enabled', 'desc' => 'Mostra un box di avviso sopra i pulsanti di login.']
        );
        $default_msg = "⚠️ <strong>Avviso Tecnico:</strong><br>I servizi di accesso SPID e CIE sono in fase di <strong>aggiornamento programmato</strong>. Il login potrebbe essere temporaneamente non disponibile.";
        add_settings_field('disclaimer_text', 'Testo dell\'Avviso', array($this, 'render_textarea_field'), $this->plugin_name . '_disclaimer', 'disclaimer_section', 
            ['id' => 'disclaimer_text', 'default' => $default_msg, 'desc' => 'HTML consentito (es. &lt;strong&gt;, &lt;br&gt;).']
        );

        // --- 5. SPID SAML (STEP 2) ---
        add_settings_section('spid_saml_section', '5. SPID SAML (Step 2)', null, $this->plugin_name . '_saml');
    }

    private function get_admin_tabs(): array {
        return [
            'ente' => ['label' => '1. Ente', 'help' => 'Dati ente riusabili (denominazione, IPA, CF, contatti, issuer/entity_id).'],
            'impostazioni' => ['label' => '2. Impostazioni', 'help' => 'Toggle pulsanti e scelta metodo SPID (SAML/OIDC).'],
            'spid_oidc' => ['label' => '3. SPID OIDC', 'help' => 'Configurazione tecnica SPID OIDC (work in progress).'],
            'spid_saml' => ['label' => '4. SPID SAML', 'help' => 'Configurazione tecnica SPID SAML (step operativi).'],
            'cie' => ['label' => '5. CIE', 'help' => 'Configurazione CIE OIDC Federation, trust anchor/trust mark e output generati.'],
            'stato' => ['label' => '6. Stato', 'help' => 'Diagnostica, checklist operativa e link metadata/endpoints.'],
        ];
    }

    private function get_current_tab(): string {
        $tabs = $this->get_admin_tabs();
        $requested = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'ente';
        $legacy_map = [
            'a_ente' => 'ente',
            'b_federazione' => 'cie',
            'c_provider' => 'spid_oidc',
            'd_disclaimer' => 'impostazioni',
            'e_operativo' => 'impostazioni',
            'f_spid_saml' => 'spid_saml',
            'g_stato' => 'stato',
        ];
        if (isset($legacy_map[$requested])) {
            $requested = $legacy_map[$requested];
        }
        return isset($tabs[$requested]) ? $requested : 'ente';
    }


    private function render_impostazioni_tab(): void {
        $options = get_option($this->plugin_name . '_options', []);
        $spid_method = isset($options['spid_auth_method']) ? sanitize_key((string) $options['spid_auth_method']) : (!empty($options['spid_saml_enabled']) ? 'saml' : 'oidc');
        if (!in_array($spid_method, ['saml', 'oidc'], true)) {
            $spid_method = 'saml';
        }

        echo '<h2>Impostazioni globali</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->render_checkbox_field(['id' => 'spid_enabled', 'desc' => 'Mostra il pulsante "Entra con SPID".']);
        $this->render_checkbox_field(['id' => 'cie_enabled', 'desc' => 'Mostra il pulsante "Entra con CIE".']);
        $this->render_checkbox_field(['id' => 'spid_saml_validator_enabled', 'desc' => 'Abilita SPID Validator (solo collaudo).']);
        echo '<tr><th scope="row"><label for="spid_auth_method">Metodo SPID</label></th><td>';
        echo '<fieldset>';
        echo '<label><input type="radio" name="' . esc_attr($this->plugin_name . '_options[spid_auth_method]') . '" value="saml" ' . checked($spid_method, 'saml', false) . ' /> SPID SAML (attivo)</label><br />';
        echo '<label><input type="radio" name="' . esc_attr($this->plugin_name . '_options[spid_auth_method]') . '" value="oidc" ' . checked($spid_method, 'oidc', false) . ' /> SPID OIDC (WIP)</label>';
        echo '<p class="description">Selezione mutuamente esclusiva: abilita un solo metodo SPID per volta.</p>';
        echo '</fieldset></td></tr>';
        echo '</tbody></table>';
    }


    private function spid_saml_keys_exist(): bool {
        $upload_dir = wp_upload_dir();
        $keys_dir = trailingslashit($upload_dir['basedir']) . 'spid-cie-oidc-keys';
        return file_exists($keys_dir . '/private.key') && file_exists($keys_dir . '/public.crt');
    }

    private function render_status_dashboard(): void {
        $options = get_option($this->plugin_name . '_options', []);
        $spid_enabled = !empty($options['spid_enabled']) && $options['spid_enabled'] === '1';
        $spid_saml_enabled = !empty($options['spid_saml_enabled']) && $options['spid_saml_enabled'] === '1';
        $spid_auth_method = isset($options['spid_auth_method']) ? sanitize_key((string) $options['spid_auth_method']) : ($spid_saml_enabled ? 'saml' : 'oidc');
        $spid_saml_effective_enabled = $spid_enabled && $spid_saml_enabled && $spid_auth_method === 'saml';

        $checks = [
            'Chiavi SP presenti' => $this->spid_saml_keys_exist(),
            'Metadata token configurato' => !empty($options['spid_saml_metadata_token']),
            'Registry IdP selezionato' => !empty($options['spid_saml_idp_registry_selected']) || !empty($options['spid_saml_idp_entity_id']),
            'SPID SAML enabled (effective)' => $spid_saml_effective_enabled,
        ];
        echo '<h2>Dashboard stato</h2><ul class="spid-readonly-list">';
        foreach ($checks as $label => $ok) {
            echo '<li><strong>' . esc_html($label) . ':</strong> ' . ($ok ? '<span style="color:#0a7f37;">OK</span>' : '<span style="color:#b32d2e;">KO</span>') . '</li>';
        }
        echo '</ul>';
    }

    private function render_spid_oidc_tab(): void {
        echo '<div class="notice notice-warning inline"><p><strong>Work in progress:</strong> integrazione SPID OIDC non prioritaria finché non sarà stabile il profilo AgID.</p></div>';
        echo '<h2>Configurazione tecnica SPID OIDC</h2>';
        echo '<table class="form-table" role="presentation"><tbody>';
        $this->render_select_field(['id' => 'provider_mode', 'options' => ['both' => 'SPID + CIE', 'spid_only' => 'Solo SPID', 'cie_only' => 'Solo CIE'], 'default' => 'both', 'desc' => 'Definisce quali provider sono autorizzati al login OIDC.']);
        $this->render_select_field(['id' => 'discovery_mode', 'options' => ['auto' => 'Auto (.well-known)', 'manual' => 'Manual endpoints'], 'default' => 'auto', 'desc' => 'Auto: usa issuer/.well-known/openid-configuration. Manual: usa endpoint configurati sotto.']);
        $this->render_select_field(['id' => 'min_loa', 'options' => ['SpidL1' => 'SpidL1', 'SpidL2' => 'SpidL2 (consigliato)', 'SpidL3' => 'SpidL3'], 'default' => 'SpidL2', 'desc' => 'Valore minimo accettato nel claim acr.']);
        $this->render_text_field(['id' => 'spid_issuer', 'placeholder' => 'https://...', 'desc' => 'Issuer SPID (usato per discovery auto e validazione iss).']);
        $this->render_text_field(['id' => 'cie_issuer', 'placeholder' => 'https://...', 'desc' => 'Issuer CIE (usato per discovery auto e validazione iss).']);
        $this->render_text_field(['id' => 'spid_scope', 'placeholder' => 'openid profile', 'desc' => 'Scope base SPID.']);
        $this->render_text_field(['id' => 'cie_scope', 'placeholder' => 'openid profile email', 'desc' => 'Scope base CIE.']);
        $this->render_text_field(['id' => 'spid_acr_values', 'placeholder' => 'https://www.spid.gov.it/SpidL2', 'desc' => 'Override opzionale acr_values SPID.']);
        $this->render_text_field(['id' => 'cie_acr_values', 'placeholder' => 'https://www.spid.gov.it/SpidL2', 'desc' => 'Override opzionale acr_values CIE.']);
        $this->render_text_field(['id' => 'spid_authorization_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'spid_token_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'spid_jwks_uri', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'spid_userinfo_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        $this->render_text_field(['id' => 'spid_end_session_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        $this->render_text_field(['id' => 'cie_authorization_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'cie_token_endpoint', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'cie_jwks_uri', 'placeholder' => 'https://...', 'desc' => 'Usato solo in modalità manual.']);
        $this->render_text_field(['id' => 'cie_userinfo_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        $this->render_text_field(['id' => 'cie_end_session_endpoint', 'placeholder' => 'https://...', 'desc' => 'Opzionale.']);
        echo '</tbody></table>';
    }

    private function render_cie_tab(): void {
        echo '<h2>Configurazione CIE</h2>';
        do_settings_sections($this->plugin_name . '_keys');
        echo '<h3>Output generati</h3>';
        echo '<ul class="spid-readonly-list">';
        echo '<li><strong>Entity Configuration URL:</strong> <code>' . esc_html(home_url('/.well-known/openid-federation')) . '</code></li>';
        echo '<li><strong>JWKS URL:</strong> <code>' . esc_html(home_url('/jwks.json')) . '</code></li>';
        echo '<li><strong>JWKS URL (REST, compat):</strong> <code>' . esc_html(home_url('/?rest_route=/wp-spid-cie/v1/jwks')) . '</code></li>';
        echo '</ul>';
    }

    private function render_disclaimer_preview(): void {
        $options = get_option($this->plugin_name . '_options', []);
        $default_msg = "⚠️ <strong>Avviso Tecnico:</strong><br>I servizi di accesso SPID e CIE sono in fase di <strong>aggiornamento programmato</strong>. Il login potrebbe essere temporaneamente non disponibile.";
        $text = !empty($options['disclaimer_text']) ? (string) $options['disclaimer_text'] : $default_msg;

        echo '<h3>Anteprima disclaimer</h3>';
        echo '<div class="spid-disclaimer-preview">' . wp_kses_post($text) . '</div>';
    }

    private function render_operational_help(): void {
        $shortcode = '[spid_cie_login]';
        $callback = add_query_arg(['oidc_action' => 'callback', 'provider' => 'spid'], home_url('/'));

                echo '<ol>';
        echo '<li>Inserisci lo shortcode <code>' . esc_html($shortcode) . '</code> in una pagina pubblica.</li>';
        echo '<li>Configura callback OIDC con URL <code>' . esc_html($callback) . '</code>.</li>';
        echo '<li>Verifica endpoint federation: <code>' . esc_html(home_url('/.well-known/openid-federation')) . '</code>.</li>';
        echo '</ol>';
        echo '<p class="description">Compatibilità login: se il path standard di WordPress è nascosto (es. WPS Hide Login), lo shortcode resta il fallback supportato.</p>';
    }

    public function render_spid_saml_endpoints_preview() {
        $metadata = home_url('/spid/saml/metadata');
        $acs = home_url('/spid/saml/acs');
        $sls = home_url('/spid/saml/sls');

        echo '<ul class="spid-readonly-list">';
        echo '<li><strong>Metadata:</strong> <code>' . esc_html($metadata) . '</code></li>';
        echo '<li><strong>Login:</strong> <code>' . esc_html(home_url('/spid/saml/login')) . '</code></li>';
        echo '<li><strong>ACS:</strong> <code>' . esc_html($acs) . '</code></li>';
        echo '<li><strong>SLS:</strong> <code>' . esc_html($sls) . '</code></li>';
        echo '</ul>';
        echo '<p class="description">Step 2b: metadata/login/ACS/SLS con validazione risposta, richiesta firmata e provisioning utente. Se manca config IdP il login non parte.</p>';
    }


    public function render_spid_saml_test_config() {
        $options = get_option($this->plugin_name . '_options', []);
        $missing = [];
        if (empty($options['spid_saml_entity_id']) && empty($options['issuer_override'])) {
            $missing[] = 'SP EntityID/Issuer non configurato';
        }

        if (empty($missing)) {
            echo '<p style="color:#0a7f37;"><strong>Configurazione OK.</strong> Parametri minimi presenti.</p>';
            return;
        }

        echo '<ul class="spid-readonly-list">';
        foreach ($missing as $m) {
            echo '<li><span style="color:#b32d2e;">' . esc_html($m) . '</span></li>';
        }
        echo '</ul>';
    }

    private function get_spid_saml_defaults(array $options): array {
        $host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST);
        return [
            'countryName' => !empty($options['spid_saml_country_name']) ? (string) $options['spid_saml_country_name'] : 'IT',
            'stateOrProvinceName' => (string) ($options['spid_saml_state_or_province_name'] ?? ''),
            'localityName' => (string) ($options['spid_saml_locality_name'] ?? ''),
            'commonName' => !empty($options['spid_saml_common_name']) ? (string) $options['spid_saml_common_name'] : $host,
            'emailAddress' => !empty($options['spid_saml_email_address']) ? (string) $options['spid_saml_email_address'] : (string) ($options['contacts_email'] ?? get_option('admin_email')),
            'sp_org_name' => !empty($options['sp_org_name']) ? (string) $options['sp_org_name'] : (string) ($options['organization_name'] ?? ''),
            'sp_org_display_name' => !empty($options['sp_org_display_name']) ? (string) $options['sp_org_display_name'] : (string) ($options['organization_name'] ?? ''),
            'sp_contact_ipa_code' => !empty($options['sp_contact_ipa_code']) ? (string) $options['sp_contact_ipa_code'] : (string) ($options['ipa_code'] ?? ''),
            'sp_contact_fiscal_code' => !empty($options['sp_contact_fiscal_code']) ? (string) $options['sp_contact_fiscal_code'] : (string) ($options['fiscal_number'] ?? ''),
            'sp_contact_email' => !empty($options['sp_contact_email']) ? (string) $options['sp_contact_email'] : (string) ($options['contacts_email'] ?? get_option('admin_email')),
            'sp_contact_phone' => (string) ($options['sp_contact_phone'] ?? ''),
            'spid_saml_idp_mode' => !empty($options['spid_saml_idp_mode']) ? (string) $options['spid_saml_idp_mode'] : 'auto',
            'spid_saml_idp_registry_selected' => (string) ($options['spid_saml_idp_registry_selected'] ?? ''),
        ];
    }

    public function normalize_spid_saml_options(): void {
        if (!is_admin()) {
            return;
        }
        $options = get_option($this->plugin_name . '_options', []);
        if (!is_array($options)) {
            $options = [];
        }
        $defaults = $this->get_spid_saml_defaults($options);
        $changed = false;
        foreach ($defaults as $k => $v) {
            if (!isset($options[$k]) || $options[$k] === '') {
                $options[$k] = $v;
                $changed = true;
            }
        }
        if (!empty($options['spid_saml_idp_cert']) && empty($options['spid_saml_idp_x509_cert'])) {
            $options['spid_saml_idp_x509_cert'] = (string) $options['spid_saml_idp_cert'];
            $changed = true;
        }
        if (empty($options['spid_saml_idp_mode'])) {
            $options['spid_saml_idp_mode'] = 'auto';
            $changed = true;
        }
        if (empty($options['spid_saml_metadata_token'])) {
            $options['spid_saml_metadata_token'] = wp_generate_password(24, false, false);
            $changed = true;
        }
        if (empty($options['spid_saml_requested_attributes']) || !is_array($options['spid_saml_requested_attributes'])) {
            $options['spid_saml_requested_attributes'] = ['name', 'familyName', 'fiscalNumber', 'email'];
            $changed = true;
        }
        if ($changed) {
            update_option($this->plugin_name . '_options', $options, false);
        }
    }

    private function get_registry_service() {
        if (!class_exists('WP_SPID_CIE_OIDC_Spid_Registry_Service')) {
            require_once plugin_dir_path(dirname(__FILE__)) . 'includes/class-wp-spid-cie-spid-registry-service.php';
        }
        return new WP_SPID_CIE_OIDC_Spid_Registry_Service();
    }

    private function ensure_spid_saml_metadata_token(array $options): array {
        if (empty($options['spid_saml_metadata_token'])) {
            $options['spid_saml_metadata_token'] = wp_generate_password(24, false, false);
            update_option($this->plugin_name . '_options', $options, false);
        }
        return $options;
    }

    private function get_registry_list_url(): string {
        return 'https://registry.spid.gov.it/entities-idp?output=json';
    }

    private function get_registry_fallback_list_url(): string {
        return 'https://registry.spid.gov.it/entities?entity_type=idp';
    }

    private function fetch_json_https(string $url) {
        $url = esc_url_raw($url);
        if ($url === '' || stripos($url, 'https://') !== 0) {
            return new WP_Error('spid_registry_invalid_url', __('URL Registry non valido.', 'wp-spid-cie'));
        }

        $resp = wp_remote_get($url, ['timeout' => 10, 'redirection' => 3, 'limit_response_size' => 1024 * 1024]);
        if (is_wp_error($resp)) {
            return $resp;
        }
        $code = (int) wp_remote_retrieve_response_code($resp);
        if ($code < 200 || $code > 299) {
            return new WP_Error('spid_registry_http_error', __('Registry SPID non disponibile.', 'wp-spid-cie'));
        }
        $body = (string) wp_remote_retrieve_body($resp);
        $data = json_decode($body, true);
        if (!is_array($data)) {
            return new WP_Error('spid_registry_json_error', __('Risposta Registry non valida.', 'wp-spid-cie'));
        }
        return $data;
    }

    private function get_registry_idp_list(bool $force = false) {
        $cache_key = 'spid_saml_registry_list_v1';
        if (!$force) {
            $cached = get_transient($cache_key);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $data = $this->fetch_json_https($this->get_registry_list_url());
        if (is_wp_error($data)) {
            $data = $this->fetch_json_https($this->get_registry_fallback_list_url());
        }
        if (is_wp_error($data)) {
            return $data;
        }

        $list = isset($data['items']) && is_array($data['items']) ? $data['items'] : $data;
        if (!is_array($list)) {
            return new WP_Error('spid_registry_list_invalid', __('Lista IdP non valida.', 'wp-spid-cie'));
        }

        set_transient($cache_key, $list, DAY_IN_SECONDS);
        return $list;
    }

    private function normalize_registry_list_item(array $item): array {
        $entity = (string) ($item['entity_id'] ?? $item['entityID'] ?? $item['id'] ?? '');
        $name = (string) ($item['organization_name'] ?? $item['info_display_base'] ?? $item['display_name'] ?? $item['name'] ?? $entity);
        $link = (string) ($item['registry_link'] ?? $item['registryLink'] ?? $item['detail_link'] ?? '');
        return ['entity_id' => $entity, 'name' => $name, 'registry_link' => $link];
    }

    private function get_registry_detail_for_entity(string $entityId, string $registryLink = '', bool $force = false) {
        $entityId = trim($entityId);
        if ($entityId === '') {
            return new WP_Error('spid_registry_entity_missing', __('EntityID IdP mancante.', 'wp-spid-cie'));
        }

        $cache_key = 'spid_saml_registry_detail_' . md5($entityId);
        if (!$force) {
            $cached = get_transient($cache_key);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $url = $registryLink;
        if ($url === '') {
            $url = 'https://registry.spid.gov.it/entities-idp/' . rawurlencode($entityId) . '?output=json';
        }

        $detail = $this->fetch_json_https($url);
        if (is_wp_error($detail)) {
            return $detail;
        }

        set_transient($cache_key, $detail, DAY_IN_SECONDS);
        return $detail;
    }

    private function extract_registry_runtime_values(array $detail): array {
        $entity = (string) ($detail['entity_id'] ?? $detail['entityID'] ?? $detail['id'] ?? '');

        $services = [];
        foreach (['single_sign_on_service', 'singleSignOnService', 'sso_services', 'sso', 'services'] as $k) {
            if (isset($detail[$k]) && is_array($detail[$k])) {
                $services = $detail[$k];
                break;
            }
        }

        if (empty($services) && isset($detail['metadata']) && is_array($detail['metadata'])) {
            $meta = $detail['metadata'];
            foreach (['idp', 'saml2_idp', 'spid_idp'] as $k) {
                if (isset($meta[$k]) && is_array($meta[$k])) {
                    $m = $meta[$k];
                    if (empty($entity)) {
                        $entity = (string) ($m['entity_id'] ?? $m['entityID'] ?? $entity);
                    }
                    foreach (['single_sign_on_service', 'singleSignOnService', 'services'] as $sk) {
                        if (isset($m[$sk]) && is_array($m[$sk])) {
                            $services = $m[$sk];
                            break 2;
                        }
                    }
                }
            }
        }

        $ssoRedirect = '';
        $ssoPost = '';
        $slo = '';
        foreach ($services as $srv) {
            if (!is_array($srv)) continue;
            $binding = (string) ($srv['binding'] ?? $srv['Binding'] ?? '');
            $loc = (string) ($srv['location'] ?? $srv['Location'] ?? $srv['url'] ?? '');
            if ($loc === '') continue;
            if (stripos($binding, 'SingleLogout') !== false || stripos($binding, 'SLO') !== false) {
                if ($slo === '') $slo = $loc;
                continue;
            }
            if (stripos($binding, 'HTTP-Redirect') !== false && $ssoRedirect === '') $ssoRedirect = $loc;
            if (stripos($binding, 'HTTP-POST') !== false && $ssoPost === '') $ssoPost = $loc;
        }

        if ($slo === '' && isset($detail['single_logout_service']) && is_array($detail['single_logout_service'])) {
            $tmp = $detail['single_logout_service'][0] ?? [];
            $slo = (string) ($tmp['location'] ?? $tmp['Location'] ?? '');
        }

        $cert = '';
        if (isset($detail['signing_certificate_x509'])) {
            $raw = $detail['signing_certificate_x509'];
            if (is_array($raw)) {
                $parts = array_filter(array_map('trim', array_map('strval', $raw)));
                $cert = implode("
", $parts);
            } else {
                $cert = (string) $raw;
            }
        } elseif (isset($detail['certificates']) && is_array($detail['certificates'])) {
            $parts = array_filter(array_map('trim', array_map('strval', $detail['certificates'])));
            $cert = implode("
", $parts);
        } elseif (isset($detail['metadata']) && is_array($detail['metadata'])) {
            $meta = $detail['metadata'];
            foreach (['idp', 'saml2_idp', 'spid_idp'] as $k) {
                if (!isset($meta[$k]) || !is_array($meta[$k])) continue;
                $m = $meta[$k];
                if (isset($m['signing_certificate_x509'])) {
                    $raw = $m['signing_certificate_x509'];
                    if (is_array($raw)) {
                        $parts = array_filter(array_map('trim', array_map('strval', $raw)));
                        $cert = implode("
", $parts);
                    } else {
                        $cert = (string) $raw;
                    }
                    break;
                }
            }
        }

        return [
            'entity_id' => sanitize_text_field($entity),
            'sso_url' => esc_url_raw($ssoRedirect !== '' ? $ssoRedirect : $ssoPost),
            'slo_url' => esc_url_raw($slo),
            'x509_cert' => trim((string) $cert),
        ];
    }

    private function sync_registry_selected_idp(array $options, bool $force = false): array {
        $mode = isset($options['spid_saml_idp_mode']) ? sanitize_key((string) $options['spid_saml_idp_mode']) : 'auto';
        if ($mode !== 'auto') {
            return $options;
        }

        $selected = isset($options['spid_saml_idp_registry_selected']) ? (string) $options['spid_saml_idp_registry_selected'] : '';
        if ($selected === '') {
            return $options;
        }

        $link = isset($options['spid_saml_idp_registry_link']) ? (string) $options['spid_saml_idp_registry_link'] : '';
        $detail = $this->get_registry_detail_for_entity($selected, $link, $force);
        if (is_wp_error($detail)) {
            add_settings_error($this->plugin_name . '_options', 'spid_saml_registry_fetch_failed', __('Impossibile aggiornare IdP dal Registry SPID. Mantengo i valori correnti.', 'wp-spid-cie'), 'error');
            return $options;
        }

        $runtime = $this->extract_registry_runtime_values($detail);
        if (!empty($runtime['entity_id']) && !empty($runtime['sso_url']) && !empty($runtime['x509_cert'])) {
            $options['spid_saml_idp_entity_id'] = $runtime['entity_id'];
            $options['spid_saml_idp_sso_url'] = $runtime['sso_url'];
            $options['spid_saml_idp_slo_url'] = $runtime['slo_url'];
            $options['spid_saml_idp_x509_cert'] = $runtime['x509_cert'];
            $options['spid_saml_idp_last_sync'] = (string) time();
        }

        return $options;
    }

    public function handle_spid_saml_registry_refresh(): void {
        if (!is_admin() || !current_user_can('manage_options')) {
            return;
        }
        if (!isset($_GET['action']) || sanitize_key((string) wp_unslash($_GET['action'])) !== 'spid_saml_refresh_registry') {
            return;
        }
        if (!isset($_GET['_wpnonce']) || !wp_verify_nonce((string) wp_unslash($_GET['_wpnonce']), 'spid_saml_refresh_registry')) {
            wp_die('Security check failed');
        }

        $service = $this->get_registry_service();
        $service->refresh_all();

        $options = get_option($this->plugin_name . '_options', []);
        if (!is_array($options)) {
            $options = [];
        }
        $options['spid_saml_idp_last_sync'] = time();
        update_option($this->plugin_name . '_options', $options, false);

        wp_safe_redirect(add_query_arg(['page' => $this->plugin_name, 'tab' => 'spid_saml', 'registry_refreshed' => '1'], admin_url('options-general.php')));
        exit;
    }

    private function render_spid_saml_module(): void {
        $this->render_spid_saml_settings_subtab();
    }


    private function render_stato_tab(): void {
        echo '<h2>Stato e diagnostica</h2>';
        $this->render_status_dashboard();

        echo '<hr>';
        echo '<h2>Checklist rapida</h2>';
        $this->render_operational_help();

        echo '<hr>';
        echo '<h2>SPID SAML: endpoint e metadata</h2>';
        $this->render_spid_saml_endpoints_preview();

        $registry = $this->get_registry_service();
        $list = $registry->get_idp_list(false);
        $status = $registry->get_status();
        $count = is_array($list) ? count($list) : (int) ($status['count'] ?? 0);
        $source = (string) ($status['source'] ?? 'n/a');
        $fetchedAt = (int) ($status['fetched_at'] ?? 0);
        echo '<h3>Registry status</h3>';
        echo '<p>IdP caricati: <strong>' . esc_html((string) $count) . '</strong></p>';
        echo '<p>Sorgente: <strong>' . esc_html(strtoupper($source)) . '</strong></p>';
        echo '<p>Cache aggiornata: <strong>' . ($fetchedAt > 0 ? esc_html(wp_date('d/m/Y H:i:s', $fetchedAt)) : 'n/d') . '</strong></p>';

        $this->render_spid_saml_metadata_subtab();

        $options = get_option($this->plugin_name . '_options', []);
        if (!is_array($options)) {
            $options = [];
        }
        $validator_enabled = !empty($options['spid_saml_validator_enabled']) && $options['spid_saml_validator_enabled'] === '1';
        echo '<p><strong>SPID Validator:</strong> ' . ($validator_enabled ? 'Abilitato' : 'Disabilitato') . '</p>';
    }

    private function render_spid_saml_settings_subtab(): void {
        $options = get_option($this->plugin_name . '_options', []);
        $d = $this->get_spid_saml_defaults($options);
        echo '<h2>Impostazioni SPID SAML</h2>';
        echo '<p class="description">Se lasci vuoto, usiamo automaticamente i valori del tab A. Ente.</p>';

        $this->render_text_field(['id' => 'spid_saml_country_name', 'placeholder' => 'IT', 'desc' => 'countryName (esempio: IT)']);
        $this->render_text_field(['id' => 'spid_saml_state_or_province_name', 'placeholder' => 'Roma', 'desc' => 'stateOrProvinceName (esempio: Roma)']);
        $this->render_text_field(['id' => 'spid_saml_locality_name', 'placeholder' => 'Roma', 'desc' => 'localityName (esempio: Roma)']);
        $this->render_text_field(['id' => 'spid_saml_common_name', 'placeholder' => $d['commonName'], 'desc' => 'commonName (esempio: comune.example.it)']);
        $this->render_text_field(['id' => 'spid_saml_email_address', 'placeholder' => $d['emailAddress'], 'desc' => 'emailAddress (esempio: protocollo@ente.it)']);

        $this->render_text_field(['id' => 'sp_org_name', 'placeholder' => $d['sp_org_name'], 'desc' => 'Denominazione ente']);
        $this->render_text_field(['id' => 'sp_org_display_name', 'placeholder' => $d['sp_org_display_name'], 'desc' => 'Nome pubblico ente']);
        $this->render_text_field(['id' => 'sp_contact_ipa_code', 'placeholder' => $d['sp_contact_ipa_code'], 'desc' => 'Codice IPA']);
        $this->render_text_field(['id' => 'sp_contact_fiscal_code', 'placeholder' => $d['sp_contact_fiscal_code'], 'desc' => 'Codice fiscale ente']);
        $this->render_text_field(['id' => 'sp_contact_email', 'placeholder' => $d['sp_contact_email'], 'desc' => 'Email contatto tecnico']);
        $this->render_text_field(['id' => 'sp_contact_phone', 'placeholder' => $d['sp_contact_phone'], 'desc' => 'Telefono contatto (opzionale)']);

        $registryStatus = $this->get_registry_service()->get_status();
        $lastSync = (int) ($registryStatus['fetched_at'] ?? 0);
        if ($lastSync > 0) {
            echo '<p><strong>Ultimo aggiornamento registry:</strong> ' . esc_html(wp_date('d/m/Y H:i:s', $lastSync)) . '</p>';
        }
        $refresh_url = wp_nonce_url(add_query_arg(['page'=>$this->plugin_name,'tab'=>'spid_saml','action'=>'spid_saml_refresh_registry'], admin_url('options-general.php')), 'spid_saml_refresh_registry');
        echo '<p><a class="button button-secondary" href="' . esc_url($refresh_url) . '">Aggiorna Registry IdP ora</a></p>';

        echo '<hr><h3>Opzioni avanzate</h3>';
        $this->render_select_field(['id' => 'spid_saml_level','options'=>['SpidL1'=>'SPID L1','SpidL2'=>'SPID L2','SpidL3'=>'SPID L3'],'default'=>'SpidL2']);
        echo '<p><strong>Response binding (ACS)</strong></p>';
        $this->render_select_field(['id' => 'spid_saml_binding','options'=>['post'=>'HTTP-POST (consigliato)','redirect'=>'HTTP-Redirect'],'default'=>'post']);
        echo '<p><strong>EntityID / Issuer SP (SAML)</strong></p>';
        $this->render_text_field(['id' => 'spid_saml_entity_id','placeholder'=>home_url('/'), 'desc' => 'Se vuoto usa Issuer/Identificativo componente del tab Ente.']);

        $selected_attrs = isset($options['spid_saml_requested_attributes']) && is_array($options['spid_saml_requested_attributes'])
            ? array_map('strval', $options['spid_saml_requested_attributes'])
            : ['name', 'familyName', 'fiscalNumber', 'email'];
        $attribute_labels = [
            'name' => 'name',
            'familyName' => 'familyName',
            'fiscalNumber' => 'fiscalNumber',
            'email' => 'email',
            'mobilePhone' => 'mobilePhone (opzionale)',
        ];
        echo '<h3>Attributi richiesti (SAML)</h3>';
        echo '<fieldset>';
        foreach ($attribute_labels as $attr_key => $attr_label) {
            $is_checked = in_array($attr_key, $selected_attrs, true);
            echo '<label style="display:block;margin-bottom:4px;"><input type="checkbox" name="' . esc_attr($this->plugin_name . '_options[spid_saml_requested_attributes][]') . '" value="' . esc_attr($attr_key) . '" ' . checked($is_checked, true, false) . ' /> ' . esc_html($attr_label) . '</label>';
        }
        echo '</fieldset>';
        $this->render_checkbox_field(['id' => 'spid_saml_debug', 'desc' => 'Debug header/log extra (solo WP_DEBUG)']);
        $this->render_text_field(['id' => 'spid_saml_clock_skew','placeholder'=>'120']);
    }

    private function render_spid_saml_metadata_subtab(): void {
        $options = get_option($this->plugin_name . '_options', []);
        if (!is_array($options)) {
            $options = [];
        }
        $options = $this->ensure_spid_saml_metadata_token($options);
        $token = isset($options['spid_saml_metadata_token']) ? (string) $options['spid_saml_metadata_token'] : '';
        if (isset($_GET['regen_metadata_token']) && check_admin_referer('spid_saml_regen_token')) {
            $token = wp_generate_password(24, false, false);
            $options['spid_saml_metadata_token'] = $token;
            update_option($this->plugin_name . '_options', $options, false);
            echo '<div class="notice notice-success inline"><p>Token metadata rigenerato.</p></div>';
        }
        $spUrl = add_query_arg('spid_metadata_token', rawurlencode($token), home_url('/spid/saml/metadata'));
        $aggUrl = add_query_arg('spid_metadata_token', rawurlencode($token), home_url('/spid/saml/metadata?aggregator=1'));
        echo '<h2>Metadata</h2>';
        echo '<p><strong>URL metadata SP:</strong> <code>' . esc_html($spUrl) . '</code></p>';
        echo '<p><strong>URL metadata Aggregator:</strong> <code>' . esc_html($aggUrl) . '</code></p>';
        echo '<p class="description">Conserva questi URL con cura. Non pubblicarli su forum o ticket pubblici.</p>';
        $regen = wp_nonce_url(add_query_arg(['page'=>$this->plugin_name,'tab'=>'stato','regen_metadata_token'=>'1'], admin_url('options-general.php')), 'spid_saml_regen_token');
        echo '<p><a class="button button-secondary" onclick="return confirm(\'Rigenerare il token rendera invalidi i vecchi URL metadata.\');" href="' . esc_url($regen) . '">Rigenera URL metadata</a></p>';
    }

    // --- CALLBACK RENDERING ---

    public function handle_key_generation() {
        if ( isset( $_GET['action'], $_GET['_wpnonce'] ) && $_GET['action'] === 'generate_oidc_keys' ) {
            if ( ! wp_verify_nonce( $_GET['_wpnonce'], 'generate_oidc_keys_nonce' ) ) { wp_die('Security check failed'); }
            
            if (!class_exists('WP_SPID_CIE_OIDC_Factory')) {
                 require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-spid-cie-factory.php';
            }
            try {
                $client = WP_SPID_CIE_OIDC_Factory::get_client();
                $client->generateKeys();
                wp_redirect(admin_url('options-general.php?page=' . $this->plugin_name . '&keys-generated=true'));
                exit;
            } catch (Exception $e) {
                set_transient('spid_cie_oidc_error', $e->getMessage(), 45);
                wp_redirect(admin_url('options-general.php?page=' . $this->plugin_name . '&keys-error=true'));
                exit;
            }
        }
    }

    public function render_keys_manager() {
        $keys_exist = false;
        $upload_dir = wp_upload_dir();
        $keys_dir = trailingslashit($upload_dir['basedir']) . 'spid-cie-oidc-keys';
        if (file_exists($keys_dir . '/private.key') && file_exists($keys_dir . '/public.crt')) {
            $keys_exist = true;
        }

        if ($keys_exist) {
            echo '<div class="spid-status-ok"><span class="dashicons dashicons-yes"></span> Chiavi crittografiche presenti e valide.</div>';
        } else {
            echo '<div class="spid-status-ko"><span class="dashicons dashicons-warning"></span> Chiavi non trovate. È necessario generarle per attivare il servizio.</div>';
        }

        echo '<p style="margin: 15px 0;">';
        $generation_url = wp_nonce_url(admin_url('options-general.php?page=' . $this->plugin_name . '&action=generate_oidc_keys'), 'generate_oidc_keys_nonce');
        echo '<a href="' . esc_url($generation_url) . '" class="button button-secondary" onclick="return confirm(\'Sei sicuro? Rigenerare le chiavi renderà invalidi i metadata attuali sui portali AgID/CIE.\');">'. ($keys_exist ? 'Rigenera Chiavi' : 'Genera Chiavi') .'</a>';
        echo '</p>';

        if ($keys_exist) {
            echo '<hr>';
            $options = get_option( $this->plugin_name . '_options', [] );
            $entity_id = !empty($options['entity_id']) ? trim((string) $options['entity_id']) : '';
            $base = $entity_id !== '' ? untrailingslashit($entity_id) : (!empty($options['issuer_override']) ? untrailingslashit($options['issuer_override']) : home_url());
            $federation_url = $base . '/.well-known/openid-federation';
            echo '<label for="entity_statement_uri"><strong>Entity Statement URI (Metadata OIDC):</strong></label>';
            echo '<p class="description">Copia questo URL per la registrazione sui portali AgID e Federazione CIE.</p>';
            echo '<input type="text" id="entity_statement_uri" readonly class="large-text code" value="' . esc_url($federation_url) . '" onclick="this.select();">';
        }
    }

    public function print_keys_section_info() {
        if (isset($_GET['keys-generated'])) { echo '<div class="notice notice-success inline"><p>Chiavi generate con successo!</p></div>'; }
        if (isset($_GET['keys-error'])) {
            $error = get_transient('spid_cie_oidc_error');
            echo '<div class="notice notice-error inline"><p>Errore: ' . esc_html($error) . '</p></div>';
        }
        echo '<p>Il sistema gestisce automaticamente la creazione dei certificati crittografici richiesti dalla federazione.</p>';
    }

    public function render_text_field( $args ) {
        $options = get_option( $this->plugin_name . '_options' );
        $id = $args['id'];
        $val = isset( $options[$id] ) ? esc_attr( $options[$id] ) : '';
        $desc = $args['desc'] ?? '';
        $placeholder = $args['placeholder'] ?? '';
        
        echo "<input type='text' name='{$this->plugin_name}_options[$id]' value='$val' class='regular-text' placeholder='$placeholder'>";
        if ($desc) { echo "<p class='description'>$desc</p>"; }
    }

    public function render_textarea_field( $args ) {
        $options = get_option( $this->plugin_name . '_options' );
        $id = $args['id'];
        $default = $args['default'] ?? '';
        $val = isset($options[$id]) ? $options[$id] : '';
        if (empty($val) && !empty($default)) { $val = $default; }
        
        $desc = $args['desc'] ?? '';
        echo "<textarea name='{$this->plugin_name}_options[$id]' class='large-text' rows='4'>" . esc_textarea($val) . "</textarea>";
        if ($desc) echo "<p class='description'>$desc</p>";
    }

    public function render_checkbox_field( $args ) {
        $options = get_option( $this->plugin_name . '_options' );
        $id = $args['id'];
        $checked = isset( $options[$id] ) && $options[$id] === '1' ? 'checked' : '';
        $desc = $args['desc'] ?? '';
        echo "<label><input type='checkbox' name='{$this->plugin_name}_options[$id]' value='1' $checked> $desc</label>";
    }
	
    public function render_select_field( $args ) {
        $options = get_option( $this->plugin_name . '_options' );
        $id = $args['id'];
        $choices = $args['options'] ?? [];
        $default = $args['default'] ?? '';
        $val = isset($options[$id]) ? (string) $options[$id] : (string) $default;
        $desc = $args['desc'] ?? '';

        echo "<select name='{$this->plugin_name}_options[$id]'>";
        foreach ($choices as $k => $label) {
            $selected = selected($val, (string) $k, false);
            echo "<option value='" . esc_attr($k) . "' $selected>" . esc_html($label) . "</option>";
        }
        echo "</select>";
        if ($desc) {
            echo "<p class='description'>" . esc_html($desc) . "</p>";
        }
    }

	public function render_public_key_field() {
		$upload_dir = wp_upload_dir();
		$keys_dir = trailingslashit($upload_dir['basedir']) . 'spid-cie-oidc-keys';

		$public_file = $keys_dir . '/public.crt';

		if (!file_exists($public_file)) {
			echo '<p style="color:#b32d2e;">Chiave pubblica non disponibile. Genera prima le chiavi.</p>';
			return;
		}

		$public_pem = file_get_contents($public_file);
		if (!$public_pem) {
			echo '<p style="color:#b32d2e;">Impossibile leggere la chiave pubblica. Verifica permessi in uploads/spid-cie-oidc-keys.</p>';
			return;
		}

		$id = 'wp_spid_cie_public_key_pem';

		echo '<textarea id="'.esc_attr($id).'" class="large-text code" rows="8" readonly>'
			. esc_textarea($public_pem)
			. '</textarea>';

		echo '<p><button type="button" class="button" onclick="(function(){const el=document.getElementById(\''.esc_js($id).'\'); el.select(); document.execCommand(\'copy\');})();">Copia</button></p>';

		echo '<p class="description"><strong>Nota:</strong> se rigeneri le chiavi, devi aggiornare questa chiave anche sul portale CIE.</p>';
	}
	
	public function render_trust_anchor_preview_field() {
		$options = get_option($this->plugin_name . '_options', []);
		$rows = [
			'CIE pre-produzione' => $options['cie_trust_anchor_preprod'] ?? '',
			'CIE produzione' => $options['cie_trust_anchor_prod'] ?? '',
			'SPID' => $options['spid_trust_anchor'] ?? '',
		];

		echo '<ul class="spid-readonly-list">';
		foreach ($rows as $label => $url) {
			echo '<li><strong>' . esc_html($label) . ':</strong> <code>' . esc_html($url !== '' ? $url : 'non impostato') . '</code></li>';
		}
		echo '</ul>';
		echo '<p class="description">Valori mostrati in sola lettura per verifica rapida pre-invio al portale di federazione.</p>';
	}

	private function get_keys_dir_path(): string {
		$upload_dir = wp_upload_dir();
		return trailingslashit($upload_dir['basedir']) . 'spid-cie-oidc-keys';
	}

	private function render_copyable_textarea(string $id, string $value, int $rows = 8, string $help = ''): void {
		echo '<textarea id="'.esc_attr($id).'" class="large-text code" rows="'.intval($rows).'" readonly>'
			. esc_textarea($value)
			. '</textarea>';

		echo '<p><button type="button" class="button" onclick="(function(){const el=document.getElementById(\''.esc_js($id).'\'); el.focus(); el.select(); document.execCommand(\'copy\');})();">Copia</button></p>';

		if ($help) {
			echo '<p class="description">'.$help.'</p>';
		}
	}

	public function render_cie_certificate_field() {
		$keys_dir = $this->get_keys_dir_path();
		$cert_file = $keys_dir . '/public.crt';

		if (!file_exists($cert_file)) {
			echo '<p style="color:#b32d2e;">Certificato non disponibile. Genera prima le chiavi.</p>';
			return;
		}

		$cert_pem = file_get_contents($cert_file);
		if (!$cert_pem) {
			echo '<p style="color:#b32d2e;">Impossibile leggere il certificato. Verifica permessi in uploads/spid-cie-oidc-keys.</p>';
			return;
		}

		// Controllo "sanity": deve essere un CERTIFICATE
		if (stripos($cert_pem, 'BEGIN CERTIFICATE') === false) {
			echo '<p style="color:#b32d2e;"><strong>Attenzione:</strong> public.crt non sembra essere un certificato X.509 (BEGIN CERTIFICATE). Rigenera le chiavi con la nuova versione del plugin.</p>';
			// Mostriamo comunque il contenuto per debug/copia
		}

		$help = '<strong>Da incollare nel portale Federazione CIE</strong> nel campo “Chiave pubblica di federazione”.'
			  . '<br><strong>Nota:</strong> se rigeneri le chiavi, devi aggiornare anche questa chiave sul portale CIE.';

		$this->render_copyable_textarea(
			'wp_spid_cie_cert_pem',
			$cert_pem,
			10,
			$help
		);
	}

	public function render_public_key_raw_field() {
		$keys_dir = $this->get_keys_dir_path();
		$pub_file = $keys_dir . '/public.key';

		if (!file_exists($pub_file)) {
			echo '<p style="color:#b32d2e;">Public key non disponibile. Genera prima le chiavi.</p>';
			return;
		}

		$pub_pem = file_get_contents($pub_file);
		if (!$pub_pem) {
			echo '<p style="color:#b32d2e;">Impossibile leggere la public key. Verifica permessi in uploads/spid-cie-oidc-keys.</p>';
			return;
		}

		$help = 'Chiave pubblica “raw” (PEM). <em>Di solito NON va usata nel portale</em> (che preferisce il certificato X.509), ma è utile per debug o interoperabilità.';

		$this->render_copyable_textarea(
			'wp_spid_cie_public_key_raw',
			$pub_pem,
			8,
			$help
		);
	}
	
    private function get_role_options(): array {
        $roles = wp_roles()->roles;
        $out = [];
        foreach ($roles as $key => $role) {
            $out[$key] = translate_user_role($role['name']);
        }
        return $out;
    }

    public function sanitize_options( $input ) {
        $existing = get_option($this->plugin_name . '_options', []);
        if (!is_array($existing)) {
            $existing = [];
        }

        $current_tab = isset($input['_current_tab']) ? sanitize_key($input['_current_tab']) : 'ente';
        $allowed_by_tab = [
            'ente' => ['organization_name', 'ipa_code', 'fiscal_number', 'contacts_email', 'issuer_override', 'entity_id'],
            'cie' => ['cie_trust_anchor_preprod', 'cie_trust_anchor_prod', 'spid_trust_anchor', 'cie_trust_mark_preprod', 'cie_trust_mark_prod'],
            'spid_oidc' => [
                'provider_mode', 'discovery_mode', 'min_loa',
                'spid_issuer', 'cie_issuer', 'spid_scope', 'cie_scope', 'spid_acr_values', 'cie_acr_values',
                'spid_authorization_endpoint', 'spid_token_endpoint', 'spid_jwks_uri', 'spid_userinfo_endpoint', 'spid_end_session_endpoint',
                'cie_authorization_endpoint', 'cie_token_endpoint', 'cie_jwks_uri', 'cie_userinfo_endpoint', 'cie_end_session_endpoint'
            ],
            'impostazioni' => ['spid_enabled', 'cie_enabled', 'spid_saml_validator_enabled', 'spid_auth_method'],
            'spid_saml' => ['spid_saml_entity_id', 'spid_saml_debug', 'spid_saml_clock_skew', 'spid_saml_level', 'spid_saml_binding', 'spid_saml_idp_entity_id', 'spid_saml_idp_sso_url', 'spid_saml_idp_slo_url', 'spid_saml_idp_x509_cert', 'spid_saml_idp_metadata_xml', 'spid_saml_idp_cert', 'spid_saml_show_advanced', 'spid_saml_country_name', 'spid_saml_state_or_province_name', 'spid_saml_locality_name', 'spid_saml_common_name', 'spid_saml_email_address', 'sp_org_name', 'sp_org_display_name', 'sp_contact_ipa_code', 'sp_contact_fiscal_code', 'sp_contact_email', 'sp_contact_phone', 'spid_saml_idp_mode', 'spid_saml_idp_registry_selected', 'spid_saml_idp_registry_link', 'spid_saml_idp_last_sync', 'spid_saml_metadata_token', 'spid_saml_requested_attributes'],
        ];

        $new_input = $existing;
        $legacy_tab_map = [
            'a_ente' => 'ente',
            'b_federazione' => 'cie',
            'c_provider' => 'spid_oidc',
            'd_disclaimer' => 'impostazioni',
            'e_operativo' => 'impostazioni',
            'f_spid_saml' => 'spid_saml',
            'g_stato' => 'stato',
        ];
        if (isset($legacy_tab_map[$current_tab])) {
            $current_tab = $legacy_tab_map[$current_tab];
        }

        $allowed = $allowed_by_tab[$current_tab] ?? [];

        $text_fields = ['organization_name', 'ipa_code', 'fiscal_number', 'contacts_email', 'spid_scope', 'cie_scope', 'spid_acr_values', 'cie_acr_values', 'spid_saml_clock_skew', 'spid_saml_country_name', 'spid_saml_state_or_province_name', 'spid_saml_locality_name', 'spid_saml_common_name', 'spid_saml_email_address', 'sp_org_name', 'sp_org_display_name', 'sp_contact_ipa_code', 'sp_contact_fiscal_code', 'sp_contact_email', 'sp_contact_phone'];
        foreach ($text_fields as $f) {
            if (in_array($f, $allowed, true) && isset($input[$f])) {
                $new_input[$f] = sanitize_text_field($input[$f]);
            }
        }

        $checkboxes = ['spid_enabled', 'cie_enabled', 'spid_test_env', 'disclaimer_enabled', 'user_provisioning_enabled', 'spid_saml_enabled', 'spid_saml_validator_enabled', 'spid_saml_debug', 'spid_saml_show_advanced'];
        foreach ($checkboxes as $c) {
            if (in_array($c, $allowed, true)) {
                $new_input[$c] = (isset($input[$c]) && $input[$c] === '1') ? '1' : '0';
            }
        }


        if (in_array('spid_auth_method', $allowed, true)) {
            $method = isset($input['spid_auth_method']) ? sanitize_key((string) $input['spid_auth_method']) : 'saml';
            $new_input['spid_auth_method'] = in_array($method, ['saml', 'oidc'], true) ? $method : 'saml';

            $current_saml_enabled = isset($existing['spid_saml_enabled']) ? (string) $existing['spid_saml_enabled'] : '1';
            if (!empty($new_input['spid_saml_enabled'])) {
                $current_saml_enabled = (string) $new_input['spid_saml_enabled'];
            }

            if (empty($new_input['spid_enabled']) || $new_input['spid_enabled'] !== '1' || $new_input['spid_auth_method'] !== 'saml') {
                $new_input['spid_saml_enabled_last'] = $current_saml_enabled;
                $new_input['spid_saml_enabled'] = '0';
            } else {
                if (isset($existing['spid_saml_enabled_last']) && $existing['spid_saml_enabled_last'] !== '') {
                    $new_input['spid_saml_enabled'] = (string) $existing['spid_saml_enabled_last'];
                } elseif (isset($existing['spid_saml_enabled']) && $existing['spid_saml_enabled'] !== '') {
                    $new_input['spid_saml_enabled'] = (string) $existing['spid_saml_enabled'];
                } else {
                    $new_input['spid_saml_enabled'] = '1';
                }
            }
        }
        if (in_array('disclaimer_text', $allowed, true) && isset($input['disclaimer_text'])) {
            $new_input['disclaimer_text'] = wp_kses_post($input['disclaimer_text']);
        }

        $tm_fields = ['cie_trust_mark_preprod', 'cie_trust_mark_prod', 'spid_saml_idp_x509_cert', 'spid_saml_idp_metadata_xml', 'spid_saml_idp_cert'];
        foreach ($tm_fields as $f) {
            if (in_array($f, $allowed, true) && isset($input[$f])) {
                $new_input[$f] = trim(sanitize_textarea_field($input[$f]));
            }
        }

        $url_fields = [
            'issuer_override', 'entity_id',
            'cie_trust_anchor_preprod', 'cie_trust_anchor_prod', 'spid_trust_anchor',
            'spid_saml_entity_id',
            'spid_saml_idp_entity_id', 'spid_saml_idp_sso_url', 'spid_saml_idp_slo_url',
            'spid_issuer', 'cie_issuer',
            'spid_authorization_endpoint', 'spid_token_endpoint', 'spid_jwks_uri', 'spid_userinfo_endpoint', 'spid_end_session_endpoint',
            'cie_authorization_endpoint', 'cie_token_endpoint', 'cie_jwks_uri', 'cie_userinfo_endpoint', 'cie_end_session_endpoint'
        ];
        foreach ($url_fields as $f) {
            if (in_array($f, $allowed, true) && isset($input[$f])) {
                $new_input[$f] = esc_url_raw(trim((string) $input[$f]));
            }
        }


        if (in_array('spid_saml_clock_skew', $allowed, true)) {
            $skew = isset($input['spid_saml_clock_skew']) ? (int) $input['spid_saml_clock_skew'] : 120;
            $new_input['spid_saml_clock_skew'] = (string) max(0, min(600, $skew));
        }


        if (in_array('spid_saml_level', $allowed, true)) {
            $lvl = isset($input['spid_saml_level']) ? sanitize_text_field((string) $input['spid_saml_level']) : 'SpidL2';
            $new_input['spid_saml_level'] = in_array($lvl, ['SpidL1', 'SpidL2', 'SpidL3'], true) ? $lvl : 'SpidL2';
        }

        if (in_array('spid_saml_idp_mode', $allowed, true)) {
            $mode = isset($input['spid_saml_idp_mode']) ? sanitize_key((string) $input['spid_saml_idp_mode']) : 'auto';
            $new_input['spid_saml_idp_mode'] = in_array($mode, ['auto', 'manual'], true) ? $mode : 'auto';
        }

        if (in_array('spid_saml_idp_registry_selected', $allowed, true)) {
            $new_input['spid_saml_idp_registry_selected'] = isset($input['spid_saml_idp_registry_selected']) ? sanitize_text_field(trim((string) $input['spid_saml_idp_registry_selected'])) : '';
            if ($new_input['spid_saml_idp_registry_selected'] !== '') {
                $list = $this->get_registry_idp_list(false);
                if (is_array($list)) {
                    foreach ($list as $it) {
                        $n = $this->normalize_registry_list_item(is_array($it) ? $it : []);
                        if ($n['entity_id'] === $new_input['spid_saml_idp_registry_selected']) {
                            $new_input['spid_saml_idp_registry_link'] = $n['registry_link'];
                            break;
                        }
                    }
                }
            }
        }

        if (in_array('spid_saml_requested_attributes', $allowed, true)) {
            $allowed_attrs = ['name', 'familyName', 'fiscalNumber', 'email', 'mobilePhone'];
            $attrs_input = isset($input['spid_saml_requested_attributes']) && is_array($input['spid_saml_requested_attributes'])
                ? array_map('sanitize_text_field', wp_unslash($input['spid_saml_requested_attributes']))
                : [];
            $new_input['spid_saml_requested_attributes'] = array_values(array_intersect($allowed_attrs, $attrs_input));
        }

        if (in_array('spid_saml_binding', $allowed, true)) {
            $binding = isset($input['spid_saml_binding']) ? sanitize_key((string) $input['spid_saml_binding']) : 'redirect';
            $new_input['spid_saml_binding'] = in_array($binding, ['redirect', 'post'], true) ? $binding : 'post';
        }

        if (in_array('provider_mode', $allowed, true)) {
            $provider_mode = isset($input['provider_mode']) ? sanitize_key($input['provider_mode']) : 'both';
            $new_input['provider_mode'] = in_array($provider_mode, ['both', 'spid_only', 'cie_only'], true) ? $provider_mode : 'both';
        }

        if (in_array('discovery_mode', $allowed, true)) {
            $discovery_mode = isset($input['discovery_mode']) ? sanitize_key($input['discovery_mode']) : 'auto';
            $new_input['discovery_mode'] = in_array($discovery_mode, ['auto', 'manual'], true) ? $discovery_mode : 'auto';
        }

        if (in_array('min_loa', $allowed, true)) {
            $loa = isset($input['min_loa']) ? sanitize_text_field($input['min_loa']) : 'SpidL2';
            $new_input['min_loa'] = in_array($loa, ['SpidL1', 'SpidL2', 'SpidL3'], true) ? $loa : 'SpidL2';
        }

        if (in_array('user_default_role', $allowed, true)) {
            $role = isset($input['user_default_role']) ? sanitize_key($input['user_default_role']) : get_option('default_role', 'subscriber');
            $new_input['user_default_role'] = get_role($role) ? $role : get_option('default_role', 'subscriber');
        }

        if (isset($new_input['spid_saml_idp_cert']) && empty($new_input['spid_saml_idp_x509_cert'])) {
            $new_input['spid_saml_idp_x509_cert'] = $new_input['spid_saml_idp_cert'];
        }

        if ($current_tab === 'spid_saml') {
            $new_input = $this->sync_registry_selected_idp($new_input, false);
        }

        return $new_input;
    }
}
