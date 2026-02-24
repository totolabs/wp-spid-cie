<?php

/**
 * La funzionalità specifica dell'area pubblica del plugin.
 *
 * @package    WP_SPID_CIE_OIDC
 * @subpackage WP_SPID_CIE_OIDC/public
 */
class WP_SPID_CIE_OIDC_Public {

    private $plugin_name;
    private $version;

    public function __construct( $plugin_name, $version ) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        add_shortcode('spid_cie_login', array($this, 'render_login_buttons'));
        add_action( 'login_form', array( $this, 'print_login_buttons_on_login_page' ) );
        add_action( 'login_message', array( $this, 'print_login_buttons_on_login_page' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_styles' ) );
        add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_styles' ) );
        add_action( 'init', array( $this, 'setup_federation_endpoints' ) );
        add_action( 'template_redirect', array( $this, 'serve_federation_endpoints' ) );
        add_action( 'template_redirect', array( $this, 'handle_login_flow' ) );
		add_filter('redirect_canonical', array($this, 'disable_canonical_for_federation'), 10, 2);
    }

    public function enqueue_styles() {
        $public_style_deps = array();

        if ($this->should_enqueue_spid_saml_access_button()) {
            wp_enqueue_style(
                $this->plugin_name . '-spid-access-button',
                plugin_dir_url(__FILE__) . 'vendor/spid-access-button/css/spid-sp-access-button.min.css',
                array(),
                $this->version,
                'all'
            );
            $public_style_deps[] = $this->plugin_name . '-spid-access-button';

            wp_enqueue_script(
                $this->plugin_name . '-spid-access-button',
                plugin_dir_url(__FILE__) . 'vendor/spid-access-button/js/spid-sp-access-button.min.js',
                array('jquery'),
                $this->version,
                true
            );
        }

        wp_enqueue_style(
            $this->plugin_name,
            plugin_dir_url( __FILE__ ) . 'css/wp-spid-cie-public.css',
            $public_style_deps,
            $this->version,
            'all'
        );

        wp_register_script($this->plugin_name . '-dropdown-inline', '', array(), $this->version, true);
        wp_enqueue_script($this->plugin_name . '-dropdown-inline');
        wp_add_inline_script($this->plugin_name . '-dropdown-inline', 'window.toggleSpidDropdown=window.toggleSpidDropdown||function(){var d=document.getElementById("spid-dropdown");if(!d)return;d.classList.toggle("visible");};document.addEventListener("click",function(e){var w=document.querySelector(".spid-button-wrapper");var d=document.getElementById("spid-dropdown");if(w&&d&&!w.contains(e.target)){d.classList.remove("visible");}});');
    }

    private function should_enqueue_spid_saml_access_button(): bool {
        $options = get_option($this->plugin_name . '_options', []);
        if (!is_array($options)) {
            $options = [];
        }

        $spid_enabled = !empty($options['spid_enabled']) && $options['spid_enabled'] === '1';
        $spid_saml_enabled = !empty($options['spid_saml_enabled']) && $options['spid_saml_enabled'] === '1';
        $spid_method = isset($options['spid_auth_method']) ? sanitize_key((string) $options['spid_auth_method']) : ($spid_saml_enabled ? 'saml' : 'oidc');

        if ($spid_enabled && $spid_saml_enabled && $spid_method === 'saml') {
            return true;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        return $request_uri !== '' && strpos($request_uri, 'wp-login.php') !== false;
    }

    public function setup_federation_endpoints() {
		add_rewrite_rule('^spid/saml/metadata/?$',              'index.php?spid_saml_route=metadata', 'top');
		add_rewrite_rule('^spid/saml/login/?$',                 'index.php?spid_saml_route=login',    'top');
		add_rewrite_rule('^spid/saml/acs/?$',                   'index.php?spid_saml_route=acs',      'top');
		add_rewrite_rule('^spid/saml/sls/?$',                   'index.php?spid_saml_route=sls',      'top');
		add_rewrite_rule('^\.well-known/openid-federation/?$', 'index.php?oidc_federation=config', 'top');
		add_rewrite_rule('^\.wellknown/openid-federation/?$',   'index.php?oidc_federation=config', 'top'); // alias (senza "-")
		add_rewrite_rule('^jwks.json/?$',                       'index.php?oidc_federation=jwks',   'top');
		add_rewrite_rule('^resolve/?$',                         'index.php?oidc_federation=resolve','top');

        add_filter( 'query_vars', function( $vars ) {
            $vars[] = 'oidc_federation';
            $vars[] = 'spid_saml_route';
            $vars[] = 'oidc_action';
            $vars[] = 'provider';
            $vars[] = 'idp';
            return $vars;
        });
    }
	
	public function disable_canonical_for_federation($redirect_url, $requested_url) {
			if (strpos($requested_url, '/spid/saml/metadata') !== false) return false;
			if (strpos($requested_url, '/spid/saml/login') !== false) return false;
			if (strpos($requested_url, '/spid/saml/acs') !== false) return false;
			if (strpos($requested_url, '/spid/saml/sls') !== false) return false;
			if (strpos($requested_url, '/.well-known/openid-federation') !== false) return false;
			if (strpos($requested_url, '/.wellknown/openid-federation') !== false) return false;
			if (strpos($requested_url, '/jwks.json') !== false) return false;
			if (strpos($requested_url, '/resolve') !== false) return false;
			return $redirect_url;
	}	

    public function serve_federation_endpoints() {
		global $wp_query;

		$saml_route = $wp_query->get('spid_saml_route');
		if (!is_string($saml_route) || $saml_route === '') {
			$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
			$path = '/' . ltrim((string) $path, '/');
			if ($path === '/spid/saml/metadata') {
				$saml_route = 'metadata';
			} elseif ($path === '/spid/saml/login') {
				$saml_route = 'login';
			} elseif ($path === '/spid/saml/acs') {
				$saml_route = 'acs';
			} elseif ($path === '/spid/saml/sls') {
				$saml_route = 'sls';
			}
		}

		if (is_string($saml_route) && in_array($saml_route, ['metadata', 'login', 'acs', 'sls'], true)) {
			$this->serve_spid_saml_route($saml_route);
		}

		$action = $wp_query->get('oidc_federation');
		if ( ! $action ) {
			$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
			$path = '/' . ltrim((string) $path, '/');
			if ($path === '/.well-known/openid-federation' || $path === '/.wellknown/openid-federation') {
				$action = 'config';
			} elseif ($path === '/jwks.json') {
				$action = 'jwks';
			} elseif ($path === '/resolve') {
				$action = 'resolve';
			} else {
				return;
			}
		}

		// Per questi endpoint l'output deve essere "pulito":
		// niente Notice/Deprecated/HTML che romperebbero JWT/JSON
		@ini_set('display_errors', '0');
		@ini_set('log_errors', '1');
		error_reporting(0);

		// Svuota qualsiasi buffer già aperto (tema/plugin)
		while (ob_get_level() > 0) {
			@ob_end_clean();
		}

		// Log hits (senza dipendere dal Factory)
		$uploads = wp_upload_dir();
		$keyDir  = trailingslashit($uploads['basedir']) . 'spid-cie-oidc-keys';
		if ( ! is_dir($keyDir) ) {
			@wp_mkdir_p($keyDir);
		}
		@file_put_contents(
			$keyDir . '/hits.log',
			'[' . gmdate('c') . '] action=' . $action . ' host=' . ($_SERVER['HTTP_HOST'] ?? '') . ' uri=' . ($_SERVER['REQUEST_URI'] ?? '') . "\n",
			FILE_APPEND
		);

		if ( ! class_exists('WP_SPID_CIE_OIDC_Factory') ) {
			require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-spid-cie-factory.php';
		}

		try {
			$client = WP_SPID_CIE_OIDC_Factory::get_client();
			$entity_id = method_exists($client, 'getEntityId') ? (string) $client->getEntityId() : '';
			$remote_ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
			$user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
			@error_log('[wp-spid-cie federation] action=' . $action . ' path=' . ($_SERVER['REQUEST_URI'] ?? '') . ' ip=' . $remote_ip . ' ua=' . $user_agent . ' entity_id=' . $entity_id);

			nocache_headers();
			status_header(200);

			// evita che venga trattato come download
			header_remove('Content-Disposition');
			header('Content-Disposition: inline');
			header('X-Content-Type-Options: nosniff');
			if (defined('WP_DEBUG') && WP_DEBUG && !empty($entity_id)) {
				header('X-SPIDCIE-Entity-ID: ' . $entity_id);
			}

			if ( $action === 'config' ) {
				$jws = $client->getEntityStatement();
				$payload = $this->extract_jwt_payload((string) $jws);
				if (is_array($payload)) {
					@error_log('[wp-spid-cie federation] entity-config iss=' . ($payload['iss'] ?? '') . ' sub=' . ($payload['sub'] ?? '') . ' client_id=' . ($payload['metadata']['openid_relying_party']['client_id'] ?? ''));
				}

				$debug_mode = isset($_GET['debug']) && $_GET['debug'] === '1';
				if ($debug_mode && defined('WP_DEBUG') && WP_DEBUG && current_user_can('manage_options')) {
					header('Content-Type: application/json; charset=utf-8');
					echo wp_json_encode([
						'entity_id_configured' => $entity_id,
						'iss' => is_array($payload) ? ($payload['iss'] ?? '') : '',
						'sub' => is_array($payload) ? ($payload['sub'] ?? '') : '',
						'client_id' => is_array($payload) ? ($payload['metadata']['openid_relying_party']['client_id'] ?? '') : '',
						'metadata_url' => home_url('/.well-known/openid-federation'),
						'resolve_url' => home_url('/resolve'),
						'note' => 'Debug enabled via ?debug=1 (WP_DEBUG + admin only)'
					], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
					exit;
				}

				header('Content-Type: application/entity-statement+jwt');
				echo trim(is_string($jws) ? $jws : (string) $jws);
				exit;
			}

			if ( $action === 'jwks' ) {
				$jwks = $client->getJwks();

				header('Content-Type: application/jwk-set+json; charset=utf-8');

				// se getJwks ritorna array, lo serializziamo in JSON
				if (is_array($jwks) || is_object($jwks)) {
					echo wp_json_encode($jwks);
				} else {
					echo (string) $jwks;
				}
				exit;
			}

			if ( $action === 'resolve' ) {
				$sub = isset($_GET['sub']) ? esc_url_raw(wp_unslash($_GET['sub'])) : '';
				$trust_anchor = isset($_GET['trust_anchor']) ? esc_url_raw(wp_unslash($_GET['trust_anchor'])) : '';
				$jws = $client->getResolveResponse($sub, $trust_anchor);

				header('Content-Type: application/resolve-response+jwt');
				echo trim(is_string($jws) ? $jws : (string) $jws);
				exit;
			}

			// azione non supportata
			status_header(404);
			header('Content-Type: text/plain; charset=utf-8');
			echo 'Not found';
			exit;

		} catch (Exception $e) {
			status_header(500);
			header('Content-Type: text/plain; charset=utf-8');
			echo 'Errore OIDC Federation: ' . $e->getMessage();
			exit;
		}
	}

	private function serve_spid_saml_route(string $route): void {
		$options = get_option($this->plugin_name . '_options', []);
		$spid_enabled = !empty($options['spid_enabled']) && $options['spid_enabled'] === '1';
		$spid_saml_enabled = !empty($options['spid_saml_enabled']) && $options['spid_saml_enabled'] === '1';
		$spid_auth_method = isset($options['spid_auth_method']) ? sanitize_key((string) $options['spid_auth_method']) : ($spid_saml_enabled ? 'saml' : 'oidc');
		$enabled = $spid_enabled && $spid_saml_enabled && $spid_auth_method === 'saml';
		$debug_enabled = !empty($options['spid_saml_debug']) && $options['spid_saml_debug'] === '1';

		if (!$enabled && $route !== 'metadata') {
			status_header(404);
			header('Content-Type: text/plain; charset=utf-8');
			echo 'Not found';
			exit;
		}

		$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'GET';
		$content_length = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		if ($content_length > 700000) {
			status_header(413);
			header('Content-Type: text/plain; charset=utf-8');
			echo 'Payload Too Large';
			exit;
		}

		if ($debug_enabled) {
			@error_log('[wp-spid-cie saml] route=' . $route . ' method=' . $method . ' content_length=' . $content_length);
		}

		nocache_headers();
		header('X-Content-Type-Options: nosniff');
		if ($debug_enabled && defined('WP_DEBUG') && WP_DEBUG) {
			header('X-SPIDCIE-SAML-Route: ' . $route);
			header('X-SPIDCIE-SAML-Method: ' . $method);
			header('X-SPIDCIE-SPID-SAML-DIAG: route=' . $route . ';status=ok');
		}

		if ($route === 'metadata') {
			if ($method !== 'GET') {
				status_header(405);
				header('Allow: GET');
				header('Content-Type: text/plain; charset=utf-8');
				echo 'Method Not Allowed';
				exit;
			}
			$this->serve_spid_saml_metadata($options);
		}

		if ($route === 'login') {
			if ($method !== 'GET') {
				status_header(405);
				header('Allow: GET');
				echo 'Method Not Allowed';
				exit;
			}
			$this->serve_spid_saml_login($options, $debug_enabled);
		}

		if ($route === 'acs') {
			if ($method !== 'POST') {
				status_header(405);
				header('Allow: POST');
				header('Content-Type: text/plain; charset=utf-8');
				echo 'Method Not Allowed';
				exit;
			}
			$this->serve_spid_saml_acs($options, $debug_enabled);
		}

		if ($route === 'sls') {
			if (!in_array($method, ['GET', 'POST'], true)) {
				status_header(405);
				header('Allow: GET, POST');
				header('Content-Type: text/plain; charset=utf-8');
				echo 'Method Not Allowed';
				exit;
			}
			$this->serve_spid_saml_sls($options, $debug_enabled);
		}

		status_header(404);
		header('Content-Type: text/plain; charset=utf-8');
		echo 'Not found';
		exit;
	}

	private function serve_spid_saml_metadata(array $options): void {
		$expected_token = isset($options['spid_saml_metadata_token']) ? (string) $options['spid_saml_metadata_token'] : '';
		$provided_token = isset($_GET['spid_metadata_token']) ? sanitize_text_field((string) wp_unslash($_GET['spid_metadata_token'])) : '';
		if ($expected_token !== '' && ($provided_token === '' || !hash_equals($expected_token, $provided_token))) {
			status_header(403);
			header('Content-Type: text/plain; charset=utf-8');
			echo 'Forbidden';
			exit;
		}

		$svc = $this->get_saml_service();
		$sp = $svc->build_sp_config($options);

		$acs_url = $sp['acs_url'];
		$sls_url = $sp['sls_url'];
		$entity_id = $sp['entity_id'];
		$organization_name = isset($options['organization_name']) ? sanitize_text_field((string) $options['organization_name']) : get_bloginfo('name');
		$contacts_email = isset($options['contacts_email']) ? sanitize_email((string) $options['contacts_email']) : get_option('admin_email');
		$ipa_code = isset($options['ipa_code']) ? sanitize_text_field((string) $options['ipa_code']) : '';
		$fiscal_number = isset($options['fiscal_number']) ? sanitize_text_field((string) $options['fiscal_number']) : '';
		$cert = $this->get_saml_signing_cert();
		$authn_requests_signed = $cert !== '' ? 'true' : 'false';

		status_header(200);
		header('Content-Type: application/samlmetadata+xml; charset=utf-8');

		echo '<?xml version="1.0" encoding="UTF-8"?>' . "
";
		echo '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="' . esc_attr($entity_id) . '">' . "
";
		echo '  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="' . esc_attr($authn_requests_signed) . '" WantAssertionsSigned="true">' . "
";
		if ($cert !== '') {
			echo '    <md:KeyDescriptor use="signing">' . "
";
			echo '      <ds:KeyInfo>' . "
";
			echo '        <ds:X509Data><ds:X509Certificate>' . esc_html($cert) . '</ds:X509Certificate></ds:X509Data>' . "
";
			echo '      </ds:KeyInfo>' . "
";
			echo '    </md:KeyDescriptor>' . "
";
		}
		echo '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>' . "
";
		echo '    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' . esc_url($acs_url) . '" index="0" isDefault="true" />' . "
";
		echo '    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="' . esc_url($sls_url) . '" />' . "
";
		$requested_attributes = $this->get_spid_saml_requested_attributes($options);
		echo '    <md:AttributeConsumingService index="0"><md:ServiceName xml:lang="it">Set base SPID</md:ServiceName>';
		foreach ($requested_attributes as $attr_name) {
			echo '<md:RequestedAttribute Name="' . esc_attr($attr_name) . '" />';
		}
		echo '</md:AttributeConsumingService>' . "
";
		echo '  </md:SPSSODescriptor>' . "
";
		echo '  <md:Organization><md:OrganizationName xml:lang="it">' . esc_html($organization_name) . '</md:OrganizationName><md:OrganizationDisplayName xml:lang="it">' . esc_html($organization_name) . '</md:OrganizationDisplayName><md:OrganizationURL xml:lang="it">' . esc_url(home_url('/')) . '</md:OrganizationURL></md:Organization>' . "
";
		echo '  <md:ContactPerson contactType="other"><md:Extensions>';
		if ($ipa_code !== '') { echo '<spid:IPACode>' . esc_html($ipa_code) . '</spid:IPACode>'; }
		echo '<spid:Public />';
		if ($fiscal_number !== '') { echo '<spid:FiscalCode>' . esc_html($fiscal_number) . '</spid:FiscalCode>'; }
		echo '</md:Extensions>';
		if (is_email($contacts_email)) { echo '<md:EmailAddress>' . esc_html($contacts_email) . '</md:EmailAddress>'; }
		echo '</md:ContactPerson>' . "
";
		echo '</md:EntityDescriptor>';
		exit;
	}

	private function serve_spid_saml_login(array $options, bool $debug_enabled): void {
		$svc = $this->get_saml_service();
		$sp = $svc->build_sp_config($options);
		$idpEntity = isset($_GET['idp']) ? sanitize_text_field((string) wp_unslash($_GET['idp'])) : '';
		$idp = [];
		$resolve_source = 'registry';
		if ($idpEntity !== '') {
			$idp = $this->resolve_registry_idp_config($idpEntity);
		}
		if (empty($idp)) {
			$resolve_source = 'options_fallback';
			$idp = $svc->read_idp_config($options);
		}
		if ($debug_enabled && defined('WP_DEBUG') && WP_DEBUG) {
			@error_log('[wp-spid-cie saml] login_resolve idp=' . sanitize_text_field($idpEntity)
				. ' source=' . $resolve_source
				. ' sso_host=' . $this->saml_debug_url_host((string) ($idp['sso_url'] ?? ''))
				. ' entity=' . sanitize_text_field((string) ($idp['entity_id'] ?? '')));
		}
		if (!$svc->is_idp_config_complete($idp)) {
			if ($debug_enabled && defined('WP_DEBUG') && WP_DEBUG) {
				@error_log('[wp-spid-cie saml] login_resolve_failed idp=' . sanitize_text_field($idpEntity) . ' source=' . $resolve_source);
			}
			$this->redirect_to_login_error('saml_config_incomplete');
		}
		$relay = isset($_GET['redirect_to']) ? (string) wp_unslash($_GET['redirect_to']) : '';
		if (strlen($relay) > 512) {
			$relay = '';
		}
		$relay = $relay !== '' ? $this->sanitize_internal_redirect($relay) : home_url('/');
		$authUrl = $svc->build_authn_request_redirect($sp, $idp, $relay);
		if (is_wp_error($authUrl)) {
			if ($debug_enabled && defined('WP_DEBUG') && WP_DEBUG) {
				@error_log('[wp-spid-cie saml] authn_build_failed code=' . $authUrl->get_error_code());
			}
			$this->redirect_to_login_error($authUrl->get_error_code());
		}
		if ($debug_enabled && defined('WP_DEBUG') && WP_DEBUG) {
			@error_log('[wp-spid-cie saml] authn_redirect target=' . $this->saml_debug_url_host((string) $authUrl));
		}
		wp_redirect($authUrl);
		exit;
	}


	private function serve_spid_saml_acs(array $options, bool $debug_enabled): void {
		if (!class_exists('WP_SPID_CIE_OIDC_Factory')) {
			require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-spid-cie-factory.php';
		}
		$runtime = WP_SPID_CIE_OIDC_Factory::get_runtime_services();
		$logger = $runtime['logger'];
		$authService = $runtime['auth_service'];
		$correlation_id = $logger->generateCorrelationId();
		$samlResponseB64 = isset($_POST['SAMLResponse']) ? (string) wp_unslash($_POST['SAMLResponse']) : '';
		if ($samlResponseB64 === '') { $this->redirect_to_login_error('saml_missing_response'); }
		$svc = $this->get_saml_service();
		$sp = $svc->build_sp_config($options);
		$idp = [];
		$issuer = $svc->extract_response_issuer($samlResponseB64);
		if ($issuer !== '') {
			$idp = $this->resolve_registry_idp_config($issuer);
		}
		if (empty($idp)) {
			$idp = $svc->read_idp_config($options);
		}
		try { $parsed = $svc->parse_and_validate_response($samlResponseB64, $sp, $idp); }
		catch (RuntimeException $e) { $this->redirect_to_login_error(sanitize_key($e->getMessage())); }
		if (is_wp_error($parsed)) {
			$logger->error('SAML ACS response parsing failed', ['correlation_id' => $correlation_id, 'error_code' => $parsed->get_error_code()]);
			$this->redirect_to_login_error($parsed->get_error_code());
		}
		$claims = $parsed['claims'];
		$provider_config = ['provider' => 'spid', 'last_id_token_acr' => isset($claims['acr']) ? (string) $claims['acr'] : ''];
		$pluginOptions = get_option('wp-spid-cie_options', []);
		$pluginOptions['auto_provisioning'] = (!empty($options['user_provisioning_enabled']) && $options['user_provisioning_enabled'] === '1') ? '1' : '0';
		$pluginOptions['default_role'] = isset($options['user_default_role']) ? sanitize_key((string) $options['user_default_role']) : get_option('default_role', 'subscriber');
		$identity = ['provider' => 'spid','sub' => sanitize_text_field((string) ($claims['sub'] ?? '')),'email' => sanitize_email((string) ($claims['email'] ?? '')),'given_name' => sanitize_text_field((string) ($claims['given_name'] ?? '')),'family_name' => sanitize_text_field((string) ($claims['family_name'] ?? '')),'fiscal_code' => strtoupper(sanitize_text_field((string) ($claims['fiscal_code'] ?? ''))),'mobile' => sanitize_text_field((string) ($claims['mobile'] ?? ''))];
		$mandatory = ['given_name', 'family_name', 'fiscal_code', 'email'];
		foreach ($mandatory as $k) {
			if (empty($identity[$k])) {
				$logger->error('SAML mandatory claim missing', ['correlation_id' => $correlation_id, 'missing' => $k]);
				$this->redirect_to_login_error('saml_missing_required_claims');
			}
		}
		if (!is_email($identity['email'])) {
			$logger->error('SAML mandatory claim invalid email', ['correlation_id' => $correlation_id]);
			$this->redirect_to_login_error('saml_invalid_email');
		}
		$user = $authService->resolveOrProvisionUser($identity, $provider_config, $pluginOptions, $correlation_id);
		if (is_wp_error($user)) { $this->redirect_to_login_error($user->get_error_code()); }
		update_user_meta($user->ID, '_spidcie_saml_idp', sanitize_text_field((string) ($claims['issuer'] ?? '')));
		update_user_meta($user->ID, '_spidcie_saml_last_login_ts', time());
		wp_set_current_user($user->ID);
		wp_set_auth_cookie($user->ID, true);
		do_action('wp_login', $user->user_login, $user);
		$target = isset($parsed['request_context']['relay_state']) ? $this->sanitize_internal_redirect((string) $parsed['request_context']['relay_state']) : home_url('/');
		if ($debug_enabled) { $logger->info('SAML ACS login completed', ['correlation_id' => $correlation_id, 'user_id' => $user->ID]); }
		wp_safe_redirect($target);
		exit;
	}

	private function serve_spid_saml_sls(array $options, bool $debug_enabled): void {
		if (is_user_logged_in()) { wp_logout(); }
		$relay = isset($_REQUEST['RelayState']) ? (string) wp_unslash($_REQUEST['RelayState']) : '';
		$target = $relay !== '' ? $this->sanitize_internal_redirect($relay) : home_url('/');
		if ($debug_enabled) { @error_log('[wp-spid-cie saml] sls local logout completed'); }
		wp_safe_redirect($target);
		exit;
	}

	private function get_saml_service(): WP_SPID_CIE_OIDC_Saml_Service {
		if (!class_exists('WP_SPID_CIE_OIDC_Saml_Service')) {
			require_once plugin_dir_path(dirname(__FILE__)) . 'includes/spid-saml-lib/class-wp-spid-cie-saml-service.php';
		}
		return new WP_SPID_CIE_OIDC_Saml_Service();
	}

	private function get_saml_signing_cert(): string {
		$upload_dir = wp_upload_dir();
		$cert_file = trailingslashit($upload_dir['basedir']) . 'spid-cie-oidc-keys/public.crt';
		if (!file_exists($cert_file) || !is_readable($cert_file)) {
			return '';
		}
		$cert = (string) file_get_contents($cert_file);
		if ($cert === '') {
			return '';
		}
		$cert = str_replace(["
", "
", '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $cert);
		return trim($cert);
	}

private function extract_jwt_payload($jwt) {
        $parts = explode('.', trim((string) $jwt));
        if (count($parts) < 2) {
            return null;
        }

        $payload_b64 = strtr($parts[1], '-_', '+/');
        $payload_b64 .= str_repeat('=', (4 - strlen($payload_b64) % 4) % 4);
        $json = base64_decode($payload_b64, true);
        if ($json === false) {
            return null;
        }

        $payload = json_decode($json, true);
        return is_array($payload) ? $payload : null;
    }

    public function handle_login_flow() {
        $action = isset($_GET['oidc_action']) ? sanitize_key(wp_unslash($_GET['oidc_action'])) : get_query_var('oidc_action');
        $provider = isset($_GET['provider']) ? sanitize_key(wp_unslash($_GET['provider'])) : get_query_var('provider');
        $idp = isset($_GET['idp']) ? sanitize_key(wp_unslash($_GET['idp'])) : get_query_var('idp');

        if (!in_array($action, ['login', 'callback'], true) || !in_array($provider, ['spid', 'cie'], true)) {
            return;
        }

        if (!class_exists('WP_SPID_CIE_OIDC_Factory')) {
            require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-spid-cie-factory.php';
        }

        $runtime = WP_SPID_CIE_OIDC_Factory::get_runtime_services();
        /** @var WP_SPID_CIE_OIDC_Logger $logger */
        $logger = $runtime['logger'];
        /** @var WP_SPID_CIE_OIDC_OidcClient $oidc */
        $oidc = $runtime['oidc_client'];
        /** @var WP_SPID_CIE_OIDC_WpUserMapper $userMapper */
        $userMapper = $runtime['user_mapper'];
        /** @var WP_SPID_CIE_OIDC_WpAuthService $authService */
        $authService = $runtime['auth_service'];
        $correlation_id = $logger->generateCorrelationId();

        $registry = WP_SPID_CIE_OIDC_Factory::get_provider_registry();
        $provider_config = $registry->resolveConfig($provider, $idp);
        if (is_wp_error($provider_config)) {
            $logger->error('OIDC provider config resolution failed', [
                'correlation_id' => $correlation_id,
                'provider' => $provider,
                'error_code' => $provider_config->get_error_code(),
            ]);
            $this->redirect_to_login_error($provider_config->get_error_code());
        }

        if ($action === 'login') {
            $target_url = $this->resolve_redirect_target();
            $auth_url = $oidc->buildAuthorizationUrl($provider_config, $target_url, $correlation_id);
            if (is_wp_error($auth_url)) {
                $logger->error('OIDC start login failed', [
                    'correlation_id' => $correlation_id,
                    'provider' => $provider,
                    'error_code' => $auth_url->get_error_code(),
                ]);
                $this->redirect_to_login_error('oidc_start_failed');
            }

            $logger->info('OIDC start login redirect', [
                'correlation_id' => $correlation_id,
                'provider' => $provider,
                'idp' => $idp,
            ]);

            wp_safe_redirect($auth_url);
            exit;
        }

        $request = [
            'state' => $_REQUEST['state'] ?? '',
            'code' => $_REQUEST['code'] ?? '',
            'error' => $_REQUEST['error'] ?? '',
            'correlation_id' => $correlation_id,
        ];

        $result = $oidc->handleCallback($request, $provider_config);
        if (is_wp_error($result)) {
            $logger->error('OIDC callback failed', [
                'correlation_id' => $correlation_id,
                'provider' => $provider,
                'error_code' => $result->get_error_code(),
            ]);
            $this->redirect_to_login_error($result->get_error_code());
        }

        $claims = $result['claims'];
        $state_context = $result['state_context'];

        $normalized = $userMapper->normalizeClaims($claims, $provider);
        $valid = $userMapper->validateMandatoryClaims($normalized, $correlation_id);
        if (is_wp_error($valid)) {
            $this->redirect_to_login_error($valid->get_error_code());
        }

        $provider_config['last_id_token_acr'] = isset($claims['acr']) ? (string) $claims['acr'] : '';
        $pluginOptions = get_option('wp-spid-cie_options', []);
        $pluginOptions['auto_provisioning'] = (!empty($pluginOptions['user_provisioning_enabled']) && $pluginOptions['user_provisioning_enabled'] === '1') ? '1' : '0';
        $pluginOptions['default_role'] = isset($pluginOptions['user_default_role']) ? sanitize_key((string) $pluginOptions['user_default_role']) : get_option('default_role', 'subscriber');
        $user = $authService->resolveOrProvisionUser($normalized, $provider_config, $pluginOptions, $correlation_id);

        if (is_wp_error($user)) {
            $logger->error('OIDC WP user resolve failed', [
                'correlation_id' => $correlation_id,
                'error_code' => $user->get_error_code(),
            ]);
            $this->redirect_to_login_error($user->get_error_code());
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);

        $target = isset($state_context['target_url']) ? $state_context['target_url'] : home_url('/');
        $target = $this->sanitize_internal_redirect($target);

        $logger->info('OIDC login completed', [
            'correlation_id' => $correlation_id,
            'provider' => $provider,
            'user_id' => $user->ID,
        ]);

        wp_safe_redirect($target);
        exit;
    }

    private function resolve_redirect_target(): string {
        $raw = isset($_GET['redirect_to']) ? wp_unslash($_GET['redirect_to']) : '';
        if (empty($raw)) {
            return home_url('/');
        }

        return $this->sanitize_internal_redirect($raw);
    }

    private function sanitize_internal_redirect(string $url): string {
        $default = home_url('/');
        $safe = wp_validate_redirect($url, $default);
        $homeHost = wp_parse_url(home_url(), PHP_URL_HOST);
        $targetHost = wp_parse_url($safe, PHP_URL_HOST);

        if ($targetHost && $homeHost && strtolower($targetHost) !== strtolower($homeHost)) {
            return $default;
        }

        return $safe;
    }

    private function redirect_to_login_error(string $code): void {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            header('X-SPIDCIE-SPID-SAML-DIAG: status=error;code=' . sanitize_key($code));
        }

        $url = add_query_arg([
            'login' => 'failed',
            'spid_cie_error' => sanitize_key($code),
        ], wp_login_url());

        wp_safe_redirect($url);
        exit;
    }


    private function resolve_login_entry_url(): string {
        if (function_exists('wp_login_url') && did_action('login_init')) {
            return wp_login_url();
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        if ($request_uri !== '') {
            $candidate = home_url($request_uri);
            return $this->sanitize_internal_redirect($candidate);
        }

        return home_url('/');
    }

    private static $buttons_printed = false;

    public function print_login_buttons_on_login_page($arg = null) {
        if (self::$buttons_printed) return $arg;
        if (is_string($arg) && !empty($arg)) echo $arg;

        if (!empty($_GET['spid_cie_error'])) {
            $code = sanitize_key(wp_unslash($_GET['spid_cie_error']));
            echo '<p class="message" style="border-left-color:#d63638;">' . esc_html__('Autenticazione SPID/CIE non completata. Riprova.', 'wp-spid-cie') . ' (' . esc_html($code) . ')</p>';
        }

        echo $this->render_login_buttons();
        self::$buttons_printed = true;
        return null;
    }

    public function render_login_buttons() {
        $options = get_option( $this->plugin_name . '_options' ); 
        
        $spid_enabled = isset($options['spid_enabled']) && $options['spid_enabled'] === '1';
        $cie_enabled = isset($options['cie_enabled']) && $options['cie_enabled'] === '1';
        $provider_mode = $options['provider_mode'] ?? 'both';
        if ($provider_mode === 'spid_only') {
            $cie_enabled = false;
        } elseif ($provider_mode === 'cie_only') {
            $spid_enabled = false;
        }
        $spid_saml_enabled = isset($options['spid_saml_enabled']) && $options['spid_saml_enabled'] === '1';
        $spid_method = isset($options['spid_auth_method']) ? sanitize_key((string) $options['spid_auth_method']) : ($spid_saml_enabled ? 'saml' : 'oidc');
        if (!in_array($spid_method, ['saml', 'oidc'], true)) {
            $spid_method = 'oidc';
        }
        $spid_visible = $spid_enabled;
        $show_spid_oidc = $spid_visible && $spid_method === 'oidc';
        $show_spid_saml = $spid_visible && $spid_method === 'saml' && $spid_saml_enabled;
        $saml_login_url = add_query_arg(['spid_saml_route' => 'login'], home_url('/'));
        
        // Gestione Disclaimer
        $disclaimer_enabled = isset($options['disclaimer_enabled']) && $options['disclaimer_enabled'] === '1';
        $disclaimer_text = !empty($options['disclaimer_text']) ? $options['disclaimer_text'] : '';

        if (!$show_spid_oidc && !$show_spid_saml && !$cie_enabled) {
            return '';
        }

        $base_url = $this->resolve_login_entry_url();
        $login_url_cie = add_query_arg(['oidc_action' => 'login', 'provider' => 'cie'], $base_url);

        if (!class_exists('WP_SPID_CIE_OIDC_Factory')) {
            require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-spid-cie-factory.php';
        }
        $client = WP_SPID_CIE_OIDC_Factory::get_client();
        $spid_idps = $client->getSpidProviders();

        $keys = array_keys($spid_idps);
        shuffle($keys);
        $shuffled_idps = [];
        foreach ($keys as $key) {
            $shuffled_idps[$key] = $spid_idps[$key];
        }

        $assets_url = plugin_dir_url(__FILE__) . 'img/';

        ob_start();
        ?>
        <div class="spid-cie-container">
            
            <?php if ($disclaimer_enabled && !empty($disclaimer_text)): ?>
            <div style="background-color: #fff8e5; border: 1px solid #faebcc; color: #8a6d3b; padding: 10px; margin-bottom: 15px; font-size: 13px; border-radius: 4px; line-height: 1.4; text-align: left;">
                <?php echo wp_kses_post($disclaimer_text); ?>
            </div>
            <?php endif; ?>

            <span class="spid-cie-title">Accedi con Identità Digitale</span>
            
            <?php if ($show_spid_oidc): ?>
                <div class="spid-button-wrapper">
                    <a href="javascript:void(0)" onclick="toggleSpidDropdown()" class="spid-cie-button spid-button">
                        Entra con SPID
                    </a>
                    <ul id="spid-dropdown">
                        <?php foreach($shuffled_idps as $key => $idp): ?>
                            <?php 
                                $url = add_query_arg(['oidc_action' => 'login', 'provider' => 'spid', 'idp' => $key], $base_url);
                                $logo_src = $assets_url . $idp['logo']; 
                            ?>
                            <li class="spid-idp-item">
                                <a href="<?php echo esc_url($url); ?>" class="spid-idp-link">
                                    <?php if(!empty($idp['logo'])): ?>
                                        <img src="<?php echo esc_url($logo_src); ?>" alt="<?php echo esc_attr($idp['name']); ?>" class="spid-idp-icon">
                                    <?php endif; ?>
                                    <span class="spid-idp-label"><?php echo esc_html($idp['name']); ?></span>
                                </a>

                            </li>
                        <?php endforeach; ?>
                        <li class="spid-dropdown-footer">
                            <a href="https://www.spid.gov.it/cos-e-spid/come-attivare-spid/" target="_blank">Non hai SPID?</a>
                            &nbsp;|&nbsp; 
                            <a href="https://www.spid.gov.it/" target="_blank">Maggiori info</a>
                        </li>
                    </ul>
                </div>
            <?php endif; ?>


            <?php if ($show_spid_saml): ?>
                <?php
                    $saml_idps = $this->get_spid_registry_idps();
                    if (is_array($saml_idps)) {
                        foreach ($saml_idps as &$idp_item) {
                            if (!is_array($idp_item)) {
                                continue;
                            }
                            $entity = isset($idp_item['entity_id']) ? (string) $idp_item['entity_id'] : '';
                            $name = isset($idp_item['name']) ? (string) $idp_item['name'] : '';
                            $idp_item['logo_local'] = $this->get_spid_idp_logo_by_entity($entity, isset($idp_item['logo']) ? (string) $idp_item['logo'] : '');
                        }
                        unset($idp_item);

                        shuffle($saml_idps);
                    }
                    $spid_menu_id = 'spid-idp-button-medium-get-' . uniqid();
                ?>
                <div class="spid-button-wrapper">
                    <button class="spid-cie-button spid-button" type="button" spid-idp-button="#<?php echo esc_attr($spid_menu_id); ?>">
                        Entra con SPID
                    </button>
                    <div id="<?php echo esc_attr($spid_menu_id); ?>" class="spid-idp-button spid-idp-button-tip spid-idp-button-relative">
                        <ul class="spid-idp-button-menu">
                            <?php if (is_wp_error($saml_idps) || empty($saml_idps)): ?>
                                <li><span class="idp-button-idp-logo">Elenco IdP non disponibile, riprovare più tardi.</span></li>
                            <?php else: ?>
                                <?php foreach($saml_idps as $idp): ?>
                                    <?php
                                        $entity_id = isset($idp['entity_id']) ? (string) $idp['entity_id'] : '';
                                        if ($entity_id === '') { continue; }
                                        $label = isset($idp['name']) && trim((string) $idp['name']) !== '' ? (string) $idp['name'] : $entity_id;
                                        $logo = isset($idp['logo_local']) ? esc_url((string) $idp['logo_local']) : '';
                                        if ($logo === '' && isset($idp['logo']) && (string) $idp['logo'] !== '') {
                                            $logo = esc_url((string) $idp['logo']);
                                        }
                                        $url = add_query_arg(['idp' => $entity_id], $saml_login_url);
                                    ?>
                                    <?php if ($logo !== ''): ?>
                                        <li><a class="idp-button-idp-logo" href="<?php echo esc_url($url); ?>"><img src="<?php echo $logo; ?>" alt="<?php echo esc_attr($label); ?>" /></a></li>
                                    <?php else: ?>
                                        <li><a class="idp-button-idp-logo" href="<?php echo esc_url($url); ?>"><span class="spid-idp-label"><?php echo esc_html($label); ?></span></a></li>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </ul>
                        <div class="spid-idp-button-support">
                            <a class="spid-idp-support-link" href="https://www.spid.gov.it/" target="_blank" rel="noopener noreferrer">Maggiori informazioni</a>
                            <a class="spid-idp-support-link" href="https://www.spid.gov.it/cos-e-spid/come-attivare-spid/" target="_blank" rel="noopener noreferrer">Non hai SPID?</a>
                            <a class="spid-idp-support-link" href="https://helpdesk.spid.gov.it/" target="_blank" rel="noopener noreferrer">Serve aiuto?</a>
                            <?php if (!empty($options['spid_saml_validator_enabled']) && $options['spid_saml_validator_enabled'] === '1'): ?>
                                <?php $validator_url = add_query_arg(['idp' => 'https://validator.spid.gov.it'], $saml_login_url); ?>
                                <a class="spid-idp-support-link spid-validator-link" href="<?php echo esc_url($validator_url); ?>">SPID Validator</a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($cie_enabled): ?>
                <a href="<?php echo esc_url($login_url_cie); ?>" class="spid-cie-button cie-button">
                    Entra con CIE
                </a>
            <?php endif; ?>
        </div>
        <?php
        return ob_get_clean();
    }

    private function get_registry_service() {
        if (!class_exists('WP_SPID_CIE_OIDC_Spid_Registry_Service')) {
            require_once plugin_dir_path(dirname(__FILE__)) . 'includes/class-wp-spid-cie-spid-registry-service.php';
        }
        return new WP_SPID_CIE_OIDC_Spid_Registry_Service();
    }

    private function get_spid_registry_idps() {
        return $this->get_registry_service()->get_idp_list(false);
    }

    private function resolve_registry_idp_config(string $entityId): array {
        if ($entityId === 'https://validator.spid.gov.it') {
            return [
                'entity_id' => 'https://validator.spid.gov.it',
                'sso_url' => 'https://validator.spid.gov.it/samlsso',
                'slo_url' => 'https://validator.spid.gov.it/samlsso',
                'x509_cert' => $this->get_spid_saml_validator_cert(),
                'alias' => 'validator',
            ];
        }

        $list = $this->get_registry_service()->get_idp_list(false);
        $link = '';
        if (is_array($list)) {
            foreach ($list as $item) {
                if (!is_array($item)) { continue; }
                if ((string) ($item['entity_id'] ?? '') === $entityId) {
                    $link = (string) ($item['registry_link'] ?? '');
                    break;
                }
            }
        }
        $detail = $this->get_registry_service()->get_idp_detail($entityId, $link, false);
        if (is_wp_error($detail) || !is_array($detail)) {
            return [];
        }
        return [
            'entity_id' => (string) ($detail['entity_id'] ?? ''),
            'sso_url' => (string) ($detail['sso_url'] ?? ''),
            'slo_url' => (string) ($detail['slo_url'] ?? ''),
            'x509_cert' => (string) ($detail['x509_cert'] ?? ''),
            'alias' => 'registry',
        ];
    }


    private function get_spid_saml_requested_attributes(array $options): array {
        $allowed = ['name', 'familyName', 'fiscalNumber', 'email', 'mobilePhone'];
        $default = ['name', 'familyName', 'fiscalNumber', 'email'];
        $attrs = isset($options['spid_saml_requested_attributes']) && is_array($options['spid_saml_requested_attributes'])
            ? array_values(array_intersect($allowed, array_map('strval', $options['spid_saml_requested_attributes'])))
            : $default;

        return !empty($attrs) ? $attrs : $default;
    }

    private function get_spid_idp_logo_by_entity(string $entityId, string $logo_uri = ''): string {
        $entity = trim($entityId);
        $base = plugin_dir_url(__FILE__) . 'vendor/spid-access-button/img/';

        $map_exact = [
            'https://loginspid.aruba.it' => 'spid-idp-arubaid.svg',
            'https://id.eht.eu' => 'spid-idp-etnaid.svg',
            'https://id.infocamere.it' => 'spid-idp-infocamereid.svg',
            'https://identity.infocert.it' => 'spid-idp-infocertid.svg',
            'https://idp.intesigroup.com' => 'spid-idp-intesigroupspid.svg',
            'https://id.lepida.it/idp/shibboleth' => 'spid-idp-lepidaid.svg',
            'https://idp.namirialtsp.com/idp' => 'spid-idp-namirialid.svg',
            'https://posteid.poste.it' => 'spid-idp-posteid.svg',
            'https://identity.sieltecloud.it' => 'spid-idp-sielteid.svg',
            'https://identity.register.it' => 'spid-idp-spiditalia.svg',
            'https://spid-idp.team.systems' => 'spid-idp-teamsystemid.svg',
            'https://login.id.tim.it/affwebservices/public/saml2sso' => 'spid-idp-timid.svg',
        ];

        if (isset($map_exact[$entity])) {
            return $base . $map_exact[$entity];
        }

        $host = strtolower((string) wp_parse_url($entity, PHP_URL_HOST));
        $map_host = [
            'aruba' => 'spid-idp-arubaid.svg',
            'eht.eu' => 'spid-idp-etnaid.svg',
            'infocamere' => 'spid-idp-infocamereid.svg',
            'infocert' => 'spid-idp-infocertid.svg',
            'intesigroup' => 'spid-idp-intesigroupspid.svg',
            'lepida' => 'spid-idp-lepidaid.svg',
            'namirial' => 'spid-idp-namirialid.svg',
            'poste' => 'spid-idp-posteid.svg',
            'sielte' => 'spid-idp-sielteid.svg',
            'register.it' => 'spid-idp-spiditalia.svg',
            'team' => 'spid-idp-teamsystemid.svg',
            'tim.it' => 'spid-idp-timid.svg',
        ];
        foreach ($map_host as $needle => $file) {
            if ($host !== '' && strpos($host, $needle) !== false) {
                return $base . $file;
            }
        }

        $logo_uri = trim($logo_uri);
        if ($logo_uri !== '') {
            return esc_url($logo_uri);
        }

        return '';
    }

    private function get_spid_saml_validator_cert(): string {
        return trim((string) apply_filters('wp_spid_cie_validator_x509_cert', 'MIIEATCCAumgAwIBAgIUKnIX6ljIqVPkFQ8hJVj8KAYegBIwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAklUMQ0wCwYDVQQIDARSb21lMQ0wCwYDVQQHDARSb21lMQ0wCwYDVQQKDARBZ0lEMQ0wCwYDVQQLDARBZ0lEMR4wHAYDVQQDDBV2YWxpZGF0b3Iuc3BpZC5nb3YuaXQxJDAiBgkqhkiG9w0BCQEWFXNwaWQudGVjaEBhZ2lkLmdvdi5pdDAeFw0yMzEwMTgwNjI1MjVaFw0yNTEwMTcwNjI1MjVaMIGPMQswCQYDVQQGEwJJVDENMAsGA1UECAwEUm9tZTENMAsGA1UEBwwEUm9tZTENMAsGA1UECgwEQWdJRDENMAsGA1UECwwEQWdJRDEeMBwGA1UEAwwVdmFsaWRhdG9yLnNwaWQuZ292Lml0MSQwIgYJKoZIhvcNAQkBFhVzcGlkLnRlY2hAYWdpZC5nb3YuaXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrvNDIgz4davA/fTJEc10f6yptnLojSspzXgP61EAg4REGmwfhbEP8+2v5pN4mVeCdL3saFUiFbn3LZRDbHAwKkoE6Uzi+mD7cPGqj10jtHU9i82C5cv2hta7VmPZkm0DFWFcayMiqfCqG8u19ntL/PX5bUa3mUcDQ6LNG+0qM9JTeHpB3UjP1Dh881i3zdqbi1mBWtJYPDkdHerZwem0+E8cdv01d3P9593Ui8zQ6jnT3eRDRVH+yquy9sxEUuds4fcF95kJhXK7YOdZQyU2+xg0bLO35XajvCSBGIqVsTBbTd5M154EU/+dfklL9AeXBwF9NoGpa2gc+CJCOfgqvAgMBAAGjUzBRMB0GA1UdDgQWBBTqP5J762zVXV2hiVxZBqw1UGdFKjAfBgNVHSMEGDAWgBTqP5J762zVXV2hiVxZBqw1UGdFKjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDRlOps/3rEXdEc2SAbFUjU6PmoD+ycpQvMvhn1fbrScLB4v4MnsaT5pCgLsxfglb+cDjgkRyEXhs1K6sTsJhTkJ9t9sYgwLVlxuqxKPPxOab0JUZ5/9UsxZ0eKnw0ZmW2VYFIZ6u3zm8RwWZXtpm97w0p43c31fQ0Dc0+KFTKjgQ5q7oG67fV1M0aQaC9wjnthtjCIkBXyK+T637INAoSN4SXIiaZR7OTSTKzJzSBfg+CHGvUTlYVZe9vUx+0filRd0NAv5eCdGPyVbLieCGxJgNnV970TE0olp2VOmAE6O6kvisIvf2Lf3kNtuDTcov+tnKsS3L1FanDUjjZnkTaO'));
    }

    private function saml_debug_url_host(string $url): string {
        $host = (string) wp_parse_url($url, PHP_URL_HOST);
        $path = (string) wp_parse_url($url, PHP_URL_PATH);
        if ($host === '' && $path === '') {
            return '';
        }
        return $host . $path;
    }

}
