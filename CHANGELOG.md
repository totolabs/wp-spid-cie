# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-05-26

### Added
- Admin: campo "URL Logo Ente" in tab 1 (formato SVG, 200×200px, obbligatorio per CIE OIDC)
- Admin: campo "Chiave pubblica JWKS (JSON)" in tab 5 CIE con textarea copiabile e link diretto
- Frontend: icona CIE nel bottone "Entra con CIE" (Logo_CIE_ID.svg da italia/cie-graphics)
- Frontend: logo SPID|AgID ufficiale nel footer pagina login
- Frontend: link "Serve aiuto?" nel dropdown IdP SPID

### Changed
- Admin: voce menu plugin spostata da Impostazioni a menu primario WordPress
- Admin: titolo plugin semplificato in "SPID & CIE Login"
- Admin: tab 1 Ente — descrizioni campi aggiornate (nota IPA+64 chars, logo SVG)
- Admin: tab 4 SPID SAML — rimossi campi duplicati, fonte unica in tab 1
- Admin: tab 5 CIE — rimossi campi PEM duplicati, aggiunto JWKS JSON copiabile
- Admin: rimosso campo spid_cert_org_name dalla UI e dalla logica
- Admin: tabella diagnostica IdP nascosta se WP_DEBUG disattivo
- Registry IdP: bump transient v2→v3, aggiornati tutti i loghi IdP dal CDN ufficiale
- CIE OIDC: rimosso refresh_token da grant_types Entity Configuration
- Admin: remove incorrect single-IdP selector UI
  (all IdPs must be available simultaneously)

### Fixed
- Tab Stato: corretto check "Registry IdP" sempre KO
- Tab Stato: corretto errore critico Class not found in tab Stato
- SPID SAML: messaggi errore specifici per test AgID 104/105/106/107/108/111
- SPID SAML: estrazione SubStatusCode dalla Response SAML
- SPID SAML: logo IntesiGroup nel vendor era residuo di IntesaID — corretto
- Frontend: rimosso IntesaID, aggiunto Intesi Group e EtnaHitech nel dropdown
- CIE OIDC: rimosso logo_uri hardcoded WordPress, aggiunto campo configurabile
- SPID SAML AuthnRequest: add ForceAuthn="true" for L2/L3,
  NameQualifier, AttributeConsumingServiceIndex="0",
  remove forbidden AllowCreate, use opaque RelayState
- SPID registry: normalize CamelCase keys from AgID registry API
  (bug caused SSO URL to be set to binding URN instead of HTTPS endpoint)
- CIE federation: add missing required RP metadata fields
  (id_token_signed_response_alg, userinfo_signed_response_alg,
  token_endpoint_auth_method, token_endpoint_auth_signing_alg)
- CIE federation: add trust_chain and trust_marks to /resolve endpoint response
- Certificate generation: write public.key file during generation
- Frontend: show spid_cie_error banner in shortcode login page
- Admin: fix redirect to correct tab after key generation

### Chore
- Translate all Italian source comments to English across
  the entire plugin codebase
- Remove TODO comment from TokenValidator.php
- Remove debug-paths.php (leftover diagnostic script)
- Update .gitignore to exclude AI context files

## [1.2.1] - 2025-05-xx

_Previous release._
