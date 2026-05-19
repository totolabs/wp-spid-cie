# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - Unreleased

### Fixed
- SPID SAML AuthnRequest: add ForceAuthn="true" for L2/L3,
  NameQualifier, AttributeConsumingServiceIndex="0",
  remove forbidden AllowCreate, use opaque RelayState
- SPID registry: normalize CamelCase keys from AgID registry API
  (bug caused SSO URL to be set to binding URN instead of HTTPS endpoint)
- SPID registry: bump transient prefix to v3 to invalidate stale cache
- CIE federation: add missing required RP metadata fields
  (id_token_signed_response_alg, userinfo_signed_response_alg,
  token_endpoint_auth_method, token_endpoint_auth_signing_alg)
- CIE federation: add trust_chain to /resolve endpoint response
- CIE federation: add trust_marks to /resolve endpoint response
- Certificate generation: write public.key file during generation
- Certificate generation: redirect to CIE tab after generation
  to show success/error banner
- Certificate generation: add spid_cert_org_name field to allow
  O/CN override for entities with name longer than 64 characters
- Frontend: show spid_cie_error banner in shortcode login page
- Admin: fix redirect to correct tab after key generation

### Changed
- Admin: remove incorrect single-IdP selector UI
  (all IdPs must be available simultaneously)

### Chore
- Translate all Italian source comments to English across
  the entire plugin codebase
- Remove TODO comment from TokenValidator.php
- Remove debug-paths.php (leftover diagnostic script)
- Update .gitignore to exclude AI context files

## [1.2.1] - 2025-05-xx

_Previous release._
