# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.4.1 — 2026-08-05

### Corretto
- **clock_skew SPID SAML: campo vuoto usa il default invece di azzerare.** `(int) ''` valeva 0,
  azzerando la tolleranza a ogni salvataggio con campo vuoto e provocando `saml_not_yet_valid` /
  `saml_expired`. Ora `''` o valore non numerico ricade su 120.

### Modificato
- **UI SPID OIDC nascosta dietro flag** `WP_SPID_CIE_ENABLE_SPID_OIDC` (default false, override da
  wp-config). Tab, selettore metodo, campo Trust Anchor SPID e preview non mostrati; option e codice
  intatti. `min_loa` spostato nel tab CIE (governa min_acr anche per CIE).
- **Omologazione UI pannello.** I renderer emettono `id` e rispettano il `type` (text|url|email|number);
  `label_for` sui campi Settings API; gruppo radio metodo in `fieldset/legend`. Tab senza numeri.
  Help CIE riscritti (JWKS = RSA non EC; il certificato X.509 non e' il valore da incollare nel portale).
- **Logo Totolabs** ripristinato nel pannello (asset aggiunto).
- Rinomine label e titoli sezione (tab Ente/CIE/Disclaimer).

Nessuna rimozione di funzionalita' o codice in questa release.

## v1.4.0 — 2026-08-03

### Corretto
- **Account duplicati a ogni login (SPID e CIE)** — bug preesistente, non introdotto in
  questa versione. `findByMetaValue()` restituiva i risultati di `WP_User_Query` senza
  reindicizzarli: con `fields => all_with_meta` WordPress li indicizza per **ID utente**,
  quindi `count()` valeva 1 ma `$results[0]` era `null`. Il codice non riconosceva l'utente
  gia' registrato e ne creava uno nuovo a ogni accesso successivo al primo (`<username>_1`),
  finche' dal terzo accesso il lookup ne trovava due e restituiva `oidc_identity_conflict`,
  **bloccando il login**. Riguardava entrambi i protocolli, perche' condividono
  `resolveOrProvisionUser`.
  *Dopo l'aggiornamento*: verificare nel tab "Stato" la presenza di conflitti e riconciliare
  gli account duplicati gia' creati.
- **Codice fiscale: un unico punto di normalizzazione** (`WP_SPID_CIE_OIDC_FiscalCode`).
  SPID SAML consegna il codice fiscale nudo, CIE OIDC lo consegna con prefisso `TINIT-`, e
  i due flussi lo trattavano in modo diverso: la stessa persona otteneva **due account
  WordPress distinti** a seconda del protocollo usato per accedere. Di conseguenza il
  ricongiungimento per codice fiscale gia' presente in `WpAuthService` — che confronta il
  valore in modo esatto — non agganciava mai nulla fra SPID e CIE. Ora entrambi i flussi
  passano dallo stesso normalizzatore.

### Aggiunto
- **Codice fiscale nel profilo utente**: visibile a tutti, modificabile solo da chi ha
  `edit_users`. Permette di collegare a mano un utente preesistente alla sua identita'
  SPID/CIE. Un codice gia' assegnato a un altro account viene rifiutato, perche' due utenti
  con lo stesso codice fiscale bloccherebbero il login di entrambi.
- **Colonna e ricerca per codice fiscale** nella lista utenti di WordPress, con evidenza dei
  valori non ancora normalizzati.
- **Strumento di migrazione** nel tab "Stato": normalizza i codici fiscali salvati dalle
  versioni precedenti, elenca i conflitti senza toccarli e, opzionalmente, rinomina gli
  username che conservano il prefisso `TINIT-`.

### Note per l'aggiornamento
- Chi possiede **un solo account** si migra da solo al primo accesso: il `sub` del provider
  continua ad agganciare l'utente, e il codice fiscale viene riscritto normalizzato.
- Chi possiede **due account** (uno creato via SPID e uno via CIE) va riconciliato **prima**
  con lo strumento di migrazione: in quel caso `sub` e codice fiscale puntano ad account
  diversi e il login fallirebbe con `oidc_identity_conflict`. Lo strumento li elenca e li
  salta invece di applicare la modifica.

## v1.3.2 — 2026-06-08

Release di manutenzione: riallinea il ramo `main` allo stato stabile di `develop`. Il
precedente rilascio v1.3.1 era stato propagato su `main` tramite squash-merge, che non
aveva incluso tutti i fix gia' presenti su `develop`; questa versione li consolida.

### Novita' di questa versione
- **SPID SAML**: validazione del livello di autenticazione nella Response — con
  RequestedAuthnContext `Comparison="exact"` la Response viene rifiutata se
  l'`AuthnContextClassRef` non corrisponde esattamente al livello richiesto (test AgID 94/96).
- **Sicurezza / Pulizia**: rimossi i log diagnostici temporanei dal client OIDC che potevano
  registrare dati sensibili (header/payload del `client_assertion` JWT, body di token e
  userinfo) nel log di WordPress.

### Consolidati su main (gia' introdotti in v1.3.0/v1.3.1, propagati ora)
- CIE OIDC federation: entity configuration, private_key_jwt, trust chain, JWE/userinfo,
  gestione claim e configurazione CIE.
- Hardening per la distribuzione WordPress.org: guardie `ABSPATH`, `uninstall.php`,
  README/CONTRIBUTING, pulizie di packaging.
- UI/integrazioni: adeguamenti frontend, pulsante SPID, bridge integrazione.

## v1.3.1 — 2026-05-26

### Fix SAML — compatibilità IdP dual-signature
- fix(spid-saml): supporto a IdP che firmano sia Response che Assertion (es. Poste Italiane) — gestione 1-2 nodi ds:Signature con preferenza per la firma a livello Response
- fix(spid-saml): rimosso LIBXML_NOBLANKS dal parsing XML per preservare whitespace nel calcolo digest C14N
- fix(spid-saml): C14N eseguito sul nodo live del documento per preservare il contesto namespace
- fix(spid-saml): enveloped-signature transform rimuove solo la firma in validazione

### Fix Registry
- fix(spid-registry): parsing corretto di IdP con più certificati — aggiunta intestazione PEM in extract_runtime_values()
- fix(spid-registry): refresh_all() cancella tutti i transient del registry inclusa la cache per-IdP

### Provisioning utenti
- feat(spid-saml): username WordPress generato dal codice fiscale SPID invece di hash opaco
- fix(spid-saml): collegamento automatico utente esistente per email se sub e codice fiscale non trovano corrispondenza

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
