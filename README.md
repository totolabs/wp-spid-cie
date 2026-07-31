# SPID & CIE Login per WordPress

![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue) ![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b) ![License](https://img.shields.io/badge/License-GPL--2.0--or--later-green)

Plugin WordPress per l'autenticazione tramite **SPID** e **CIE** nelle Pubbliche Amministrazioni italiane, conforme alla misura PNRR 1.4.4 e alle linee guida AgID.

## Funzionalità

- **SPID SAML2** — Autenticazione tramite il Sistema Pubblico di Identità Digitale con protocollo SAML 2.0. Supporto a tutti gli Identity Provider del registro AgID (inclusi IdP con firme dual-signature).
- **CIE OIDC Federation** — Autenticazione tramite Carta d'Identità Elettronica con OpenID Connect Federation 1.0.
- **SPID OIDC** — Supporto OpenID Connect Federation per SPID (in sviluppo).
- **Smart Button** — Pulsante SPID conforme alle linee guida UX AgID con selezione IdP tramite menu a tendina.
- **Generazione certificati** — Generazione one-click di chiavi RSA e certificato X.509 self-signed conformi al profilo SP pubblico SPID.
- **Auto-provisioning utenti** — Creazione automatica dell'utente WordPress al primo accesso con username dal codice fiscale SPID/CIE.
- **Registry IdP** — Cache locale del registry AgID con aggiornamento manuale dall'area admin.

## Requisiti

- WordPress 6.0 o superiore
- PHP 7.4 o superiore
- Estensioni PHP: `openssl`, `gmp`, `mbstring`, `curl`, `json`
- Server HTTPS con certificato valido
- Accesso SFTP/FTP per il deploy iniziale

## Installazione

1. Caricare la cartella del plugin in `/wp-content/plugins/`.
2. Attivare il plugin dal menu **Plugin** in WordPress.
3. Andare su **Impostazioni > SPID & CIE Login**.
4. Compilare i dati dell'Ente nel tab **Ente** (denominazione, IPA, codice fiscale, email).
5. Generare i certificati SPID nel tab **SPID SAML** con il bottone dedicato.
6. Configurare gli endpoint IdP nel tab **SPID SAML** o abilitare il registry AgID.
7. Configurare CIE nel tab **CIE** con trust anchor e chiavi JWKS.
8. Inserire lo shortcode `[spid_cie_login]` nella pagina di login.

## Federazione CIE

Il trust anchor CIE di produzione è `https://oidc.registry.servizicie.interno.gov.it`. Va compilato **solo** il campo "Trust Anchor CIE (Produzione)", lasciando vuoti "CIE pre-produzione" e "SPID": è l'unico valore che deve comparire in `authority_hints` nell'entity configuration.

L'email del tab **Ente** deve coincidere con l'indirizzo registrato nei dettagli dell'ente sul portale CIE. Il portale incrocia i due valori quando si valida la componente tecnica e, se differiscono, restituisce `[metadata.federation_entity.contacts] Elemento non presente` — messaggio fuorviante, perché l'elemento è presente ma non corrisponde.

Prima dell'approvazione della federazione, `trust_marks: null` e una trust chain a 1 solo elemento in `/resolve` sono lo stato atteso: il trust mark viene rilasciato dal portale **dopo** la federazione.

Endpoint da verificare dopo ogni modifica alla configurazione CIE:

```bash
curl -sS -H "Accept: application/entity-statement+jwt" https://DOMINIO/.well-known/openid-federation
curl -sS "https://DOMINIO/resolve?sub=https://DOMINIO&trust_anchor=https://oidc.registry.servizicie.interno.gov.it"
curl -sS "https://oidc.registry.servizicie.interno.gov.it/fetch?sub=https://DOMINIO"
```

## Siti in produzione

Il plugin è utilizzato da Pubbliche Amministrazioni italiane (Ordini Professionali, Enti Locali) in ambiente di produzione con SPID SAML e CIE OIDC Federation attivi.

## Sviluppo

```
main      ← release stabili con tag vX.Y.Z
develop   ← branch di integrazione
fix/*     ← bugfix creati da develop
feat/*    ← nuove funzionalità create da develop
```

Per contribuire: aprire una Pull Request verso `develop`. Vedere [CONTRIBUTING.md](CONTRIBUTING.md) per il workflow completo.

Per testare i metadata SPID SAML:

```bash
docker run --rm python:3.11-slim bash -c \
  "apt-get update -qq && apt-get install -y -qq xmlsec1 libxmlsec1-openssl && \
   pip install -q spid-sp-test && \
   spid_sp_test --metadata-url https://DOMINIO/sp-metadata.xml"
```

## Licenza

GPL-2.0-or-later — vedere [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html).

Sviluppato da [Totolabs Srl](https://totolabs.it).
