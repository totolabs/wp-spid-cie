# wp-spid-cie
Plugin WordPress per l'autenticazione tramite SPID e CIE con protocollo OpenID Connect, dedicato alle Pubbliche Amministrazioni italiane.

## Collaudo SPID SAML Step 2

Checklist operativa GO/NO-GO disponibile in `docs/spid-saml-step2-go-no-go-checklist.md`.


## SPID SAML Step 2b

- Runbook rapido: `docs/spid-saml-step2b-runbook-15min.md`
- Checklist GO/NO-GO estesa: `docs/spid-saml-step2-go-no-go-checklist.md`

- Admin SPID SAML: configura solo dati SP/metadata; la scelta IdP avviene lato frontend utente da Registry SPID (cache locale).

## Note aggiornamento configurazione (admin)

- Nuova organizzazione backend in 5 tab principali: **Ente**, **Impostazioni**, **SPID OIDC**, **SPID SAML**, **CIE**.
- In **Impostazioni** è disponibile la selezione mutuamente esclusiva del metodo SPID (`SAML`/`OIDC`).
- Endpoint metadata SPID SAML protetto da token: usare l'URL con query string `?spid_metadata_token=...` generata nella sezione SPID SAML/Metadata.
