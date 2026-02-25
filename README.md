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

## Certificati SPID SAML one-click (SP pubblico)

- Il plugin genera automaticamente `private.key` + `public.crt` self-signed in `wp-content/uploads/wp-spid-cie-keys/` (più `csr.pem` opzionale) usando solo estensione OpenSSL PHP.
- Requisiti minimi implementati: RSA 2048 (default), digest SHA-256, Subject con `C=IT`, `L`, `O`, `CN`, OID `2.5.4.83` (URI=EntityID) e OID `2.5.4.97` (`PA:IT-<codice IPA>`).
- Estensioni certificate SPID: `keyUsage` critical (`digitalSignature`, `nonRepudiation/contentCommitment`), `basicConstraints=CA:FALSE`, `certificatePolicies` con OID richiesti dal profilo SP pubblico.
- In area admin è disponibile il bottone **“Genera/Rigenera certificati SPID”** con warning: la rigenerazione cambia fingerprint e richiede aggiornamento metadata su AgID/CIE.
- Stato mostrato in UI: presenza certificato, scadenza, subject e verifica modulus match chiave/certificato.
- Al primo salvataggio configurazione (tab Ente/SPID SAML/Impostazioni), se i certificati mancano, il plugin prova a generarli automaticamente e mostra eventuali errori chiari.

