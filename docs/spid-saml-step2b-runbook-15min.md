# SPID SAML Step 2b — Runbook 15 minuti

## 1) Configurazione (5 minuti)
1. Aggiorna plugin e salva permalink.
2. Tab **F. SPID SAML**:
   - abilita SPID SAML
   - configura IdP EntityID, SSO URL, (SLO URL opzionale), cert X.509 o metadata XML
   - clock skew 120
   - provisioning ON/OFF secondo test
3. Verifica endpoint:
   - `/spid/saml/metadata`
   - `/spid/saml/login`
   - `/spid/saml/acs`
   - `/spid/saml/sls`

## 2) Smoke rapido endpoint (3 minuti)
```bash
curl -i https://example.gov.it/spid/saml/metadata
curl -i https://example.gov.it/spid/saml/login
curl -i https://example.gov.it/spid/saml/acs
curl -i https://example.gov.it/spid/saml/sls
```
Atteso:
- metadata: `200` XML
- login: redirect verso IdP (302) o errore configurazione incompleta
- acs GET: `405`
- sls GET: logout locale + redirect interno

## 3) Flusso login (5 minuti)
1. Clic su “Entra con SPID SAML”.
2. Login su IdP.
3. Ritorno su ACS.
4. Verifica:
   - login WP effettuato
   - redirect interno da RelayState
   - meta utente aggiornati (`_spidcie_fiscal_code`, `_spidcie_saml_idp`)

## 4) Provisioning ON/OFF (2 minuti)
- ON: utente non esistente -> creato + login.
- OFF: utente non esistente -> blocco con `spid_cie_error`.

## GO/NO-GO
### GO
- Endpoint ok, login ok, provisioning coerente, nessun fatal.

### NO-GO
- Errori firma/issuer/destination ricorrenti, redirect esterni, fatal PHP.

## Limiti noti (Step 2b)
- Validazione firma con verifica SignedInfo + digest reference (anti-replay e check URI univoco attivi). Per allineamento 1:1 a wp-spid-italia in produzione è comunque raccomandata integrazione toolkit XMLDSig completo (es. xmlseclibs) quando disponibile nel pacchetto plugin.
- Configurazione IdP attuale single-provider (si può estendere in Step successivo).
