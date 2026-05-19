# wp-spid-cie — Contesto di sviluppo

## Progetto
Plugin WordPress per l'integrazione di SPID e CIE nelle PA italiane.
Repository: https://github.com/totolabs/wp-spid-cie

## Stack
PHP, WordPress, OIDC Federation, SAML2, phpseclib3

## Siti di riferimento
- https://tsrmpstrpsalerno.it (TSRM Salerno, IPA: CPDTSRS)
- https://ofinaavbnce.it (Fisioterapisti NA-AV-BN-CE, IPA: NW2VXORJ)

## Workflow
- Branch sviluppo: develop
- Ogni fix su branch dedicato: fix/nome-fix o feat/nome-feature
- Mai committare direttamente su develop o main
- Merge su develop dopo verifica
- PR develop → main solo per release stabili

## Convenzioni commit
fix(scope): descrizione breve
feat(scope): descrizione breve

Scope validi: spid-saml, cie-federation, spid-registry, admin, public

## Deploy
- File modificati → FileZilla SFTP su entrambi i siti
- Prima di deploy SPID: test metadata con spid-sp-test
- Dopo rigenerazione certificati: aggiornare metadata presso AgID

## Test SPID metadata
docker run --rm python:3.11-slim bash -c \
  "apt-get update -qq && \
   apt-get install -y -qq xmlsec1 libxmlsec1-openssl && \
   pip install -q spid-sp-test && \
   spid_sp_test --metadata-url URL"

## Endpoint da verificare dopo ogni modifica CIE
- DOMINIO/.well-known/openid-federation
- DOMINIO/resolve?sub=DOMINIO&trust_anchor=https://registry.interno.gov.it

## Python locale
C:\Python\Python313\python.exe

## Note operative
- Backup private.key e public.crt prima di rigenerare certificati
- WP_DEBUG deve essere false in produzione
- Cache registry IdP: premere "Aggiorna Registry IdP ora" dopo
  modifiche al registry service
