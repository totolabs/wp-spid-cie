# Endpoints e Comandi di Test
*wp-spid-cie — aggiornato 19/05/2026*

---

## Siti

| Sito | Dominio |
|------|---------|
| TSRM Salerno | https://tsrmpstrpsalerno.it |
| Fisioterapisti Napoli | https://ofinaavbnce.it |

Nei comandi sotto sostituisci `DOMINIO` con uno dei due URL sopra.

---

## CIE OIDC Federation

### Entity Configuration
```bash
curl -s -I DOMINIO/.well-known/openid-federation
# Atteso: HTTP 200, Content-Type: application/entity-statement+jwt

curl -s DOMINIO/.well-known/openid-federation
# Atteso: stringa JWT (eyJ...) senza testo prima
```

### Decodifica Entity Configuration (payload leggibile)
```powershell
$jwt = curl.exe -s "DOMINIO/.well-known/openid-federation"
$parts = $jwt.Split('.')
function Decode-B64Url($s) {
    $s = $s -replace '-','+' -replace '_','/'
    $pad = (4 - ($s.Length % 4)) % 4
    $bytes = [Convert]::FromBase64String($s + ('=' * $pad))
    [System.Text.Encoding]::UTF8.GetString($bytes)
}
Write-Host "=== HEADER ===" ; Decode-B64Url $parts[0] | ConvertFrom-Json | ConvertTo-Json
Write-Host "=== PAYLOAD ===" ; Decode-B64Url $parts[1] | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

### Resolve Endpoint
```bash
curl -s -I "DOMINIO/resolve?sub=DOMINIO&trust_anchor=https://oidc.registry.servizicie.interno.gov.it"
# Atteso: HTTP 200, Content-Type: application/resolve-response+jwt
```

### Campi obbligatori da verificare nel payload Entity Configuration
- `sub` = DOMINIO (stringa semplice)
- `iss` = DOMINIO
- `iat`, `exp` presenti
- `jwks.keys` presente con chiave RSA
- `metadata.openid_relying_party.subject_type` = "pairwise"
- `metadata.openid_relying_party.id_token_signed_response_alg` = "RS256"
- `metadata.openid_relying_party.token_endpoint_auth_method` = "private_key_jwt"
- `metadata.openid_relying_party.userinfo_signed_response_alg` = "RS256"
- `authority_hints` ASSENTE
- `jwks_uri` ASSENTE

### Campi obbligatori da verificare nel payload Resolve
- `trust_chain` presente (array con almeno 1 elemento JWT)
- `trust_anchor` = "https://oidc.registry.servizicie.interno.gov.it"
- Tutti i campi sopra dell'Entity Configuration

---

## SPID SAML

### Metadata SP
```bash
curl -s -I DOMINIO/sp-metadata.xml
# Atteso: HTTP 200, Content-Type: application/xml o text/xml

curl -s DOMINIO/sp-metadata.xml | head -5
# Atteso: XML con EntityDescriptor
```

### Test metadata completo con spid-sp-test (via Docker)
```bash
docker run --rm python:3.11-slim bash -c \
  "apt-get update -qq && \
   apt-get install -y -qq xmlsec1 libxmlsec1-openssl && \
   pip install -q spid-sp-test && \
   spid_sp_test --metadata-url DOMINIO/sp-metadata.xml"
# Atteso: executed 85 tests, 0 failed. 0 warnings.
```

### Verifica certificato nel metadata
```bash
curl -s DOMINIO/sp-metadata.xml | python -c "
import sys, re, base64, hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
xml = sys.stdin.read()
certs = re.findall(r'<[^>]*X509Certificate[^>]*>([^<]+)</', xml)
for i, c in enumerate(certs):
    der = base64.b64decode(c.strip())
    cert = x509.load_der_x509_certificate(der, default_backend())
    print(f'Cert #{i+1}:')
    print(f'  Subject: {cert.subject}')
    print(f'  NotBefore: {cert.not_valid_before_utc}')
    print(f'  NotAfter:  {cert.not_valid_after_utc}')
    print(f'  SHA-1: {hashlib.sha1(der).hexdigest()}')
"
```

### Test login SPID (verifica redirect verso IdP)
```bash
curl -s -o /dev/null -D - \
  "DOMINIO/?spid_saml_route=login&idp=https%3A%2F%2Fposteid.poste.it" \
  | grep -i "^location:"
# Atteso: Location: https://posteid.poste.it/jod-fs/... (URL HTTPS, non URN)
```

### Decodifica SAMLRequest
```python
import base64, zlib, urllib.parse

# Prendi il valore SAMLRequest dall'URL di redirect
saml_encoded = "INCOLLA_QUI_IL_VALORE_SAMLRequest"
decoded = base64.b64decode(urllib.parse.unquote(saml_encoded) + "==")
try:
    xml = zlib.decompress(decoded, -15).decode()
except:
    xml = decoded.decode()
print(xml)
```

---

## JWKS

```bash
curl -s DOMINIO/jwks.json
# Atteso: JSON con array "keys"

curl -s "DOMINIO?rest_route=/wp-spid-cie/v1/jwks"
# URL alternativo REST API
```

---

## Pagine frontend

```bash
# Pagina di login con pulsanti SPID e CIE
curl -s -I DOMINIO/accedi
# Atteso: HTTP 200

# Verifica che il pulsante SPID sia presente nell'HTML
curl -s DOMINIO/accedi | grep -i "spid"
```

---

## Comandi utili

### Verifica WP_DEBUG disabilitato
```bash
curl -s DOMINIO/.well-known/openid-federation | head -c 3
# Atteso: "eyJ" — se inizia con altro (es. spazio, HTML) WP_DEBUG è attivo
```

### Confronto certificato metadata vs chiave firma SAMLRequest
```bash
# 1. Ottieni SHA-1 cert dal metadata
curl -s DOMINIO/sp-metadata.xml | python -c "
import sys,re,base64,hashlib
xml=sys.stdin.read()
c=re.findall(r'X509Certificate[^>]*>([^<]+)<',xml)[0]
print(hashlib.sha1(base64.b64decode(c.strip())).hexdigest())
"

# 2. Il SigAlg nell'URL di redirect deve essere:
# SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
```

### Registry IdP AgID
```bash
# Lista tutti gli IdP
curl -s "https://registry.spid.gov.it/entities-idp?output=json" | python -c "
import sys,json
data=json.load(sys.stdin)
for item in data:
    print(item.get('entity_id',''), '-', item.get('organization_name',''))
"

# Dettaglio singolo IdP
curl -s "https://registry.spid.gov.it/entities-idp/https%3A%2F%2Fposteid.poste.it?output=json"
```

---

## Note operative

- **Non eseguire test di login** sul sito TSRM Salerno durante l'orario lavorativo dell'ente
- **Prima di rigenerare certificati**: backup di `wp-content/uploads/wp-spid-cie-keys/private.key` e `public.crt`
- **Dopo rigenerazione certificati**: aggiornare immediatamente i metadata presso AgID (email a spid.tech@agid.gov.it)
- **Cache registry IdP**: dopo modifiche al registry service, premere "Aggiorna Registry IdP ora" nel pannello admin per invalidare i transient
