# Release Checklist

Checklist operativa per pubblicare una nuova release del plugin WordPress.

## 1) Preparazione

- [ ] Allineare `develop` con lo stato più recente.
- [ ] Verificare che tutte le PR previste siano state mergiate.
- [ ] Eseguire test/check previsti dal progetto.

## 2) Bump versione

- [ ] Aggiornare la versione del plugin nei file necessari (es. header plugin, readme, changelog).
- [ ] Commit del bump versione con messaggio chiaro.

## 3) Tag Git

- [ ] Creare tag annotato con versione semantica (es. `v1.2.3`).
- [ ] Push di commit e tag verso remoto.

Esempio:

```bash
git checkout main
git pull origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main --tags
```

## 4) GitHub Release

- [ ] Creare una GitHub Release dal tag `vX.Y.Z`.
- [ ] Inserire note di release (novità, fix, eventuali breaking change).

## 5) Pacchetto ZIP WP-ready

L'artefatto canonico di distribuzione NON è il working tree e NON è lo ZIP "Source code" generato
da GitHub: è un archive prodotto con `git archive` da un tag (o SHA) preciso.

- Le esclusioni del pacchetto sono definite **solo** in `.gitattributes` (direttive `export-ignore`):
  file di sviluppo/repository (`tests/`, `tooling/`, `docs/`, `lib/`, `composer.*`, `README.md`,
  `CONTRIBUTING.md`, `.git*`). `vendor/` resta nel pacchetto.
- `export-ignore` è letto dal **commit archiviato**, non dal working tree: modificare `.gitattributes`
  ha effetto solo dopo il commit.
- `git archive` include solo file tracciati: materiale locale non versionato (chiavi, test locali,
  diario) non può finire nel pacchetto.
- `core.autocrlf=false` è **obbligatorio**: con `autocrlf=true` (Windows) l'archive esce in CRLF.

Comando canonico (sostituire versione e riferimento):

```bash
git -c core.autocrlf=false archive --format=zip --prefix=wp-spid-cie/ -o <scratch>/wp-spid-cie-X.Y.Z.zip <TAG|SHA>
```

Verifiche sull'artefatto prima di distribuirlo:

- [ ] Due archive dallo stesso riferimento hanno lo stesso SHA-256 (determinismo).
- [ ] Root unica `wp-spid-cie/`; dimensione < 10 MB; manifest (`unzip -Z1`) acquisito.
- [ ] Assenti: `tests/`, `tooling/`, `docs/`, `lib/` (root), `composer.json`, `composer.lock`, `.git*`,
      `README.md`, `CONTRIBUTING.md`, chiavi/certificati fuori da `vendor/`.
- [ ] Presenti: `wp-spid-cie.php`, `uninstall.php`, `readme.txt`, `LICENSE`, `CHANGELOG.md`, `admin/`,
      `includes/`, `public/`, `vendor/autoload.php` e le dipendenze runtime in `vendor/`.
- [ ] Nessun dato reale di enti nei file non-vendor; nessun byte CR nei `.php`; `php -l` pulito.
- [ ] Copia estratta in directory pulita: bootstrap del plugin senza errori e suite `tests/` del
      repository eseguita contro la copia estratta.
- [ ] Validare installazione/aggiornamento da ambiente WordPress pulito.
- [ ] Allegare lo ZIP verificato alla GitHub Release (se previsto dal processo interno).

Per WordPress.org (SVN): estrarre l'artefatto verificato e copiare i **contenuti** di `wp-spid-cie/`
in `trunk/`. Lo ZIP non si committa in SVN; il tag SVN della versione nasce da `trunk/`.

## 6) Post-release

- [ ] Verificare che il tag e la release siano pubblici e corretti.
- [ ] Comunicare la release al team/stakeholder.
