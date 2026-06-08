# Contributing

Guida per contribuire al plugin **SPID & CIE Login per WordPress**.

## Workflow branch

Il repository usa un flusso basato su `develop` come branch di integrazione.

```
main      ← solo release stabili (merge da develop con tag)
develop   ← branch di integrazione continua
fix/*     ← bugfix, sempre creati da develop
feat/*    ← nuove funzionalità, sempre create da develop
```

**Regole:**
- Non fare push diretto su `main` o `develop`.
- Ogni `fix/*` o `feat/*` viene mergiato su `develop` via Pull Request.
- `develop` → `main` solo per release stabili, con squash merge e tag.

## Flusso di lavoro

```bash
# 1. Partire sempre da develop aggiornato
git checkout develop
git pull origin develop

# 2. Creare il branch di lavoro
git checkout -b fix/nome-bug
# oppure
git checkout -b feat/nome-funzionalita

# 3. Lavorare e committare
git add <files>
git commit -m "fix(scope): descrizione breve"

# 4. Push e PR verso develop
git push origin fix/nome-bug
```

## Convenzioni commit

```
tipo(scope): descrizione breve in italiano o inglese
```

**Tipi:** `fix`, `feat`, `chore`, `refactor`, `docs`

**Scope validi:** `spid-saml`, `cie-federation`, `spid-registry`, `admin`, `public`

**Esempi:**
```
fix(spid-saml): correggi parsing certificati multipli nel registry
feat(admin): aggiungi tab configurazione CIE
chore(release): bump version to 1.3.1
```

**Regole:**
- Non aggiungere righe `Co-authored-by` nei commit message.
- Il git user del repository è configurato a livello di repo — non modificarlo.

## Pull Request verso develop

1. Aprire la PR da `fix/*` o `feat/*` verso `develop`.
2. Descrivere cosa cambia e perché.
3. Attendere la revisione prima del merge.
4. Usare **merge commit** (no squash sui branch fix/feat → develop, per mantenere la storia).

## Release process (develop → main)

1. Aggiornare `readme.txt` (`Stable tag`) e `wp-spid-cie.php` (numero versione).
2. Aggiornare `CHANGELOG.md` con la sezione della nuova versione.
3. Aggiornare la sezione `== Changelog ==` in `readme.txt`.
4. Merge `develop` → `main` con `--no-ff`.
5. Creare il tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

## Internazionalizzazione

- Tutto il testo visibile all'utente deve usare `__()`, `_e()`, `esc_html__()` o equivalenti con textdomain `wp-spid-cie`.
- Non usare stringhe hardcoded in HTML output.

## Compatibilità WordPress.org

- Ogni file PHP deve avere `defined( 'ABSPATH' ) || exit;` come seconda riga.
- Nessuna funzione globale senza prefisso `wp_spid_cie_` fuori dalle classi.
- Testare con PHP 7.4 (versione minima dichiarata) prima di ogni release.
