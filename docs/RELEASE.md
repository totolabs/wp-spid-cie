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

- [ ] Generare ZIP installabile da WordPress (struttura plugin valida, no file non necessari).
- [ ] Validare installazione/aggiornamento da ambiente WordPress pulito.
- [ ] Allegare lo ZIP alla GitHub Release (se previsto dal processo interno).

## 6) Post-release

- [ ] Verificare che il tag e la release siano pubblici e corretti.
- [ ] Comunicare la release al team/stakeholder.
